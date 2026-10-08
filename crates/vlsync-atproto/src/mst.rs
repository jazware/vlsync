//! Merkle Search Tree, ported from indigo's `atproto/repo/mst` so that tree
//! shapes and sync 1.1 proof block sets match the reference implementation.
//!
//! Nodes are `Arc`-shared and mutated copy-on-write, so a snapshot of the
//! root costs one refcount.
//!
//! `dirty` means "emit this node's block in the next diff". Mutations mark
//! the nodes they rewrite and drop their cached encoding (`bytes`);
//! `prove_mutation` also marks the neighbours a verifier needs to invert the
//! operation, whose cached encoding stays valid.

use crate::cbor;
use crate::cid::Cid;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum MstError {
    #[error("MST is not complete")]
    Partial,
    #[error("invalid MST structure: {0}")]
    Invalid(&'static str),
    #[error("invalid MST key")]
    InvalidKey,
    /// A lazy tree's no-I/O pass met an unloaded node: the caller loads it
    /// asynchronously and retries.
    #[error("MST node not loaded")]
    NotLoaded,
    #[error("MST store read failed: {0}")]
    Store(String),
}

type Result<T> = std::result::Result<T, MstError>;

pub mod single_create;

/// The root of an empty tree: a repo with no records.
pub static EMPTY_ROOT: std::sync::LazyLock<Cid> =
    std::sync::LazyLock::new(|| Tree::new().root_cid().expect("empty tree root"));

const MAX_KEY_BYTES: usize = 1024;

/// Deepest tree accepted from a block set. 2^32 keys give a tree ~16 levels
/// deep; the bound keeps recursive walks off the end of the stack, since a
/// chain of `{e: [], l: child}` nodes is otherwise unbounded.
pub const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug)]
pub struct Node {
    pub height: i32,
    pub entries: Vec<Entry>,
    pub cid: Option<Cid>,
    pub dirty: bool,
    /// Known only by CID.
    pub stub: bool,
    /// The encoded block, kept from its last write while the content is
    /// unchanged. Only internal nodes keep one: leaves are ~3/4 of the nodes
    /// and bytes, and every proof path has just one.
    pub bytes: Option<Arc<[u8]>>,
}

#[derive(Clone, Debug)]
pub enum Entry {
    Value {
        key: Arc<[u8]>,
        val: Cid,
    },
    /// `node` is None in partial trees; `cid` is authoritative only then
    /// (or once `node` has been written).
    Child {
        node: Option<Arc<Node>>,
        cid: Option<Cid>,
    },
}

impl Entry {
    fn is_child(&self) -> bool {
        matches!(self, Entry::Child { .. })
    }
    fn key(&self) -> Option<&[u8]> {
        match self {
            Entry::Value { key, .. } => Some(key),
            _ => None,
        }
    }
    fn child(node: Arc<Node>) -> Entry {
        Entry::Child { node: Some(node), cid: None }
    }
}

/// Leading zero 2-bit pairs of the key's SHA-256.
pub fn height_for_key(key: &[u8]) -> i32 {
    let hv: [u8; 32] = Sha256::digest(key).into();
    for (i, w) in hv.as_chunks::<8>().0.iter().enumerate() {
        let w = u64::from_be_bytes(*w);
        if w != 0 {
            return (i * 32) as i32 + (w.leading_zeros() / 2) as i32;
        }
    }
    128
}

fn valid_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY_BYTES
}

impl Node {
    fn empty(height: i32) -> Node {
        Node { height, entries: Vec::new(), cid: None, dirty: true, stub: false, bytes: None }
    }

    /// A node as decoded or built: not dirty, no cached block.
    pub fn clean(height: i32, entries: Vec<Entry>, cid: Option<Cid>) -> Node {
        Node { height, entries, cid, dirty: false, stub: false, bytes: None }
    }

    fn stub(height: i32, cid: Option<Cid>) -> Node {
        Node { stub: true, ..Node::clean(height, Vec::new(), cid) }
    }

    fn touch(&mut self) {
        self.dirty = true;
        self.bytes = None;
    }

    /// The cached encoding, or a fresh one.
    pub fn block(&self) -> Result<std::borrow::Cow<'_, [u8]>> {
        if let Some(b) = &self.bytes {
            return Ok(std::borrow::Cow::Borrowed(b));
        }
        let mut buf = Vec::with_capacity(64 + self.entries.len() * 80);
        encode_node(self, &mut buf)?;
        Ok(std::borrow::Cow::Owned(buf))
    }

    /// None for an empty or partial subtree.
    fn first_key(&self) -> Option<&Arc<[u8]>> {
        let mut n = self;
        loop {
            match n.entries.first()? {
                Entry::Value { key, .. } => return Some(key),
                Entry::Child { node, .. } => n = node.as_ref()?,
            }
        }
    }

    /// For a [`NodeRef`]: the node's own first value if it has one, sparing a
    /// walk down a chain of cold nodes to the leftmost leaf.
    fn subtree_key(&self) -> Option<&Arc<[u8]>> {
        self.entries
            .iter()
            .find_map(|e| match e {
                Entry::Value { key, .. } => Some(key),
                Entry::Child { .. } => None,
            })
            .or_else(|| self.first_key())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn find_existing_entry(&self, key: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| e.key() == Some(key))
    }

    fn find_existing_child(&self, key: &[u8]) -> Option<usize> {
        let mut idx = None;
        for (i, e) in self.entries.iter().enumerate() {
            match e {
                Entry::Child { .. } => idx = Some(i),
                Entry::Value { key: k, .. } => {
                    if key <= &k[..] {
                        break;
                    }
                    idx = None;
                }
            }
        }
        idx
    }

    /// Returns (index, needs_split).
    fn find_insertion_index(&self, key: &[u8]) -> Result<(usize, bool)> {
        if self.stub {
            return Err(MstError::Partial);
        }
        for (i, e) in self.entries.iter().enumerate() {
            match e {
                Entry::Value { key: k, .. } => {
                    if key < &k[..] {
                        return Ok((i, false));
                    }
                }
                Entry::Child { node, .. } => {
                    if let Some(Entry::Value { key: nk, .. }) = self.entries.get(i + 1) {
                        if key > &nk[..] {
                            continue;
                        }
                    }
                    let child = node.as_ref().ok_or(MstError::Partial)?;
                    match child.compare_key(key)? {
                        Ordering::Less => return Ok((i, false)),
                        Ordering::Greater => continue,
                        Ordering::Equal => return Ok((i, true)),
                    }
                }
            }
        }
        Ok((self.entries.len(), false))
    }

    /// Where `key` falls relative to the key range of this subtree:
    /// Less = before all keys, Greater = after all, Equal = within.
    fn compare_key(&self, key: &[u8]) -> Result<Ordering> {
        match self.compare_step(key)? {
            Compare::Done(o) => Ok(o),
            Compare::Child(i) => match &self.entries[i] {
                Entry::Child { node: Some(c), .. } => Ok(self.child_order(i, c.compare_key(key)?)),
                _ => Err(MstError::Partial),
            },
        }
    }

    /// [`compare_key`](Self::compare_key), marking every node it inspects
    /// dirty (proof).
    fn compare_key_mark(&mut self, key: &[u8]) -> Result<Ordering> {
        let step = self.compare_step(key)?;
        self.dirty = true;
        let i = match step {
            Compare::Done(o) => return Ok(o),
            Compare::Child(i) => i,
        };
        let Entry::Child { node, .. } = &mut self.entries[i] else { unreachable!() };
        let order = Arc::make_mut(node.as_mut().ok_or(MstError::Partial)?).compare_key_mark(key)?;
        Ok(self.child_order(i, order))
    }

    /// One node's part of `compare_key`: an answer, or the child to ask.
    fn compare_step(&self, key: &[u8]) -> Result<Compare> {
        if self.stub {
            return Err(MstError::Partial);
        }
        if self.is_empty() {
            return Err(MstError::Invalid("can't determine key range of empty node"));
        }
        if let Some(Entry::Value { key: k, .. }) = self.entries.first() {
            if key < &k[..] {
                return Ok(Compare::Done(Ordering::Less));
            }
        }
        if let Some(Entry::Value { key: k, .. }) = self.entries.last() {
            if key > &k[..] {
                return Ok(Compare::Done(Ordering::Greater));
            }
        }
        for (i, e) in self.entries.iter().enumerate() {
            match e {
                Entry::Value { key: k, .. } if key < &k[..] => return Ok(Compare::Done(Ordering::Equal)),
                Entry::Value { .. } => {}
                Entry::Child { .. } => {
                    if let Some(Entry::Value { key: nk, .. }) = self.entries.get(i + 1) {
                        if key > &nk[..] {
                            continue;
                        }
                    }
                    return Ok(Compare::Child(i));
                }
            }
        }
        Ok(Compare::Done(Ordering::Equal))
    }

    /// This subtree's order for `key` given child `i`'s.
    fn child_order(&self, i: usize, order: Ordering) -> Ordering {
        match order {
            Ordering::Less if i == 0 => Ordering::Less,
            Ordering::Greater if i == self.entries.len() - 1 => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }

    fn get(&self, key: &[u8], height: i32) -> Result<Option<Cid>> {
        if self.stub {
            return Err(MstError::Partial);
        }
        if height > self.height {
            return Ok(None);
        }
        if height < self.height {
            return match self.find_existing_child(key) {
                Some(idx) => match &self.entries[idx] {
                    Entry::Child { node: Some(c), .. } => c.get(key, height),
                    _ => Err(MstError::Partial),
                },
                None => Ok(None),
            };
        }
        Ok(self.find_existing_entry(key).map(|i| match &self.entries[i] {
            Entry::Value { val, .. } => *val,
            _ => unreachable!(),
        }))
    }
}

enum Compare {
    Done(Ordering),
    Child(usize),
}

/// Marks the nodes adjacent to `key` dirty so they are included as a
/// "covering proof" for the mutation at `key`.
fn prove_mutation(n: &mut Node, key: &[u8]) -> Result<()> {
    let len = n.entries.len();
    for i in 0..len {
        if let Entry::Value { key: k, .. } = &n.entries[i] {
            if key < &k[..] {
                return Ok(());
            }
            continue;
        }
        if let Some(Entry::Value { key: nk, .. }) = n.entries.get(i + 1) {
            if key > &nk[..] {
                continue;
            }
        }
        let Entry::Child { node, .. } = &mut n.entries[i] else { unreachable!() };
        let child = Arc::make_mut(node.as_mut().ok_or(MstError::Partial)?);
        match child.compare_key_mark(key)? {
            Ordering::Greater => continue,
            Ordering::Less => return Ok(()),
            Ordering::Equal => return prove_mutation(child, key),
        }
    }
    Ok(())
}

fn ignore_partial(r: Result<()>) -> Result<()> {
    match r {
        Err(MstError::Partial) => Ok(()),
        other => other,
    }
}

fn insert(mut n: Arc<Node>, key: &[u8], val: Cid, height: i32, prove: bool) -> Result<(Arc<Node>, Option<Cid>)> {
    if n.stub {
        return Err(MstError::Partial);
    }
    if height > n.height {
        return insert_parent(n, key, val, height, prove);
    }
    if height < n.height {
        return insert_child(n, key, val, height, prove);
    }
    if let Some(idx) = n.find_existing_entry(key) {
        if let Entry::Value { val: existing, .. } = &n.entries[idx] {
            if *existing == val {
                return Ok((n, Some(val)));
            }
        }
        let nm = Arc::make_mut(&mut n);
        let Entry::Value { val: existing, .. } = &mut nm.entries[idx] else { unreachable!() };
        let prev = *existing;
        *existing = val;
        nm.touch();
        return Ok((n, Some(prev)));
    }

    let (idx, split) = n.find_insertion_index(key)?;
    let nm = Arc::make_mut(&mut n);
    nm.touch();
    if prove {
        ignore_partial(prove_mutation(nm, key))?;
    }
    let new_entry = Entry::Value { key: key.into(), val };
    if !split {
        nm.entries.insert(idx, new_entry);
        return Ok((n, None));
    }
    let child = match &nm.entries[idx] {
        Entry::Child { node: Some(c), .. } => c.clone(),
        _ => return Err(MstError::Partial),
    };
    let (left, right) = split_node(&child, key)?;
    nm.entries.splice(idx..idx + 1, [Entry::child(left), new_entry, Entry::child(right)]);
    Ok((n, None))
}

fn split_entries(n: &Node, idx: usize) -> Result<(Arc<Node>, Arc<Node>)> {
    if idx == 0 || idx >= n.entries.len() {
        return Err(MstError::Invalid("splitting at one end of entries"));
    }
    let left = Node { entries: n.entries[..idx].to_vec(), ..Node::empty(n.height) };
    let right = Node { entries: n.entries[idx..].to_vec(), ..Node::empty(n.height) };
    Ok((Arc::new(left), Arc::new(right)))
}

fn split_node(n: &Node, key: &[u8]) -> Result<(Arc<Node>, Arc<Node>)> {
    if n.is_empty() {
        return Err(MstError::Invalid("tried to split an empty node"));
    }
    let (idx, split) = n.find_insertion_index(key)?;
    if !split {
        return split_entries(n, idx);
    }
    let child = match &n.entries[idx] {
        Entry::Child { node: Some(c), .. } => c,
        _ => return Err(MstError::Partial),
    };
    let (lower_left, lower_right) = split_node(child, key)?;
    let mut le = n.entries[..idx].to_vec();
    le.push(Entry::child(lower_left));
    let mut re = vec![Entry::child(lower_right)];
    re.extend_from_slice(&n.entries[idx + 1..]);
    Ok((
        Arc::new(Node { entries: le, ..Node::empty(n.height) }),
        Arc::new(Node { entries: re, ..Node::empty(n.height) }),
    ))
}

fn insert_parent(n: Arc<Node>, key: &[u8], val: Cid, height: i32, prove: bool) -> Result<(Arc<Node>, Option<Cid>)> {
    let parent = if n.is_empty() {
        Node::empty(height)
    } else {
        let h = n.height + 1;
        Node { entries: vec![Entry::child(n)], ..Node::empty(h) }
    };
    insert(Arc::new(parent), key, val, height, prove)
}

fn insert_child(mut n: Arc<Node>, key: &[u8], val: Cid, height: i32, prove: bool) -> Result<(Arc<Node>, Option<Cid>)> {
    if let Some(idx) = n.find_existing_child(key) {
        let nm = Arc::make_mut(&mut n);
        let Entry::Child { node, .. } = &mut nm.entries[idx] else { unreachable!() };
        let child = node.take().ok_or(MstError::Partial)?;
        let (new_child, prev) = insert(child, key, val, height, prove)?;
        *node = Some(new_child);
        if prev == Some(val) {
            return Ok((n, Some(val)));
        }
        nm.touch();
        return Ok((n, prev));
    }
    let (idx, split) = n.find_insertion_index(key)?;
    if split {
        return Err(MstError::Invalid("unexpected split when inserting child"));
    }
    let nm = Arc::make_mut(&mut n);
    nm.touch();
    let (new_child, _) = insert(Arc::new(Node::empty(nm.height - 1)), key, val, height, prove)?;
    nm.entries.insert(idx, Entry::child(new_child));
    Ok((n, None))
}

fn remove(mut n: Arc<Node>, key: &[u8], height: Option<i32>, prove: bool) -> Result<(Arc<Node>, Option<Cid>)> {
    if n.stub {
        return Err(MstError::Partial);
    }
    let top = height.is_none();
    let height = height.unwrap_or_else(|| height_for_key(key));
    if height > n.height {
        return Ok((n, None));
    }
    if height < n.height {
        return remove_child(n, key, height, prove);
    }
    let Some(idx) = n.find_existing_entry(key) else {
        return Ok((n, None));
    };
    let nm = Arc::make_mut(&mut n);
    nm.touch();
    let Entry::Value { val: prev, .. } = nm.entries[idx] else { unreachable!() };

    let len = nm.entries.len();
    if idx > 0 && idx + 1 < len && nm.entries[idx - 1].is_child() && nm.entries[idx + 1].is_child() {
        let (left, right) = match (&nm.entries[idx - 1], &nm.entries[idx + 1]) {
            (Entry::Child { node: Some(l), .. }, Entry::Child { node: Some(r), .. }) => (l.clone(), r.clone()),
            _ => return Err(MstError::Partial),
        };
        let merged = merge_nodes(&left, &right)?;
        nm.entries.drain(idx..idx + 2);
        nm.entries[idx - 1] = Entry::child(merged);
    } else {
        nm.entries.remove(idx);
    }

    if prove {
        ignore_partial(prove_mutation(nm, key))?;
    }

    if top {
        loop {
            if n.entries.len() != 1 || !n.entries[0].is_child() {
                break;
            }
            let Entry::Child { node, cid } = &n.entries[0] else { unreachable!() };
            n = match (node, cid) {
                (Some(c), _) => c.clone(),
                (None, Some(c)) => Arc::new(Node::stub(n.height - 1, Some(*c))),
                (None, None) => return Err(MstError::Partial),
            };
        }
    }
    Ok((n, Some(prev)))
}

fn merge_nodes(left: &Node, right: &Node) -> Result<Arc<Node>> {
    let idx = left.entries.len();
    let mut entries = Vec::with_capacity(left.entries.len() + right.entries.len());
    entries.extend_from_slice(&left.entries);
    entries.extend_from_slice(&right.entries);
    if idx > 0 && idx < entries.len() && entries[idx - 1].is_child() && entries[idx].is_child() {
        let merged = match (&entries[idx - 1], &entries[idx]) {
            (Entry::Child { node: Some(l), .. }, Entry::Child { node: Some(r), .. }) => merge_nodes(l, r)?,
            _ => return Err(MstError::Partial),
        };
        entries[idx - 1] = Entry::child(merged);
        entries.remove(idx);
    }
    Ok(Arc::new(Node { entries, ..Node::empty(left.height) }))
}

fn remove_child(mut n: Arc<Node>, key: &[u8], height: i32, prove: bool) -> Result<(Arc<Node>, Option<Cid>)> {
    // Tree::remove checked the key exists, so a no-op delete doesn't
    // copy-on-write the path
    let Some(idx) = n.find_existing_child(key) else {
        return Ok((n, None));
    };
    let nm = Arc::make_mut(&mut n);
    let Entry::Child { node, .. } = &mut nm.entries[idx] else { unreachable!() };
    let child = node.take().ok_or(MstError::Partial)?;
    let (new_child, prev) = remove(child, key, Some(height), prove)?;
    if !new_child.is_empty() {
        *node = Some(new_child);
    } else {
        nm.entries.remove(idx);
    }
    nm.touch();
    Ok((n, prev))
}

/// 8 bytes at a time: keys in one node share most of their bytes
/// (`collection/` and the TID's leading characters).
fn count_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i + 8 <= n {
        let x =
            u64::from_le_bytes(a[i..i + 8].try_into().unwrap()) ^ u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        if x != 0 {
            return i + (x.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    i + a[i..n].iter().zip(&b[i..n]).take_while(|(x, y)| x == y).count()
}

fn child_cid(e: &Entry) -> Option<Cid> {
    match e {
        Entry::Child { node: Some(n), cid } => n.cid.or(*cid),
        Entry::Child { node: None, cid } => *cid,
        _ => None,
    }
}

/// Encodes a node whose children all have CIDs computed. The map keys and
/// link heads are fixed byte strings in a node's one canonical encoding, so
/// they go out as literals.
pub fn encode_node(n: &Node, out: &mut Vec<u8>) -> Result<()> {
    let nvals = n.entries.iter().filter(|e| !e.is_child()).count();
    let mut left = None;
    let mut start = 0;
    if let Some(e @ Entry::Child { .. }) = n.entries.first() {
        left = Some(child_cid(e).ok_or(MstError::Invalid("child without cid"))?);
        start = 1;
    }
    // ~55 bytes of framing and links per entry, plus key suffixes
    out.reserve(48 + nvals * 64);
    out.extend_from_slice(&[0xa2, 0x61, b'e']);
    cbor::write_array_head(out, nvals);
    let mut prev_key: &[u8] = &[];
    let mut i = start;
    while i < n.entries.len() {
        let Entry::Value { key, val } = &n.entries[i] else {
            return Err(MstError::Invalid("two adjacent child pointers"));
        };
        let right = match n.entries.get(i + 1) {
            Some(e @ Entry::Child { .. }) => {
                i += 1;
                Some(child_cid(e).ok_or(MstError::Invalid("child without cid"))?)
            }
            _ => None,
        };
        encode_entry(out, prev_key, key, right.as_ref(), val);
        prev_key = key;
        i += 1;
    }
    out.extend_from_slice(&[0x61, b'l']);
    write_opt_link(out, left.as_ref());
    Ok(())
}

/// `key` prefix-compressed against the entry before it; `right` is the
/// subtree after it.
#[inline]
fn encode_entry(out: &mut Vec<u8>, prev_key: &[u8], key: &[u8], right: Option<&Cid>, val: &Cid) {
    let p = count_prefix_len(prev_key, key);
    out.extend_from_slice(&[0xa4, 0x61, b'k']);
    cbor::write_bytes(out, &key[p..]);
    out.extend_from_slice(&[0x61, b'p']);
    cbor::write_uint(out, p as u64);
    out.extend_from_slice(&[0x61, b't']);
    write_opt_link(out, right);
    out.extend_from_slice(&[0x61, b'v']);
    out.extend_from_slice(&cbor::link_bytes(val));
}

/// [`encode_node`] of a leaf one entry at a time, from keys the caller
/// doesn't keep (an export's record stream): the entries are written after
/// room for the head, which [`finish`](LeafEncoder::finish) fills in once
/// their count is known. The buffers are reused from leaf to leaf.
#[derive(Default)]
pub struct LeafEncoder {
    /// `LEAF_HEAD_ROOM` bytes of room, then the entries.
    buf: Vec<u8>,
    head: Vec<u8>,
    prev: Vec<u8>,
    n: usize,
}

/// `{"e": [` with the longest array head (9 bytes).
const LEAF_HEAD_ROOM: usize = 3 + 9;

impl LeafEncoder {
    pub fn clear(&mut self) {
        self.buf.clear();
        self.buf.resize(LEAF_HEAD_ROOM, 0);
        self.prev.clear();
        self.n = 0;
    }

    /// Appends an entry (keys in ascending order).
    pub fn push(&mut self, key: &[u8], val: &Cid) {
        if self.buf.len() < LEAF_HEAD_ROOM {
            self.clear();
        }
        encode_entry(&mut self.buf, &self.prev, key, None, val);
        self.prev.clear();
        self.prev.extend_from_slice(key);
        self.n += 1;
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The leaf's block. Call once per [`clear`](LeafEncoder::clear).
    pub fn finish(&mut self) -> &[u8] {
        if self.buf.len() < LEAF_HEAD_ROOM {
            self.clear();
        }
        self.head.clear();
        self.head.extend_from_slice(&[0xa2, 0x61, b'e']);
        cbor::write_array_head(&mut self.head, self.n);
        let start = LEAF_HEAD_ROOM - self.head.len();
        self.buf[start..LEAF_HEAD_ROOM].copy_from_slice(&self.head);
        self.buf.extend_from_slice(&[0x61, b'l', 0xf6]);
        &self.buf[start..]
    }
}

#[inline]
fn write_opt_link(out: &mut Vec<u8>, c: Option<&Cid>) {
    match c {
        Some(c) => out.extend_from_slice(&cbor::link_bytes(c)),
        None => out.push(0xf6),
    }
}

/// Recomputes CIDs of dirty nodes, emitting their blocks into `out`. A node
/// marked only as proof (content and children's CIDs unchanged) emits its
/// cached block without re-encoding or re-hashing it.
fn write_blocks(
    n: &mut Arc<Node>,
    out: &mut Option<&mut Vec<(Cid, Vec<u8>)>>,
    refs: &mut Option<&mut Vec<(Cid, NodeRef)>>,
    depth: usize,
) -> Result<Cid> {
    if depth > MAX_DEPTH {
        return Err(MstError::Invalid("tree too deep"));
    }
    if n.stub {
        return Err(MstError::Invalid("nil tree node"));
    }
    if !n.dirty {
        if let Some(c) = n.cid {
            return Ok(c);
        }
    }
    let nm = Arc::make_mut(n);
    let mut children_changed = false;
    for e in nm.entries.iter_mut() {
        if let Entry::Child { node: Some(c), cid } = e {
            let new = if c.dirty || c.cid.is_none() {
                write_blocks(c, out, refs, depth + 1)?
            } else {
                c.cid.ok_or(MstError::Invalid("child without cid"))?
            };
            children_changed |= *cid != Some(new);
            *cid = Some(new);
        }
    }
    if children_changed {
        nm.bytes = None;
    }
    let c = match (nm.cid, &nm.bytes) {
        (Some(c), Some(b)) => {
            if let Some(out) = out.as_mut() {
                out.push((c, b.to_vec()));
            }
            c
        }
        _ => {
            let mut buf = Vec::with_capacity(64 + nm.entries.len() * 80);
            encode_node(nm, &mut buf)?;
            let c = Cid::dag_cbor(&buf);
            nm.cid = Some(c);
            if nm.height >= 1 {
                nm.bytes = Some(Arc::from(&buf[..]));
            }
            if let Some(out) = out.as_mut() {
                out.push((c, buf));
            }
            c
        }
    };
    nm.dirty = false;
    if let (Some(refs), Some(k)) = (refs.as_mut(), nm.subtree_key()) {
        refs.push((c, (k.clone(), nm.height)));
    }
    Ok(c)
}

/// Decodes one node block, checking that it is the canonical encoding of a
/// valid node: exactly the `e` and `l` fields (both required, `l` and each
/// `t` a link or null, as the reference's NodeData schema), entries with
/// exactly `k`/`p`/`t`/`v`, keys strictly ascending and all of one height,
/// maximal prefix lengths (the first entry's is 0), and no child pointers
/// in a height-0 node. Heights across nodes are checked by `load_from_blocks`.
pub fn decode_node(data: &[u8], c: Cid) -> Result<Node> {
    // the generic decoder names the error of anything the fast path refuses
    decode_node_fast(data, c, None).map_or_else(|| decode_node_reference(data, c), Ok)
}

/// [`decode_node`] of a node whose height is known (its parent's minus one)
/// and whose bytes are trusted to hash to `c` (read back from this PDS's own
/// store): the keys aren't hashed for their heights. A node without keys
/// (only a root can be) gets -1 as from [`decode_node`].
pub fn decode_trusted_node(data: &[u8], c: Cid, height: i32) -> Result<Node> {
    decode_node_fast(data, c, Some(height)).map_or_else(|| decode_node_reference(data, c), Ok)
}

/// The height of a canonical node's first key (whole: its prefix length is
/// 0), hashing only that key. None for a node without keys, or bytes not in
/// [`decode_node_fast`]'s encoding.
pub fn first_key_height(data: &[u8]) -> Option<i32> {
    let mut r = cbor::Cursor::new(data);
    if !r.lit(&[0xa2, 0x61, b'e']) || r.head(4)? == 0 || !r.lit(&[0xa4, 0x61, b'k']) {
        return None;
    }
    Some(height_for_key(r.bytes()?))
}

/// [`decode_node`] specialized to the one encoding a valid node can have,
/// `{"e": [{"k", "p", "t", "v"}...], "l"}` with canonical heads, read
/// straight off the bytes. Returns a node only when
/// [`decode_node_reference`] would return the same node
/// (tests/all/shrike_adopt.rs).
fn decode_node_fast(data: &[u8], c: Cid, known_height: Option<i32>) -> Option<Node> {
    let mut r = cbor::Cursor::new(data);
    // {"e": [...
    if !r.lit(&[0xa2, 0x61, b'e']) {
        return None;
    }
    let n = r.head(4)?;
    // an entry takes at least 53 bytes (two links); a child pointer adds a
    // slot, so internal nodes may grow this once
    let mut entries = Vec::with_capacity(n.min(data.len() as u64 / 53) as usize + 1);
    let mut key: Vec<u8> = Vec::with_capacity(64);
    let mut height = -1;
    let mut has_child = false;
    for i in 0..n {
        if !r.lit(&[0xa4, 0x61, b'k']) {
            return None;
        }
        let k = r.bytes()?;
        if !r.lit(&[0x61, b'p']) {
            return None;
        }
        let p = r.head(0)?;
        if p > key.len() as u64 {
            return None;
        }
        let p = p as usize;
        // the new key is key[..p] + k: canonical prefix compression wants
        // it to differ from the previous key right at p (or extend it), and
        // ascending order wants it greater there
        if i > 0 {
            let ok = match key.get(p) {
                Some(&prev_byte) => k.first().is_some_and(|&b| b > prev_byte),
                None => !k.is_empty(),
            };
            if !ok {
                return None;
            }
        }
        if !r.lit(&[0x61, b't']) {
            return None;
        }
        let t = r.opt_link()?;
        if !r.lit(&[0x61, b'v']) {
            return None;
        }
        let val = r.link()?;
        key.truncate(p);
        key.extend_from_slice(k);
        if !valid_key(&key) {
            return None;
        }
        match known_height {
            Some(h) => height = h,
            None => {
                let h = height_for_key(&key);
                if height < 0 {
                    height = h;
                } else if h != height {
                    return None;
                }
            }
        }
        entries.push(Entry::Value { key: Arc::from(&key[..]), val });
        if let Some(t) = t {
            has_child = true;
            entries.push(Entry::Child { node: None, cid: Some(t) });
        }
    }
    if !r.lit(&[0x61, b'l']) {
        return None;
    }
    let l = r.opt_link()?;
    if !r.at_end() {
        return None;
    }
    if let Some(l) = l {
        has_child = true;
        entries.insert(0, Entry::Child { node: None, cid: Some(l) });
    }
    if height == 0 && has_child {
        return None;
    }
    Some(Node::clean(height, entries, Some(c)))
}

/// The generic decoder: the oracle for [`decode_node_fast`] and the source
/// of [`decode_node`]'s errors.
#[doc(hidden)]
pub fn decode_node_reference(data: &[u8], c: Cid) -> Result<Node> {
    use cbor::Value;
    let v = Value::decode(data).map_err(|_| MstError::Invalid("bad node cbor"))?;
    let link = |v: Option<&Value>| match v {
        Some(Value::Link(l)) => Ok(Some(*l)),
        Some(Value::Null) => Ok(None),
        _ => Err(MstError::Invalid("bad link")),
    };
    let fields = |v: &Value| match v {
        Value::Map(m) => m.len(),
        _ => 0,
    };
    if fields(&v) != 2 {
        return Err(MstError::Invalid("node must have exactly e and l"));
    }
    let mut entries = Vec::new();
    if let Some(l) = link(v.get("l"))? {
        entries.push(Entry::Child { node: None, cid: Some(l) });
    }
    let Some(Value::Array(es)) = v.get("e") else {
        return Err(MstError::Invalid("bad e"));
    };
    let mut prev: Vec<u8> = Vec::new();
    let mut height = -1;
    for (i, e) in es.iter().enumerate() {
        if fields(e) != 4 {
            return Err(MstError::Invalid("entry must have exactly k, p, t and v"));
        }
        let p = match e.get("p") {
            Some(Value::Int(p)) if *p >= 0 && (*p as usize) <= prev.len() => *p as usize,
            _ => return Err(MstError::Invalid("bad prefix len")),
        };
        let Some(Value::Bytes(k)) = e.get("k") else {
            return Err(MstError::Invalid("bad k"));
        };
        let Some(Value::Link(val)) = e.get("v") else {
            return Err(MstError::Invalid("bad v"));
        };
        let t = link(e.get("t"))?;
        let mut key = prev[..p].to_vec();
        key.extend_from_slice(k);
        if !valid_key(&key) {
            return Err(MstError::InvalidKey);
        }
        if i > 0 && key <= prev {
            return Err(MstError::Invalid("keys not in ascending order"));
        }
        // canonical prefix compression; for the first entry prev is empty, so p == 0
        if count_prefix_len(&prev, &key) != p {
            return Err(MstError::Invalid("non-canonical prefix len"));
        }
        let h = height_for_key(&key);
        if height < 0 {
            height = h;
        } else if h != height {
            return Err(MstError::Invalid("keys of different heights in one node"));
        }
        entries.push(Entry::Value { key: key.clone().into(), val: *val });
        prev = key;
        if let Some(t) = t {
            entries.push(Entry::Child { node: None, cid: Some(t) });
        }
    }
    if height == 0 && entries.iter().any(Entry::is_child) {
        return Err(MstError::Invalid("child of a height-0 node"));
    }
    Ok(Node::clean(height, entries, Some(c)))
}

/// One load of a (possibly partial) tree from an untrusted block set.
///
/// A block set is a DAG, not a tree: expanding every link of a node that
/// links one child many times materializes an exponential tree from a few
/// KB. A valid MST never repeats a node (it would repeat its keys), so a
/// node reached twice is rejected, and every node's keys must fall strictly
/// between its parent's separators (else lookups by key order would miss
/// them). Load work and memory are linear in the input.
struct Loader<'a, B, S> {
    blocks: &'a HashMap<Cid, B, S>,
    seen: std::collections::HashSet<Cid>,
    /// Only the nodes on the key-order path to this key (proofs).
    path: Option<&'a [u8]>,
}

impl<B: AsRef<[u8]>, S: std::hash::BuildHasher> Loader<'_, B, S> {
    /// The subtree at `c`, whose keys must lie strictly between `lo` and
    /// `hi`. Children missing from `blocks` or off `path` stay unloaded. A
    /// node without keys takes its height from its child.
    fn load(
        &mut self,
        c: Cid,
        depth: usize,
        lo: Option<&Arc<[u8]>>,
        hi: Option<&Arc<[u8]>>,
    ) -> Result<Option<Arc<Node>>> {
        if depth >= MAX_DEPTH {
            return Err(MstError::Invalid("tree too deep"));
        }
        let Some(data) = self.blocks.get(&c) else {
            return Ok(None);
        };
        if !self.seen.insert(c) {
            return Err(MstError::Invalid("node appears more than once"));
        }
        let mut n = decode_node(data.as_ref(), c)?;
        if depth > 0 && n.entries.is_empty() {
            return Err(MstError::Invalid("empty child node"));
        }
        let first = n.entries.iter().find_map(Entry::key);
        let last = n.entries.iter().rev().find_map(Entry::key);
        if first.zip(lo).is_some_and(|(k, lo)| k <= &lo[..]) || last.zip(hi).is_some_and(|(k, hi)| k >= &hi[..]) {
            return Err(MstError::Invalid("node key outside its parent's range"));
        }
        let value_key = |e: Option<&Entry>| match e {
            Some(Entry::Value { key, .. }) => Some(key.clone()),
            _ => None,
        };
        for i in 0..n.entries.len() {
            let Entry::Child { cid: Some(cc), .. } = n.entries[i] else {
                continue;
            };
            // decode_node never puts two children side by side
            let clo = i.checked_sub(1).and_then(|j| value_key(n.entries.get(j))).or_else(|| lo.cloned());
            let chi = value_key(n.entries.get(i + 1)).or_else(|| hi.cloned());
            if let Some(k) = self.path {
                if clo.as_ref().is_some_and(|l| k <= &l[..]) || chi.as_ref().is_some_and(|h| k >= &h[..]) {
                    continue;
                }
            }
            if let Some(child) = self.load(cc, depth + 1, clo.as_ref(), chi.as_ref())? {
                if child.height >= 0 {
                    if n.height < 0 {
                        n.height = child.height + 1;
                    } else if child.height != n.height - 1 {
                        return Err(MstError::Invalid("child height is not parent height - 1"));
                    }
                }
                if let Entry::Child { node, .. } = &mut n.entries[i] {
                    *node = Some(child);
                }
            }
        }
        Ok(Some(Arc::new(n)))
    }
}

/// Pushes known heights down into loaded nodes without keys (whose subtrees
/// had no keys either). Depth is bounded by `load_from_blocks`.
fn ensure_heights(n: &mut Arc<Node>, depth: usize) -> Result<()> {
    debug_assert!(depth <= MAX_DEPTH);
    if n.height < 0 {
        return Ok(());
    }
    if n.height == 0 {
        // a key-less node pushed down to height 0 cannot have children either
        return match n.entries.iter().any(Entry::is_child) {
            true => Err(MstError::Invalid("child of a height-0 node")),
            false => Ok(()),
        };
    }
    let h = n.height;
    let nm = Arc::make_mut(n);
    for e in nm.entries.iter_mut() {
        if let Entry::Child { node: Some(c), .. } = e {
            if c.height < 0 {
                Arc::make_mut(c).height = h - 1;
            }
            ensure_heights(c, depth + 1)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Tree {
    pub root: Arc<Node>,
    /// Grown from [`Tree::new`] by inserts and removes alone, so a mutation
    /// can only fail on a bug: such trees mutate in place. Trees loaded from
    /// blocks expect `Partial` and structure errors and keep the old root to
    /// restore on error.
    built: bool,
    /// Mutate in place like a built tree, poisoning on error: for a caller
    /// that drops the tree at the first error (a verifier).
    no_rollback: bool,
}

/// What `self.root` holds while a mutation owns the real root.
fn placeholder() -> Arc<Node> {
    static P: std::sync::OnceLock<Arc<Node>> = std::sync::OnceLock::new();
    P.get_or_init(|| Arc::new(Node::empty(0))).clone()
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new()
    }
}

impl Tree {
    pub fn new() -> Tree {
        Tree { root: Arc::new(Node::empty(0)), built: true, no_rollback: false }
    }

    /// Runs a mutation that consumes the root. A built tree hands over its
    /// only reference, so copy-on-write copies nothing (a second reference
    /// kept to restore on error would copy every node on the path). If a
    /// built tree's mutation fails anyway, the tree is poisoned: its root
    /// becomes a stub, so every later read or write fails rather than report
    /// a half-applied tree's root.
    fn mutate<T>(&mut self, root: Arc<Node>, f: impl FnOnce(Arc<Node>) -> Result<(Arc<Node>, T)>) -> Result<T> {
        if self.built || self.no_rollback {
            return match f(root) {
                Ok((r, x)) => {
                    self.root = r;
                    Ok(x)
                }
                Err(e) => {
                    self.root = Arc::new(Node::stub(0, None));
                    self.built = false;
                    Err(e)
                }
            };
        }
        match f(root.clone()) {
            Ok((r, x)) => {
                self.root = r;
                Ok(x)
            }
            Err(e) => {
                self.root = root;
                Err(e)
            }
        }
    }

    /// Returns the previous value. Marks proof nodes.
    pub fn insert(&mut self, key: &[u8], val: Cid) -> Result<Option<Cid>> {
        self.insert_inner(key, val, true)
    }

    /// Without proof marking (bulk loads).
    pub fn insert_no_proof(&mut self, key: &[u8], val: Cid) -> Result<Option<Cid>> {
        self.insert_inner(key, val, false)
    }

    fn insert_inner(&mut self, key: &[u8], val: Cid, prove: bool) -> Result<Option<Cid>> {
        if !valid_key(key) {
            return Err(MstError::InvalidKey);
        }
        let height = height_for_key(key);
        let root = std::mem::replace(&mut self.root, placeholder());
        // an emptied tree can be left with a non-zero height: restart it at
        // the key's to keep the shape canonical
        let root =
            if root.is_empty() && !root.stub && root.height != height { Arc::new(Node::empty(height)) } else { root };
        self.mutate(root, |r| insert(r, key, val, height, prove))
    }

    pub fn remove(&mut self, key: &[u8]) -> Result<Option<Cid>> {
        self.remove_inner(key, true)
    }

    /// Mutations stop keeping the old root to restore on error (which makes
    /// every one copy the nodes on its path); after an error the tree is
    /// poisoned instead.
    pub fn without_rollback(mut self) -> Tree {
        self.no_rollback = true;
        self
    }

    /// Without proof marking: a verifier undoing ops only wants the new
    /// root, and marked neighbours would be re-encoded and re-hashed for it.
    pub fn remove_no_proof(&mut self, key: &[u8]) -> Result<Option<Cid>> {
        self.remove_inner(key, false)
    }

    fn remove_inner(&mut self, key: &[u8], prove: bool) -> Result<Option<Cid>> {
        if !valid_key(key) {
            return Err(MstError::InvalidKey);
        }
        if self.root.get(key, height_for_key(key))?.is_none() {
            return Ok(None);
        }
        let root = std::mem::replace(&mut self.root, placeholder());
        self.mutate(root, |r| remove(r, key, None, prove))
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Cid>> {
        if !valid_key(key) {
            return Err(MstError::InvalidKey);
        }
        self.root.get(key, height_for_key(key))
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// Clears dirty flags without collecting blocks.
    pub fn root_cid(&mut self) -> Result<Cid> {
        if self.root.stub && !self.root.dirty {
            if let Some(c) = self.root.cid {
                return Ok(c);
            }
        }
        write_blocks(&mut self.root, &mut None, &mut None, 0)
    }

    /// Emits every dirty block (new nodes + proof nodes).
    pub fn write_diff_blocks(&mut self, out: &mut Vec<(Cid, Vec<u8>)>) -> Result<Cid> {
        write_blocks(&mut self.root, &mut Some(out), &mut None, 0)
    }

    /// [`Tree::write_diff_blocks`], also reporting where each emitted node
    /// sits (for [`NodeIndex::advance`]).
    pub fn write_diff_blocks_with_refs(
        &mut self,
        out: &mut Vec<(Cid, Vec<u8>)>,
        refs: &mut Vec<(Cid, NodeRef)>,
    ) -> Result<Cid> {
        write_blocks(&mut self.root, &mut Some(out), &mut Some(refs), 0)
    }

    /// The oracle for [`NodeIndex`]; an empty root has no key and is left out.
    #[cfg(test)]
    pub fn node_refs(&self, out: &mut HashMap<Cid, NodeRef>) -> Result<()> {
        fn rec(n: &Node, out: &mut HashMap<Cid, NodeRef>, depth: usize) -> Result<()> {
            if depth > MAX_DEPTH {
                return Err(MstError::Invalid("tree too deep"));
            }
            let c = n.cid.ok_or(MstError::Invalid("unwritten node"))?;
            if let Some(k) = n.subtree_key() {
                out.insert(c, (k.clone(), n.height));
            }
            for e in &n.entries {
                if let Entry::Child { node: Some(c), .. } = e {
                    rec(c, out, depth + 1)?;
                }
            }
            Ok(())
        }
        rec(&self.root, out, 0)
    }

    /// A (possibly partial) tree. Linear in the input (see [`Loader`]).
    pub fn load_from_blocks<B: AsRef<[u8]>, S: std::hash::BuildHasher>(
        blocks: &HashMap<Cid, B, S>,
        root: Cid,
    ) -> Result<Tree> {
        Self::load_with(blocks, root, None)
    }

    /// Only the nodes on the key-order path to `key`: enough for
    /// [`Tree::get`] of `key` without decoding the rest of an untrusted
    /// block set.
    pub fn load_path_from_blocks<B: AsRef<[u8]>, S: std::hash::BuildHasher>(
        blocks: &HashMap<Cid, B, S>,
        root: Cid,
        key: &[u8],
    ) -> Result<Tree> {
        Self::load_with(blocks, root, Some(key))
    }

    fn load_with<B: AsRef<[u8]>, S: std::hash::BuildHasher>(
        blocks: &HashMap<Cid, B, S>,
        root: Cid,
        path: Option<&[u8]>,
    ) -> Result<Tree> {
        let mut l = Loader { blocks, seen: Default::default(), path };
        let mut r = l.load(root, 0, None, None)?.ok_or(MstError::Partial)?;
        ensure_heights(&mut r, 0)?;
        Ok(Tree { root: r, built: false, no_rollback: false })
    }

    pub fn walk(&self, f: &mut dyn FnMut(&[u8], Cid)) {
        fn rec(n: &Node, f: &mut dyn FnMut(&[u8], Cid), depth: usize) {
            // loaded trees are bounded by load_from_blocks, built ones by key heights
            debug_assert!(depth <= MAX_DEPTH);
            for e in &n.entries {
                match e {
                    Entry::Value { key, val } => f(key, *val),
                    Entry::Child { node: Some(c), .. } => rec(c, f, depth + 1),
                    _ => {}
                }
            }
        }
        rec(&self.root, f, 0)
    }

    /// The tree must be fully written (no dirty nodes).
    pub fn walk_blocks(&self, f: &mut dyn FnMut(Cid, &[u8])) -> Result<()> {
        fn rec(n: &Node, buf: &mut Vec<u8>, f: &mut dyn FnMut(Cid, &[u8]), depth: usize) -> Result<()> {
            if depth > MAX_DEPTH {
                return Err(MstError::Invalid("tree too deep"));
            }
            let c = n.cid.ok_or(MstError::Invalid("unwritten node"))?;
            match &n.bytes {
                Some(b) if !n.dirty => f(c, b),
                _ => {
                    buf.clear();
                    encode_node(n, buf)?;
                    f(c, buf);
                }
            }
            for e in &n.entries {
                if let Entry::Child { node: Some(c), .. } = e {
                    rec(c, buf, f, depth + 1)?;
                }
            }
            Ok(())
        }
        let mut buf = Vec::with_capacity(1024);
        rec(&self.root, &mut buf, f, 0)
    }

    /// `index` must cover this tree's version for a None to be final.
    #[cfg(test)]
    pub fn find_node(&self, cid: &Cid, index: &NodeIndex) -> Result<Option<Vec<u8>>> {
        if self.root.cid == Some(*cid) {
            return Ok(Some(self.root.block()?.into_owned()));
        }
        match index.get(cid) {
            Some((key, height)) => self.node_block(cid, key, *height),
            None => Ok(None),
        }
    }

    /// The node at `height` on the path to `key`, if its CID is `cid`.
    #[cfg(test)]
    pub fn node_block(&self, cid: &Cid, key: &[u8], height: i32) -> Result<Option<Vec<u8>>> {
        let mut n: &Node = &self.root;
        loop {
            if n.height <= height {
                return match n.height == height && n.cid == Some(*cid) {
                    true => Ok(Some(n.block()?.into_owned())),
                    false => Ok(None),
                };
            }
            match n.find_existing_child(key).map(|i| &n.entries[i]) {
                Some(Entry::Child { node: Some(c), .. }) => n = c,
                _ => return Ok(None),
            }
        }
    }

    /// The tree must be written.
    pub fn root_block(&self) -> Result<(Cid, Vec<u8>)> {
        Ok((self.root.cid.ok_or(MstError::Invalid("unwritten node"))?, self.root.block()?.into_owned()))
    }

    /// Inclusion or exclusion proof. Like the reference's `cidsForPath`, the
    /// path follows key order to the node holding `key` or to the bottom:
    /// verifiers search by key order alone, so an absent key's proof must
    /// reach the lowest node it would sort into, even below its own height.
    pub fn proof_blocks(&self, key: &[u8]) -> Result<Vec<(Cid, Vec<u8>)>> {
        let mut out = Vec::new();
        let mut n: &Node = &self.root;
        loop {
            out.push((n.cid.ok_or(MstError::Invalid("unwritten node"))?, n.block()?.into_owned()));
            if n.find_existing_entry(key).is_some() {
                return Ok(out);
            }
            match n.find_existing_child(key) {
                Some(idx) => match &n.entries[idx] {
                    Entry::Child { node: Some(c), .. } => n = c,
                    _ => return Err(MstError::Partial),
                },
                None => return Ok(out),
            }
        }
    }
}

/// Where a node sits: a key in its subtree and its height. The node is the
/// one at that height on the path from the root to the key.
pub type NodeRef = (Arc<[u8]>, i32);

/// Node CID -> [`NodeRef`] for one repo, so getBlocks finds nodes in
/// O(depth). Advanced by each commit's written nodes, it only grows, so it
/// covers every version in `from..=to` (revs) and a miss for one of those is
/// final. Entries of replaced nodes linger until a rebuild; lookups check
/// the CID against the tree they read.
pub struct NodeIndex {
    map: HashMap<Cid, NodeRef>,
    pub from: u64,
    pub to: u64,
    /// Nodes at the last build: rebuild once stale entries outnumber them.
    live: usize,
}

impl NodeIndex {
    #[cfg(test)]
    pub fn build(tree: &Tree, rev: u64) -> Result<NodeIndex> {
        let mut map = HashMap::new();
        tree.node_refs(&mut map)?;
        let live = map.len();
        Ok(NodeIndex { map, from: rev, to: rev, live })
    }

    pub fn from_refs(map: HashMap<Cid, NodeRef>, rev: u64) -> NodeIndex {
        let live = map.len();
        NodeIndex { map, from: rev, to: rev, live }
    }

    pub fn covers(&self, rev: u64) -> bool {
        (self.from..=self.to).contains(&rev)
    }

    pub fn get(&self, cid: &Cid) -> Option<&NodeRef> {
        self.map.get(cid)
    }

    /// False (unchanged) if the index doesn't end at `prev`.
    pub fn advance(&mut self, prev: u64, rev: u64, written: &[(Cid, NodeRef)]) -> bool {
        if self.to != prev || rev < prev {
            return false;
        }
        self.map.extend(written.iter().cloned());
        self.to = rev;
        true
    }

    /// Mostly stale entries: drop and rebuild on the next miss.
    fn bloated(&self) -> bool {
        self.map.len() > 2 * self.live + 4096
    }
}

/// Shared by the repo worker (which advances it per commit once anyone has
/// asked for it) and getBlocks (which builds it).
#[derive(Default)]
pub struct NodeIndexCell {
    pub index: Option<NodeIndex>,
    /// Set by the first getBlocks that needed node blocks.
    pub wanted: bool,
    /// The latest commits' written nodes (prev rev, rev, refs) while there
    /// is no index to advance, so a build from an older view can catch up.
    pub recent: std::collections::VecDeque<(u64, u64, Vec<(Cid, NodeRef)>)>,
}

const RECENT_COMMITS: usize = 64;

impl NodeIndexCell {
    pub fn commit(&mut self, prev: u64, rev: u64, written: Vec<(Cid, NodeRef)>) {
        if let Some(ix) = &mut self.index {
            if ix.advance(prev, rev, &written) && !ix.bloated() {
                return;
            }
            self.index = None;
        }
        if self.recent.len() >= RECENT_COMMITS {
            self.recent.pop_front();
        }
        self.recent.push_back((prev, rev, written));
    }

    /// Catches `ix` up with the commits recorded since; keeps the current
    /// index if it reaches further.
    pub fn install(&mut self, mut ix: NodeIndex) {
        for (prev, rev, written) in &self.recent {
            ix.advance(*prev, *rev, written);
        }
        if self.index.as_ref().is_none_or(|cur| cur.to < ix.to) {
            self.recent.clear();
            self.index = Some(ix);
        }
    }
}

pub type SharedNodeIndex = Arc<parking_lot::Mutex<NodeIndexCell>>;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{seq::SliceRandom, Rng, SeedableRng};
    use std::collections::BTreeMap;

    fn leaf() -> Cid {
        Cid::parse("bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454").unwrap()
    }

    #[test]
    fn empty_tree_cid() {
        let mut t = Tree::new();
        assert_eq!(t.root_cid().unwrap().to_string(), "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    }

    #[test]
    fn known_heights() {
        // from the atproto MST interop tests
        assert_eq!(height_for_key(b""), 0);
        assert_eq!(height_for_key(b"asdf"), 0);
        assert_eq!(height_for_key(b"blue"), 1);
        assert_eq!(height_for_key(b"2653ae71"), 0);
        assert_eq!(height_for_key(b"88bfafc7"), 2);
        assert_eq!(height_for_key(b"2a92d355"), 4);
        assert_eq!(height_for_key(b"884976f5"), 6);
        assert_eq!(height_for_key(b"app.bsky.feed.post/454397e440ec"), 4);
        assert_eq!(height_for_key(b"app.bsky.feed.post/9adeb165882c"), 8);
    }

    #[derive(serde::Deserialize)]
    struct Fixture {
        comment: String,
        #[serde(rename = "leafValue")]
        leaf_value: String,
        keys: Vec<String>,
        adds: Vec<String>,
        dels: Vec<String>,
        #[serde(rename = "rootBeforeCommit")]
        root_before: String,
        #[serde(rename = "rootAfterCommit")]
        root_after: String,
        #[serde(rename = "blocksInProof")]
        blocks_in_proof: Vec<String>,
    }

    /// The atproto commit-proof interop fixtures (copied from indigo).
    #[test]
    fn commit_proof_fixtures() {
        let raw = include_str!("../testdata/commit-proof-fixtures.json");
        let fixtures: Vec<Fixture> = serde_json::from_str(raw).unwrap();
        for f in fixtures {
            let v = Cid::parse(&f.leaf_value).unwrap();
            let mut t = Tree::new();
            for k in &f.keys {
                t.insert_no_proof(k.as_bytes(), v).unwrap();
            }
            assert_eq!(t.root_cid().unwrap().to_string(), f.root_before, "{}", f.comment);
            for k in &f.adds {
                t.insert(k.as_bytes(), v).unwrap();
            }
            for k in &f.dels {
                assert_eq!(t.remove(k.as_bytes()).unwrap(), Some(v));
            }
            let mut blocks = Vec::new();
            let root = t.write_diff_blocks(&mut blocks).unwrap();
            assert_eq!(root.to_string(), f.root_after, "{}", f.comment);
            let map: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
            for b in &f.blocks_in_proof {
                assert!(map.contains_key(&Cid::parse(b).unwrap()), "{}: missing proof block {b}", f.comment);
            }
            // invert using only the diff blocks
            let mut inv = Tree::load_from_blocks(&map, root).unwrap();
            for k in &f.adds {
                assert_eq!(inv.remove(k.as_bytes()).unwrap(), Some(v), "{}", f.comment);
            }
            for k in &f.dels {
                assert_eq!(inv.insert(k.as_bytes(), v).unwrap(), None, "{}", f.comment);
            }
            assert_eq!(inv.root_cid().unwrap().to_string(), f.root_before, "{}", f.comment);
        }
    }

    fn rand_key(rng: &mut impl Rng) -> String {
        let colls = ["app.bsky.feed.post", "app.bsky.feed.like", "app.bsky.graph.follow"];
        format!(
            "{}/{}",
            colls[rng.gen_range(0..3)],
            crate::tid::Tid::from_parts(rng.gen::<u64>() >> 11, rng.gen_range(0..1024))
        )
    }

    fn rand_cid(rng: &mut impl Rng) -> Cid {
        Cid::dag_cbor(&rng.gen::<[u8; 16]>())
    }

    /// The MST is a function of its contents: any history must yield the same
    /// root as building the final map from scratch, and every commit's diff
    /// blocks alone must be enough to invert it (sync 1.1).
    #[test]
    fn random_history_canonical_and_invertible() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for round in 0..40 {
            let mut t = Tree::new();
            let mut model: BTreeMap<String, Cid> = BTreeMap::new();
            let n0 = rng.gen_range(0..300);
            for _ in 0..n0 {
                let k = rand_key(&mut rng);
                let v = rand_cid(&mut rng);
                t.insert_no_proof(k.as_bytes(), v).unwrap();
                model.insert(k, v);
            }
            let mut prev_root = t.root_cid().unwrap();
            for _ in 0..30 {
                // a multi-op commit
                let nops = rng.gen_range(1..8);
                let mut ops: Vec<(String, Option<Cid>, Option<Cid>)> = Vec::new(); // path, new, prev
                for _ in 0..nops {
                    let roll = rng.gen_range(0..10);
                    let existing: Vec<String> = model.keys().cloned().collect();
                    let (k, newv) = if roll < 5 || existing.is_empty() {
                        (rand_key(&mut rng), Some(rand_cid(&mut rng)))
                    } else if roll < 7 {
                        (existing.choose(&mut rng).unwrap().clone(), Some(rand_cid(&mut rng)))
                    } else {
                        (existing.choose(&mut rng).unwrap().clone(), None)
                    };
                    if ops.iter().any(|o| o.0 == k) {
                        continue;
                    }
                    let prev = match newv {
                        Some(v) => {
                            model.insert(k.clone(), v);
                            t.insert(k.as_bytes(), v).unwrap()
                        }
                        None => {
                            model.remove(&k);
                            t.remove(k.as_bytes()).unwrap()
                        }
                    };
                    ops.push((k, newv, prev));
                }
                let mut blocks = Vec::new();
                let root = t.write_diff_blocks(&mut blocks).unwrap();
                let map: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
                let mut inv = Tree::load_from_blocks(&map, root).unwrap();
                // invert in a different order than applied: deletes first, then by path
                let mut sorted = ops.clone();
                sorted.sort_by(|a, b| (a.1.is_some(), &a.0).cmp(&(b.1.is_some(), &b.0)));
                for (k, newv, prev) in &sorted {
                    match (newv, prev) {
                        (Some(_), None) => {
                            inv.remove(k.as_bytes()).unwrap();
                        }
                        (_, Some(p)) => {
                            inv.insert(k.as_bytes(), *p).unwrap();
                        }
                        (None, None) => unreachable!(),
                    }
                }
                assert_eq!(inv.root_cid().unwrap(), prev_root, "round {round}: inversion failed");
                prev_root = root;
            }
            let mut fresh = Tree::new();
            let mut entries: Vec<_> = model.iter().collect();
            entries.shuffle(&mut rng);
            for (k, v) in entries {
                fresh.insert_no_proof(k.as_bytes(), *v).unwrap();
            }
            assert_eq!(fresh.root_cid().unwrap(), prev_root, "round {round}: not canonical");
            let mut walked = Vec::new();
            t.walk(&mut |k, v| walked.push((String::from_utf8(k.to_vec()).unwrap(), v)));
            assert_eq!(walked, model.into_iter().collect::<Vec<_>>());
        }
    }

    fn rss_mb() -> f64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().unwrap_or(0.0) / 1024.0
    }

    /// Build, commit-shaped insert/delete (snapshot clone + insert + diff
    /// blocks per op, as the repo worker does), getRepo walk and proofs on
    /// an n-key tree.
    fn tree_bench(entries: &[(String, Cid)], fresh: &[(String, Cid)], probes: &[&(String, Cid)]) -> Tree {
        use std::time::Instant;
        let rss0 = rss_mb();
        let t = Instant::now();
        let mut tree = Tree::new();
        for (k, v) in entries {
            tree.insert_no_proof(k.as_bytes(), *v).unwrap();
        }
        let build = t.elapsed();
        let t = Instant::now();
        tree.root_cid().unwrap();
        let rc = t.elapsed();
        let rss = rss_mb() - rss0;
        let mut snap = tree.clone();
        let t = Instant::now();
        for (k, v) in fresh {
            tree.insert(k.as_bytes(), *v).unwrap();
            let mut out = Vec::new();
            tree.write_diff_blocks(&mut out).unwrap();
            snap = tree.clone();
        }
        let ins = t.elapsed();
        let t = Instant::now();
        for (k, _) in fresh {
            tree.remove(k.as_bytes()).unwrap();
            let mut out = Vec::new();
            tree.write_diff_blocks(&mut out).unwrap();
            snap = tree.clone();
        }
        let del = t.elapsed();
        drop(snap);
        let t = Instant::now();
        let mut bytes = 0usize;
        tree.walk_blocks(&mut |_, b| bytes += b.len()).unwrap();
        let walk = t.elapsed();
        let t = Instant::now();
        let mut pb = 0;
        for (k, _) in probes {
            pb += tree.proof_blocks(k.as_bytes()).unwrap().len();
        }
        let proof = t.elapsed().as_secs_f64() * 1e6 / probes.len() as f64;
        let ops = fresh.len() as f64;
        println!(
            "build {:.2}s + root {:?} (rss +{:.0} MB) | commit ops: insert {:.0}/s delete {:.0}/s | getRepo walk {:.1} MB {:?} | proof {:.2} us ({pb})",
            build.as_secs_f64(), rc, rss, ops / ins.as_secs_f64(), ops / del.as_secs_f64(),
            bytes as f64 / 1e6, walk, proof
        );
        tree
    }

    /// Plus node-index build and getBlocks node lookups. Run alone (RSS):
    /// `cargo test --profile dev-release --lib mst::tests::bench_mst -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn bench_mst() {
        use std::time::Instant;
        let n: usize = std::env::var("MST_BENCH_N").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let entries: Vec<(String, Cid)> = (0..n).map(|_| (rand_key(&mut rng), rand_cid(&mut rng))).collect();
        let fresh: Vec<(String, Cid)> = (0..20_000).map(|_| (rand_key(&mut rng), rand_cid(&mut rng))).collect();
        let probes: Vec<&(String, Cid)> = (0..10_000).map(|_| &entries[rng.gen_range(0..n)]).collect();
        let tree = tree_bench(&entries, &fresh, &probes);
        let t = Instant::now();
        let ix = NodeIndex::build(&tree, 1).unwrap();
        println!("node index build: {:?} ({} nodes)", t.elapsed(), ix.map.len());
        let mut node_cids = Vec::new();
        tree.walk_blocks(&mut |c, _| node_cids.push(c)).unwrap();
        let t = Instant::now();
        for i in 0..10_000 {
            let c = node_cids[(i * 7919) % node_cids.len()];
            assert!(tree.find_node(&c, &ix).unwrap().is_some());
        }
        println!("getBlocks node lookup: {:.2} us/cid", t.elapsed().as_secs_f64() * 1e6 / 10_000.0);
    }

    /// Every node's cached block is its fresh encoding and hashes to its
    /// CID, through random inserts/removes with snapshots held (copy on
    /// write) and proof marking (cached blocks reused).
    fn assert_blocks_fresh(t: &Tree) {
        fn rec(n: &Node) {
            let mut fresh = Vec::new();
            encode_node(n, &mut fresh).unwrap();
            assert_eq!(n.block().unwrap().as_ref(), &fresh[..]);
            assert_eq!(Some(Cid::dag_cbor(&fresh)), n.cid);
            for e in &n.entries {
                if let Entry::Child { node: Some(c), cid } = e {
                    assert_eq!(*cid, c.cid);
                    rec(c);
                }
            }
        }
        rec(&t.root);
    }

    /// The node index, advanced commit by commit, finds every node of every
    /// version it covers (and nothing else), in that version's tree.
    #[test]
    fn node_index_tracks_commits() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(21);
        let mut t = Tree::new();
        let mut model: Vec<String> = Vec::new();
        for _ in 0..500 {
            let k = rand_key(&mut rng);
            t.insert_no_proof(k.as_bytes(), rand_cid(&mut rng)).unwrap();
            model.push(k);
        }
        t.root_cid().unwrap();
        let mut ix = NodeIndex::build(&t, 1).unwrap();
        let mut versions: Vec<(u64, Tree)> = vec![(1, t.clone())];
        for rev in 2..120u64 {
            for _ in 0..rng.gen_range(1..6) {
                if rng.gen_bool(0.6) || model.is_empty() {
                    let k = rand_key(&mut rng);
                    t.insert(k.as_bytes(), rand_cid(&mut rng)).unwrap();
                    model.push(k);
                } else if rng.gen_bool(0.5) {
                    let k = model.swap_remove(rng.gen_range(0..model.len()));
                    t.remove(k.as_bytes()).unwrap();
                } else {
                    let k = &model[rng.gen_range(0..model.len())];
                    t.insert(k.as_bytes(), rand_cid(&mut rng)).unwrap();
                }
            }
            let (mut blocks, mut refs) = (Vec::new(), Vec::new());
            let root = t.write_diff_blocks_with_refs(&mut blocks, &mut refs).unwrap();
            assert_eq!(blocks.len(), refs.len() + t.root.first_key().is_none() as usize);
            for (c, b) in &blocks {
                assert_eq!(Cid::dag_cbor(b), *c);
            }
            assert!(ix.advance(rev - 1, rev, &refs));
            assert!(!ix.advance(rev - 1, rev, &refs), "advanced twice");
            assert_eq!(t.root.cid, Some(root));
            assert_blocks_fresh(&t);
            versions.push((rev, t.clone()));
        }
        for (rev, v) in versions.iter().step_by(7) {
            assert!(ix.covers(*rev));
            let mut nodes = Vec::new();
            v.walk_blocks(&mut |c, b| nodes.push((c, b.to_vec()))).unwrap();
            for (c, b) in &nodes {
                assert_eq!(v.find_node(c, &ix).unwrap().as_ref(), Some(b), "rev {rev}");
            }
            // another version's nodes and record CIDs are not this tree's
            let other = &versions[0].1;
            let mut theirs = Vec::new();
            other.walk_blocks(&mut |c, _| theirs.push(c)).unwrap();
            for c in theirs.iter().filter(|c| !nodes.iter().any(|(n, _)| n == *c)) {
                assert_eq!(v.find_node(c, &ix).unwrap(), None);
            }
            assert_eq!(v.find_node(&rand_cid(&mut rng), &ix).unwrap(), None);
        }
        // a cell catches a late build up through its recent commits
        let mut cell = NodeIndexCell { wanted: true, ..Default::default() };
        let base = versions[100].1.clone();
        let mut t2 = base.clone();
        for rev in 101..105u64 {
            t2.insert(rand_key(&mut rng).as_bytes(), rand_cid(&mut rng)).unwrap();
            let (mut blocks, mut refs) = (Vec::new(), Vec::new());
            t2.write_diff_blocks_with_refs(&mut blocks, &mut refs).unwrap();
            cell.commit(rev - 1, rev, refs);
        }
        cell.install(NodeIndex::build(&base, 100).unwrap());
        let ix = cell.index.as_ref().unwrap();
        assert!(ix.covers(100) && ix.covers(104) && !ix.covers(105));
        t2.walk_blocks(&mut |c, b| assert_eq!(t2.find_node(&c, ix).unwrap().as_deref(), Some(b))).unwrap();
        // a commit that doesn't chain drops it
        cell.commit(200, 201, Vec::new());
        assert!(cell.index.is_none());
    }

    #[test]
    fn proof_blocks_follow_key_order_to_the_bottom() {
        // A verifier searches the proof by key order alone (reference
        // cidsForPath / verifyProofs), so an absent key's proof must reach the
        // lowest node it sorts into, not stop at the key's own height.
        let mut rng = rand::rngs::StdRng::seed_from_u64(9);
        let mut t = Tree::new();
        let keys: Vec<String> = (0..400).map(|_| rand_key(&mut rng)).collect();
        for k in &keys {
            t.insert(k.as_bytes(), leaf()).unwrap();
        }
        let root = t.root_cid().unwrap();
        let probes: Vec<String> = keys.iter().take(50).cloned().chain((0..200).map(|_| rand_key(&mut rng))).collect();
        let mut deep_absent = 0;
        for k in &probes {
            let proof: HashMap<Cid, Vec<u8>> = t.proof_blocks(k.as_bytes()).unwrap().into_iter().collect();
            // walk the proof by key order, never by height
            let mut c = root;
            let found = loop {
                let n = decode_node(&proof[&c], c).unwrap();
                if let Some(i) = n.find_existing_entry(k.as_bytes()) {
                    break match &n.entries[i] {
                        Entry::Value { val, .. } => Some(*val),
                        _ => unreachable!(),
                    };
                }
                match n.find_existing_child(k.as_bytes()).map(|i| &n.entries[i]) {
                    Some(Entry::Child { cid: Some(cc), .. }) => c = *cc,
                    _ => break None,
                }
            };
            assert_eq!(found, t.get(k.as_bytes()).unwrap(), "{k}");
            if found.is_none() && proof.len() as i32 > t.root.height - height_for_key(k.as_bytes()) + 1 {
                deep_absent += 1;
            }
        }
        assert!(deep_absent > 0, "no absent key below its own height was probed");
    }

    #[test]
    fn delete_everything_then_reinsert() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let mut t = Tree::new();
        let keys: Vec<String> = (0..200).map(|_| rand_key(&mut rng)).collect();
        for k in &keys {
            t.insert(k.as_bytes(), leaf()).unwrap();
        }
        t.root_cid().unwrap();
        for k in &keys {
            t.remove(k.as_bytes()).unwrap();
        }
        assert_eq!(t.root_cid().unwrap(), Tree::new().root_cid().unwrap());
        t.insert(b"app.bsky.feed.post/aaaa", leaf()).unwrap();
        let mut fresh = Tree::new();
        fresh.insert(b"app.bsky.feed.post/aaaa", leaf()).unwrap();
        assert_eq!(t.root_cid().unwrap(), fresh.root_cid().unwrap());
    }

    /// Raw node bytes: `l`, then entries of (key suffix, prefix len, t).
    fn raw_node(l: Option<Cid>, es: &[(&[u8], u64, Option<Cid>)]) -> Vec<u8> {
        let mut b = Vec::new();
        cbor::write_map_head(&mut b, 2);
        cbor::write_text(&mut b, "e");
        cbor::write_array_head(&mut b, es.len());
        for (k, p, t) in es {
            cbor::write_map_head(&mut b, 4);
            cbor::write_text(&mut b, "k");
            cbor::write_bytes(&mut b, k);
            cbor::write_text(&mut b, "p");
            cbor::write_uint(&mut b, *p);
            cbor::write_text(&mut b, "t");
            cbor::write_opt_cid(&mut b, t.as_ref());
            cbor::write_text(&mut b, "v");
            cbor::write_cid(&mut b, &leaf());
        }
        cbor::write_text(&mut b, "l");
        cbor::write_opt_cid(&mut b, l.as_ref());
        b
    }

    fn add(blocks: &mut HashMap<Cid, Vec<u8>>, b: Vec<u8>) -> Cid {
        let c = Cid::dag_cbor(&b);
        blocks.insert(c, b);
        c
    }

    fn load(blocks: &HashMap<Cid, Vec<u8>>, root: Cid) -> Result<Tree> {
        Tree::load_from_blocks(blocks, root)
    }

    /// A chain of `{e: [], l: child}` nodes used to overflow the stack (and
    /// abort the process) in load_from_blocks; it is an error now, on the
    /// 2 MiB stack of a tokio blocking thread.
    #[test]
    fn deep_chain_rejected_not_overflowed() {
        let mut blocks = HashMap::new();
        let mut c = add(&mut blocks, raw_node(None, &[(b"asdf", 0, None)]));
        let mut depth_ok = None;
        for d in 1..200_000 {
            c = add(&mut blocks, raw_node(Some(c), &[]));
            if d == MAX_DEPTH - 1 {
                depth_ok = Some(c);
            }
        }
        let r = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || {
                let ok = load(&blocks, depth_ok.unwrap()).map(|t| t.root.height);
                (ok, load(&blocks, c).err())
            })
            .unwrap()
            .join()
            .unwrap();
        // MAX_DEPTH levels load (heights inferred upward from the leaf)
        assert_eq!(r.0, Ok(MAX_DEPTH as i32 - 1));
        assert_eq!(r.1, Some(MstError::Invalid("tree too deep")));
    }

    #[test]
    fn heights_must_step_down_by_one() {
        // "blue" has height 1, "88bfafc7" height 2, "asdf"/"2653ae71" height 0
        let mut blocks = HashMap::new();
        let h0 = add(&mut blocks, raw_node(None, &[(b"asdf", 0, None)]));
        let h1 = add(&mut blocks, raw_node(None, &[(b"blue", 0, None)]));
        let good = add(&mut blocks, raw_node(Some(h0), &[(b"blue", 0, None)]));
        assert_eq!(load(&blocks, good).unwrap().get(b"asdf").unwrap(), Some(leaf()));
        // height 2 over height 0, height 1 over height 1
        let skip = add(&mut blocks, raw_node(Some(h0), &[(b"88bfafc7", 0, None)]));
        let same = add(&mut blocks, raw_node(None, &[(b"blue", 0, Some(h1))]));
        // a key-less node over height 0 is height 1; over that, height 2 is fine
        let mid = add(&mut blocks, raw_node(Some(h0), &[]));
        // ("asdf" sorts after "88bfafc7": the subtree hangs to its right)
        let ok2 = add(&mut blocks, raw_node(None, &[(b"88bfafc7", 0, Some(mid))]));
        let bad2 = add(&mut blocks, raw_node(Some(mid), &[(b"blue", 0, None)]));
        for c in [skip, same, bad2] {
            assert!(load(&blocks, c).is_err());
        }
        assert!(load(&blocks, ok2).is_ok());
        // key-less nodes pushed down to height 0 cannot have children: the
        // stub below `mid0` is missing, so its height comes from above
        let stub = add(&mut blocks, raw_node(Some(leaf()), &[]));
        let mid0 = add(&mut blocks, raw_node(Some(stub), &[]));
        let top = add(&mut blocks, raw_node(Some(mid0), &[(b"blue", 0, None)]));
        assert_eq!(load(&blocks, top).err(), Some(MstError::Invalid("child of a height-0 node")));
        // empty non-root nodes don't exist in a canonical tree
        let empty = add(&mut blocks, raw_node(None, &[]));
        let over_empty = add(&mut blocks, raw_node(Some(empty), &[(b"blue", 0, None)]));
        assert!(load(&blocks, over_empty).is_err());
        assert!(load(&blocks, empty).unwrap().is_empty());
    }

    /// A block set where every level links one child block `fan + 1` times
    /// used to expand to (fan + 1)^levels nodes (fan 40, 4 levels: ~116M
    /// entries from 17.7 KB). A repeated node is rejected now, fast.
    #[test]
    fn dag_with_shared_children_rejected() {
        let mut blocks = HashMap::new();
        let keys_at = |h: i32, n: usize| -> Vec<Vec<u8>> {
            let mut ks: Vec<Vec<u8>> = (0..)
                .map(|i| format!("com.example.dag/{h}-{i}").into_bytes())
                .filter(|k| height_for_key(k) == h)
                .take(n)
                .collect();
            ks.sort();
            ks
        };
        let node = |child: Option<Cid>, keys: &[Vec<u8>]| {
            let mut n = Node::empty(0);
            if let Some(c) = child {
                n.entries.push(Entry::Child { node: None, cid: Some(c) });
            }
            for k in keys {
                n.entries.push(Entry::Value { key: k.clone().into(), val: leaf() });
                if let Some(c) = child {
                    n.entries.push(Entry::Child { node: None, cid: Some(c) });
                }
            }
            let mut b = Vec::new();
            encode_node(&n, &mut b).unwrap();
            b
        };
        let mut c = add(&mut blocks, node(None, &keys_at(0, 40)));
        for h in 1..=4 {
            c = add(&mut blocks, node(Some(c), &keys_at(h, 40)));
        }
        let leftmost = keys_at(0, 1).remove(0);
        let mut mid = keys_at(1, 1).remove(0);
        mid.push(b'x');
        let t = std::time::Instant::now();
        let full = load(&blocks, c).err();
        let left = Tree::load_path_from_blocks(&blocks, c, &leftmost).map(|t| t.get(&leftmost));
        let right = Tree::load_path_from_blocks(&blocks, c, &mid).err();
        assert!(t.elapsed() < std::time::Duration::from_secs(1), "{:?}", t.elapsed());
        assert_eq!(full, Some(MstError::Invalid("node appears more than once")));
        // a path walk reaches one copy per level: down the left edge it is a
        // consistent path; anywhere else the leaf's keys fall outside the
        // separators that route to it
        assert_eq!(left, Ok(Ok(Some(leaf()))));
        assert_eq!(right, Some(MstError::Invalid("node key outside its parent's range")));
    }

    /// Keys a parent's separators don't route to (a lookup by key order
    /// would never find them) make the tree invalid.
    #[test]
    fn child_keys_outside_separators_rejected() {
        // "blue" has height 1, "asdf"/"2653ae71" height 0; "asdf" > "2653ae71"
        let mut blocks = HashMap::new();
        let low = add(&mut blocks, raw_node(None, &[(b"2653ae71", 0, None)]));
        let high = add(&mut blocks, raw_node(None, &[(b"asdf", 0, None)]));
        let zkey = (0..).map(|i| format!("z{i}").into_bytes()).find(|k| height_for_key(k) == 0).unwrap();
        let late = add(&mut blocks, raw_node(None, &[(&zkey, 0, None)]));
        let both = add(&mut blocks, raw_node(Some(low), &[(b"blue", 0, Some(late))]));
        assert!(load(&blocks, both).is_ok());
        for bad in [
            raw_node(Some(late), &[(b"blue", 0, None)]),
            raw_node(None, &[(b"blue", 0, Some(low))]),
            raw_node(Some(high), &[(b"blue", 0, Some(high))]),
        ] {
            let c = add(&mut blocks, bad);
            assert!(load(&blocks, c).is_err());
        }
    }

    /// A path load answers `get` exactly as a full load, for present and
    /// absent keys, and leaves the rest of the tree unloaded.
    #[test]
    fn path_load_matches_full_load() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let mut t = Tree::new();
        let keys: Vec<String> = (0..500).map(|_| rand_key(&mut rng)).collect();
        for k in &keys {
            t.insert_no_proof(k.as_bytes(), leaf()).unwrap();
        }
        let mut blocks = Vec::new();
        let root = t.write_diff_blocks(&mut blocks).unwrap();
        let blocks: HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
        let full = load(&blocks, root).unwrap();
        let absent: Vec<String> = (0..100).map(|_| rand_key(&mut rng)).collect();
        for k in keys.iter().chain(&absent).chain([&"a".to_string(), &"zzzz".to_string()]) {
            let p = Tree::load_path_from_blocks(&blocks, root, k.as_bytes()).unwrap();
            assert_eq!(p.get(k.as_bytes()).unwrap(), full.get(k.as_bytes()).unwrap(), "{k}");
            let mut n = 0;
            p.walk(&mut |_, _| n += 1);
            assert!(n < keys.len(), "path load loaded the whole tree");
        }
    }

    #[test]
    fn decode_node_structural_checks() {
        let c = leaf();
        let ok = |b: Vec<u8>| decode_node(&b, Cid::dag_cbor(&b));
        // "asdf" < "asdg", both height 0, sharing a 3-byte prefix
        assert!(ok(raw_node(None, &[(b"asdf", 0, None), (b"g", 3, None)])).is_ok());
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("unsorted", raw_node(None, &[(b"asdf", 0, None), (b"2653ae71", 0, None)])),
            ("duplicate", raw_node(None, &[(b"asdf", 0, None), (b"", 4, None)])),
            ("mixed heights", raw_node(None, &[(b"asdf", 0, None), (b"blue", 0, None)])),
            ("first p != 0", raw_node(None, &[(b"asdf", 1, None)])),
            ("prefix not maximal", raw_node(None, &[(b"asdf", 0, None), (b"asdg", 0, None)])),
            ("empty key", raw_node(None, &[(b"", 0, None)])),
            ("height-0 child", raw_node(Some(c), &[(b"asdf", 0, None)])),
            ("height-0 right child", raw_node(None, &[(b"asdf", 0, Some(c))])),
        ];
        for (what, b) in bad {
            assert!(ok(b).is_err(), "{what} accepted");
        }
        use cbor::Value as V;
        let entry = |extra: Option<(&str, V)>, t: Option<V>| {
            let mut m = vec![
                ("k".to_string(), V::Bytes(b"blue".to_vec())),
                ("p".to_string(), V::Int(0)),
                ("v".to_string(), V::Link(c)),
            ];
            if let Some(t) = t {
                m.push(("t".to_string(), t));
            }
            if let Some((k, v)) = extra {
                m.push((k.to_string(), v));
            }
            m.sort_by(|a, b| cbor::key_cmp(&a.0, &b.0));
            V::Map(m)
        };
        let node = |e: V, l: Option<V>, extra: Option<(&str, V)>| {
            let mut m = vec![("e".to_string(), V::Array(vec![e]))];
            if let Some(l) = l {
                m.push(("l".to_string(), l));
            }
            if let Some((k, v)) = extra {
                m.push((k.to_string(), v));
            }
            m.sort_by(|a, b| cbor::key_cmp(&a.0, &b.0));
            V::Map(m).to_cbor()
        };
        assert!(ok(node(entry(None, Some(V::Null)), Some(V::Null), None)).is_ok());
        assert!(ok(node(entry(None, Some(V::Link(c))), Some(V::Link(c)), None)).is_ok());
        let bad = [
            ("missing l", node(entry(None, Some(V::Null)), None, None)),
            ("missing t", node(entry(None, None), Some(V::Null), None)),
            ("unknown node field", node(entry(None, Some(V::Null)), Some(V::Null), Some(("x", V::Null)))),
            ("unknown entry field", node(entry(Some(("x", V::Null)), Some(V::Null)), Some(V::Null), None)),
            ("t not a link", node(entry(None, Some(V::Bytes(c.to_bytes().to_vec()))), Some(V::Null), None)),
            ("t int", node(entry(None, Some(V::Int(0))), Some(V::Null), None)),
            ("l not a link", node(entry(None, Some(V::Null)), Some(V::Text("x".into())), None)),
        ];
        for (what, b) in bad {
            assert!(ok(b).is_err(), "{what} accepted");
        }
    }

    /// Leaves of 1 to dozens of entries (one- and two-byte array heads), the
    /// encoder reused from leaf to leaf.
    #[test]
    fn leaf_encoder_and_trusted_decode_match() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut t = Tree::new();
        for i in 0..3000u32 {
            let k = format!("app.bsky.feed.post/{:013x}", rng.gen::<u64>() >> 12);
            t.insert_no_proof(k.as_bytes(), Cid::dag_cbor(&i.to_be_bytes())).unwrap();
        }
        // a run of keys under one prefix (long, shared prefixes)
        for i in 0..40u32 {
            t.insert_no_proof(format!("z.col/{i:04}").as_bytes(), leaf()).unwrap();
        }
        t.root_cid().unwrap();
        let mut enc = LeafEncoder::default();
        let (mut leaves, mut interior) = (0, 0);
        t.walk_blocks(&mut |c, b| {
            let n = decode_node(b, c).unwrap();
            if n.height == 0 {
                enc.clear();
                for e in &n.entries {
                    let Entry::Value { key, val } = e else { panic!() };
                    enc.push(key, val);
                }
                assert_eq!(enc.finish(), b);
                leaves += 1;
            } else {
                let tn = decode_trusted_node(b, c, n.height).unwrap();
                assert_eq!(tn.height, n.height);
                assert_eq!(format!("{:?}", tn.entries), format!("{:?}", n.entries));
                interior += 1;
            }
        })
        .unwrap();
        assert!(leaves > 500 && interior > 100, "{leaves} leaves, {interior} interior");
        let mut big = LeafEncoder::default();
        let entries: Vec<Entry> =
            (0..30u32).map(|i| Entry::Value { key: Arc::from(format!("a/{i:03}").as_bytes()), val: leaf() }).collect();
        for e in &entries {
            let Entry::Value { key, val } = e else { unreachable!() };
            big.push(key, val);
        }
        let mut want = Vec::new();
        encode_node(&Node::clean(0, entries, None), &mut want).unwrap();
        assert_eq!(big.finish(), &want[..]);
    }
}
