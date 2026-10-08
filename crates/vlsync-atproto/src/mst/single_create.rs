//! A verifier's fast path for the commonest commit, one create: load the
//! partial tree from an untrusted block set, check the key holds the record,
//! and undo the create to get the previous root, without building a [`Tree`].
//!
//! It answers only when [`Tree::load_from_blocks`] + [`Tree::get`] +
//! [`Tree::remove`] + [`Tree::root_cid`] would succeed with the same result:
//! it runs the same checks on every loaded node and, for the removal, covers
//! only the case where no node merges or empties. Anything else (an error,
//! a merge, a key-less node, a mismatch) is `None`, and the caller runs the
//! general path, which also names the error.
//!
//! [`Tree`]: super::Tree
//! [`Tree::load_from_blocks`]: super::Tree::load_from_blocks
//! [`Tree::get`]: super::Tree::get
//! [`Tree::remove`]: super::Tree::remove
//! [`Tree::root_cid`]: super::Tree::root_cid

use super::{encode_entry, height_for_key, valid_key, MAX_DEPTH};
use crate::cbor::{self, Cursor};
use crate::cid::Cid;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::BuildHasher;

const NONE: u32 = u32::MAX;

/// More loaded nodes than this go to the general path, which keeps the
/// linear "seen" scan below cheap. A one-op proof has ~10.
const MAX_NODES: usize = 48;

#[derive(Clone, Copy)]
struct Ent {
    /// A value's key, `keys[key.0..key.0 + key.1]`; unused for a child.
    key: (u32, u32),
    /// The value, or the child's CID.
    cid: Cid,
    /// The loaded child's index in `nodes`, NONE if not loaded; NONE for a
    /// value too, with `is_child` telling them apart.
    child: u32,
    is_child: bool,
}

struct Node {
    cid: Cid,
    height: i32,
    first: u32,
    len: u32,
}

#[derive(Default)]
struct Scratch {
    keys: Vec<u8>,
    ents: Vec<Ent>,
    nodes: Vec<Node>,
    key: Vec<u8>,
    buf: Vec<u8>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// The fast path of a one-create commit's checks. `Some(prev)` means the
/// general path would load the tree, find `val` at `key`, and (with
/// `want_prev`) undo the create to root `prev`; `want_prev == false` stops
/// after the lookup and returns `Some(None)`.
pub fn undo_single_create<B: AsRef<[u8]>, S: BuildHasher>(
    blocks: &HashMap<Cid, B, S>,
    root: Cid,
    key: &[u8],
    val: Cid,
    want_prev: bool,
) -> Option<Option<Cid>> {
    if !valid_key(key) {
        return None;
    }
    SCRATCH.with_borrow_mut(|s| {
        s.keys.clear();
        s.ents.clear();
        s.nodes.clear();
        let mut l = Loader { blocks, s };
        let r = l.load(root, 0, None, None)?;
        let s = l.s;
        if r != NONE {
            s.ensure_heights(r)?;
        }
        s.undo(r, key, val, want_prev)
    })
}

struct Loader<'a, B, S> {
    blocks: &'a HashMap<Cid, B, S>,
    s: &'a mut Scratch,
}

impl<B: AsRef<[u8]>, S: BuildHasher> Loader<'_, B, S> {
    /// [`super::Loader::load`], with `None` for "ask the general path"
    /// and `Some(NONE)` for a child not in the block set.
    fn load(&mut self, c: Cid, depth: usize, lo: Option<(u32, u32)>, hi: Option<(u32, u32)>) -> Option<u32> {
        if depth >= MAX_DEPTH {
            return None;
        }
        let Some(data) = self.blocks.get(&c) else {
            return Some(NONE);
        };
        if self.s.nodes.len() >= MAX_NODES || self.s.nodes.iter().any(|n| n.cid == c) {
            return None;
        }
        let me = self.s.nodes.len() as u32;
        let (first, len, height) = self.s.decode(data.as_ref())?;
        if depth > 0 && len == 0 {
            return None;
        }
        self.s.nodes.push(Node { cid: c, height, first, len });
        let s = &*self.s;
        let range = |i: u32| s.ents[i as usize];
        let fk = (first..first + len).map(range).find(|e| !e.is_child).map(|e| e.key);
        let lk = (first..first + len).rev().map(range).find(|e| !e.is_child).map(|e| e.key);
        if fk.zip(lo).is_some_and(|(k, lo)| s.k(k) <= s.k(lo)) || lk.zip(hi).is_some_and(|(k, hi)| s.k(k) >= s.k(hi)) {
            return None;
        }
        for i in first..first + len {
            let e = self.s.ents[i as usize];
            if !e.is_child {
                continue;
            }
            // decode never puts two children side by side
            let clo = if i > first { Some(self.s.ents[i as usize - 1].key) } else { lo };
            let chi = if i + 1 < first + len { Some(self.s.ents[i as usize + 1].key) } else { hi };
            let child = self.load(e.cid, depth + 1, clo, chi)?;
            if child != NONE {
                let ch = self.s.nodes[child as usize].height;
                if ch >= 0 {
                    // a node without keys takes its height from a child
                    let h = &mut self.s.nodes[me as usize].height;
                    if *h < 0 {
                        *h = ch + 1;
                    } else if ch != *h - 1 {
                        return None;
                    }
                }
                self.s.ents[i as usize].child = child;
            }
        }
        Some(me)
    }
}

impl Scratch {
    fn k(&self, (at, n): (u32, u32)) -> &[u8] {
        &self.keys[at as usize..(at + n) as usize]
    }

    /// [`super::ensure_heights`]: known heights pushed down into nodes
    /// without keys. Depth is bounded by the load.
    fn ensure_heights(&mut self, n: u32) -> Option<()> {
        let Node { height, first, len, .. } = self.nodes[n as usize];
        if height < 0 {
            return Some(());
        }
        if height == 0 {
            return (!(first..first + len).any(|i| self.ents[i as usize].is_child)).then_some(());
        }
        for i in first..first + len {
            let e = self.ents[i as usize];
            if e.is_child && e.child != NONE {
                let c = &mut self.nodes[e.child as usize];
                if c.height < 0 {
                    c.height = height - 1;
                }
                self.ensure_heights(e.child)?;
            }
        }
        Some(())
    }

    /// [`super::decode_node_fast`] into the arenas: (first entry, entry
    /// count, height), the height -1 for a node without keys.
    fn decode(&mut self, data: &[u8]) -> Option<(u32, u32, i32)> {
        let mut r = Cursor::new(data);
        if !r.lit(&[0xa2, 0x61, b'e']) {
            return None;
        }
        let n = r.head(4)?;
        let first = self.ents.len() as u32;
        // the left child goes first, but is read last
        self.ents.push(Ent { key: (0, 0), cid: Cid { codec: 0, digest: [0; 32] }, child: NONE, is_child: true });
        self.key.clear();
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
            if p > self.key.len() as u64 {
                return None;
            }
            let p = p as usize;
            if i > 0 {
                let ok = match self.key.get(p) {
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
            self.key.truncate(p);
            self.key.extend_from_slice(k);
            if !valid_key(&self.key) {
                return None;
            }
            let h = height_for_key(&self.key);
            if height < 0 {
                height = h;
            } else if h != height {
                return None;
            }
            let at = self.keys.len() as u32;
            self.keys.extend_from_slice(&self.key);
            self.ents.push(Ent { key: (at, self.key.len() as u32), cid: val, child: NONE, is_child: false });
            if let Some(t) = t {
                has_child = true;
                self.ents.push(Ent { key: (0, 0), cid: t, child: NONE, is_child: true });
            }
        }
        if !r.lit(&[0x61, b'l']) {
            return None;
        }
        let l = r.opt_link()?;
        if !r.at_end() {
            return None;
        }
        let mut first = first;
        match l {
            Some(l) => {
                has_child = true;
                self.ents[first as usize].cid = l;
            }
            None => first += 1,
        }
        if height == 0 && has_child {
            return None;
        }
        Some((first, self.ents.len() as u32 - first, height))
    }

    fn undo(&mut self, root: u32, key: &[u8], val: Cid, want_prev: bool) -> Option<Option<Cid>> {
        if root == NONE {
            return None;
        }
        let h = height_for_key(key);
        // [`super::Node::get`], keeping the path: (node, child entry) pairs
        let mut path: Vec<(u32, u32)> = Vec::with_capacity(16);
        let mut n = root;
        let idx = loop {
            let node = &self.nodes[n as usize];
            if h > node.height {
                return None;
            }
            let (first, end) = (node.first, node.first + node.len);
            if h == node.height {
                break (first..end).find(|&i| {
                    let e = self.ents[i as usize];
                    !e.is_child && self.k(e.key) == key
                })?;
            }
            let mut idx = None;
            for i in first..end {
                let e = self.ents[i as usize];
                if e.is_child {
                    idx = Some(i);
                } else {
                    if key <= self.k(e.key) {
                        break;
                    }
                    idx = None;
                }
            }
            let i = idx?;
            path.push((n, i));
            n = self.ents[i as usize].child;
            if n == NONE {
                return None;
            }
        };
        if self.ents[idx as usize].cid != val {
            return None;
        }
        if !want_prev {
            return Some(None);
        }
        // [`super::remove`] without a merge, and with the node keeping
        // entries (else the parent drops its pointer)
        let node = &self.nodes[n as usize];
        let (first, end) = (node.first, node.first + node.len);
        let is_child = |i: u32| self.ents[i as usize].is_child;
        if idx > first && idx + 1 < end && is_child(idx - 1) && is_child(idx + 1) {
            return None;
        }
        if node.len == 1 {
            return None;
        }
        if path.is_empty() {
            // the root lost an entry: a root left with one child pointer is
            // replaced by that child, down the chain
            if node.len == 2 {
                let other = if idx == first { first + 1 } else { first };
                let mut e = self.ents[other as usize];
                if e.is_child {
                    loop {
                        if e.child == NONE {
                            return Some(Some(e.cid));
                        }
                        let c = &self.nodes[e.child as usize];
                        if c.len != 1 || !self.ents[c.first as usize].is_child {
                            return Some(Some(c.cid));
                        }
                        e = self.ents[c.first as usize];
                    }
                }
            }
        }
        let mut cid = self.encode(n, idx, None)?;
        while let Some((p, i)) = path.pop() {
            cid = self.encode(p, NONE, Some((i, cid)))?;
        }
        Some(Some(cid))
    }

    /// [`super::encode_node`] of node `n` without entry `skip`, with child
    /// entry `.0` of `replace` pointing at CID `.1`; its CID.
    fn encode(&mut self, n: u32, skip: u32, replace: Option<(u32, Cid)>) -> Option<Cid> {
        let node = &self.nodes[n as usize];
        let (first, end) = (node.first, node.first + node.len);
        let mut out = std::mem::take(&mut self.buf);
        out.clear();
        let child_cid = |i: u32| match replace {
            Some((r, c)) if r == i => c,
            _ => self.ents[i as usize].cid,
        };
        let live = |i: u32| i != skip;
        let mut i = first;
        let mut left = None;
        while i < end && !live(i) {
            i += 1;
        }
        if i < end && self.ents[i as usize].is_child {
            left = Some(child_cid(i));
            i += 1;
        }
        let nvals = (i..end).filter(|&j| live(j) && !self.ents[j as usize].is_child).count();
        out.extend_from_slice(&[0xa2, 0x61, b'e']);
        cbor::write_array_head(&mut out, nvals);
        let mut prev: (u32, u32) = (0, 0);
        let mut ok = true;
        while i < end {
            if !live(i) {
                i += 1;
                continue;
            }
            let e = self.ents[i as usize];
            if e.is_child {
                // two child pointers side by side: encode_node's error
                ok = false;
                break;
            }
            let mut j = i + 1;
            while j < end && !live(j) {
                j += 1;
            }
            let right = if j < end && self.ents[j as usize].is_child {
                let c = child_cid(j);
                i = j + 1;
                Some(c)
            } else {
                i = j;
                None
            };
            encode_entry(&mut out, self.k(prev), self.k(e.key), right.as_ref(), &e.cid);
            prev = e.key;
        }
        out.extend_from_slice(&[0x61, b'l']);
        match left {
            Some(c) => out.extend_from_slice(&cbor::link_bytes(&c)),
            None => out.push(0xf6),
        }
        let c = Cid::dag_cbor(&out);
        self.buf = out;
        ok.then_some(c)
    }
}
