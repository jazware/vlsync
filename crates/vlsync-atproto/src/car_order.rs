//! The streamable CAR block order of the atproto repository spec
//! ("Streamable CAR Block Ordering", still marked work in progress): the
//! commit block first, then the MST in preorder starting at the commit's
//! `data` node. After each node come its slots in the order the node lists
//! them: its `l` subtree, then for each entry its record block followed by
//! its `t` subtree, recursing depth-first into every subtree. Records thus
//! arrive in key order, and a reader verifies the whole repo in one pass
//! holding only the nodes on the path from the root. A record CID under
//! several keys is written at each of them.
//!
//! [`Walk`] is the order for both sides: getRepo writes it and importRepo's
//! fast path (src/xrpc/repo.rs) reads it.

use std::sync::Arc;

use crate::car;
use crate::cid::Cid;
use crate::mst::{self, Entry, Node};

/// The block a stream holds next.
#[derive(Debug, PartialEq)]
pub enum Next {
    /// An MST node: decode it and pass it to [`Walk::enter`].
    Node(Cid),
    Record {
        key: Arc<[u8]>,
        cid: Cid,
    },
    Done,
}

/// Position in the stream order of one MST: the unvisited slots of each
/// node on the path from the root.
pub struct Walk {
    root: Option<Cid>,
    stack: Vec<std::vec::IntoIter<Entry>>,
}

impl Walk {
    pub fn new(root: Cid) -> Walk {
        Walk { root: Some(root), stack: Vec::new() }
    }

    #[allow(clippy::should_implement_trait)] // yields Next, not Option: not an Iterator
    pub fn next(&mut self) -> Next {
        if let Some(r) = self.root.take() {
            return Next::Node(r);
        }
        while let Some(slots) = self.stack.last_mut() {
            match slots.next() {
                Some(Entry::Value { key, val }) => return Next::Record { key, cid: val },
                Some(Entry::Child { cid: Some(c), .. }) => return Next::Node(c),
                // decoded nodes name every child by CID
                Some(Entry::Child { cid: None, .. }) => {}
                None => {
                    self.stack.pop();
                }
            }
        }
        Next::Done
    }

    /// The node [`Walk::next`] just named. Refuses one deeper than
    /// [`mst::MAX_DEPTH`], as loading the tree from blocks does.
    pub fn enter(&mut self, n: Node) -> Result<(), mst::MstError> {
        if self.stack.len() >= mst::MAX_DEPTH {
            return Err(mst::MstError::Invalid("tree too deep"));
        }
        self.stack.push(n.entries.into_iter());
        Ok(())
    }
}

/// A CAR of `commit` over the tree at `data` in stream order, every node and
/// record block taken from `blocks`.
pub fn write_car<B: AsRef<[u8]>>(
    commit: (Cid, &[u8]),
    data: Cid,
    blocks: &std::collections::HashMap<Cid, B>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    car::write_header(&mut out, &commit.0);
    car::write_block(&mut out, &commit.0, commit.1);
    let get = |c: &Cid| blocks.get(c).map(AsRef::as_ref).ok_or_else(|| anyhow::anyhow!("missing block {c}"));
    let mut walk = Walk::new(data);
    loop {
        match walk.next() {
            Next::Node(c) => {
                let b = get(&c)?;
                car::write_block(&mut out, &c, b);
                walk.enter(mst::decode_node(b, c)?)?;
            }
            Next::Record { cid, .. } => car::write_block(&mut out, &cid, get(&cid)?),
            Next::Done => return Ok(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records come in key order, each node before everything under it, and
    /// every block of the tree exactly once.
    #[test]
    fn order_is_preorder_with_records_in_key_order() {
        let mut tree = mst::Tree::new();
        let mut blocks: Vec<(Cid, Vec<u8>)> = Vec::new();
        let keys: Vec<String> = (0..2000).map(|i| format!("com.example.x/{i:05}")).collect();
        for k in &keys {
            let rec = crate::cbor::Value::Text(k.clone()).to_cbor();
            let c = Cid::dag_cbor(&rec);
            tree.insert_no_proof(k.as_bytes(), c).unwrap();
            blocks.push((c, rec));
        }
        let data = tree.write_diff_blocks(&mut blocks).unwrap();
        let n_blocks = blocks.len();
        let map: std::collections::HashMap<Cid, Vec<u8>> = blocks.into_iter().collect();
        let commit = b"\xa0";
        let car = write_car((Cid::dag_cbor(commit), commit), data, &map).unwrap();
        let (_, read) = car::read_car(&car).unwrap();
        assert_eq!(read.len(), n_blocks + 1);
        assert_eq!(read[1].0, data);
        let mut got = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (c, b) in &read[1..] {
            assert!(seen.insert(*c));
            match mst::decode_node(b, *c) {
                Ok(n) => {
                    // every child named here comes later
                    for e in &n.entries {
                        if let Entry::Child { cid: Some(cc), .. } = e {
                            assert!(!seen.contains(cc));
                        }
                    }
                }
                Err(_) => got.push(crate::cbor::Value::decode(b).unwrap()),
            }
        }
        let want: Vec<_> = keys.iter().map(|k| crate::cbor::Value::Text(k.clone())).collect();
        assert_eq!(got, want);
    }
}
