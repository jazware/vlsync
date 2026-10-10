//! The table as one object, `assign/topology`, so a router learns every
//! range's owner and replicas with one GET instead of a LIST and a GET per
//! range.
//!
//! Any node may publish it, at any time, from any view: [`Topology::publish`]
//! merges into what's stored, keeping each range's newest record
//! (by `version`, which every write to a record bumps). A stale publisher
//! can't roll a range back, so publishers need no lease of their own. A
//! router's copy is still only a hint: an owner refuses a request for a
//! range it no longer holds, and the router reads again.

use crate::alive::Alive;
use crate::cas::{self, Expect, Versioned};
use crate::lease::Liveness;
use crate::table::{Assignment, Member};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

pub const REL: &str = "assign/topology";

/// One range as a router sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct RangeView {
    pub epoch: u64,
    pub version: u64,
    pub owner: Option<Member>,
    pub replicas: Vec<Member>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub frozen: bool,
}

impl From<&Assignment> for RangeView {
    fn from(a: &Assignment) -> RangeView {
        RangeView {
            epoch: a.epoch,
            version: a.version,
            owner: a.owner.clone(),
            replicas: a.replicas.clone(),
            frozen: a.frozen.is_some(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Topology {
    /// +1 on every published change.
    pub generation: u64,
    /// By `ShardId::key()`.
    pub ranges: BTreeMap<String, RangeView>,
}

impl Topology {
    pub fn from_table<'a>(it: impl IntoIterator<Item = (ShardId, &'a Assignment)>) -> Topology {
        Topology { generation: 0, ranges: it.into_iter().map(|(s, a)| (s.key(), RangeView::from(a))).collect() }
    }

    pub fn range(&self, shard: ShardId) -> Option<&RangeView> {
        self.ranges.get(&shard.key())
    }

    /// Takes each range's newer view from `other`. True if anything changed.
    pub fn merge(&mut self, other: &Topology) -> bool {
        let mut changed = false;
        for (k, v) in &other.ranges {
            match self.ranges.get(k) {
                Some(cur) if cur.version >= v.version => {}
                _ => {
                    self.ranges.insert(k.clone(), v.clone());
                    changed = true;
                }
            }
        }
        changed
    }

    pub async fn read(store: &Store) -> anyhow::Result<Option<Versioned<Topology>>> {
        cas::read(store, REL).await
    }

    /// Merges this view into the stored one and writes it if that changed
    /// anything. Returns what's stored afterwards.
    pub async fn publish(&self, store: &Store) -> anyhow::Result<Versioned<Topology>> {
        for _ in 0..16 {
            let read = Self::read(store).await?;
            let mut next = read.as_ref().map(|v| v.value.clone()).unwrap_or_default();
            if !next.merge(self) {
                if let Some(r) = read {
                    return Ok(r);
                }
            }
            next.generation += 1;
            match cas::write(store, REL, &next, Expect::from_read(read.as_ref())).await {
                Ok(etag) => return Ok(Versioned { value: next, etag }),
                Err(e) if cas::moved(&e) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("{REL}: still contended after 16 attempts")
    }

    /// Who can serve a read of `shard` that must reflect position `min`:
    /// the owner and replicas that `alive` knows are up and whose published
    /// position for the range (in their lease, or their beats) is at least
    /// `min`, owner first. `min = 0` takes any of them.
    pub fn readable<A: Alive + ?Sized>(&self, shard: ShardId, min: u64, alive: &A) -> Vec<Member> {
        let Some(r) = self.range(shard) else { return Vec::new() };
        let key = shard.key();
        r.owner
            .iter()
            .chain(r.replicas.iter())
            .filter(|m| {
                alive.verdict(&m.node_id, &m.incarnation).is_some_and(|h| h.liveness != Liveness::Dead)
                    && (min == 0 || alive.position(&m.node_id, &m.incarnation, &key).is_some_and(|p| p >= min))
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(version: u64, owner: &str) -> RangeView {
        RangeView {
            epoch: version,
            version,
            owner: Some(Member { node_id: owner.into(), incarnation: "i".into(), addr: String::new() }),
            ..Default::default()
        }
    }

    #[test]
    fn merge_keeps_each_ranges_newest_view() {
        let mut a = Topology::default();
        a.ranges.insert("1".into(), view(3, "a"));
        a.ranges.insert("2".into(), view(1, "a"));
        let mut b = Topology::default();
        b.ranges.insert("1".into(), view(2, "b"));
        b.ranges.insert("2".into(), view(5, "b"));
        b.ranges.insert("3".into(), view(1, "b"));
        assert!(a.merge(&b));
        assert_eq!(a.ranges["1"].owner.as_ref().unwrap().node_id, "a");
        assert_eq!(a.ranges["2"].owner.as_ref().unwrap().node_id, "b");
        assert!(a.ranges.contains_key("3"));
        assert!(!a.merge(&b));
    }

    /// Publishers with stale and fresh views, racing: the stored topology
    /// ends with every range at its newest version.
    #[tokio::test]
    async fn racing_publishers_never_roll_a_range_back() {
        let s = Store::memory(None);
        let tasks: Vec<_> = (0..8u64)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move {
                    for round in 0..10u64 {
                        let mut t = Topology::default();
                        for r in 0..4u64 {
                            // each publisher knows a different version of each range
                            let v = (i * 3 + round * 5 + r) % 23 + 1;
                            t.ranges.insert(ShardId(r as u32).key(), view(v, &format!("n{v}")));
                        }
                        let stored = t.publish(&s).await.unwrap().value;
                        for (k, v) in &t.ranges {
                            assert!(stored.ranges[k].version >= v.version);
                        }
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        let stored = Topology::read(&s).await.unwrap().unwrap().value;
        for r in 0..4u64 {
            let max =
                (0..8u64).flat_map(|i| (0..10u64).map(move |round| (i * 3 + round * 5 + r) % 23 + 1)).max().unwrap();
            assert_eq!(stored.range(ShardId(r as u32)).unwrap().version, max);
        }
    }
}
