//! Fixed hash-slot space. A DID's slot never changes (top 16 bits of
//! sha256(did)); shards own contiguous slot ranges, recorded in a versioned
//! [`Layout`], so shards split and merge online without rehashing any
//! account (DESIGN.md "Online shard split/merge").

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SLOTS: u32 = 65_536;

/// Names one SlateDB (`state/{key}/`), one assignment (`assign/{key}`) and
/// the `shard` tag of log entries. Ids come from [`Layout::next_id`] and are
/// never reused, so a stale clone or a crashed op's leftovers can never be
/// mistaken for a later shard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShardId(pub u32);

impl ShardId {
    /// `u32::MAX` has 10 digits.
    pub const KEY_WIDTH: usize = 10;

    /// Zero-padded so keys LIST in id order.
    pub fn key(self) -> String {
        format!("{:010}", self.0)
    }

    pub fn from_key(s: &str) -> Option<ShardId> {
        (s.len() == Self::KEY_WIDTH && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok().map(ShardId))
            .flatten()
    }

    pub fn next(self) -> Option<ShardId> {
        self.0.checked_add(1).map(ShardId)
    }
}

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::fmt::Debug for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<u32> for ShardId {
    fn from(v: u32) -> ShardId {
        ShardId(v)
    }
}

impl std::str::FromStr for ShardId {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<ShardId, Self::Err> {
        s.parse().map(ShardId)
    }
}

pub fn slot_of(did: &str) -> u16 {
    slot_of_bytes(did.as_bytes())
}

pub fn slot_of_bytes(did: &[u8]) -> u16 {
    let h = Sha256::digest(did);
    u16::from_be_bytes([h[0], h[1]])
}

/// Uniform layout: shard i owns slots [i*65536/n, (i+1)*65536/n).
pub fn shard_of_slot(slot: u16, shards: u32) -> ShardId {
    ShardId((slot as u64 * shards as u64 / SLOTS as u64) as u32)
}

/// Shard of `did` in the initial uniform layout of `shards` (layout v1).
/// Splits and merges change it: route with `PartitionTable::shard_of`.
pub fn shard_of(did: &str, shards: u32) -> ShardId {
    shard_of_slot(slot_of(did), shards)
}

/// One shard of a layout: slots [lo, hi).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardRange {
    pub id: ShardId,
    pub lo: u32,
    pub hi: u32,
}

impl ShardRange {
    pub fn contains(&self, slot: u16) -> bool {
        (self.lo..self.hi).contains(&(slot as u32))
    }
}

/// A split or merge in flight (at most one per cluster).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reshard {
    pub id: u64,
    /// Adjacent shards being replaced, in slot order (1 = split, 2 = merge).
    pub parents: Vec<ShardId>,
    pub children: Vec<ShardRange>,
    /// Node completing it once every parent is frozen.
    pub driver: String,
    /// Fields of a newer feature level, kept across our CAS writes.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Reshard {
    pub fn is_split(&self) -> bool {
        self.parents.len() == 1
    }
}

/// `assign/layout`: contiguous slot ranges covering [0, 65536). `version`
/// grows when routing changes; `op` is a split/merge being prepared.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Layout {
    pub version: u64,
    pub shards: Vec<ShardRange>,
    /// Every id below it has been handed out (to a shard, or to an op's
    /// children whether the op flipped or not). Only grows, by a CAS of this
    /// object, so ids are never reused.
    pub next_id: ShardId,
    pub op_seq: u64,
    pub op: Option<Reshard>,
    /// Fields of a newer feature level, kept across our CAS writes.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Layout {
    /// Version 1: `n` (at most 65,536) uniform ranges with ids 0..n.
    pub fn uniform(n: u32) -> Layout {
        let n = n.clamp(1, SLOTS);
        let shards = (0..n)
            .map(|k| {
                let r = SlotRange::new(k, n).expect("k < n");
                ShardRange { id: ShardId(k), lo: r.lo, hi: r.hi }
            })
            .collect();
        Layout { version: 1, shards, next_id: ShardId(n), op_seq: 0, op: None, extra: Default::default() }
    }

    /// The next `n` unused ids. `with_op` advances `next_id` past them; the
    /// layout's CAS makes that stick exactly once.
    pub fn alloc(&self, n: u32) -> anyhow::Result<Vec<ShardId>> {
        let end = self
            .next_id
            .0
            .checked_add(n)
            .ok_or_else(|| anyhow::anyhow!("shard ids exhausted (next_id {})", self.next_id))?;
        Ok((self.next_id.0..end).map(ShardId).collect())
    }

    fn next_id_after(&self, op: &Reshard) -> ShardId {
        op.children.iter().filter_map(|c| c.id.next()).fold(self.next_id, ShardId::max)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.shards.is_empty(), "empty layout");
        anyhow::ensure!(
            self.shards[0].lo == 0 && self.shards.last().unwrap().hi == SLOTS,
            "layout must cover [0, 65536)"
        );
        for c in self.op.iter().flat_map(|o| &o.children) {
            anyhow::ensure!(c.id < self.next_id, "op child id {} >= next_id {}", c.id, self.next_id);
        }
        let mut ids = std::collections::HashSet::new();
        for w in self.shards.windows(2) {
            anyhow::ensure!(w[0].hi == w[1].lo, "layout ranges not contiguous at {}", w[0].hi);
        }
        for s in &self.shards {
            anyhow::ensure!(s.lo < s.hi, "empty range for shard {}", s.id);
            anyhow::ensure!(s.id < self.next_id, "shard id {} >= next_id {}", s.id, self.next_id);
            anyhow::ensure!(ids.insert(s.id), "duplicate shard id {}", s.id);
        }
        Ok(())
    }

    pub fn index_of_slot(&self, slot: u16) -> usize {
        self.shards.partition_point(|r| r.hi <= slot as u32).min(self.shards.len() - 1)
    }

    pub fn shard_of_slot(&self, slot: u16) -> ShardId {
        self.shards[self.index_of_slot(slot)].id
    }

    /// `key`: a DID or a private routing key.
    pub fn shard_of(&self, key: &str) -> ShardId {
        self.shard_of_slot(slot_of(key))
    }

    pub fn range_of(&self, id: ShardId) -> Option<ShardRange> {
        self.shards.iter().find(|r| r.id == id).copied()
    }

    pub fn contains(&self, id: ShardId) -> bool {
        self.shards.iter().any(|r| r.id == id)
    }

    pub fn ids(&self) -> Vec<ShardId> {
        self.shards.iter().map(|r| r.id).collect()
    }

    /// Splits at slot `at` (default: the midpoint).
    pub fn plan_split(&self, id: ShardId, at: Option<u32>, driver: &str) -> anyhow::Result<Reshard> {
        anyhow::ensure!(self.op.is_none(), "a reshard is already in progress");
        let r = self.range_of(id).ok_or_else(|| anyhow::anyhow!("no shard {id} in layout v{}", self.version))?;
        anyhow::ensure!(r.hi - r.lo >= 2, "shard {id} holds a single slot");
        let at = at.unwrap_or(r.lo + (r.hi - r.lo) / 2);
        anyhow::ensure!(r.lo < at && at < r.hi, "split point {at} outside ({}, {})", r.lo, r.hi);
        let ids = self.alloc(2)?;
        let (a, b) = (ids[0], ids[1]);
        Ok(Reshard {
            id: self.op_seq + 1,
            parents: vec![id],
            children: vec![ShardRange { id: a, lo: r.lo, hi: at }, ShardRange { id: b, lo: at, hi: r.hi }],
            driver: driver.to_string(),
            extra: Default::default(),
        })
    }

    /// `left` and `right` must be adjacent, in slot order.
    pub fn plan_merge(&self, left: ShardId, right: ShardId, driver: &str) -> anyhow::Result<Reshard> {
        anyhow::ensure!(self.op.is_none(), "a reshard is already in progress");
        let i = self
            .shards
            .iter()
            .position(|r| r.id == left)
            .ok_or_else(|| anyhow::anyhow!("no shard {left} in layout v{}", self.version))?;
        let r = self
            .shards
            .get(i + 1)
            .filter(|r| r.id == right)
            .ok_or_else(|| anyhow::anyhow!("shard {right} does not follow {left}"))?;
        let id = self.alloc(1)?[0];
        Ok(Reshard {
            id: self.op_seq + 1,
            parents: vec![left, right],
            children: vec![ShardRange { id, lo: self.shards[i].lo, hi: r.hi }],
            driver: driver.to_string(),
            extra: Default::default(),
        })
    }

    /// Uses up `op`'s child ids now, whether it flips or is aborted: a
    /// child's state is cloned from its parents as frozen *for this op*, so
    /// a later op must never find (and reuse) an aborted op's clone.
    pub fn with_op(&self, op: Reshard) -> Layout {
        let next_id = self.next_id_after(&op);
        Layout { op_seq: op.id, op: Some(op), next_id, ..self.clone() }
    }

    pub fn flipped(&self, op: &Reshard) -> anyhow::Result<Layout> {
        let first = self
            .shards
            .iter()
            .position(|r| r.id == op.parents[0])
            .ok_or_else(|| anyhow::anyhow!("parent {} not in layout", op.parents[0]))?;
        for (k, p) in op.parents.iter().enumerate() {
            anyhow::ensure!(self.shards.get(first + k).is_some_and(|r| r.id == *p), "parents not adjacent in layout");
        }
        let mut shards = self.shards.clone();
        shards.splice(first..first + op.parents.len(), op.children.iter().copied());
        let next_id = self.next_id_after(op);
        let l = Layout {
            version: self.version + 1,
            shards,
            next_id,
            op_seq: self.op_seq,
            op: None,
            extra: self.extra.clone(),
        };
        l.validate()?;
        Ok(l)
    }
}

/// Shard `k` of `n` of the slot space (`subscribeRepos?shard=k/n`): the
/// slots `shard_of_slot` puts in shard k of an n-shard uniform layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotRange {
    pub k: u32,
    pub n: u32,
    pub lo: u32,
    pub hi: u32,
}

impl SlotRange {
    pub fn new(k: u32, n: u32) -> Option<SlotRange> {
        if n == 0 || n > SLOTS || k >= n {
            return None;
        }
        // first slot s with s * n >= k * SLOTS
        let first = |k: u32| ((k as u64 * SLOTS as u64).div_ceil(n as u64)) as u32;
        Some(SlotRange { k, n, lo: first(k), hi: first(k + 1) })
    }

    /// "k/n" (decimal, no signs or spaces).
    pub fn parse(s: &str) -> Option<SlotRange> {
        let (k, n) = s.split_once('/')?;
        let num = |x: &str| x.bytes().all(|b| b.is_ascii_digit()).then(|| x.parse::<u32>().ok()).flatten();
        SlotRange::new(num(k)?, num(n)?)
    }

    pub fn contains(&self, slot: u16) -> bool {
        (self.lo..self.hi).contains(&(slot as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u32) -> ShardId {
        ShardId(n)
    }

    fn ids(v: &[u32]) -> Vec<ShardId> {
        v.iter().copied().map(ShardId).collect()
    }

    #[test]
    fn uniform_ranges() {
        assert_eq!(shard_of_slot(0, 256), s(0));
        assert_eq!(shard_of_slot(255, 256), s(0));
        assert_eq!(shard_of_slot(256, 256), s(1));
        assert_eq!(shard_of_slot(65535, 256), s(255));
        // a 2-way split of every shard keeps each slot inside its parent's range
        for x in [0u16, 1000, 40000, 65535] {
            assert_eq!(shard_of_slot(x, 512).0 / 2, shard_of_slot(x, 256).0);
        }
    }

    #[test]
    fn slot_ranges_partition_the_space() {
        for n in [1u32, 2, 3, 7, 16, 256, 1000, 65_535, 65_536] {
            let ranges: Vec<SlotRange> = (0..n).map(|k| SlotRange::new(k, n).unwrap()).collect();
            // contiguous and covering
            assert_eq!((ranges[0].lo, ranges[n as usize - 1].hi), (0, SLOTS));
            for w in ranges.windows(2) {
                assert_eq!(w[0].hi, w[1].lo);
            }
            // range k holds exactly the slots shard_of_slot puts in shard k
            for x in 0..=u16::MAX {
                let k = (x as u64 * n as u64 / SLOTS as u64) as usize;
                assert!(ranges[k].contains(x), "slot {x} of {n}");
                assert_eq!(k, shard_of_slot(x, n).0 as usize);
            }
        }
        assert_eq!(SlotRange::parse("3/16"), SlotRange::new(3, 16));
        // the uniform layout is shard_of_slot's
        let l = Layout::uniform(7);
        l.validate().unwrap();
        for x in [0u16, 9362, 9363, 30000, 65535] {
            assert_eq!(l.shard_of_slot(x), shard_of_slot(x, 7));
        }
        assert_eq!(Layout::uniform(70_000).shards.len(), SLOTS as usize, "one slot per shard at most");
        for bad in ["", "1", "1/", "/2", "2/2", "0/0", "-1/2", "+1/2", " 1/2", "1/65537", "1/2/3", "a/b"] {
            assert_eq!(SlotRange::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn split_and_merge_regroup_slots() {
        let l = Layout::uniform(4);
        let op = l.plan_split(s(1), None, "n").unwrap();
        assert_eq!(
            op.children,
            vec![ShardRange { id: s(4), lo: 16384, hi: 24576 }, ShardRange { id: s(5), lo: 24576, hi: 32768 }]
        );
        let l2 = l.with_op(op.clone());
        assert!(l2.plan_split(s(0), None, "n").is_err(), "one op at a time");
        let l2 = l2.flipped(&op).unwrap();
        assert_eq!((l2.version, l2.ids(), l2.next_id, l2.op.clone()), (2, ids(&[0, 4, 5, 2, 3]), s(6), None));
        assert_eq!(l2.shard_of_slot(16384), s(4));
        assert_eq!(l2.shard_of_slot(24575), s(4));
        assert_eq!(l2.shard_of_slot(24576), s(5));
        assert!(l2.plan_merge(s(4), s(2), "n").is_err(), "not adjacent");
        let m = l2.plan_merge(s(5), s(2), "n").unwrap();
        assert_eq!(m.children, vec![ShardRange { id: s(6), lo: 24576, hi: 49152 }]);
        let l3 = l2.with_op(m.clone()).flipped(&m).unwrap();
        assert_eq!((l3.ids(), l3.next_id), (ids(&[0, 4, 6, 3]), s(7)));
        // an aborted op's ids stay used: the next op gets fresh ones
        let aborted = Layout { op: None, ..l3.with_op(l3.plan_split(s(0), None, "n").unwrap()) };
        assert_eq!(aborted.plan_split(s(0), None, "n").unwrap().children[0].id, s(9));
        assert!(l.plan_split(s(9), None, "n").is_err());
        assert!(l.plan_split(s(0), Some(0), "n").is_err());
        let one = Layout {
            shards: vec![ShardRange { id: s(0), lo: 0, hi: 1 }, ShardRange { id: s(1), lo: 1, hi: SLOTS }],
            next_id: s(2),
            ..Layout::uniform(1)
        };
        one.validate().unwrap();
        assert!(one.plan_split(s(0), None, "n").is_err(), "a single slot can't split");
    }

    #[test]
    fn shard_id_keys_sort_and_parse() {
        for v in [0u32, 7, 999, 1000, 65_535, 65_536, 1 << 31, u32::MAX] {
            let k = ShardId(v).key();
            assert_eq!(k.len(), ShardId::KEY_WIDTH);
            assert_eq!(ShardId::from_key(&k), Some(ShardId(v)));
        }
        assert_eq!(ShardId(65_536).key(), "0000065536");
        let mut keys: Vec<String> =
            [70_000u32, 3, 65_535, 1000, 4_000_000_000, 12].iter().map(|v| ShardId(*v).key()).collect();
        keys.sort();
        let back: Vec<u32> = keys.iter().map(|k| ShardId::from_key(k).unwrap().0).collect();
        assert_eq!(back, vec![3, 12, 1000, 65_535, 70_000, 4_000_000_000], "keys sort like the ids");
        for bad in ["", "3", "003", "00000000003", "+000000003", "000000000a", "4294967296", "layout"] {
            assert_eq!(ShardId::from_key(bad), None, "{bad:?}");
        }
        // JSON and Display are the plain number
        assert_eq!(serde_json::to_string(&ShardId(70_000)).unwrap(), "70000");
        assert_eq!(serde_json::from_str::<ShardId>("70000").unwrap(), ShardId(70_000));
        assert_eq!(format!("{} {:?}", ShardId(5), vec![ShardId(5)]), "5 [5]");
    }

    /// The allocator hands out every id once: random splits, merges and
    /// aborts (an aborted op's ids stay used), with "crashes" that re-plan
    /// from an older read of the layout (a lost CAS: the planner's copy is
    /// discarded) and resumes from the stored layout, never repeat an id.
    #[test]
    fn shard_ids_are_never_reused() {
        use rand::{Rng, SeedableRng};
        for seed in 0..20u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            // the "stored" layout: only CAS-winning writes replace it
            let mut stored = Layout::uniform(rng.gen_range(1..8));
            let mut handed: std::collections::HashSet<ShardId> = stored.ids().into_iter().collect();
            let mut last_next = stored.next_id;
            for step in 0..300 {
                let n = stored.shards.len();
                let plan = if n > 1 && rng.gen_bool(0.4) {
                    let i = rng.gen_range(0..n - 1);
                    stored.plan_merge(stored.shards[i].id, stored.shards[i + 1].id, "d")
                } else {
                    stored.plan_split(stored.shards[rng.gen_range(0..n)].id, None, "d")
                };
                let Ok(op) = plan else { continue };
                // a racing planner that lost its CAS: never stored
                if rng.gen_bool(0.2) {
                    continue;
                }
                for c in &op.children {
                    assert!(handed.insert(c.id), "seed {seed} step {step}: id {} handed out twice", c.id);
                }
                stored = stored.with_op(op.clone());
                stored.validate().unwrap();
                // driver crash-resume: re-read the stored layout and flip, or abort
                if rng.gen_bool(0.25) {
                    stored = Layout { op: None, ..stored };
                } else {
                    stored = stored.flipped(&op).unwrap();
                }
                assert!(stored.next_id > last_next, "next_id only grows");
                last_next = stored.next_id;
            }
            assert!(stored.ids().iter().all(|i| *i < stored.next_id));
        }
    }

    /// Ids past 16 bits plan, flip and route like any other, and the
    /// allocator stops (instead of wrapping) at u32::MAX.
    #[test]
    fn shard_ids_past_u16() {
        let mut l = Layout::uniform(4);
        l.next_id = ShardId(65_534);
        let op = l.plan_split(s(2), None, "n").unwrap();
        assert_eq!(op.children.iter().map(|c| c.id).collect::<Vec<_>>(), ids(&[65_534, 65_535]));
        let l = l.with_op(op.clone()).flipped(&op).unwrap();
        let op = l.plan_split(s(65_535), None, "n").unwrap();
        assert_eq!(op.children.iter().map(|c| c.id).collect::<Vec<_>>(), ids(&[65_536, 65_537]));
        let l = l.with_op(op.clone()).flipped(&op).unwrap();
        let m = l.plan_merge(s(65_534), s(65_536), "n").unwrap();
        let l = l.with_op(m.clone()).flipped(&m).unwrap();
        assert_eq!((l.ids(), l.next_id), (ids(&[0, 1, 65_538, 65_537, 3]), s(65_539)));
        assert_eq!(l.shard_of_slot(32768), s(65_538));
        let back: Layout = serde_json::from_slice(&serde_json::to_vec(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        let mut full = Layout::uniform(2);
        full.next_id = ShardId(u32::MAX - 1);
        assert!(full.plan_split(s(0), None, "n").is_err(), "ids exhausted");
        assert_eq!(full.plan_merge(s(0), s(1), "n").unwrap().children[0].id, ShardId(u32::MAX - 1));
    }

    /// A newer level's fields on the layout (and on its op) survive an
    /// older node planning, flipping and aborting reshards: every layout
    /// write derives from the one it read.
    #[test]
    fn unknown_layout_fields_round_trip() {
        let mut j = serde_json::to_value(Layout::uniform(4)).unwrap();
        j["placement"] = serde_json::json!({"zones": ["a", "b"]});
        let l: Layout = serde_json::from_value(j).unwrap();
        let op = l.plan_split(s(1), None, "n").unwrap();
        let mut planned = serde_json::to_value(l.with_op(op)).unwrap();
        assert_eq!(planned["placement"]["zones"][1], "b");
        planned["op"]["weight"] = serde_json::json!(3);
        let planned: Layout = serde_json::from_value(planned).unwrap();
        let op = planned.op.clone().unwrap();
        let again = serde_json::to_value(&planned).unwrap();
        assert_eq!(
            (again["op"]["weight"].as_u64(), &again["placement"]["zones"][0]),
            (Some(3), &serde_json::json!("a"))
        );
        let flipped = serde_json::to_value(planned.flipped(&op).unwrap()).unwrap();
        assert_eq!(flipped["placement"]["zones"][0], "a");
        let aborted = serde_json::to_value(Layout { op: None, ..planned }).unwrap();
        assert_eq!(aborted["placement"]["zones"][0], "a");
    }
}
