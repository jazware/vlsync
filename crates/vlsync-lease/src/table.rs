//! The assignment table: `assign/{shard}`, one record per slot range
//! (`vlsync_store::slots::Layout` names the ranges; `assign/layout` and
//! `assign/topology` sit beside the records and aren't ranges).
//!
//! A record names the range's owner and its epoch. The epoch is the fencing
//! token: it grows by one on every change of who may write the range
//! (acquire, release, hand off, freeze), never otherwise. The history is
//! the spans of positions each epoch decided, `[from, until]`, contiguous
//! and in epoch order; the open one (no `until`) is the owner's. Positions
//! are the user's: relay seqs for vlDB's enrich stage, log ordinals for a
//! vlpds-style shard.
//!
//! Every change is one CAS on the record, so each epoch has one owner. A
//! new owner of a range whose owner died first fences that incarnation
//! (the caller's fence returns the last position it made durable), closes
//! its span there and opens its own right after. A cooperative release
//! closes the span at the position the releaser stopped at. Either way an
//! old owner's writes past its span's end are outside the history, and a
//! reader that keeps only what [`Assignment::accepts`] drops them.
//!
//! Replicas are listed but hold no epoch: they replay what the owner
//! decided. Their progress rides on their own node leases (`positions`),
//! which are renewed anyway, so a replica's watermark costs no writes here.

use crate::cas::{self, Expect, Updated, Versioned};
use crate::epoch::Epoched;
use crate::lease::{self, LeaseBody, Liveness, Membership, NodeLease};
use crate::topology::Topology;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::watch;
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

/// Where the table lives, under the store's prefix (`ctl_assign`).
pub const ASSIGN: &str = "assign";

/// CAS attempts before an op gives up on a contended record.
const ATTEMPTS: u32 = 4;

/// One incarnation of a node, as assignments name it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Member {
    pub node_id: String,
    pub incarnation: String,
    pub addr: String,
}

impl Member {
    pub fn of<T>(l: &NodeLease<T>) -> Member {
        Member { node_id: l.node_id.clone(), incarnation: l.incarnation.clone(), addr: l.addr.clone() }
    }

    pub fn same(&self, other: &Member) -> bool {
        self.node_id == other.node_id && self.incarnation == other.incarnation
    }
}

/// The positions one epoch decided.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub epoch: u64,
    pub node_id: String,
    pub incarnation: String,
    pub from: u64,
    /// Inclusive. None: still open (the owner's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

impl Span {
    pub fn contains(&self, pos: u64) -> bool {
        pos >= self.from && self.until.is_none_or(|u| pos <= u)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Assignment {
    /// The fencing token.
    pub epoch: u64,
    /// +1 on every write: routers keep the newest view of each range.
    pub version: u64,
    pub owner: Option<Member>,
    pub replicas: Vec<Member>,
    /// Every position up to here is decided: the next span starts at
    /// `floor + 1`.
    pub floor: u64,
    pub history: Vec<Span>,
    /// The reshard op this range was frozen for: never acquired again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frozen: Option<u64>,
    /// Fields a newer version wrote, kept across our CAS writes.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Epoched for Assignment {
    fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Assignment {
    pub fn owned_by(&self, m: &Member) -> bool {
        self.owner.as_ref().is_some_and(|o| o.same(m))
    }

    pub fn open_span(&self) -> Option<&Span> {
        self.history.last().filter(|s| s.until.is_none())
    }

    /// The span that decided (or decides) `pos`.
    pub fn authority_at(&self, pos: u64) -> Option<&Span> {
        self.history.iter().rev().find(|s| s.contains(pos))
    }

    /// Whether a write at `pos` by `incarnation` under `epoch` is part of
    /// the range's history. False for anything a deposed owner wrote past
    /// its span's end, and for positions below the retained history.
    pub fn accepts(&self, epoch: u64, incarnation: &str, pos: u64) -> bool {
        self.authority_at(pos).is_some_and(|s| s.epoch == epoch && s.incarnation == incarnation)
    }

    /// The record's invariants: epochs strictly grow along the history,
    /// spans are contiguous and nonempty, only the last may be open, and
    /// it's open exactly when there's an owner, at the current epoch.
    pub fn check(&self) -> anyhow::Result<()> {
        for w in self.history.windows(2) {
            anyhow::ensure!(w[0].epoch < w[1].epoch, "span epochs {} then {}", w[0].epoch, w[1].epoch);
            let until = w[0].until.ok_or_else(|| anyhow::anyhow!("open span before the last"))?;
            anyhow::ensure!(until + 1 == w[1].from, "spans not contiguous: until {until} then from {}", w[1].from);
        }
        for s in &self.history {
            anyhow::ensure!(s.epoch <= self.epoch, "span epoch {} past the record's {}", s.epoch, self.epoch);
            if let Some(u) = s.until {
                anyhow::ensure!(u >= s.from, "empty span [{}, {u}]", s.from);
                anyhow::ensure!(u <= self.floor, "span until {u} past the floor {}", self.floor);
            }
        }
        match (&self.owner, self.open_span()) {
            (Some(o), Some(s)) => {
                anyhow::ensure!(s.epoch == self.epoch, "open span epoch {} isn't the record's {}", s.epoch, self.epoch);
                anyhow::ensure!(s.incarnation == o.incarnation, "open span isn't the owner's");
                anyhow::ensure!(s.from == self.floor + 1, "open span from {} with floor {}", s.from, self.floor);
            }
            (None, None) => {}
            (o, s) => anyhow::bail!("owner {o:?} with open span {s:?}"),
        }
        anyhow::ensure!(
            !self.replicas.iter().any(|r| self.owner.as_ref().is_some_and(|o| o.node_id == r.node_id)),
            "the owner is also a replica"
        );
        Ok(())
    }

    /// Closes the open span at `end` (dropped if it decided nothing).
    fn close(&mut self, end: u64) {
        if let Some(s) = self.history.last_mut().filter(|s| s.until.is_none()) {
            if end >= s.from {
                s.until = Some(end);
                self.floor = self.floor.max(end);
            } else {
                self.history.pop();
            }
        }
        self.owner = None;
    }

    /// Opens `m`'s span at `floor + 1` under the next epoch.
    fn open(&mut self, m: &Member) {
        self.epoch += 1;
        self.history.push(Span {
            epoch: self.epoch,
            node_id: m.node_id.clone(),
            incarnation: m.incarnation.clone(),
            from: self.floor + 1,
            until: None,
        });
        self.replicas.retain(|r| r.node_id != m.node_id);
        self.owner = Some(m.clone());
    }
}

/// What [`Table::acquire`] did.
#[derive(Clone, Debug, PartialEq)]
pub enum Acquired {
    /// Ours now, at its epoch; the span to write is its open one.
    Taken(Assignment),
    /// Already ours.
    Held(Assignment),
    /// A live owner holds it.
    Busy(Member),
    Frozen,
    Missing,
}

/// The table as this node last read it, with the topology it implies.
pub struct Table {
    store: Store,
    cache: Mutex<BTreeMap<ShardId, Versioned<Assignment>>>,
    topo: watch::Sender<Arc<Topology>>,
}

pub fn rel(shard: ShardId) -> String {
    format!("{ASSIGN}/{}", shard.key())
}

impl Table {
    pub fn new(store: Store) -> Table {
        Table { store, cache: Mutex::new(BTreeMap::new()), topo: watch::channel(Arc::new(Topology::default())).0 }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn cached(&self, shard: ShardId) -> Option<Versioned<Assignment>> {
        self.cache.lock().get(&shard).cloned()
    }

    pub fn all(&self) -> BTreeMap<ShardId, Assignment> {
        self.cache.lock().iter().map(|(k, v)| (*k, v.value.clone())).collect()
    }

    /// The ranges `m` owns, as cached.
    pub fn owned_by(&self, m: &Member) -> Vec<(ShardId, Assignment)> {
        self.cache.lock().iter().filter(|(_, v)| v.value.owned_by(m)).map(|(k, v)| (*k, v.value.clone())).collect()
    }

    /// The topology of the cached table.
    pub fn topology(&self) -> Arc<Topology> {
        self.topo.borrow().clone()
    }

    /// Fires on every change to the cached table's topology.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Topology>> {
        self.topo.subscribe()
    }

    fn put_cache(&self, shard: ShardId, v: Option<Versioned<Assignment>>) {
        {
            let mut c = self.cache.lock();
            match v {
                // never replace a newer cached version with an older read
                Some(v) if c.get(&shard).is_none_or(|old| old.value.version <= v.value.version) => {
                    c.insert(shard, v);
                }
                Some(_) => {}
                None => {
                    c.remove(&shard);
                }
            }
        }
        self.publish_local();
    }

    fn publish_local(&self) {
        let t = Topology::from_table(self.cache.lock().iter().map(|(k, v)| (*k, &v.value)));
        self.topo.send_if_modified(|cur| {
            if cur.ranges != t.ranges {
                *cur = Arc::new(t);
                true
            } else {
                false
            }
        });
    }

    /// Lists `assign/` and reads the records whose ETag changed.
    pub async fn refresh(&self) -> anyhow::Result<Arc<Topology>> {
        use futures::TryStreamExt;
        let dir = cas::path(&self.store, ASSIGN);
        let listed: Vec<object_store::ObjectMeta> = self.store.raw.list(Some(&dir)).try_collect().await?;
        let mut current = BTreeMap::new();
        for m in listed {
            if let Some(s) = m.location.filename().and_then(ShardId::from_key) {
                current.insert(s, m.e_tag);
            }
        }
        let stale: Vec<ShardId> = {
            let c = self.cache.lock();
            current
                .iter()
                .filter(|(s, e)| c.get(*s).is_none_or(|v| v.etag != **e || e.is_none()))
                .map(|(s, _)| *s)
                .collect()
        };
        let reads = futures::future::try_join_all(
            stale
                .into_iter()
                .map(|s| async move { anyhow::Ok((s, cas::read::<Assignment>(&self.store, &rel(s)).await?)) }),
        )
        .await?;
        {
            let mut c = self.cache.lock();
            c.retain(|s, _| current.contains_key(s));
            for (s, v) in reads {
                match v {
                    Some(v) => {
                        c.insert(s, v);
                    }
                    None => {
                        c.remove(&s);
                    }
                }
            }
        }
        self.publish_local();
        Ok(self.topology())
    }

    /// A fresh read of one record (cached).
    pub async fn read(&self, shard: ShardId) -> anyhow::Result<Option<Versioned<Assignment>>> {
        let v = cas::read::<Assignment>(&self.store, &rel(shard)).await?;
        match &v {
            Some(v) => self.put_cache(shard, Some(v.clone())),
            None => self.put_cache(shard, None),
        }
        Ok(v)
    }

    async fn update(
        &self,
        shard: ShardId,
        f: impl FnMut(Option<&Assignment>) -> Option<Assignment>,
    ) -> anyhow::Result<Option<Assignment>> {
        let start = self.cached(shard).map(Some);
        match cas::update(&self.store, &rel(shard), start, ATTEMPTS, f).await? {
            Updated::Written(v) => {
                let a = v.value.clone();
                self.put_cache(shard, Some(v));
                Ok(Some(a))
            }
            Updated::Declined(v) => {
                if let Some(v) = v {
                    self.put_cache(shard, Some(v));
                }
                Ok(None)
            }
        }
    }

    /// Creates a range's record if it has none: positions up to `floor` are
    /// already decided (a snapshot's, a parent's freeze point). With an
    /// owner it starts at epoch 1, owned. None: it exists.
    pub async fn create(
        &self,
        shard: ShardId,
        floor: u64,
        owner: Option<&Member>,
    ) -> anyhow::Result<Option<Assignment>> {
        let mut a = Assignment { floor, version: 1, ..Default::default() };
        if let Some(o) = owner {
            a.open(o);
        }
        match cas::write(&self.store, &rel(shard), &a, Expect::Absent).await {
            Ok(etag) => {
                self.put_cache(shard, Some(Versioned { value: a.clone(), etag }));
                Ok(Some(a))
            }
            Err(e) if cas::moved(&e) => {
                let cur = self.read(shard).await?;
                Ok(cur.filter(|v| v.value == a).map(|v| v.value))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Takes `shard` for `me` unless a live incarnation owns it. An owner
    /// that's dead (by `members`, its lease's incarnation, or its lease
    /// ended) is fenced first: `fence` gets its open span and returns the
    /// last position that incarnation made durable for the range; our span
    /// starts right after. The fence must leave that incarnation unable to
    /// make anything past it durable (a create-only fence object at the end
    /// of its stream, say), since it may still be running.
    pub async fn acquire<T, F, Fut>(
        &self,
        shard: ShardId,
        me: &Member,
        members: &Membership<T>,
        mut fence: F,
    ) -> anyhow::Result<Acquired>
    where
        T: LeaseBody,
        F: FnMut(Span) -> Fut,
        Fut: Future<Output = anyhow::Result<u64>>,
    {
        let mut cur = match self.cached(shard) {
            Some(v) => Some(v),
            None => self.read(shard).await?,
        };
        for _ in 0..ATTEMPTS {
            let Some(read) = cur.clone() else { return Ok(Acquired::Missing) };
            let a = &read.value;
            if a.frozen.is_some() {
                return Ok(Acquired::Frozen);
            }
            if a.owned_by(me) {
                return Ok(Acquired::Held(a.clone()));
            }
            let mut next = a.clone();
            if let Some(o) = &a.owner {
                if self.owner_up(o, members).await? {
                    return Ok(Acquired::Busy(o.clone()));
                }
                let open = a.open_span().cloned().ok_or_else(|| anyhow::anyhow!("{shard}: owner without a span"))?;
                let end = fence(open.clone()).await?;
                tracing::info!(%shard, owner = %o.node_id, incarnation = %o.incarnation, epoch = open.epoch, end, "fenced the range's dead owner");
                next.close(end);
            }
            next.open(me);
            next.version += 1;
            match cas::write(&self.store, &rel(shard), &next, Expect::Version(read.etag.clone())).await {
                Ok(etag) => {
                    self.put_cache(shard, Some(Versioned { value: next.clone(), etag }));
                    tracing::info!(%shard, epoch = next.epoch, from = next.floor + 1, "acquired range");
                    return Ok(Acquired::Taken(next));
                }
                Err(e) if cas::moved(&e) => {
                    cur = self.read(shard).await?;
                    if cur.as_ref().is_some_and(|v| v.value == next) {
                        return Ok(Acquired::Taken(next));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("{shard}: still contended after {ATTEMPTS} acquire attempts")
    }

    /// Whether `o` may still be acting. A listing can predate a lease
    /// (a node that joined since, or restarted under the same id), so
    /// anything other than a plain verdict on `o`'s own incarnation is
    /// checked against a fresh read of its lease.
    async fn owner_up<T: LeaseBody>(&self, o: &Member, members: &Membership<T>) -> anyhow::Result<bool> {
        match members.incarnation(&o.node_id, &o.incarnation) {
            Some(Liveness::Live | Liveness::Suspect) => return Ok(true),
            Some(Liveness::Dead) if members.get(&o.node_id).is_some_and(|(l, _)| l.incarnation == o.incarnation) => {
                return Ok(false);
            }
            _ => {}
        }
        let fresh = cas::read::<NodeLease<T>>(&self.store, &lease::rel(&o.node_id)).await?;
        Ok(fresh.is_some_and(|l| l.value.incarnation == o.incarnation && !l.value.ended))
    }

    /// `me` stops writing at `end` (every position up to it is durable,
    /// none past it will be) and hands the range to `to` (its span starts
    /// at `end + 1` under the next epoch), or leaves it unowned. None: we
    /// don't own it.
    pub async fn release(
        &self,
        shard: ShardId,
        me: &Member,
        end: u64,
        to: Option<&Member>,
    ) -> anyhow::Result<Option<Assignment>> {
        self.update(shard, |cur| {
            let a = cur?;
            if !a.owned_by(me) || a.frozen.is_some() {
                return None;
            }
            let mut n = a.clone();
            n.close(end);
            match to {
                Some(t) => n.open(t),
                None => n.epoch += 1,
            }
            n.version += 1;
            Some(n)
        })
        .await
    }

    /// Closes the range for reshard op `op`: like a release to nobody, and
    /// never acquired again. Its children are then [`Table::create`]d with
    /// `floor = end`.
    pub async fn freeze(&self, shard: ShardId, me: &Member, end: u64, op: u64) -> anyhow::Result<Option<Assignment>> {
        self.update(shard, |cur| {
            let a = cur?;
            if a.frozen == Some(op) {
                return None;
            }
            if !a.owned_by(me) || a.frozen.is_some() {
                return None;
            }
            let mut n = a.clone();
            n.close(end);
            n.epoch += 1;
            n.frozen = Some(op);
            n.version += 1;
            Some(n)
        })
        .await
    }

    /// Changes the replica list (never the owner, never the epoch).
    pub async fn set_replicas(
        &self,
        shard: ShardId,
        f: impl Fn(&mut Vec<Member>),
    ) -> anyhow::Result<Option<Assignment>> {
        self.update(shard, |cur| {
            let a = cur?;
            let mut n = a.clone();
            f(&mut n.replicas);
            let owner = n.owner.as_ref().map(|o| o.node_id.clone());
            n.replicas.retain(|r| Some(&r.node_id) != owner.as_ref());
            n.replicas.sort();
            n.replicas.dedup_by(|a, b| a.node_id == b.node_id);
            if n.replicas == a.replicas {
                return None;
            }
            n.version += 1;
            Some(n)
        })
        .await
    }

    /// Drops closed spans that end below `below` (everything a snapshot at
    /// `below - 1` already holds). The open span always stays.
    pub async fn trim(&self, shard: ShardId, below: u64) -> anyhow::Result<Option<Assignment>> {
        self.update(shard, |cur| {
            let a = cur?;
            let mut n = a.clone();
            n.history.retain(|s| s.until.is_none_or(|u| u >= below));
            if n.history.len() == a.history.len() {
                return None;
            }
            n.version += 1;
            Some(n)
        })
        .await
    }
}

#[cfg(test)]
mod tests;
