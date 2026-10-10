//! Node leases: `nodes/{id}`, one per node, renewed by CAS.
//!
//! The holder ([`Holder`]) may act on its lease only until `sent + TTL −
//! skew` on its own monotonic clock, where `sent` is when its last landed
//! write left. An observer ([`Observer`]) presumes the holder dead once the
//! lease has gone unchanged for `TTL + skew` of *its* monotonic clock,
//! counted from when it first saw the current version. The observer saw
//! that version no earlier than it was sent, so the holder's validity ends
//! first as long as neither clock runs more than skew/TTL fast or slow
//! (20 % at the default ratios). Wall clocks are never compared: a node's
//! `expires_ms` is for people.
//!
//! A wrong verdict is safe as long as whoever acts on it fences first (see
//! `table`): the holder loses its next CAS and stops. The holder stops
//! itself too: when a renewal finds the lease taken (another incarnation of
//! its id, or a peer's [`Observer::end`]), and when its validity has been
//! over for 2 × skew without a landed renewal (the watchdog, for a store
//! that hangs instead of failing).
//!
//! R2 takes about one write a second to a key, so writes to one lease are
//! at least `key_gap` apart.

use crate::cas::{self, Expect, Versioned};
use object_store::ObjectStore;
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{watch, Notify};
use tokio::time::Instant;
use vlsync_store::store::Store;

/// Where leases live, under the store's prefix (`ctl_lease` in the request
/// metrics, with the throttle-aware retry of `Store::s3_ctl`).
pub const NODES: &str = "nodes";

/// The least time between writes to one lease key.
pub const KEY_GAP: Duration = Duration::from_secs(1);

/// What a lease carries for its users. `()` for nothing.
pub trait LeaseBody: Serialize + DeserializeOwned + Clone + Default + PartialEq + Send + Sync + 'static {}
impl<T: Serialize + DeserializeOwned + Clone + Default + PartialEq + Send + Sync + 'static> LeaseBody for T {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: DeserializeOwned + Default"))]
pub struct NodeLease<T> {
    pub node_id: String,
    /// One per process start. Assignments name it, so a restart under the
    /// same id is a different owner (the old one's spans get fenced).
    pub incarnation: String,
    pub addr: String,
    /// Bumped by every write: observers judge liveness by seeing it change.
    pub renewals: u64,
    /// Informational: nobody compares it with their own clock.
    pub expires_ms: u64,
    /// Leaving: hand nothing new to it.
    #[serde(default)]
    pub draining: bool,
    /// This incarnation is over: it released, or a peer fenced it and said
    /// so. It never renews again.
    #[serde(default)]
    pub ended: bool,
    /// Range key -> how far this node has applied it (a replica's
    /// watermark), as of the last renewal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub positions: BTreeMap<String, u64>,
    #[serde(default)]
    pub body: T,
    /// Fields a newer version wrote, kept across our writes.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct LeaseConfig {
    pub node_id: String,
    pub addr: String,
    pub ttl: Duration,
    pub renew_every: Duration,
    /// The margin each side gives clock drift: the holder stops `skew`
    /// before TTL, observers wait `skew` past it.
    pub skew: Duration,
    /// Least time between writes to our key (R2: ~1 a second). Capped at
    /// `renew_every`.
    pub key_gap: Duration,
    /// Tests: offsets the `expires_ms` we publish (a wrong wall clock).
    pub clock_offset_ms: i64,
}

impl LeaseConfig {
    /// vlpds's ratios: renewal every TTL/5, skew TTL/5.
    pub fn new(node_id: impl Into<String>, addr: impl Into<String>, ttl: Duration) -> LeaseConfig {
        LeaseConfig {
            node_id: node_id.into(),
            addr: addr.into(),
            ttl,
            renew_every: ttl / 5,
            skew: ttl / 5,
            key_gap: KEY_GAP,
            clock_offset_ms: 0,
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.node_id.is_empty() && !self.node_id.contains('/'), "bad node id {:?}", self.node_id);
        anyhow::ensure!(self.skew * 2 < self.ttl, "skew {:?} must be under TTL/2 ({:?})", self.skew, self.ttl);
        anyhow::ensure!(
            self.renew_every < self.ttl - self.skew,
            "renewal every {:?} can't keep a {:?} lease valid with {:?} skew",
            self.renew_every,
            self.ttl,
            self.skew
        );
        Ok(())
    }

    /// The fastest any two clocks may drift apart (as a rate) with the
    /// holder's validity still ending before an observer's verdict:
    /// `(TTL − skew)(1 + ρ) ≤ (TTL + skew)(1 − ρ)` gives ρ ≤ skew / TTL.
    pub fn max_drift(&self) -> f64 {
        self.skew.as_secs_f64() / self.ttl.as_secs_f64()
    }

    fn gap(&self) -> Duration {
        self.key_gap.min(self.renew_every)
    }

    fn wall_ms(&self) -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
        (now + self.clock_offset_ms).max(0) as u64
    }
}

pub fn rel(node_id: &str) -> String {
    format!("{NODES}/{node_id}")
}

/// Why a holder stopped holding. Every one is final.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lost {
    /// A renewal's CAS found someone else's write: a newer incarnation of
    /// our id.
    Taken,
    /// A peer fenced this incarnation and marked the lease ended.
    Ended,
    /// Validity ran out before a renewal landed.
    Lapsed,
    /// We released it.
    Released,
}

#[derive(Debug)]
pub enum RenewError {
    Lost(Lost),
    /// Nothing landed; the next renewal tries again.
    Transient(anyhow::Error),
}

impl std::fmt::Display for RenewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenewError::Lost(l) => write!(f, "lease lost: {l:?}"),
            RenewError::Transient(e) => write!(f, "lease renewal failed: {e:#}"),
        }
    }
}

impl std::error::Error for RenewError {}

struct Own<T> {
    lease: NodeLease<T>,
    etag: Option<String>,
    /// When the last write to our key was answered.
    last_write: Option<Instant>,
}

/// This node's lease.
pub struct Holder<T> {
    store: Store,
    cfg: LeaseConfig,
    rel: String,
    own: Mutex<Own<T>>,
    valid_until: Mutex<Instant>,
    lost: watch::Sender<Option<Lost>>,
    renewing: tokio::sync::Mutex<()>,
    renew_now: Notify,
    spawned: AtomicBool,
}

impl<T: LeaseBody> Holder<T> {
    /// Writes our lease: a create, or a CAS over an earlier incarnation's
    /// (a restart under the same id). Its assignments then name an
    /// incarnation whose lease is gone, which is how peers know to fence
    /// and take them.
    pub async fn acquire(store: Store, cfg: LeaseConfig, incarnation: String, body: T) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        anyhow::ensure!(!incarnation.is_empty(), "empty incarnation");
        let rel = rel(&cfg.node_id);
        let mut lease = NodeLease {
            node_id: cfg.node_id.clone(),
            incarnation,
            addr: cfg.addr.clone(),
            renewals: 0,
            expires_ms: 0,
            draining: false,
            ended: false,
            positions: BTreeMap::new(),
            body,
            extra: Default::default(),
        };
        let mut last_write = None;
        for _ in 0..8 {
            if let Some(t) = last_write {
                tokio::time::sleep_until(t + cfg.gap()).await;
            }
            let read = cas::read::<NodeLease<T>>(&store, &rel).await?;
            if let Some(r) = &read {
                anyhow::ensure!(
                    r.value.incarnation != lease.incarnation,
                    "{rel}: incarnation {} already wrote this lease",
                    lease.incarnation
                );
                lease.renewals = r.value.renewals;
            }
            lease.renewals += 1;
            lease.expires_ms = cfg.wall_ms() + cfg.ttl.as_millis() as u64;
            let sent = Instant::now();
            let put = cas::write(&store, &rel, &lease, Expect::from_read(read.as_ref())).await;
            last_write = Some(Instant::now());
            let etag = match put {
                Ok(etag) => etag,
                Err(e) if cas::moved(&e) => match cas::read::<NodeLease<T>>(&store, &rel).await? {
                    // ours landed with its answer lost
                    Some(v) if v.value == lease => v.etag,
                    _ => continue,
                },
                Err(e) => return Err(e.into()),
            };
            tracing::info!(node = %cfg.node_id, incarnation = %lease.incarnation, "node lease acquired");
            let valid_until = sent + cfg.ttl - cfg.skew;
            return Ok(Arc::new(Holder {
                store,
                cfg,
                rel,
                own: Mutex::new(Own { lease, etag, last_write }),
                valid_until: Mutex::new(valid_until),
                lost: watch::channel(None).0,
                renewing: tokio::sync::Mutex::new(()),
                renew_now: Notify::new(),
                spawned: AtomicBool::new(false),
            }));
        }
        anyhow::bail!("{rel}: kept changing under our acquire")
    }

    pub fn config(&self) -> &LeaseConfig {
        &self.cfg
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn incarnation(&self) -> String {
        self.own.lock().lease.incarnation.clone()
    }

    pub fn lease(&self) -> NodeLease<T> {
        self.own.lock().lease.clone()
    }

    /// True while we may act as the holder: before `valid_until` and not
    /// lost. Check it right before every write that relies on ownership.
    pub fn valid(&self) -> bool {
        self.lost.borrow().is_none() && Instant::now() < *self.valid_until.lock()
    }

    pub fn valid_until(&self) -> Instant {
        *self.valid_until.lock()
    }

    pub fn lost(&self) -> Option<Lost> {
        self.lost.borrow().clone()
    }

    /// Fires once with the reason we stopped holding.
    pub fn watch_lost(&self) -> watch::Receiver<Option<Lost>> {
        self.lost.subscribe()
    }

    /// Changes what the next renewal publishes (draining, positions, body).
    pub fn update(&self, f: impl FnOnce(&mut NodeLease<T>)) {
        let mut own = self.own.lock();
        let (inc, id, renewals, ended) =
            (own.lease.incarnation.clone(), own.lease.node_id.clone(), own.lease.renewals, own.lease.ended);
        f(&mut own.lease);
        // what identifies and times the lease is ours to keep
        own.lease.incarnation = inc;
        own.lease.node_id = id;
        own.lease.renewals = renewals;
        own.lease.ended = ended;
    }

    /// Asks the renew loop to write now (a published change that peers
    /// should see before the next tick).
    pub fn renew_soon(&self) {
        self.renew_now.notify_one();
    }

    fn mark_lost(&self, why: Lost) -> RenewError {
        self.lost.send_if_modified(|l| {
            if l.is_none() {
                tracing::error!(node = %self.cfg.node_id, ?why, "node lease lost");
                *l = Some(why.clone());
                true
            } else {
                false
            }
        });
        RenewError::Lost(self.lost().unwrap_or(why))
    }

    /// One renewal: a CAS on the version we last wrote. A lapsed lease is
    /// never renewed (peers may have fenced us meanwhile), so it's lost.
    pub async fn renew(&self) -> Result<(), RenewError> {
        let _g = self.renewing.lock().await;
        for _ in 0..2 {
            if let Some(l) = self.lost() {
                return Err(RenewError::Lost(l));
            }
            let last = self.own.lock().last_write;
            if let Some(t) = last {
                let next = t + self.cfg.gap();
                if next > Instant::now() {
                    tokio::time::sleep_until(next.min(self.valid_until())).await;
                }
            }
            if !self.valid() {
                return Err(self.mark_lost(Lost::Lapsed));
            }
            let (next, expect) = {
                let own = self.own.lock();
                let mut l = own.lease.clone();
                l.renewals += 1;
                l.expires_ms = self.cfg.wall_ms() + self.cfg.ttl.as_millis() as u64;
                (l, Expect::Version(own.etag.clone()))
            };
            let sent = Instant::now();
            let put = cas::write(&self.store, &self.rel, &next, expect).await;
            self.own.lock().last_write = Some(Instant::now());
            match put {
                Ok(etag) => {
                    self.landed(&next, etag, sent);
                    return Ok(());
                }
                Err(e) if cas::moved(&e) => {
                    let stored =
                        cas::read::<NodeLease<T>>(&self.store, &self.rel).await.map_err(RenewError::Transient)?;
                    match stored {
                        Some(v) if v.value.incarnation == next.incarnation && v.value.ended => {
                            return Err(self.mark_lost(Lost::Ended));
                        }
                        // Only we write our incarnation without `ended`: the
                        // stored version is one of our writes whose answer
                        // was lost (this one, or the one before it).
                        Some(v) if v.value.incarnation == next.incarnation => {
                            if v.value.renewals == next.renewals {
                                self.landed(&next, v.etag, sent);
                                return Ok(());
                            }
                            tracing::warn!(node = %self.cfg.node_id, "an earlier lease write landed with its answer lost: adopted it");
                            let mut own = self.own.lock();
                            own.etag = v.etag;
                            own.lease.renewals = v.value.renewals;
                        }
                        _ => return Err(self.mark_lost(Lost::Taken)),
                    }
                }
                Err(e) => return Err(RenewError::Transient(e.into())),
            }
        }
        Err(RenewError::Transient(anyhow::anyhow!("{}: our own lost answers moved it twice", self.rel)))
    }

    fn landed(&self, sent_lease: &NodeLease<T>, etag: Option<String>, sent: Instant) {
        {
            let mut own = self.own.lock();
            own.etag = etag;
            own.lease.renewals = sent_lease.renewals;
            own.lease.expires_ms = sent_lease.expires_ms;
        }
        let mut v = self.valid_until.lock();
        *v = (*v).max(sent + self.cfg.ttl - self.cfg.skew);
    }

    /// Starts the renew loop and the watchdog. Returns the lost watch.
    pub fn spawn(self: &Arc<Self>) -> watch::Receiver<Option<Lost>> {
        if self.spawned.swap(true, Ordering::AcqRel) {
            return self.watch_lost();
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.renew_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = me.renew_now.notified() => {}
                }
                match me.renew().await {
                    Ok(()) => {}
                    Err(RenewError::Lost(_)) => return,
                    Err(RenewError::Transient(e)) => tracing::warn!(node = %me.cfg.node_id, "lease renewal: {e:#}"),
                }
            }
        });
        // A store call that hangs never returns to the checks above.
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.renew_every / 2);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if me.lost().is_some() {
                    return;
                }
                if Instant::now() > me.valid_until() + me.cfg.skew * 2 {
                    me.mark_lost(Lost::Lapsed);
                    return;
                }
            }
        });
        self.watch_lost()
    }

    /// Ends this incarnation: marks the lease ended so peers take what's
    /// left at once (hand off or fence everything first). The id's next
    /// incarnation writes over it.
    pub async fn release(&self) -> anyhow::Result<()> {
        let _g = self.renewing.lock().await;
        if self.lost().is_some() {
            return Ok(());
        }
        let (mut l, etag) = {
            let own = self.own.lock();
            (own.lease.clone(), own.etag.clone())
        };
        l.ended = true;
        l.draining = true;
        l.renewals += 1;
        self.mark_lost(Lost::Released);
        match cas::write(&self.store, &self.rel, &l, Expect::Version(etag)).await {
            Ok(_) => Ok(()),
            // taken or ended already: nothing of ours to end
            Err(e) if cas::moved(&e) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// How an observer judges a lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    Live,
    /// Quiet for over half its TTL: route around it, don't take from it.
    Suspect,
    /// Quiet past TTL + skew, or ended: fence it, then take its ranges.
    Dead,
}

struct Seen<T> {
    etag: Option<String>,
    lease: NodeLease<T>,
    /// Our monotonic time when this version (incarnation, renewals) was
    /// first seen.
    changed_at: Instant,
}

/// Every lease as one observer judged them right after listing.
#[derive(Clone, Debug)]
pub struct Membership<T> {
    pub leases: BTreeMap<String, (NodeLease<T>, Liveness)>,
}

impl<T> Default for Membership<T> {
    fn default() -> Self {
        Membership { leases: BTreeMap::new() }
    }
}

impl<T: Clone> Membership<T> {
    pub fn get(&self, node_id: &str) -> Option<&(NodeLease<T>, Liveness)> {
        self.leases.get(node_id)
    }

    pub fn with(&self, l: Liveness) -> Vec<NodeLease<T>> {
        self.leases.values().filter(|(_, v)| *v == l).map(|(n, _)| n.clone()).collect()
    }

    /// Live and suspect leases: nodes that may still be acting.
    pub fn up(&self) -> Vec<NodeLease<T>> {
        self.leases.values().filter(|(_, v)| *v != Liveness::Dead).map(|(n, _)| n.clone()).collect()
    }

    /// Live, not draining: where new work may go.
    pub fn settled(&self) -> Vec<NodeLease<T>> {
        self.leases.values().filter(|(n, v)| *v == Liveness::Live && !n.draining).map(|(n, _)| n.clone()).collect()
    }

    /// How `node_id`'s `incarnation` stands as listed: Dead if its lease
    /// names another incarnation or ended, None if it isn't listed.
    pub fn incarnation(&self, node_id: &str, incarnation: &str) -> Option<Liveness> {
        let (l, v) = self.leases.get(node_id)?;
        if l.incarnation != incarnation {
            return Some(Liveness::Dead);
        }
        Some(*v)
    }
}

/// Reads every lease and judges each on our monotonic clock.
pub struct Observer<T> {
    store: Store,
    ttl: Duration,
    skew: Duration,
    seen: Mutex<BTreeMap<String, Seen<T>>>,
}

impl<T: LeaseBody> Observer<T> {
    pub fn new(store: Store, ttl: Duration, skew: Duration) -> Observer<T> {
        Observer { store, ttl, skew, seen: Mutex::new(BTreeMap::new()) }
    }

    pub fn for_holder(h: &Holder<T>) -> Observer<T> {
        Observer::new(h.store.clone(), h.cfg.ttl, h.cfg.skew)
    }

    /// Lists `nodes/` and fetches only the leases whose ETag changed. A
    /// lease that can't be read fails the whole call: a verdict from a
    /// stale view could presume a renewing node dead.
    pub async fn observe(&self) -> anyhow::Result<Membership<T>> {
        use futures::TryStreamExt;
        let dir = cas::path(&self.store, NODES);
        let listed: Vec<object_store::ObjectMeta> = self.store.raw.list(Some(&dir)).try_collect().await?;
        let mut current = BTreeMap::new();
        for m in listed {
            let Some(id) = m.location.filename() else { continue };
            current.insert(id.to_string(), (m.location.clone(), m.e_tag.clone()));
        }
        let stale: Vec<(String, object_store::path::Path)> = {
            let seen = self.seen.lock();
            current
                .iter()
                .filter(|(id, (_, etag))| seen.get(*id).is_none_or(|s| s.etag != *etag || etag.is_none()))
                .map(|(id, (p, _))| (id.clone(), p.clone()))
                .collect()
        };
        let reads = futures::future::try_join_all(stale.into_iter().map(|(id, p)| {
            let raw = self.store.raw.clone();
            async move {
                let v = cas::read_at::<NodeLease<T>>(raw.as_ref() as &dyn ObjectStore, &p).await?;
                anyhow::Ok((id, v))
            }
        }))
        .await?;
        let now = Instant::now();
        let mut seen = self.seen.lock();
        seen.retain(|id, _| current.contains_key(id));
        for (id, v) in reads {
            let Some(Versioned { value, etag }) = v else {
                seen.remove(&id);
                continue;
            };
            let changed = seen.get(&id).is_none_or(|s| {
                s.lease.incarnation != value.incarnation
                    || s.lease.renewals != value.renewals
                    || s.lease.ended != value.ended
            });
            let changed_at = if changed { now } else { seen[&id].changed_at };
            seen.insert(id, Seen { etag, lease: value, changed_at });
        }
        drop(seen);
        Ok(self.classify_at(now))
    }

    /// The verdicts as of `now` from what was last observed.
    pub fn classify_at(&self, now: Instant) -> Membership<T> {
        let seen = self.seen.lock();
        let leases = seen
            .iter()
            .map(|(id, s)| {
                let quiet = now.saturating_duration_since(s.changed_at);
                let v = if s.lease.ended || quiet > self.ttl + self.skew {
                    Liveness::Dead
                } else if quiet > self.ttl / 2 {
                    Liveness::Suspect
                } else {
                    Liveness::Live
                };
                (id.clone(), (s.lease.clone(), v))
            })
            .collect();
        Membership { leases }
    }

    /// Marks a dead incarnation's lease ended, by CAS on the version we
    /// judged. Call it only after fencing everything the incarnation could
    /// still write. False: the lease changed since (it renewed after all,
    /// or the id restarted), so leave it.
    pub async fn end(&self, dead: &NodeLease<T>) -> anyhow::Result<bool> {
        let etag = {
            let seen = self.seen.lock();
            match seen.get(&dead.node_id) {
                Some(s) if s.lease == *dead => s.etag.clone(),
                _ => return Ok(false),
            }
        };
        if dead.ended {
            return Ok(true);
        }
        let mut l = dead.clone();
        l.ended = true;
        match cas::write(&self.store, &rel(&dead.node_id), &l, Expect::Version(etag)).await {
            Ok(etag) => {
                let mut seen = self.seen.lock();
                if let Some(s) = seen.get_mut(&dead.node_id) {
                    s.lease = l;
                    s.etag = etag;
                }
                Ok(true)
            }
            Err(e) if cas::moved(&e) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests;
