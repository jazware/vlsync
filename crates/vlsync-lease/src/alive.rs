//! Liveness, pluggable: who's alive, and may I still write. The table asks
//! it before taking a range from its owner. Safety doesn't depend on which
//! one runs, since a taker always fences first.
//!
//! - [`Leases`]: bucket leases (`lease`). Costs a class A write per node per
//!   renewal, and a LIST per observation.
//! - [`Peers`](crate::peers::Peers): heartbeats between members. Costs no
//!   bucket requests.

use crate::cas;
use crate::lease::{self, Holder, LeaseBody, Liveness, Membership, NodeLease, Observer};
use crate::peers::Peers;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::time::Instant;
use vlsync_store::store::Store;

/// A verdict and the local monotonic instant it stands as of: when the
/// incarnation was last heard from (Live, Suspect), or when it was judged
/// Dead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heard {
    pub liveness: Liveness,
    pub as_of: Instant,
}

#[async_trait]
pub trait Alive: Send + Sync {
    /// How `node_id`'s `incarnation` stands. None: this source doesn't know
    /// (the table then asks [`Alive::confirm_up`]).
    fn verdict(&self, node_id: &str, incarnation: &str) -> Option<Heard>;

    /// The self-check: may this node still act as an owner? Check it
    /// before every durable write that relies on ownership.
    fn may_write(&self) -> bool;

    /// How far `node_id`'s `incarnation` has applied range `range` (a
    /// `ShardId::key()`), as it last published it. None: unknown.
    fn position(&self, _node_id: &str, _incarnation: &str, _range: &str) -> Option<u64> {
        None
    }

    /// Whether an incarnation this source doesn't know may still be acting.
    /// By default its lease in the bucket decides (a listing can predate
    /// a lease written since).
    async fn confirm_up(&self, store: &Store, node_id: &str, incarnation: &str) -> anyhow::Result<bool> {
        let fresh = cas::read::<NodeLease<serde_json::Value>>(store, &lease::rel(node_id)).await?;
        Ok(fresh.is_some_and(|l| l.value.incarnation == incarnation && !l.value.ended))
    }
}

/// A listing as an observer took it. It knows nothing about this node's
/// own lease, so `may_write` is always true: use [`Leases`] for that.
#[async_trait]
impl<T: LeaseBody> Alive for Membership<T> {
    fn verdict(&self, node_id: &str, incarnation: &str) -> Option<Heard> {
        let (l, v) = self.get(node_id)?;
        if l.incarnation != incarnation {
            return None;
        }
        let as_of = self.heard.get(node_id).copied().unwrap_or_else(Instant::now);
        Some(Heard { liveness: *v, as_of: if *v == Liveness::Dead { Instant::now() } else { as_of } })
    }

    fn may_write(&self) -> bool {
        true
    }

    fn position(&self, node_id: &str, incarnation: &str, range: &str) -> Option<u64> {
        let (l, _) = self.get(node_id)?;
        (l.incarnation == incarnation).then(|| l.positions.get(range).copied()).flatten()
    }
}

/// Bucket leases: this node's [`Holder`] for the self-check and an
/// [`Observer`] for everyone else, judged as of the last [`Leases::observe`].
pub struct Leases<T> {
    holder: Arc<Holder<T>>,
    observer: Observer<T>,
    last: Mutex<Membership<T>>,
}

impl<T: LeaseBody> Leases<T> {
    pub fn new(holder: Arc<Holder<T>>) -> Leases<T> {
        let observer = Observer::for_holder(&holder);
        Leases { holder, observer, last: Mutex::new(Membership::default()) }
    }

    pub fn holder(&self) -> &Arc<Holder<T>> {
        &self.holder
    }

    pub fn observer(&self) -> &Observer<T> {
        &self.observer
    }

    /// Lists the leases: verdicts stand as of this call.
    pub async fn observe(&self) -> anyhow::Result<Membership<T>> {
        let m = self.observer.observe().await?;
        *self.last.lock() = m.clone();
        Ok(m)
    }

    pub fn membership(&self) -> Membership<T> {
        self.last.lock().clone()
    }
}

#[async_trait]
impl<T: LeaseBody> Alive for Leases<T> {
    fn verdict(&self, node_id: &str, incarnation: &str) -> Option<Heard> {
        self.last.lock().verdict(node_id, incarnation)
    }

    fn may_write(&self) -> bool {
        self.holder.valid()
    }

    fn position(&self, node_id: &str, incarnation: &str, range: &str) -> Option<u64> {
        self.last.lock().position(node_id, incarnation, range)
    }
}

#[async_trait]
impl Alive for Peers {
    fn verdict(&self, node_id: &str, incarnation: &str) -> Option<Heard> {
        Peers::verdict(self, node_id, incarnation)
    }

    fn may_write(&self) -> bool {
        Peers::may_write(self)
    }

    fn position(&self, node_id: &str, incarnation: &str, range: &str) -> Option<u64> {
        Peers::position(self, node_id, incarnation, range)
    }

    /// Not a member: never presumed dead (nothing would ever say so).
    async fn confirm_up(&self, _: &Store, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
}
