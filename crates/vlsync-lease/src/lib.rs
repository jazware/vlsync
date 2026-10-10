//! Ownership for every vlsync server that has more than one node
//! (docs/leases.md). Safety lives in the bucket, liveness is pluggable:
//!
//! - [`cas`]: JSON objects moved only by conditional PUTs, the errors that
//!   mean "someone else wrote it", and a read-modify-write loop that adopts
//!   a write whose answer was lost.
//! - [`epoch`]: records whose epoch only grows. A claim is a CAS to
//!   epoch + 1, and a fence raises a downstream record to the claimer's
//!   epoch so an older writer's next CAS fails (vlRelay's `qlog/leader` and
//!   `qlog/manifest`).
//! - [`table`]: `assign/{shard}`, one record per slot range: the owner, its
//!   epoch (the fencing token), the spans of positions each epoch decided,
//!   and the replicas. Acquire, release, hand off, freeze and seed are each
//!   one CAS.
//! - [`topology`]: the whole table as one object for routers.
//! - [`alive`]: who's alive and may I write, as a trait with two
//!   implementations:
//!   - [`lease`]: one lease per node at `nodes/{id}`, renewed by CAS, judged
//!     on each node's own monotonic clock (vlpds's model). Bucket writes
//!     every renewal.
//!   - [`peers`]: heartbeats between members with vlRelay's quorum rules.
//!     No bucket requests.
//! - [`rpc`]: the TCP request/response client vlRelay's quorum log and the
//!   heartbeats share.
//! - `chaos` (feature `chaos`): an object store that injects latency,
//!   errors and lost answers, and `peers::mem`, an in-memory network.
//!
//! Safety never rests on clocks: a wrong verdict costs a fence and a
//! fail-stop, never a position decided twice. Clocks decide only when.

pub mod alive;
pub mod cas;
#[cfg(any(test, feature = "chaos"))]
pub mod chaos;
pub mod epoch;
pub mod lease;
pub mod peers;
pub mod rpc;
pub mod table;
pub mod topology;

pub use alive::{Alive, Heard, Leases};
pub use cas::Versioned;
pub use lease::{Holder, LeaseConfig, Membership, NodeLease, Observer};
pub use peers::{PeerConfig, Peers};
pub use table::{Assignment, Member, Span, Table};
pub use topology::Topology;
