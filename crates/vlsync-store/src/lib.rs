//! The storage layer vlpds, vlRelay and delta share: the S3/R2 client with
//! per-component request accounting, in-flight limits and throttle counts
//! ([`store`]), the log segment format ([`segment`]) and the feature levels
//! that gate it ([`version`]), slots and slot-major SlateDB keys ([`slots`],
//! [`keys`]), and the process plumbing every vlsync server runs on
//! ([`lifecycle`], [`metrics`], [`secret_file`]).
#![allow(clippy::type_complexity)]

pub mod keys;
pub mod lifecycle;
pub mod metrics;
pub mod objlimit;
pub mod objstats;
pub mod secret_file;
pub mod segment;
pub mod slots;
pub mod store;
pub mod store_stats;
pub mod throttle;
pub mod version;
