//! The read side of node logs: their layout in the bucket ([`log`]), the
//! firehose merging them into one seq-ordered subscribeRepos stream
//! ([`firehose`]), and cursor backfill from S3 ([`backfill`]).
#![allow(clippy::type_complexity)]

pub mod backfill;
pub mod firehose;
pub mod log;
pub mod metrics;
