//! Firehose frames and commit objects, encoded straight to DAG-CBOR bytes.
//!
//! A frame is built without its `seq` (split into `prefix` and `suffix` around
//! the "seq" map entry, which sorts in the middle of every event body), so CPU
//! workers do the encoding and the partition sequencer just splices the seq in.

use crate::cbor::*;
use crate::cid::Cid;
use prometheus::{register_int_counter_vec, IntCounterVec};

vlsync_store::lazy!(IDENTITY_EVENTS: IntCounterVec = register_int_counter_vec!("vlpds_identity_events_total", "#identity and #account firehose events built (new accounts, handle changes, status changes), by kind", &["kind"]));

#[derive(Clone, Debug)]
pub struct Frame {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    /// How many of the log entry's leading mutations replay rebuilds from
    /// this #commit frame (vlpds's `derived::derive_commit_muts`), so the segment
    /// doesn't store them twice. 0 = all stored.
    pub derived_muts: usize,
    /// The repo generation the derived muts' keys carry (`state::Gen`).
    pub derived_gen: u64,
}

impl Frame {
    pub fn finish(&self, seq: i64, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.prefix);
        write_text(out, "seq");
        write_int(out, seq);
        out.extend_from_slice(&self.suffix);
    }

    pub fn len_hint(&self) -> usize {
        self.prefix.len() + self.suffix.len() + 14
    }
}

fn header(out: &mut Vec<u8>, t: &str) {
    write_map_head(out, 2);
    write_text(out, "t");
    write_text(out, t);
    write_text(out, "op");
    write_uint(out, 1);
}

pub struct RepoOp<'a> {
    pub action: &'a str,
    pub path: &'a str,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

pub struct CommitFrame<'a> {
    pub repo: &'a str,
    pub rev: &'a str,
    pub since: Option<&'a str>,
    pub commit: Cid,
    pub prev_data: Option<Cid>,
    pub blocks: &'a [u8],
    pub ops: &'a [RepoOp<'a>],
    pub time: &'a str,
}

/// `#commit`. Body keys in canonical order:
/// ops rev seq repo time blobs since blocks commit rebase tooBig prevData
pub fn commit_frame(c: &CommitFrame) -> Frame {
    // sized to fit (a realloc of the suffix copies the whole CAR again)
    let ops_len: usize = c.ops.iter().map(|op| 128 + op.path.len()).sum();
    let mut p = Vec::with_capacity(48 + c.rev.len() + ops_len);
    header(&mut p, "#commit");
    write_map_head(&mut p, if c.prev_data.is_some() { 12 } else { 11 });
    write_text(&mut p, "ops");
    write_array_head(&mut p, c.ops.len());
    for op in c.ops {
        // keys: cid path prev action
        write_map_head(&mut p, if op.prev.is_some() { 4 } else { 3 });
        write_text(&mut p, "cid");
        write_opt_cid(&mut p, op.cid.as_ref());
        write_text(&mut p, "path");
        write_text(&mut p, op.path);
        if let Some(prev) = &op.prev {
            write_text(&mut p, "prev");
            write_cid(&mut p, prev);
        }
        write_text(&mut p, "action");
        write_text(&mut p, op.action);
    }
    write_text(&mut p, "rev");
    write_text(&mut p, c.rev);

    let mut s = Vec::with_capacity(c.blocks.len() + 192 + c.repo.len() + c.time.len() + c.since.map_or(0, str::len));
    write_text(&mut s, "repo");
    write_text(&mut s, c.repo);
    write_text(&mut s, "time");
    write_text(&mut s, c.time);
    write_text(&mut s, "blobs");
    write_array_head(&mut s, 0);
    write_text(&mut s, "since");
    match c.since {
        Some(v) => write_text(&mut s, v),
        None => write_null(&mut s),
    }
    write_text(&mut s, "blocks");
    write_bytes(&mut s, c.blocks);
    write_text(&mut s, "commit");
    write_cid(&mut s, &c.commit);
    write_text(&mut s, "rebase");
    write_bool(&mut s, false);
    write_text(&mut s, "tooBig");
    write_bool(&mut s, false);
    if let Some(pd) = &c.prev_data {
        write_text(&mut s, "prevData");
        write_cid(&mut s, pd);
    }
    Frame { prefix: p, suffix: s, derived_muts: 0, derived_gen: 0 }
}

/// `#sync`: did rev seq time blocks
pub fn sync_frame(did: &str, rev: &str, blocks: &[u8], time: &str) -> Frame {
    let mut p = Vec::with_capacity(96);
    header(&mut p, "#sync");
    write_map_head(&mut p, 5);
    write_text(&mut p, "did");
    write_text(&mut p, did);
    write_text(&mut p, "rev");
    write_text(&mut p, rev);
    let mut s = Vec::with_capacity(blocks.len() + 48);
    write_text(&mut s, "time");
    write_text(&mut s, time);
    write_text(&mut s, "blocks");
    write_bytes(&mut s, blocks);
    Frame { prefix: p, suffix: s, derived_muts: 0, derived_gen: 0 }
}

/// `#identity`: did seq time handle
pub fn identity_frame(did: &str, handle: &str, time: &str) -> Frame {
    IDENTITY_EVENTS.with_label_values(&["identity"]).inc();
    let mut p = Vec::with_capacity(96);
    header(&mut p, "#identity");
    write_map_head(&mut p, 4);
    write_text(&mut p, "did");
    write_text(&mut p, did);
    let mut s = Vec::with_capacity(96);
    write_text(&mut s, "time");
    write_text(&mut s, time);
    write_text(&mut s, "handle");
    write_text(&mut s, handle);
    Frame { prefix: p, suffix: s, derived_muts: 0, derived_gen: 0 }
}

/// `#account`: did seq time active [status]
pub fn account_frame(did: &str, active: bool, status: Option<&str>, time: &str) -> Frame {
    IDENTITY_EVENTS.with_label_values(&["account"]).inc();
    let mut p = Vec::with_capacity(96);
    header(&mut p, "#account");
    write_map_head(&mut p, if status.is_some() { 5 } else { 4 });
    write_text(&mut p, "did");
    write_text(&mut p, did);
    let mut s = Vec::with_capacity(64);
    write_text(&mut s, "time");
    write_text(&mut s, time);
    write_text(&mut s, "active");
    write_bool(&mut s, active);
    if let Some(st) = status {
        write_text(&mut s, "status");
        write_text(&mut s, st);
    }
    Frame { prefix: p, suffix: s, derived_muts: 0, derived_gen: 0 }
}

/// Error frame header `{op: -1}` + body `{error, message}`.
pub fn error_frame(error: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_map_head(&mut out, 1);
    write_text(&mut out, "op");
    write_int(&mut out, -1);
    write_map_head(&mut out, 2);
    write_text(&mut out, "error");
    write_text(&mut out, error);
    write_text(&mut out, "message");
    write_text(&mut out, message);
    out
}

/// Commit object, unsigned (for signing) or signed.
/// Keys in canonical order: did rev sig data prev version
pub fn encode_commit(did: &str, rev: &str, data: &Cid, sig: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    write_map_head(&mut out, if sig.is_some() { 6 } else { 5 });
    write_text(&mut out, "did");
    write_text(&mut out, did);
    write_text(&mut out, "rev");
    write_text(&mut out, rev);
    if let Some(sig) = sig {
        write_text(&mut out, "sig");
        write_bytes(&mut out, sig);
    }
    write_text(&mut out, "data");
    write_cid(&mut out, data);
    write_text(&mut out, "prev");
    write_null(&mut out);
    write_text(&mut out, "version");
    write_uint(&mut out, 3);
    out
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
