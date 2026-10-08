//! A node log in the bucket, as its readers see it: one log per writer
//! incarnation (`log_id`), its segments at `log/{log_id}/{ordinal:012}.seg`
//! (created with If-None-Match on dense ordinals) and closed by a fence, the
//! seqs its writer assigns, and the `retain/{log_id}` reports that bound
//! what retention deleted. vlpds's node log (src/nodelog.rs) and vlRelay's
//! qlog both write this layout; the firehose and backfill read it.

use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path;
use object_store::ObjectStoreExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use vlsync_store::segment::{self, LogObject};
use vlsync_store::slots::ShardId;
use vlsync_store::store::Store;

/// Durable, ordered events from one log, handed to the firehose merger.
#[derive(Clone)]
pub struct LogBatch {
    pub log_id: Arc<str>,
    pub ordinal: u64,
    pub events: Vec<(i64, Bytes)>,
}

pub fn seq_floor(now_us: u64) -> i64 {
    (now_us as i64) << 8
}

/// The highest seq <= `v` carrying `writer` in its low byte: as `assigned`, it
/// makes the next seq (>= it + 256) exceed `v` and keep the writer byte.
fn own_seq_at_or_below(v: i64, writer: u8) -> i64 {
    let wr = writer as i64;
    if v & 0xff >= wr {
        (v & !0xff) | wr
    } else {
        ((v & !0xff) - 256) | wr
    }
}

/// Every event with seq <= `get()` is durable and has been handed to the merger.
pub struct Watermark {
    writer: u8,
    inner: Mutex<(i64, i64)>, // (assigned, durable)
    cap: std::sync::atomic::AtomicI64,
}

impl Watermark {
    pub fn new(writer: u8, last: i64) -> Watermark {
        Watermark {
            writer,
            inner: Mutex::new((own_seq_at_or_below(last, writer), last)),
            cap: std::sync::atomic::AtomicI64::new(i64::MAX),
        }
    }

    /// Time-based, strictly increasing; the low byte is this node's writer id
    /// (unique among live nodes), so seqs are unique across logs.
    pub fn assign(&self) -> i64 {
        let mut w = self.inner.lock();
        let now = seq_floor(vlsync_atproto::tid::now_micros()) | self.writer as i64;
        let seq = now.max(w.0 + 256);
        w.0 = seq;
        seq
    }

    pub fn set_durable(&self, seq: i64) {
        self.inner.lock().1 = seq;
    }

    pub fn idle(&self) -> bool {
        let w = self.inner.lock();
        w.0 <= w.1
    }

    pub fn get(&self) -> i64 {
        let mut w = self.inner.lock();
        if w.0 > w.1 {
            return w.1;
        }
        let v =
            w.1.max(seq_floor(vlsync_atproto::tid::now_micros()) - 1).min(self.cap.load(Ordering::Acquire).max(w.1));
        if v > w.1 {
            // Idle: we advertise the clock. Record it, so a later seq can't land
            // at or below it if the wall clock steps back (assign() is
            // max(now, last + 256)); the merger would drop such events as late.
            w.0 = w.0.max(own_seq_at_or_below(v, self.writer));
            w.1 = v;
        }
        v
    }

    /// Never announce beyond our node lease: a successor's seqs start after it.
    pub fn set_lease_expiry(&self, expiry_us: u64) {
        self.cap.store(seq_floor(expiry_us), Ordering::Release);
    }
}

pub fn segment_path(store: &Store, log_id: &str, ordinal: u64) -> Path {
    Path::from(format!("{}/log/{}/{:012}.seg", store.prefix, log_id, ordinal))
}

/// What occupies one ordinal of a log.
#[derive(Debug)]
pub enum Head {
    Missing,
    Fence,
    Segment(segment::SegHeader),
}

/// Errs unless a segment header names the log and ordinal it was read from.
pub fn check_header(h: &segment::SegHeader, log_id: &str, ordinal: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        h.log_id == log_id && h.ordinal == ordinal,
        "log object {log_id}/{ordinal} has header {}/{}",
        h.log_id,
        h.ordinal
    );
    Ok(())
}

/// The header of the object at `log_id/ordinal`, via one small range GET.
pub async fn read_head(store: &Store, log_id: &str, ordinal: u64) -> anyhow::Result<Head> {
    use object_store::{GetOptions, GetRange};
    let opts = GetOptions { range: Some(GetRange::Bounded(0..4096)), ..Default::default() };
    let data = match store.raw.get_opts(&segment_path(store, log_id, ordinal), opts).await {
        Ok(r) => r.bytes().await?,
        Err(object_store::Error::NotFound { .. }) => return Ok(Head::Missing),
        Err(e) => return Err(e.into()),
    };
    let Some((h, _)) = segment::parse_header(&data)? else { return Ok(Head::Fence) };
    check_header(&h, log_id, ordinal)?;
    Ok(Head::Segment(h))
}

/// The object at `log_id/ordinal`, parsed without muts (None = missing).
pub async fn read_object(store: &Store, log_id: &str, ordinal: u64) -> anyhow::Result<Option<LogObject>> {
    let data = match store.raw.get(&segment_path(store, log_id, ordinal)).await {
        Ok(r) => r.bytes().await?,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let obj = segment::parse(data, false, None)?;
    if let LogObject::Segment(h, _) = &obj {
        check_header(h, log_id, ordinal)?;
    }
    Ok(Some(obj))
}

/// The first ordinal below segment `h` that isn't a segment (missing, or a
/// fence), or None if `h` is inside its log's gap-free prefix. Only
/// [h.prefix_end, h.ordinal) needs probing (at most K - 1 small GETs): the
/// writer had every ordinal below prefix_end durable when it sealed `h`.
/// A segment past a hole is garbage (never acked: acks are in order), and
/// past a fence it can only be a zombie's. Ordinals below `floor` (the
/// lowest still stored: retention prunes a log's head) aren't probed.
pub async fn prefix_hole(store: &Store, h: &segment::SegHeader, floor: u64) -> anyhow::Result<Option<u64>> {
    for ord in h.prefix_end.max(floor)..h.ordinal {
        if !matches!(read_head(store, &h.log_id, ord).await?, Head::Segment(_)) {
            return Ok(Some(ord));
        }
    }
    Ok(None)
}

/// The end of `log_id`'s durable prefix: its first ordinal that isn't a
/// segment, and whether a fence is there already. Every segment below it
/// exists; everything above it is garbage (or, on a live log, not acked yet).
/// Probes the highest segment's header and its prefix_end window, so it
/// costs one LIST plus a few small GETs however long the log is.
pub async fn first_free(store: &Store, log_id: &str) -> anyhow::Result<(u64, bool)> {
    use futures::StreamExt;
    let prefix = Path::from(format!("{}/log/{}", store.prefix, log_id));
    let mut listed = Vec::new();
    let mut list = store.raw.list(Some(&prefix));
    while let Some(meta) = list.next().await {
        if let Some(ord) =
            meta?.location.filename().and_then(|f| f.strip_suffix(".seg")).and_then(|f| f.parse::<u64>().ok())
        {
            listed.push(ord);
        }
    }
    listed.sort_unstable();
    // the highest segment: everything listed above it is a fence (or gone).
    // With none (retention pruned a dead log down to its fence) the end is
    // the lowest object left.
    let mut free = listed.first().copied().unwrap_or(0);
    for &ord in listed.iter().rev() {
        if let Head::Segment(h) = read_head(store, log_id, ord).await? {
            free = prefix_hole(store, &h, listed[0]).await?.unwrap_or(ord + 1);
            break;
        }
    }
    let fenced = matches!(read_head(store, log_id, free).await?, Head::Fence);
    Ok((free, fenced))
}

/// `retain/{log_id}`, written by that log's owner.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Report {
    /// shard -> highest epoch the log's owner opened it at
    pub opened: BTreeMap<ShardId, u64>,
    /// highest seq deleted by this node (including reports of dead logs it
    /// folded in when it deleted them)
    pub pruned_seq: i64,
    /// The test feature level's field (DESIGN.md "Migrations"): a lower
    /// bound on the segment level of the log's unpruned segments. Written
    /// only while that level is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_seg_format: Option<u32>,
}

impl Report {
    pub fn new(opened: BTreeMap<ShardId, u64>, pruned_seq: i64, log_level: u32) -> Report {
        Report { opened, pruned_seq, min_seg_format: vlsync_store::version::test_level_active().then_some(log_level) }
    }
}

pub fn report_path(store: &Store, log_id: &str) -> Path {
    Path::from(format!("{}/retain/{}", store.prefix, log_id))
}

/// Every retention report, by log id.
pub async fn read_reports(store: &Store) -> anyhow::Result<HashMap<String, Report>> {
    Ok(read_json_dir(store, "retain", |name| Some(name.to_string()), 16).await?.into_iter().collect())
}

/// Every JSON object directly under `{prefix}/{dir}/` whose name `key`
/// accepts, read `concurrency` at a time (objects gone meanwhile skipped).
pub async fn read_json_dir<K: Send, T: serde::de::DeserializeOwned>(
    store: &Store,
    dir: &str,
    key: impl Fn(&str) -> Option<K>,
    concurrency: usize,
) -> anyhow::Result<Vec<(K, T)>> {
    let prefix = Path::from(format!("{}/{dir}", store.prefix));
    let names: Vec<(K, Path)> = store
        .raw
        .list(Some(&prefix))
        .filter_map(|m| {
            let k = m.ok().and_then(|m| Some((key(m.location.filename()?)?, m.location)));
            async move { k }
        })
        .collect()
        .await;
    let got: Vec<anyhow::Result<Option<(K, T)>>> = futures::stream::iter(names)
        .map(|(k, path)| async move {
            match store.raw.get(&path).await {
                Ok(r) => Ok(Some((k, serde_json::from_slice(&r.bytes().await?)?))),
                Err(object_store::Error::NotFound { .. }) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    got.into_iter().filter_map(Result::transpose).collect()
}

/// The retained floor: every event deleted from any log has seq <= this,
/// so a cursor at or past it is served in full. Raised before each delete.
pub async fn retained_floor(store: &Store) -> anyhow::Result<i64> {
    Ok(read_reports(store).await?.values().map(|r| r.pruned_seq).max().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An idle watermark advertises the clock; after the clock steps back,
    /// new seqs must still land above what was advertised.
    #[test]
    fn idle_watermark_is_monotonic_across_clock_steps() {
        let writer = 9u8;
        let wm = Watermark::new(writer, seq_floor(vlsync_atproto::tid::now_micros()));
        let advertised = wm.get();
        assert!(wm.idle());
        vlsync_atproto::tid::set_test_skew_us(-5_000_000);
        let seq = wm.assign();
        vlsync_atproto::tid::set_test_skew_us(0);
        assert!(seq > advertised, "seq {seq} <= advertised watermark {advertised}");
        assert_eq!(seq & 0xff, writer as i64);
        assert!(!wm.idle());
        assert!(wm.get() < seq);
        wm.set_durable(seq);
        assert!(wm.get() >= seq);
        // a log started with the clock ahead of its first seq keeps the writer byte
        let wm = Watermark::new(writer, seq_floor(vlsync_atproto::tid::now_micros() + 1_000_000));
        assert_eq!(wm.assign() & 0xff, writer as i64);
        // the bump keeps the writer byte under a lease cap that ends in 0x00
        let wm = Watermark::new(writer, 0);
        wm.set_lease_expiry(vlsync_atproto::tid::now_micros() - 1_000_000);
        let capped = wm.get();
        assert!(wm.idle());
        vlsync_atproto::tid::set_test_skew_us(-60_000_000);
        let seq = wm.assign();
        vlsync_atproto::tid::set_test_skew_us(0);
        assert!(seq > capped && seq & 0xff == writer as i64);
    }
}
