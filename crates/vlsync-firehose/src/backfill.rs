//! Firehose cursor backfill from S3 segments.
//!
//! A subscriber whose cursor is older than the in-memory ring is served by
//! reading the node logs straight from S3: for each log, find the first
//! segment past the cursor (exponential probe + binary search on segment
//! headers), stream its segments, and k-way merge every log by seq. The
//! merged order equals the live merger's order (both are "by seq"), so the
//! subscriber sees one continuous stream when it hands off to the ring.
//!
//! Each log reads ahead (several segment GETs in flight, bounded by bytes)
//! through a segment cache shared by every subscriber, and stops at the
//! first ordinal that isn't a segment (the hole rule, DESIGN.md).

use crate::log::{check_header, prefix_hole, read_head, segment_path, Head};
use crate::metrics;
use bytes::Bytes;
use object_store::path::Path;
use object_store::ObjectStoreExt;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, OnceCell};
use tokio::task::JoinHandle;
use vlsync_store::segment::{self, LogObject};
use vlsync_store::slots::SlotRange;
use vlsync_store::store::Store;

/// (first, last) seq of a segment, or None if missing / a fence.
async fn seg_header(store: &Store, log_id: &str, ordinal: u64) -> anyhow::Result<Option<(i64, i64)>> {
    Ok(match read_head(store, log_id, ordinal).await? {
        Head::Segment(h) => Some((h.first_seq, h.last_seq)),
        Head::Missing | Head::Fence => None,
    })
}

pub async fn list_logs(store: &Store) -> anyhow::Result<Vec<String>> {
    let prefix = Path::from(format!("{}/log", store.prefix));
    let r = store.raw.list_with_delimiter(Some(&prefix)).await?;
    Ok(r.common_prefixes.iter().filter_map(|p| p.filename().map(String::from)).collect())
}

/// Retention deleted segments a reader was about to read.
#[derive(Debug, thiserror::Error)]
#[error("log {log_id} was pruned past ordinal {ordinal} while being read")]
pub struct Pruned {
    pub log_id: String,
    pub ordinal: u64,
}

/// A non-segment at `ordinal` that retention made: it is below the lowest
/// object left in the log (a hole or a fence never is).
async fn pruned_at(store: &Store, log_id: &str, ordinal: u64) -> anyhow::Result<Option<Pruned>> {
    Ok(first_ordinal(store, log_id)
        .await?
        .is_none_or(|f| f > ordinal)
        .then(|| Pruned { log_id: log_id.to_string(), ordinal }))
}

/// First ordinal of `log_id` whose segment has events with seq > `after`
/// (None if the log has nothing past it).
///
/// Retention deletes logs oldest first, and the logs a cursor seeks are
/// mostly ones it is deleting: dead logs and live logs' heads, wholly below
/// the cursor. A delete landing between the seek's LIST and its header reads
/// makes them miss (`Pruned`). If the retained floor (raised before every
/// delete) is still at or below `after`, nothing past `after` went: seek
/// again from the new lowest object. Otherwise the reader really is behind
/// the floor and the caller sends OutdatedCursor.
async fn first_ordinal_after(store: &Store, log_id: &str, after: i64) -> anyhow::Result<Option<u64>> {
    let mut tries = 0;
    loop {
        match seek_once(store, log_id, after).await {
            Err(e) if e.downcast_ref::<Pruned>().is_some() && tries < MAX_SEEK_RETRIES => {
                if crate::log::retained_floor(store).await? > after {
                    return Err(e);
                }
                tries += 1;
                metrics::FIREHOSE_BACKFILL_RETRIES.with_label_values(&["seek"]).inc();
            }
            r => return r,
        }
    }
}

/// Each retry needs a new delete, so this is a bound, not a budget.
const MAX_SEEK_RETRIES: u32 = 16;

async fn seek_once(store: &Store, log_id: &str, after: i64) -> anyhow::Result<Option<u64>> {
    let o = seek(store, log_id, after).await?;
    if seg_header(store, log_id, o).await?.is_some() {
        return Ok(Some(o));
    }
    match pruned_at(store, log_id, o).await? {
        Some(p) => Err(p.into()),
        None => Ok(None),
    }
}

/// The lowest ordinal of `log_id` still in the store (None = no objects).
/// Listings are lexicographic and ordinals zero-padded, so the first key
/// listed is the lowest.
pub async fn first_ordinal(store: &Store, log_id: &str) -> anyhow::Result<Option<u64>> {
    use futures::StreamExt;
    let prefix = Path::from(format!("{}/log/{}", store.prefix, log_id));
    let mut list = store.raw.list(Some(&prefix));
    while let Some(meta) = list.next().await {
        let meta = meta?;
        if let Some(ord) =
            meta.location.filename().and_then(|f| f.strip_suffix(".seg")).and_then(|f| f.parse::<u64>().ok())
        {
            return Ok(Some(ord));
        }
    }
    Ok(None)
}

/// First ordinal of `log_id`'s durable prefix that is missing (not written
/// yet, or the fence) or whose segment has events with seq > `after`. Seqs
/// increase with the ordinal, so everything before it is <= `after`.
///
/// The probes below assume "present" is monotone, which holes break: with K
/// PUTs in flight a crash leaves segments past the first hole (garbage, never
/// acked, cut off by the fence there), and the search can land past the hole
/// on one of them. So the answer is checked against the prefix rule: the
/// segment before it must be in the gap-free prefix, else the hole is the
/// answer (a reader stops there). Skipping garbage <= `after` is harmless;
/// reading garbage > `after` would emit events nobody acked.
pub async fn seek(store: &Store, log_id: &str, after: i64) -> anyhow::Result<u64> {
    let base = first_ordinal(store, log_id).await?.unwrap_or(0);
    let o = seek_unchecked(store, log_id, base, after).await?;
    if o == base {
        return Ok(o);
    }
    // the search saw o - 1 as a segment <= after
    match read_head(store, log_id, o - 1).await? {
        Head::Segment(h) => Ok(prefix_hole(store, &h, base).await?.unwrap_or(o)),
        Head::Missing | Head::Fence => match pruned_at(store, log_id, o - 1).await? {
            Some(p) => Err(p.into()),
            None => anyhow::bail!("log {log_id}: segment {} vanished", o - 1),
        },
    }
}

async fn seek_unchecked(store: &Store, log_id: &str, base: u64, after: i64) -> anyhow::Result<u64> {
    // exponential probe for an upper bound (first missing ordinal or a segment past `after`)
    match seg_header(store, log_id, base).await? {
        Some((_, last0)) if last0 <= after => {}
        _ => return Ok(base),
    }
    let (mut lo, mut hi) = (base, base + 1); // invariant: seg(lo).last <= after
    loop {
        match seg_header(store, log_id, hi).await? {
            Some((_, last)) if last <= after => {
                lo = hi;
                hi = base + (hi - base) * 2;
            }
            _ => break,
        }
    }
    // binary search in (lo, hi]: first ordinal that is missing or has last > after
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match seg_header(store, log_id, mid).await? {
            Some((_, last)) if last <= after => lo = mid,
            _ => hi = mid,
        }
    }
    Ok(hi)
}

/// A parsed segment's events, sharing the GET body.
pub struct Seg {
    pub events: Vec<(i64, Bytes)>,
    /// decompressed object size
    pub bytes: usize,
    /// Computed by the first sharded reader.
    slots: std::sync::OnceLock<Vec<u16>>,
}

impl Seg {
    fn slot(&self, i: usize) -> u16 {
        self.slots.get_or_init(|| self.events.iter().map(|(_, f)| crate::firehose::event_slot(f)).collect())[i]
    }
}

#[derive(Clone)]
enum Fetched {
    Seg(Arc<Seg>),
    /// Missing or a fence: the end of the durable prefix (the hole rule):
    /// a reader stops here and ignores every later ordinal.
    End,
}

/// Recently read segments, shared by every backfill reader of one store so
/// subscribers replaying the same range GET each segment once. Segments are
/// immutable once written, so a cached one never goes stale; missing
/// ordinals and fences aren't cached (a missing one may still land).
/// Bounded by decompressed bytes, evicted oldest first (replays are
/// sequential).
pub struct SegCache {
    max_bytes: usize,
    inner: parking_lot::Mutex<CacheInner>,
}

/// (log id, ordinal)
type SegKey = (Arc<str>, u64);

#[derive(Default)]
struct CacheInner {
    map: HashMap<SegKey, Arc<OnceCell<Arc<Seg>>>>,
    /// loaded entries, oldest first, with their sizes
    order: VecDeque<(SegKey, usize)>,
    bytes: usize,
}

impl SegCache {
    pub fn new(max_bytes: usize) -> Arc<SegCache> {
        Arc::new(SegCache { max_bytes, inner: Default::default() })
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().bytes
    }

    async fn get(&self, store: &Store, log_id: &Arc<str>, ordinal: u64) -> anyhow::Result<Fetched> {
        if self.max_bytes == 0 {
            return fetch(store, log_id, ordinal).await;
        }
        let key = (log_id.clone(), ordinal);
        let cell = self.inner.lock().map.entry(key.clone()).or_default().clone();
        if let Some(seg) = cell.get() {
            metrics::FIREHOSE_BACKFILL_CACHE.with_label_values(&["hit"]).inc();
            return Ok(Fetched::Seg(seg.clone()));
        }
        // Err(None) = not a segment (nothing to cache)
        let mut loaded = false;
        let r = cell
            .get_or_try_init(|| async {
                loaded = true;
                match fetch(store, log_id, ordinal).await {
                    Ok(Fetched::Seg(s)) => Ok(s),
                    Ok(Fetched::End) => Err(None),
                    Err(e) => Err(Some(e)),
                }
            })
            .await
            .cloned();
        metrics::FIREHOSE_BACKFILL_CACHE.with_label_values(&[if loaded { "miss" } else { "hit" }]).inc();
        let mut inner = self.inner.lock();
        match r {
            Ok(seg) => {
                if loaded {
                    inner.bytes += seg.bytes;
                    inner.order.push_back((key, seg.bytes));
                    while inner.bytes > self.max_bytes {
                        let Some((k, n)) = inner.order.pop_front() else { break };
                        inner.bytes -= n;
                        inner.map.remove(&k);
                    }
                }
                Ok(Fetched::Seg(seg))
            }
            Err(e) => {
                // forget the empty cell unless someone else is still loading it
                if Arc::strong_count(&cell) <= 2 {
                    if let Some(c) = inner.map.get(&key) {
                        if Arc::ptr_eq(c, &cell) && c.get().is_none() {
                            inner.map.remove(&key);
                        }
                    }
                }
                match e {
                    None => Ok(Fetched::End),
                    Some(e) => Err(e),
                }
            }
        }
    }

    /// Drops empty cells nobody is loading (reads cancelled mid-GET).
    fn purge(&self) {
        let mut inner = self.inner.lock();
        if inner.map.len() > inner.order.len() + 1024 {
            inner.map.retain(|_, c| c.get().is_some() || Arc::strong_count(c) > 1);
        }
    }
}

async fn fetch(store: &Store, log_id: &str, ordinal: u64) -> anyhow::Result<Fetched> {
    let data = match store.raw.get(&segment_path(store, log_id, ordinal)).await {
        Ok(r) => r.bytes().await?,
        Err(object_store::Error::NotFound { .. }) => return Ok(Fetched::End),
        Err(e) => return Err(e.into()),
    };
    metrics::FIREHOSE_BACKFILL_GETS.inc();
    // the cache and read-ahead hold the decompressed object (frames are
    // slices of it), so that's what they count
    let data = segment::decode(data)?;
    let bytes = data.len();
    match segment::parse(data, false, None)? {
        LogObject::Fence { .. } => Ok(Fetched::End),
        LogObject::Segment(h, entries) => {
            check_header(&h, log_id, ordinal)?;
            Ok(Fetched::Seg(Arc::new(Seg { events: segment::events(entries), bytes, slots: Default::default() })))
        }
    }
}

#[derive(Clone)]
pub struct Reader {
    pub store: Store,
    pub cache: Arc<SegCache>,
    /// Per backfill (all logs together), in decompressed object bytes.
    pub readahead_bytes: usize,
    /// Only events whose repo is in this slot range.
    pub shard: Option<SlotRange>,
}

impl Reader {
    /// A reader with its own cache and the default read-ahead.
    pub fn new(store: Store) -> Reader {
        Reader {
            store,
            cache: SegCache::new(DEFAULT_CACHE_BYTES),
            readahead_bytes: DEFAULT_READAHEAD_BYTES,
            shard: None,
        }
    }
}

pub const DEFAULT_READAHEAD_BYTES: usize = 64 << 20;
pub const DEFAULT_CACHE_BYTES: usize = 256 << 20;

/// GETs in flight per log, however small its segments.
const MAX_AHEAD: usize = 32;

/// Aborts a read-ahead GET nobody will consume.
struct Ahead(JoinHandle<anyhow::Result<Fetched>>);

impl Drop for Ahead {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One log's read position: the segment being merged plus GETs in flight
/// for the following ordinals, consumed in ordinal order. The first
/// non-segment ends the log (the hole rule): GETs past it are dropped
/// unread, so segments a crash left beyond a hole are never served.
struct LogCursor {
    log_id: Arc<str>,
    /// next ordinal to request
    next: u64,
    ahead: VecDeque<(u64, Ahead)>,
    seg: Option<Arc<Seg>>,
    pos: usize,
    /// saw the end of the prefix: request nothing more
    end: bool,
    /// segments read and their total size (the mean sizes the read-ahead)
    reads: usize,
    read_bytes: usize,
}

impl LogCursor {
    fn new(log_id: String, ordinal: u64) -> LogCursor {
        LogCursor {
            log_id: log_id.into(),
            next: ordinal,
            ahead: VecDeque::new(),
            seg: None,
            pos: 0,
            end: false,
            reads: 0,
            read_bytes: 0,
        }
    }

    fn head(&self) -> Option<&(i64, Bytes)> {
        self.seg.as_ref().and_then(|s| s.events.get(self.pos))
    }

    fn wanted(&self, r: &Reader) -> bool {
        match (&r.shard, &self.seg) {
            (Some(range), Some(s)) => range.contains(s.slot(self.pos)),
            _ => true,
        }
    }

    /// Keeps GETs in flight: at least one, then while the in-flight bytes
    /// (estimated from the sizes seen so far) fit in `budget`. Until a
    /// segment has been read there's no estimate, so just the one: a relay's
    /// segments run to tens of MB, and `MAX_AHEAD` of them is gigabytes.
    fn top_up(&mut self, r: &Reader, budget: usize) {
        let avg = self.read_bytes.checked_div(self.reads).unwrap_or(budget).max(1);
        while !self.end
            && self.ahead.len() < MAX_AHEAD
            && (self.ahead.is_empty() || (self.ahead.len() + 1) * avg <= budget)
        {
            let (r, log_id, ord) = (r.clone(), self.log_id.clone(), self.next);
            self.ahead.push_back((ord, Ahead(tokio::spawn(async move { r.cache.get(&r.store, &log_id, ord).await }))));
            self.next += 1;
        }
    }

    /// Advances to the next event with seq > `after` (that the reader's shard
    /// filter takes), reading segments as needed; None once the log's
    /// durable prefix is exhausted.
    async fn advance(&mut self, r: &Reader, budget: usize, after: i64) -> anyhow::Result<Option<i64>> {
        loop {
            if let Some((seq, _)) = self.head() {
                if *seq > after && self.wanted(r) {
                    return Ok(Some(*seq));
                }
                self.pos += 1;
                continue;
            }
            self.seg = None;
            self.top_up(r, budget);
            let Some((ord, mut a)) = self.ahead.pop_front() else { return Ok(None) };
            match (&mut a.0).await?? {
                Fetched::Seg(s) => {
                    self.reads += 1;
                    self.read_bytes += s.bytes;
                    // skip what's <= after with a binary search (seqs ascend)
                    self.pos = s.events.partition_point(|(seq, _)| *seq <= after);
                    self.seg = Some(s);
                }
                Fetched::End => {
                    self.end = true;
                    self.ahead.clear(); // past the hole: never read
                                        // not the end of the log: retention deleted it under us
                    if let Some(p) = pruned_at(&r.store, &self.log_id, ord).await? {
                        return Err(p.into());
                    }
                    return Ok(None);
                }
            }
            self.top_up(r, budget);
        }
    }
}

/// Sends every event with `after < seq <= until`, in seq order, across all
/// logs (a seq seen twice is sent once). Returns the last seq sent (or
/// `after`).
pub async fn backfill(store: &Store, after: i64, until: i64, tx: &mpsc::Sender<(i64, Bytes)>) -> anyhow::Result<i64> {
    backfill_with(&Reader::new(store.clone()), after, until, tx).await
}

pub async fn backfill_with(r: &Reader, after: i64, until: i64, tx: &mpsc::Sender<(i64, Bytes)>) -> anyhow::Result<i64> {
    r.cache.purge();
    let mut cursors = Vec::new();
    for log_id in list_logs(&r.store).await? {
        if let Some(ord) = first_ordinal_after(&r.store, &log_id, after).await? {
            cursors.push(LogCursor::new(log_id, ord));
        }
    }
    let budget = r.readahead_bytes / cursors.len().max(1);
    for c in cursors.iter_mut() {
        c.top_up(r, budget);
    }
    let mut heap = BinaryHeap::new();
    for (i, c) in cursors.iter_mut().enumerate() {
        if let Some(seq) = c.advance(r, budget, after).await? {
            heap.push(Reverse((seq, i)));
        }
    }
    let mut last = after;
    while let Some(Reverse((seq, i))) = heap.pop() {
        if seq > until {
            break;
        }
        let c = &mut cursors[i];
        let (s, frame) = c.head().cloned().expect("heap entry has an event");
        c.pos += 1;
        if s > last {
            if tx.send((s, frame)).await.is_err() {
                return Ok(last); // subscriber went away
            }
            last = s;
        }
        if let Some(next) = c.advance(r, budget, after).await? {
            heap.push(Reverse((next, i)));
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::PutPayload;
    use vlsync_store::segment::SegmentBuilder;

    async fn put_seg(store: &Store, log: &str, ord: u64, seq: i64) {
        let mut b = SegmentBuilder::new();
        b.push(seq, vlsync_store::slots::ShardId(0), 1, |o| o.extend_from_slice(b"frame"), &[]);
        let mut obj = b.header(log, ord);
        obj.extend_from_slice(&b.body);
        store.raw.put(&segment_path(store, log, ord), PutPayload::from(obj)).await.unwrap();
    }

    /// A crashed K-in-flight log: 0..=2, a fence at the hole 3, and garbage
    /// 4..=6 sealed while 3 was pending (prefix_end 3). The probes see 4 as
    /// "present, <= after" and must not land past the hole.
    #[tokio::test]
    async fn seek_never_lands_past_a_hole() {
        let store = Store::memory(None);
        for ord in 0..3u64 {
            put_seg(&store, "A", ord, 1000 + ord as i64).await;
        }
        store.raw.put(&segment_path(&store, "A", 3), PutPayload::from_bytes(segment::fence_object("B"))).await.unwrap();
        for ord in 4..7u64 {
            let mut b = SegmentBuilder::new();
            b.push(1000 + ord as i64, vlsync_store::slots::ShardId(0), 1, |o| o.extend_from_slice(b"garbage"), &[]);
            let mut obj = b.sealed_header("A", ord, 3);
            obj.extend_from_slice(&b.body);
            store.raw.put(&segment_path(&store, "A", ord), PutPayload::from(obj)).await.unwrap();
        }
        assert_eq!(seek(&store, "A", 1004).await.unwrap(), 3);
        assert_eq!(seek(&store, "A", 1001).await.unwrap(), 2);
        let (tx, mut rx) = mpsc::channel(64);
        assert_eq!(backfill(&store, 1000, i64::MAX, &tx).await.unwrap(), 1002);
        assert_eq!(backfill(&store, 1004, i64::MAX, &tx).await.unwrap(), 1004);
        drop(tx);
        let mut seqs = Vec::new();
        while let Some((s, _)) = rx.recv().await {
            seqs.push(s);
        }
        assert_eq!(seqs, vec![1001, 1002]);
        // the same log still open (3 in flight, not fenced): 3 is where readers stop
        store.raw.delete(&segment_path(&store, "A", 3)).await.unwrap();
        assert_eq!(seek(&store, "A", 1004).await.unwrap(), 3);
    }

    /// The first top-up, with no segment sizes seen yet, asks for one; once
    /// sizes are known it fills the budget.
    #[tokio::test]
    async fn read_ahead_waits_for_a_size_before_filling_the_budget() {
        let store = Store::memory(None);
        let r = Reader::new(store);
        let mut c = LogCursor::new("A".into(), 0);
        c.top_up(&r, 64 << 20);
        assert_eq!(c.ahead.len(), 1);
        c.reads = 1;
        c.read_bytes = 8 << 20;
        c.top_up(&r, 64 << 20);
        assert_eq!(c.ahead.len(), 8);
    }

    /// A log whose first segments were pruned is still found and read.
    #[tokio::test]
    async fn seek_starts_at_the_first_existing_segment() {
        let store = Store::memory(None);
        for ord in 5..12u64 {
            put_seg(&store, "A", ord, 1000 + ord as i64).await;
        }
        assert_eq!(first_ordinal(&store, "A").await.unwrap(), Some(5));
        assert_eq!(first_ordinal(&store, "B").await.unwrap(), None);
        assert_eq!(seek(&store, "A", 0).await.unwrap(), 5);
        assert_eq!(seek(&store, "A", 1007).await.unwrap(), 8);
        assert_eq!(seek(&store, "A", 5000).await.unwrap(), 12);
        let (tx, mut rx) = mpsc::channel(64);
        assert_eq!(backfill(&store, 1006, i64::MAX, &tx).await.unwrap(), 1011);
        drop(tx);
        let mut seqs = Vec::new();
        while let Some((s, _)) = rx.recv().await {
            seqs.push(s);
        }
        assert_eq!(seqs, (1007..=1011).collect::<Vec<_>>());
        // a segment stored under the wrong ordinal is an error, not data
        put_seg(&store, "A", 12, 2000).await;
        store
            .raw
            .put(
                &segment_path(&store, "A", 13),
                PutPayload::from(store.raw.get(&segment_path(&store, "A", 12)).await.unwrap().bytes().await.unwrap()),
            )
            .await
            .unwrap();
        let (tx, _rx) = mpsc::channel(64);
        assert!(backfill(&store, 1011, i64::MAX, &tx).await.is_err());
    }

    /// A segment of `seqs` (one event each), sealed with `prefix_end`.
    async fn put_multi(store: &Store, log: &str, ord: u64, prefix_end: u64, seqs: &[i64]) {
        let mut b = SegmentBuilder::new();
        for seq in seqs {
            b.push(
                *seq,
                vlsync_store::slots::ShardId(0),
                1,
                |o| o.extend_from_slice(format!("{log}:{seq}").as_bytes()),
                &[],
            );
        }
        let mut obj = b.sealed_header(log, ord, prefix_end);
        obj.extend_from_slice(&b.body);
        store.raw.put(&segment_path(store, log, ord), PutPayload::from(obj)).await.unwrap();
    }

    async fn collect(r: &Reader, after: i64, until: i64) -> (i64, Vec<(i64, Bytes)>) {
        let (tx, mut rx) = mpsc::channel(16);
        let job = {
            let r = r.clone();
            tokio::spawn(async move { backfill_with(&r, after, until, &tx).await })
        };
        let mut got = Vec::new();
        while let Some(e) = rx.recv().await {
            got.push(e);
        }
        (job.await.unwrap().unwrap(), got)
    }

    /// A small cache and read-ahead hold what they're given: across every
    /// log, the GETs in flight never total more than the read-ahead (or one
    /// segment per log when it's smaller than that), and the cache never
    /// keeps more than its size, at every step of a full replay.
    #[tokio::test]
    async fn small_cache_and_read_ahead_hold_their_limits() {
        let store = Store::memory(None);
        let (logs, segs, per_seg) = (["A", "B", "C"], 24u64, 8i64);
        for (l, log) in logs.iter().enumerate() {
            for ord in 0..segs {
                let mut b = SegmentBuilder::new();
                for j in 0..per_seg {
                    let seq = 1_000_000 + (ord as i64 * per_seg + j) * 3 + l as i64;
                    b.push(seq, vlsync_store::slots::ShardId(0), 1, |o| o.extend_from_slice(&[b'x'; 4096]), &[]);
                }
                let mut obj = b.header(log, ord);
                obj.extend_from_slice(&b.body);
                store.raw.put(&segment_path(&store, log, ord), PutPayload::from(obj)).await.unwrap();
            }
        }
        let mut sizes = std::collections::BTreeSet::new();
        for log in logs {
            for ord in 0..segs {
                let Fetched::Seg(s) = fetch(&store, log, ord).await.unwrap() else { panic!("{log}/{ord}") };
                sizes.insert(s.bytes);
            }
        }
        // equal sizes make the read-ahead's estimate exact
        assert_eq!(sizes.len(), 1, "{sizes:?}");
        let seg = *sizes.first().unwrap();
        let total = logs.len() * (segs as usize) * per_seg as usize;

        for (readahead, cache) in [(0, 0), (seg, 2 * seg), (3 * seg, 3 * seg), (12 * seg, 5 * seg + 1)] {
            let r =
                Reader { store: store.clone(), cache: SegCache::new(cache), readahead_bytes: readahead, shard: None };
            let mut cursors: Vec<LogCursor> = logs.iter().map(|l| LogCursor::new(l.to_string(), 0)).collect();
            let budget = readahead / cursors.len();
            let (mut sent, mut most) = (0, 0);
            loop {
                let mut progressed = false;
                for i in 0..cursors.len() {
                    if cursors[i].advance(&r, budget, -1).await.unwrap().is_some() {
                        cursors[i].pos += 1;
                        sent += 1;
                        progressed = true;
                    }
                    let in_flight: usize = cursors.iter().map(|c| c.ahead.len()).sum();
                    most = most.max(in_flight);
                    assert!(
                        in_flight * seg <= readahead.max(cursors.len() * seg),
                        "read-ahead {readahead}: {in_flight} segments of {seg} in flight"
                    );
                    assert!(r.cache.bytes() <= cache, "cache {cache}: holds {}", r.cache.bytes());
                }
                if !progressed {
                    break;
                }
            }
            assert_eq!(sent, total, "read-ahead {readahead}");
            if readahead >= 12 * seg {
                // the budget, not the one-segment floor, set the depth
                assert!(most > cursors.len(), "read-ahead {readahead}: at most {most} in flight");
            }
            let (_, got) = collect(&r, -1, i64::MAX).await;
            assert_eq!(got.len(), total);
            assert!(r.cache.bytes() <= cache);
        }
    }

    /// Read-ahead across three logs: the merge is in seq order with
    /// duplicates (the same seq in two logs) sent once; a log stops at its
    /// first hole (B: segments past it, already in flight, are dropped) or
    /// fence (C), whatever the read-ahead depth; and concurrent readers of
    /// the same range share the segment cache.
    #[tokio::test]
    async fn read_ahead_merges_in_order_and_stops_at_holes() {
        let store = Store::memory(None);
        let mut want = Vec::new();
        // A: 40 segments of 3 events, seqs 10*k + {0,3,6}
        for ord in 0..40u64 {
            let seqs: Vec<i64> = (0..3).map(|j| 10 * ord as i64 + 3 * j).collect();
            want.extend(seqs.iter().copied());
            put_multi(&store, "A", ord, ord, &seqs).await;
        }
        // B: 0..10 with seqs 10*k + 1, then a hole at 10, then garbage
        // (sealed while 10 was in flight) that must never be served
        for ord in 0..10u64 {
            let seq = 10 * ord as i64 + 1;
            want.push(seq);
            put_multi(&store, "B", ord, ord, &[seq]).await;
        }
        for ord in 11..20u64 {
            put_multi(&store, "B", ord, 10, &[10 * ord as i64 + 1]).await;
        }
        // C: a duplicate of one of A's seqs, then more, then a fence at 5
        // and garbage past it
        for ord in 0..5u64 {
            let seq = if ord == 0 { 30 } else { 10 * ord as i64 + 102 };
            if ord != 0 {
                want.push(seq);
            }
            put_multi(&store, "C", ord, ord, &[seq]).await;
        }
        store.raw.put(&segment_path(&store, "C", 5), PutPayload::from_bytes(segment::fence_object("X"))).await.unwrap();
        put_multi(&store, "C", 6, 5, &[205]).await;
        want.sort_unstable();

        for readahead in [1, 400, 64 << 20] {
            let r = Reader {
                store: store.clone(),
                cache: SegCache::new(if readahead == 1 { 0 } else { 1 << 20 }),
                readahead_bytes: readahead,
                shard: None,
            };
            let (last, got) = collect(&r, -1, i64::MAX).await;
            let seqs: Vec<i64> = got.iter().map(|(s, _)| *s).collect();
            assert_eq!(seqs, want, "readahead {readahead}");
            assert_eq!(last, *want.last().unwrap());
            // frames come from the right log (the duplicate is A's or C's)
            for (s, f) in &got {
                assert!(f.ends_with(format!(":{s}").as_bytes()));
            }
            // a window in the middle, bounded above
            let (_, got) = collect(&r, 95, 250).await;
            let seqs: Vec<i64> = got.iter().map(|(s, _)| *s).collect();
            assert_eq!(seqs, want.iter().copied().filter(|s| *s > 95 && *s <= 250).collect::<Vec<_>>());
        }

        // two concurrent readers of the same range share one cache: the
        // second costs (almost) no GETs
        let r = Reader { store: store.clone(), cache: SegCache::new(64 << 20), readahead_bytes: 64 << 20, shard: None };
        let gets = || metrics::FIREHOSE_BACKFILL_GETS.get();
        let before = gets();
        let (a, b) = tokio::join!(collect(&r, -1, i64::MAX), collect(&r, -1, i64::MAX));
        assert_eq!(a.1.iter().map(|e| e.0).collect::<Vec<_>>(), want);
        assert_eq!(b.1.iter().map(|e| e.0).collect::<Vec<_>>(), want);
        let first = gets() - before;
        assert!(r.cache.bytes() > 0);
        let before = gets();
        let (_, again) = collect(&r, -1, i64::MAX).await;
        assert_eq!(again.len(), want.len());
        // other tests may GET concurrently: only check this reader's share is
        // far below a full read (66 segments, plus probes)
        assert!(gets() - before < first, "cached replay made {} GETs, the first two {first}", gets() - before);
    }
}
