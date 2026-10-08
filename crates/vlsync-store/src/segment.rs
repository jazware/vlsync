//! Log segment object format (one log per node incarnation).
//!
//! Segments carry the finished firehose frames plus the state mutations used
//! to apply and replay them, each entry tagged with its shard and ownership
//! epoch.

use crate::slots::ShardId;
use bytes::{BufMut, Bytes};

#[derive(Clone, Debug)]
pub struct Mutation {
    pub key: Bytes,
    pub val: Option<Bytes>,
}

// ---------------------------------------------------------------------------
// A log is closed by a *fence* object written at its next ordinal
// (If-None-Match), after which the writer can never append again.
//
// "VLSEG06\n"
// header: log_id_len u16 | log_id | ordinal u64 | prefix_end u64
//         | first_seq i64 | last_seq i64 | count u32 | codec u8 | body_len u32
// body:   entry* (codec 0), or one zstd frame of them (codec 1)
// entry:  seq i64 | shard u32 | epoch u64 | frame_len u32 | frame
//         | mut_count u32 | (key_len u16 | key | val_len u32 (MAX = delete) | val)*
//
// The header is never compressed, so header-only range reads work on either
// codec. `body_len` is the uncompressed body length. The writer keeps the
// uncompressed object in memory (the live ring and the merger slice frames
// out of it) and stores `compress(obj)`; readers `decode` the stored object
// back to exactly those bytes (codec byte reset to 0), so entry offsets are
// the same in both (DESIGN.md "Log compression").
//
// The test feature level (cargo feature `test-level`, `version::TEST_LEVEL`,
// never in a release build) writes "VLSEGT1\n" with one more header field,
// `checksum u64` (sha256(uncompressed body)[..8]) between count and codec,
// so codec and body_len stay the header's last 5 bytes. A builder writes
// the level that was active when it was made: segments are homogeneous.
//
// mut_count with its top bit set: bits 0-15 count the muts stored, bits
// 16-30 the muts *derived* from the #commit frame, which come first (vlpds's
// `derived::derive_commit_muts`, handed to [`parse_derived`]): a commit's
// record and head values repeat blocks its CAR already carries. Such a
// mut_count is followed by the repo's generation (LEB128, `keys::Gen`),
// which the derived keys carry and the frame doesn't.
//
// "VLFENCE\n" | fenced_by (utf8)
//
// Up to K segment PUTs are in flight per log, so a crash can leave holes
// (ordinal n missing, n+1 present). `prefix_end` is the writer's promise when
// it sealed the segment: every ordinal below it was already durable. Holes
// can therefore only sit in [prefix_end, ordinal), at most K - 1 ordinals,
// which lets a reader prove a segment is inside the log's gap-free prefix
// with a bounded number of probes (see vlsync-firehose's `log::prefix_hole`).
// ---------------------------------------------------------------------------

/// The newest segment magic (level 1's). Writers emit
/// `version::segment_magic(version::active())`; readers accept every magic
/// of the build's level window (`version::segment_magics`).
pub const MAGIC: &[u8; 8] = b"VLSEG06\n";
/// Bytes of an entry before its frame: seq, shard, epoch, frame_len.
const ENTRY_HEAD: usize = 8 + 4 + 8 + 4;

pub const CODEC_NONE: u8 = 0;
pub const CODEC_ZSTD: u8 = 1;

/// 0 = store segments uncompressed.
static ZSTD_LEVEL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(DEFAULT_ZSTD_LEVEL);
pub const DEFAULT_ZSTD_LEVEL: i32 = 1;

pub fn set_compression_level(level: i32) {
    ZSTD_LEVEL.store(level, std::sync::atomic::Ordering::Relaxed);
}

pub fn compression_level() -> i32 {
    ZSTD_LEVEL.load(std::sync::atomic::Ordering::Relaxed)
}

/// mut_count flag: derived muts precede the stored ones.
const DERIVED: u32 = 1 << 31;
pub const FENCE_MAGIC: &[u8; 8] = b"VLFENCE\n";

#[derive(Clone, Debug)]
pub struct SegHeader {
    pub log_id: String,
    pub ordinal: u64,
    /// Every ordinal below this was durable when this segment was sealed.
    pub prefix_end: u64,
    pub first_seq: i64,
    pub last_seq: i64,
    pub count: u32,
    pub codec: u8,
    /// Uncompressed body length.
    pub body_len: u32,
    /// Feature level of the segment's magic.
    pub level: u32,
    /// The test level's sha256(uncompressed body)[..8], checked by [`parse`].
    pub checksum: Option<u64>,
}

pub struct SegEntry {
    pub seq: i64,
    pub shard: ShardId,
    pub epoch: u64,
    pub frame: Bytes,
    pub muts: Vec<Mutation>,
    /// How many of `muts` (the first ones) were derived from the #commit
    /// frame (0 when parsed without muts).
    pub derived: usize,
    /// The repo generation the derived muts are keyed under.
    pub gen: u64,
}

pub enum LogObject {
    Segment(SegHeader, Vec<SegEntry>),
    Fence { by: String },
}

pub struct SegmentBuilder {
    pub body: Vec<u8>,
    pub first_seq: i64,
    pub last_seq: i64,
    pub count: u32,
    /// Bytes reserved at the start of `body` for the header (`for_log`).
    header_room: usize,
    /// Fixed when the builder is made, so a segment is homogeneous and a
    /// level change takes effect at the next one.
    level: u32,
}

impl Default for SegmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentBuilder {
    pub fn new() -> Self {
        SegmentBuilder {
            body: Vec::with_capacity(1 << 20),
            first_seq: 0,
            last_seq: 0,
            count: 0,
            header_room: 0,
            level: crate::version::active(),
        }
    }

    /// A builder whose body starts with room for `log_id`'s header, so
    /// `seal` writes it in place instead of copying the body behind it.
    /// Entry ranges from `push` are then offsets into the sealed object.
    pub fn for_log(log_id: &str) -> Self {
        Self::for_log_at(log_id, crate::version::active())
    }

    /// Golden fixtures of an older level; writers use the active one.
    pub fn for_log_at(log_id: &str, level: u32) -> Self {
        let room = header_len(log_id, level);
        let mut body = Vec::with_capacity(1 << 20);
        body.resize(room, 0);
        SegmentBuilder { body, first_seq: 0, last_seq: 0, count: 0, header_room: room, level }
    }

    pub fn level(&self) -> u32 {
        self.level
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.body.len()
    }

    pub fn push(
        &mut self,
        seq: i64,
        shard: ShardId,
        epoch: u64,
        write_frame: impl FnOnce(&mut Vec<u8>),
        muts: &[Mutation],
    ) -> std::ops::Range<usize> {
        self.push_derived(seq, shard, epoch, write_frame, muts, 0, 0)
    }

    /// [`push`](Self::push) where the first `derived` muts are left out:
    /// replay rebuilds them from the #commit frame and the repo's generation
    /// `gen` (see [`parse_derived`]).
    #[allow(clippy::too_many_arguments)]
    pub fn push_derived(
        &mut self,
        seq: i64,
        shard: ShardId,
        epoch: u64,
        write_frame: impl FnOnce(&mut Vec<u8>),
        muts: &[Mutation],
        derived: usize,
        gen: u64,
    ) -> std::ops::Range<usize> {
        let stored = &muts[derived.min(muts.len())..];
        let derived = if derived > 0 && derived <= muts.len() && derived < 1 << 15 && stored.len() < 1 << 16 {
            derived
        } else {
            0
        };
        let stored = &muts[derived..];
        if self.count == 0 {
            self.first_seq = seq;
        }
        self.last_seq = seq;
        self.count += 1;
        self.body.put_i64(seq);
        self.body.put_u32(shard.0);
        self.body.put_u64(epoch);
        let len_at = self.body.len();
        self.body.put_u32(0);
        let start = self.body.len();
        write_frame(&mut self.body);
        let end = self.body.len();
        self.body[len_at..start].copy_from_slice(&((end - start) as u32).to_be_bytes());
        if derived > 0 {
            self.body.put_u32(DERIVED | (derived as u32) << 16 | stored.len() as u32);
            self.body.put_slice(&crate::keys::Gen(gen).bytes());
        } else {
            self.body.put_u32(stored.len() as u32);
        }
        for m in stored {
            self.body.put_u16(m.key.len() as u16);
            self.body.put_slice(&m.key);
            match &m.val {
                Some(v) => {
                    self.body.put_u32(v.len() as u32);
                    self.body.put_slice(v);
                }
                None => self.body.put_u32(u32::MAX),
            }
        }
        start..end
    }

    /// Header bytes for a segment written after every earlier ordinal was
    /// durable (a dense log: `prefix_end` = `ordinal`).
    pub fn header(&self, log_id: &str, ordinal: u64) -> Vec<u8> {
        self.sealed_header(log_id, ordinal, ordinal)
    }

    /// The sealed (uncompressed) object: the header written into the room
    /// `for_log` left (no copy), or prepended. [`compress`] makes the stored form.
    pub fn seal(self, log_id: &str, ordinal: u64, prefix_end: u64) -> Vec<u8> {
        let h = self.sealed_header(log_id, ordinal, prefix_end);
        if self.header_room == h.len() {
            let mut body = self.body;
            body[..h.len()].copy_from_slice(&h);
            return body;
        }
        let mut obj = h;
        obj.extend_from_slice(&self.body[self.header_room..]);
        obj
    }

    /// Header bytes; entry ranges returned by `push` are relative to the body,
    /// so add the header length to address the full object.
    pub fn sealed_header(&self, log_id: &str, ordinal: u64, prefix_end: u64) -> Vec<u8> {
        debug_assert!(prefix_end <= ordinal);
        let mut h = Vec::with_capacity(header_len(log_id, self.level));
        h.put_slice(crate::version::segment_magic(self.level));
        h.put_u16(log_id.len() as u16);
        h.put_slice(log_id.as_bytes());
        h.put_u64(ordinal);
        h.put_u64(prefix_end);
        h.put_i64(self.first_seq);
        h.put_i64(self.last_seq);
        h.put_u32(self.count);
        if has_checksum(self.level) {
            h.put_u64(body_checksum(&self.body[self.header_room..]));
        }
        h.put_u8(CODEC_NONE);
        h.put_u32((self.body.len() - self.header_room) as u32);
        h
    }
}

/// Header bytes after the log id.
const HEADER_TAIL: usize = 41;

/// Whether segments of `level` carry the test level's body checksum (between
/// `count` and `codec`, so codec and body_len stay the header's last 5 bytes).
fn has_checksum(level: u32) -> bool {
    cfg!(feature = "test-level") && level >= crate::version::TEST_LEVEL
}

fn header_tail(level: u32) -> usize {
    HEADER_TAIL + if has_checksum(level) { 8 } else { 0 }
}

/// Bytes of a sealed segment's header for `log_id` at `level`.
pub fn header_len(log_id: &str, level: u32) -> usize {
    MAGIC.len() + 2 + log_id.len() + header_tail(level)
}

fn body_checksum(body: &[u8]) -> u64 {
    use sha2::Digest;
    u64::from_be_bytes(sha2::Sha256::digest(body)[..8].try_into().unwrap())
}

thread_local! {
    static ZCTX: std::cell::RefCell<Option<(i32, zstd::bulk::Compressor<'static>)>> = const { std::cell::RefCell::new(None) };
    static DCTX: std::cell::RefCell<Option<zstd::bulk::Decompressor<'static>>> = const { std::cell::RefCell::new(None) };
}

/// The stored form of a sealed, uncompressed segment `obj`: its body as one
/// zstd frame at `level` (header unchanged but for the codec byte). None if
/// `level` is 0 or compression doesn't make it smaller: store `obj` as is.
pub fn compress(obj: &[u8], level: i32) -> anyhow::Result<Option<Vec<u8>>> {
    if level == 0 {
        return Ok(None);
    }
    let Some((h, hl)) = parse_header(obj)? else { return Ok(None) };
    anyhow::ensure!(
        h.codec == CODEC_NONE && hl + h.body_len as usize == obj.len(),
        "compress: not a sealed uncompressed segment"
    );
    let body = &obj[hl..];
    let mut out = Vec::with_capacity(hl + zstd::zstd_safe::compress_bound(body.len()));
    out.extend_from_slice(&obj[..hl]);
    out[hl - 5] = CODEC_ZSTD;
    out.resize(out.capacity(), 0);
    let n = ZCTX.with(|c| -> anyhow::Result<usize> {
        let mut c = c.borrow_mut();
        if c.as_ref().is_none_or(|(l, _)| *l != level) {
            *c = Some((level, zstd::bulk::Compressor::new(level)?));
        }
        Ok(c.as_mut().unwrap().1.compress_to_buffer(body, &mut out[hl..])?)
    })?;
    if n >= body.len() {
        return Ok(None);
    }
    out.truncate(hl + n);
    Ok(Some(out))
}

/// Largest body [`decode`] allocates for a zstd frame that doesn't state
/// its decompressed size.
const MAX_UNDECLARED_BODY: usize = 1 << 30;

/// A stored log object in the form the writer sealed it: a compressed
/// segment's body decompressed (and its codec byte reset), so entry offsets
/// match the writer's in-memory object. Fences and uncompressed segments
/// come back as they are (no copy).
pub fn decode(data: Bytes) -> anyhow::Result<Bytes> {
    let Some((h, hl)) = parse_header(&data)? else { return Ok(data) };
    let body_len = h.body_len as usize;
    match h.codec {
        CODEC_NONE => {
            anyhow::ensure!(
                data.len() == hl + body_len,
                "segment {} body is {} bytes, header says {body_len}",
                h.ordinal,
                data.len() - hl
            );
            Ok(data)
        }
        CODEC_ZSTD => {
            // body_len comes from the object: allocate it only if the zstd
            // frame declares the same size (the writer's always does), or,
            // for a frame without one, up to a sanity bound
            let declared = zstd::zstd_safe::get_frame_content_size(&data[hl..]).ok().flatten();
            anyhow::ensure!(
                declared.map_or(body_len <= MAX_UNDECLARED_BODY, |d| d == body_len as u64),
                "segment {} header says {body_len} body bytes, its zstd frame {declared:?}",
                h.ordinal
            );
            let mut out = Vec::with_capacity(hl + body_len);
            out.extend_from_slice(&data[..hl]);
            out[hl - 5] = CODEC_NONE;
            out.resize(hl + body_len, 0);
            let n = DCTX.with(|d| -> anyhow::Result<usize> {
                let mut d = d.borrow_mut();
                if d.is_none() {
                    *d = Some(zstd::bulk::Decompressor::new()?);
                }
                Ok(d.as_mut().unwrap().decompress_to_buffer(&data[hl..], &mut out[hl..])?)
            })?;
            anyhow::ensure!(n == body_len, "segment {} decompressed to {n} bytes, header says {body_len}", h.ordinal);
            crate::metrics::SEGMENT_DECODES.inc();
            Ok(out.into())
        }
        c => {
            crate::version::format_error("segment");
            anyhow::bail!("segment {} has unknown codec {c}", h.ordinal)
        }
    }
}

pub fn fence_object(by: &str) -> Bytes {
    let mut b = Vec::with_capacity(8 + by.len());
    b.put_slice(FENCE_MAGIC);
    b.put_slice(by.as_bytes());
    b.into()
}

/// Parses just the header of a log object (a prefix of it is enough): None
/// for a fence. Returns the header and its length.
pub fn parse_header(data: &[u8]) -> anyhow::Result<Option<(SegHeader, usize)>> {
    if data.starts_with(FENCE_MAGIC) {
        return Ok(None);
    }
    let level = match data.get(..8).and_then(crate::version::segment_level) {
        Some(l) if data.len() >= 10 => l,
        Some(_) => anyhow::bail!("truncated segment header"),
        None => {
            crate::version::format_error("segment");
            anyhow::bail!(
                "bad segment magic {:?} (not a level this build reads)",
                String::from_utf8_lossy(&data[..data.len().min(8)])
            )
        }
    };
    let idlen = u16::from_be_bytes(data[8..10].try_into()?) as usize;
    let pos = 10 + idlen;
    let tail = header_tail(level);
    anyhow::ensure!(data.len() >= pos + tail, "truncated segment header");
    let rd8 = |p: usize| -> [u8; 8] { data[p..p + 8].try_into().unwrap() };
    // the test level's checksum sits between count and codec
    let (checksum, c) =
        if has_checksum(level) { (Some(u64::from_be_bytes(rd8(pos + 36))), pos + 44) } else { (None, pos + 36) };
    let h = SegHeader {
        log_id: String::from_utf8(data[10..pos].to_vec())?,
        ordinal: u64::from_be_bytes(rd8(pos)),
        prefix_end: u64::from_be_bytes(rd8(pos + 8)),
        first_seq: i64::from_be_bytes(rd8(pos + 16)),
        last_seq: i64::from_be_bytes(rd8(pos + 24)),
        count: u32::from_be_bytes(data[pos + 32..pos + 36].try_into()?),
        codec: data[c],
        body_len: u32::from_be_bytes(data[c + 1..c + 5].try_into()?),
        level,
        checksum,
    };
    anyhow::ensure!(h.prefix_end <= h.ordinal, "segment {} has prefix_end {} past it", h.ordinal, h.prefix_end);
    Ok(Some((h, pos + tail)))
}

/// Parses a stored log object; frames and values are slices of the
/// uncompressed object. With `shard` set, only that shard's entries are
/// returned. An entry with derived muts errs with `with_muts` (only
/// [`parse_derived`] can rebuild them).
pub fn parse(data: Bytes, with_muts: bool, shard: Option<ShardId>) -> anyhow::Result<LogObject> {
    parse_with(data, with_muts, None, shard)
}

/// Rebuilds the `n` muts an entry derives from its #commit frame, keyed
/// under the repo generation `gen`: (frame, n, gen) -> muts.
pub type Derive = fn(&[u8], usize, u64) -> anyhow::Result<Vec<Mutation>>;

/// [`parse`] with muts, each entry's derived ones rebuilt by `derive` and
/// put first.
pub fn parse_derived(data: Bytes, shard: Option<ShardId>, derive: Derive) -> anyhow::Result<LogObject> {
    parse_with(data, true, Some(derive), shard)
}

fn parse_with(
    data: Bytes,
    with_muts: bool,
    derive: Option<Derive>,
    shard: Option<ShardId>,
) -> anyhow::Result<LogObject> {
    let data = decode(data)?;
    let Some((h, mut pos)) = parse_header(&data)? else {
        return Ok(LogObject::Fence { by: String::from_utf8_lossy(&data[8..]).into_owned() });
    };
    if let Some(sum) = h.checksum {
        anyhow::ensure!(
            body_checksum(&data[pos..]) == sum,
            "segment {} of {}: body checksum mismatch",
            h.ordinal,
            h.log_id
        );
    }
    let need = |pos: usize, n: usize| -> anyhow::Result<()> {
        anyhow::ensure!(pos + n <= data.len(), "truncated segment");
        Ok(())
    };
    let rd8 = |p: usize| -> [u8; 8] { data[p..p + 8].try_into().unwrap() };
    let count = h.count;
    let mut out = Vec::new();
    for _ in 0..count {
        need(pos, ENTRY_HEAD)?;
        let seq = i64::from_be_bytes(rd8(pos));
        let sh = ShardId(u32::from_be_bytes(data[pos + 8..pos + 12].try_into()?));
        let epoch = u64::from_be_bytes(rd8(pos + 12));
        let flen = u32::from_be_bytes(data[pos + 20..pos + 24].try_into()?) as usize;
        pos += ENTRY_HEAD;
        need(pos, flen + 4)?;
        let frame = data.slice(pos..pos + flen);
        pos += flen;
        let nm = u32::from_be_bytes(data[pos..pos + 4].try_into()?);
        pos += 4;
        let (derived, nm) = if nm & DERIVED != 0 {
            (((nm & !DERIVED) >> 16) as usize, (nm & 0xffff) as usize)
        } else {
            (0, nm as usize)
        };
        let mut gen = 0u64;
        if derived > 0 {
            let mut shift = 0;
            loop {
                need(pos, 1)?;
                let b = data[pos];
                pos += 1;
                anyhow::ensure!(shift < 64, "segment entry {seq}: bad generation");
                gen |= ((b & 0x7f) as u64) << shift;
                shift += 7;
                if b & 0x80 == 0 {
                    break;
                }
            }
        }
        let keep = shard.is_none_or(|s| s == sh);
        let mut muts = Vec::new();
        if derived > 0 && with_muts && keep {
            let derive = derive.ok_or_else(|| {
                anyhow::anyhow!("segment entry {seq}: derived muts need the writer's derivation (parse_derived)")
            })?;
            muts = derive(&frame, derived, gen).map_err(|e| anyhow::anyhow!("segment entry {seq}: {e:#}"))?;
        }
        for _ in 0..nm {
            need(pos, 2)?;
            let kl = u16::from_be_bytes(data[pos..pos + 2].try_into()?) as usize;
            pos += 2;
            need(pos, kl + 4)?;
            let key = data.slice(pos..pos + kl);
            pos += kl;
            let vl = u32::from_be_bytes(data[pos..pos + 4].try_into()?);
            pos += 4;
            let val = if vl == u32::MAX {
                None
            } else {
                need(pos, vl as usize)?;
                let v = data.slice(pos..pos + vl as usize);
                pos += vl as usize;
                Some(v)
            };
            if with_muts && keep {
                muts.push(Mutation { key, val });
            }
        }
        if keep {
            let derived = if with_muts { derived } else { 0 };
            out.push(SegEntry { seq, shard: sh, epoch, frame, muts, derived, gen });
        }
    }
    Ok(LogObject::Segment(h, out))
}

/// The firehose events of parsed entries (private-state entries, with an
/// empty frame, dropped).
pub fn events(entries: Vec<SegEntry>) -> Vec<(i64, Bytes)> {
    entries.into_iter().filter(|e| !e.frame.is_empty()).map(|e| (e.seq, e.frame)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_filter() {
        let mut b = SegmentBuilder::new();
        let m = |k: &str, v: Option<&str>| Mutation {
            key: Bytes::from(k.to_string()),
            val: v.map(|v| Bytes::from(v.to_string())),
        };
        b.push(10, ShardId(3), 7, |o| o.extend_from_slice(b"frame-a"), &[m("k1", Some("v1"))]);
        b.push(11, ShardId(1 << 20), 1, |o| o.extend_from_slice(b"frame-b"), &[m("k2", None)]);
        b.push(12, ShardId(3), 7, |_| {}, &[m("k3", Some("v3"))]);
        let mut obj = b.sealed_header("node-a.1", 42, 39);
        obj.extend_from_slice(&b.body);
        let LogObject::Segment(h, all) = parse(Bytes::from(obj.clone()), true, None).unwrap() else { panic!() };
        assert_eq!(
            (h.log_id.as_str(), h.ordinal, h.prefix_end, h.first_seq, h.last_seq, h.count),
            ("node-a.1", 42, 39, 10, 12, 3)
        );
        let (hh, len) = parse_header(&obj[..80]).unwrap().unwrap();
        assert_eq!((hh.ordinal, hh.prefix_end, len), (42, 39, b.header("node-a.1", 42).len()));
        assert!(parse_header(&fence_object("node-b")).unwrap().is_none());
        assert_eq!(all.len(), 3);
        assert_eq!(&all[1].frame[..], b"frame-b");
        assert!(all[1].muts[0].val.is_none());
        assert_eq!((all[1].shard, all[1].epoch), (ShardId(1 << 20), 1));
        let LogObject::Segment(_, only3) = parse(Bytes::from(obj), true, Some(ShardId(3))).unwrap() else { panic!() };
        assert_eq!(only3.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![10, 12]);
        assert!(
            matches!(parse(fence_object("node-b"), false, None).unwrap(), LogObject::Fence { by } if by == "node-b")
        );
    }

    /// A compressed segment keeps its header readable on its own, decodes
    /// to exactly the bytes the writer sealed (so frame ranges from `push`
    /// address both), and parses like the uncompressed one.
    #[test]
    fn compressed_roundtrip() {
        let mut b = SegmentBuilder::for_log("node-a.7");
        let mut ranges = Vec::new();
        for i in 0..200u32 {
            let m = Mutation {
                key: Bytes::from(format!("R/did:plc:aaaa{}\0app.bsky.feed.like/{i:08}", i % 7)),
                val: Some(Bytes::from(vec![b'v'; 40])),
            };
            ranges.push(b.push(
                1000 + i as i64,
                ShardId(70_000 + i % 3),
                2,
                |o| o.extend_from_slice(format!("frame {i} {}", "x".repeat(64)).as_bytes()),
                &[m],
            ));
        }
        let sealed = b.seal("node-a.7", 5, 3);
        let stored = compress(&sealed, 1).unwrap().expect("compressible");
        assert!(stored.len() * 3 < sealed.len(), "{} -> {}", sealed.len(), stored.len());
        // header-only read of the stored object
        let (h, hl) = parse_header(&stored[..80]).unwrap().unwrap();
        assert_eq!(
            (h.ordinal, h.prefix_end, h.first_seq, h.last_seq, h.count, h.codec),
            (5, 3, 1000, 1199, 200, CODEC_ZSTD)
        );
        assert_eq!((h.body_len as usize, hl), (sealed.len() - hl, header_len("node-a.7", h.level)));
        let decoded = decode(Bytes::from(stored.clone())).unwrap();
        assert_eq!(&decoded[..], &sealed[..]);
        let LogObject::Segment(h2, entries) = parse(Bytes::from(stored), true, Some(ShardId(70_001))).unwrap() else {
            panic!()
        };
        assert_eq!(h2.codec, CODEC_NONE);
        assert_eq!(entries.len(), 67);
        for e in &entries {
            let i = (e.seq - 1000) as usize;
            assert_eq!(&e.frame[..], &sealed[ranges[i].clone()]);
            assert_eq!((e.muts.len(), e.shard, e.epoch), (1, ShardId(70_001), 2));
        }
        // level 0, fences and incompressible bodies are stored as they are
        assert!(compress(&sealed, 0).unwrap().is_none());
        assert!(compress(&fence_object("x"), 1).unwrap().is_none());
        let mut b = SegmentBuilder::new();
        let noise: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();
        b.push(1, ShardId(0), 0, |o| o.extend_from_slice(&noise), &[]);
        assert!(compress(&b.seal("L", 0, 0), 1).unwrap().is_none());
        // a corrupt body is an error, not a short segment
        let mut bad = compress(&sealed, 1).unwrap().unwrap();
        let n = bad.len();
        bad.truncate(n - 8);
        assert!(decode(Bytes::from(bad)).is_err());
        // a header claiming a body its frame doesn't declare is refused
        // before anything is allocated for it
        let mut big = compress(&sealed, 1).unwrap().unwrap();
        let (_, hl) = parse_header(&big).unwrap().unwrap();
        big[hl - 4..hl].copy_from_slice(&u32::MAX.to_be_bytes());
        let e = decode(Bytes::from(big)).unwrap_err();
        assert!(e.to_string().contains("zstd frame"), "{e}");
    }
}
