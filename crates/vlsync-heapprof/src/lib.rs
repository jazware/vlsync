//! Continuous heap profiles of a jemalloc process, in Go's pprof format.
//!
//! [`malloc_conf!`] starts jemalloc's sampler with the process: one
//! allocation in every 512 KiB allocated keeps its backtrace until it's
//! freed, as Go's default `MemProfileRate` does. [`dump_pprof`] reads them
//! (`prof.dump`), scales each stack's sampled objects and bytes up to an
//! estimate of the whole heap (jeprof's unbiasing, which jemalloc 5.3's
//! dump is written for), names the addresses from this binary's symbols and
//! encodes a gzipped profile.proto with Go's `inuse_objects` and
//! `inuse_space`, so `go tool pprof` and Go heap scrapers read it as they
//! read Go's `/debug/pprof/heap`. There are no `alloc_*` types: jemalloc
//! only keeps totals with `prof_accum`, whose memory grows with every stack
//! it ever sampled.
//!
//! `_RJEM_MALLOC_CONF` overrides the binary's settings at start:
//! `prof_active:false` stops the sampler (dumps then answer
//! [`Error::Inactive`]), `lg_prof_sample:21` samples every 2 MiB.

use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tikv_jemalloc_ctl::raw;

/// Defines the binary's `malloc_conf` with the heap sampler on, after the
/// binary's own settings: `vlsync_heapprof::malloc_conf!("background_thread:true")`.
/// Use it once, in the binary crate (a library's definition may not be
/// linked), instead of a `_rjem_malloc_conf` static of its own.
#[macro_export]
macro_rules! malloc_conf {
    () => {
        $crate::malloc_conf!(@define concat!("prof:true,prof_active:true,lg_prof_sample:19", "\0"));
    };
    ($conf:literal) => {
        $crate::malloc_conf!(@define concat!($conf, ",prof:true,prof_active:true,lg_prof_sample:19\0"));
    };
    (@define $s:expr) => {
        #[doc(hidden)]
        #[repr(transparent)]
        pub struct MallocConf(*const u8);
        // SAFETY: a pointer to a static string that jemalloc only reads.
        unsafe impl Sync for MallocConf {}
        #[unsafe(export_name = "_rjem_malloc_conf")]
        pub static MALLOC_CONF: MallocConf = MallocConf($s.as_ptr());
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// jemalloc was built with profiling and started with `prof:true`.
    pub enabled: bool,
    /// The sampler is on (`prof.active`).
    pub active: bool,
    /// The mean bytes allocated between samples.
    pub sample_bytes: u64,
}

pub fn status() -> Status {
    // SAFETY: documented mallctl names of these types. They answer ENOENT
    // when jemalloc was built without profiling.
    let enabled = unsafe { raw::read::<bool>(b"opt.prof\0") }.unwrap_or(false);
    if !enabled {
        return Status { enabled, active: false, sample_bytes: 0 };
    }
    let active = unsafe { raw::read::<bool>(b"prof.active\0") }.unwrap_or(false);
    let lg = unsafe { raw::read::<usize>(b"prof.lg_sample\0") }.unwrap_or(0);
    Status { enabled, active, sample_bytes: 1u64 << lg.min(63) }
}

/// Turns the sampler on or off. Off keeps what was sampled before: those
/// allocations stay in dumps until they're freed.
pub fn set_active(on: bool) -> Result<(), Error> {
    if !status().enabled {
        return Err(Error::Disabled);
    }
    // SAFETY: prof.active is a writable bool.
    unsafe { raw::write(b"prof.active\0", on) }.map_err(|e| Error::Dump(format!("prof.active: {e}")))
}

/// One line at start saying whether heap profiles are on.
pub fn log_status() {
    let s = status();
    if s.active {
        tracing::info!(
            sample_bytes = s.sample_bytes,
            "heap profiles: jemalloc samples an allocation every {} KiB",
            s.sample_bytes >> 10
        );
    } else if s.enabled {
        tracing::info!("heap profiles: jemalloc's sampler is off (prof_active:false)");
    } else {
        tracing::info!("heap profiles: off (jemalloc without prof:true)");
    }
}

#[derive(Debug)]
pub enum Error {
    /// jemalloc wasn't built with profiling, or started without `prof:true`.
    Disabled,
    /// The sampler is off (`prof_active:false`).
    Inactive,
    Dump(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Disabled => {
                f.write_str("heap profiles are off: jemalloc runs without prof:true (vlsync_heapprof::malloc_conf!)")
            }
            Error::Inactive => f.write_str("heap profiles are off: jemalloc's sampler is inactive (prof_active:false)"),
            Error::Dump(e) => write!(f, "heap profile: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// The symbol cache, and one dump at a time.
static STATE: parking_lot::Mutex<Option<Symbols>> = parking_lot::Mutex::new(None);

/// The heap in use, as a gzipped pprof profile. Blocking: a few ms to a few
/// hundred (the first dump reads the binary's symbol table).
pub fn dump_pprof() -> Result<Vec<u8>, Error> {
    let st = status();
    if !st.enabled {
        return Err(Error::Disabled);
    }
    if !st.active {
        return Err(Error::Inactive);
    }
    let mut guard = STATE.lock();
    let syms = guard.get_or_insert_with(Symbols::default);
    let t0 = Instant::now();
    let text = dump_text()?;
    let heap = parse(&text)?;
    let out = encode(&heap, syms, t0);
    tracing::debug!(
        stacks = heap.stacks.len(),
        bytes = out.len(),
        took_ms = t0.elapsed().as_millis() as u64,
        "heap profile"
    );
    Ok(out)
}

fn dump_text() -> Result<String, Error> {
    let path = std::env::temp_dir().join(format!("vlsync-heapprof-{}.heap", std::process::id()));
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|e| Error::Dump(e.to_string()))?;
    // SAFETY: prof.dump takes a NUL-terminated file name, which outlives the call.
    let r = unsafe { raw::write(b"prof.dump\0", c.as_ptr()) };
    let text = r
        .map_err(|e| Error::Dump(format!("prof.dump to {}: {e}", path.display())))
        .and_then(|()| std::fs::read_to_string(&path).map_err(|e| Error::Dump(format!("{}: {e}", path.display()))));
    let _ = std::fs::remove_file(&path);
    text
}

#[derive(Debug, Default, PartialEq)]
struct Heap {
    sample_bytes: u64,
    /// Addresses leaf first, and the estimated objects and bytes in use.
    stacks: Vec<(Vec<u64>, i64, i64)>,
    maps: Vec<Map>,
}

#[derive(Debug, Clone, PartialEq)]
struct Map {
    start: u64,
    end: u64,
    offset: u64,
    path: String,
}

/// jemalloc's `heap_v2` dump: a `heap_v2/<sample bytes>` header, then for
/// each stack an `@ <addr> ...` line (leaf first) and its `t*: <objects>:
/// <bytes> [...]` line over all threads, then `MAPPED_LIBRARIES:` and the
/// process's /proc maps (Linux only).
fn parse(text: &str) -> Result<Heap, Error> {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    let sample_bytes: u64 = first
        .trim()
        .strip_prefix("heap_v2/")
        .and_then(|r| r.parse().ok())
        .filter(|r| *r > 0)
        .ok_or_else(|| Error::Dump(format!("not a heap_v2 dump: {first:?}")))?;
    let rate = sample_bytes as f64;
    let mut heap = Heap { sample_bytes, ..Default::default() };
    let mut cur: Option<Vec<u64>> = None;
    let mut in_maps = false;
    for line in lines {
        if in_maps {
            heap.maps.extend(parse_map(line));
            continue;
        }
        let l = line.trim();
        if l == "MAPPED_LIBRARIES:" {
            in_maps = true;
        } else if let Some(rest) = l.strip_prefix('@') {
            let addrs = rest
                .split_ascii_whitespace()
                .map(|w| u64::from_str_radix(w.trim_start_matches("0x"), 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Dump(format!("stack {l:?}: {e}")))?;
            cur = Some(addrs);
        } else if let Some(rest) = l.strip_prefix("t*:") {
            let Some(addrs) = cur.take() else { continue };
            let mut it = rest.split(|c: char| c == ':' || c.is_ascii_whitespace()).filter(|s| !s.is_empty());
            let objs: f64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let bytes: f64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
            if objs <= 0.0 || bytes <= 0.0 || addrs.is_empty() {
                continue;
            }
            // jeprof's AdjustSamples: a sample of mean size s stood for
            // 1 / (1 - e^(-s/rate)) allocations of that size.
            let scale = 1.0 / (1.0 - (-(bytes / objs) / rate).exp());
            heap.stacks.push((addrs, (objs * scale).round() as i64, (bytes * scale).round() as i64));
        }
    }
    Ok(heap)
}

/// An executable line of /proc/<pid>/maps:
/// `55d0c6a00000-55d0c6b23000 r-xp 00001000 08:01 1234   /usr/local/bin/vlrelay`.
fn parse_map(line: &str) -> Option<Map> {
    let mut it = line.split_ascii_whitespace();
    let (range, perms, offset) = (it.next()?, it.next()?, it.next()?);
    let (_dev, _inode) = (it.next()?, it.next()?);
    let path = it.collect::<Vec<_>>().join(" ");
    if !perms.contains('x') || path.is_empty() || path.starts_with('[') {
        return None;
    }
    let (s, e) = range.split_once('-')?;
    Some(Map {
        start: u64::from_str_radix(s, 16).ok()?,
        end: u64::from_str_radix(e, 16).ok()?,
        offset: u64::from_str_radix(offset, 16).ok()?,
        path,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Frame {
    /// Demangled, without the hash.
    name: String,
    system: String,
    file: String,
    line: u32,
}

/// One address of a stack, symbolized.
struct Loc {
    /// Innermost (inlined) first, less the allocation primitives the
    /// address inlined ([`primitive`]).
    frames: Arc<[Frame]>,
    /// It's the global allocator's entry ([`allocator_entry`]).
    entry: bool,
    /// It's jemalloc's ([`allocator_internal`]).
    internal: bool,
}

impl Loc {
    fn new(frames: Vec<Frame>) -> Loc {
        let entry = frames.iter().any(allocator_entry);
        let internal = allocator_internal(&frames);
        let keep = frames.iter().position(|f| !primitive(f)).unwrap_or(frames.len());
        Loc { frames: frames[keep..].into(), entry, internal }
    }
}

/// Each address's [`Loc`]. Addresses don't move while the process runs, so
/// this lives as long as the process.
#[derive(Default)]
struct Symbols {
    by_addr: HashMap<u64, Arc<Loc>>,
}

impl Symbols {
    fn loc(&mut self, addr: u64) -> Arc<Loc> {
        self.by_addr
            .entry(addr)
            .or_insert_with(|| {
                let mut out = Vec::new();
                // A return address: the call is the instruction before it.
                backtrace::resolve(addr.saturating_sub(1) as usize as *mut c_void, |s| {
                    let Some(n) = s.name() else { return };
                    out.push(Frame {
                        name: format!("{n:#}"),
                        system: String::from_utf8_lossy(n.as_bytes()).into_owned(),
                        file: s.filename().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
                        line: s.lineno().unwrap_or(0),
                    });
                });
                Arc::new(Loc::new(out))
            })
            .clone()
    }
}

/// The global allocator's entry from Rust: `__rust_alloc` and its kin
/// (`__rustc::__rust_realloc` in newer toolchains), or the GlobalAlloc
/// impl when it wasn't inlined into them.
fn allocator_entry(f: &Frame) -> bool {
    let n = f.name.as_str();
    n.contains("__rust_alloc") || n.contains("__rust_realloc") || n.contains("__rdl_") || n.contains("GlobalAlloc>::")
}

/// jemalloc's own frames, for a stack that didn't come through Rust's
/// allocator entry: C names, or no name.
fn allocator_internal(fs: &[Frame]) -> bool {
    fs.iter().all(|f| {
        let n = f.name.as_str();
        !n.contains("::")
            && (n.starts_with("_rjem_") || n.starts_with("je_") || n.contains("prof_") || n.contains("alloc"))
    })
}

/// std's allocation calls inlined into the caller (`alloc::alloc::alloc`,
/// `Global::alloc_impl`), as Go's heap profiles start past mallocgc. A bare
/// `alloc` is the GlobalAlloc impl as line tables alone name it (inlined
/// frames there have no path).
fn primitive(f: &Frame) -> bool {
    let n = f.name.as_str();
    matches!(
        n,
        "alloc" | "realloc" | "alloc_zeroed" | "alloc_impl" | "alloc_impl_runtime" | "allocate" | "allocate_zeroed"
    ) || n.starts_with("alloc::alloc::")
        || n.starts_with("<alloc::alloc::Global")
        || allocator_entry(f)
}

/// How many leaf addresses are jemalloc and the allocator shim: the stack
/// starts at the code that allocated.
fn allocator_frames(locs: &[Arc<Loc>]) -> usize {
    if let Some(i) = locs.iter().take(24).rposition(|l| l.entry) {
        return i + 1;
    }
    locs.iter().take_while(|l| l.internal).count()
}

fn encode(heap: &Heap, syms: &mut Symbols, t0: Instant) -> Vec<u8> {
    let mut strings = Strings::default();
    let mut p = Pb::default();
    for (ty, unit) in [("inuse_objects", "count"), ("inuse_space", "bytes")] {
        let mut v = Pb::default();
        v.int(1, strings.id(ty));
        v.int(2, strings.id(unit));
        p.msg(1, &v);
    }
    let mut maps = heap.maps.clone();
    maps.sort_by_key(|m| m.start);
    let mut locations: HashMap<u64, u64> = HashMap::new();
    let mut functions: HashMap<(String, String, String), u64> = HashMap::new();
    let mut loc_msgs = Pb::default();
    let mut fn_msgs = Pb::default();
    let mut used_maps = vec![false; maps.len()];
    for (addrs, objs, bytes) in &heap.stacks {
        let locs: Vec<Arc<Loc>> = addrs.iter().map(|a| syms.loc(*a)).collect();
        let last = addrs.len() - 1;
        let skip = allocator_frames(&locs).min(last);
        let mut ids = Vec::with_capacity(addrs.len() - skip);
        for (i, (addr, loc)) in addrs.iter().zip(&locs).enumerate().skip(skip) {
            // an address that was all allocation primitives, unless it's all there is
            if loc.frames.is_empty() && !(ids.is_empty() && i == last) {
                continue;
            }
            let fs = &loc.frames;
            let next = locations.len() as u64 + 1;
            let id = *locations.entry(*addr).or_insert_with(|| {
                let mut loc = Pb::default();
                loc.int(1, next as i64);
                let m = maps.partition_point(|m| m.start <= *addr);
                if m > 0 && *addr < maps[m - 1].end {
                    used_maps[m - 1] = true;
                    loc.int(2, m as i64);
                }
                loc.int(3, *addr as i64);
                for f in fs.iter() {
                    let key = (f.name.clone(), f.system.clone(), f.file.clone());
                    let n = functions.len() as u64 + 1;
                    let fid = *functions.entry(key).or_insert_with(|| {
                        let mut fm = Pb::default();
                        fm.int(1, n as i64);
                        fm.int(2, strings.id(&f.name));
                        fm.int(3, strings.id(&f.system));
                        fm.int(4, strings.id(&f.file));
                        fn_msgs.msg(5, &fm);
                        n
                    });
                    let mut line = Pb::default();
                    line.int(1, fid as i64);
                    line.int(2, f.line as i64);
                    loc.msg(4, &line);
                }
                loc_msgs.msg(4, &loc);
                next
            });
            ids.push(id);
        }
        let mut s = Pb::default();
        s.packed(1, ids.iter().copied());
        s.packed(2, [*objs as u64, *bytes as u64].into_iter());
        p.msg(2, &s);
    }
    for (i, m) in maps.iter().enumerate() {
        if !used_maps[i] {
            continue;
        }
        let mut mm = Pb::default();
        mm.int(1, i as i64 + 1);
        mm.int(2, m.start as i64);
        mm.int(3, m.end as i64);
        mm.int(4, m.offset as i64);
        mm.int(5, strings.id(&m.path));
        mm.int(7, 1);
        p.msg(3, &mm);
    }
    p.0.extend_from_slice(&loc_msgs.0);
    p.0.extend_from_slice(&fn_msgs.0);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0);
    let mut period = Pb::default();
    period.int(1, strings.id("space"));
    period.int(2, strings.id("bytes"));
    let default_type = strings.id("inuse_space");
    let comment = strings.id(&format!("jemalloc heap, one sample per {} bytes allocated", heap.sample_bytes));
    for s in &strings.list {
        p.bytes(6, s.as_bytes());
    }
    p.int(9, now);
    p.int(10, t0.elapsed().as_nanos() as i64);
    p.msg(11, &period);
    p.int(12, heap.sample_bytes as i64);
    p.int(13, comment);
    p.int(14, default_type);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&p.0).expect("writing to a Vec");
    gz.finish().expect("writing to a Vec")
}

/// pprof's string table: index 0 is "".
struct Strings {
    ids: HashMap<String, i64>,
    list: Vec<String>,
}

impl Default for Strings {
    fn default() -> Self {
        Strings { ids: HashMap::from([(String::new(), 0)]), list: vec![String::new()] }
    }
}

impl Strings {
    fn id(&mut self, s: &str) -> i64 {
        if let Some(i) = self.ids.get(s) {
            return *i;
        }
        let i = self.list.len() as i64;
        self.list.push(s.to_string());
        self.ids.insert(s.to_string(), i);
        i
    }
}

/// The few protobuf encodings profile.proto needs.
#[derive(Default)]
struct Pb(Vec<u8>);

impl Pb {
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push(v as u8 | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }

    /// A varint field (int64, uint64, bool); zero is the default and left out.
    fn int(&mut self, field: u32, v: i64) {
        if v != 0 {
            self.varint((field as u64) << 3);
            self.varint(v as u64);
        }
    }

    fn bytes(&mut self, field: u32, b: &[u8]) {
        self.varint((field as u64) << 3 | 2);
        self.varint(b.len() as u64);
        self.0.extend_from_slice(b);
    }

    fn msg(&mut self, field: u32, m: &Pb) {
        self.bytes(field, &m.0);
    }

    fn packed(&mut self, field: u32, vs: impl Iterator<Item = u64>) {
        let mut p = Pb::default();
        for v in vs {
            p.varint(v);
        }
        self.bytes(field, &p.0);
    }
}

#[cfg(feature = "axum")]
mod http;
#[cfg(feature = "axum")]
pub use http::{from_loopback, handler};

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "heap_v2/524288
  t*: 3: 1572864 [0: 0]
  t0: 3: 1572864 [0: 0]
@ 0x10 0x20 0x30
  t*: 2: 1048576 [0: 0]
  t0: 2: 1048576 [0: 0]
@ 0x10 0x40
  t*: 1: 64 [0: 0]
@ 0x50
  t*: 0: 0 [0: 0]

MAPPED_LIBRARIES:
55d0c6a00000-55d0c6b23000 r--p 00000000 08:01 1234                       /usr/local/bin/vlrelay
55d0c6b23000-55d0c7000000 r-xp 00123000 08:01 1234                       /usr/local/bin/vlrelay
7ffd5c1fe000-7ffd5c200000 r-xp 00000000 00:00 0                          [vdso]
";

    #[test]
    fn parses_and_unbiases_a_dump() {
        let h = parse(DUMP).unwrap();
        assert_eq!(h.sample_bytes, 524288);
        assert_eq!(h.stacks.len(), 2, "the freed stack is left out");
        // 512 KiB samples at a 512 KiB rate: each stood for 1/(1-1/e) of itself
        let (addrs, objs, bytes) = &h.stacks[0];
        assert_eq!(addrs, &[0x10, 0x20, 0x30]);
        assert_eq!((*objs, *bytes), (3, 1_658_823));
        // a 64-byte sample stood for ~8192 allocations of 64 bytes
        let (_, objs, bytes) = &h.stacks[1];
        assert_eq!((*objs, *bytes), (8193, 524_320));
        assert_eq!(
            h.maps,
            vec![Map {
                start: 0x55d0c6b23000,
                end: 0x55d0c7000000,
                offset: 0x123000,
                path: "/usr/local/bin/vlrelay".into()
            }]
        );
    }

    #[test]
    fn refuses_what_isnt_a_dump() {
        assert!(parse("").is_err());
        assert!(parse("heap_v2/0\n").is_err());
        assert!(parse("heap_v2/524288\n@ 0xzz\n").is_err());
    }

    fn loc(names: &[&str]) -> Arc<Loc> {
        Arc::new(Loc::new(
            names
                .iter()
                .map(|n| Frame { name: n.to_string(), system: n.to_string(), file: String::new(), line: 0 })
                .collect(),
        ))
    }

    #[test]
    fn stacks_start_at_the_allocating_code() {
        let locs = [
            loc(&["prof_backtrace_impl"]),
            loc(&["_rjem_malloc"]),
            loc(&["alloc", "__rustc::__rust_alloc"]),
            loc(&["alloc::raw_vec::finish_grow"]),
            loc(&["vlrelay::ring::Ring::push"]),
        ];
        assert_eq!(allocator_frames(&locs), 3);
        let c = [loc(&["prof_backtrace"]), loc(&["je_malloc_default"]), loc(&["ZSTD_createCCtx"]), loc(&["main"])];
        assert_eq!(allocator_frames(&c), 2);
        // std's inlined allocation calls go; the caller they're inlined into stays
        let l = loc(&["alloc::alloc::alloc", "<alloc::alloc::Global>::alloc_impl", "vlrelay::ring::Ring::push"]);
        assert_eq!(l.frames.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["vlrelay::ring::Ring::push"]);
    }

    #[test]
    fn encodes_a_profile_go_reads() {
        let h = parse(DUMP).unwrap();
        let gz = encode(&h, &mut Symbols::default(), Instant::now());
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
        for s in ["inuse_objects", "inuse_space", "count", "bytes", "space"] {
            assert!(raw.windows(s.len()).any(|w| w == s.as_bytes()), "{s} missing");
        }
    }
}
