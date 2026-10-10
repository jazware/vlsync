//! Prometheus metrics of the storage layer and the process, and the /metrics
//! text every vlsync server renders: one default registry, so a server's own
//! series and every vlsync crate's land in one [`render`].

use prometheus::{
    exponential_buckets, register_gauge, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, register_int_gauge_vec, Encoder, Gauge, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, TextEncoder,
};
use std::sync::LazyLock;

pub fn latency_buckets() -> Vec<f64> {
    exponential_buckets(0.0001, 2.0, 20).unwrap()
}

/// `lazy!(NAME: Type = register_...!(...))`: a registered metric, created on
/// first use.
#[macro_export]
macro_rules! lazy {
    ($name:ident: $t:ty = $e:expr) => {
        pub static $name: ::std::sync::LazyLock<$t> = ::std::sync::LazyLock::new(|| $e.unwrap());
    };
}

lazy!(SEGMENT_DECODES: IntCounter = register_int_counter!("vlpds_segment_decodes_total", "Compressed segments decompressed by readers (replay, follower catch-up, backfill, merger read-back)"));
lazy!(OBJ_REQUESTS: IntCounterVec = register_int_counter_vec!("vlpds_object_store_requests_total", "Object-store requests sent to the store, by billable op (put, put_create, put_cas, get, get_range, head, list pages, delete (single DELETEs only), copy, mpu_*), key component, client pool and result (ok, not_found, precondition, timeout, error, cancelled: the caller dropped it unanswered) (objstats.rs)", &["op", "component", "client", "result"]));
lazy!(STORE_THROTTLED: IntCounterVec = register_int_counter_vec!("vlpds_object_store_throttled_total", "Object-store answers of 429 Too Many Requests or 503 SlowDown (not other 503s), each one counted (object_store retries them inside its client, so vlpds_object_store_requests_total sees only the final result), by key kind (lease: node leases, assignments, writer claims, cluster version, LISTs by prefix; segment: commit-log segments; other, bulk deletes included) (throttle.rs)", &["kind"]));
lazy!(OBJ_BYTES: IntCounterVec = register_int_counter_vec!("vlpds_object_store_bytes_total", "Object-store payload bytes by direction (up, down), key component and client pool", &["dir", "component", "client"]));
lazy!(OBJ_INFLIGHT: IntGaugeVec = register_int_gauge_vec!("vlpds_object_store_inflight", "Object-store requests holding an in-flight permit, by client pool (log, state, ctl) and lane (main; reserved: log writes, ctl lease writes) (objlimit.rs)", &["client", "lane"]));
lazy!(OBJ_INFLIGHT_LIMIT: IntGaugeVec = register_int_gauge_vec!("vlpds_object_store_inflight_limit", "In-flight permits of each object-store client pool and lane (--store-inflight, --log-store-inflight)", &["client", "lane"]));
lazy!(OBJ_PERMIT_WAITS: IntCounterVec = register_int_counter_vec!("vlpds_object_store_permit_waits_total", "Object-store requests that found every in-flight permit of their pool and lane taken and queued", &["client", "lane"]));
lazy!(OBJ_PERMIT_WAIT_SECONDS: HistogramVec = register_histogram_vec!("vlpds_object_store_permit_wait_seconds", "How long object-store requests that queued for an in-flight permit waited", &["client", "lane"], latency_buckets()));
lazy!(JEMALLOC: IntGaugeVec = register_int_gauge_vec!("vlpds_jemalloc_bytes", "jemalloc stats", &["stat"]));
lazy!(PROCESS_RSS: IntGauge = register_int_gauge!("vlpds_process_resident_bytes", "Resident set size"));
lazy!(PROCESS_CPU: prometheus::CounterVec = prometheus::register_counter_vec!("vlpds_process_cpu_seconds_total", "CPU time consumed by mode (getrusage)", &["mode"]));
lazy!(PROCESS_THREADS: IntGauge = register_int_gauge!("vlpds_process_threads", "OS threads"));
lazy!(TOKIO_WORKERS: IntGauge = register_int_gauge!("vlpds_tokio_workers", "Tokio worker threads"));
lazy!(TOKIO_TASKS: IntGauge = register_int_gauge!("vlpds_tokio_alive_tasks", "Tokio tasks alive"));
lazy!(TOKIO_GLOBAL_QUEUE: IntGauge = register_int_gauge!("vlpds_tokio_global_queue_depth", "Tasks in the tokio injection queue"));
lazy!(TOKIO_BUSY: prometheus::Counter = prometheus::register_counter!("vlpds_tokio_busy_seconds_total", "Busy time summed over tokio workers (rate / workers = utilization)"));
lazy!(PROCESS_START: Gauge = register_gauge!("vlpds_process_start_time_seconds", "Start time of this process since the Unix epoch, in seconds"));
lazy!(PROCESS_START_STD: Gauge = register_gauge!("process_start_time_seconds", "Start time of the process since unix epoch in seconds."));
lazy!(LAST_EXIT: IntGaugeVec = register_int_gauge_vec!("vlpds_last_exit_reason_info", "1, labeled with how the previous process using this exit-state file ended (lifecycle.rs): a fail-stop reason with its exit code, clean, error, crash (no exit recorded: SIGKILL, OOM kill, abort, host loss) or none (first run, or no exit-state file)", &["reason", "code"]));
lazy!(LAST_EXIT_TIME: Gauge = register_gauge!("vlpds_last_exit_time_seconds", "When the previous process recorded its exit (Unix seconds; 0 if unknown)"));
lazy!(FEATURE_LEVEL: IntGaugeVec = register_int_gauge_vec!("vlpds_feature_level", "Feature levels (version.rs): active = the cluster's active level as this node last read cluster/version (what writers emit), binary_min / binary_max = the levels this build can run. binary_max > active on every node = a finalize is available", &["kind"]));
lazy!(FORMAT_ERRORS: IntCounterVec = register_int_counter_vec!("vlpds_format_errors_total", "Decodes that failed on an unknown or malformed format marker (segment: magic/codec; log_stream: message type, skipped; applied_marker: meta/applied2; cluster_version / control_object: unreadable control JSON). Any is a node of a newer level writing early, or corruption", &["format"]));
lazy!(OBJ_DURATION: HistogramVec = register_histogram_vec!("vlpds_object_store_request_seconds", "Object-store request latency by op and key component (objstats.rs), answered requests only: to the response head for GETs, to the first page for LISTs; deletes are not timed", &["op", "component"], latency_buckets()));

/// Exports the throttle counters at 0 before their first event, so `rate()`
/// sees the first one.
fn init_counters() {
    static DONE: std::sync::Once = std::sync::Once::new();
    DONE.call_once(|| {
        for k in crate::throttle::KINDS {
            STORE_THROTTLED.with_label_values(&[k]);
        }
    });
}

type Refresher = Box<dyn Fn() -> bool + Send + Sync>;

static REFRESHERS: LazyLock<parking_lot::Mutex<Vec<Refresher>>> = LazyLock::new(Default::default);

/// Runs `f` before every render while it returns true (false: its source
/// is gone, drop it).
pub fn on_render(f: impl Fn() -> bool + Send + Sync + 'static) {
    REFRESHERS.lock().push(Box::new(f));
}

pub fn render() -> String {
    init_counters();
    REFRESHERS.lock().retain(|f| f());
    crate::lifecycle::refresh_metrics();
    refresh_jemalloc();
    refresh_process();
    refresh_tokio();
    let mut buf = Vec::new();
    TextEncoder::new().encode(&prometheus::gather(), &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[cfg(not(feature = "jemalloc"))]
fn refresh_jemalloc() {}

#[cfg(feature = "jemalloc")]
fn refresh_jemalloc() {
    use tikv_jemalloc_ctl::{epoch, stats};
    if epoch::advance().is_err() {
        return;
    }
    for (name, v) in [
        ("allocated", stats::allocated::read()),
        ("active", stats::active::read()),
        ("resident", stats::resident::read()),
        ("mapped", stats::mapped::read()),
        ("retained", stats::retained::read()),
        ("metadata", stats::metadata::read()),
    ] {
        if let Ok(v) = v {
            JEMALLOC.with_label_values(&[name]).set(v as i64);
        }
    }
}

/// Mirrors a cumulative total read at scrape time. Never moves down (a total
/// from another runtime, or one that went back); serialized so concurrent
/// scrapes don't add the same delta twice.
fn advance(c: &prometheus::Counter, total: f64) {
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let _g = LOCK.lock();
    let cur = c.get();
    if total > cur {
        c.inc_by(total - cur);
    }
}

fn refresh_tokio() {
    let Ok(h) = tokio::runtime::Handle::try_current() else { return };
    let m = h.metrics();
    let n = m.num_workers();
    TOKIO_WORKERS.set(n as i64);
    TOKIO_TASKS.set(m.num_alive_tasks() as i64);
    TOKIO_GLOBAL_QUEUE.set(m.global_queue_depth() as i64);
    advance(&TOKIO_BUSY, (0..n).map(|w| m.worker_total_busy_duration(w).as_secs_f64()).sum());
}

pub fn resident_bytes() -> Option<u64> {
    #[cfg(all(any(target_os = "macos", target_os = "linux"), target_pointer_width = "64"))]
    return sys::rss_threads().map(|(rss, _)| rss);
    #[allow(unreachable_code)]
    None
}

/// User plus system CPU seconds this process has used.
pub fn cpu_seconds() -> Option<f64> {
    sys::cpu_seconds().map(|(u, s)| u + s)
}

fn refresh_process() {
    if let Some((user, system)) = sys::cpu_seconds() {
        advance(&PROCESS_CPU.with_label_values(&["user"]), user);
        advance(&PROCESS_CPU.with_label_values(&["system"]), system);
    }
    if let Some((rss, threads)) = sys::rss_threads() {
        PROCESS_RSS.set(rss as i64);
        PROCESS_THREADS.set(threads as i64);
    }
}

/// Process stats without a libc dependency: getrusage (macOS and 64-bit
/// Linux share the layout but for `tv_usec`'s width), proc_pidinfo on macOS,
/// /proc/self/status on Linux.
#[cfg(all(any(target_os = "macos", target_os = "linux"), target_pointer_width = "64"))]
mod sys {
    #[repr(C)]
    struct Timeval {
        sec: i64,
        #[cfg(target_os = "macos")]
        usec: i32,
        #[cfg(target_os = "linux")]
        usec: i64,
    }
    #[repr(C)]
    struct Rusage {
        utime: Timeval,
        stime: Timeval,
        rest: [i64; 14],
    }
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    pub fn cpu_seconds() -> Option<(f64, f64)> {
        let mut r = std::mem::MaybeUninit::<Rusage>::zeroed();
        // RUSAGE_SELF = 0
        if unsafe { getrusage(0, r.as_mut_ptr()) } != 0 {
            return None;
        }
        let r = unsafe { r.assume_init() };
        let s = |t: &Timeval| t.sec as f64 + t.usec as f64 / 1e6;
        Some((s(&r.utime), s(&r.stime)))
    }

    #[cfg(target_os = "macos")]
    pub fn rss_threads() -> Option<(u64, u64)> {
        /// <sys/proc_info.h> struct proc_taskinfo
        #[repr(C)]
        struct ProcTaskinfo {
            virtual_size: u64,
            resident_size: u64,
            total_user: u64,
            total_system: u64,
            threads_user: u64,
            threads_system: u64,
            policy: i32,
            faults: i32,
            pageins: i32,
            cow_faults: i32,
            messages_sent: i32,
            messages_received: i32,
            syscalls_mach: i32,
            syscalls_unix: i32,
            csw: i32,
            threadnum: i32,
            numrunning: i32,
            priority: i32,
        }
        extern "C" {
            fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut ProcTaskinfo, size: i32) -> i32;
        }
        const PROC_PIDTASKINFO: i32 = 4;
        let size = std::mem::size_of::<ProcTaskinfo>() as i32;
        let mut ti = std::mem::MaybeUninit::<ProcTaskinfo>::zeroed();
        let n = unsafe { proc_pidinfo(std::process::id() as i32, PROC_PIDTASKINFO, 0, ti.as_mut_ptr(), size) };
        if n != size {
            return None;
        }
        let ti = unsafe { ti.assume_init() };
        Some((ti.resident_size, ti.threadnum.max(0) as u64))
    }

    #[cfg(target_os = "linux")]
    pub fn rss_threads() -> Option<(u64, u64)> {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let field = |name: &str| {
            s.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        };
        Some((field("VmRSS:")? * 1024, field("Threads:")?))
    }
}

#[cfg(not(all(any(target_os = "macos", target_os = "linux"), target_pointer_width = "64")))]
mod sys {
    pub fn cpu_seconds() -> Option<(f64, f64)> {
        None
    }
    pub fn rss_threads() -> Option<(u64, u64)> {
        None
    }
}
