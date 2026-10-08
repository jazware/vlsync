//! Process lifecycle metrics that outlive the process: start time and how
//! the previous process ended.
//!
//! A fail-stop exits right after deciding to, so a counter bumped on the way
//! out is almost never scraped. Instead [`fail_stop`] writes its reason to a
//! small local file that the next process exports at startup ([`init`]).
//! `init` marks the file `running`, so a process that dies without recording
//! an exit (SIGKILL, OOM, host loss) is reported as `crash` next time.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static STARTED: LazyLock<f64> = LazyLock::new(unix_secs);

static FILE: OnceLock<PathBuf> = OnceLock::new();

fn unix_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ExitRecord {
    /// `running` while a process uses the file, else how it ended.
    reason: String,
    code: Option<i32>,
    at: f64,
    pid: u32,
}

/// (reason, code label, time) as exported.
fn previous(record: Option<ExitRecord>) -> (String, String, f64) {
    match record {
        None => ("none".into(), String::new(), 0.0),
        Some(r) if r.reason == "running" => ("crash".into(), String::new(), 0.0),
        Some(r) => (r.reason, r.code.map(|c| c.to_string()).unwrap_or_default(), r.at),
    }
}

fn read(path: &Path) -> Option<ExitRecord> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write(path: &Path, rec: &ExitRecord) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(rec).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

pub fn init(path: Option<PathBuf>) {
    LazyLock::force(&STARTED);
    let prev = path.as_deref().and_then(read);
    let (reason, code, at) = previous(prev);
    crate::metrics::LAST_EXIT.reset();
    crate::metrics::LAST_EXIT.with_label_values(&[reason.as_str(), code.as_str()]).set(1);
    crate::metrics::LAST_EXIT_TIME.set(at);
    if reason != "none" {
        tracing::info!(reason, code, "previous process exit");
    }
    let Some(path) = path else { return };
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(dir);
    }
    let running = ExitRecord { reason: "running".into(), code: None, at: *STARTED, pid: std::process::id() };
    match write(&path, &running) {
        Ok(()) => {
            let _ = FILE.set(path);
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), "exit-state file not writable (fail-stop reasons will not be kept): {e}")
        }
    }
}

pub fn record_exit(code: i32, reason: &str) {
    if let Some(path) = FILE.get() {
        let rec = ExitRecord { reason: reason.into(), code: Some(code), at: unix_secs(), pid: std::process::id() };
        if let Err(e) = write(path, &rec) {
            tracing::warn!(path = %path.display(), "recording exit failed: {e}");
        }
    }
}

/// Exit codes: 2 segment upload, 3 log fenced / ordinal taken, 4 state
/// apply, 5 lease lost or lapsed, 6 repeated signature faults, 8 a graceful
/// shutdown couldn't fence its own log, 9 a critical thread or task panicked.
pub fn fail_stop(code: i32, reason: &str) -> ! {
    record_exit(code, reason);
    // Straight to fd 2, not eprintln!: libtest captures eprintln! and loses
    // it when exit kills the binary, leaving a bare "exit status: N".
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "vlpds fail-stop: exit {code} ({reason}) on thread {}",
        std::thread::current().name().unwrap_or("?")
    );
    std::process::exit(code)
}

// Critical threads and tasks are never restarted (repo workers, the node
// log's sequencer and finalizer, the firehose merger). Tokio catches task
// panics, so without this a panic in one would leave the node up but wedged;
// the panic hook fail-stops instead so peers take its shards over.
thread_local! {
    static CRITICAL_THREAD: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

tokio::task_local! {
    static CRITICAL_TASK: &'static str;
}

pub fn mark_critical_thread(name: &'static str) {
    CRITICAL_THREAD.with(|c| c.set(Some(name)));
}

/// A panic while `fut` is polled fail-stops the process.
pub fn critical<F: std::future::Future>(name: &'static str, fut: F) -> impl std::future::Future<Output = F::Output> {
    CRITICAL_TASK.scope(name, fut)
}

fn critical_context() -> Option<&'static str> {
    CRITICAL_TASK.try_with(|n| *n).ok().or_else(|| CRITICAL_THREAD.with(|c| c.get()))
}

fn fail_stop_critical(name: &'static str) {
    tracing::error!(task = name, "critical task panicked: fail-stop (exit 9)");
    fail_stop(9, "critical_task_panicked")
}

pub fn install_panic_hook() {
    install_panic_hook_with(fail_stop_critical)
}

fn install_panic_hook_with(on_critical: fn(&'static str)) {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        prev(info);
        if let Some(name) = critical_context() {
            on_critical(name);
        }
    }));
}

pub fn refresh_metrics() {
    crate::metrics::PROCESS_START.set(*STARTED);
    crate::metrics::PROCESS_START_STD.set(*STARTED);
}

/// Test hook: asked at each named phase of some multi-step work; true stops
/// that work dead there, as a crash would.
pub type CrashHook = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Test crash hooks keyed by whatever names the work (a node id, a DID).
pub struct CrashHooks(parking_lot::RwLock<Option<std::collections::HashMap<String, CrashHook>>>);

impl CrashHooks {
    pub const fn new() -> Self {
        CrashHooks(parking_lot::RwLock::new(None))
    }

    pub fn set(&self, key: &str, h: Option<CrashHook>) {
        let mut g = self.0.write();
        let m = g.get_or_insert_with(Default::default);
        match h {
            Some(h) => m.insert(key.to_string(), h),
            None => m.remove(key),
        };
    }

    pub fn fires(&self, key: &str, phase: &str) -> bool {
        let h = self.0.read().as_ref().and_then(|m| m.get(key).cloned());
        h.is_some_and(|h| h(phase))
    }
}

impl Default for CrashHooks {
    fn default() -> Self {
        CrashHooks::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_micros() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros()
    }

    #[test]
    fn previous_exit_from_the_file() {
        let dir = std::env::temp_dir().join(format!("vlpds-lifecycle-{}-{}", std::process::id(), now_micros()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("exit.json");
        assert_eq!(previous(read(&path)).0, "none");
        write(&path, &ExitRecord { reason: "running".into(), code: None, at: 1.0, pid: 1 }).unwrap();
        assert_eq!(previous(read(&path)), ("crash".into(), String::new(), 0.0));
        write(&path, &ExitRecord { reason: "fenced".into(), code: Some(3), at: 42.0, pid: 1 }).unwrap();
        assert_eq!(previous(read(&path)), ("fenced".into(), "3".into(), 42.0));
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(previous(read(&path)).0, "none");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The only test that calls `init` (it sets the process-wide file).
    #[test]
    fn init_exports_the_previous_exit_and_marks_running() {
        let dir = std::env::temp_dir().join(format!("vlpds-lifecycle-init-{}-{}", std::process::id(), now_micros()));
        let path = dir.join("sub").join("exit.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write(&path, &ExitRecord { reason: "lease_lost".into(), code: Some(5), at: 7.0, pid: 1 }).unwrap();
        init(Some(path.clone()));
        assert_eq!(crate::metrics::LAST_EXIT.with_label_values(&["lease_lost", "5"]).get(), 1);
        assert_eq!(crate::metrics::LAST_EXIT_TIME.get(), 7.0);
        let now = read(&path).unwrap();
        assert_eq!((now.reason.as_str(), now.code, now.pid), ("running", None, std::process::id()));
        record_exit(3, "fenced");
        assert_eq!(previous(read(&path)).0, "fenced");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn critical_panics_reach_the_hook() {
        static HITS: parking_lot::Mutex<Vec<&'static str>> = parking_lot::Mutex::new(Vec::new());
        fn record(name: &'static str) {
            HITS.lock().push(name);
        }
        install_panic_hook_with(record);
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async {
            assert!(tokio::spawn(async { panic!("ordinary task") }).await.is_err());
            assert!(tokio::spawn(critical("test-critical-task", async {
                tokio::task::yield_now().await;
                panic!("injected")
            }))
            .await
            .is_err());
            assert_eq!(critical_context(), None);
        });
        assert!(std::thread::spawn(|| panic!("ordinary thread")).join().is_err());
        assert!(std::thread::spawn(|| {
            mark_critical_thread("test-critical-thread");
            panic!("injected")
        })
        .join()
        .is_err());
        let hits = HITS.lock().clone();
        assert!(hits.contains(&"test-critical-task") && hits.contains(&"test-critical-thread"), "{hits:?}");
    }

    #[test]
    fn start_time_is_exported() {
        refresh_metrics();
        let now = unix_secs();
        let v = crate::metrics::PROCESS_START.get();
        assert!(v > 1.7e9 && v <= now, "{v}");
        assert_eq!(crate::metrics::PROCESS_START_STD.get(), v);
    }
}
