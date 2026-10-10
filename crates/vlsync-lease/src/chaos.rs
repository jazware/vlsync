//! An object store that misbehaves the ways a real one does: latency, 5xx
//! errors before a request is applied, and lost answers (applied, then the
//! client sees an error; a conditional PUT's retry would see a conflict,
//! which is what a lost answer looks like through object_store).
//!
//! Faults are random at the configured rates (seeded, so a failing run
//! replays), or armed one at a time with `fail_next` and `landed_next`.
//! `pause` makes every call wait until `resume`, like a partitioned node.

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMode,
    PutMultipartOptions, PutOptions, PutPayload, PutResult, Result,
};
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug)]
pub struct Knobs {
    rng: Mutex<StdRng>,
    /// Each call waits a uniform time in [0, this).
    pub latency: Mutex<Duration>,
    /// Probability a call fails before it's applied.
    pub error_rate: Mutex<f64>,
    /// Probability a PUT is applied and its answer lost.
    pub lost_rate: Mutex<f64>,
    fail: AtomicU32,
    landed: AtomicU32,
    paused: watch::Sender<bool>,
    /// Faults injected so far.
    pub injected: AtomicU64,
}

impl Knobs {
    /// The next `n` calls fail before they're applied.
    pub fn fail_next(&self, n: u32) {
        self.fail.store(n, Ordering::SeqCst);
    }

    /// The next `n` PUTs land and answer a conflict.
    pub fn landed_next(&self, n: u32) {
        self.landed.store(n, Ordering::SeqCst);
    }

    pub fn set(&self, latency: Duration, error_rate: f64, lost_rate: f64) {
        *self.latency.lock() = latency;
        *self.error_rate.lock() = error_rate;
        *self.lost_rate.lock() = lost_rate;
    }

    pub fn pause(&self) {
        self.paused.send_replace(true);
    }

    pub fn resume(&self) {
        self.paused.send_replace(false);
    }

    /// Waits while paused: a simulated node's own work (not a store call)
    /// stalls with its store, like a process stopped between a check and
    /// the write it guarded.
    pub async fn wait_resumed(&self) {
        let mut rx = self.paused.subscribe();
        let _ = rx.wait_for(|p| !*p).await;
    }

    fn take(n: &AtomicU32) -> bool {
        let mut cur = n.load(Ordering::SeqCst);
        while cur > 0 {
            match n.compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
        false
    }

    fn roll(&self, p: f64) -> bool {
        p > 0.0 && self.rng.lock().gen_bool(p.min(1.0))
    }

    async fn before(&self) -> Result<()> {
        let mut rx = self.paused.subscribe();
        let _ = rx.wait_for(|p| !*p).await;
        let max = *self.latency.lock();
        if !max.is_zero() {
            let d = max.mul_f64(self.rng.lock().gen::<f64>());
            tokio::time::sleep(d).await;
        }
        if Self::take(&self.fail) || self.roll(*self.error_rate.lock()) {
            self.injected.fetch_add(1, Ordering::Relaxed);
            return Err(object_store::Error::Generic { store: "chaos", source: "injected 503".into() });
        }
        Ok(())
    }

    fn lost(&self) -> bool {
        let lost = Self::take(&self.landed) || self.roll(*self.lost_rate.lock());
        if lost {
            self.injected.fetch_add(1, Ordering::Relaxed);
        }
        lost
    }
}

#[derive(Clone, Debug)]
pub struct ChaosStore {
    inner: Arc<dyn ObjectStore>,
    knobs: Arc<Knobs>,
}

impl ChaosStore {
    pub fn new(inner: Arc<dyn ObjectStore>) -> ChaosStore {
        ChaosStore::seeded(inner, 0)
    }

    pub fn seeded(inner: Arc<dyn ObjectStore>, seed: u64) -> ChaosStore {
        let knobs = Knobs {
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            latency: Mutex::new(Duration::ZERO),
            error_rate: Mutex::new(0.0),
            lost_rate: Mutex::new(0.0),
            fail: AtomicU32::new(0),
            landed: AtomicU32::new(0),
            paused: watch::channel(false).0,
            injected: AtomicU64::new(0),
        };
        ChaosStore { inner, knobs: Arc::new(knobs) }
    }

    /// Another client of the same objects with its own faults (one per
    /// simulated node).
    pub fn sibling(&self, seed: u64) -> ChaosStore {
        ChaosStore::seeded(self.inner.clone(), seed)
    }

    pub fn knobs(&self) -> &Arc<Knobs> {
        &self.knobs
    }
}

impl std::fmt::Display for ChaosStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChaosStore({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for ChaosStore {
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> Result<PutResult> {
        self.knobs.before().await?;
        let conditional = !matches!(opts.mode, PutMode::Overwrite);
        let r = self.inner.put_opts(location, payload, opts).await?;
        if self.knobs.lost() {
            // object_store retried and the retry was refused (conditional),
            // or it gave up on a timeout (unconditional)
            return Err(if conditional {
                object_store::Error::Precondition {
                    path: location.to_string(),
                    source: "chaos: landed, answer lost".into(),
                }
            } else {
                object_store::Error::Generic { store: "chaos", source: "landed, answer lost".into() }
            });
        }
        Ok(r)
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
        self.knobs.before().await?;
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        self.knobs.before().await?;
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(&self, locations: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
        let knobs = self.knobs.clone();
        let inner = self.inner.clone();
        futures::stream::once(async move {
            match knobs.before().await {
                Ok(()) => inner.delete_stream(locations),
                Err(e) => futures::stream::once(async move { Err(e) }).boxed(),
            }
        })
        .flatten()
        .boxed()
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        let knobs = self.knobs.clone();
        let inner = self.inner.clone();
        let prefix = prefix.cloned();
        futures::stream::once(async move {
            match knobs.before().await {
                Ok(()) => inner.list(prefix.as_ref()),
                Err(e) => futures::stream::once(async move { Err(e) }).boxed(),
            }
        })
        .flatten()
        .boxed()
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        self.knobs.before().await?;
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        self.knobs.before().await?;
        self.inner.copy_opts(from, to, options).await
    }
}
