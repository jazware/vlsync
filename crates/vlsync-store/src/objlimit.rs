//! Bounds the object-store requests one client (connection pool) has in
//! flight, so a burst queues for a permit instead of opening a connection
//! each. The HTTP client opens a connection whenever every pooled one is
//! busy and closes the surplus into TIME_WAIT; unbounded, a takeover at load
//! exhausted the host's ephemeral ports and lease renewals failed with
//! everything else. With `limit` permits and `limit` idle connections kept,
//! a pool never churns.
//!
//! A client may have a reserved lane for requests matching its [`Reserve`]
//! (segment PUTs on the log client, lease renewals on the control plane), so
//! bulk traffic never delays them.
//!
//! A permit is held for the whole request, including retries and a GET's
//! body until read or dropped (the connection is busy until then), except:
//! blob bodies stream to HTTP clients at their pace, so one slow reader
//! must not hold a permit; LIST and bulk-DELETE streams release at their
//! first response, since a caller may issue requests while walking a listing
//! and holding it could deadlock a saturated pool.

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, GetResultPayload, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult, Result, UploadPart,
};
use prometheus::{Histogram, IntCounter, IntGauge};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Headroom, not a throttle: steady state is far below it.
pub const DEFAULT_STATE_INFLIGHT: usize = 1024;
pub const DEFAULT_LOG_INFLIGHT: usize = 256;
pub const LOG_WRITE_PERMITS: usize = 64;
/// A control-plane step fans out to at most 32 calls at once.
pub const CTL_PERMITS: usize = 64;
pub const LEASE_PERMITS: usize = 8;

/// Each in-flight segment PUT may be hedged once more.
pub fn log_write_permits(log_inflight: usize) -> usize {
    LOG_WRITE_PERMITS.max(4 * log_inflight)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserve {
    None,
    Writes,
    /// PUTs to node leases (`nodes/*`).
    LeaseWrites,
}

impl Reserve {
    fn reserved(self, write: bool, comp: &str) -> bool {
        match self {
            Reserve::None => false,
            Reserve::Writes => write,
            Reserve::LeaseWrites => write && comp == "ctl_lease",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    main: usize,
    reserved: usize,
    reserve: Reserve,
}

impl Limits {
    pub fn new(main: usize) -> Limits {
        Limits { main: main.max(1), reserved: 0, reserve: Reserve::None }
    }

    pub fn with_reserved(self, reserve: Reserve, n: usize) -> Limits {
        Limits { reserved: n.max(1), reserve, ..self }
    }

    /// What the client's pool should keep idle so none is closed and reopened.
    pub fn connections(&self) -> usize {
        self.main + if self.reserve == Reserve::None { 0 } else { self.reserved }
    }
}

#[derive(Clone, Debug)]
struct Lane {
    sem: Arc<Semaphore>,
    inflight: IntGauge,
    waits: IntCounter,
    wait_s: Histogram,
}

impl Lane {
    fn new(client: &str, lane: &str, n: usize) -> Lane {
        let l = [client, lane];
        crate::metrics::OBJ_INFLIGHT_LIMIT.with_label_values(&l).set(n as i64);
        Lane {
            sem: Arc::new(Semaphore::new(n)),
            inflight: crate::metrics::OBJ_INFLIGHT.with_label_values(&l),
            waits: crate::metrics::OBJ_PERMIT_WAITS.with_label_values(&l),
            wait_s: crate::metrics::OBJ_PERMIT_WAIT_SECONDS.with_label_values(&l),
        }
    }

    async fn acquire(&self) -> Permit {
        let p = match self.sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.waits.inc();
                let t = Instant::now();
                let p = self.sem.clone().acquire_owned().await.expect("object-store semaphore is never closed");
                self.wait_s.observe(t.elapsed().as_secs_f64());
                p
            }
        };
        self.inflight.inc();
        Permit { _p: p, inflight: self.inflight.clone() }
    }
}

struct Permit {
    _p: OwnedSemaphorePermit,
    inflight: IntGauge,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.inflight.dec();
    }
}

#[derive(Debug)]
struct Limited {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
    client: &'static str,
    main: Lane,
    reserved: Option<Lane>,
    reserve: Reserve,
}

pub fn limited(
    inner: Arc<dyn ObjectStore>,
    prefix: &str,
    client: &'static str,
    limits: Limits,
) -> Arc<dyn ObjectStore> {
    Arc::new(Limited {
        inner,
        prefix: prefix.trim_end_matches('/').to_string(),
        client,
        main: Lane::new(client, "main", limits.main),
        reserved: (limits.reserve != Reserve::None).then(|| Lane::new(client, "reserved", limits.reserved)),
        reserve: limits.reserve,
    })
}

impl Limited {
    fn lane(&self, write: bool, p: &Path) -> &Lane {
        match &self.reserved {
            Some(r) if self.reserve.reserved(write, crate::objstats::component(&self.prefix, p.as_ref())) => r,
            _ => &self.main,
        }
    }
}

impl std::fmt::Display for Limited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Limited({}, {})", self.client, self.inner)
    }
}

fn hold_until_end<T: Send + 'static>(
    mut s: BoxStream<'static, Result<T>>,
    permit: Permit,
) -> BoxStream<'static, Result<T>> {
    let mut permit = Some(permit);
    futures::stream::poll_fn(move |cx| {
        let item = futures::ready!(s.poll_next_unpin(cx));
        if !matches!(item, Some(Ok(_))) {
            drop(permit.take());
        }
        std::task::Poll::Ready(item)
    })
    .boxed()
}

fn hold_until_first<T: Send + 'static>(
    lane: Lane,
    make: impl FnOnce() -> BoxStream<'static, T> + Send + 'static,
) -> BoxStream<'static, T> {
    futures::stream::once(async move {
        let mut permit = Some(lane.acquire().await);
        make().inspect(move |_| {
            permit.take();
        })
    })
    .flatten()
    .boxed()
}

#[async_trait]
impl ObjectStore for Limited {
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> Result<PutResult> {
        let _p = self.lane(true, location).acquire().await;
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
        let lane = self.lane(true, location).clone();
        let inner = {
            let _p = lane.acquire().await;
            self.inner.put_multipart_opts(location, opts).await?
        };
        Ok(Box::new(LimitedUpload { inner, lane }))
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        let p = self.lane(false, location).acquire().await;
        let head = options.head;
        let mut r = self.inner.get_opts(location, options).await?;
        if !head && crate::objstats::component(&self.prefix, location.as_ref()) != "blob" {
            if let GetResultPayload::Stream(s) = r.payload {
                r.payload = GetResultPayload::Stream(hold_until_end(s, p));
            }
        }
        Ok(r)
    }

    fn delete_stream(&self, locations: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
        let inner = self.inner.clone();
        hold_until_first(self.main.clone(), move || inner.delete_stream(locations))
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        let (inner, prefix) = (self.inner.clone(), prefix.cloned());
        hold_until_first(self.main.clone(), move || inner.list(prefix.as_ref()))
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) -> BoxStream<'static, Result<ObjectMeta>> {
        let (inner, prefix, offset) = (self.inner.clone(), prefix.cloned(), offset.clone());
        hold_until_first(self.main.clone(), move || inner.list_with_offset(prefix.as_ref(), &offset))
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        let _p = self.main.acquire().await;
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        let _p = self.lane(true, to).acquire().await;
        self.inner.copy_opts(from, to, options).await
    }
}

#[derive(Debug)]
struct LimitedUpload {
    inner: Box<dyn MultipartUpload>,
    lane: Lane,
}

#[async_trait]
impl MultipartUpload for LimitedUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        // the part's request starts when its future is first polled
        let part = self.inner.put_part(data);
        let lane = self.lane.clone();
        Box::pin(async move {
            let _p = lane.acquire().await;
            part.await
        })
    }

    async fn complete(&mut self) -> Result<PutResult> {
        let _p = self.lane.acquire().await;
        self.inner.complete().await
    }

    async fn abort(&mut self) -> Result<()> {
        let _p = self.lane.acquire().await;
        self.inner.abort().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::{ObjectStoreExt, PutMode};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Counts concurrent requests (to the response head; a GET's body until
    /// read) and their peak; each takes `delay`.
    #[derive(Debug)]
    struct Gauge {
        inner: Arc<dyn ObjectStore>,
        read_delay: Duration,
        write_delay: Duration,
        now: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl Gauge {
        fn new(inner: Arc<dyn ObjectStore>, delay: Duration) -> Arc<Gauge> {
            Self::with(inner, delay, delay)
        }

        fn with(inner: Arc<dyn ObjectStore>, read_delay: Duration, write_delay: Duration) -> Arc<Gauge> {
            Arc::new(Gauge { inner, read_delay, write_delay, now: Default::default(), peak: Default::default() })
        }

        async fn enter(&self, write: bool) -> impl Drop {
            struct G(Arc<AtomicUsize>);
            impl Drop for G {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(n, Ordering::SeqCst);
            let g = G(self.now.clone());
            tokio::time::sleep(if write { self.write_delay } else { self.read_delay }).await;
            g
        }
    }

    impl std::fmt::Display for Gauge {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Gauge")
        }
    }

    #[async_trait]
    impl ObjectStore for Gauge {
        async fn put_opts(&self, l: &Path, p: PutPayload, o: PutOptions) -> Result<PutResult> {
            let _g = self.enter(true).await;
            self.inner.put_opts(l, p, o).await
        }
        async fn put_multipart_opts(&self, l: &Path, o: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(l, o).await
        }
        async fn get_opts(&self, l: &Path, o: GetOptions) -> Result<GetResult> {
            let _g = self.enter(false).await;
            self.inner.get_opts(l, o).await
        }
        fn delete_stream(&self, l: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
            self.inner.delete_stream(l)
        }
        fn list(&self, p: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
            self.inner.list(p)
        }
        fn list_with_offset(&self, p: Option<&Path>, o: &Path) -> BoxStream<'static, Result<ObjectMeta>> {
            self.inner.list_with_offset(p, o)
        }
        async fn list_with_delimiter(&self, p: Option<&Path>) -> Result<ListResult> {
            let _g = self.enter(false).await;
            self.inner.list_with_delimiter(p).await
        }
        async fn copy_opts(&self, f: &Path, t: &Path, o: CopyOptions) -> Result<()> {
            let _g = self.enter(true).await;
            self.inner.copy_opts(f, t, o).await
        }
    }

    #[tokio::test]
    async fn bounds_concurrent_requests() {
        let gauge = Gauge::new(Arc::new(object_store::memory::InMemory::new()), Duration::from_millis(5));
        let s = limited(gauge.clone(), "lim", "test_bound", Limits::new(8));
        let p = Path::from("lim/state/001/x");
        s.put(&p, PutPayload::from_static(b"hello")).await.unwrap();
        futures::future::join_all((0..200).map(|_| async { s.get(&p).await.unwrap().bytes().await.unwrap() })).await;
        assert!(gauge.peak.load(Ordering::SeqCst) <= 8, "peak {}", gauge.peak.load(Ordering::SeqCst));
        let l = ["test_bound", "main"];
        assert_eq!(crate::metrics::OBJ_INFLIGHT.with_label_values(&l).get(), 0, "every permit returned");
        assert!(crate::metrics::OBJ_PERMIT_WAITS.with_label_values(&l).get() > 0);
        assert_eq!(crate::metrics::OBJ_INFLIGHT_LIMIT.with_label_values(&l).get(), 8);
    }

    #[tokio::test]
    async fn get_bodies_hold_their_permit_until_read() {
        let s = limited(Arc::new(object_store::memory::InMemory::new()), "lim", "test_body", Limits::new(1));
        let (a, b) = (Path::from("lim/state/001/a"), Path::from("lim/blob/did/cid"));
        s.put(&a, PutPayload::from_static(b"a")).await.unwrap();
        s.put(&b, PutPayload::from_static(b"b")).await.unwrap();
        let held = s.get(&a).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), s.get(&a)).await.is_err(),
            "the unread body holds the only permit"
        );
        drop(held);
        // a blob body streams at its reader's pace: released at the head
        let blob = s.get(&b).await.unwrap();
        assert_eq!(s.get(&a).await.unwrap().bytes().await.unwrap().as_ref(), b"a");
        assert_eq!(blob.bytes().await.unwrap().as_ref(), b"b");
    }

    #[tokio::test]
    async fn listings_release_after_their_first_response() {
        let s = limited(Arc::new(object_store::memory::InMemory::new()), "lim", "test_list", Limits::new(1));
        for i in 0..3 {
            s.put(&Path::from(format!("lim/log/x/{i}")), PutPayload::from_static(b"x")).await.unwrap();
        }
        // a caller may GET each listed key while it walks the listing
        let mut list = s.list(Some(&Path::from("lim/log/x")));
        let mut n = 0;
        while let Some(m) = list.next().await {
            let m = m.unwrap();
            tokio::time::timeout(Duration::from_secs(5), s.get(&m.location)).await.expect("no deadlock").unwrap();
            n += 1;
        }
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn reserved_lane_is_never_starved() {
        // reads stall for an hour; writes answer at once
        let gauge =
            Gauge::with(Arc::new(object_store::memory::InMemory::new()), Duration::from_secs(3600), Duration::ZERO);
        let s = limited(gauge, "lim", "test_ctl", Limits::new(2).with_reserved(Reserve::LeaseWrites, 1));
        // the main lane is full, more requests queue behind it
        let stalled: Vec<_> = (0..4)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move { s.get(&Path::from(format!("lim/assign/{i}"))).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(crate::metrics::OBJ_INFLIGHT.with_label_values(&["test_ctl", "main"]).get(), 2);
        // a lease PUT still goes through; a PUT elsewhere waits in the main lane
        let (lease, assign) = (Path::from("lim/nodes/n1"), Path::from("lim/assign/9"));
        let renew = s.put_opts(&lease, PutPayload::from_static(b"{}"), PutMode::Overwrite.into());
        tokio::time::timeout(Duration::from_secs(5), renew).await.expect("renewal not starved").unwrap();
        let other = s.put_opts(&assign, PutPayload::from_static(b"{}"), PutMode::Overwrite.into());
        assert!(tokio::time::timeout(Duration::from_millis(50), other).await.is_err());
        for t in stalled {
            t.abort();
        }
    }
}
