//! Store throttling (HTTP 429, and S3's 503 SlowDown). object_store retries
//! both inside its client, so the request counters above it (objstats.rs)
//! never see them: each answer is counted here, at the HTTP layer, by the
//! kind of key it was for.
//!
//! R2 takes about one write a second to one key and answers more with 429.
//! A node renews its own lease key every TTL/5, so those writes back off
//! from a 1 s floor ([`ctl_write_retry`]). Everything else keeps
//! object_store's default schedule. Assignment and writer-claim CASes run
//! under the step's call deadline (min(TTL, 5 s)), where a 1 s floor would
//! turn a throttled answer into a step timeout. They are retried next step
//! anyway, and a lost race there is a precondition failure, never a 429
//! loop.

use async_trait::async_trait;
use futures::stream::BoxStream;
use object_store::client::{
    HttpClient, HttpConnector, HttpError, HttpRequest, HttpResponse, HttpService, ReqwestConnector,
};
use object_store::path::Path;
use object_store::{
    BackoffConfig, ClientOptions, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMultipartOptions, PutOptions, PutPayload, PutResult, Result, RetryConfig,
};
use std::sync::Arc;
use std::time::Duration;

pub const KINDS: [&str; 3] = ["lease", "segment", "other"];

/// The first retry of a throttled lease write waits at least this long
/// (one write a second to a key), or `renew_every` if that's shorter.
pub const CTL_WRITE_FLOOR: Duration = Duration::from_secs(1);
/// No retry of a lease write waits longer.
pub const CTL_WRITE_CAP: Duration = Duration::from_secs(4);

/// `lease` for control-plane objects (node leases, assignments, writer
/// claims, the cluster version), `segment` for commit-log segments.
pub fn kind(component: &str) -> &'static str {
    match component {
        c if c.starts_with("ctl_") => "lease",
        "log_segment" => "segment",
        _ => "other",
    }
}

/// The retry schedule of a node's writes to its own lease. object_store
/// waits exactly `init_backoff` before the first retry and then a uniform
/// draw from [init, 2 x the last wait], capped. `jitter` (in [0, 1)) moves
/// the floor up to half again, so nodes throttled together don't all
/// resend a second later. The floor never exceeds `renew_every`: a renewal
/// earns validity from its first send, so a long first wait at a short TTL
/// would eat the margin the next tick needs.
pub fn ctl_write_retry(jitter: f64, renew_every: Duration) -> RetryConfig {
    let init = CTL_WRITE_FLOOR.mul_f64(1.0 + jitter.clamp(0.0, 1.0) / 2.0).min(renew_every);
    RetryConfig {
        backoff: BackoffConfig { init_backoff: init, max_backoff: CTL_WRITE_CAP.max(init), base: 2.0 },
        ..RetryConfig::default()
    }
}

/// Wraps the reqwest connector to count throttled answers.
#[derive(Debug)]
pub struct Counting {
    bucket: String,
    prefix: String,
}

impl Counting {
    pub fn new(bucket: &str, prefix: &str) -> Counting {
        Counting { bucket: bucket.to_string(), prefix: prefix.trim_end_matches('/').to_string() }
    }
}

impl HttpConnector for Counting {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        let inner = ReqwestConnector::default().connect(options)?;
        Ok(HttpClient::new(CountingService { inner, bucket: self.bucket.clone(), prefix: self.prefix.clone() }))
    }
}

#[derive(Debug)]
struct CountingService {
    inner: HttpClient,
    bucket: String,
    prefix: String,
}

/// `%XX` escapes decoded (S3 query values; keys here are ASCII).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b'+', _, _) => {
                out.push(b' ');
                i += 1;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl CountingService {
    /// By the key a path-style request names, or for a bucket-level one
    /// (a LIST) its `prefix=`. A bulk delete (POST ?delete) names its keys
    /// only in the body: `other`.
    fn kind_of(&self, uri_path: &str, query: Option<&str>) -> &'static str {
        let path = uri_path.strip_prefix('/').unwrap_or(uri_path);
        let key = match path.strip_prefix(self.bucket.as_str()) {
            Some("") | Some("/") => {
                let prefix = query
                    .into_iter()
                    .flat_map(|q| q.split('&'))
                    .find_map(|kv| kv.strip_prefix("prefix="))
                    .map(percent_decode);
                match prefix {
                    Some(p) => p,
                    None => return "other",
                }
            }
            Some(rest) => percent_decode(rest.strip_prefix('/').unwrap_or(rest)),
            None => return "other",
        };
        kind(crate::objstats::component(&self.prefix, &key))
    }
}

#[async_trait]
impl HttpService for CountingService {
    async fn call(&self, req: HttpRequest) -> std::result::Result<HttpResponse, HttpError> {
        let kind = self.kind_of(req.uri().path(), req.uri().query());
        let r = self.inner.execute(req).await?;
        match r.status().as_u16() {
            429 => crate::metrics::STORE_THROTTLED.with_label_values(&[kind]).inc(),
            // a 503 is throttling only when S3 says SlowDown; else an outage
            503 => {
                let (parts, body) = r.into_parts();
                let body = body.bytes().await?;
                if body.windows(8).any(|w| w == b"SlowDown") {
                    crate::metrics::STORE_THROTTLED.with_label_values(&[kind]).inc();
                }
                return Ok(HttpResponse::from_parts(parts, body.into()));
            }
            _ => {}
        }
        Ok(r)
    }
}

/// The control plane's client: writes to node leases (`nodes/`) on one
/// with [`ctl_write_retry`], everything else on one with the default
/// schedule.
#[derive(Debug)]
pub struct LeaseWrites {
    pub plain: Arc<dyn ObjectStore>,
    pub lease: Arc<dyn ObjectStore>,
    pub prefix: String,
}

impl LeaseWrites {
    fn for_put(&self, location: &Path) -> &Arc<dyn ObjectStore> {
        if crate::objstats::component(&self.prefix, location.as_ref()) == "ctl_lease" {
            &self.lease
        } else {
            &self.plain
        }
    }
}

impl std::fmt::Display for LeaseWrites {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LeaseWrites({})", self.plain)
    }
}

#[async_trait]
impl ObjectStore for LeaseWrites {
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> Result<PutResult> {
        self.for_put(location).put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOptions) -> Result<Box<dyn MultipartUpload>> {
        self.plain.put_multipart_opts(location, opts).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        self.plain.get_opts(location, options).await
    }

    fn delete_stream(&self, locations: BoxStream<'static, Result<Path>>) -> BoxStream<'static, Result<Path>> {
        self.plain.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        self.plain.list(prefix)
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) -> BoxStream<'static, Result<ObjectMeta>> {
        self.plain.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        self.plain.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        self.plain.copy_opts(from, to, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        let s = CountingService {
            inner: ReqwestConnector::default().connect(&ClientOptions::new()).unwrap(),
            bucket: "b".into(),
            prefix: "vlpds".into(),
        };
        for (path, query, want) in [
            ("/b/vlpds/nodes/a", None, "lease"),
            ("/b/vlpds/assign/0000000001", None, "lease"),
            ("/b/vlpds/writers/007", None, "lease"),
            ("/b/vlpds/cluster/version", None, "lease"),
            ("/b/vlpds/log/a.1/00000000000000000001.seg", None, "segment"),
            ("/b/vlpds/log/a.1/00000000000000000001.seg", Some("uploads"), "segment"),
            ("/b/vlpds/state/0000000001/manifest/1.manifest", None, "other"),
            // LISTs name the prefix in the query
            ("/b", Some("list-type=2&prefix=vlpds%2Fnodes%2F"), "lease"),
            ("/b/", Some("list-type=2&prefix=vlpds%2Fassign%2F&start-after=x"), "lease"),
            ("/b", Some("list-type=2&prefix=vlpds%2Flog%2Fa.1%2F"), "segment"),
            ("/b", Some("list-type=2"), "other"),
            // a bulk delete names its keys in the body
            ("/b", Some("delete"), "other"),
            ("/elsewhere/x", None, "other"),
            ("/bb/vlpds/nodes/a", None, "other"),
        ] {
            assert_eq!(s.kind_of(path, query), want, "{path}?{query:?}");
        }
    }

    #[test]
    fn ctl_write_schedule_starts_at_the_floor_and_is_capped() {
        let every = Duration::from_secs(2);
        let r = ctl_write_retry(0.0, every);
        assert_eq!(r.backoff.init_backoff, CTL_WRITE_FLOOR);
        assert_eq!(r.backoff.max_backoff, CTL_WRITE_CAP);
        assert_eq!(r.backoff.base, 2.0);
        assert_eq!(ctl_write_retry(0.999_999, every).backoff.init_backoff.as_millis(), 1499);
        assert_eq!(ctl_write_retry(7.0, every).backoff.init_backoff, CTL_WRITE_FLOOR.mul_f64(1.5));
        // a short TTL's renew interval caps the floor (one throttled answer
        // must not eat its validity margin)
        let short = Duration::from_millis(600);
        assert_eq!(ctl_write_retry(0.9, short).backoff.init_backoff, short);
        assert_eq!(ctl_write_retry(0.9, Duration::from_millis(50)).backoff.max_backoff, CTL_WRITE_CAP);
        // the rest is object_store's default (10 retries within 3 min)
        let d = RetryConfig::default();
        assert_eq!((r.max_retries, r.retry_timeout), (d.max_retries, d.retry_timeout));
    }

    /// Against a fake S3 that answers each key's first two PUTs 429 (or a
    /// 503, SlowDown or not): a node lease's retries wait at least the
    /// floor, an assignment CAS and a segment keep object_store's 100 ms
    /// start, every 429 and SlowDown is counted by kind, and a plain 503
    /// (an outage) isn't.
    #[tokio::test]
    async fn throttled_writes_back_off_by_client_and_are_counted() {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        use object_store::{ObjectStoreExt, PutMode, UpdateVersion};
        use std::time::Instant;

        let hits = Arc::new(parking_lot::Mutex::new(Vec::<(String, Instant)>::new()));
        let h = hits.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let h = h.clone();
            async move {
                let key = format!("{} {}", req.method(), req.uri().path());
                let n = {
                    let mut v = h.lock();
                    v.push((key.clone(), Instant::now()));
                    v.iter().filter(|(k, _)| *k == key).count()
                };
                if n <= 2 && key.contains("outage") {
                    (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable").into_response()
                } else if n <= 2 && key.contains("slow") {
                    (StatusCode::SERVICE_UNAVAILABLE, "<Error><Code>SlowDown</Code></Error>").into_response()
                } else if n <= 2 {
                    (StatusCode::TOO_MANY_REQUESTS, "<Error><Code>TooManyRequests</Code></Error>").into_response()
                } else {
                    (StatusCode::OK, [("etag", "\"e1\"")], "").into_response()
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let cfg = crate::store::S3Config {
            endpoint: format!("http://{addr}"),
            bucket: "b".into(),
            access_key: "k".into(),
            secret_key: "s".into(),
            region: "auto".into(),
        };
        let ctl = crate::store::Store::s3_ctl(&cfg, "vlpds", 4, Duration::from_secs(2)).unwrap();
        let log = crate::store::Store::s3(&cfg, "vlpds", None, 4).unwrap();
        let count = |k: &str| crate::metrics::STORE_THROTTLED.with_label_values(&[k]).get();
        let (lease0, seg0, other0) = (count("lease"), count("segment"), count("other"));

        let cas = PutOptions {
            mode: PutMode::Update(UpdateVersion { e_tag: Some("\"e0\"".into()), version: None }),
            ..Default::default()
        };
        ctl.raw.put_opts(&Path::from("vlpds/nodes/a"), PutPayload::from_static(b"{}"), cas.clone()).await.unwrap();
        ctl.raw.put_opts(&Path::from("vlpds/assign/0000000001"), PutPayload::from_static(b"{}"), cas).await.unwrap();
        for key in ["vlpds/blob/slow", "vlpds/blob/outage"] {
            log.raw.put(&Path::from(key), PutPayload::from_static(b"x")).await.unwrap();
        }
        log.raw
            .put(&Path::from("vlpds/log/a.1/00000000000000000001.seg"), PutPayload::from_static(b"x"))
            .await
            .unwrap();

        let sent =
            |key: &str| -> Vec<Instant> { hits.lock().iter().filter(|(k, _)| k == key).map(|&(_, t)| t).collect() };
        let lease = sent("PUT /b/vlpds/nodes/a");
        let seg = sent("PUT /b/vlpds/log/a.1/00000000000000000001.seg");
        assert_eq!((lease.len(), seg.len()), (3, 3));
        for w in lease.windows(2) {
            assert!(w[1] - w[0] >= CTL_WRITE_FLOOR, "lease retry {:?} after the last", w[1] - w[0]);
            assert!(w[1] - w[0] < CTL_WRITE_CAP + Duration::from_millis(500), "lease retry {:?}", w[1] - w[0]);
        }
        assert!(seg[2] - seg[0] < CTL_WRITE_FLOOR, "segment retries keep the default: {:?}", seg[2] - seg[0]);
        let assign = sent("PUT /b/vlpds/assign/0000000001");
        assert_eq!(assign.len(), 3);
        assert!(assign[2] - assign[0] < CTL_WRITE_FLOOR, "a CAS keeps the default: {:?}", assign[2] - assign[0]);
        assert_eq!(sent("PUT /b/vlpds/blob/outage").len(), 3, "a plain 503 is retried too");
        assert_eq!(
            (count("lease") - lease0, count("segment") - seg0, count("other") - other0),
            (4, 2, 2),
            "429s and SlowDowns, not the outage's 503s"
        );
    }
}
