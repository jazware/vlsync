//! DID document resolution with a TTL cache, plus the SSRF policy for
//! outbound requests to user-controlled endpoints. DIDs of accounts active
//! here never come through this (`xrpc::identity::account_did_doc`).

use parking_lot::Mutex;
use serde_json::Value as J;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(600);
const MAX_DOC_BYTES: usize = 256 << 10;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Failures are remembered so a stream of requests naming a bogus DID
/// (forged service JWTs, ...) doesn't turn into a stream of outbound fetches.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);
const SIDE_MAP_CAP: usize = 10_000;

#[derive(Clone, Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("unsupported or malformed DID: {0}")]
    BadDid(String),
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("could not resolve DID {0}: {1}")]
    Failed(String, String),
}

pub struct DidResolver {
    plc_url: String,
    /// Allow http:// and private addresses (dev/test only).
    allow_insecure: bool,
    http: crate::http::Guarded,
    /// Not guarded: the operator-configured PLC directory may be local.
    plc_http: reqwest::Client,
    cache: Arc<DocCache>,
    cap: fn() -> usize,
    negative: Mutex<TtlMap<ResolveError>>,
    refreshed: Mutex<TtlMap<()>>,
}

pub type TtlMap<V> = HashMap<String, (Instant, V)>;

/// When full, entries older than `ttl` go, else all of them.
fn bounded_insert<V>(m: &mut TtlMap<V>, k: &str, v: V, ttl: Duration, cap: usize) {
    if m.len() >= cap && !m.contains_key(k) {
        m.retain(|_, (at, _)| at.elapsed() < ttl);
        if m.len() >= cap {
            m.clear();
        }
    }
    m.insert(k.to_string(), (Instant::now(), v));
}

/// Documents a [`DidResolver::new`] resolver caches.
pub const DEFAULT_CACHE_ENTRIES: usize = 10_000;

/// The resolver's document cache, which a server can count against its own
/// memory budget ([`DidResolver::doc_cache`]).
pub type DocCache = Mutex<TtlMap<Arc<J>>>;

impl DidResolver {
    pub fn new(plc_url: &str, allow_insecure: bool) -> DidResolver {
        DidResolver::with_cache_cap(plc_url, allow_insecure, || DEFAULT_CACHE_ENTRIES)
    }

    /// `cap` is read on every insert, so a server can resize the cache live.
    pub fn with_cache_cap(plc_url: &str, allow_insecure: bool, cap: fn() -> usize) -> DidResolver {
        DidResolver {
            plc_url: plc_url.trim_end_matches('/').to_string(),
            allow_insecure,
            http: crate::http::guarded(allow_insecure),
            plc_http: crate::http::public().clone(),
            cache: Default::default(),
            cap,
            negative: Default::default(),
            refreshed: Default::default(),
        }
    }

    pub fn doc_cache(&self) -> Arc<DocCache> {
        self.cache.clone()
    }

    pub fn cached(&self, did: &str) -> Option<Arc<J>> {
        let c = self.cache.lock();
        c.get(did).filter(|(at, _)| at.elapsed() < CACHE_TTL).map(|(_, d)| d.clone())
    }

    pub fn invalidate(&self, did: &str) {
        self.cache.lock().remove(did);
        self.negative.lock().remove(did);
    }

    /// [`Self::invalidate`] at most once per [`REFRESH_MIN_INTERVAL`] per
    /// DID: outside parties can trigger it (a service JWT that doesn't match
    /// the cached key), and must not evict a busy DID on every request.
    /// Returns whether the cache was dropped.
    pub fn refresh(&self, did: &str) -> bool {
        {
            let mut r = self.refreshed.lock();
            if r.get(did).is_some_and(|(at, _)| at.elapsed() < REFRESH_MIN_INTERVAL) {
                return false;
            }
            bounded_insert(&mut r, did, (), REFRESH_MIN_INTERVAL, SIDE_MAP_CAP);
        }
        self.invalidate(did);
        true
    }

    pub async fn resolve(&self, did: &str) -> Result<Arc<J>, ResolveError> {
        if let Some(d) = self.cached(did) {
            return Ok(d);
        }
        if let Some((_, e)) = self.negative.lock().get(did).filter(|(at, _)| at.elapsed() < NEGATIVE_TTL) {
            return Err(e.clone());
        }
        let r = self.fetch(did).await;
        if let Err(e) = &r {
            if !matches!(e, ResolveError::BadDid(_)) {
                bounded_insert(&mut self.negative.lock(), did, e.clone(), NEGATIVE_TTL, SIDE_MAP_CAP);
            }
        }
        r
    }

    async fn fetch(&self, did: &str) -> Result<Arc<J>, ResolveError> {
        let req = if let Some(id) = did.strip_prefix("did:plc:") {
            // alphanumeric only: nothing that could change the PLC URL's path
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(ResolveError::BadDid(did.into()));
            }
            self.plc_http.get(format!("{}/{}", self.plc_url, did))
        } else if let Some(rest) = did.strip_prefix("did:web:") {
            let url = self.did_web_url(did, rest)?;
            self.http.get(&url).map_err(|e| ResolveError::Failed(did.into(), e))?
        } else {
            return Err(ResolveError::BadDid(did.into()));
        };
        let doc = tokio::time::timeout(RESOLVE_TIMEOUT, fetch_json(req))
            .await
            .map_err(|_| ResolveError::Failed(did.into(), "timed out".into()))?
            .map_err(|e| match e {
                FetchError::NotFound => ResolveError::NotFound(did.into()),
                FetchError::Other(m) => ResolveError::Failed(did.into(), m),
            })?;
        if doc.get("id").and_then(|v| v.as_str()) != Some(did) {
            return Err(ResolveError::Failed(did.into(), "document id does not match DID".into()));
        }
        let doc = Arc::new(doc);
        let cap = (self.cap)();
        bounded_insert(&mut self.cache.lock(), did, doc.clone(), CACHE_TTL, cap);
        Ok(doc)
    }

    fn did_web_url(&self, did: &str, rest: &str) -> Result<String, ResolveError> {
        // atproto supports only hostname-level did:web
        if rest.is_empty() || rest.contains(':') || rest.contains('/') {
            return Err(ResolveError::BadDid(did.into()));
        }
        let host = rest.replace("%3A", ":").replace("%3a", ":");
        if !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':') {
            return Err(ResolveError::BadDid(did.into()));
        }
        let hostname = host.split(':').next().unwrap_or("");
        // https, except localhost (as the TS resolver does) and, in dev mode,
        // IP literals (so tests can serve did.json from 127.0.0.1:port).
        let plain = hostname == "localhost" || (self.allow_insecure && is_ip_literal(hostname));
        let scheme = if plain { "http" } else { "https" };
        Ok(format!("{scheme}://{host}/.well-known/did.json"))
    }
}

fn is_ip_literal(h: &str) -> bool {
    h.parse::<IpAddr>().is_ok()
}

enum FetchError {
    NotFound,
    Other(String),
}

async fn fetch_json(req: reqwest::RequestBuilder) -> Result<J, FetchError> {
    use futures::StreamExt;
    let resp = req
        .header("accept", "application/did+ld+json, application/json")
        .send()
        .await
        .map_err(|e| FetchError::Other(e.to_string()))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::GONE {
        return Err(FetchError::NotFound);
    }
    if !resp.status().is_success() {
        return Err(FetchError::Other(format!("status {}", resp.status())));
    }
    if resp.content_length().is_some_and(|l| l as usize > MAX_DOC_BYTES) {
        return Err(FetchError::Other("document too large".into()));
    }
    let mut buf = Vec::new();
    let mut s = resp.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk.map_err(|e| FetchError::Other(e.to_string()))?;
        if buf.len() + chunk.len() > MAX_DOC_BYTES {
            return Err(FetchError::Other("document too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|e| FetchError::Other(format!("invalid JSON: {e}")))
}

/// `service_id` without '#'; both "#id" and "{did}#id" ids match.
pub fn service_endpoint(doc: &J, service_id: &str) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let short = format!("#{service_id}");
    let full = format!("{did}#{service_id}");
    doc.get("service")?.as_array()?.iter().find_map(|s| {
        let id = s.get("id")?.as_str()?;
        if id != short && id != full {
            return None;
        }
        let ep = s.get("serviceEndpoint")?.as_str()?;
        reqwest::Url::parse(ep).ok().filter(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some())?;
        Some(ep.to_string())
    })
}

pub fn signing_key_multibase(doc: &J) -> Option<String> {
    let did = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let full = format!("{did}#atproto");
    doc.get("verificationMethod")?.as_array()?.iter().find_map(|m| {
        let id = m.get("id")?.as_str()?;
        (id == "#atproto" || id == full).then(|| m.get("publicKeyMultibase")?.as_str().map(String::from))?
    })
}

/// Globally routable unicast only (SSRF protection).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99/24 6to4 relay anycast
                || o[0] >= 240) // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local
                || (s[0] & 0xffc0) == 0xfec0 // site-local fec0::/10 (deprecated)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 64:ff9b::/96 and 64:ff9b:1::/48
                || s[0] == 0x2002 // 6to4: embeds any IPv4 (relays reach private ones)
                || (s[0] == 0x2001 && s[1] == 0) // Teredo 2001::/32: embeds an IPv4
                || (s[0] == 0x2001 && (s[1] & 0xffe0) == 0x0020) // ORCHIDv2 2001:20::/28
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // ORCHID 2001:10::/28
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // discard 100::/64
                // IPv4-compatible ::a.b.c.d (deprecated) and the rest of ::/96
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0))
        }
    }
}

/// https only and no non-public IP literals; DNS names are filtered by the
/// guarded client's resolver.
pub fn check_outbound_url(url: &reqwest::Url, allow_insecure: bool) -> Result<(), String> {
    if allow_insecure {
        return match url.scheme() {
            "http" | "https" => Ok(()),
            s => Err(format!("Forbidden protocol \"{s}:\"")),
        };
    }
    if url.scheme() != "https" {
        return Err(format!("Forbidden protocol \"{}:\"", url.scheme()));
    }
    let refused = || Err("Hostname resolved to non-unicast address".to_string());
    // the URL parser has already rewritten decimal, octal, hex and short
    // IPv4 forms ("2130706433", "0177.1", "0x7f.1") as dotted quads
    let host = url.host_str().ok_or("missing host")?;
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return if is_public_ip(ip) { Ok(()) } else { refused() };
    }
    // a trailing dot names the same host
    let name = bare.trim_end_matches('.').to_ascii_lowercase();
    if name == "localhost" || name.ends_with(".localhost") {
        return refused();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ips() {
        for s in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "::10.0.0.1",
            "::8.8.8.8",
            "224.0.0.1",
            "192.88.99.1",
            // 6to4 of 127.0.0.1 / 10.0.0.1 / a public address (all refused)
            "2002:7f00:1::1",
            "2002:a00:1::",
            "2002:808:808::1",
            // Teredo (server 65.54.227.120, client embedded)
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001::1",
            "fec0::1",
            "feff::1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001:10::1",
            "2001:20::1",
        ] {
            assert!(!is_public_ip(s.parse().unwrap()), "{s}");
        }
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "2001:4860:4860::8888",
            "2001:200::1",
            "2003::1",
        ] {
            assert!(is_public_ip(s.parse().unwrap()), "{s}");
        }
    }

    /// Failed resolutions are remembered briefly; forced refreshes are
    /// rate-limited per DID; invalidate clears both caches.
    #[tokio::test]
    async fn negative_cache_and_refresh_limit() {
        // nothing listens on port 1: connection refused, no outbound traffic
        let r = DidResolver::new("http://127.0.0.1:1", true);
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        assert!(matches!(r.resolve(did).await, Err(ResolveError::Failed(..))));
        assert!(r.negative.lock().contains_key(did), "failure remembered");
        assert!(matches!(r.resolve(did).await, Err(ResolveError::Failed(..))));
        // malformed DIDs are refused without a fetch and not remembered
        assert!(matches!(r.resolve("did:plc:").await, Err(ResolveError::BadDid(_))));
        assert!(!r.negative.lock().contains_key("did:plc:"));
        assert!(r.refresh(did), "first forced refresh goes through");
        assert!(!r.negative.lock().contains_key(did), "a refresh drops the negative entry");
        assert!(!r.refresh(did), "a second one within the interval is refused");
        assert!(r.refresh("did:plc:other"), "per DID");
    }

    /// did:web naming a loopback, private or metadata address, in any
    /// spelling, is refused before connecting; in dev mode the same DID is
    /// fetched (the control), and a redirect from it is a failure, not
    /// followed.
    #[tokio::test]
    async fn did_web_private_targets_refused() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = hits.clone();
        let router = axum::Router::new().route(
            "/.well-known/did.json",
            axum::routing::get(move |h: axum::http::HeaderMap| {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("").replace(':', "%3A");
                std::future::ready(axum::Json(serde_json::json!({"id": format!("did:web:{host}")})))
            }),
        );
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        let strict = DidResolver::new("https://plc.invalid", false);
        for did in [
            format!("did:web:localhost%3A{port}"),
            format!("did:web:127.0.0.1%3A{port}"),
            format!("did:web:2130706433%3A{port}"),
            format!("did:web:0x7f.1%3A{port}"),
            format!("did:web:sub.localhost%3A{port}"),
            "did:web:169.254.169.254".to_string(),
            "did:web:10.0.0.1".to_string(),
            "did:web:100.100.100.200".to_string(),
        ] {
            match strict.resolve(&did).await {
                Err(ResolveError::Failed(_, m)) => {
                    assert!(m.contains("non-unicast") || m.contains("Forbidden protocol"), "{did}: {m}")
                }
                r => panic!("{did}: {r:?}"),
            }
        }
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        let dev = DidResolver::new("https://plc.invalid", true);
        let did = format!("did:web:127.0.0.1%3A{port}");
        assert!(dev.resolve(&did).await.is_ok());
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn did_web_redirects_not_followed() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let router = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::FOUND,
                [(axum::http::header::LOCATION, "http://169.254.169.254/latest/meta-data/")],
            )
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        let dev = DidResolver::new("https://plc.invalid", true);
        match dev.resolve(&format!("did:web:127.0.0.1%3A{port}")).await {
            Err(ResolveError::Failed(_, m)) => assert!(m.contains("302"), "{m}"),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn did_web_urls() {
        let r = DidResolver::new("https://plc.directory", false);
        assert_eq!(
            r.did_web_url("did:web:example.com", "example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(r.did_web_url("x", "localhost%3A1234").unwrap(), "http://localhost:1234/.well-known/did.json");
        assert!(r.did_web_url("x", "example.com:path").is_err());
        let dev = DidResolver::new("https://plc.directory", true);
        assert_eq!(dev.did_web_url("x", "127.0.0.1%3A99").unwrap(), "http://127.0.0.1:99/.well-known/did.json");
        assert_eq!(dev.did_web_url("x", "example.com").unwrap(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn service_lookup() {
        let doc = serde_json::json!({"id": "did:web:x", "service": [
            {"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds.example"},
            {"id": "did:web:x#bsky_appview", "type": "BskyAppView", "serviceEndpoint": "https://api.example"},
        ]});
        assert_eq!(service_endpoint(&doc, "atproto_pds").as_deref(), Some("https://pds.example"));
        assert_eq!(service_endpoint(&doc, "bsky_appview").as_deref(), Some("https://api.example"));
        assert_eq!(service_endpoint(&doc, "nope"), None);
    }
}
