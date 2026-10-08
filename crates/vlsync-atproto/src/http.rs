//! Outbound HTTP clients every vlsync server shares, each built once so
//! connections are reused: [`public`] (operator-configured upstreams) and
//! [`guarded`] (URLs derived from untrusted input), and the builders a
//! server's own clients start from ([`base`], [`outbound`]).
//!
//! No client follows redirects: a redirect from a user-controlled host could
//! point anywhere.

use prometheus::{register_int_counter_vec, IntCounterVec};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

vlsync_store::lazy!(HTTP_CLIENT_CONNECTS: IntCounterVec = register_int_counter_vec!("vlpds_http_client_connects_total", "New outbound connections by client role (peer, public, guarded); should stay flat under steady load", &["role"]));

static USER_AGENT: OnceLock<&'static str> = OnceLock::new();

/// Sets the User-Agent of every client built after it (call it first thing
/// in main); unset, it is `vlsync/{version}`.
pub fn set_user_agent(ua: &'static str) {
    let _ = USER_AGENT.set(ua);
}

pub fn user_agent() -> &'static str {
    USER_AGENT.get_or_init(|| concat!("vlsync/", env!("CARGO_PKG_VERSION")))
}

/// rustls's ring provider: reqwest already links it.
pub fn tls_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static P: LazyLock<Arc<rustls::crypto::CryptoProvider>> =
        LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));
    P.clone()
}

pub fn base(role: &'static str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(user_agent())
        .tcp_nodelay(true)
        .tcp_keepalive(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .connector_layer(CountConnects(role))
}

/// `max_idle` must cover the steady-state concurrency per host: a busy
/// HTTP/1.1 upstream beyond it opens and closes a connection per request.
pub fn outbound(role: &'static str, max_idle: usize) -> reqwest::ClientBuilder {
    outbound_no_read_timeout(role, max_idle).read_timeout(Duration::from_secs(30))
}

/// reqwest re-arms the read timeout for every body frame, and every tokio
/// timer operation takes the runtime's one timer-wheel lock: callers that
/// bound their requests themselves skip it.
pub fn outbound_no_read_timeout(role: &'static str, max_idle: usize) -> reqwest::ClientBuilder {
    base(role)
        .connect_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(max_idle)
        // below the 90-120 s idle close of common load balancers/CDNs, so we
        // close first instead of racing a reused socket the server dropped
        .pool_idle_timeout(Duration::from_secs(60))
        .http2_keep_alive_interval(Duration::from_secs(20))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_adaptive_window(true)
}

/// Operator-configured upstreams. Callers set per-request deadlines.
pub fn public() -> &'static reqwest::Client {
    static C: LazyLock<reqwest::Client> = LazyLock::new(|| {
        // the AppView proxy runs ~100-500 requests in flight to one host
        outbound("public", 1024).build().expect("reqwest client")
    });
    &C
}

/// The one client for destinations taken from untrusted input (DID
/// documents, handles, OAuth client metadata, `atproto-proxy`). Every
/// request URL passes [`crate::did_resolver::check_outbound_url`] (https
/// only, no non-public IP literals: the resolver never sees those), and DNS
/// names resolve through [`PublicOnlyResolver`], whose vetted addresses are
/// the ones connected to, so a rebinding answer can't slip in between check
/// and connect. Redirects aren't followed and no system proxy is used (it
/// would resolve the name itself). Dev mode (`--dev-mode`, tests) allows
/// http and any address. Callers bound the response size and overall time.
#[derive(Clone, Copy, Debug)]
pub struct Guarded {
    dev_mode: bool,
    fanout: bool,
}

pub fn guarded(dev_mode: bool) -> Guarded {
    Guarded { dev_mode, fanout: false }
}

/// [`guarded`] on a pool of its own for Spaces write notifications to
/// registered services: kept-alive connections to the same few syncers
/// (HTTP/2 where their ALPN offers it), apart from the one-off fetches.
pub fn guarded_fanout(dev_mode: bool) -> Guarded {
    Guarded { dev_mode, fanout: true }
}

impl Guarded {
    pub fn request(&self, method: reqwest::Method, url: &str) -> Result<reqwest::RequestBuilder, String> {
        let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
        crate::did_resolver::check_outbound_url(&u, self.dev_mode)?;
        let client = match self.fanout {
            true => fanout_client(self.dev_mode),
            false => guarded_client(self.dev_mode),
        };
        Ok(client.request(method, u))
    }

    pub fn get(&self, url: &str) -> Result<reqwest::RequestBuilder, String> {
        self.request(reqwest::Method::GET, url)
    }
}

fn guarded_client(dev_mode: bool) -> &'static reqwest::Client {
    static STRICT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        outbound("guarded", 32).no_proxy().dns_resolver(Arc::new(PublicOnlyResolver)).build().expect("reqwest client")
    });
    static DEV: LazyLock<reqwest::Client> =
        LazyLock::new(|| outbound("guarded", 32).no_proxy().build().expect("reqwest client"));
    if dev_mode {
        &DEV
    } else {
        &STRICT
    }
}

fn fanout_client(dev_mode: bool) -> &'static reqwest::Client {
    static STRICT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        outbound("space_fanout", 64)
            .no_proxy()
            .dns_resolver(Arc::new(PublicOnlyResolver))
            .build()
            .expect("reqwest client")
    });
    static DEV: LazyLock<reqwest::Client> =
        LazyLock::new(|| outbound("space_fanout", 64).no_proxy().build().expect("reqwest client"));
    if dev_mode {
        &DEV
    } else {
        &STRICT
    }
}

/// SSRF guard: a hostname can't be used to reach internal services.
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = public_addrs(&host).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

async fn public_addrs(host: &str) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<SocketAddr> =
        tokio::net::lookup_host((host, 0)).await?.filter(|a| crate::did_resolver::is_public_ip(a.ip())).collect();
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve to a public unicast address").into());
    }
    Ok(addrs)
}

/// `vlpds_http_client_connects_total{role}`: reuse regressions show up.
#[derive(Clone)]
struct CountConnects(&'static str);

impl<S> tower::Layer<S> for CountConnects {
    type Service = Counted<S>;
    fn layer(&self, inner: S) -> Counted<S> {
        Counted { inner, role: self.0 }
    }
}

#[derive(Clone)]
struct Counted<S> {
    inner: S,
    role: &'static str,
}

impl<S: tower::Service<R>, R> tower::Service<R> for Counted<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, req: R) -> S::Future {
        HTTP_CLIENT_CONNECTS.with_label_values(&[self.role]).inc();
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A loopback listener counting the connections it accepts.
    async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let n = Arc::new(AtomicUsize::new(0));
        let seen = n.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        (port, n)
    }

    #[tokio::test]
    async fn guarded_refuses_private_hosts() {
        let (port, accepted) = counting_listener().await;
        // refused before any connection: a non-https scheme, loopback names,
        // and non-public IP literals in every spelling the URL parser reads
        let local = [
            "http://example.com",
            "ftp://example.com",
            "file:///etc/passwd",
            "https://localhost:{port}",
            "https://LOCALHOST.:{port}",
            "https://a.b.localhost:{port}",
            "https://127.0.0.1:{port}",
            "https://127.0.0.1.:{port}",
            "https://127.1:{port}",
            "https://2130706433:{port}",
            "https://0x7f000001:{port}",
            "https://0x7f.1:{port}",
            "https://0177.0.0.1:{port}",
            "https://[::1]:{port}",
            "https://[::ffff:127.0.0.1]:{port}",
            "https://[::ffff:7f00:1]:{port}",
            "https://[64:ff9b::7f00:1]:{port}",
            "https://[2002:7f00:1::]:{port}",
            "https://0.0.0.0:{port}",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fd00:ec2::254]/latest/meta-data/",
            "https://[fe80::1%25en0]/",
            "https://10.0.0.1/",
            "https://172.16.0.1/",
            "https://192.168.1.1/",
            "https://100.64.0.1/",
            "https://224.0.0.1/",
            "https://255.255.255.255/",
        ];
        for u in local {
            let u = u.replace("{port}", &port.to_string());
            let e = guarded(false).get(&u).unwrap_err();
            assert!(
                e.contains("non-unicast") || e.contains("Forbidden protocol") || e.contains("invalid URL"),
                "{u}: {e}"
            );
        }
        // a public address passes the URL check (nothing is sent here)
        assert!(guarded(false).get("https://8.8.8.8/x").is_ok());
        assert!(guarded(false).get("https://example.com/x").is_ok());

        // a DNS name resolving to loopback, past the URL check: the strict
        // client's resolver refuses it, and the vetted addresses are the ones
        // connected to, so no answer can change between check and connect
        let url = format!("http://localhost:{port}/.well-known/atproto-did");
        let e = guarded_client(false).get(&url).send().await.unwrap_err();
        assert!(e.is_connect(), "{e:?}");
        assert!(format!("{e:?}").contains("public unicast"), "{e:?}");
        assert!(public_addrs("localhost").await.is_err());
        assert_eq!(accepted.load(Ordering::SeqCst), 0);

        // dev mode reaches it
        let _ = tokio::time::timeout(Duration::from_secs(2), guarded(true).get(&url).unwrap().send()).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    /// A redirect from an untrusted host comes back as the response; its
    /// target (an internal service here) is never contacted.
    #[tokio::test]
    async fn guarded_never_follows_redirects() {
        let (internal, hits) = counting_listener().await;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = format!("http://{}/.well-known/did.json", l.local_addr().unwrap());
        let to = format!("http://127.0.0.1:{internal}/metrics");
        let router = axum::Router::new().fallback(move || {
            let to = to.clone();
            async move { (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, to)]) }
        });
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        let r = guarded(true).get(&front).unwrap().send().await.unwrap();
        assert_eq!(r.status(), 302);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
