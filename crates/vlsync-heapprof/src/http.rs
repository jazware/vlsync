use axum::extract::{ConnectInfo, Request};
use axum::http::{header, Extensions, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::{IpAddr, SocketAddr};

/// `GET /debug/pprof/heap`: the heap in use as a gzipped pprof profile, as
/// Go's net/http/pprof serves it (its query parameters are ignored). The
/// caller decides who may ask: see [`from_loopback`].
pub async fn handler() -> Response {
    let text = |status: StatusCode, msg: String| (status, [(header::CACHE_CONTROL, "no-store")], msg + "\n");
    match tokio::task::spawn_blocking(crate::dump_pprof).await {
        Ok(Ok(body)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"heap\""),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Ok(Err(e @ crate::Error::Disabled)) => text(StatusCode::NOT_IMPLEMENTED, e.to_string()).into_response(),
        Ok(Err(e @ crate::Error::Inactive)) => text(StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
        Ok(Err(e)) => text(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, format!("heap profile: {e}")).into_response(),
    }
}

/// The request's TCP peer is this host's (or this container's) loopback,
/// and no proxy forwarded it: a reverse proxy on the same host connects
/// from loopback too, but says whom it's forwarding for. A published Docker
/// port doesn't count either: Docker delivers those from the bridge's
/// gateway. The server must put [`ConnectInfo`]`<SocketAddr>` on requests
/// (`into_make_service_with_connect_info`).
pub fn from_loopback(req: &Request) -> bool {
    let forwarded = ["x-forwarded-for", "forwarded", "x-real-ip"].iter().any(|h| req.headers().contains_key(*h));
    !forwarded && peer_is_loopback(req.extensions())
}

fn peer_is_loopback(ext: &Extensions) -> bool {
    ext.get::<ConnectInfo<SocketAddr>>().is_some_and(|c| match c.0.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(v6.is_loopback(), |v4| v4.is_loopback()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(peer: [u8; 4], header: Option<&str>) -> Request {
        let mut b = axum::http::Request::get("/debug/pprof/heap");
        if let Some(h) = header {
            b = b.header(h, "203.0.113.9");
        }
        let mut r = b.body(axum::body::Body::empty()).unwrap();
        r.extensions_mut().insert(ConnectInfo(SocketAddr::from((peer, 1))));
        r
    }

    #[test]
    fn loopback_unless_proxied() {
        assert!(from_loopback(&req([127, 0, 0, 1], None)));
        assert!(!from_loopback(&req([172, 31, 84, 1], None)));
        assert!(!from_loopback(&req([127, 0, 0, 1], Some("x-forwarded-for"))));
        assert!(!from_loopback(&req([127, 0, 0, 1], Some("forwarded"))));
        assert!(!from_loopback(&axum::http::Request::get("/").body(axum::body::Body::empty()).unwrap()));
    }
}
