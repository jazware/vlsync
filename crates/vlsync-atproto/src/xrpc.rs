//! XRPC errors: `{"error", "message"}` JSON with the HTTP status.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Clone)]
pub struct XrpcError {
    pub status: StatusCode,
    pub error: String,
    pub message: String,
}

impl XrpcError {
    pub fn bad(error: &str, message: impl Into<String>) -> XrpcError {
        XrpcError { status: StatusCode::BAD_REQUEST, error: error.into(), message: message.into() }
    }
    pub fn auth(message: &str) -> XrpcError {
        XrpcError { status: StatusCode::UNAUTHORIZED, error: "AuthenticationRequired".into(), message: message.into() }
    }
    pub fn internal(message: impl Into<String>) -> XrpcError {
        XrpcError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "InternalServerError".into(),
            message: message.into(),
        }
    }
    pub fn unavailable(error: &str, message: impl Into<String>) -> XrpcError {
        XrpcError { status: StatusCode::SERVICE_UNAVAILABLE, error: error.into(), message: message.into() }
    }
    pub fn from_err(e: impl std::fmt::Display) -> XrpcError {
        XrpcError::internal(e.to_string())
    }
}

/// A signature failed verification after signing (src/crypto.rs): nothing
/// was emitted, retry.
pub const SIGNATURE_FAULT: &str = "SignatureFault";

impl From<crate::crypto::SignatureFault> for XrpcError {
    fn from(e: crate::crypto::SignatureFault) -> XrpcError {
        XrpcError::unavailable(SIGNATURE_FAULT, e.to_string())
    }
}

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        let unavailable = self.status == StatusCode::SERVICE_UNAVAILABLE;
        let mut r = (self.status, Json(json!({"error": self.error, "message": self.message}))).into_response();
        // every 503 here is transient (shard moving, shedding, repo loading)
        if unavailable {
            r.headers_mut().insert(header::RETRY_AFTER, axum::http::HeaderValue::from_static("1"));
        }
        r
    }
}

/// Compares SHA-256 digests, so neither content nor length leaks through
/// timing. An empty `expected` (unset secret) never matches.
pub fn token_eq(expected: &str, given: &str) -> bool {
    use sha2::{Digest, Sha256};
    let (a, b) = (Sha256::digest(expected), Sha256::digest(given));
    !expected.is_empty() && a.iter().zip(b.iter()).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `b64` is the `Authorization: Basic` value after the scheme.
pub fn basic_admin_ok(b64: &str, admin_token: &str) -> bool {
    use base64::Engine;
    let dec = base64::engine::general_purpose::STANDARD.decode(b64.trim()).unwrap_or_default();
    std::str::from_utf8(&dec).ok().and_then(|s| s.strip_prefix("admin:")).is_some_and(|tok| token_eq(admin_token, tok))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn token_compare() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abc", "abd"));
        assert!(!token_eq("abc", "abcd"));
        assert!(!token_eq("", ""), "an unset token never matches");
        let b = base64::engine::general_purpose::STANDARD.encode("admin:tok");
        assert!(basic_admin_ok(&b, "tok"));
        assert!(!basic_admin_ok(&b, "other"));
        let empty = base64::engine::general_purpose::STANDARD.encode("admin:");
        assert!(!basic_admin_ok(&empty, ""));
    }
}
