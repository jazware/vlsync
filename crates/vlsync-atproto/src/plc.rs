//! did:plc operations as did-method-plc (`@did-plc/lib`) types them.

use serde_json::{Map, Value as J};

/// Also guarantees the DID is path-safe.
pub fn valid_plc_did(did: &str) -> bool {
    did.strip_prefix("did:plc:")
        .is_some_and(|id| id.len() == 24 && id.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpType {
    Operation,
    Tombstone,
    /// The legacy v1 genesis `create`.
    LegacyCreate,
}

fn is_str(v: Option<&J>) -> bool {
    matches!(v, Some(J::String(_)))
}

fn str_array(v: Option<&J>) -> bool {
    matches!(v, Some(J::Array(a)) if a.iter().all(|x| x.is_string()))
}

fn only_keys(m: &Map<String, J>, allowed: &[&str]) -> bool {
    m.keys().all(|k| allowed.contains(&k.as_str())) && m.len() == allowed.len()
}

/// The zod schemas of @did-plc/lib types.ts, strict: exactly the fields of
/// one type, with `sig` iff `signed`. None = not a valid operation.
pub fn op_type(op: &J, signed: bool) -> Option<OpType> {
    let m = op.as_object()?;
    let sig: &[&str] = if signed { &["sig"] } else { &[] };
    let with = |fields: &[&'static str]| -> Vec<&str> { fields.iter().copied().chain(sig.iter().copied()).collect() };
    if signed && !is_str(m.get("sig")) {
        return None;
    }
    match m.get("type").and_then(J::as_str) {
        Some("plc_operation") => {
            let ok = only_keys(
                m,
                &with(&["type", "rotationKeys", "verificationMethods", "alsoKnownAs", "services", "prev"]),
            ) && str_array(m.get("rotationKeys"))
                && str_array(m.get("alsoKnownAs"))
                && matches!(m.get("verificationMethods"), Some(J::Object(v)) if v.values().all(J::is_string))
                && matches!(m.get("services"), Some(J::Object(s)) if s.values().all(|s| {
                    matches!(s, J::Object(o) if only_keys(o, &["type", "endpoint"]) && is_str(o.get("type")) && is_str(o.get("endpoint")))
                }))
                && matches!(m.get("prev"), Some(J::String(_) | J::Null));
            ok.then_some(OpType::Operation)
        }
        Some("plc_tombstone") => {
            (only_keys(m, &with(&["type", "prev"])) && is_str(m.get("prev"))).then_some(OpType::Tombstone)
        }
        Some("create") => {
            let ok = only_keys(m, &with(&["type", "signingKey", "recoveryKey", "handle", "service", "prev"]))
                && ["signingKey", "recoveryKey", "handle", "service"].iter().all(|k| is_str(m.get(*k)))
                && m.get("prev") == Some(&J::Null);
            ok.then_some(OpType::LegacyCreate)
        }
        _ => None,
    }
}
