//! Minimal DAG-CBOR: a byte-level encoder for the hot path (MST nodes,
//! commits, firehose frames) and a `Value` tree for records, with JSON
//! conversion following the atproto data model ($link, $bytes).

use crate::cid::{Cid, CID_BYTES_LEN};
use base64::Engine;
use std::borrow::Cow;

/// Decodes a `$bytes` string as the reference's `@atproto/lex-data`
/// `fromBase64` does: standard alphabet, padding optional (up to two `=`,
/// never past the padded length: `"AQ="` is `[1]`, `"AQID="` is invalid),
/// and non-zero trailing bits accepted (`"AR"` is `[1]`).
fn decode_bytes(s: &str) -> Result<Vec<u8>, ()> {
    const LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
    );
    let body = s.strip_suffix("==").or_else(|| s.strip_suffix('=')).unwrap_or(s);
    if s.len() > body.len().div_ceil(4) * 4 {
        return Err(());
    }
    LENIENT.decode(body).map_err(|_| ())
}

#[inline]
fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

#[inline]
pub fn write_uint(out: &mut Vec<u8>, n: u64) {
    write_head(out, 0, n);
}

#[inline]
pub fn write_int(out: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        write_head(out, 0, n as u64);
    } else {
        write_head(out, 1, (-1 - n) as u64);
    }
}

#[inline]
pub fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
    write_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

#[inline]
pub fn write_text(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

#[inline]
pub fn write_array_head(out: &mut Vec<u8>, n: usize) {
    write_head(out, 4, n as u64);
}

#[inline]
pub fn write_map_head(out: &mut Vec<u8>, n: usize) {
    write_head(out, 5, n as u64);
}

#[inline]
pub fn write_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

#[inline]
pub fn write_bool(out: &mut Vec<u8>, b: bool) {
    out.push(if b { 0xf5 } else { 0xf4 });
}

/// Tag 42, a 37-byte byte string head, the 0x00 multibase-identity prefix.
const LINK_PREFIX: [u8; 5] = [0xd8, 0x2a, 0x58, 0x25, 0x00];

const LINK_LEN: usize = LINK_PREFIX.len() + CID_BYTES_LEN;

#[inline]
pub fn link_bytes(c: &Cid) -> [u8; LINK_LEN] {
    let mut b = [0u8; LINK_LEN];
    b[..5].copy_from_slice(&LINK_PREFIX);
    b[5..].copy_from_slice(&c.to_bytes());
    b
}

#[inline]
pub fn write_cid(out: &mut Vec<u8>, c: &Cid) {
    out.extend_from_slice(&link_bytes(c));
}

#[inline]
pub fn write_opt_cid(out: &mut Vec<u8>, c: Option<&Cid>) {
    match c {
        Some(c) => write_cid(out, c),
        None => write_null(out),
    }
}

/// DAG-CBOR canonical map key order.
pub fn key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Kept sorted in canonical key order.
    Map(Vec<(String, Value)>),
    Link(Cid),
}

#[derive(Debug, thiserror::Error)]
pub enum CborError {
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid cbor: {0}")]
    Invalid(&'static str),
    #[error("invalid data model value: {0}")]
    DataModel(String),
}

impl Value {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Null => write_null(out),
            Value::Bool(b) => write_bool(out, *b),
            Value::Int(n) => write_int(out, *n),
            Value::Bytes(b) => write_bytes(out, b),
            Value::Text(s) => write_text(out, s),
            Value::Array(a) => {
                write_array_head(out, a.len());
                for v in a {
                    v.encode(out);
                }
            }
            Value::Map(m) => {
                write_map_head(out, m.len());
                for (k, v) in m {
                    write_text(out, k);
                    v.encode(out);
                }
            }
            Value::Link(c) => write_cid(out, c),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        self.encode(&mut out);
        out
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// atproto data-model JSON -> value. Strict like the reference's
    /// lex-json: `$link` / `$bytes` objects must have exactly that one
    /// string field holding a valid CID / base64; `$type` must be a non-empty
    /// string; `{"$type": "blob"}` needs a `$link` ref, a string mimeType
    /// and an integer size; numbers must be safe integers, |n| <= 2^53 - 1
    /// (JSON `123.0` parses as the integer 123, as in JavaScript; the
    /// reference's lex-cbor encoder refuses any number that isn't
    /// `Number.isSafeInteger`, whether written `2^60` or `2^60.0`).
    pub fn from_json(j: &serde_json::Value) -> Result<Value, CborError> {
        let dm = |m: &str| CborError::DataModel(m.to_string());
        Ok(match j {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(i) if safe_int(i) => Value::Int(i),
                Some(_) => return Err(dm("integers beyond 2^53 - 1 are not allowed")),
                None => match n.as_f64() {
                    // integer-valued floats within JS's safe integer range
                    Some(f) if f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 => Value::Int(f as i64),
                    _ => return Err(dm("floats are not allowed")),
                },
            },
            serde_json::Value::String(s) => Value::Text(s.clone()),
            serde_json::Value::Array(a) => Value::Array(a.iter().map(Value::from_json).collect::<Result<_, _>>()?),
            serde_json::Value::Object(o) => {
                if let Some(l) = o.get("$link") {
                    return match (l, o.len()) {
                        (serde_json::Value::String(s), 1) => {
                            Cid::parse(s).map(Value::Link).map_err(|_| CborError::DataModel(format!("bad $link {s}")))
                        }
                        _ => Err(dm("$link must be the only field and a CID string")),
                    };
                }
                if let Some(b) = o.get("$bytes") {
                    return match (b, o.len()) {
                        (serde_json::Value::String(s), 1) => {
                            decode_bytes(s).map(Value::Bytes).map_err(|_| dm("bad $bytes"))
                        }
                        _ => Err(dm("$bytes must be the only field and a base64 string")),
                    };
                }
                match o.get("$type") {
                    None => {}
                    Some(serde_json::Value::String(t)) if !t.is_empty() => {
                        if t == "blob" {
                            let link = match o.get("ref") {
                                Some(serde_json::Value::Object(r)) if r.len() == 1 => {
                                    r.get("$link").and_then(|l| l.as_str())
                                }
                                _ => None,
                            };
                            let ok = o.len() == 4
                                && link.is_some_and(blob_link_ok)
                                && o.get("mimeType").and_then(|m| m.as_str()).is_some_and(blob_mime_ok)
                                && o.get("size").and_then(|n| n.as_i64()).is_some_and(blob_size_ok);
                            if !ok {
                                return Err(dm(
                                    "blob needs exactly ref ($link to a raw CID), mimeType (non-empty string) and size (integer >= 0)",
                                ));
                            }
                        }
                    }
                    Some(_) => return Err(dm("$type must be a non-empty string")),
                }
                let mut m = Vec::with_capacity(o.len());
                for (k, v) in o {
                    m.push((k.clone(), Value::from_json(v)?));
                }
                m.sort_by(|a, b| key_cmp(&a.0, &b.0));
                Value::Map(m)
            }
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            Value::Null => J::Null,
            Value::Bool(b) => J::Bool(*b),
            Value::Int(n) => J::from(*n),
            Value::Bytes(b) => serde_json::json!({
                "$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
            }),
            Value::Text(s) => J::String(s.clone()),
            Value::Array(a) => J::Array(a.iter().map(|v| v.to_json()).collect()),
            Value::Map(m) => {
                let mut o = serde_json::Map::with_capacity(m.len());
                for (k, v) in m {
                    o.insert(k.clone(), v.to_json());
                }
                J::Object(o)
            }
            Value::Link(c) => serde_json::json!({ "$link": c.to_string() }),
        }
    }

    /// One strict DAG-CBOR value (the whole input). Accepts exactly what
    /// [`Value::decode_reference`] accepts, with the same value and, on
    /// rejection, the same error.
    pub fn decode(data: &[u8]) -> Result<Value, CborError> {
        let mut d = Decoder { data, pos: 0 };
        match d.owned(0) {
            Ok(v) if d.pos == data.len() => Ok(v),
            _ => Value::decode_reference(data),
        }
    }

    /// Also returns the bytes consumed.
    pub fn decode_prefix(data: &[u8]) -> Result<(Value, usize), CborError> {
        let mut d = Decoder { data, pos: 0 };
        match d.owned(0) {
            Ok(v) => Ok((v, d.pos)),
            Err(_) => Value::decode_prefix_reference(data),
        }
    }

    /// The oracle the fast paths are tested against
    /// (`tests/all/shrike_adopt.rs`) and the source of their errors.
    #[doc(hidden)]
    pub fn decode_reference(data: &[u8]) -> Result<Value, CborError> {
        let mut d = Decoder { data, pos: 0 };
        let v = d.value(0)?;
        if d.pos != data.len() {
            return Err(CborError::Invalid("trailing bytes"));
        }
        Ok(v)
    }

    #[doc(hidden)]
    pub fn decode_prefix_reference(data: &[u8]) -> Result<(Value, usize), CborError> {
        let mut d = Decoder { data, pos: 0 };
        let v = d.value(0)?;
        Ok((v, d.pos))
    }
}

/// A [`Value`] whose strings and byte strings borrow from the input, for
/// read-only consumers. Same strictness as [`Value`].
#[derive(Clone, Debug, PartialEq)]
pub enum ValueRef<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<ValueRef<'a>>),
    Map(Vec<(&'a str, ValueRef<'a>)>),
    Link(Cid),
}

impl<'a> ValueRef<'a> {
    /// Accepts exactly what [`Value::decode`] accepts (same error on rejection).
    pub fn decode(data: &'a [u8]) -> Result<ValueRef<'a>, CborError> {
        let mut d = Decoder { data, pos: 0 };
        match d.borrowed(0) {
            Ok(v) if d.pos == data.len() => Ok(v),
            _ => Err(reference_error(Value::decode_reference(data).err())),
        }
    }

    /// Also returns the bytes consumed.
    pub fn decode_prefix(data: &'a [u8]) -> Result<(ValueRef<'a>, usize), CborError> {
        let mut d = Decoder { data, pos: 0 };
        match d.borrowed(0) {
            Ok(v) => Ok((v, d.pos)),
            Err(_) => Err(reference_error(Value::decode_prefix_reference(data).err())),
        }
    }

    pub fn get(&self, key: &str) -> Option<&ValueRef<'a>> {
        match self {
            ValueRef::Map(m) => m.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            ValueRef::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            ValueRef::Null => Value::Null,
            ValueRef::Bool(b) => Value::Bool(*b),
            ValueRef::Int(n) => Value::Int(*n),
            ValueRef::Bytes(b) => Value::Bytes(b.to_vec()),
            ValueRef::Text(s) => Value::Text(s.to_string()),
            ValueRef::Array(a) => Value::Array(a.iter().map(ValueRef::to_value).collect()),
            ValueRef::Map(m) => Value::Map(m.iter().map(|(k, v)| (k.to_string(), v.to_value())).collect()),
            ValueRef::Link(c) => Value::Link(*c),
        }
    }
}

/// Both decoders accept the same inputs, so `None` (the reference accepted
/// what a fast decoder rejected) is a fast-path bug.
fn reference_error(e: Option<CborError>) -> CborError {
    debug_assert!(e.is_some(), "fast DAG-CBOR decoder rejected what the reference accepts");
    e.unwrap_or(CborError::Invalid("decoder mismatch"))
}

/// A JSON value borrowing its strings from the request body: record writes
/// parse into it, validate it against lexicons (with `serde_json::Value`'s
/// semantics) and encode it straight to DAG-CBOR
/// ([`JsonValue::encode_record`]).
#[derive(Clone, Debug, PartialEq)]
pub enum JsonValue<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    /// Above `i64::MAX`: never a valid record value.
    BigUint(u64),
    Str(Cow<'a, str>),
    Array(Vec<JsonValue<'a>>),
    /// Sorted in DAG-CBOR key order; a repeated key keeps its last value,
    /// as `serde_json::Value` does.
    Object(Vec<(Cow<'a, str>, JsonValue<'a>)>),
}

/// In the order a walk of the record's `Value` visits them (map keys in
/// DAG-CBOR order, a map before its children).
#[derive(Debug, Default, PartialEq)]
pub struct RecordRefs {
    /// (cid, mimeType, size).
    pub blobs: Vec<(Cid, Option<String>, Option<i64>)>,
    /// The first legacy (`{"cid", "mimeType"}`, no `$type`) ref whose `cid`
    /// parses.
    pub legacy: Option<String>,
}

impl RecordRefs {
    /// Distinct, in order of first reference.
    pub fn cids(&self) -> Vec<Cid> {
        // a 1 MB record holds ~9k refs
        let mut seen = std::collections::HashSet::with_capacity(self.blobs.len());
        self.blobs.iter().map(|(c, ..)| *c).filter(|c| seen.insert(*c)).collect()
    }
}

/// JS's `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE_INT: f64 = 9_007_199_254_740_991.0;

fn safe_int(n: i64) -> bool {
    n.unsigned_abs() <= MAX_SAFE_INT as u64
}

// A typed blob ref, as @atproto/lex-data's strict `isTypedBlobRef` checks
// it: exactly `$type`, `ref`, `mimeType` and `size`; `ref` a raw-codec CID,
// `size` a safe non-negative integer. The reference also wants a `/` in
// `mimeType`; the data model only asks for a non-empty string, and records
// with `"mimeType": "jpeg"` are on the network, so vlpds takes them.
fn blob_link_ok(link: &str) -> bool {
    Cid::parse(link).is_ok_and(|c| c.codec == crate::cid::CODEC_RAW)
}

fn blob_mime_ok(mime: &str) -> bool {
    !mime.is_empty()
}

fn blob_size_ok(size: i64) -> bool {
    (0..=MAX_SAFE_INT as i64).contains(&size)
}

fn obj_get<'v, 'a>(m: &'v [(Cow<'a, str>, JsonValue<'a>)], key: &str) -> Option<&'v JsonValue<'a>> {
    m.binary_search_by(|(k, _)| key_cmp(k, key)).ok().map(|i| &m[i].1)
}

impl<'a> JsonValue<'a> {
    /// serde_json's parser, so its syntax errors and nesting limit.
    pub fn parse(body: &'a [u8]) -> serde_json::Result<JsonValue<'a>> {
        serde_json::from_slice(body)
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue<'a>> {
        match self {
            JsonValue::Object(m) => obj_get(m, key),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonValue<'a>> {
        match self {
            JsonValue::Object(m) => match m.binary_search_by(|(k, _)| key_cmp(k, key)) {
                Ok(i) => Some(&mut m[i].1),
                Err(_) => None,
            },
            _ => None,
        }
    }

    pub fn insert(&mut self, key: &'a str, v: JsonValue<'a>) {
        if let JsonValue::Object(m) = self {
            match m.binary_search_by(|(k, _)| key_cmp(k, key)) {
                Ok(i) => m[i].1 = v,
                Err(i) => m.insert(i, (Cow::Borrowed(key), v)),
            }
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value as J;
        match self {
            JsonValue::Null => J::Null,
            JsonValue::Bool(b) => J::Bool(*b),
            JsonValue::Int(n) => J::from(*n),
            JsonValue::Float(f) => serde_json::Number::from_f64(*f).map_or(J::Null, J::Number),
            JsonValue::BigUint(n) => J::from(*n),
            JsonValue::Str(s) => J::String(s.to_string()),
            JsonValue::Array(a) => J::Array(a.iter().map(|v| v.to_json()).collect()),
            JsonValue::Object(m) => J::Object(m.iter().map(|(k, v)| (k.to_string(), v.to_json())).collect()),
        }
    }

    /// Appends exactly `Value::from_json(self)?.to_cbor()` (same bytes, same
    /// accept/reject decision, same error) and collects the record's blob
    /// refs on the way. Integral floats become `Int` in place, so `self`
    /// then validates as the encoded record would. On error `out` is left
    /// as it was.
    pub fn encode_record(&mut self, out: &mut Vec<u8>, refs: &mut RecordRefs) -> Result<(), CborError> {
        let start = out.len();
        if self.encode(out, refs).is_ok() {
            return Ok(());
        }
        out.truncate(start);
        // `from_json` names the error its own traversal order meets first
        match Value::from_json(&self.to_json()) {
            Err(e) => Err(e),
            Ok(_) => {
                debug_assert!(false, "encode_record rejected what from_json accepts");
                Err(CborError::DataModel("invalid record".into()))
            }
        }
    }

    fn encode(&mut self, out: &mut Vec<u8>, refs: &mut RecordRefs) -> Result<(), ()> {
        match self {
            JsonValue::Null => write_null(out),
            JsonValue::Bool(b) => write_bool(out, *b),
            JsonValue::Int(n) if safe_int(*n) => write_int(out, *n),
            JsonValue::Int(_) => return Err(()),
            JsonValue::Float(f) => {
                if f.fract() != 0.0 || f.abs() > MAX_SAFE_INT {
                    return Err(());
                }
                let n = *f as i64;
                write_int(out, n);
                *self = JsonValue::Int(n);
            }
            JsonValue::BigUint(_) => return Err(()),
            JsonValue::Str(s) => write_text(out, s),
            JsonValue::Array(a) => {
                write_array_head(out, a.len());
                for v in a {
                    v.encode(out, refs)?;
                }
            }
            JsonValue::Object(m) => {
                if let Some(l) = obj_get(m, "$link") {
                    return match (l, m.len()) {
                        (JsonValue::Str(s), 1) => {
                            write_cid(out, &Cid::parse(s).map_err(|_| ())?);
                            Ok(())
                        }
                        _ => Err(()),
                    };
                }
                if let Some(b) = obj_get(m, "$bytes") {
                    return match (b, m.len()) {
                        (JsonValue::Str(s), 1) => {
                            let b = decode_bytes(s).map_err(|_| ())?;
                            write_bytes(out, &b);
                            Ok(())
                        }
                        _ => Err(()),
                    };
                }
                let text = |k: &str| obj_get(m, k).and_then(|v| v.as_str());
                match obj_get(m, "$type") {
                    None => {
                        if let (Some(c), Some(_), None) = (text("cid"), text("mimeType"), &refs.legacy) {
                            if Cid::parse(c).is_ok() {
                                refs.legacy = Some(c.to_string());
                            }
                        }
                    }
                    Some(JsonValue::Str(t)) if !t.is_empty() => {
                        if t == "blob" {
                            let link = match obj_get(m, "ref") {
                                Some(JsonValue::Object(r)) if r.len() == 1 => obj_get(r, "$link").ok_or(())?,
                                _ => return Err(()),
                            };
                            let (Some(mime), Some(JsonValue::Int(size))) = (text("mimeType"), obj_get(m, "size"))
                            else {
                                return Err(());
                            };
                            let JsonValue::Str(link) = link else { return Err(()) };
                            if m.len() != 4 || !blob_link_ok(link) || !blob_mime_ok(mime) || !blob_size_ok(*size) {
                                return Err(());
                            }
                            let c = Cid::parse(link).map_err(|_| ())?;
                            refs.blobs.push((c, Some(mime.to_string()), Some(*size)));
                        }
                    }
                    Some(_) => return Err(()),
                }
                write_map_head(out, m.len());
                for (k, v) in m.iter_mut() {
                    write_text(out, k);
                    v.encode(out, refs)?;
                }
            }
        }
        Ok(())
    }
}

impl<'de> serde::Deserialize<'de> for JsonValue<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> serde::de::Visitor<'de> for JsonVisitor {
    type Value = JsonValue<'de>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any valid JSON value")
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }
    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(JsonValue::Int(v))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(match i64::try_from(v) {
            Ok(n) => JsonValue::Int(n),
            Err(_) => JsonValue::BigUint(v),
        })
    }
    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
        Ok(JsonValue::Float(v))
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(JsonValue::Str(Cow::Borrowed(v)))
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(JsonValue::Str(Cow::Owned(v.to_string())))
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(JsonValue::Str(Cow::Owned(v)))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(a.size_hint().unwrap_or(0).min(64));
        while let Some(v) = a.next_element()? {
            out.push(v);
        }
        Ok(JsonValue::Array(out))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut m: Vec<(Cow<'de, str>, JsonValue<'de>)> = Vec::with_capacity(a.size_hint().unwrap_or(0).min(64));
        while let Some(JsonKey(k)) = a.next_key()? {
            m.push((k, a.next_value()?));
        }
        if m.len() > 1 {
            // stable sort of the reversed entries puts a repeated key's last
            // value first; dedup keeps the first of each run
            m.reverse();
            m.sort_by(|x, y| key_cmp(&x.0, &y.0));
            m.dedup_by(|later, kept| later.0 == kept.0);
        }
        Ok(JsonValue::Object(m))
    }
}

struct JsonKey<'de>(Cow<'de, str>);

impl<'de> serde::Deserialize<'de> for JsonKey<'de> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = JsonKey<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string key")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(JsonKey(Cow::Borrowed(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(JsonKey(Cow::Owned(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(JsonKey(Cow::Owned(v)))
            }
        }
        d.deserialize_str(V)
    }
}

/// Transcodes one DAG-CBOR value straight to atproto JSON. Accepts exactly
/// what `Value::decode` accepts, and the output parses to the same JSON as
/// `Value::decode(bytes)?.to_json()`. On error `out` is left as it was.
pub fn write_json(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), CborError> {
    let start = out.len();
    let mut d = Decoder { data: bytes, pos: 0 };
    let r = d.json(0, out).and_then(|()| {
        if d.pos != bytes.len() {
            return Err(CborError::Invalid("trailing bytes"));
        }
        Ok(())
    });
    if r.is_err() {
        out.truncate(start);
    }
    r
}

#[inline]
fn json_str(out: &mut Vec<u8>, s: &str) {
    // most keys and texts need no escaping
    if s.bytes().all(|b| b >= 0x20 && b != b'"' && b != b'\\') {
        out.reserve(s.len() + 2);
        out.push(b'"');
        out.extend_from_slice(s.as_bytes());
        out.push(b'"');
        return;
    }
    let _ = serde_json::to_writer(&mut *out, s);
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    #[inline(always)]
    fn byte(&mut self) -> Result<u8, CborError> {
        let b = *self.data.get(self.pos).ok_or(CborError::Eof)?;
        self.pos += 1;
        Ok(b)
    }

    /// `n` is untrusted (up to u64::MAX): compared with what remains, never
    /// added to `pos`.
    #[inline(always)]
    fn take(&mut self, n: u64) -> Result<&'a [u8], CborError> {
        let rest = self.data.len() - self.pos;
        if n > rest as u64 {
            return Err(CborError::Eof);
        }
        let s = &self.data[self.pos..self.pos + n as usize];
        self.pos += n as usize;
        Ok(s)
    }

    /// DAG-CBOR requires the shortest encoding of every argument.
    #[inline(always)]
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let b = self.byte()?;
        let major = b >> 5;
        let info = b & 31;
        // major 7: only the one-byte false/true/null; floats (25-27), two-byte
        // simple values (24) and the other simple values are not data model
        if major == 7 {
            return match info {
                20..=22 => Ok((7, info as u64)),
                _ => Err(CborError::Invalid("floats/simple values not allowed")),
            };
        }
        let (n, min) = match info {
            0..=23 => (info as u64, 0),
            24 => (self.byte()? as u64, 24),
            25 => (u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64, 1 << 8),
            26 => (u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64, 1 << 16),
            27 => (u64::from_be_bytes(self.take(8)?.try_into().unwrap()), 1 << 32),
            _ => return Err(CborError::Invalid("indefinite length or reserved")),
        };
        if n < min {
            return Err(CborError::Invalid("non-minimal integer encoding"));
        }
        Ok((major, n))
    }

    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        let (major, n) = self.head()?;
        Ok(match major {
            0 | 1 => Value::Int(int(major, n)?),
            2 => Value::Bytes(self.take(n)?.to_vec()),
            3 => Value::Text(utf8(self.take(n)?)?.to_string()),
            4 => {
                let mut a = Vec::with_capacity((n as usize).min(1024));
                for _ in 0..n {
                    a.push(self.value(depth + 1)?);
                }
                Value::Array(a)
            }
            5 => {
                let mut m: Vec<(String, Value)> = Vec::with_capacity((n as usize).min(1024));
                for _ in 0..n {
                    let k = match self.value(depth + 1)? {
                        Value::Text(s) => s,
                        _ => return Err(CborError::Invalid("non-string map key")),
                    };
                    if let Some((prev, _)) = m.last() {
                        key_order(prev, &k)?;
                    }
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                }
                Value::Map(m)
            }
            6 => {
                if n != 42 {
                    return Err(CborError::Invalid("unsupported tag"));
                }
                match self.value(depth + 1)? {
                    Value::Bytes(b) if b.first() == Some(&0) => {
                        Value::Link(Cid::from_bytes(&b[1..]).map_err(|_| CborError::Invalid("bad cid"))?)
                    }
                    _ => return Err(CborError::Invalid("bad cid link")),
                }
            }
            7 => match n {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                _ => Value::Null,
            },
            _ => unreachable!(),
        })
    }
}

/// Canonical order, which also rules out duplicates.
fn key_order(prev: &str, k: &str) -> Result<(), CborError> {
    match key_cmp(prev, k) {
        std::cmp::Ordering::Less => Ok(()),
        std::cmp::Ordering::Equal => Err(CborError::Invalid("duplicate map key")),
        std::cmp::Ordering::Greater => Err(CborError::Invalid("map keys not in canonical order")),
    }
}

/// Major type 0 or 1.
fn int(major: u8, n: u64) -> Result<i64, CborError> {
    let n = i64::try_from(n).map_err(|_| CborError::Invalid("int range"))?;
    Ok(if major == 1 { -1 - n } else { n })
}

fn utf8(b: &[u8]) -> Result<&str, CborError> {
    std::str::from_utf8(b).map_err(|_| CborError::Invalid("utf8"))
}

// The fast decoders accept exactly what `value` accepts but read map keys
// and links in place and size vectors by what the input can hold. On any
// error the callers re-run `value` for the error to report, so the fast
// paths only need to get accept/reject right.
impl<'a> Decoder<'a> {
    /// `depth` is the key's own depth, as `value` counts it.
    #[inline(always)]
    fn map_key(&mut self, depth: usize, prev: Option<&str>) -> Result<&'a str, CborError> {
        let k = self.json_key(depth)?;
        if let Some(prev) = prev {
            if key_cmp(prev, k) != std::cmp::Ordering::Less {
                return Err(CborError::Invalid("map keys not in canonical order"));
            }
        }
        Ok(k)
    }

    #[inline(always)]
    fn cap(&self, n: u64, min: usize) -> usize {
        (n.min(((self.data.len() - self.pos) / min) as u64)) as usize
    }

    fn owned(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        let (major, n) = self.head()?;
        Ok(match major {
            0 | 1 => Value::Int(int(major, n)?),
            2 => Value::Bytes(self.take(n)?.to_vec()),
            3 => Value::Text(utf8(self.take(n)?)?.to_owned()),
            4 => {
                let mut a = Vec::with_capacity(self.cap(n, 1));
                for _ in 0..n {
                    a.push(self.owned(depth + 1)?);
                }
                Value::Array(a)
            }
            5 => {
                let mut m: Vec<(String, Value)> = Vec::with_capacity(self.cap(n, 2));
                let mut prev: Option<&str> = None;
                for _ in 0..n {
                    let k = self.map_key(depth + 1, prev)?;
                    let v = self.owned(depth + 1)?;
                    m.push((k.to_owned(), v));
                    prev = Some(k);
                }
                Value::Map(m)
            }
            6 => {
                if n != 42 {
                    return Err(CborError::Invalid("unsupported tag"));
                }
                Value::Link(self.json_link(depth + 1)?)
            }
            7 => match n {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                _ => Value::Null,
            },
            _ => unreachable!(),
        })
    }

    fn borrowed(&mut self, depth: usize) -> Result<ValueRef<'a>, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        let (major, n) = self.head()?;
        Ok(match major {
            0 | 1 => ValueRef::Int(int(major, n)?),
            2 => ValueRef::Bytes(self.take(n)?),
            3 => ValueRef::Text(utf8(self.take(n)?)?),
            4 => {
                let mut a = Vec::with_capacity(self.cap(n, 1));
                for _ in 0..n {
                    a.push(self.borrowed(depth + 1)?);
                }
                ValueRef::Array(a)
            }
            5 => {
                let mut m: Vec<(&'a str, ValueRef<'a>)> = Vec::with_capacity(self.cap(n, 2));
                let mut prev: Option<&str> = None;
                for _ in 0..n {
                    let k = self.map_key(depth + 1, prev)?;
                    m.push((k, self.borrowed(depth + 1)?));
                    prev = Some(k);
                }
                ValueRef::Map(m)
            }
            6 => {
                if n != 42 {
                    return Err(CborError::Invalid("unsupported tag"));
                }
                ValueRef::Link(self.json_link(depth + 1)?)
            }
            7 => match n {
                20 => ValueRef::Bool(false),
                21 => ValueRef::Bool(true),
                _ => ValueRef::Null,
            },
            _ => unreachable!(),
        })
    }
}

/// For decoders specialized to one fixed shape (MST nodes). Each read
/// applies `Value::decode`'s rules for that item; `None` means "not that
/// item here", and the caller falls back to the generic decoder.
pub struct Cursor<'a> {
    d: Decoder<'a>,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { d: Decoder { data, pos: 0 } }
    }

    pub fn at_end(&self) -> bool {
        self.d.pos == self.d.data.len()
    }

    #[inline(always)]
    pub fn lit(&mut self, lit: &[u8]) -> bool {
        let ok = self.d.data[self.d.pos..].starts_with(lit);
        if ok {
            self.d.pos += lit.len();
        }
        ok
    }

    #[inline(always)]
    pub fn head(&mut self, major: u8) -> Option<u64> {
        match self.d.head() {
            Ok((m, n)) if m == major => Some(n),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.head(2)?;
        self.d.take(n).ok()
    }

    #[inline(always)]
    pub fn link(&mut self) -> Option<Cid> {
        if !self.lit(&LINK_PREFIX) {
            return None;
        }
        let c = Cid::from_bytes(self.d.take(CID_BYTES_LEN as u64).ok()?).ok()?;
        Some(c)
    }

    /// A map key, in canonical order after `prev`.
    pub fn map_key(&mut self, prev: Option<&str>) -> Option<&'a str> {
        self.d.map_key(1, prev).ok()
    }

    #[inline(always)]
    pub fn opt_link(&mut self) -> Option<Option<Cid>> {
        if self.lit(&[0xf6]) {
            return Some(None);
        }
        self.link().map(Some)
    }
}

/// Distinct blob CIDs of a stored record, in walk order, typed and legacy
/// (`{"cid", "mimeType"}`) refs alike, as the reference's `enumBlobRefs`
/// with `allowLegacy: true, strict: false`. Writes refuse legacy refs, but
/// migrated-in repos hold them, and an unindexed ref would be missing from
/// listMissingBlobs/listBlobs and collected by the blob GC.
pub fn blob_refs(v: &Value, out: &mut Vec<Cid>) {
    fn walk(v: &Value, out: &mut Vec<Cid>, seen: &mut std::collections::HashSet<Cid>) {
        match v {
            Value::Map(m) => {
                let found = match (v.get("$type"), v.get("ref"), v.get("cid"), v.get("mimeType")) {
                    (Some(Value::Text(t)), Some(Value::Link(c)), ..) if t == "blob" => Some(*c),
                    (None, _, Some(Value::Text(c)), Some(Value::Text(mime))) if m.len() == 2 && !mime.is_empty() => {
                        Cid::parse(c).ok()
                    }
                    _ => None,
                };
                if let Some(c) = found.filter(|c| seen.insert(*c)) {
                    out.push(c);
                }
                for (_, child) in m {
                    walk(child, out, seen);
                }
            }
            Value::Array(a) => a.iter().for_each(|c| walk(c, out, seen)),
            _ => {}
        }
    }
    let mut seen = out.iter().copied().collect();
    walk(v, out, &mut seen);
}
/// The blob refs [`blob_refs`] finds in `Value::decode(data)`,
/// in the same order, accepting exactly what it accepts but holding only the
/// refs: a record of a million one-byte items would be ~40 MB as a `Value`.
pub fn scan_blob_refs(data: &[u8]) -> Result<Vec<Cid>, CborError> {
    let mut d = Decoder { data, pos: 0 };
    let mut out = Vec::new();
    d.scan(0, &mut out)?;
    if d.pos != data.len() {
        return Err(CborError::Invalid("trailing bytes"));
    }
    let mut seen = std::collections::HashSet::with_capacity(out.len());
    out.retain(|c| seen.insert(*c));
    Ok(out)
}

#[derive(Clone, Copy)]
enum Scanned<'a> {
    Text(&'a str),
    Link(Cid),
    Other,
}

// `scan` mirrors `owned` check for check.
impl<'a> Decoder<'a> {
    fn scan(&mut self, depth: usize, out: &mut Vec<Cid>) -> Result<Scanned<'a>, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        let (major, n) = self.head()?;
        Ok(match major {
            0 | 1 => {
                int(major, n)?;
                Scanned::Other
            }
            2 => {
                self.take(n)?;
                Scanned::Other
            }
            3 => Scanned::Text(utf8(self.take(n)?)?),
            4 => {
                for _ in 0..n {
                    self.scan(depth + 1, out)?;
                }
                Scanned::Other
            }
            5 => {
                // a map's own ref goes before its children's, as `blob_refs` walks
                let at = out.len();
                let (mut ty, mut rf, mut cid, mut mime) = (None, None, None, None);
                let mut prev: Option<&str> = None;
                for _ in 0..n {
                    let k = self.map_key(depth + 1, prev)?;
                    let v = self.scan(depth + 1, out)?;
                    match k {
                        "$type" => ty = Some(v),
                        "ref" => rf = Some(v),
                        "cid" => cid = Some(v),
                        "mimeType" => mime = Some(v),
                        _ => {}
                    }
                    prev = Some(k);
                }
                let found = match (ty, rf, cid, mime) {
                    (Some(Scanned::Text("blob")), Some(Scanned::Link(c)), ..) => Some(c),
                    (None, _, Some(Scanned::Text(c)), Some(Scanned::Text(m))) if n == 2 && !m.is_empty() => {
                        Cid::parse(c).ok()
                    }
                    _ => None,
                };
                if let Some(c) = found {
                    out.insert(at, c);
                }
                Scanned::Other
            }
            6 => {
                if n != 42 {
                    return Err(CborError::Invalid("unsupported tag"));
                }
                Scanned::Link(self.json_link(depth + 1)?)
            }
            _ => Scanned::Other,
        })
    }
}

// The transcoder mirrors `value` check for check so both accept the same inputs.
impl<'a> Decoder<'a> {
    fn json(&mut self, depth: usize, out: &mut Vec<u8>) -> Result<(), CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        let (major, n) = self.head()?;
        match major {
            0 | 1 => {
                let _ = serde_json::to_writer(&mut *out, &int(major, n)?);
            }
            2 => {
                let b = self.take(n)?;
                out.extend_from_slice(b"{\"$bytes\":\"");
                let at = out.len();
                out.resize(at + b.len().div_ceil(3) * 4, 0);
                let w = base64::engine::general_purpose::STANDARD_NO_PAD
                    .encode_slice(b, &mut out[at..])
                    .map_err(|_| CborError::Invalid("base64"))?;
                out.truncate(at + w);
                out.extend_from_slice(b"\"}");
            }
            3 => json_str(out, utf8(self.take(n)?)?),
            4 => {
                out.push(b'[');
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    self.json(depth + 1, out)?;
                }
                out.push(b']');
            }
            5 => {
                out.push(b'{');
                let mut prev: Option<&str> = None;
                for i in 0..n {
                    if i > 0 {
                        out.push(b',');
                    }
                    let k = self.json_key(depth + 1)?;
                    if let Some(prev) = prev {
                        key_order(prev, k)?;
                    }
                    json_str(out, k);
                    out.push(b':');
                    self.json(depth + 1, out)?;
                    prev = Some(k);
                }
                out.push(b'}');
            }
            6 => {
                if n != 42 {
                    return Err(CborError::Invalid("unsupported tag"));
                }
                let c = self.json_link(depth + 1)?;
                out.extend_from_slice(b"{\"$link\":\"");
                c.write_string(out);
                out.extend_from_slice(b"\"}");
            }
            7 => out.extend_from_slice(match n {
                20 => b"false",
                21 => b"true",
                _ => b"null",
            }),
            _ => unreachable!(),
        }
        Ok(())
    }

    #[inline(always)]
    fn json_key(&mut self, depth: usize) -> Result<&'a str, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        match self.head()? {
            (3, n) => utf8(self.take(n)?),
            _ => Err(CborError::Invalid("non-string map key")),
        }
    }

    #[inline(always)]
    fn json_link(&mut self, depth: usize) -> Result<Cid, CborError> {
        if depth > 128 {
            return Err(CborError::Invalid("nesting too deep"));
        }
        match self.head()? {
            (2, n) => match self.take(n)? {
                [0, c @ ..] => Cid::from_bytes(c).map_err(|_| CborError::Invalid("bad cid")),
                _ => Err(CborError::Invalid("bad cid link")),
            },
            _ => Err(CborError::Invalid("bad cid link")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `scan_blob_refs` finds what `Value::decode` and `blob_refs` find, and
    /// refuses what they refuse.
    #[test]
    fn scan_blob_refs_matches_decode() {
        let blob = |i: u8| Cid::raw(&[i]);
        let m = |pairs: Vec<(&str, Value)>| {
            let mut v: Vec<(String, Value)> = pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
            v.sort_by(|a, b| key_cmp(&a.0, &b.0));
            Value::Map(v)
        };
        let t = |s: &str| Value::Text(s.into());
        let b = |i: u8| {
            m(vec![
                ("$type", t("blob")),
                ("ref", Value::Link(blob(i))),
                ("mimeType", t("image/png")),
                ("size", Value::Int(3)),
            ])
        };
        let legacy = |i: u8| m(vec![("cid", t(&blob(i).to_string())), ("mimeType", t("image/png"))]);
        let records = [
            m(vec![("text", t("none"))]),
            m(vec![
                ("a", b(1)),
                ("b", Value::Array(vec![b(2), m(vec![("x", b(1))]), legacy(3)])),
                ("c", m(vec![("d", b(4))])),
            ]),
            // a blob map holding another blob: the outer one first
            m(vec![("$type", t("blob")), ("ref", Value::Link(blob(5))), ("mimeType", t("x/y")), ("z", b(6))]),
            m(vec![("$type", t("blob")), ("ref", t("not a link")), ("mimeType", t("x/y"))]),
            m(vec![("$type", Value::Int(1)), ("ref", Value::Link(blob(5)))]),
            m(vec![("cid", t(&blob(7).to_string())), ("mimeType", t(""))]),
            m(vec![("cid", t(&blob(7).to_string())), ("mimeType", t("a/b")), ("extra", Value::Int(1))]),
            m(vec![("cid", t("nope")), ("mimeType", t("a/b"))]),
            Value::Array(vec![b(8), Value::Array(vec![Value::Array(vec![b(9)])]), b(8)]),
        ];
        for r in &records {
            let bytes = r.to_cbor();
            let mut want = Vec::new();
            blob_refs(&Value::decode(&bytes).unwrap(), &mut want);
            assert_eq!(scan_blob_refs(&bytes).unwrap(), want, "{r:?}");
        }
        assert_eq!(scan_blob_refs(&records[1].to_cbor()).unwrap(), vec![blob(1), blob(2), blob(3), blob(4)]);
        let ok = records[1].to_cbor();
        let mut bad: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x01], // keys out of order
            vec![0xf9, 0, 0],                               // a float
            vec![0xc5, 0x01],                               // tag 5
            vec![0x18, 0x01],                               // non-minimal
            vec![0x9f, 0xff],                               // indefinite
            [&ok[..], &[0x01]].concat(),                    // trailing
            ok[..ok.len() - 1].to_vec(),                    // truncated
        ];
        let mut deep = vec![0x81; 200];
        deep.push(0x01);
        bad.push(deep);
        for b in &bad {
            assert!(Value::decode(b).is_err(), "{b:02x?}");
            assert!(scan_blob_refs(b).is_err(), "{b:02x?}");
        }
    }

    #[test]
    fn json_roundtrip_sorted() {
        let j = serde_json::json!({"text": "hi", "$type": "app.bsky.feed.post", "createdAt": "2026-01-01T00:00:00Z", "n": -5});
        let v = Value::from_json(&j).unwrap();
        let b = v.to_cbor();
        let back = Value::decode(&b).unwrap();
        assert_eq!(back, v);
        assert_eq!(back.to_json(), j);
        // canonical order: "n" (1), "text" (4), "$type" (5), "createdAt" (9)
        if let Value::Map(m) = &v {
            let keys: Vec<_> = m.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(keys, vec!["n", "text", "$type", "createdAt"]);
        }
    }

    #[test]
    fn bytes_base64_like_the_reference() {
        // @atproto/lex-data fromBase64: padding optional (partial padding
        // too, never past the padded length), trailing bits ignored
        for (s, want) in [
            ("", Some(vec![])),
            ("AQID", Some(vec![1, 2, 3])),
            ("AQ", Some(vec![1])),
            ("AQ==", Some(vec![1])),
            ("AQ=", Some(vec![1])),
            ("AR", Some(vec![1])),
            ("AQI", Some(vec![1, 2])),
            ("AQJ=", Some(vec![1, 2])),
            ("AQID=", None),
            ("AQ===", None),
            ("A", None),
            ("_-8", None),
            ("AQ ID", None),
        ] {
            assert_eq!(decode_bytes(s).ok(), want, "{s:?}");
            let j = serde_json::json!({"b": {"$bytes": s}});
            let tree = Value::from_json(&j).ok().map(|v| v.to_cbor());
            let text = j.to_string();
            let mut out = Vec::new();
            let one_pass = JsonValue::parse(text.as_bytes())
                .unwrap()
                .encode_record(&mut out, &mut RecordRefs::default())
                .ok()
                .map(|()| out);
            assert_eq!(tree, one_pass, "{s:?}");
            assert_eq!(tree.is_some(), want.is_some(), "{s:?}");
        }
    }

    #[test]
    fn blob_refs_like_the_reference() {
        // @atproto/lex-data strict isTypedBlobRef
        let raw = Cid::raw(b"x").to_string();
        let dag = Cid::dag_cbor(b"x").to_string();
        let blob = |link: &str, mime: serde_json::Value, size: serde_json::Value| serde_json::json!({"$type": "blob", "ref": {"$link": link}, "mimeType": mime, "size": size});
        let mut extra = blob(&raw, "image/png".into(), 1.into());
        extra["alt"] = "x".into();
        for (j, ok) in [
            (blob(&raw, "image/png".into(), 0.into()), true),
            (blob(&raw, "image/png".into(), 9_007_199_254_740_991i64.into()), true),
            (blob(&raw, "image/png".into(), (-1).into()), false),
            (blob(&raw, "image/png".into(), 9_007_199_254_740_992i64.into()), false),
            (blob(&raw, "jpeg".into(), 1.into()), true),
            (blob(&raw, "".into(), 1.into()), false),
            (blob(&dag, "image/png".into(), 1.into()), false),
            (blob(&raw, "image/png".into(), "1".into()), false),
            (extra, false),
            (serde_json::json!({"$type": "blob", "ref": {"$link": raw}, "mimeType": "image/png"}), false),
        ] {
            let rec = serde_json::json!({"img": j});
            let text = rec.to_string();
            let mut out = Vec::new();
            let one_pass =
                JsonValue::parse(text.as_bytes()).unwrap().encode_record(&mut out, &mut RecordRefs::default());
            assert_eq!(Value::from_json(&rec).is_ok(), ok, "{text}");
            assert_eq!(one_pass.is_ok(), ok, "{text}");
        }
    }

    /// Numbers are safe integers however they are written (lex-cbor's
    /// encoder: `Number.isSafeInteger`), integer or integral float.
    #[test]
    fn json_numbers_must_be_safe_integers() {
        for (text, ok) in [
            ("9007199254740991", true),
            ("-9007199254740991", true),
            ("9007199254740991.0", true),
            ("9007199254740992", false),
            ("-9007199254740992", false),
            ("9007199254740992.0", false),
            ("9223372036854775807", false),
            ("-9223372036854775808", false),
            ("18446744073709551615", false),
            ("1.5", false),
        ] {
            let rec = format!(r#"{{"n": {text}}}"#);
            let j: serde_json::Value = serde_json::from_str(&rec).unwrap();
            let mut out = Vec::new();
            let one_pass =
                JsonValue::parse(rec.as_bytes()).unwrap().encode_record(&mut out, &mut RecordRefs::default());
            assert_eq!(Value::from_json(&j).is_ok(), ok, "{text}");
            assert_eq!(one_pass.is_ok(), ok, "{text}");
        }
    }

    #[test]
    fn huge_lengths_are_errors_not_panics() {
        // byte/text strings and arrays of length u64::MAX
        for major in [0x5b, 0x7b, 0x9b, 0xbb] {
            let mut b = vec![major, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            b.extend_from_slice(&[0; 10]);
            assert!(Value::decode(&b).is_err(), "{major:#x}");
            assert!(write_json(&b, &mut Vec::new()).is_err(), "{major:#x}");
        }
        // one past the end
        assert!(Value::decode(&[0x43, 1, 2]).is_err());
    }

    #[test]
    fn major_7_only_false_true_null() {
        assert_eq!(Value::decode(&[0xf4]).unwrap(), Value::Bool(false));
        assert_eq!(Value::decode(&[0xf5]).unwrap(), Value::Bool(true));
        assert_eq!(Value::decode(&[0xf6]).unwrap(), Value::Null);
        for b in [
            &[0xf7][..],                                             // undefined
            &[0xf0],                                                 // simple(16)
            &[0xf8, 0x14],                                           // two-byte simple(20)
            &[0xf8, 0x16],                                           // two-byte simple(22)
            &[0xf8, 0xff],                                           // simple(255)
            &[0xf9, 0x00, 0x14],                                     // f16 with bits 20
            &[0xf9, 0x3c, 0x00],                                     // f16 1.0
            &[0xfa, 0x00, 0x00, 0x00, 0x15],                         // f32 with bits 21
            &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0x16],                      // f64 with bits 22
            &[0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18], // f64 pi
            &[0xff],                                                 // break
        ] {
            assert!(Value::decode(b).is_err(), "{b:02x?} accepted");
            assert!(write_json(b, &mut Vec::new()).is_err(), "{b:02x?} transcoded");
        }
    }

    #[test]
    fn write_json_matches_to_json() {
        let j = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "quote \" backslash \\ nl \n tab \t ctl \u{1} emoji \u{1F600}",
            "n": [0, -1, 23, 24, -25, 255, 256, 65536, 9_007_199_254_740_991i64, -9_007_199_254_740_991i64],
            "b": {"$bytes": "AQIDBA"},
            "e": {"$bytes": ""},
            "l": {"$link": "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"},
            "o": {"a": null, "b": true, "c": false, "d": [], "e": {}},
        });
        let b = Value::from_json(&j).unwrap().to_cbor();
        let mut out = b"prefix".to_vec();
        write_json(&b, &mut out).unwrap();
        let got: serde_json::Value = serde_json::from_slice(&out[6..]).unwrap();
        assert_eq!(got, j);
        // errors leave the output untouched
        let before = out.clone();
        let mut bad = b.clone();
        bad.push(0);
        assert!(write_json(&bad, &mut out).is_err());
        assert_eq!(out, before);
        // stored records may hold any 64-bit integer (CBOR from a CAR)
        let big = Value::Array([i64::MAX, i64::MIN + 1, i64::MIN].map(Value::Int).to_vec()).to_cbor();
        let mut out = Vec::new();
        write_json(&big, &mut out).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
            serde_json::json!([i64::MAX, i64::MIN + 1, i64::MIN])
        );
    }
}
