//! CIDv1 with a sha2-256 multihash: every CID a repo holds is one of these
//! (dag-cbor records/nodes/commits, raw blobs), so 33 bytes suffice.

use sha2::{Digest, Sha256};
use std::fmt;

pub const CODEC_DAG_CBOR: u8 = 0x71;
pub const CODEC_RAW: u8 = 0x55;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cid {
    pub codec: u8,
    pub digest: [u8; 32],
}

/// Hashes 16 digest bytes and the codec instead of all 33 bytes (the commit
/// path hashes many CIDs). Still HashDoS-resistant: every map keyed by `Cid`
/// uses a per-process random hasher key, so only the hasher's input is
/// chosen here, and two CIDs collide outright only if 128 digest bits match.
impl std::hash::Hash for Cid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let [a, b] =
            [&self.digest[..8], &self.digest[8..16]].map(|w| u64::from_le_bytes(w.try_into().expect("8 bytes")));
        state.write_u64(a ^ self.codec as u64);
        state.write_u64(b);
    }
}

/// version + codec + mh code + mh len + 32-byte digest.
pub const CID_BYTES_LEN: usize = 36;

impl Cid {
    pub fn dag_cbor(data: &[u8]) -> Cid {
        Cid { codec: CODEC_DAG_CBOR, digest: Sha256::digest(data).into() }
    }

    pub fn raw(data: &[u8]) -> Cid {
        Cid { codec: CODEC_RAW, digest: Sha256::digest(data).into() }
    }

    pub fn to_bytes(&self) -> [u8; CID_BYTES_LEN] {
        let mut out = [0u8; CID_BYTES_LEN];
        out[0] = 0x01;
        out[1] = self.codec;
        out[2] = 0x12;
        out[3] = 0x20;
        out[4..].copy_from_slice(&self.digest);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Cid, CidError> {
        if b.len() != CID_BYTES_LEN {
            return Err(CidError::Unsupported);
        }
        if b[0] != 0x01 || (b[1] != CODEC_DAG_CBOR && b[1] != CODEC_RAW) || b[2] != 0x12 || b[3] != 0x20 {
            return Err(CidError::Unsupported);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&b[4..]);
        Ok(Cid { codec: b[1], digest })
    }

    /// Returns the CID and the bytes consumed.
    pub fn read_prefix(b: &[u8]) -> Result<(Cid, usize), CidError> {
        if b.len() < CID_BYTES_LEN {
            return Err(CidError::Unsupported);
        }
        Ok((Cid::from_bytes(&b[..CID_BYTES_LEN])?, CID_BYTES_LEN))
    }

    /// `b` + 58 base32-lower characters, canonical (the last character's 2
    /// padding bits zero). Accepts exactly what
    /// `Cid::from_bytes(&base32_decode(rest)?)` accepts: no other length
    /// decodes canonically to 36 bytes.
    pub fn parse(s: &str) -> Result<Cid, CidError> {
        let s = s.as_bytes();
        if s.len() != 1 + CID_STR_LEN || s[0] != b'b' {
            return Err(CidError::Unsupported);
        }
        let mut b = [0u8; CID_BYTES_LEN];
        if !decode_cid_body(&s[1..], &mut b) {
            return Err(CidError::Unsupported);
        }
        Cid::from_bytes(&b)
    }

    #[inline]
    fn encode_str(&self) -> [u8; 1 + CID_STR_LEN] {
        let raw = self.to_bytes();
        let mut out = [0u8; 1 + CID_STR_LEN];
        out[0] = b'b';
        // 7 groups of 5 bytes, then 1 byte in 2 characters
        for g in 0..7 {
            enc5(&raw[g * 5..g * 5 + 5], &mut out[1 + g * 8..1 + g * 8 + 8]);
        }
        let last = raw[35];
        out[57] = B32[(last >> 3) as usize];
        out[58] = B32[((last & 7) << 2) as usize];
        out
    }
}

const CID_STR_LEN: usize = 58;

impl Cid {
    pub fn write_string(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encode_str());
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.encode_str();
        f.write_str(std::str::from_utf8(&s).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CidError {
    #[error("unsupported or malformed CID")]
    Unsupported,
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// 0xff outside base32-lower.
const B32_DEC: [u8; 256] = {
    let mut t = [0xffu8; 256];
    let mut i = 0;
    while i < 32 {
        t[B32[i] as usize] = i as u8;
        i += 1;
    }
    t
};

#[inline(always)]
fn enc5(src: &[u8], dst: &mut [u8]) {
    let v =
        (src[0] as u64) << 32 | (src[1] as u64) << 24 | (src[2] as u64) << 16 | (src[3] as u64) << 8 | src[4] as u64;
    for (i, d) in dst[..8].iter_mut().enumerate() {
        *d = B32[((v >> (35 - 5 * i)) & 31) as usize];
    }
}

#[inline(always)]
fn dec8(src: &[u8], dst: &mut [u8]) -> bool {
    let mut v = 0u64;
    let mut bad = 0u8;
    for &c in &src[..8] {
        let d = B32_DEC[c as usize];
        bad |= d;
        v = v << 5 | (d & 31) as u64;
    }
    dst[..5].copy_from_slice(&v.to_be_bytes()[3..]);
    bad & 0x80 == 0
}

#[inline]
fn decode_cid_body(s: &[u8], out: &mut [u8; CID_BYTES_LEN]) -> bool {
    debug_assert_eq!(s.len(), CID_STR_LEN);
    let mut ok = true;
    for g in 0..7 {
        ok &= dec8(&s[g * 8..g * 8 + 8], &mut out[g * 5..g * 5 + 5]);
    }
    let (a, b) = (B32_DEC[s[56] as usize], B32_DEC[s[57] as usize]);
    // 10 bits: one byte, then 2 padding bits that must be zero
    if !ok || (a | b) & 0x80 != 0 || b & 3 != 0 {
        return false;
    }
    out[35] = a << 3 | b >> 2;
    true
}

pub fn base32_encode(data: &[u8]) -> String {
    let whole = data.len() / 5 * 5;
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    let mut chunk = [0u8; 8];
    for g in data[..whole].as_chunks::<5>().0 {
        enc5(g, &mut chunk);
        out.extend_from_slice(&chunk);
    }
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in &data[whole..] {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize]);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize]);
    }
    String::from_utf8(out).expect("base32 is ASCII")
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let whole = s.len() / 8 * 8;
    let mut chunk = [0u8; 5];
    for g in s[..whole].as_chunks::<8>().0 {
        if !dec8(g, &mut chunk) {
            return None;
        }
        out.extend_from_slice(&chunk);
    }
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in &s[whole..] {
        let v = B32_DEC[c as usize];
        if v == 0xff {
            return None;
        }
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    // the leftover padding bits must be zero so each byte string has one encoding
    if bits >= 5 || buf & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_string() {
        // CID of the empty MST node, a well-known value in atproto.
        let c = Cid::parse("bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm").unwrap();
        assert_eq!(c.to_string(), "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    }

    #[test]
    fn non_canonical_base32_rejected() {
        let s = "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm";
        // 36 bytes = 288 bits in 58 characters: the last character carries 3
        // data bits and 2 padding bits, which must be zero
        let last = s.as_bytes()[s.len() - 1];
        let v = B32.iter().position(|&c| c == last).unwrap();
        assert_eq!(v & 3, 0);
        for pad in 1..4 {
            let mut t = s[..s.len() - 1].to_string();
            t.push(B32[v | pad] as char);
            assert!(Cid::parse(&t).is_err(), "{t}");
        }
        // an extra character is padding too
        assert!(Cid::parse(&format!("{s}a")).is_err());
        assert!(base32_decode("a").is_none());
        // every byte string round-trips through its one encoding
        for n in 0..12u8 {
            let data: Vec<u8> = (0..n).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
    }
}
