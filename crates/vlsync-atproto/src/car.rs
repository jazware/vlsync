//! CAR v1 encoding (header + varint-framed blocks).

use crate::cbor;
use crate::cid::Cid;

pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

pub fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let mut n = 0u64;
    for (i, &byte) in b.iter().enumerate().take(10) {
        n |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((n, i + 1));
        }
    }
    None
}

pub fn write_header(out: &mut Vec<u8>, root: &Cid) {
    let mut h = Vec::with_capacity(64);
    cbor::write_map_head(&mut h, 2);
    cbor::write_text(&mut h, "roots");
    cbor::write_array_head(&mut h, 1);
    cbor::write_cid(&mut h, root);
    cbor::write_text(&mut h, "version");
    cbor::write_uint(&mut h, 1);
    write_varint(out, h.len() as u64);
    out.extend_from_slice(&h);
}

pub fn write_block(out: &mut Vec<u8>, c: &Cid, data: &[u8]) {
    let cb = c.to_bytes();
    write_varint(out, (cb.len() + data.len()) as u64);
    out.extend_from_slice(&cb);
    out.extend_from_slice(data);
}

pub fn read_car(b: &[u8]) -> anyhow::Result<(Vec<Cid>, Vec<(Cid, &[u8])>)> {
    // untrusted lengths (up to u64::MAX): compare with what remains, never add to a position
    let (hlen, n) = read_varint(b).ok_or_else(|| anyhow::anyhow!("bad car header"))?;
    if hlen > (b.len() - n) as u64 {
        anyhow::bail!("short car");
    }
    let mut pos = n + hlen as usize;
    let roots = read_header(&b[n..pos])?;
    let mut blocks = Vec::new();
    while pos < b.len() {
        let (len, n) = read_varint(&b[pos..]).ok_or_else(|| anyhow::anyhow!("bad block len"))?;
        pos += n;
        if len > (b.len() - pos) as u64 {
            anyhow::bail!("short block");
        }
        let end = pos + len as usize;
        let blk = &b[pos..end];
        let (c, cl) = Cid::read_prefix(blk)?;
        blocks.push((c, &blk[cl..]));
        pos = end;
    }
    Ok((roots, blocks))
}

/// The roots of a CAR header (the bytes after its length varint).
pub fn read_header(h: &[u8]) -> anyhow::Result<Vec<Cid>> {
    // go-car and the reference refuse a v2 or rootless header
    let header = cbor::ValueRef::decode(h)?;
    if header.get("version") != Some(&cbor::ValueRef::Int(1)) {
        anyhow::bail!("car header version must be 1");
    }
    match header.get("roots") {
        Some(cbor::ValueRef::Array(a)) => a
            .iter()
            .map(|v| match v {
                cbor::ValueRef::Link(c) => Ok(*c),
                _ => Err(anyhow::anyhow!("car root is not a CID")),
            })
            .collect(),
        _ => anyhow::bail!("car header has no roots array"),
    }
}

/// Whether an untrusted block's bytes hash to its CID.
pub fn block_matches(c: &Cid, data: &[u8]) -> bool {
    let actual = if c.codec == crate::cid::CODEC_RAW { Cid::raw(data) } else { Cid::dag_cbor(data) };
    actual == *c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_lengths_are_errors() {
        let max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        // header length u64::MAX
        assert!(read_car(&max).is_err());
        // a valid header, then a block length of u64::MAX
        let mut car = Vec::new();
        write_header(&mut car, &Cid::dag_cbor(b"x"));
        car.extend_from_slice(&max);
        car.extend_from_slice(&[0; 40]);
        assert!(read_car(&car).is_err());
        // and lengths just past the end
        let mut car = Vec::new();
        write_header(&mut car, &Cid::dag_cbor(b"x"));
        write_varint(&mut car, 41);
        car.extend_from_slice(&[0; 40]);
        assert!(read_car(&car).is_err());
        assert!(read_car(&[0x05, 0xa0]).is_err());
    }

    #[test]
    fn header_must_be_carv1() {
        let c = Cid::dag_cbor(b"x");
        let car = |h: cbor::Value| {
            let hb = h.to_cbor();
            let mut out = Vec::new();
            write_varint(&mut out, hb.len() as u64);
            out.extend_from_slice(&hb);
            write_block(&mut out, &c, b"x");
            out
        };
        let roots = cbor::Value::Array(vec![cbor::Value::Link(c)]);
        let ok = car(cbor::Value::Map(vec![("roots".into(), roots.clone()), ("version".into(), cbor::Value::Int(1))]));
        assert_eq!(read_car(&ok).unwrap().0, vec![c]);
        for h in [
            cbor::Value::Map(vec![("roots".into(), roots.clone())]),
            cbor::Value::Map(vec![("roots".into(), roots.clone()), ("version".into(), cbor::Value::Int(2))]),
            cbor::Value::Map(vec![("version".into(), cbor::Value::Int(1))]),
            cbor::Value::Map(vec![("roots".into(), cbor::Value::Int(1)), ("version".into(), cbor::Value::Int(1))]),
            cbor::Value::Map(vec![
                ("roots".into(), cbor::Value::Array(vec![cbor::Value::Null])),
                ("version".into(), cbor::Value::Int(1)),
            ]),
        ] {
            assert!(read_car(&car(h.clone())).is_err(), "{h:?}");
        }
    }
}
