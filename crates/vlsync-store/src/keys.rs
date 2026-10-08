//! Slot-major keys in SlateDB: `0x01 ‖ slot (u16 BE) ‖ family ‖ rest`, the
//! slot being that of the key's routing key (`slots::slot_of`). A shard's
//! slot range is one contiguous key range, so a shard splits or merges by
//! cloning its SlateDB with a projection range. vlpds's state layout
//! (src/state.rs) and vlRelay's records are built on these.

use bytes::Bytes;

pub const SLOT_TAG: u8 = 0x01;
pub const SLOT_PREFIX_LEN: usize = 3;

pub fn slot_prefix(slot: u16) -> [u8; SLOT_PREFIX_LEN] {
    let [a, b] = slot.to_be_bytes();
    [SLOT_TAG, a, b]
}

pub fn slot_family(slot: u16, fam: &[u8]) -> Vec<u8> {
    [&slot_prefix(slot)[..], fam].concat()
}

pub fn key_slot(key: &[u8]) -> Option<u16> {
    (key.len() >= SLOT_PREFIX_LEN && key[0] == SLOT_TAG).then(|| u16::from_be_bytes([key[1], key[2]]))
}

/// family ‖ rest.
pub fn key_body(key: &[u8]) -> &[u8] {
    key.get(SLOT_PREFIX_LEN..).unwrap_or_default()
}

/// Slots [lo, hi), hi <= 65,536.
pub fn slot_range_keys(lo: u32, hi: u32) -> (Bytes, Bytes) {
    let at = |s: u32| -> Bytes {
        if s >= crate::slots::SLOTS {
            Bytes::from_static(&[SLOT_TAG + 1])
        } else {
            Bytes::copy_from_slice(&slot_prefix(s as u16))
        }
    };
    (at(lo), at(hi))
}

/// A repo generation in keys: LEB128, which is prefix-free, so no
/// generation's range holds another's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gen(pub u64);

impl Gen {
    pub fn bytes(self) -> GenBytes {
        let mut b = GenBytes { buf: [0; 10], len: 0 };
        let mut v = self.0;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                b.buf[b.len] = byte;
                b.len += 1;
                return b;
            }
            b.buf[b.len] = byte | 0x80;
            b.len += 1;
        }
    }
}

pub struct GenBytes {
    buf: [u8; 10],
    len: usize,
}

impl std::ops::Deref for GenBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

const SCAN_BATCH: usize = 256;

/// `DbIterator::next_batch` skips the await (and tracing span) per row down
/// SlateDB's iterator stack. For scans read to (near) their end: it reads up
/// to a batch ahead of what the caller takes.
pub struct BatchedScan {
    iter: slatedb::DbIterator,
    rows: std::vec::IntoIter<slatedb::KeyValue>,
}

impl BatchedScan {
    pub fn new(iter: slatedb::DbIterator) -> BatchedScan {
        BatchedScan { iter, rows: Vec::new().into_iter() }
    }

    pub async fn next(&mut self) -> Result<Option<slatedb::KeyValue>, slatedb::Error> {
        if let Some(kv) = self.rows.next() {
            return Ok(Some(kv));
        }
        self.rows = self.iter.next_batch(SCAN_BATCH).await?.into_iter();
        Ok(self.rows.next())
    }

    pub fn next_buffered(&mut self) -> Option<slatedb::KeyValue> {
        self.rows.next()
    }
}

pub fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return end;
        }
    }
    vec![0xff; prefix.len() + 1]
}
