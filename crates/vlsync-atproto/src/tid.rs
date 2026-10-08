//! atproto TIDs: 53 bits of microseconds + 10 bits of clock id, base32-sortable.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Tid(pub u64);

impl Tid {
    pub fn from_parts(micros: u64, clock_id: u64) -> Tid {
        Tid(((micros & ((1 << 53) - 1)) << 10) | (clock_id & 0x3ff))
    }

    pub fn micros(&self) -> u64 {
        self.0 >> 10
    }

    pub fn parse(s: &str) -> Option<Tid> {
        if s.len() != 13 {
            return None;
        }
        let mut v: u64 = 0;
        for (i, c) in s.bytes().enumerate() {
            let d = ALPHABET.iter().position(|&a| a == c)? as u64;
            if i == 0 && d >= 16 {
                return None; // top bit must be zero
            }
            v = (v << 5) | d;
        }
        Some(Tid(v))
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; 13];
        let mut v = self.0;
        for i in (0..13).rev() {
            buf[i] = ALPHABET[(v & 31) as usize];
            v >>= 5;
        }
        f.write_str(std::str::from_utf8(&buf).unwrap())
    }
}

pub fn now_micros() -> u64 {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as u64;
    #[cfg(any(test, feature = "test-clock"))]
    let t = t.wrapping_add_signed(TEST_SKEW_US.with(|s| s.get()));
    t
}

#[cfg(any(test, feature = "test-clock"))]
thread_local! {
    static TEST_SKEW_US: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

/// Shifts this thread's wall clock (e.g. a backward NTP step).
#[cfg(any(test, feature = "test-clock"))]
pub fn set_test_skew_us(us: i64) {
    TEST_SKEW_US.with(|s| s.set(us));
}

pub struct TidClock {
    last: AtomicU64,
    clock_id: u64,
}

impl TidClock {
    pub fn new() -> TidClock {
        TidClock { last: AtomicU64::new(0), clock_id: rand::random::<u64>() & 0x3ff }
    }

    pub fn next(&self) -> Tid {
        let now = now_micros();
        let mut prev = self.last.load(Ordering::Relaxed);
        loop {
            let next = now.max(prev + 1);
            match self.last.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Tid::from_parts(next, self.clock_id),
                Err(p) => prev = p,
            }
        }
    }
}

impl Default for TidClock {
    fn default() -> Self {
        Self::new()
    }
}

/// The current time, but strictly after `prev`.
pub fn next_rev(prev: Option<Tid>, clock_id: u64) -> Tid {
    let now = Tid::from_parts(now_micros(), clock_id);
    match prev {
        Some(p) if now <= p => Tid(p.0 + 1),
        _ => now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let t = Tid::parse("3jzfcijpj2z2a").unwrap();
        assert_eq!(t.to_string(), "3jzfcijpj2z2a");
        let c = TidClock::new();
        let a = c.next();
        let b = c.next();
        assert!(b > a && b.to_string() > a.to_string());
    }
}
