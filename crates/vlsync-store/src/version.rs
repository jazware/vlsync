//! Feature levels: which persisted and wire formats a build reads and
//! writes, and which one the cluster has committed to in `cluster/version`.
//! Writers emit the *active* level's formats, so a build ahead of the
//! cluster writes byte for byte what the previous build writes: that is the
//! rollback window. See DESIGN.md "Rolling upgrades and format versioning".

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct Level {
    pub level: u32,
    pub name: &'static str,
    pub description: &'static str,
    /// Puts new bytes in the bucket, so it can never be lowered again;
    /// false = only gates wire behavior.
    pub persistent: bool,
    /// Set only if this level changed the segment magic.
    pub segment_magic: Option<&'static [u8; 8]>,
}

/// Recorded in testdata/formats/L1.
const BASELINE: Level = Level {
    level: 1,
    name: "baseline",
    description: "VLSEG06 log segments (32-bit shard tags, zstd bodies, derived #commit muts), \
                  VLFENCE fences, h/ R/ c/ C/ b/ n/ M/ a/ p/ state rows, meta/applied2 markers, \
                  JSON control objects, vw1 wrapped secrets, log stream messages 0 (batch) and 1 (watermark)",
    persistent: true,
    segment_magic: Some(b"VLSEG06\n"),
};

pub const REAL_MAX: u32 = 1;

/// Compiled in only with the `test-level` cargo feature (never a release
/// image). It changes two on-bucket formats the way a real level would
/// (segment magic + body checksum, `min_seg_format` in retain reports), so
/// mixed-version behavior runs between real builds (tests/level_gating.rs,
/// bench/ha `upgrade-*`). Fixtures: `testdata/formats/Ltest`, not in the
/// MANIFEST.
pub const TEST_LEVEL: u32 = REAL_MAX + 1;
pub const TEST_SEGMENT_MAGIC: &[u8; 8] = b"VLSEGT1\n";

#[cfg(feature = "test-level")]
const TEST: Level = Level {
    level: TEST_LEVEL,
    name: "test",
    description: "TEST ONLY (cargo feature test-level): VLSEGT1 segments (header + body checksum), \
                  retain/ reports with min_seg_format",
    persistent: true,
    segment_magic: Some(TEST_SEGMENT_MAGIC),
};

/// Oldest first.
#[cfg(not(feature = "test-level"))]
pub const LEVELS: &[Level] = &[BASELINE];
#[cfg(feature = "test-level")]
pub const LEVELS: &[Level] = &[BASELINE, TEST];

pub const MIN_LEVEL: u32 = 1;
pub const MAX_LEVEL: u32 = if cfg!(feature = "test-level") { TEST_LEVEL } else { REAL_MAX };
/// Highest level that has shipped: its fixtures are frozen by
/// testdata/formats/MANIFEST.
pub const RELEASED: u32 = 1;

pub fn test_level_active() -> bool {
    cfg!(feature = "test-level") && active() >= TEST_LEVEL
}

/// Whether the cluster may go from `active` down to `to`: only past levels
/// that put no new bytes in the bucket (a node at `to` couldn't read what a
/// persistent level wrote). Err = why not.
pub fn check_lower(table: &[Level], active: u32, to: u32) -> Result<(), String> {
    if to == 0 || to >= active {
        return Err(format!("level {to} is not below the active level {active}"));
    }
    for l in to + 1..=active {
        match table.iter().find(|x| x.level == l) {
            None => return Err(format!("level {l} is unknown to this build")),
            Some(x) if x.persistent => {
                return Err(format!(
                    "level {l} ({}) is persistent: it wrote new formats to the bucket, so it is never lowered",
                    x.name
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub const OBJECT: &str = "cluster/version";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Window {
    pub min: u32,
    pub max: u32,
}

impl Window {
    pub const BUILD: Window = Window { min: MIN_LEVEL, max: MAX_LEVEL };

    pub fn contains(&self, level: u32) -> bool {
        (self.min..=self.max).contains(&level)
    }

    /// Err = why not (for the exit-7 log line).
    pub fn check(&self, v: &ClusterVersion) -> Result<(), String> {
        if !self.contains(v.active) {
            return Err(format!(
                "cluster level {} is outside this build's levels {}..={}",
                v.active, self.min, self.max
            ));
        }
        if let Some(t) = v.target.filter(|t| *t > self.max) {
            return Err(format!("cluster is raising its level to {t}, past this build's max level {}", self.max));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClusterVersion {
    pub active: u32,
    /// Set while a raise is in progress; a node whose max level is below it
    /// refuses to start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<u32>,
    pub history: Vec<Change>,
    /// Fields of a newer build, kept by read-modify-CAS.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Change {
    pub level: u32,
    /// RFC 3339.
    pub at: String,
    pub by: String,
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ClusterVersion {
    pub fn new(active: u32, by: &str) -> ClusterVersion {
        ClusterVersion { active, target: None, history: vec![Change::new(active, by)], extra: Default::default() }
    }
}

impl Change {
    pub fn new(level: u32, by: &str) -> Change {
        Change {
            level,
            at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            by: by.into(),
            extra: Default::default(),
        }
    }
}

/// 0 until `cluster/version` is read. Process-wide: in-process test
/// clusters share it.
static ACTIVE: AtomicU32 = AtomicU32::new(0);

pub fn active() -> u32 {
    match ACTIVE.load(Ordering::Acquire) {
        0 => MIN_LEVEL,
        l => l,
    }
}

pub fn set_active(level: u32) {
    let prev = ACTIVE.swap(level, Ordering::AcqRel);
    if prev != 0 && prev != level {
        tracing::warn!(from = prev, to = level, "cluster feature level changed");
    }
    crate::metrics::FEATURE_LEVEL.with_label_values(&["active"]).set(level as i64);
}

pub fn segment_magic(level: u32) -> &'static [u8; 8] {
    LEVELS.iter().rev().filter(|l| l.level <= level).find_map(|l| l.segment_magic).unwrap_or(crate::segment::MAGIC)
}

pub fn segment_magics() -> impl Iterator<Item = (&'static [u8; 8], u32)> {
    LEVELS
        .iter()
        .filter(|l| l.level >= MIN_LEVEL && l.level <= MAX_LEVEL)
        .filter_map(|l| l.segment_magic.map(|m| (m, l.level)))
}

pub fn segment_level(magic: &[u8]) -> Option<u32> {
    segment_magics().find(|(m, _)| m.as_slice() == magic).map(|(_, l)| l)
}

/// The `vlpds_format_errors_total` labels.
const FORMATS: &[&str] = &["segment", "log_stream", "applied_marker", "cluster_version", "control_object"];

/// A decode failed on an unknown magic, codec, message type or value tag:
/// a node of a newer level wrote it, or it is corrupt.
pub fn format_error(format: &'static str) {
    crate::metrics::FORMAT_ERRORS.with_label_values(&[format]).inc();
}

pub fn init_metrics() {
    if cfg!(feature = "test-level") {
        tracing::warn!(test_level = TEST_LEVEL, "TEST BUILD: the test-only feature level is compiled in (cargo feature test-level); never run it in production");
    }
    crate::metrics::FEATURE_LEVEL.with_label_values(&["binary_min"]).set(MIN_LEVEL as i64);
    crate::metrics::FEATURE_LEVEL.with_label_values(&["binary_max"]).set(MAX_LEVEL as i64);
    for f in FORMATS {
        crate::metrics::FORMAT_ERRORS.with_label_values(&[f]);
    }
}

const EXIT_CODE: i32 = 7;
pub const EXIT_REASON: &str = "incompatible_level";

type RefuseHook = Arc<dyn Fn(&str, &str) + Send + Sync>;
static REFUSE_HOOK: parking_lot::RwLock<Option<RefuseHook>> = parking_lot::RwLock::new(None);

/// Tests: replaces the exit-7 fail-stop with `f(node_id, why)`.
#[doc(hidden)]
pub fn set_refuse_hook(f: Option<RefuseHook>) {
    *REFUSE_HOOK.write() = f;
}

/// A node can't run the cluster's level: fail-stop (or the test hook).
/// Returns the error the caller propagates when a hook is set.
pub fn refuse(node_id: &str, why: &str) -> anyhow::Error {
    tracing::error!(node = node_id, levels = ?Window::BUILD, "incompatible feature level: {why}; fail-stop (exit {EXIT_CODE})");
    let hook = REFUSE_HOOK.read().clone();
    match hook {
        Some(h) => h(node_id, why),
        None if cfg!(test) => {}
        None => crate::lifecycle::fail_stop(EXIT_CODE, EXIT_REASON),
    }
    anyhow::Error::new(Refused(why.to_string()))
}

/// What [`refuse`] returns: startup never retries it.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{EXIT_REASON}: {}", self.0)
    }
}

impl std::error::Error for Refused {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_table_is_consistent() {
        for (i, l) in LEVELS.iter().enumerate() {
            assert_eq!(l.level, i as u32 + 1, "levels are dense from 1");
        }
        const { assert!(MIN_LEVEL >= 1 && MIN_LEVEL <= MAX_LEVEL && RELEASED <= MAX_LEVEL) };
        assert_eq!(MAX_LEVEL as usize, LEVELS.len());
        assert_eq!(segment_magic(REAL_MAX), crate::segment::MAGIC);
        if cfg!(feature = "test-level") {
            assert_eq!(
                (MAX_LEVEL, segment_magic(MAX_LEVEL), segment_level(TEST_SEGMENT_MAGIC)),
                (TEST_LEVEL, TEST_SEGMENT_MAGIC, Some(TEST_LEVEL))
            );
        } else {
            assert_eq!(
                (MAX_LEVEL, segment_level(TEST_SEGMENT_MAGIC)),
                (REAL_MAX, None),
                "the test level is not in this build"
            );
        }
        // a level above every table entry writes the newest magic
        assert_eq!(segment_magic(MAX_LEVEL + 5), segment_magic(MAX_LEVEL));
        assert_eq!(segment_level(b"VLSEG06\n"), Some(1));
        assert_eq!(segment_level(b"VLSEG05\n"), None);
    }

    #[test]
    fn window_checks() {
        let w = Window { min: 1, max: 2 };
        let v = |active, target| ClusterVersion { active, target, history: vec![], extra: Default::default() };
        assert!(w.check(&v(1, None)).is_ok());
        assert!(w.check(&v(2, None)).is_ok());
        assert!(w.check(&v(1, Some(2))).is_ok());
        assert!(w.check(&v(3, None)).unwrap_err().contains("outside"));
        assert!(w.check(&v(1, Some(3))).unwrap_err().contains("raising"));
        assert!(Window { min: 2, max: 3 }.check(&v(1, None)).is_err(), "can no longer read level 1");
    }

    #[test]
    fn only_wire_levels_are_lowered() {
        let l = |level, persistent| Level { level, name: "x", description: "", persistent, segment_magic: None };
        let table = [l(1, true), l(2, false), l(3, false), l(4, true)];
        assert!(check_lower(&table, 3, 1).is_ok(), "2 and 3 only gate wire behavior");
        assert!(check_lower(&table, 3, 2).is_ok());
        assert!(check_lower(&table, 4, 3).unwrap_err().contains("persistent"));
        assert!(check_lower(&table, 4, 1).unwrap_err().contains("persistent"));
        assert!(check_lower(&table, 2, 2).unwrap_err().contains("not below"));
        assert!(check_lower(&table, 2, 0).is_err());
        assert!(check_lower(&table, 6, 4).unwrap_err().contains("unknown"));
        // this build's own table: nothing below level 1; the test level is persistent
        assert!(check_lower(LEVELS, MAX_LEVEL, MAX_LEVEL - 1).is_err());
    }

    /// A newer build's fields survive an older node's read-modify-write.
    #[test]
    fn unknown_fields_round_trip() {
        let j = serde_json::json!({"active": 1, "history": [{"level": 1, "at": "t", "by": "a", "op": "x"}], "pinned": true});
        let v: ClusterVersion = serde_json::from_value(j.clone()).unwrap();
        assert_eq!(serde_json::to_value(&v).unwrap(), j);
    }
}
