//! JSON objects that move only by conditional PUT.
//!
//! A conditional PUT on S3, R2 and GCS is linearizable: `If-None-Match: *`
//! creates once, `If-Match: <etag>` replaces only the version read. Three
//! answers mean someone else's write decides it: `Precondition` (the etag
//! moved), `AlreadyExists` (a create lost) and, on S3, `NotFound` for an
//! If-Match on a key deleted since the read ([`moved`]).
//!
//! A write can land with its answer lost: object_store retries a 5xx or a
//! timeout, and the retry of a conditional PUT that already landed is
//! refused as a conflict. [`update`] reads back after every conflict and
//! takes a stored value equal to the one it sent as its own write.

use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion};
use serde::de::DeserializeOwned;
use serde::Serialize;
use vlsync_store::store::Store;

/// A value and the ETag of the version it was read or written as.
#[derive(Clone, Debug, PartialEq)]
pub struct Versioned<T> {
    pub value: T,
    pub etag: Option<String>,
}

/// What a write expects to find.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Nothing: `If-None-Match: *`.
    Absent,
    /// The version read: `If-Match`.
    Version(Option<String>),
}

impl Expect {
    /// From a read: absent, or the version it returned.
    pub fn from_read<T>(read: Option<&Versioned<T>>) -> Expect {
        match read {
            None => Expect::Absent,
            Some(v) => Expect::Version(v.etag.clone()),
        }
    }

    pub fn mode(&self) -> PutMode {
        match self {
            Expect::Absent => PutMode::Create,
            Expect::Version(e_tag) => PutMode::Update(UpdateVersion { e_tag: e_tag.clone(), version: None }),
        }
    }
}

/// `{prefix}/{rel}`.
pub fn path(store: &Store, rel: &str) -> Path {
    if store.prefix.is_empty() {
        Path::from(rel)
    } else {
        Path::from(format!("{}/{rel}", store.prefix))
    }
}

/// The etag moved or a create lost.
pub fn is_conflict(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
}

/// The key isn't there (on a write: an If-Match on S3 after a delete).
pub fn is_gone(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::NotFound { .. })
}

/// The version a conditional write expected is no longer the stored one.
pub fn moved(e: &object_store::Error) -> bool {
    is_conflict(e) || is_gone(e)
}

/// An error that may pass on retry: a 5xx past object_store's own retries,
/// a transport error, a timeout. Never a refusal or an answer.
pub fn transient(e: &object_store::Error) -> bool {
    matches!(e, object_store::Error::Generic { .. })
}

pub async fn read<T: DeserializeOwned>(store: &Store, rel: &str) -> anyhow::Result<Option<Versioned<T>>> {
    read_at(store.raw.as_ref(), &path(store, rel)).await
}

pub async fn read_at<T: DeserializeOwned>(raw: &dyn ObjectStore, path: &Path) -> anyhow::Result<Option<Versioned<T>>> {
    match raw.get(path).await {
        Ok(r) => {
            let etag = r.meta.e_tag.clone();
            let value = serde_json::from_slice(&r.bytes().await?)?;
            Ok(Some(Versioned { value, etag }))
        }
        Err(e) if is_gone(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// One conditional PUT. Returns the new version's ETag.
pub async fn write<T: Serialize>(
    store: &Store,
    rel: &str,
    value: &T,
    expect: Expect,
) -> object_store::Result<Option<String>> {
    write_at(store.raw.as_ref(), &path(store, rel), value, expect).await
}

pub async fn write_at<T: Serialize>(
    raw: &dyn ObjectStore,
    path: &Path,
    value: &T,
    expect: Expect,
) -> object_store::Result<Option<String>> {
    let body = serde_json::to_vec(value)
        .map_err(|e| object_store::Error::Generic { store: "vlsync-lease", source: Box::new(e) })?;
    let opts = PutOptions { mode: expect.mode(), ..Default::default() };
    raw.put_opts(path, PutPayload::from(body), opts).await.map(|r| r.e_tag)
}

/// What [`update`] did.
#[derive(Clone, Debug, PartialEq)]
pub enum Updated<T> {
    /// Our write is the stored version (possibly adopted after a lost answer).
    Written(Versioned<T>),
    /// `f` declined: the stored version, as read.
    Declined(Option<Versioned<T>>),
}

impl<T> Updated<T> {
    pub fn written(self) -> Option<Versioned<T>> {
        match self {
            Updated::Written(v) => Some(v),
            Updated::Declined(_) => None,
        }
    }
}

/// Read-modify-write by CAS. `f` gets the stored value (None: absent) and
/// returns the next one, or None to leave it. A conflict re-reads and calls
/// `f` again, up to `attempts` writes; a transient error is returned. A
/// conflict whose re-read finds exactly what we sent is our own write
/// whose answer was lost, so `T` must carry what makes each write unique
/// (a version or a writer's counter): an equal value is an equal outcome.
///
/// `start` is a cached read to try first (it may be stale: a conflict costs
/// one more read).
pub async fn update<T, F>(
    store: &Store,
    rel: &str,
    start: Option<Option<Versioned<T>>>,
    attempts: u32,
    mut f: F,
) -> anyhow::Result<Updated<T>>
where
    T: Serialize + DeserializeOwned + PartialEq + Clone,
    F: FnMut(Option<&T>) -> Option<T>,
{
    let mut cur = match start {
        Some(c) => c,
        None => read(store, rel).await?,
    };
    for _ in 0..attempts.max(1) {
        let Some(next) = f(cur.as_ref().map(|v| &v.value)) else {
            return Ok(Updated::Declined(cur));
        };
        match write(store, rel, &next, Expect::from_read(cur.as_ref())).await {
            Ok(etag) => return Ok(Updated::Written(Versioned { value: next, etag })),
            Err(e) if moved(&e) => {
                cur = read(store, rel).await?;
                if let Some(v) = cur.as_ref().filter(|v| v.value == next) {
                    tracing::debug!(rel, "a write whose answer was lost landed: adopted it");
                    return Ok(Updated::Written(v.clone()));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("{rel}: still contended after {attempts} CAS attempts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::Arc;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Counter {
        n: u64,
    }

    #[tokio::test]
    async fn create_once_and_replace_only_the_version_read() {
        let s = Store::memory(None);
        let a = write(&s, "x", &Counter { n: 1 }, Expect::Absent).await.unwrap();
        let e = write(&s, "x", &Counter { n: 2 }, Expect::Absent).await.unwrap_err();
        assert!(is_conflict(&e) && moved(&e));
        let b = write(&s, "x", &Counter { n: 2 }, Expect::Version(a.clone())).await.unwrap();
        let e = write(&s, "x", &Counter { n: 3 }, Expect::Version(a)).await.unwrap_err();
        assert!(moved(&e));
        let v = read::<Counter>(&s, "x").await.unwrap().unwrap();
        assert_eq!(v, Versioned { value: Counter { n: 2 }, etag: b });
        assert!(read::<Counter>(&s, "y").await.unwrap().is_none());
    }

    /// N tasks each add one by CAS: every increment lands exactly once.
    #[tokio::test]
    async fn racing_updates_lose_nothing() {
        let s = Store::memory(None);
        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let s = s.clone();
                tokio::spawn(async move {
                    for _ in 0..10 {
                        let r = update::<Counter, _>(&s, "c", None, 1000, |c| {
                            Some(Counter { n: c.map_or(0, |c| c.n) + 1 })
                        })
                        .await
                        .unwrap();
                        assert!(matches!(r, Updated::Written(_)));
                    }
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(read::<Counter>(&s, "c").await.unwrap().unwrap().value.n, 160);
    }

    #[tokio::test]
    async fn a_stale_start_costs_one_read() {
        let s = Store::memory(None);
        let first = update::<Counter, _>(&s, "c", Some(None), 3, |_| Some(Counter { n: 1 })).await.unwrap();
        let stale = Some(Some(Versioned { value: Counter { n: 5 }, etag: Some("nope".into()) }));
        let r = update::<Counter, _>(&s, "c", stale, 3, |c| Some(Counter { n: c.unwrap().n + 1 })).await.unwrap();
        assert!(matches!(first, Updated::Written(_)));
        assert_eq!(r.written().unwrap().value.n, 2);
        let d = update::<Counter, _>(&s, "c", None, 3, |_| None).await.unwrap();
        assert!(matches!(d, Updated::Declined(Some(v)) if v.value.n == 2));
    }

    /// Why `T` must name its writer or version: a stale read whose next
    /// value someone else already wrote is taken as our own landed write.
    #[tokio::test]
    async fn equal_values_are_taken_as_ours() {
        let s = Store::memory(None);
        update::<Counter, _>(&s, "c", Some(None), 3, |_| Some(Counter { n: 1 })).await.unwrap();
        let stale = Some(Some(Versioned { value: Counter { n: 0 }, etag: Some("nope".into()) }));
        let r = update::<Counter, _>(&s, "c", stale, 3, |c| Some(Counter { n: c.unwrap().n + 1 })).await.unwrap();
        assert_eq!(r.written().unwrap().value.n, 1);
    }

    #[tokio::test]
    async fn a_landed_write_with_a_lost_answer_is_adopted() {
        let chaos = crate::chaos::ChaosStore::new(Arc::new(object_store::memory::InMemory::new()));
        let s = Store { raw: Arc::new(chaos.clone()), prefix: "t".into(), latency: None };
        update::<Counter, _>(&s, "c", None, 3, |_| Some(Counter { n: 1 })).await.unwrap();
        chaos.knobs().landed_next(1);
        let r = update::<Counter, _>(&s, "c", None, 1, |c| Some(Counter { n: c.unwrap().n + 1 })).await.unwrap();
        assert_eq!(r.written().unwrap().value.n, 2);
        assert_eq!(read::<Counter>(&s, "c").await.unwrap().unwrap().value.n, 2);
    }
}
