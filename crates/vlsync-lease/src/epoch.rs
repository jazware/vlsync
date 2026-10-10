//! Records whose epoch only grows: the fencing tokens of a single writer.
//!
//! vlRelay's quorum log runs on two of them. `qlog/leader` is claimed by a
//! CAS to epoch + 1 from the version read ([`claim`]): one winner per
//! epoch. The winner then raises `qlog/manifest` to its epoch before its
//! first flush ([`raise`]); an older leader's next manifest CAS fails (its
//! ETag moved), and one that reads the manifest sees a newer epoch and
//! steps down ([`holds`]).
//!
//! The same three calls fence any downstream object: whoever claims an
//! epoch raises every record it will write under it before writing, and a
//! writer checks [`holds`] (or simply loses its CAS) to learn it was
//! deposed. An epoch is never lowered and never reused, so a token compares
//! by `>` alone.

use crate::cas::{self, Expect, Versioned};
use serde::de::DeserializeOwned;
use serde::Serialize;
use vlsync_store::store::Store;

/// A record that carries the epoch of the writer that wrote it.
pub trait Epoched {
    fn epoch(&self) -> u64;
}

/// Claims `next` (whose epoch is past `read`'s) by one CAS from the version
/// read. False: someone else's write landed first; read again.
pub async fn claim<T: Serialize + Epoched>(
    store: &Store,
    rel: &str,
    read: Option<&Versioned<T>>,
    next: &T,
) -> anyhow::Result<Option<Versioned<()>>> {
    let floor = read.map_or(0, |r| r.value.epoch());
    anyhow::ensure!(next.epoch() > floor, "{rel}: a claim must raise the epoch past {floor} (got {})", next.epoch());
    match cas::write(store, rel, next, Expect::from_read(read)).await {
        Ok(etag) => Ok(Some(Versioned { value: (), etag })),
        Err(e) if cas::moved(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Makes the record at `rel` epoch `epoch`'s: `f` builds it from the stored
/// one (None: absent) and must return a record of exactly `epoch`. Retries
/// conflicts until it lands or the stored record is newer than `epoch`
/// (None: we were fenced ourselves). A record already at `epoch` is
/// rewritten, so the caller holds a fresh ETag.
pub async fn raise<T, F>(store: &Store, rel: &str, epoch: u64, f: F) -> anyhow::Result<Option<Versioned<T>>>
where
    T: Serialize + DeserializeOwned + Epoched,
    F: Fn(Option<T>) -> T,
{
    loop {
        let read = cas::read::<T>(store, rel).await?;
        let expect = Expect::from_read(read.as_ref());
        let cur = match read {
            Some(v) if v.value.epoch() > epoch => return Ok(None),
            r => r.map(|v| v.value),
        };
        let next = f(cur);
        anyhow::ensure!(next.epoch() == epoch, "{rel}: raise to {epoch} built a record of epoch {}", next.epoch());
        match cas::write(store, rel, &next, expect).await {
            Ok(etag) => return Ok(Some(Versioned { value: next, etag })),
            Err(e) if cas::moved(&e) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// Whether the record still names `epoch` as its newest.
#[derive(Clone, Debug, PartialEq)]
pub enum Holds<T> {
    /// It's at `epoch` (or older: not raised yet).
    Yes(Versioned<T>),
    /// A newer epoch wrote it: stop writing under ours.
    Superseded(u64),
    Missing,
}

pub async fn holds<T: DeserializeOwned + Epoched>(store: &Store, rel: &str, epoch: u64) -> anyhow::Result<Holds<T>> {
    Ok(match cas::read::<T>(store, rel).await? {
        None => Holds::Missing,
        Some(v) if v.value.epoch() > epoch => Holds::Superseded(v.value.epoch()),
        Some(v) => Holds::Yes(v),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Leader {
        epoch: u64,
        leader: String,
    }

    impl Epoched for Leader {
        fn epoch(&self) -> u64 {
            self.epoch
        }
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Manifest {
        epoch: u64,
        flushed: u64,
    }

    impl Epoched for Manifest {
        fn epoch(&self) -> u64 {
            self.epoch
        }
    }

    /// Candidates that read the same version race one CAS: one wins each
    /// epoch, and the epochs the winners hold strictly increase.
    #[tokio::test]
    async fn one_winner_per_epoch() {
        let s = Store::memory(None);
        let mut won = Vec::new();
        for _round in 0..20 {
            let read = cas::read::<Leader>(&s, "leader").await.unwrap();
            let epoch = read.as_ref().map_or(0, |r| r.value.epoch) + 1;
            let tasks: Vec<_> = (0..8)
                .map(|i| {
                    let (s, read) = (s.clone(), read.clone());
                    tokio::spawn(async move {
                        let rec = Leader { epoch, leader: format!("n{i}") };
                        claim(&s, "leader", read.as_ref(), &rec).await.unwrap().map(|_| rec)
                    })
                })
                .collect();
            let mut winners = Vec::new();
            for t in tasks {
                winners.extend(t.await.unwrap());
            }
            assert_eq!(winners.len(), 1, "epoch {epoch}: {winners:?}");
            won.push(winners[0].clone());
        }
        assert!(won.windows(2).all(|w| w[0].epoch < w[1].epoch));
        let stale = Leader { epoch: 3, leader: "x".into() };
        assert!(claim(&s, "leader", None, &stale).await.unwrap().is_none());
        let read = cas::read::<Leader>(&s, "leader").await.unwrap().unwrap();
        assert!(claim(&s, "leader", Some(&read), &stale).await.is_err(), "a claim must raise the epoch");
    }

    /// vlRelay's manifest fence: once a newer leader raised the manifest,
    /// an older leader's raise reports it was fenced and its CAS from an
    /// earlier read fails.
    #[tokio::test]
    async fn raise_fences_older_writers() {
        let s = Store::memory(None);
        let mk = |e: u64| move |m: Option<Manifest>| Manifest { epoch: e, flushed: m.map_or(0, |m| m.flushed) };
        let old = raise(&s, "manifest", 1, mk(1)).await.unwrap().unwrap();
        let next = Manifest { epoch: 1, flushed: 10 };
        let e1 = cas::write(&s, "manifest", &next, Expect::Version(old.etag.clone())).await.unwrap();
        assert!(raise(&s, "manifest", 2, mk(2)).await.unwrap().is_some());
        let e = cas::write(&s, "manifest", &Manifest { epoch: 1, flushed: 20 }, Expect::Version(e1)).await;
        assert!(cas::moved(&e.unwrap_err()));
        assert!(raise(&s, "manifest", 1, mk(1)).await.unwrap().is_none());
        assert_eq!(holds::<Manifest>(&s, "manifest", 1).await.unwrap(), Holds::Superseded(2));
        assert!(matches!(holds::<Manifest>(&s, "manifest", 2).await.unwrap(), Holds::Yes(v) if v.value.flushed == 10));
        assert_eq!(holds::<Manifest>(&s, "nothing", 2).await.unwrap(), Holds::Missing);
        // re-raising the same epoch is idempotent and returns a fresh ETag
        let again = raise(&s, "manifest", 2, mk(2)).await.unwrap().unwrap();
        assert_eq!(again.value, Manifest { epoch: 2, flushed: 10 });
        assert!(raise(&s, "manifest", 3, |_| Manifest { epoch: 4, flushed: 0 }).await.is_err());
    }

    /// Writers racing raises to random epochs: the stored epoch never goes
    /// down, and every raise that returned Some was the newest at its CAS.
    #[tokio::test]
    async fn concurrent_raises_never_lower_the_epoch() {
        let s = Store::memory(None);
        let tasks: Vec<_> = (0..12u64)
            .map(|i| {
                let s = s.clone();
                tokio::spawn(async move {
                    let mut seen = Vec::new();
                    for k in 0..10u64 {
                        let e = (i * 7 + k * 13) % 40 + 1;
                        if raise(&s, "m", e, |_| Manifest { epoch: e, flushed: 0 }).await.unwrap().is_some() {
                            seen.push(e);
                        }
                        let now = cas::read::<Manifest>(&s, "m").await.unwrap().unwrap().value.epoch;
                        seen.push(now);
                    }
                    seen
                })
            })
            .collect();
        let mut max = 0;
        for t in tasks {
            for e in t.await.unwrap() {
                max = max.max(e);
            }
        }
        assert_eq!(cas::read::<Manifest>(&s, "m").await.unwrap().unwrap().value.epoch, max);
    }
}
