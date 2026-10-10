use super::*;
use crate::chaos::ChaosStore;
use std::sync::Arc;

const TTL: Duration = Duration::from_secs(10);

fn cfg(id: &str) -> LeaseConfig {
    LeaseConfig::new(id, format!("{id}:1"), TTL)
}

fn shared() -> Arc<object_store::memory::InMemory> {
    Arc::new(object_store::memory::InMemory::new())
}

/// A client of `mem` with its own faults.
fn client(mem: &Arc<object_store::memory::InMemory>, seed: u64) -> (Store, ChaosStore) {
    let c = ChaosStore::seeded(mem.clone(), seed);
    (Store { raw: Arc::new(c.clone()), prefix: "t".into(), latency: None }, c)
}

async fn holder(s: &Store, id: &str, inc: &str) -> Arc<Holder<()>> {
    Holder::acquire(s.clone(), cfg(id), inc.into(), ()).await.unwrap()
}

#[test]
fn config_is_checked() {
    assert!(cfg("a").validate().is_ok());
    let mut c = cfg("a");
    c.skew = TTL / 2;
    assert!(c.validate().is_err());
    let mut c = cfg("a");
    c.renew_every = TTL;
    assert!(c.validate().is_err());
    assert!(cfg("a/b").validate().is_err());
    assert!((cfg("a").max_drift() - 0.2).abs() < 1e-9);
}

#[tokio::test(start_paused = true)]
async fn acquire_renew_observe() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let h = holder(&s, "a", "a1").await;
    assert!(h.valid());
    let obs = Observer::<()>::new(s.clone(), TTL, TTL / 5);
    let m = obs.observe().await.unwrap();
    assert_eq!(m.get("a").unwrap().1, Liveness::Live);
    h.update(|l| {
        l.positions.insert("0000000001".into(), 42);
        l.renewals = 999; // ignored: the holder's own
    });
    h.renew().await.unwrap();
    let m = obs.observe().await.unwrap();
    let (l, v) = m.get("a").unwrap();
    assert_eq!((l.positions["0000000001"], l.renewals, *v), (42, 2, Liveness::Live));
    // a second acquire by the same incarnation is refused
    assert!(Holder::<()>::acquire(s.clone(), cfg("a"), "a1".into(), ()).await.is_err());
}

/// Renewals stay `key_gap` apart however often they're asked for.
#[tokio::test(start_paused = true)]
async fn renewals_keep_the_key_gap() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let h = holder(&s, "a", "a1").await;
    let mut at = vec![Instant::now()];
    for _ in 0..5 {
        h.renew().await.unwrap();
        at.push(Instant::now());
    }
    for w in at.windows(2) {
        assert!(w[1] - w[0] >= KEY_GAP, "{:?}", w[1] - w[0]);
    }
}

/// The holder stops acting before any observer that keeps observing
/// presumes it dead: the store stops answering it (a partition), the
/// observer's view keeps working.
#[tokio::test(start_paused = true)]
async fn validity_ends_before_any_observer_presumes_death() {
    let mem = shared();
    let (hs, hc) = client(&mem, 1);
    let (os, _) = client(&mem, 2);
    let h = holder(&hs, "a", "a1").await;
    let mut lost = h.spawn();
    let lost_at = tokio::spawn(async move {
        lost.wait_for(|l| l.is_some()).await.unwrap();
        Instant::now()
    });
    let obs = Observer::<()>::new(os, TTL, TTL / 5);
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(obs.observe().await.unwrap().get("a").unwrap().1, Liveness::Live);
    hc.knobs().pause();
    let cut = Instant::now();
    let dead_at = loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let m = obs.observe().await.unwrap();
        if m.get("a").unwrap().1 == Liveness::Dead {
            break Instant::now();
        }
        if m.get("a").unwrap().1 == Liveness::Suspect {
            assert!(Instant::now() - cut > TTL / 2 - TTL / 5, "suspect too early");
        }
    };
    assert!(!h.valid(), "observer presumed a valid holder dead");
    assert!(h.valid_until() < dead_at);
    // the watchdog fail-stops it 2 x skew after its validity (give or
    // take its tick)
    let lost_at = lost_at.await.unwrap();
    assert_eq!(h.lost(), Some(Lost::Lapsed));
    assert!(lost_at > h.valid_until() + TTL / 5 * 2);
    assert!(lost_at <= h.valid_until() + TTL / 5 * 2 + TTL / 10 + Duration::from_millis(10));
}

/// Wall clocks hours apart change nothing: only monotonic time judges.
#[tokio::test(start_paused = true)]
async fn wall_clock_offsets_dont_matter() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let mut fast = cfg("fast");
    fast.clock_offset_ms = 3_600_000;
    let mut slow = cfg("slow");
    slow.clock_offset_ms = -3_600_000;
    let f = Holder::<()>::acquire(s.clone(), fast, "f1".into(), ()).await.unwrap();
    let sl = Holder::<()>::acquire(s.clone(), slow, "s1".into(), ()).await.unwrap();
    f.spawn();
    sl.spawn();
    let obs = Observer::<()>::new(s.clone(), TTL, TTL / 5);
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let m = obs.observe().await.unwrap();
        assert_eq!(m.with(Liveness::Live).len(), 2);
    }
    let m = obs.observe().await.unwrap();
    let gap = m.get("fast").unwrap().0.expires_ms - m.get("slow").unwrap().0.expires_ms;
    assert!(gap > 7_000_000, "published wall times are informational: {gap}");
}

/// Clock *rates* within `max_drift` keep the order of events: a slow
/// holder clock (its validity lasts longer in real time) against a fast
/// observer clock (its verdict comes sooner) still has the holder stop
/// first. Past the bound it doesn't, which is why the bound is the one
/// clock assumption.
#[tokio::test(start_paused = true)]
async fn drift_within_the_bound_keeps_the_order() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let c = cfg("a");
    let h = holder(&s, "a", "a1").await;
    let sent = Instant::now() - Duration::from_millis(1);
    let obs = Observer::<()>::new(s.clone(), c.ttl, c.skew);
    obs.observe().await.unwrap();
    let seen = Instant::now();
    let real_end_of_validity = |rho: f64| (h.valid_until() - sent).div_f64(1.0 - rho);
    let real_verdict = |rho: f64| {
        // the observer's clock runs 1 + rho times as fast as real time
        let mut t = Duration::ZERO;
        loop {
            t += Duration::from_millis(1);
            let local = seen + t.mul_f64(1.0 + rho);
            if obs.classify_at(local).get("a").unwrap().1 == Liveness::Dead {
                return t;
            }
        }
    };
    for rho in [0.0, 0.05, 0.1, 0.19] {
        assert!(rho <= c.max_drift());
        assert!(real_end_of_validity(rho) < real_verdict(rho), "rho {rho}");
    }
    assert!(real_end_of_validity(0.3) > real_verdict(0.3), "past the bound the order breaks");
}

/// A new incarnation of our id takes the lease: our next renewal finds out
/// and stops.
#[tokio::test(start_paused = true)]
async fn a_restart_under_our_id_takes_the_lease() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let old = holder(&s, "a", "a1").await;
    let new = holder(&s, "a", "a2").await;
    assert!(matches!(old.renew().await, Err(RenewError::Lost(Lost::Taken))));
    assert!(!old.valid());
    new.renew().await.unwrap();
    let obs = Observer::<()>::new(s.clone(), TTL, TTL / 5);
    let m = obs.observe().await.unwrap();
    assert_eq!(m.incarnation("a", "a1"), Some(Liveness::Dead));
    assert_eq!(m.incarnation("a", "a2"), Some(Liveness::Live));
    assert_eq!(m.incarnation("b", "b1"), None);
}

/// A renewal that landed with its answer lost (the client's retry got a
/// conflict) is ours: adopted, validity granted, and the next one works.
#[tokio::test(start_paused = true)]
async fn a_renewal_whose_answer_was_lost_is_adopted() {
    let mem = shared();
    let (s, c) = client(&mem, 1);
    let h = holder(&s, "a", "a1").await;
    let before = h.valid_until();
    c.knobs().landed_next(1);
    h.renew().await.unwrap();
    assert!(h.valid_until() > before);
    assert_eq!(h.lease().renewals, 2);
    h.renew().await.unwrap();
    assert_eq!(h.lease().renewals, 3);
    // an acquire whose answer was lost is adopted too
    c.knobs().landed_next(1);
    let b = Holder::<()>::acquire(s.clone(), cfg("b"), "b1".into(), ()).await.unwrap();
    b.renew().await.unwrap();
}

/// A lapsed lease is never renewed: peers may have fenced us meanwhile.
#[tokio::test(start_paused = true)]
async fn a_lapsed_lease_is_never_renewed() {
    let mem = shared();
    let (s, c) = client(&mem, 1);
    let h = holder(&s, "a", "a1").await;
    c.knobs().fail_next(100);
    for _ in 0..12 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = h.renew().await;
    }
    c.knobs().fail_next(0);
    assert!(matches!(h.renew().await, Err(RenewError::Lost(Lost::Lapsed))));
    let stored = cas::read::<NodeLease<()>>(&s, &rel("a")).await.unwrap().unwrap();
    assert_eq!(stored.value.renewals, 1, "nothing written after the lapse");
}

/// A peer that fenced a dead incarnation marks its lease ended: every
/// observer then judges it dead at once, and the holder, if it was only
/// paused, stops at its next renewal. A lease that renewed since the
/// verdict isn't ended.
#[tokio::test(start_paused = true)]
async fn end_marks_a_fenced_incarnation() {
    let mem = shared();
    let (hs, hc) = client(&mem, 1);
    let (os, _) = client(&mem, 2);
    let h = holder(&hs, "a", "a1").await;
    let obs = Observer::<()>::new(os.clone(), TTL, TTL / 5);
    let m = obs.observe().await.unwrap();
    let judged = m.get("a").unwrap().0.clone();
    h.renew().await.unwrap();
    assert!(!obs.end(&judged).await.unwrap(), "stale verdict");
    // a change counts from when the observer first sees it
    obs.observe().await.unwrap();
    hc.knobs().pause();
    tokio::time::sleep(TTL + TTL / 2).await;
    let m = obs.observe().await.unwrap();
    let (dead, v) = m.get("a").unwrap().clone();
    assert_eq!(v, Liveness::Dead);
    assert!(obs.end(&dead).await.unwrap());
    let fresh = Observer::<()>::new(os, TTL, TTL / 5);
    assert_eq!(fresh.observe().await.unwrap().get("a").unwrap().1, Liveness::Dead);
    hc.knobs().resume();
    assert!(matches!(h.renew().await, Err(RenewError::Lost(Lost::Ended | Lost::Lapsed))));
    // the id's next incarnation writes over the ended lease
    let n = holder(&hs, "a", "a2").await;
    n.renew().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn release_ends_the_incarnation_at_once() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let h = holder(&s, "a", "a1").await;
    let obs = Observer::<()>::new(s.clone(), TTL, TTL / 5);
    assert_eq!(obs.observe().await.unwrap().get("a").unwrap().1, Liveness::Live);
    h.release().await.unwrap();
    assert_eq!(h.lost(), Some(Lost::Released));
    assert!(!h.valid());
    assert_eq!(obs.observe().await.unwrap().get("a").unwrap().1, Liveness::Dead);
}

/// Many holders under 5% errors and 2% lost answers with up to 300 ms of
/// latency: nobody loses a lease it kept renewing, and one observer sees
/// them all live throughout.
#[tokio::test(start_paused = true)]
async fn leases_survive_a_flaky_store() {
    let mem = shared();
    let mut hs = Vec::new();
    for i in 0..6u64 {
        let (s, c) = client(&mem, 10 + i);
        let h = holder(&s, &format!("n{i}"), &format!("n{i}-1")).await;
        c.knobs().set(Duration::from_millis(300), 0.05, 0.02);
        h.spawn();
        hs.push((h, c));
    }
    let (os, oc) = client(&mem, 99);
    oc.knobs().set(Duration::from_millis(300), 0.05, 0.0);
    let obs = Observer::<()>::new(os, TTL, TTL / 5);
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(m) = obs.observe().await {
            assert_eq!(m.with(Liveness::Dead).len(), 0);
        }
    }
    for (h, c) in &hs {
        assert!(h.valid() && h.lost().is_none());
        assert!(c.knobs().injected.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }
}
