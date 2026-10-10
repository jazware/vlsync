use super::*;
use crate::chaos::ChaosStore;
use crate::lease::{Holder, LeaseConfig, Observer};
use std::time::Duration;
use tokio::time::Instant;

const TTL: Duration = Duration::from_secs(2);

fn shared() -> Arc<object_store::memory::InMemory> {
    Arc::new(object_store::memory::InMemory::new())
}

fn client(mem: &Arc<object_store::memory::InMemory>, seed: u64) -> (Store, ChaosStore) {
    let c = ChaosStore::seeded(mem.clone(), seed);
    (Store { raw: Arc::new(c.clone()), prefix: "t".into(), latency: None }, c)
}

fn cfg(id: &str) -> LeaseConfig {
    let mut c = LeaseConfig::new(id, format!("{id}:1"), TTL);
    c.key_gap = Duration::from_millis(100);
    c
}

async fn node(s: &Store, id: &str, inc: &str) -> (Arc<Holder<()>>, Member) {
    let h = Holder::acquire(s.clone(), cfg(id), inc.into(), ()).await.unwrap();
    let m = Member::of(&h.lease());
    (h, m)
}

async fn members(s: &Store) -> Membership<()> {
    Observer::<()>::new(s.clone(), TTL, TTL / 5).observe().await.unwrap()
}

fn no_fence(_: Span) -> std::future::Ready<anyhow::Result<u64>> {
    panic!("nothing to fence")
}

const S: ShardId = ShardId(7);

#[tokio::test(start_paused = true)]
async fn acquire_release_handoff() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let t = Table::new(s.clone());
    let (_ha, a) = node(&s, "a", "a1").await;
    let (_hb, b) = node(&s, "b", "b1").await;
    let m = members(&s).await;
    assert_eq!(t.acquire(S, &a, &m, no_fence).await.unwrap(), Acquired::Missing);
    t.create(S, 100, None).await.unwrap().unwrap();
    assert!(t.create(S, 5, None).await.unwrap().is_none(), "create only once");
    let Acquired::Taken(x) = t.acquire(S, &a, &m, no_fence).await.unwrap() else { panic!() };
    assert_eq!((x.epoch, x.open_span().unwrap().from), (1, 101));
    assert!(matches!(t.acquire(S, &a, &m, no_fence).await.unwrap(), Acquired::Held(_)));
    assert_eq!(t.acquire(S, &b, &m, no_fence).await.unwrap(), Acquired::Busy(a.clone()));
    assert!(t.release(S, &b, 150, None).await.unwrap().is_none(), "not b's to release");
    // a stops at 150 and hands to b: b's span starts at 151 under epoch 2
    let y = t.release(S, &a, 150, Some(&b)).await.unwrap().unwrap();
    y.check().unwrap();
    assert_eq!((y.epoch, y.floor, y.owner.as_ref().unwrap().node_id.as_str()), (2, 150, "b"));
    assert!(y.accepts(1, "a1", 150) && !y.accepts(1, "a1", 151) && y.accepts(2, "b1", 151));
    assert!(!y.accepts(2, "a1", 151) && !y.accepts(1, "a1", 100), "below the history");
    // b releases having written nothing: its span is dropped, the epoch still moves
    let z = t.release(S, &b, 150, None).await.unwrap().unwrap();
    z.check().unwrap();
    assert_eq!((z.epoch, z.history.len(), z.owner.clone()), (3, 1, None));
    let Acquired::Taken(w) = t.acquire(S, &b, &m, no_fence).await.unwrap() else { panic!() };
    assert_eq!((w.epoch, w.open_span().unwrap().from), (4, 151));
    let stored = cas::read::<Assignment>(&s, &rel(S)).await.unwrap().unwrap().value;
    assert_eq!(stored, w);
    stored.check().unwrap();
}

/// Nodes racing to acquire one free range: one wins each epoch.
#[tokio::test(start_paused = true)]
async fn racing_acquires_have_one_winner() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    Table::new(s.clone()).create(S, 0, None).await.unwrap();
    let mut ms = Vec::new();
    let mut hs = Vec::new();
    for i in 0..8 {
        let (h, m) = node(&s, &format!("n{i}"), &format!("n{i}-1")).await;
        hs.push(h);
        ms.push(m);
    }
    let view = members(&s).await;
    let tasks: Vec<_> = ms
        .iter()
        .map(|m| {
            let (s, m, view) = (s.clone(), m.clone(), view.clone());
            tokio::spawn(async move { Table::new(s).acquire(S, &m, &view, no_fence).await.unwrap() })
        })
        .collect();
    let mut taken = 0;
    for t in tasks {
        match t.await.unwrap() {
            Acquired::Taken(a) => {
                assert_eq!(a.epoch, 1);
                taken += 1;
            }
            Acquired::Busy(_) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(taken, 1);
}

/// A dead owner is fenced before its range is taken: its span closes at
/// the last position it made durable, and the taker's starts right after.
/// A restart under the same node id counts as dead (another incarnation),
/// and a node whose lease the listing predates isn't.
#[tokio::test(start_paused = true)]
async fn dead_and_superseded_owners_are_fenced_first() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let (a_store, a_chaos) = client(&mem, 2);
    let t = Table::new(s.clone());
    t.create(S, 0, None).await.unwrap();
    let (_ha, a) = node(&a_store, "a", "a1").await;
    let (hb, b) = node(&s, "b", "b1").await;
    hb.spawn();
    let obs = Observer::<()>::new(s.clone(), TTL, TTL / 5);
    let m = obs.observe().await.unwrap();
    assert!(matches!(t.acquire(S, &a, &m, no_fence).await.unwrap(), Acquired::Taken(_)));
    // a stops renewing (paused); b presumes it dead only after TTL + skew
    a_chaos.knobs().pause();
    tokio::time::sleep(TTL).await;
    let m = obs.observe().await.unwrap();
    assert!(matches!(t.acquire(S, &b, &m, no_fence).await.unwrap(), Acquired::Busy(_)));
    tokio::time::sleep(TTL).await;
    let m = obs.observe().await.unwrap();
    let mut fenced = Vec::new();
    let got = t
        .acquire(S, &b, &m, |span| {
            fenced.push(span.clone());
            async { Ok(41) }
        })
        .await
        .unwrap();
    let Acquired::Taken(x) = got else { panic!("{got:?}") };
    assert_eq!(fenced.len(), 1);
    assert_eq!((fenced[0].incarnation.as_str(), fenced[0].epoch), ("a1", 1));
    x.check().unwrap();
    assert_eq!((x.epoch, x.history[0].until, x.open_span().unwrap().from), (2, Some(41), 42));
    assert!(x.accepts(1, "a1", 41) && !x.accepts(1, "a1", 42));
    assert!(obs.end(&m.get("a").unwrap().0).await.unwrap());

    // b restarts under its id: its old incarnation's range is taken over
    let (hb2, b2) = node(&s, "b", "b2").await;
    let m = obs.observe().await.unwrap();
    let got = t.acquire(S, &b2, &m, |_| async { Ok(41) }).await.unwrap();
    let Acquired::Taken(y) = got else { panic!("{got:?}") };
    y.check().unwrap();
    assert_eq!((y.epoch, y.history.len()), (3, 2), "b1's empty span was dropped");
    assert!(matches!(hb.renew().await, Err(crate::lease::RenewError::Lost(_))));

    // c's lease landed after the listing: not presumed dead
    let stale = obs.observe().await.unwrap();
    let (_hc, c) = node(&s, "c", "c1").await;
    let y2 = t.release(S, &b2, 41, Some(&c)).await.unwrap().unwrap();
    assert_eq!(y2.owner.as_ref().unwrap().incarnation, "c1");
    let got = t.acquire(S, &b2, &stale, no_fence).await.unwrap();
    assert_eq!(got, Acquired::Busy(c));
    drop(hb2);
}

/// Freeze for a split, then seed the children at the freeze point.
#[tokio::test(start_paused = true)]
async fn freeze_and_seed_children() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let t = Table::new(s.clone());
    let (_ha, a) = node(&s, "a", "a1").await;
    let m = members(&s).await;
    t.create(S, 0, Some(&a)).await.unwrap().unwrap().check().unwrap();
    let f = t.freeze(S, &a, 500, 9).await.unwrap().unwrap();
    f.check().unwrap();
    assert_eq!((f.frozen, f.owner.clone(), f.floor, f.epoch), (Some(9), None, 500, 2));
    assert!(t.freeze(S, &a, 500, 9).await.unwrap().is_none());
    assert_eq!(t.acquire(S, &a, &m, no_fence).await.unwrap(), Acquired::Frozen);
    assert!(t.release(S, &a, 600, None).await.unwrap().is_none());
    for child in [ShardId(20), ShardId(21)] {
        let c = t.create(child, f.floor, Some(&a)).await.unwrap().unwrap();
        c.check().unwrap();
        assert_eq!((c.epoch, c.open_span().unwrap().from), (1, 501));
    }
    let topo = t.refresh().await.unwrap();
    assert!(topo.range(S).unwrap().frozen);
    assert_eq!(topo.range(ShardId(21)).unwrap().owner.as_ref().unwrap().node_id, "a");
}

/// Replicas: listed without an epoch change; their watermarks come from
/// their leases. A replica promoted by acquire leaves the list.
#[tokio::test(start_paused = true)]
async fn replicas_and_routing() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let t = Table::new(s.clone());
    let rx = t.subscribe();
    let (_ha, a) = node(&s, "a", "a1").await;
    let (hb, b) = node(&s, "b", "b1").await;
    let (hc, c) = node(&s, "c", "c1").await;
    t.create(S, 0, Some(&a)).await.unwrap();
    let r = t
        .set_replicas(S, |r| {
            r.push(b.clone());
            r.push(c.clone());
            r.push(a.clone());
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!((r.epoch, r.replicas.len()), (1, 2), "the owner isn't its own replica");
    assert!(t.set_replicas(S, |_| {}).await.unwrap().is_none());
    assert!(rx.has_changed().unwrap());
    hb.update(|l| {
        l.positions.insert(S.key(), 90);
    });
    hc.update(|l| {
        l.positions.insert(S.key(), 120);
    });
    hb.renew().await.unwrap();
    hc.renew().await.unwrap();
    let m = members(&s).await;
    let topo = t.topology();
    let names = |v: Vec<Member>| v.into_iter().map(|m| m.node_id).collect::<Vec<_>>();
    assert_eq!(names(topo.readable(S, 0, &m)), ["a", "b", "c"]);
    assert_eq!(names(topo.readable(S, 100, &m)), ["c"]);
    // publish for routers; a stale publisher can't roll it back
    let old = (*topo).clone();
    topo.publish(&s).await.unwrap();
    t.release(S, &a, 0, Some(&c)).await.unwrap().unwrap().check().unwrap();
    t.topology().publish(&s).await.unwrap();
    let stored = old.publish(&s).await.unwrap().value;
    assert_eq!(stored.range(S).unwrap().owner.as_ref().unwrap().node_id, "c");
    assert_eq!(names(stored.range(S).unwrap().replicas.clone()), ["b"]);
}

#[tokio::test(start_paused = true)]
async fn trim_keeps_the_open_span() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let t = Table::new(s.clone());
    let (_ha, a) = node(&s, "a", "a1").await;
    let (_hb, b) = node(&s, "b", "b1").await;
    t.create(S, 0, Some(&a)).await.unwrap();
    for k in 1..=6u64 {
        let (from, to) = if k % 2 == 1 { (&a, &b) } else { (&b, &a) };
        t.release(S, from, k * 10, Some(to)).await.unwrap().unwrap();
    }
    let x = t.trim(S, 35).await.unwrap().unwrap();
    x.check().unwrap();
    assert_eq!(x.history.first().unwrap().from, 31);
    assert!(x.open_span().is_some());
    let y = t.trim(S, 10_000).await.unwrap().unwrap();
    assert_eq!(y.history.len(), 1);
    assert!(t.trim(S, 10_000).await.unwrap().is_none());
}

/// An old record with fields a newer version added keeps them through our
/// writes.
#[tokio::test]
async fn unknown_fields_survive_a_cas() {
    let mem = shared();
    let (s, _) = client(&mem, 1);
    let mut raw = serde_json::to_value(Assignment { floor: 3, version: 1, ..Default::default() }).unwrap();
    raw["future"] = serde_json::json!({"x": 1});
    cas::write(&s, &rel(S), &raw, Expect::Absent).await.unwrap();
    let t = Table::new(s.clone());
    let a = Member { node_id: "a".into(), incarnation: "a1".into(), addr: String::new() };
    t.set_replicas(S, |r| r.push(a.clone())).await.unwrap().unwrap();
    let back: serde_json::Value = cas::read(&s, &rel(S)).await.unwrap().unwrap().value;
    assert_eq!(back["future"]["x"], 1);
}

mod sim;
