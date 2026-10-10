//! A cluster under chaos: nodes own ranges through the table, write
//! positions into their own streams (vlDB's enriched streams, a vlpds node
//! log), and crash, stall, get partitioned, restart and hand ranges off
//! while every store call may be slow, fail, or land with its answer lost.
//! Liveness is either bucket leases or peer heartbeats; safety is the same
//! bucket CAS and fence in both.
//!
//! A stream is fenced the way a bucket log is: once fenced, its holder's
//! next write fails and it stops. Nothing else protects the history: a
//! node checks `may_write` before a burst of writes, but may stall between
//! the check and the writes, and during some partitions a node ignores its
//! self-check altogether (a clock jump, a bug): a partitioned old owner its
//! peers rightly or wrongly declared dead, still writing.
//!
//! At the end:
//! - every record keeps its invariants (`Assignment::check`);
//! - every write in every stream is accepted by its range's history:
//!   no deposed owner's write survives past its span;
//! - every closed span holds every position it claims, written by its own
//!   epoch, and no position is decided twice;
//! - once faults stop, every range has a live owner that keeps writing.
//!
//! With the fence switched off the second check must fail for some seeds,
//! which shows the sim can tell.

use super::*;
use crate::alive::{Alive, Leases};
use crate::peers::mem::Net;
use crate::peers::{PeerConfig, Peers};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const NODES: usize = 4;
const RANGES: u32 = 8;
const STEP: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Leases,
    Heartbeats,
}

#[derive(Clone, Copy, Debug)]
struct Op {
    shard: ShardId,
    pos: u64,
    epoch: u64,
}

#[derive(Default)]
struct Stream {
    ops: Vec<Op>,
    fenced: bool,
}

#[derive(Default)]
struct Streams(parking_lot::Mutex<HashMap<String, Stream>>);

impl Streams {
    fn append(&self, inc: &str, op: Op) -> bool {
        let mut m = self.0.lock();
        let s = m.entry(inc.to_string()).or_default();
        if s.fenced {
            return false;
        }
        s.ops.push(op);
        true
    }

    /// Fences `inc`'s stream (unless fencing is off) and returns the last
    /// position it holds for `shard` (0: none).
    fn fence(&self, inc: &str, shard: ShardId, on: bool) -> u64 {
        let mut m = self.0.lock();
        let s = m.entry(inc.to_string()).or_default();
        s.fenced |= on;
        s.ops.iter().filter(|o| o.shard == shard).map(|o| o.pos).max().unwrap_or(0)
    }
}

struct World {
    mode: Mode,
    fence: bool,
    mem: Arc<object_store::memory::InMemory>,
    net: Arc<Net>,
    streams: Streams,
    head: AtomicU64,
    /// Faults on: chaos knobs set, crashes, stalls and partitions happen.
    stormy: AtomicBool,
    /// Nodes ignoring their self-check right now.
    rogue: parking_lot::Mutex<HashSet<String>>,
    handoffs: AtomicU64,
    takeovers: AtomicU64,
    rogue_writes: AtomicU64,
}

fn shards() -> Vec<ShardId> {
    (0..RANGES).map(ShardId).collect()
}

fn all_ids() -> Vec<String> {
    (0..NODES).map(|i| format!("n{i}")).collect()
}

/// This process's liveness, either kind. The guards stop its renewals
/// or beats when the process ends.
#[allow(dead_code)]
enum Live {
    Leases(Arc<Leases<()>>, AbortOnDrop),
    Peers(Arc<Peers>, AbortOnDrop),
}

impl Live {
    async fn start(w: &Arc<World>, id: &str, inc: &str, store: &Store) -> Live {
        match w.mode {
            Mode::Leases => {
                let h = loop {
                    match Holder::<()>::acquire(store.clone(), cfg(id), inc.to_string(), ()).await {
                        Ok(h) => break h,
                        Err(_) => tokio::time::sleep(STEP).await,
                    }
                };
                let renewer = {
                    let h = h.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(h.config().renew_every).await;
                            if let Err(crate::lease::RenewError::Lost(_)) = h.renew().await {
                                return;
                            }
                        }
                    })
                };
                Live::Leases(Arc::new(Leases::new(h)), AbortOnDrop(renewer))
            }
            Mode::Heartbeats => {
                let me = Member { node_id: id.into(), incarnation: inc.into(), addr: format!("{id}:1") };
                let members = all_ids().into_iter().map(|i| (i.clone(), format!("{i}:1"))).collect();
                let p = Peers::new(PeerConfig::new(me, members), w.net.transport(id)).unwrap();
                w.net.join(&p);
                let beats = p.spawn();
                Live::Peers(p, AbortOnDrop(beats))
            }
        }
    }

    fn alive(&self) -> &dyn Alive {
        match self {
            Live::Leases(l, _) => l.as_ref(),
            Live::Peers(p, _) => p.as_ref(),
        }
    }

    fn me(&self) -> Member {
        match self {
            Live::Leases(l, _) => Member::of(&l.holder().lease()),
            Live::Peers(p, _) => p.me().clone(),
        }
    }

    /// A fresh view. Err: try again next round.
    async fn observe(&self) -> anyhow::Result<()> {
        match self {
            Live::Leases(l, _) => l.observe().await.map(|_| ()),
            Live::Peers(..) => Ok(()),
        }
    }

    /// Lost for good (a lease taken, lapsed or ended): fail-stop.
    fn lost(&self) -> bool {
        match self {
            Live::Leases(l, _) => l.holder().lost().is_some(),
            Live::Peers(..) => false,
        }
    }

    /// Live members other nodes may hand ranges to.
    fn settled(&self) -> Vec<Member> {
        match self {
            Live::Leases(l, _) => l.membership().settled().iter().map(Member::of).collect(),
            Live::Peers(p, _) => {
                let incs = p.incarnations();
                p.live()
                    .into_iter()
                    .filter_map(|id| {
                        Some(Member { incarnation: incs.get(&id)?.clone(), addr: format!("{id}:1"), node_id: id })
                    })
                    .collect()
            }
        }
    }

    /// Marks fully fenced, ownerless dead incarnations' leases ended.
    async fn end_dead(&self, t: &Table) {
        let Live::Leases(l, _) = self else { return };
        for (lease, v) in l.membership().leases.values() {
            if *v == Liveness::Dead
                && !lease.ended
                && !t.all().values().any(|a| a.owner.as_ref().is_some_and(|o| o.incarnation == lease.incarnation))
            {
                let _ = l.observer().end(lease).await;
            }
        }
    }
}

/// One process: its liveness, a table, its owned ranges.
async fn process(w: Arc<World>, id: String, inc: String, store: Store, chaos: ChaosStore, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let live = Live::start(&w, &id, &inc, &store).await;
    let me = live.me();
    let t = Table::new(store.clone());
    // shard -> (epoch, next position to write)
    let mut mine: BTreeMap<ShardId, (u64, u64)> = BTreeMap::new();
    // With heartbeats the table is read every 2 s, as a cost-aware node
    // would (it changes only when ownership does), so a deposed owner's
    // view of it can be that stale. With leases, every round.
    let every = if w.mode == Mode::Heartbeats { 20 } else { 1 };
    for round in 0u64.. {
        tokio::time::sleep(STEP).await;
        let rogue = w.rogue.lock().contains(&id);
        if live.lost() && !rogue {
            return;
        }
        if live.observe().await.is_err() || (round % every == 0 && t.refresh().await.is_err()) {
            continue;
        }
        // stop writing what the table no longer gives us at our epoch; pick
        // up what it does (a release whose answer we never got)
        mine.retain(|s, (e, _)| t.cached(*s).is_some_and(|v| v.value.owned_by(&me) && v.value.epoch == *e));
        for (s, a) in t.owned_by(&me) {
            mine.entry(s).or_insert_with(|| {
                let next = w.streams.0.lock().get(&inc).map_or(0, |st| {
                    st.ops.iter().filter(|o| o.shard == s && o.epoch == a.epoch).map(|o| o.pos).max().unwrap_or(0)
                });
                (a.epoch, next.max(a.floor) + 1)
            });
        }
        let settled = live.settled();
        let fair = (RANGES as usize).div_ceil(settled.len().max(1));
        let mut order = shards();
        order.sort_by_key(|_| rng.gen::<u32>());
        for s in order {
            if mine.len() >= fair {
                break;
            }
            if mine.contains_key(&s) {
                continue;
            }
            let w2 = w.clone();
            let got = t
                .acquire(s, &me, live.alive(), |span| {
                    let end = w2.streams.fence(&span.incarnation, s, w2.fence);
                    async move { Ok(end) }
                })
                .await;
            match got {
                Ok(Acquired::Taken(a)) => {
                    if a.history.len() > 1 && a.history[a.history.len() - 2].until.is_some() {
                        w.takeovers.fetch_add(1, Ordering::Relaxed);
                    }
                    mine.insert(s, (a.epoch, a.floor + 1));
                }
                Ok(Acquired::Unable) => break,
                _ => {}
            }
        }
        live.end_dead(&t).await;
        // the writes: one self-check, then a burst that may stall
        let may = live.alive().may_write();
        if !may && !rogue {
            continue;
        }
        let head = w.head.load(Ordering::SeqCst);
        for (s, (epoch, next)) in mine.iter_mut() {
            // a segment PUT takes a while: a stall can land between the
            // check above and the write
            tokio::time::sleep(Duration::from_millis(rng.gen_range(0..40))).await;
            while *next <= head {
                chaos.knobs().wait_resumed().await;
                if !w.streams.append(&inc, Op { shard: *s, pos: *next, epoch: *epoch }) {
                    // fenced: fail-stop
                    return;
                }
                if !may {
                    w.rogue_writes.fetch_add(1, Ordering::Relaxed);
                }
                *next += 1;
            }
        }
        // now and then hand a range to a peer
        if w.stormy.load(Ordering::Relaxed) && may && rng.gen_bool(0.1) && !mine.is_empty() {
            let peers: Vec<_> = settled.into_iter().filter(|m| m.node_id != id).collect();
            if !peers.is_empty() {
                let s = *mine.keys().nth(rng.gen_range(0..mine.len())).unwrap();
                let to = peers[rng.gen_range(0..peers.len())].clone();
                let end = mine[&s].1 - 1;
                // stop writing it before the CAS; if the answer is lost the
                // next refresh says whose it is
                mine.remove(&s);
                if let Ok(Some(_)) = t.release(s, &me, end, Some(&to)).await {
                    w.handoffs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Slot {
    id: String,
    gen: u64,
    chaos: ChaosStore,
    store: Store,
    task: Option<tokio::task::JoinHandle<()>>,
    down_until: Option<Instant>,
    resume_at: Option<Instant>,
    heal_at: Option<Instant>,
}

impl Slot {
    fn start(&mut self, w: &Arc<World>) {
        self.gen += 1;
        let inc = format!("{}-{}", self.id, self.gen);
        let seed = self.gen * 1000 + self.id.as_bytes()[1] as u64;
        self.task =
            Some(tokio::spawn(process(w.clone(), self.id.clone(), inc, self.store.clone(), self.chaos.clone(), seed)));
        self.down_until = None;
    }

    fn running(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
    }
}

fn faults(c: &ChaosStore, on: bool) {
    if on {
        c.knobs().set(Duration::from_millis(40), 0.03, 0.02);
    } else {
        c.knobs().set(Duration::ZERO, 0.0, 0.0);
        c.knobs().resume();
    }
}

#[derive(Debug, Default)]
struct Outcome {
    /// Surviving writes outside their range's history.
    outside: usize,
    crashes: u64,
    stalls: u64,
    partitions: u64,
    takeovers: u64,
    handoffs: u64,
    rogue_writes: u64,
}

async fn run(seed: u64, mode: Mode, fence: bool) -> Outcome {
    let mem = shared();
    let w = Arc::new(World {
        mode,
        fence,
        mem: mem.clone(),
        net: Net::new(),
        streams: Streams::default(),
        head: AtomicU64::new(0),
        stormy: AtomicBool::new(true),
        rogue: Default::default(),
        handoffs: AtomicU64::new(0),
        takeovers: AtomicU64::new(0),
        rogue_writes: AtomicU64::new(0),
    });
    let (admin, _) = client(&w.mem, seed);
    let t = Table::new(admin.clone());
    for s in shards() {
        t.create(s, 0, None).await.unwrap();
    }
    let mut slots: Vec<Slot> = (0..NODES)
        .map(|i| {
            let (store, chaos) = client(&mem, seed * 100 + i as u64);
            faults(&chaos, true);
            Slot {
                id: format!("n{i}"),
                gen: 0,
                chaos,
                store,
                task: None,
                down_until: None,
                resume_at: None,
                heal_at: None,
            }
        })
        .collect();
    for s in &mut slots {
        s.start(&w);
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let mut out = Outcome::default();
    let storm = 900; // 90 s of faults
    let calm = 300; // then 30 s without
    let ids = all_ids();
    for tick in 0..storm + calm {
        tokio::time::sleep(STEP).await;
        w.head.fetch_add(5, Ordering::SeqCst);
        let now = Instant::now();
        if tick == storm {
            w.stormy.store(false, Ordering::Relaxed);
            w.net.heal_all();
            w.rogue.lock().clear();
            for s in &mut slots {
                faults(&s.chaos, false);
                s.resume_at = None;
                s.heal_at = None;
            }
        }
        for s in &mut slots {
            if s.resume_at.is_some_and(|r| now >= r) {
                s.chaos.knobs().resume();
                w.net.heal(&s.id);
                s.resume_at = None;
            }
            if s.heal_at.is_some_and(|r| now >= r) {
                w.net.heal(&s.id);
                w.rogue.lock().remove(&s.id);
                s.heal_at = None;
            }
            if !s.running() && s.down_until.is_none_or(|d| now >= d) {
                s.start(&w);
            }
        }
        if tick < storm && tick % 10 == 0 {
            let i = rng.gen_range(0..NODES);
            let up = slots.iter().filter(|s| s.running()).count();
            let busy = slots[i].resume_at.is_some() || slots[i].heal_at.is_some();
            match rng.gen_range(0..5) {
                // kill -9: the process and its renewals stop, its writes stay
                0 if up > 2 && slots[i].running() => {
                    slots[i].task.take().unwrap().abort();
                    w.net.leave(&slots[i].id);
                    slots[i].down_until = Some(now + Duration::from_millis(rng.gen_range(500..3000)));
                    out.crashes += 1;
                }
                // a stall (GC, a frozen VM), sometimes long enough to be
                // taken over: no store calls, no beats, no writes
                1 if !busy => {
                    slots[i].chaos.knobs().pause();
                    w.net.isolate(&slots[i].id, &ids);
                    slots[i].resume_at = Some(now + Duration::from_millis(rng.gen_range(300..6000)));
                    out.stalls += 1;
                }
                // a network partition from its peers (the bucket still
                // answers), half the time with the node ignoring its
                // self-check: it keeps writing after peers take over
                2 if mode == Mode::Heartbeats && !busy => {
                    w.net.isolate(&slots[i].id, &ids);
                    if rng.gen_bool(0.5) {
                        w.rogue.lock().insert(slots[i].id.clone());
                    }
                    slots[i].heal_at = Some(now + Duration::from_millis(rng.gen_range(500..10_000)));
                    out.partitions += 1;
                }
                _ => {}
            }
        }
    }
    for s in &mut slots {
        if let Some(t) = s.task.take() {
            t.abort();
        }
    }

    let streams = std::mem::take(&mut *w.streams.0.lock());
    let head = w.head.load(Ordering::SeqCst);
    out.handoffs = w.handoffs.load(Ordering::Relaxed);
    out.takeovers = w.takeovers.load(Ordering::Relaxed);
    out.rogue_writes = w.rogue_writes.load(Ordering::Relaxed);
    let (check, _) = client(&mem, 0);
    for s in shards() {
        let a = cas::read::<Assignment>(&check, &rel(s)).await.unwrap().unwrap().value;
        let mut decided = HashSet::new();
        for (inc, st) in streams.iter() {
            for o in st.ops.iter().filter(|o| o.shard == s) {
                if !a.accepts(o.epoch, inc, o.pos) {
                    out.outside += 1;
                    if fence {
                        panic!(
                            "seed {seed} {mode:?} {s}: {inc}'s write at {} (epoch {}) is outside the history\n{a:#?}",
                            o.pos, o.epoch
                        );
                    }
                }
                if fence {
                    assert!(decided.insert(o.pos), "seed {seed} {mode:?} {s}: position {} decided twice", o.pos);
                }
            }
        }
        if !fence {
            continue;
        }
        a.check().unwrap_or_else(|e| panic!("seed {seed} {mode:?} {s}: {e:#}\n{a:#?}"));
        // every closed span holds every position it claims
        for sp in &a.history {
            let end = sp.until.unwrap_or_else(|| {
                streams[&sp.incarnation].ops.iter().filter(|o| o.shard == s).map(|o| o.pos).max().unwrap_or(sp.from - 1)
            });
            for p in sp.from..=end {
                assert!(decided.contains(&p), "seed {seed} {mode:?} {s}: span {sp:?} is missing position {p}");
            }
        }
        assert_eq!(decided.len() as u64, decided.iter().max().copied().unwrap_or(0), "seed {seed} {mode:?} {s}: a gap");
        // after the calm, a live owner is writing it
        let o = a.owner.as_ref().unwrap_or_else(|| panic!("seed {seed} {mode:?} {s}: no owner after the calm"));
        let slot = slots.iter().find(|x| x.id == o.node_id).unwrap();
        assert_eq!(
            o.incarnation,
            format!("{}-{}", slot.id, slot.gen),
            "seed {seed} {mode:?} {s}: owned by a dead incarnation"
        );
        assert!(decided.len() as u64 + 20 >= head, "seed {seed} {mode:?} {s}: stalled at {} of {head}", decided.len());
    }
    let injected: u64 = slots.iter().map(|s| s.chaos.knobs().injected.load(Ordering::Relaxed)).sum();
    eprintln!("seed {seed} {mode:?} fence={fence}: {out:?}, {injected} injected faults, head {head}");
    if fence {
        assert!(out.crashes > 2 && out.stalls > 2 && out.takeovers > 5 && out.handoffs > 5);
        // heartbeats make far fewer store calls to inject faults into
        assert!(injected > if mode == Mode::Heartbeats { 10 } else { 100 });
        if mode == Mode::Heartbeats {
            assert!(out.partitions > 2);
        }
    }
    out
}

/// Seeds run one after another, each on its own paused clock.
fn seeds(range: std::ops::Range<u64>, mode: Mode, fence: bool) -> Vec<Outcome> {
    range
        .map(|seed| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .start_paused(true)
                .build()
                .unwrap()
                .block_on(run(seed, mode, fence))
        })
        .collect()
}

#[test]
fn leases_seeds_1_to_8() {
    seeds(1..9, Mode::Leases, true);
}

#[test]
fn leases_seeds_9_to_16() {
    seeds(9..17, Mode::Leases, true);
}

#[test]
fn heartbeats_seeds_1_to_8() {
    let o = seeds(1..9, Mode::Heartbeats, true);
    // rogue owners did write after losing their quorum, and the fence
    // stopped every such write that mattered
    assert!(o.iter().map(|o| o.rogue_writes).sum::<u64>() > 0);
}

#[test]
fn heartbeats_seeds_9_to_16() {
    seeds(9..17, Mode::Heartbeats, true);
}

/// More seeds, by hand: `cargo test -p vlsync-lease many_seeds -- --ignored`.
#[test]
#[ignore]
fn many_seeds() {
    seeds(17..129, Mode::Heartbeats, true);
    seeds(17..129, Mode::Leases, true);
}

/// Without the fence, deposed owners' writes survive outside the history:
/// the checks above can tell.
#[test]
fn without_the_fence_the_sim_catches_deposed_writes() {
    for mode in [Mode::Leases, Mode::Heartbeats] {
        let o = seeds(1..9, mode, false);
        let caught = o.iter().filter(|o| o.outside > 0).count();
        eprintln!("{mode:?} without the fence: {caught} of 8 seeds caught");
        assert!(caught > 0, "{mode:?}: no seed caught a deposed owner's write without the fence");
    }
}

/// The case by itself: an owner cut off from its peers that keeps writing
/// (it ignores its self-check) is declared dead, its range is taken, and
/// its next write fails through the fence; nothing it wrote is lost or
/// doubled.
#[tokio::test(start_paused = true)]
async fn a_partitioned_owner_declared_dead_fails_its_next_write() {
    let mem = shared();
    let net = Net::new();
    let ids = all_ids()[..3].to_vec();
    let members: Vec<_> = ids.iter().map(|i| (i.clone(), format!("{i}:1"))).collect();
    let mut ps = Vec::new();
    let mut beats = Vec::new();
    for id in &ids {
        let me = Member { node_id: id.clone(), incarnation: format!("{id}-1"), addr: format!("{id}:1") };
        let p = Peers::new(PeerConfig::new(me, members.clone()), net.transport(id)).unwrap();
        net.join(&p);
        beats.push(AbortOnDrop(p.spawn()));
        ps.push(p);
    }
    let (s0, _) = client(&mem, 1);
    let (s1, _) = client(&mem, 2);
    let (t0, t1) = (Table::new(s0.clone()), Table::new(s1.clone()));
    let streams = Streams::default();
    tokio::time::sleep(Duration::from_secs(3)).await;
    t0.create(S, 0, None).await.unwrap();
    let Acquired::Taken(a) = t0.acquire(S, ps[0].me(), ps[0].as_ref(), no_fence).await.unwrap() else { panic!() };
    for pos in 1..=50 {
        assert!(streams.append("n0-1", Op { shard: S, pos, epoch: a.epoch }));
    }
    // cut off: n0 stops passing its self-check, n1 can't take it yet
    net.isolate("n0", &ids);
    tokio::time::sleep(ps[0].config().timeout + ps[0].config().interval).await;
    assert!(!ps[0].may_write());
    assert_eq!(t1.acquire(S, ps[1].me(), ps[1].as_ref(), no_fence).await.unwrap(), Acquired::Busy(ps[0].me().clone()));
    // a rogue n0 writes on anyway (a clock jump), then peers take over
    for pos in 51..=60 {
        assert!(streams.append("n0-1", Op { shard: S, pos, epoch: a.epoch }));
    }
    tokio::time::sleep(ps[1].config().dead_after).await;
    assert_eq!(ps[1].verdict("n0", "n0-1").unwrap().liveness, Liveness::Dead);
    let got = t1
        .acquire(S, ps[1].me(), ps[1].as_ref(), |span| {
            let end = streams.fence(&span.incarnation, S, true);
            async move { Ok(end) }
        })
        .await
        .unwrap();
    let Acquired::Taken(b) = got else { panic!("{got:?}") };
    assert_eq!((b.epoch, b.history[0].until, b.open_span().unwrap().from), (2, Some(60), 61));
    // n0's next durable write fails: it learns it was fenced and stops
    assert!(!streams.append("n0-1", Op { shard: S, pos: 61, epoch: a.epoch }));
    for pos in 61..=70 {
        assert!(streams.append("n1-1", Op { shard: S, pos, epoch: b.epoch }));
    }
    let st = streams.0.lock();
    let mut decided = HashSet::new();
    for (inc, s) in st.iter() {
        for o in &s.ops {
            assert!(b.accepts(o.epoch, inc, o.pos), "{inc} {o:?}");
            assert!(decided.insert(o.pos));
        }
    }
    assert_eq!(decided.len(), 70);
    // the cut-off node never declared anyone dead
    assert_ne!(ps[0].verdict("n1", "n1-1").unwrap().liveness, Liveness::Dead);
}
