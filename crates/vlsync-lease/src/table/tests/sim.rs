//! A cluster under chaos: nodes own ranges through leases and the table,
//! write positions into their own streams (vlDB's enriched streams, a
//! vlpds node log), and crash, stall, restart and hand ranges off while
//! every store call may be slow, fail, or land with its answer lost.
//!
//! A stream is fenced the way a bucket log is: once fenced, its holder's
//! next write fails and it stops. Nothing else protects the history: a
//! node checks its lease before a burst of writes, but may stall between
//! the check and the writes.
//!
//! At the end:
//! - every record keeps its invariants (`Assignment::check`);
//! - every write in every stream is accepted by its range's history:
//!   no deposed owner's write survives past its span;
//! - every closed span holds every position it claims, written by its own
//!   epoch, and no position is decided twice;
//! - once faults stop, every range has a live owner that keeps writing.

use super::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const NODES: usize = 4;
const RANGES: u32 = 8;
const STEP: Duration = Duration::from_millis(100);

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

    /// Fences `inc`'s stream and returns the last position it holds for
    /// `shard` (0: none).
    fn fence(&self, inc: &str, shard: ShardId) -> u64 {
        let mut m = self.0.lock();
        let s = m.entry(inc.to_string()).or_default();
        s.fenced = true;
        s.ops.iter().filter(|o| o.shard == shard).map(|o| o.pos).max().unwrap_or(0)
    }
}

struct World {
    mem: Arc<object_store::memory::InMemory>,
    streams: Streams,
    head: AtomicU64,
    /// Faults on: chaos knobs set, crashes and stalls happen.
    stormy: AtomicBool,
    handoffs: AtomicU64,
    takeovers: AtomicU64,
}

fn shards() -> Vec<ShardId> {
    (0..RANGES).map(ShardId).collect()
}

/// One process: a lease, an observer, a table, its owned ranges.
async fn process(w: Arc<World>, id: String, inc: String, store: Store, chaos: ChaosStore, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let h = loop {
        match Holder::<()>::acquire(store.clone(), cfg(&id), inc.clone(), ()).await {
            Ok(h) => break h,
            Err(_) => tokio::time::sleep(STEP).await,
        }
    };
    let me = Member::of(&h.lease());
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
    let _stop_renewer = AbortOnDrop(renewer);
    let obs = Observer::for_holder(&h);
    let t = Table::new(store.clone());
    // shard -> (epoch, next position to write)
    let mut mine: BTreeMap<ShardId, (u64, u64)> = BTreeMap::new();
    loop {
        tokio::time::sleep(STEP).await;
        if h.lost().is_some() {
            return;
        }
        let Ok(m) = obs.observe().await else { continue };
        if t.refresh().await.is_err() {
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
        let fair = (RANGES as usize).div_ceil(m.settled().len().max(1));
        let mut order = shards();
        order.sort_by_key(|_| rng.gen::<u32>());
        for s in order {
            if mine.len() >= fair || !h.valid() {
                break;
            }
            if mine.contains_key(&s) {
                continue;
            }
            let w2 = w.clone();
            let got = t
                .acquire(s, &me, &m, |span| {
                    let end = w2.streams.fence(&span.incarnation, s);
                    async move { Ok(end) }
                })
                .await;
            if let Ok(Acquired::Taken(a)) = got {
                if a.history.len() > 1 && a.history[a.history.len() - 2].until.is_some() {
                    w.takeovers.fetch_add(1, Ordering::Relaxed);
                }
                mine.insert(s, (a.epoch, a.floor + 1));
            }
        }
        for (l, v) in m.leases.values() {
            if *v == Liveness::Dead && !l.ended {
                // a dead incarnation whose ranges are all fenced and moved
                if !t.all().values().any(|a| a.owner.as_ref().is_some_and(|o| o.incarnation == l.incarnation)) {
                    let _ = obs.end(l).await;
                }
            }
        }
        // the writes: one lease check, then a burst that may stall
        if !h.valid() {
            continue;
        }
        let head = w.head.load(Ordering::SeqCst);
        for (s, (epoch, next)) in mine.iter_mut() {
            while *next <= head {
                chaos.knobs().wait_resumed().await;
                if !w.streams.append(&inc, Op { shard: *s, pos: *next, epoch: *epoch }) {
                    // fenced: fail-stop
                    return;
                }
                *next += 1;
            }
        }
        // now and then hand a range to a peer
        if w.stormy.load(Ordering::Relaxed) && rng.gen_bool(0.1) && !mine.is_empty() {
            let peers: Vec<_> = m.settled().into_iter().filter(|l| l.node_id != id).collect();
            if !peers.is_empty() {
                let s = *mine.keys().nth(rng.gen_range(0..mine.len())).unwrap();
                let to = Member::of(&peers[rng.gen_range(0..peers.len())]);
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

async fn run(seed: u64) {
    let mem = shared();
    let w = Arc::new(World {
        mem: mem.clone(),
        streams: Streams::default(),
        head: AtomicU64::new(0),
        stormy: AtomicBool::new(true),
        handoffs: AtomicU64::new(0),
        takeovers: AtomicU64::new(0),
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
            Slot { id: format!("n{i}"), gen: 0, chaos, store, task: None, down_until: None, resume_at: None }
        })
        .collect();
    for s in &mut slots {
        s.start(&w);
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let (mut crashes, mut stalls) = (0, 0);
    let storm = 900; // 90 s of faults
    let calm = 300; // then 30 s without
    for tick in 0..storm + calm {
        tokio::time::sleep(STEP).await;
        w.head.fetch_add(5, Ordering::SeqCst);
        let now = Instant::now();
        if tick == storm {
            w.stormy.store(false, Ordering::Relaxed);
            for s in &mut slots {
                faults(&s.chaos, false);
                s.resume_at = None;
            }
        }
        for s in &mut slots {
            if s.resume_at.is_some_and(|r| now >= r) {
                s.chaos.knobs().resume();
                s.resume_at = None;
            }
            if !s.running() && s.down_until.is_none_or(|d| now >= d) {
                s.start(&w);
            }
        }
        if tick < storm && tick % 10 == 0 {
            let i = rng.gen_range(0..NODES);
            let up = slots.iter().filter(|s| s.running()).count();
            match rng.gen_range(0..4) {
                // kill -9: the process and its renewals stop, its writes stay
                0 if up > 2 && slots[i].running() => {
                    slots[i].task.take().unwrap().abort();
                    slots[i].down_until = Some(now + Duration::from_millis(rng.gen_range(500..3000)));
                    crashes += 1;
                }
                // a stall (GC, a frozen VM, a partition from the bucket),
                // sometimes long enough to be taken over
                1 if slots[i].resume_at.is_none() => {
                    slots[i].chaos.knobs().pause();
                    slots[i].resume_at = Some(now + Duration::from_millis(rng.gen_range(300..6000)));
                    stalls += 1;
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
    let (handoffs, takeovers) = (w.handoffs.load(Ordering::Relaxed), w.takeovers.load(Ordering::Relaxed));
    let (check, _) = client(&mem, 0);
    let mut epochs_total = 0;
    for s in shards() {
        let a = cas::read::<Assignment>(&check, &rel(s)).await.unwrap().unwrap().value;
        a.check().unwrap_or_else(|e| panic!("seed {seed} {s}: {e:#}\n{a:#?}"));
        epochs_total += a.epoch;
        // every surviving write is part of the history, once
        let mut decided = HashSet::new();
        for (inc, st) in streams.iter() {
            for o in st.ops.iter().filter(|o| o.shard == s) {
                assert!(
                    a.accepts(o.epoch, inc, o.pos),
                    "seed {seed} {s}: {inc}'s write at {} (epoch {}) is outside the history\n{a:#?}",
                    o.pos,
                    o.epoch
                );
                assert!(decided.insert(o.pos), "seed {seed} {s}: position {} decided twice", o.pos);
            }
        }
        // every closed span holds every position it claims
        for sp in &a.history {
            let end = sp.until.unwrap_or_else(|| {
                streams[&sp.incarnation].ops.iter().filter(|o| o.shard == s).map(|o| o.pos).max().unwrap_or(sp.from - 1)
            });
            for p in sp.from..=end {
                assert!(decided.contains(&p), "seed {seed} {s}: span {sp:?} is missing position {p}");
            }
        }
        assert_eq!(decided.len() as u64, decided.iter().max().copied().unwrap_or(0), "seed {seed} {s}: a gap");
        // after the calm, a live owner is writing it
        let o = a.owner.as_ref().unwrap_or_else(|| panic!("seed {seed} {s}: no owner after the calm"));
        let slot = slots.iter().find(|x| x.id == o.node_id).unwrap();
        assert_eq!(o.incarnation, format!("{}-{}", slot.id, slot.gen), "seed {seed} {s}: owned by a dead incarnation");
        assert!(decided.len() as u64 + 20 >= head, "seed {seed} {s}: stalled at {} of {head}", decided.len());
    }
    let injected: u64 = slots.iter().map(|s| s.chaos.knobs().injected.load(Ordering::Relaxed)).sum();
    eprintln!(
        "seed {seed}: {crashes} crashes, {stalls} stalls, {takeovers} takeovers, {handoffs} handoffs, {injected} injected faults, {epochs_total} epochs, head {head}"
    );
    assert!(crashes > 5 && stalls > 5 && takeovers > 5 && handoffs > 5 && injected > 100);
}

/// Seeds run in their own tasks, each on its own paused clock.
fn seeds(range: std::ops::Range<u64>) {
    for seed in range {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(run(seed));
    }
}

#[test]
fn chaos_seeds_1_to_8() {
    seeds(1..9);
}

#[test]
fn chaos_seeds_9_to_16() {
    seeds(9..17);
}
