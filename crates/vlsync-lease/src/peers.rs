//! Liveness by peer heartbeats, with no bucket requests at all.
//!
//! The quorum rules are vlRelay's (`qlog::node`, which now calls them from
//! here): a member counts as heard if a message from it arrived within a
//! window, a node with fewer than a quorum heard (itself included) stops
//! (vlRelay's leader steps down), and a minority never acts on its own
//! view (vlRelay's candidate needs a quorum reachable before it takes over).
//! A refused port means the process is gone (vlRelay's probe).
//!
//! [`Peers`] runs them for a symmetric cluster such as vlDB's, where every
//! member beats every other one every `interval` and each reply carries the
//! replier's view of everyone:
//!
//! - Self-check: [`Peers::may_write`] is true while a quorum of members
//!   (this node included) was heard within `timeout`. A node cut off from a
//!   quorum stops writing within `timeout`.
//! - Verdict: an incarnation is Dead only when this node may write and a
//!   quorum of members, counting this node and never the suspect, have
//!   each gone `dead_after` without hearing it (or heard a newer
//!   incarnation, or found its port refused). Their views come from replies
//!   received within `timeout`, aged on our clock since.
//!
//! Every time is a local monotonic instant. A peer's view travels as an
//! age ("I heard it 1.2 s ago"), never as a timestamp.
//!
//! Ordering: if X wrote at t, it heard a quorum Q within `timeout` before t.
//! Any quorum that declares X dead shares a member with Q (two quorums of n,
//! one without X, always intersect), and that member heard X when it
//! answered. So with `dead_after > 2 × timeout + interval` plus drift, X
//! stops first. Safety doesn't rest on that: a taker fences before it takes
//! (see `table`), and a wrong verdict costs a fail-stop.

use crate::rpc::{self, CallError, Faults, Rpc, Wire};
use crate::table::Member;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

/// The smallest majority of `members` (vlRelay's quorum).
pub fn quorum(members: usize) -> usize {
    members / 2 + 1
}

/// The members heard within `within`, `me` always among them. `age` is how
/// long ago a member was last heard (None: never). This is vlRelay's
/// leader's view of who can own hosts (`Node::live_members`).
pub fn heard_within<'a>(
    members: &'a [String],
    me: &'a str,
    age: impl Fn(&str) -> Option<Duration> + 'a,
    within: Duration,
) -> impl Iterator<Item = &'a String> {
    members.iter().filter(move |m| *m == me || age(m).is_some_and(|a| a < within))
}

/// Whether a quorum of `members` (`me` included) was heard within
/// `within`. vlRelay's leader steps down when it isn't.
pub fn has_quorum(members: &[String], me: &str, age: impl Fn(&str) -> Option<Duration>, within: Duration) -> bool {
    heard_within(members, me, age, within).count() >= quorum(members.len())
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub me: Member,
    /// Every member as (node id, address), this node included. A seed list
    /// from config: membership changes are a restart with a new list.
    pub members: Vec<(String, String)>,
    /// How often to beat every other member.
    pub interval: Duration,
    /// The self-check window, and how fresh a peer's view must be to count.
    pub timeout: Duration,
    /// How long a quorum must go without hearing a node before it's dead.
    pub dead_after: Duration,
    /// A beat that takes longer has failed.
    pub rpc_timeout: Duration,
}

impl PeerConfig {
    /// 500 ms beats, a 2 s self-check and dead after 5 s.
    pub fn new(me: Member, members: Vec<(String, String)>) -> PeerConfig {
        PeerConfig {
            me,
            members,
            interval: Duration::from_millis(500),
            timeout: Duration::from_secs(2),
            dead_after: Duration::from_secs(5),
            rpc_timeout: Duration::from_millis(500),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.members.iter().any(|(id, _)| *id == self.me.node_id), "members must include this node");
        anyhow::ensure!(
            self.interval < self.timeout,
            "beats every {:?} can't keep a {:?} window",
            self.interval,
            self.timeout
        );
        anyhow::ensure!(
            self.dead_after > self.timeout * 2 + self.interval,
            "dead_after {:?} must exceed 2 x timeout + interval ({:?}) so a node stops before it's presumed dead",
            self.dead_after,
            self.timeout * 2 + self.interval
        );
        Ok(())
    }
}

/// One node's view of another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    pub node_id: String,
    /// The incarnation last heard (None: never heard).
    pub incarnation: Option<String>,
    /// Since it was last heard, or since the viewer started if never.
    pub age_ms: u64,
    /// Its port refused a connection after it was last heard.
    #[serde(default)]
    pub gone: bool,
}

/// A heartbeat and its reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Beat {
    pub from: String,
    pub incarnation: String,
    pub views: Vec<View>,
    /// The newest `assign/topology` generation the sender knows of, so a
    /// node re-reads the topology only when it changed.
    #[serde(default)]
    pub topology: u64,
    /// Range key -> how far the sender has applied it (a replica's
    /// watermark), for routers.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub positions: std::collections::BTreeMap<String, u64>,
}

/// How beats travel: TCP ([`TcpTransport`]), an in-memory network for
/// tests, or a user's own RPC (vlDB's) calling [`Peers::on_beat`] on the
/// other side.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    async fn beat(&self, peer: &str, beat: Beat, timeout: Duration) -> Result<Beat, CallError>;
}

#[derive(Default)]
struct Entry {
    incarnation: Option<String>,
    heard_at: Option<Instant>,
    gone_at: Option<Instant>,
    /// The views in its last beat or reply, and when it arrived.
    report: Option<(Instant, Vec<View>)>,
    positions: std::collections::BTreeMap<String, u64>,
}

/// A node's heartbeat liveness.
pub struct Peers {
    cfg: PeerConfig,
    ids: Vec<String>,
    transport: Arc<dyn Transport>,
    started: Instant,
    state: Mutex<HashMap<String, Entry>>,
    stopped: AtomicBool,
    topology: AtomicU64,
    positions: Mutex<std::collections::BTreeMap<String, u64>>,
}

/// What one member's view says of an incarnation.
enum Vote {
    /// Nothing from the node for `age` (`ours`: and the last thing heard was
    /// this incarnation).
    Heard { age: Duration, ours: bool },
    /// Gone (port refused) or replaced by another incarnation.
    Unheard,
}

impl Vote {
    fn unheard(&self, dead_after: Duration) -> bool {
        match self {
            Vote::Heard { age, .. } => *age > dead_after,
            Vote::Unheard => true,
        }
    }

    fn heard_ours(&self) -> Option<Duration> {
        match self {
            Vote::Heard { age, ours: true } => Some(*age),
            _ => None,
        }
    }
}

impl Peers {
    pub fn new(cfg: PeerConfig, transport: Arc<dyn Transport>) -> anyhow::Result<Arc<Peers>> {
        cfg.validate()?;
        let ids = cfg.members.iter().map(|(id, _)| id.clone()).collect();
        Ok(Arc::new(Peers {
            cfg,
            ids,
            transport,
            started: Instant::now(),
            state: Mutex::new(HashMap::new()),
            stopped: AtomicBool::new(false),
            topology: AtomicU64::new(0),
            positions: Mutex::new(Default::default()),
        }))
    }

    pub fn config(&self) -> &PeerConfig {
        &self.cfg
    }

    pub fn me(&self) -> &Member {
        &self.cfg.me
    }

    /// Beats every other member every `interval`, each call on its own task
    /// so a member that's down or cut off holds up nobody (vlRelay's
    /// `broadcast`).
    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(me.cfg.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if me.stopped.load(Ordering::Acquire) {
                    return;
                }
                me.beat_all();
            }
        })
    }

    /// Stops beating (and answering): this node is going away.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    fn beat_all(self: &Arc<Self>) {
        for id in self.ids.iter().filter(|id| **id != self.cfg.me.node_id) {
            let (me, id, b) = (self.clone(), id.clone(), self.beat());
            tokio::spawn(async move {
                match me.transport.beat(&id, b, me.cfg.rpc_timeout).await {
                    Ok(reply) => me.heard(reply),
                    Err(CallError::Refused) => {
                        me.state.lock().entry(id).or_default().gone_at = Some(Instant::now());
                    }
                    Err(_) => {}
                }
            });
        }
    }

    /// This node's beat: who it is and its view of every member.
    pub fn beat(&self) -> Beat {
        let now = Instant::now();
        let st = self.state.lock();
        let views = self
            .ids
            .iter()
            .filter(|id| **id != self.cfg.me.node_id)
            .map(|id| {
                let e = st.get(id);
                let heard = e.and_then(|e| e.heard_at);
                View {
                    node_id: id.clone(),
                    incarnation: e.and_then(|e| e.incarnation.clone()),
                    age_ms: now.saturating_duration_since(heard.unwrap_or(self.started)).as_millis() as u64,
                    gone: e.is_some_and(|e| e.gone_at.is_some_and(|g| heard.is_none_or(|h| g > h))),
                }
            })
            .collect();
        Beat {
            from: self.cfg.me.node_id.clone(),
            incarnation: self.cfg.me.incarnation.clone(),
            views,
            topology: self.topology.load(Ordering::Acquire),
            positions: self.positions.lock().clone(),
        }
    }

    /// Publishes how far this node has applied a range (`ShardId::key()`)
    /// with its next beats.
    pub fn set_position(&self, range: &str, pos: u64) {
        self.positions.lock().insert(range.to_string(), pos);
    }

    /// `node_id`'s published position for `range`, if it's `incarnation`.
    pub fn position(&self, node_id: &str, incarnation: &str, range: &str) -> Option<u64> {
        if node_id == self.cfg.me.node_id {
            return (incarnation == self.cfg.me.incarnation).then(|| self.positions.lock().get(range).copied())?;
        }
        let st = self.state.lock();
        let e = st.get(node_id)?;
        (e.incarnation.as_deref() == Some(incarnation)).then(|| e.positions.get(range).copied())?
    }

    /// Notes a topology generation (one this node published or read): the
    /// beats spread the newest one.
    pub fn saw_topology(&self, generation: u64) {
        self.topology.fetch_max(generation, Ordering::AcqRel);
    }

    /// The newest topology generation any member has mentioned. A node that
    /// last read an older one reads `assign/topology` again.
    pub fn topology(&self) -> u64 {
        self.topology.load(Ordering::Acquire)
    }

    fn heard(&self, b: Beat) {
        if !self.ids.contains(&b.from) || b.from == self.cfg.me.node_id {
            return;
        }
        self.saw_topology(b.topology);
        let now = Instant::now();
        let mut st = self.state.lock();
        let e = st.entry(b.from).or_default();
        e.incarnation = Some(b.incarnation);
        e.heard_at = Some(now);
        e.report = Some((now, b.views));
        e.positions = b.positions;
    }

    /// A peer's beat arrived: note it, and answer with ours.
    pub fn on_beat(&self, b: Beat) -> Option<Beat> {
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        self.heard(b);
        Some(self.beat())
    }

    fn age(&self, id: &str, now: Instant) -> Option<Duration> {
        self.state.lock().get(id).and_then(|e| e.heard_at).map(|t| now.saturating_duration_since(t))
    }

    /// The self-check: a quorum (this node included) heard within
    /// `timeout`. A node that can't reach a quorum stops writing.
    pub fn may_write(&self) -> bool {
        if self.stopped.load(Ordering::Acquire) {
            return false;
        }
        let now = Instant::now();
        has_quorum(&self.ids, &self.cfg.me.node_id, |m| self.age(m, now), self.cfg.timeout)
    }

    /// Members heard within `timeout`, this node included.
    pub fn live(&self) -> Vec<String> {
        let now = Instant::now();
        heard_within(&self.ids, &self.cfg.me.node_id, |m| self.age(m, now), self.cfg.timeout).cloned().collect()
    }

    /// The incarnation each member was last heard as.
    pub fn incarnations(&self) -> HashMap<String, String> {
        let st = self.state.lock();
        let mut m: HashMap<String, String> =
            st.iter().filter_map(|(id, e)| Some((id.clone(), e.incarnation.clone()?))).collect();
        m.insert(self.cfg.me.node_id.clone(), self.cfg.me.incarnation.clone());
        m
    }

    /// How `node_id`'s `incarnation` stands. None: not a member.
    pub fn verdict(&self, node_id: &str, incarnation: &str) -> Option<crate::alive::Heard> {
        use crate::alive::Heard;
        use crate::lease::Liveness;
        let now = Instant::now();
        if node_id == self.cfg.me.node_id {
            let l = if incarnation == self.cfg.me.incarnation { Liveness::Live } else { Liveness::Dead };
            return Some(Heard { liveness: l, as_of: now });
        }
        if !self.ids.iter().any(|i| i == node_id) {
            return None;
        }
        let st = self.state.lock();
        let mut votes = Vec::new();
        if let Some(e) = st.get(node_id) {
            let gone = e.gone_at.is_some_and(|g| e.heard_at.is_none_or(|h| g > h));
            let age = now.saturating_duration_since(e.heard_at.unwrap_or(self.started));
            votes.push(self.vote(e.incarnation.as_deref(), age, gone, incarnation));
        } else {
            votes.push(self.vote(None, now.saturating_duration_since(self.started), false, incarnation));
        }
        for (_, e) in st.iter().filter(|(id, _)| id.as_str() != node_id && self.ids.contains(id)) {
            let Some((at, views)) = &e.report else { continue };
            let since = now.saturating_duration_since(*at);
            if since >= self.cfg.timeout {
                continue;
            }
            let Some(v) = views.iter().find(|v| v.node_id == node_id) else { continue };
            let age = Duration::from_millis(v.age_ms) + since;
            votes.push(self.vote(v.incarnation.as_deref(), age, v.gone, incarnation));
        }
        drop(st);
        let against = votes.iter().filter(|v| v.unheard(self.cfg.dead_after)).count();
        let last = votes.iter().filter_map(|v| v.heard_ours()).min().and_then(|a| now.checked_sub(a));
        let liveness = if against >= quorum(self.ids.len()) && self.may_write() {
            Liveness::Dead
        } else if last.is_some_and(|t| now.saturating_duration_since(t) < self.cfg.timeout) {
            Liveness::Live
        } else {
            Liveness::Suspect
        };
        Some(Heard { liveness, as_of: if liveness == Liveness::Dead { now } else { last.unwrap_or(now) } })
    }

    /// One viewer's say on `incarnation`, from what it last heard of the
    /// node: which incarnation, how long ago (since the viewer started if
    /// never), and whether its port refused since.
    fn vote(&self, seen: Option<&str>, age: Duration, gone: bool, incarnation: &str) -> Vote {
        match seen {
            _ if gone => Vote::Unheard,
            Some(i) if i == incarnation => Vote::Heard { age, ours: true },
            // another process answers under its id
            Some(_) if age < self.cfg.timeout => Vote::Unheard,
            _ => Vote::Heard { age, ours: false },
        }
    }
}

/// Beats as frames of vlRelay's shape: a u32 length, a tag, the request id,
/// then JSON.
pub struct BeatFrame(pub Option<Beat>);

impl Wire for BeatFrame {
    const MAX_FRAME: usize = 1 << 20;
    const NAME: &'static str = "peers";

    fn encode(&self, rid: u64) -> Bytes {
        let body = serde_json::to_vec(&self.0).expect("a beat serializes");
        let mut b = BytesMut::with_capacity(13 + body.len());
        b.put_u32((9 + body.len()) as u32);
        b.put_u8(1);
        b.put_u64(rid);
        b.put_slice(&body);
        b.freeze()
    }

    fn decode(mut body: Bytes) -> Result<(u64, Self), &'static str> {
        if body.len() < 9 || body.get_u8() != 1 {
            return Err("not a beat");
        }
        let rid = body.get_u64();
        let b = serde_json::from_slice(&body).map_err(|_| "bad beat")?;
        Ok((rid, BeatFrame(b)))
    }
}

/// Beats over TCP with the shared [`Rpc`] client.
pub struct TcpTransport {
    addrs: HashMap<String, String>,
    rpcs: Mutex<HashMap<String, Arc<Rpc<BeatFrame>>>>,
    faults: Arc<Faults>,
}

impl TcpTransport {
    pub fn new(members: &[(String, String)], faults: Arc<Faults>) -> TcpTransport {
        TcpTransport { addrs: members.iter().cloned().collect(), rpcs: Mutex::new(HashMap::new()), faults }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn beat(&self, peer: &str, beat: Beat, timeout: Duration) -> Result<Beat, CallError> {
        let rpc = {
            let Some(addr) = self.addrs.get(peer) else { return Err(CallError::Io(format!("no address for {peer}"))) };
            self.rpcs
                .lock()
                .entry(peer.to_string())
                .or_insert_with(|| Arc::new(Rpc::new(peer, addr, self.faults.clone())))
                .clone()
        };
        match rpc.call(&BeatFrame(Some(beat)), timeout).await? {
            BeatFrame(Some(b)) => Ok(b),
            // it says it is going away: as good as a refused port
            BeatFrame(None) => Err(CallError::Refused),
        }
    }
}

/// Answers beats on `listener` until it fails.
pub async fn serve(listener: TcpListener, peers: Arc<Peers>, faults: Arc<Faults>) {
    loop {
        match listener.accept().await {
            Ok((s, _)) => {
                let _ = s.set_nodelay(true);
                tokio::spawn(serve_conn(s, peers.clone(), faults.clone()));
            }
            Err(e) => {
                tracing::warn!("peers: accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_conn(mut s: TcpStream, peers: Arc<Peers>, faults: Arc<Faults>) {
    while let Ok((rid, BeatFrame(b))) = rpc::read_frame::<BeatFrame, _>(&mut s).await {
        let Some(b) = b else { continue };
        if faults.blocked(&b.from) {
            continue;
        }
        let reply = BeatFrame(peers.on_beat(b));
        if rpc::write_frame(&mut s, rid, &reply).await.is_err() {
            return;
        }
    }
}

/// An in-memory network for tests: nodes join and leave (a crash refuses),
/// and links can be cut one way or both (a blackhole).
#[cfg(any(test, feature = "chaos"))]
pub mod mem {
    use super::*;
    use std::collections::HashSet;

    #[derive(Default)]
    pub struct Net {
        nodes: Mutex<HashMap<String, std::sync::Weak<Peers>>>,
        cut: Mutex<HashSet<(String, String)>>,
    }

    impl Net {
        pub fn new() -> Arc<Net> {
            Arc::new(Net::default())
        }

        pub fn join(&self, p: &Arc<Peers>) {
            self.nodes.lock().insert(p.me().node_id.clone(), Arc::downgrade(p));
        }

        pub fn leave(&self, node_id: &str) {
            self.nodes.lock().remove(node_id);
        }

        /// Cuts `a` off from every other node, both ways.
        pub fn isolate(&self, a: &str, all: &[String]) {
            let mut c = self.cut.lock();
            for b in all.iter().filter(|b| *b != a) {
                c.insert((a.to_string(), b.clone()));
                c.insert((b.clone(), a.to_string()));
            }
        }

        pub fn cut(&self, from: &str, to: &str) {
            self.cut.lock().insert((from.to_string(), to.to_string()));
        }

        pub fn heal(&self, a: &str) {
            self.cut.lock().retain(|(x, y)| x != a && y != a);
        }

        pub fn heal_all(&self) {
            self.cut.lock().clear();
        }

        pub fn transport(self: &Arc<Self>, me: &str) -> Arc<dyn Transport> {
            Arc::new(MemTransport { net: self.clone(), me: me.to_string() })
        }
    }

    struct MemTransport {
        net: Arc<Net>,
        me: String,
    }

    #[async_trait]
    impl Transport for MemTransport {
        async fn beat(&self, peer: &str, beat: Beat, timeout: Duration) -> Result<Beat, CallError> {
            let blocked = |a: &str, b: &str| self.net.cut.lock().contains(&(a.to_string(), b.to_string()));
            if blocked(&self.me, peer) {
                tokio::time::sleep(timeout).await;
                return Err(CallError::Blocked);
            }
            let Some(p) = self.net.nodes.lock().get(peer).and_then(|w| w.upgrade()) else {
                return Err(CallError::Refused);
            };
            tokio::time::sleep(Duration::from_millis(1)).await;
            let reply = p.on_beat(beat).ok_or(CallError::Refused)?;
            if blocked(peer, &self.me) {
                tokio::time::sleep(timeout).await;
                return Err(CallError::Blocked);
            }
            Ok(reply)
        }
    }
}

#[cfg(test)]
mod tests;
