use super::mem::Net;
use super::*;
use crate::lease::Liveness;

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("n{i}")).collect()
}

fn member(id: &str, inc: &str) -> Member {
    Member { node_id: id.into(), incarnation: inc.into(), addr: format!("{id}:1") }
}

fn start(net: &Arc<Net>, id: &str, inc: &str, n: usize) -> (Arc<Peers>, tokio::task::JoinHandle<()>) {
    let members = ids(n).into_iter().map(|i| (i.clone(), format!("{i}:1"))).collect();
    let p = Peers::new(PeerConfig::new(member(id, inc), members), net.transport(id)).unwrap();
    net.join(&p);
    let h = p.spawn();
    (p, h)
}

fn cluster(net: &Arc<Net>, n: usize) -> Vec<Arc<Peers>> {
    ids(n).iter().map(|id| start(net, id, &format!("{id}-1"), n).0).collect()
}

fn liveness(p: &Peers, id: &str, inc: &str) -> Liveness {
    p.verdict(id, inc).unwrap().liveness
}

#[test]
fn quorum_rules_are_vlrelays() {
    assert_eq!((quorum(1), quorum(2), quorum(3), quorum(4), quorum(5)), (1, 2, 2, 3, 3));
    let m = ids(3);
    let w = Duration::from_secs(1);
    let ages = |a: &str| match a {
        "n1" => Some(Duration::from_millis(500)),
        "n2" => Some(Duration::from_secs(5)),
        _ => None,
    };
    assert_eq!(heard_within(&m, "n0", ages, w).collect::<Vec<_>>(), ["n0", "n1"]);
    assert!(has_quorum(&m, "n0", ages, w));
    assert!(!has_quorum(&m, "n0", |_| None, w));
    assert!(has_quorum(&ids(1), "n0", |_| None, w), "a single member is its own quorum");
}

#[test]
fn config_is_checked() {
    let members = vec![("a".to_string(), String::new())];
    assert!(PeerConfig::new(member("a", "1"), members.clone()).validate().is_ok());
    assert!(PeerConfig::new(member("b", "1"), members.clone()).validate().is_err());
    let mut c = PeerConfig::new(member("a", "1"), members);
    c.dead_after = c.timeout * 2;
    assert!(c.validate().is_err());
}

#[tokio::test(start_paused = true)]
async fn a_healthy_cluster_is_live_and_may_write() {
    let net = Net::new();
    let ps = cluster(&net, 3);
    tokio::time::sleep(Duration::from_secs(3)).await;
    for p in &ps {
        assert!(p.may_write());
        assert_eq!(p.live().len(), 3);
        for q in &ps {
            assert_eq!(liveness(p, &q.me().node_id, &q.me().incarnation), Liveness::Live);
        }
    }
}

/// A node cut off from everyone stops writing within `timeout`, and the
/// others presume it dead only after `dead_after`: it stopped first.
#[tokio::test(start_paused = true)]
async fn a_partitioned_node_stops_before_it_is_presumed_dead() {
    let net = Net::new();
    let ps = cluster(&net, 3);
    tokio::time::sleep(Duration::from_secs(3)).await;
    net.isolate("n0", &ids(3));
    let cut = Instant::now();
    let (mut stopped, mut dead) = (None, None);
    while dead.is_none() || stopped.is_none() {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if stopped.is_none() && !ps[0].may_write() {
            stopped = Some(Instant::now());
        }
        if dead.is_none() && liveness(&ps[1], "n0", "n0-1") == Liveness::Dead {
            dead = Some(Instant::now());
        }
        // the cut-off node never presumes anyone dead: it has no quorum
        assert_ne!(liveness(&ps[0], "n1", "n1-1"), Liveness::Dead);
        assert!(Instant::now() - cut < Duration::from_secs(20));
    }
    let (stopped, dead) = (stopped.unwrap(), dead.unwrap());
    assert!(stopped - cut <= ps[0].config().timeout + ps[0].config().interval);
    // n1 last heard n0 up to an interval before the cut
    assert!(dead - cut >= ps[1].config().dead_after - ps[1].config().interval);
    assert!(stopped < dead);
    assert_eq!(liveness(&ps[2], "n0", "n0-1"), Liveness::Dead);
    assert!(ps[1].may_write() && ps[2].may_write());
    net.heal("n0");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(ps[0].may_write());
    assert_eq!(liveness(&ps[1], "n0", "n0-1"), Liveness::Live);
}

/// One observer that can't hear a node, while the rest of the quorum can,
/// can't declare it dead alone.
#[tokio::test(start_paused = true)]
async fn one_observer_cant_declare_a_live_node_dead() {
    let net = Net::new();
    let ps = cluster(&net, 3);
    tokio::time::sleep(Duration::from_secs(3)).await;
    net.cut("n2", "n0");
    net.cut("n0", "n2");
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        for p in &ps {
            assert!(p.may_write(), "{} still hears a quorum", p.me().node_id);
        }
        assert_ne!(liveness(&ps[2], "n0", "n0-1"), Liveness::Dead);
        assert_ne!(liveness(&ps[0], "n2", "n2-1"), Liveness::Dead);
    }
}

/// A crashed node's port refuses: that's taken as gone at once (vlRelay's
/// probe), so it's dead as soon as a quorum has tried it.
#[tokio::test(start_paused = true)]
async fn a_refused_port_is_dead_without_waiting() {
    let net = Net::new();
    let ps = cluster(&net, 3);
    tokio::time::sleep(Duration::from_secs(3)).await;
    ps[0].stop();
    net.leave("n0");
    let t = Instant::now();
    while liveness(&ps[1], "n0", "n0-1") != Liveness::Dead {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(Instant::now() - t < ps[1].config().timeout, "{:?}", Instant::now() - t);
}

/// A restart under the same id is a new incarnation: the old one is dead
/// once a quorum hears the new one.
#[tokio::test(start_paused = true)]
async fn a_restart_supersedes_the_old_incarnation() {
    let net = Net::new();
    let mut ps = cluster(&net, 3);
    tokio::time::sleep(Duration::from_secs(3)).await;
    ps[0].stop();
    let (p, _h) = start(&net, "n0", "n0-2", 3);
    ps[0] = p;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(liveness(&ps[1], "n0", "n0-1"), Liveness::Dead);
    assert_eq!(liveness(&ps[1], "n0", "n0-2"), Liveness::Live);
    assert_eq!(liveness(&ps[0], "n0", "n0-1"), Liveness::Dead);
    assert!(ps[1].incarnations()["n0"] == "n0-2");
}

/// A topology generation one node saw reaches every member with the beats.
#[tokio::test(start_paused = true)]
async fn beats_spread_the_topology_generation() {
    let net = Net::new();
    let ps = cluster(&net, 3);
    ps[2].saw_topology(7);
    ps[2].saw_topology(5);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(ps.iter().all(|p| p.topology() == 7));
}

/// Replica watermarks ride the beats, and routing reads them.
#[tokio::test(start_paused = true)]
async fn positions_ride_the_beats() {
    use crate::table::Assignment;
    use crate::topology::Topology;
    use vlsync_store::slots::ShardId;
    let net = Net::new();
    let ps = cluster(&net, 3);
    let s = ShardId(3);
    ps[1].set_position(&s.key(), 90);
    ps[2].set_position(&s.key(), 120);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(ps[0].position("n2", "n2-1", &s.key()), Some(120));
    assert_eq!(ps[0].position("n2", "n2-0", &s.key()), None);
    let a = Assignment {
        owner: Some(ps[0].me().clone()),
        replicas: vec![ps[1].me().clone(), ps[2].me().clone()],
        ..Default::default()
    };
    let t = Topology::from_table([(s, &a)]);
    let names = |v: Vec<Member>| v.into_iter().map(|m| m.node_id).collect::<Vec<_>>();
    assert_eq!(names(t.readable(s, 0, ps[0].as_ref())), ["n0", "n1", "n2"]);
    assert_eq!(names(t.readable(s, 100, ps[0].as_ref())), ["n2"]);
}

/// Two members can't fail over (a quorum of two always includes the
/// suspect), and an unknown node isn't judged.
#[tokio::test(start_paused = true)]
async fn two_members_never_presume_each_other_dead() {
    let net = Net::new();
    let ps = cluster(&net, 2);
    tokio::time::sleep(Duration::from_secs(3)).await;
    net.isolate("n0", &ids(2));
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(!ps[0].may_write() && !ps[1].may_write());
    assert_ne!(liveness(&ps[1], "n0", "n0-1"), Liveness::Dead);
    assert!(ps[1].verdict("zz", "1").is_none());
}

/// Beats over real TCP with the shared client, real clocks.
#[tokio::test]
async fn beats_over_tcp() {
    let mut listeners = Vec::new();
    let mut members = Vec::new();
    for i in 0..3 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        members.push((format!("n{i}"), l.local_addr().unwrap().to_string()));
        listeners.push(l);
    }
    let mut ps = Vec::new();
    let mut servers = Vec::new();
    for (i, l) in listeners.into_iter().enumerate() {
        let faults = Arc::new(Faults::default());
        let mut c = PeerConfig::new(
            Member { node_id: format!("n{i}"), incarnation: format!("n{i}-1"), addr: members[i].1.clone() },
            members.clone(),
        );
        c.interval = Duration::from_millis(50);
        c.timeout = Duration::from_millis(300);
        c.dead_after = Duration::from_millis(800);
        c.rpc_timeout = Duration::from_millis(200);
        let p = Peers::new(c, Arc::new(TcpTransport::new(&members, faults.clone()))).unwrap();
        p.spawn();
        servers.push(tokio::spawn(serve(l, p.clone(), faults)));
        ps.push(p);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    for p in &ps {
        assert!(p.may_write());
        assert_eq!(p.live().len(), 3);
    }
    // n0 exits: its port refuses, and the others presume it dead quickly
    ps[0].stop();
    servers[0].abort();
    let t = std::time::Instant::now();
    while liveness(&ps[1], "n0", "n0-1") != Liveness::Dead {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(t.elapsed() < Duration::from_secs(5), "n0 never presumed dead");
    }
    assert!(ps[1].may_write() && ps[2].may_write());
}
