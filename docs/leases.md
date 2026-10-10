# Leases, epochs and fencing (`vlsync-lease`)

vlRelay and vlpds both decide who may write by CAS on objects in the bucket, and each grew its own
copy of the parts. vlDB needs the same thing over many slot ranges per node, with replicas. So
`vlsync-lease` holds one implementation. Safety lives in the bucket: typed CAS on JSON objects,
epoch records and their fences, and an assignment table over slot ranges with a topology routers
can read in one GET. Liveness is pluggable: bucket leases (vlpds's model) or peer heartbeats
(vlRelay's quorum rules), which cost no bucket requests at all.

## What vlRelay and vlpds do today

| | vlRelay (quorum log) | vlpds (cluster) |
|---|---|---|
| Who writes | One leader per epoch for the whole log | One owner per shard, many shards per node |
| Liveness | Peer heartbeats over TCP, `--qlog-election-timeout` | A lease per node at `nodes/{id}`, renewed by CAS every TTL/5 |
| Epoch record | `qlog/leader`: a candidate CASes it to epoch + 1 from the version it read | `assign/{shard}`: `epoch` + 1 on every acquire and handoff |
| Fence | The new leader raises `qlog/manifest` to its epoch before its first flush, so an old leader's manifest CAS fails | The taker writes a create-only fence object at the dead node's first free log ordinal, so the dead node's next segment PUT fails |
| What a deposed writer can't do | Commit a flush (the manifest is the commit point) | Make a segment durable past the fence (acks are in ordinal order) |
| History | The manifest's F and R | `Assignment.history`: spans of log ordinals per epoch |
| Clock use | None for safety. Timeouts decide when to campaign | None for safety. TTL + skew of the observer's monotonic clock decides when a node is presumed dead |
| Cost | Two objects, written once per flush (30 s) and per takeover | One lease write per node every TTL/5 (2 s at the 10 s default), assignment writes only on moves |

Both rest on the same three things:

- CAS on a JSON object, where `Precondition`, `AlreadyExists` and (on S3) a `NotFound` for an
  If-Match all mean someone else's write decided it. Both had their own `read_*`/`cas_*` pairs.
- An epoch that only grows, claimed by CAS from the version read, so each epoch has one writer.
- A fence that makes a deposed writer's next durable write fail, so safety never waits for it to
  notice. vlRelay fences the commit object (the manifest). vlpds fences the data (the log).

They differ in liveness. vlRelay's quorum already has heartbeats, and bucket leases with a 10 s TTL
would have cost ~$56 a month on R2 (vlRelay `docs/design.md`), so vlRelay has no leases. vlpds has
no quorum, so it needs them. Its lease model is the part with the most care in it: the holder's
validity ends `skew` early on its own clock, the observer waits `skew` late on its own clock, wall
clocks are never compared, a renewal whose answer was lost is adopted, a lapsed lease is never
renewed, and a watchdog fail-stops a node whose store calls hang.

## What vlDB needs

vlDB (the design is the vlIndex artifact, "Ownership, replicas and rebalancing") runs many slot
ranges per node. Each range has one owner that runs enrich and writes snapshots, and R − 1
replicas that replay the owner's enriched stream. Its control plane has to give it:

- per-range ownership with a fencing token, where moving a range costs one CAS and no renewals
  (64+ ranges renewing their own leases would be 64× the writes of one lease per node),
- an old owner that stops enriching at seq S, with everyone agreeing on S, whether it handed the
  range off or died,
- replicas whose watermarks routers can see, so a read with `min_seq` goes to a replica that's past
  it,
- range splits, which `vlsync_store::slots::Layout` already plans (`plan_split`, `flipped`),
- one object a router reads to learn the whole topology, and
- next to no class A requests at steady state. The bucket is written only when ownership changes
  (an epoch claim, an assignment, a fence object).

So vlDB P3 runs heartbeats for liveness and keeps every safety decision on R2.

## The crate

`crates/vlsync-lease`, on `vlsync-store` alone (no vlatproto, no firehose).

### Objects

| Key (under the store's prefix) | What | Written |
|---|---|---|
| `assign/{shard}` | `Assignment`: epoch, version, owner, replicas, floor, history of spans, `frozen` | One CAS per acquire, release, handoff, freeze, replica change or trim |
| `assign/topology` | `Topology`: every range's epoch, version, owner and replicas, and a `generation` | By any node after a table change, merged so a stale view can't roll a range back |
| `assign/layout` | `vlsync_store::slots::Layout` (not this crate's) | On splits and merges |
| `nodes/{node_id}` | `NodeLease<T>` (lease liveness only): incarnation, address, renewal counter, `draining`, `ended`, `positions`, a user body | By its holder every `renew_every`, and once by a peer that fenced it (`ended`) |

The keys match vlpds's, so the request metrics count them as `ctl_assign` and `ctl_lease`, and a
store from `Store::s3_ctl` gives lease writes the throttle-aware retry.

### Modules

- `cas`: `read`/`write` of a JSON object with an `Expect` (absent, or the ETag read), `moved()`
  for the three "someone else won" errors, and `update`, a read-modify-write loop that reads back
  after a conflict and takes a stored value equal to what it sent as its own landed write. A lost
  answer looks like a conflict through object_store (it retries, and the retry of a conditional PUT
  that already landed is refused), so that read-back is how every caller adopts one.
- `epoch`: `claim` (CAS to a higher epoch from the version read), `raise` (make a record this
  epoch's unless a newer one wrote it, retrying conflicts) and `holds` (is the record still at my
  epoch). These are vlRelay's `qlog/leader` takeover and `qlog/manifest` fence.
- `table`: `Table` (`create`, `acquire`, `release` with or without a successor, `freeze`,
  `set_replicas`, `trim`, `read`, `refresh`, a watch of the topology) over `Assignment`
  (`accepts`, `authority_at`, `check`).
- `topology`: `Topology::publish`, `read`, `merge` and `readable(shard, min, &alive)`.
- `alive`: the `Alive` trait, with `Leases` (a `Holder` plus an `Observer`), `Membership` (one
  listing) and `Peers` as implementations.
- `lease`: `Holder` (acquire, `renew`, `valid`, `spawn` for the renew loop and watchdog, `update`,
  `release`) and `Observer` (`observe`, `classify_at`, `end`).
- `peers`: `Peers` (heartbeats, `may_write`, `verdict`, `set_position`, `saw_topology`), vlRelay's
  quorum rules (`quorum`, `heard_within`, `has_quorum`), the `Transport` trait with `TcpTransport`
  and `serve`, and `mem::Net`, an in-memory network for tests.
- `rpc`: one TCP connection per peer, length-prefixed frames with a request id, a timeout, and
  `Faults` for in-process partitions. This is vlRelay's quorum-log client, moved here.
- `chaos` (feature `chaos`): `ChaosStore`, an object store with latency, errors before a request
  applies, lost answers after it applies, armed one-shot faults, and pause/resume.

### Liveness, pluggable

```rust
pub trait Alive {
    /// How node_id's incarnation stands (Live, Suspect, Dead) and as of
    /// what local monotonic instant. None: this source doesn't know it.
    fn verdict(&self, node_id: &str, incarnation: &str) -> Option<Heard>;
    /// The self-check: may this node still act as an owner?
    fn may_write(&self) -> bool;
    /// A replica's published watermark for a range.
    fn position(&self, node_id: &str, incarnation: &str, range: &str) -> Option<u64>;
    /// An incarnation the source doesn't know: may it still be acting?
    async fn confirm_up(&self, store: &Store, node_id: &str, incarnation: &str) -> Result<bool>;
}
```

`Table::acquire` takes any `Alive`. It refuses to take anything while `may_write` is false
(`Acquired::Unable`), takes a range from its owner only on a Dead verdict, and fences that owner
first either way. So a liveness source decides when a range moves, and never whether a position is
decided twice.

### Bucket leases (`Leases`)

A node writes its lease once per process start under a fresh incarnation id. If its id already has
a lease (an earlier incarnation), the write is a CAS over it, so assignments that name the old
incarnation now name one whose lease is gone. That's how peers know to fence it, even when the
restart was faster than the TTL.

The holder may act until `sent + TTL − skew` on its monotonic clock, where `sent` is when its last
landed write left. An observer presumes it dead once the lease hasn't changed for `TTL + skew` of
the observer's monotonic clock, counted from when it first saw the current version. The observer
saw that version no earlier than it was sent, so the holder stops first as long as clock rates stay
within `skew / TTL` of each other (20 % at the default ratios, `LeaseConfig::max_drift`). Wall
clocks only go into `expires_ms`, which is for people.

The holder stops on its own when:

- a renewal's CAS finds the lease isn't its own write (another incarnation took it: `Lost::Taken`),
- the stored lease is its incarnation marked `ended` by a peer (`Lost::Ended`),
- a renewal is due and validity already ran out (`Lost::Lapsed`). A lapsed lease is never renewed,
  since peers may have fenced it meanwhile.
- the watchdog sees validity over for 2 × skew without a landed renewal (`Lost::Lapsed`). That
  covers a store that hangs instead of failing.

A renewal whose answer was lost is adopted. Only the holder writes its incarnation without `ended`,
so a stored lease with our incarnation and our renewal count is our write. Writes to one lease are
at least `key_gap` apart (1 s for R2).

Leases are never deleted. A clean shutdown writes `ended` (`Holder::release`), and so does a peer
after fencing a dead incarnation (`Observer::end`, a CAS on the version it judged dead, so a lease
that renewed since is left alone). Every observer then judges it dead at once, and the id's next
incarnation writes over it. An unconditional delete could race a restart's create, and object
stores have no conditional delete.

### Peer heartbeats (`Peers`)

The rules are vlRelay's quorum log's, and vlRelay now calls them from here:

- A member counts as heard if a message from it arrived within a window (`heard_within`, which is
  vlRelay's `Node::live_members`).
- A node that hasn't heard a quorum (itself included) within the window stops. vlRelay's leader
  steps down on `has_quorum` failing. A `Peers` node's `may_write` turns false.
- A minority never acts on its own view. vlRelay's candidate needs a quorum reachable before it
  takes over. A `Peers` node needs a quorum's agreement before it calls anyone dead.
- A refused port means the process is gone (vlRelay's probe), so there's no waiting for a timeout.

`Peers` runs them for a symmetric cluster. Members come from a seed list in config (a membership
change is a restart with a new list). Every `interval` each node beats every other member over a
`Transport`, each call on its own task so a member that's down holds up nobody (vlRelay's
`broadcast`). A beat carries the sender's incarnation, its view of every member (which incarnation
it last heard and how long ago, as an age on its own clock), the newest topology generation it
knows, and its replica positions. The reply is the receiver's beat.

- Self-check: `may_write` is true while a quorum of members, this node included, was heard within
  `timeout`.
- Verdict: an incarnation is Dead only when this node may write and a quorum of members, counting
  this node and never the suspect, each report not having heard it for `dead_after` (or hearing a
  newer incarnation under its id, or a refused port). A peer's report counts only if it arrived
  within `timeout`, and its age is extended by the time since, on our clock. A node cut off from the
  quorum can't call anyone dead, and one observer that can't reach a node can't either while the
  others still hear it.
- Ordering: if X wrote at time t, it heard a quorum Q within `timeout` before t. A quorum that
  declares X dead (without X) always shares a member with Q, since 2 × quorum − 1 ≥ n. That member
  heard X when it answered, so with `dead_after > 2 × timeout + interval` X has stopped before a
  quorum agrees it's dead (`PeerConfig::validate` checks the inequality). Clock rates only need to
  stay close enough that `dead_after` still exceeds that sum.
- Defaults (`PeerConfig::new`): beats every 500 ms, `timeout` 2 s, `dead_after` 5 s, 500 ms per
  beat. A crash is seen in about one beat (the port refuses). A partitioned node stops writing
  within ~2.5 s and its ranges move after ~5 s.
- Failover needs three members or more. With two, a quorum of two always includes the suspect, so
  neither ever declares the other dead (and both stop writing when they can't reach each other).

Safety doesn't rest on any of that. If a node's self-check is wrong (a clock jump, a bug, a stall
between the check and the write), peers that take its ranges fence it first, and its next durable
write fails.

### Costs

R2 bills class A (PUT, LIST, copy) at $4.50 a million and class B (GET, HEAD) at $0.36 a million.
A 30-day month is 2.59M seconds. Per node:

| | Leases (TTL 10 s, renew every 2 s) | Heartbeats |
|---|---|---|
| Liveness writes | 1 lease PUT / 2 s = 1.30M class A = $5.83 | 0 |
| Liveness reads | 1 LIST of `nodes/` / 2 s = 1.30M class A = $5.83, plus a GET per changed peer lease: (n − 1) × 1.30M class B, $1.40 at n = 4 | 0 |
| Learning table changes | A LIST of `assign/` per step: 1.30M class A = $5.83 (or the topology GET below) | One GET of `assign/topology` when a beat names a newer generation: ~0 |
| Steady state, per node | ~$13 a month (~$19 with the table LIST), so ~$52 to ~$76 for 4 nodes | $0 |
| Network | none | n − 1 beats per `interval`, ~6 small messages a second per node at 4 nodes |

Both models pay the same for ownership changes, which are rare:

- A takeover of one range costs ~4 class A: the fence (a LIST of the dead stream's ordinals and a
  create-only PUT), the assignment CAS, and a topology publish (plus ~3 class B reads).
- A handoff costs 2 class A (the CAS and a topology publish).
- A node dying with 16 ranges moves them for ~64 class A, about $0.0003.

R2's free tier (1M class A and 10M class B a month per account) covers the heartbeat model's
ownership changes many times over. It doesn't cover the lease model's ~3.9M class A per node.

### Assignments, epochs and spans

A range's `epoch` is its fencing token. It grows by one on every change of who may write the range
(acquire, release, handoff, freeze), and never otherwise. Replica changes and trims bump only
`version`, which routers use to keep the newest view.

`history` is the list of spans `[from, until]` each epoch decided, contiguous and in epoch order.
The open span (no `until`) is the owner's and starts at `floor + 1`. Positions are the user's to
define. For vlDB they're relay seqs, and for a vlpds-style shard they'd be log ordinals.

- `release(shard, me, end, to)`: the owner stops writing at `end` first, then one CAS closes its
  span at `end` and, with a successor, opens the successor's span at `end + 1` under the next
  epoch. This is the cooperative handoff. A span that decided nothing is dropped.
- `acquire(shard, me, &alive, fence)`: takes an unowned range, or one whose owner is dead. A dead
  owner is fenced first. The caller's `fence` gets the owner's open span and returns the last
  position that incarnation made durable for the range, after making sure it can't make anything
  past that durable (a create-only fence object at the end of its stream). Then one CAS closes the
  span there and opens ours right after. An incarnation `alive` doesn't know (a lease listing that
  predates it) is checked against a fresh read of its lease, so a new node isn't presumed dead.
- `freeze(shard, me, end, op)`: a release to nobody that also marks the range frozen for reshard op
  `op`. It's never acquired again. The children are then `create`d with `floor = end`.
- `create(shard, floor, owner)`: a record for a new range, where everything up to `floor` is
  already decided (a snapshot, a parent's freeze point).
- `trim(shard, below)`: drops closed spans that end below `below`, once a snapshot holds them.

`Assignment::accepts(epoch, incarnation, pos)` is the reader's side of fencing. A write is part of
the range's history only if the span covering its position belongs to that incarnation at that
epoch. A deposed owner's writes past its span's end are dropped by every reader, whatever it wrote
before it noticed.

An op that fails may still have landed (a write whose answer was lost, then a failed read-back).
`Table` then drops its cached record, so `owned_by` stops naming the range until a fresh read. An
owner that resumed writing on the strength of the old cache could write past a handoff that did
land, into a span nobody fenced (no fence protects a cooperative handoff). The chaos sim found this
with heartbeat liveness, where the table is read rarely.

### Replicas and the topology

Replicas are listed in the assignment and hold no epoch. Their watermarks ride on what they already
send: their beats (`Peers::set_position`) or their lease (`positions`). So watermarks cost no extra
requests, and they're as fresh as the last beat or renewal. A read that needs exactly `min_seq`
still asks the replica, which waits until it's past.

`Topology::publish` merges a node's view into `assign/topology`, keeping each range's highest
`version` and bumping `generation`. Any node can publish, and a stale publisher can't roll a range
back. A router reads it with one GET, then calls `readable(shard, min_seq, &alive)` for the owner
and replicas that are up and past `min_seq`. The topology is a hint, so an owner refuses a request
for a range it doesn't hold and the router reads again.

### Why safety needs no clocks

Clocks decide when a node is presumed dead. A wrong verdict costs a fence and a fail-stop, never a
position decided twice:

1. Every change to a range is a CAS, so each epoch has one owner and one span.
2. A taker fences before its CAS, and the fence stops the old incarnation from making anything past
   `end` durable. So every durable write of the old owner is inside its closed span.
3. Readers keep only what `accepts` says, so writes past a span's end are never applied, even when
   the old owner's self-check raced the takeover.
4. An op with an unknown outcome makes the cached record unknown, so a handoff that landed can't be
   written past.
5. Each node stops on its own self-check: lease validity, a conflict, `ended`, the watchdog, or no
   quorum heard.

The remaining assumptions are vlpds's (`DESIGN.md`, "Why safety needs no clocks"): clock rates
within the margin each model leaves, and a suspended process whose monotonic clock stopped wakes
believing it may write, then fails at its next fenced write.

## Users

vlRelay uses `cas`, `epoch`, `rpc` and the quorum rules in `peers`. `read_leader`, `cas_leader`,
`read_manifest`, `cas_manifest` and the manifest fence (`flush::fence`, now `epoch::raise`) moved
onto the crate with the same error handling. Its peer client (`qlog::node::Rpc`, `CallError`,
`Faults`) is now `rpc::Rpc<Msg>` with `Msg` implementing `rpc::Wire`, and its frame reads and
writes go through `rpc::read_frame` and `rpc::write_frame` (same framing, same limits, same "qlog:
frame too large"). Its leader's step-down (`has_quorum` over `acked_at` within the election
timeout), `live_members` (`heard_within`) and `quorum` are the crate's functions. The rest of its
heartbeat path stays in vlRelay: appends are its heartbeats, and the follower's election timer and
probe live in its node's core, since they're tied to the Raft-style log. vlRelay doesn't use
`Peers`, the table or leases.

vlpds is unchanged. Its `cluster.rs` (~4,900 lines) carries much more than leases: writer ids,
joins that wait for every peer to follow the joiner's log, `wm_cap` watermarks, feature levels, a
lease plane on its own runtime, revalidation of a lapsed lease over an unfenced log, and shard
history keyed to log ordinals with `applied_epoch` trimming. It's in production, so moving it is its
own project. The crate's lease and table follow vlpds's rules closely enough that a later
migration could start with `cas` (its `get_json`/`put_json`/`is_conflict`) and the `Observer`
verdicts.

## How vlDB P3 should use it

Heartbeats for liveness, R2 only for safety:

1. Each process makes a fresh incarnation id (a ULID) and builds `PeerConfig::new(me, members)`
   from a seed list of at least three members (node id and peer address). It answers beats on its
   own RPC by calling `Peers::on_beat`, with a `Transport` that sends them the same way (or uses
   `TcpTransport` and `peers::serve`), then calls `spawn()`.
2. At startup it reads the table once (`Table::refresh`, a LIST) and the topology. After that it
   reads `assign/topology` (one GET) only when `Peers::topology()` names a newer generation than it
   last read, and reads one range's record (`Table::read`, a GET) before acting on it. Nothing polls
   the bucket.
3. A control loop every `interval` or so: acquire up to its fair share of `Peers::live()` and hand
   off what's over it. `Table::acquire(shard, &me, &*peers, fence)` returns `Unable` while this node
   has no quorum.
4. The fence fences the dead incarnation's enriched stream (`enrich/{incarnation}/` in vlsync
   segment format) with a create-only fence object at its first free ordinal, the way vlpds's
   `Cluster::fence_as` does, and returns the last relay seq that stream covered for the range.
   Segment headers need to carry the relay seq a segment covers through, not just their ops' seqs,
   so S is right for a range that had no ops near the end.
5. After any table change, publish the topology and pass its generation to `Peers::saw_topology`,
   so the beats tell everyone to read it.
6. The owner enriches its range from `open_span().from` and tags every op with `(range, epoch)`.
   Before each segment PUT it checks `Peers::may_write()`. A PUT that hits a fence means it was
   deposed, so it fail-stops.
7. To move a range: the new node clones the latest snapshot, replays to near the head, and joins as
   a replica (`set_replicas`). The owner then stops enriching at S, makes S durable, and calls
   `release(shard, me, S, Some(&new))`. The new owner enriches from S + 1 under the new epoch. If
   the release fails, the owner doesn't resume the range until a fresh `Table::read` says it still
   owns it.
8. Appliers (the owner and every replica) keep an op only if `Assignment::accepts(op.epoch,
   stream_incarnation, op.seq)` for the op's range, using the record they read when they opened the
   range and re-reading it when they meet an epoch they don't know.
9. Replicas publish their applied seq per range with `Peers::set_position`. Members route with
   `Topology::readable(shard, min_seq, &*peers)`. A router that isn't a member asks a member, or
   P3 gives routers a listen-only `Peers` (not built yet).
10. Splits: `Layout::plan_split` → `freeze(parent, me, S, op)` → `create(child, S, Some(owner))`
    for each child → `Layout::flipped` CASed into `assign/layout`. A child's spans start at S + 1 at
    epoch 1, so ops are tagged with the child range from then on.
11. `trim(shard, applied_seq)` after each snapshot keeps the history short.

One thing to settle in P3 that the crate leaves to vlDB: a node's enriched stream is shared by all
its ranges, so a range acquired while the node's stream is ahead of the range's `from` gets
catch-up ops below the stream's current seq. So the apply-side merge can't assume each stream is
sorted. Either it's gated on each stream's watermark, or the node writes catch-up ops to a side
stream.

## Tests

`cargo test -p vlsync-lease` (~3 s, all on tokio's paused clock but one TCP test):

- CAS: create-once, If-Match, racing read-modify-writes lose nothing, a stale cached read costs one
  read, a write whose answer was lost is adopted.
- Epochs: one winner per epoch among racing claimers, raises never lower the epoch, an older
  writer's raise reports it was fenced.
- Leases: the holder's validity ends before an observer that keeps observing presumes it dead,
  wall clocks an hour apart change nothing, clock rates within `max_drift` keep that order and past
  it they don't, the key gap holds, a restart under the same id takes the lease, a lost renewal
  answer is adopted, a lapsed lease is never renewed, `end` and `release` end an incarnation at
  once, and six holders on a store with 5 % errors, 2 % lost answers and 300 ms of latency keep
  their leases for two minutes.
- Heartbeats: vlRelay's quorum rules, a partitioned node stops writing before the others presume
  it dead (and never presumes anyone dead itself), one observer that can't hear a node can't
  declare it dead while the rest still hear it, a refused port is dead within a beat, a restart
  supersedes the old incarnation, two members never fail over, the topology generation and replica
  positions ride the beats, and three nodes beat over real TCP.
- Table: acquire, release and handoff with their spans and epochs, racing acquires have one winner,
  dead and superseded owners are fenced first, a listing that predates a lease doesn't presume a
  new node dead, freeze and seeded children, replicas and routing by watermark, trims, unknown
  fields survive a CAS, an op with an unknown outcome forgets the record, and racing topology
  publishers never roll a range back.
- A partitioned owner that keeps writing after it lost its quorum is declared dead, its range is
  taken, and its next write fails through the fence, with nothing lost or doubled
  (`a_partitioned_owner_declared_dead_fails_its_next_write`).
- Chaos (`table::tests::sim`): four nodes, eight ranges, 90 s of crashes, stalls between a
  self-check and the writes it guarded (up to 6 s), handoffs, and a store with 40 ms of latency,
  3 % errors and 2 % lost answers, then 30 s of calm. With heartbeats there are also network
  partitions of up to 10 s, half of them with the cut-off node ignoring its self-check and writing
  on, and nodes read the table only every 2 s. Each node writes positions into its own fenceable
  stream. At the end every record passes `Assignment::check`, every write in every stream is
  accepted by its range's history, no position is decided twice, every closed span holds every
  position it claims, and every range has a live owner within 20 positions of the head. 16 seeds
  run for each liveness model, and `many_seeds` (ignored, ~45 s) runs 112 more of each. Without the
  stream fence the same checks catch deposed owners' writes in 6 to 8 of 8 seeds with leases and 3
  to 4 of 8 with heartbeats (runs vary a little, since some of the sim's maps iterate in random
  order).
