# Leases, epochs and fencing (`vlsync-lease`)

vlRelay and vlpds both decide who may write by CAS on objects in the bucket, and each grew its own
copy of the parts. vlDB needs the same thing over many slot ranges per node, with replicas. So
`vlsync-lease` holds one implementation: typed CAS on JSON objects, epoch records and their fences,
node leases, and an assignment table over slot ranges with a topology routers can read in one GET.

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
would have cost ~$56 a month on R2 for three nodes (vlRelay `docs/design.md`), so vlRelay has no
leases. vlpds has no quorum, so it needs them. Its lease model is the part with the most care in
it: the holder's validity ends `skew` early on its own clock, the observer waits `skew` late on its
own clock, wall clocks are never compared, a renewal whose answer was lost is adopted, a lapsed
lease is never renewed, and a watchdog fail-stops a node whose store calls hang.

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
- range splits, which `vlsync_store::slots::Layout` already plans (`plan_split`, `flipped`), and
- one object a router reads to learn the whole topology.

That's vlpds's model (node leases plus per-shard CAS assignments with spans), generalized from log
ordinals to any position, with vlRelay's epoch fence as a primitive beside it.

## The crate

`crates/vlsync-lease`, on `vlsync-store` alone (no vlatproto, no firehose).

### Objects

| Key (under the store's prefix) | What | Written |
|---|---|---|
| `nodes/{node_id}` | `NodeLease<T>`: incarnation, address, renewal counter, `draining`, `ended`, `positions` (range key → applied position), a user body | By its holder every `renew_every` (at most once per `key_gap`, 1 s for R2), and once by a peer that fenced it (`ended`) |
| `assign/{shard}` | `Assignment`: epoch, version, owner, replicas, floor, history of spans, `frozen` | One CAS per acquire, release, handoff, freeze, replica change or trim |
| `assign/topology` | `Topology`: every range's epoch, version, owner and replicas | By any node, merged so a stale view can't roll a range back |
| `assign/layout` | `vlsync_store::slots::Layout` (not this crate's) | On splits and merges |

The keys match vlpds's, so the request metrics count them as `ctl_lease` and `ctl_assign`, and a
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
- `lease`: `Holder` (acquire, `renew`, `valid`, `spawn` for the renew loop and watchdog, `update`
  for what the next renewal publishes, `release`) and `Observer` (`observe` lists `nodes/`, GETs
  only changed ETags and judges each lease Live, Suspect or Dead, and `end` marks a fenced
  incarnation's lease ended).
- `table`: `Table` (`create`, `acquire`, `release` with or without a successor, `freeze`,
  `set_replicas`, `trim`, `refresh`, a watch of the topology) over `Assignment` (`accepts`,
  `authority_at`, `check`).
- `topology`: `Topology::publish`, `read`, `merge` and `readable(shard, min, &membership)`.
- `chaos` (feature `chaos`): `ChaosStore`, an object store with latency, errors before a request
  applies, lost answers after it applies, armed one-shot faults, and pause/resume.

### Leases and liveness

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
at least `key_gap` apart.

Leases are never deleted. A clean shutdown writes `ended` (`Holder::release`), and so does a peer
after fencing a dead incarnation (`Observer::end`, a CAS on the version it judged dead, so a lease
that renewed since is left alone). Every observer then judges it dead at once, and the id's next
incarnation writes over it. An unconditional delete could race a restart's create, and object
stores have no conditional delete.

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
- `acquire(shard, me, membership, fence)`: takes an unowned range, or one whose owner is dead. A
  dead owner is fenced first. The caller's `fence` gets the owner's open span and returns the last
  position that incarnation made durable for the range, after making sure it can't make anything
  past that durable (a create-only fence object at the end of its stream). Then one CAS closes the
  span there and opens ours right after. An owner counts as dead when the membership says so for
  its incarnation, when its lease names another incarnation, or when its lease is ended. A listing
  that predates the owner's lease is checked against a fresh read, so a new node isn't presumed
  dead.
- `freeze(shard, me, end, op)`: a release to nobody that also marks the range frozen for reshard op
  `op`. It's never acquired again. The children are then `create`d with `floor = end`.
- `create(shard, floor, owner)`: a record for a new range, where everything up to `floor` is
  already decided (a snapshot, a parent's freeze point).
- `trim(shard, below)`: drops closed spans that end below `below`, once a snapshot holds them.

`Assignment::accepts(epoch, incarnation, pos)` is the reader's side of fencing. A write is part of
the range's history only if the span covering its position belongs to that incarnation at that
epoch. A deposed owner's writes past its span's end are dropped by every reader, whatever it wrote
before it noticed.

### Replicas and the topology

Replicas are listed in the assignment and hold no epoch. Their progress rides on their own node
lease (`positions`, range key → applied position), which they renew anyway, so watermarks cost no
extra writes. A watermark is as fresh as the last renewal (TTL/5). A read that needs exactly
`min_seq` still asks the replica, which waits until it's past.

`Topology::publish` merges a node's view into `assign/topology`, keeping each range's highest
`version`. Any node can publish, and a stale publisher can't roll a range back. A router reads it
with one GET, then calls `readable(shard, min_seq, &membership)` for the owner and replicas whose
leases are up and past `min_seq`. The topology is a hint, so an owner refuses a request for a range
it doesn't hold and the router reads again.

### Why safety needs no clocks

Clocks decide when a node is presumed dead. A wrong verdict costs a fence and a fail-stop, never a
position decided twice:

1. Every change to a range is a CAS, so each epoch has one owner and one span.
2. A taker fences before its CAS, and the fence stops the old incarnation from making anything past
   `end` durable. So every durable write of the old owner is inside its closed span.
3. Readers keep only what `accepts` says, so writes past a span's end are never applied, even when
   the old owner's own check of its lease raced the takeover.
4. The holder stops at its validity, on a conflict, when ended, and at the watchdog.

The remaining assumptions are vlpds's (`DESIGN.md`, "Why safety needs no clocks"): clock rates
within `skew / TTL`, and a suspended process whose monotonic clock stopped wakes believing its lease
valid, then fails at its next fenced write.

## Users

vlRelay uses `cas` and `epoch` now. `read_leader`, `cas_leader`, `read_manifest`, `cas_manifest`
and the manifest fence (`flush::fence`, now `epoch::raise`) moved onto the crate with the same
error handling: `cas_leader` still treats only `Precondition` and `AlreadyExists` as a lost race,
and `cas_manifest` also treats `NotFound`, as before. vlRelay has no leases or assignment table, and
doesn't need them while its quorum gives it heartbeats.

vlpds is unchanged. Its `cluster.rs` (~4,900 lines) carries much more than leases: writer ids,
joins that wait for every peer to follow the joiner's log, `wm_cap` watermarks, feature levels, a
lease plane on its own runtime, revalidation of a lapsed lease over an unfenced log, and shard
history keyed to log ordinals with `applied_epoch` trimming. It's in production, so moving it is its
own project. The crate's lease and table follow vlpds's rules closely enough that a later
migration could start with `cas` (its `get_json`/`put_json`/`is_conflict`) and the `Observer`
verdicts.

## How vlDB P3 should use it

1. Each process makes a fresh incarnation id (a ULID), builds a `Store::s3_ctl` for its prefix and
   calls `Holder::acquire` with `LeaseConfig::new(node_id, addr, ttl)` (10 s TTL in production),
   then `spawn()`. When the lost watch fires, it stops serving writes and exits (vlpds exits 3).
2. A control loop every `renew_every`: `Observer::observe()`, `Table::refresh()`, then acquire up
   to its fair share of `Membership::settled()` and release what's over it.
3. Acquire passes a fence that fences the dead incarnation's enriched stream (`enrich/{incarnation}/`
   in vlsync segment format) with a create-only fence object at its first free ordinal, the way
   vlpds's `Cluster::fence_as` does, and returns the last relay seq that stream covered for the
   range. Segment headers need to carry the relay seq a segment covers through, not just its ops'
   seqs, so S is right for a range that had no ops near the end. After fencing everything an
   incarnation held, call `Observer::end` on its lease.
4. The owner enriches its range from `open_span().from` and tags every op with `(range, epoch)`.
   Before each segment PUT it checks `Holder::valid()`. A PUT that hits a fence means it was
   deposed, so it fail-stops.
5. To move a range: the new node clones the latest snapshot, replays to near the head, and joins as
   a replica (`set_replicas`). The owner then stops enriching at S, makes S durable, and calls
   `release(shard, me, S, Some(&new))`. The new owner enriches from S + 1 under the new epoch.
6. Appliers (the owner and every replica) keep an op only if `Assignment::accepts(op.epoch,
   stream_incarnation, op.seq)` for the op's range, using the record they read when they opened
   the range and re-reading it when they meet an epoch they don't know.
7. Replicas publish their applied seq per range in `positions` with `Holder::update`, and some node
   (the owner of slot 0's range, say) publishes `assign/topology` after every table change. Routers
   read the topology and the leases (`Observer`) and route with `Topology::readable`.
8. Splits: `Layout::plan_split` → `freeze(parent, me, S, op)` → `create(child, S, Some(owner))` for
   each child → `Layout::flipped` CASed into `assign/layout`. A child's spans start at S + 1 at
   epoch 1, so ops are tagged with the child range from then on.
9. `trim(shard, applied_seq)` after each snapshot keeps the history short.

One thing to settle in P3 that the crate leaves to vlDB: a node's enriched stream is shared by all
its ranges, so a range acquired while the node's stream is ahead of the range's `from` gets
catch-up ops below the stream's current seq. So the apply-side merge can't assume each stream is
sorted. Either it's gated on each stream's watermark, or the node writes catch-up ops to a side
stream.

## Tests

`cargo test -p vlsync-lease` (about a second, all on tokio's paused clock):

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
- Table: acquire, release and handoff with their spans and epochs, racing acquires have one winner,
  dead and superseded owners are fenced first, a listing that predates a lease doesn't presume a
  new node dead, freeze and seeded children, replicas and routing by watermark, trims, unknown
  fields survive a CAS, and racing topology publishers never roll a range back.
- Chaos (`table::tests::sim`, 16 seeds): four nodes, eight ranges, 90 s of crashes, stalls between
  a lease check and the writes it guarded (up to 6 s), handoffs, and a store with 40 ms of latency,
  3 % errors and 2 % lost answers, then 30 s of calm. Each node writes positions into its own
  fenceable stream. At the end every record passes `Assignment::check`, every write in every stream
  is accepted by its range's history, no position is decided twice, every closed span holds every
  position it claims, and every range has a live owner within 20 positions of the head. Each seed
  sees ~20 crashes, ~20 stalls, ~80 takeovers and ~120 handoffs. With the stream fence turned off
  the check catches a deposed owner's writes in most seeds.
