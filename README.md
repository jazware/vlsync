# vlsync

The Rust crates vlpds, vlRelay and delta share: the object-store layer, the
log segment format, the node logs and the firehose that serves them, and the
SlateDB pin. Building deltad or vlRelay compiles these and not the PDS.
atproto itself (CBOR, CIDs, the MST, crypto, firehose frames) is
[vlatproto](https://github.com/jazware/vlatproto), which `vlsync-firehose`
builds on and `vlsync-store` doesn't, so deltad doesn't compile it.

Its public home is [github.com/jazware/vlsync](https://github.com/jazware/vlsync).
Its history there starts when the crates moved out of vlpds; the files'
earlier history is [jazware/vlpds](https://github.com/jazware/vlpds)'s
(`src/store.rs`, `src/segment.rs`, `src/firehose.rs` and the rest).

| Crate | What | Used by |
|-------|------|---------|
| `vlsync-store` | The S3/R2 client with per-component request accounting, in-flight limits and throttle counts (`store`, `objstats`, `objlimit`, `throttle`, `store_stats`); the log segment format (`segment`) and the feature levels that gate it (`version`); slots and slot-major SlateDB keys (`slots`, `keys`); process lifecycle, the `/metrics` registry with process, tokio and jemalloc stats, secret files | vlpds, vlRelay, delta |
| `vlsync-firehose` | A node log in the bucket as its readers see it (`log`: paths, headers, the gap-free prefix, `retain/` reports, writer seqs), the firehose that merges logs into one seq-ordered subscribeRepos stream, and cursor backfill from S3 | vlpds, vlRelay |
| `slate-metrics` | SlateDB's metrics in Prometheus with a `db` label, and each database's LSM shape | vlpds, vlRelay |
| `vlsync-lease` | Ownership with safety in the bucket and pluggable liveness ([docs/leases.md](docs/leases.md)): typed CAS on JSON objects, epoch records and their fences (`qlog/leader`, `qlog/manifest`), an assignment table over slot ranges with epochs, spans, replicas and a published topology; liveness by bucket leases judged on each node's own monotonic clock, or by peer heartbeats with vlRelay's quorum rules (no bucket requests); vlRelay's peer RPC client; a chaos object store and in-memory network for tests (feature `chaos`) | vlRelay (CAS, epochs, RPC, quorum rules), vlDB |
| `vlsync-heapprof` | Continuous jemalloc heap profiles: `malloc_conf!` starts the sampler (one allocation per 512 KiB) with the process, and `GET /debug/pprof/heap` (the `axum` feature) answers the heap in use as Go's pprof, symbolized in process | vlpds, vlRelay, delta |
| `vlsync-slatedb` | The SlateDB fork rev every user builds against, in one place | all of the above |

## Using a crate

In the monorepo, by path:

```toml
[dependencies]
vlsync-store = { path = "../vlsync/crates/vlsync-store" }
# SlateDB comes from the fork pin, under its usual name:
slatedb = { package = "vlsync-slatedb", path = "../vlsync/crates/vlsync-slatedb" }
```

Elsewhere, by git rev (the public vlpds and vlRelay pin the commit that
matches theirs):

```toml
vlsync-store = { git = "https://github.com/jazware/vlsync", rev = "<commit>" }
slatedb = { package = "vlsync-slatedb", git = "https://github.com/jazware/vlsync", rev = "<commit>" }
```

No user has a `[patch.crates-io]` for SlateDB: `vlsync-slatedb` depends on the
fork by git rev (its Cargo.toml lists the fork's patches) and re-exports it,
so `slatedb::...` paths stay as they were. Bumping the fork is one edit there.

Features:

- `vlsync-store/jemalloc`: jemalloc's stats in `/metrics` (`vlpds_jemalloc_bytes`), for a
  binary whose global allocator is jemalloc.
- `vlsync-store/test-level`: TEST ONLY, the test feature level (a different segment magic and
  header), for rolling-upgrade tests.
- `vlsync-heapprof/axum`: `handler()` for `GET /debug/pprof/heap` and `from_loopback()`, the
  check that a request came from this host and no proxy. Depending on the crate at all builds
  the binary's jemalloc with profiling, which costs nothing until `malloc_conf!` turns it on.

Metric names keep their `vlpds_` prefix: dashboards and alerts of all three
read them.

## Working on it

```sh
just check         # every crate, every target
just test          # the crates' own tests
just check-users   # vlpds, vlRelay and delta against this tree (monorepo only)
just ci            # fmt, the private-name scan, check, clippy, test
```

A change here can break a user that compiles fine alone: run `just
check-users` before committing, and the users' suites for anything
behavioral. `just check-private` keeps private hostnames, addresses and
accounts out of it, as the public export's audit does.

## License

MIT
