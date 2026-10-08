# vlsync

The Rust crates vlpds, vlRelay and delta share: the object-store layer, the
log segment format, atproto's data model and crypto, and the firehose. Each
user depends on the crates by path, so building deltad or vlRelay compiles
these and not the PDS.

| Crate | What | Used by |
|-------|------|---------|
| `vlsync-store` | The S3/R2 client with per-component request accounting, in-flight limits and throttle counts (`store`, `objstats`, `objlimit`, `throttle`, `store_stats`); the log segment format (`segment`) and the feature levels that gate it (`version`); slots and slot-major SlateDB keys (`slots`, `keys`); process lifecycle, the `/metrics` registry with process, tokio and jemalloc stats, secret files | vlpds, vlRelay, delta |
| `vlsync-atproto` | DAG-CBOR, CIDs, TIDs, CARs, the MST, K-256 keys, firehose frames, PLC operation types, identifier syntax, DID resolution, the shared outbound HTTP clients (`public`, the SSRF-guarded `guarded`), XRPC errors and admin-token checks | vlpds, vlRelay |
| `vlsync-firehose` | A node log in the bucket as its readers see it (`log`: paths, headers, the gap-free prefix, `retain/` reports, writer seqs), the firehose that merges logs into one seq-ordered subscribeRepos stream, and cursor backfill from S3 | vlpds, vlRelay |
| `slate-metrics` | SlateDB's metrics in Prometheus with a `db` label, and each database's LSM shape | vlpds, vlRelay |
| `vlsync-slatedb` | The SlateDB fork rev every user builds against, in one place | all of the above |

## Using a crate

```toml
[dependencies]
vlsync-store = { path = "../vlsync/crates/vlsync-store" }
# SlateDB comes from the fork pin, under its usual name:
slatedb = { package = "vlsync-slatedb", path = "../vlsync/crates/vlsync-slatedb" }
```

No user has a `[patch.crates-io]` for SlateDB: `vlsync-slatedb` depends on the
fork by git rev (its Cargo.toml lists the fork's patches) and re-exports it,
so `slatedb::...` paths stay as they were. Bumping the fork is one edit there.

Features:

- `vlsync-store/jemalloc`: jemalloc's stats in `/metrics` (`vlpds_jemalloc_bytes`), for a
  binary whose global allocator is jemalloc.
- `vlsync-store/test-level`: TEST ONLY, the test feature level (a different segment magic and
  header), for rolling-upgrade tests.
- `vlsync-atproto/test-clock`: TEST ONLY, `tid::set_test_skew_us`.

Metric names keep their `vlpds_` prefix: dashboards and alerts of all three
read them.

## Working on it

```sh
just check         # every crate, every target
just test          # the crates' own tests
just check-users   # vlpds, vlRelay and delta against this tree
just ci            # fmt, the private-name scan, check, clippy, test
```

A change here can break a user that compiles fine alone: run `just
check-users` before committing, and the users' suites for anything
behavioral. vlsync is published with vlpds (github.com/jazware/vlpds, at
`vlsync/`), so `just check-private` keeps private hostnames, addresses and
accounts out of it.
