# vlsync: the crates vlpds, vlRelay and delta share. They build inside each
# user's workspace; this one builds and tests them on their own.

# Type-check every crate and its tests
check:
    cargo check --workspace --all-targets
    cargo check -p vlsync-store --features jemalloc,test-level
    cargo check -p vlsync-heapprof --all-features --all-targets

test *args:
    cargo test --workspace {{args}}

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# No private names or secrets (the public export's audit patterns; monorepo only)
check-private:
    python3 ../../scripts/vlsync-public/vlsync_public.py scan .

ci: fmt-check check-private check clippy test

# What uses vlsync, checked against this tree (vlpds, vlRelay and its interop
# tests, delta; monorepo only)
check-users:
    cd ../vlpds && cargo check --all-targets
    cd ../vlrelay && cargo check --all-targets
    cd ../vlrelay/interop && cargo check --all-targets
    cd ../delta && cargo check --workspace --all-targets
