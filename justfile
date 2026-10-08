# vlsync: the crates vlpds, vlRelay and delta share. They build inside each
# user's workspace; this one builds and tests them on their own.

# Type-check every crate and its tests
check:
    cargo check --workspace --all-targets
    cargo check -p vlsync-store --features jemalloc,test-level

test *args:
    cargo test --workspace {{args}}

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# vlsync is published in jazware/vlpds as it is (scripts/vlpds-public): no private names or secrets here
check-private:
    python3 ../../scripts/vlpds-public/vlpds_public.py scan .

ci: fmt-check check-private check clippy test

# What uses vlsync, checked against this tree (vlpds, vlRelay, delta)
check-users:
    cd ../vlpds && cargo check --all-targets
    cd ../vlrelay && cargo check --all-targets
    cd ../delta && cargo check --workspace --all-targets
