#!/bin/sh
# What CI checks, run on a computer before a pull request: the format, clippy
# and the docs as CI runs them; and what only CI found before, as it builds
# them and a computer's `cargo clippy --workspace` does not: the fuzz targets,
# a workspace of their own, and the code of other systems (Windows' and
# macOS' own calls), checked from any system where their targets are
# installed (`rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin`).
set -eu
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --locked --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --all-features
python3 -m py_compile scripts/testdata.py

# The fuzz targets, built as `cargo fuzz` builds them, without running them.
(cd fuzz && RUSTFLAGS="--cfg fuzzing" cargo check --features unsafe-fast --bins)

# Windows' and macOS' own code, where their targets are installed.
installed=$(rustup target list --installed)
for target in x86_64-pc-windows-msvc aarch64-apple-darwin; do
    if echo "$installed" | grep -qx "$target"; then
        cargo clippy -p hivepack --all-features --target "$target" --locked -- -D warnings
    else
        echo "skipped $target: rustup target add $target"
    fi
done
echo "all checked"
