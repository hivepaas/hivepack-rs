# Contributing

Open an issue before a large change. A pull request should pass what CI runs:

```sh
scripts/check.sh
cargo test --workspace --locked
```

`scripts/check.sh` runs the format, clippy and the docs as CI does, and builds what CI builds that `cargo clippy --workspace` does not: the fuzz targets, a workspace of their own, and Windows' and macOS' own code, where those targets are installed (`rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin`).

A pull request runs what is quick: every test on every system and 32-bit (i686), and each fuzz target for 10 seconds; one that changes only `docs/` or Markdown runs nothing. `main` runs it all on every push: the big-endian job, s390x, which is emulated and takes most of an hour, and each fuzz target for as long as CI's step says. A pull request labelled `full-ci` runs as `main` does, as one that changes how bytes are read or written, or a fuzz target's code, should. Under emulation (`HIVEPACK_EMULATED`), the tests that compare threads run one thread and two, not eight and all (`tests/threads_support`).

The rules for `unsafe` code are in [docs/unsafe.md](docs/unsafe.md) and [docs/safety.md](docs/safety.md); how a port follows its library is in [docs/porting.md](docs/porting.md). A change to a port keeps its output the same as the original's, and its tests say how it was compared.

Contributions are under the repository's license (MIT, and the license of the original library for a port's crate).
