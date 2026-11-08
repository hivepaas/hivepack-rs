# Contributing

Open an issue before a large change. A pull request should pass what CI runs:

```sh
scripts/check.sh
cargo test --workspace --locked
```

`scripts/check.sh` runs the format, clippy and the docs as CI does, and builds what CI builds that `cargo clippy --workspace` does not: the fuzz targets, a workspace of their own, and Windows' and macOS' own code, where those targets are installed (`rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin`).

The rules for `unsafe` code are in [docs/unsafe.md](docs/unsafe.md) and [docs/safety.md](docs/safety.md); how a port follows its library is in [docs/porting.md](docs/porting.md). A change to a port keeps its output the same as the original's, and its tests say how it was compared.

Contributions are under the repository's license (MIT, and the license of the original library for a port's crate).
