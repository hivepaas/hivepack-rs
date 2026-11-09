# Contributing

Open an issue before a large change. A pull request should pass what CI runs:

```sh
scripts/check.sh
cargo test --workspace --locked
```

`scripts/check.sh` runs the format, clippy and the docs as CI does, and builds what CI builds that `cargo clippy --workspace` does not: the fuzz targets, a workspace of their own, and Windows' and macOS' own code, where those targets are installed (`rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin`).

A pull request runs what is basic, and `main` runs as much as there is, on every push:

| | A pull request | `main`, or a pull request labelled `full-ci` |
|---|---|---|
| The tests | every system's whole suite; arm64's as packwing builds hivepack (`unsafe-fast`, `memory`); the `unsafe-fast` modules on their own on Linux, and deflate's on macOS | as well, every system's whole suite with `unsafe-fast` and `memory`, and the `unsafe-fast` modules on every system |
| 32-bit (i686) | yes | yes |
| Big-endian (s390x), emulated, most of an hour | no | yes |
| The fuzz targets of the `unsafe-fast` code (`decompress`, `compress`, `lz4`, `hw_crc`) | their whole time | their whole time |
| The other fuzz targets | 10 seconds each | their whole time, and the formats' again with `unsafe-fast` |

A pull request that changes only `docs/` or Markdown runs nothing. Label `full-ci` one that changes how bytes are read or written, the `unsafe-fast` code, or a fuzz target. Under emulation (`HIVEPACK_EMULATED`), the tests that compare threads run one thread and two, not eight and all (`tests/threads_support`).

The rules for `unsafe` code are in [docs/unsafe.md](docs/unsafe.md) and [docs/safety.md](docs/safety.md); how a port follows its library is in [docs/porting.md](docs/porting.md). A change to a port keeps its output the same as the original's, and its tests say how it was compared.

Contributions are under the repository's license (MIT, and the license of the original library for a port's crate).
