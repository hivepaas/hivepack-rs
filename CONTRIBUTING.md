# Contributing

Open an issue before a large change. A pull request should pass what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The rules for `unsafe` code are in [docs/unsafe.md](docs/unsafe.md) and [docs/safety.md](docs/safety.md); how a port follows its library is in [docs/porting.md](docs/porting.md). A change to a port keeps its output the same as the original's, and its tests say how it was compared.

Contributions are under the repository's license (MIT, and the license of the original library for a port's crate).
