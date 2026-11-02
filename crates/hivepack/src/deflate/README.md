# hivepack::deflate

Deflate, zlib and gzip compression and decompression in safe Rust, ported from the official library, [zlib](https://zlib.net) 1.3.2.

> **Status:** compression gives zlib's output, byte for byte, at every level, strategy, memory level and flush, and decompression zlib's results and messages, raw or with the zlib and gzip wrappers, with dictionaries and gzip headers. It decodes Deflate64 too, ZIP's method 9, as zlib's `contrib/infback9` does, whole or a piece at a time. All run at about zlib's speed on x86-64 (Silesia). This crate is not on crates.io.

```rust
use hivepack::deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};

// "hello", deflated with no header or trailer, as in a ZIP archive.
let raw = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
let mut inflate = Inflate::new(-15)?;
let mut out = [0; 16];
let mut output = OutBuffer::new(&mut out);
let status = inflate.inflate(&mut output, &mut InBuffer::new(&raw), Flush::Finish)?;
assert_eq!(status, Status::StreamEnd);
let written = output.pos;
assert_eq!(&out[..written], b"hello");
```

It also has zlib's checksums, `crc32` and `adler32`, with their `_combine` functions.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../../../docs/safety.md).
- **The same output as zlib.** Compressed output is identical byte for byte; decompression gives the same output, return codes and error messages.
- **The same speed as zlib**, on x86-64 and arm64.

How the port follows zlib, how it is checked, and what is left are in [docs/deflate.md](../../../../docs/deflate.md).

## Speed

Against zlib 1.3.2, with `tools/deflate-bench`, on the Silesia corpus at levels 1, 6 and 9. Above 1× the port is faster.

| | Mean | Range |
|---|---|---|
| Compression | 0.99× | 0.95–1.03× |
| Decompression, in one call | 1.00× | 0.92–1.09× |
| Decompression, streaming | 1.05× | 0.95–1.14× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in October 2026, the best of three rounds taken in turn. More is in [docs/deflate.md](../../../../docs/deflate.md#the-speed-target).

### On GitHub's runners

Against zlib 1.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression, in one call | 0.89× (0.80–0.96×) | 0.93× (0.86–1.02×) | 0.95× (0.86–1.05×) |
| Decompression, streaming | 0.96× (0.85–1.06×) | 0.98× (0.88–1.11×) | 0.94× (0.85–1.07×) |
| Compression, levels 1, 6 and 9 | 0.97× (0.92–1.01×) | 1.06× (0.94–1.16×) | 1.00× (0.83–1.17×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression, in one call | 0.89× (0.80–0.96×) | 0.91× (0.82–1.01×) | 0.97× (0.87–1.06×) |
| Decompression, streaming | 0.96× (0.85–1.06×) | 0.96× (0.83–1.10×) | 0.96× (0.87–1.07×) |
| Compression, levels 1, 6 and 9 | 0.97× (0.92–1.05×) | 1.12× (0.99–1.28×) | 0.99× (0.85–1.13×) |

**Measured on** `.github/workflows/bench.yml`, on November 1, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 25 Model 17 Stepping 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

## License

The zlib license, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler, and (c) 2026 HivePaaS.
