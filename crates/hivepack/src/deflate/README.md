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

Beside the port of zlib, `Compressor` is a port of [libdeflate](https://github.com/ebiggers/libdeflate) 1.26's compressor: a whole buffer compressed at once, raw deflate, at levels 0 to 12, with libdeflate's output, byte for byte. Its levels 10 to 12 find the cheapest way through each block, and make smaller streams than zlib's level 9. Not in libdeflate, `Compressor::deflate_compress_part` compresses a part of a stream that is not its last, and `DeflateMt` with `Library::Libdeflate` compresses blocks of 1 to 4 MiB with it in threads, joined into one stream.

```rust
use hivepack::deflate::Compressor;

let data = b"compressed in one call ".repeat(1000);
let mut compressor = Compressor::new(12).expect("a level from 0 to 12");
let mut out = vec![0; compressor.deflate_compress_bound(data.len())];
let size = compressor.deflate_compress(&data, &mut out);
assert!(size > 0 && size < 200);
```

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
| Decompression, in one call | 1.61× | 1.20–1.97× |
| Decompression, streaming | 1.29× | 1.09–1.47× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), compression in October 2026 and decompression in November 2026, the best of three rounds taken in turn. More is in [docs/deflate.md](../../../../docs/deflate.md#the-speed-target).

### On GitHub's runners

Against zlib 1.3.2, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression, in one call | 1.62× (1.20–2.00×) | 1.49× (1.13–1.74×) | 1.63× (1.18–1.96×) |
| Decompression, streaming | 1.37× (1.13–1.55×) | 1.22× (1.02–1.35×) | 1.30× (1.13–1.44×) |
| Compression, levels 1, 6 and 9 | 0.95× (0.88–0.99×) | 1.12× (0.97–1.27×) | 1.00× (0.81–1.19×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression, in one call | 1.47× (1.13–1.70×) | 1.62× (1.31–1.85×) | 1.66× (1.21–1.92×) |
| Decompression, streaming | 1.24× (1.04–1.37×) | 1.31× (1.14–1.52×) | 1.31× (1.13–1.49×) |
| Compression, levels 1, 6 and 9 | 0.98× (0.93–1.02×) | 1.10× (1.04–1.23×) | 0.99× (0.84–1.12×) |

**Measured on** `.github/workflows/bench.yml`, on November 10, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on AMD EPYC 9V45 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). With it: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on Intel64 Family 6 Model 207 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

## License

The zlib license, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1995-2026 Jean-loup Gailly and Mark Adler, and (c) 2026 HivePaaS.

The port of libdeflate's compressor, in `libdeflate/`, is under the MIT license, libdeflate's. See [libdeflate/LICENSE](libdeflate/LICENSE). Copyright 2016 Eric Biggers, 2024 Google LLC, and (c) 2026 HivePaaS.
