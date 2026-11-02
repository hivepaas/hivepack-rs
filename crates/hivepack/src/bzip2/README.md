# hivepack::bzip2

bzip2 compression and decompression in safe Rust, ported from the official library, [libbzip2](https://sourceware.org/bzip2/) 1.0.8.

> **Status:** compression gives libbzip2's output, byte for byte, at every block size and work factor, whatever pieces the input and output come in, and decompression libbzip2's results, call by call, in its fast and small modes, randomised blocks included. Both run at about libbzip2's speed on x86-64 (Silesia). This crate is not on crates.io.

```rust
use hivepack::bzip2::{Action, Compress, Decompress, InBuffer, OutBuffer, Status};

let mut stream = [0; 128];
let mut output = OutBuffer::new(&mut stream);
let mut compress = Compress::new(9, 0)?;
let status = compress.compress(&mut output, &mut InBuffer::new(b"hello"), Action::Finish)?;
assert_eq!(status, Status::StreamEnd);
let len = output.pos;

let mut out = [0; 16];
let mut output = OutBuffer::new(&mut out);
let status = Decompress::new(false).decompress(&mut output, &mut InBuffer::new(&stream[..len]))?;
assert_eq!(status, Status::StreamEnd);
let written = output.pos;
assert_eq!(&out[..written], b"hello");
```

It also has libbzip2's one-call functions, `buff_to_buff_compress` and `buff_to_buff_decompress`.

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../../../docs/safety.md).
- **The same output as libbzip2.** Compressed output is identical byte for byte; decompression gives the same output and return codes.
- **The same speed as libbzip2**, on x86-64 and arm64.

How the port follows libbzip2, how it is checked, and what is left are in [docs/bzip2.md](../../../../docs/bzip2.md).

## Speed

Against libbzip2 1.0.8, with `tools/bzip2-bench`, on the 12 Silesia files. Above 1× the port is faster.

| | Mean | Range |
|---|---|---|
| Compression, block sizes 1 and 9 | 1.05× | 0.97–1.18× |
| Decompression, block size 9 | 1.01× | 0.98–1.05× |
| Decompression, small mode | 1.03× | 0.99–1.04× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in October 2026, the best of three rounds taken in turn. More is in [docs/bzip2.md](../../../../docs/bzip2.md#the-speed-target).

### On GitHub's runners

Against libbzip2 1.0.8, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression, block size 9 | 0.96× (0.90–1.00×) | 0.94× (0.91–0.99×) | 0.93× (0.75–1.09×) |
| Compression, block sizes 1 and 9 | 1.05× (0.99–1.17×) | 1.03× (0.98–1.08×) | 1.04× (0.88–1.22×) |

**Measured on** `.github/workflows/bench.yml`, on November 1, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 9V45 (4 threads); Windows x86-64 on AMD64 Family 25 Model 17 Stepping 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

## License

libbzip2's BSD-style license (`bzip2-1.0.6`), the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1996-2019 Julian R Seward, and (c) 2026 HivePaaS.
