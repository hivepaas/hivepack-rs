# hivepack::zstd

Zstandard (zstd) compression and decompression in safe Rust, ported from the official library, [libzstd](https://github.com/facebook/zstd) 1.5.7.

> **Status:** decompression works, in one call, streaming, or bufferless (`DCtx::decompress_continue`), with dictionaries, and gives the same output and errors as libzstd on all the test data. It runs at about 0.9× libzstd's speed on Apple M1 and arm64 Linux, about 0.95× with the `unsafe-fast` feature, and at 0.72× (0.78×) on x86-64 Linux ([docs/porting.md](../../../../docs/porting.md#on-linux-x86-64-and-arm64)). Compression works at every level, with every strategy, the block splitter after the sequences, long distance matching and a target size for compressed blocks (`CParameter::TargetCBlockSize`), in one call (`hivepack::zstd::compress`, `CCtx::compress2`) or streaming (`CCtx::compress_stream2`), with libzstd's parameters, and gives the frames libzstd gives, byte for byte, at about 0.88× libzstd's speed at levels 1 to 3, 0.81–0.84× at levels 5 to 8 and 0.68–0.74× at levels 9 to 12 (0.83–0.87× at levels 5 to 12 with the `unsafe-fast` feature), and 0.89–1.05× from level 13 on. With dictionaries too: loaded, prefixes, and `CDict`s attached, copied in or loaded again as libzstd decides. On several threads (`CParameter::NbWorkers`), with the frames libzstd writes with its workers, whatever their number, its speed scaling as libzstd's; the context's own threads, or a pool that contexts share (`ThreadPool`, `CCtx::ref_thread_pool`), and how far a frame has got (`CCtx::get_frame_progression`, `CCtx::to_flush_now`). Beside the port, the input in frames of their own, each compressed in a thread, with zstd's seekable format's seek table after them (`CompressFrames`), for readers that decode a frame in each thread. And from sequences found outside its match finder, with the frames libzstd writes from them: the caller's (`CCtx::compress_sequences`, `CCtx::compress_sequences_and_literals`), or those a match finder of the caller's gives for each block (`CCtx::register_sequence_producer`). And dictionaries trained from samples, the dictionaries libzstd trains, byte for byte: with the default trainer (`hivepack::zstd::train_from_buffer`), the COVER and fast COVER trainers and their optimizers, on several threads too, the legacy trainer (`train_from_buffer_legacy`), and the headers of contents given (`finalize_dictionary`). This crate is not on crates.io.

```rust
let frame = [
    0x28, 0xb5, 0x2f, 0xfd, // magic number
    0x20, 0x05, // header: single segment, content size 5
    0x29, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o', // one raw block, the last
];
let mut out = [0u8; 5];
let size = hivepack::zstd::decompress(&mut out, &frame)?;
assert_eq!(&out[..size], b"hello");
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../../../docs/safety.md). The one exception is opt-in: the `unsafe-fast` feature copies without bounds checks in the decoder's hottest loop, for 4–6% more speed, and prefetches in the encoder's row match finder, as libzstd does, for 2–28% more at levels 5 to 12. See [docs/unsafe.md](../../../../docs/unsafe.md).
- **The same output as libzstd.** Compressed output is identical byte for byte at every level. Decompression gives the same result and the same errors. Trained dictionaries are identical too.
- **The same speed as libzstd**, on x86-64 and arm64.

How the port follows libzstd, and the order of work, are in [docs/porting.md](../../../../docs/porting.md).

## Speed

Against libzstd 1.5.7, with `tools/zstd-bench`, on the 12 Silesia files, in one call. Above 1× the port is faster. The second figure of a cell is with the `unsafe-fast` feature.

| | Apple M1 Pro | x86-64, AMD EPYC 7763 | arm64, Neoverse-N2 |
|---|---|---|---|
| Decompression | 0.92×, 0.95× | 0.72×, 0.78× | 0.91×, 0.96× |
| Compression, level 1 | 0.88× | 0.83× | 0.84× |
| Level 3 | 0.88× | 0.89×, 0.88× | 0.84× |
| Level 9 | 0.74×, 0.83× | 0.54×, 0.77× | 0.50×, 0.80× |
| Level 12 | 0.70×, 0.83× | 0.49×, 0.69× | 0.53×, 0.82× |
| Level 19 | 0.93× | 0.84×, 0.85× | 0.91×, 0.93× |

**Measured on:** an Apple M1 Pro, and GitHub's hosted runners, shared machines with 4 threads (`ubuntu-latest` and `ubuntu-24.04-arm`, with `.github/workflows/bench.yml`), in October 2026, the best of three rounds taken in turn. On x86-64, libzstd decodes Huffman with its assembly loop. These are means; the ranges and every level are in [docs/porting.md](../../../../docs/porting.md#the-speed-target).

### On GitHub's runners

Against libzstd 1.5.7, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression | 0.72× (0.69–0.80×) | 0.92× (0.87–1.00×) | 0.91× (0.76–1.19×) |
| Compression, level 1 | 0.83× (0.78–0.89×) | 0.95× (0.91–0.98×) | 0.88× (0.75–0.92×) |
| Compression, level 3 | 0.88× (0.84–0.92×) | 0.91× (0.84–0.96×) | 0.88× (0.75–1.01×) |
| Compression, level 9 | 0.53× (0.43–0.68×) | 0.64× (0.53–0.85×) | 0.62× (0.42–0.77×) |
| Compression, level 19 | 0.85× (0.76–0.94×) | 0.97× (0.91–1.04×) | 0.95× (0.74–1.11×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression | 0.81× (0.77–0.85×) | 1.03× (0.93–1.21×) | 0.95× (0.74–1.25×) |
| Compression, level 1 | 0.82× (0.78–0.85×) | 0.94× (0.92–0.97×) | 0.90× (0.81–1.07×) |
| Compression, level 3 | 0.87× (0.83–0.92×) | 0.91× (0.85–0.95×) | 0.87× (0.71–1.00×) |
| Compression, level 9 | 0.77× (0.71–0.89×) | 0.90× (0.84–0.96×) | 0.88× (0.79–0.97×) |
| Compression, level 19 | 0.85× (0.76–0.91×) | 1.00× (0.94–1.05×) | 0.91× (0.84–1.00×) |

**Measured on** `.github/workflows/bench.yml`, on November 1, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 Stepping 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) Meta Platforms, Inc. and affiliates, and (c) 2026 HivePaaS. The suffix sort of the dictionary builder, `src/dict_builder/divsufsort.rs`, is ported from libdivsufsort-lite, which libzstd ships, and is under the MIT license, with its notice there and in [LICENSE](LICENSE): Copyright (c) 2003-2008 Yuta Mori.
