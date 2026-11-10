# hivepack::zstd

Zstandard (zstd) compression and decompression in safe Rust, ported from the official library, [libzstd](https://github.com/facebook/zstd) 1.5.7.

> **Status:** decompression works, in one call, streaming, or bufferless (`DCtx::decompress_continue`), with dictionaries, and gives the same output and errors as libzstd on all the test data. It runs at about 0.9× libzstd's speed on Apple M1 and arm64 Linux, about 0.95× with the `unsafe-fast` feature, and at 0.74–0.78× (0.81–0.82×) on x86-64 Linux, a runner's and a desktop's ([docs/porting.md](../../../../docs/porting.md#on-linux-x86-64-and-arm64)). Compression works at every level, with every strategy, the block splitter after the sequences, long distance matching and a target size for compressed blocks (`CParameter::TargetCBlockSize`), in one call (`hivepack::zstd::compress`, `CCtx::compress2`) or streaming (`CCtx::compress_stream2`), with libzstd's parameters, and gives the frames libzstd gives, byte for byte, at about 0.88× libzstd's speed at levels 1 to 3, 0.81–0.84× at levels 5 to 8 and 0.68–0.74× at levels 9 to 12 (0.83–0.87× at levels 5 to 12 with the `unsafe-fast` feature), and 0.89–1.05× from level 13 on. With dictionaries too: loaded, prefixes, and `CDict`s attached, copied in or loaded again as libzstd decides. On several threads (`CParameter::NbWorkers`), with the frames libzstd writes with its workers, whatever their number, its speed scaling as libzstd's; the context's own threads, or a pool that contexts share (`ThreadPool`, `CCtx::ref_thread_pool`), and how far a frame has got (`CCtx::get_frame_progression`, `CCtx::to_flush_now`). Beside the port, the input in frames of their own, each compressed in a thread, with zstd's seekable format's seek table after them (`CompressFrames`), for readers that decode a frame in each thread. And from sequences found outside its match finder, with the frames libzstd writes from them: the caller's (`CCtx::compress_sequences`, `CCtx::compress_sequences_and_literals`), or those a match finder of the caller's gives for each block (`CCtx::register_sequence_producer`). And dictionaries trained from samples, the dictionaries libzstd trains, byte for byte: with the default trainer (`hivepack::zstd::train_from_buffer`), the COVER and fast COVER trainers and their optimizers, on several threads too, the legacy trainer (`train_from_buffer_legacy`), and the headers of contents given (`finalize_dictionary`). This crate is not on crates.io.

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

Against libzstd 1.5.7, with `tools/zstd-bench`, on the 12 Silesia files, in one call. Above 1× the port is faster.

| | Mean | Range | With `unsafe-fast` | Range |
|---|---|---|---|---|
| Decompression | 0.78× | 0.71–0.97× | 0.82× | 0.73–0.93× |
| Compression, level 1 | 0.85× | 0.76–0.89× | 0.85× | 0.76–0.91× |
| Level 3 | 0.86× | 0.79–0.93× | 0.85× | 0.77–0.95× |
| Level 9 | 0.56× | 0.50–0.66× | 0.71× | 0.64–0.75× |
| Level 12 | 0.45× | 0.37–0.57× | 0.54× | 0.49–0.62× |
| Level 19 | 0.96× | 0.87–1.08× | 0.94× | 0.91–1.04× |

**Measured on:** AMD Ryzen 9 9950X (x86-64, Linux), in November 2026, after hivepack-rs#201, the best of three rounds taken in turn; libzstd as zstd-sys builds it, which on x86-64 decodes Huffman with its assembly loop. The row match finder (levels 5 to 12) is furthest behind on this machine, where its tables outgrow the caches and libzstd prefetches. On an Apple M1 Pro, in October 2026, the port was at 0.92× in decompression and 0.70–0.88× at levels 1 to 12; those figures, with their ranges and every level, are in [docs/porting.md](../../../../docs/porting.md#the-speed-target).

### On GitHub's runners

Against libzstd 1.5.7, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression | 0.74× (0.68–0.77×) | 0.91× (0.86–0.99×) | 0.93× (0.73–1.27×) |
| Compression, level 1 | 0.83× (0.75–0.87×) | 0.90× (0.89–0.93×) | 0.87× (0.76–0.97×) |
| Compression, level 3 | 0.85× (0.79–0.93×) | 0.87× (0.82–0.90×) | 0.88× (0.73–1.08×) |
| Compression, level 9 | 0.52× (0.41–0.65×) | 0.59× (0.45–0.72×) | 0.57× (0.35–0.80×) |
| Compression, level 19 | 0.94× (0.87–1.00×) | 0.95× (0.91–1.00×) | 0.92× (0.79–1.00×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Decompression | 0.81× (0.69–0.85×) | 1.04× (0.96–1.13×) | 1.01× (0.86–1.28×) |
| Compression, level 1 | 0.83× (0.75–0.89×) | 0.94× (0.90–0.97×) | 0.87× (0.78–0.93×) |
| Compression, level 3 | 0.85× (0.80–0.92×) | 0.93× (0.87–0.98×) | 0.91× (0.81–1.12×) |
| Compression, level 9 | 0.74× (0.71–0.78×) | 0.90× (0.83–0.95×) | 0.86× (0.72–1.02×) |
| Compression, level 19 | 0.92× (0.87–0.96×) | 0.98× (0.94–1.06×) | 0.93× (0.68–1.17×) |

**Measured on** `.github/workflows/bench.yml`, on November 10, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on AMD EPYC 9V74 (4 threads); Windows x86-64 on Intel64 Family 6 Model 207 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). With it: Linux x86-64 on AMD EPYC 9V74 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

### Where decompression stands on a desktop x86-64

On an AMD Ryzen 9 9950X (Zen 5), November 2026, a `.tar.zst` of 2.35 GB (programs and libraries, one frame of `zstd -9 -T0`) decoded streaming, 128 KiB in and out, best of three, with `unsafe-fast`:

| | Time |
|---|---|
| hivepack (after hivepack-rs#201) | 1.40 s, 0.84× |
| libzstd 1.5.7 | 1.17 s |
| libzstd built without its assembly and BMI2 code (`no_asm`, `DYNAMIC_BMI2=0`) | 1.24 s |

The sequence loop (`decompress_sequences_body_with`) is about 83% of the gap. It runs about 148 instructions a sequence, where libzstd's C runs 130 and its BMI2 build 115. There are 140 million sequences, of 16.8 bytes on average. Branch misses are the same, and so are the slots lost to the front end and the back end: the difference is the µops retired. They come from registers. The loop holds a base and an index for each buffer where C holds one pointer, so the three FSE states and the bit container are kept on the stack from one sequence to the next. Huffman decoding is within 12% of libzstd's assembly loop, and the FSE tables' building within 35%; together they are the rest.

Tried, and kept or not, in hivepack-rs#201:

| Change | Result | Kept |
|---|---|---|
| The repeat offsets taken apart, out of an indexed array | −1.5% | yes |
| The bitstream register read without its bounds check | −0.8% | no |
| `SeqSymbol` as separate fields, read by reference as libzstd does | slower | no |
| The rare path (`exec_sequence_end`) given the sequence as scalars | fewer instructions, same time or slower | no |
| A BMI2 build | 8% fewer instructions, 1.3% fewer cycles | no |
| `x86-64-v3` | slower | no |

**Not done yet: the sequence loop on raw pointers.** With `unsafe-fast`, the loop's fast path already copies without bounds checks once per block (`unchecked_loop_fits`). The loop could also go on raw pointers for the output, the literals and the bitstream, as libzstd's does, which frees the registers the bases take. It is the only change seen that could close most of the 11% between the port and libzstd's own C. It would take `unsafe` from the copies into the whole loop: the decoding of each sequence, the bitstream's reloads and the state updates. So it is a decision on what `unsafe-fast` covers, left until it is made. Its tests would be the ones of the copies today: the checked and unchecked loops compared byte for byte, Miri, and the fuzzer against libzstd under AddressSanitizer.

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (c) Meta Platforms, Inc. and affiliates, and (c) 2026 HivePaaS. The suffix sort of the dictionary builder, `src/dict_builder/divsufsort.rs`, is ported from libdivsufsort-lite, which libzstd ships, and is under the MIT license, with its notice there and in [LICENSE](LICENSE): Copyright (c) 2003-2008 Yuta Mori.
