# Porting libbzip2

`hivepack::bzip2` is a port of the official bzip2 library, [libbzip2](https://sourceware.org/bzip2/), to safe Rust. ZIP archives use it for their method 12, tar files for `.tar.bz2`, and any other format that holds bzip2 streams can too. The goal is the one [porting.md](porting.md) sets for zstd: the same output as libbzip2, at the same speed.

## The version

The port follows bzip2 **1.0.8** (13 July 2019), still the current release as of October 2026: `bzip2-1.0.8.tar.gz` from sourceware.org, SHA-256 `ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269`, whose signature by Mark Wielaard (key `EC3CFE88F6CA0788774F5C1D1AA44BE649DE760A`) was checked. `hivepack::bzip2::UPSTREAM_VERSION` names it, and `hivepack::bzip2::version()` gives what `BZ2_bzlibVersion()` gives, `"1.0.8, 13-Jul-2019"`. The 1.1 branch in bzip2's repository has had no release, and the port follows releases.

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of libbzip2 becomes a module of the same name: `blocksort.c` becomes `crates/hivepack/src/bzip2/blocksort.rs`, `decompress.c` becomes `decompress.rs`. `bzlib_private.h`'s constants are in `private.rs`, and its two structures, `EState` and `DState`, beside the code that uses them, in `compress.rs` and `decompress.rs`.
- **The same names**, in snake case, with the C name in every doc comment. A stream and its state are one type, `Compress` or `Decompress`, whose methods drop the prefix: `BZ2_bzCompress` becomes `Compress::compress`, `BZ2_bzBuffToBuffDecompress` becomes `buff_to_buff_decompress`.
- **The same algorithms, constants and tables.** `crctable.c` and `randtable.c` are copied as they are, and a test checks the CRC table against its polynomial. That is what makes the output identical.
- **The same results.** A call returns libbzip2's code, as `Result<Status, Error>`, with the same numbers (`Status::number`, `Error::number`) and the names `BZ2_bzerror()` gives (`"DATA_ERROR_MAGIC"`).
- **Differences are marked** with a comment starting `Differs from libbzip2`.

The main difference is the stream itself. A `bz_stream` holds pointers to the caller's input and output; the port takes them for each call as an `InBuffer` and an `OutBuffer`, a slice and a position, as `hivepack::deflate` and `hivepack::zstd` do, and keeps the totals in the stream. `BZ2_decompress`, which libbzip2 writes as one `switch` whose `case` labels sit inside its loops so that it can stop wherever the input runs out and start there again, is a `match` on the same states, with the loop counters and other locals in the same save area, copied in and out as libbzip2 copies them.

The other differences:

- **After an error, the decompressor returns it again.** libbzip2's manual allows only `BZ2_bzDecompressEnd` after an error. Calling `BZ2_bzDecompress` anyway goes on from wherever it stopped: a selector rejected for counting up to the number of groups is taken at the next call, and with six groups then reads past `pos[]`, a stack array of six, while it undoes the selectors' MTF coding. The port keeps the first error instead, and the comparisons stop at it.
- **The compressor's arrays are apart.** libbzip2 keeps the block, its sorted order, the MTF values, the fallback sort's classes and the compressed bits in two arrays, `arr1` and `arr2`, read as several types at once. The port gives each its own vector, with the capacity reserved when the stream is made, as libbzip2 allocates its arrays then (so that failing to reserve it is `BZ_MEM_ERROR`, as a `NULL` from `BZALLOC` is), and each sized to what the current block needs. What libbzip2 reads of them is what the block wrote, so the output is the same; the memory touched is about 9 bytes for each byte of a block, against libbzip2's 8. The fallback sort reads the block where libbzip2 reads it through its classes' memory, so it leaves the block as it was instead of writing it back.
- **The decompressor's arrays hold one block.** `tt`, or `ll16` and `ll4` in the small mode, get their capacity once the stream's header gives the block size, as libbzip2 allocates them then, and hold what the current block wrote: libbzip2's are not initialised, and it reads only what the block wrote.
- **`mainGtU` compares eight bytes at a time.** libbzip2 compares the bytes of two rotations one at a time, then a byte and its quadrant value at a time; the port compares eight bytes at once (four for the end of the first twelve), as big-endian numbers, and the quadrant values in front of the first byte that differs. The result is the same, and so is the work counted against the work factor, so the fallback sort is chosen for the same blocks.
- **No verbosity**, so nothing is printed and `Compress::new` and `Decompress::new` take no verbosity. `small` is a `bool`.
- **What C needs and Rust does not:** custom allocators (`bzalloc`, `bzfree`), the checks of a null or uninitialised stream, `BZ_CONFIG_ERROR` (the sizes of C's types), and `BZ_PARAM_ERROR` for an action that is not one: `Action` has only the three. A buffer whose `pos` is past its end fails with `BZ_PARAM_ERROR`.
- **`AssertH`.** Where libbzip2 checks that something that cannot happen did not, and exits with an internal error if it did, the port says why it cannot happen. Where it still could, a bounds check would panic rather than exit; none has been reached.

## How it is shown

The reference is libbzip2 1.0.8 itself, reached two ways: built from the sources bundled in `bzip2-sys` 0.1.13 (its `static` feature, so that a system libbz2, which distributions patch, is never used) and called through the `bzip2` crate with its default backend, `libbz2-rs-sys`, left out, both development dependencies only; and `tools/bzip2-oracle`, a small C program built from the release tarball by `scripts/testdata.py`, as `tools/zlib-oracle` is for zlib.

- **`tests/oracle.rs`** compares every call. A request is a list of calls and their input and output space; the port must answer each as libbzip2 does, with the result and the bytes read and written, then the totals and a hash of the output. The compressor's requests give inputs of eight kinds (text, random bytes from alphabets of every size, runs around the lengths the first run-length coding cuts at, periodic data that sends the main sort to the fallback, and others), from none to 250 KB, at block sizes 1 to 9 and work factors 0 to 250, in random pieces with flushes on the way, calls refused for the wrong action or a changed input, runs with nothing to do, and calls after the end. The decompressor's give libbzip2's streams in random pieces, fast and small, some damaged, cut short, followed by another stream or bytes, with the first block marked randomised, or randomised and valid (see below). The buffer-to-buffer functions get outputs too small and inputs cut short. 1,035 requests are compared with libbzip2 where the oracle is built (Linux and macOS in CI); most streams end, and the others fail in every way libbzip2 can (`BZ_DATA_ERROR`, `BZ_DATA_ERROR_MAGIC`, `BZ_UNEXPECTED_EOF`, `BZ_OUTBUFF_FULL`, `BZ_SEQUENCE_ERROR`, `BZ_PARAM_ERROR`). `testdata/oracle/bzip2.txt` replays 730 earlier answers everywhere else, including Windows, 32-bit and big-endian machines.
- **`tests/bzip2.rs`** compares with libbzip2 through the `bzip2` crate on every machine CI tests: streams compressed whole, byte for byte, at every block size and work factor, up to 2 MB and repetitive enough for the fallback; compressed in pieces, with flushes and the end in pieces, call by call; decompressed in pieces, call by call, fast and small, valid and damaged; the release's samples, compressed at block sizes 1, 2 and 3 as its `make test` does and decompressed; and the buffer-to-buffer functions.
- **Randomised blocks**, which bzip2 0.9.0 and earlier wrote and no release since does, are made by the tests: a block with no two bytes in a row the same (so that the first run-length coding leaves it as it is, flipped bits and all) has its low bits flipped where `BZ2_rNums` says, is compressed by libbzip2, and is marked randomised with the CRCs of the original. Both decompressors must give the original back.
- **A unit test** checks the CRC table against its polynomial and the check value of CRC-32/BZIP2.
- **`fuzz/fuzz_targets/bzip2.rs`** does what `tests/bzip2.rs` does, with the fuzzer's input as the stream or the data (see [fuzz/README.md](../fuzz/README.md)). Before the first commit, the same checks ran on 2 million generated inputs (damaged streams, and data compressed in random pieces) over two hours of CPU, with overflow checks and debug assertions on: no difference and no panic.

## The speed target

At least 0.95× libbzip2's speed, as for zstd and zlib, measured with `tools/bzip2-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench` fetches it):

```sh
cargo run --release -p bzip2-bench -- [--levels 1,9] [--small | --compress] target/testdata/silesia
```

Each run is one call with all the input and room for all the output, on a new stream. With `--compress`, the tool also checks that the port's streams are libbzip2's, byte for byte.

### Where it stands

AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the 12 Silesia files at block sizes 1 and 9 (decompression at 9), best of three rounds taken in turn:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| Compression | 1.05× libbzip2 | 0.97–1.18× | 24 of 24 |
| Decompression | 1.01× | 0.98–1.05× | 12 of 12 |
| Decompression, small | 1.03× | 0.99–1.04× | 12 of 12 |

Every stream was libbzip2's, byte for byte. Decompression was there as first ported. Compression was at 0.81–0.94× until `mainGtU` compared eight bytes at a time; the most repetitive files, `nci` and `xml`, gained most, as their rotations share the longest prefixes. arm64 is not measured yet.

## Progress

| libbzip2 | Port | Status | Checked against libbzip2 by |
|---|---|---|---|
| `bzlib.h`, `bzlib_private.h` | `bzlib.rs`, `private.rs`, `compress.rs`, `decompress.rs` | done | the return codes in every comparison |
| `crctable.c` | `crctable.rs` | done | the polynomial; every block's and stream's CRC |
| `randtable.c` | `randtable.rs` | done | the randomised streams |
| `huffman.c` | `huffman.rs` | done | every block of every comparison |
| `blocksort.c` | `blocksort.rs` | done | `tests/bzip2.rs` and `tests/oracle.rs`, byte for byte, with the main sort, the fallback, and the work factors that choose between them |
| `compress.c` | `compress.rs` | done | `tests/bzip2.rs` and `tests/oracle.rs`, byte for byte, call by call |
| `decompress.c` | `decompress.rs` | done | `tests/bzip2.rs` and `tests/oracle.rs`, call by call, fast and small, randomised blocks included |
| `bzlib.c`: the stream functions and `BZ2_bzBuffToBuff*` | `bzlib.rs` | done | `tests/oracle.rs`, for every action and mode; `tests/bzip2.rs` |

## Not ported, for now

- `bzlib.c`'s file functions: `BZ2_bzReadOpen`, `BZ2_bzRead`, `BZ2_bzWriteOpen` and the others, and the zlib-like `BZ2_bzopen`, `BZ2_bzread`, `BZ2_bzwrite` and `BZ2_bzclose`, built on `FILE*`. Reading concatenated streams, as `bzip2 -d` and `BZ2_bzRead` do, is a decompressor for each stream: `Decompress` stops at the end of one and leaves the rest of the input unread.
- The programs: `bzip2.c`, `bzip2recover.c`, and the tests' tools.
- Verbosity, and the `BZ_DEBUG` checks (`AssertD`).

## Following new releases

When bzip2 releases a new version:

1. Diff the two tags and port each change.
2. Update `UPSTREAM_VERSION`, the release in `testdata/manifest.json`, and the `bzip2-sys` version that bundles it.
3. Run everything again.

## Licenses

The port is derived from libbzip2, which is under its own BSD-style license (SPDX `bzip2-1.0.6`), and asks, as zlib's does, that altered versions be marked as such. That is why `hivepack::bzip2` is under that license, and its [LICENSE](../crates/hivepack/src/bzip2/LICENSE) keeps libbzip2's notice and says that this is an altered version.
