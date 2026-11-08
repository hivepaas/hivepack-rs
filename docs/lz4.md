# Porting liblz4

`hivepack::lz4` is a port of the official LZ4 library, [liblz4](https://github.com/lz4/lz4), to safe Rust: `.lz4` files, `.tar.lz4` once tar comes, and any other format that holds LZ4 blocks or frames. ZIP has no method for LZ4 (APPNOTE lists none, and libzip has none), so `hivepack::zip` does not use it. The goal is the one [porting.md](porting.md) sets for zstd: the same results as liblz4, at the same speed.

Decompression and compression are both ported: blocks (`LZ4_decompress_safe` and its forms, `LZ4_compress_fast` and its forms, and `lz4hc.c` at every level), streams of blocks with dictionaries, frames (`LZ4F_decompress`, and `LZ4F_compressBegin` to `LZ4F_compressEnd`, with dictionaries digested or not), and `.lz4` files as `std::io` readers and writers.

## The version

The port follows lz4 **1.10.0** (22 July 2024, tag `v1.10.0`, commit `ebb370ca83af193212df4dcbadcc5d87bc0de2f0`), still the latest release as of October 2026: `lz4-1.10.0.tar.gz` from the release's page, SHA-256 `537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b`, the checksum the release gives beside it (lz4's releases are not signed). Its `lib/` is the same, file for file, as the `liblz4/lib` that `lz4-sys` 1.11.1 bundles. `hivepack::lz4::UPSTREAM_VERSION` names it, and `block::version_number()` and `block::version_string()` give what `LZ4_versionNumber()` and `LZ4_versionString()` give, 11000 and `"1.10.0"`.

Only `lib/` is ported: it is under the BSD 2-Clause license, and the rest of lz4 (the `lz4` program, its tests and tools) under the GPL. `hivepack::lz4` is under the BSD 2-Clause license too, with liblz4's and xxHash's notices ([LICENSE](../crates/hivepack/src/lz4/LICENSE)).

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of `lib/` becomes a module of the same name: `lz4.c` becomes `crates/hivepack/src/lz4/lz4.rs` (decoding) and `lz4_compress.rs` (encoding), `lz4hc.c` `lz4hc.rs`, `lz4frame.c` `lz4frame.rs` (decoding) and `lz4frame_compress.rs` (encoding), and the 32-bit half of `xxhash.c` (xxHash 0.6.5, which liblz4 ships) `xxhash.rs`. The public items are in three modules after liblz4's three headers: `hivepack::lz4::block` (`lz4.h`), `hivepack::lz4::hc` (`lz4hc.h`) and `hivepack::lz4::frame` (`lz4frame.h`).
- **The same names**, in snake case, with the C name in every doc comment: `LZ4_decompress_safe_partial` becomes `block::decompress_safe_partial`, `LZ4F_decompress` `DecompressionContext::decompress`.
- **The same results.** A block function returns liblz4's result: the size decoded, or a `DecodeError` whose `number()` is liblz4's negative result, `-(position) - 1`, the position in the block where the decoder found the error. A frame call returns liblz4's hint, or its error code, as `frame::Error` with the same numbers and the names `LZ4F_getErrorName()` gives (`"ERROR_frameType_unknown"`).
- **The same writes.** liblz4 decodes with wild copies, 8, 16 or 32 bytes at a time, writing past the end of a literal run or a match where the block's rules leave room. The port makes the same copies, so the output holds the same bytes as liblz4's, past what was decoded too, and a malformed block (an offset of 0, which liblz4 does not refuse) decodes to the same bytes.
- **The same blocks and frames.** The compressors make liblz4's output, byte for byte, at every acceleration and level, into outputs of every size, in streams and frames, and on every machine: liblz4 hashes 5 bytes on 64-bit machines and 4 on 32-bit ones, reads them in the machine's byte order, and on 32-bit machines keeps pointers in its table for inputs past 64 KB (where an empty entry never matches); the port does the same, by target. What `compress_dest_size` and `compress_hc_dest_size` fit in their output is liblz4's too.
- **Differences are marked** with a comment starting `Differs from liblz4`.

### The differences

- **Buffers, not pointers.** Where liblz4 takes a pointer to the output and finds the dictionary by comparing pointers (`dictStart + dictSize == dest`), the port takes slices: `block::decompress_safe_using_dict` has the dictionary apart from the output, and `block::decompress_safe_with_prefix` has it before the output, in the same buffer. The decoder is `LZ4_decompress_generic` with indices into that buffer, its prefix and its dictionary. The checks for pointers that wrap around the address space are left out, as indices cannot.
- **The fast loop is always on.** liblz4 decodes most of a block in its fast loop (`LZ4_FAST_DEC_LOOP`) on x86, x86-64 and arm64 (with GCC, or Apple's compilers), and in its safe loop alone elsewhere. The two write different bytes past what they decode; the port is liblz4 with the fast loop, on every machine.
- **`StreamDecode` keeps its own history.** liblz4's `LZ4_decompress_safe_continue` remembers where the last block was decoded, and decodes the next as a continuation if it is right after it, or with the last blocks as a separate dictionary if not. The port keeps a copy of the last 64 KB and decodes each block after it, as liblz4 does when the blocks are decoded one after another in one buffer. The output is the same either way; a malformed block can fail at another position, or not fail, as it can between liblz4's own two ways (a match that ends in the block's last 5 bytes is refused when it starts in a separate dictionary, and not always when it starts in the output: liblz4's shortcut copies it unchecked).
- **The frame context's history.** `LZ4F_dctx` points at the history its next block refers to, which is in the caller's output, in its own buffer, or in the dictionary the caller gave. The port's context knows which of those it is (`DictAt`), and keeps a copy of the dictionary of `decompress_using_dict`, which liblz4 asks the caller to keep. At the end of each call, it moves the history into its own buffer, as liblz4 does unless the caller promises that the output stays where it is (`stableDst`), which the port does not take.
- **Errors are kept.** After an error, liblz4 says the frame context is in an undefined state; the port's returns the same error until `reset`. The comparisons stop at the first error.
- **The compression streams keep their own history.** `LZ4_compress_fast_continue` and `LZ4_compress_HC_continue` refer to the blocks given before, where the caller keeps them, or to a dictionary, and compress differently when the next block is right after the last one in memory (a prefix) than when it is apart (an external dictionary). `block::Stream` and `hc::StreamHc` keep a copy of the last 64 KB instead, and compress as liblz4 does when the caller saves the history after each block (`LZ4_saveDict` and `LZ4_saveDictHC`, with 64 KB): the blocks are liblz4's in that case.
- **The frame compressor's history.** `LZ4F_cctx` points at the history of the next linked block: in its own buffer, in the caller's input, in the dictionary the caller gave (which it asks the caller to keep), or in a `CDict`. The port's context knows which of those it is (`Loc`), and keeps a copy of the last 64 KB of the dictionary of `compress_begin_using_dict`. At the end of each call that compressed from the input, it saves the history into its own buffer, as liblz4 does unless the caller promises the input stays (`stableSrc`); the port takes that promise only within `compress_frame`, where no call follows, and has no `CompressOptions`. A dictionary and an input that are next to each other in memory are taken as apart.
- **Where liblz4 1.10.0 goes wrong**, the port refuses: `LZ4_compress_destSize_extState` does not clamp its acceleration as the other functions do, and one below 1 makes its search step negative (undefined): the port takes it as 1. `LZ4F_uncompressedUpdate` with linked blocks, which liblz4 says it does not support, makes frames that do not decompress to their input (its compressor does not see the stored blocks the decompressor refers to; with high compression, its indexes then start from 0 and a search reads past the end of its dictionary): the port returns `ERROR_blockMode_invalid`. And when `LZ4F_compressUpdate` or `LZ4F_uncompressedUpdate` first flushes what the other kept, `LZ4F_compressBound` does not count that block, and liblz4 writes past the end of the output, up to a block and 8 bytes (AddressSanitizer shows it; lz4's development branch has rewritten this since): the port returns `ERROR_dstMaxSize_tooSmall` unless the output holds that block too.
- **Not ported:** the `LZ4_decompress_fast` functions, deprecated in liblz4 as unsafe on malformed input; in-place decompression (the input and output in one buffer); `LZ4_decoderRingBufferSize`; liblz4's deprecated compression functions (`LZ4_compress_limitedOutput` and the like) and the functions that tell the size of its states (`LZ4_sizeofState`), which the port's types make unneeded; custom allocators (`LZ4F_CustomMem`, `LZ4F_createCDict_advanced`); and `lz4file.c`'s reader, which works on a `FILE*`, reads one frame only, and fails on a file of less than 19 bytes. Its writer is ported as `Encoder`.

### `.lz4` files

`hivepack::lz4::Encoder` writes one frame as an `std::io::Write`, as `lz4file.c`'s writer does (`LZ4F_writeOpen`, `LZ4F_write`, `LZ4F_writeClose`): the input goes to `LZ4F_compressUpdate` a block at most at a time, `flush` is `LZ4F_flush`, and `finish` ends the frame, so the frame is liblz4's for the same writes and flushes.

`hivepack::lz4::Decoder` reads what `lz4 -d` reads, as an `std::io::Read`: frames one after another, skippable frames skipped, and the legacy format (`lz4 -l`, which the Linux kernel's images use: blocks of 8 MB, the last ended by the end of the input or by a magic number). `lz4 -d` itself, `programs/lz4io.c`, is under the GPL; `Decoder` is the port's own, from the frame format's description (`doc/lz4_Frame_format.md`) and what `lz4 -d` 1.10.0 does with each case:

- An empty input is an empty stream; data that is not a frame, at the start or after the frames, is an error (`lz4 -d` says "Stream followed by undecodable data" for the latter, and fails); so is a frame or magic number cut short, or damaged data.
- Unlike `lz4 -d` 1.10.0, a legacy frame may follow a frame of the frame format, as the description says (`lz4 -d` reads its magic number as a frame header and fails with `ERROR_frameType_unknown`), and a skippable frame cut short at the end of the input is an error (`lz4 -d` seeks past the end of its file).

### Frames in threads, beside the port

liblz4's frame API compresses on one thread; `lz4 -T` cuts a frame of independent blocks across threads in its program. `lz4::EncoderMt` (`crates/hivepack/src/lz4/mt.rs`) does the same as an `io::Write`: the input cut into blocks of the frame's block size (4 MB by default, as `lz4` writes), each compressed in a thread by a `CompressionContext` of its own, begun once in independent blocks, so that each block is what that context makes of it; the header is the context's, and the content checksum, on by default as `lz4` writes it, is computed on the caller's thread as the input comes. The frame is `compress_frame`'s with the same preferences, byte for byte, whatever the threads, and `lz4 -1 -T4`'s. Two blocks for each thread are in flight at most; `MtOptions::memory_limit` lowers the threads to fit `MtOptions::memory_usage`, 16.5 MiB a thread for blocks of 4 MB. `tests/lz4_mt.rs` compares it with `compress_frame` at levels −3 to 12, with each checksum, sizes around a block's, 1, 2 and 8 threads, written whole and in pieces, and reads blocks of 4 MB back with liblz4.

3 GB of programs (a tar of `/usr/lib`), 32 threads of an AMD machine with 32: level 1, 3.43 s on one thread, 1.07 s on 32, where `lz4 -1 -T32` takes 1.63 s; level 9, 52.8 s and 2.90 s. At level 1 the caller's thread is what is left: it copies the input into blocks and computes the checksum.

## How it is shown

The reference is liblz4 1.10.0 itself, reached two ways: built from the sources bundled in `lz4-sys` 1.11.1 and called through the `lz4` crate 1.28.1, both development dependencies only; and `tools/lz4-oracle`, a small C program built from the release tarball by `scripts/testdata.py`, as `tools/bzip2-oracle` is for libbzip2.

- **`tests/oracle.rs`** compares what the `lz4` crate cannot reach, call by call. Block requests decode with every function (`LZ4_decompress_safe`, `_partial`, `_usingDict` with the dictionary apart or right before the output, and their partial forms) into an output filled with a pattern; the port must return the same result, the error position included, and leave the same bytes in all of the output. The blocks are liblz4's, at every level from acceleration 70 to HC 12, some damaged or cut short; the second and later blocks of liblz4's linked frames, with the 64 KB before them as their dictionary (all of it, 65,535 bytes, or less); and blocks made up by the test, valid or not, with every literal and match length, offsets from 0 to 65,535 and past the history, and the end-of-block rules kept or broken. Stream requests decode blocks one after another with `LZ4_decompress_safe_continue`, with and without a dictionary. Frame requests decode liblz4's frames, of every block size, block mode, checksum and level, and frames the test puts together (linked blocks with their dictionary, every header flag and field, reserved bits, wrong versions and sizes, wrong content sizes, skippable frames in front), damaged, cut short or followed by more, in random pieces of input and output, some of the same output size for every call (to flush a block over several calls); the port must answer each `LZ4F_decompress` and `LZ4F_getFrameInfo` call as liblz4 does, with the hint or error, the bytes read and written, and the frame info, then a hash of all the output. XXH32 is compared in one call and streamed. The compressors are compared call by call too: blocks compressed alone by one state for several (`LZ4_compress_fast_extState`, then `_fastReset`), at accelerations from 1 to past `LZ4_ACCELERATION_MAX`, into outputs large enough, a little too small or far too small, and as much as fits (`LZ4_compress_destSize`); streams after a dictionary loaded (`LZ4_loadDict`, `LZ4_loadDictSlow`) or attached (`LZ4_attach_dictionary`), with blocks around 4 KB, where liblz4 changes how it uses an attached one; the same for high compression, at every level from 1 to 13, with `favorDecSpeed`; and frames, from one to three per context, begun with a dictionary, a `CDict` or neither, with every preference (levels from acceleration 70,000 to 13, every block size and mode, checksums, content sizes right and wrong, `autoFlush`, `favorDecSpeed`), their input in pieces of every size, flushed now and then, some stored (`LZ4F_uncompressedUpdate`), some calls given too little room, some frames left unfinished before the next, and frames made in one call (`LZ4F_compressFrame`, `_usingCDict`); the port must return what each call returns and write the same bytes. 1,831 requests are compared with liblz4 where the oracle is built (Linux and macOS in CI), and `testdata/oracle/lz4.txt` replays 984 earlier answers everywhere else, including Windows, 32-bit and big-endian machines (the compressors' 375 only on 64-bit little-endian ones, where they were recorded: liblz4's output depends on the machine, which `tests/compress.rs` covers). The oracle leaves room after each of its buffers: liblz4's streams take a block that starts where their history ends as its continuation, by comparing pointers, which macOS's allocator, putting buffers side by side, made happen by chance. Before the first commit of the frame compressor, the requests were run with 8 more seeds, and its requests alone 70,000 times: no difference.
- **`tests/compress.rs`** compares the compressors with liblz4 through the `lz4` crate on every machine CI tests, 32-bit and big-endian ones included: blocks up to 3 MB, fast at accelerations up to 70,000 and at every high-compression level; and frames up to 1.5 MB through the `lz4` crate's `Encoder` and the port's, with every setting it can give, in writes of every size and flushes: the same bytes. Frames made in one call and call by call, with dictionaries and stored blocks, are decompressed again, by the port and by liblz4.
- **`tests/lz4.rs`** compares with liblz4 through the `lz4` crate on every machine CI tests: blocks liblz4 compressed at every level, up to 2 MB, decoded whole and partially, and damaged ones, which both must decode the same or refuse; frames liblz4 compressed with every setting, up to 6 MB, decoded in pieces of every size, and damaged ones.
- **`tests/decoder.rs`** reads `.lz4` streams with `Decoder`: liblz4's frames one after another, skippable frames between them, legacy frames of 8 MB blocks (made from liblz4's blocks), and what ends a stream (nothing, data that is not LZ4, trailing data, frames cut short anywhere). Files written by the `lz4` program 1.10.0 (`-l`, `-9 --content-size -BD -B4`, `-1 --no-frame-crc -BX`, and those concatenated) were read the same as `lz4 -d` reads them before the first commit.
- **A unit test** checks XXH32 against xxHash's own values.
- **`fuzz/fuzz_targets/lz4.rs`** decodes its input as a block with both, comparing the result and every byte of the output; reads it as a frame through the `lz4` crate's `Decoder` and the same loop over the port's context, comparing every read; decodes it in the ways the `lz4` crate cannot reach, and with `Decoder`, for panics; compresses it into a block and a frame with both, comparing them; and compresses it in the ways the `lz4` crate cannot reach, for panics and to decompress what is made (see [fuzz/README.md](../fuzz/README.md)). Before the first commit it ran for 20 minutes on 8 cores (31 million inputs), seeded with the recorded requests, with overflow checks and debug assertions on, and for 7 minutes on 4 cores (12 million) after the speed work: no difference and no panic. The compression modes ran for 20 minutes on 8 cores (580,000 inputs of up to 140 KB) before the first commit of the frame compressor, with debug assertions on: after two mistakes of the target's own, no difference and no panic.

Running the comparisons found what is behind several of the differences above: the frame compressor's comparisons found liblz4's two frame bugs (the write past the output, which crashed the oracle, and the stored blocks of linked frames, which made the port's search read past its dictionary), and the recorded answers a mistake of the port's own, which dropped a dictionary attached to a stream after an empty block, where liblz4 keeps it for the next. Earlier, the decoder's found that liblz4's two ways of decoding a block after a dictionary give different results on malformed blocks (the fuzzer), and that liblz4's frame context points before the output when a block flushed from its buffer over several calls ends a call, and then copies nothing (`tests/lz4.rs`; the port does the same without the pointer).

## The speed target

At least 0.95× liblz4's speed, as for zstd and zlib, measured with `tools/lz4-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench` fetches it):

```sh
cargo run --release -p lz4-bench -- [--levels 1,9] [--frame] [--compress] target/testdata/silesia
```

Blocks are decoded in one call each, with room for all the output. With `--frame`, frames of 4 MB linked blocks with a content checksum (`lz4`'s defaults) are read by each library's reader. With `--compress`, the same are compressed, blocks in one call each and frames through each library's writer; the port's must be liblz4's, byte for byte. The tool times lz4_flex too, the other LZ4 in Rust, with its safe code (its default) or, built with `--no-default-features`, its unsafe code; it has one compression level, its own, timed against liblz4's level 1. `--features unsafe-fast` builds the port with its feature.

### Where it stands: decoding

The safe build is below the target, the `unsafe-fast` one at it. AMD Ryzen 9 9950X (x86-64, Linux), October 2026, the 12 Silesia files compressed by liblz4 at levels 1 and 9, decoded as blocks in one call each, best of five rounds taken in turn, on one pinned core:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| hivepack::lz4 | 0.75× liblz4 | 0.70–0.83× | 0 of 24 |
| lz4_flex 0.14.0, its safe code (its default) | 0.77× | 0.64–0.89× | 0 of 24 |

With the `unsafe-fast` feature (off by default; see [unsafe.md](unsafe.md)), the fast loop reads and writes its pieces without bounds checks, as liblz4 does:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| hivepack::lz4, `unsafe-fast` | 0.96× liblz4 | 0.92–0.99× | 15 of 24 |
| lz4_flex 0.14.0, its safe code, in the same runs | 0.81× | | |

lz4_flex with its unsafe code was at 0.68–0.98× on five of the files (`dickens`, `mozilla`, `nci`, `reymont`, `x-ray`), where the port was at 0.73–0.85× safe and 0.92–0.99× with the feature.

As first ported, the safe port was at 0.65–0.86×. Most of the gap is bounds checks in the fast loop: liblz4 has six branches for a short sequence, the safe port up to a dozen checks more. The safe build decodes the most common sequence (a token, up to 14 literals and an offset in the next 18 bytes, and a match of up to 18 bytes) through windows of the input and output of a known size, where the compiler sees the copies are in bounds, and makes wild copies whose source ends before their destination in one copy; text files gained most (`dickens` from 0.64× to 0.77–0.79×). arm64 is not measured yet.

### Where it stands: compression

The same machine and corpus, blocks compressed in one call each with room for all the output, best of five rounds (three for high compression):

| | Level 1 | Acceleration 9 | Level 2 | Level 9 | Level 12 |
|---|---|---|---|---|---|
| hivepack::lz4 | 0.92–0.98× liblz4 (mean 0.95×) | 0.81–0.95× | 0.81–0.95× | 0.74–0.90× | 0.81–0.98× |
| lz4_flex 0.14.0, its safe code | 0.91–0.96×, 1.23× on `x-ray` | | | | |

Frames of 4 MB linked blocks with a content checksum, written through each library's writer (`--compress --frame`), best of three rounds:

| | Level 1 | Level 9 |
|---|---|---|
| hivepack::lz4 | 0.87–1.30× liblz4 | 0.76–0.91× |
| lz4_flex 0.14.0, its safe code | 1.09–1.92× | |

liblz4 compresses frames more slowly than blocks (its linked blocks go through `LZ4_compress_fast_continue`, then `LZ4_saveDict`); the port, whose stream functions are specialised as its block functions are, is faster on four files. lz4_flex makes its own blocks, not liblz4's. As first ported, the fast compressor was at 0.49–0.90×: `LZ4_compress_generic` is now inlined at each call, as liblz4's, each with its directives constant, and its search reads through a window of the input whose end is the search's own limit. High compression's strategies are inlined as liblz4's are, which made level 2 about 5% faster; reading the chains without bounds checks, tried in a scratch copy, gained 4–7% at level 9, and the safe ways to get there tried so far moved the speed by as much in either direction as the code's layout does.

## Progress

| liblz4 | Port | Status | Checked against liblz4 by |
|---|---|---|---|
| `lz4.c`: decoding | `lz4.rs` | done | `tests/oracle.rs`, every function, result, error position and byte written; `tests/lz4.rs` |
| `lz4.c`: `LZ4_streamDecode_t` | `lz4.rs`, `StreamDecode` | done | `tests/oracle.rs`, blocks one after another, with and without a dictionary |
| `xxhash.c`: XXH32 | `xxhash.rs` | done | xxHash's values; `tests/oracle.rs`, in one call and streamed |
| `lz4frame.c`: decoding | `lz4frame.rs` | done | `tests/oracle.rs`, call by call; `tests/lz4.rs` |
| `lz4.c`: encoding | `lz4_compress.rs` | done | `tests/oracle.rs`, every function, result and byte written; `tests/compress.rs` |
| `lz4.c`: `LZ4_stream_t` | `lz4_compress.rs`, `Stream` | done | `tests/oracle.rs`, blocks one after another, after dictionaries loaded or attached |
| `lz4hc.c` | `lz4hc.rs` | done | `tests/oracle.rs`, every level, alone, as much as fits, and in streams; `tests/compress.rs` |
| `lz4frame.c`: encoding | `lz4frame_compress.rs` | done | `tests/oracle.rs`, call by call; `tests/compress.rs` |
| `lz4file.c`: writing | `encoder.rs`, `Encoder` | done | `tests/compress.rs`, against the `lz4` crate's `Encoder` |
| `lz4file.c`: reading | `decoder.rs`, `Decoder`, the port's own | done | `tests/decoder.rs`, and the `lz4` program's files |

## Following new releases

When lz4 releases a new version:

1. Diff the two tags' `lib/` and port each change.
2. Update `UPSTREAM_VERSION`, the release in `testdata/manifest.json`, and the `lz4-sys` version that bundles it.
3. Run everything again.
