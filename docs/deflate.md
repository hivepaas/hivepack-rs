# Porting zlib

`hivepack::deflate` is a port of the official Deflate library, [zlib](https://zlib.net), to safe Rust. ZIP needs it first (see [zip.md](zip.md)), and gzip and every other Deflate-based format will use it too. The goal is the one [porting.md](porting.md) sets for zstd: the same output as zlib, at the same speed.

## The version

The port follows zlib **1.3.2** (tag `v1.3.2`, commit `da607da739fa6047df13e66a2af6b8bec7c2a498`, February 2026), the latest release as of October 2026. `hivepack::deflate::UPSTREAM_VERSION` names it.

## What following the official code means

The rules of [porting.md](porting.md):

- **The same layout.** Each file of zlib becomes a module of the same name: `inflate.c` becomes `crates/hivepack/src/deflate/inflate.rs`, `inffixed.h` becomes `inffixed.rs`.
- **The same names**, in snake case, with the C name in every doc comment. A stream and its state are one type, `Inflate` or `Deflate`, whose methods drop the prefix: `inflateSetDictionary` becomes `Inflate::set_dictionary`, `deflateParams` becomes `Deflate::params`.
- **The same algorithms, constants and tables.** The fixed-code tables of `inffixed.h` are copied as they are. The CRC tables of `crc32.h` and the static trees of `trees.h` are computed while compiling, by the functions zlib uses to write those files, and tests compare them with the files. The compressor's configuration table is zlib's. That is what makes the output identical.
- **The same results.** A call returns zlib's code, as `Result<Status, Error>`, and an error carries the message zlib leaves in `strm->msg`, such as `"invalid distance too far back"`.
- **Differences are marked** with a comment starting `Differs from zlib:`.

The main difference is the stream itself. zlib's `z_stream` holds pointers to the caller's input and output; the port takes them for each call as an `InBuffer` and an `OutBuffer`, a slice and a position, as `hivepack::zstd` does. Positions in the window, the code tables and the buffers are indices. A stream cannot be used before it is initialised or after it ends, so the checks zlib makes for that (`inflateStateCheck`, `deflateStateCheck`) have nothing to check.

The compressor keeps zlib's memory layout where the output depends on it: the symbol buffer overlays the pending output in one buffer (`pending_buf`), and the window's bytes past the input are those zlib leaves there. The few other differences:

- A gzip header's name and comment end at their first zero byte, or at their end; zlib needs the zero and would read past a buffer without one. An extra field shorter than `extra_len` is written with zeros after it.
- The operating system written in a gzip header is the one zlib's build would write: 3 (Unix), 10 on Windows, 19 on Apple systems.
- `deflateParams`, which calls `deflate()` with the stream's current buffers, takes them as arguments: `Deflate::params(output, input, level, strategy)`.
- The Deflate64 decoder, `InflateBack9`, has its own 64K window, which zlib's caller gives `inflateBack9Init`. Its `in()` and `out()` are the traits `BackIn` and `BackOut`, and the input it leaves unused, which zlib puts back in `strm->next_in` and `strm->avail_in`, comes with its result.

## How it is shown

The reference is zlib 1.3.2 itself, reached two ways: built from the sources bundled in `libz-sys` 1.1.31 (its `static` feature, so that a system zlib of another version is never used) and called through `flate2`, both development dependencies only; and `tools/zlib-oracle`, a small C program built from the zlib 1.3.2 release by `scripts/testdata.py`, as `tools/zstd-oracle` is for libzstd.

- **`tests/deflate.rs`** compresses the same inputs with the port and with zlib, in the same random pieces of input and output, with the same flushes (none, sync, full, partial, finish). Every call must return the same result and read and write the same number of bytes, and the bytes must be the same: at every level from −1 to 9, raw, zlib and gzip, with windows of 512 bytes to 32 KiB, on text, random bytes, runs, long-distance matches, `testdata`'s files and, where it is fetched, 400 KB of five Silesia files.
- **`tests/zlib.rs`** decompresses streams that zlib's own compressor wrote, with the port and with zlib, in the same pieces of input and output, chosen at random from one byte up. Every call must return the same result and message and read and write the same number of bytes, and the output must be the same. The streams are raw, zlib and gzip; at levels 0, 1, 6 and 9; with windows of 512 bytes to 32 KiB; with sync, full and partial flushes in between; with preset dictionaries, right and wrong; decompressed with a smaller window than they need; with a gzip header that has every field; and 2,880 of them damaged, with bytes changed, bits flipped and cut short. The inputs are text, random bytes, runs, matches from up to 40 KiB back, and the uncompressed files in `testdata/zstd/golden-compression`.
- **`tests/oracle.rs`** reaches what `flate2` cannot: `Flush::Block` and `Flush::Trees`, `data_type`, `inflateMark`, `inflatePrime`, `inflateSync`, `inflateValidate`, dictionaries set at any point, and the gzip header fields, on streams from every level, window, memory level, strategy and flush (`Z_BLOCK` included) of zlib's compressor, some of them damaged. Each request is a stream and a list of calls; the port must answer each call as zlib does: the result, bytes read and written, `data_type`, `inflateMark` and `msg`, then the totals, the check value, a hash of the output and the header. About 1,800 requests are compared with zlib where the oracle is built (Linux and macOS in CI), and `testdata/oracle/inflate.txt` replays 1,173 earlier answers everywhere else, including Windows, 32-bit and big-endian machines.

  The compressor is compared the same way, through the oracle's `deflate2` requests, for what `flate2` cannot set: every memory level and strategy (`Z_FILTERED`, `Z_HUFFMAN_ONLY`, `Z_RLE`, `Z_FIXED`), parameters out of range, gzip headers with every field, dictionaries before and between blocks, `deflateParams` and `deflateTune` between calls, `deflatePrime`, `deflateBound`, `Z_BLOCK`, and output space from none up. Each call is answered with the result, bytes read and written, `data_type`, `deflatePending`, `deflateUsed` and `msg`, then the totals, the check value and a hash of the output. About 800 requests are compared live, and `testdata/oracle/deflate.txt` replays 586.
- **`tests/deflate64.rs`** compares `Inflate9` with `infback9.c` too, on the oracle's answers live and recorded: with its input and output in pieces of random sizes, it must end as `infback9.c` ends, with the same message, and give the same output (`infback9.c` gives a full window at a time before an error). 19,000 requests over 40 seeds agreed before the first commit, every message among them, and the end and the output never depended on the pieces.
- **`tests/deflate64.rs`** compares Deflate64 decoding with zlib's `contrib/infback9`, through the oracle's `inflate9` requests. zlib has no Deflate64 compressor, so the test makes the streams: stored, fixed and dynamic blocks, with random complete codes up to 15 bits, lengths up to 65,538 and distances up to 65,536, knowing the data each decodes to. Some are damaged, some code a distance their table leaves out, and deflate streams and random bytes are given too. Each is decoded by `inflateBack9` with its input in random pieces and an `out()` that fails now and then; the port must give the same result and message, the same input left unused, the same number of `in()` and `out()` calls and the same output. Every message of `infback9.c` comes up. About 600 requests are compared live, `testdata/oracle/inflate9.txt` replays 414, and on every machine the generated streams must decode to their data.
- **`tests/infcover.rs`** is zlib's own coverage test of inflate, `test/infcover.c`, ported with the same inputs and expected results, including the messages of every data error.
- **Unit tests** compare the CRC tables with `crc32.h` and the static trees with `trees.h`, build `inffixed.h`'s tables with the ported `inflate_table` as zlib's `makefixed()` does, and `inffix9.h`'s with `inflate_table9` (whose entries for the two unused length symbols, 286 and 287, are from an older table, but are invalid codes either way), and check CRC-32 and Adler-32, combined or not, against their definitions.
- **`fuzz/fuzz_targets/inflate.rs`** and **`deflate.rs`** do what `tests/zlib.rs` and `tests/deflate.rs` do, with the fuzzer's input as the stream or the data (see [fuzz/README.md](../fuzz/README.md)). **`inflate9.rs`** decodes its input as Deflate64 all at once and in pieces, which must agree, and with `Inflate9`, which must end as `InflateBack9` does with the same output.

## The speed target

At least 0.95× zlib's speed, as for zstd, measured with `tools/deflate-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench` fetches it):

```sh
cargo run --release -p deflate-bench -- [--levels 1,6,9] [--stream | --compress] target/testdata/silesia
```

With `--compress`, the tool also checks that the port's streams are zlib's, byte for byte.

### Where compression stands

The port as it is, with no speed work: AMD Ryzen 9 9950X (x86-64, Linux), October 2026, Silesia at levels 1, 6 and 9, one call each, best of three rounds taken in turn:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| Compression | 0.99× zlib | 0.95–1.03× | 36 of 36 |

Every stream was zlib's, byte for byte.

### Where decompression stands

AMD Ryzen 9 9950X (x86-64, Linux), November 2026, the Silesia corpus compressed by zlib at levels 1, 6 and 9, best of three rounds taken in turn:

| | Mean | Range | At 0.95× or more |
|---|---|---|---|
| In one call | 1.61× zlib | 1.20–1.97× | 36 of 36 |
| Streaming, in pieces of 16 KiB as zlib's `zpipe.c` | 1.29× | 1.09–1.47× | 36 of 36 |

It was 0.82× in one call (0.71–0.86×) and 0.90× streaming before the speed work, all of it in `inflate_fast`; 0.97× (0.89–1.07×) and 1.04× (0.94–1.15×) before whole pieces; and 1.49× (1.12–2.04×) and 1.27× (1.01–1.51×) before tables of its own. What made the difference, measured at level 6 in one call:

- **Tables of its own, a word an entry.** A dynamic block's tables are built with roots of 11 and 8 bits where zlib's are of 9 and 6 (`LEN_ROOT`, `DIST_ROOT`; `enough 286 11 15` and `enough 30 8 15` give their room, 2,340 and 400 entries), so that fewer codes take a sub-table; and the fast loop's tables (`FastTables`) are made from them, each entry a word that says what it is (a literal, a link, the end of the block, an invalid code, or a base), the bits it takes with its extra bits, and its value, so that a code is one load and one test, and its extra bits come with it. inflate()'s own decoding takes the same bits from roots of 11 and 8 as from 9 and 6, and stops in the same places: a code is decoded once as many bits as it has are there, whatever the root, and `tests/oracle.rs`, which compares `avail_in`, `total_in` and `inflateMark` after each call, finds no difference. Fixed blocks keep `inffixed.h`'s tables, and the loop has tables made once for them. After a literal, two more literals of the root are decoded without going round, where the loop's test is known to hold for them (six bytes more of input left, two more bytes of output space): each where zlib's loop decodes it. The window's part of a match is copied by a function of its own, which takes the output's position and gives it back, so that the loop keeps its own registers. 1.49× to 1.61× in one call: `osdb`, `mr`, `reymont` and `x-ray` 17–23% faster, `ooffice` and `mozilla` 15%; `sao`, `nci` and `dickens` at level 1, almost all literals, 1–4% slower. One ZIP entry of 2.3 GB of programs and libraries inflates in 2.93 s where it took 3.31 s, CRC included, as zlib-rs takes 2.80 s without its CRC. The state is 11 KB larger for the room, and the tables 18 KB, made with the first dynamic block. Tried on zlib's own tables, and slower: looking the next code up before the refill (−3%), three pieces copied whatever a short match's length (−1%), the loop made twice with constant masks for roots of 9 and 6 (−3%), and literals decoded without going round (−6%), which only the words of these tables made worth it.

- **Whole pieces, sixteen bytes at a time.** Where the output has room for a piece past a match, a match at least eight bytes back is copied in whole pieces, the last one too, writing up to 15 bytes past the match into space the output has not reached yet, as zlib-ng and libdeflate copy; sixteen bytes at a time where the match starts sixteen or more back. The last piece cut to the match, byte by byte, was most of a copy's cost on text, whose matches are short. 0.97× to 1.49× over the levels; text at level 1 gains the most (dickens and reymont 0.89× to 2.0×), x-ray the least (1.0× to 1.12×). Inflating the 2.3 GB of a computer's own programs and libraries, as one ZIP entry, takes 3.60 s where it took 4.55 s, CRC included. Pieces of 32 bytes made little more difference (1%), and are not in the port. `Inflate::inflate` may so write over the bytes of `output` past what it says it wrote, as zlib-ng's does; zlib writes none.

- **Eight bytes of input at once.** zlib pulls two bytes into its bit buffer whenever it has fewer than 15 bits, up to six times per length and distance. The port reads eight bytes once per code, to 56 bits or more, which is enough for a length, a distance and their extra bits (48 at most). The bits past those counted are the input's next bits, so they can be or-ed in again. 0.83× to 0.94×.

  Where the loop stops has to be zlib's too, or an error found by one loop and not the other leaves a different `inflateMark`. zlib's loop stops when fewer than six bytes are left past those it has pulled, which depends on when it pulled them; but it then gives back the bytes it did not use, and inflate() calls it again at once if six or more are left. So zlib decodes a code in its fast loop exactly when six bytes or more are left past the bytes already used, and the port's loop tests that, which costs nothing. The first version of the speed work needed eight bytes to enter the loop, and `tests/oracle.rs` found the difference.
- **Matches copied eight bytes at a time**, when they start at least eight bytes back, each piece read from bytes already written. zlib copies three bytes per loop; byte by byte, every one was a bounds check. +3%.
- **Runs of one byte filled**: matches one byte back, the commonest of those that overlap. +2%, and 11% on `mr`.
- **Tables of a fixed size.** `inflate_fast` took each code table as an array of 1024 entries (the most a table needed was 852), so that an index masked with 1023 needed no bounds check. +1%. Its own tables have 4,096 and 512 entries for the same reason.

Tried, and not worth it: copying matches two to seven bytes back eight bytes at a time too, from the nearest multiple of their distance that is eight or more back. That made decompression 9% slower on average, and is not in the port.

The slowest input is now `sao`, star positions that are almost all literals. arm64 is not measured yet.

### Deflate64

zlib's `contrib/infback9` has no fast loop: it decodes one code at a time and pulls one byte at a time, and so does the port. A zlib stream with no length code 285 decodes the same as Deflate64; at level 6 that is three of the Silesia files. Timed by hand (`tools/deflate-bench` cannot reach `infback9`, which `libz-sys` does not bundle), same machine, best of seven runs:

| File | Port | zlib's `infback9` | |
|---|---|---|---|
| osdb | 550 MB/s | 492 MB/s | 1.12× |
| sao | 370 MB/s | 360 MB/s | 1.03× |
| x-ray | 255 MB/s | 265 MB/s | 0.96× |

It was 0.92–0.94× as first ported. The codes of a block are now decoded in a loop of their own, with the block's tables looked up once, and a match that does not overlap the bytes it writes is copied at once rather than byte by byte.

`InflateBack9` takes the whole stream through call-backs, so a reader that pulls data a piece at a time, as a ZIP reader does, cannot use it. `Inflate9` is for that: hivepack's own, with the structure of `inflate.c` (a mode for each place where the input or the output can run out, the 64K window kept between calls, copies from the output or the window) and the decoding and messages of `infback9.c`. It reads input a byte at a time as it needs it, as `inflate.c`'s slow loop does, so at the end of a stream what is left of the input is what follows it. On the same files and machine:

| File | One call | In pieces of 16 KiB | zlib's `infback9` |
|---|---|---|---|
| osdb | 530 MB/s (1.11×) | 482 MB/s (1.00×) | 479 MB/s |
| sao | 343 MB/s (0.97×) | 321 MB/s (0.91×) | 353 MB/s |
| x-ray | 233 MB/s (0.89×) | 223 MB/s (0.85×) | 262 MB/s |

Its literals are written in the loop that decodes the length codes, while there is room, without going through a mode of their own; that took it from 0.75–0.91×. Masking the root table's index, to spare a bounds check, made it slower and was left out. On mostly literals it is still below the 0.95× target: a fast loop as `inflate.c` has would be the next step.
## Deflate in threads, beside the port

zlib compresses on one thread. `DeflateMt` (`deflate/mt.rs`) compresses in threads as pigz does, and is not part of the port: nothing in it changes what `Deflate` does.

- **One stream.** The input is cut into blocks of 128 KiB (`MtOptions::block_size`), and each is compressed by a `Deflate` of raw deflate, reset for it, with the 32 KiB of input before it as its dictionary (`Deflate::set_dictionary`), so that it may refer back to them as one stream would. A block is ended on a byte as pigz 2.8 ends one: `Flush::Block`, then empty fixed blocks of 10 bits (`Deflate::prime`) until the bits left make whole bytes, or a sync marker (`Flush::SyncFlush`) where an odd number of bits left cannot; the last block is finished (`Flush::Finish`). The blocks one after the other are one deflate stream, in one gzip member with its CRC-32, combined from each block's (`crc32_combine`), and its size: what every gzip reader reads. `MtOptions::raw` leaves out gzip's header and trailer, as a ZIP entry has it.
- **The same output whatever the threads.** Blocks end where their size says, and where a flush or the end is asked for, never where the threads would: the stream depends on the input, the options and where the flushes are, and is the same with `Threads::One`, which compresses each block in the call that fills it, as with many. A full block is given to a thread only once more input says it is not the last, as pigz reads ahead to know; so at the default block size and without flushes the stream is pigz's, byte for byte, at every level, and its header too but for the operating system, which is the one zlib's build would write (pigz writes Unix's).
- **Flushes.** `Flush::SyncFlush` ends the current block on a byte, so that what was given can be decompressed; `Flush::FullFlush` ends it with a sync marker, and the block after it takes no dictionary, so that a reader can start there. A flush with nothing given since the last writes nothing, where zlib writes an empty stored block. `Flush::PartialFlush`, `Flush::Block` and `Flush::Trees`, which say where zlib's own blocks end, are refused.
- **Memory.** With more than one thread, two blocks for each thread are in flight at most, and a call waits for the oldest when it can go no further without. Each thread keeps its `Deflate`, 256 KiB of zlib's buffers; each block holds its input, the 32 KiB before it and room for what it compresses to: 0.84 MiB a thread at the default block size. `MtOptions::memory_limit` lowers the threads until `MtOptions::memory_usage` fits it, one always allowed, and the stream is the same ([memory.md](memory.md#deflate-in-threads)).
- **What it costs.** A block's start has only the 32 KiB before it, which is all a deflate stream can refer back to anyway, and its Huffman codes are chosen for its own data: on 546 MB of mixed files, the stream is smaller than zlib's one stream, by 0.12% at level 1, 0.03% at 6 and 0.04% at 9. One thread is 5% slower than `Deflate` at level 1, for the dictionary each block takes in.
- **Reading.** A gzip member is one stream, which one thread decodes from its start: reading it is no faster.

`tests/deflate_threads.rs` compresses inputs of no bytes up to several blocks, at levels 0, 1, 6 and 9, with every strategy and blocks of other sizes, with 1, 2, 8 and all threads, in one call and a little at a time through buffers down to one byte, and compares them byte for byte; reads them back with the port's inflate and `gzip -d`; checks the header and the trailer, raw deflate as the member's stream, flushes after which what was given decompresses, and after a full flush, needs nothing before it; and compares the streams with `pigz -n` at levels 1, 2, 6 and 9 where it is installed. `tests/memory_limits.rs` measures what it holds against its estimate.

On an AMD Ryzen 9 9950X (16 cores, 32 threads), November 2026, 546 MB of mixed files (a tar of source code, documents, binaries and media) compressed from memory, one round; `pigz` 2.8 with its own threads, on zlib 1.3.1:

| Level | `Deflate`, one stream | `DeflateMt`, 1 thread | 8 | 16 | 32 | `pigz -p 32` |
|---|---|---|---|---|---|---|
| 1 | 3.85 s, 234,013,219 B | 4.06 s | 0.54 s | | 0.22 s | 0.21 s |
| 6 | 10.94 s, 215,844,640 B | 11.16 s | 1.47 s | 0.78 s | 0.53 s | 0.50 s |
| 9 | 30.43 s, 214,970,712 B | 30.74 s | 4.31 s | | 1.56 s | 1.42 s |

`DeflateMt`'s streams are 233,725,171, 215,781,426 and 214,892,302 bytes, whatever the threads, and pigz's the same but for its header's file name.

## libdeflate's compressor, beside the port

zlib's level 9 parses lazily, looking one position ahead. 7-Zip's Deflate and libdeflate's levels 10 to 12 look for the cheapest way through each block, and make streams a few per cent smaller, which a ZIP writer wants. `Compressor` (`deflate/libdeflate/`) is a port of [libdeflate](https://github.com/ebiggers/libdeflate)'s compressor, a second port beside zlib's, with the same rules. It shares no code with zlib's; its tests inflate what it writes with the zlib port's `Inflate`.

### The version

The port follows libdeflate **1.26** (tag `v1.26`, commit `75390569905da2f4aa03c5bc03e03c9d18b9b2d0`): `libdeflate-1.26.tar.gz` from the release's page, SHA-256 `125856d4656e0feab660f94842f835923410c9281fedbcee64598c918da42b5a`. `hivepack::deflate::LIBDEFLATE_VERSION` names it.

### What is ported

Each file of libdeflate's `lib/` that the compressor needs is a module of the same name in `deflate/libdeflate/`: `deflate_compress.c` (with `deflate_compress.h`) becomes `deflate_compress.rs`, `deflate_constants.h` `deflate_constants.rs`, and `matchfinder_common.h`, `hc_matchfinder.h`, `ht_matchfinder.h` and `bt_matchfinder.h` the modules of their names. What they take from `common_defs.h` and `lib_common.h`, `bsr32` and the unaligned loads, is in `common_defs.rs`. Functions keep their C names, which are already in snake case, and each one's doc comment names its C original. The tables are copied as they are, and so are the levels' parameters, the block splitting and the cost model; unit tests check the slot tables against their bases, and the static codes against the format's.

The API is libdeflate's, in Rust's shape:

- `Compressor::new(level)` is `libdeflate_alloc_compressor`: levels 0 to 12, and -1 for the default, 6, as libdeflate 1.26 takes it; `None` for any other, where libdeflate returns `NULL`.
- `Compressor::deflate_compress(input, output)` is `libdeflate_deflate_compress`: the whole input at once into the output, raw deflate, and the size written, or 0 if it does not fit. Past the size returned, the output may have been written to, as libdeflate writes whole words.
- `Compressor::deflate_compress_bound(len)` is `libdeflate_deflate_compress_bound`, and `Compressor::compression_level()` `libdeflate_get_compression_level`.

A compressor keeps its tables from one call to the next, as libdeflate's does, and its output does not depend on what it compressed before. It takes what libdeflate's takes: about 0.2 MB at level 1, 0.7 MB at levels 2 to 9, and 9 MB at levels 10 to 12.

### What is not

- The decompressor, the zlib and gzip wrappers (`libdeflate_zlib_compress`, `libdeflate_gzip_compress` and their decompressors), and the checksums: the zlib port has all of them.
- The memory allocator of `libdeflate_alloc_compressor_ex`'s options and `libdeflate_set_memory_allocator`, and `libdeflate_free_compressor`, which dropping does.
- The processor-specific `matchfinder_init` and `matchfinder_rebase` (SSE2, AVX2, NEON and RISC-V vectors): plain loops, which the compiler vectorizes, give the same tables. And `prefetchw`, which only hints the processor: safe Rust cannot prefetch.
- The build options, which keep libdeflate's defaults: `SUPPORT_NEAR_OPTIMAL_PARSING` 1 and the block, sequence and cache lengths. The port writes bits as libdeflate does on a 64-bit machine; on a 32-bit one libdeflate flushes its bit buffer more often, and writes the same bits.
- `programs/`: `libdeflate-gzip` and the benchmark.

Where the Rust code works differently, a comment says so, starting `Differs from libdeflate:`. The input and output are slices, and positions in them indices where libdeflate has pointers; the parsers' union of data is an enum; and the loads read little-endian on any machine, where libdeflate reads in the machine's order where it only compares the bytes, so the output is the same on both.

### How it is shown

The reference is libdeflate 1.26 itself: `tools/libdeflate-oracle`, a small C program built from the release by `scripts/testdata.py` with the flags of libdeflate's release build (`-O2 -DNDEBUG`), as `tools/zlib-oracle` is for zlib. It keeps a compressor for each level, as a program does, and answers each request with what each call returned and a hash of what it wrote.

- **`tests/deflate_libdeflate.rs`** compresses generated inputs with the port and with libdeflate, at every level from -1 to 12, into output buffers of the bound, of exactly the stream's size, of one byte less and one more, of none, of a few bytes, and of sizes at random below the stream's: each call must return the same size, and write the same bytes. Each stream that fits must be the same whatever the buffer, and must inflate back to the input with `Inflate`. The inputs are text, random bytes, runs, a piece repeated and now and then changed, matches of 258 bytes and more, small alphabets, records of numbers, text with bytes changed, prefixes of one string a byte longer each time, words of three bytes, and pieces of several kinds joined, whose changes the block splitting has to find; from no bytes to 4 MB, every size up to 64 and sizes about where blocks end, and `testdata/zstd/golden-compression` and Silesia where it is fetched. Two inputs end blocks early: 700 KB of random words of three bytes, whose matches fill the greedy and lazy parsers' 50,000 sequences, and 1.2 MB of random bits, a byte each, at whose positions the binary trees find more than five matches and fill the near-optimal parser's match cache. By default the test compares 39,032 calls, 2,788 at each level, in under 30 seconds; three longer runs with other seeds (`HIVEPACK_LIBDEFLATE_SEED`, `HIVEPACK_LIBDEFLATE_INPUTS=100`) compared 564,312 more, 40,308 at each level. Every one agreed. libdeflate's own check that a block takes the bits its cost said (an `ASSERT` in `deflate_flush_block`) is a `debug_assert!` in the port, and holds in every test.
- **`fuzz/fuzz_targets/deflate_libdeflate.rs`** compresses the fuzzer's input at a level its first byte picks: the stream inflates back, is the same from the same compressor again and from a new one, does not fit a byte shorter, and fits a buffer of a size its second byte picks as the same stream or not at all.

### Speed and size

On an AMD Ryzen 9 9950X (x86-64, Linux), November 2026, one thread, with `tools/deflate-bench --libdeflate`: libdeflate 1.26 built as above, and the port, each in one call with room for the whole stream, best of three rounds taken in turn; the zlib port at the same level, or 9 for 10 to 12, beside them. The inputs are a tar of `/usr/include` (54.4 MB) and a tar of 209 shared libraries from `/usr/lib/x86_64-linux-gnu` (100.2 MB):

| Input | Level | libdeflate 1.26 | Port | Port / libdeflate | Size, both | zlib port (its level) | Its size |
|---|---|---|---|---|---|---|---|
| `/usr/include` | 1 | 513 MB/s | 478 MB/s | 0.93× | 10,623,096 | 280 MB/s (1) | 11,890,366 |
| | 6 | 223 MB/s | 193 MB/s | 0.87× | 9,468,047 | 85.7 MB/s (6) | 9,442,478 |
| | 9 | 78.5 MB/s | 70.4 MB/s | 0.90× | 9,317,096 | 32.9 MB/s (9) | 9,347,465 |
| | 12 | 7.5 MB/s | 7.9 MB/s | 1.05× | 8,965,509 | 35.7 MB/s (9) | 9,347,465 |
| Shared libraries | 1 | 298 MB/s | 266 MB/s | 0.89× | 39,209,839 | 144 MB/s (1) | 39,974,873 |
| | 6 | 147 MB/s | 127 MB/s | 0.87× | 35,954,026 | 40.6 MB/s (6) | 36,411,044 |
| | 9 | 52.8 MB/s | 46.7 MB/s | 0.88× | 35,743,790 | 11.8 MB/s (9) | 36,233,124 |
| | 12 | 11.2 MB/s | 11.6 MB/s | 1.03× | 34,732,729 | 13.1 MB/s (9) | 36,233,124 |

The streams are libdeflate's, byte for byte. At levels 1 to 9 the port is 0.87–0.93× as fast as libdeflate (levels 2 to 8, measured too on `/usr/include`, 0.86–0.89×); at 10 to 12, where most of the time goes into the binary trees and the minimum-cost path, it is a little faster. The hash chains' loop of levels 2 to 9 is where the difference is: in the port, the bytes compared are bounds-checked and libdeflate's prefetch of the next position's buckets is left out, but taking the checks out made no difference (1%), and neither did reading the next buckets as a prefetch would. The compiled loop keeps fewer of its values in registers than GCC's.

The near-optimal levels are what they are for: level 12 makes streams 4.1% smaller than the zlib port's level 9 on both inputs, at 0.22× its speed on the headers and 0.89× on the libraries, where zlib's long hash chains are slow. libdeflate's level 6 is 2.6× and 3.6× as fast as zlib's, its streams 0.3% larger on the headers and 1.3% smaller on the libraries; its level 9 is smaller than zlib's 9 on both.

## Progress

| zlib | Port | Status | Checked against zlib by |
|---|---|---|---|
| `zlib.h`, `zconf.h`, `zutil.{h,c}` (the parts inflate uses) | `zutil.rs` | done | the return codes and messages in every comparison |
| `adler32.c` | `adler32.rs` | done | the definition; the trailers of zlib streams |
| `crc32.c`, `crc32.h` | `crc32.rs` | done; with `unsafe-fast`, arm64's CRC-32 instructions where zlib uses them, and x86-64's carry-less multiplication (`PCLMULQDQ`), which zlib does not use, folding as zlib-ng does: 22 GB/s where the braided code runs at 7.2 (see [unsafe.md](unsafe.md)) | `crc32.h`'s tables; the definition; the trailers of gzip streams; the instructions against the braided code |
| `inftrees.{h,c}`, `inffixed.h` | `inftrees.rs`, `inffixed.rs` | done | `inffixed.h` rebuilt; `infcover.c`'s `cover_trees`; every dynamic block in `tests/zlib.rs` |
| `inffast.{h,c}` | `inffast.rs` | done; its own tables of roots of 11 and 8 bits, made from zlib's | `tests/zlib.rs`; `tests/oracle.rs`; `infcover.c`'s `cover_fast` |
| `inflate.{h,c}` | `inflate.rs` | done | `tests/zlib.rs`; `tests/oracle.rs`, for every function and flush; `infcover.c`'s `cover_support`, `cover_wrap` and `cover_inflate` |
| `trees.{h,c}` | `trees.rs` | done | `trees.h`'s tables; every block of `tests/deflate.rs` and `tests/oracle.rs` |
| `deflate.{h,c}` | `deflate.rs` | done | `tests/deflate.rs`, byte for byte, call by call; `tests/oracle.rs`, for every function, strategy, memory level and flush |
| `compress.c`, `uncompr.c` | | later | |
| Compressing in threads (pigz's way, zlib has none) | `mt.rs` | done | `tests/deflate_threads.rs`: the same stream whatever the threads, pigz 2.8's byte for byte |
| `contrib/infback9`: `infback9.{h,c}`, `inftree9.{h,c}`, `inffix9.h`, `inflate9.h` (Deflate64) | `infback9.rs`, `inftree9.rs`, `inffix9.rs` | done | `tests/deflate64.rs`, through the oracle; `inffix9.h` rebuilt |
| Deflate64 a piece at a time (hivepack's own, from `inflate.c` and `infback9.c`) | `inflate9.rs` | done | `tests/deflate64.rs`: the same ends, messages and output as `infback9.c` |
| libdeflate 1.26's `deflate_compress.c`, `deflate_compress.h`, `deflate_constants.h`, `matchfinder_common.h`, `hc_matchfinder.h`, `ht_matchfinder.h`, `bt_matchfinder.h` (beside the port) | `libdeflate/*.rs` | done | `tests/deflate_libdeflate.rs`, byte for byte at every level, through `tools/libdeflate-oracle` |

## Not ported, for now

- `infback.c`: `inflateBack`, a callback interface to the same decoder.
- `gzlib.c`, `gzread.c`, `gzwrite.c`, `gzclose.c`: reading and writing gzip files. The gzip format itself is in `inflate.c` and is ported.
- Parts that exist only because zlib is in C: custom allocators (`zalloc`, `zfree`), the version checks of `inflateInit_` and `deflateInit_`, the `method` argument of `deflateInit2` (always `Z_DEFLATED`), the checks of a null or uninitialised stream, and building the CRC tables on first use (`DYNAMIC_CRC_TABLE`).
- Build options that zlib leaves off by default: `INFLATE_STRICT`, `INFLATE_ALLOW_INVALID_DISTANCE_TOOFAR_ARRR` (so `inflateUndermine` always fails, as in a default build), `PKZIP_BUG_WORKAROUND`, `BUILDFIXED`, and in the compressor `FASTEST`, `LIT_MEM`, `UNALIGNED_OK`, `FORCE_STATIC`, `FORCE_STORED`, `GEN_TREES_H` and `ZLIB_DEBUG`.
- `contrib/`, except `infback9`.

## Following new releases

The release followed until now is kept in the [mirror of upstream sources](../testdata/README.md#the-upstream-sources-mirrored), to compare the new one with even once its URL is gone. The new release's source set goes into the manifest and the mirror: `python3 scripts/testdata.py mirror --set <name>`.

When zlib releases a new version:

1. Diff the two tags and port each change.
2. Update `UPSTREAM_VERSION` and the `libz-sys` version that bundles the new release.
3. Run everything again.

When libdeflate does, the same for `lib/deflate_compress.c` and the headers it includes: diff, port each change, update `LIBDEFLATE_VERSION` and the `libdeflate-*-source` set (and the oracle's), and run `tests/deflate_libdeflate.rs` again.

## Licenses

The port is derived from zlib, which is under the zlib license. That is why `hivepack::deflate` is under the zlib license, and its [LICENSE](../crates/hivepack/src/deflate/LICENSE) keeps zlib's notice and says that this is an altered version, as the license asks. `tests/infcover.rs` is derived from zlib's `test/infcover.c`, under the same license.

The port of libdeflate's compressor, `deflate/libdeflate/`, is derived from libdeflate, which is under the MIT license (Copyright 2016 Eric Biggers, 2024 Google LLC). Its [LICENSE](../crates/hivepack/src/deflate/libdeflate/LICENSE) keeps that notice, and says that this is an altered version. `hivepack::deflate` is so under `Zlib AND MIT`; both are in the crate's `license` field already. `tools/libdeflate-oracle` is under MIT, as the rest of hivepack's own code.
