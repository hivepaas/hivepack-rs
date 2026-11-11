# Porting lzokay's LZO1X decompressor

`hivepack::lzo` decompresses LZO1X blocks in safe Rust: the format of liblzo2's `lzo1x_*` compressors, which SquashFS images made with `-comp lzo` hold (SquashFS's compressor 3, decoded a block at a time with liblzo2's `lzo1x_decompress_safe`, by `unsquashfs` and by the Linux kernel's own decoder alike), and UBIFS, Btrfs and `lzop` hold too. It is a port of the decompressor of [lzokay](https://github.com/jackoalan/lzokay), under the MIT license, made to give the results of liblzo2's safe decoder: the same bytes on every stream, and on a damaged one the same error, with the same bytes left in the output.

Only decompression of raw blocks is here: one call, `decompress(input, output)`, which returns the number of bytes written or an `Error`. Not the `.lzo` files of `lzop`, which wrap blocks in headers and checksums, and no compression.

## The version

lzokay has no releases. The port follows its latest commit, **`db2df1fcbebc2ed06c10f727f72567d40f06a2be`** (22 October 2023, "Fix building on gcc>=12 and Clang >=13 by including `<iterator>` explicitly"), on its `master` branch, still the latest as of November 2026. `hivepack::lzo::UPSTREAM_VERSION` names it. lzokay's `LICENSE` is the MIT license (Copyright (c) 2018 Jack Andersen), kept in [crates/hivepack/src/lzo/LICENSE](../crates/hivepack/src/lzo/LICENSE).

What the port's results are compared with is **liblzo2 2.10** (1 March 2017, the latest release), `lzo-2.10.tar.gz` from [oberhumer.com](https://www.oberhumer.com/opensource/lzo/), SHA-256 `c0f892943208266f9b6543b3ae308fab6284c5c90e627931446fb49b4221a072`; `hivepack::lzo::LIBLZO2_VERSION` names it. liblzo2 is under the GPL, version 2 or later. It is used only to build the test oracle, `tools/lzo-oracle`, and is never part of hivepack: none of its code is in the port, which is lzokay's, and the oracle is a program apart that the tests run.

## What following lzokay means

The rules of [porting.md](porting.md), for a library of one file:

- **The same layout.** `lzokay.cpp`'s `decompress` is `crates/hivepack/src/lzo/lzokay.rs`'s `decompress`; lzokay's compressor, the rest of the file, is not ported.
- **The same names**, in snake case: `CONSUME_ZERO_BYTE_LENGTH` is `zero_byte_length`, `M2MaxOffset` `M2_MAX_OFFSET`, and `EResult`'s errors keep their names in `Error` (`InputOverrun`, `OutputOverrun`, `LookbehindOverrun`, `InputNotConsumed`). lzokay's comments, which describe each instruction from the Linux kernel's `Documentation/lzo.txt`, are kept where its code is.
- **The same loop**: the first byte, then each instruction told by its high bits and, for the low ones, by the literals the one before copied (lzokay's `state`), each match copied and then the 0 to 3 literals after it.
- **Differences are marked** with a comment starting `Differs from lzokay`. Each is there so that the port returns what liblzo2's `lzo1x_decompress_safe` returns.

### Where lzokay and liblzo2 differ, and the port follows liblzo2

On every valid stream, lzokay and liblzo2 give the same bytes. On damaged ones they do not always fail alike, and lzokay can read past its input:

- **The order of the checks, and liblzo2's slack.** liblzo2 asks for 3 bytes of input at the start of an instruction that no literals came before, and for 3 more than a run of literals takes: the least the next instruction needs, the end-of-stream marker being 3 bytes. It checks the output before the input, and copies a match before it checks for the literals after it. lzokay asks for the bytes as it reads them, the input first, and checks the input for the literals and the output for both before it copies the match. So on a damaged stream liblzo2 can fail with `LZO_E_INPUT_OVERRUN` where lzokay finds a match before the output, or with `LZO_E_OUTPUT_OVERRUN` where lzokay finds the input short; and an output too small for the literals after a match is left with that match in it by liblzo2, without it by lzokay. The port checks where and in the order liblzo2 does.
- **A short input.** lzokay refuses an input of less than 3 bytes with `InputOverrun` before it writes anything; liblzo2 asks for one byte, and for the rest as it reads them, so that `12 61` into an empty output is `LZO_E_OUTPUT_OVERRUN`.
- **The end-of-stream marker's length.** The marker is an M4 instruction whose distance is 0; liblzo2's compressors write it as `11 00 00`, of length 3. lzokay fails with `EResult::Error` (-1) on a marker of another length; liblzo2 takes any length, and so does the port.
- **Bytes after the marker.** lzokay returns `EResult::InputNotConsumed`, which it numbers 1, as a success; liblzo2 returns `LZO_E_INPUT_NOT_CONSUMED` (-8), which `unsquashfs` and the kernel take for a failure. The port returns `Err(Error::InputNotConsumed)`, with the block decoded in the output, as liblzo2 leaves it.
- **The zero bytes of a long length.** A length too long for its instruction goes on in zero bytes, each 255 more, then a byte that is not zero. lzokay's `CONSUME_ZERO_BYTE_LENGTH` reads on while the bytes are zero, without looking at where the input ends, so a damaged stream that ends in zeros makes it read past the input. liblzo2 checks for a byte after each one, and so does the port. Past a length of `usize::MAX - 511`, liblzo2 fails, with `LZO_E_INPUT_OVERRUN` for literals and `LZO_E_OUTPUT_OVERRUN` for a match (`TEST_IV`, `TEST_OV`), where lzokay fails on its count of bytes with `EResult::Error`; only a 32-bit machine gets there, after 16 MiB of zero bytes.
- **The error numbers** are liblzo2's (`Error::number`): -4, -5, -6 and -8. lzokay's are -2, -3, -4 and 1. liblzo2's safe LZO1X decoder never returns `LZO_E_ERROR` or `LZO_E_EOF_NOT_FOUND`.
- **Copies.** lzokay copies a byte at a time. The port copies literals, and a match apart from what it writes, in two pieces that may overlap when they are 32 bytes or less (1 to 3 bytes as the first, the middle and the last), and with `copy_from_slice` when longer; a match that overlaps what it writes, 8 bytes back or more, in pieces of 8, as liblzo2 does on 64-bit machines; and one less than 8 back a byte at a time. Nothing is written past the end of what is decoded, as in both: a larger output keeps its bytes past it.

### Not ported

lzokay's compressor; liblzo2's other decoders (`lzo1x_decompress`, which does not check its input, `lzo1x_decompress_dict_safe`, with a dictionary before the output, and the LZO1, LZO1A to LZO1Z and LZO2A formats); `lzop`'s files. Nor the Linux kernel's LZO-RLE, a variant whose blocks start with 17 and a version byte, written only by the kernel's own compressor for zram, never in a SquashFS image: liblzo2 reads such a block as an M4 instruction at the start, and fails, as the port does.

## How it is shown

The reference is liblzo2 2.10 itself, through `tools/lzo-oracle`, a small C++ program that `scripts/testdata.py` builds (sets `lzo-2.10-source`, `lzokay-db2df1f-source` and `lzo-oracle`, in the `generated` group): liblzo2's C files for the LZO1X compressors and the safe decoder, compiled as C with `-O2`, as liblzo2's own build does, and lzokay's `lzokay.cpp`, the code the port follows. Its requests compress with liblzo2 (`lzo1x_1`, its `1_11`, `1_12` and `1_15` forms, and `lzo1x_999` at every level 1 to 9), and decode into an output of exactly a given size, filled with a pattern first, with `lzo1x_decompress_safe` and with `lzokay::decompress`, answering each one's result, output length and a hash of the whole output, past what was written too. lzokay reads its input from a copy followed by a byte `0xff`, which stops its count of zero bytes there.

- **`tests/lzo_oracle.rs`** compares the port with liblzo2 where the oracle is built (Linux and macOS in CI), and replays `testdata/oracle/lzo.txt`, 1,962 earlier answers of liblzo2's, everywhere else, Windows, 32-bit and big-endian machines included. The inputs are of many kinds and sizes: empty and of a few bytes, random bytes, random bytes of small alphabets, runs of up to 5,000 bytes (whose lengths take many zero bytes), short periods, text, and random pieces with copies of earlier ones from up to 49,200 bytes back, of every length; sizes around where `lzo1x_1` gives up looking for matches (20 bytes) and around the 49,152 bytes it compresses at a time, and SquashFS's blocks of 128 KiB and 1 MiB, by every compressor. Each stream is decoded into an output of exactly its size, one byte short, empty, and larger; and damaged, with bits flipped, bytes changed, cut short, bytes inserted, and bits flipped in its last bytes, where the marker is. The port must give liblzo2's answer to every request: the same result, the same length, and the same bytes in all of the output. 3,239 requests are compared: 1,468 decode, 609 fail with `LZO_E_INPUT_OVERRUN`, 824 with `LZO_E_OUTPUT_OVERRUN`, 331 with `LZO_E_LOOKBEHIND_OVERRUN` and 7 with `LZO_E_INPUT_NOT_CONSUMED`. No difference.
- **lzokay beside them.** In the same requests, lzokay gives liblzo2's bytes on all 1,217 of liblzo2's streams decoded whole into outputs large enough, and wherever it decodes a damaged stream, liblzo2 decodes it the same. Of the 2,022 other requests (outputs too small, and damaged streams), 1,977 fail or decode alike in both, and 45 differ as above: 28 that liblzo2 refuses with `LZO_E_OUTPUT_OVERRUN` and lzokay with `InputOverrun` (the order of the checks); 2 that liblzo2 refuses with `LZO_E_INPUT_OVERRUN`, for want of its 3 bytes of slack, where lzokay reads on and finds a match before the output, with other bytes left in it; 12 that liblzo2 decodes and lzokay refuses with `Error`, and 3 that liblzo2 decodes with bytes after them (`LZO_E_INPUT_NOT_CONSUMED`) and lzokay refuses with `Error`: markers of another length than 3.
- **The Silesia corpus**, when it is fetched (`--group bench`): each of its 12 files compressed by `lzo1x_1` in blocks of 128 KiB and of 1 MiB, and its first 4 MiB by `lzo1x_999` in blocks of 128 KiB, every block decoded into exactly its size by the port and by liblzo2: 2,212 blocks, each the file's bytes.
- **Unit tests** in `lzokay.rs` decode streams made by hand: each instruction, the marker with other lengths, bytes after it, inputs cut short at every byte, outputs exactly the size, one byte short and larger, and matches that overlap what they write.
- **`fuzz/fuzz_targets/lzo.rs`** decodes any input into outputs of two sizes the input picks, and into the smaller again filled differently: no panic, the same result both times, the same bytes written and nothing past them, and the larger output agreeing (the same end, or further where the smaller ran out of room). There is no LZO compressor in Rust to round-trip with, and liblzo2 is not linked into the fuzzer. Before the first commit it ran for 5 minutes on 8 cores, seeded with the recorded requests: 3.9 million inputs, no failure; and for 3 minutes on 8 cores with debug assertions and overflow checks on (`cargo fuzz run -a`), 1.7 million more, no failure.

## The speed target

At least liblzo2's `lzo1x_decompress_safe`, measured with `tools/lzo-bench` on the Silesia corpus (`python3 scripts/testdata.py fetch --group bench --set lzo-oracle`):

```sh
cargo run --release -p lzo-bench -- [--methods 1,999] [--block 131072] [--rounds 5] target/testdata/silesia
```

Each file is compressed in blocks of 128 KiB, SquashFS's default, by `lzo1x_1` and `lzo1x_999` (`mksquashfs -comp lzo` takes `lzo1x_999` by default), and each round decodes every block into exactly its size, as many times as make 50 MB, with liblzo2 and lzokay in the oracle's process and with the port in the tool's, and keeps the fastest; rounds take turns.

### Where it stands

Above the target on 23 of 24, and at 0.97× on the last. AMD Ryzen 9 9950X (x86-64, Linux), November 2026, rustc 1.99.1, liblzo2 and lzokay built with GCC 15.2 at `-O2`, on one pinned core; the 12 Silesia files in blocks of 128 KiB, best of five rounds taken in turn, each of as many decodings as make 50 MB:

| Compressor | Port / liblzo2, mean | Range | Port / lzokay, mean | Range |
|---|---|---|---|---|
| `lzo1x_1` | 1.48× | 1.11–1.63× | 2.02× | 1.21–7.49× |
| `lzo1x_999` | 1.32× | 0.97–1.53× | 1.34× | 0.96–1.66× |

Each file, in MB/s of decompressed data (ratio: compressed size over size):

| input | MB | compressor | ratio | liblzo2 2.10 | lzokay | port | port/liblzo2 | port/lzokay |
|---|---|---|---|---|---|---|---|---|
| dickens | 10.2 | lzo1x_1 | 0.61 | 601 | 578 | 944 | 1.57× | 1.63× |
| dickens | 10.2 | lzo1x_999 | 0.45 | 610 | 638 | 849 | 1.39× | 1.33× |
| mozilla | 51.2 | lzo1x_1 | 0.50 | 1208 | 1223 | 1695 | 1.40× | 1.39× |
| mozilla | 51.2 | lzo1x_999 | 0.41 | 1027 | 1041 | 1327 | 1.29× | 1.27× |
| mr | 10.0 | lzo1x_1 | 0.54 | 1516 | 1395 | 1684 | 1.11× | 1.21× |
| mr | 10.0 | lzo1x_999 | 0.41 | 1016 | 993 | 1112 | 1.10× | 1.12× |
| nci | 33.6 | lzo1x_1 | 0.19 | 2225 | 1905 | 3097 | 1.39× | 1.63× |
| nci | 33.6 | lzo1x_999 | 0.12 | 2769 | 2228 | 3697 | 1.34× | 1.66× |
| ooffice | 6.2 | lzo1x_1 | 0.68 | 783 | 816 | 1270 | 1.62× | 1.56× |
| ooffice | 6.2 | lzo1x_999 | 0.55 | 577 | 590 | 780 | 1.35× | 1.32× |
| osdb | 10.1 | lzo1x_1 | 0.58 | 1601 | 1495 | 2345 | 1.46× | 1.57× |
| osdb | 10.1 | lzo1x_999 | 0.43 | 1345 | 1301 | 1813 | 1.35× | 1.39× |
| reymont | 6.6 | lzo1x_1 | 0.48 | 655 | 653 | 1049 | 1.60× | 1.61× |
| reymont | 6.6 | lzo1x_999 | 0.33 | 809 | 864 | 1241 | 1.53× | 1.44× |
| samba | 21.6 | lzo1x_1 | 0.37 | 1130 | 1143 | 1783 | 1.58× | 1.56× |
| samba | 21.6 | lzo1x_999 | 0.28 | 1257 | 1285 | 1824 | 1.45× | 1.42× |
| sao | 7.3 | lzo1x_1 | 0.89 | 1479 | 1325 | 1815 | 1.23× | 1.37× |
| sao | 7.3 | lzo1x_999 | 0.80 | 1035 | 959 | 1187 | 1.15× | 1.24× |
| webster | 41.5 | lzo1x_1 | 0.49 | 704 | 730 | 1137 | 1.62× | 1.56× |
| webster | 41.5 | lzo1x_999 | 0.34 | 736 | 798 | 1056 | 1.44× | 1.32× |
| x-ray | 8.5 | lzo1x_1 | 1.00 | 23658 | 5147 | 38572 | 1.63× | 7.49× |
| x-ray | 8.5 | lzo1x_999 | 0.81 | 806 | 818 | 784 | 0.97× | 0.96× |
| xml | 5.3 | lzo1x_1 | 0.24 | 1381 | 1359 | 2201 | 1.59× | 1.62× |
| xml | 5.3 | lzo1x_999 | 0.15 | 1765 | 1669 | 2643 | 1.50× | 1.58× |

liblzo2's decoder is the C one: its x86 assembly decoders are 32-bit only, and `lzo1x_decompress_safe` copies in pieces of 8 bytes on 64-bit machines. `x-ray`'s blocks of `lzo1x_1` are mostly long runs of literals, a copy each, whose speed is the memory's; those of `lzo1x_999` are the other way round, one instruction for every 4 or 5 bytes, a match of 3 to 5 bytes and one literal, where the port's bounds checks cost what its copies gain: 0.96–0.98× over several runs. Tried there, and slower everywhere: short matches copied in two pieces of 2 or 4 bytes with `copy_within` (`dickens` from 1.56× to 1.16×), and 1 to 3 literals copied a byte at a time behind branches, as liblzo2 does (`x-ray` from 0.97× to 0.84×). arm64 is not measured yet.

What made the difference: lzokay copies a byte at a time, and so did the port as first written, `copy_within` for matches apart from what they write; it ran at 0.81–1.16× liblzo2 on `lzo1x_1`'s blocks, and 0.59× on `x-ray`'s long literal runs. Short copies in two pieces that may overlap (1 to 3 bytes as the first, the middle and the last), and matches in pieces of 8, made it 0.97–1.63×.

## Following new commits and releases

The commit followed until now, and liblzo2 2.10, are kept in the [mirror of upstream sources](../testdata/README.md#the-upstream-sources-mirrored) (`lzokay-db2df1f-source` and `lzo-2.10-source`), to compare with a new one even once its URL is gone.

When lzokay has a new commit that touches `decompress`:

1. Diff `lzokay.cpp` between the two commits and port each change to the decoder, keeping liblzo2's results.
2. Update `UPSTREAM_VERSION`, and add the new commit's source set to `testdata/manifest.json` (`lzokay-<commit>-source`), with `lzo-oracle` built from it; mirror it with `python3 scripts/testdata.py mirror --set <name>`.
3. Run everything again.

When liblzo2 has a new release, its source set goes in the same way (`lzo-<version>-source`), the oracle is built from it, `LIBLZO2_VERSION` and `testdata/oracle/lzo.txt` (`record_oracle_answers`) are updated, and any change in what `lzo1x_decompress_safe` returns is followed in the port, marked as above.

## Licenses

`hivepack::lzo` is under the MIT license, lzokay's, with its notice ([LICENSE](../crates/hivepack/src/lzo/LICENSE)). liblzo2, under the GPL, is only built into `tools/lzo-oracle`, a test program, which is not part of the crate; the oracle's own code is MIT.
