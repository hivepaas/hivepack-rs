# Unsafe code

Every crate in this repository forbids unsafe code. The process for an exception is in [safety.md](safety.md).

## Approved exceptions

Each behind its crate's opt-in feature `unsafe-fast`: without it, the crate has no unsafe code at all.

| Crate and module | What it does | Why safe code is not enough (with numbers) | How it is checked | Approved |
|---|---|---|---|---|
| `hivepack-zstd`, feature `unsafe-fast`: `src/decompress/unchecked.rs`, and the block in `decompress_sequences_body_with` (`src/decompress/zstd_decompress_block.rs`) that turns it on | The fast path of the main sequence loop copies literals and matches in 16- and 32-byte pieces without a bounds check per piece, as libzstd's `ZSTD_execSequence` does | Apple M1 Pro, October 2026, Silesia at levels 1, 3, 9 and 19 against libzstd 1.5.7: in one call 0.95× libzstd on average (0.92–0.98×; the safe code, in the same run, 0.92×, 0.85–0.98×), streaming 0.96× (0.87–1.00×; safe 0.90×, 0.86–0.97×). 29 of the 48 cases reach 0.95× in one call (safe: 7), 41 streaming (safe: 2). libzstd's fast-path condition keeps every piece within the buffers, but the compiler cannot see it, and keeps a check on each | The checks it relies on are made once per block: `unchecked_loop_fits`; if they fail, the block is decoded with the checks (the tests assert this never happens). Tests: the unchecked copies against the checked ones, byte for byte (`unchecked_tests`), the whole test suite with the feature, and the committed frames decoded with it (`tests/unchecked.rs`). Miri runs the first and the last, and fails on any access out of bounds. `fuzz/` compares the decoder with libzstd under AddressSanitizer. CI runs all of these | HivePaaS, 27 October 2026, as a feature that is off by default |
| `hivepack-zstd`, feature `unsafe-fast`: `src/common/prefetch.rs` | `PREFETCH_L1`: a prefetch instruction (`prfm pldl1keep` through `asm!` on aarch64, `_mm_prefetch` on x86-64) where libzstd's row match finder, levels 5 to 12, prefetches: each row 8 positions before it is searched or written, each candidate as the search gathers them, and the attached `CDict`'s row or bucket. The search then compares its candidates once it has gathered them all, as libzstd's does | Apple M1 Pro, October 2026, six Silesia files (`dickens`, `mozilla`, `ooffice`, `sao`, `x-ray`, `xml`) at levels 5 to 12 against libzstd 1.5.7, in one call, best of three rounds taken in turn: levels 9 to 12 at 0.83–0.87× libzstd on average (the safe code, in the same runs, 0.68–0.74×), levels 5 to 8 at 0.83–0.86× (safe: 0.81–0.84×); `x-ray` at level 10 from 0.46× to 0.86×. libzstd itself, built without its prefetches (`NO_PREFETCH`), is 13–21% slower at levels 7 to 12: most of the gap. Stable Rust has no safe prefetch (`std::hint::prefetch_read` is unstable), and loads ahead in its place made the finder slower | A prefetch is a hint: it reads nothing the program sees, writes nothing and never faults, so the module's two blocks are sound for any address, and take one without a precondition. The frames stay libzstd's: the whole test suite runs with the feature on x86-64 and arm64, comparing them with libzstd's, and the `compress` fuzzer runs with it. Miri cannot run the assembly: under Miri the prefetch is off | HivePaaS, 29 October 2026, in the same feature |
| `hivepack-lz4`, feature `unsafe-fast`: `src/unchecked.rs`, and the block in `decompress_generic` (`src/lz4.rs`) that turns it on | The block decoder's fast loop (`LZ4_FAST_DEC_LOOP`) reads and writes its pieces (the token, the offset, 16 and 32 bytes of literals, 8, 16 and 2 bytes of matches) without a bounds check per piece, as liblz4 does | AMD Ryzen 9 9950X, October 2026, the 12 Silesia files at levels 1 and 9 against liblz4 1.10.0, block decoding in one call, best of five rounds taken in turn on one pinned core: 0.96× liblz4 on average (0.92–0.99×; the safe code, on the same machine, 0.75×, 0.70–0.83×), 15 of 24 at 0.95× or more (safe: 0). The safe code keeps up to a dozen checks for each short sequence, where liblz4 has six branches; with the common sequence through windows of a known size (which the safe build does) it gained 0.03–0.15, not more | The fast loop's own checks, liblz4's, keep every piece in bounds: its `SAFETY` comment goes through each. `Unchecked` asserts each piece in bounds in debug builds, where the tests run. Tests: the unchecked pieces against slice indexing (`unchecked::tests`), the whole suite with the feature (liblz4's results and every byte of the output, as without it), and `tests/unchecked.rs`, the recorded blocks with small buffers, which Miri runs with the unit test. `fuzz/` runs `lz4` with the feature, comparing with liblz4 under AddressSanitizer. CI runs all of these, on 32-bit and big-endian machines too | HivePaaS, 30 October 2026, as a feature that is off by default |
| `hivepack-deflate`, feature `unsafe-fast`: `crc32` and `arm_crc32` in `src/crc32.rs` | CRC-32 with arm64's instructions, one call, when the processor says it has them | zlib built for Apple's processors uses them, and reading stored ZIP entries was 0.53× there; with them, 0.68×. Calling a function with a `target_feature` takes `unsafe`, as the compiler refuses it otherwise. | `same_as_braided`: the instructions against the code on lengths, offsets and start values. Run on arm64 by CI's Linux job. | November 2026, by the project's owner |
| `hivepack-crypto`, feature `unsafe-fast`: `src/aes_hw.rs` | AES with AES-NI on x86-64 and the AES instructions on arm64, round keys from the same constant-time key schedule | See the table below | `instructions_same_as_bitsliced`, and the published vectors and the comparisons with nettle and Go, all of which go through it with the feature on | November 2026, by the project's owner |
| `hivepack-crypto`, feature `unsafe-fast`: `src/sha_hw.rs` | SHA-1 and SHA-256 with the SHA extensions on x86-64 and the SHA instructions on arm64 | See the table below | `instructions_same_as_code` in `sha1.rs` and `sha2small.rs`, and the same vectors and comparisons | November 2026, by the project's owner |
| `hivepack-crypto`, feature `unsafe-fast`: `src/chacha_hw.rs` | ChaCha20 on eight blocks at once with AVX2, four with NEON | See the table below | `instructions_same_as_code` in `chacha20_ct.rs`, around a group and with the counter wrapping, and the same vectors and comparisons | November 2026, by the project's owner |

## The `unsafe-fast` feature

```toml
hivepack-zstd = { version = "…", features = ["unsafe-fast"] }
hivepack-lz4 = { version = "…", features = ["unsafe-fast"] }
hivepack-deflate = { version = "…", features = ["unsafe-fast"] }
hivepack-crypto = { version = "…", features = ["unsafe-fast"] }
```

or `--features hivepack-zstd/unsafe-fast` (`hivepack-lz4/unsafe-fast`) on the command line. Cargo turns a feature on for the whole build as soon as one crate in it asks for it, so a program can check which build it got with `hivepack_zstd::UNSAFE_FAST` (`hivepack_lz4::UNSAFE_FAST`).

What the feature changes in `hivepack-zstd`:

- The copies take a `Mode` (`zstd_decompress_block.rs`): `Checked`, with bounds checks, or `unchecked::Unchecked`, whose reads and writes are `read_unaligned` and `write_unaligned` on raw pointers. Only `unsafe fn Unchecked::new` makes an `Unchecked`, so safe code cannot reach those accesses by itself.
- `decompress_sequences_body_with` checks, once per block, that the output reaches `oend`, that the literals have libzstd's 32 bytes of margin past their end (`WILDCOPY_OVERLENGTH`), and where the loop starts. Then it makes an `Unchecked` and runs the loop with it; its `SAFETY` comment shows how the loop keeps every fast-path copy within those bounds. If the check fails, which the decoder never lets happen, the loop runs `Checked`.
- Everything else, the slow path near the end of the output, the other sequence loops and the Huffman and FSE decoders, keeps its bounds checks.
- The unchecked copies only on 64-bit machines: the `SAFETY` argument uses positions below 2^63. On 32-bit machines the decoder is the same with and without the feature.
- In the encoder, `prefetch_l1` (`common/prefetch.rs`) gives a prefetch instruction on aarch64 and x86-64, and nothing elsewhere or under Miri; `PREFETCH` then turns the row match finder (`compress/zstd_lazy.rs`) to libzstd's order: gather a row's candidates, prefetching each, insert the position, compare them. The safe build has the same order, with a read of each candidate in place of its prefetch: no branch waits on those reads, so the processor takes their cache misses side by side. It gets part of the prefetch's gain, and the frames are the same either way.
- Without the feature, `lib.rs` forbids unsafe code again (`forbid(unsafe_code)`), and the crate is as safe as the others. The crate's own lints are `deny` rather than the workspace's `forbid`, since `forbid` cannot be lifted for the one module.

What it changes in `hivepack-lz4`:

- The fast loop's pieces go through a `Mode` (`lz4.rs`): `Checked`, with bounds checks, or `unchecked::Unchecked`, whose reads and writes are `read_unaligned` and `write_unaligned` on raw pointers, and which only `unsafe fn Unchecked::new` makes. `decompress_generic` makes one for every block; its `SAFETY` comment shows how the fast loop's checks (64 bytes free past `op` at the loop's top, the literal and match lengths checked before each copy, the offset checked before each match) keep every piece in bounds. The length checks are written so as not to wrap around, on 32-bit machines too.
- The safe loop near the end of the output, `read_variable_length`, matches from an external dictionary, and copies longer than 32 bytes keep their bounds checks.
- The output is the same, byte for byte, with and without the feature: the same copies, without the checks (and without the safe build's windows, which the unchecked loop does not need).
- Without the feature, `lib.rs` forbids unsafe code again, as `hivepack-zstd`'s does.

## The processor's instructions

`hivepack-deflate` and `hivepack-crypto` use the feature for instructions, not for skipping checks. `hivepack-zip` and `hivepack-7z` turn on both with their own `unsafe-fast`, and `hivepack-age` the second.

What the unsafe code is, in all of them:

- **Calling a function with `#[target_feature]`.** Each call is behind a check of the processor at run time (`is_x86_feature_detected!`, `is_aarch64_feature_detected!`), which caches its answer. Without the instruction, the safe code runs, so one build works on every processor of its architecture. Other architectures have none of this code.
- **Loading and storing 16 or 32 bytes** of an array or a slice of known length, with the intrinsics that take any alignment.

What it does not do: no pointer arithmetic, no lengths taken on trust, no uninitialized memory. The bodies of those functions are otherwise safe Rust, with bounds checks.

Secrets:

- **AES** was bitsliced to be constant time. The instructions are too, as the processors' manuals describe them, and use no tables in memory. Round keys still come from the bitsliced key schedule, so `aeskeygenassist` is not needed. They are cleared on drop, on a best effort, as the others are.
- **ChaCha20** has no tables and no branches on its data, in either form.
- **SHA-1 and SHA-256** work on what HMAC and key derivation give them, in the same order as the code.

Not checked: **Miri cannot run these intrinsics**, and they are not fuzzed apart. The output is compared with the safe code in the unit tests above, which CI's Linux jobs run on x86-64 and arm64. The bench tools also compare results with the reference on Linux, Windows and macOS. Timing was not measured.

Port / reference, on GitHub's runners, on November 1, 2026, each job on the processor it got. Before is without the feature, from the crates' READMEs and earlier runs, on the processors those got, so a row compares loosely:

| | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| WinZip AES, read and written | 2.57–3.26×, before 0.61–0.80× | 3.22–4.18×, before 0.68–0.97× | 2.31–2.89×, before 0.45–0.69× |
| WinZip AES-256, small entries | 1.50–1.63× | 1.55–1.68× | 1.19–1.20× |
| 7z AES-256 with Copy | 0.70×, before 0.07× | 0.81×, before 0.10× | 0.78×, before 0.06× |
| 7z AES-256 behind LZMA2 | 1.04×, before 0.76–0.79× | 1.02×, before 0.80× | 0.71×, before 0.53× |
| age, a big file | 0.42×, before 0.22× | 0.44×, before 0.33× | 0.75×, before 0.52× |
| age, a big file in ASCII armor | 1.69×, before 1.23× | 1.94×, before 1.19× | 1.40×, before 1.29× |
| ZIP, reading big stored entries | 1.40×, the same | 1.30×, the same | 0.68×, before 0.53× |

The last row stays below 1× on macOS for what else that row does, which has not been looked into. 7z's Copy without AES is unchanged by this, at 0.43–0.50×. Go keeps the lead on age's payload with one assembly routine for ChaCha20 and Poly1305 together; here Poly1305 is still the portable code.

