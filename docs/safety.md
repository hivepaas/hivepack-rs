# Safety rules

These rules hold for every crate in the repository. CI checks the parts a tool can check.

## No unsafe code

The workspace sets `unsafe_code = "forbid"`, and every crate inherits it with `[lints] workspace = true`. `forbid` cannot be lifted by an `allow` further in, so no `unsafe` block, `unsafe fn` or `#[no_mangle]` compiles anywhere.

The exceptions are all opt-in: the `unsafe-fast` feature of `hivepack-zstd`, `hivepack-lz4`, `hivepack-deflate` and `hivepack-crypto` (see [unsafe.md](unsafe.md)). Without the feature, those crates forbid unsafe code too. Adding an exception takes all of these steps:

1. Show with numbers from `tools/zstd-bench` (same machine, interleaved rounds) that the safe code misses the speed target in [porting.md](porting.md), and that the unsafe code closes the gap.
2. Keep the unsafe code in one module, as small as it can be. Every block gets a `// SAFETY:` comment that says why it is sound, and preconditions are checked once at the module's entry.
3. Cover it with tests, fuzzing and Miri.
4. Record it in [unsafe.md](unsafe.md): where it is, why, the numbers, and how it is checked.
5. HivePaaS approves it before it merges. Only that crate then moves from `forbid` to `deny`, with `#[allow(unsafe_code)]` on that one module. Where it can be, it is a feature that is off by default, and the crate forbids unsafe code without it.

These are the places in libzstd where safe Rust is known to fall short. Each one is measured first, while the safe code is tried; two are exceptions so far, behind a feature.

| In libzstd | Why safe Rust cannot do the same (Rust 1.99) | Safe approach first |
|---|---|---|
| Choosing BMI2 code at run time (`DYNAMIC_BMI2`) | Calling a `#[target_feature]` function from ordinary code needs `unsafe`, even after `is_x86_feature_detected!` | BMI2 only when built with `-C target-cpu`, such as `x86-64-v3` |
| The x86-64 Huffman decoding loop in assembly (`huf_decompress_amd64.S`) | No assembly | Port the C loop that libzstd uses everywhere else |
| SSE2 and NEON in the row-based match finder (`zstd_lazy.c`) | Loads through `core::arch` take raw pointers, and any `#[target_feature]` call needs `unsafe`, even for SSE2 and NEON, which are always present | Eight-byte words (SWAR), and loops the compiler vectorises |
| Prefetching (`PREFETCH_L1`) in the decoder and the match finders | No safe prefetch on stable Rust | Measure what it is worth. In the decoder it is worth nothing: a `prfm` where libzstd prefetches each match, tried through `asm!`, changed speeds by −2.5% to +0.2% (Apple M1 Pro, October 2026). In the row match finder it is most of the gap at levels 5 to 12: libzstd built without its prefetches is 13–21% slower there, and with them the port goes from 0.68–0.74× to 0.83–0.87× libzstd at levels 9 to 12 (same machine, October 2026). Loads ahead in safe code, a row read 8 positions early or the candidates' first bytes read as they are gathered, made it slower. The `unsafe-fast` feature, approved (see [unsafe.md](unsafe.md)) |
| Unchecked reads in hot loops | Bounds checks cost time | Buffers with slack and fixed-size arrays, so the checks fold away. Measured in the decoder (Apple M1 Pro, October 2026): the compiler cannot see that libzstd's fast-path condition keeps the sequence loop's copies in bounds. With them unchecked, decompression goes from 0.92× to 0.95× libzstd on average over Silesia in one call, and from 0.90× to 0.96× streaming: the `unsafe-fast` feature, approved (see [unsafe.md](unsafe.md)). The bitstreams' 8-byte reads stay checked. In the encoder's match finders (same machine, October 2026), measured on a scratch copy: with their input reads and hash table accesses unchecked, compression gains 4% to 40% (`sao` at level −1 the most, to 0.71× libzstd). Not proposed: the finders' loops reshaped in safe code since gained more (`sao` at level −1 at 0.76×; see [porting.md](porting.md#where-compression-stands)) |
| Output buffers that are never initialised | Needs `unsafe` | Zero them first, which costs little |

## Dependencies with unsafe code

A library may depend on a crate that has `unsafe` code only where there is no other way: the standard library has nothing that does the job, and doing it in the library would take `unsafe` code of its own (a system call the standard library does not wrap, for one). HivePaaS settled this in October 2026. Each such dependency is listed here, with what it is for, why it is needed, and what would replace it; it stays out of every crate but the one that needs it.

| Dependency | In | For | Why | Replaced by |
|---|---|---|---|---|
| `cap-std`, `cap-fs-ext` (Bytecode Alliance; with `rustix` on Unix, `windows-sys` and `winx` on Windows) | `hivepack-extract` | Opening each directory under the destination from its parent's handle without following a symbolic link, and creating files there: `openat2` with `RESOLVE_BENEATH` on Linux, `openat` with `O_NOFOLLOW` a component at a time elsewhere on Unix, handles relative to a directory's on Windows | The standard library's directory handles (`std::fs::Dir`, tracking issue rust-lang/rust#120426) are not stable. Without them, a path is checked and then opened again, and a link put in between is followed | `std::fs::Dir`, once stable |
| `rustix` (Bytecode Alliance), on macOS only, already there for `cap-std` | `hivepack-extract` | Reading and setting macOS's quarantine attribute (`com.apple.quarantine`) by file descriptor: `fgetxattr` and `fsetxattr`, so that files extracted from a downloaded archive keep its mark | The standard library has no extended attributes, and calling `fsetxattr` is `unsafe` | an extended attributes API in the standard library |

The rest of the repository, the codecs, the cryptography and the ZIP container among them, depends on nothing with `unsafe` code.

## Untrusted input never panics

Library code returns errors and never panics, whatever the input:

- Clippy denies `unwrap`, `expect`, `panic!`, `todo!` and `unimplemented!` outside tests.
- Indexing is allowed, since a failed bounds check panics instead of reading out of bounds. No input may reach such a panic, though, and fuzzing, seeded with zstd's own corpora, is how that is shown. A panic found by a fuzzer is a bug.
- Where libzstd relies on unsigned integers wrapping around, the port says so with `wrapping_*`. Tests and fuzzing run with overflow checks, so an overflow nobody meant panics there instead of passing silently.
- A failure gives the same error as libzstd's `ZSTD_ErrorCode` for that input.

## Bounded resources

- Decoding refuses windows larger than libzstd's default limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT`, 2^27 bytes = 128 MiB) unless the caller raises it, as `ZSTD_d_windowLogMax` does.
- Streaming keeps one block of input and, unless the output buffer is stable, the window plus two blocks of output, at most the frame's content size. Buffers much larger than the frames need shrink after 128 frames, as in libzstd.
- No allocation is sized from a header before that size is checked against the limits.
- Nothing recurses to a depth the input chooses.

## No C in the libraries

libzstd and zlib are development dependencies only: they are the references in tests and benchmarks, and they never end up in a library. `cargo deny` (see `deny.toml`) keeps every dependency under a permissive license, from crates.io, and free of open security advisories.
