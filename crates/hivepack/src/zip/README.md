# hivepack::zip

ZIP archives in safe Rust, the container logic ported from [libzip](https://libzip.org) 1.12.1.

> **Status:** opens archives, reads their central directory and local headers, and reads stored, deflated, bzip2, LZMA, XZ, Zstandard, Deflate64 and PPMd entries, with libzip's rules and errors (PPMd, which libzip lacks, as 7-Zip reads it); edits entries' names, comments, times and attributes, deletes them, adds and replaces data, stored, deflated, bzip2, LZMA, XZ or Zstandard, and writes the archive as libzip writes it, byte for byte; encrypts and decrypts ZipCrypto and WinZip AES entries; compresses and encrypts new data in threads when asked (`Archive::set_threads`), which libzip cannot, the archive the same, byte for byte, as with one thread; reads split archives (`name.z01`, …, `name.zip`, and 7-Zip's `name.zip.001`, …) from their volumes, which libzip refuses. All compared with libzip itself, and PPMd and the split archives with 7-Zip. This crate is not on crates.io.

```rust
use hivepack::zip::{Archive, Flags, OpenFlags};

let file = std::fs::File::open("archive.zip")?;
let archive = Archive::open(file, OpenFlags::CHECKCONS)?;
for i in 0..archive.get_num_entries(Flags::NONE) {
    let st = archive.stat_index(i, Flags::NONE)?;
    println!("{} {}", String::from_utf8_lossy(st.name.unwrap_or_default()), st.size);
}
// Decompressed, its CRC-32 and length checked at the end.
let mut data = Vec::new();
let mut file = archive.fopen(b"README.md", Flags::NONE)?;
std::io::Read::read_to_end(&mut file, &mut data)?;
file.fclose()?;
```

`OpenFlags::CHECKCONS` compares every local header with the central directory and checks more strictly, as libzip's `ZIP_CHECKCONS` does. Without it, the archive opens as libzip opens it by default.

Entries encrypted with ZipCrypto or WinZip AES are read with a password, the archive's default one or one given to `fopen_index_encrypted`; a wrong one fails with `ErrorCode::WrongPasswd`, or for WinZip AES with `ErrorCode::Crc` at the end if the data was changed:

```rust
archive.set_default_password(Some(b"secret"));
let mut file = archive.fopen(b"notes.txt", Flags::NONE)?;
```

`file_set_encryption` encrypts an entry when the archive is written, with its password or the default one. The random bytes that takes come from `/dev/urandom` on Unix; elsewhere, give them with `set_random_source` (from the `getrandom` crate, for example).

Changes are kept until the archive is written, to an output of the caller's:

```rust
use hivepack::zip::{Archive, BufferSource, Closed, Flags, OpenFlags};

let mut archive = Archive::open(std::fs::File::open("archive.zip")?, OpenFlags::CHECKCONS)?;
let index = archive.name_locate(b"old.txt", Flags::NONE)?;
archive.file_rename(index, b"new.txt", Flags::NONE)?;
archive.file_add(b"notes.txt", BufferSource::new(b"added".to_vec()), Flags::NONE)?;
archive.set_archive_comment(b"renamed")?;
let mut out = std::fs::File::create("archive.zip.new")?;
if archive.close_to(&mut out)? == Closed::Written {
    drop(archive);
    std::fs::rename("archive.zip.new", "archive.zip")?;
}
```

The goals:

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../../../docs/safety.md).
- **libzip's answers.** An archive libzip opens opens, with the same entries; one it refuses is refused with the same error and detail.

How the port follows libzip, how it is checked, and what is left are in [docs/zip.md](../../../../docs/zip.md).

## Speed

Against libzip 1.12.1, with `tools/zip-bench`. Above 1× the port is faster.

| | hivepack::zip / libzip |
|---|---|
| Reading stored entries | 1.29–1.37× |
| Reading Deflate and bzip2 | 0.98–1.06× |
| Reading LZMA and XZ | 0.76–0.79× |
| Writing stored entries | 1.21–1.25× |
| Writing compressed, every method and level | 0.96–1.05× |
| Opening 200,000 entries | 0.78×, 1.30× with `ZIP_CHECKCONS` |
| Finding entries | 1.16–2.67× |
| ZipCrypto | 0.90–0.93× |
| Editing, the data copied | 1.56–1.59× |
| Editing each of 200,000 entries | 1.46–1.99× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, in October 2026. libzip is built with GCC 15.2 and `-O2`, from the releases of zlib 1.3.2, nettle 3.10.2, bzip2 1.0.8 and XZ Utils 5.8.4, without assembly files. The data is the Silesia corpus cut to 64 MiB, on a nearly idle machine, the best of five rounds taken in turn. What the two wrote without encryption was the same, byte for byte.

LZMA and XZ read below liblzma because its x86-64 range decoder is inline assembly. WinZip AES is on the runners' tables below, as the machine above has no measure of it since it went to the `aes` crate.

### On GitHub's runners

Against libzip 1.12.1, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many entries | 0.81× | 5.26× | 1.78× |
| Opening with `ZIP_CHECKCONS` | 1.66× | 6.68× | 1.81× |
| Finding entries by name | 1.03× | 1.10× | 1.11× |
| Reading stored entries | 1.39× (1.34–1.44×) | 1.35× (1.31–1.39×) | 1.18× (0.62–1.74×) |
| Reading Deflate and bzip2 | 0.97× (0.90–1.06×) | 1.02× (0.98–1.06×) | 0.85× (0.77–0.94×) |
| Reading LZMA and XZ | 0.84× (0.83–0.85×) | 0.72× (0.71–0.74×) | 0.85× (0.75–0.96×) |
| Writing stored entries | 1.31× (1.23–1.39×) | 1.56× (1.07–2.05×) | 1.39× (1.30–1.47×) |
| Writing compressed, every method and level | 1.00× (0.91–1.06×) | 1.01× (0.96–1.05×) | 1.03× (0.92–1.12×) |
| ZipCrypto, both ways | 1.05× (0.94–1.17×) | 1.15× (1.12–1.17×) | 0.89× (0.76–1.01×) |
| WinZip AES, both ways | 2.69× (2.03–3.30×) | 2.73× (2.32–3.27×) | 3.11× (2.74–3.74×) |
| Editing, the data copied | 11.91× (11.85–11.98×) | 1.23× (1.23–1.24×) | 1.79× (1.77–1.81×) |
| Editing many entries | 2.84× (2.46–3.32×) | 8.77× (6.37–11.19×) | 1.94× (1.67–2.19×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many entries | 0.65× | 5.22× | 1.60× |
| Opening with `ZIP_CHECKCONS` | 1.87× | 6.83× | 2.15× |
| Finding entries by name | 0.86× | 1.06× | 1.07× |
| Reading stored entries | 1.34× (1.30–1.39×) | 1.35× (1.34–1.35×) | 1.44× (0.74–2.13×) |
| Reading Deflate and bzip2 | 0.99× (0.92–1.03×) | 1.00× (0.97–1.06×) | 0.95× (0.88–1.04×) |
| Reading LZMA and XZ | 0.74× (0.73–0.75×) | 0.73× (0.72–0.74×) | 1.00× (0.99–1.01×) |
| Writing stored entries | 1.28× (1.15–1.41×) | 1.58× (1.13–2.03×) | 1.48× (1.40–1.56×) |
| Writing compressed, every method and level | 0.97× (0.94–1.02×) | 1.01× (0.98–1.05×) | 1.01× (0.87–1.11×) |
| ZipCrypto, both ways | 1.10× (1.07–1.13×) | 1.15× (1.12–1.17×) | 1.10× (0.97–1.23×) |
| WinZip AES, both ways | 2.51× (1.97–3.07×) | 2.72× (2.32–3.25×) | 3.13× (2.72–3.88×) |
| Editing, the data copied | 1.45× (1.34–1.55×) | 1.21× (1.21–1.21×) | 1.88× (1.88–1.88×) |
| Editing many entries | 2.72× (2.24–3.33×) | 8.27× (6.10–10.39×) | 1.92× (1.66–2.22×) |

**Measured on** `.github/workflows/bench.yml`, on November 2, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on INTEL XEON PLATINUM 8573C (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). With it: Linux x86-64 on AMD EPYC 7763 (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). `unsafe-fast` here is now only CRC-32 on arm64: AES has the processor's instructions in both, and differences between the tables on x86-64 are the machines. Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

Reading big stored entries on macOS stays below 1× as zlib, built for Apple's processors, has the CRC instruction; `unsafe-fast` narrows it. `zip_stat_index` is left out: libzip's calls `mktime` for each entry, which says more about `mktime` than about the port.

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1999-2026 Dieter Baron and Thomas Klausner, and (c) 2026 HivePaaS.
