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
| Reading stored entries | 1.32× |
| Reading Deflate and bzip2 | 1.02–1.53× |
| Reading LZMA and XZ | 0.92–0.95× |
| Writing stored entries | 1.25–1.44× |
| Writing compressed, every method and level | 0.96–1.05× |
| Opening 200,000 entries | 0.71×, 1.25× with `ZIP_CHECKCONS` |
| Finding entries | 1.00–3.39× |
| ZipCrypto | 0.89–0.93× |
| WinZip AES | 1.74–2.93× |
| Editing, the data copied | 1.54–1.62× |
| Editing each of 200,000 entries | 1.49–1.81× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, in November 2026. libzip is built with GCC 15.2 and `-O2`, from the releases of zlib 1.3.2, nettle 3.10.2, bzip2 1.0.8 and XZ Utils 5.8.4, without assembly files. The data is the Silesia corpus cut to 64 MiB, on a nearly idle machine, the best of five rounds taken in turn. What the two wrote without encryption was the same, byte for byte.

LZMA and XZ read just below liblzma because its x86-64 range decoder is inline assembly. WinZip AES is ahead because the port's AES has the processor's instructions and nettle's C, which libzip is built with here, does not. Opening many entries moves the most from one run to the next: 0.66–0.79× over four runs, and 1.04–1.25× with `ZIP_CHECKCONS` ([docs/zip.md](../../../../docs/zip.md#the-speed)).

### On GitHub's runners

Against libzip 1.12.1, as the crate comes by default, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many entries | 0.78× | 5.31× | 1.70× |
| Opening with `ZIP_CHECKCONS` | 1.61× | 6.61× | 2.07× |
| Finding entries by name | 0.99× | 1.07× | 1.20× |
| Reading stored entries | 1.40× (1.36–1.43×) | 1.37× (1.36–1.37×) | 1.05× (0.46–1.65×) |
| Reading Deflate and bzip2 | 1.24× (0.92–1.72×) | 1.20× (1.02–1.50×) | 1.10× (0.87–1.39×) |
| Reading LZMA and XZ | 1.02× (1.01–1.03×) | 0.89× (0.87–0.90×) | 1.10× (1.05–1.15×) |
| Writing stored entries | 1.30× (1.22–1.39×) | 1.56× (1.09–2.02×) | 1.41× (1.29–1.52×) |
| Writing compressed, every method and level | 1.00× (0.89–1.05×) | 1.02× (0.95–1.08×) | 1.01× (0.89–1.08×) |
| ZipCrypto, both ways | 1.05× (0.91–1.19×) | 1.08× (1.05–1.10×) | 0.86× (0.76–0.97×) |
| WinZip AES, both ways | 2.64× (1.86–3.31×) | 2.69× (2.18–3.26×) | 3.17× (2.89–3.67×) |
| Editing, the data copied | 10.76× (10.60–10.92×) | 1.20× (1.20–1.20×) | 1.86× (1.66–2.07×) |
| Editing many entries | 2.71× (2.41–3.18×) | 8.51× (6.44–10.51×) | 1.92× (1.63–2.16×) |

With the `unsafe-fast` feature, off by default (see [docs/unsafe.md](../../../../docs/unsafe.md)):

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many entries | 0.68× | 3.64× | 1.87× |
| Opening with `ZIP_CHECKCONS` | 2.42× | 4.84× | 2.05× |
| Finding entries by name | 0.86× | 1.23× | 0.92× |
| Reading stored entries | 2.63× (1.97–3.29×) | 1.79× (1.54–2.05×) | 1.34× (0.73–1.95×) |
| Reading Deflate and bzip2 | 1.23× (0.97–1.67×) | 1.37× (1.14–1.81×) | 1.11× (0.77–1.54×) |
| Reading LZMA and XZ | 0.93× (0.91–0.94×) | 0.91× (0.90–0.92×) | 1.11× (1.09–1.13×) |
| Writing stored entries | 1.52× (1.45–1.59×) | 1.75× (1.33–2.17×) | 1.23× (1.16–1.31×) |
| Writing compressed, every method and level | 1.00× (0.95–1.03×) | 1.07× (0.99–1.18×) | 1.02× (0.92–1.21×) |
| ZipCrypto, both ways | 1.10× (1.06–1.14×) | 1.16× (0.94–1.38×) | 2.63× (1.69–3.58×) |
| WinZip AES, both ways | 2.80× (1.97–3.97×) | 2.31× (1.75–3.05×) | 3.02× (2.47–3.81×) |
| Editing, the data copied | 5.62× (5.55–5.69×) | 1.23× (1.22–1.23×) | 1.69× (1.68–1.69×) |
| Editing many entries | 4.14× (3.18–5.40×) | 6.86× (5.13–8.12×) | 1.81× (1.61–2.10×) |

**Measured on** `.github/workflows/bench.yml`, on November 10, 2026, with rustc 1.99.1. Without the feature: Linux x86-64 on INTEL XEON PLATINUM 8573C (4 threads); Windows x86-64 on AMD64 Family 25 Model 1 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). With it: Linux x86-64 on AMD EPYC 9V74 (4 threads); Windows x86-64 on AMD64 Family 26 Model 2 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). `unsafe-fast` here is CRC-32 with the processor's instructions, arm64's own and x86-64's carry-less multiplication: AES has the processor's instructions in both tables. Each job gets what the runner has that day, so the two tables, and the formats, are not on the same processor, and they are shared machines: the ratios hold better than the speeds.

Reading big stored entries on macOS stays below 1× as zlib, built for Apple's processors, has the CRC instruction; `unsafe-fast` narrows it. `zip_stat_index` is left out: libzip's calls `mktime` for each entry, which says more about `mktime` than about the port.

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1999-2026 Dieter Baron and Thomas Klausner, and (c) 2026 HivePaaS.
