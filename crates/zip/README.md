# hivepack-zip

ZIP archives in safe Rust, the container logic ported from [libzip](https://libzip.org) 1.12.1.

> **Status:** opens archives, reads their central directory and local headers, and reads stored, deflated, bzip2, LZMA, XZ, Zstandard, Deflate64 and PPMd entries, with libzip's rules and errors (PPMd, which libzip lacks, as 7-Zip reads it); edits entries' names, comments, times and attributes, deletes them, adds and replaces data, stored, deflated, bzip2, LZMA, XZ or Zstandard, and writes the archive as libzip writes it, byte for byte; encrypts and decrypts ZipCrypto and WinZip AES entries; reads split archives (`name.z01`, …, `name.zip`, and 7-Zip's `name.zip.001`, …) from their volumes, which libzip refuses. All compared with libzip itself, and PPMd and the split archives with 7-Zip. This crate is not on crates.io.

```rust
use hivepack_zip::{Archive, Flags, OpenFlags};

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
use hivepack_zip::{Archive, BufferSource, Closed, Flags, OpenFlags};

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

- **No unsafe code.** The crate forbids it; see [docs/safety.md](../../docs/safety.md).
- **libzip's answers.** An archive libzip opens opens, with the same entries; one it refuses is refused with the same error and detail.

How the port follows libzip, how it is checked, and what is left are in [docs/zip.md](../../docs/zip.md).

## Speed

Against libzip 1.12.1, with `tools/zip-bench`. Above 1× the port is faster.

| | hivepack-zip / libzip |
|---|---|
| Reading stored entries | 1.29–1.37× |
| Reading Deflate and bzip2 | 0.98–1.06× |
| Reading LZMA and XZ | 0.76–0.79× |
| Writing stored entries | 1.21–1.25× |
| Writing compressed, every method and level | 0.96–1.05× |
| Opening 200,000 entries | 0.78×, 1.30× with `ZIP_CHECKCONS` |
| Finding entries | 1.16–2.67× |
| ZipCrypto | 0.90–0.93× |
| WinZip AES | 0.57–0.66× |
| Editing, the data copied | 1.56–1.59× |
| Editing each of 200,000 entries | 1.46–1.99× |

**Measured on:** AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile, in October 2026. libzip is built with GCC 15.2 and `-O2`, from the releases of zlib 1.3.2, nettle 3.10.2, bzip2 1.0.8 and XZ Utils 5.8.4, without assembly files. The data is the Silesia corpus cut to 64 MiB, on a nearly idle machine, the best of five rounds taken in turn. What the two wrote without encryption was the same, byte for byte.

LZMA and XZ read below liblzma because its x86-64 range decoder is inline assembly. AES here is against nettle's C: a libzip that uses the processor's AES instructions, as a usual build does, is further ahead. The whole table and the reasons are in [docs/zip.md](../../docs/zip.md#the-speed).

### On GitHub's runners

Against libzip 1.12.1, each row the mean and the range over its files or workloads.

| Port / reference | Linux x86-64 | Windows x86-64 | macOS arm64 |
|---|---|---|---|
| Opening many entries | 0.69× | 4.06× | 1.77× |
| Opening with `ZIP_CHECKCONS` | 1.94× | 5.71× | 2.13× |
| Finding entries by name | 0.93× | 1.28× | 0.96× |
| Reading stored entries | 1.34× (1.30–1.38×) | 1.40× (1.29–1.50×) | 1.17× (0.53–1.80×) |
| Reading Deflate and bzip2 | 0.98× (0.92–1.01×) | 1.03× (0.99–1.11×) | 0.90× (0.81–0.97×) |
| Reading LZMA and XZ | 0.76× (0.74–0.77×) | 0.77× (0.77–0.77×) | 1.02× (1.01–1.04×) |
| Writing stored entries | 1.29× (1.15–1.43×) | 1.53× (1.11–1.95×) | 1.42× (1.39–1.45×) |
| Writing compressed, every method and level | 0.98× (0.94–1.01×) | 1.06× (0.98–1.15×) | 1.03× (0.92–1.07×) |
| ZipCrypto, both ways | 1.08× (1.04–1.11×) | 1.11× (1.03–1.19×) | 0.90× (0.74–1.06×) |
| WinZip AES, both ways | 0.71× (0.61–0.80×) | 0.79× (0.68–0.97×) | 0.55× (0.45–0.69×) |
| Editing, the data copied | 1.77× (1.75–1.79×) | 1.12× (1.12–1.13×) | 1.81× (1.79–1.82×) |
| Editing many entries | 2.87× (2.29–3.51×) | 7.48× (5.47–9.20×) | 1.78× (1.27–2.18×) |

**Measured on** `.github/workflows/bench.yml`, on October 31 and November 1, 2026, with rustc 1.99.1: Linux x86-64 on AMD EPYC 7763 64-Core Processor (4 threads); Windows x86-64 on Intel64 Family 6 Model 207 Stepping 2 (4 threads); macOS arm64 on Apple M1 (Virtual) (3 threads). Each job gets what the runner has that day, so these are not the same processor from format to format, and they are shared machines: the ratios hold better than the speeds. Reading big stored entries on macOS is 0.51–0.61×, in four runs: zlib, built for Apple's processors, uses the CRC instruction there, which the port's safe code cannot call. `zip_stat_index` is left out: libzip's calls `mktime` for each entry, and the row was about 70× on macOS and about 4× on Linux, which says more about `mktime` than about the port. Encrypting draws its random bytes from a stand-in on both sides.

## License

BSD-3-Clause, the license of the code it is ported from. See [LICENSE](LICENSE). Copyright (C) 1999-2026 Dieter Baron and Thomas Klausner, and (c) 2026 HivePaaS.
