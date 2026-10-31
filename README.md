# hivepack

Read and write archives and compressed files in Rust: one library for many formats, in the spirit of [libarchive](https://github.com/libarchive/libarchive).

> **Status:** early development. Nothing is published on crates.io yet.

## 📦 Crates

| Crate | What it is | Status |
|---|---|---|
| [`hivepack-7z`](crates/7z) | Reading 7z archives in safe Rust, ported from the LZMA SDK's 7z decoder (7-Zip 26.05), and writing them | Opens what the SDK opens and decodes what it decodes, Copy, LZMA, LZMA2 and PPMd with their filters and BCJ2, with its answers and error numbers, and past it what 7-Zip's program reads: any graph of coders, with Deflate, Deflate64, BZip2, Zstandard and AES with a password; folders are read in pieces, so that a solid block of any size takes little memory; extracted by `hivepack-extract` |
| [`hivepack-age`](crates/age) | Decrypting [age](https://age-encryption.org) files in safe Rust, ported from age v1.3.2, the reference implementation in Go | Decrypts with passphrases, X25519 keys and SSH Ed25519 keys (passphrase-protected ones too), armored or not, with age's outcomes on all 128 of C2SP's test vectors it reads (the other 19 need post-quantum keys) and on files age encrypts and that are then damaged. SSH RSA keys come later |
| [`hivepack-bzip2`](crates/bzip2) | bzip2 in safe Rust, ported from libbzip2 1.0.8: the same output, at the same speed | Compresses with libbzip2's output, byte for byte, at every block size and work factor, and decompresses with its results, fast or small, randomised blocks included, both at about its speed |
| [`hivepack-cpio`](crates/cpio) | cpio archives and RPM packages' payloads in safe Rust, ported from libarchive 3.8.10's cpio reader and RPM filter | Reads odc, newc, crc, afio's large headers and binary cpio in both byte orders, with symbolic and hard links and the search for a header after garbage, with libarchive's headers, warnings, data and errors on its test archives, archives its writers make and tens of thousands of damaged ones; takes the lead and headers off RPM packages as libarchive does. Writing is not ported |
| [`hivepack-crypto`](crates/crypto) | The cryptography of ZIP's encryption, of age and of RAR 5's and XAR's hashes in safe Rust, ported from BearSSL 0.6 and the BLAKE2 reference implementation: AES, SHA-1, SHA-256, SHA-512, MD5, BLAKE2s, BLAKE2sp, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305, X25519 and scrypt | AES, ChaCha20-Poly1305 and X25519 run in constant time, as BearSSL's do; all checked against the published vectors, and against nettle for ZIP's and XAR's or Go's `x/crypto` for age's. `hivepack-zip` encrypts and decrypts WinZip AES with them |
| [`hivepack-deflate`](crates/deflate) | Deflate, zlib and gzip in safe Rust, ported from zlib 1.3.2: the same output, at the same speed | Compresses with zlib's output, byte for byte, and decompresses with its results and messages, both at about its speed. Decodes Deflate64 as zlib's `contrib/infback9` does |
| [`hivepack-extract`](crates/extract) | Extracting archives to disk, safe by default: nothing outside the destination, through links, over what is there, or past limits | Extracts ZIP, tar, 7z, RAR (with its feature `rar`, under UnRAR's license), cpio (RPM packages' payloads among them) and XAR archives (macOS packages and `.xip` files, their payloads expanded as `pkgutil --expand-full` does), ISO 9660 images and UDF volumes, refusing unportable names, the same path twice, links and overlapping data, writing by handle and counting what is written; tar, cpio, XAR and ISO read twice, to check everything before writing. RAR comes later |
| [`hivepack-iso`](crates/iso) | ISO 9660 images in safe Rust, ported from libarchive 3.8.10's reader | Reads ISO 9660 with Rock Ridge, Joliet, files in several extents and zisofs, with libarchive's headers, warnings, data and errors, on its test images, images its writer makes and tens of thousands of damaged ones. UDF and writing are not ported |
| [`hivepack-lz4`](crates/lz4) | LZ4 in safe Rust, ported from liblz4 1.10.0: blocks, frames and `.lz4` files | Compresses blocks and frames with liblz4's output, byte for byte, at every acceleration and level, with dictionaries, call by call; decodes blocks with liblz4's results, error positions included, and the same bytes in the output; decodes frames call by call as `LZ4F_decompress` does; writes `.lz4` files as liblz4 does and reads them, legacy ones included, as `lz4 -d` does; decodes at 0.75× liblz4's speed, or 0.96× with its `unsafe-fast` feature |
| [`hivepack-open`](crates/open) | Opening what hivepack reads through the layers around it: age, zstd, xz, lzip, .lzma, LZ4, gzip, bzip2, pbzx and RPM packages, found by their first bytes and stacked, then the container told | Opens `.tar.zst.age`, `.iso.xz`, `.rpm`, `.pkg` and any stack of these layers with hivepack's ports, each read as its tools read it, a passphrase asked for once however often the file is read; a tar, cpio or XAR archive or ISO 9660 image under them extracts with `hivepack-extract`, which reads the stream to its end to check it before writing; UDF volumes are told too |
| [`hivepack-rar`](crates/rar) | Reading RAR archives in safe Rust, ported from RARLAB's UnRAR 7.3.2, under UnRAR's license: it reads RAR and never writes it | Reads what UnRAR reads, as UnRAR does, broken archives included: the headers of RAR 1.4 to 7, every algorithm and cipher, volumes, comments and QuickOpen records, with UnRAR's fields, positions and exit codes on the archives of four other projects and hundreds of thousands of damaged copies |
| [`hivepack-tar`](crates/tar) | tar archives in safe Rust, ported from Go 1.27.2's `archive/tar`, its reading half | Reads V7, USTAR, PAX, GNU and STAR archives, PAX records, GNU long names and sparse files included, with Go's headers, data and errors on Go's test archives, archives Go writes and thousands of damaged ones |
| [`hivepack-udf`](crates/udf) | Reading UDF volumes in safe Rust, ported from NetBSD's UDF file system (`sys/fs/udf`): DVD, Blu-ray and disk images | Reads UDF 1.02 to 2.60 on physical, sparable, virtual (VAT) and metadata partitions, with blocks of 512 to 4096 bytes, as NetBSD mounts them, but where NetBSD loops, crashes or reads wrong; the same as Linux's udf file system on 36 images mkudffs, genisoimage and its tests make; extracted by `hivepack-extract` |
| [`hivepack-xar`](crates/xar) | XAR archives (macOS `.pkg` and `.xip` files) in safe Rust, ported from libarchive 3.8.10's reader, with the parts of libxml2 2.15.4 it reads the table of contents with | Reads every file with its metadata, extended attributes, links and data (stored, gzip, bzip2, lzma, xz; MD5, SHA-1, SHA-256 and SHA-512 checked), with libarchive's headers, warnings, data and errors, on its test archives, archives its writer, macOS's `xar` and `pkgbuild` make, archives the tests make, and tens of thousands of damaged ones. Writing is not ported |
| [`hivepack-xz`](crates/xz) | XZ and LZMA in safe Rust, ported from liblzma of XZ Utils 5.8.4: the same output, at the same speed | Compresses `.xz`, `.lzma`, and raw LZMA1 and LZMA2 with liblzma's output, byte for byte, with every preset, option and match finder, at about its speed; decompresses those and `.lz` with its results, call by call, at 1.06–1.34× the speed of liblzma's C and 0.74–0.89× of its x86-64 assembly; with the delta and BCJ filters, and in threads for `.xz` |
| [`hivepack-zip`](crates/zip) | ZIP archives in safe Rust, the container logic ported from libzip 1.12.1 | Opens archives, reads their headers, and reads stored, deflated, bzip2, LZMA, XZ, Zstandard, Deflate64 and PPMd entries with libzip's rules and errors; edits names, comments, times and attributes, deletes entries, adds and replaces data, stored, deflated, bzip2, LZMA, XZ or Zstandard, and writes the archive as libzip does, byte for byte; encrypts and decrypts ZipCrypto and WinZip AES; reads split archives, which libzip refuses, compared with 7-Zip. The rest compared with libzip, and 174 of libzip's own tests pass through the port's `ziptool` |
| [`hivepack-zstd`](crates/zstd) | Zstandard in safe Rust, ported from libzstd 1.5.7: the same output, at the same speed | Decompresses, in one call or streaming, with the same output and errors as libzstd, at about 0.9× its speed. Compresses at every level, in one call or streaming, with dictionaries, on several threads, with libzstd's frames. Trains dictionaries as libzstd does |

Every crate forbids `unsafe` code; the exceptions, the `unsafe-fast` features of `hivepack-zstd` and `hivepack-lz4`, are off by default (see [docs/unsafe.md](docs/unsafe.md)). The dependencies with `unsafe` code, cap-std and, on macOS, rustix, are in `hivepack-extract` only, until the standard library can open files from a directory's handle and set extended attributes. The rules are in [docs/safety.md](docs/safety.md), and how the ports follow the official libraries is in [docs/porting.md](docs/porting.md) (zstd), [docs/deflate.md](docs/deflate.md) (zlib), [docs/bzip2.md](docs/bzip2.md) (libbzip2), [docs/lz4.md](docs/lz4.md) (liblz4), [docs/xz.md](docs/xz.md) (liblzma), [docs/zip.md](docs/zip.md) (libzip), [docs/crypto.md](docs/crypto.md) (BearSSL) and [docs/age.md](docs/age.md) (age), [docs/tar.md](docs/tar.md) (Go's archive/tar), [docs/7z.md](docs/7z.md) (the LZMA SDK), [docs/iso.md](docs/iso.md), [docs/cpio.md](docs/cpio.md) and [docs/xar.md](docs/xar.md) (libarchive, and libxml2 for XAR), and [docs/udf.md](docs/udf.md) (NetBSD's UDF).

## ⚡ Speed

Each port is timed against the library it comes from, on the same data, and every tool is in `tools/`. Above 1× the port is faster. Each crate's README has its table, and how it was measured.

| Crate | Against | Where it is ahead or even | Where it is behind |
|---|---|---|---|
| [`hivepack-bzip2`](crates/bzip2#speed) | libbzip2 1.0.8 | compression 1.05×, decompression 1.01× | |
| [`hivepack-deflate`](crates/deflate#speed) | zlib 1.3.2 | compression 0.99×, decompression 1.00–1.05× | |
| [`hivepack-xz`](crates/xz#speed) | liblzma 5.8.4 | compression 1.02×, decompression 1.18× against its C | decompression 0.81× against its x86-64 assembly |
| [`hivepack-lz4`](crates/lz4#speed) | liblz4 1.10.0 | decoding 0.96× with `unsafe-fast`, compression 0.95× at level 1 | decoding 0.75× without it, high compression 0.74–0.98× |
| [`hivepack-zstd`](crates/zstd#speed) | libzstd 1.5.7 | levels 13 and 15, 0.94–1.05× | decompression 0.72–0.92× (0.78–0.96× with `unsafe-fast`), levels 5 to 12 0.49–0.84× (0.69–0.87×) |
| [`hivepack-zip`](crates/zip#speed) | libzip 1.12.1 | stored data 1.21–1.37×, compression 0.96–1.05×, finding entries 1.16–2.67×, editing many entries 1.46–1.99× | opening 200,000 entries 0.78×, WinZip AES 0.57–0.66× |
| [`hivepack-7z`](crates/7z#speed) | LZMA SDK 26.05, 7-Zip | LZMA and LZMA2 1.10–1.24× against C, Deflate 1.39× | PPMd 0.88–0.92×, BZip2 0.62×, AES-256 with Copy 0.08× |
| [`hivepack-tar`](crates/tar#speed) | Go 1.27.2's `archive/tar` | going through entries 1.48–2.61×, reading data 1.02–2.00×, seeking past data 2.05× | |
| [`hivepack-age`](crates/age#speed) | age v1.3.2, in Go | X25519 2.23–2.35×, scrypt 1.02–1.28×, a big file in ASCII armor 1.29× | a big file's payload 0.40× |
| [`hivepack-crypto`](crates/crypto#speed) | BearSSL 0.6 | 1.01–1.94× | Go's assembly, by up to 5.7×, on SHA-256 and ChaCha20-Poly1305 |

**Measured on,** in October 2026, with safe code unless it says otherwise:

- `hivepack-zip`, `hivepack-7z`, `hivepack-tar` and `hivepack-age`: AMD Ryzen 9 9950X (16 cores, x86-64), 45 GiB of memory, Ubuntu 26.04 with Linux 7.0 and the `powersave` governor, rustc 1.99.1 in the workspace's release profile; the libraries built with GCC 15.2.
- Each of them, except `hivepack-crypto`, also on GitHub's runners, Linux x86-64, Windows x86-64 and macOS arm64: see their READMEs. `.github/workflows/bench.yml` runs each format on those three; `hivepack-zip` and `hivepack-7z` are not on Windows yet.
- `hivepack-bzip2`, `hivepack-deflate`, `hivepack-lz4`, `hivepack-xz` and `hivepack-crypto`: an AMD Ryzen 9 9950X (x86-64, Linux).
- `hivepack-zstd`: an Apple M1 Pro, and GitHub's runners, an AMD EPYC 7763 and a Neoverse-N2.

These are snapshots of one machine or two, on the Silesia corpus: run the tools to see your own. How a reference is built matters: liblzma and libzstd have x86-64 assembly, and the usual builds of 7-Zip and of libzip's crypto libraries go further than the ones timed here, as each README says. `hivepack-iso`, `hivepack-udf`, `hivepack-rar`, `hivepack-open` and `hivepack-extract` have no such comparison yet.

## 🧪 Tests

```sh
python3 scripts/testdata.py fetch    # the test files too big to commit (16 MB)
cargo test --workspace
```

The test files come from zstd itself and from other zstd implementations (Go, Java, Rust), with their licenses. [testdata/README.md](testdata/README.md) lists them.

## 🦀 Rust versions

- **Oldest supported: 1.88**, `rust-version` in `Cargo.toml`, which CI checks.
  It is a promise to the crates' users: raised only when the code needs
  something newer, never to a Rust less than a year old, and, once the crates
  are published, in a minor release with a line in its notes.
- **Development:** `rust-toolchain.toml` pins the stable Rust that formats,
  lints, documents and tests, so a new Rust never turns CI red on its own. It
  is raised by hand every second Rust release (about every twelve weeks), once
  that release is two weeks old, in a pull request of its own, together with
  the nightly that Miri and cargo-fuzz use (`NIGHTLY` in
  `.github/workflows/ci.yml`).
- **Newer Rust:** a weekly workflow (`.github/workflows/newer-rust.yml`) lints
  and tests with the latest stable and beta, which users may build with before
  the pin is raised. A failure there warns; it blocks nothing.

## 🐝 Made by HivePaaS

hivepack is built and maintained by HivePaaS, who also make:

- [hivepaas](https://github.com/hivepaas/hivepaas): a self-hosted PaaS.
- [context-menu-rs](https://github.com/hivepaas/context-menu-rs): put your app in the right-click menu of Windows Explorer, macOS Finder and Linux file managers, from Rust.
- [shellwing](https://shellwing.app): a fast, native SSH client for macOS, Windows and Linux.
- [authwing](https://github.com/hivepaas/authwing): a two-factor code app for macOS, Windows and Linux that knows the window you are in.
- [packwing](https://github.com/hivepaas/packwing): a file archiver for macOS, Windows and Linux that opens archives safely, built on hivepack.

⭐ If hivepack, or any of these, is useful to you, please give it a star on GitHub: it helps others find it, and helps us keep making them.

## 📜 License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 HivePaaS.

The exceptions are the ports, under the licenses of the code they are ported from: `hivepack-zstd` under BSD-3-Clause, with its suffix sort, from libdivsufsort, under MIT (see [crates/zstd/LICENSE](crates/zstd/LICENSE)), `hivepack-deflate` under the zlib license (see [crates/deflate/LICENSE](crates/deflate/LICENSE)), `hivepack-bzip2` under libbzip2's license (see [crates/bzip2/LICENSE](crates/bzip2/LICENSE)), `hivepack-lz4` under BSD-2-Clause (see [crates/lz4/LICENSE](crates/lz4/LICENSE)), `hivepack-xz` under liblzma's, the BSD Zero Clause License (see [crates/xz/LICENSE](crates/xz/LICENSE)), `hivepack-zip` under BSD-3-Clause (see [crates/zip/LICENSE](crates/zip/LICENSE)), `hivepack-age` under BSD-3-Clause (see [crates/age/LICENSE](crates/age/LICENSE)), `hivepack-tar` under BSD-3-Clause (see [crates/tar/LICENSE](crates/tar/LICENSE)), `hivepack-iso` and `hivepack-cpio` under BSD-2-Clause, as libarchive is (see [crates/iso/LICENSE](crates/iso/LICENSE) and [crates/cpio/LICENSE](crates/cpio/LICENSE)), `hivepack-xar` under BSD-2-Clause too, with its XML reader, from libxml2, under MIT (see [crates/xar/LICENSE](crates/xar/LICENSE)), `hivepack-udf` under BSD-2-Clause and BSD-3-Clause, as NetBSD's UDF file system is (see [crates/udf/LICENSE](crates/udf/LICENSE)), and `hivepack-rar` under UnRAR's own license, which allows reading RAR and not writing it (see [crates/rar/LICENSE](crates/rar/LICENSE) and [docs/rar.md](docs/rar.md)). `hivepack-crypto`, ported from BearSSL, is under the MIT license too, with BearSSL's notice (see [crates/crypto/LICENSE](crates/crypto/LICENSE)), and so is `hivepack-7z`, ported from the LZMA SDK's C files, which are in the public domain. The test files in `testdata/` keep their own licenses, listed in [testdata/README.md](testdata/README.md).
