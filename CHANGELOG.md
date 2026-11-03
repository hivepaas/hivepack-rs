# Changelog

## Unreleased

- `open`: a `.tlz` file is `.tar.lzma` (its short name, as file managers give it) when its bytes are no other format's: lzip's `.tlz` is still told by its magic.

## 0.2.0

- `sevenz`: `Writer::set_method` changes the method from the next file on, which starts a folder of its own: what is compressed already can be stored with `Method::Copy` beside what is not.

## 0.1.0

The first release, as one crate, `hivepack`, with a module and a feature for each format. Before 1.0 a minor release (0.2.0) may change an API; a patch release (0.1.x) only fixes.

- Ports, with the output, errors and speed of the libraries they come from: `deflate` (zlib 1.3.2), `bzip2` (libbzip2 1.0.8), `lz4` (liblz4 1.10.0), `xz` (liblzma 5.8.4), `zstd` (libzstd 1.5.7), `zip` (libzip 1.12.1), `tar` (Go 1.27.2), `sevenz` (LZMA SDK 26.05), `rar` (UnRAR 7.3.2), `age` (age v1.3.2), `iso`, `cpio`, `xar` (libarchive 3.8.10), `udf` (NetBSD).
- `extract`: extraction to disk, safe by default, for ZIP, tar, 7z, RAR (feature `rar`), cpio, XAR, ISO 9660 and UDF.
- `open`: finds and stacks the layers around an archive (age, zstd, xz, lzip, LZ4, gzip, bzip2, pbzx, RPM).
- `sign`: whole-file signatures in `ssh-keygen -Y sign`'s format, and hybrid Ed25519 + ML-DSA-65 keys.
- `crypto`: one small interface over RustCrypto and dalek crates; no cryptography of its own.
- `unsafe` code is forbidden in every module. The `unsafe-fast` features of `zstd`, `lz4` and `deflate` are off by default ([docs/unsafe.md](docs/unsafe.md)).
- Known limits: `ml-dsa` has not been audited independently (it never signs alone); `rar` is under UnRAR's license and never writes RAR; Windows does not mark a sparse file's holes on extraction; SSH RSA keys are not taken by `age` and `sign`.
