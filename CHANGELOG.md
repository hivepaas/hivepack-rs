# Changelog

## 0.1.0

The first release of all 18 crates. Before 1.0 a minor release (0.2.0) may change an API; a patch release (0.1.x) only fixes.

- Ports, with the output, errors and speed of the libraries they come from: `hivepack-deflate` (zlib 1.3.2), `hivepack-bzip2` (libbzip2 1.0.8), `hivepack-lz4` (liblz4 1.10.0), `hivepack-xz` (liblzma 5.8.4), `hivepack-zstd` (libzstd 1.5.7), `hivepack-zip` (libzip 1.12.1), `hivepack-tar` (Go 1.27.2), `hivepack-7z` (LZMA SDK 26.05), `hivepack-rar` (UnRAR 7.3.2), `hivepack-age` (age v1.3.2), `hivepack-iso`, `hivepack-cpio`, `hivepack-xar` (libarchive 3.8.10), `hivepack-udf` (NetBSD).
- `hivepack-extract`: extraction to disk, safe by default, for ZIP, tar, 7z, RAR (feature `rar`), cpio, XAR, ISO 9660 and UDF.
- `hivepack-open`: finds and stacks the layers around an archive (age, zstd, xz, lzip, LZ4, gzip, bzip2, pbzx, RPM).
- `hivepack-sign`: whole-file signatures in `ssh-keygen -Y sign`'s format, and hybrid Ed25519 + ML-DSA-65 keys.
- `hivepack-crypto`: one small interface over RustCrypto and dalek crates; no cryptography of its own.
- `unsafe` code is forbidden in every crate. The `unsafe-fast` features of `hivepack-zstd`, `hivepack-lz4` and `hivepack-deflate` are off by default ([docs/unsafe.md](docs/unsafe.md)).
- Known limits: `ml-dsa` has not been audited independently (it never signs alone); `hivepack-rar` is under UnRAR's license and never writes RAR; Windows does not mark a sparse file's holes on extraction; SSH RSA keys are not taken by `hivepack-age` and `hivepack-sign`.
