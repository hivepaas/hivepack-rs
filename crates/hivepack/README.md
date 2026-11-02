# hivepack

Read and write archives and compressed files in Rust: one crate for many formats, in the spirit of libarchive. Most of it is ported from the libraries of each format and compared with them, output and errors alike.

```toml
[dependencies]
hivepack = "0.1"                                                            # every format but RAR
# hivepack = { version = "0.1", default-features = false, features = ["zip", "zstd"] }  # only these
# hivepack = { version = "0.1", features = ["rar"] }                        # RAR too, under UnRAR's license
```

| Module | Reads and writes |
|---|---|
| `zip`, `tar`, `sevenz` | ZIP, tar and 7z archives |
| `rar` | RAR, reading only (feature off by default, under UnRAR's license) |
| `iso`, `udf`, `cpio`, `xar` | ISO 9660 images, UDF volumes, cpio and RPM payloads, XAR (`.pkg`, `.xip`), reading |
| `deflate`, `bzip2`, `lz4`, `xz`, `zstd` | Deflate, zlib, gzip, bzip2, LZ4, XZ, LZMA, Zstandard |
| `age`, `sign` | age encryption, and whole-file signatures with SSH Ed25519 and hybrid ML-DSA-65 keys |
| `open` | Files through their layers: `.tar.zst.age` opens as the tar archive |
| `extract` | Extracting to disk, safe by default: nothing outside the destination, through links, or past limits |

Own code is safe Rust. The `unsafe-fast` features, off by default, are the exception, and [docs/unsafe.md](https://github.com/hivepaas/hivepack-rs/blob/main/docs/unsafe.md) documents each use. Dependencies with `unsafe` code are the cryptography's crates and `cap-std`.

Licenses differ by module, as each port keeps its origin's: see [LICENSE.md](LICENSE.md). ML-DSA's crate has not been audited independently, so it never signs alone.

More: [the repository](https://github.com/hivepaas/hivepack-rs), with a README and a document for each format.
