# Licenses of the hivepack crate

The crate's own code is under the MIT license ([LICENSE](LICENSE)). Each port keeps the license of the code it is derived from, and its text is in the module's folder. A program that uses a module follows that module's license, and those of the modules it needs.

| Module (feature) | License | Text |
|---|---|---|
| `age` | BSD-3-Clause | [src/age/LICENSE](src/age/LICENSE) |
| `appimage` | MIT | [src/appimage/LICENSE](src/appimage/LICENSE) |
| `bzip2` | bzip2-1.0.6 | [src/bzip2/LICENSE](src/bzip2/LICENSE) |
| `cpio` | BSD-2-Clause | [src/cpio/LICENSE](src/cpio/LICENSE) |
| `crypto` | MIT | [src/crypto/LICENSE](src/crypto/LICENSE) |
| `deflate` | Zlib AND MIT (libdeflate's compressor, `deflate::Compressor`) | [src/deflate/LICENSE](src/deflate/LICENSE), [src/deflate/libdeflate/LICENSE](src/deflate/libdeflate/LICENSE) |
| `extract` | MIT AND Unicode-3.0 | [LICENSE](LICENSE), [src/extract/LICENSE-UNICODE](src/extract/LICENSE-UNICODE) |
| `iso` | BSD-2-Clause | [src/iso/LICENSE](src/iso/LICENSE) |
| `lz4` | BSD-2-Clause | [src/lz4/LICENSE](src/lz4/LICENSE) |
| `lzo` | MIT | [src/lzo/LICENSE](src/lzo/LICENSE) |
| `open` | MIT | [src/open/LICENSE](src/open/LICENSE) |
| `rar` | **UnRAR**, which is not an open source license: it may not be used to develop a RAR-compatible archiver or to re-create RAR's compression | [src/rar/LICENSE](src/rar/LICENSE) |
| `sevenz` | MIT | [src/sevenz/LICENSE](src/sevenz/LICENSE) |
| `sign` | MIT | [src/sign/LICENSE](src/sign/LICENSE) |
| `squashfs` | BSD-2-Clause | [src/squashfs/LICENSE](src/squashfs/LICENSE) |
| `tar` | BSD-3-Clause | [src/tar/LICENSE](src/tar/LICENSE) |
| `udf` | BSD-2-Clause AND BSD-3-Clause | [src/udf/LICENSE](src/udf/LICENSE) |
| `xar` | BSD-2-Clause AND MIT | [src/xar/LICENSE](src/xar/LICENSE) |
| `xz` | 0BSD | [src/xz/LICENSE](src/xz/LICENSE) |
| `zip` | BSD-3-Clause | [src/zip/LICENSE](src/zip/LICENSE) |
| `zstd` | BSD-3-Clause AND MIT | [src/zstd/LICENSE](src/zstd/LICENSE) |

The `license` field of `Cargo.toml` lists them all, UnRAR among them, because the package holds all of this code, whichever features are on. The `rar` feature is off by default, and without it the module is not compiled.
