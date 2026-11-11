//! Read and write archives and compressed files in safe Rust: one crate for many
//! formats, in the spirit of libarchive.
//!
//! Each format is a module behind a feature of the same name, and the ones it
//! needs come with it. All but `rar` are on by default; use
//! `default-features = false` and name the ones you want to compile less.
//! Beside the formats, `memory`, off by default, measures how much memory
//! the program may still take, for an application to choose the threads of
//! its coders under it.
//!
//! | Module | Feature | What it is |
//! |---|---|---|
//! | [`age`] | `age` | age encryption (decrypt, encrypt, keys) |
//! | [`ar`] | `ar` | ar archives and Debian packages (`.deb`) |
//! | [`bzip2`] | `bzip2` | bzip2 (libbzip2 1.0.8) |
//! | [`cpio`] | `cpio` | cpio archives and RPM payloads |
//! | [`crypto`] | `crypto` | the cryptography of the formats, behind one interface |
//! | [`deflate`] | `deflate` | Deflate, zlib, gzip (zlib 1.3.2) |
//! | [`extract`] | `extract` | extracting archives to disk, safe by default |
//! | [`iso`] | `iso` | ISO 9660 images |
//! | [`lz4`] | `lz4` | LZ4 (liblz4 1.10.0) |
//! | [`lzo`] | `lzo` | LZO1X blocks, decompression (lzokay; liblzo2 2.10's results) |
//! | [`memory`](memory/index.html) | `memory` | the memory the program may still take, and a budget for threads |
//! | [`open`] | `open` | opening files through their layers (age, zstd, xz, gzip, ...) |
//! | [`rar`] | `rar` | reading RAR (UnRAR 7.3.2), under UnRAR's license |
//! | [`sevenz`] | `sevenz` | 7z archives |
//! | [`sign`] | `sign` | file signatures (Ed25519 and Ed25519 + ML-DSA-65) |
//! | [`squashfs`] | `squashfs` | SquashFS images: snaps, AppImages (squashfuse 0.6.5) |
//! | [`tar`] | `tar` | tar archives |
//! | [`udf`] | `udf` | UDF volumes |
//! | [`xar`] | `xar` | XAR archives (macOS `.pkg` and `.xip`) |
//! | [`xz`] | `xz` | XZ and LZMA (liblzma 5.8.4) |
//! | [`zip`] | `zip` | ZIP archives (libzip 1.12.1) |
//! | [`zstd`] | `zstd` | Zstandard (libzstd 1.5.7) |
//!
//! The crate is under several licenses, one for each port's origin: see
//! `LICENSE.md`. The `rar` feature is under UnRAR's, which does not allow
//! writing RAR.

// So that code shared with the integration tests names the crate one way.
#[cfg(test)]
extern crate self as hivepack;

#[cfg(feature = "age")]
pub mod age;
#[cfg(feature = "ar")]
pub mod ar;
#[cfg(feature = "bzip2")]
pub mod bzip2;
#[cfg(all(
    target_arch = "x86_64",
    not(miri),
    any(
        all(feature = "deflate", feature = "deflate-unsafe-fast"),
        all(feature = "xz", feature = "xz-unsafe-fast")
    )
))]
mod clmul;
#[cfg(feature = "cpio")]
pub mod cpio;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "deflate")]
pub mod deflate;
#[cfg(feature = "extract")]
pub mod extract;
#[cfg(feature = "extract")]
mod hidden;
#[cfg(feature = "iso")]
pub mod iso;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "lzo")]
pub mod lzo;
#[cfg(feature = "memory")]
pub mod memory;
#[cfg(feature = "open")]
pub mod open;
#[cfg(feature = "rar")]
pub mod rar;
#[cfg(feature = "sevenz")]
pub mod sevenz;
#[cfg(feature = "sign")]
pub mod sign;
#[cfg(feature = "squashfs")]
pub mod squashfs;
#[cfg(feature = "tar")]
pub mod tar;
#[cfg(feature = "udf")]
pub mod udf;
#[cfg(feature = "xar")]
pub mod xar;
#[cfg(feature = "xz")]
pub mod xz;
#[cfg(feature = "zip")]
pub mod zip;
#[cfg(feature = "zstd")]
pub mod zstd;

mod threads;
pub use threads::Threads;
#[cfg(any(
    feature = "deflate",
    feature = "lz4",
    feature = "sevenz",
    feature = "zip",
    feature = "zstd"
))]
mod workers;
