//! Extracting archives to disk, safe by default: nothing is written
//! outside the destination, through a link, over what is there, or past
//! limits set against archive bombs.
//!
//! What extractors get wrong is logic, not memory: names that climb out of
//! the destination (`../`, `/etc`, `C:`, `a:stream`), links in the archive
//! or already on disk that lead elsewhere, the same path given twice,
//! setuid bits, and archives whose entries share one compressed stream to
//! write terabytes. This crate refuses rather than repairs, so that an
//! archive extracts the same everywhere:
//!
//! - **Names**: [`check_name`] refuses names that are absolute, climb with
//!   `..`, carry a backslash, a colon, a control character or a Windows
//!   device name, or end a component with a space or a dot, on every
//!   system alike. Two entries may not name the same path, ignoring case
//!   and how accents are written (`é` as one character or as `e` and an
//!   accent), with the tables of one Unicode version ([`UNICODE_VERSION`]).
//! - **Links** are not created, unless [`Options::links`] says to create
//!   those that stay inside the destination; a device or FIFO in a ZIP
//!   archive, only a mode with data, is written as a file.
//! - **Writing** goes through handles: each directory is opened from its
//!   parent without following a link, and each file is created new, so a
//!   link already in the destination, or put there while extracting, is
//!   not followed, and nothing is overwritten.
//! - **Limits** ([`Limits`]) count entries, the bytes each writes and all
//!   write, and the bytes written for each compressed byte; entries whose
//!   compressed data overlap are refused before anything is written.
//! - **Integrity**: a file whose data fails its check (CRC-32, or WinZip
//!   AES's authentication code) is removed.
//! - **Permissions** are masked: no setuid, setgid or sticky bit, and
//!   nothing writable by group or others.
//! - **Time**: an extraction can be given a time limit
//!   ([`Options::time_limit`]), stopped from another thread ([`Cancel`]),
//!   and followed ([`Options::progress`]).
//! - **Threads**: a ZIP archive's files, a RAR archive's that is not solid,
//!   a SquashFS image's, and a 7z archive's folders can be written several
//!   at once, each in a thread of its own, a tar or cpio archive's by threads while it is read,
//!   a XAR package's payloads decoded in threads too, and a solid RAR 5
//!   archive's decompressed a Huffman block in each thread
//!   ([`Options::threads`]); what is written is the same.
//! - **Marks of origin**: the archive's Mark of the Web on Windows, or its
//!   quarantine on macOS ([`Origin`]), is carried to every file written.
//!
//! ```no_run
//! use hivepack::extract::{Options, Origin, extract_zip};
//! use hivepack::zip::{Archive, OpenFlags, Volumes};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let path = std::path::Path::new("archive.zip");
//! // The file, or the volumes of a split archive (archive.z01, … archive.zip).
//! let archive = Archive::open(Volumes::open(path)?, OpenFlags::CHECKCONS)?;
//! let mut options = Options::default();
//! // Downloaded files are marked; what is extracted from them must be too.
//! options.origin = Origin::of(path)?;
//! let summary = extract_zip(&archive, "out".as_ref(), &options)?;
//! println!("{} files, {} bytes", summary.files, summary.bytes);
//! # Ok(())
//! # }
//! ```
//!
//! [`extract_tar`] extracts tar archives with the same rules, reading them
//! once into a private folder in the destination, every entry checked before
//! any moves into place; [`extract_cpio`] cpio archives (RPM packages'
//! payloads among them) and [`extract_xar`] XAR archives (macOS packages,
//! their payloads expanded) the same way; [`extract_iso`] ISO 9660 images
//! reading them twice: once to check, once to write; [`extract_udf`] UDF
//! volumes, [`extract_squashfs`] SquashFS images (snaps, AppImages) and
//! [`extract_7z`] 7z archives, checked first, as ZIP archives are.
//!
//! With the feature `ext`, `extract_ext` extracts the ext2, ext3 and ext4
//! file systems `hivepack::ext` reads — a card's root partition, what
//! WSL2's `ext4.vhdx` holds — checked first in the same way. It is the
//! first thing here that can give back who owned a file and what was
//! beside it: a file system records the owner and group of every inode, and
//! the extended attributes SELinux labels and ACLs live in, which go
//! through the same `Options::owners` and `Options::xattrs` a tar
//! archive's do.
//!
//! With the feature `fat`, `extract_fat` extracts the FAT12, FAT16 and
//! FAT32 file systems `hivepack::fat` reads — a card's boot partition, an
//! EFI system partition, a camera's card. FAT keeps less than the others
//! and what it does not keep is not invented: no permissions, no owner, no
//! extended attributes and neither kind of link, so only files and
//! directories come out.
//!
//! With the feature `exfat`, `extract_exfat` extracts the exFAT file
//! systems `hivepack::exfat` reads — a memory card larger than 32 GB, a
//! camera's card, a stick as it was sold. It keeps as little beside a file
//! as FAT does, so only files and directories come out; what it keeps and
//! FAT does not is the offset from UTC beside each time, which is taken
//! off, and the length a file has been written to, past which the file
//! comes out as zeroes rather than as whatever is in the clusters.
//!
//! With the feature `ntfs`, off by default as the library that reads the
//! structures is not in a release that can be fuzzed (`docs/ntfs.md`),
//! `extract_ntfs` extracts the NTFS file systems `hivepack::ntfs` reads —
//! a Windows VHDX, a VM's disk. What NTFS keeps that cannot come out whole
//! is refused rather than written: data NTFS compressed itself, which the
//! library hands back compressed with no error at all, data the
//! encrypting file system holds the key to, and reparse points. The
//! streams beside a file are left where they are, and the security
//! descriptor every file carries is not turned into a Unix owner or mode.
//!
//! With the feature `rar`, off by default as it takes UnRAR's license,
//! `extract_rar` extracts RAR archives the same way, reading them twice.
//!
//! Each also extracts into a [`Sink`] in place of a folder
//! ([`extract_zip_to`] and the other `_to` functions): an archive being
//! written, an index, a checksum of each file. The sink is given what the
//! folder would be, after the same checks and in the same order, a piece of
//! data at a time.
//!
//! The design is in the repository's `docs/extract.md`.

#![forbid(unsafe_code)]

mod cpio;
mod destination;
mod error;
#[cfg(feature = "exfat")]
mod exfat;
#[cfg(feature = "ext")]
mod ext;
#[cfg(feature = "fat")]
mod fat;
mod iso;
mod name;
#[cfg(feature = "ntfs")]
mod ntfs;
mod once;
mod origin;
mod plan;
mod progress;
#[cfg(feature = "rar")]
mod rar;
mod remote;
mod sevenz;
mod sink;
mod squashfs;
mod tar;
mod udf;
mod unicode;
mod writers;
mod xar;
mod zip;

pub use cpio::{extract_cpio, extract_cpio_to};
#[cfg(feature = "rar")]
pub use error::RarProblem;
pub use error::{Error, ErrorKind};
#[cfg(feature = "exfat")]
pub use exfat::{extract_exfat, extract_exfat_to};
#[cfg(feature = "ext")]
pub use ext::{extract_ext, extract_ext_to};
#[cfg(feature = "fat")]
pub use fat::{extract_fat, extract_fat_to};
pub use iso::{extract_iso, extract_iso_to};
pub use name::{MAX_COMPONENT, Name, NameError, NameRules, check_name, check_name_for};
#[cfg(feature = "ntfs")]
pub use ntfs::{extract_ntfs, extract_ntfs_to};
pub use origin::Origin;
pub use plan::{
    Limits, LinkOutside, Links, NameDecoder, Names, OnDamaged, OnDamagedFn, OnLinksOutside,
    OnLinksOutsideFn, OnRefused, OnUnnamable, OnUnnamableFn, OnWrittenFn, Options, Owners,
    Packages, Permissions, Renamed, Select, Written, WrittenKind,
};
pub use progress::{Cancel, Progress, ProgressFn};
#[cfg(feature = "rar")]
pub use rar::{extract_rar, extract_rar_to};
pub use sevenz::{extract_7z, extract_7z_to};
pub use sink::{Entry, Sink};
pub use squashfs::{extract_squashfs, extract_squashfs_to};
pub use tar::{extract_tar, extract_tar_to, remove_stale};
pub use udf::{extract_udf, extract_udf_to};
/// The version of Unicode names are compared with: major, minor, update.
pub use unicode::VERSION as UNICODE_VERSION;
pub use xar::{extract_xar, extract_xar_to};
pub use zip::{Damaged, Summary, extract_zip, extract_zip_to};
