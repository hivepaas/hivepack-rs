//! AppImages: where the program at the start of an AppImage ends, ported
//! from AppImage's type 2 runtime, and the image after it.
//!
//! An AppImage is an ELF program, the runtime, with a file system image:
//! of type 2, a SquashFS image after the program's end, which the runtime
//! mounts from there; of type 1, the older, an ISO 9660 image whose first
//! 32 KiB, the system area, hold the program. Bytes 8 to 10 of the ELF
//! header, which ELF leaves as padding, say which: `AI` and 2 or 1.
//!
//! ```no_run
//! use hivepack::appimage::{AppImageType, appimage_type, open_squashfs};
//!
//! let mut file = std::fs::File::open("app.AppImage")?;
//! let mut head = [0u8; 16];
//! std::io::Read::read_exact(&mut file, &mut head)?;
//! if appimage_type(&head) == Some(AppImageType::Two) {
//!     let mut fs = open_squashfs(file)?;
//!     let root = fs.root()?;
//!     for entry in fs.read_dir(&root)? {
//!         println!("{}", String::from_utf8_lossy(&entry?.name));
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod runtime;

use std::fmt;
use std::io::{self, Read, Seek};

use crate::squashfs::Squashfs;

pub use runtime::appimage_get_elf_size as elf_size;

/// The release of AppImage's type 2 runtime this module follows.
pub const UPSTREAM_VERSION: &str = "20251108";

/// An ELF file's magic.
pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

/// What an AppImage holds after its program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AppImageType {
    /// Type 1: the file is an ISO 9660 image, the program in its system
    /// area; `hivepack::iso` reads it from the file's start.
    One,
    /// Type 2: a SquashFS image after the program: [`open_squashfs`].
    Two,
}

/// The AppImage type of a file, from its first bytes: an ELF file's magic,
/// then at byte 8 `AI` and the type, 1 or 2, as AppImage's specification
/// and `file` tell one. `None` for anything else, an ELF program that is no
/// AppImage among them.
pub fn appimage_type(head: &[u8]) -> Option<AppImageType> {
    if !head.starts_with(&ELF_MAGIC) {
        return None;
    }
    match head.get(8..11)? {
        b"AI\x01" => Some(AppImageType::One),
        b"AI\x02" => Some(AppImageType::Two),
        _ => None,
    }
}

/// The SquashFS image of a type 2 AppImage, opened where its program ends
/// ([`elf_size`]), as the runtime mounts it.
pub fn open_squashfs<R: Read + Seek>(mut reader: R) -> Result<Squashfs<R>, Error> {
    let offset = elf_size(&mut reader)?;
    Squashfs::open_at(reader, offset).map_err(Error::Squashfs)
}

/// A failure to find an AppImage's image.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reading the file failed.
    Io(io::Error),
    /// The ELF header or section header is not one the runtime reads: the
    /// runtime's message.
    Elf(&'static str),
    /// The SquashFS image after the program does not open.
    Squashfs(crate::squashfs::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "AppImage: read error: {e}"),
            Error::Elf(what) => write!(f, "AppImage: {what}"),
            Error::Squashfs(e) => write!(f, "AppImage: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Elf(_) => None,
            Error::Squashfs(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}
