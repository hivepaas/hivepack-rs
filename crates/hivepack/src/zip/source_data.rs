//! What new data for an entry is read from: the role of the `zip_source_t`
//! given to `zip_file_add` and `zip_file_replace`, with libzip's buffer
//! and file sources (`zip_source_buffer.c`, `zip_source_file_common.c`
//! and `zip_source_file_stdio.c`), and `zip_file_attributes_t` with the
//! way a stack of sources merges them (`zip_source_get_file_attributes.c`).
//!
//! Differs from libzip: a source is read at a position, as an archive is,
//! so that it can be shared, read by several open entries at once and by
//! `zip_close`, where libzip seeks one source before each read.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::zip::{Stat, cm, em, opsys, stat};

/// Which fields of [`FileAttributes`] are set: `ZIP_FILE_ATTRIBUTES_*`.
pub mod file_attributes {
    pub const HOST_SYSTEM: u64 = 0x0001;
    pub const ASCII: u64 = 0x0002;
    pub const VERSION_NEEDED: u64 = 0x0004;
    pub const EXTERNAL_FILE_ATTRIBUTES: u64 = 0x0008;
    pub const GENERAL_PURPOSE_BIT_FLAGS: u64 = 0x0010;
}

/// `ZIP_FILE_ATTRIBUTES_GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK`: the bits of
/// the general purpose flags a source may set.
pub(crate) const GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK: u16 = 0x083e;

/// What a source says about the file its data is: `zip_file_attributes_t`.
/// The default has nothing set, as `zip_file_attributes_init` makes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileAttributes {
    /// Which fields have valid values: [`file_attributes`] bits.
    pub valid: u64,
    /// The system the file was made on, an [`opsys`] value.
    pub host_system: u8,
    /// Whether the file is ASCII text.
    pub ascii: bool,
    /// The version needed to extract it, at least.
    pub version_needed: u8,
    /// The external attributes, as the host system has them.
    pub external_file_attributes: u32,
    /// General purpose bit flags, of those in `general_purpose_bit_mask`.
    pub general_purpose_bit_flags: u16,
    /// Which of `general_purpose_bit_flags` are valid.
    pub general_purpose_bit_mask: u16,
}

impl FileAttributes {
    /// Takes from `lower`, the attributes of the source below, what these
    /// do not set: the host system, ASCII and external attributes if not
    /// set here, the larger version needed, and the general purpose bits
    /// outside this mask. Port of the layering in
    /// `zip_source_get_file_attributes`.
    pub(crate) fn merge_lower(&mut self, lower: &FileAttributes) {
        use file_attributes::*;
        if lower.valid & HOST_SYSTEM != 0 && self.valid & HOST_SYSTEM == 0 {
            self.host_system = lower.host_system;
            self.valid |= HOST_SYSTEM;
        }
        if lower.valid & ASCII != 0 && self.valid & ASCII == 0 {
            self.ascii = lower.ascii;
            self.valid |= ASCII;
        }
        if lower.valid & VERSION_NEEDED != 0 {
            if self.valid & VERSION_NEEDED != 0 {
                self.version_needed = self.version_needed.max(lower.version_needed);
            } else {
                self.version_needed = lower.version_needed;
                self.valid |= VERSION_NEEDED;
            }
        }
        if lower.valid & EXTERNAL_FILE_ATTRIBUTES != 0 && self.valid & EXTERNAL_FILE_ATTRIBUTES == 0
        {
            self.external_file_attributes = lower.external_file_attributes;
            self.valid |= EXTERNAL_FILE_ATTRIBUTES;
        }
        if lower.valid & GENERAL_PURPOSE_BIT_FLAGS != 0 {
            if self.valid & GENERAL_PURPOSE_BIT_FLAGS != 0 {
                // only take from lower level what is not defined at current
                // level
                let mask = lower.general_purpose_bit_mask & !self.general_purpose_bit_mask;
                self.general_purpose_bit_flags |= lower.general_purpose_bit_flags & mask;
                self.general_purpose_bit_mask |= mask;
            } else {
                self.valid |= GENERAL_PURPOSE_BIT_FLAGS;
                self.general_purpose_bit_flags = lower.general_purpose_bit_flags;
                self.general_purpose_bit_mask = lower.general_purpose_bit_mask;
            }
        }
    }
}

/// What an entry's new data is read from, for
/// [`Archive::file_add`](crate::zip::Archive::file_add) and
/// [`Archive::file_replace`](crate::zip::Archive::file_replace): the commands of
/// a libzip source that `zip_close` and `zip_fopen` use. The data is read
/// at a position, as an archive is.
pub trait DataSource: Send + Sync {
    /// What is known about the data (`ZIP_SOURCE_STAT`): its size, time,
    /// CRC, and the method it is compressed with, if it is. A size that is
    /// not known makes the entry Zip64, as libzip makes it.
    fn stat(&self) -> Result<Stat<'static>>;

    /// What is known about the file (`ZIP_SOURCE_GET_FILE_ATTRIBUTES`):
    /// nothing, unless the source says.
    fn file_attributes(&self) -> Result<FileAttributes> {
        Ok(FileAttributes::default())
    }

    /// The time in MS-DOS format, `(time, date)`, if the source has it
    /// as stored (`ZIP_SOURCE_GET_DOS_TIME`); otherwise the entry takes
    /// the time of the stat.
    fn dos_time(&self) -> Result<Option<(u16, u16)>> {
        Ok(None)
    }

    /// Reads bytes at `offset` into `buf`, as many as there are, up to its
    /// length; fewer only at the end.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
}

/// The time now, in seconds since 1970, as `time(NULL)` gives it.
pub(crate) fn time_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Data in memory: port of `zip_source_buffer`. Its time is when it was
/// made, unless given.
#[derive(Clone, Debug)]
pub struct BufferSource {
    data: Arc<[u8]>,
    mtime: i64,
    attributes: FileAttributes,
}

impl BufferSource {
    /// `data`, with the time now: `zip_source_buffer_create`.
    pub fn new(data: impl Into<Arc<[u8]>>) -> BufferSource {
        BufferSource::with_mtime(data, time_now())
    }

    /// `data`, with the modification time `mtime`, in seconds since 1970.
    pub fn with_mtime(data: impl Into<Arc<[u8]>>, mtime: i64) -> BufferSource {
        BufferSource {
            data: data.into(),
            mtime,
            attributes: FileAttributes::default(),
        }
    }

    /// The same, with `attributes`: `zip_source_buffer_with_attributes`.
    pub fn attributes(mut self, attributes: FileAttributes) -> BufferSource {
        self.attributes = attributes;
        self
    }
}

impl DataSource for BufferSource {
    /// Port of `ZIP_SOURCE_STAT`: the size and time, stored, not
    /// encrypted.
    fn stat(&self) -> Result<Stat<'static>> {
        Ok(Stat {
            mtime: self.mtime,
            size: self.data.len() as u64,
            comp_size: self.data.len() as u64,
            comp_method: cm::STORE,
            encryption_method: em::NONE,
            valid: stat::MTIME
                | stat::SIZE
                | stat::COMP_SIZE
                | stat::COMP_METHOD
                | stat::ENCRYPTION_METHOD,
            ..Stat::default()
        })
    }

    fn file_attributes(&self) -> Result<FileAttributes> {
        Ok(self.attributes)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
}

/// A file, or part of one: port of `zip_source_file_create`. Its stat and
/// attributes are taken when it is made: the size of the part, the file's
/// time, and its mode as Unix external attributes, as libzip gives them on
/// every system.
#[derive(Debug)]
pub struct FileSource {
    /// none for a file that is not there
    file: Option<std::fs::File>,
    start: u64,
    stat: Stat<'static>,
    attributes: FileAttributes,
}

/// `errno` of a failed system call, or 0.
fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

impl FileSource {
    /// The file at `path`, from `start`, `len` bytes of it (to its end if
    /// `None`): `zip_source_file_create`. A file that is not there fails
    /// with `ZIP_ER_READ` and `ENOENT`, as libzip's does, but when all of
    /// it is asked for: then its stat fails so, when it is read.
    pub fn new(
        path: impl AsRef<std::path::Path>,
        start: u64,
        len: Option<u64>,
    ) -> Result<FileSource> {
        match std::fs::File::open(path) {
            Ok(file) => FileSource::from_file(file, start, len),
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && start == 0
                    && len.unwrap_or(0) == 0 =>
            {
                Ok(FileSource {
                    file: None,
                    start,
                    stat: Stat::default(),
                    attributes: FileAttributes::default(),
                })
            }
            Err(e) => Err(Error::new(ErrorCode::Read, errno(&e))),
        }
    }

    /// The file at `path` from `start` to its end when it is read, its
    /// size not known before: `zip_source_file_create` with
    /// `ZIP_LENGTH_UNCHECKED`.
    pub fn unchecked(path: impl AsRef<std::path::Path>, start: u64) -> Result<FileSource> {
        let mut source = FileSource::new(path, start, None)?;
        source.stat.valid &= !stat::SIZE;
        Ok(source)
    }

    /// An open file, from `start`, `len` bytes of it (to its end if
    /// `None`): `zip_source_filep_create`.
    pub fn from_file(file: std::fs::File, start: u64, len: Option<u64>) -> Result<FileSource> {
        let length = len.unwrap_or(0);
        if start > i64::MAX as u64 || start.checked_add(length).is_none() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let metadata = file
            .metadata()
            .map_err(|e| Error::new(ErrorCode::Read, errno(&e)))?;

        let mut st = Stat::default();
        if length > 0 {
            st.size = length;
            st.valid |= stat::SIZE;
        }
        st.mtime = mtime_of(&metadata);
        st.valid |= stat::MTIME;
        if metadata.is_file() {
            if start + length > metadata.len() {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            if length == 0 {
                st.size = metadata.len() - start;
                st.valid |= stat::SIZE;
            }
        }

        // We're using UNIX file API, even on Windows; thus, we supply
        // external file attributes with Unix values.
        let mode = mode_of(&metadata);
        let attributes = FileAttributes {
            valid: file_attributes::HOST_SYSTEM | file_attributes::EXTERNAL_FILE_ATTRIBUTES,
            host_system: opsys::UNIX,
            external_file_attributes: (mode << 16) | u32::from(mode & 0o200 == 0),
            ..FileAttributes::default()
        };
        Ok(FileSource {
            file: Some(file),
            start,
            stat: st,
            attributes,
        })
    }
}

/// `st_mtime`.
fn mtime_of(metadata: &std::fs::Metadata) -> i64 {
    match metadata.modified().map(|t| t.duration_since(UNIX_EPOCH)) {
        Ok(Ok(d)) => d.as_secs() as i64,
        Ok(Err(e)) => -(e.duration().as_secs() as i64),
        Err(_) => 0,
    }
}

/// `st_mode`: as the system has it on Unix, and as the C runtime's `stat`
/// makes it up elsewhere (a regular file or a directory, writable unless
/// read-only).
fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        std::os::unix::fs::MetadataExt::mode(metadata)
    }
    #[cfg(not(unix))]
    {
        let kind = if metadata.is_dir() {
            0o040000
        } else {
            0o100000
        };
        let access = if metadata.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        kind | access
    }
}

/// `ENOENT`.
const ENOENT: i32 = 2;

impl DataSource for FileSource {
    fn stat(&self) -> Result<Stat<'static>> {
        match self.file {
            Some(_) => Ok(self.stat),
            None => Err(Error::new(ErrorCode::Read, ENOENT)),
        }
    }

    fn file_attributes(&self) -> Result<FileAttributes> {
        Ok(self.attributes)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Some(file) = &self.file else {
            return Err(Error::new(ErrorCode::Read, ENOENT));
        };
        let n = if self.stat.valid & stat::SIZE != 0 {
            (buf.len() as u64).min(self.stat.size.saturating_sub(offset)) as usize
        } else {
            buf.len()
        };
        crate::zip::source::ReadAt::read_at(file, self.start + offset, &mut buf[..n])
            .map_err(|e| Error::new(ErrorCode::Read, errno(&e)))
    }
}
