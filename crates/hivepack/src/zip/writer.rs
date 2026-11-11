//! Writing an archive an entry at a time, each written as it is added: not in
//! libzip, which writes every entry at `zip_close`, so that each is added from a
//! source it can read when it gets there. Here an entry's data is read once, as it
//! is added, from a reader that is given only then: one entry of another archive
//! being read, a pipe, a file. Nothing more of it is held than a piece.
//!
//! Each entry is written as [`Archive::close_to`] writes one of new data, through
//! the same layers (compression, CRC, encryption), its local header written again
//! once its sizes are known; the central directory is written by
//! [`Writer::finish`]. Until then what is written is no archive.

use std::io::{Read, Seek, Write};

use crate::deflate::Library;
use crate::zip::close_threads::Taken;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::random::RandomSource;
use crate::zip::source_data::{BufferSource, FileAttributes, file_attributes};
use crate::zip::source_write::Output;
use crate::zip::zip::{Flags, OpenFlags, Stat, cm, opsys, stat};

/// The type bits of a Unix mode, and those of each type an entry is.
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// An entry to add to a [`Writer`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct NewEntry {
    /// Its name, with `/` between directories: a directory's gets a `/` at its end
    /// if it has none.
    pub name: String,
    /// When it was last changed, in seconds since 1970; the time it is added if
    /// none.
    pub mtime: Option<i64>,
    /// Its Unix permission bits, kept with the type of entry in the external
    /// attributes, as Info-ZIP keeps them; none, the DOS attributes alone.
    pub mode: Option<u32>,
    /// A file's size, if it is known beforehand: an entry that may come to 4 GiB
    /// has the Zip64 extra field, and one whose size is not known has it whatever it
    /// comes to.
    pub size: Option<u64>,
}

impl NewEntry {
    /// An entry of this name, and nothing else.
    pub fn new(name: impl Into<String>) -> Self {
        NewEntry {
            name: name.into(),
            ..NewEntry::default()
        }
    }
}

/// Writes a ZIP archive to `W`, an entry at a time, each as it is added.
///
/// ```
/// use std::io::Cursor;
/// use hivepack::zip::{Archive, NewEntry, OpenFlags, Writer};
///
/// # fn main() -> hivepack::zip::Result<()> {
/// let mut writer = Writer::new(Cursor::new(Vec::new()));
/// writer.add_directory(&NewEntry::new("docs"))?;
/// writer.add_file(&NewEntry::new("docs/a.txt"), &mut &b"some text"[..])?;
/// let zip = writer.finish()?.into_inner();
///
/// let archive = Archive::open(&zip[..], OpenFlags::CHECKCONS)?;
/// assert_eq!(archive.get_num_entries(Default::default()), 2);
/// # Ok(())
/// # }
/// ```
pub struct Writer<W: Write + Seek> {
    /// The entries, as an archive keeps them: their names, which no two may share,
    /// and what the central directory says of them once written.
    archive: Archive<&'static [u8]>,
    out: Output<W>,
    /// The entries written, in order.
    written: Vec<usize>,
    method: (i32, u32),
    encryption: Option<(u16, Vec<u8>)>,
}

impl<W: Write + Seek> Writer<W> {
    /// A writer to `out`, from where it is: offsets in the archive count from
    /// there. Its files are compressed with Deflate, or stored if that is smaller,
    /// as libzip's default.
    pub fn new(out: W) -> Writer<W> {
        Writer {
            archive: Archive::open(&[][..], OpenFlags(0))
                .unwrap_or_else(|_| unreachable!("an empty archive opens")),
            out: Output::new(out),
            written: Vec::new(),
            method: (cm::DEFAULT, 0),
            encryption: None,
        }
    }

    /// Compresses the files added from now on with `method` (see [`cm`]), at
    /// `level` (0 for the method's default), as
    /// [`Archive::set_file_compression`] takes them.
    pub fn set_compression(&mut self, method: i32, level: u32) {
        self.method = (method, level);
    }

    /// Deflates the files added from now on with `library`'s compressor,
    /// as [`Archive::set_deflate_library`] says: [`Library::Zlib`] by
    /// default. With [`Library::Libdeflate`], at levels 1 to 12, on the
    /// caller's thread, in blocks of 1, 2 or 4 MiB as the size
    /// [`NewEntry`] tells says, 1 MiB if it tells none.
    pub fn set_deflate_library(&mut self, library: Library) {
        self.archive.set_deflate_library(library);
    }

    /// Encrypts the files added from now on with `method` (see
    /// [`em`](crate::zip::em)) and `password`, or not, with
    /// [`em::NONE`](crate::zip::em::NONE). Where the system is not Unix, a file
    /// encrypted fails with [`ErrorCode::Internal`] unless
    /// [`set_random_source`](Writer::set_random_source) has given where its salt
    /// comes from.
    pub fn set_encryption(&mut self, method: u16, password: &[u8]) {
        self.encryption = (method != crate::zip::em::NONE).then(|| (method, password.to_vec()));
    }

    /// Where the random bytes encrypting takes come from: `source`, or with
    /// `None` the system, as [`Archive::set_random_source`] says.
    pub fn set_random_source(&mut self, source: Option<RandomSource>) {
        self.archive.set_random_source(source);
    }

    /// Adds the file `entry`, its data read from `reader` to its end: the bytes
    /// read. A name another entry has is refused ([`ErrorCode::Exists`]). On an
    /// error, what was written of the entry stays, and the archive is not to be
    /// finished.
    pub fn add_file(&mut self, entry: &NewEntry, reader: &mut dyn Read) -> Result<u64> {
        let i = self.add(entry, S_IFREG, BufferSource::new(Vec::new()))?;
        let (method, level) = self.method;
        self.archive.set_file_compression(i as u64, method, level)?;
        if let Some((method, password)) = &self.encryption {
            self.archive
                .file_set_encryption(i as u64, *method, Some(password))?;
        }
        let mut st = Stat {
            valid: stat::COMP_METHOD,
            comp_method: cm::STORE,
            ..Stat::default()
        };
        if let Some(size) = entry.size {
            st.valid |= stat::SIZE;
            st.size = size;
        }
        let attributes = match entry.mode {
            Some(_) => attributes_of(entry, S_IFREG),
            None => FileAttributes::default(),
        };
        self.archive
            .write_reader(i, reader, st, attributes, &mut self.out)?;
        self.written.push(i);
        let size = self
            .archive
            .entry
            .get(i)
            .and_then(|e| e.changes.as_deref())
            .map_or(0, |de| de.uncomp_size);
        Ok(size)
    }

    /// Adds the directory `entry`.
    pub fn add_directory(&mut self, entry: &NewEntry) -> Result<()> {
        let i = self.add(entry, S_IFDIR, BufferSource::new(Vec::new()))?;
        self.write(i)
    }

    /// Adds the symbolic link `entry` to `target`, its data, as Info-ZIP writes a
    /// link: stored, with the type in its mode.
    pub fn add_symlink(&mut self, entry: &NewEntry, target: &str) -> Result<()> {
        let data = target.as_bytes().to_vec();
        let i = self.add(entry, S_IFLNK, BufferSource::new(data))?;
        self.archive
            .set_file_compression(i as u64, i32::from(cm::STORE), 0)?;
        self.write(i)
    }

    /// Writes the central directory: the archive ends, and its output is given
    /// back.
    pub fn finish(mut self) -> Result<W> {
        self.archive.write_cdir_of(&self.written, &mut self.out)?;
        Ok(self.out.into_inner())
    }

    /// The entry `entry` added to the list, of the type `kind` and the data of
    /// `source` if it is not a file: its index.
    fn add(&mut self, entry: &NewEntry, kind: u32, source: BufferSource) -> Result<usize> {
        let name = entry.name.as_bytes();
        if name.is_empty() || name.contains(&0) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let i = if kind == S_IFDIR {
            self.archive.dir_add(name, Flags::ENC_UTF_8)?
        } else {
            self.archive.file_add(name, source, Flags::ENC_UTF_8)?
        };
        if let Some(mtime) = entry.mtime {
            self.archive.file_set_mtime(i, mtime, Flags::NONE)?;
        }
        if entry.mode.is_some() || kind == S_IFLNK {
            let attributes = attributes_of(entry, kind);
            self.archive.file_set_external_attributes(
                i,
                Flags::NONE,
                attributes.host_system,
                attributes.external_file_attributes,
            )?;
        }
        usize::try_from(i).map_err(|_| Error::new(ErrorCode::Internal, 0))
    }

    /// Writes the entry `i`, whose data its source holds.
    fn write(&mut self, i: usize) -> Result<()> {
        self.archive.write_entry(
            i,
            &mut self.out,
            &mut None,
            &mut Vec::new(),
            Taken::default(),
        )?;
        self.written.push(i);
        Ok(())
    }
}

/// The external attributes of `entry`, of the type `kind`: its mode, as Info-ZIP
/// keeps it, with the DOS bit of a directory; or nothing but a directory's DOS
/// bit if it has no mode.
fn attributes_of(entry: &NewEntry, kind: u32) -> FileAttributes {
    let dos = if kind == S_IFDIR { 0x10 } else { 0 };
    let mode = match (entry.mode, kind) {
        (Some(mode), _) => Some(mode & !S_IFMT),
        (None, S_IFLNK) => Some(0o777),
        (None, _) => None,
    };
    match mode {
        Some(mode) => FileAttributes {
            valid: file_attributes::HOST_SYSTEM | file_attributes::EXTERNAL_FILE_ATTRIBUTES,
            host_system: opsys::UNIX,
            external_file_attributes: ((kind | mode) << 16) | dos,
            ..FileAttributes::default()
        },
        None => FileAttributes {
            valid: file_attributes::HOST_SYSTEM | file_attributes::EXTERNAL_FILE_ATTRIBUTES,
            host_system: opsys::DOS,
            external_file_attributes: dos,
            ..FileAttributes::default()
        },
    }
}
