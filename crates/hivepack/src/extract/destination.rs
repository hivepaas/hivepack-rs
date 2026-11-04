//! Writing under the destination by handle: each directory is opened from
//! its parent's handle without following a symbolic link, and each file is
//! created new, so nothing is written outside the destination, through a
//! link that is there or that appears while extracting, or over what is
//! there.
//!
//! cap-std does the opening, with `openat2` and `RESOLVE_BENEATH` on
//! Linux, `openat` and `O_NOFOLLOW` a component at a time elsewhere on
//! Unix, and handles relative to a directory's on Windows. It is the one
//! dependency here with `unsafe` code (see the repository's
//! `docs/safety.md`): the standard library's directory handles
//! (`std::fs::Dir`) are not stable yet.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::origin::Origin;
use crate::extract::plan::{Item, Links, Options};
use crate::extract::zip::{set_modified, set_permissions};

/// The destination, open, and the mark of origin of what is written in it.
pub(crate) struct Destination<'a> {
    root: Dir,
    origin: Option<&'a Origin>,
}

impl<'a> Destination<'a> {
    /// Opens `path`, creating it first if it is not there. The path itself
    /// is the caller's, and is followed as given.
    pub(crate) fn open(path: &Path, origin: Option<&'a Origin>) -> io::Result<Destination<'a>> {
        std::fs::create_dir_all(path)?;
        let root = Dir::open_ambient_dir(path, ambient_authority())?;
        Ok(Destination { root, origin })
    }

    /// The directory at `components`, as a destination of its own, opened
    /// as [`Destination::directory`] opens it: a package's payload is
    /// extracted into one.
    pub(crate) fn within(&self, components: &[String]) -> Result<Destination<'a>, ErrorKind> {
        Ok(Destination {
            root: self.directory(components)?,
            origin: self.origin,
        })
    }

    /// The directory at `components`, created where it is not there, each
    /// opened from the one before without following a link; those created
    /// get the mark of origin.
    pub(crate) fn directory(&self, components: &[String]) -> Result<Dir, ErrorKind> {
        let mut dir = self.root.try_clone().map_err(ErrorKind::Io)?;
        for component in components {
            let created = match dir.create_dir(component) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(ErrorKind::Io(e)),
            };
            dir = match dir.open_dir_nofollow(component) {
                Ok(next) => next,
                Err(e) => {
                    // A link, or a file, where a directory was to be.
                    return Err(match dir.symlink_metadata(component) {
                        Ok(metadata) if !metadata.is_dir() => ErrorKind::NotADirectory,
                        _ => ErrorKind::Io(e),
                    });
                }
            };
            if let (true, Some(origin)) = (created, self.origin) {
                origin.write_dir(&dir).map_err(ErrorKind::Origin)?;
            }
        }
        Ok(dir)
    }

    /// Creates the file `name` in `dir`, which must not be there, not even
    /// as a link; with `overwrite`, replaces one that is there if it is a
    /// file, opened without following a link and emptied.
    pub(crate) fn create_file(dir: &Dir, name: &str, overwrite: bool) -> Result<File, ErrorKind> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        match dir.open_with(name, &options) {
            Ok(file) => Ok(file),
            // What is there decides, not the error: Windows says a
            // directory is there as access denied.
            Err(e) => match dir.symlink_metadata(name) {
                Ok(metadata) if overwrite && metadata.is_file() => {
                    let mut options = OpenOptions::new();
                    options.write(true).truncate(true);
                    options.follow(FollowSymlinks::No);
                    dir.open_with(name, &options).map_err(ErrorKind::Io)
                }
                Ok(_) => Err(ErrorKind::Exists),
                Err(_) => Err(ErrorKind::Io(e)),
            },
        }
    }

    /// Creates a symbolic link `name` in `dir` to `target`, relative, with
    /// `/` for separator; `to_dir` says whether it leads to a directory,
    /// which Windows needs to know.
    pub(crate) fn symlink(
        dir: &Dir,
        name: &str,
        target: &str,
        to_dir: bool,
    ) -> Result<(), ErrorKind> {
        #[cfg(windows)]
        let created = {
            let target = target.replace('/', "\\");
            if to_dir {
                dir.symlink_dir(target, name)
            } else {
                dir.symlink_file(target, name)
            }
        };
        #[cfg(not(windows))]
        let created = {
            let _ = to_dir;
            dir.symlink(target, name)
        };
        created.map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => ErrorKind::Exists,
            _ => ErrorKind::Io(e),
        })
    }

    /// Creates `name` in `dir`, a hard link to the file `src` in `src_dir`,
    /// which is not followed if it is a symbolic link.
    pub(crate) fn hard_link(
        src_dir: &Dir,
        src: &str,
        dir: &Dir,
        name: &str,
    ) -> Result<(), ErrorKind> {
        src_dir
            .hard_link(src, dir, name)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => ErrorKind::Exists,
                _ => ErrorKind::Io(e),
            })
    }

    /// Opens the file `name` in `dir` to read it, without following a link.
    pub(crate) fn open_file(dir: &Dir, name: &str) -> Result<File, ErrorKind> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.follow(FollowSymlinks::No);
        dir.open_with(name, &options).map_err(ErrorKind::Io)
    }

    /// Sets the time of `name` in `dir`, without following a link.
    pub(crate) fn set_time(dir: &Dir, name: &str, mtime: SystemTime) -> Result<(), ErrorKind> {
        let mtime = SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(mtime));
        // A time the system cannot hold is left, as for files
        // (`zip::set_modified`).
        match dir.set_symlink_times(name, None, Some(mtime)) {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            result => result.map_err(ErrorKind::Io),
        }
    }
}

/// Where an extraction writes: a folder on disk ([`Destination`]), or a caller's
/// [`Sink`](crate::extract::Sink). Each entry is given with its path's components,
/// checked; what a folder needs of directories on the way it opens itself.
pub(crate) trait Target: Sized {
    /// A file being written.
    type File<'t>: TargetFile
    where
        Self: 't;

    /// The directory `item`, at `components`.
    fn directory(&self, item: &Item, components: &[String]) -> Result<(), ErrorKind>;

    /// The directory `item`, at `components`, as a target of its own: a package's
    /// payload is extracted into one.
    fn within(&self, item: &Item, components: &[String]) -> Result<Self, ErrorKind>;

    /// The file `item`, at `components`, of `size` bytes if they are known, to write
    /// its data into.
    fn create_file(
        &self,
        item: &Item,
        components: &[String],
        size: Option<u64>,
        options: &Options,
    ) -> Result<Self::File<'_>, ErrorKind>;

    /// The file, its data written: its mark of origin, time and permissions.
    fn finish_file(
        &self,
        file: Self::File<'_>,
        item: &Item,
        options: &Options,
    ) -> Result<(), ErrorKind>;

    /// The file at `components`, whose data failed, not left.
    fn remove_file(&self, components: &[String]);

    /// The symbolic link `item`, at `components`, to `target`, relative, with `/`
    /// for separator; `to_dir` says whether it leads to a directory.
    fn symlink(
        &self,
        item: &Item,
        components: &[String],
        target: &str,
        to_dir: bool,
    ) -> Result<(), ErrorKind>;

    /// The hard link `item`, at `components`, to the file at `target`, written
    /// before it.
    fn hard_link(
        &self,
        item: &Item,
        components: &[String],
        target: &[String],
    ) -> Result<(), ErrorKind>;

    /// The file at `components`, written before, to read again, and its length: for
    /// a copy of it.
    fn open_file(&self, components: &[String]) -> Result<(Box<dyn Read + '_>, u64), ErrorKind>;

    /// The time of the directory at `components`, once nothing more is written in
    /// it.
    fn set_time(&self, components: &[String], mtime: SystemTime) -> Result<(), ErrorKind>;

    /// Whether a hard link is written as a copy of its file, as
    /// [`Links::AsFile`] says for a folder.
    fn copies_hard_links(&self, options: &Options) -> bool;

    /// The file being written is damaged, as `error` says, and is to be gone on
    /// from: kept as it is, or removed, next.
    fn damaged(&self, _error: &Error) {}
}

/// A file a [`Target`] writes, and how long it is so far.
pub(crate) struct Counted<F> {
    pub(crate) file: F,
    pub(crate) len: u64,
}

impl<F: Write> Write for Counted<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.file.write(buf)?;
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl<F: TargetFile> TargetFile for Counted<F> {
    fn has_holes(&self) -> bool {
        self.file.has_holes()
    }

    fn skip(&mut self, n: u64) -> io::Result<()> {
        self.file.skip(n)?;
        self.len += n;
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.len = len;
        Ok(())
    }
}

/// A file a [`Target`] writes.
pub(crate) trait TargetFile: Write {
    /// Whether zeros can be gone past, leaving a hole, rather than written.
    fn has_holes(&self) -> bool;

    /// Goes `n` bytes past where it is, which read as zeros.
    fn skip(&mut self, n: u64) -> io::Result<()>;

    /// Ends it at `len` bytes, the zeros gone past to its end among them.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

/// The parent's components and the last, or the error of an empty name.
fn split(components: &[String]) -> Result<(&String, &[String]), ErrorKind> {
    components
        .split_last()
        .ok_or(ErrorKind::Name(NameError::Empty))
}

impl Target for Destination<'_> {
    type File<'t>
        = std::fs::File
    where
        Self: 't;

    fn directory(&self, _: &Item, components: &[String]) -> Result<(), ErrorKind> {
        Destination::directory(self, components).map(drop)
    }

    fn within(&self, _: &Item, components: &[String]) -> Result<Self, ErrorKind> {
        Destination::within(self, components)
    }

    fn create_file(
        &self,
        _: &Item,
        components: &[String],
        _: Option<u64>,
        options: &Options,
    ) -> Result<std::fs::File, ErrorKind> {
        let (last, parents) = split(components)?;
        let dir = Destination::directory(self, parents)?;
        Ok(Destination::create_file(&dir, last, options.overwrite)?.into_std())
    }

    fn finish_file(
        &self,
        file: std::fs::File,
        item: &Item,
        options: &Options,
    ) -> Result<(), ErrorKind> {
        // The mark first: writing a stream can change the file's time.
        if let Some(origin) = self.origin {
            origin.write_file(&file).map_err(ErrorKind::Origin)?;
        }
        if let Some(mtime) = item.mtime {
            set_modified(&file, mtime)?;
        }
        set_permissions(&file, item.mode, options.permissions)?;
        let mut file = file;
        file.flush().map_err(ErrorKind::Io)
    }

    fn remove_file(&self, components: &[String]) {
        if let Ok((last, parents)) = split(components)
            && let Ok(dir) = Destination::directory(self, parents)
        {
            let _ = dir.remove_file(last);
        }
    }

    fn symlink(
        &self,
        _: &Item,
        components: &[String],
        target: &str,
        to_dir: bool,
    ) -> Result<(), ErrorKind> {
        let (last, parents) = split(components)?;
        let dir = Destination::directory(self, parents)?;
        Destination::symlink(&dir, last, target, to_dir)
    }

    fn hard_link(
        &self,
        _: &Item,
        components: &[String],
        target: &[String],
    ) -> Result<(), ErrorKind> {
        let (last, parents) = split(components)?;
        let dir = Destination::directory(self, parents)?;
        let (target_last, target_parents) = target.split_last().ok_or(ErrorKind::HardLinkTarget)?;
        let target_dir = Destination::directory(self, target_parents)?;
        Destination::hard_link(&target_dir, target_last, &dir, last)
    }

    fn open_file(&self, components: &[String]) -> Result<(Box<dyn Read + '_>, u64), ErrorKind> {
        let (last, parents) = components.split_last().ok_or(ErrorKind::HardLinkTarget)?;
        let dir = Destination::directory(self, parents)?;
        let source = Destination::open_file(&dir, last)?;
        let size = source.metadata().map_err(ErrorKind::Io)?.len();
        Ok((Box::new(source.into_std()), size))
    }

    fn set_time(&self, components: &[String], mtime: SystemTime) -> Result<(), ErrorKind> {
        let (last, parents) = split(components)?;
        let dir = Destination::directory(self, parents)?;
        Destination::set_time(&dir, last, mtime)
    }

    fn copies_hard_links(&self, options: &Options) -> bool {
        options.links == Links::AsFile
    }
}

impl TargetFile for std::fs::File {
    fn has_holes(&self) -> bool {
        true
    }

    fn skip(&mut self, n: u64) -> io::Result<()> {
        let ahead = i64::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.seek(SeekFrom::Current(ahead)).map(drop)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        std::fs::File::set_len(self, len)
    }
}
