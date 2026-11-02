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

use std::io;
use std::path::Path;
use std::time::SystemTime;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

use crate::extract::error::ErrorKind;
use crate::extract::origin::Origin;

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
