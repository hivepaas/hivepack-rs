//! Extracting into something other than a folder: an archive being written, an
//! index, a checksum of each file. A [`Sink`] is given each entry as it would be
//! written, after every check a folder's extraction makes, and in the same order.

use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::time::SystemTime;

use crate::extract::destination::{Target, TargetFile};
use crate::extract::error::ErrorKind;
use crate::extract::plan::{Item, Options, Permissions};

/// An entry, as it is given to a [`Sink`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Entry<'a> {
    /// Its path, a component at a time, checked as
    /// [`check_name`](crate::extract::check_name) checks it, and not the same path
    /// as another entry's.
    pub path: &'a [String],
    /// A file's size, if it is known before its data: the data then comes to it,
    /// or the extraction stops.
    pub size: Option<u64>,
    /// Its time, if the archive has one.
    pub mtime: Option<SystemTime>,
    /// Its Unix permission bits, as [`Options::permissions`] has them: masked, by
    /// default, and none with [`Permissions::Ignore`].
    pub mode: Option<u32>,
}

/// What an extraction writes into, in place of a folder: see
/// [`extract_zip_to`](crate::extract::extract_zip_to) and the other `_to`
/// functions.
///
/// It is given directories, files, and the links [`Options::links`] keeps, each
/// once, in the order a folder's extraction writes them: symbolic links after the
/// rest, and a hard link after the file it names. A directory on the way to an
/// entry is not given unless the archive has an entry for it. A file is given as
/// [`Sink::start_file`], then its data in pieces of [`Sink::write`], then
/// [`Sink::finish_file`], or [`Sink::discard_file`] if its data failed, after which
/// the extraction stops with its error.
///
/// What is not a folder has no holes, nothing already there and no marks of
/// origin: [`Options::overwrite`] and [`Options::origin`] do nothing here. A hard
/// link is given as one, whatever [`Options::links`] says, since what was given
/// cannot be read back to copy; for the same reason, a RAR file that is a copy of
/// another fails, with [`ErrorKind::Io`] and [`io::ErrorKind::Unsupported`].
///
/// An error a method returns stops the extraction, with [`ErrorKind::Io`].
pub trait Sink {
    /// A directory.
    fn directory(&mut self, entry: &Entry<'_>) -> io::Result<()>;

    /// A file, whose data follows.
    fn start_file(&mut self, entry: &Entry<'_>) -> io::Result<()>;

    /// A piece of the file's data.
    fn write(&mut self, data: &[u8]) -> io::Result<()>;

    /// The end of the file's data, all of it given.
    fn finish_file(&mut self) -> io::Result<()>;

    /// The end of the file, whose data failed: what was given of it is not to be
    /// kept. The extraction stops after.
    fn discard_file(&mut self);

    /// A symbolic link to `target`, relative to the link's directory, with `/` for
    /// separator, which stays inside what is extracted.
    fn symlink(&mut self, entry: &Entry<'_>, target: &str) -> io::Result<()>;

    /// A hard link to the file at `target`, given before it.
    fn hard_link(&mut self, entry: &Entry<'_>, target: &[String]) -> io::Result<()>;
}

/// The permission bits a sink is told of, as `zip::set_permissions` sets them
/// on disk.
fn mode_of(mode: Option<u32>, permissions: Permissions) -> Option<u32> {
    match (mode, permissions) {
        (Some(mode), Permissions::Masked) => Some((mode & 0o755) | 0o600),
        (Some(mode), Permissions::Preserve) => Some(mode & 0o777),
        (None, _) | (_, Permissions::Ignore) => None,
    }
}

/// A [`Sink`] as an extraction's [`Target`]: the components it is given under
/// `prefix`, the path of a package's payload.
pub(crate) struct SinkTarget<'s, 'k> {
    sink: &'s RefCell<&'k mut dyn Sink>,
    /// Whether a file is started and not ended.
    open: &'s Cell<bool>,
    prefix: Vec<String>,
    options: &'s Options,
}

/// What [`SinkTarget`] holds, for the targets it makes to share.
pub(crate) struct SinkState<'k> {
    sink: RefCell<&'k mut dyn Sink>,
    open: Cell<bool>,
}

impl<'k> SinkState<'k> {
    pub(crate) fn new(sink: &'k mut dyn Sink) -> SinkState<'k> {
        SinkState {
            sink: RefCell::new(sink),
            open: Cell::new(false),
        }
    }

    pub(crate) fn target<'s>(&'s self, options: &'s Options) -> SinkTarget<'s, 'k> {
        SinkTarget {
            sink: &self.sink,
            open: &self.open,
            prefix: Vec::new(),
            options,
        }
    }
}

impl SinkTarget<'_, '_> {
    fn path(&self, components: &[String]) -> Vec<String> {
        let mut path = self.prefix.clone();
        path.extend_from_slice(components);
        path
    }

    fn with<T>(
        &self,
        item: &Item,
        components: &[String],
        size: Option<u64>,
        f: impl FnOnce(&mut dyn Sink, &Entry<'_>) -> io::Result<T>,
    ) -> Result<T, ErrorKind> {
        let path = self.path(components);
        let entry = Entry {
            path: &path,
            size,
            mtime: item.mtime,
            mode: mode_of(item.mode, self.options.permissions),
        };
        let mut sink = self.sink.borrow_mut();
        f(&mut **sink, &entry).map_err(ErrorKind::Io)
    }
}

/// A file a [`SinkTarget`] is given.
pub(crate) struct SinkFile<'t, 'k> {
    sink: &'t RefCell<&'k mut dyn Sink>,
    /// The bytes given so far.
    given: u64,
}

impl Write for SinkFile<'_, '_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.sink.borrow_mut().write(data)?;
        self.given += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TargetFile for SinkFile<'_, '_> {
    fn has_holes(&self) -> bool {
        false
    }

    fn skip(&mut self, n: u64) -> io::Result<()> {
        let zeros = [0u8; 4096];
        let mut left = n;
        while left > 0 {
            let piece = left.min(zeros.len() as u64) as usize;
            self.write_all(&zeros[..piece])?;
            left -= piece as u64;
        }
        Ok(())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        // What was given cannot be taken back: a file only grows here.
        match len.checked_sub(self.given) {
            Some(zeros) => self.skip(zeros),
            None => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }
}

impl<'s, 'k: 's> Target for SinkTarget<'s, 'k> {
    type File<'t>
        = SinkFile<'t, 'k>
    where
        Self: 't;

    fn directory(&self, item: &Item, components: &[String]) -> Result<(), ErrorKind> {
        self.with(item, components, None, |sink, entry| sink.directory(entry))
    }

    fn within(&self, item: &Item, components: &[String]) -> Result<Self, ErrorKind> {
        self.directory(item, components)?;
        Ok(SinkTarget {
            sink: self.sink,
            open: self.open,
            prefix: self.path(components),
            options: self.options,
        })
    }

    fn create_file(
        &self,
        item: &Item,
        components: &[String],
        size: Option<u64>,
        _: &Options,
    ) -> Result<SinkFile<'_, 'k>, ErrorKind> {
        self.with(item, components, size, |sink, entry| sink.start_file(entry))?;
        self.open.set(true);
        Ok(SinkFile {
            sink: self.sink,
            given: 0,
        })
    }

    fn finish_file(&self, _: SinkFile<'_, 'k>, _: &Item, _: &Options) -> Result<(), ErrorKind> {
        self.open.set(false);
        self.sink.borrow_mut().finish_file().map_err(ErrorKind::Io)
    }

    fn remove_file(&self, _: &[String]) {
        if self.open.replace(false) {
            self.sink.borrow_mut().discard_file();
        }
    }

    fn symlink(
        &self,
        item: &Item,
        components: &[String],
        target: &str,
        _: bool,
    ) -> Result<(), ErrorKind> {
        self.with(item, components, None, |sink, entry| {
            sink.symlink(entry, target)
        })
    }

    fn hard_link(
        &self,
        item: &Item,
        components: &[String],
        target: &[String],
    ) -> Result<(), ErrorKind> {
        let target = self.path(target);
        self.with(item, components, None, |sink, entry| {
            sink.hard_link(entry, &target)
        })
    }

    fn open_file(&self, _: &[String]) -> Result<(Box<dyn Read + '_>, u64), ErrorKind> {
        Err(ErrorKind::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "what a sink was given cannot be read back",
        )))
    }

    fn set_time(&self, _: &[String], _: SystemTime) -> Result<(), ErrorKind> {
        // A directory's time came with it.
        Ok(())
    }

    fn copies_hard_links(&self, _: &Options) -> bool {
        false
    }
}
