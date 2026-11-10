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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

use crate::extract::error::{Error, ErrorKind};
use crate::extract::name::NameError;
use crate::extract::origin::Origin;
use crate::extract::plan::{Item, Links, OnWrittenFn, Options, Owners, Written, WrittenKind};
use crate::extract::zip::{set_modified, set_permissions};

/// The destination, open, and the mark of origin of what is written in it.
pub(crate) struct Destination<'a> {
    root: Dir,
    origin: Option<&'a Origin>,
    /// Told of each entry written ([`Options::on_written`]); none in a
    /// private folder, whose files are told as they move into place.
    written: Option<&'a OnWrittenFn>,
    /// Where this is under the destination the caller gave, a component at a
    /// time: a package's payload's folder ([`Destination::within`]).
    prefix: Vec<String>,
    /// Shared with the destinations within, and the threads writing.
    owning: Arc<Owning>,
    /// Each thread's [`Walk`], for the files it makes: the directories on the
    /// way to its last file's, closed with the destination.
    walks: Walks,
}

/// The [`Walk`] of each thread that makes files in a destination, by thread:
/// taken out while it is used, so that the lock is held only to take it and
/// put it back.
#[derive(Default)]
struct Walks(std::sync::Mutex<std::collections::HashMap<std::thread::ThreadId, Walk>>);

impl Walks {
    fn take(&self) -> Walk {
        let id = std::thread::current().id();
        self.lock().remove(&id).unwrap_or_default()
    }

    fn put(&self, walk: Walk) {
        self.lock().insert(std::thread::current().id(), walk);
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<std::thread::ThreadId, Walk>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What the private folders of archives read once are named, before a number
/// of their own: hidden on Unix, and told apart from what an archive holds.
pub(crate) const STAGING: &str = ".hivepack-extracting-";

/// The file in a private folder that its extraction keeps locked.
const OWNER: &str = "owner";

/// A private folder an archive read once is written into
/// ([`Destination::staging`]): the destination its files are written into,
/// within it, and the lock that tells it is used.
pub(crate) struct Staging<'a> {
    pub(crate) data: Destination<'a>,
    name: String,
    _owner: std::fs::File,
}

/// What giving files their owners keeps as it goes: the names this system was
/// asked for, and how many owners were left.
#[derive(Default)]
struct Owning {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    users: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Option<u32>>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    groups: std::sync::Mutex<std::collections::HashMap<Vec<u8>, Option<u32>>>,
    left: AtomicU64,
}

impl<'a> Destination<'a> {
    /// Opens `path`, creating it first if it is not there. The path itself
    /// is the caller's, and is followed as given.
    pub(crate) fn open(
        path: &Path,
        origin: Option<&'a Origin>,
        written: Option<&'a OnWrittenFn>,
    ) -> io::Result<Destination<'a>> {
        std::fs::create_dir_all(path)?;
        let root = Dir::open_ambient_dir(path, ambient_authority())?;
        Ok(Destination {
            root,
            origin,
            written,
            prefix: Vec::new(),
            owning: Arc::default(),
            walks: Walks::default(),
        })
    }

    /// Tells [`Options::on_written`] of the entry at `components`, written.
    fn told(&self, components: &[String], kind: WrittenKind) {
        let Some(tell) = self.written else {
            return;
        };
        if self.prefix.is_empty() {
            tell(&Written {
                path: components,
                kind,
            });
        } else {
            let path: Vec<String> = self.prefix.iter().chain(components).cloned().collect();
            tell(&Written { path: &path, kind });
        }
    }

    /// A private folder in this destination, for an archive read once: its
    /// entries are written there as they come, then moved into place once
    /// every check has passed. Named [`STAGING`] and a number of its own, made
    /// by this process (mode 0700 on Unix), with a file `owner` in it that is
    /// locked for as long as the folder is used, which the system lets go of
    /// however the process ends: a folder whose `owner` can be locked is no
    /// one's ([`Destination::remove_stale`]).
    pub(crate) fn staging(&self, path: &Path) -> Result<Staging<'a>, ErrorKind> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        for n in 0u32..1000 {
            let name = format!("{STAGING}{:x}-{nanos:x}-{n}", std::process::id());
            #[cfg_attr(not(unix), allow(unused_mut))]
            let mut builder = cap_std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use cap_std::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match self.root.create_dir_with(&name, &builder) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(ErrorKind::Io(e)),
            }
            // Hidden on Windows, where its dot does not hide it: if that
            // fails, it is seen while it lasts, and nothing else changes.
            crate::hidden::hide(&path.join(&name));
            let made = (|| {
                let dir = self.root.open_dir_nofollow(&name).map_err(ErrorKind::Io)?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                options.follow(FollowSymlinks::No);
                let owner = dir
                    .open_with(OWNER, &options)
                    .map_err(ErrorKind::Io)?
                    .into_std();
                owner
                    .try_lock()
                    .map_err(|_| ErrorKind::Io(io::Error::from(io::ErrorKind::WouldBlock)))?;
                Ok(Staging {
                    data: Destination {
                        root: dir,
                        origin: self.origin,
                        written: None,
                        prefix: Vec::new(),
                        owning: Arc::clone(&self.owning),
                        walks: Walks::default(),
                    },
                    name: name.clone(),
                    _owner: owner,
                })
            })();
            if made.is_err() {
                let _ = self.root.remove_dir_all(&name);
            }
            return made;
        }
        Err(ErrorKind::Io(io::Error::from(io::ErrorKind::AlreadyExists)))
    }

    /// Removes the private folder `staging`, with all that is in it, by handle,
    /// following no link.
    pub(crate) fn remove_staging(&self, staging: Staging<'_>) {
        let Staging { data, name, _owner } = staging;
        drop(data);
        // Closed first: Windows removes no file that is open. Another process
        // may take it for left behind meanwhile, and remove it too.
        drop(_owner);
        let _ = self.root.remove_dir_all(&name);
    }

    /// Removes the private folders of extractions that are no more: those
    /// whose `owner` can be locked, a process that wrote into them having
    /// ended without removing them. One being used is left: its `owner` is
    /// locked.
    pub(crate) fn remove_stale(&self) {
        let Ok(entries) = self.root.entries() else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|n| n.starts_with(STAGING)) else {
                continue;
            };
            let free = {
                let Ok(dir) = self.root.open_dir_nofollow(name) else {
                    continue;
                };
                let mut options = OpenOptions::new();
                options.write(true);
                options.follow(FollowSymlinks::No);
                match dir.open_with(OWNER, &options) {
                    Ok(owner) => owner.into_std().try_lock().is_ok(),
                    // Made, and left before its `owner` was.
                    Err(e) => e.kind() == io::ErrorKind::NotFound,
                }
                // The folder's handle and its owner's closed here, before it
                // is removed: Windows removes nothing that is open.
            };
            if free {
                let _ = self.root.remove_dir_all(name);
            }
        }
    }

    /// Whether what is at `components` here is in the way of an entry put
    /// there: a directory (`dir`) merges into one, and a file replaces a file
    /// with `overwrite`; anything else in the way is refused, as writing it
    /// would refuse it ([`ErrorKind::NotADirectory`] on the way or for a
    /// directory, [`ErrorKind::Exists`] for the rest).
    /// The parents are opened through `walk`, which keeps them for the next
    /// entry's.
    pub(crate) fn in_the_way(
        &self,
        components: &[String],
        dir: bool,
        overwrite: bool,
        walk: &mut Walk,
    ) -> Result<(), ErrorKind> {
        let Some((last, parents)) = components.split_last() else {
            return Ok(());
        };
        let on_way = walk.keep(parents);
        for component in &parents[on_way..] {
            let from = walk.deepest(&self.root);
            match from.open_dir_nofollow(component) {
                Ok(next) => walk.dirs.push((component.clone(), next)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(not_a_directory(from, component, e)),
            }
        }
        match walk.deepest(&self.root).symlink_metadata(last) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ErrorKind::Io(e)),
            Ok(there) if dir && there.is_dir() => Ok(()),
            Ok(_) if dir => Err(ErrorKind::NotADirectory),
            Ok(there) if overwrite && there.is_file() => Ok(()),
            Ok(_) => Err(ErrorKind::Exists),
        }
    }

    /// Moves the file `name` of `from` (a private folder's) to `components`
    /// here: by a hard link, which never replaces what is there, then
    /// removing it from `from`. With `overwrite`, a file there is replaced by
    /// a rename. Where the file system has no hard links (FAT32, exFAT), the
    /// file is renamed after one more look.
    ///
    /// The parents are opened, and made, through `walk`, which keeps them for
    /// the next entry's.
    pub(crate) fn place(
        &self,
        from: &Dir,
        name: &str,
        components: &[String],
        overwrite: bool,
        walk: &mut Walk,
    ) -> Result<(), ErrorKind> {
        let (last, parents) = split(components)?;
        let dir = self.walk_to(parents, walk)?;
        let rename = || from.rename(name, dir, last).map_err(ErrorKind::Io);
        let there = |e: io::Error| match dir.symlink_metadata(last) {
            Ok(metadata) if overwrite && metadata.is_file() => rename(),
            Ok(_) => Err(ErrorKind::Exists),
            Err(found) if found.kind() == io::ErrorKind::NotFound => Err(ErrorKind::Io(e)),
            Err(found) => Err(ErrorKind::Io(found)),
        };
        match from.hard_link(name, dir, last) {
            Ok(()) => {
                let _ = from.remove_file(name);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => there(e),
            // No hard links here, or none across: a rename, if nothing is there.
            Err(e) => match dir.symlink_metadata(last) {
                Err(found) if found.kind() == io::ErrorKind::NotFound => rename(),
                _ => there(e),
            },
        }
        .inspect(|()| self.told(components, WrittenKind::File))
    }

    /// The directory of the private folder's files, `components` within it.
    pub(crate) fn open_dir(&self, components: &[String]) -> Result<Dir, ErrorKind> {
        self.directory(components)
    }

    /// The directory at `components`, as a destination of its own, opened
    /// as [`Destination::directory`] opens it: a package's payload is
    /// extracted into one.
    pub(crate) fn within(&self, components: &[String]) -> Result<Destination<'a>, ErrorKind> {
        Ok(Destination {
            root: self.directory(components)?,
            origin: self.origin,
            written: self.written,
            prefix: self.prefix.iter().chain(components).cloned().collect(),
            owning: Arc::clone(&self.owning),
            walks: Walks::default(),
        })
    }

    /// The directory at `components`, created where it is not there, each
    /// opened from the one before without following a link; those created
    /// get the mark of origin.
    pub(crate) fn directory(&self, components: &[String]) -> Result<Dir, ErrorKind> {
        let mut dir = self.root.try_clone().map_err(ErrorKind::Io)?;
        for component in components {
            // Opened first: most are there, and opening one takes no lock on
            // its parent, as creating one does, which threads writing files
            // at once would all wait for.
            let (next, created) = match dir.open_dir_nofollow(component) {
                Ok(next) => (next, false),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let created = match dir.create_dir(component) {
                        Ok(()) => true,
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                        Err(e) => return Err(ErrorKind::Io(e)),
                    };
                    match dir.open_dir_nofollow(component) {
                        Ok(next) => (next, created),
                        Err(e) => return Err(not_a_directory(&dir, component, e)),
                    }
                }
                Err(e) => return Err(not_a_directory(&dir, component, e)),
            };
            dir = next;
            if let (true, Some(origin)) = (created, self.origin) {
                origin.write_dir(&dir).map_err(ErrorKind::Origin)?;
            }
        }
        Ok(dir)
    }

    /// [`Destination::directory`] through `walk`: the directories on the way
    /// to the last ones it was given kept, those after opened, or made, from
    /// the deepest of them.
    pub(crate) fn walk_to<'w>(
        &'w self,
        components: &[String],
        walk: &'w mut Walk,
    ) -> Result<&'w Dir, ErrorKind> {
        let on_way = walk.keep(components);
        for component in &components[on_way..] {
            let dir = walk.deepest(&self.root);
            let (next, created) = match dir.open_dir_nofollow(component) {
                Ok(next) => (next, false),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let created = match dir.create_dir(component) {
                        Ok(()) => true,
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                        Err(e) => return Err(ErrorKind::Io(e)),
                    };
                    match dir.open_dir_nofollow(component) {
                        Ok(next) => (next, created),
                        Err(e) => return Err(not_a_directory(dir, component, e)),
                    }
                }
                Err(e) => return Err(not_a_directory(dir, component, e)),
            };
            if let (true, Some(origin)) = (created, self.origin) {
                origin.write_dir(&next).map_err(ErrorKind::Origin)?;
            }
            walk.dirs.push((component.clone(), next));
        }
        Ok(walk.deepest(&self.root))
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
        // The target as it is, which the checks before took (Links::Inside
        // keeps it inside, Links::Any anywhere): cap-std's `symlink` would
        // refuse an absolute one. `name` is one name in `dir`, by its handle.
        #[cfg(not(windows))]
        let created = {
            let _ = to_dir;
            dir.symlink_contents(target, name)
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
        // cap-std's times on Unix are from 1970 on, and it panics on one
        // before: a directory of then is opened to read, without following a
        // link, and given its time as a file is, which the standard library
        // takes back to `time_t`'s start.
        #[cfg(unix)]
        if mtime < SystemTime::UNIX_EPOCH {
            use cap_fs_ext::OpenOptionsMaybeDirExt;
            let mut options = OpenOptions::new();
            options.read(true).maybe_dir(true);
            options.follow(FollowSymlinks::No);
            let opened = dir.open_with(name, &options).map_err(ErrorKind::Io)?;
            return set_modified(&opened.into_std(), mtime);
        }
        let mtime = SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(mtime));
        // A time the system cannot hold is left, as for files
        // (`zip::set_modified`).
        match dir.set_symlink_times(name, None, Some(mtime)) {
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            result => result.map_err(ErrorKind::Io),
        }
    }
}

/// Whether `options` asks something restored that `item` keeps.
/// The directories opened on the way to the last entry's, from a
/// destination's root down, each with its name: the next entry's are opened
/// from the deepest that is on its way too, as an archive's entries one
/// after another are mostly in the same directory, where each was opened
/// from the root again. Each was opened without following a link, as
/// [`Destination::directory`] opens them, and is used by its handle. For one
/// thread going through the entries in turn, and one destination.
#[derive(Default)]
pub(crate) struct Walk {
    dirs: Vec<(String, Dir)>,
}

impl Walk {
    /// How many of `components` are on the way already: those after them are
    /// let go of.
    fn keep(&mut self, components: &[String]) -> usize {
        let same = self
            .dirs
            .iter()
            .zip(components)
            .take_while(|((name, _), component)| name == *component)
            .count();
        self.dirs.truncate(same);
        same
    }

    /// The deepest directory on the way, or `root`.
    fn deepest<'d>(&'d self, root: &'d Dir) -> &'d Dir {
        self.dirs.last().map_or(root, |(_, dir)| dir)
    }
}

fn wants_kept(item: &Item, options: &Options) -> bool {
    (options.owners != Owners::Ignore && item.owner.is_some())
        || (options.xattrs && !item.xattrs.is_empty())
}

/// The id this system has for the user, or group, `name`, looked up once:
/// none for no name, one not UTF-8, or one the system does not know.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn id_named(
    names: &std::sync::Mutex<std::collections::HashMap<Vec<u8>, Option<u32>>>,
    name: &[u8],
    look_up: fn(&str) -> Option<u32>,
) -> Option<u32> {
    if name.is_empty() {
        return None;
    }
    let mut names = names
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *names
        .entry(name.to_vec())
        .or_insert_with(|| std::str::from_utf8(name).ok().and_then(look_up))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_named(name: &str) -> Option<u32> {
    Some(nix::unistd::User::from_name(name).ok()??.uid.as_raw())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_named(name: &str) -> Option<u32> {
    Some(nix::unistd::Group::from_name(name).ok()??.gid.as_raw())
}

/// Restores on `handle`, a file or folder open, what `item` keeps and `options`
/// asks: its extended attributes, then its owner, as GNU tar does. What the file
/// system or the user's rights do not take is left as it is; an owner left is
/// counted in `owning`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn restore_kept(
    handle: &impl std::os::fd::AsFd,
    item: &Item,
    options: &Options,
    owning: &Owning,
) -> Result<(), ErrorKind> {
    use rustix::io::Errno;
    use std::os::unix::ffi::OsStrExt;
    // Not taken: the file system has none, the user may not, or it is not one
    // the system knows (a Linux name on macOS, an ACL of another system).
    let left = |e: Errno| {
        matches!(
            e,
            Errno::NOTSUP | Errno::PERM | Errno::ACCESS | Errno::INVAL | Errno::NOSPC
        )
    };
    if options.xattrs {
        for (name, value) in &item.xattrs {
            // Rights for a program, as a setuid bit gives, which are never
            // restored.
            if name.as_slice() == b"security.capability" || name.contains(&0) {
                continue;
            }
            let name = std::ffi::OsStr::from_bytes(name);
            match rustix::fs::fsetxattr(handle, name, value, rustix::fs::XattrFlags::empty()) {
                Ok(()) => {}
                Err(e) if left(e) => {}
                Err(e) => return Err(ErrorKind::Io(e.into())),
            }
        }
    }
    let Some(owner) = item.owner.as_ref() else {
        return Ok(());
    };
    let (uid, gid) = match options.owners {
        Owners::Ignore => return Ok(()),
        Owners::ByName => (
            id_named(&owning.users, &owner.user, user_named).unwrap_or(owner.uid),
            id_named(&owning.groups, &owner.group, group_named).unwrap_or(owner.gid),
        ),
        Owners::ByNumber => (owner.uid, owner.gid),
    };
    let (uid, gid) = (
        rustix::fs::Uid::from_raw(uid),
        rustix::fs::Gid::from_raw(gid),
    );
    match rustix::fs::fchown(handle, Some(uid), Some(gid)) {
        Ok(()) => {}
        // The owner not the user's to give, the group may be: one of theirs.
        Err(e) if left(e) => {
            match rustix::fs::fchown(handle, None, Some(gid)) {
                Ok(()) => {}
                Err(e) if left(e) => {}
                Err(e) => return Err(ErrorKind::Io(e.into())),
            }
            owning.left.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => return Err(ErrorKind::Io(e.into())),
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn restore_kept<H>(_: &H, _: &Item, _: &Options, _: &Owning) -> Result<(), ErrorKind> {
    Ok(())
}

/// The error of `component` in `dir`, which did not open as a directory with
/// `e`: a link, or a file, where a directory was to be.
fn not_a_directory(dir: &Dir, component: &str, e: io::Error) -> ErrorKind {
    match dir.symlink_metadata(component) {
        Ok(metadata) if !metadata.is_dir() => ErrorKind::NotADirectory,
        _ => ErrorKind::Io(e),
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

    /// The directory at `components`, made: what [`Options::owners`] and
    /// [`Options::xattrs`] restore of `item`. Nothing, but in a folder.
    fn restore_directory(
        &self,
        _components: &[String],
        _item: &Item,
        _options: &Options,
    ) -> Result<(), ErrorKind> {
        Ok(())
    }

    /// The file, its data written: its mark of origin, time and permissions.
    fn finish_file(
        &self,
        file: Self::File<'_>,
        item: &Item,
        options: &Options,
    ) -> Result<(), ErrorKind>;

    /// The file at `components`, whose data failed, not left.
    fn remove_file(&self, components: &[String]);

    /// How many files and folders kept their owner or group, not given:
    /// [`Summary::owners_left`](crate::extract::Summary::owners_left).
    fn owners_left(&self) -> u64 {
        0
    }

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

    /// This target, if it is a folder on disk, which threads can write files
    /// into at once.
    fn folder(&self) -> Option<&Destination<'_>> {
        None
    }
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
        Destination::directory(self, components)?;
        self.told(components, WrittenKind::Directory);
        Ok(())
    }

    fn within(&self, _: &Item, components: &[String]) -> Result<Self, ErrorKind> {
        Destination::within(self, components)
    }

    fn restore_directory(
        &self,
        components: &[String],
        item: &Item,
        options: &Options,
    ) -> Result<(), ErrorKind> {
        if !wants_kept(item, options) {
            return Ok(());
        }
        // Opened from its parent, to read and not through a link: a handle of
        // `directory`'s may be one for paths alone (`O_PATH` on Linux), which
        // takes no attributes.
        let (last, parents) = split(components)?;
        let parent = Destination::directory(self, parents)?;
        let mut how = OpenOptions::new();
        how.read(true).follow(FollowSymlinks::No);
        let dir = parent.open_with(last, &how).map_err(ErrorKind::Io)?;
        restore_kept(&dir, item, options, &self.owning)
    }

    fn create_file(
        &self,
        _: &Item,
        components: &[String],
        _: Option<u64>,
        options: &Options,
    ) -> Result<std::fs::File, ErrorKind> {
        let (last, parents) = split(components)?;
        if parents.is_empty() {
            // At the root, as a private folder's files are: no handle of its
            // own to open.
            return Ok(Destination::create_file(&self.root, last, options.overwrite)?.into_std());
        }
        // Through this thread's walk: the files one thread makes one after
        // another are mostly in the same directory.
        let mut walk = self.walks.take();
        let made = self
            .walk_to(parents, &mut walk)
            .and_then(|dir| Destination::create_file(dir, last, options.overwrite));
        self.walks.put(walk);
        Ok(made?.into_std())
    }

    fn finish_file(
        &self,
        file: std::fs::File,
        item: &Item,
        options: &Options,
    ) -> Result<(), ErrorKind> {
        // What the archive kept for a backup before the mark, which its
        // attributes never stand for.
        restore_kept(&file, item, options, &self.owning)?;
        // The mark first: writing a stream can change the file's time.
        if let Some(origin) = self.origin {
            origin.write_file(&file).map_err(ErrorKind::Origin)?;
        }
        if let Some(mtime) = item.mtime {
            set_modified(&file, mtime)?;
        }
        set_permissions(&file, item.mode, options.permissions)?;
        let mut file = file;
        file.flush().map_err(ErrorKind::Io)?;
        if let Ok(name) = &item.name {
            self.told(&name.components, WrittenKind::File);
        }
        Ok(())
    }

    fn owners_left(&self) -> u64 {
        self.owning.left.load(Ordering::Relaxed)
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
        Destination::symlink(&dir, last, target, to_dir)?;
        self.told(components, WrittenKind::Link);
        Ok(())
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
        Destination::hard_link(&target_dir, target_last, &dir, last)?;
        self.told(components, WrittenKind::HardLink);
        Ok(())
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

    fn folder(&self) -> Option<&Destination<'_>> {
        Some(self)
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
