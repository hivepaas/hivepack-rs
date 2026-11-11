//! Walking a tree: `traverse.c`, with `stack.c`'s stack as a `Vec`.

use std::io::{Read, Seek};

use super::dir::{Dir, DirEntry};
use super::error::{Result, err};
use super::fs::{Inode, Sqfs};

/// How deep a walk goes: a directory this many levels down is not entered.
///
/// Differs from squashfuse, which has no bound, and goes on through a
/// directory that holds itself until its memory runs out.
pub const MAX_DEPTH: usize = 1024;

/// `TRAVERSE_PATH_SEPARATOR`.
const SEPARATOR: &[u8] = b"/";

/// `sqfs_traverse_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Descend into the current entry, a directory.
    Descend,
    /// Remove the name from the end of the path.
    NameRemove,
    Error,
    Finished,
    /// Done with a directory: ascend a level.
    Ascend,
    /// Add a name to the end of the path.
    NameAdd,
    /// The next entry at the same level.
    GetEntry,
}

/// `sqfs_traverse_level`.
#[derive(Clone, Debug)]
struct Level {
    dir: Dir,
    name_size: usize,
}

/// What a walk gives next: `Squashfs::traverse`'s `next`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// An entry, and its path from where the walk started.
    Entry {
        /// Its path, the names separated by `/`.
        path: Vec<u8>,
        /// The entry.
        entry: DirEntry,
    },
    /// The end of a directory (`dir_end`), after its entries.
    DirEnd,
}

/// `sqfs_traverse`: a walk of everything under a directory, in order,
/// depth first.
#[derive(Clone, Debug)]
pub struct Traverse {
    entry: DirEntry,
    /// The path, without squashfuse's NUL.
    path: Vec<u8>,
    path_last_size: usize,
    state: State,
    stack: Vec<Level>,
}

impl Traverse {
    /// `sqfs_traverse_open_inode`: a walk of what `inode`, a directory,
    /// holds, not of itself.
    pub(crate) fn open<R: Read + Seek>(fs: &mut Sqfs<R>, inode: &Inode) -> Result<Traverse> {
        let mut trv = Traverse {
            entry: DirEntry::default(),
            path: Vec::new(),
            path_last_size: 0,
            state: State::Error,
            stack: Vec::new(),
        };
        trv.sqfs_traverse_descend_inode(fs, inode)?;
        // The root has no name.
        trv.path_last_size = 0;
        trv.state = State::NameRemove;
        Ok(trv)
    }

    /// `sqfs_traverse_next`: the next entry, or the end of a directory;
    /// `None` at the end. After an error, there is nothing more.
    pub(crate) fn next<R: Read + Seek>(&mut self, fs: &mut Sqfs<R>) -> Result<Option<Step>> {
        match self.next_inner(fs) {
            Ok(step) => Ok(step),
            Err(e) => {
                self.state = State::Error;
                Err(e)
            }
        }
    }

    fn next_inner<R: Read + Seek>(&mut self, fs: &mut Sqfs<R>) -> Result<Option<Step>> {
        loop {
            match self.state {
                State::GetEntry => {
                    let Some(level) = self.stack.last_mut() else {
                        return Err(err("an empty stack"));
                    };
                    match fs.sqfs_dir_next(&mut level.dir, true)? {
                        Some(entry) => {
                            self.entry = entry;
                            self.state = State::NameAdd;
                        }
                        None => self.state = State::Ascend,
                    }
                }
                State::NameAdd => {
                    self.path_last_size = self.entry.name.len();
                    self.path.extend_from_slice(&self.entry.name);
                    self.state = if self.entry.is_dir() {
                        State::Descend
                    } else {
                        State::NameRemove
                    };
                    return Ok(Some(Step::Entry {
                        path: self.path.clone(),
                        entry: self.entry.clone(),
                    }));
                }
                State::NameRemove => {
                    self.path_remove(self.path_last_size);
                    self.state = State::GetEntry;
                }
                State::Descend => {
                    if self.stack.len() >= MAX_DEPTH {
                        return Err(err("a tree too deep"));
                    }
                    let inode = fs.sqfs_inode_get(self.entry.inode)?;
                    self.sqfs_traverse_descend_inode(fs, &inode)?;
                    self.state = State::GetEntry;
                }
                State::Ascend => {
                    self.sqfs_traverse_ascend()?;
                    if !self.stack.is_empty() {
                        self.state = State::NameRemove;
                        return Ok(Some(Step::DirEnd));
                    }
                    self.state = State::Finished;
                }
                State::Finished => return Ok(None),
                State::Error => return Err(err("the walk failed before")),
            }
        }
    }

    /// `sqfs_traverse_prune`: does not go into the directory just given.
    pub(crate) fn prune(&mut self) {
        self.state = State::NameRemove;
    }

    /// `sqfs_traverse_path_remove`: `size` bytes off the path's end.
    fn path_remove(&mut self, size: usize) {
        // path_size counts the NUL.
        let path_size = self.path.len() + 1;
        if path_size > size {
            self.path.truncate(path_size - size - 1);
        } else {
            self.path.clear();
        }
    }

    /// `sqfs_traverse_descend_inode`.
    fn sqfs_traverse_descend_inode<R: Read + Seek>(
        &mut self,
        fs: &mut Sqfs<R>,
        inode: &Inode,
    ) -> Result<()> {
        let initial = self.stack.is_empty();
        let dir = fs.sqfs_dir_open(inode, 0)?;
        let name_size = if initial {
            // No separator, nor name size, for the root.
            0
        } else {
            self.path.extend_from_slice(SEPARATOR);
            self.entry.name.len()
        };
        self.stack.push(Level { dir, name_size });
        Ok(())
    }

    /// `sqfs_traverse_ascend`.
    fn sqfs_traverse_ascend(&mut self) -> Result<()> {
        let Some(level) = self.stack.pop() else {
            return Err(err("an empty stack"));
        };
        // Safe even for the root.
        self.path_remove(SEPARATOR.len());
        self.path_last_size = level.name_size;
        Ok(())
    }
}
