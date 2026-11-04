//! Stopping an extraction, from another thread or past a time, and
//! following how far it is.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::extract::error::{Error, ErrorKind};
use crate::extract::plan::{Item, OnDamaged, Options};
use crate::extract::zip::Damaged;

/// Stops an extraction from another thread, or from
/// [`Options::progress`](crate::extract::Options::progress): clones share one
/// token, and an extraction given one stops with
/// [`ErrorKind::Cancelled`] soon after [`cancel`](Cancel::cancel) is called.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    /// Stops the extractions given this token, or a clone of it.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// How far an extraction is, as [`Options::progress`] is told it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// Directories, files and links written.
    pub entries: u64,
    /// Directories, files and links to write, once the entries are
    /// checked.
    pub total_entries: u64,
    /// Bytes written.
    pub bytes: u64,
    /// Bytes to write, as the archive says them; the data is checked
    /// against them, so `bytes` does not pass them.
    pub total_bytes: u64,
}

/// What [`Options::progress`] calls.
pub type ProgressFn = Arc<dyn Fn(&Progress) + Send + Sync>;

/// Where an extraction is, and what stops it before it ends: the time
/// limit and the token of [`Options`].
pub(crate) struct Run<'a> {
    options: &'a Options,
    deadline: Option<Instant>,
    progress: Cell<Progress>,
    /// The entries gone on from, their data damaged.
    damaged: RefCell<Vec<Damaged>>,
}

impl Run<'_> {
    pub(crate) fn new(options: &Options) -> Run<'_> {
        Run {
            options,
            // A limit too far to count is none.
            deadline: options
                .time_limit
                .and_then(|limit| Instant::now().checked_add(limit)),
            progress: Cell::new(Progress::default()),
            damaged: RefCell::new(Vec::new()),
        }
    }

    /// Whether the extraction is to stop: cancelled, or past its time.
    pub(crate) fn check(&self) -> Result<(), ErrorKind> {
        if self
            .options
            .cancel
            .as_ref()
            .is_some_and(Cancel::is_cancelled)
        {
            return Err(ErrorKind::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(ErrorKind::TimeLimit);
        }
        Ok(())
    }

    /// What to do with `item`, whose data failed with `kind`: its error, to stop
    /// with, unless it is damage and [`Options::on_damaged`] says to go on, how,
    /// with the error to keep.
    pub(crate) fn decide(&self, item: &Item, kind: ErrorKind) -> Result<(OnDamaged, Error), Error> {
        self.decide_on(item.error(kind))
    }

    /// What to do with the damage `error` says: itself, to stop with, unless
    /// [`Options::on_damaged`] says to go on, how.
    pub(crate) fn decide_on(&self, error: Error) -> Result<(OnDamaged, Error), Error> {
        let Some(on_damaged) = self
            .options
            .on_damaged
            .as_ref()
            .filter(|_| error.kind.is_damage())
        else {
            return Err(error);
        };
        match on_damaged(&error) {
            OnDamaged::Stop => Err(error),
            how => Ok((how, error)),
        }
    }

    /// `error`'s entry gone on from, with `kept` bytes of its data.
    pub(crate) fn damaged(&self, error: Error, kept: Option<u64>) {
        self.damaged.borrow_mut().push(Damaged { error, kept });
    }

    /// Whether a stream that ends before its archive does is gone on from, if
    /// [`Options::on_damaged`] says so once it is met: what is before it is
    /// read, and the rest lost.
    pub(crate) fn may_be_cut(&self, kind: &ErrorKind) -> bool {
        self.options.on_damaged.is_some() && kind.is_damage()
    }

    /// The index of the entry last gone on from.
    pub(crate) fn last_damaged(&self) -> Option<u64> {
        self.damaged.borrow().last().and_then(|d| d.error.index)
    }

    /// How many entries were gone on from so far.
    pub(crate) fn damaged_count(&self) -> usize {
        self.damaged.borrow().len()
    }

    /// The entries gone on from so far, taken.
    pub(crate) fn take_damaged(&self) -> Vec<Damaged> {
        self.damaged.take()
    }

    /// The entries are checked: `entries` to write, which say they hold
    /// `bytes`.
    pub(crate) fn start(&self, entries: u64, bytes: u64) {
        self.update(|progress| {
            progress.total_entries = entries;
            progress.total_bytes = bytes;
        });
    }

    /// `bytes` more than was said at the start are to be written: an entry
    /// whose size is not known.
    #[cfg(feature = "rar")]
    pub(crate) fn more_to_write(&self, bytes: u64) {
        self.update(|progress| progress.total_bytes += bytes);
    }

    /// `bytes` more are written.
    pub(crate) fn wrote(&self, bytes: u64) {
        self.update(|progress| progress.bytes += bytes);
    }

    /// One more entry is written.
    pub(crate) fn entry_done(&self) {
        self.update(|progress| progress.entries += 1);
    }

    /// Changes the progress and tells [`Options::progress`].
    fn update(&self, change: impl FnOnce(&mut Progress)) {
        let mut progress = self.progress.get();
        change(&mut progress);
        self.progress.set(progress);
        if let Some(f) = &self.options.progress {
            f(&progress);
        }
    }
}
