//! Stopping an extraction, from another thread or past a time, and
//! following how far it is.

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::extract::error::ErrorKind;
use crate::extract::plan::Options;

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
