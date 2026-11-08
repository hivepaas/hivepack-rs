//! Files written by threads while the caller reads a stream on: tar and cpio
//! archives, whose data comes one entry after the other, on the caller's
//! thread, and must. What goes to the threads is the work on the file system
//! for each file: creating it, writing its data, its time and permissions,
//! closing it. The caller reads a file's data whole into memory and hands it
//! to the next thread free, within a bound on what is handed and not yet
//! written ([`HELD`]); a larger file, or one whose data does not read as its
//! header says, it writes itself, as it does with one thread.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

use crate::extract::destination::{Destination, Target};
use crate::extract::error::{Error, ErrorKind};
use crate::extract::plan::{Item, Options};
use crate::extract::progress::Run;
use crate::extract::tar::write_with;

/// The data handed to threads and not yet written, at most: 32 MiB, whatever
/// the threads, or [`Options::memory_limit`] if less.
pub(crate) const HELD: u64 = 32 << 20;

/// The files handed to threads and not yet written, at most, whatever their
/// data.
const JOBS: usize = 1024;

/// What a piece of data written is, at most, between checks of [`Run::check`]
/// and calls of [`Run::wrote`], as when one thread writes.
const PIECE: usize = 64 << 10;

/// What is handed and not yet written: data at most [`Writers::held`], files
/// at most [`JOBS`].
#[derive(Default)]
struct Queue<'a> {
    jobs: VecDeque<Job<'a>>,
    /// The bytes of data handed, or being read to hand, and not yet written.
    held: u64,
    /// The files handed and not yet written: those queued and those being
    /// written.
    busy: usize,
    /// No more files come: the threads end once the queue is empty.
    closed: bool,
    /// A thread panicked: what it had is not written, and the caller stops
    /// waiting for it.
    panicked: bool,
}

/// A file to write, its data read whole, or a directory to make.
struct Job<'a> {
    item: JobItem<'a>,
    /// The file's data; none for a directory.
    data: Option<Vec<u8>>,
}

/// The entry a job writes: one of the plan's, or one made as the archive is
/// read, which the job keeps (a file written into the private folder of an
/// archive read once).
pub(crate) enum JobItem<'a> {
    Borrowed(&'a Item),
    Owned(Box<Item>),
}

impl std::ops::Deref for JobItem<'_> {
    type Target = Item;

    fn deref(&self) -> &Item {
        match self {
            JobItem::Borrowed(item) => item,
            JobItem::Owned(item) => item,
        }
    }
}

impl<'a> From<&'a Item> for JobItem<'a> {
    fn from(item: &'a Item) -> JobItem<'a> {
        JobItem::Borrowed(item)
    }
}

impl From<Item> for JobItem<'_> {
    fn from(item: Item) -> Self {
        JobItem::Owned(Box::new(item))
    }
}

/// The threads writing files, and what the caller hands them.
pub(crate) struct Writers<'a> {
    destination: &'a Destination<'a>,
    run: &'a Run<'a>,
    options: &'a Options,
    threads: usize,
    /// The data that may be held, handed and not yet written.
    held: u64,
    queue: Mutex<Queue<'a>>,
    /// A file is handed, or no more come: for the threads.
    handed: Condvar,
    /// A file is written: for the caller, waiting for room or for all of them.
    written: Condvar,
    /// The first error, of a thread or of the caller: the one returned.
    failed: Mutex<Option<Error>>,
}

/// What `mutex` holds, even if a thread panicked holding it: the panic goes on
/// to the caller anyway.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The threads to write files with besides the caller's, which reads the
/// archive, and the data they may be handed.
pub(crate) struct Writing {
    threads: usize,
    held: u64,
    /// What they hold of [`Options::memory_budget`], until they are done.
    #[cfg(feature = "memory")]
    _budget: Option<crate::memory::Held>,
}

/// The threads to write `files` with: none where [`Options::threads`] says
/// one, or fewer than two files are written. The data they may be handed is
/// [`HELD`], or [`Options::memory_limit`] if less; with the feature `memory`,
/// it is held from [`Options::memory_budget`], which may lower them to none.
pub(crate) fn writer_threads(options: &Options, files: u64) -> Option<Writing> {
    let wanted = options.threads.count();
    if wanted < 2 || files < 2 {
        return None;
    }
    let held = HELD.min(options.memory_limit.unwrap_or(u64::MAX));
    // The caller's thread needs nothing more than with one; the others share
    // what is handed.
    #[cfg(feature = "memory")]
    let (threads, budget) = match &options.memory_budget {
        Some(budget) => {
            let (fit, holds) = budget.hold_threads(wanted, |n| if n > 1 { held } else { 0 });
            (fit, Some(holds))
        }
        None => (wanted, None),
    };
    #[cfg(not(feature = "memory"))]
    let threads = wanted;
    let threads = usize::try_from(threads - 1)
        .unwrap_or(usize::MAX)
        .min(usize::try_from(files).unwrap_or(usize::MAX));
    (threads > 0).then_some(Writing {
        threads,
        held,
        #[cfg(feature = "memory")]
        _budget: budget,
    })
}

/// Runs `body` on this thread, with the threads of `writing` writing the files
/// it hands them into `destination`; then waits for them to end. The first error, of `body` or of a thread, halts the others and
/// is the one returned; a thread that panicked has its panic go on to the
/// caller.
pub(crate) fn with_writers<'a, R>(
    destination: &'a Destination<'a>,
    run: &'a Run<'a>,
    options: &'a Options,
    writing: &Writing,
    body: impl FnOnce(&Writers<'a>) -> Result<R, Error>,
) -> Result<R, Error> {
    let writers = Writers {
        destination,
        run,
        options,
        threads: writing.threads,
        held: writing.held,
        queue: Mutex::new(Queue::default()),
        handed: Condvar::new(),
        written: Condvar::new(),
        failed: Mutex::new(None),
    };
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..writers.threads)
            .map(|_| scope.spawn(|| writers.work()))
            .collect();
        let result = body(&writers).map_err(|e| writers.fail(e));
        lock(&writers.queue).closed = true;
        writers.handed.notify_all();
        for handle in handles {
            if let Err(panic) = handle.join() {
                std::panic::resume_unwind(panic);
            }
        }
        match lock(&writers.failed).take() {
            Some(e) => Err(e),
            // An error of `body` is kept by `fail`, if none was before.
            None => result.map_err(|()| Error::global(ErrorKind::Cancelled)),
        }
    })
}

/// Marks the queue when a thread panics, so that the caller does not wait for
/// what it was to write.
struct Panicked<'q, 'a>(&'q Writers<'a>);

impl Drop for Panicked<'_, '_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            lock(&self.0.queue).panicked = true;
            self.0.run.halt();
            self.0.written.notify_all();
        }
    }
}

impl<'a> Writers<'a> {
    /// Keeps `e` if it is the first error, and halts the threads.
    fn fail(&self, e: Error) {
        // Kept before the others are halted: their errors come after it.
        lock(&self.failed).get_or_insert(e);
        self.run.halt();
    }

    /// What a thread does: writes the files handed, one after the other,
    /// until no more come. Once one failed, or the extraction is stopped, the
    /// rest are passed over.
    fn work(&self) {
        let _panicked = Panicked(self);
        loop {
            let job = {
                let mut queue = lock(&self.queue);
                loop {
                    if let Some(job) = queue.jobs.pop_front() {
                        break job;
                    }
                    if queue.closed {
                        return;
                    }
                    queue = self
                        .handed
                        .wait(queue)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            };
            let len = job.data.as_ref().map_or(0, |data| data.len() as u64);
            if let Err(e) = self.write(&job) {
                self.fail(e);
            }
            drop(job);
            let mut queue = lock(&self.queue);
            queue.held -= len;
            queue.busy -= 1;
            drop(queue);
            self.written.notify_all();
        }
    }

    /// Writes `job`'s file, as one thread writes it.
    fn write(&self, job: &Job<'_>) -> Result<(), Error> {
        let (item, run) = (&*job.item, self.run);
        let error = |kind| item.error(kind);
        run.check().map_err(error)?;
        match &job.data {
            Some(data) => write_data(self.destination, item, data, run, self.options)?,
            None => {
                let name = item.name.as_ref().map_err(|e| error(ErrorKind::Name(*e)))?;
                Target::directory(self.destination, item, &name.components).map_err(error)?;
            }
        }
        run.entry_done();
        Ok(())
    }

    /// The largest file handed to a thread: an eighth of what may be held,
    /// 4 MiB. A larger one is written on the caller's thread.
    fn largest(&self) -> u64 {
        self.held / 8
    }

    /// Waits until every file handed is written: before what needs one of them
    /// there, as a hard link does. The error of a thread, if one failed.
    pub(crate) fn wait(&self, item: &Item) -> Result<(), Error> {
        let mut queue = lock(&self.queue);
        while queue.busy > 0 && !queue.panicked {
            queue = self
                .written
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(queue);
        self.run.check().map_err(|kind| item.error(kind))
    }

    /// Takes `size` bytes of room for data, waiting for the threads to write
    /// what was handed before, if it is not there: the most data is
    /// [`Writers::held`], unless no file is held at all.
    fn room(&self, size: u64) {
        let mut queue = lock(&self.queue);
        while queue.busy > 0
            && !queue.panicked
            && (queue.held + size > self.held || queue.busy >= JOBS)
        {
            queue = self
                .written
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
        queue.held += size;
    }

    /// Gives back the room taken for data not handed.
    fn give_back(&self, size: u64) {
        lock(&self.queue).held -= size;
        self.written.notify_all();
    }

    /// Hands the directory `item` to a thread to make: its files may come
    /// before it is, which make it.
    pub(crate) fn directory(&self, item: &'a Item) {
        self.room(0);
        self.hand(item.into(), None);
    }

    /// Hands `item`'s file to a thread, its `data` read, in room taken.
    fn hand(&self, item: JobItem<'a>, data: Option<Vec<u8>>) {
        let mut queue = lock(&self.queue);
        queue.busy += 1;
        queue.jobs.push_back(Job { item, data });
        drop(queue);
        self.handed.notify_one();
    }

    /// Hands `item`'s file of `size` bytes to a thread, its data read from `r`
    /// here: `None` once handed, its bytes to count as written. `remaining` is
    /// what [`Limits::max_total_size`](crate::extract::Limits::max_total_size)
    /// leaves. With `ends`, `r` must end after the data, as tar's entry does.
    ///
    /// A file larger than [`Writers::largest`] or the limits leave, or whose
    /// data does not read as `size` bytes (cut short, damaged, or longer), is
    /// left to the caller to write as one thread does, from what `r` gives:
    /// the data read of it, then the rest of `r`. An error is the extraction's,
    /// to stop with: it was stopped while the data was read.
    pub(crate) fn file<'r, R: Read>(
        &'r self,
        r: &'r mut R,
        item: impl Into<JobItem<'a>>,
        size: u64,
        remaining: u64,
        ends: bool,
    ) -> Result<Option<Replay<'r, 'a, R>>, Error> {
        let item = item.into();
        let limits = &self.options.limits;
        let fits = size <= self.largest() && size <= limits.max_entry_size && size <= remaining;
        if !fits {
            return Ok(Some(Replay::new(Vec::new(), None, r, None)));
        }
        self.room(size);
        let mut data = Vec::new();
        let read = read_data(r, &mut data, size, ends, self.run);
        // What was read stays counted until it is written, here.
        let room = Some((self, size));
        match read {
            Ok(true) => {
                self.hand(item, Some(data));
                Ok(None)
            }
            Ok(false) => Ok(Some(Replay::new(data, None, r, room))),
            Err(Stopped::Read(e)) => Ok(Some(Replay::new(data, Some(e), r, room))),
            Err(Stopped::Run(kind)) => {
                self.give_back(size);
                Err(item.error(kind))
            }
        }
    }
}

/// Writes `item` as a file of `data`, into `destination`, as one thread writes
/// it, a piece at a time.
fn write_data<T: Target>(
    destination: &T,
    item: &Item,
    data: &[u8],
    run: &Run<'_>,
    options: &Options,
) -> Result<(), Error> {
    let size = data.len() as u64;
    let written = write_with(item, Some(size), destination, run, options, |file| {
        for piece in data.chunks(PIECE) {
            run.check()?;
            file.write_all(piece).map_err(ErrorKind::Io)?;
            run.wrote(piece.len() as u64);
        }
        Ok(size)
    })?;
    // Its data is whole: nothing is gone on from.
    debug_assert_eq!(written, Some(size));
    Ok(())
}

/// Why reading a file's data stopped.
enum Stopped {
    /// Its data failed.
    Read(io::Error),
    /// The extraction is stopped.
    Run(ErrorKind),
}

/// Reads `size` bytes of `r` into `data`: whether they are all there, and with
/// `ends` nothing after them. What was read is in `data`, whatever comes.
fn read_data(
    r: &mut impl Read,
    data: &mut Vec<u8>,
    size: u64,
    ends: bool,
    run: &Run<'_>,
) -> Result<bool, Stopped> {
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    data.resize(size, 0);
    let mut filled = 0;
    while filled < size {
        run.check().map_err(Stopped::Run)?;
        let want = (size - filled).min(PIECE);
        match r.read(&mut data[filled..filled + want]) {
            Ok(0) => {
                data.truncate(filled);
                return Ok(false);
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                data.truncate(filled);
                return Err(Stopped::Read(e));
            }
        }
    }
    if !ends {
        return Ok(true);
    }
    // Nothing after it, as one thread reads to the end.
    let mut more = [0u8; 1];
    loop {
        match r.read(&mut more) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                data.extend_from_slice(&more[..n]);
                return Ok(false);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Stopped::Read(e)),
        }
    }
}

/// What a file's data read as, for the caller to write it as one thread
/// does: what was read, then the error the reading met, if any, then the
/// rest of the stream.
pub(crate) struct Replay<'r, 'a, R> {
    data: io::Cursor<Vec<u8>>,
    error: Option<io::Error>,
    rest: &'r mut R,
    /// The room `data` takes, given back once it is written.
    room: Option<(&'r Writers<'a>, u64)>,
}

impl<'r, 'a, R> Replay<'r, 'a, R> {
    fn new(
        data: Vec<u8>,
        error: Option<io::Error>,
        rest: &'r mut R,
        room: Option<(&'r Writers<'a>, u64)>,
    ) -> Replay<'r, 'a, R> {
        Replay {
            data: io::Cursor::new(data),
            error,
            rest,
            room,
        }
    }
}

impl<R> Drop for Replay<'_, '_, R> {
    fn drop(&mut self) {
        if let Some((writers, size)) = self.room {
            writers.give_back(size);
        }
    }
}

impl<R: Read> Read for Replay<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.data.read(buf)?;
        if n > 0 || buf.is_empty() {
            return Ok(n);
        }
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        self.rest.read(buf)
    }
}
