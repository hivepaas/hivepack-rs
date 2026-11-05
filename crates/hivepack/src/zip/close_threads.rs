//! New data compressed in threads ahead of the entry being written, each
//! entry's data then written in order as if it had been compressed there.
//! Not in libzip, which compresses each entry as it writes it.
//!
//! When the archive is written ([`Archive::close_to`] and the others), each
//! entry of new data that is to be compressed, and whose source tells its
//! size, is given to a thread, in the order the entries are written. The
//! thread reads its source and runs the layers `add_data` stacks under the
//! encrypting one (the CRC and the compressing layer), in reads of the sizes
//! `add_data` reads them in, and keeps what they give: the compressed bytes,
//! the error that ended them if one did, and what their stat and attributes
//! said from each read on that changed them. The thread writing the archive
//! then takes it in place of those layers ([`Precompressed`]), under the
//! encrypting layer if there is one, so that the random bytes are drawn in
//! the same order: everything it writes, and every error, is what it would
//! have been with the layers there.
//!
//! What waits to be written is bounded: an entry is charged the most its
//! data can compress to, from when it is given to a thread until it is
//! written, and no more is given while that would pass
//! [`MEMORY_PER_THREAD`] for each thread. An entry that could take more than
//! all of it is compressed by the thread writing, as with one thread, while
//! the others go on with the entries after it.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::threads::Threads;
use crate::workers::Workers;
use crate::zip::dirent::{Dirent, cm_actual};
use crate::zip::error::Result;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_compress::{Compress, maximum_compressed_size};
use crate::zip::source_crc::Crc;
use crate::zip::source_data::{DataSource, FileAttributes};
use crate::zip::source_stack::{Base, Layer, WriteStack};
use crate::zip::zip::{Stat, cm, em, stat};
use crate::zip::zipint::{
    BUFSIZE, CRYPTO_PKWARE_HEADERLEN, WINZIP_AES_PASSWORD_VERIFY_LENGTH, salt_length,
};

/// What may wait to be written, for each thread: the most the entries given
/// to threads and not yet written can compress to.
pub(crate) const MEMORY_PER_THREAD: u64 = 32 << 20;

/// What an entry is charged besides its data, for what is kept of it.
const ENTRY_COST: u64 = 1024;

#[cfg(test)]
thread_local! {
    /// [`MEMORY_PER_THREAD`], smaller for a test.
    static TEST_MEMORY: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// How many entries were written from what a thread made.
    static TAKEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// What may wait to be written, for each thread.
fn memory_per_thread() -> u64 {
    #[cfg(test)]
    if let Some(memory) = TEST_MEMORY.with(std::cell::Cell::get) {
        return memory;
    }
    MEMORY_PER_THREAD
}

impl<R> Archive<R> {
    /// Sets how many threads compress new data when the archive is written
    /// ([`Archive::close_to`], [`Archive::close_to_stream`] and
    /// [`Archive::close_to_cloning`]): [`Threads::One`], the caller's, by
    /// default. libzip has no threads.
    ///
    /// With more, the entries added with
    /// [`file_add`](Archive::file_add) or [`file_replace`](Archive::file_replace)
    /// that are compressed are compressed in threads, each reading its
    /// source, ahead of the entry being written, while the caller's thread
    /// writes the entries in order, encrypting those that are encrypted.
    /// The archive is the same, byte for byte, whatever this says, and so is
    /// an error and what was written before it. Each thread keeps its own
    /// compressor (deflate takes about 300 KiB, bzip2 7 MiB, LZMA and XZ at
    /// preset 6 94 MiB), and up to 32 MiB for each thread waits to be
    /// written, counted as the most each entry can compress to. An entry
    /// that could take more than all of it, or whose source does not tell
    /// its size, is compressed on the caller's thread when it is written,
    /// while the threads go on with the entries after it. Everything else
    /// is written as with one thread: entries stored, copied as they are,
    /// or compressed again from an entry of the archive.
    pub fn set_threads(&mut self, threads: Threads) {
        self.threads = threads;
    }
}

/// What a thread's work on an entry is for: it is taken only if the entry
/// is still to be compressed so when it is written.
pub(crate) struct Key {
    source: Arc<dyn DataSource>,
    /// the method and level the compressing layer is made with
    method: i32,
    level: u32,
    /// the size of the first read, which the encrypting layer makes smaller
    /// by its header: with `ZIP_CM_DEFAULT`, it decides whether the data is
    /// stored
    first_read: usize,
    /// whether the compressing layer may not give way to storing
    keep_compressing: bool,
}

impl Key {
    fn fits(&self, other: &Key) -> bool {
        Arc::ptr_eq(&self.source, &other.source)
            && self.method == other.method
            && self.level == other.level
            && self.first_read == other.first_read
            && self.keep_compressing == other.keep_compressing
    }
}

/// The header the encrypting layer gives before the data, in the first read:
/// none without encryption, `None` for a method it does not have.
fn encryption_header_length(encryption_method: u16) -> Option<usize> {
    match encryption_method {
        em::NONE => Some(0),
        em::TRAD_PKWARE => Some(CRYPTO_PKWARE_HEADERLEN),
        em::AES_128 | em::AES_192 | em::AES_256 => {
            Some(salt_length(encryption_method) + WINZIP_AES_PASSWORD_VERIFY_LENGTH)
        }
        _ => None,
    }
}

/// What the stat and attributes under the encrypting layer said.
#[derive(Clone, Copy)]
pub(crate) struct Shown {
    pub(crate) stat: Result<Stat<'static>>,
    pub(crate) attributes: Result<FileAttributes>,
}

/// What a thread made of an entry's data: what reading the layers under the
/// encrypting one gave, read again in the same order.
pub(crate) struct Precompressed {
    key: Key,
    /// what opening the layers gave
    open: Result<()>,
    data: Vec<u8>,
    /// how much of `data` is read
    position: usize,
    /// how the reading ended: at the end, or with an error
    end: Result<()>,
    /// what the stat and attributes said, from the read they changed in on
    shown: Vec<(u64, Shown)>,
    /// the reads made of the top of the layers
    reads: u64,
}

impl Precompressed {
    /// Whether this was made for the entry as `key` would compress it.
    pub(crate) fn fits(
        &self,
        source: &Arc<dyn DataSource>,
        method: i32,
        level: u32,
        encryption_method: u16,
        stream: bool,
    ) -> bool {
        let Some(header) = encryption_header_length(encryption_method) else {
            return false;
        };
        let encrypt = encryption_method != em::NONE;
        self.key.fits(&Key {
            source: Arc::clone(source),
            method,
            level,
            first_read: BUFSIZE - header,
            keep_compressing: stream && encrypt,
        })
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) -> Result<()> {
        #[cfg(test)]
        TAKEN.with(|taken| taken.set(taken.get() + 1));
        self.position = 0;
        self.reads = 0;
        self.open
    }

    /// Counts a read of the top of the layers.
    pub(crate) fn count_read(&mut self) {
        self.reads += 1;
    }

    /// `ZIP_SOURCE_READ`: the data, then its end.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let rest = &self.data[self.position..];
        if rest.is_empty() {
            return self.end.map(|()| 0);
        }
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.position += n;
        Ok(n)
    }

    /// What the stat and attributes said after the reads made so far.
    pub(crate) fn shown(&self) -> Shown {
        let at = self.shown.partition_point(|(read, _)| *read <= self.reads);
        // The first is from before any read.
        self.shown[at.saturating_sub(1)].1
    }
}

/// An entry for a thread to compress.
struct Job {
    key: Key,
    /// the most the data can compress to: more, and the thread gives up
    most: u64,
    stop: Arc<AtomicBool>,
}

/// What [`compress`] gives: none if it gave up.
type Made = Option<Box<Precompressed>>;

fn lost() -> Made {
    None
}

/// What the layers under the encrypting one say.
fn shown<R: ReadAt + ?Sized>(stack: &WriteStack<'_, R>) -> Shown {
    Shown {
        stat: stack.stat_below_encrypt(),
        attributes: stack.attributes_below_encrypt(),
    }
}

/// Reads the job's source through the layers `add_data` stacks under the
/// encrypting one, as it reads them, and keeps what they give. Gives up,
/// for the entry to be compressed where it is written, if the compressing
/// layer cannot be made, the data comes to more than it could, or the
/// archive is no longer written.
fn compress(_: &mut (), job: Job) -> Made {
    let Job { key, most, stop } = job;
    let mut compress = Compress::new(key.method, key.level).ok()?;
    if key.keep_compressing {
        compress.keep_compressing();
    }
    let mut stack: WriteStack<'_, [u8]> = WriteStack {
        base: Base::data(Arc::clone(&key.source)),
        decrypt: None,
        decompress: None,
        crc: Some(Layer::new(Crc::new(false))),
        compress: Some(Layer::new(compress)),
        precompressed: None,
        encrypt: None,
    };
    let mut seen = stack.shown_key();
    let mut shows = vec![(0, shown(&stack))];
    let open = stack.open();
    let mut data = Vec::new();
    let mut end = Ok(());
    if open.is_ok() {
        let mut buf = vec![0; BUFSIZE];
        let mut want = key.first_read;
        let mut reads = 0;
        loop {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let got = stack.read(&mut buf[..want]);
            reads += 1;
            let now = stack.shown_key();
            if now != seen {
                seen = now;
                shows.push((reads, shown(&stack)));
            }
            match got {
                Ok(0) => break,
                Ok(n) => {
                    let len = data.len() + n;
                    if len as u64 > most {
                        return None;
                    }
                    if len > data.capacity() {
                        // Grown by half again, never past the most.
                        let grown = (data.capacity() + data.capacity() / 2)
                            .max(len)
                            .max(BUFSIZE)
                            .min(most as usize);
                        data.reserve_exact(grown - data.len());
                    }
                    data.extend_from_slice(&buf[..n]);
                }
                Err(e) => {
                    end = Err(e);
                    break;
                }
            }
            want = BUFSIZE;
        }
    }
    // As `copy_source` closes, failing nothing.
    let _ = stack.close();
    Some(Box::new(Precompressed {
        key,
        open,
        data,
        position: 0,
        end,
        shown: shows,
        reads: 0,
    }))
}

/// The entries given to threads, and those to give, in the order they are
/// written.
pub(crate) struct Ahead {
    workers: Workers<(), Job, Made>,
    /// entries to give: the index, what for, and the most each can take
    planned: VecDeque<(usize, Key, u64)>,
    /// entries given, with what each is charged
    given: VecDeque<(usize, u64)>,
    /// what the entries given are charged
    held: u64,
    budget: u64,
    stop: Arc<AtomicBool>,
}

impl Ahead {
    /// Gives threads the entries planned, in order, while they fit.
    fn give(&mut self) {
        while let Some(&(_, _, most)) = self.planned.front() {
            let cost = most + ENTRY_COST;
            if self.held + cost > self.budget {
                break;
            }
            let Some((i, key, most)) = self.planned.pop_front() else {
                break;
            };
            self.held += cost;
            self.given.push_back((i, cost));
            self.workers.give(Job {
                key,
                most,
                stop: Arc::clone(&self.stop),
            });
        }
    }

    /// What a thread made of entry `i`, the next written, if it was given
    /// one: waited for. The entries after it are given as they fit.
    pub(crate) fn take(&mut self, i: usize) -> Option<Box<Precompressed>> {
        self.give();
        let made = match self.given.front() {
            Some(&(j, cost)) if j == i => {
                self.given.pop_front();
                let made = self.workers.take().flatten();
                self.held -= cost;
                made
            }
            _ => None,
        };
        self.give();
        made
    }
}

/// The threads stop at their next read, as what they make is no longer
/// wanted.
impl Drop for Ahead {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl<R: ReadAt> Archive<R> {
    /// The threads that compress the entries of `written`, in that order,
    /// ahead of them; none with one thread, or with nothing for them.
    pub(crate) fn compress_ahead(&self, written: &[usize], stream: bool) -> Option<Ahead> {
        let threads = match self.threads {
            Threads::One => return None,
            threads => threads.count(),
        };
        if threads <= 1 {
            return None;
        }
        let budget = memory_per_thread().saturating_mul(u64::from(threads));
        let planned: VecDeque<(usize, Key, u64)> = written
            .iter()
            .filter_map(|&i| {
                let (key, most) = self.plan(i, stream)?;
                (most + ENTRY_COST <= budget).then_some((i, key, most))
            })
            .collect();
        if planned.is_empty() {
            return None;
        }
        Some(Ahead {
            workers: Workers::new(threads, "zip-compress", compress, lost),
            planned,
            given: VecDeque::new(),
            held: 0,
            budget,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// How entry `i` is compressed when it is written, and the most it can
    /// compress to, if it is new data that a thread can compress: what
    /// `write_entry` and `add_data` will decide, from the same dirent and
    /// stat. It is checked again then ([`Precompressed::fits`]).
    fn plan(&self, i: usize, stream: bool) -> Option<(Key, u64)> {
        let entry = &self.entry[i];
        let source = entry.source.as_ref()?;
        let mut de = match (entry.changes.as_deref(), entry.orig.as_deref()) {
            (None, orig) => Dirent::clone_changes(orig),
            (Some(changes), Some(orig)) => {
                let mut de = changes.clone();
                de.merge(orig, true);
                de
            }
            (Some(changes), None) => changes.clone(),
        };
        if self.want_torrentzip() {
            de.torrentzip_normalize();
        }
        let st = source.stat().ok()?;
        if st.valid & stat::COMP_METHOD != 0 && st.comp_method != cm::STORE
            || st.valid & stat::ENCRYPTION_METHOD != 0 && st.encryption_method != em::NONE
            || st.valid & stat::SIZE == 0
        {
            return None;
        }
        let method = cm_actual(de.comp_method);
        if method == cm::STORE {
            return None;
        }
        let most = maximum_compressed_size(method, st.size)?;
        let header = encryption_header_length(de.encryption_method)?;
        let key = Key {
            source: Arc::clone(source),
            method: de.comp_method,
            level: de.compression_level,
            first_read: BUFSIZE - header,
            keep_compressing: stream && de.encryption_method != em::NONE,
        };
        Some((key, most))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Cursor;
    use std::num::NonZeroU32;

    use super::*;
    use crate::zip::{BufferSource, Flags, OpenFlags};

    fn text(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b"abcdefgh  \n"[(x % 11) as usize]
            })
            .collect()
    }

    /// The archive of entries of `sizes`, deflated, written with `threads`
    /// and `memory` for each: its bytes, and how many entries were taken
    /// from a thread.
    fn write(sizes: &[usize], threads: Threads, memory: u64, stream: bool) -> (Vec<u8>, usize) {
        TEST_MEMORY.with(|m| m.set(Some(memory)));
        TAKEN.with(|taken| taken.set(0));
        let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
        archive.set_threads(threads);
        for (i, &n) in sizes.iter().enumerate() {
            let data = text(i as u64, n);
            archive
                .file_add(
                    format!("{i}").as_bytes(),
                    BufferSource::with_mtime(data, 1_700_000_000),
                    Flags::NONE,
                )
                .unwrap();
        }
        let mut out = Cursor::new(Vec::new());
        if stream {
            archive.close_to_stream(&mut out).unwrap();
        } else {
            archive.close_to(&mut out).unwrap();
        }
        TEST_MEMORY.with(|m| m.set(None));
        (out.into_inner(), TAKEN.with(std::cell::Cell::get))
    }

    /// Entries larger than the threads may hold are compressed where they
    /// are written, those around them in threads, and the archive is the
    /// same; so with a budget that holds a few entries at a time, or one.
    #[test]
    fn larger_than_the_budget() {
        let mut sizes = vec![300_000, 0, 1];
        sizes.extend((0..40).map(|i| 1000 + i * 1500));
        sizes.push(250_000);
        sizes.extend((0..20).map(|i| 30_000 + i));
        sizes.push(140_000);
        let two = Threads::Exactly(NonZeroU32::new(2).unwrap());
        for stream in [false, true] {
            let (one, taken) = write(&sizes, Threads::One, 64 << 10, stream);
            assert_eq!(taken, 0);
            for memory in [64 << 10, 36 << 10, 1 << 30] {
                let (got, taken) = write(&sizes, two, memory, stream);
                assert!(got == one, "{memory}: bytes differ");
                let large = sizes
                    .iter()
                    .filter(|&&n| {
                        maximum_compressed_size(cm::DEFLATE, n as u64).unwrap() + ENTRY_COST
                            > 2 * memory
                    })
                    .count();
                assert_eq!(taken, sizes.len() - large, "{memory}");
            }
        }
    }

    /// What was shown is the last change at or before the reads made.
    #[test]
    fn shown_after_reads() {
        let source: Arc<dyn DataSource> = Arc::new(BufferSource::new(Vec::new()));
        let show = |size: u64| {
            let st = Stat {
                size,
                ..Stat::default()
            };
            Shown {
                stat: Ok(st),
                attributes: Ok(FileAttributes::default()),
            }
        };
        let mut made = Precompressed {
            key: Key {
                source,
                method: 8,
                level: 0,
                first_read: BUFSIZE,
                keep_compressing: false,
            },
            open: Ok(()),
            data: b"abc".to_vec(),
            position: 0,
            end: Ok(()),
            shown: vec![(0, show(0)), (2, show(2)), (5, show(5))],
            reads: 0,
        };
        let size = |made: &Precompressed| made.shown().stat.unwrap().size;
        assert_eq!(size(&made), 0);
        for (reads, want) in [(1, 0), (2, 2), (3, 2), (4, 2), (5, 5), (9, 5)] {
            while made.reads < reads {
                made.count_read();
            }
            assert_eq!(size(&made), want, "{reads}");
        }
        let mut buf = [0; 2];
        assert_eq!(made.read(&mut buf), Ok(2));
        assert_eq!(made.read(&mut buf), Ok(1));
        assert_eq!(made.read(&mut buf), Ok(0));
    }
}
