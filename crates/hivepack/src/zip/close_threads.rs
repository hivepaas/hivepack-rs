//! New data compressed and encrypted in threads ahead of the entry being
//! written, each entry's data then written in order as if it had been
//! compressed and encrypted there. Not in libzip, which compresses and
//! encrypts each entry as it writes it.
//!
//! When the archive is written ([`Archive::close_to`] and the others), each
//! entry of new data that is to be compressed, and whose source tells its
//! size, is given to a thread, in the order the entries are written. The
//! thread reads its source and runs the layers `add_data` stacks on it (the
//! CRC, the compressing layer, and the encrypting one if it has its random
//! bytes), in reads of the sizes `add_data` reads them in, and keeps what
//! they give: the bytes, the error that ended them if one did, and what the
//! stat and attributes under the encrypting layer said from each read on
//! that changed them. The thread writing the archive then takes it in place
//! of those layers ([`Precompressed`]): everything it writes, and every
//! error, is what it would have been with the layers there.
//!
//! Encrypting draws random bytes when it starts, a salt for WinZip AES and
//! 11 bytes of header for ZipCrypto, and with one thread each entry draws
//! them as it is written, one after the other. With more, the thread writing
//! draws them ahead, in the same order and as many: before an entry is given
//! to a thread to encrypt, those of every entry before it are drawn, and
//! those of the entries the threads do not encrypt (too large for them, not
//! compressed, or not taken) are kept for them, to be taken in place of
//! drawing when each is written ([`Drawn`]). What each entry draws is told
//! before the archive is written ([`Draw`]), but for one written again from
//! an entry of the archive: none is drawn past one of those until it is
//! written, and drawing itself then, it keeps the order; the entries given
//! to threads meanwhile are encrypted on the thread writing. Nothing else
//! draws. If writing fails, the entries after the one that failed may have
//! drawn theirs, which one thread would not have: never in another order.
//!
//! What waits to be written is bounded: an entry is charged the most its
//! data can come to, encrypted, from when it is given to a thread until it
//! is written, and no more is given while that would pass
//! [`MEMORY_PER_THREAD`] for each thread. An entry that could take more than
//! all of it is compressed by the thread writing, as with one thread, while
//! the others go on with the entries after it.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::system_random;
use crate::threads::Threads;
use crate::workers::Workers;
use crate::zip::close::{needs, pkware_time, settle_methods};
use crate::zip::dirent::{Dirent, DosTime, cm_actual};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::get_encryption_implementation::Encrypt;
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::random::{RandomSource, secure_random};
use crate::zip::source::ReadAt;
use crate::zip::source_compress::{Compress, maximum_compressed_size};
use crate::zip::source_crc::Crc;
use crate::zip::source_data::{DataSource, FileAttributes};
use crate::zip::source_stack::{Base, Layer, WriteStack};
use crate::zip::zip::{Stat, cm, em, stat};
use crate::zip::zipint::{
    BUFSIZE, CRYPTO_PKWARE_HEADERLEN, HMAC_LENGTH, Password, WINZIP_AES_PASSWORD_VERIFY_LENGTH,
    salt_length,
};

/// What may wait to be written, for each thread: the most the entries given
/// to threads and not yet written can come to.
pub(crate) const MEMORY_PER_THREAD: u64 = 32 << 20;

/// What an entry is charged besides its data, for what is kept of it.
const ENTRY_COST: u64 = 1024;

#[cfg(test)]
thread_local! {
    /// [`MEMORY_PER_THREAD`], smaller for a test.
    static TEST_MEMORY: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    /// How many entries were written from what a thread made.
    static TAKEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// How many of those a thread encrypted.
    static ENCRYPTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
    /// Sets how many threads compress and encrypt new data when the archive
    /// is written ([`Archive::close_to`], [`Archive::close_to_stream`] and
    /// [`Archive::close_to_cloning`]): [`Threads::One`], the caller's, by
    /// default. libzip has no threads.
    ///
    /// With more, the entries added with
    /// [`file_add`](Archive::file_add) or [`file_replace`](Archive::file_replace)
    /// that are compressed are compressed in threads, each reading its
    /// source, and encrypted there if they are encrypted, ahead of the entry
    /// being written, while the caller's thread writes the entries in order.
    /// The random bytes encrypting takes (see
    /// [`set_random_source`](Archive::set_random_source)) are drawn on the
    /// caller's thread, in the order and the sizes one thread draws them, so
    /// the archive is the same, byte for byte, whatever this says, and so is
    /// an error and what was written before it; after an error, though, the
    /// entries after it may have drawn theirs. Each thread keeps its own
    /// compressor (deflate takes about 300 KiB, bzip2 7 MiB, LZMA and XZ at
    /// preset 6 94 MiB), and up to 32 MiB for each thread waits to be
    /// written, counted as the most each entry can come to. An entry that
    /// could take more than all of it, or whose source does not tell its
    /// size, is compressed and encrypted on the caller's thread when it is
    /// written, while the threads go on with the entries after it.
    /// Everything else is written as with one thread: entries stored,
    /// copied as they are, or compressed again from an entry of the archive.
    pub fn set_threads(&mut self, threads: Threads) {
        self.threads = threads;
    }
}

/// How a thread encrypts an entry.
struct Encryption {
    method: u16,
    password: Password,
    /// the time ZipCrypto's header ends with; none for WinZip AES
    dostime: Option<DosTime>,
    /// the random bytes drawn for it
    random: Arc<[u8]>,
}

/// How the entry is encrypted where it is written, to tell whether a thread
/// encrypted it so.
pub(crate) struct Encrypting<'a> {
    pub(crate) method: u16,
    pub(crate) password: Option<&'a [u8]>,
    /// the time ZipCrypto's header ends with ([`pkware_time`])
    pub(crate) dostime: Option<DosTime>,
    /// the random bytes drawn for it ahead
    pub(crate) drawn: Option<&'a Drawn>,
}

/// What a thread's work on an entry is for: it is taken only if the entry
/// is still to be compressed, and encrypted, so when it is written.
pub(crate) struct Key {
    source: Arc<dyn DataSource>,
    /// the method and level the compressing layer is made with
    method: i32,
    level: u32,
    /// the size of the first read of the compressing layer, which the
    /// encrypting layer, if the thread does not stack it, makes smaller by
    /// its header: with `ZIP_CM_DEFAULT`, it decides whether the data is
    /// stored
    first_read: usize,
    /// whether the compressing layer may not give way to storing
    keep_compressing: bool,
    /// how the thread encrypts it, if it does
    encryption: Option<Encryption>,
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

/// What the encrypting layer adds to the data: its header, and WinZip AES's
/// authentication code after it.
fn encryption_overhead(encryption_method: u16) -> Option<u64> {
    let header = encryption_header_length(encryption_method)? as u64;
    Some(match encryption_method {
        em::AES_128 | em::AES_192 | em::AES_256 => header + HMAC_LENGTH as u64,
        _ => header,
    })
}

/// What the stat and attributes under the encrypting layer said.
#[derive(Clone, Copy)]
pub(crate) struct Shown {
    pub(crate) stat: Result<Stat<'static>>,
    pub(crate) attributes: Result<FileAttributes>,
}

/// What a thread made of an entry's data: what reading the layers gave,
/// read again in the same order.
pub(crate) struct Precompressed {
    key: Key,
    /// what opening the layers gave
    open: Result<()>,
    data: Vec<u8>,
    /// how much of `data` is read
    position: usize,
    /// how the reading ended: at the end, or with an error
    end: Result<()>,
    /// what the stat and attributes under the encrypting layer said, from
    /// the read they changed in on
    shown: Vec<(u64, Shown)>,
    /// the reads made of the top of the layers
    reads: u64,
}

impl Precompressed {
    /// Whether this was made for the entry as it is compressed, with
    /// `method` and `level`, and encrypted, as `encrypting` says.
    pub(crate) fn fits(
        &self,
        source: &Arc<dyn DataSource>,
        method: i32,
        level: u32,
        encrypting: Option<Encrypting<'_>>,
        stream: bool,
    ) -> bool {
        let first_read = match (&self.key.encryption, &encrypting) {
            (None, _) => {
                let method = encrypting.as_ref().map_or(em::NONE, |e| e.method);
                let Some(header) = encryption_header_length(method) else {
                    return false;
                };
                BUFSIZE - header
            }
            (Some(mine), Some(theirs)) => {
                let same = mine.method == theirs.method
                    && theirs.password.map(c_string) == Some(&*mine.password)
                    && mine.dostime == theirs.dostime
                    && theirs.drawn.and_then(Drawn::bytes) == Some(&*mine.random);
                if !same {
                    return false;
                }
                BUFSIZE
            }
            (Some(_), None) => return false,
        };
        self.key.fits(&Key {
            source: Arc::clone(source),
            method,
            level,
            first_read,
            keep_compressing: stream && encrypting.is_some(),
            encryption: None,
        })
    }

    /// Whether the thread encrypted it: then it stands for the encrypting
    /// layer too.
    pub(crate) fn encrypted(&self) -> bool {
        self.key.encryption.is_some()
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) -> Result<()> {
        #[cfg(test)]
        {
            TAKEN.with(|taken| taken.set(taken.get() + 1));
            if self.encrypted() {
                ENCRYPTED.with(|n| n.set(n.get() + 1));
            }
        }
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

/// The random bytes drawn ahead for an entry, as many as encrypting it
/// draws when it is written: none if drawing them failed.
pub(crate) struct Drawn {
    len: usize,
    bytes: Option<Arc<[u8]>>,
}

impl Drawn {
    fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }

    /// What encrypting the entry draws from: these bytes, or their failure,
    /// for as many as were drawn; `random`, or the system without one, for
    /// another size, which a source that tells another stat when it is
    /// written than before would ask.
    pub(crate) fn source(&self, random: Option<&RandomSource>) -> RandomSource {
        let len = self.len;
        let bytes = self.bytes.clone();
        let random = random.cloned();
        Arc::new(move |buf: &mut [u8]| {
            if buf.len() != len {
                return match &random {
                    Some(random) => random(buf),
                    None => system_random(buf),
                };
            }
            match &bytes {
                Some(bytes) => {
                    buf.copy_from_slice(bytes);
                    Ok(())
                }
                None => Err(io::Error::other("the random bytes could not be drawn")),
            }
        })
    }
}

/// What threads made of an entry, and the random bytes drawn for it.
#[derive(Default)]
pub(crate) struct Taken {
    pub(crate) made: Option<Box<Precompressed>>,
    pub(crate) drawn: Option<Drawn>,
}

/// An entry for a thread to compress, and encrypt.
struct Job {
    key: Key,
    /// the most the data can come to: more, and the thread gives up
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

/// The encrypting layer of `encryption`, whose random bytes are those drawn
/// for it.
fn encrypt_layer(encryption: &Encryption) -> Option<Layer<Encrypt>> {
    let random = Arc::clone(&encryption.random);
    let random: RandomSource = Arc::new(move |buf: &mut [u8]| {
        if buf.len() != random.len() {
            return Err(io::Error::other("not the random bytes drawn"));
        }
        buf.copy_from_slice(&random);
        Ok(())
    });
    // The time is told, so the stat is not asked.
    let encrypt = Encrypt::new(
        encryption.method,
        Some(&encryption.password),
        encryption.dostime,
        || Err(Error::new(ErrorCode::Internal, 0)),
        Some(random),
    )
    .ok()?;
    Some(Layer::new(encrypt))
}

/// Reads the job's source through the layers `add_data` stacks, as it reads
/// them, and keeps what they give. Gives up, for the entry to be compressed
/// where it is written, if a layer cannot be made, the data comes to more
/// than it could, or the archive is no longer written.
fn compress(_: &mut (), job: Job) -> Made {
    let Job { key, most, stop } = job;
    let mut compress = Compress::new(key.method, key.level).ok()?;
    if key.keep_compressing {
        compress.keep_compressing();
    }
    let encrypt = match &key.encryption {
        Some(encryption) => Some(encrypt_layer(encryption)?),
        None => None,
    };
    let mut stack: WriteStack<'_, [u8]> = WriteStack {
        base: Base::data(Arc::clone(&key.source)),
        decrypt: None,
        decompress: None,
        crc: Some(Layer::new(Crc::new(false))),
        compress: Some(Layer::new(compress)),
        precompressed: None,
        encrypt,
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

/// The random bytes an entry draws when it is written, to encrypt it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Draw {
    Nothing,
    Bytes(usize),
    /// what it draws is told only when it is written
    Unknown,
}

/// An entry to write, as planned before the archive is written.
struct Planned {
    i: usize,
    draw: Draw,
    /// what a thread does with it, if one can
    job: Option<PlannedJob>,
}

struct PlannedJob {
    /// what a thread compresses, not encrypting it
    key: Key,
    /// the most it can come to, encrypted
    most: u64,
    /// how a thread can encrypt it, given its random bytes: the method, the
    /// password and the time ZipCrypto's header ends with
    encrypt: Option<(u16, Password, Option<DosTime>)>,
}

/// The entries given to threads, and those to give, in the order they are
/// written, and the random bytes drawn for them.
pub(crate) struct Ahead {
    workers: Workers<(), Job, Made>,
    random: Option<RandomSource>,
    /// the entries written, in order
    entries: Vec<Planned>,
    /// the next of `entries` to give a thread, to write, and to draw for:
    /// those before it drew theirs, or are written
    next_give: usize,
    next_write: usize,
    next_draw: usize,
    /// a draw failed: no more are drawn ahead
    failed: bool,
    /// the bytes drawn for entries not yet written, in order
    drawn: VecDeque<(usize, Drawn)>,
    /// entries given, with what each is charged
    given: VecDeque<(usize, u64)>,
    /// what the entries given are charged
    held: u64,
    budget: u64,
    stop: Arc<AtomicBool>,
}

impl Ahead {
    /// Draws the random bytes of the entries up to the `to`th of `entries`,
    /// in order, as far as what they draw is known, and stops after one
    /// fails: whether those of that one were drawn.
    fn draw_to(&mut self, to: usize) -> bool {
        while self.next_draw <= to && !self.failed {
            let Some(entry) = self.entries.get(self.next_draw) else {
                break;
            };
            match entry.draw {
                Draw::Nothing => {}
                // It draws its own when it is written.
                Draw::Unknown => break,
                Draw::Bytes(len) => {
                    let mut bytes = vec![0; len];
                    let drew = secure_random(self.random.as_ref(), &mut bytes);
                    self.failed = !drew;
                    let bytes = drew.then(|| Arc::from(bytes));
                    self.drawn.push_back((entry.i, Drawn { len, bytes }));
                }
            }
            self.next_draw += 1;
        }
        self.next_draw > to
    }

    /// Gives threads the entries planned, in order, while they fit, each
    /// to be encrypted there if its random bytes can be drawn.
    fn give(&mut self) {
        while let Some(entry) = self.entries.get(self.next_give) {
            let at = self.next_give;
            let i = entry.i;
            let Some(job) = &entry.job else {
                self.next_give += 1;
                continue;
            };
            let cost = job.most + ENTRY_COST;
            if self.held + cost > self.budget {
                break;
            }
            let random = match job.encrypt.is_some() && self.draw_to(at) {
                true => self
                    .drawn
                    .iter()
                    .rev()
                    .find(|(j, _)| *j == i)
                    .and_then(|(_, drawn)| drawn.bytes.clone()),
                false => None,
            };
            let Some(PlannedJob {
                mut key,
                most,
                encrypt,
            }) = self.entries[at].job.take()
            else {
                break;
            };
            if let (Some(random), Some((method, password, dostime))) = (random, encrypt) {
                // The thread reads the encrypting layer, which reads under
                // it what it reads with one thread.
                key.first_read = BUFSIZE;
                key.encryption = Some(Encryption {
                    method,
                    password,
                    dostime,
                    random,
                });
            }
            self.next_give += 1;
            self.held += cost;
            self.given.push_back((i, cost));
            self.workers.give(Job {
                key,
                most,
                stop: Arc::clone(&self.stop),
            });
        }
    }

    /// What threads made of entry `i`, the next written, if it was given
    /// one, waited for, and the random bytes drawn for it. The entries
    /// after it are given as they fit.
    pub(crate) fn take(&mut self, i: usize) -> Taken {
        let at = self.next_write;
        if self.entries.get(at).is_none_or(|entry| entry.i != i) {
            return Taken::default();
        }
        self.next_write = at + 1;
        // Those before it are written: one that drew its own is passed.
        self.next_draw = self.next_draw.max(at);
        self.draw_to(at);
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
        let drawn = match self.drawn.front() {
            Some(&(j, _)) if j == i => self.drawn.pop_front().map(|(_, drawn)| drawn),
            _ => None,
        };
        self.give();
        Taken { made, drawn }
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
        let entries: Vec<Planned> = written
            .iter()
            .map(|&i| {
                let mut planned = self.plan(i, stream);
                if planned
                    .job
                    .as_ref()
                    .is_some_and(|job| job.most + ENTRY_COST > budget)
                {
                    planned.job = None;
                }
                planned
            })
            .collect();
        if entries.iter().all(|planned| planned.job.is_none()) {
            return None;
        }
        Some(Ahead {
            workers: Workers::new(threads, "zip-compress", compress, lost),
            random: self.random.clone(),
            entries,
            next_give: 0,
            next_write: 0,
            next_draw: 0,
            failed: false,
            drawn: VecDeque::new(),
            given: VecDeque::new(),
            held: 0,
            budget,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// What writing entry `i` draws, and how a thread can compress and
    /// encrypt it, if it is new data that one can: what `write_entry` and
    /// `add_data` will decide, from the same dirent and stat. A thread's
    /// work is checked again then ([`Precompressed::fits`]).
    fn plan(&self, i: usize, stream: bool) -> Planned {
        let entry = &self.entry[i];
        let Some(source) = entry.source.as_ref() else {
            // Written again from the archive, or copied as it is.
            let draw = match self.new_data(i) {
                true => Draw::Unknown,
                false => Draw::Nothing,
            };
            return Planned { i, draw, job: None };
        };
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
        let Ok(mut st) = source.stat() else {
            // Writing it fails before it draws.
            return Planned {
                i,
                draw: Draw::Unknown,
                job: None,
            };
        };
        settle_methods(&mut st, &mut de);
        let encrypts = needs(&st, &de, self.want_torrentzip()).encrypt;
        let password = de.password.as_deref().or(self.default_password.as_deref());
        // Without a password, or a method it has, it fails before it draws.
        let draw = match (encrypts, de.encryption_method, password) {
            (true, em::TRAD_PKWARE, Some(_)) => Draw::Bytes(CRYPTO_PKWARE_HEADERLEN - 1),
            (true, method @ (em::AES_128 | em::AES_192 | em::AES_256), Some(_)) => {
                Draw::Bytes(salt_length(method))
            }
            _ => Draw::Nothing,
        };
        let job = (|| {
            if st.comp_method != cm::STORE
                || st.encryption_method != em::NONE
                || st.valid & stat::SIZE == 0
            {
                return None;
            }
            let method = cm_actual(de.comp_method);
            if method == cm::STORE {
                return None;
            }
            let encryption_method = match encrypts {
                true => de.encryption_method,
                false => em::NONE,
            };
            let header = encryption_header_length(encryption_method)?;
            let most = maximum_compressed_size(method, st.size)?
                .checked_add(encryption_overhead(encryption_method)?)?;
            let encrypt = match (draw, password) {
                (Draw::Bytes(_), Some(password)) => match encryption_method {
                    // Its header ends with a time, which must not be now.
                    em::TRAD_PKWARE => pkware_time(&de, &st)
                        .map(|time| (encryption_method, Password::new(password), Some(time))),
                    _ => Some((encryption_method, Password::new(password), None)),
                },
                _ => None,
            };
            let key = Key {
                source: Arc::clone(source),
                method: de.comp_method,
                level: de.compression_level,
                first_read: BUFSIZE - header,
                keep_compressing: stream && encrypts,
                encryption: None,
            };
            Some(PlannedJob { key, most, encrypt })
        })();
        Planned { i, draw, job }
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
        let (bytes, taken, _) = write_encrypted(sizes, threads, memory, stream, em::NONE);
        (bytes, taken)
    }

    /// As [`write`], each entry encrypted with `encryption`: also how many
    /// a thread encrypted.
    fn write_encrypted(
        sizes: &[usize],
        threads: Threads,
        memory: u64,
        stream: bool,
        encryption: u16,
    ) -> (Vec<u8>, usize, usize) {
        TEST_MEMORY.with(|m| m.set(Some(memory)));
        TAKEN.with(|taken| taken.set(0));
        ENCRYPTED.with(|n| n.set(0));
        let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
        archive.set_threads(threads);
        let next = Arc::new(std::sync::atomic::AtomicU8::new(0));
        archive.set_random_source(Some(Arc::new(move |buf: &mut [u8]| {
            buf.fill(next.fetch_add(1, Ordering::Relaxed));
            Ok(())
        })));
        for (i, &n) in sizes.iter().enumerate() {
            let data = text(i as u64, n);
            archive
                .file_add(
                    format!("{i}").as_bytes(),
                    BufferSource::with_mtime(data, 1_700_000_000),
                    Flags::NONE,
                )
                .unwrap();
            if encryption != em::NONE {
                archive
                    .file_set_encryption(i as u64, encryption, Some(b"pw"))
                    .unwrap();
            }
        }
        let mut out = Cursor::new(Vec::new());
        if stream {
            archive.close_to_stream(&mut out).unwrap();
        } else {
            archive.close_to(&mut out).unwrap();
        }
        TEST_MEMORY.with(|m| m.set(None));
        (
            out.into_inner(),
            TAKEN.with(std::cell::Cell::get),
            ENCRYPTED.with(std::cell::Cell::get),
        )
    }

    /// Encrypted entries larger than the threads may hold, charged with what
    /// encrypting adds, are encrypted where they are written, with the bytes
    /// drawn for them ahead; the threads encrypt every other one, and the
    /// archive is the same.
    #[test]
    fn encrypted_larger_than_the_budget() {
        let mut sizes = vec![300_000, 0, 1];
        sizes.extend((0..30).map(|i| 1000 + i * 1500));
        sizes.push(250_000);
        sizes.extend((0..10).map(|i| 30_000 + i));
        sizes.push(140_000);
        let two = Threads::Exactly(NonZeroU32::new(2).unwrap());
        for encryption in [em::AES_128, em::AES_256, em::TRAD_PKWARE] {
            let overhead = encryption_overhead(encryption).unwrap();
            for stream in [false, true] {
                let (one, taken, _) =
                    write_encrypted(&sizes, Threads::One, 64 << 10, stream, encryption);
                assert_eq!(taken, 0);
                for memory in [64 << 10, 36 << 10, 1 << 30] {
                    let (got, taken, encrypted) =
                        write_encrypted(&sizes, two, memory, stream, encryption);
                    assert!(got == one, "{encryption}, {memory}: bytes differ");
                    let large = sizes
                        .iter()
                        .filter(|&&n| {
                            maximum_compressed_size(cm::DEFLATE, n as u64).unwrap()
                                + overhead
                                + ENTRY_COST
                                > 2 * memory
                        })
                        .count();
                    assert_eq!(taken, sizes.len() - large, "{encryption}, {memory}");
                    assert_eq!(encrypted, taken, "{encryption}, {memory}");
                }
            }
        }
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
                encryption: None,
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
