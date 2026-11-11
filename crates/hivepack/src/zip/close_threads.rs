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
//! An entry deflated by libdeflate's compressor in blocks
//! ([`Archive::set_deflate_library`] and [`Archive::set_deflate_in_blocks`]),
//! of more than one block, is given to the threads a block at a time
//! instead ([`compress_block`]): each thread reads its block as the layers
//! read it with one thread, compresses it as `DeflateMt` does, alone, and
//! takes its CRC-32. The thread writing waits for all of an entry's blocks,
//! then joins them, and their CRC-32s, into what the CRC and compressing
//! layers give with one thread ([`Joined`]), which stands for them as what a
//! thread read does; the encrypting layer, if there is one, stays where it
//! is written. If a block's data does not read as its source's stat says,
//! failing, ending before it or going on after it, the entry is compressed
//! where it is written, as one thread compresses it, its blocks one after
//! the other: what it writes, and its error, are that thread's.
//!
//! Encrypting draws random bytes when it starts, a salt for WinZip AES and
//! 11 bytes of header for ZipCrypto, and with one thread each entry draws
//! them as it is written, one after the other. With more, the thread writing
//! draws them ahead, in the same order and as many: before an entry is given
//! to a thread to encrypt, those of every entry before it are drawn, and
//! those of the entries the threads do not encrypt (too large for them, not
//! compressed, in blocks, or not taken) are kept for them, to be taken in
//! place of drawing when each is written ([`Drawn`]). What each entry draws
//! is told before the archive is written ([`Draw`]), but for one written
//! again from an entry of the archive: none is drawn past one of those
//! until it is written, and drawing itself then, it keeps the order; the
//! entries given to threads meanwhile are encrypted on the thread writing.
//! Nothing else draws. If writing fails, the entries after the one that
//! failed may have drawn theirs, which one thread would not have: never in
//! another order.
//!
//! What waits to be written is bounded: an entry is charged the most its
//! data can come to, encrypted, from when it is given to a thread until it
//! is written, and no more is given while that would pass
//! [`MEMORY_PER_THREAD`] for each thread. An entry in blocks is charged the
//! most each block can come to, from when the block is given until the
//! entry is written. An entry that could take more than all of it is
//! compressed by the thread writing, as with one thread, while the others
//! go on with the entries after it.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::system_random;
use crate::deflate::{Compressor, Library, crc32, crc32_combine, libdeflate_block};
use crate::threads::Threads;
use crate::workers::Workers;
use crate::zip::algorithm_deflate::{self, Deflating};
use crate::zip::close::{needs, pkware_time, settle_methods};
use crate::zip::dirent::{Dirent, DosTime, cm_actual};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::get_encryption_implementation::Encrypt;
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::random::{RandomSource, secure_random};
use crate::zip::source::ReadAt;
use crate::zip::source_compress::{self, Compress, maximum_compressed_size, stat_compressed};
use crate::zip::source_crc::{Crc, stat_complete};
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
    /// How many of those were blocks compressed in threads, joined.
    static JOINED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

    /// Sets whether new data is deflated in blocks, as pigz does, when the
    /// archive is written: off by default, as libzip deflates, one zlib
    /// stream for each entry. libzip has no such thing.
    ///
    /// On, each deflated entry of new data is one raw deflate stream of
    /// blocks of 128 KiB, each compressed with the 32 KiB before it as its
    /// dictionary ([`DeflateMt`](crate::deflate::DeflateMt)), which every
    /// ZIP reader reads, and no larger: 3 GB of programs at level 6 is
    /// 0.05% smaller. An entry the threads of [`set_threads`] would compress
    /// one each, and that could take more than 32 MiB, is compressed where
    /// it is written, its blocks in all of them: one large file is deflated
    /// on every core, where it was on one. With libdeflate's compressor
    /// ([`set_deflate_library`]), whose blocks take no dictionary, an entry
    /// of more than one block is given to the threads a block at a time
    /// instead, as long as all its blocks fit what they may hold. The
    /// archive is the same, byte for byte, whatever the threads. Not for
    /// torrentzip, whose streams are zlib's.
    ///
    /// [`set_threads`]: Archive::set_threads
    /// [`set_deflate_library`]: Archive::set_deflate_library
    pub fn set_deflate_in_blocks(&mut self, blocks: bool) {
        self.deflate_blocks = blocks;
    }

    /// Sets whose compressor deflates new data when the archive is written:
    /// [`Library::Zlib`] by default, as libzip deflates. libzip has no
    /// other.
    ///
    /// With [`Library::Libdeflate`], each deflated entry of new data is
    /// compressed by libdeflate's compressor
    /// ([`Compressor`](crate::deflate::Compressor)), whose levels 10 to 12
    /// make smaller entries than zlib's 9. An entry's level
    /// ([`file_set_compression`]) is then 1 to 12, and 0 or another is 9,
    /// as for zlib; its general purpose bits say fast below 3 and maximum
    /// from 8 up, as for zlib. libdeflate compresses a whole buffer at a
    /// time, so each entry is cut into blocks, compressed alone and joined
    /// into one deflate stream that every ZIP reader reads
    /// ([`DeflateMt`](crate::deflate::DeflateMt) with
    /// [`Library::Libdeflate`]): in the threads of [`set_threads`] if
    /// [`set_deflate_in_blocks`] is on, each block of an entry in any of
    /// them, else in the thread that compresses the entry. The blocks are
    /// of 1, 2 or 4 MiB, the largest that still cuts the entry into 32 or
    /// more, as the size its source tells before it is read says, 1 MiB if
    /// it tells none
    /// ([`libdeflate_block_size`](crate::deflate::libdeflate_block_size));
    /// an entry no larger than its block is one call. They depend on the
    /// size alone, never on the threads or the machine, so the archive is
    /// the same, byte for byte, whatever the threads, and whether in blocks
    /// or not. Each thread keeps libdeflate's compressor (0.2 MB at level
    /// 1, 0.7 MB at 2 to 9 and 9 MB at 10 to 12) and two blocks of up to
    /// 4 MiB, each with room for what it compresses to. Not for
    /// torrentzip, whose streams are zlib's.
    ///
    /// [`file_set_compression`]: Archive::set_file_compression
    /// [`set_threads`]: Archive::set_threads
    /// [`set_deflate_in_blocks`]: Archive::set_deflate_in_blocks
    pub fn set_deflate_library(&mut self, library: Library) {
        self.deflate_library = library;
    }

    /// How new data is deflated where it is written: in blocks in which
    /// threads, if it is, and whose compressor.
    pub(crate) fn deflating(&self) -> Deflating {
        Deflating {
            blocks: self.deflate_blocks.then_some(self.threads),
            library: self.deflate_library,
            block_size: 0,
        }
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
    /// whether deflate is in blocks, which the thread compresses alone
    blocks: bool,
    /// whose compressor deflates, and libdeflate's blocks
    library: Library,
    block_size: usize,
}

impl Key {
    fn fits(&self, other: &Key) -> bool {
        Arc::ptr_eq(&self.source, &other.source)
            && self.method == other.method
            && self.level == other.level
            && self.first_read == other.first_read
            && self.keep_compressing == other.keep_compressing
            && self.blocks == other.blocks
            && self.library == other.library
            && self.block_size == other.block_size
    }

    /// How the thread deflates it: in blocks one after the other, if it
    /// does.
    fn deflating(&self) -> Deflating {
        Deflating {
            blocks: self.blocks.then_some(Threads::One),
            library: self.library,
            block_size: self.block_size,
        }
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Shown {
    pub(crate) stat: Result<Stat<'static>>,
    pub(crate) attributes: Result<FileAttributes>,
}

/// What a thread made of an entry's data: what reading the layers gave,
/// read again in the same order, or its blocks joined.
pub(crate) struct Precompressed {
    key: Key,
    data: Data,
}

/// What stands for the layers.
enum Data {
    Read(Read),
    Joined(Joined),
}

/// What reading the layers gave in a thread.
struct Read {
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

/// An entry's blocks, each compressed by a thread ([`compress_block`]),
/// joined: the stream the compressing layer gives with one thread, and what
/// the CRC and compressing layers say as it is read.
///
/// With one thread, the compressing layer reads the data in pieces of
/// [`source_compress::BUFSIZE`] as its stream needs them, compresses a
/// block once a byte past it is read, and reads its stream out before it
/// reads more. The CRC is complete with the piece the data ends in. Where
/// the last block is a piece or more, that piece is read once the stream of
/// every block before the last is read out; where it is shorter, it is the
/// last block's first piece, read once the stream of every block before
/// the last but one is. A read that takes the stream past that point reads
/// the end of the data, and the one that takes its last byte ends the
/// stream.
struct Joined {
    blocks: Vec<Vec<u8>>,
    /// the block read next, and how much of it is read
    block: usize,
    in_block: usize,
    /// how much of the stream is read
    position: u64,
    /// the data's size and CRC-32
    size: u64,
    crc: u32,
    /// how much of the stream is read before the end of the data is
    crc_after: u64,
    /// the stream's size
    len: u64,
    /// the compressing layer's attributes
    attributes: FileAttributes,
}

impl Joined {
    /// The blocks `made` of data cut as `blocks` says, more than one, in
    /// order; `attributes` are the compressing layer's.
    fn new(blocks: Blocks, made: Vec<Block>, attributes: FileAttributes) -> Joined {
        let mut crc = 0;
        for (k, block) in made.iter().enumerate() {
            crc = crc32_combine(crc, block.crc, blocks.len(k as u64) as i64);
        }
        // The blocks whose stream is read out before the end of the data.
        let count = made.len();
        let last = blocks.len(count as u64 - 1);
        let before = if last < source_compress::BUFSIZE {
            count.saturating_sub(2)
        } else {
            count - 1
        };
        let stream = |blocks: &[Block]| blocks.iter().map(|b| b.bytes.len() as u64).sum();
        Joined {
            crc_after: stream(&made[..before]),
            len: stream(&made),
            blocks: made.into_iter().map(|block| block.bytes).collect(),
            block: 0,
            in_block: 0,
            position: 0,
            size: blocks.size,
            crc,
            attributes,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n < buf.len() {
            let Some(block) = self.blocks.get(self.block) else {
                break;
            };
            let rest = &block[self.in_block..];
            if rest.is_empty() {
                self.block += 1;
                self.in_block = 0;
                continue;
            }
            let m = rest.len().min(buf.len() - n);
            buf[n..n + m].copy_from_slice(&rest[..m]);
            n += m;
            self.in_block += m;
        }
        self.position += n as u64;
        n
    }

    /// What the stat and attributes under the encrypting layer say, on
    /// those of `source`, the data.
    fn shown(&self, source: &dyn DataSource, method: u16) -> Shown {
        let stat = source.stat().and_then(|mut st| {
            if self.position > self.crc_after {
                stat_complete(&mut st, self.size, self.crc)?;
            }
            let ended = self.position >= self.len;
            stat_compressed(&mut st, ended.then_some((method, self.len)));
            Ok(st)
        });
        let attributes = source.file_attributes().map(|lower| {
            let mut attributes = self.attributes;
            attributes.merge_lower(&lower);
            attributes
        });
        Shown { stat, attributes }
    }
}

impl Precompressed {
    /// Whether this was made for the entry as it is compressed, with
    /// `method` and `level`, deflated as `deflating` says, and encrypted, as
    /// `encrypting` says.
    pub(crate) fn fits(
        &self,
        source: &Arc<dyn DataSource>,
        method: i32,
        level: u32,
        deflating: Deflating,
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
        let deflating = deflating.for_flags(level);
        self.key.fits(&Key {
            source: Arc::clone(source),
            method,
            level,
            first_read,
            keep_compressing: stream && encrypting.is_some(),
            encryption: None,
            blocks: deflating.blocks.is_some(),
            library: deflating.library,
            block_size: deflating.libdeflate_block_size(),
        })
    }

    /// Whether the thread encrypted it: then it stands for the encrypting
    /// layer too.
    pub(crate) fn encrypted(&self) -> bool {
        self.key.encryption.is_some()
    }

    /// `ZIP_SOURCE_OPEN`. For blocks joined, what opening the layers does
    /// with one thread: the compressing layer asks for the stat and
    /// attributes of the data.
    pub(crate) fn open(&mut self) -> Result<()> {
        #[cfg(test)]
        {
            TAKEN.with(|taken| taken.set(taken.get() + 1));
            if self.encrypted() {
                ENCRYPTED.with(|n| n.set(n.get() + 1));
            }
            if matches!(self.data, Data::Joined(_)) {
                JOINED.with(|n| n.set(n.get() + 1));
            }
        }
        match &mut self.data {
            Data::Read(read) => {
                read.position = 0;
                read.reads = 0;
                read.open
            }
            Data::Joined(joined) => {
                joined.block = 0;
                joined.in_block = 0;
                joined.position = 0;
                let source = &self.key.source;
                source.stat()?;
                source.file_attributes()?;
                Ok(())
            }
        }
    }

    /// Counts a read of the top of the layers.
    pub(crate) fn count_read(&mut self) {
        if let Data::Read(read) = &mut self.data {
            read.reads += 1;
        }
    }

    /// `ZIP_SOURCE_READ`: the data, then its end.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = match &mut self.data {
            Data::Read(read) => read,
            Data::Joined(joined) => return Ok(joined.read(buf)),
        };
        let rest = &read.data[read.position..];
        if rest.is_empty() {
            return read.end.map(|()| 0);
        }
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        read.position += n;
        Ok(n)
    }

    /// What the stat and attributes said after the reads made so far.
    pub(crate) fn shown(&self) -> Shown {
        match &self.data {
            Data::Read(read) => {
                let at = read
                    .shown
                    .partition_point(|(reads, _)| *reads <= read.reads);
                // The first is from before any read.
                read.shown[at.saturating_sub(1)].1
            }
            Data::Joined(joined) => joined.shown(&*self.key.source, cm_actual(self.key.method)),
        }
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
    /// Its blocks did not read as its source's stat says: it is compressed
    /// where it is written as one thread compresses it, its blocks one
    /// after the other ([`Deflating::alone`]), so that what is written, and
    /// the error, are that thread's.
    pub(crate) alone: bool,
}

/// How an entry's data is cut into libdeflate's blocks, each compressed by a
/// thread: as `DeflateMt` cuts it with one thread, by the size its source
/// tells.
#[derive(Clone, Copy, Debug)]
struct Blocks {
    /// the data's size
    size: u64,
    /// the input of each block, whole pieces the compressing layer reads
    block: usize,
    /// libdeflate's level
    level: i32,
}

impl Blocks {
    fn count(&self) -> u64 {
        self.size.div_ceil(self.block as u64)
    }

    /// The input of block `k`.
    fn len(&self, k: u64) -> usize {
        (self.size - k * self.block as u64).min(self.block as u64) as usize
    }

    /// The most block `k` can come to: libdeflate's bound for a part.
    fn most(&self, k: u64) -> u64 {
        Compressor::part_bound(self.len(k)) as u64
    }

    /// The most all the blocks can come to.
    fn total(&self) -> u64 {
        let full = self.size / self.block as u64;
        let mut most = full.saturating_mul(self.most(0));
        if !self.size.is_multiple_of(self.block as u64) {
            most = most.saturating_add(self.most(full));
        }
        most
    }
}

/// A block compressed, and the CRC-32 of its input.
struct Block {
    bytes: Vec<u8>,
    crc: u32,
}

/// What a thread does: an entry, through the layers, or a block of one.
enum Job {
    Entry {
        key: Key,
        /// the most the data can come to: more, and the thread gives up
        most: u64,
        stop: Arc<AtomicBool>,
    },
    Block {
        source: Arc<dyn DataSource>,
        blocks: Blocks,
        /// which block
        k: u64,
        stop: Arc<AtomicBool>,
    },
}

/// What a thread gives: none if it gave up.
enum Done {
    Entry(Option<Box<Precompressed>>),
    Block(Option<Block>),
    /// The thread failed.
    Lost,
}

fn lost() -> Done {
    Done::Lost
}

/// What a thread keeps from one job to the next: the input of a block, read
/// into it.
#[derive(Default)]
struct Worker {
    input: Vec<u8>,
}

fn work(worker: &mut Worker, job: Job) -> Done {
    match job {
        Job::Entry { key, most, stop } => Done::Entry(compress(key, most, &stop)),
        Job::Block {
            source,
            blocks,
            k,
            stop,
        } => Done::Block(compress_block(worker, &*source, blocks, k, &stop)),
    }
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

/// Reads the source of `key` through the layers `add_data` stacks, as it
/// reads them, and keeps what they give. Gives up, for the entry to be
/// compressed where it is written, if a layer cannot be made, the data
/// comes to more than `most`, or the archive is no longer written (`stop`).
fn compress(key: Key, most: u64, stop: &AtomicBool) -> Option<Box<Precompressed>> {
    let mut compress = Compress::new(key.method, key.level, key.deflating()).ok()?;
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
        data: Data::Read(Read {
            open,
            data,
            position: 0,
            end,
            shown: shows,
            reads: 0,
        }),
    }))
}

/// Block `k` of `source`'s data cut as `blocks` says, read as the layers
/// read it with one thread and compressed as `DeflateMt` compresses it,
/// with the CRC-32 of its input. Gives up if the data does not read as the
/// stat says there, failing, ending or going on, which the thread writing
/// finds again, or if the archive is no longer written (`stop`).
fn compress_block(
    worker: &mut Worker,
    source: &dyn DataSource,
    blocks: Blocks,
    k: u64,
    stop: &AtomicBool,
) -> Option<Block> {
    const PIECE: usize = source_compress::BUFSIZE;
    let len = blocks.len(k);
    let last = k + 1 == blocks.count();
    // The compressing layer reads the data in pieces from its start, each
    // until it is full, the data ends or a read fails: a block is whole
    // pieces, and the last is read to the piece the data ends in, the one
    // after it if it ends with a piece.
    let room = if last { (len / PIECE + 1) * PIECE } else { len };
    if worker.input.len() < room {
        worker.input.resize(room, 0);
    }
    let start = k * blocks.block as u64;
    let mut read = 0;
    let mut ended = false;
    for piece in worker.input[..room].chunks_mut(PIECE) {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let mut filled = 0;
        while filled < piece.len() {
            let at = start + (read + filled) as u64;
            let n = source.read_at(at, &mut piece[filled..]).ok()?;
            if n == 0 {
                ended = true;
                break;
            }
            if n > piece.len() - filled {
                return None;
            }
            filled += n;
        }
        read += filled;
        if ended {
            break;
        }
    }
    // Every block but the last has data after it; the last ends with it.
    if read != len || ended != last || stop.load(Ordering::Relaxed) {
        return None;
    }
    let input = &worker.input[..len];
    let bytes = libdeflate_block(blocks.level, input, last).ok()?;
    Some(Block {
        bytes,
        crc: crc32(0, input),
    })
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
    /// its blocks, each given to a thread, if it is in libdeflate's blocks
    /// and more than one: then it is encrypted where it is written
    blocks: Option<Blocks>,
}

/// The entries given to threads, and those to give, in the order they are
/// written, and the random bytes drawn for them.
pub(crate) struct Ahead {
    workers: Workers<Worker, Job, Done>,
    random: Option<RandomSource>,
    /// the entries written, in order
    entries: Vec<Planned>,
    /// the next of `entries` to give a thread, to write, and to draw for:
    /// those before it drew theirs, or are written
    next_give: usize,
    next_write: usize,
    next_draw: usize,
    /// the next block to give of the entry `next_give` is at, if it is in
    /// blocks
    next_block: u64,
    /// a draw failed: no more are drawn ahead
    failed: bool,
    /// the bytes drawn for entries not yet written, in order
    drawn: VecDeque<(usize, Drawn)>,
    /// the jobs given, the entry of each and what it is charged
    given: VecDeque<(usize, u64)>,
    /// what the jobs given are charged
    held: u64,
    budget: u64,
    /// what the entry in blocks being written is charged, until it is
    writing: u64,
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
    /// to be encrypted there if its random bytes can be drawn; an entry in
    /// blocks a block at a time.
    fn give(&mut self) {
        while let Some(entry) = self.entries.get(self.next_give) {
            let at = self.next_give;
            let i = entry.i;
            let Some(job) = &entry.job else {
                self.next_give += 1;
                continue;
            };
            if let Some(blocks) = job.blocks {
                let source = Arc::clone(&job.key.source);
                if !self.give_blocks(i, &source, blocks) {
                    break;
                }
                self.next_give += 1;
                continue;
            }
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
                ..
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
            self.workers.give(Job::Entry {
                key,
                most,
                stop: Arc::clone(&self.stop),
            });
        }
    }

    /// Gives threads the blocks of entry `i` not yet given, in order, while
    /// they fit: whether all are given.
    fn give_blocks(&mut self, i: usize, source: &Arc<dyn DataSource>, blocks: Blocks) -> bool {
        while self.next_block < blocks.count() {
            let k = self.next_block;
            // What is kept of the entry is charged with its first block.
            let cost = blocks.most(k) + if k == 0 { ENTRY_COST } else { 0 };
            if self.held + cost > self.budget {
                return false;
            }
            self.next_block += 1;
            self.held += cost;
            self.given.push_back((i, cost));
            self.workers.give(Job::Block {
                source: Arc::clone(source),
                blocks,
                k,
                stop: Arc::clone(&self.stop),
            });
        }
        self.next_block = 0;
        true
    }

    /// What threads made of entry `i`, the next written, if it was given
    /// one, waited for, and the random bytes drawn for it. The entries
    /// after it are given as they fit.
    pub(crate) fn take(&mut self, i: usize) -> Taken {
        // The entry in blocks taken before is written.
        self.held -= std::mem::take(&mut self.writing);
        let at = self.next_write;
        if self.entries.get(at).is_none_or(|entry| entry.i != i) {
            return Taken::default();
        }
        self.next_write = at + 1;
        // Those before it are written: one that drew its own is passed.
        self.next_draw = self.next_draw.max(at);
        self.draw_to(at);
        self.give();
        let blocks = self.entries[at].job.as_ref().and_then(|job| job.blocks);
        let (made, alone) = match blocks {
            Some(blocks) => self.take_blocks(at, blocks),
            None => match self.given.front() {
                Some(&(j, cost)) if j == i => {
                    self.given.pop_front();
                    let made = match self.workers.take() {
                        Some(Done::Entry(made)) => made,
                        _ => None,
                    };
                    self.held -= cost;
                    (made, false)
                }
                _ => (None, false),
            },
        };
        let drawn = match self.drawn.front() {
            Some(&(j, _)) if j == i => self.drawn.pop_front().map(|(_, drawn)| drawn),
            _ => None,
        };
        self.give();
        Taken { made, drawn, alone }
    }

    /// The blocks of the `at`th entry, the next written, waited for, the
    /// rest of them given, and joined: none if a block's data did not read
    /// as its stat says, and then it is to be compressed alone. They stay
    /// charged until it is written.
    fn take_blocks(&mut self, at: usize, blocks: Blocks) -> (Option<Box<Precompressed>>, bool) {
        let i = self.entries[at].i;
        let mut made = Vec::with_capacity(blocks.count() as usize);
        let mut read = true;
        loop {
            match self.given.front() {
                Some(&(j, cost)) if j == i => {
                    self.given.pop_front();
                    self.writing += cost;
                    match self.workers.take() {
                        Some(Done::Block(Some(block))) => made.push(block),
                        _ => read = false,
                    }
                }
                // The rest fit, as all its blocks do and nothing else is
                // held but them.
                _ if self.next_give == at => {
                    let given = self.given.len();
                    self.give();
                    if self.given.len() == given {
                        self.next_give += 1;
                        self.next_block = 0;
                        read = false;
                    }
                }
                _ => break,
            }
        }
        let key = match self.entries[at].job.take() {
            Some(job) if read && made.len() as u64 == blocks.count() => job.key,
            _ => return (None, true),
        };
        let attributes = match Compress::new(key.method, key.level, key.deflating()) {
            Ok(compress) => compress.file_attributes(),
            Err(_) => return (None, true),
        };
        let data = Data::Joined(Joined::new(blocks, made, attributes));
        (Some(Box::new(Precompressed { key, data })), false)
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
                let large = planned.job.as_ref().is_some_and(|job| match job.blocks {
                    // All its blocks wait for the last.
                    Some(blocks) => blocks.total() + ENTRY_COST > budget,
                    None => {
                        job.most + ENTRY_COST > budget
                            // Deflated in blocks where it is written, in all
                            // the threads.
                            || (job.key.blocks
                                && cm_actual(job.key.method) == cm::DEFLATE
                                && job.most > memory_per_thread())
                    }
                });
                if large {
                    planned.job = None;
                }
                planned
            })
            .collect();
        if entries.iter().all(|planned| planned.job.is_none()) {
            return None;
        }
        Some(Ahead {
            workers: Workers::new(threads, "zip-compress", work, lost),
            random: self.random.clone(),
            entries,
            next_give: 0,
            next_write: 0,
            next_draw: 0,
            next_block: 0,
            failed: false,
            drawn: VecDeque::new(),
            given: VecDeque::new(),
            held: 0,
            budget,
            writing: 0,
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
            let deflating = self
                .deflating()
                .for_flags(de.compression_level)
                .with_size(Some(st.size));
            let most = maximum_compressed_size(method, st.size, deflating.library)?
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
            let block = deflating.libdeflate_block_size();
            let blocks = (method == cm::DEFLATE
                && deflating.blocks.is_some()
                && deflating.library == Library::Libdeflate
                && block > 0
                && block.is_multiple_of(source_compress::BUFSIZE)
                && st.size > block as u64)
                .then(|| Blocks {
                    size: st.size,
                    block,
                    level: algorithm_deflate::level(de.compression_level, deflating.library),
                });
            let key = Key {
                source: Arc::clone(source),
                method: de.comp_method,
                level: de.compression_level,
                first_read: BUFSIZE - header,
                keep_compressing: stream && encrypts,
                encryption: None,
                blocks: deflating.blocks.is_some(),
                library: deflating.library,
                block_size: block,
            };
            Some(PlannedJob {
                key,
                most,
                encrypt,
                blocks,
            })
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
                            maximum_compressed_size(cm::DEFLATE, n as u64, Library::Zlib).unwrap()
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
                        maximum_compressed_size(cm::DEFLATE, n as u64, Library::Zlib).unwrap()
                            + ENTRY_COST
                            > 2 * memory
                    })
                    .count();
                assert_eq!(taken, sizes.len() - large, "{memory}");
            }
        }
    }

    /// With libdeflate's compressor, entries are compressed in the threads
    /// ahead, and taken, and the archive is the same; in blocks, those of
    /// more than one a block in each thread, joined, but for those larger
    /// than all the threads hold, compressed where they are written.
    #[test]
    fn libdeflate_in_threads() {
        let sizes = [0, 1, 70_000, 3 << 20, 20_000, (1 << 20) + 1, 5];
        let write = |threads: Threads, blocks: bool, memory: u64| {
            TEST_MEMORY.with(|m| m.set(Some(memory)));
            TAKEN.with(|taken| taken.set(0));
            JOINED.with(|n| n.set(0));
            let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
            archive.set_threads(threads);
            archive.set_deflate_library(Library::Libdeflate);
            archive.set_deflate_in_blocks(blocks);
            for (i, &n) in sizes.iter().enumerate() {
                archive
                    .file_add(
                        format!("{i}").as_bytes(),
                        BufferSource::with_mtime(text(i as u64, n), 1_700_000_000),
                        Flags::NONE,
                    )
                    .unwrap();
                archive
                    .set_file_compression(i as u64, i32::from(cm::DEFLATE), 12)
                    .unwrap();
            }
            let mut out = Cursor::new(Vec::new());
            archive.close_to(&mut out).unwrap();
            TEST_MEMORY.with(|m| m.set(None));
            (
                out.into_inner(),
                TAKEN.with(std::cell::Cell::get),
                JOINED.with(std::cell::Cell::get),
            )
        };
        let (one, taken, _) = write(Threads::One, false, 2 << 20);
        assert_eq!(taken, 0);
        let two = Threads::Exactly(NonZeroU32::new(2).unwrap());
        for (blocks, memory, large, joined) in [
            (false, 2 << 20, 0, 0),
            // The two of more than 1 MiB, in blocks.
            (true, 2 << 20, 0, 2),
            // The one of 3 MiB, more than the 2 MiB of both threads, is
            // compressed where it is written, in both.
            (true, 1 << 20, 1, 1),
        ] {
            let what = format!("in blocks {blocks}, {memory}");
            let got = write(two, blocks, memory);
            assert!(got.0 == one, "{what}: bytes differ");
            assert_eq!(got.1, sizes.len() - large, "{what}");
            assert_eq!(got.2, joined, "{what}");
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
                blocks: false,
                library: Library::Zlib,
                block_size: 0,
            },
            data: Data::Read(Read {
                open: Ok(()),
                data: b"abc".to_vec(),
                position: 0,
                end: Ok(()),
                shown: vec![(0, show(0)), (2, show(2)), (5, show(5))],
                reads: 0,
            }),
        };
        let size = |made: &Precompressed| made.shown().stat.unwrap().size;
        assert_eq!(size(&made), 0);
        for (reads, want) in [(1, 0), (2, 2), (3, 2), (4, 2), (5, 5), (9, 5)] {
            while matches!(&made.data, Data::Read(read) if read.reads < reads) {
                made.count_read();
            }
            assert_eq!(size(&made), want, "{reads}");
        }
        let mut buf = [0; 2];
        assert_eq!(made.read(&mut buf), Ok(2));
        assert_eq!(made.read(&mut buf), Ok(1));
        assert_eq!(made.read(&mut buf), Ok(0));
    }

    /// Bytes that do not compress.
    fn noise(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// A source whose stat tells `said` bytes, whatever its data, and that
    /// fails once `fail_at` bytes are read, what comes before first.
    struct Odd {
        data: Arc<[u8]>,
        said: u64,
        fail_at: Option<u64>,
    }

    impl Odd {
        fn new(data: Vec<u8>) -> Odd {
            Odd {
                said: data.len() as u64,
                data: data.into(),
                fail_at: None,
            }
        }
    }

    impl DataSource for Odd {
        fn stat(&self) -> Result<Stat<'static>> {
            Ok(Stat {
                valid: stat::SIZE | stat::MTIME,
                size: self.said,
                mtime: 1_700_000_000,
                ..Stat::default()
            })
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            if let Some(at) = self.fail_at
                && offset + buf.len() as u64 > at
            {
                if offset < at {
                    let n = (at - offset) as usize;
                    buf[..n].copy_from_slice(&self.data[offset as usize..at as usize]);
                    return Ok(n);
                }
                return Err(Error::new(ErrorCode::Read, 5));
            }
            let rest = self.data.get(offset as usize..).unwrap_or(&[]);
            let n = rest.len().min(buf.len());
            buf[..n].copy_from_slice(&rest[..n]);
            Ok(n)
        }
    }

    /// libdeflate's blocks of `unit` bytes at least for what this thread
    /// does in `f`.
    fn with_unit<T>(unit: usize, f: impl FnOnce() -> T) -> T {
        crate::deflate::TEST_UNIT.with(|u| u.set(Some(unit)));
        let out = f();
        crate::deflate::TEST_UNIT.with(|u| u.set(None));
        out
    }

    /// What the layers give, read with reads of `sizes` (the last again
    /// and again): after each read, its bytes, and the stat and attributes.
    fn read_through(
        stack: &mut WriteStack<'_, [u8]>,
        sizes: &[usize],
    ) -> Vec<(Result<Vec<u8>>, Shown)> {
        let shown = |stack: &WriteStack<'_, [u8]>| Shown {
            stat: stack.stat(),
            attributes: stack.file_attributes(),
        };
        let mut got = vec![(stack.open().map(|()| Vec::new()), shown(stack))];
        let mut buf = vec![0; sizes.iter().copied().max().unwrap()];
        let mut ends = 0;
        for k in 0.. {
            let want = sizes[k.min(sizes.len() - 1)];
            let read = stack.read(&mut buf[..want]);
            if !matches!(read, Ok(n) if n > 0) {
                ends += 1;
            }
            got.push((read.map(|n| buf[..n].to_vec()), shown(stack)));
            if ends == 3 {
                break;
            }
        }
        got
    }

    /// An entry's blocks, compressed in threads and joined, read as the CRC
    /// and compressing layers read with one thread: the same bytes in each
    /// read, and the same stat and attributes after it, whatever the reads,
    /// for data that ends with a block, a piece, or within one, and blocks
    /// of each size.
    #[test]
    fn joined_reads_as_the_layers() {
        const UNIT: usize = 16 << 10;
        const PIECE: usize = source_compress::BUFSIZE;
        let reads: [&[usize]; 6] = [
            &[BUFSIZE],
            &[BUFSIZE - 28, BUFSIZE],
            &[BUFSIZE - 12, BUFSIZE],
            &[1000],
            &[100_000],
            &[1, 8191, 3, 65_536, 77, 20_000],
        ];
        let mut cases = Vec::new();
        for n in [
            UNIT + 1,
            UNIT + 100,
            UNIT + PIECE - 1,
            UNIT + PIECE,
            UNIT + PIECE + 1,
            2 * UNIT - 1,
            2 * UNIT,
            2 * UNIT + 1,
            2 * UNIT + PIECE - 1,
            3 * UNIT + 5,
            5 * UNIT + 12_345,
            // Blocks of 32 and 64 KiB.
            (1 << 20) - 1,
            1 << 20,
            (2 << 20) - 1,
            2 << 20,
            (2 << 20) + PIECE - 1,
        ] {
            cases.push((text(n as u64, n), 1));
        }
        cases.push((noise(1, UNIT + 100), 1));
        cases.push((noise(2, 3 * UNIT + PIECE), 6));
        cases.push((text(3, 2 * UNIT + 9), 12));
        cases.push((text(4, 5 * UNIT + PIECE), 12));
        with_unit(UNIT, || {
            for (data, level) in cases {
                let n = data.len();
                let source: Arc<dyn DataSource> = Arc::new(BufferSource::with_mtime(data, 7));
                let deflating = Deflating {
                    blocks: Some(Threads::One),
                    library: Library::Libdeflate,
                    block_size: 0,
                }
                .with_size(Some(n as u64));
                let block = deflating.libdeflate_block_size();
                let blocks = Blocks {
                    size: n as u64,
                    block,
                    level: algorithm_deflate::level(level, Library::Libdeflate),
                };
                let method = i32::from(cm::DEFLATE);
                let key = || Key {
                    source: Arc::clone(&source),
                    method,
                    level,
                    first_read: BUFSIZE,
                    keep_compressing: false,
                    encryption: None,
                    blocks: true,
                    library: Library::Libdeflate,
                    block_size: block,
                };
                for sizes in reads {
                    let what = format!("{n} bytes, blocks of {block}, level {level}, {sizes:?}");
                    let mut layers: WriteStack<'_, [u8]> = WriteStack {
                        base: Base::data(Arc::clone(&source)),
                        decrypt: None,
                        decompress: None,
                        crc: Some(Layer::new(Crc::new(false))),
                        compress: Some(Layer::new(
                            Compress::new(method, level, deflating).unwrap(),
                        )),
                        precompressed: None,
                        encrypt: None,
                    };
                    let want = read_through(&mut layers, sizes);
                    let mut worker = Worker::default();
                    let stop = AtomicBool::new(false);
                    let made: Vec<Block> = (0..blocks.count())
                        .map(|k| compress_block(&mut worker, &*source, blocks, k, &stop).unwrap())
                        .collect();
                    let attributes = Compress::new(method, level, deflating)
                        .unwrap()
                        .file_attributes();
                    let joined = Precompressed {
                        key: key(),
                        data: Data::Joined(Joined::new(blocks, made, attributes)),
                    };
                    let mut stack: WriteStack<'_, [u8]> = WriteStack {
                        base: Base::data(Arc::clone(&source)),
                        decrypt: None,
                        decompress: None,
                        crc: None,
                        compress: None,
                        precompressed: Some(Layer::new(joined)),
                        encrypt: None,
                    };
                    let got = read_through(&mut stack, sizes);
                    assert_eq!(got.len(), want.len(), "{what}");
                    for (k, (got, want)) in got.iter().zip(&want).enumerate() {
                        assert!(got == want, "{what}: read {k}");
                    }
                }
            }
        });
    }

    /// Entries in libdeflate's blocks, of no bytes to many blocks and
    /// across the sizes the blocks grow at, compressed a block in each
    /// thread and joined, among others, encrypted too: the same archive as
    /// one thread's, to a file and to a stream; those larger than the
    /// threads hold are compressed where they are written.
    #[test]
    fn libdeflate_blocks_joined() {
        const UNIT: usize = 16 << 10;
        let mut entries: Vec<(usize, u32, u16)> = vec![
            (0, 12, em::NONE),
            (1, 1, em::NONE),
            (UNIT - 1, 1, em::NONE),
            (UNIT, 6, em::NONE),
            (UNIT + 1, 1, em::NONE),
            (2 * UNIT + 8191, 12, em::NONE),
            (5 * UNIT + 3, 9, em::AES_256),
            (3 * UNIT, 1, em::TRAD_PKWARE),
            ((1 << 20) - 1, 1, em::NONE),
            (1 << 20, 1, em::AES_128),
            ((2 << 20) + 5, 1, em::NONE),
            (1_200_000, 1, em::NONE),
        ];
        entries.extend((0..30).map(|i| (20_000 + i * 7_919, [1, 6, 10][i % 3] as u32, em::NONE)));
        let write = |threads: Threads, stream: bool| {
            TEST_MEMORY.with(|m| m.set(Some(512 << 10)));
            TAKEN.with(|taken| taken.set(0));
            JOINED.with(|n| n.set(0));
            let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
            archive.set_threads(threads);
            archive.set_deflate_library(Library::Libdeflate);
            archive.set_deflate_in_blocks(true);
            let next = Arc::new(std::sync::atomic::AtomicU8::new(0));
            archive.set_random_source(Some(Arc::new(move |buf: &mut [u8]| {
                buf.fill(next.fetch_add(1, Ordering::Relaxed));
                Ok(())
            })));
            for (i, &(n, level, encryption)) in entries.iter().enumerate() {
                let data = if i % 5 == 4 {
                    noise(i as u64, n)
                } else {
                    text(i as u64, n)
                };
                archive
                    .file_add(
                        format!("{i}").as_bytes(),
                        BufferSource::with_mtime(data, 1_700_000_000),
                        Flags::NONE,
                    )
                    .unwrap();
                archive
                    .set_file_compression(i as u64, i32::from(cm::DEFLATE), level)
                    .unwrap();
                if encryption != em::NONE {
                    archive
                        .file_set_encryption(i as u64, encryption, Some(b"pw"))
                        .unwrap();
                }
            }
            let mut out = Cursor::new(Vec::new());
            with_unit(UNIT, || {
                if stream {
                    archive.close_to_stream(&mut out).unwrap();
                } else {
                    archive.close_to(&mut out).unwrap();
                }
            });
            TEST_MEMORY.with(|m| m.set(None));
            (
                out.into_inner(),
                TAKEN.with(std::cell::Cell::get),
                JOINED.with(std::cell::Cell::get),
            )
        };
        let blocked = entries.iter().filter(|e| e.0 > UNIT).count();
        // Those more than the threads hold: no other comes near.
        let large = |threads: Threads| {
            let budget = u64::from(threads.count()) * (512 << 10);
            with_unit(UNIT, || {
                entries
                    .iter()
                    .filter(|e| {
                        let most =
                            maximum_compressed_size(cm::DEFLATE, e.0 as u64, Library::Libdeflate);
                        most.unwrap() + ENTRY_COST > budget
                    })
                    .count()
            })
        };
        for stream in [false, true] {
            let (one, taken, _) = write(Threads::One, stream);
            assert_eq!(taken, 0);
            for threads in [2, 3, 8, 0] {
                let threads = Threads::of(threads);
                let got = write(threads, stream);
                let what = format!("{threads:?}, stream {stream}");
                assert!(got.0 == one, "{what}: bytes differ");
                let large = large(threads);
                assert!(threads.count() > 2 || large >= 3, "{what}");
                assert_eq!(got.1, entries.len() - large, "{what}");
                assert_eq!(got.2, blocked - large, "{what}");
            }
        }
    }

    /// Entries in blocks whose data does not read as their stat says, which
    /// fails, ends before it or goes on after it, at the start of a block,
    /// within one, and in the last: the same error as one thread's, after
    /// the same bytes, to a file and to a stream.
    #[test]
    fn libdeflate_blocks_that_do_not_read() {
        const UNIT: usize = 16 << 10;
        let n = 4 * UNIT + 5000;
        let mut odd = Vec::new();
        for at in [0, 1, UNIT - 1, UNIT, UNIT + 1, 3 * UNIT, 4 * UNIT, n - 1] {
            odd.push((n as u64, Some(at as u64)));
        }
        for said in [
            n - 1,
            n + 1,
            n - 5000,
            n + 8192,
            4 * UNIT,
            3 * UNIT + 1,
            5 * UNIT,
        ] {
            odd.push((said as u64, None));
        }
        for (said, fail_at) in odd {
            let write = |threads: Threads, stream: bool| {
                let mut archive = Archive::open(&[][..], OpenFlags(0)).unwrap();
                archive.set_threads(threads);
                archive.set_deflate_library(Library::Libdeflate);
                archive.set_deflate_in_blocks(true);
                for i in 0..6u64 {
                    let mut source = Odd::new(text(i, n));
                    if i == 2 {
                        source.said = said;
                        source.fail_at = fail_at;
                    }
                    archive
                        .file_add(format!("{i}").as_bytes(), source, Flags::NONE)
                        .unwrap();
                    archive
                        .set_file_compression(i, i32::from(cm::DEFLATE), 1)
                        .unwrap();
                }
                let mut out = Cursor::new(Vec::new());
                let closed = with_unit(UNIT, || {
                    if stream {
                        archive.close_to_stream(&mut out).map(|_| ())
                    } else {
                        archive.close_to(&mut out).map(|_| ())
                    }
                });
                (out.into_inner(), closed)
            };
            for stream in [false, true] {
                let one = write(Threads::One, stream);
                assert!(one.1.is_err(), "{said}, {fail_at:?}");
                for threads in [2, 8, 0] {
                    let got = write(Threads::of(threads), stream);
                    let what = format!("{said}, {fail_at:?}, {threads} threads, {stream}");
                    assert_eq!(got.1, one.1, "{what}");
                    assert!(got.0 == one.0, "{what}: bytes differ");
                }
            }
        }
    }
}
