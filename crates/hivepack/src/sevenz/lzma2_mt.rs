//! LZMA2 decoded in threads, a block in each. Not in the LZMA SDK's 7z
//! decoder, which has no threads: written from LZMA2's format, as
//! `hivepack::xz`'s decoder reads it, beside the port, which it leaves as it
//! is. `dec.rs` takes it for a folder's LZMA2 coder when it may use more than
//! one thread.
//!
//! An LZMA2 stream is chunks, each starting with a control byte:
//!
//! - `0x00` ends the stream;
//! - `0x01` is a chunk stored as it is, the dictionary reset before it, and
//!   `0x02` one without the reset: two bytes of its size, less one, follow;
//! - `0x80` to `0xFF` is an LZMA chunk. Bits 5 and 6 say what is reset before
//!   it: nothing, the state, the state and new properties, or these and the
//!   dictionary (`0xE0` and above). Bits 0 to 4 are the top of its unpacked
//!   size, less one; two more bytes of it follow, two of its packed size,
//!   less one, and the properties' byte if they are new;
//! - `0x03` to `0x7F` are no chunk.
//!
//! Where the dictionary is reset (`0x01`, or `0xE0` and above), nothing after
//! refers to what came before, and the decoder needs new properties and a
//! new state, as a new one does: a decoder started there decodes the rest as
//! the one that decoded from the start would, errors and all. 7-Zip's
//! encoder in threads, and [`Writer`](crate::sevenz::Writer) with
//! [`Lzma2Blocks`](crate::sevenz::Lzma2Blocks), start each block so.
//!
//! The headers say how long each chunk is, packed and not, so the blocks are
//! found without decoding. The caller's thread reads the packed stream in
//! order, decrypted first if it is encrypted, gathers blocks into jobs of at
//! least [`JOB_LEAST`] bytes, and gives each to a thread, which decodes it
//! whole into memory; it then gives the output in order, to the filter after
//! it if there is one. Jobs wait while those given and not yet read would
//! take more than what is left of `Options::decoder_memory_limit`, or than
//! what an extraction gives the folder of `extract::Options::memory_limit`
//! ([`Lzma2Threads::jobs`]). Where an extraction decodes folders at once, each
//! job in flight beyond the first takes one of the threads they share
//! ([`Spare`]), and the others wait for one. A job that would hold more than
//! the memory, or more than [`PACKED_MOST`] or
//! [`UNPACKED_MOST`], as a long stream with no resets does, is decoded on the
//! caller's thread as it is read, as one decoder would, and so is the rest of
//! the stream. So is the last job when none is before it: a stream that is
//! one job makes no thread, and takes no more memory than with one thread.
//!
//! Damaged data fails with the error the decoder from the start gives, at the
//! same place in the output. What a job gives before its error is all it
//! decoded, where one decoder loses what it decoded in the call that failed:
//! read in pieces as large as a file's, as `Files` reads, the error comes in
//! the same file; behind a filter, which reads ahead of the files, it may come
//! a file later than with one thread, the files before it whole.

use std::collections::VecDeque;
use std::io::{Read, Seek};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::xz::{Action, Filter, InBuffer, LzmaOptions, OutBuffer, Status, Stream};

use crate::sevenz::dec::PackReader;
use crate::sevenz::error::{Error, Result};
use crate::workers::Workers;

/// Blocks are gathered into a job until it has this many bytes, so that a
/// thread is not given too little to do.
pub(crate) const JOB_LEAST: u64 = 1 << 18;
/// The most packed bytes a job holds.
pub(crate) const PACKED_MOST: usize = 64 << 20;
/// The most bytes a job decodes to.
pub(crate) const UNPACKED_MOST: u64 = 1 << 30;

/// How an LZMA2 coder may decode in threads: in up to `threads`, its jobs
/// holding no more than `jobs` bytes beside what is left of the folder's limit,
/// and, where folders are decoded at once, those beyond the first in flight
/// each taking one of the `spare` threads they share.
#[derive(Clone, Debug)]
pub(crate) struct Lzma2Threads {
    pub(crate) threads: u32,
    pub(crate) jobs: u64,
    pub(crate) spare: Option<Arc<Spare>>,
}

impl Lzma2Threads {
    /// One thread, the caller's.
    pub(crate) fn one() -> Lzma2Threads {
        Lzma2Threads {
            threads: 1,
            jobs: 0,
            spare: None,
        }
    }
}

/// The threads that folders decoded at once share, besides one each, for
/// their LZMA2 blocks: as one folder ends, the others take its thread.
#[derive(Debug)]
pub(crate) struct Spare(AtomicU32);

impl Spare {
    /// `threads` of them.
    #[cfg(any(feature = "extract", test))]
    pub(crate) fn new(threads: u32) -> Arc<Spare> {
        Arc::new(Spare(AtomicU32::new(threads)))
    }

    /// One of them, if one is free.
    fn take(&self) -> bool {
        let mut free = self.0.load(Ordering::Acquire);
        while free > 0 {
            match self
                .0
                .compare_exchange_weak(free, free - 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(now) => free = now,
            }
        }
        false
    }

    /// `n` given back, or given.
    pub(crate) fn give(&self, n: u32) {
        self.0.fetch_add(n, Ordering::AcqRel);
    }
}

/// How a job ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JobEnd {
    /// Where the next block starts.
    Reset,
    /// Where the stream ends: its end, a byte no chunk starts with, or the end
    /// of the packed stream.
    Last,
    /// Where the packed stream could not be read, with that error.
    Failed(Error),
}

/// Blocks for a thread to decode.
struct Job {
    packed: Vec<u8>,
    /// What the chunks' headers say they decode to.
    unpacked: u64,
    dict: u32,
    end: JobEnd,
}

impl Job {
    /// The memory it takes, decoded.
    fn cost(&self) -> u64 {
        self.packed.len() as u64 + self.unpacked + u64::from(self.dict)
    }
}

/// A job decoded: its output, and the error after it if any.
struct Done {
    out: Vec<u8>,
    pos: usize,
    error: Option<Error>,
    /// The stream's end was found.
    ended: bool,
}

/// What a decoding error of `hivepack::xz` is to 7z.
fn data_error(e: crate::xz::Error) -> Error {
    match e {
        crate::xz::Error::Mem => Error::Mem,
        _ => Error::Data,
    }
}

/// A raw LZMA2 decoder with a dictionary of `dict` bytes.
fn decoder(dict: u32) -> Result<Stream> {
    let options = LzmaOptions {
        dict_size: dict.max(4096),
        ..LzmaOptions::preset(0).ok_or(Error::Fail)?
    };
    Stream::raw_decoder(&[Filter::lzma2(options)]).map_err(|e| match e {
        crate::xz::Error::Mem => Error::Mem,
        _ => Error::Unsupported,
    })
}

/// Decodes a job, in a thread.
fn decode_job(_: &mut (), job: Job) -> Done {
    let mut done = Done {
        out: Vec::new(),
        pos: 0,
        error: None,
        ended: false,
    };
    let Ok(size) = usize::try_from(job.unpacked) else {
        done.error = Some(Error::Mem);
        return done;
    };
    if done.out.try_reserve_exact(size).is_err() {
        done.error = Some(Error::Mem);
        return done;
    }
    done.out.resize(size, 0);
    let result = decode_into(&job, &mut done);
    done.error = match (result, job.end) {
        (Err(e), _) => Some(e),
        (Ok(()), JobEnd::Reset) if done.ended || done.out.len() != size => Some(Error::Data),
        (Ok(()), JobEnd::Last) if !done.ended => Some(Error::Data),
        (Ok(()), JobEnd::Failed(e)) if !done.ended => Some(e),
        (Ok(()), _) => None,
    };
    done
}

/// Decodes `job.packed` into `done.out`, which is cut to what it decodes
/// to.
fn decode_into(job: &Job, done: &mut Done) -> Result<()> {
    let mut stream = match decoder(job.dict) {
        Ok(stream) => stream,
        Err(e) => {
            done.out.clear();
            return Err(e);
        }
    };
    let mut input = InBuffer::new(&job.packed);
    let mut output = OutBuffer::new(&mut done.out);
    let result = loop {
        let before = (input.pos, output.pos);
        match stream.code(&mut output, &mut input, Action::Run) {
            Err(e) => break Err(data_error(e)),
            Ok(Status::StreamEnd) => {
                done.ended = true;
                break Ok(());
            }
            Ok(_) if input.pos == input.src.len() => break Ok(()),
            // More output than the headers say.
            Ok(_) if (input.pos, output.pos) == before => break Err(Error::Data),
            Ok(_) => {}
        }
    };
    let written = output.pos;
    done.out.truncate(written);
    result
}

/// The result of a job whose thread failed.
fn job_lost() -> Done {
    Done {
        out: Vec::new(),
        pos: 0,
        error: Some(Error::Fail),
        ended: false,
    }
}

/// What gathering a job found.
enum Gathered {
    Job(Job),
    /// A job past the limits: what is left is decoded as it is read.
    TooLarge,
}

/// An LZMA2 coder's output, decoded a block in each thread.
pub(crate) struct Lzma2Mt {
    /// The dictionary the properties say.
    dict: u32,
    /// The dictionary of the decoder on the caller's thread, no larger than
    /// the output.
    serial_dict: u32,
    /// What the jobs given and not yet read may take.
    budget: u64,
    workers: Workers<(), Job, Done>,
    /// The memory each job given takes, the oldest first, until all its
    /// output is read.
    costs: VecDeque<u64>,
    /// The job whose output is being read.
    head: Option<Done>,
    /// A job gathered that waits for memory.
    held: Option<Job>,
    /// The packed bytes read and not given: from the start of the job being
    /// gathered, with its chunks whole up to `at`; or, once all is
    /// gathered, those after the last job, which `serial` reads from `at`.
    buf: Vec<u8>,
    at: usize,
    /// The bytes the chunks up to `at` decode to, and those of the chunk
    /// after them, whose header is read and data not.
    unpacked: u64,
    partial: u64,
    /// No more jobs are to be gathered.
    all_gathered: bool,
    /// The decoder on the caller's thread, past a job too large.
    serial: Option<Box<Stream>>,
    /// The stream has ended, its output all read.
    ended: bool,
    /// The threads shared with other folders, and how many of them are taken:
    /// each job in flight beyond the first takes one.
    spare: Option<Arc<Spare>>,
    taken: u32,
}

impl Drop for Lzma2Mt {
    fn drop(&mut self) {
        if let Some(spare) = &self.spare {
            spare.give(self.taken);
        }
    }
}

impl Lzma2Mt {
    /// The decoder of LZMA2 with these properties, into `out_size` bytes, in
    /// the threads `lzma2` says. Its dictionary is charged to `limit` as the
    /// one decoder's is, and the jobs take no more than what is left, nor
    /// more than `lzma2.jobs`.
    pub(crate) fn new(
        props: &[u8],
        out_size: u64,
        lzma2: Lzma2Threads,
        limit: &mut u64,
    ) -> Result<Self> {
        // SzDecodeLzma2, Lzma2Dec_AllocateProbs, as `lzma_decoder` checks
        // them.
        if props.len() != 1 {
            return Err(Error::Data);
        }
        let prop = u32::from(props[0]);
        if prop > 40 {
            return Err(Error::Unsupported);
        }
        let dict = if prop == 40 {
            u32::MAX
        } else {
            (2 | (prop & 1)) << (prop / 2 + 11)
        };
        let dict_cap = out_size.clamp(4096, u64::from(u32::MAX)) as u32;
        let serial_dict = dict.min(dict_cap).max(4096);
        *limit = limit
            .checked_sub(u64::from(serial_dict))
            .ok_or(Error::Mem)?;
        Ok(Lzma2Mt {
            dict,
            serial_dict,
            budget: (*limit).min(lzma2.jobs),
            workers: Workers::new(lzma2.threads, "sevenz-lzma2", decode_job, job_lost),
            costs: VecDeque::new(),
            head: None,
            held: None,
            buf: Vec::new(),
            at: 0,
            unpacked: 0,
            partial: 0,
            all_gathered: false,
            serial: None,
            ended: false,
            spare: lzma2.spare,
            taken: 0,
        })
    }

    /// Whether another job may be given: the first in flight always, those
    /// after it if they have, or get, a thread of those shared.
    fn may_give(&mut self) -> bool {
        let Some(spare) = &self.spare else {
            return true;
        };
        if self.workers.pending() <= self.taken as usize {
            return true;
        }
        let took = spare.take();
        self.taken += u32::from(took);
        took
    }

    /// The shared threads no job in flight needs, given back.
    fn give_back(&mut self) {
        let needed = self.workers.pending().saturating_sub(1) as u32;
        if let Some(spare) = &self.spare
            && self.taken > needed
        {
            spare.give(self.taken - needed);
            self.taken = needed;
        }
    }

    /// The dictionary a job of `unpacked` bytes needs.
    fn job_dict(&self, unpacked: u64) -> u32 {
        let most = u32::try_from(unpacked).unwrap_or(u32::MAX);
        self.dict.min(most).max(4096)
    }

    /// The job up to `at` in the buffer, the rest kept for the next.
    fn cut(&mut self, at: usize, end: JobEnd) -> Gathered {
        let rest = self.buf.split_off(at.min(self.buf.len()));
        let packed = std::mem::replace(&mut self.buf, rest);
        let mut unpacked = self.unpacked;
        if end != JobEnd::Reset {
            // The chunk the stream ends in decodes to some of its size.
            unpacked += self.partial;
            self.all_gathered = true;
        }
        self.at = 0;
        self.unpacked = 0;
        self.partial = 0;
        Gathered::Job(Job {
            packed,
            unpacked,
            dict: self.job_dict(unpacked),
            end,
        })
    }

    /// Reads the packed stream up to the end of the next job: the first
    /// reset of the dictionary once it has [`JOB_LEAST`] bytes, or the end of
    /// the stream.
    fn gather<R: Read + Seek>(&mut self, input: &mut PackReader, r: &mut R) -> Gathered {
        loop {
            // The chunks whose headers are in the buffer.
            while let Some(&control) = self.buf.get(self.at) {
                let rest = &self.buf[self.at..];
                let byte = |i: usize| u64::from(rest[i]);
                let (header, unpacked, packed, reset) = match control {
                    0x00 => return self.cut(self.at + 1, JobEnd::Last),
                    0x01 | 0x02 if rest.len() >= 3 => {
                        let size = (byte(1) << 8 | byte(2)) + 1;
                        (3, size, size, control == 0x01)
                    }
                    0x80..=0xFF => {
                        let header = if control >= 0xC0 { 6 } else { 5 };
                        if rest.len() < header {
                            break;
                        }
                        let unpacked =
                            (u64::from(control & 0x1F) << 16 | byte(1) << 8 | byte(2)) + 1;
                        let packed = (byte(3) << 8 | byte(4)) + 1;
                        (header, unpacked, packed, control >= 0xE0)
                    }
                    0x01 | 0x02 => break,
                    // No chunk: the decoder fails on it.
                    _ => return self.cut(self.at + 1, JobEnd::Last),
                };
                if reset && self.at > 0 && self.unpacked >= JOB_LEAST {
                    return self.cut(self.at, JobEnd::Reset);
                }
                let len = header + packed as usize;
                if rest.len() < len {
                    self.partial = unpacked;
                    break;
                }
                self.at += len;
                self.unpacked += unpacked;
                self.partial = 0;
            }
            let unpacked = self.unpacked + self.partial;
            let cost = self.buf.len() as u64 + unpacked + u64::from(self.job_dict(unpacked));
            if self.buf.len() > PACKED_MOST || unpacked > UNPACKED_MOST || cost > self.budget {
                return Gathered::TooLarge;
            }
            if input.remaining() == 0 {
                return self.cut(self.buf.len(), JobEnd::Last);
            }
            match input.fill(r, Error::Data) {
                Ok(bytes) => {
                    let n = bytes.len();
                    self.buf.extend_from_slice(bytes);
                    input.consume(n);
                }
                Err(e) => return self.cut(self.buf.len(), JobEnd::Failed(e)),
            }
        }
    }

    /// Gives the threads jobs, as many as there are threads and memory for;
    /// the shared threads not needed given back.
    fn pump<R: Read + Seek>(&mut self, input: &mut PackReader, r: &mut R) -> Result<()> {
        let pumped = self.pump_jobs(input, r);
        self.give_back();
        pumped
    }

    fn pump_jobs<R: Read + Seek>(&mut self, input: &mut PackReader, r: &mut R) -> Result<()> {
        while self.workers.pending() < self.workers.most() && self.may_give() {
            let job = match self.held.take() {
                Some(job) => job,
                None if self.all_gathered => return Ok(()),
                None => match self.gather(input, r) {
                    Gathered::Job(job)
                        if (job.end == JobEnd::Last && self.costs.is_empty())
                            || (job.end == JobEnd::Reset && job.cost() > self.budget) =>
                    {
                        // The last, with nothing beside it, or one past the
                        // memory: read here from its start, as one decoder
                        // reads it, with no thread and no more memory, and the
                        // rest of the stream after it.
                        let mut packed = job.packed;
                        packed.extend_from_slice(&self.buf);
                        self.buf = packed;
                        self.at = 0;
                        self.all_gathered = true;
                        self.serial = Some(Box::new(decoder(self.serial_dict)?));
                        return Ok(());
                    }
                    Gathered::Job(job) => job,
                    Gathered::TooLarge => {
                        // From the start of the job, the rest is read here.
                        self.all_gathered = true;
                        self.at = 0;
                        self.serial = Some(Box::new(decoder(self.serial_dict)?));
                        return Ok(());
                    }
                },
            };
            let cost = job.cost();
            let taken: u64 = self.costs.iter().sum();
            if !self.costs.is_empty() && taken.saturating_add(cost) > self.budget {
                self.held = Some(job);
                return Ok(());
            }
            self.costs.push_back(cost);
            if job.end != JobEnd::Reset && self.workers.pending() == 0 {
                // Nothing to do beside it.
                self.workers.do_here(job);
            } else {
                self.workers.give(job);
            }
        }
        Ok(())
    }

    /// Up to `out.len()` bytes of the output; 0 at the end of the stream.
    pub(crate) fn read<R: Read + Seek>(
        &mut self,
        input: &mut PackReader,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(head) = &mut self.head {
                if head.pos < head.out.len() {
                    let n = (head.out.len() - head.pos).min(out.len());
                    out[..n].copy_from_slice(&head.out[head.pos..head.pos + n]);
                    head.pos += n;
                    return Ok(n);
                }
                if let Some(e) = head.error {
                    return Err(e);
                }
                self.ended = head.ended;
                self.head = None;
                self.costs.pop_front();
            }
            if self.ended {
                return Ok(0);
            }
            self.pump(input, r)?;
            if let Some(done) = self.workers.take() {
                self.head = Some(done);
                continue;
            }
            return match self.serial.is_some() {
                true => self.read_serial(input, r, out),
                // Each last job ends the stream or fails.
                false => Err(Error::Data),
            };
        }
    }

    /// Decodes on the caller's thread, the bytes gathered first, as
    /// `MainCoder` decodes LZMA2.
    fn read_serial<R: Read + Seek>(
        &mut self,
        input: &mut PackReader,
        r: &mut R,
        out: &mut [u8],
    ) -> Result<usize> {
        let Some(stream) = self.serial.as_mut() else {
            return Err(Error::Fail);
        };
        loop {
            let gathered = self.at < self.buf.len();
            let buf = if gathered {
                &self.buf[self.at..]
            } else if input.remaining() == 0 {
                &[][..]
            } else {
                input.fill(r, Error::Data)?
            };
            let mut from = InBuffer::new(buf);
            let mut output = OutBuffer::new(out);
            let action = if buf.is_empty() {
                Action::Finish
            } else {
                Action::Run
            };
            let status = stream
                .code(&mut output, &mut from, action)
                .map_err(data_error)?;
            let (read, written) = (from.pos, output.pos);
            if gathered {
                self.at += read;
            } else {
                input.consume(read);
            }
            if status == Status::StreamEnd {
                self.ended = true;
            }
            if written > 0 {
                return Ok(written);
            }
            if self.ended {
                return Ok(0);
            }
            if read == 0 {
                // No progress.
                return Err(Error::Data);
            }
        }
    }

    /// The checks once the output is full: the stream ends there, and
    /// nothing read follows it.
    pub(crate) fn finish<R: Read + Seek>(
        &mut self,
        input: &mut PackReader,
        r: &mut R,
    ) -> Result<()> {
        if self.read(input, r, &mut [0u8; 1])? != 0 || self.at < self.buf.len() {
            return Err(Error::Data);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Text of some kind, `len` bytes.
    fn text(len: usize, seed: u64) -> Vec<u8> {
        let words: [&[u8]; 6] = [b"seven ", b"zip ", b"block ", b"thread ", b"reset ", b"\n"];
        let mut state = seed;
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(words[(state >> 60) as usize % words.len()]);
        }
        out.truncate(len);
        out
    }

    /// `data` in LZMA2, a stream of its own for each `block` bytes, each but
    /// the last without its end, with a dictionary of 64 KiB (the
    /// properties' byte 8).
    fn blocks(data: &[u8], block: usize) -> Vec<u8> {
        let mut options = LzmaOptions::preset(1).unwrap_or_else(|| unreachable!());
        options.dict_size = 1 << 16;
        let mut out = Vec::new();
        for piece in data.chunks(block) {
            let mut stream = Stream::raw_encoder(&[Filter::lzma2(options.clone())])
                .unwrap_or_else(|_| unreachable!());
            let mut buf = vec![0; piece.len() * 2 + 1024];
            let mut input = InBuffer::new(piece);
            let mut output = OutBuffer::new(&mut buf);
            let status = stream.code(&mut output, &mut input, Action::Finish);
            assert_eq!(status, Ok(Status::StreamEnd));
            let made = output.pos;
            out.extend_from_slice(&buf[..made - 1]);
        }
        out.push(0);
        out
    }

    /// What `threads` decode of `packed` into `size` bytes, read `piece`
    /// bytes at a time, with `limit` bytes of memory; the threads made, and
    /// whether it went on in the caller's thread.
    fn decode(
        packed: &[u8],
        size: u64,
        threads: u32,
        limit: u64,
        piece: usize,
    ) -> (Result<Vec<u8>>, usize, bool) {
        let lzma2 = Lzma2Threads {
            threads,
            jobs: u64::MAX,
            spare: None,
        };
        decode_with(packed, size, lzma2, limit, piece)
    }

    /// [`decode`] with the threads `lzma2` says.
    fn decode_with(
        packed: &[u8],
        size: u64,
        lzma2: Lzma2Threads,
        limit: u64,
        piece: usize,
    ) -> (Result<Vec<u8>>, usize, bool) {
        let mut limit = limit;
        let mut mt = match Lzma2Mt::new(&[8], size, lzma2, &mut limit) {
            Ok(mt) => mt,
            Err(e) => return (Err(e), 0, false),
        };
        let mut r = Cursor::new(packed);
        let mut input = PackReader::new(0, packed.len() as u64);
        let mut out = Vec::new();
        let mut buf = vec![0; piece];
        let result = loop {
            if out.len() as u64 == size {
                break mt.finish(&mut input, &mut r).and_then(|()| {
                    if input.remaining() != 0 {
                        return Err(Error::Data);
                    }
                    Ok(())
                });
            }
            let want = piece.min((size - out.len() as u64) as usize);
            match mt.read(&mut input, &mut r, &mut buf[..want]) {
                Ok(0) => break Err(Error::Data),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => break Err(e),
            }
        };
        let serial = mt.serial.is_some();
        (result.map(|()| out), mt.workers.threads(), serial)
    }

    #[test]
    fn blocks_in_threads() {
        let data = text(3 << 20, 1);
        let packed = blocks(&data, 300_000);
        for (threads, piece) in [(1, 1000), (2, 65536), (8, 7777), (8, 1 << 20)] {
            let (got, made, _) = decode(&packed, data.len() as u64, threads, 1 << 32, piece);
            assert!(got == Ok(data.clone()), "{threads} threads");
            if threads > 1 {
                assert!(made > 0 && made <= threads as usize, "{made} of {threads}");
            } else {
                assert_eq!(made, 0);
            }
        }
    }

    /// Threads shared with other folders: a job in flight beyond the first
    /// takes one, and gives it back; with none free, one job at a time.
    #[test]
    fn shared_threads() {
        let data = text(3 << 20, 4);
        let packed = blocks(&data, 300_000);
        for free in [0, 2] {
            let spare = Spare::new(free);
            let lzma2 = Lzma2Threads {
                threads: 8,
                jobs: u64::MAX,
                spare: Some(Arc::clone(&spare)),
            };
            let (got, made, _) = decode_with(&packed, data.len() as u64, lzma2, 1 << 32, 65536);
            assert!(got == Ok(data.clone()), "{free} free");
            assert!(made <= free as usize + 1, "{made} threads, {free} free");
            assert_eq!(spare.0.load(Ordering::Acquire), free, "given back");
        }
        // Jobs held to `jobs` bytes wait for one another.
        let lzma2 = Lzma2Threads {
            threads: 8,
            jobs: 1 << 20,
            spare: None,
        };
        let (got, _, _) = decode_with(&packed, data.len() as u64, lzma2, 1 << 32, 65536);
        assert!(got == Ok(data));
    }

    #[test]
    fn one_job_makes_no_thread() {
        let data = text(200_000, 2);
        let packed = blocks(&data, 1 << 30);
        let (got, made, _) = decode(&packed, data.len() as u64, 8, 1 << 32, 4096);
        assert!(got == Ok(data));
        assert_eq!(made, 0);
    }

    #[test]
    fn little_memory() {
        let data = text(3 << 20, 3);
        let packed = blocks(&data, 300_000);
        let size = data.len() as u64;
        // Room for a job or two at a time: the others wait.
        let (got, made, _) = decode(&packed, size, 8, (1 << 16) + (1 << 20), 9999);
        assert!(got == Ok(data.clone()));
        assert!(made > 0);
        // Room for none: decoded here, as one decoder would.
        let (got, made, serial) = decode(&packed, size, 8, (1 << 16) + 100_000, 9999);
        assert!(got == Ok(data.clone()));
        assert!(serial && made == 0);
        // No resets past the first, and little memory.
        let whole = blocks(&data, 1 << 30);
        let (got, _, serial) = decode(&whole, size, 8, (1 << 16) + 100_000, 9999);
        assert!(got == Ok(data));
        assert!(serial);
    }

    #[test]
    fn damaged_streams_fail_as_one_decoder_does() {
        let data = text(2 << 20, 4);
        let packed = blocks(&data, 300_000);
        let size = data.len() as u64;
        // Cut short, anywhere.
        for cut in [1, 100, packed.len() / 2, packed.len() - 1] {
            let (got, ..) = decode(&packed[..cut], size, 4, 1 << 32, 65536);
            assert_eq!(got, Err(Error::Data), "cut at {cut}");
        }
        // A byte no chunk starts with, where a chunk starts.
        let mut bad = packed.clone();
        let at = (packed.len() / 2..packed.len())
            .find(|&i| bad[i] == 0xE0)
            .unwrap_or(0);
        assert!(at > 0);
        bad[at] = 0x05;
        assert_eq!(decode(&bad, size, 4, 1 << 32, 65536).0, Err(Error::Data));
        // More after the end, or the end early or late.
        let mut longer = packed.clone();
        longer.push(0);
        assert_eq!(decode(&longer, size, 4, 1 << 32, 65536).0, Err(Error::Data));
        assert_eq!(
            decode(&packed, size + 1, 4, 1 << 32, 65536).0,
            Err(Error::Data)
        );
        assert_eq!(
            decode(&packed, size - 1, 4, 1 << 32, 65536).0,
            Err(Error::Data)
        );
        // Each the error one decoder gives, after the same output.
        for at in (0..packed.len()).step_by(packed.len() / 60) {
            let mut bad = packed.clone();
            bad[at] ^= 0x10;
            let (one, ..) = decode(&bad, size, 1, 1 << 32, 65536);
            let (many, ..) = decode(&bad, size, 4, 1 << 32, 65536);
            assert_eq!(one.err(), many.err(), "at {at}");
        }
    }
}
