// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! RAR 5's blocks decoded in threads, as UnRAR's unpack50mt.cpp does: each
//! block's Huffman codes are decoded ahead, in a thread of its own, into what
//! they say (literals, matches, filters), and the caller's thread writes that
//! into the window in order. Not UnRAR's code, which differs from its own
//! single thread where data is damaged (a block without tables of its own
//! decoded with other tables than the block before it; a filter that cannot
//! be read or added gone on from): what comes out here is always what one
//! thread gives, damaged data and errors too.
//!
//! The caller's thread runs `Unpack5` as it is, reading the packed data as it
//! does, and only takes, at each block, what a thread decoded ahead in place
//! of decoding it itself, where that is what it would decode: the block's
//! header is where its own is, its codes start at the same bit, its tables
//! were made from the same lengths, and the thread read only packed data, not
//! past its end, where `Unpack5` would read what its buffer still holds.
//! Each symbol taken moves the caller's bits on by those it took, so that its
//! buffer is refilled where it would be. Anything else, it decodes itself.
//!
//! What the threads read is the packed data read again, apart, from its
//! start ([`UnpIo::packed_ahead`]): a scan goes through the block headers and
//! tables, each block where the one before ends as its header says, and
//! hands each block to the threads with its tables.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};

use crate::rar::error::Error;

use super::v50::{RawFilter, Symbol, decode_symbol, read_filter_bits};
use super::{
    BC, BitInput, BlockTables, DCB, DCX, HUFF_TABLE_SIZEB, HUFF_TABLE_SIZEX, LDC, NC, RC,
    TableLengths, UnpIo, Unpack,
};

/// A block larger than this is decoded on the caller's thread, so that what
/// is held ahead stays small; RAR's blocks are far smaller.
const LARGEST_BLOCK: i64 = 4 << 20;
/// What is read ahead at a time.
const READ_SIZE: usize = 1 << 20;
/// The packed data of the blocks handed to threads and not yet taken, at
/// most, whatever the threads: what they decode is held to
/// [`HELD_PER_BYTE`] times it.
const IN_FLIGHT: usize = 8 << 20;
/// What a block decoded ahead may hold for each byte of its packed data:
/// 2 for a literal, 24 for a match. Past it, the block is decoded on the
/// caller's thread.
const HELD_PER_BYTE: usize = 6;
/// Bytes of packed data given to a thread past its block's end, for a last
/// symbol that runs over it, as `Unpack5` reads one.
const PAST_END: u64 = 64;

/// What a block's codes said, in order: literals counted here, their bytes in
/// [`Decoded::lits`].
#[derive(Clone, Copy)]
enum Op {
    Literals(u32),
    Match {
        length: u32,
        distance: usize,
        bits: u32,
    },
    Filter {
        main_bits: u32,
        raw: RawFilter,
        bits: u32,
    },
    FullRep {
        bits: u32,
    },
    Rep {
        dist_num: u8,
        length: u32,
        bits: u32,
    },
}

/// A block decoded ahead: each symbol, with the bits it took.
pub(super) struct Decoded {
    /// Whether it is what the caller's thread would decode: it read nothing
    /// past the packed data, and is not too large to hold.
    whole: bool,
    lits: Vec<u8>,
    lit_bits: Vec<u8>,
    ops: Vec<Op>,
}

/// A block's symbols taken in place of decoding them, each moving the bits
/// on by those it took.
pub(super) struct Replay {
    decoded: Decoded,
    op: usize,
    lit: usize,
    lits_left: u32,
}

impl Replay {
    /// The literals that come next, and the bits each takes: none if the next
    /// symbol is not one.
    #[inline(always)]
    pub(super) fn literals(&mut self) -> Option<(&[u8], &[u8])> {
        if self.lits_left == 0 {
            let Some(&Op::Literals(n)) = self.decoded.ops.get(self.op) else {
                return None;
            };
            self.op += 1;
            self.lits_left = n;
        }
        let (at, n) = (self.lit, self.lits_left as usize);
        Some((
            &self.decoded.lits[at..at + n],
            &self.decoded.lit_bits[at..at + n],
        ))
    }

    /// The first `n` of [`Replay::literals`] taken.
    #[inline(always)]
    pub(super) fn took_literals(&mut self, n: usize) {
        self.lit += n;
        self.lits_left -= n as u32;
    }

    /// The next symbol, `inp` moved past it; none once all are taken.
    #[inline(always)]
    pub(super) fn next(&mut self, inp: &mut BitInput) -> Option<Symbol> {
        loop {
            if self.lits_left > 0 {
                self.lits_left -= 1;
                let at = self.lit;
                self.lit += 1;
                inp.addbits(u32::from(self.decoded.lit_bits[at]));
                return Some(Symbol::Literal(self.decoded.lits[at]));
            }
            let op = *self.decoded.ops.get(self.op)?;
            self.op += 1;
            return Some(match op {
                Op::Literals(n) => {
                    self.lits_left = n;
                    continue;
                }
                Op::Match {
                    length,
                    distance,
                    bits,
                } => {
                    inp.addbits(bits);
                    Symbol::Match { length, distance }
                }
                Op::Filter {
                    main_bits,
                    raw,
                    bits,
                } => {
                    inp.addbits(main_bits);
                    Symbol::Filter(Some((raw, bits)))
                }
                Op::FullRep { bits } => {
                    inp.addbits(bits);
                    Symbol::FullRep
                }
                Op::Rep {
                    dist_num,
                    length,
                    bits,
                } => {
                    inp.addbits(bits);
                    Symbol::Rep {
                        dist_num: usize::from(dist_num),
                        length,
                    }
                }
            });
        }
    }
}

/// A block for a thread: its packed data from the byte its codes start in,
/// then zeros.
struct Job {
    bytes: Box<[u8]>,
    /// The bit its codes start at, in the first byte.
    first_bit: u32,
    /// How many of `bytes` are packed data.
    real: usize,
    /// The block's last byte, from the first of `bytes`, and how many of its
    /// bits are the block's: its end as `Unpack5` sees it.
    end: i64,
    bit_size: i32,
    tables: Arc<BlockTables>,
    reply: mpsc::Sender<Decoded>,
}

/// Where a bit input is, in bits.
fn bits_at(inp: &BitInput) -> i64 {
    i64::from(inp.in_addr) * 8 + i64::from(inp.in_bit)
}

/// Decodes `job`'s block until its end, as `Unpack5` meets it before each
/// symbol, or until what it reads is no longer packed data.
fn decode_block(job: Job) -> (Decoded, mpsc::Sender<Decoded>) {
    let Job {
        bytes,
        first_bit,
        real,
        end,
        bit_size,
        tables,
        reply,
    } = job;
    let most = HELD_PER_BYTE * bytes.len() + (64 << 10);
    let mut inp = BitInput::over(bytes, first_bit);
    let real_bits = real as i64 * 8;
    let mut decoded = Decoded {
        whole: true,
        lits: Vec::new(),
        lit_bits: Vec::new(),
        ops: Vec::new(),
    };
    loop {
        let at = i64::from(inp.in_addr);
        if at > end || at == end && inp.in_bit as i32 >= bit_size {
            break;
        }
        let before = bits_at(&inp);
        if before >= real_bits {
            decoded.whole = false;
            break;
        }
        let symbol = decode_symbol(&tables, &mut inp);
        let taken = (bits_at(&inp) - before) as u32;
        match symbol {
            Symbol::Literal(byte) => {
                decoded.lits.push(byte);
                decoded.lit_bits.push(taken as u8);
                match decoded.ops.last_mut() {
                    Some(Op::Literals(n)) => *n += 1,
                    _ => decoded.ops.push(Op::Literals(1)),
                }
            }
            Symbol::Match { length, distance } => decoded.ops.push(Op::Match {
                length,
                distance,
                bits: taken,
            }),
            Symbol::Filter(_) => {
                let middle = bits_at(&inp);
                let raw = read_filter_bits(&mut inp);
                decoded.ops.push(Op::Filter {
                    main_bits: taken,
                    raw,
                    bits: (bits_at(&inp) - middle) as u32,
                });
            }
            Symbol::FullRep => decoded.ops.push(Op::FullRep { bits: taken }),
            Symbol::Rep { dist_num, length } => decoded.ops.push(Op::Rep {
                dist_num: dist_num as u8,
                length,
                bits: taken,
            }),
        }
        // What a symbol reads past what it takes makes no difference to it:
        // only the bits it takes have to be packed data.
        let held = decoded.lits.len() * 2 + decoded.ops.len() * std::mem::size_of::<Op>();
        if bits_at(&inp) > real_bits || held > most {
            decoded.whole = false;
            break;
        }
    }
    (decoded, reply)
}

/// A block the scan went through, in order, and what a thread made of it,
/// if one was given it.
struct Pending {
    /// The packed data handed to a thread for it.
    bytes: usize,
    header_at: i64,
    data_bits: i64,
    lengths: Option<Arc<TableLengths>>,
    result: Option<mpsc::Receiver<Decoded>>,
}

/// The scan of the packed data, read again apart, and the blocks handed to
/// the threads, for the caller's thread to take in order.
pub(super) struct Speculation {
    jobs: mpsc::Sender<Job>,
    /// The packed data read ahead, from `base`.
    ahead: Vec<u8>,
    base: u64,
    size: u64,
    read_done: bool,
    /// Where the next block header is; none once the scan has stopped.
    scan_at: Option<u64>,
    tables: Option<(Arc<BlockTables>, Arc<TableLengths>)>,
    extra_dist: bool,
    pending: VecDeque<Pending>,
    /// How many blocks are scanned ahead of the caller's thread.
    depth: usize,
    /// The packed data of `pending`'s blocks handed to threads.
    in_flight: usize,
}

impl Speculation {
    fn new(jobs: mpsc::Sender<Job>, size: u64, extra_dist: bool, workers: usize) -> Speculation {
        Speculation {
            jobs,
            ahead: Vec::new(),
            base: 0,
            size,
            read_done: false,
            scan_at: Some(0),
            tables: None,
            extra_dist,
            pending: VecDeque::new(),
            depth: 2 * workers + 2,
            in_flight: 0,
        }
    }

    /// What the caller's thread may take for the block whose header it read
    /// at `header_at`, its codes starting at `data_bits`, with tables made
    /// from `lengths`: the next block scanned, if it is that one.
    pub(super) fn block(
        &mut self,
        io: &mut dyn UnpIo,
        header_at: i64,
        data_bits: i64,
        lengths: Option<&TableLengths>,
    ) -> Option<Replay> {
        self.fill(io);
        let front = self.pending.pop_front()?;
        self.in_flight -= front.bytes;
        if front.header_at != header_at || front.data_bits != data_bits {
            // Damaged data has taken the blocks elsewhere than their
            // headers say: the rest is decoded on the caller's thread.
            self.stop();
            return None;
        }
        let result = front.result?;
        if front.lengths.as_deref() != lengths {
            return None;
        }
        let decoded = result.recv().ok()?;
        decoded.whole.then_some(Replay {
            decoded,
            op: 0,
            lit: 0,
            lits_left: 0,
        })
    }

    fn stop(&mut self) {
        self.pending.clear();
        self.in_flight = 0;
        self.scan_at = None;
    }

    /// Scans until `depth` blocks are ahead, or the scan stops.
    fn fill(&mut self, io: &mut dyn UnpIo) {
        while self.pending.len() < self.depth
            && self.in_flight < IN_FLIGHT
            && self.scan_at.is_some()
        {
            self.scan(io);
        }
    }

    /// Reads ahead until `end`, or the end of the packed data.
    fn read_until(&mut self, io: &mut dyn UnpIo, end: u64) {
        let end = end.min(self.size);
        while !self.read_done && self.base + (self.ahead.len() as u64) < end {
            let at = self.ahead.len();
            self.ahead.resize(at + READ_SIZE, 0);
            let offset = self.base + at as u64;
            match io.packed_ahead(offset, &mut self.ahead[at..]) {
                Ok(Some(n)) if n > 0 => self.ahead.truncate(at + n),
                _ => {
                    self.ahead.truncate(at);
                    self.read_done = true;
                }
            }
        }
    }

    /// The packed data from `from` to `to` that has been read, with zeros
    /// for the rest and eight bytes past `to`, and how much of it was read.
    fn copy(&self, from: u64, to: u64) -> (Box<[u8]>, usize) {
        let have = self.base + self.ahead.len() as u64;
        let real = to.min(have).saturating_sub(from) as usize;
        let mut bytes = vec![0; (to - from) as usize + 16];
        if real > 0 {
            let start = (from - self.base) as usize;
            bytes[..real].copy_from_slice(&self.ahead[start..start + real]);
        }
        (bytes.into_boxed_slice(), real)
    }

    /// The block header at `scan_at`, its tables, and its block for a thread.
    fn scan(&mut self, io: &mut dyn UnpIo) {
        let Some(header_at) = self.scan_at else {
            return;
        };
        self.read_until(io, header_at + 8);
        let (header, real) = self.copy(header_at, header_at + 8);
        let Some(header) = parse_header(&header, real) else {
            self.stop();
            return;
        };
        let block_start = header_at + header.length;
        let end = block_start as i64 + i64::from(header.block_size) - 1;
        let mut data_bits = block_start as i64 * 8;
        if header.table_present {
            // More than the tables can take, in bytes: 20 lengths of 8 bits
            // at most, then 430 of 22.
            let room = 2048;
            self.read_until(io, block_start + room);
            let (bytes, real) = self.copy(block_start, block_start + room);
            let mut inp = BitInput::over(bytes, 0);
            match read_tables(&mut inp, self.extra_dist) {
                Some(lengths) if bits_at(&inp) <= real as i64 * 8 => {
                    let mut tables = BlockTables::zero();
                    make_tables(&mut tables, &lengths);
                    self.tables = Some((Arc::new(tables), Arc::new(lengths)));
                    data_bits += bits_at(&inp);
                }
                _ => {
                    self.stop();
                    return;
                }
            }
        }
        let mut pending = Pending {
            bytes: 0,
            header_at: header_at as i64,
            data_bits,
            lengths: None,
            result: None,
        };
        if let Some((tables, lengths)) = self.tables.clone()
            && i64::from(header.block_size) <= LARGEST_BLOCK
        {
            let from = (data_bits / 8) as u64;
            let to = (end + 1).max(from as i64) as u64 + PAST_END;
            self.read_until(io, to);
            let (bytes, real) = self.copy(from, to);
            let held = bytes.len();
            let (reply, result) = mpsc::channel();
            let job = Job {
                bytes,
                first_bit: (data_bits % 8) as u32,
                real,
                end: end - from as i64,
                bit_size: header.bit_size,
                tables,
                reply,
            };
            if self.jobs.send(job).is_ok() {
                pending.bytes = held;
                self.in_flight += held;
                pending.lengths = Some(lengths);
                pending.result = Some(result);
            }
        }
        self.pending.push_back(pending);
        self.scan_at =
            (!header.last).then_some(block_start + u64::try_from(header.block_size).unwrap_or(0));
        // What is behind the scan is no longer needed.
        if let Some(at) = self.scan_at
            && at > self.base + (8 << 20)
        {
            let gone = ((at - self.base) as usize).min(self.ahead.len());
            self.ahead.drain(..gone);
            self.base += gone as u64;
        }
    }
}

/// A block header as `ReadBlockHeader` reads it.
struct Header {
    /// Its length in bytes.
    length: u64,
    block_size: i32,
    bit_size: i32,
    last: bool,
    table_present: bool,
}

/// The block header at the start of `bytes`, of which `real` are packed
/// data: none if it is not one, or not all packed data.
fn parse_header(bytes: &[u8], real: usize) -> Option<Header> {
    let flags = bytes[0];
    let byte_count = usize::from((flags >> 3) & 3) + 1;
    if byte_count == 4 || 2 + byte_count > real {
        return None;
    }
    let saved_check_sum = bytes[1];
    let mut block_size = 0i32;
    for i in 0..byte_count {
        block_size += i32::from(bytes[2 + i]) << (i * 8);
    }
    let check_sum =
        (0x5a ^ i32::from(flags) ^ block_size ^ (block_size >> 8) ^ (block_size >> 16)) as u8;
    if check_sum != saved_check_sum {
        return None;
    }
    Some(Header {
        length: 2 + byte_count as u64,
        block_size,
        bit_size: i32::from(flags & 7) + 1,
        last: flags & 0x40 != 0,
        table_present: flags & 0x80 != 0,
    })
}

/// `ReadTables`, from `inp`, which holds what they can take: the lengths, or
/// none where it gives false.
fn read_tables(inp: &mut BitInput, extra_dist: bool) -> Option<TableLengths> {
    let mut bit_length = [0u8; BC];
    let mut i = 0;
    while i < BC {
        let length = (inp.getbits() >> 12) as u8;
        inp.addbits(4);
        if length == 15 {
            let zero_count = (inp.getbits() >> 12) as u8;
            inp.addbits(4);
            if zero_count == 0 {
                bit_length[i] = 15;
            } else {
                let mut zero_count = zero_count + 2;
                while zero_count > 0 && i < BC {
                    zero_count -= 1;
                    bit_length[i] = 0;
                    i += 1;
                }
                i -= 1;
            }
        } else {
            bit_length[i] = length;
        }
        i += 1;
    }
    let mut bd = super::DecodeTable::zero();
    bd.make(&bit_length);

    let mut table = [0u8; HUFF_TABLE_SIZEX];
    let table_size = if extra_dist {
        HUFF_TABLE_SIZEX
    } else {
        HUFF_TABLE_SIZEB
    };
    let mut i = 0;
    while i < table_size {
        let number = bd.decode(inp);
        if number < 16 {
            table[i] = number as u8;
            i += 1;
        } else if number < 18 {
            let n = if number == 16 {
                let n = (inp.getbits() >> 13) + 3;
                inp.addbits(3);
                n
            } else {
                let n = (inp.getbits() >> 9) + 11;
                inp.addbits(7);
                n
            };
            if i == 0 {
                return None;
            }
            for _ in 0..n {
                if i >= table_size {
                    break;
                }
                table[i] = table[i - 1];
                i += 1;
            }
        } else {
            let n = if number == 18 {
                let n = (inp.getbits() >> 13) + 3;
                inp.addbits(3);
                n
            } else {
                let n = (inp.getbits() >> 9) + 11;
                inp.addbits(7);
                n
            };
            for _ in 0..n {
                if i >= table_size {
                    break;
                }
                table[i] = 0;
                i += 1;
            }
        }
    }
    Some(TableLengths {
        lengths: table,
        extra_dist,
    })
}

/// The tables `ReadTables` makes from `lengths`.
pub(super) fn make_tables(tables: &mut BlockTables, lengths: &TableLengths) {
    let table = &lengths.lengths;
    let d_codes = if lengths.extra_dist { DCX } else { DCB };
    tables.ld.make(&table[..NC]);
    tables.dd.make(&table[NC..NC + d_codes]);
    tables.ldd.make(&table[NC + d_codes..NC + d_codes + LDC]);
    tables
        .rd
        .make(&table[NC + d_codes + LDC..NC + d_codes + LDC + RC]);
}

impl Unpack {
    /// [`Unpack::unpack5_with`], its blocks decoded ahead by threads, all but
    /// the caller's, which writes what they decode.
    pub(super) fn unpack5_mt(
        &mut self,
        solid: bool,
        io: &mut dyn UnpIo,
        size: u64,
    ) -> Result<(), Error> {
        let workers = (self.threads as usize).saturating_sub(1).max(1);
        let (jobs, taken) = mpsc::channel::<Job>();
        let taken = Mutex::new(taken);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let job = taken.lock().unwrap_or_else(PoisonError::into_inner).recv();
                        let Ok(job) = job else {
                            break;
                        };
                        let (decoded, reply) = decode_block(job);
                        // The caller's thread may have gone on without it.
                        let _ = reply.send(decoded);
                    }
                });
            }
            let mut spec = Speculation::new(jobs, size, self.extra_dist, workers);
            // The first blocks go to the threads while this one starts.
            spec.fill(io);
            let result = self.unpack5_with(solid, io, Some(&mut spec));
            // The threads end once no job can come.
            drop(spec);
            result
        })
    }
}
