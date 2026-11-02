//! Compression: port of `deflate.{h,c}`.
//!
//! The "deflation" process depends on being able to identify portions of
//! the input text which are identical to earlier input (within a sliding
//! window trailing behind the input currently being processed). The most
//! straightforward technique turns out to be the fastest for most input
//! files: try all possible matches and select the longest. The key feature
//! of this algorithm is that insertions into the string dictionary are very
//! simple and thus fast, and deletions are avoided completely. Insertions
//! are performed at each input character, whereas string matches are
//! performed only when the previous match ends. So it is preferable to
//! spend more time in matches to allow very fast string insertions and
//! avoid deletions. The matching algorithm for small strings is inspired
//! from that of Rabin & Karp. A brute force approach is used to find longer
//! strings when a small match has been found.
//!
//! Differs from zlib: the stream (`z_stream`) and its state are one value,
//! [`Deflate`], whose input and output are given to each call as an
//! [`InBuffer`] and an [`OutBuffer`], as for [`crate::deflate::Inflate`].

use crate::deflate::adler32::{ADLER32_INIT, adler32};
use crate::deflate::crc32::crc32;
use crate::deflate::inflate::{GzHeader, InBuffer, OutBuffer};
use crate::deflate::trees::{
    BL_CODES, CtData, D_CODES, HEAP_SIZE, Heap, MAX_MATCH, MIN_MATCH, STATIC_BL_DESC,
    STATIC_D_DESC, STATIC_L_DESC, TreeDesc, Z_UNKNOWN,
};
use crate::deflate::zutil::{
    Error, ErrorCode, Flush, MAX_WBITS, Result, Status, Z_BUF_ERROR, Z_OK, Z_STREAM_END, result,
};

/// `Z_DEFAULT_COMPRESSION`: level 6.
pub const Z_DEFAULT_COMPRESSION: i32 = -1;
/// The compression strategies: `Z_FILTERED`, `Z_HUFFMAN_ONLY`, `Z_RLE`,
/// `Z_FIXED` and `Z_DEFAULT_STRATEGY`, with zlib's numbers.
pub const Z_FILTERED: i32 = 1;
pub const Z_HUFFMAN_ONLY: i32 = 2;
pub const Z_RLE: i32 = 3;
pub const Z_FIXED: i32 = 4;
pub const Z_DEFAULT_STRATEGY: i32 = 0;
/// `MAX_MEM_LEVEL`, `DEF_MEM_LEVEL`: the largest memory level, and the one
/// `deflateInit` uses.
pub const MAX_MEM_LEVEL: i32 = 9;
pub const DEF_MEM_LEVEL: i32 = 8;

/// `NIL`: tail of hash chains.
const NIL: u16 = 0;
/// `TOO_FAR`: matches of length 3 are discarded if their distance exceeds
/// TOO_FAR.
const TOO_FAR: u32 = 4096;
/// `MIN_LOOKAHEAD`: minimum amount of lookahead, except at the end of the
/// input file.
const MIN_LOOKAHEAD: u32 = (MAX_MATCH + MIN_MATCH + 1) as u32;
/// `WIN_INIT`: number of bytes after end of data in window to initialize in
/// order to avoid memory checker errors from longest match routines.
const WIN_INIT: usize = MAX_MATCH;
/// `MAX_STORED`: maximum stored block length in deflate format (not
/// including header).
const MAX_STORED: u32 = 65535;
/// `PRESET_DICT`: preset dictionary flag in zlib header.
const PRESET_DICT: u32 = 0x20;
/// `Z_DEFLATED`.
const Z_DEFLATED: u32 = 8;

/// `OS_CODE`: the operating system zlib writes in a gzip header, which is
/// chosen when it is built, as here.
const OS_CODE: u8 = if cfg!(windows) {
    10
} else if cfg!(target_vendor = "apple") {
    19
} else {
    3
};

/// The stream's status: `INIT_STATE` to `FINISH_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// zlib header -> BUSY_STATE
    Init = 42,
    /// gzip header -> BUSY_STATE | EXTRA_STATE
    Gzip = 57,
    /// gzip extra block -> NAME_STATE
    Extra = 69,
    /// gzip file name -> COMMENT_STATE
    Name = 73,
    /// gzip comment -> HCRC_STATE
    Comment = 91,
    /// gzip header CRC -> BUSY_STATE
    Hcrc = 103,
    /// deflate -> FINISH_STATE
    Busy = 113,
    /// stream complete
    Finish = 666,
}

/// `block_state`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BlockState {
    /// block not completed, need more input or more output
    NeedMore,
    /// block flush performed
    BlockDone,
    /// finish started, need only more output at next deflate
    FinishStarted,
    /// finish done, accept no more input or output
    FinishDone,
}

/// Which compression function a level uses (`compress_func`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Func {
    Stored,
    Fast,
    Slow,
}

/// `config`: values for max_lazy_match, good_match, nice_match and
/// max_chain_length, depending on the desired pack level (0..9).
struct Config {
    /// reduce lazy search above this match length
    good_length: u16,
    /// do not perform lazy search above this match length
    max_lazy: u16,
    /// quit search above this match length
    nice_length: u16,
    max_chain: u16,
    func: Func,
}

/// `configuration_table`. The values have been tuned to exclude worst case
/// performance for pathological files. Better values may be found for
/// specific files.
#[rustfmt::skip]
static CONFIGURATION_TABLE: [Config; 10] = [
    //     good lazy nice chain
    /* 0 */ Config { good_length: 0, max_lazy: 0, nice_length: 0, max_chain: 0, func: Func::Stored }, // store only
    /* 1 */ Config { good_length: 4, max_lazy: 4, nice_length: 8, max_chain: 4, func: Func::Fast }, // max speed, no lazy matches
    /* 2 */ Config { good_length: 4, max_lazy: 5, nice_length: 16, max_chain: 8, func: Func::Fast },
    /* 3 */ Config { good_length: 4, max_lazy: 6, nice_length: 32, max_chain: 32, func: Func::Fast },
    /* 4 */ Config { good_length: 4, max_lazy: 4, nice_length: 16, max_chain: 16, func: Func::Slow }, // lazy matches
    /* 5 */ Config { good_length: 8, max_lazy: 16, nice_length: 32, max_chain: 32, func: Func::Slow },
    /* 6 */ Config { good_length: 8, max_lazy: 16, nice_length: 128, max_chain: 128, func: Func::Slow },
    /* 7 */ Config { good_length: 8, max_lazy: 32, nice_length: 128, max_chain: 256, func: Func::Slow },
    /* 8 */ Config { good_length: 32, max_lazy: 128, nice_length: 258, max_chain: 1024, func: Func::Slow },
    /* 9 */ Config { good_length: 32, max_lazy: 258, nice_length: 258, max_chain: 4096, func: Func::Slow }, // max compression
];

/// `RANK`: ranks Z_BLOCK between Z_NO_FLUSH and Z_PARTIAL_FLUSH.
fn rank(f: i32) -> i32 {
    (f * 2) - if f > 4 { 9 } else { 0 }
}

/// The pending output: `pending_buf`, `pending_out`, `pending` and the bit
/// buffer of `deflate_state`. The symbol buffer is in `buf` too, from
/// `DeflateState::sym_buf` on, as zlib overlays them.
#[derive(Clone)]
pub(crate) struct Pending {
    /// output still pending, and the symbols (`pending_buf`); its length is
    /// `pending_buf_size`
    pub buf: Vec<u8>,
    /// next pending byte to output to the stream (`pending_out`)
    pub out: usize,
    /// nb of bytes in the pending buffer
    pub pending: usize,
    /// Output buffer. bits are inserted starting at the bottom (least
    /// significant bits).
    pub bi_buf: u16,
    /// Number of valid bits in bi_buf. All bits above the last valid bit
    /// are always zero.
    pub bi_valid: i32,
    /// Last number of used bits when going to a byte boundary.
    pub bi_used: i32,
}

/// The stream the functions below read from and write to, during one call:
/// `z_stream`'s buffers and counts.
pub(crate) struct Strm<'a, 'b> {
    pub input: &'a [u8],
    pub next_in: usize,
    pub output: &'b mut [u8],
    pub next_out: usize,
    pub total_in: u64,
    pub total_out: u64,
    pub adler: u32,
    pub data_type: i32,
}

impl Strm<'_, '_> {
    fn avail_in(&self) -> usize {
        self.input.len() - self.next_in
    }

    fn avail_out(&self) -> usize {
        self.output.len() - self.next_out
    }
}

/// The internal compression state: `deflate_state` in `deflate.h`.
#[derive(Clone)]
pub(crate) struct DeflateState {
    /// as the name implies
    status: State,
    /// the pending output and the bit buffer
    pub(crate) out: Pending,
    /// bit 0 true for zlib, bit 1 true for gzip; negated once the trailer
    /// is written
    wrap: i32,
    /// gzip header information to write
    gzhead: Option<GzHeader>,
    /// where in extra, name, or comment
    gzindex: usize,
    /// value of flush param for previous deflate call
    last_flush: i32,

    // used by deflate.c:
    /// LZ77 window size (32K by default)
    w_size: u32,
    /// log2(w_size) (8..16)
    w_bits: u32,
    /// w_size - 1
    w_mask: u32,
    /// Sliding window. Input bytes are read into the second half of the
    /// window, and move to the first half later to keep a dictionary of at
    /// least wSize bytes. With this organization, matches are limited to a
    /// distance of wSize-MAX_MATCH bytes, but this ensures that IO is
    /// always performed with a length multiple of the block size.
    pub(crate) window: Vec<u8>,
    /// Actual size of window: 2*wSize
    window_size: u32,
    /// Link to older string with same hash index. To limit the size of
    /// this array to 64K, this link is maintained only for the last 32K
    /// strings. An index in this array is thus a window index modulo 32K.
    prev: Vec<u16>,
    /// Heads of the hash chains or NIL.
    head: Vec<u16>,
    /// hash index of string to be inserted
    ins_h: u32,
    /// number of elements in hash table
    #[allow(
        dead_code,
        reason = "kept as zlib has it; the buffers' lengths give it"
    )]
    hash_size: u32,
    /// log2(hash_size)
    hash_bits: u32,
    /// hash_size-1
    hash_mask: u32,
    /// Number of bits by which ins_h must be shifted at each input step. It
    /// must be such that after MIN_MATCH steps, the oldest byte no longer
    /// takes part in the hash key, that is: hash_shift * MIN_MATCH >=
    /// hash_bits
    hash_shift: u32,
    /// Window position at the beginning of the current output block. Gets
    /// negative when the window is moved backwards.
    block_start: i64,
    /// length of best match
    match_length: u32,
    /// previous match
    prev_match: u32,
    /// set if previous match exists
    match_available: bool,
    /// start of string to insert
    strstart: u32,
    /// start of matching string
    match_start: u32,
    /// number of valid bytes ahead in window
    lookahead: u32,
    /// Length of the best match at previous step. Matches not greater than
    /// this are discarded. This is used in the lazy match evaluation.
    prev_length: u32,
    /// To speed up deflation, hash chains are never searched beyond this
    /// length. A higher limit improves compression ratio but degrades the
    /// speed.
    max_chain_length: u32,
    /// Attempt to find a better match only when the current match is
    /// strictly smaller than this value. This mechanism is used only for
    /// compression levels >= 4. For levels <= 3 it is `max_insert_length`:
    /// insert new strings in the hash table only if the match length is not
    /// greater than this length.
    max_lazy_match: u32,
    /// compression level (1..9)
    pub(crate) level: i32,
    /// favor or force Huffman coding
    pub(crate) strategy: i32,
    /// Use a faster search when the previous match is longer than this
    good_match: u32,
    /// Stop searching when current match exceeds this
    nice_match: i32,

    // used by trees.c:
    /// literal and length tree
    pub(crate) dyn_ltree: [CtData; HEAP_SIZE],
    /// distance tree
    pub(crate) dyn_dtree: [CtData; 2 * D_CODES + 1],
    /// Huffman tree for bit lengths
    pub(crate) bl_tree: [CtData; 2 * BL_CODES + 1],
    /// desc. for literal tree
    pub(crate) l_desc: TreeDesc,
    /// desc. for distance tree
    pub(crate) d_desc: TreeDesc,
    /// desc. for bit length tree
    pub(crate) bl_desc: TreeDesc,
    /// the trees' working space, and the block lengths
    pub(crate) heap: Heap,
    /// where the symbol buffer (distances and literals/lengths) starts in
    /// `out.buf` (`sym_buf`)
    pub(crate) sym_buf: usize,
    /// Size of match buffer for literals/lengths.
    #[allow(
        dead_code,
        reason = "kept as zlib has it; the buffers' lengths give it"
    )]
    lit_bufsize: usize,
    /// running index in symbol buffer
    pub(crate) sym_next: usize,
    /// symbol table full when sym_next reaches this
    pub(crate) sym_end: usize,
    /// number of string matches in current block
    pub(crate) matches: u32,
    /// bytes at end of window left to insert
    insert: u32,
    /// High water mark offset in window for initialized bytes -- bytes
    /// above this are set to zero in order to avoid memory check warnings
    /// when longest match routines access bytes past the input. This is
    /// then updated to the new high water mark.
    high_water: usize,
    /// True if the hash table has been slid since it was cleared.
    slid: bool,
}

/// A compression stream: `z_stream` with its `deflate_state`.
///
/// ```
/// # fn main() -> Result<(), hivepack::deflate::Error> {
/// use hivepack::deflate::{Deflate, Flush, InBuffer, OutBuffer, Status};
///
/// let mut deflate = Deflate::new(6, -15, 8, 0)?;
/// let mut out = [0; 64];
/// let mut output = OutBuffer::new(&mut out);
/// let status = deflate.deflate(&mut output, &mut InBuffer::new(b"hello"), Flush::Finish)?;
/// assert_eq!(status, Status::StreamEnd);
/// let written = output.pos;
/// assert_eq!(&out[..written], [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Deflate {
    /// total number of input bytes read so far
    total_in: u64,
    /// total number of bytes output so far
    total_out: u64,
    /// last error message, `None` if no error
    msg: Option<&'static str>,
    /// best guess about the data type: binary or text
    data_type: i32,
    /// Adler-32 or CRC-32 value of the uncompressed data
    adler: u32,
    state: Box<DeflateState>,
}

/// `ERR_MSG`: the message zlib sets with `ERR_RETURN`.
fn err_msg(code: ErrorCode) -> Option<&'static str> {
    Some(code.message())
}

impl Deflate {
    /// A stream that compresses at `level` (0 to 9, or
    /// [`Z_DEFAULT_COMPRESSION`]), with a window of 2^`window_bits` bytes
    /// (9 to 15 for a zlib stream, −9 to −15 for raw deflate, 16 more for
    /// gzip; 8 is taken as 9 for zlib streams only), a memory level of 1 to
    /// 9 ([`DEF_MEM_LEVEL`] is zlib's default), and a strategy
    /// ([`Z_DEFAULT_STRATEGY`] to [`Z_FIXED`]).
    ///
    /// Port of `deflateInit2_`, `deflate.c`.
    pub fn new(level: i32, mut window_bits: i32, mem_level: i32, strategy: i32) -> Result<Deflate> {
        let mut level = level;
        let mut wrap = 1;

        if level == Z_DEFAULT_COMPRESSION {
            level = 6;
        }

        if window_bits < 0 {
            // suppress zlib wrapper
            wrap = 0;
            if window_bits < -15 {
                return Err(Error::stream());
            }
            window_bits = -window_bits;
        } else if window_bits > 15 {
            wrap = 2; // write gzip wrapper instead
            window_bits -= 16;
        }
        if !(1..=MAX_MEM_LEVEL).contains(&mem_level)
            || !(8..=15).contains(&window_bits)
            || !(0..=9).contains(&level)
            || !(0..=Z_FIXED).contains(&strategy)
            || (window_bits == 8 && wrap != 1)
        {
            return Err(Error::stream());
        }
        if window_bits == 8 {
            window_bits = 9; // until 256-byte window bug fixed
        }

        let w_bits = window_bits as u32;
        let w_size = 1u32 << w_bits;
        let hash_bits = mem_level as u32 + 7;
        let hash_size = 1u32 << hash_bits;
        let lit_bufsize = 1usize << (mem_level + 6); // 16K elements by default

        // We overlay pending_buf and sym_buf. This works since the average
        // size for length/distance pairs over any compressed block is
        // assured to be 31 bits or less. (See deflate.c for the analysis.)
        // Differs from zlib: the buffers are zeroed, where zlib leaves them
        // as allocated; nothing reads a byte before it is written.
        let state = DeflateState {
            status: State::Init, // to pass state test in deflateReset()
            out: Pending {
                buf: vec![0; lit_bufsize * 4],
                out: 0,
                pending: 0,
                bi_buf: 0,
                bi_valid: 0,
                bi_used: 0,
            },
            wrap,
            gzhead: None,
            gzindex: 0,
            last_flush: 0,
            w_size,
            w_bits,
            w_mask: w_size - 1,
            window: vec![0; 2 * w_size as usize],
            window_size: 0,
            prev: vec![0; w_size as usize],
            head: vec![0; hash_size as usize],
            ins_h: 0,
            hash_size,
            hash_bits,
            hash_mask: hash_size - 1,
            hash_shift: hash_bits.div_ceil(MIN_MATCH as u32),
            block_start: 0,
            match_length: 0,
            prev_match: 0,
            match_available: false,
            strstart: 0,
            match_start: 0,
            lookahead: 0,
            prev_length: 0,
            max_chain_length: 0,
            max_lazy_match: 0,
            level,
            strategy,
            good_match: 0,
            nice_match: 0,
            dyn_ltree: [CtData::default(); HEAP_SIZE],
            dyn_dtree: [CtData::default(); 2 * D_CODES + 1],
            bl_tree: [CtData::default(); 2 * BL_CODES + 1],
            l_desc: TreeDesc {
                max_code: 0,
                stat_desc: &STATIC_L_DESC,
            },
            d_desc: TreeDesc {
                max_code: 0,
                stat_desc: &STATIC_D_DESC,
            },
            bl_desc: TreeDesc {
                max_code: 0,
                stat_desc: &STATIC_BL_DESC,
            },
            heap: Heap::default(),
            sym_buf: lit_bufsize,
            lit_bufsize,
            sym_next: 0,
            // We avoid equality with lit_bufsize*3 because of wraparound at
            // 64K on 16 bit machines and because stored blocks are
            // restricted to 64K-1 bytes.
            sym_end: (lit_bufsize - 1) * 3,
            matches: 0,
            insert: 0,
            high_water: 0, // nothing written to s->window yet
            slid: false,
        };
        let mut strm = Deflate {
            total_in: 0,
            total_out: 0,
            msg: None,
            data_type: 0,
            adler: 0,
            state: Box::new(state),
        };
        strm.reset();
        Ok(strm)
    }

    /// A zlib stream at `level`, with zlib's default window, memory level
    /// and strategy: `deflateInit`.
    pub fn new_default(level: i32) -> Result<Deflate> {
        Deflate::new(level, MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY)
    }

    /// Sets the dictionary: before the first call of [`Deflate::deflate`]
    /// for a zlib stream, or at any time between blocks for a raw stream.
    /// Not for gzip streams.
    ///
    /// Port of `deflateSetDictionary`, `deflate.c`.
    pub fn set_dictionary(&mut self, mut dictionary: &[u8]) -> Result<()> {
        let s = &mut *self.state;
        let wrap = s.wrap;
        if wrap == 2 || (wrap == 1 && s.status != State::Init) || s.lookahead != 0 {
            return Err(Error::stream());
        }

        // when using zlib wrappers, compute Adler-32 for provided dictionary
        if wrap == 1 {
            self.adler = adler32(self.adler, dictionary);
        }
        s.wrap = 0; // avoid computing Adler-32 in read_buf

        // if dictionary would fill window, just replace the history
        if dictionary.len() >= s.w_size as usize {
            if wrap == 0 {
                // already empty otherwise
                s.clear_hash();
                s.strstart = 0;
                s.block_start = 0;
                s.insert = 0;
            }
            dictionary = &dictionary[dictionary.len() - s.w_size as usize..]; // use the tail
        }

        // insert dictionary into window and hash
        let mut output = [0u8; 0];
        let mut strm = Strm {
            input: dictionary,
            next_in: 0,
            output: &mut output,
            next_out: 0,
            total_in: self.total_in,
            total_out: self.total_out,
            adler: self.adler,
            data_type: self.data_type,
        };
        s.fill_window(&mut strm);
        while s.lookahead >= MIN_MATCH as u32 {
            let mut str = s.strstart;
            let mut n = s.lookahead - (MIN_MATCH as u32 - 1);
            loop {
                s.update_hash(s.window[(str + MIN_MATCH as u32 - 1) as usize]);
                s.prev[(str & s.w_mask) as usize] = s.head[s.ins_h as usize];
                s.head[s.ins_h as usize] = str as u16;
                str += 1;
                n -= 1;
                if n == 0 {
                    break;
                }
            }
            s.strstart = str;
            s.lookahead = MIN_MATCH as u32 - 1;
            s.fill_window(&mut strm);
        }
        // fill_window counted the dictionary as input; zlib restores
        // next_in and avail_in only, but total_in was changed by read_buf.
        self.total_in = strm.total_in;
        s.strstart += s.lookahead;
        s.block_start = i64::from(s.strstart);
        s.insert = s.lookahead;
        s.lookahead = 0;
        s.match_length = MIN_MATCH as u32 - 1;
        s.prev_length = MIN_MATCH as u32 - 1;
        s.match_available = false;
        s.wrap = wrap;
        Ok(())
    }

    /// Copies the last window of what was given to compress, up to 32 KiB,
    /// the dictionary for what follows, to the start of `dictionary` if
    /// given, and returns its length.
    ///
    /// Port of `deflateGetDictionary`, `deflate.c`.
    pub fn get_dictionary(&self, dictionary: Option<&mut [u8]>) -> usize {
        let s = &*self.state;
        let len = ((s.strstart + s.lookahead) as usize).min(s.w_size as usize);
        if len != 0
            && let Some(dictionary) = dictionary
        {
            let end = (s.strstart + s.lookahead) as usize;
            dictionary[..len].copy_from_slice(&s.window[end - len..end]);
        }
        len
    }

    /// Resets the stream for a new one, keeping the dictionary state.
    ///
    /// Port of `deflateResetKeep`, `deflate.c`.
    pub fn reset_keep(&mut self) {
        self.total_in = 0;
        self.total_out = 0;
        self.msg = None; // use zfree if we ever allocate msg dynamically
        self.data_type = Z_UNKNOWN;

        let s = &mut *self.state;
        s.out.pending = 0;
        s.out.out = 0;

        if s.wrap < 0 {
            s.wrap = -s.wrap; // was made negative by deflate(..., Z_FINISH);
        }
        s.status = if s.wrap == 2 {
            State::Gzip
        } else {
            State::Init
        };
        self.adler = if s.wrap == 2 {
            crc32(0, &[])
        } else {
            ADLER32_INIT
        };
        s.last_flush = -2;

        s.tr_init();
    }

    /// Resets the stream for a new one with the same parameters.
    ///
    /// Port of `deflateReset`, `deflate.c`.
    pub fn reset(&mut self) {
        self.reset_keep();
        self.state.lm_init();
    }

    /// Gives the gzip header to write, for a gzip stream, before the first
    /// call of [`Deflate::deflate`]. The name and comment end at their
    /// first zero byte (or their end); the extra field is its first
    /// `extra_len` bytes.
    ///
    /// Port of `deflateSetHeader`, `deflate.c`.
    pub fn set_header(&mut self, head: GzHeader) -> Result<()> {
        if self.state.wrap != 2 {
            return Err(Error::stream());
        }
        self.state.gzhead = Some(head);
        Ok(())
    }

    /// The bytes and bits of output still pending: zlib's
    /// `deflatePending`, which fails with `ErrorCode::Buf` when the bytes
    /// do not fit in an `unsigned`.
    pub fn pending(&self) -> (usize, i32) {
        (self.state.out.pending, self.state.out.bi_valid)
    }

    /// The number of bits used in the last byte of the last block written:
    /// `deflateUsed`.
    pub fn used(&self) -> i32 {
        self.state.out.bi_used
    }

    /// Inserts `bits` bits of `value` into the output, before what follows.
    ///
    /// Port of `deflatePrime`, `deflate.c`.
    pub fn prime(&mut self, mut bits: i32, mut value: i32) -> Result<()> {
        let s = &mut *self.state;
        if !(0..=16).contains(&bits) || s.sym_buf < s.out.out + ((16 + 7) >> 3) {
            return Err(Error::new(ErrorCode::Buf, self.msg));
        }
        loop {
            let put = (16 - s.out.bi_valid).min(bits);
            s.out.bi_buf |= ((value & ((1 << put) - 1)) << s.out.bi_valid) as u16;
            s.out.bi_valid += put;
            s.tr_flush_bits();
            value >>= put;
            bits -= put;
            if bits == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Changes the level and strategy, compressing what was given so far
    /// with the old ones first: that calls [`Deflate::deflate`] with
    /// `Flush::Block`, with `output` and `input`, and fails with
    /// `ErrorCode::Buf` if that could not finish.
    ///
    /// Port of `deflateParams`, `deflate.c`.
    pub fn params(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        mut level: i32,
        strategy: i32,
    ) -> Result<()> {
        if level == Z_DEFAULT_COMPRESSION {
            level = 6;
        }
        if !(0..=9).contains(&level) || !(0..=Z_FIXED).contains(&strategy) {
            return Err(Error::stream());
        }
        let s = &*self.state;
        let func = CONFIGURATION_TABLE[s.level as usize].func;

        if (strategy != s.strategy || func != CONFIGURATION_TABLE[level as usize].func)
            && s.last_flush != -2
        {
            // Flush the last buffer:
            let err = self.deflate(output, input, Flush::Block);
            if let Err(e) = err
                && e.code() == ErrorCode::Stream
            {
                return Err(e);
            }
            let s = &*self.state;
            if input.pos < input.src.len()
                || (i64::from(s.strstart) - s.block_start) + i64::from(s.lookahead) != 0
            {
                return Err(Error::new(ErrorCode::Buf, self.msg));
            }
        }
        let s = &mut *self.state;
        if s.level != level {
            if s.level == 0 && s.matches != 0 {
                if s.matches == 1 {
                    s.slide_hash();
                } else {
                    s.clear_hash();
                }
                s.matches = 0;
            }
            s.level = level;
            let config = &CONFIGURATION_TABLE[level as usize];
            s.max_lazy_match = u32::from(config.max_lazy);
            s.good_match = u32::from(config.good_length);
            s.nice_match = i32::from(config.nice_length);
            s.max_chain_length = u32::from(config.max_chain);
        }
        s.strategy = strategy;
        Ok(())
    }

    /// Sets the match finder's parameters directly, as the levels'
    /// configuration does.
    ///
    /// Port of `deflateTune`, `deflate.c`.
    pub fn tune(&mut self, good_length: i32, max_lazy: i32, nice_length: i32, max_chain: i32) {
        let s = &mut *self.state;
        s.good_match = good_length as u32;
        s.max_lazy_match = max_lazy as u32;
        s.nice_match = nice_length;
        s.max_chain_length = max_chain as u32;
    }

    /// An upper bound on the compressed size of `source_len` bytes.
    ///
    /// Port of `deflateBound_z` (and `deflateBound`), `deflate.c`.
    pub fn bound(&self, source_len: u64) -> u64 {
        let s = &*self.state;

        // upper bound for fixed blocks with 9-bit literals and length 255
        // (memLevel == 2, which is the lowest that may not use stored
        // blocks) -- ~13% overhead plus a small constant
        let fixedlen = source_len
            .saturating_add((source_len >> 3) + (source_len >> 8) + (source_len >> 9) + 4);

        // upper bound for stored blocks with length 127 (memLevel == 1) --
        // ~4% overhead plus a small constant
        let storelen = source_len
            .saturating_add((source_len >> 5) + (source_len >> 7) + (source_len >> 11) + 7);

        // compute wrapper length
        let wraplen: u64 = match s.wrap.abs() {
            0 => 0,                                       // raw deflate
            1 => 6 + if s.strstart != 0 { 4 } else { 0 }, // zlib wrapper
            2 => {
                // gzip wrapper
                let mut wraplen = 18;
                if let Some(head) = &s.gzhead {
                    // user-supplied gzip header
                    if head.extra.is_some() {
                        wraplen += 2 + u64::from(head.extra_len);
                    }
                    for text in [&head.name, &head.comment].into_iter().flatten() {
                        wraplen += zero_terminated(text).len() as u64;
                    }
                    if head.hcrc != 0 {
                        wraplen += 2;
                    }
                }
                wraplen
            }
            _ => 18, // for compiler happiness
        };

        // if not default parameters, return one of the conservative bounds
        if s.w_bits != 15 || s.hash_bits != 8 + 7 {
            let bound = if s.w_bits <= s.hash_bits && s.level != 0 {
                fixedlen
            } else {
                storelen
            };
            return bound.saturating_add(wraplen);
        }

        // default settings: return tight bound for that case -- ~0.03%
        // overhead plus a small constant
        let bound = source_len.wrapping_add(
            (source_len >> 12) + (source_len >> 14) + (source_len >> 25) + 13 - 6 + wraplen,
        );
        if bound < source_len { u64::MAX } else { bound }
    }

    /// Compresses as much as `input` and the space in `output` allow, and
    /// moves their positions past what was read and written. With
    /// `Flush::Finish`, finishes the stream: `Status::StreamEnd` once all
    /// of it is written, `Status::Ok` while more output space is needed.
    /// `ErrorCode::Buf` means that no progress was possible; it is not
    /// fatal.
    ///
    /// Port of `deflate`, `deflate.c`.
    pub fn deflate(
        &mut self,
        output: &mut OutBuffer<'_>,
        input: &mut InBuffer<'_>,
        flush: Flush,
    ) -> Result<Status> {
        if output.pos > output.dst.len() || input.pos > input.src.len() {
            return Err(Error::stream());
        }
        let flush_n = flush as i32;
        if flush_n > Flush::Block as i32 {
            return Err(Error::stream());
        }
        let Deflate {
            total_in,
            total_out,
            msg,
            data_type,
            adler,
            state,
        } = self;
        let s = &mut **state;
        let mut strm = Strm {
            input: input.src,
            next_in: input.pos,
            output: &mut *output.dst,
            next_out: output.pos,
            total_in: *total_in,
            total_out: *total_out,
            adler: *adler,
            data_type: *data_type,
        };
        let ret = s.deflate(&mut strm, flush_n, msg);
        input.pos = strm.next_in;
        output.pos = strm.next_out;
        *total_in = strm.total_in;
        *total_out = strm.total_out;
        *adler = strm.adler;
        *data_type = strm.data_type;
        result(ret, *msg)
    }

    /// Ends the stream: fails with `ErrorCode::Data` if it was not
    /// finished, which only says that output was lost.
    ///
    /// Port of `deflateEnd`, `deflate.c`.
    pub fn end(self) -> Result<()> {
        if self.state.status == State::Busy {
            Err(Error::new(ErrorCode::Data, self.msg))
        } else {
            Ok(())
        }
    }

    /// The number of input bytes read so far: `total_in`.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    /// The number of bytes written so far: `total_out`.
    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// The Adler-32 (zlib) or CRC-32 (gzip) of the input so far: `adler`.
    pub fn adler(&self) -> u32 {
        self.adler
    }

    /// Whether the input looked like text (1) or binary (0), or 2 before
    /// the first block was written: `data_type`.
    pub fn data_type(&self) -> i32 {
        self.data_type
    }

    /// The message of the last error, if any: `msg`.
    pub fn msg(&self) -> Option<&'static str> {
        self.msg
    }
}

/// The bytes of a zero-terminated string, the zero included: up to the
/// first zero, or all of them and a zero if there is none.
fn zero_terminated(text: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = text.iter().copied().take_while(|&b| b != 0).collect();
    bytes.push(0);
    bytes
}

impl DeflateState {
    /// `UPDATE_HASH`: updates the hash value with the given input byte.
    /// All calls to UPDATE_HASH are made with consecutive input characters,
    /// so that a running hash key can be computed from the previous key
    /// instead of complete recalculation each time.
    #[inline(always)]
    fn update_hash(&mut self, c: u8) {
        self.ins_h = ((self.ins_h << self.hash_shift) ^ u32::from(c)) & self.hash_mask;
    }

    /// `INSERT_STRING`: inserts string str in the dictionary and returns
    /// the previous head of the hash chain (the most recent string with
    /// same hash key). All calls are made with consecutive input
    /// characters and the first MIN_MATCH bytes of str are valid (except
    /// for the last MIN_MATCH-1 bytes of the input file).
    #[inline(always)]
    fn insert_string(&mut self, str: u32) -> u32 {
        self.update_hash(self.window[(str + MIN_MATCH as u32 - 1) as usize]);
        let match_head = self.head[self.ins_h as usize];
        self.prev[(str & self.w_mask) as usize] = match_head;
        self.head[self.ins_h as usize] = str as u16;
        u32::from(match_head)
    }

    /// `CLEAR_HASH`: initializes the hash table. prev[] will be initialized
    /// on the fly.
    fn clear_hash(&mut self) {
        self.head.fill(NIL);
        self.slid = false;
    }

    /// Slides the hash table when sliding the window down (could be avoided
    /// with 32 bit values at the expense of memory usage). We slide even
    /// when level == 0 to keep the hash table consistent if we switch back
    /// to level > 0 later.
    ///
    /// Port of `slide_hash`, `deflate.c`.
    fn slide_hash(&mut self) {
        let wsize = self.w_size;
        for p in self.head.iter_mut() {
            let m = u32::from(*p);
            *p = if m >= wsize { (m - wsize) as u16 } else { NIL };
        }
        for p in self.prev.iter_mut() {
            let m = u32::from(*p);
            *p = if m >= wsize { (m - wsize) as u16 } else { NIL };
            // If n is not on any hash chain, prev[n] is garbage but its
            // value will never be used.
        }
        self.slid = true;
    }

    /// Reads a new buffer from the current input stream into the window at
    /// `pos`, updates the adler32 and total number of bytes read. All
    /// deflate() input goes through this function, or through
    /// `read_buf_out`.
    ///
    /// Port of `read_buf`, `deflate.c`.
    fn read_buf(&mut self, strm: &mut Strm<'_, '_>, pos: usize, size: usize) -> usize {
        let len = strm.avail_in().min(size);
        if len == 0 {
            return 0;
        }
        let src = &strm.input[strm.next_in..strm.next_in + len];
        self.window[pos..pos + len].copy_from_slice(src);
        if self.wrap == 1 {
            strm.adler = adler32(strm.adler, src);
        } else if self.wrap == 2 {
            strm.adler = crc32(strm.adler, src);
        }
        strm.next_in += len;
        strm.total_in += len as u64;
        len
    }

    /// `read_buf` into the output, for stored blocks copied straight from
    /// the input.
    fn read_buf_out(&mut self, strm: &mut Strm<'_, '_>, size: usize) -> usize {
        let len = strm.avail_in().min(size);
        if len == 0 {
            return 0;
        }
        let (next_in, next_out) = (strm.next_in, strm.next_out);
        strm.output[next_out..next_out + len].copy_from_slice(&strm.input[next_in..next_in + len]);
        let src = &strm.input[next_in..next_in + len];
        if self.wrap == 1 {
            strm.adler = adler32(strm.adler, src);
        } else if self.wrap == 2 {
            strm.adler = crc32(strm.adler, src);
        }
        strm.next_in += len;
        strm.total_in += len as u64;
        len
    }

    /// Fills the window when the lookahead becomes insufficient. Updates
    /// strstart and lookahead. In: lookahead < MIN_LOOKAHEAD. Out:
    /// strstart <= window_size-MIN_LOOKAHEAD; at least one byte has been
    /// read, or avail_in == 0.
    ///
    /// Port of `fill_window`, `deflate.c`.
    fn fill_window(&mut self, strm: &mut Strm<'_, '_>) {
        let wsize = self.w_size;

        loop {
            // Amount of free space at the end of the window.
            let mut more = self.window_size - self.lookahead - self.strstart;

            // If the window is almost full and there is insufficient
            // lookahead, move the upper half to the lower one to make room
            // in the upper half.
            if self.strstart >= wsize + self.max_dist() {
                let w = wsize as usize;
                self.window.copy_within(w..2 * w - more as usize, 0);
                self.match_start = self.match_start.wrapping_sub(wsize);
                self.strstart -= wsize; // we now have strstart >= MAX_DIST
                self.block_start -= i64::from(wsize);
                if self.insert > self.strstart {
                    self.insert = self.strstart;
                }
                self.slide_hash();
                more += wsize;
            }
            if strm.avail_in() == 0 {
                break;
            }

            // If there was no sliding: strstart <= WSIZE+MAX_DIST-1 &&
            // lookahead <= MIN_LOOKAHEAD - 1 && more == window_size -
            // lookahead - strstart => more >= window_size - (MIN_LOOKAHEAD-1
            // + WSIZE + MAX_DIST-1) => more >= window_size - 2*WSIZE + 2. If
            // there was sliding, more >= WSIZE. So in all cases, more >= 2.
            let n = self.read_buf(
                strm,
                (self.strstart + self.lookahead) as usize,
                more as usize,
            );
            self.lookahead += n as u32;

            // Initialize the hash value now that we have some input:
            if self.lookahead + self.insert >= MIN_MATCH as u32 {
                let mut str = self.strstart - self.insert;
                self.ins_h = u32::from(self.window[str as usize]);
                self.update_hash(self.window[str as usize + 1]);
                while self.insert != 0 {
                    self.update_hash(self.window[(str + MIN_MATCH as u32 - 1) as usize]);
                    self.prev[(str & self.w_mask) as usize] = self.head[self.ins_h as usize];
                    self.head[self.ins_h as usize] = str as u16;
                    str += 1;
                    self.insert -= 1;
                    if self.lookahead + self.insert < MIN_MATCH as u32 {
                        break;
                    }
                }
            }
            // If the whole input has less than MIN_MATCH bytes, ins_h is
            // garbage, but this is not important since only literal bytes
            // will be emitted.

            if !(self.lookahead < MIN_LOOKAHEAD && strm.avail_in() != 0) {
                break;
            }
        }

        // If the WIN_INIT bytes after the end of the current data have never
        // been written, then zero those bytes in order to avoid memory check
        // reports of the use of uninitialized bytes by the longest match
        // routines. Update the high water mark for the next time through
        // here. WIN_INIT is set to MAX_MATCH since the longest match
        // routines allow scanning to strstart + MAX_MATCH, ignoring
        // lookahead.
        let window_size = self.window_size as usize;
        if self.high_water < window_size {
            let curr = (self.strstart + self.lookahead) as usize;
            if self.high_water < curr {
                // Previous high water mark below current data -- zero
                // WIN_INIT bytes or up to end of window, whichever is less.
                let init = (window_size - curr).min(WIN_INIT);
                self.window[curr..curr + init].fill(0);
                self.high_water = curr + init;
            } else if self.high_water < curr + WIN_INIT {
                // High water mark at or above current data, but below
                // current data plus WIN_INIT -- zero out to current data
                // plus WIN_INIT, or up to end of window, whichever is less.
                let init = (curr + WIN_INIT - self.high_water).min(window_size - self.high_water);
                let high_water = self.high_water;
                self.window[high_water..high_water + init].fill(0);
                self.high_water += init;
            }
        }
    }

    /// `MAX_DIST`: in order to simplify the code, particularly on 16 bit
    /// machines, match distances are limited to MAX_DIST instead of WSIZE.
    #[inline(always)]
    fn max_dist(&self) -> u32 {
        self.w_size - MIN_LOOKAHEAD
    }

    /// Initializes the "longest match" routines for a new zlib stream.
    ///
    /// Port of `lm_init`, `deflate.c`.
    fn lm_init(&mut self) {
        self.window_size = 2 * self.w_size;

        self.clear_hash();

        // Set the default configuration parameters:
        let config = &CONFIGURATION_TABLE[self.level as usize];
        self.max_lazy_match = u32::from(config.max_lazy);
        self.good_match = u32::from(config.good_length);
        self.nice_match = i32::from(config.nice_length);
        self.max_chain_length = u32::from(config.max_chain);

        self.strstart = 0;
        self.block_start = 0;
        self.lookahead = 0;
        self.insert = 0;
        self.match_length = MIN_MATCH as u32 - 1;
        self.prev_length = MIN_MATCH as u32 - 1;
        self.match_available = false;
        self.ins_h = 0;
    }

    /// Puts a short in the pending buffer, MSB first.
    ///
    /// Port of `putShortMSB`, `deflate.c`.
    fn put_short_msb(&mut self, b: u32) {
        self.out.put_byte((b >> 8) as u8);
        self.out.put_byte(b as u8);
    }

    /// Flushes as much pending output as possible. All deflate() output,
    /// except for some deflate_stored() output, goes through this function.
    ///
    /// Port of `flush_pending`, `deflate.c`.
    fn flush_pending(&mut self, strm: &mut Strm<'_, '_>) {
        self.tr_flush_bits();
        let len = self.out.pending.min(strm.avail_out());
        if len == 0 {
            return;
        }

        let (from, to) = (self.out.out, strm.next_out);
        strm.output[to..to + len].copy_from_slice(&self.out.buf[from..from + len]);
        strm.next_out += len;
        self.out.out += len;
        strm.total_out += len as u64;
        self.out.pending -= len;
        if self.out.pending == 0 {
            self.out.out = 0;
        }
    }

    /// `HCRC_UPDATE`: updates the header CRC with the bytes
    /// `pending_buf[beg..pending]`.
    fn hcrc_update(&self, strm: &mut Strm<'_, '_>, beg: usize) {
        if let Some(head) = &self.gzhead
            && head.hcrc != 0
            && self.out.pending > beg
        {
            strm.adler = crc32(strm.adler, &self.out.buf[beg..self.out.pending]);
        }
    }

    /// The body of deflate() once the stream is checked: returns zlib's
    /// code, and sets `msg` where zlib's `ERR_RETURN` does.
    ///
    /// Port of `deflate`, `deflate.c`.
    fn deflate(
        &mut self,
        strm: &mut Strm<'_, '_>,
        flush: i32,
        msg: &mut Option<&'static str>,
    ) -> i32 {
        if self.status == State::Finish && flush != Flush::Finish as i32 {
            *msg = err_msg(ErrorCode::Stream);
            return ErrorCode::Stream.number();
        }
        if strm.avail_out() == 0 {
            *msg = err_msg(ErrorCode::Buf);
            return Z_BUF_ERROR;
        }

        let old_flush = self.last_flush; // value of flush param for previous deflate call
        self.last_flush = flush;

        // Flush as much pending output as possible
        if self.out.pending != 0 {
            self.flush_pending(strm);
            if strm.avail_out() == 0 {
                // Since avail_out is 0, deflate will be called again with
                // more output space, but possibly with both pending and
                // avail_in equal to zero. There won't be anything to do, but
                // this is not an error situation so make sure we return OK
                // instead of BUF_ERROR at next call of deflate:
                self.last_flush = -1;
                return Z_OK;
            }

        // Make sure there is something to do and avoid duplicate consecutive
        // flushes. For repeated and useless calls with Z_FINISH, we keep
        // returning Z_STREAM_END instead of Z_BUF_ERROR.
        } else if strm.avail_in() == 0
            && rank(flush) <= rank(old_flush)
            && flush != Flush::Finish as i32
        {
            *msg = err_msg(ErrorCode::Buf);
            return Z_BUF_ERROR;
        }

        // User must not provide more input after the first FINISH:
        if self.status == State::Finish && strm.avail_in() != 0 {
            *msg = err_msg(ErrorCode::Buf);
            return Z_BUF_ERROR;
        }

        // Write the header
        if self.status == State::Init && self.wrap == 0 {
            self.status = State::Busy;
        }
        if self.status == State::Init {
            // zlib header
            let mut header = (Z_DEFLATED + ((self.w_bits - 8) << 4)) << 8;
            let level_flags = if self.strategy >= Z_HUFFMAN_ONLY || self.level < 2 {
                0
            } else if self.level < 6 {
                1
            } else if self.level == 6 {
                2
            } else {
                3
            };
            header |= level_flags << 6;
            if self.strstart != 0 {
                header |= PRESET_DICT;
            }
            header += 31 - (header % 31);

            self.put_short_msb(header);

            // Save the adler32 of the preset dictionary:
            if self.strstart != 0 {
                self.put_short_msb(strm.adler >> 16);
                self.put_short_msb(strm.adler & 0xffff);
            }
            strm.adler = ADLER32_INIT;
            self.status = State::Busy;

            // Compression must start with an empty pending buffer
            self.flush_pending(strm);
            if self.out.pending != 0 {
                self.last_flush = -1;
                return Z_OK;
            }
        }
        if self.status == State::Gzip {
            // gzip header
            strm.adler = crc32(0, &[]);
            self.out.put_byte(31);
            self.out.put_byte(139);
            self.out.put_byte(8);
            let xfl = if self.level == 9 {
                2
            } else if self.strategy >= Z_HUFFMAN_ONLY || self.level < 2 {
                4
            } else {
                0
            };
            match &self.gzhead {
                None => {
                    for _ in 0..5 {
                        self.out.put_byte(0);
                    }
                    self.out.put_byte(xfl);
                    self.out.put_byte(OS_CODE);
                    self.status = State::Busy;

                    // Compression must start with an empty pending buffer
                    self.flush_pending(strm);
                    if self.out.pending != 0 {
                        self.last_flush = -1;
                        return Z_OK;
                    }
                }
                Some(head) => {
                    let flags = u8::from(head.text != 0)
                        + if head.hcrc != 0 { 2 } else { 0 }
                        + if head.extra.is_some() { 4 } else { 0 }
                        + if head.name.is_some() { 8 } else { 0 }
                        + if head.comment.is_some() { 16 } else { 0 };
                    let (time, os, extra, extra_len, hcrc) = (
                        head.time,
                        head.os,
                        head.extra.is_some(),
                        head.extra_len,
                        head.hcrc,
                    );
                    self.out.put_byte(flags);
                    self.out.put_byte(time as u8);
                    self.out.put_byte((time >> 8) as u8);
                    self.out.put_byte((time >> 16) as u8);
                    self.out.put_byte((time >> 24) as u8);
                    self.out.put_byte(xfl);
                    self.out.put_byte(os as u8);
                    if extra {
                        self.out.put_byte(extra_len as u8);
                        self.out.put_byte((extra_len >> 8) as u8);
                    }
                    if hcrc != 0 {
                        strm.adler = crc32(strm.adler, &self.out.buf[..self.out.pending]);
                    }
                    self.gzindex = 0;
                    self.status = State::Extra;
                }
            }
        }
        if self.status == State::Extra {
            // Differs from zlib: an extra field shorter than extra_len is
            // written with zeros after it, where zlib would read past it.
            let extra = self.gzhead.as_ref().and_then(|head| {
                head.extra.as_ref().map(|e| {
                    let mut e = e.clone();
                    e.resize((head.extra_len & 0xffff) as usize, 0);
                    (e, head.extra_len)
                })
            });
            if let Some((extra, extra_len)) = extra {
                let mut beg = self.out.pending; // start of bytes to update crc
                let mut left = (extra_len & 0xffff) as usize - self.gzindex;
                let size = self.out.buf.len();
                while self.out.pending + left > size {
                    let copy = size - self.out.pending;
                    let pending = self.out.pending;
                    self.out.buf[pending..size]
                        .copy_from_slice(&extra[self.gzindex..self.gzindex + copy]);
                    self.out.pending = size;
                    self.hcrc_update(strm, beg);
                    self.gzindex += copy;
                    self.flush_pending(strm);
                    if self.out.pending != 0 {
                        self.last_flush = -1;
                        return Z_OK;
                    }
                    beg = 0;
                    left -= copy;
                }
                let pending = self.out.pending;
                self.out.buf[pending..pending + left]
                    .copy_from_slice(&extra[self.gzindex..self.gzindex + left]);
                self.out.pending += left;
                self.hcrc_update(strm, beg);
                self.gzindex = 0;
            }
            self.status = State::Name;
        }
        if self.status == State::Name {
            let name = self
                .gzhead
                .as_ref()
                .and_then(|head| head.name.as_deref().map(zero_terminated));
            if let Some(name) = name
                && let Some(ret) = self.put_string(strm, &name, true)
            {
                return ret;
            }
            self.status = State::Comment;
        }
        if self.status == State::Comment {
            let comment = self
                .gzhead
                .as_ref()
                .and_then(|head| head.comment.as_deref().map(zero_terminated));
            if let Some(comment) = comment
                && let Some(ret) = self.put_string(strm, &comment, false)
            {
                return ret;
            }
            self.status = State::Hcrc;
        }
        if self.status == State::Hcrc {
            if self.gzhead.as_ref().is_some_and(|head| head.hcrc != 0) {
                if self.out.pending + 2 > self.out.buf.len() {
                    self.flush_pending(strm);
                    if self.out.pending != 0 {
                        self.last_flush = -1;
                        return Z_OK;
                    }
                }
                self.out.put_byte(strm.adler as u8);
                self.out.put_byte((strm.adler >> 8) as u8);
                strm.adler = crc32(0, &[]);
            }
            self.status = State::Busy;

            // Compression must start with an empty pending buffer
            self.flush_pending(strm);
            if self.out.pending != 0 {
                self.last_flush = -1;
                return Z_OK;
            }
        }

        // Start a new block or continue the current one.
        if strm.avail_in() != 0
            || self.lookahead != 0
            || (flush != Flush::NoFlush as i32 && self.status != State::Finish)
        {
            let bstate = if self.level == 0 {
                self.deflate_stored(strm, flush)
            } else if self.strategy == Z_HUFFMAN_ONLY {
                self.deflate_huff(strm, flush)
            } else if self.strategy == Z_RLE {
                self.deflate_rle(strm, flush)
            } else {
                match CONFIGURATION_TABLE[self.level as usize].func {
                    Func::Stored => self.deflate_stored(strm, flush),
                    Func::Fast => self.deflate_fast(strm, flush),
                    Func::Slow => self.deflate_slow(strm, flush),
                }
            };

            if bstate == BlockState::FinishStarted || bstate == BlockState::FinishDone {
                self.status = State::Finish;
            }
            if bstate == BlockState::NeedMore || bstate == BlockState::FinishStarted {
                if strm.avail_out() == 0 {
                    self.last_flush = -1; // avoid BUF_ERROR next call, see above
                }
                return Z_OK;
                // If flush != Z_NO_FLUSH && avail_out == 0, the next call of
                // deflate should use the same flush parameter to make sure
                // that the flush is complete. So we don't have to output an
                // empty block here, this will be done at next call. This
                // also ensures that for a very small output buffer, we emit
                // at most one empty block.
            }
            if bstate == BlockState::BlockDone {
                if flush == Flush::PartialFlush as i32 {
                    self.tr_align();
                } else if flush != Flush::Block as i32 {
                    // FULL_FLUSH or SYNC_FLUSH
                    self.tr_stored_block(None, 0, false);
                    // For a full flush, this empty block will be recognized
                    // as a special marker by inflate_sync().
                    if flush == Flush::FullFlush as i32 {
                        self.clear_hash(); // forget history
                        if self.lookahead == 0 {
                            self.strstart = 0;
                            self.block_start = 0;
                            self.insert = 0;
                        }
                    }
                }
                self.flush_pending(strm);
                if strm.avail_out() == 0 {
                    self.last_flush = -1; // avoid BUF_ERROR at next call, see above
                    return Z_OK;
                }
            }
        }

        if flush != Flush::Finish as i32 {
            return Z_OK;
        }
        if self.wrap <= 0 {
            return Z_STREAM_END;
        }

        // Write the trailer
        if self.wrap == 2 {
            let adler = strm.adler;
            let total = strm.total_in;
            for byte in adler.to_le_bytes() {
                self.out.put_byte(byte);
            }
            for byte in (total as u32).to_le_bytes() {
                self.out.put_byte(byte);
            }
        } else {
            self.put_short_msb(strm.adler >> 16);
            self.put_short_msb(strm.adler & 0xffff);
        }
        self.flush_pending(strm);
        // If avail_out is zero, the application will call deflate again to
        // flush the rest.
        if self.wrap > 0 {
            self.wrap = -self.wrap; // write the trailer only once!
        }
        if self.out.pending != 0 {
            Z_OK
        } else {
            Z_STREAM_END
        }
    }

    /// Writes the gzip name or comment, flushing the pending buffer when it
    /// is full. Returns zlib's return code if it has to stop for more
    /// output space.
    fn put_string(&mut self, strm: &mut Strm<'_, '_>, text: &[u8], name: bool) -> Option<i32> {
        let mut beg = self.out.pending; // start of bytes to update crc
        loop {
            if self.out.pending == self.out.buf.len() {
                self.hcrc_update(strm, beg);
                self.flush_pending(strm);
                if self.out.pending != 0 {
                    self.last_flush = -1;
                    return Some(Z_OK);
                }
                beg = 0;
            }
            let val = text[self.gzindex];
            self.gzindex += 1;
            self.out.put_byte(val);
            if val == 0 {
                break;
            }
        }
        self.hcrc_update(strm, beg);
        // zlib resets gzindex after the name only; the comment is the last
        // to use it before the next header.
        if name {
            self.gzindex = 0;
        }
        None
    }

    /// Sets match_start to the longest match starting at the given string
    /// and returns its length. Matches shorter or equal to prev_length are
    /// discarded, in which case the result is equal to prev_length and
    /// match_start is garbage. In: cur_match is the head of the hash chain
    /// for the current string (strstart) and its distance is <= MAX_DIST,
    /// and prev_length >= 1. Out: the match length is not greater than
    /// s->lookahead.
    ///
    /// Port of `longest_match`, `deflate.c` (the version without
    /// `UNALIGNED_OK`, as zlib is built by default).
    fn longest_match(&mut self, mut cur_match: u32) -> u32 {
        let mut chain_length = self.max_chain_length; // max hash chain length
        let window = &self.window[..];
        let scan0 = self.strstart as usize; // current string
        let mut best_len = self.prev_length as usize; // best match length so far
        let mut nice_match = self.nice_match; // stop if match long enough
        let limit = if self.strstart > self.max_dist() {
            self.strstart - self.max_dist()
        } else {
            u32::from(NIL)
        };
        // Stop when cur_match becomes <= limit. To simplify the code, we
        // prevent matches with the string of window index 0.
        let prev = &self.prev[..];
        let wmask = self.w_mask;

        let strend = scan0 + MAX_MATCH;
        let mut scan_end1 = window[scan0 + best_len - 1];
        let mut scan_end = window[scan0 + best_len];

        // Do not waste too much time if we already have a good match:
        if self.prev_length >= self.good_match {
            chain_length >>= 2;
        }
        // Do not look for matches beyond the end of the input. This is
        // necessary to make deflate deterministic.
        if nice_match as u32 > self.lookahead {
            nice_match = self.lookahead as i32;
        }

        let mut match_start = self.match_start;
        loop {
            let m = cur_match as usize;

            // Skip to next match if the match length cannot increase or if
            // the match length is less than 2. Note that the checks below
            // for insufficient lookahead only occur occasionally for
            // performance reasons. Therefore uninitialized memory will be
            // accessed, and conditional jumps will be made that depend on
            // those values. However the length of the match is limited to
            // the lookahead, so the output of deflate is not affected by the
            // uninitialized values.
            if window[m + best_len] == scan_end
                && window[m + best_len - 1] == scan_end1
                && window[m] == window[scan0]
                && window[m + 1] == window[scan0 + 1]
            {
                // The check at best_len - 1 can be removed because it will
                // be made again later. (This heuristic is not always a win.)
                // It is not necessary to compare scan[2] and match[2] since
                // they are always equal when the other bytes match, given
                // that the hash keys are equal and that HASH_BITS >= 8.
                let mut scan = scan0 + 2;
                let mut mat = m + 2;

                // We check for insufficient lookahead only every 8th
                // comparison; the 256th check will be made at strstart +
                // 258.
                loop {
                    let mut same = true;
                    for _ in 0..8 {
                        scan += 1;
                        mat += 1;
                        if window[scan] != window[mat] {
                            same = false;
                            break;
                        }
                    }
                    if !(same && scan < strend) {
                        break;
                    }
                }

                let len = MAX_MATCH - (strend - scan);

                if len > best_len {
                    match_start = cur_match;
                    best_len = len;
                    if len as i32 >= nice_match {
                        break;
                    }
                    scan_end1 = window[scan0 + best_len - 1];
                    scan_end = window[scan0 + best_len];
                }
            }
            cur_match = u32::from(prev[(cur_match & wmask) as usize]);
            chain_length = chain_length.wrapping_sub(1);
            if !(cur_match > limit && chain_length != 0) {
                break;
            }
        }
        self.match_start = match_start;

        if best_len as u32 <= self.lookahead {
            best_len as u32
        } else {
            self.lookahead
        }
    }

    /// `FLUSH_BLOCK_ONLY`: flushes the current block, with given
    /// end-of-file flag. strstart is set to the end of the current match.
    fn flush_block_only(&mut self, strm: &mut Strm<'_, '_>, last: bool) {
        let buf = (self.block_start >= 0).then_some(self.block_start as usize);
        let stored_len = (i64::from(self.strstart) - self.block_start) as usize;
        self.tr_flush_block(buf, stored_len, last, &mut strm.data_type);
        self.block_start = i64::from(self.strstart);
        self.flush_pending(strm);
    }

    /// `FLUSH_BLOCK`: the same but force premature exit if necessary:
    /// returns the block state to return then.
    fn flush_block(&mut self, strm: &mut Strm<'_, '_>, last: bool) -> Option<BlockState> {
        self.flush_block_only(strm, last);
        if strm.avail_out() == 0 {
            return Some(if last {
                BlockState::FinishStarted
            } else {
                BlockState::NeedMore
            });
        }
        None
    }

    /// Copies without compression as much as possible from the input
    /// stream, returns the current block state.
    ///
    /// In case deflateParams() is used to later switch to a non-zero
    /// compression level, s->matches (otherwise unused when storing) keeps
    /// track of the number of hash table slides to perform. If s->matches
    /// is 1, then one hash table slide will be done when switching. If
    /// s->matches is 2, the maximum value allowed here, then the hash table
    /// will be cleared, since two or more slides is the same as a clear.
    ///
    /// deflate_stored() is written to minimize the number of times an input
    /// byte is copied. It is most efficient with large input and output
    /// buffers, which maximizes the opportunities to have a single copy from
    /// next_in to next_out.
    ///
    /// Port of `deflate_stored`, `deflate.c`.
    fn deflate_stored(&mut self, strm: &mut Strm<'_, '_>, flush: i32) -> BlockState {
        // Smallest worthy block size when not flushing or finishing. By
        // default this is 32K. This can be as small as 507 bytes for
        // memLevel == 1. For large input and output buffers, the stored
        // block size will be larger.
        let mut min_block = (self.out.buf.len() - 5).min(self.w_size as usize) as u32;

        // Copy as many min_block or larger stored blocks directly to
        // next_out as possible. If flushing, copy the remaining available
        // input to next_out as stored blocks, if there is enough space.
        let mut last = false;
        let used = strm.avail_in() as u32;
        loop {
            // Set len to the maximum size block that we can copy directly
            // with the available input data and output space. Set left to
            // how much of that would be copied from what's left in the
            // window.
            let mut len = MAX_STORED; // maximum deflate stored block length
            let have = ((self.out.bi_valid + 42) >> 3) as u32; // bytes in header
            if (strm.avail_out() as u64) < u64::from(have) {
                // need room for header
                break;
            }
            // maximum stored block length that will fit in avail_out:
            let have = (strm.avail_out() as u64 - u64::from(have)) as u32;
            let mut left = (i64::from(self.strstart) - self.block_start) as u32; // window bytes
            let avail_in = strm.avail_in() as u32;
            if u64::from(len) > u64::from(left) + u64::from(avail_in) {
                len = left + avail_in; // limit len to the input
            }
            if len > have {
                len = have; // limit len to the output
            }

            // If the stored block would be less than min_block in length, or
            // if unable to copy all of the available input when flushing,
            // then try copying to the window and the pending buffer instead.
            // Also don't write an empty block when flushing -- deflate()
            // does that.
            if len < min_block
                && ((len == 0 && flush != Flush::Finish as i32)
                    || flush == Flush::NoFlush as i32
                    || len != left + avail_in)
            {
                break;
            }

            // Make a dummy stored block in pending to get the header bytes,
            // including any pending bits. This also updates the debugging
            // counts.
            last = flush == Flush::Finish as i32 && len == left + avail_in;
            self.tr_stored_block(None, 0, last);

            // Replace the lengths in the dummy stored block with len.
            let p = self.out.pending;
            self.out.buf[p - 4] = len as u8;
            self.out.buf[p - 3] = (len >> 8) as u8;
            self.out.buf[p - 2] = !len as u8;
            self.out.buf[p - 1] = (!len >> 8) as u8;

            // Write the stored block header bytes.
            self.flush_pending(strm);

            // Copy uncompressed bytes from the window to next_out.
            if left != 0 {
                if left > len {
                    left = len;
                }
                let (from, to) = (self.block_start as usize, strm.next_out);
                strm.output[to..to + left as usize]
                    .copy_from_slice(&self.window[from..from + left as usize]);
                strm.next_out += left as usize;
                strm.total_out += u64::from(left);
                self.block_start += i64::from(left);
                len -= left;
            }

            // Copy uncompressed bytes directly from next_in to next_out,
            // updating the check value.
            if len != 0 {
                self.read_buf_out(strm, len as usize);
                strm.next_out += len as usize;
                strm.total_out += u64::from(len);
            }
            if last {
                break;
            }
        }

        // Update the sliding window with the last s->w_size bytes of the
        // copied data, or append all of the copied data to the existing
        // window if less than s->w_size bytes were copied. Also update the
        // number of bytes to insert in the hash tables, in the event that
        // deflateParams() switches to a non-zero compression level.
        let used = used - strm.avail_in() as u32; // number of input bytes directly copied
        if used != 0 {
            // If any input was used, then no unused input remains in the
            // window, therefore s->block_start == s->strstart.
            let w = self.w_size as usize;
            if used >= self.w_size {
                // supplant the previous history
                self.matches = 2; // clear hash
                self.window[..w].copy_from_slice(&strm.input[strm.next_in - w..strm.next_in]);
                self.strstart = self.w_size;
                self.insert = self.strstart;
            } else {
                if self.window_size - self.strstart <= used {
                    // Slide the window down.
                    self.strstart -= self.w_size;
                    self.window.copy_within(w..w + self.strstart as usize, 0);
                    if self.matches < 2 {
                        self.matches += 1; // add a pending slide_hash()
                    }
                    if self.insert > self.strstart {
                        self.insert = self.strstart;
                    }
                }
                let start = self.strstart as usize;
                self.window[start..start + used as usize]
                    .copy_from_slice(&strm.input[strm.next_in - used as usize..strm.next_in]);
                self.strstart += used;
                self.insert += used.min(self.w_size - self.insert);
            }
            self.block_start = i64::from(self.strstart);
        }
        if self.high_water < self.strstart as usize {
            self.high_water = self.strstart as usize;
        }

        // If the last block was written to next_out, then done.
        if last {
            self.out.bi_used = 8;
            return BlockState::FinishDone;
        }

        // If flushing and all input has been consumed, then done.
        if flush != Flush::NoFlush as i32
            && flush != Flush::Finish as i32
            && strm.avail_in() == 0
            && i64::from(self.strstart) == self.block_start
        {
            return BlockState::BlockDone;
        }

        // Fill the window with any remaining input.
        let mut have = self.window_size - self.strstart;
        if strm.avail_in() as u64 > u64::from(have) && self.block_start >= i64::from(self.w_size) {
            // Slide the window down.
            self.block_start -= i64::from(self.w_size);
            self.strstart -= self.w_size;
            let w = self.w_size as usize;
            self.window.copy_within(w..w + self.strstart as usize, 0);
            if self.matches < 2 {
                self.matches += 1; // add a pending slide_hash()
            }
            have += self.w_size; // more space now
            if self.insert > self.strstart {
                self.insert = self.strstart;
            }
        }
        if u64::from(have) > strm.avail_in() as u64 {
            have = strm.avail_in() as u32;
        }
        if have != 0 {
            self.read_buf(strm, self.strstart as usize, have as usize);
            self.strstart += have;
            self.insert += have.min(self.w_size - self.insert);
        }
        if self.high_water < self.strstart as usize {
            self.high_water = self.strstart as usize;
        }

        // There was not enough avail_out to write a complete worthy or
        // flushed stored block to next_out. Write a stored block to pending
        // instead, if we have enough input for a worthy block, or if
        // flushing and there is enough room for the remaining input as a
        // stored block in the pending buffer.
        let have = ((self.out.bi_valid + 42) >> 3) as usize; // bytes in header
        // maximum stored block length that will fit in pending:
        let have = (self.out.buf.len() - have).min(MAX_STORED as usize) as u32;
        min_block = have.min(self.w_size);
        let left = (i64::from(self.strstart) - self.block_start) as u32;
        if left >= min_block
            || ((left != 0 || flush == Flush::Finish as i32)
                && flush != Flush::NoFlush as i32
                && strm.avail_in() == 0
                && left <= have)
        {
            let len = left.min(have);
            last = flush == Flush::Finish as i32 && strm.avail_in() == 0 && len == left;
            self.tr_stored_block(Some(self.block_start as usize), len as usize, last);
            self.block_start += i64::from(len);
            self.flush_pending(strm);
        }

        // We've done all we can with the available input and output.
        if last {
            self.out.bi_used = 8;
        }
        if last {
            BlockState::FinishStarted
        } else {
            BlockState::NeedMore
        }
    }

    /// Compresses as much as possible from the input stream, returns the
    /// current block state. This function does not perform lazy evaluation
    /// of matches and inserts new strings in the dictionary only for
    /// unmatched strings or for short matches. It is used only for the fast
    /// compression options.
    ///
    /// Port of `deflate_fast`, `deflate.c`.
    fn deflate_fast(&mut self, strm: &mut Strm<'_, '_>, flush: i32) -> BlockState {
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. We need MAX_MATCH bytes for the next
            // match, plus MIN_MATCH bytes to insert the string following the
            // next match.
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::NoFlush as i32 {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break; // flush the current block
                }
            }

            // Insert the string window[strstart .. strstart + 2] in the
            // dictionary, and set hash_head to the head of the hash chain:
            let mut hash_head = u32::from(NIL);
            if self.lookahead >= MIN_MATCH as u32 {
                hash_head = self.insert_string(self.strstart);
            }

            // Find the longest match, discarding those <= prev_length. At
            // this point we have always match_length < MIN_MATCH
            if hash_head != u32::from(NIL) && self.strstart - hash_head <= self.max_dist() {
                // To simplify the code, we prevent matches with the string
                // of window index 0 (in particular we have to avoid a match
                // of the string with itself at the start of the input file).
                self.match_length = self.longest_match(hash_head);
                // longest_match() sets match_start
            }
            let bflush;
            if self.match_length >= MIN_MATCH as u32 {
                bflush = self.tr_tally_dist(
                    (self.strstart - self.match_start) as usize,
                    (self.match_length - MIN_MATCH as u32) as usize,
                );

                self.lookahead -= self.match_length;

                // Insert new strings in the hash table only if the match
                // length is not too large. This saves time but degrades
                // compression.
                if self.match_length <= self.max_lazy_match && self.lookahead >= MIN_MATCH as u32 {
                    self.match_length -= 1; // string at strstart already in table
                    loop {
                        self.strstart += 1;
                        self.insert_string(self.strstart);
                        // strstart never exceeds WSIZE-MAX_MATCH, so there
                        // are always MIN_MATCH bytes ahead.
                        self.match_length -= 1;
                        if self.match_length == 0 {
                            break;
                        }
                    }
                    self.strstart += 1;
                } else {
                    self.strstart += self.match_length;
                    self.match_length = 0;
                    self.ins_h = u32::from(self.window[self.strstart as usize]);
                    self.update_hash(self.window[self.strstart as usize + 1]);
                    // If lookahead < MIN_MATCH, ins_h is garbage, but it
                    // does not matter since it will be recomputed at next
                    // deflate call.
                }
            } else {
                // No match, output a literal byte
                bflush = self.tr_tally_lit(self.window[self.strstart as usize]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush && let Some(state) = self.flush_block(strm, false) {
                return state;
            }
        }
        self.insert = self.strstart.min(MIN_MATCH as u32 - 1);
        if flush == Flush::Finish as i32 {
            if let Some(state) = self.flush_block(strm, true) {
                return state;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0
            && let Some(state) = self.flush_block(strm, false)
        {
            return state;
        }
        BlockState::BlockDone
    }

    /// Same as deflate_fast(), but achieves better compression. We use a
    /// lazy evaluation for matches: a match is finally adopted only if
    /// there is no better match at the next window position.
    ///
    /// Port of `deflate_slow`, `deflate.c`.
    fn deflate_slow(&mut self, strm: &mut Strm<'_, '_>, flush: i32) -> BlockState {
        // Process the input block.
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. We need MAX_MATCH bytes for the next
            // match, plus MIN_MATCH bytes to insert the string following the
            // next match.
            if self.lookahead < MIN_LOOKAHEAD {
                self.fill_window(strm);
                if self.lookahead < MIN_LOOKAHEAD && flush == Flush::NoFlush as i32 {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break; // flush the current block
                }
            }

            // Insert the string window[strstart .. strstart + 2] in the
            // dictionary, and set hash_head to the head of the hash chain:
            let mut hash_head = u32::from(NIL);
            if self.lookahead >= MIN_MATCH as u32 {
                hash_head = self.insert_string(self.strstart);
            }

            // Find the longest match, discarding those <= prev_length.
            self.prev_length = self.match_length;
            self.prev_match = self.match_start;
            self.match_length = MIN_MATCH as u32 - 1;

            if hash_head != u32::from(NIL)
                && self.prev_length < self.max_lazy_match
                && self.strstart - hash_head <= self.max_dist()
            {
                // To simplify the code, we prevent matches with the string
                // of window index 0 (in particular we have to avoid a match
                // of the string with itself at the start of the input file).
                self.match_length = self.longest_match(hash_head);
                // longest_match() sets match_start

                if self.match_length <= 5
                    && (self.strategy == Z_FILTERED
                        || (self.match_length == MIN_MATCH as u32
                            && self.strstart.wrapping_sub(self.match_start) > TOO_FAR))
                {
                    // If prev_match is also MIN_MATCH, match_start is
                    // garbage but we will ignore the current match anyway.
                    self.match_length = MIN_MATCH as u32 - 1;
                }
            }
            // If there was a match at the previous step and the current
            // match is not better, output the previous match:
            if self.prev_length >= MIN_MATCH as u32 && self.match_length <= self.prev_length {
                let max_insert = (self.strstart + self.lookahead).wrapping_sub(MIN_MATCH as u32);
                // Do not insert strings in hash table beyond this.

                let bflush = self.tr_tally_dist(
                    (self.strstart - 1).wrapping_sub(self.prev_match) as usize,
                    (self.prev_length - MIN_MATCH as u32) as usize,
                );

                // Insert in hash table all strings up to the end of the
                // match. strstart - 1 and strstart are already inserted. If
                // there is not enough lookahead, the last two strings are not
                // inserted in the hash table.
                self.lookahead -= self.prev_length - 1;
                self.prev_length -= 2;
                loop {
                    self.strstart += 1;
                    if self.strstart <= max_insert {
                        self.insert_string(self.strstart);
                    }
                    self.prev_length -= 1;
                    if self.prev_length == 0 {
                        break;
                    }
                }
                self.match_available = false;
                self.match_length = MIN_MATCH as u32 - 1;
                self.strstart += 1;

                if bflush && let Some(state) = self.flush_block(strm, false) {
                    return state;
                }
            } else if self.match_available {
                // If there was no match at the previous position, output a
                // single literal. If there was a match but the current match
                // is longer, truncate the previous match to a single
                // literal.
                let bflush = self.tr_tally_lit(self.window[self.strstart as usize - 1]);
                if bflush {
                    self.flush_block_only(strm, false);
                }
                self.strstart += 1;
                self.lookahead -= 1;
                if strm.avail_out() == 0 {
                    return BlockState::NeedMore;
                }
            } else {
                // There is no previous match to compare with, wait for the
                // next step to decide.
                self.match_available = true;
                self.strstart += 1;
                self.lookahead -= 1;
            }
        }
        if self.match_available {
            self.tr_tally_lit(self.window[self.strstart as usize - 1]);
            self.match_available = false;
        }
        self.insert = self.strstart.min(MIN_MATCH as u32 - 1);
        if flush == Flush::Finish as i32 {
            if let Some(state) = self.flush_block(strm, true) {
                return state;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0
            && let Some(state) = self.flush_block(strm, false)
        {
            return state;
        }
        BlockState::BlockDone
    }

    /// For Z_RLE, simply looks for runs of bytes, generates matches only of
    /// distance one. Does not maintain a hash table. (It will be regenerated
    /// if this run of deflate switches away from Z_RLE.)
    ///
    /// Port of `deflate_rle`, `deflate.c`.
    fn deflate_rle(&mut self, strm: &mut Strm<'_, '_>, flush: i32) -> BlockState {
        loop {
            // Make sure that we always have enough lookahead, except at the
            // end of the input file. We need MAX_MATCH bytes for the longest
            // run, plus one for the unrolled loop.
            if self.lookahead <= MAX_MATCH as u32 {
                self.fill_window(strm);
                if self.lookahead <= MAX_MATCH as u32 && flush == Flush::NoFlush as i32 {
                    return BlockState::NeedMore;
                }
                if self.lookahead == 0 {
                    break; // flush the current block
                }
            }

            // See how many times the previous byte repeats
            self.match_length = 0;
            if self.lookahead >= MIN_MATCH as u32 && self.strstart > 0 {
                let window = &self.window[..];
                let mut scan = self.strstart as usize - 1;
                let prev = window[scan];
                if prev == window[scan + 1] && prev == window[scan + 2] && prev == window[scan + 3]
                {
                    scan += 3;
                    let strend = self.strstart as usize + MAX_MATCH;
                    loop {
                        let mut same = true;
                        for _ in 0..8 {
                            scan += 1;
                            if prev != window[scan] {
                                same = false;
                                break;
                            }
                        }
                        if !(same && scan < strend) {
                            break;
                        }
                    }
                    self.match_length = (MAX_MATCH - (strend - scan)) as u32;
                    if self.match_length > self.lookahead {
                        self.match_length = self.lookahead;
                    }
                }
            }

            // Emit match if have run of MIN_MATCH or longer, else emit
            // literal
            let bflush;
            if self.match_length >= MIN_MATCH as u32 {
                bflush = self.tr_tally_dist(1, (self.match_length - MIN_MATCH as u32) as usize);

                self.lookahead -= self.match_length;
                self.strstart += self.match_length;
                self.match_length = 0;
            } else {
                // No match, output a literal byte
                bflush = self.tr_tally_lit(self.window[self.strstart as usize]);
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if bflush && let Some(state) = self.flush_block(strm, false) {
                return state;
            }
        }
        self.insert = 0;
        if flush == Flush::Finish as i32 {
            if let Some(state) = self.flush_block(strm, true) {
                return state;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0
            && let Some(state) = self.flush_block(strm, false)
        {
            return state;
        }
        BlockState::BlockDone
    }

    /// For Z_HUFFMAN_ONLY, does not look for matches. Does not maintain a
    /// hash table. (It will be regenerated if this run of deflate switches
    /// away from Huffman.)
    ///
    /// Port of `deflate_huff`, `deflate.c`.
    fn deflate_huff(&mut self, strm: &mut Strm<'_, '_>, flush: i32) -> BlockState {
        loop {
            // Make sure that we have a literal to write.
            if self.lookahead == 0 {
                self.fill_window(strm);
                if self.lookahead == 0 {
                    if flush == Flush::NoFlush as i32 {
                        return BlockState::NeedMore;
                    }
                    break; // flush the current block
                }
            }

            // Output a literal byte
            self.match_length = 0;
            let bflush = self.tr_tally_lit(self.window[self.strstart as usize]);
            self.lookahead -= 1;
            self.strstart += 1;
            if bflush && let Some(state) = self.flush_block(strm, false) {
                return state;
            }
        }
        self.insert = 0;
        if flush == Flush::Finish as i32 {
            if let Some(state) = self.flush_block(strm, true) {
                return state;
            }
            return BlockState::FinishDone;
        }
        if self.sym_next != 0
            && let Some(state) = self.flush_block(strm, false)
        {
            return state;
        }
        BlockState::BlockDone
    }
}
