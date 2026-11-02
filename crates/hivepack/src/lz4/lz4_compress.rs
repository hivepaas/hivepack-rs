//! The LZ4 block format: `lz4.c`'s encoding half.
//!
//! In its own module, as `lz4.c`'s decoding half is in `lz4.rs`: the two
//! share only the constants.

use crate::lz4::lz4::{
    KB, LASTLITERALS, MAX_INPUT_SIZE, MFLIMIT, MINMATCH, ML_BITS, ML_MASK, RUN_MASK, compress_bound,
};

/*-************************************
 *  Tuning parameters
 **************************************/

/// `LZ4_ACCELERATION_DEFAULT`: the acceleration of `LZ4_compress_fast`
/// for a value of 0 or less.
pub const ACCELERATION_DEFAULT: i32 = 1;
/// `LZ4_ACCELERATION_MAX`: higher accelerations are taken as this.
pub const ACCELERATION_MAX: i32 = 65537;

/// `LZ4_MEMORY_USAGE_DEFAULT`: 2^14 bytes of hash table.
const MEMORY_USAGE: u32 = 14;
/// `LZ4_HASHLOG`.
const HASHLOG: u32 = MEMORY_USAGE - 2;
/// `LZ4_HASH_SIZE_U32`.
const HASH_SIZE_U32: usize = 1 << HASHLOG;
/// `LZ4_DISTANCE_MAX`.
const DISTANCE_MAX: usize = 65535;

/// `LZ4_64Klimit`.
const LIMIT_64K: usize = 64 * KB + (MFLIMIT - 1);
/// `LZ4_skipTrigger`: increasing it makes compression slower on
/// incompressible data.
const SKIP_TRIGGER: u32 = 6;
/// `LZ4_minLength`.
const MIN_LENGTH: usize = MFLIMIT + 1;

/// `reg_t` is 8 bytes wide: positions are hashed by their first 5 bytes
/// (`LZ4_hash5`), as liblz4 does on 64-bit machines. On 32-bit machines,
/// liblz4 hashes 4 (`LZ4_hash4`) and keeps the positions of inputs of 64
/// KB or more as pointers (`byPtr`), and the port does the same, so that
/// its output is liblz4's on the same machine.
const REG_IS_64: bool = usize::BITS == 64;

/*-************************************
 *  Local Structures and types
 **************************************/

/// `tableType_t`: what the hash table holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TableType {
    #[default]
    ClearedTable,
    /// Positions, as pointers. Differs from liblz4: as positions in the
    /// input plus one, 0 standing for `NULL`.
    ByPtr,
    ByU32,
    ByU16,
}

/// `dict_directive`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DictDirective {
    NoDict,
    WithPrefix64k,
    UsingExtDict,
    UsingDictCtx,
}

/// `dictIssue_directive`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DictIssue {
    NoDictIssue,
    DictSmall,
}

/// `limitedOutput_directive`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutputDirective {
    NotLimited,
    LimitedOutput,
    FillOutput,
}

/// `LZ4_stream_t_internal`: a compression state, its hash table and
/// history.
///
/// Differs from liblz4: the history is not a pointer the state keeps, but
/// given with each call (see `Input`).
#[derive(Clone)]
pub(crate) struct StreamState {
    /// The hash table as `U32`s (`byU32`, and `byPtr`).
    hash_table: Box<[u32; HASH_SIZE_U32]>,
    /// The hash table as `U16`s (`byU16`). liblz4 overlays the two; a
    /// table is reset whenever its type changes, so one is never read as
    /// the other.
    hash_table16: Box<[u16; 2 * HASH_SIZE_U32]>,
    current_offset: u32,
    table_type: TableType,
    dict_size: u32,
}

impl core::fmt::Debug for StreamState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamState")
            .field("current_offset", &self.current_offset)
            .field("table_type", &self.table_type)
            .field("dict_size", &self.dict_size)
            .finish_non_exhaustive()
    }
}

impl Default for StreamState {
    fn default() -> Self {
        StreamState {
            hash_table: Box::new([0; HASH_SIZE_U32]),
            hash_table16: Box::new([0; 2 * HASH_SIZE_U32]),
            current_offset: 0,
            table_type: TableType::ClearedTable,
            dict_size: 0,
        }
    }
}

/// The input of a compression: the source, and the history before it.
pub(crate) struct Input<'a> {
    /// The source, and before it, with a prefix (`withPrefix64k`), the
    /// history: `buf[src - dict_size..src]`.
    pub buf: &'a [u8],
    /// Where the source starts in `buf`.
    pub src: usize,
    /// The source's size (`inputSize`).
    pub len: usize,
    /// The external dictionary (`usingExtDict`), `dictSize` bytes.
    pub dict: &'a [u8],
}

/*-************************************
 *  Reading
 **************************************/

pub(crate) fn read32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_ne_bytes(word)
}

fn read64(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_ne_bytes(word)
}

/// `LZ4_count`: how many bytes from `a[pin..]` are the same as from
/// `b[pmatch..]`, up to `a[..limit]`. The bytes are compared 8 at a time;
/// the count does not depend on how many.
#[inline(always)]
pub(crate) fn count(a: &[u8], pin: usize, b: &[u8], pmatch: usize, limit: usize) -> usize {
    let start = pin;
    let (mut pin, mut pmatch) = (pin, pmatch);
    while pin + 8 <= limit {
        let mut x = [0; 8];
        let mut y = [0; 8];
        x.copy_from_slice(&a[pin..pin + 8]);
        y.copy_from_slice(&b[pmatch..pmatch + 8]);
        let diff = u64::from_le_bytes(x) ^ u64::from_le_bytes(y);
        if diff != 0 {
            return pin - start + (diff.trailing_zeros() / 8) as usize;
        }
        pin += 8;
        pmatch += 8;
    }
    while pin < limit && a[pin] == b[pmatch] {
        pin += 1;
        pmatch += 1;
    }
    pin - start
}

/*-******************************
 *  Compression functions
 ********************************/

/// `LZ4_hash4`.
#[inline(always)]
fn hash4(sequence: u32, table_type: TableType) -> u32 {
    if table_type == TableType::ByU16 {
        sequence.wrapping_mul(2_654_435_761) >> ((MINMATCH as u32 * 8) - (HASHLOG + 1))
    } else {
        sequence.wrapping_mul(2_654_435_761) >> ((MINMATCH as u32 * 8) - HASHLOG)
    }
}

/// `LZ4_hash5`.
#[inline(always)]
fn hash5(sequence: u64, table_type: TableType) -> u32 {
    let hash_log = if table_type == TableType::ByU16 {
        HASHLOG + 1
    } else {
        HASHLOG
    };
    if cfg!(target_endian = "little") {
        const PRIME5BYTES: u64 = 889_523_592_379;
        ((sequence << 24).wrapping_mul(PRIME5BYTES) >> (64 - hash_log)) as u32
    } else {
        const PRIME8BYTES: u64 = 11_400_714_785_074_694_791;
        ((sequence >> 24).wrapping_mul(PRIME8BYTES) >> (64 - hash_log)) as u32
    }
}

/// The 8 bytes at `p` of `window`, which ends 8 bytes after the last
/// position the search may hash (`mflimitPlusOne`, `last`): none past it.
/// The search compares `p` with `last` itself, which spares the compiler
/// the bounds checks.
#[inline(always)]
fn chunk8(window: &[u8], last: usize, p: usize) -> Option<[u8; 8]> {
    if p > last {
        return None;
    }
    window.get(p..)?.first_chunk::<8>().copied()
}

/// `LZ4_read32` at `m`, a match in `window`, which liblz4 asserts is
/// before the position searched, itself at `last` at most. Read at `last`
/// at most, which tells the compiler the read is in bounds, and changes
/// nothing for such a match.
#[inline(always)]
fn read32_before(window: &[u8], last: usize, m: usize) -> u32 {
    let at = m.min(last);
    match window.get(at..).and_then(|w| w.first_chunk::<4>()) {
        Some(bytes) => u32::from_ne_bytes(*bytes),
        None => 0,
    }
}

/// `LZ4_read32` of the bytes `chunk` starts with.
#[inline(always)]
fn word(chunk: [u8; 8]) -> u32 {
    u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
}

/// `LZ4_hashPosition` of the bytes `chunk` holds.
#[inline(always)]
fn hash_chunk(chunk: [u8; 8], table_type: TableType) -> u32 {
    if REG_IS_64 && table_type != TableType::ByU16 {
        return hash5(u64::from_ne_bytes(chunk), table_type);
    }
    hash4(word(chunk), table_type)
}

/// A hash's entry in the `U32` table. Hashes are always below the table's
/// size; the mask tells the compiler, which loses track of it between a
/// search's steps.
#[inline(always)]
fn slot(h: u32) -> usize {
    h as usize & (HASH_SIZE_U32 - 1)
}

/// A hash's entry in the `U16` table.
#[inline(always)]
fn slot16(h: u32) -> usize {
    h as usize & (2 * HASH_SIZE_U32 - 1)
}

/// `LZ4_hashPosition`: the hash of the bytes at `p`, read as the machine
/// reads them.
#[inline(always)]
fn hash_position(bytes: &[u8], p: usize, table_type: TableType) -> u32 {
    if REG_IS_64 && table_type != TableType::ByU16 {
        return hash5(read64(bytes, p), table_type);
    }
    hash4(read32(bytes, p), table_type)
}

impl StreamState {
    /// `LZ4_clearHash`.
    fn clear_hash(&mut self, h: u32, table_type: TableType) {
        match table_type {
            TableType::ByPtr | TableType::ByU32 => self.hash_table[h as usize] = 0,
            TableType::ByU16 => self.hash_table16[h as usize] = 0,
            TableType::ClearedTable => debug_assert!(false, "a cleared table"),
        }
    }

    /// `LZ4_putIndexOnHash`, and `LZ4_putPositionOnHash` for `byPtr`.
    #[inline(always)]
    fn put_index_on_hash(&mut self, idx: u32, h: u32, table_type: TableType) {
        match table_type {
            // The index is truncated as in liblz4: it can pass 65535 after
            // a dictionary of less than HASH_UNIT bytes was loaded (the
            // offset moved by 64 KB, the table still cleared), and then
            // every match is refused (dictSmall).
            TableType::ByU16 => self.hash_table16[slot16(h)] = idx as u16,
            _ => self.hash_table[slot(h)] = idx,
        }
    }

    /// `LZ4_getIndexOnHash`, and `LZ4_getPositionOnHash` for `byPtr`.
    #[inline(always)]
    fn get_index_on_hash(&self, h: u32, table_type: TableType) -> u32 {
        match table_type {
            TableType::ByU16 => u32::from(self.hash_table16[slot16(h)]),
            _ => self.hash_table[slot(h)],
        }
    }

    /// `MEM_INIT(cctx->hashTable, 0, LZ4_HASHTABLESIZE)`.
    fn clear_table(&mut self) {
        self.hash_table.fill(0);
        self.hash_table16.fill(0);
    }

    /// `LZ4_initStream`.
    pub(crate) fn init(&mut self) {
        self.clear_table();
        self.current_offset = 0;
        self.table_type = TableType::ClearedTable;
        self.dict_size = 0;
    }

    /// `LZ4_prepareTable`.
    fn prepare_table(&mut self, input_size: usize, table_type: TableType) {
        // If the table hasn't been used, it's guaranteed to be zeroed out,
        // and is therefore safe to use no matter what mode we're in.
        // Otherwise, we figure out if it's safe to leave as is or whether it
        // needs to be reset.
        if self.table_type != TableType::ClearedTable
            && (self.table_type != table_type
                || (table_type == TableType::ByU16
                    && u64::from(self.current_offset) + input_size as u64 >= 0xFFFF)
                || (table_type == TableType::ByU32 && self.current_offset > (1 << 30))
                || table_type == TableType::ByPtr
                || input_size >= 4 * KB)
        {
            self.clear_table();
            self.current_offset = 0;
            self.table_type = TableType::ClearedTable;
        }

        // Adding a gap, so all previous entries are > LZ4_DISTANCE_MAX back,
        // is faster than compressing without a gap. However, compressing
        // with currentOffset == 0 is faster still, so we preserve that case.
        if self.current_offset != 0 && table_type == TableType::ByU32 {
            self.current_offset += 64 * KB as u32;
        }

        // Finally, clear history.
        self.dict_size = 0;
    }
}

/// Where a match candidate is: in the source and what is before it in
/// the same buffer, or in the external dictionary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seg {
    Buf,
    Dict,
}

/// `LZ4_compress_generic_validated`: compresses `input` into `dst`, with
/// the state `cctx` (and, for `usingDictCtx`, the dictionary's state
/// `dict_ctx` and its dictionary `ctx_dict`). Returns the compressed size,
/// or 0 if it does not fit; with `FillOutput`, `input_consumed` gets how
/// much of the source was compressed.
///
/// Differs from liblz4: positions are indices into the input's buffer or
/// the dictionary rather than pointers.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn compress_generic_validated(
    cctx: &mut StreamState,
    input: &Input<'_>,
    dst: &mut [u8],
    input_consumed: &mut usize,
    max_output_size: usize,
    output_directive: OutputDirective,
    table_type: TableType,
    dict_directive: DictDirective,
    dict_issue: DictIssue,
    acceleration: u32,
    dict_ctx: Option<(&StreamState, &[u8])>,
) -> usize {
    let src = input.buf;
    let source = input.src;
    let input_size = input.len;
    let mut ip = source;

    let start_index = cctx.current_offset;
    // base = source - startIndex: index i is at buf[source - startIndex + i].
    let pos_of = |index: u32| {
        (source as u64)
            .wrapping_add(u64::from(index))
            .wrapping_sub(u64::from(start_index)) as usize
    };

    let (dictionary, dict_size): (&[u8], u32) = match (dict_directive, dict_ctx) {
        (DictDirective::UsingDictCtx, Some((_, d))) => (d, d.len() as u32),
        (DictDirective::UsingExtDict, _) => (input.dict, input.dict.len() as u32),
        _ => (&[], cctx.dict_size),
    };
    // Makes indexes in dictCtx comparable with indexes in the current
    // context.
    let dict_delta = match (dict_directive, dict_ctx) {
        (DictDirective::UsingDictCtx, Some((ctx, _))) => {
            start_index.wrapping_sub(ctx.current_offset)
        }
        _ => 0,
    };
    let dict_ctx_offset = dict_ctx.map_or(0, |(ctx, _)| ctx.current_offset);
    // The position in the dictionary of an index there: dictBase + index.
    // The dictCtx's currentOffset is indexed on the end of its dictionary,
    // while a dictionary in the current context precedes currentOffset.
    let dict_pos = |index: u32| -> usize {
        if dict_directive == DictDirective::UsingDictCtx {
            u64::from(dict_size)
                .wrapping_add(u64::from(index))
                .wrapping_sub(u64::from(dict_ctx_offset)) as usize
        } else {
            u64::from(dict_size)
                .wrapping_add(u64::from(index))
                .wrapping_sub(u64::from(start_index)) as usize
        }
    };

    let maybe_ext_mem = dict_directive == DictDirective::UsingExtDict
        || dict_directive == DictDirective::UsingDictCtx;
    // Used when dictIssue == dictSmall.
    let prefix_idx_limit = start_index.wrapping_sub(dict_size);
    let dict_end = dictionary.len();
    let mut anchor = source;
    let iend = ip + input_size;
    let mflimit_plus_one = iend as isize - MFLIMIT as isize + 1;
    let matchlimit = iend as isize - LASTLITERALS as isize;

    let mut op = 0usize;
    let olimit = max_output_size;

    let mut offset: u32 = 0;
    let mut forward_h: u32;

    debug_assert!(table_type != TableType::ByU16 || input_size < LIMIT_64K);
    debug_assert!(table_type != TableType::ByPtr || dict_directive == DictDirective::NoDict);
    // If init conditions are not met, we don't have to mark the stream as
    // having a dirty context, since no action was taken yet.
    if output_directive == OutputDirective::FillOutput && max_output_size < 1 {
        // Impossible to store anything.
        return 0;
    }

    let low_limit_buf = if dict_directive == DictDirective::WithPrefix64k {
        source - dict_size as usize
    } else {
        source
    };
    // lowLimit: where catching up stops, in the buffer or the dictionary.
    let mut low_limit: (Seg, usize) = (Seg::Buf, low_limit_buf);

    // Update the context state.
    if dict_directive == DictDirective::UsingDictCtx {
        // Subsequent linked blocks can't use the dictionary. Instead, they
        // use the block just compressed.
        cctx.dict_size = input_size as u32;
    } else {
        cctx.dict_size = cctx.dict_size.wrapping_add(input_size as u32);
    }
    cctx.current_offset = cctx.current_offset.wrapping_add(input_size as u32);
    cctx.table_type = table_type;

    let mut token: usize;

    'last_literals: {
        if input_size < MIN_LENGTH {
            // Input too small, no compression (all literals).
            break 'last_literals;
        }

        // Where the search reads: up to 8 bytes after mflimitPlusOne.
        let window = &src[..iend - MFLIMIT + 1 + 8];
        let Some(last) = window.len().checked_sub(8) else {
            break 'last_literals;
        };
        // The bytes at the next position the search looks at.
        let mut forward_chunk: [u8; 8];

        // First byte.
        {
            let Some(chunk) = chunk8(window, last, ip) else {
                break 'last_literals;
            };
            let h = hash_chunk(chunk, table_type);
            if table_type == TableType::ByPtr {
                cctx.put_index_on_hash(ip as u32 + 1, h, table_type);
            } else {
                cctx.put_index_on_hash(start_index, h, table_type);
            }
        }
        ip += 1;
        let Some(chunk) = chunk8(window, last, ip) else {
            break 'last_literals;
        };
        forward_chunk = chunk;
        forward_h = hash_chunk(chunk, table_type);

        // Main loop.
        loop {
            let mut mtch: (Seg, usize);

            // Find a match.
            if table_type == TableType::ByPtr {
                let mut forward_ip = ip;
                let mut step = 1usize;
                let mut search_match_nb = acceleration << SKIP_TRIGGER;
                loop {
                    let h = forward_h;
                    ip = forward_ip;
                    let ip_word = word(forward_chunk);
                    forward_ip += step;
                    step = (search_match_nb >> SKIP_TRIGGER) as usize;
                    search_match_nb += 1;

                    // forward_ip > mflimitPlusOne.
                    let Some(chunk) = chunk8(window, last, forward_ip) else {
                        break 'last_literals;
                    };

                    let stored = cctx.get_index_on_hash(h, table_type);
                    forward_chunk = chunk;
                    forward_h = hash_chunk(chunk, table_type);
                    cctx.put_index_on_hash(ip as u32 + 1, h, table_type);

                    // NULL is more than LZ4_DISTANCE_MAX behind: liblz4
                    // takes this table only for a source at an address
                    // past that.
                    if stored == 0 {
                        continue;
                    }
                    let m = stored as usize - 1;
                    if m + DISTANCE_MAX < ip || read32_before(window, last, m) != ip_word {
                        continue;
                    }
                    mtch = (Seg::Buf, m);
                    break;
                }
            } else {
                // byU32, byU16.
                let mut forward_ip = ip;
                let mut step = 1usize;
                let mut search_match_nb = acceleration << SKIP_TRIGGER;
                loop {
                    let h = forward_h;
                    let current = ((forward_ip - source) as u32).wrapping_add(start_index);
                    let mut match_index = cctx.get_index_on_hash(h, table_type);
                    debug_assert!(match_index <= current);
                    ip = forward_ip;
                    let ip_word = word(forward_chunk);
                    forward_ip += step;
                    step = (search_match_nb >> SKIP_TRIGGER) as usize;
                    search_match_nb += 1;

                    // forward_ip > mflimitPlusOne.
                    let Some(chunk) = chunk8(window, last, forward_ip) else {
                        break 'last_literals;
                    };

                    match dict_directive {
                        DictDirective::UsingDictCtx => {
                            if match_index < start_index {
                                // There was no match: try the dictionary.
                                let ctx = dict_ctx.map_or(&*cctx, |(c, _)| c);
                                match_index = ctx.get_index_on_hash(h, TableType::ByU32);
                                mtch = (Seg::Dict, dict_pos(match_index));
                                // Make the dictCtx index comparable with the
                                // current context.
                                match_index = match_index.wrapping_add(dict_delta);
                                low_limit = (Seg::Dict, 0);
                            } else {
                                mtch = (Seg::Buf, pos_of(match_index));
                                low_limit = (Seg::Buf, source);
                            }
                        }
                        DictDirective::UsingExtDict => {
                            if match_index < start_index {
                                debug_assert!(start_index - match_index >= MINMATCH as u32);
                                mtch = (Seg::Dict, dict_pos(match_index));
                                low_limit = (Seg::Dict, 0);
                            } else {
                                mtch = (Seg::Buf, pos_of(match_index));
                                low_limit = (Seg::Buf, source);
                            }
                        }
                        // A single continuous memory segment.
                        _ => mtch = (Seg::Buf, pos_of(match_index)),
                    }
                    forward_chunk = chunk;
                    forward_h = hash_chunk(chunk, table_type);
                    cctx.put_index_on_hash(current, h, table_type);

                    if dict_issue == DictIssue::DictSmall && match_index < prefix_idx_limit {
                        // A match outside of the valid area.
                        continue;
                    }
                    debug_assert!(match_index < current);
                    if table_type != TableType::ByU16
                        && match_index as usize + DISTANCE_MAX < current as usize
                    {
                        // Too far.
                        continue;
                    }

                    let candidate = match mtch.0 {
                        Seg::Buf => read32_before(window, last, mtch.1),
                        Seg::Dict => read32(dictionary, mtch.1),
                    };
                    if candidate == ip_word {
                        if maybe_ext_mem {
                            offset = current - match_index;
                        }
                        // Match found.
                        break;
                    }
                }
            }

            // Catch up.
            let filled_ip = ip;
            debug_assert!(ip > anchor);
            {
                let seg = match mtch.0 {
                    Seg::Buf => src,
                    Seg::Dict => dictionary,
                };
                let ll = if low_limit.0 == mtch.0 {
                    low_limit.1
                } else {
                    0
                };
                if mtch.1 > ll && src[ip - 1] == seg[mtch.1 - 1] {
                    loop {
                        ip -= 1;
                        mtch.1 -= 1;
                        if !((ip > anchor) & (mtch.1 > ll) && src[ip - 1] == seg[mtch.1 - 1]) {
                            break;
                        }
                    }
                }
            }

            // Encode literals.
            {
                let lit_length = ip - anchor;
                token = op;
                op += 1;
                if output_directive == OutputDirective::LimitedOutput
                    && op + lit_length + (2 + 1 + LASTLITERALS) + lit_length / 255 > olimit
                {
                    // Cannot compress within the dst budget. The indexes
                    // stored in the hash table are nonetheless fine.
                    return 0;
                }
                if output_directive == OutputDirective::FillOutput
                    && op + (lit_length + 240) / 255 + lit_length + 2 + 1 + MFLIMIT - MINMATCH
                        > olimit
                {
                    op -= 1;
                    break 'last_literals;
                }
                if lit_length >= RUN_MASK {
                    let mut len = lit_length - RUN_MASK;
                    dst[token] = (RUN_MASK << ML_BITS) as u8;
                    while len >= 255 {
                        dst[op] = 255;
                        op += 1;
                        len -= 255;
                    }
                    dst[op] = len as u8;
                    op += 1;
                } else {
                    dst[token] = (lit_length << ML_BITS) as u8;
                }

                // Copy the literals.
                wild_copy8_from(dst, op, src, anchor, op + lit_length);
                op += lit_length;
            }

            // _next_match:
            loop {
                // At this stage: ip at the start of the LZ operation, mtch at
                // the start of the earlier occurrence (in the prefix or the
                // external dictionary), offset (with maybe_ext_mem),
                // low_limit (the dictionary's start for a match within it),
                // and the token's literal length written.

                if output_directive == OutputDirective::FillOutput
                    && op + 2 + 1 + MFLIMIT - MINMATCH > olimit
                {
                    // The match was too close to the end: rewind, and go to
                    // the last literals.
                    op = token;
                    break 'last_literals;
                }

                // Encode the offset.
                let match_offset = if maybe_ext_mem {
                    debug_assert!(offset as usize <= DISTANCE_MAX && offset > 0);
                    offset
                } else {
                    debug_assert!(mtch.0 == Seg::Buf && ip - mtch.1 <= DISTANCE_MAX);
                    (ip - mtch.1) as u32
                };
                dst[op..op + 2].copy_from_slice(&(match_offset as u16).to_le_bytes());
                op += 2;

                // Encode the match length.
                {
                    let mut match_code: usize;
                    if maybe_ext_mem && low_limit.0 == Seg::Dict && mtch.0 == Seg::Dict {
                        // A match within the external dictionary.
                        let mut limit = ip + (dict_end - mtch.1);
                        debug_assert!(dict_end > mtch.1);
                        if limit as isize > matchlimit {
                            limit = matchlimit as usize;
                        }
                        match_code =
                            count(src, ip + MINMATCH, dictionary, mtch.1 + MINMATCH, limit);
                        ip += match_code + MINMATCH;
                        if ip == limit {
                            let more = count(src, limit, src, source, matchlimit as usize);
                            match_code += more;
                            ip += more;
                        }
                    } else {
                        match_code = count(
                            src,
                            ip + MINMATCH,
                            src,
                            mtch.1 + MINMATCH,
                            matchlimit as usize,
                        );
                        ip += match_code + MINMATCH;
                    }

                    if output_directive != OutputDirective::NotLimited
                        && op + (1 + LASTLITERALS) + (match_code + 240) / 255 > olimit
                    {
                        if output_directive == OutputDirective::FillOutput {
                            // The match description is too long: reduce it.
                            let new_match_code = 15 /* in token */ - 1 /* to avoid needing a zero byte */
                                + (olimit - op - 1 - LASTLITERALS) * 255;
                            ip -= match_code - new_match_code;
                            debug_assert!(new_match_code < match_code);
                            match_code = new_match_code;
                            if ip <= filled_ip {
                                // ip is before what the hash table was
                                // filled up to: remove those positions from
                                // it, as the table may be reused.
                                let mut ptr = ip;
                                while ptr <= filled_ip {
                                    let h = hash_position(src, ptr, table_type);
                                    cctx.clear_hash(h, table_type);
                                    ptr += 1;
                                }
                            }
                        } else {
                            // Cannot compress within the dst budget.
                            return 0;
                        }
                    }
                    if match_code >= ML_MASK {
                        dst[token] += ML_MASK as u8;
                        match_code -= ML_MASK;
                        dst[op..op + 4].fill(0xFF);
                        while match_code >= 4 * 255 {
                            op += 4;
                            dst[op..op + 4].fill(0xFF);
                            match_code -= 4 * 255;
                        }
                        op += match_code / 255;
                        dst[op] = (match_code % 255) as u8;
                        op += 1;
                    } else {
                        dst[token] += match_code as u8;
                    }
                }
                // Ensure there is enough space for the last literals.
                debug_assert!(
                    !(output_directive == OutputDirective::FillOutput
                        && op + 1 + LASTLITERALS > olimit)
                );

                anchor = ip;

                // Test the end of the chunk.
                if ip as isize >= mflimit_plus_one {
                    break 'last_literals;
                }

                // Fill the table.
                {
                    let h = hash_position(src, ip - 2, table_type);
                    if table_type == TableType::ByPtr {
                        cctx.put_index_on_hash((ip - 2) as u32 + 1, h, table_type);
                    } else {
                        let idx = ((ip - 2 - source) as u32).wrapping_add(start_index);
                        cctx.put_index_on_hash(idx, h, table_type);
                    }
                }

                // Test the next position (ip < mflimitPlusOne).
                let Some(chunk) = chunk8(window, last, ip) else {
                    break 'last_literals;
                };
                let ip_word = word(chunk);
                if table_type == TableType::ByPtr {
                    let h = hash_chunk(chunk, table_type);
                    let stored = cctx.get_index_on_hash(h, table_type);
                    cctx.put_index_on_hash(ip as u32 + 1, h, table_type);
                    if stored != 0 {
                        let m = stored as usize - 1;
                        if m + DISTANCE_MAX >= ip && read32_before(window, last, m) == ip_word {
                            mtch = (Seg::Buf, m);
                            token = op;
                            op += 1;
                            dst[token] = 0;
                            continue;
                        }
                    }
                } else {
                    // byU32, byU16.
                    let h = hash_chunk(chunk, table_type);
                    let current = ((ip - source) as u32).wrapping_add(start_index);
                    let mut match_index = cctx.get_index_on_hash(h, table_type);
                    debug_assert!(match_index < current);
                    match dict_directive {
                        DictDirective::UsingDictCtx => {
                            if match_index < start_index {
                                // There was no match: try the dictionary.
                                let ctx = dict_ctx.map_or(&*cctx, |(c, _)| c);
                                match_index = ctx.get_index_on_hash(h, TableType::ByU32);
                                mtch = (Seg::Dict, dict_pos(match_index));
                                // Required for the match length counter.
                                low_limit = (Seg::Dict, 0);
                                match_index = match_index.wrapping_add(dict_delta);
                            } else {
                                mtch = (Seg::Buf, pos_of(match_index));
                                low_limit = (Seg::Buf, source);
                            }
                        }
                        DictDirective::UsingExtDict => {
                            if match_index < start_index {
                                mtch = (Seg::Dict, dict_pos(match_index));
                                low_limit = (Seg::Dict, 0);
                            } else {
                                mtch = (Seg::Buf, pos_of(match_index));
                                low_limit = (Seg::Buf, source);
                            }
                        }
                        // A single memory segment.
                        _ => mtch = (Seg::Buf, pos_of(match_index)),
                    }
                    cctx.put_index_on_hash(current, h, table_type);
                    debug_assert!(match_index < current);
                    if (dict_issue != DictIssue::DictSmall || match_index >= prefix_idx_limit)
                        && (table_type == TableType::ByU16
                            || match_index as usize + DISTANCE_MAX >= current as usize)
                    {
                        let candidate = match mtch.0 {
                            Seg::Buf => read32_before(window, last, mtch.1),
                            Seg::Dict => read32(dictionary, mtch.1),
                        };
                        if candidate == ip_word {
                            token = op;
                            op += 1;
                            dst[token] = 0;
                            if maybe_ext_mem {
                                offset = current - match_index;
                            }
                            continue;
                        }
                    }
                }
                break;
            }

            // Prepare the next loop (ip <= mflimitPlusOne).
            ip += 1;
            let Some(chunk) = chunk8(window, last, ip) else {
                break 'last_literals;
            };
            forward_chunk = chunk;
            forward_h = hash_chunk(chunk, table_type);
        }
    }

    // _last_literals: encode the last literals.
    {
        let mut last_run = iend - anchor;
        if output_directive != OutputDirective::NotLimited
            && op + last_run + 1 + (last_run + 255 - RUN_MASK) / 255 > olimit
        {
            if output_directive == OutputDirective::FillOutput {
                // Adapt lastRun to fill dst.
                debug_assert!(olimit >= op);
                last_run = olimit - op - 1 /* token */;
                // Additional length tokens.
                last_run -= (last_run + 256 - RUN_MASK) / 256;
            } else {
                // Cannot compress within the dst budget.
                return 0;
            }
        }
        if last_run >= RUN_MASK {
            let mut accumulator = last_run - RUN_MASK;
            dst[op] = (RUN_MASK << ML_BITS) as u8;
            op += 1;
            while accumulator >= 255 {
                dst[op] = 255;
                op += 1;
                accumulator -= 255;
            }
            dst[op] = accumulator as u8;
            op += 1;
        } else {
            dst[op] = (last_run << ML_BITS) as u8;
            op += 1;
        }
        dst[op..op + last_run].copy_from_slice(&src[anchor..anchor + last_run]);
        ip = anchor + last_run;
        op += last_run;
    }

    if output_directive == OutputDirective::FillOutput {
        *input_consumed = ip - source;
    }
    debug_assert!(op > 0);
    op
}

/// `LZ4_wildCopy8` from the input to the output: 8 bytes at a time, at
/// least once, up to 8 bytes past `end`.
#[inline(always)]
pub(crate) fn wild_copy8_from(
    dst: &mut [u8],
    mut op: usize,
    src: &[u8],
    mut ip: usize,
    end: usize,
) {
    loop {
        dst[op..op + 8].copy_from_slice(&src[ip..ip + 8]);
        op += 8;
        ip += 8;
        if op >= end {
            break;
        }
    }
}

/// `LZ4_compress_generic`: also takes care of an empty source, and of one
/// too large. Inlined, as liblz4's (`LZ4_FORCE_INLINE`), so that each
/// caller's constant directives and table type specialise the loop.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn compress_generic(
    cctx: &mut StreamState,
    input: &Input<'_>,
    dst: &mut [u8],
    input_consumed: &mut usize,
    dst_capacity: usize,
    output_directive: OutputDirective,
    table_type: TableType,
    dict_directive: DictDirective,
    dict_issue: DictIssue,
    acceleration: u32,
    dict_ctx: Option<(&StreamState, &[u8])>,
) -> usize {
    if input.len > MAX_INPUT_SIZE {
        // Unsupported source size, too large.
        return 0;
    }
    if input.len == 0 {
        if output_directive != OutputDirective::NotLimited && dst_capacity == 0 {
            // No output: nothing can be written.
            return 0;
        }
        // An empty block.
        dst[0] = 0;
        if output_directive == OutputDirective::FillOutput {
            *input_consumed = 0;
        }
        return 1;
    }
    compress_generic_validated(
        cctx,
        input,
        dst,
        input_consumed,
        dst_capacity,
        output_directive,
        table_type,
        dict_directive,
        dict_issue,
        acceleration,
        dict_ctx,
    )
}

/// The table for a source of `size` bytes without a dictionary: `byU16`
/// under 64 KB; else `byU32`, or `byPtr` on 32-bit machines (where liblz4
/// takes it for a source at an address past 64 KB, which is any).
fn large_table() -> TableType {
    if usize::BITS == 32 {
        TableType::ByPtr
    } else {
        TableType::ByU32
    }
}

/// The acceleration liblz4 uses for `acceleration`.
fn clamp_acceleration(acceleration: i32) -> u32 {
    acceleration.clamp(ACCELERATION_DEFAULT, ACCELERATION_MAX) as u32
}

impl StreamState {
    /// `LZ4_compress_fast_extState`: the state initialised, then `src`
    /// compressed alone.
    pub(crate) fn compress_fast_ext_state(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> usize {
        self.init();
        let acceleration = clamp_acceleration(acceleration);
        let input = Input {
            buf: src,
            src: 0,
            len: src.len(),
            dict: &[],
        };
        let mut unused = 0;
        let limited = dst.len() < compress_bound(src.len());
        let capacity = if limited { dst.len() } else { 0 };
        // One call for each case, with its directives constant, as in
        // liblz4, so that each is specialised.
        macro_rules! generic {
            ($output:expr, $table:expr) => {
                compress_generic(
                    self,
                    &input,
                    dst,
                    &mut unused,
                    capacity,
                    $output,
                    $table,
                    DictDirective::NoDict,
                    DictIssue::NoDictIssue,
                    acceleration,
                    None,
                )
            };
        }
        match (limited, src.len() < LIMIT_64K) {
            (false, true) => generic!(OutputDirective::NotLimited, TableType::ByU16),
            (false, false) => generic!(OutputDirective::NotLimited, large_table()),
            (true, true) => generic!(OutputDirective::LimitedOutput, TableType::ByU16),
            (true, false) => generic!(OutputDirective::LimitedOutput, large_table()),
        }
    }

    /// `LZ4_compress_fast_extState_fastReset`: as `compress_fast_ext_state`,
    /// on a state known to be clean, without initialising it.
    pub(crate) fn compress_fast_ext_state_fast_reset(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> usize {
        let acceleration = clamp_acceleration(acceleration);
        let input = Input {
            buf: src,
            src: 0,
            len: src.len(),
            dict: &[],
        };
        let mut unused = 0;
        let limited = dst.len() < compress_bound(src.len());
        let capacity = if limited { dst.len() } else { 0 };
        macro_rules! generic {
            ($output:expr, $table:expr, $issue:expr) => {
                compress_generic(
                    self,
                    &input,
                    dst,
                    &mut unused,
                    capacity,
                    $output,
                    $table,
                    DictDirective::NoDict,
                    $issue,
                    acceleration,
                    None,
                )
            };
        }
        let small = src.len() < LIMIT_64K;
        let table = if small {
            TableType::ByU16
        } else {
            large_table()
        };
        self.prepare_table(src.len(), table);
        let dict_small = self.current_offset != 0;
        match (limited, small, dict_small) {
            (false, true, true) => generic!(
                OutputDirective::NotLimited,
                TableType::ByU16,
                DictIssue::DictSmall
            ),
            (false, true, false) => generic!(
                OutputDirective::NotLimited,
                TableType::ByU16,
                DictIssue::NoDictIssue
            ),
            (false, false, _) => generic!(
                OutputDirective::NotLimited,
                large_table(),
                DictIssue::NoDictIssue
            ),
            (true, true, true) => generic!(
                OutputDirective::LimitedOutput,
                TableType::ByU16,
                DictIssue::DictSmall
            ),
            (true, true, false) => generic!(
                OutputDirective::LimitedOutput,
                TableType::ByU16,
                DictIssue::NoDictIssue
            ),
            (true, false, _) => generic!(
                OutputDirective::LimitedOutput,
                large_table(),
                DictIssue::NoDictIssue
            ),
        }
    }

    /// `LZ4_compress_destSize_extState_internal`: as much of `src` as fits
    /// in `dst`, compressed. `src_size` gets how much that is.
    pub(crate) fn compress_dest_size(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        src_size: &mut usize,
        acceleration: i32,
    ) -> usize {
        self.init();
        if dst.len() >= compress_bound(src.len()) {
            // Compression success is guaranteed.
            *src_size = src.len();
            return self.compress_fast_ext_state(src, dst, acceleration);
        }
        // Differs from liblz4: liblz4 passes the acceleration on as it is
        // here, where the other functions clamp it. One below 1 makes its
        // search step negative, which is undefined; the port takes it as 1.
        // One higher than ACCELERATION_MAX is kept, as liblz4 keeps it.
        let acceleration = acceleration.clamp(1, 1 << 24) as u32;
        let input = Input {
            buf: src,
            src: 0,
            len: src.len(),
            dict: &[],
        };
        let capacity = dst.len();
        macro_rules! generic {
            ($table:expr) => {
                compress_generic(
                    self,
                    &input,
                    dst,
                    src_size,
                    capacity,
                    OutputDirective::FillOutput,
                    $table,
                    DictDirective::NoDict,
                    DictIssue::NoDictIssue,
                    acceleration,
                    None,
                )
            };
        }
        if src.len() < LIMIT_64K {
            generic!(TableType::ByU16)
        } else {
            generic!(large_table())
        }
    }
}

/// `LZ4_compress_fast`: `src` compressed alone into `dst`, with
/// `acceleration` (1 is the default; higher is faster, and compresses
/// less). Returns the compressed size, or 0 if it does not fit in `dst`.
pub fn compress_fast(src: &[u8], dst: &mut [u8], acceleration: i32) -> usize {
    StreamState::default().compress_fast_ext_state(src, dst, acceleration)
}

/// `LZ4_compress_default`: `compress_fast` with an acceleration of 1.
pub fn compress_default(src: &[u8], dst: &mut [u8]) -> usize {
    compress_fast(src, dst, 1)
}

/// `LZ4_compress_destSize`: as much of `src` as fits in `dst`, compressed.
/// Returns the compressed size and how much of `src` it holds.
pub fn compress_dest_size(src: &[u8], dst: &mut [u8]) -> (usize, usize) {
    let mut src_size = src.len();
    let written = StreamState::default().compress_dest_size(src, dst, &mut src_size, 1);
    (written, src_size)
}

/// `LZ4_stream_t`, as a state for the one-call compressors that take one
/// (`LZ4_compress_fast_extState` and its `_fastReset` form), so that its
/// hash table is allocated once.
#[derive(Clone, Debug, Default)]
pub struct State {
    state: StreamState,
}

impl State {
    /// `LZ4_createStream`: an initialised state.
    pub fn new() -> Self {
        State::default()
    }

    /// `LZ4_compress_fast_extState`: as [`compress_fast`], with this state,
    /// which it initialises first.
    pub fn compress_fast_ext_state(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> usize {
        self.state.compress_fast_ext_state(src, dst, acceleration)
    }

    /// `LZ4_compress_fast_extState_fastReset`: as
    /// [`compress_fast_ext_state`](Self::compress_fast_ext_state), but the
    /// table is reset only where it has to be, which is faster for small
    /// inputs. The output can differ from `compress_fast`'s, as liblz4's
    /// does.
    pub fn compress_fast_ext_state_fast_reset(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> usize {
        self.state
            .compress_fast_ext_state_fast_reset(src, dst, acceleration)
    }

    /// `LZ4_compress_destSize_extState`: as [`compress_dest_size`], with this
    /// state, which is initialised again after.
    pub fn compress_dest_size_ext_state(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> (usize, usize) {
        let mut src_size = src.len();
        let written = self
            .state
            .compress_dest_size(src, dst, &mut src_size, acceleration);
        self.state.init();
        (written, src_size)
    }
}

/*-******************************
 *  Streaming functions
 ********************************/

/// `HASH_UNIT`: `sizeof(reg_t)`.
const HASH_UNIT: usize = if REG_IS_64 { 8 } else { 4 };

/// Where the history of a block given to `compress_fast_continue` is.
pub(crate) enum History<'a> {
    /// Right before the source, in the same buffer: `dictEnd == source`
    /// (`withPrefix64k`), the state's `dictSize` bytes.
    Prefix,
    /// Apart from the source (`usingExtDict`): the state's `dictSize`
    /// bytes.
    Ext(&'a [u8]),
}

/// `LZ4_loadDict_internal`'s two ways.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadDictMode {
    Fast,
    Slow,
}

impl StreamState {
    /// The size of the history, `dictSize`.
    pub(crate) fn dict_size(&self) -> usize {
        self.dict_size as usize
    }

    /// `LZ4_resetStream_fast`.
    pub(crate) fn reset_fast(&mut self) {
        self.prepare_table(0, TableType::ByU32);
    }

    /// `LZ4_loadDict_internal`: the state reset, and the last 64 KB of
    /// `dictionary` loaded as its history. Returns their size, which is also
    /// how many bytes of `dictionary`'s end the history is (0 for less than
    /// `HASH_UNIT`).
    pub(crate) fn load_dict(&mut self, dictionary: &[u8], mode: LoadDictMode) -> usize {
        let table_type = TableType::ByU32;
        // It's necessary to reset the context, and not just continue it
        // with prepareTable(), to avoid any risk of generating overflowing
        // matchIndex when compressing using this dictionary.
        self.init();

        // We always increment the offset by 64 KB, since, if the dict is
        // longer, we truncate it to the last 64k, and if it's shorter, we
        // still want to advance by a whole window length so we can provide
        // the guarantee that there are only valid offsets in the window.
        self.current_offset += 64 * KB as u32;

        if dictionary.len() < HASH_UNIT {
            return 0;
        }

        let dict = &dictionary[dictionary.len() - dictionary.len().min(64 * KB)..];
        self.dict_size = dict.len() as u32;
        self.table_type = table_type;
        let start = self.current_offset - self.dict_size;

        let mut p = 0;
        while p + HASH_UNIT <= dict.len() {
            let h = hash_position(dict, p, table_type);
            // Overwriting favors the positions at the end of the dictionary.
            self.put_index_on_hash(start + p as u32, h, table_type);
            p += 3;
        }

        if mode == LoadDictMode::Slow {
            // Fill the hash table with additional references, to improve
            // compression.
            let mut p = 0;
            while p + HASH_UNIT <= dict.len() {
                let h = hash_position(dict, p, table_type);
                let limit = self.current_offset - 64 * KB as u32;
                if self.get_index_on_hash(h, table_type) <= limit {
                    // Not overwriting favors the positions at the beginning
                    // of the dictionary.
                    self.put_index_on_hash(start + p as u32, h, table_type);
                }
                p += 1;
            }
        }
        self.dict_size as usize
    }

    /// `LZ4_renormDictT`: rescales the hash table before the indexes could
    /// overflow. Returns whether it did, the history then cut to 64 KB.
    fn renorm_dict(&mut self, next_size: usize) -> bool {
        if u64::from(self.current_offset) + next_size as u64 > 0x8000_0000 {
            // Rescale the hash table.
            let delta = self.current_offset - 64 * KB as u32;
            for entry in self.hash_table.iter_mut() {
                *entry = entry.saturating_sub(delta);
            }
            self.current_offset = 64 * KB as u32;
            if self.dict_size > 64 * KB as u32 {
                self.dict_size = 64 * KB as u32;
            }
            return true;
        }
        false
    }

    /// `LZ4_compress_fast_continue`: `input`'s source compressed with the
    /// history `history`, the state's `dictSize` bytes there, or, with a
    /// dictionary attached (`dict_ctx`, its state and content), with that.
    /// After it, the history is the source itself, or (with a prefix) the
    /// history and the source.
    ///
    /// Differs from liblz4: liblz4 finds the prefix case by comparing
    /// pointers (`dictEnd == source`); the caller says it. The case of a
    /// source that overlaps the end of its history is not taken.
    pub(crate) fn compress_fast_continue(
        &mut self,
        input: &Input<'_>,
        history: History<'_>,
        dst: &mut [u8],
        acceleration: i32,
        dict_ctx: &mut Option<std::sync::Arc<(StreamState, Vec<u8>)>>,
    ) -> usize {
        let table_type = TableType::ByU32;
        // Fix index overflow.
        self.renorm_dict(input.len);
        let acceleration = clamp_acceleration(acceleration);
        let mut history = history;

        // Invalidate tiny dictionaries: not enough for a hash. In prefix mode
        // they stay, in case a later call would use them; with no input,
        // too.
        if self.dict_size < 4
            && !matches!(history, History::Prefix)
            && input.len > 0
            && dict_ctx.is_none()
        {
            // Remove the dictionary from the history, to employ the faster
            // prefix mode.
            self.dict_size = 0;
            history = History::Prefix;
        }

        let capacity = dst.len();
        let mut unused = 0;
        let dict_small = self.dict_size < 64 * KB as u32 && self.dict_size < self.current_offset;
        match history {
            // Prefix mode: the source follows the dictionary.
            History::Prefix => {
                // One call for each case, as in liblz4, so that each is
                // specialised.
                macro_rules! generic {
                    ($issue:expr) => {
                        compress_generic(
                            self,
                            input,
                            dst,
                            &mut unused,
                            capacity,
                            OutputDirective::LimitedOutput,
                            table_type,
                            DictDirective::WithPrefix64k,
                            $issue,
                            acceleration,
                            None,
                        )
                    };
                }
                if dict_small {
                    generic!(DictIssue::DictSmall)
                } else {
                    generic!(DictIssue::NoDictIssue)
                }
            }
            // External dictionary mode.
            History::Ext(dict) => {
                let result = if let Some(ctx) = dict_ctx.clone() {
                    // dictCtx'es (from LZ4_loadDict) guarantee that their
                    // tables contain no references to offsets between
                    // dictCtx->currentOffset - 64 KB and
                    // dictCtx->currentOffset - dictCtx->dictSize, so
                    // noDictIssue is safe even when the dict isn't a full 64
                    // KB.
                    if input.len > 4 * KB {
                        // For large blobs, it is faster to copy the
                        // dictionary's tables into the active context, so
                        // that the loop looks into one table.
                        *self = ctx.0.clone();
                        *dict_ctx = None;
                        let with_dict = Input {
                            buf: input.buf,
                            src: input.src,
                            len: input.len,
                            dict: &ctx.1,
                        };
                        compress_generic(
                            self,
                            &with_dict,
                            dst,
                            &mut unused,
                            capacity,
                            OutputDirective::LimitedOutput,
                            table_type,
                            DictDirective::UsingExtDict,
                            DictIssue::NoDictIssue,
                            acceleration,
                            None,
                        )
                    } else {
                        // Subsequent linked blocks can't use the
                        // dictionary: they use this block. Unless it is
                        // empty, or too large, which compress_generic
                        // returns from before.
                        if (1..=MAX_INPUT_SIZE).contains(&input.len) {
                            *dict_ctx = None;
                        }
                        compress_generic(
                            self,
                            input,
                            dst,
                            &mut unused,
                            capacity,
                            OutputDirective::LimitedOutput,
                            table_type,
                            DictDirective::UsingDictCtx,
                            DictIssue::NoDictIssue,
                            acceleration,
                            Some((&ctx.0, &ctx.1)),
                        )
                    }
                } else {
                    let with_dict = Input {
                        buf: input.buf,
                        src: input.src,
                        len: input.len,
                        dict,
                    };
                    macro_rules! generic {
                        ($issue:expr) => {
                            compress_generic(
                                self,
                                &with_dict,
                                dst,
                                &mut unused,
                                capacity,
                                OutputDirective::LimitedOutput,
                                table_type,
                                DictDirective::UsingExtDict,
                                $issue,
                                acceleration,
                                None,
                            )
                        };
                    }
                    if dict_small {
                        generic!(DictIssue::DictSmall)
                    } else {
                        generic!(DictIssue::NoDictIssue)
                    }
                };
                // The history is now the source.
                self.dict_size = input.len as u32;
                result
            }
        }
    }

    /// `LZ4_attach_dictionary`, for the state: the offset bumped so that a
    /// miss can be told from a dictionary entry.
    pub(crate) fn attach(&mut self, dictionary: &StreamState) -> bool {
        // If the current offset is zero, we will never look in the external
        // dictionary context, since there is no value a table entry can take
        // that indicates a miss. In that case, we need to bump the offset to
        // something non-zero.
        if self.current_offset == 0 {
            self.current_offset = 64 * KB as u32;
        }
        // Don't actually attach an empty dictionary.
        dictionary.dict_size != 0
    }

    /// `LZ4_saveDict`'s effect on the state: the history is its last
    /// `dict_size` bytes, at most 64 KB and at most what it was. Returns the
    /// size kept.
    pub(crate) fn save_dict(&mut self, dict_size: usize) -> usize {
        let size = dict_size.min(64 * KB).min(self.dict_size as usize);
        self.dict_size = size as u32;
        size
    }
}

/// `LZ4_stream_t`, streaming: blocks compressed one after another, each
/// with the ones before (up to 64 KB) as its history
/// (`LZ4_compress_fast_continue`), and dictionaries (`LZ4_loadDict`,
/// `LZ4_attach_dictionary`).
///
/// Differs from liblz4: liblz4 refers to the history where the caller keeps
/// it, the blocks given before or a dictionary; the stream keeps a copy of
/// it instead, as liblz4 does when the caller saves it after each block
/// (`LZ4_saveDict`, with 64 KB). The blocks are liblz4's in that case.
#[derive(Clone, Debug, Default)]
pub struct Stream {
    state: StreamState,
    /// The history: the state's `dictSize` bytes.
    history: Vec<u8>,
    dict_ctx: Option<std::sync::Arc<(StreamState, Vec<u8>)>>,
}

impl Stream {
    /// `LZ4_createStream`: a stream with no history.
    pub fn new() -> Self {
        Stream::default()
    }

    /// `LZ4_resetStream_fast`: the history forgotten, the hash table reset
    /// only where it has to be.
    pub fn reset_fast(&mut self) {
        self.state.reset_fast();
        self.history.clear();
        self.dict_ctx = None;
    }

    /// `LZ4_loadDict`: the stream reset, with the last 64 KB of
    /// `dictionary` as the history of the next block. Returns their size (0
    /// for less than 8 bytes, 4 on 32-bit machines).
    pub fn load_dict(&mut self, dictionary: &[u8]) -> usize {
        self.load(dictionary, LoadDictMode::Fast)
    }

    /// `LZ4_loadDictSlow`: as `load_dict`, with more of the dictionary's
    /// positions in the table, which compresses better.
    pub fn load_dict_slow(&mut self, dictionary: &[u8]) -> usize {
        self.load(dictionary, LoadDictMode::Slow)
    }

    fn load(&mut self, dictionary: &[u8], mode: LoadDictMode) -> usize {
        self.dict_ctx = None;
        let size = self.state.load_dict(dictionary, mode);
        self.history.clear();
        self.history
            .extend_from_slice(&dictionary[dictionary.len() - size..]);
        size
    }

    /// `LZ4_attach_dictionary`: `dictionary`, a stream a dictionary was
    /// loaded into, as the history of the next block, without copying its
    /// table now (for the blocks of 4 KB or less; larger ones copy it). The
    /// stream must have been reset (`reset_fast`) or be new. Only the next
    /// block uses it.
    pub fn attach_dictionary(&mut self, dictionary: &Stream) {
        if self.state.attach(&dictionary.state) {
            self.dict_ctx = Some(std::sync::Arc::new((
                dictionary.state.clone(),
                dictionary.history.clone(),
            )));
        } else {
            self.dict_ctx = None;
        }
    }

    /// `LZ4_compress_fast_continue`: the next block, with the ones before as
    /// its history. Returns its compressed size, or 0 if it does not fit in
    /// `dst` (then the stream must be reset before it is used again).
    pub fn compress_fast_continue(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
        acceleration: i32,
    ) -> usize {
        let input = Input {
            buf: src,
            src: 0,
            len: src.len(),
            dict: &[],
        };
        let history = core::mem::take(&mut self.history);
        let result = self.state.compress_fast_continue(
            &input,
            History::Ext(&history),
            dst,
            acceleration,
            &mut self.dict_ctx,
        );
        // `LZ4_saveDict(stream, safeBuffer, 64 KB)`: the last 64 KB of the
        // history and the block.
        let mut kept = history;
        if src.len() >= 64 * KB || self.state.dict_size() == 0 {
            kept.clear();
        }
        kept.extend_from_slice(src);
        let size = self.state.save_dict(64 * KB);
        kept.drain(..kept.len() - size.min(kept.len()));
        self.history = kept;
        result
    }

    /// `LZ4_saveDict`: the history cut to its last `dict_size` bytes (at
    /// most 64 KB), which are copied into `safe_buffer` when it is given.
    /// Returns the size kept.
    pub fn save_dict(&mut self, dict_size: usize) -> usize {
        let size = self.state.save_dict(dict_size);
        let len = self.history.len();
        self.history.drain(..len - size.min(len));
        size
    }

    /// The history: what the next block may refer to.
    pub fn history(&self) -> &[u8] {
        &self.history
    }
}
