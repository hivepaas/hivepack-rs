//! Decompression machinery: port of `decompress.c`, with the
//! decompression-side structure of `bzlib_private.h`.
//!
//! `BZ2_decompress` reads a stream's header and then one block at a time,
//! up to the point where the block can be written out, which `bzlib.rs`
//! does. libbzip2 stops wherever the input runs out and resumes there on
//! the next call: every place it reads bits is a `case` of one `switch`,
//! with the loop counters and other locals saved in the state between
//! calls. The port keeps that shape: each state is an arm of a `match`,
//! and the locals live in [`Save`], copied in and out as libbzip2 copies
//! its `save_*` fields.

use crate::bzip2::bzlib::InBuffer;
use crate::bzip2::crctable::CRC_INIT;
use crate::bzip2::huffman::create_decode_tables;
use crate::bzip2::private::*;
use crate::bzip2::randtable::Rand;

/// The locals of `BZ2_decompress` that live from one call to the next:
/// libbzip2's `save_*` fields. `save_gLimit`, `save_gBase` and
/// `save_gPerm` point at the tables of group `g_sel`, which the port uses
/// in their place.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Save {
    pub(crate) i: i32,
    pub(crate) j: i32,
    pub(crate) t: i32,
    pub(crate) alpha_size: i32,
    pub(crate) n_groups: i32,
    pub(crate) n_selectors: i32,
    pub(crate) eob: i32,
    pub(crate) group_no: i32,
    pub(crate) group_pos: i32,
    pub(crate) next_sym: i32,
    pub(crate) nblock_max: i32,
    pub(crate) nblock: i32,
    pub(crate) es: i32,
    pub(crate) n: i32,
    pub(crate) curr: i32,
    pub(crate) zn: i32,
    pub(crate) zvec: i32,
    pub(crate) zj: i32,
    pub(crate) g_sel: i32,
    pub(crate) g_minlen: i32,
}

/// `DState`: the decompressor.
pub(crate) struct DState {
    /// State indicator for this stream: one of the `BZ_X_*` constants.
    pub(crate) state: i32,

    // For doing the final run-length decoding.
    pub(crate) state_out_ch: u8,
    pub(crate) state_out_len: i32,
    pub(crate) block_randomised: bool,
    pub(crate) rand: Rand,

    // The buffer for bit stream reading.
    pub(crate) bs_buff: u32,
    pub(crate) bs_live: i32,

    // Misc administratium.
    pub(crate) block_size_100k: i32,
    pub(crate) small_decompress: bool,
    curr_block_no: i32,

    // For undoing the Burrows-Wheeler transform.
    orig_ptr: i32,
    pub(crate) t_pos: u32,
    pub(crate) k0: u8,
    unzftab: [i32; 256],
    pub(crate) nblock_used: i32,
    pub(crate) cftab: [i32; 257],
    cftab_copy: [i32; 257],

    // For undoing the Burrows-Wheeler transform (FAST).
    //
    // Differs from libbzip2: `tt`, `ll16` and `ll4` are allocated once the
    // header gives the block size, as libbzip2 allocates them, but hold
    // only what the current block wrote: `tt` and `ll16` grow as the block
    // is decoded, and `ll4` is sized for each block. libbzip2's
    // allocations are left uninitialized, and it reads only what the block
    // wrote, so nothing it reads differs.
    pub(crate) tt: Vec<u32>,

    // For undoing the Burrows-Wheeler transform (SMALL).
    pub(crate) ll16: Vec<u16>,
    pub(crate) ll4: Vec<u8>,

    // Stored and calculated CRCs.
    pub(crate) stored_block_crc: u32,
    pub(crate) stored_combined_crc: u32,
    pub(crate) calculated_block_crc: u32,
    pub(crate) calculated_combined_crc: u32,

    // Map of bytes used in block.
    n_in_use: i32,
    in_use: [bool; 256],
    in_use16: [bool; 16],
    seq_to_unseq: [u8; 256],

    // For decoding the MTF values.
    mtfa: [u8; MTFA_SIZE as usize],
    mtfbase: [i32; (256 / MTFL_SIZE) as usize],
    selector: [u8; BZ_MAX_SELECTORS],
    selector_mtf: [u8; BZ_MAX_SELECTORS],
    len: [[u8; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],

    limit: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    base: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    perm: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    min_lens: [i32; BZ_N_GROUPS],

    /// Save area for scalars in the main decompress code.
    pub(crate) save: Save,

    // `total_in_lo32` and `total_in_hi32` of the `bz_stream`, and the same
    // for the output.
    pub(crate) total_in: u64,
    pub(crate) total_out: u64,

    /// Not libbzip2's: once a block's output is all given, `bz_decompress`
    /// returns `BZ_BLOCK_DONE` before reading the next block's magic, for a
    /// thread that decodes one block.
    pub(crate) stop_after_block: bool,
}

impl DState {
    /// The state `BZ2_bzDecompressInit` sets up.
    pub(crate) fn new(small: bool) -> Box<DState> {
        Box::new(DState {
            state: BZ_X_MAGIC_1,
            state_out_ch: 0,
            state_out_len: 0,
            block_randomised: false,
            rand: Rand::default(),
            bs_buff: 0,
            bs_live: 0,
            block_size_100k: 0,
            small_decompress: small,
            curr_block_no: 0,
            orig_ptr: 0,
            t_pos: 0,
            k0: 0,
            unzftab: [0; 256],
            nblock_used: 0,
            cftab: [0; 257],
            cftab_copy: [0; 257],
            tt: Vec::new(),
            ll16: Vec::new(),
            ll4: Vec::new(),
            stored_block_crc: 0,
            stored_combined_crc: 0,
            calculated_block_crc: 0,
            calculated_combined_crc: 0,
            n_in_use: 0,
            in_use: [false; 256],
            in_use16: [false; 16],
            seq_to_unseq: [0; 256],
            mtfa: [0; MTFA_SIZE as usize],
            mtfbase: [0; (256 / MTFL_SIZE) as usize],
            selector: [0; BZ_MAX_SELECTORS],
            selector_mtf: [0; BZ_MAX_SELECTORS],
            len: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            limit: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            base: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            perm: [[0; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
            min_lens: [0; BZ_N_GROUPS],
            save: Save::default(),
            total_in: 0,
            total_out: 0,
            stop_after_block: false,
        })
    }

    /// `SET_LL4`.
    #[inline(always)]
    fn set_ll4(&mut self, i: usize, n: u32) {
        let b = &mut self.ll4[i >> 1];
        if i & 0x1 == 0 {
            *b = (*b & 0xf0) | n as u8;
        } else {
            *b = (*b & 0x0f) | ((n as u8) << 4);
        }
    }

    /// `GET_LL4`.
    #[inline(always)]
    fn get_ll4(&self, i: usize) -> u32 {
        (u32::from(self.ll4[i >> 1]) >> ((i << 2) & 0x4)) & 0xF
    }

    /// `SET_LL`.
    #[inline(always)]
    fn set_ll(&mut self, i: usize, n: u32) {
        self.ll16[i] = (n & 0x0000_ffff) as u16;
        self.set_ll4(i, n >> 16);
    }

    /// `GET_LL`.
    #[inline(always)]
    pub(crate) fn get_ll(&self, i: usize) -> u32 {
        u32::from(self.ll16[i]) | (self.get_ll4(i) << 16)
    }
}

/// `BZ2_indexIntoF`: the byte whose run of the first column `indx` is in.
#[inline(always)]
pub(crate) fn index_into_f(indx: i32, cftab: &[i32; 257]) -> i32 {
    let mut nb = 0;
    let mut na = 256;
    loop {
        let mid = (nb + na) >> 1;
        if indx >= cftab[mid] {
            nb = mid;
        } else {
            na = mid;
        }
        if na - nb == 1 {
            break;
        }
    }
    nb as i32
}

/// `makeMaps_d`.
fn make_maps_d(s: &mut DState) {
    s.n_in_use = 0;
    for i in 0..256 {
        if s.in_use[i] {
            s.seq_to_unseq[s.n_in_use as usize] = i as u8;
            s.n_in_use += 1;
        }
    }
}

/// `BZ2_decompress`: reads on from where the last call stopped, up to the
/// end of a block's data (it then sets `BZ_X_OUTPUT` and returns `BZ_OK`),
/// the end of the stream (`BZ_STREAM_END`), the end of the input
/// (`BZ_OK`), or an error.
pub(crate) fn decompress(s: &mut DState, input: &mut InBuffer<'_>) -> i32 {
    if s.state == BZ_X_MAGIC_1 {
        // Initialise the save area.
        s.save = Save::default();
    }

    // Restore from the save area.
    let mut v = s.save;

    // `GET_BITS`: `nnn` bits, or a return with `BZ_OK` when the input runs
    // out first, the state set to `lll` for the next call to start again
    // there.
    macro_rules! get_bits {
        ($ret:lifetime, $lll:expr, $nnn:expr) => {{
            s.state = $lll;
            let nnn: i32 = $nnn;
            loop {
                if s.bs_live >= nnn {
                    let bits = (s.bs_buff >> (s.bs_live - nnn)) & ((1u32 << nnn) - 1);
                    s.bs_live -= nnn;
                    break bits;
                }
                if input.pos >= input.src.len() {
                    break $ret BZ_OK;
                }
                s.bs_buff = (s.bs_buff << 8) | u32::from(input.src[input.pos]);
                s.bs_live += 8;
                input.pos += 1;
                s.total_in += 1;
            }
        }};
    }
    macro_rules! get_uchar {
        ($ret:lifetime, $lll:expr) => {
            get_bits!($ret, $lll, 8) as u8
        };
    }
    macro_rules! get_bit {
        ($ret:lifetime, $lll:expr) => {
            get_bits!($ret, $lll, 1)
        };
    }

    // `GET_MTF_VAL`: the next symbol of the block, with the code table of
    // its group of 50. `resume` is true when the call starts again inside
    // it, at `label1` or `label2`; the group's bookkeeping is then done.
    macro_rules! get_mtf_val {
        ($ret:lifetime, $label1:expr, $label2:expr, $resume:ident) => {{
            let at_label2 = $resume && s.state == $label2;
            if !$resume {
                if v.group_pos == 0 {
                    v.group_no += 1;
                    if v.group_no >= v.n_selectors {
                        break $ret BZ_DATA_ERROR;
                    }
                    v.group_pos = BZ_G_SIZE;
                    v.g_sel = i32::from(s.selector[v.group_no as usize]);
                    v.g_minlen = s.min_lens[v.g_sel as usize];
                }
                v.group_pos -= 1;
                v.zn = v.g_minlen;
            }
            $resume = false;
            if at_label2 {
                v.zj = get_bit!($ret, $label2) as i32;
                v.zvec = (v.zvec << 1) | v.zj;
            } else {
                v.zvec = get_bits!($ret, $label1, v.zn) as i32;
            }
            let g = v.g_sel as usize;
            loop {
                if v.zn > 20
                // the longest code
                {
                    break $ret BZ_DATA_ERROR;
                }
                if v.zvec <= s.limit[g][v.zn as usize] {
                    break;
                }
                v.zn += 1;
                v.zj = get_bit!($ret, $label2) as i32;
                v.zvec = (v.zvec << 1) | v.zj;
            }
            let at = v.zvec - s.base[g][v.zn as usize];
            if at < 0 || at >= BZ_MAX_ALPHA_SIZE as i32 {
                break $ret BZ_DATA_ERROR;
            }
            s.perm[g][at as usize]
        }};
    }

    // Set when the MTF values are started afresh rather than resumed.
    let mut mtf_start = false;

    let ret_val = 'save: {
        loop {
            match s.state {
                BZ_X_MAGIC_1 => {
                    let uc = get_uchar!('save, BZ_X_MAGIC_1);
                    if uc != BZ_HDR_B {
                        break 'save BZ_DATA_ERROR_MAGIC;
                    }
                    s.state = BZ_X_MAGIC_2;
                }
                BZ_X_MAGIC_2 => {
                    let uc = get_uchar!('save, BZ_X_MAGIC_2);
                    if uc != BZ_HDR_Z {
                        break 'save BZ_DATA_ERROR_MAGIC;
                    }
                    s.state = BZ_X_MAGIC_3;
                }
                BZ_X_MAGIC_3 => {
                    let uc = get_uchar!('save, BZ_X_MAGIC_3);
                    if uc != BZ_HDR_H {
                        break 'save BZ_DATA_ERROR_MAGIC;
                    }
                    s.state = BZ_X_MAGIC_4;
                }
                BZ_X_MAGIC_4 => {
                    s.block_size_100k = get_bits!('save, BZ_X_MAGIC_4, 8) as i32;
                    if s.block_size_100k < i32::from(BZ_HDR_0 + 1)
                        || s.block_size_100k > i32::from(BZ_HDR_0 + 9)
                    {
                        break 'save BZ_DATA_ERROR_MAGIC;
                    }
                    s.block_size_100k -= i32::from(BZ_HDR_0);

                    let n = s.block_size_100k as usize * 100000;
                    let allocated = if s.small_decompress {
                        s.ll16.clear();
                        s.ll4.clear();
                        s.ll16.try_reserve_exact(n).is_ok()
                            && s.ll4.try_reserve_exact((1 + n) >> 1).is_ok()
                    } else {
                        s.tt.clear();
                        s.tt.try_reserve_exact(n).is_ok()
                    };
                    if !allocated {
                        break 'save BZ_MEM_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_1;
                }
                BZ_X_BLKHDR_1 => {
                    let uc = get_uchar!('save, BZ_X_BLKHDR_1);
                    if uc == 0x17 {
                        s.state = BZ_X_ENDHDR_2;
                        continue;
                    }
                    if uc != 0x31 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_2;
                }
                BZ_X_BLKHDR_2 => {
                    if get_uchar!('save, BZ_X_BLKHDR_2) != 0x41 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_3;
                }
                BZ_X_BLKHDR_3 => {
                    if get_uchar!('save, BZ_X_BLKHDR_3) != 0x59 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_4;
                }
                BZ_X_BLKHDR_4 => {
                    if get_uchar!('save, BZ_X_BLKHDR_4) != 0x26 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_5;
                }
                BZ_X_BLKHDR_5 => {
                    if get_uchar!('save, BZ_X_BLKHDR_5) != 0x53 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_BLKHDR_6;
                }
                BZ_X_BLKHDR_6 => {
                    if get_uchar!('save, BZ_X_BLKHDR_6) != 0x59 {
                        break 'save BZ_DATA_ERROR;
                    }
                    // Differs from libbzip2: no verbosity, so nothing is
                    // printed.
                    s.curr_block_no += 1;
                    s.stored_block_crc = 0;
                    s.state = BZ_X_BCRC_1;
                }
                BZ_X_BCRC_1 | BZ_X_BCRC_2 | BZ_X_BCRC_3 | BZ_X_BCRC_4 => {
                    let state = s.state;
                    let uc = get_uchar!('save, state);
                    s.stored_block_crc = (s.stored_block_crc << 8) | u32::from(uc);
                    s.state = if state == BZ_X_BCRC_4 {
                        BZ_X_RANDBIT
                    } else {
                        state + 1
                    };
                }
                BZ_X_RANDBIT => {
                    s.block_randomised = get_bits!('save, BZ_X_RANDBIT, 1) != 0;
                    s.orig_ptr = 0;
                    s.state = BZ_X_ORIGPTR_1;
                }
                BZ_X_ORIGPTR_1 | BZ_X_ORIGPTR_2 | BZ_X_ORIGPTR_3 => {
                    let state = s.state;
                    let uc = get_uchar!('save, state);
                    s.orig_ptr = (s.orig_ptr << 8) | i32::from(uc);
                    if state != BZ_X_ORIGPTR_3 {
                        s.state = state + 1;
                        continue;
                    }
                    if s.orig_ptr < 0 {
                        break 'save BZ_DATA_ERROR;
                    }
                    if s.orig_ptr > 10 + 100000 * s.block_size_100k {
                        break 'save BZ_DATA_ERROR;
                    }
                    // Receive the mapping table.
                    v.i = 0;
                    s.state = BZ_X_MAPPING_1;
                }
                BZ_X_MAPPING_1 => {
                    while v.i < 16 {
                        let uc = get_bit!('save, BZ_X_MAPPING_1);
                        s.in_use16[v.i as usize] = uc == 1;
                        v.i += 1;
                    }
                    s.in_use = [false; 256];
                    v.i = 0;
                    v.j = 0;
                    s.state = BZ_X_MAPPING_2;
                }
                BZ_X_MAPPING_2 => {
                    while v.i < 16 {
                        if s.in_use16[v.i as usize] {
                            while v.j < 16 {
                                let uc = get_bit!('save, BZ_X_MAPPING_2);
                                if uc == 1 {
                                    s.in_use[(v.i * 16 + v.j) as usize] = true;
                                }
                                v.j += 1;
                            }
                        }
                        v.i += 1;
                        v.j = 0;
                    }
                    make_maps_d(s);
                    if s.n_in_use == 0 {
                        break 'save BZ_DATA_ERROR;
                    }
                    v.alpha_size = s.n_in_use + 2;
                    s.state = BZ_X_SELECTOR_1;
                }
                BZ_X_SELECTOR_1 => {
                    // Now the selectors.
                    v.n_groups = get_bits!('save, BZ_X_SELECTOR_1, 3) as i32;
                    if v.n_groups < 2 || v.n_groups > BZ_N_GROUPS as i32 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_SELECTOR_2;
                }
                BZ_X_SELECTOR_2 => {
                    v.n_selectors = get_bits!('save, BZ_X_SELECTOR_2, 15) as i32;
                    if v.n_selectors < 1 {
                        break 'save BZ_DATA_ERROR;
                    }
                    v.i = 0;
                    v.j = 0;
                    s.state = BZ_X_SELECTOR_3;
                }
                BZ_X_SELECTOR_3 => {
                    while v.i < v.n_selectors {
                        loop {
                            let uc = get_bit!('save, BZ_X_SELECTOR_3);
                            if uc == 0 {
                                break;
                            }
                            v.j += 1;
                            if v.j >= v.n_groups {
                                break 'save BZ_DATA_ERROR;
                            }
                        }
                        // Having more than BZ_MAX_SELECTORS doesn't make
                        // much sense since they will never be used, but
                        // some implementations might "round up" the number
                        // of selectors, so just ignore those.
                        if (v.i as usize) < BZ_MAX_SELECTORS {
                            s.selector_mtf[v.i as usize] = v.j as u8;
                        }
                        v.i += 1;
                        v.j = 0;
                    }
                    if v.n_selectors > BZ_MAX_SELECTORS as i32 {
                        v.n_selectors = BZ_MAX_SELECTORS as i32;
                    }

                    // Undo the MTF values for the selectors.
                    let mut pos = [0u8; BZ_N_GROUPS];
                    for (vv, p) in pos.iter_mut().enumerate().take(v.n_groups as usize) {
                        *p = vv as u8;
                    }
                    for i in 0..v.n_selectors as usize {
                        let mut vv = usize::from(s.selector_mtf[i]);
                        let tmp = pos[vv];
                        while vv > 0 {
                            pos[vv] = pos[vv - 1];
                            vv -= 1;
                        }
                        pos[0] = tmp;
                        s.selector[i] = tmp;
                    }
                    v.i = v.n_selectors;

                    // Now the coding tables.
                    v.t = 0;
                    s.state = BZ_X_CODING_1;
                }
                BZ_X_CODING_1 | BZ_X_CODING_2 | BZ_X_CODING_3 => {
                    // Where this call starts again: at the 5 bits of a
                    // table's first length, or at one of the two bits of a
                    // change to the current length. Once past, every step
                    // is taken in full.
                    let mut entry = s.state;
                    while v.t < v.n_groups {
                        if entry == BZ_X_CODING_1 {
                            v.curr = get_bits!('save, BZ_X_CODING_1, 5) as i32;
                            v.i = 0;
                        }
                        while v.i < v.alpha_size {
                            loop {
                                if entry != BZ_X_CODING_3 {
                                    if v.curr < 1 || v.curr > 20 {
                                        break 'save BZ_DATA_ERROR;
                                    }
                                    let uc = get_bit!('save, BZ_X_CODING_2);
                                    if uc == 0 {
                                        break;
                                    }
                                }
                                entry = BZ_X_CODING_1;
                                let uc = get_bit!('save, BZ_X_CODING_3);
                                if uc == 0 {
                                    v.curr += 1;
                                } else {
                                    v.curr -= 1;
                                }
                            }
                            s.len[v.t as usize][v.i as usize] = v.curr as u8;
                            v.i += 1;
                            entry = BZ_X_CODING_1;
                        }
                        v.t += 1;
                        entry = BZ_X_CODING_1;
                    }

                    // Create the Huffman decoding tables.
                    for t in 0..v.n_groups as usize {
                        let mut min_len = 32;
                        let mut max_len = 0;
                        for i in 0..v.alpha_size as usize {
                            let l = i32::from(s.len[t][i]);
                            if l > max_len {
                                max_len = l;
                            }
                            if l < min_len {
                                min_len = l;
                            }
                        }
                        create_decode_tables(
                            &mut s.limit[t],
                            &mut s.base[t],
                            &mut s.perm[t],
                            &s.len[t],
                            min_len,
                            max_len,
                            v.alpha_size,
                        );
                        s.min_lens[t] = min_len;
                    }

                    // Now the MTF values.
                    v.eob = s.n_in_use + 1;
                    v.nblock_max = 100000 * s.block_size_100k;
                    v.group_no = -1;
                    v.group_pos = 0;

                    s.unzftab = [0; 256];

                    // MTF init.
                    let mut kk = MTFA_SIZE - 1;
                    for ii in (0..256 / MTFL_SIZE).rev() {
                        for jj in (0..MTFL_SIZE).rev() {
                            s.mtfa[kk as usize] = (ii * MTFL_SIZE + jj) as u8;
                            kk -= 1;
                        }
                        s.mtfbase[ii as usize] = kk + 1;
                    }

                    v.nblock = 0;
                    s.tt.clear();
                    s.ll16.clear();
                    mtf_start = true;
                    s.state = BZ_X_MTF_1;
                }
                BZ_X_MTF_1..=BZ_X_MTF_6 => {
                    // The GET_MTF_VAL in progress: the first, the one in a
                    // run of RUNA and RUNB, or the one after a byte. A call
                    // that stopped inside one starts again there.
                    let mut site = match s.state {
                        BZ_X_MTF_1 | BZ_X_MTF_2 => BZ_X_MTF_1,
                        BZ_X_MTF_3 | BZ_X_MTF_4 => BZ_X_MTF_3,
                        _ => BZ_X_MTF_5,
                    };
                    let mut resume = !mtf_start;
                    loop {
                        match site {
                            BZ_X_MTF_1 => {
                                v.next_sym = get_mtf_val!('save, BZ_X_MTF_1, BZ_X_MTF_2, resume);
                            }
                            BZ_X_MTF_3 => {
                                v.next_sym = get_mtf_val!('save, BZ_X_MTF_3, BZ_X_MTF_4, resume);
                                if v.next_sym == BZ_RUNA || v.next_sym == BZ_RUNB {
                                    // Check that N doesn't get too big, so
                                    // that es doesn't go negative. The
                                    // maximum value that can be RUNA/RUNB
                                    // encoded is equal to the block size
                                    // (post the initial RLE), viz, 900k, so
                                    // bounding N at 2 million should guard
                                    // against overflow without rejecting
                                    // any legitimate inputs.
                                    if v.n >= 2 * 1024 * 1024 {
                                        break 'save BZ_DATA_ERROR;
                                    }
                                    if v.next_sym == BZ_RUNA {
                                        v.es += v.n;
                                    } else {
                                        v.es += 2 * v.n;
                                    }
                                    v.n *= 2;
                                    continue;
                                }

                                v.es += 1;
                                let uc = s.seq_to_unseq[usize::from(s.mtfa[s.mtfbase[0] as usize])];
                                s.unzftab[usize::from(uc)] += v.es;

                                // Differs from libbzip2, without a
                                // difference to see: libbzip2 writes the
                                // run a byte at a time and fails at the
                                // first one past the block's end; the port
                                // checks first and writes it whole. What
                                // was written is never read after the
                                // error, which every later call returns.
                                if v.nblock + v.es > v.nblock_max {
                                    break 'save BZ_DATA_ERROR;
                                }
                                let end = (v.nblock + v.es) as usize;
                                if s.small_decompress {
                                    s.ll16.resize(end, u16::from(uc));
                                } else {
                                    s.tt.resize(end, u32::from(uc));
                                }
                                v.nblock += v.es;
                                v.es = 0;
                            }
                            _ => {
                                v.next_sym = get_mtf_val!('save, BZ_X_MTF_5, BZ_X_MTF_6, resume);
                            }
                        }

                        if v.next_sym == v.eob {
                            break;
                        }

                        if v.next_sym == BZ_RUNA || v.next_sym == BZ_RUNB {
                            v.es = -1;
                            v.n = 1;
                            // The first step of the run: N is 1, below the
                            // bound.
                            if v.next_sym == BZ_RUNA {
                                v.es += v.n;
                            } else {
                                v.es += 2 * v.n;
                            }
                            v.n *= 2;
                            site = BZ_X_MTF_3;
                            continue;
                        }

                        if v.nblock >= v.nblock_max {
                            break 'save BZ_DATA_ERROR;
                        }

                        // uc = MTF ( nextSym-1 )
                        let uc;
                        let mut nn = (v.next_sym - 1) as u32;
                        if nn < MTFL_SIZE as u32 {
                            // Avoid general-case expense.
                            let pp = s.mtfbase[0] as usize;
                            uc = s.mtfa[pp + nn as usize];
                            while nn > 3 {
                                let z = pp + nn as usize;
                                s.mtfa[z] = s.mtfa[z - 1];
                                s.mtfa[z - 1] = s.mtfa[z - 2];
                                s.mtfa[z - 2] = s.mtfa[z - 3];
                                s.mtfa[z - 3] = s.mtfa[z - 4];
                                nn -= 4;
                            }
                            while nn > 0 {
                                s.mtfa[pp + nn as usize] = s.mtfa[pp + nn as usize - 1];
                                nn -= 1;
                            }
                            s.mtfa[pp] = uc;
                        } else {
                            // General case.
                            let mut lno = (nn / MTFL_SIZE as u32) as usize;
                            let off = (nn % MTFL_SIZE as u32) as i32;
                            let mut pp = s.mtfbase[lno] + off;
                            uc = s.mtfa[pp as usize];
                            while pp > s.mtfbase[lno] {
                                s.mtfa[pp as usize] = s.mtfa[pp as usize - 1];
                                pp -= 1;
                            }
                            s.mtfbase[lno] += 1;
                            while lno > 0 {
                                s.mtfbase[lno] -= 1;
                                s.mtfa[s.mtfbase[lno] as usize] =
                                    s.mtfa[(s.mtfbase[lno - 1] + MTFL_SIZE - 1) as usize];
                                lno -= 1;
                            }
                            s.mtfbase[0] -= 1;
                            s.mtfa[s.mtfbase[0] as usize] = uc;
                            if s.mtfbase[0] == 0 {
                                let mut kk = MTFA_SIZE - 1;
                                for ii in (0..256 / MTFL_SIZE).rev() {
                                    for jj in (0..MTFL_SIZE).rev() {
                                        s.mtfa[kk as usize] =
                                            s.mtfa[(s.mtfbase[ii as usize] + jj) as usize];
                                        kk -= 1;
                                    }
                                    s.mtfbase[ii as usize] = kk + 1;
                                }
                            }
                        }

                        let byte = s.seq_to_unseq[usize::from(uc)];
                        s.unzftab[usize::from(byte)] += 1;
                        if s.small_decompress {
                            s.ll16.push(u16::from(byte));
                        } else {
                            s.tt.push(u32::from(byte));
                        }
                        v.nblock += 1;
                        site = BZ_X_MTF_5;
                    }

                    // Now we know what nblock is, we can do a better sanity
                    // check on s->origPtr.
                    if s.orig_ptr < 0 || s.orig_ptr >= v.nblock {
                        break 'save BZ_DATA_ERROR;
                    }

                    // Set up cftab to facilitate generation of T^(-1).
                    // Check: unzftab entries in range.
                    for i in 0..256 {
                        if s.unzftab[i] < 0 || s.unzftab[i] > v.nblock {
                            break 'save BZ_DATA_ERROR;
                        }
                    }
                    // Actually generate cftab.
                    s.cftab[0] = 0;
                    for i in 1..=256 {
                        s.cftab[i] = s.unzftab[i - 1];
                    }
                    for i in 1..=256 {
                        s.cftab[i] += s.cftab[i - 1];
                    }
                    // Check: cftab entries in range.
                    for i in 0..=256 {
                        if s.cftab[i] < 0 || s.cftab[i] > v.nblock {
                            // s->cftab[i] can legitimately be == nblock.
                            break 'save BZ_DATA_ERROR;
                        }
                    }
                    // Check: cftab entries non-descending.
                    for i in 1..=256 {
                        if s.cftab[i - 1] > s.cftab[i] {
                            break 'save BZ_DATA_ERROR;
                        }
                    }

                    s.state_out_len = 0;
                    s.state_out_ch = 0;
                    s.calculated_block_crc = CRC_INIT;
                    s.state = BZ_X_OUTPUT;

                    let limit = 100000 * s.block_size_100k as u32;
                    let nblock = v.nblock as usize;
                    if s.small_decompress {
                        // Make a copy of cftab, used in generation of T.
                        s.cftab_copy = s.cftab;
                        s.ll4.clear();
                        s.ll4.resize((nblock + 1) >> 1, 0);

                        // Compute the T vector.
                        for i in 0..nblock {
                            let uc = s.ll16[i] as u8 as usize;
                            let n = s.cftab_copy[uc] as u32;
                            s.set_ll(i, n);
                            s.cftab_copy[uc] += 1;
                        }

                        // Compute T^(-1) by pointer reversal on T.
                        let mut i = s.orig_ptr as usize;
                        let mut j = s.get_ll(i) as usize;
                        loop {
                            let tmp = s.get_ll(j) as usize;
                            s.set_ll(j, i as u32);
                            i = j;
                            j = tmp;
                            if i == s.orig_ptr as usize {
                                break;
                            }
                        }
                        v.i = i as i32;
                        v.j = j as i32;

                        s.t_pos = s.orig_ptr as u32;
                        s.nblock_used = 0;
                        // BZ_GET_SMALL: tPos is origPtr, below nblock.
                        if s.t_pos >= limit {
                            break 'save BZ_DATA_ERROR;
                        }
                        s.k0 = index_into_f(s.t_pos as i32, &s.cftab) as u8;
                        s.t_pos = s.get_ll(s.t_pos as usize);
                        s.nblock_used += 1;
                        if s.block_randomised {
                            s.rand.init();
                            s.k0 ^= s.rand.update_mask();
                        }
                    } else {
                        // Compute the T^(-1) vector.
                        for i in 0..nblock {
                            let uc = (s.tt[i] & 0xff) as usize;
                            s.tt[s.cftab[uc] as usize] |= (i as u32) << 8;
                            s.cftab[uc] += 1;
                        }
                        v.i = v.nblock;

                        s.t_pos = s.tt[s.orig_ptr as usize] >> 8;
                        s.nblock_used = 0;
                        // BZ_GET_FAST returns True from BZ2_decompress here
                        // when tPos is past the block, which it never is:
                        // every entry of tt points into the block. The
                        // caller would then fail with BZ_DATA_ERROR.
                        if s.t_pos >= limit {
                            break 'save BZ_DATA_ERROR;
                        }
                        s.t_pos = s.tt[s.t_pos as usize];
                        s.k0 = (s.t_pos & 0xff) as u8;
                        s.t_pos >>= 8;
                        s.nblock_used += 1;
                        if s.block_randomised {
                            s.rand.init();
                            s.k0 ^= s.rand.update_mask();
                        }
                    }

                    break 'save BZ_OK;
                }
                BZ_X_ENDHDR_2 => {
                    if get_uchar!('save, BZ_X_ENDHDR_2) != 0x72 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_ENDHDR_3;
                }
                BZ_X_ENDHDR_3 => {
                    if get_uchar!('save, BZ_X_ENDHDR_3) != 0x45 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_ENDHDR_4;
                }
                BZ_X_ENDHDR_4 => {
                    if get_uchar!('save, BZ_X_ENDHDR_4) != 0x38 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_ENDHDR_5;
                }
                BZ_X_ENDHDR_5 => {
                    if get_uchar!('save, BZ_X_ENDHDR_5) != 0x50 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.state = BZ_X_ENDHDR_6;
                }
                BZ_X_ENDHDR_6 => {
                    if get_uchar!('save, BZ_X_ENDHDR_6) != 0x90 {
                        break 'save BZ_DATA_ERROR;
                    }
                    s.stored_combined_crc = 0;
                    s.state = BZ_X_CCRC_1;
                }
                BZ_X_CCRC_1 | BZ_X_CCRC_2 | BZ_X_CCRC_3 | BZ_X_CCRC_4 => {
                    let state = s.state;
                    let uc = get_uchar!('save, state);
                    s.stored_combined_crc = (s.stored_combined_crc << 8) | u32::from(uc);
                    if state != BZ_X_CCRC_4 {
                        s.state = state + 1;
                        continue;
                    }
                    s.state = BZ_X_IDLE;
                    break 'save BZ_STREAM_END;
                }
                // AssertH(False, 4001): every state is above.
                _ => break 'save BZ_DATA_ERROR,
            }
        }
    };

    s.save = v;
    ret_val
}
