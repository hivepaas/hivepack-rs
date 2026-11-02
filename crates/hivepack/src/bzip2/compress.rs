//! Compression machinery, not including block sorting: port of
//! `compress.c`, with the compression-side structure of
//! `bzlib_private.h`.

use crate::bzip2::blocksort::block_sort;
use crate::bzip2::huffman::{assign_codes, make_code_lengths};
use crate::bzip2::private::*;

/// `EState`: the compressor.
///
/// Differs from libbzip2: libbzip2 keeps the block, its sorted order, the
/// MTF values and the compressed bits in two arrays, `arr1` and `arr2`,
/// read as several types at once (`ptr` and `mtfv` share `arr1`; `block`,
/// `quadrant`, the fallback sort's `eclass` and `zbits` share `arr2`).
/// The port gives each its own vector, with the capacity reserved when the
/// compressor is made, as libbzip2 allocates its arrays then, and each set
/// to the length the current block needs. What libbzip2 reads of them is
/// what the block wrote, so the output is the same; the memory touched is
/// about 9 bytes for each byte of the block, against libbzip2's 8.
pub(crate) struct EState {
    /// Mode this stream is in (`BZ_M_*`), and whether inputting or
    /// outputting data (`BZ_S_*`).
    pub(crate) mode: i32,
    pub(crate) state: i32,

    /// Remembers avail_in when flush/finish requested.
    pub(crate) avail_in_expect: usize,

    // For doing the block sorting.
    pub(crate) ptr: Vec<u32>,
    pub(crate) block: Vec<u8>,
    pub(crate) quadrant: Vec<u16>,
    pub(crate) eclass: Vec<u32>,
    pub(crate) ftab: Vec<u32>,
    pub(crate) orig_ptr: i32,
    pub(crate) mtfv: Vec<u16>,
    /// The compressed block; its length is libbzip2's `numZ`.
    pub(crate) zbits: Vec<u8>,

    /// For deciding when to use the fallback sorting algorithm.
    pub(crate) work_factor: i32,

    // Run-length-encoding of the input.
    pub(crate) state_in_ch: u32,
    pub(crate) state_in_len: i32,

    // Input and output limits and current posns.
    pub(crate) nblock: i32,
    pub(crate) nblock_max: i32,
    pub(crate) state_out_pos: usize,

    // Map of bytes used in block.
    pub(crate) n_in_use: i32,
    pub(crate) in_use: [bool; 256],
    pub(crate) unseq_to_seq: [u8; 256],

    // The buffer for bit stream creation.
    pub(crate) bs_buff: u32,
    pub(crate) bs_live: i32,

    // Block and combined CRCs.
    pub(crate) block_crc: u32,
    pub(crate) combined_crc: u32,

    // Misc administratium.
    pub(crate) block_no: i32,
    pub(crate) block_size_100k: i32,

    // Stuff for coding the MTF values.
    pub(crate) n_mtf: i32,
    pub(crate) mtf_freq: [i32; BZ_MAX_ALPHA_SIZE],
    pub(crate) selector: [u8; BZ_MAX_SELECTORS],
    pub(crate) selector_mtf: [u8; BZ_MAX_SELECTORS],

    pub(crate) len: [[u8; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    pub(crate) code: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    pub(crate) rfreq: [[i32; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    /// Second dimension: only 3 needed; 4 makes index calculations faster.
    pub(crate) len_pack: [[u32; 4]; BZ_MAX_ALPHA_SIZE],

    // `total_in_lo32` and `total_in_hi32` of the `bz_stream`, and the same
    // for the output.
    pub(crate) total_in: u64,
    pub(crate) total_out: u64,
}

impl EState {
    /// `BZ2_bsInitWrite`.
    pub(crate) fn bs_init_write(&mut self) {
        self.bs_live = 0;
        self.bs_buff = 0;
    }

    /// `bsFinishWrite`.
    fn bs_finish_write(&mut self) {
        while self.bs_live > 0 {
            self.zbits.push((self.bs_buff >> 24) as u8);
            self.bs_buff <<= 8;
            self.bs_live -= 8;
        }
    }

    /// `bsW`, with `bsNEEDW`: `n` bits of `v`.
    #[inline(always)]
    fn bs_w(&mut self, n: i32, v: u32) {
        while self.bs_live >= 8 {
            self.zbits.push((self.bs_buff >> 24) as u8);
            self.bs_buff <<= 8;
            self.bs_live -= 8;
        }
        self.bs_buff |= v << (32 - self.bs_live - n);
        self.bs_live += n;
    }

    /// `bsPutUInt32`.
    fn bs_put_u_int32(&mut self, u: u32) {
        self.bs_w(8, (u >> 24) & 0xff);
        self.bs_w(8, (u >> 16) & 0xff);
        self.bs_w(8, (u >> 8) & 0xff);
        self.bs_w(8, u & 0xff);
    }

    /// `bsPutUChar`.
    fn bs_put_u_char(&mut self, c: u8) {
        self.bs_w(8, u32::from(c));
    }

    /// `makeMaps_e`.
    fn make_maps_e(&mut self) {
        self.n_in_use = 0;
        for i in 0..256 {
            if self.in_use[i] {
                self.unseq_to_seq[i] = self.n_in_use as u8;
                self.n_in_use += 1;
            }
        }
    }

    /// `generateMTFValues`: the block, in its sorted order, coded as MTF
    /// values with runs of zeros as RUNA and RUNB, into `mtfv`.
    fn generate_mtf_values(&mut self) {
        let mut yy = [0u8; 256];

        // After sorting, ptr[0 .. nblock-1] holds sorted order and
        // block[0 .. nblock-1] holds the original block data. The MTF
        // values go to mtfv.
        self.make_maps_e();
        let eob = self.n_in_use + 1;

        for i in 0..=eob as usize {
            self.mtf_freq[i] = 0;
        }

        self.mtfv.clear();
        let mut z_pend: i32 = 0;
        for i in 0..self.n_in_use as usize {
            yy[i] = i as u8;
        }

        // The run of zPend zeros, as RUNA and RUNB.
        fn put_run(s: &mut EState, mut z_pend: i32) {
            z_pend -= 1;
            loop {
                if z_pend & 1 != 0 {
                    s.mtfv.push(BZ_RUNB as u16);
                    s.mtf_freq[BZ_RUNB as usize] += 1;
                } else {
                    s.mtfv.push(BZ_RUNA as u16);
                    s.mtf_freq[BZ_RUNA as usize] += 1;
                }
                if z_pend < 2 {
                    break;
                }
                z_pend = (z_pend - 2) / 2;
            }
        }

        let nblock = self.nblock;
        for i in 0..nblock as usize {
            let mut j = self.ptr[i] as i32 - 1;
            if j < 0 {
                j += nblock;
            }
            let ll_i = self.unseq_to_seq[usize::from(self.block[j as usize])];

            if yy[0] == ll_i {
                z_pend += 1;
            } else {
                if z_pend > 0 {
                    put_run(self, z_pend);
                    z_pend = 0;
                }
                let mut rtmp = yy[1];
                yy[1] = yy[0];
                let mut ryy_j = 1;
                let rll_i = ll_i;
                while rll_i != rtmp {
                    ryy_j += 1;
                    core::mem::swap(&mut rtmp, &mut yy[ryy_j]);
                }
                yy[0] = rtmp;
                let j = ryy_j;
                self.mtfv.push((j + 1) as u16);
                self.mtf_freq[j + 1] += 1;
            }
        }

        if z_pend > 0 {
            put_run(self, z_pend);
        }

        self.mtfv.push(eob as u16);
        self.mtf_freq[eob as usize] += 1;

        self.n_mtf = self.mtfv.len() as i32;
    }

    /// `sendMTFValues`: the coding tables, chosen for the MTF values, and
    /// the values coded with them.
    fn send_mtf_values(&mut self) {
        const BZ_LESSER_ICOST: u8 = 0;
        const BZ_GREATER_ICOST: u8 = 15;

        let mut cost = [0u16; BZ_N_GROUPS];
        let mut fave = [0i32; BZ_N_GROUPS];

        let alpha_size = (self.n_in_use + 2) as usize;
        for t in 0..BZ_N_GROUPS {
            for v in 0..alpha_size {
                self.len[t][v] = BZ_GREATER_ICOST;
            }
        }

        // Decide how many coding tables to use.
        // AssertH(s->nMTF > 0, 3001): there is always the EOB.
        let n_groups: usize = if self.n_mtf < 200 {
            2
        } else if self.n_mtf < 600 {
            3
        } else if self.n_mtf < 1200 {
            4
        } else if self.n_mtf < 2400 {
            5
        } else {
            6
        };

        // Generate an initial set of coding tables.
        {
            let mut n_part = n_groups as i32;
            let mut rem_f = self.n_mtf;
            let mut gs: i32 = 0;
            while n_part > 0 {
                let t_freq = rem_f / n_part;
                let mut ge = gs - 1;
                let mut a_freq = 0;
                while a_freq < t_freq && ge < alpha_size as i32 - 1 {
                    ge += 1;
                    a_freq += self.mtf_freq[ge as usize];
                }

                if ge > gs
                    && n_part != n_groups as i32
                    && n_part != 1
                    && ((n_groups as i32 - n_part) % 2 == 1)
                {
                    a_freq -= self.mtf_freq[ge as usize];
                    ge -= 1;
                }

                for v in 0..alpha_size {
                    self.len[n_part as usize - 1][v] = if v as i32 >= gs && v as i32 <= ge {
                        BZ_LESSER_ICOST
                    } else {
                        BZ_GREATER_ICOST
                    };
                }

                n_part -= 1;
                gs = ge + 1;
                rem_f -= a_freq;
            }
        }

        // Iterate up to BZ_N_ITERS times to improve the tables.
        let n_mtf = self.n_mtf as usize;
        let mut n_selectors = 0;
        for _iter in 0..BZ_N_ITERS {
            for f in fave.iter_mut().take(n_groups) {
                *f = 0;
            }

            for t in 0..n_groups {
                for v in 0..alpha_size {
                    self.rfreq[t][v] = 0;
                }
            }

            // Set up an auxiliary length table which is used to fast-track
            // the common case (nGroups == 6).
            if n_groups == 6 {
                for v in 0..alpha_size {
                    self.len_pack[v][0] =
                        (u32::from(self.len[1][v]) << 16) | u32::from(self.len[0][v]);
                    self.len_pack[v][1] =
                        (u32::from(self.len[3][v]) << 16) | u32::from(self.len[2][v]);
                    self.len_pack[v][2] =
                        (u32::from(self.len[5][v]) << 16) | u32::from(self.len[4][v]);
                }
            }

            n_selectors = 0;
            let mut gs = 0;
            loop {
                // Set group start & end marks.
                if gs >= n_mtf {
                    break;
                }
                let mut ge = gs + BZ_G_SIZE as usize - 1;
                if ge >= n_mtf {
                    ge = n_mtf - 1;
                }

                // Calculate the cost of this group as coded by each of the
                // coding tables.
                for c in cost.iter_mut().take(n_groups) {
                    *c = 0;
                }

                let mtfv = &self.mtfv[gs..=ge];
                if n_groups == 6 && 50 == ge - gs + 1 {
                    // Fast track the common case.
                    let mut cost01: u32 = 0;
                    let mut cost23: u32 = 0;
                    let mut cost45: u32 = 0;
                    for &icv in mtfv {
                        let pack = &self.len_pack[usize::from(icv)];
                        cost01 = cost01.wrapping_add(pack[0]);
                        cost23 = cost23.wrapping_add(pack[1]);
                        cost45 = cost45.wrapping_add(pack[2]);
                    }
                    cost[0] = (cost01 & 0xffff) as u16;
                    cost[1] = (cost01 >> 16) as u16;
                    cost[2] = (cost23 & 0xffff) as u16;
                    cost[3] = (cost23 >> 16) as u16;
                    cost[4] = (cost45 & 0xffff) as u16;
                    cost[5] = (cost45 >> 16) as u16;
                } else {
                    // Slow version which correctly handles all situations.
                    for &icv in mtfv {
                        for t in 0..n_groups {
                            cost[t] =
                                cost[t].wrapping_add(u16::from(self.len[t][usize::from(icv)]));
                        }
                    }
                }

                // Find the coding table which is best for this group, and
                // record its identity in the selector table.
                let mut bc: i32 = 999_999_999;
                let mut bt: i32 = -1;
                for t in 0..n_groups {
                    if i32::from(cost[t]) < bc {
                        bc = i32::from(cost[t]);
                        bt = t as i32;
                    }
                }
                let bt = bt as usize;
                fave[bt] += 1;
                self.selector[n_selectors] = bt as u8;
                n_selectors += 1;

                // Increment the symbol frequencies for the selected table.
                let rfreq = &mut self.rfreq[bt];
                for &icv in &self.mtfv[gs..=ge] {
                    rfreq[usize::from(icv)] += 1;
                }

                gs = ge + 1;
            }

            // Recompute the tables based on the accumulated frequencies.
            // maxLen was changed from 20 to 17 in bzip2-1.0.3. See comment
            // in huffman.c for details.
            for t in 0..n_groups {
                make_code_lengths(&mut self.len[t], &self.rfreq[t], alpha_size as i32, 17);
            }
        }

        // AssertH(nGroups < 8, 3002) and AssertH(nSelectors < 32768 &&
        // nSelectors <= BZ_MAX_SELECTORS, 3003): there are at most 6
        // groups, and a selector for each 50 values of a block of at most
        // 900,000 bytes, with the EOB.

        // Compute MTF values for the selectors.
        {
            let mut pos = [0u8; BZ_N_GROUPS];
            for (i, p) in pos.iter_mut().enumerate().take(n_groups) {
                *p = i as u8;
            }
            for i in 0..n_selectors {
                let ll_i = self.selector[i];
                let mut j = 0;
                let mut tmp = pos[j];
                while ll_i != tmp {
                    j += 1;
                    core::mem::swap(&mut tmp, &mut pos[j]);
                }
                pos[0] = tmp;
                self.selector_mtf[i] = j as u8;
            }
        }

        // Assign actual codes for the tables.
        for t in 0..n_groups {
            let mut min_len = 32;
            let mut max_len = 0;
            for i in 0..alpha_size {
                let l = i32::from(self.len[t][i]);
                if l > max_len {
                    max_len = l;
                }
                if l < min_len {
                    min_len = l;
                }
            }
            // AssertH(!(maxLen > 17), 3004) and AssertH(!(minLen < 1),
            // 3005): BZ2_hbMakeCodeLengths makes codes of 1 to 17 bits.
            assign_codes(
                &mut self.code[t],
                &self.len[t],
                min_len,
                max_len,
                alpha_size as i32,
            );
        }

        // Transmit the mapping table.
        {
            let mut in_use16 = [false; 16];
            for i in 0..16 {
                for j in 0..16 {
                    if self.in_use[i * 16 + j] {
                        in_use16[i] = true;
                    }
                }
            }

            for &used in &in_use16 {
                self.bs_w(1, u32::from(used));
            }

            for i in 0..16 {
                if in_use16[i] {
                    for j in 0..16 {
                        let used = self.in_use[i * 16 + j];
                        self.bs_w(1, u32::from(used));
                    }
                }
            }
        }

        // Now the selectors.
        self.bs_w(3, n_groups as u32);
        self.bs_w(15, n_selectors as u32);
        for i in 0..n_selectors {
            for _ in 0..self.selector_mtf[i] {
                self.bs_w(1, 1);
            }
            self.bs_w(1, 0);
        }

        // Now the coding tables.
        for t in 0..n_groups {
            let mut curr = i32::from(self.len[t][0]);
            self.bs_w(5, curr as u32);
            for i in 0..alpha_size {
                let l = i32::from(self.len[t][i]);
                while curr < l {
                    self.bs_w(2, 2);
                    curr += 1; // 10
                }
                while curr > l {
                    self.bs_w(2, 3);
                    curr -= 1; // 11
                }
                self.bs_w(1, 0);
            }
        }

        // And finally, the block data proper.
        let mut sel_ctr = 0;
        let mut gs = 0;
        loop {
            if gs >= n_mtf {
                break;
            }
            let mut ge = gs + BZ_G_SIZE as usize - 1;
            if ge >= n_mtf {
                ge = n_mtf - 1;
            }
            // AssertH(s->selector[selCtr] < nGroups, 3006): every selector
            // is a group.
            let sel = usize::from(self.selector[sel_ctr]);
            for i in gs..=ge {
                let mtfv_i = usize::from(self.mtfv[i]);
                let (n, v) = (self.len[sel][mtfv_i], self.code[sel][mtfv_i]);
                self.bs_w(i32::from(n), v as u32);
            }

            gs = ge + 1;
            sel_ctr += 1;
        }
        // AssertH(selCtr == nSelectors, 3007): the same groups as above.
    }

    /// `BZ2_compressBlock`: the block sorted and coded into `zbits`, after
    /// the stream's header for the first block and before its trailer for
    /// the last.
    pub(crate) fn compress_block(&mut self, is_last_block: bool) {
        if self.nblock > 0 {
            self.block_crc = !self.block_crc;
            self.combined_crc = self.combined_crc.rotate_left(1);
            self.combined_crc ^= self.block_crc;
            if self.block_no > 1 {
                self.zbits.clear();
            }

            // Differs from libbzip2: no verbosity, so nothing is printed,
            // here or below.
            block_sort(self);
        }

        // If this is the first block, create the stream header.
        if self.block_no == 1 {
            self.bs_init_write();
            self.bs_put_u_char(BZ_HDR_B);
            self.bs_put_u_char(BZ_HDR_Z);
            self.bs_put_u_char(BZ_HDR_H);
            self.bs_put_u_char(BZ_HDR_0 + self.block_size_100k as u8);
        }

        if self.nblock > 0 {
            self.bs_put_u_char(0x31);
            self.bs_put_u_char(0x41);
            self.bs_put_u_char(0x59);
            self.bs_put_u_char(0x26);
            self.bs_put_u_char(0x53);
            self.bs_put_u_char(0x59);

            // Now the block's CRC, so it is in a known place.
            self.bs_put_u_int32(self.block_crc);

            // Now a single bit indicating (non-)randomisation. As of
            // version 0.9.5, we use a better sorting algorithm which makes
            // randomisation unnecessary. So always set the randomised bit
            // to 'no'. Of course, the decoder still needs to be able to
            // handle randomised blocks so as to maintain backwards
            // compatibility with older versions of bzip2.
            self.bs_w(1, 0);

            self.bs_w(24, self.orig_ptr as u32);
            self.generate_mtf_values();
            self.send_mtf_values();
        }

        // If this is the last block, add the stream trailer.
        if is_last_block {
            self.bs_put_u_char(0x17);
            self.bs_put_u_char(0x72);
            self.bs_put_u_char(0x45);
            self.bs_put_u_char(0x38);
            self.bs_put_u_char(0x50);
            self.bs_put_u_char(0x90);
            self.bs_put_u_int32(self.combined_crc);
            self.bs_finish_write();
        }
    }
}
