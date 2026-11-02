//! The branch converters' decoders: `Bra.c`, `Bra86.c` and `BraIA64.c`.
//!
//! Each converts the relative addresses of some branch instructions in
//! `data`, at the program counter `pc` for `data[0]`, and returns how many
//! bytes it processed: a caller with more data calls it again from there,
//! with `pc` moved as far.
//!
//! Differs from the LZMA SDK: positions are indices, so the program counter
//! of `data[i]` is `pc + i` (the SDK adds the pointer's value instead, with
//! the same result); and the loops are written once, for every machine,
//! where the SDK picks loads for the machine it is built for.

fn get16(data: &[u8], at: usize) -> u32 {
    u32::from(u16::from_le_bytes([data[at], data[at + 1]]))
}

fn set16(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
}

fn get32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn set32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn set_be32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

/// `z7_BranchConv_ARM64_Dec`.
pub(crate) fn arm64_dec(data: &mut [u8], pc: u32) -> usize {
    let flag: u32 = 1 << (24 - 4);
    let mask: u32 = (1 << 24) - (flag << 1);
    let lim = data.len() & !3;
    let mut p = 0;
    while p < lim {
        let mut v = get32(data, p);
        // The program counter of the instruction.
        let at = pc.wrapping_add(p as u32);
        p += 4;
        if v.wrapping_sub(0x9400_0000) & 0xfc00_0000 == 0 {
            let c = at >> 2;
            v = v.wrapping_sub(c);
            v &= 0x03ff_ffff;
            v |= 0x9400_0000;
            set32(data, p - 4, v);
            continue;
        }
        v = v.wrapping_sub(0x9000_0000);
        if v & 0x9f00_0000 == 0 {
            v = v.wrapping_add(flag);
            if v & mask != 0 {
                continue;
            }
            let mut z = (v & 0xffff_ffe0) | (v >> 26);
            let c = (at >> (12 - 3)) & !7u32;
            z = z.wrapping_sub(c);
            v &= 0x1f;
            v |= 0x9000_0000;
            v |= z << 26;
            v |= 0x00ff_ffe0 & (z & ((flag << 1) - 1)).wrapping_sub(flag);
            set32(data, p - 4, v);
        }
    }
    lim
}

/// `z7_BranchConv_ARM_Dec`.
pub(crate) fn arm_dec(data: &mut [u8], pc: u32) -> usize {
    let lim = data.len() & !3;
    let mut p = 0;
    while p < lim {
        p += 4;
        if data[p - 1] != 0xeb {
            continue;
        }
        let mut v = get32(data, p - 4);
        // The offset is from 2 instructions past the branch.
        let c = pc.wrapping_add((p - 4) as u32 + 8) >> 2;
        v = v.wrapping_sub(c);
        v &= 0x00ff_ffff;
        v |= 0xeb00_0000;
        set32(data, p - 4, v);
    }
    lim
}

/// `z7_BranchConv_PPC_Dec`.
pub(crate) fn ppc_dec(data: &mut [u8], pc: u32) -> usize {
    let lim = data.len() & !3;
    let mut p = 0;
    while p < lim {
        let mut v = get_be32(data, p);
        p += 4;
        if v.wrapping_sub(0x4800_0001) & 0xfc00_0003 != 0 {
            continue;
        }
        let c = pc.wrapping_add((p - 4) as u32);
        v = v.wrapping_sub(c);
        v &= 0x03ff_ffff;
        v |= 0x4800_0000;
        set_be32(data, p - 4, v);
    }
    lim
}

/// `z7_BranchConv_SPARC_Dec`.
pub(crate) fn sparc_dec(data: &mut [u8], pc: u32) -> usize {
    let flag: u32 = 1 << 22;
    let lim = data.len() & !3;
    let mut p = 0;
    while p < lim {
        let mut v = get_be32(data, p);
        p += 4;
        v = v.wrapping_add(5 << 29);
        v ^= 7 << 29;
        v = v.wrapping_add(flag);
        if v & 0u32.wrapping_sub(flag << 1) != 0 {
            continue;
        }
        v <<= 2;
        let c = pc.wrapping_add((p - 4) as u32);
        v = v.wrapping_sub(c);
        v &= (flag << 3) - 1;
        v = v.wrapping_sub(flag << 2);
        v >>= 2;
        v |= 1 << 30;
        set_be32(data, p - 4, v);
    }
    lim
}

/// `z7_BranchConv_ARMT_Dec`.
pub(crate) fn armt_dec(data: &mut [u8], pc: u32) -> usize {
    let size = data.len() & !1;
    if size <= 2 {
        return 0;
    }
    let lim = size - 2;
    let mut p = 0;
    // Each step looks at the instruction at p, of 2 bytes, and the one
    // after it: together a BL whose two halves are 11110 and 11111.
    while p < lim {
        let b1 = u32::from(data[p + 1]);
        let b3 = u32::from(data[p + 3]);
        p += 2;
        if b3 & (b1 ^ 8) < 0xf8 {
            continue;
        }
        let mut v = (get16(data, p - 2) << 11) | (get16(data, p) & 0x7FF);
        p += 2;
        // The offset is from 4 bytes past the instruction.
        let c = pc.wrapping_add(p as u32) >> 1;
        v = v.wrapping_sub(c);
        set16(data, p - 4, ((v >> 11) & 0x7ff) | 0xf000);
        set16(data, p - 2, v | 0xf800);
    }
    p
}

/// `z7_BranchConv_IA64_Dec`.
pub(crate) fn ia64_dec(data: &mut [u8], pc: u32) -> usize {
    let lim = data.len() & !15;
    let mut pc = pc.wrapping_sub(1 << 4) >> (4 - 1);
    let mut p = 0;
    while p < lim {
        let m0 = (0x334b_0000u32 >> (data[p] & 0x1e)) & 3;
        p += 16;
        pc = pc.wrapping_add(1 << 1);
        if m0 == 0 {
            continue;
        }
        let mut m = m0;
        let mut q = p + (m as usize) * 5 - 20;
        loop {
            let t = get16(data, q);
            let mut z = get32(data, q + 1) >> m;
            q += 5;
            if (t >> m) & (0x70 << 1) == 0
                && z.wrapping_sub(0x500_0000 << 1) & (0xf00_0000 << 1) == 0
            {
                let mut v = ((0x8f_ffffu32 << 1) | 1) & z;
                z ^= v;
                pc |= !((0x1f_ffffu32 << 1) | 1);
                v = v.wrapping_sub(pc);
                v &= !(0x60_0000u32 << 1);
                v = v.wrapping_add(0x70_0000 << 1);
                v &= (0x8f_ffff << 1) | 1;
                z |= v;
                z <<= m;
                set32(data, q + 1 - 5, z);
            }
            m = (m + 1) & 3;
            if m == 0 {
                break;
            }
        }
    }
    lim
}

/// `z7_BranchConv_RISCV_Dec`.
pub(crate) fn riscv_dec(data: &mut [u8], pc: u32) -> usize {
    const INSTR_SIZE: usize = 2;
    const STEP_1: usize = 4 + INSTR_SIZE;
    const STEP_2: usize = 4;
    const REG_VAL: u32 = 2 << 7;
    const CMD_VAL: u32 = 3;
    const DELTA_7F: u32 = 0x7f;
    let check_1 = |v: u32, b: u32| (b.wrapping_sub(CMD_VAL) ^ (v << 8)) & (0xf8000 + CMD_VAL) == 0;
    let check_2 =
        |v: u32, r: u32| (v.wrapping_sub((CMD_VAL << 12) | REG_VAL | 8) << 18) < (r & 0x1d);

    let size = data.len() & !(INSTR_SIZE - 1);
    if size <= 6 {
        return 0;
    }
    let lim = size - 6;
    let mut p = 0;
    loop {
        // The scan for JAL and AUIPC.
        let mut a;
        loop {
            if p >= lim {
                return p;
            }
            a = (get16(data, p) ^ 0x10).wrapping_add(1);
            if a & 0x77 == 0 {
                break;
            }
            a = (get16(data, p + INSTR_SIZE) ^ 0x10).wrapping_add(1);
            p += INSTR_SIZE * 2;
            if a & 0x77 == 0 {
                p -= INSTR_SIZE;
                if p >= lim {
                    return p;
                }
                break;
            }
        }
        let at = pc.wrapping_add(p as u32);
        if a & 8 == 0 {
            // JAL.
            a = a.wrapping_sub(0x100 - DELTA_7F);
            if a & 0xd80 != 0 {
                p += INSTR_SIZE;
                continue;
            }
            let a_old = a.wrapping_add(0xef - DELTA_7F) & 0xfff;
            let mut v =
                (u32::from(data[p + 3]) << 1) | (u32::from(data[p + 2]) << 9) | ((a & 0xf000) << 5);
            v = v.wrapping_sub(at);
            a = a_old
                | ((v << 11) & (1u32 << 31))
                | ((v << 20) & (0x3ff << 21))
                | ((v << 9) & (1 << 20))
                | (v & (0xff << 12));
            set32(data, p, a);
            p += 4;
            continue;
        }
        // AUIPC.
        let v = a;
        a = get32(data, p);
        if v & 0xe80 == 0 {
            // x0/x2.
            let r = a >> 27;
            if check_2(v, r) {
                let mut b = get_be32(data, p + 4);
                let v = a >> 12;
                b = b.wrapping_sub(at);
                a = (r << 7) + 0x17;
                a = a.wrapping_add(b.wrapping_add(0x800) & 0xffff_f000);
                let v = v | (b << 20);
                set32(data, p, a);
                set32(data, p + 4, v);
                p += 8;
            } else {
                p += STEP_2;
            }
        } else {
            let b = get32(data, p + 4);
            if !check_1(v, b) {
                p += STEP_1;
            } else {
                let v = (a & 0xffff_f000) | (b >> 20);
                let a = (b << 12) | (0x17 + REG_VAL);
                set32(data, p, a);
                set32(data, p + 4, v);
                p += 8;
            }
        }
    }
}

/// `Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL`.
pub(crate) const X86_STATE_INIT: u32 = 0;

/// `BR86_NEED_CONV_FOR_MS_BYTE`.
fn need_conv_for_ms_byte(b: u32) -> bool {
    (b.wrapping_add(1) & 0xfe) == 0
}

/// `z7_BranchConvSt_X86_Dec`: E8 (CALL) and E9 (JMP), their offsets made
/// relative again. `state` keeps, across calls, which of the last bytes
/// were E8 or E9.
pub(crate) fn x86_dec(data: &mut [u8], pc: u32, state: &mut u32) -> usize {
    let size = data.len();
    if size < 5 {
        return 0;
    }
    let lim = size - 4;
    let mut mask = *state;
    // The offset is from the next instruction, 4 bytes after the offset's
    // position.
    let pc_at = |p: usize| pc.wrapping_add(4).wrapping_add(p as u32);
    let is_bcj = |b: u8| b & 0xfe == 0xe8;
    let mut p = 0usize;

    #[derive(Clone, Copy)]
    enum Go {
        Start,
        MainLoop,
        // The byte before p is E8 or E9, found after Start's scan of n
        // bytes (0 to 2), with the mask as it then is.
        M,
        // The byte before p is E8 or E9, found by the main loop.
        A3,
        Fin,
        FinP,
    }
    let mut go = Go::Start;
    loop {
        match go {
            Go::Start => {
                if p >= lim {
                    go = Go::Fin;
                    continue;
                }
                let b = [data[p], data[p + 1], data[p + 2], data[p + 3]];
                p += 4;
                if is_bcj(b[0]) {
                    p -= 3;
                    go = Go::M;
                    continue;
                }
                mask >>= 1;
                if is_bcj(b[1]) {
                    p -= 2;
                    go = Go::M;
                    continue;
                }
                mask >>= 1;
                if is_bcj(b[2]) {
                    p -= 1;
                    go = Go::M;
                    continue;
                }
                mask = 0;
                if is_bcj(b[3]) {
                    go = Go::A3;
                    continue;
                }
                go = Go::MainLoop;
            }
            Go::M => {
                if mask == 0 {
                    go = Go::A3;
                    continue;
                }
                if p > lim {
                    go = Go::FinP;
                    continue;
                }
                if mask > 4 || mask == 3 {
                    mask >>= 1;
                    // continue: mask |= 4, then start.
                    mask |= 4;
                    go = Go::Start;
                    continue;
                }
                mask >>= 1;
                if need_conv_for_ms_byte(u32::from(data[p + mask as usize])) {
                    mask |= 4;
                    go = Go::Start;
                    continue;
                }
                let mut v = get32(data, p);
                v = v.wrapping_add(1 << 24);
                if v & 0xfe00_0000 != 0 {
                    mask |= 4;
                    go = Go::Start;
                    continue;
                }
                let c = pc_at(p);
                v = v.wrapping_sub(c);
                mask <<= 3;
                if need_conv_for_ms_byte(v >> mask) {
                    v ^= (0x100u32 << mask).wrapping_sub(1);
                    v = v.wrapping_sub(c);
                }
                mask = 0;
                v &= (1 << 25) - 1;
                v = v.wrapping_sub(1 << 24);
                set32(data, p, v);
                p += 4;
                go = Go::MainLoop;
            }
            Go::MainLoop => {
                if p >= lim {
                    go = Go::Fin;
                    continue;
                }
                loop {
                    let b = [data[p], data[p + 1], data[p + 2], data[p + 3]];
                    p += 4;
                    if is_bcj(b[0]) {
                        p -= 3;
                        break;
                    }
                    if is_bcj(b[1]) {
                        p -= 2;
                        break;
                    }
                    if is_bcj(b[2]) {
                        p -= 1;
                        break;
                    }
                    if is_bcj(b[3]) {
                        break;
                    }
                    if p >= lim {
                        break;
                    }
                }
                // Found one, or at the end: A3 tells.
                if p >= lim && !is_bcj(data[p - 1]) {
                    go = Go::Fin;
                    continue;
                }
                go = Go::A3;
            }
            Go::A3 => {
                if p > lim {
                    go = Go::FinP;
                    continue;
                }
                let mut v = get32(data, p);
                v = v.wrapping_add(1 << 24);
                if v & 0xfe00_0000 != 0 {
                    // continue: the loop's step sets mask |= 4.
                    mask |= 4;
                    go = Go::Start;
                    continue;
                }
                let c = pc_at(p);
                v = v.wrapping_sub(c);
                v &= (1 << 25) - 1;
                v = v.wrapping_sub(1 << 24);
                set32(data, p, v);
                p += 4;
                go = Go::MainLoop;
            }
            Go::FinP => {
                p -= 1;
                go = Go::Fin;
            }
            Go::Fin => {
                *state = mask;
                return p;
            }
        }
    }
}
