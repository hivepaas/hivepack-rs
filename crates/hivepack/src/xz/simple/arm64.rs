//! BCJ for ARM64: port of `simple/arm64.c`.

/// `arm64_code`.
///
/// Differs from liblzma, without a difference to see: the conversions are
/// functions that are not inlined. liblzma keeps Clang from vectorizing
/// the loop, which makes it bigger and slower; Rust cannot ask that of a
/// loop, and LLVM vectorizes it too, unless the loop makes calls.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    // The instructions, four bytes each: liblzma's loop over i, in steps of
    // four up to size & ~3.
    let (instructions, _) = buffer.as_chunks_mut::<4>();

    for (i, bytes) in instructions.iter_mut().enumerate() {
        let pc = now_pos.wrapping_add((i * 4) as u32);
        let instr = u32::from_le_bytes(*bytes);

        if (instr >> 26) == 0x25 {
            *bytes = convert_bl(instr, pc, is_encoder).to_le_bytes();
        } else if (instr & 0x9F00_0000) == 0x9000_0000 {
            // ADRP instruction: only values in the range +/-512 MiB are
            // converted.
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);

            // With the addition only one branch is needed to check the
            // +/- range.
            if (src.wrapping_add(0x0002_0000) & 0x001C_0000) == 0 {
                *bytes = convert_adrp(instr, src, pc, is_encoder).to_le_bytes();
            }
        }
    }

    instructions.len() * 4
}

/// A BL instruction converted: the full 26-bit immediate. The range is
/// +/-128 MiB.
#[inline(never)]
fn convert_bl(src: u32, mut pc: u32, is_encoder: bool) -> u32 {
    let mut instr = 0x9400_0000;

    pc >>= 2;
    if !is_encoder {
        pc = pc.wrapping_neg();
    }

    instr |= src.wrapping_add(pc) & 0x03FF_FFFF;
    instr
}

/// An ADRP instruction converted, whose address `src` is in range.
#[inline(never)]
fn convert_adrp(mut instr: u32, src: u32, mut pc: u32, is_encoder: bool) -> u32 {
    instr &= 0x9000_001F;

    pc >>= 12;
    if !is_encoder {
        pc = pc.wrapping_neg();
    }

    let dest = src.wrapping_add(pc);
    instr |= (dest & 3) << 29;
    instr |= (dest & 0x0003_FFFC) << 3;
    instr |= 0u32.wrapping_sub(dest & 0x0002_0000) & 0x00E0_0000;
    instr
}

/// `lzma_bcj_arm64_encode`: converts `buf`, whose first byte is at
/// `start_offset` in the file (rounded down to a multiple of four), in
/// place; the number of bytes converted.
pub fn bcj_arm64_encode(start_offset: u32, buf: &mut [u8]) -> usize {
    code(start_offset & !3, true, buf)
}

/// `lzma_bcj_arm64_decode`: the inverse of [`bcj_arm64_encode`].
pub fn bcj_arm64_decode(start_offset: u32, buf: &mut [u8]) -> usize {
    code(start_offset & !3, false, buf)
}
