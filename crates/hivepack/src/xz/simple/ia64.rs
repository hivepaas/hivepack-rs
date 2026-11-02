//! BCJ for IA-64 (Itanium): port of `simple/ia64.c`.

/// `ia64_code`.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    const BRANCH_TABLE: [u32; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4,
        0, 0,
    ];

    let size = buffer.len() & !15;

    let mut i = 0;
    while i < size {
        let instr_template = u32::from(buffer[i] & 0x1F);
        let mask = BRANCH_TABLE[instr_template as usize];

        let mut bit_pos: u32 = 5;
        for slot in 0..3 {
            if (mask >> slot) & 1 != 0 {
                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 0x7;
                let mut instruction: u64 = 0;

                for j in 0..6 {
                    instruction += u64::from(buffer[i + j + byte_pos]) << (8 * j);
                }

                let mut inst_norm = instruction >> bit_res;

                if ((inst_norm >> 37) & 0xF) == 0x5 && ((inst_norm >> 9) & 0x7) == 0
                /* &&  (inst_norm & 0x3F)== 0 */
                {
                    let mut src = ((inst_norm >> 13) & 0xFFFFF) as u32;
                    src |= (((inst_norm >> 36) & 1) << 20) as u32;

                    src <<= 4;

                    let mut dest = if is_encoder {
                        now_pos.wrapping_add(i as u32).wrapping_add(src)
                    } else {
                        src.wrapping_sub(now_pos.wrapping_add(i as u32))
                    };

                    dest >>= 4;

                    inst_norm &= !(0x8F_FFFFu64 << 13);
                    inst_norm |= u64::from(dest & 0xFFFFF) << 13;
                    inst_norm |= u64::from(dest & 0x100000) << (36 - 20);

                    instruction &= u64::from((1u32 << bit_res) - 1);
                    instruction |= inst_norm << bit_res;

                    for j in 0..6 {
                        buffer[i + j + byte_pos] = (instruction >> (8 * j)) as u8;
                    }
                }
            }
            bit_pos += 41;
        }
        i += 16;
    }

    i
}
