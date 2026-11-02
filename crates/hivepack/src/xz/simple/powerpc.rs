//! BCJ for big-endian PowerPC: port of `simple/powerpc.c`.

/// `powerpc_code`.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    let size = buffer.len() & !3;

    let mut i = 0;
    while i < size {
        // PowerPC branch 6(48) 24(Offset) 1(Abs) 1(Link)
        if (buffer[i] >> 2) == 0x12 && (buffer[i + 3] & 3) == 1 {
            let src = ((u32::from(buffer[i]) & 3) << 24)
                | (u32::from(buffer[i + 1]) << 16)
                | (u32::from(buffer[i + 2]) << 8)
                | (u32::from(buffer[i + 3]) & !3);

            let dest = if is_encoder {
                now_pos.wrapping_add(i as u32).wrapping_add(src)
            } else {
                src.wrapping_sub(now_pos.wrapping_add(i as u32))
            };

            buffer[i] = 0x48 | ((dest >> 24) & 0x03) as u8;
            buffer[i + 1] = (dest >> 16) as u8;
            buffer[i + 2] = (dest >> 8) as u8;
            buffer[i + 3] &= 0x03;
            buffer[i + 3] |= dest as u8;
        }
        i += 4;
    }

    i
}
