//! BCJ for ARM-Thumb: port of `simple/armthumb.c`.

/// `armthumb_code`.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    if buffer.len() < 4 {
        return 0;
    }

    let size = buffer.len() - 4;

    let mut i = 0;
    while i <= size {
        if (buffer[i + 1] & 0xF8) == 0xF0 && (buffer[i + 3] & 0xF8) == 0xF8 {
            let mut src = ((u32::from(buffer[i + 1]) & 7) << 19)
                | (u32::from(buffer[i]) << 11)
                | ((u32::from(buffer[i + 3]) & 7) << 8)
                | u32::from(buffer[i + 2]);

            src <<= 1;

            let pos = now_pos.wrapping_add(i as u32).wrapping_add(4);
            let mut dest = if is_encoder {
                pos.wrapping_add(src)
            } else {
                src.wrapping_sub(pos)
            };

            dest >>= 1;

            buffer[i + 1] = 0xF0 | ((dest >> 19) & 0x7) as u8;
            buffer[i] = (dest >> 11) as u8;
            buffer[i + 3] = 0xF8 | ((dest >> 8) & 0x7) as u8;
            buffer[i + 2] = dest as u8;
            i += 2;
        }
        i += 2;
    }

    i
}
