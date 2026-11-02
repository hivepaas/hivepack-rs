//! BCJ for 32-bit ARM: port of `simple/arm.c`.

/// `arm_code`.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    let size = buffer.len() & !3;

    let mut i = 0;
    while i < size {
        if buffer[i + 3] == 0xEB {
            let mut src = (u32::from(buffer[i + 2]) << 16)
                | (u32::from(buffer[i + 1]) << 8)
                | u32::from(buffer[i]);
            src <<= 2;

            let pos = now_pos.wrapping_add(i as u32).wrapping_add(8);
            let mut dest = if is_encoder {
                pos.wrapping_add(src)
            } else {
                src.wrapping_sub(pos)
            };

            dest >>= 2;
            buffer[i + 2] = (dest >> 16) as u8;
            buffer[i + 1] = (dest >> 8) as u8;
            buffer[i] = dest as u8;
        }
        i += 4;
    }

    i
}
