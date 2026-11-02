//! BCJ for SPARC: port of `simple/sparc.c`.

/// `sparc_code`.
pub(crate) fn code(now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
    let size = buffer.len() & !3;

    let mut i = 0;
    while i < size {
        if (buffer[i] == 0x40 && (buffer[i + 1] & 0xC0) == 0x00)
            || (buffer[i] == 0x7F && (buffer[i + 1] & 0xC0) == 0xC0)
        {
            let mut src = (u32::from(buffer[i]) << 24)
                | (u32::from(buffer[i + 1]) << 16)
                | (u32::from(buffer[i + 2]) << 8)
                | u32::from(buffer[i + 3]);

            src <<= 2;

            let pos = now_pos.wrapping_add(i as u32);
            let mut dest = if is_encoder {
                pos.wrapping_add(src)
            } else {
                src.wrapping_sub(pos)
            };

            dest >>= 2;

            dest = ((0u32.wrapping_sub((dest >> 22) & 1) << 22) & 0x3FFF_FFFF)
                | (dest & 0x3F_FFFF)
                | 0x4000_0000;

            buffer[i] = (dest >> 24) as u8;
            buffer[i + 1] = (dest >> 16) as u8;
            buffer[i + 2] = (dest >> 8) as u8;
            buffer[i + 3] = dest as u8;
        }
        i += 4;
    }

    i
}
