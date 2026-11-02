//! BCJ for x86 and x86-64: port of `simple/x86.c`.

/// `Test86MSByte`.
#[inline(always)]
fn test_86_ms_byte(b: u8) -> bool {
    b == 0 || b == 0xFF
}

/// `lzma_simple_x86`: the state of the x86 filter.
#[derive(Clone, Copy, Debug)]
pub(crate) struct X86 {
    prev_mask: u32,
    prev_pos: u32,
}

impl X86 {
    /// The state of `x86_coder_init`.
    pub(crate) fn new() -> X86 {
        X86 {
            prev_mask: 0,
            prev_pos: 5u32.wrapping_neg(),
        }
    }

    /// `x86_code`.
    pub(crate) fn code(&mut self, now_pos: u32, is_encoder: bool, buffer: &mut [u8]) -> usize {
        const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];

        let mut prev_mask = self.prev_mask;
        let mut prev_pos = self.prev_pos;

        if buffer.len() < 5 {
            return 0;
        }

        if now_pos.wrapping_sub(prev_pos) > 5 {
            prev_pos = now_pos.wrapping_sub(5);
        }

        let limit = buffer.len() - 5;
        let mut buffer_pos = 0;

        while buffer_pos <= limit {
            let mut b = buffer[buffer_pos];
            if b != 0xE8 && b != 0xE9 {
                buffer_pos += 1;
                continue;
            }

            let offset = now_pos
                .wrapping_add(buffer_pos as u32)
                .wrapping_sub(prev_pos);
            prev_pos = now_pos.wrapping_add(buffer_pos as u32);

            if offset > 5 {
                prev_mask = 0;
            } else {
                for _ in 0..offset {
                    prev_mask &= 0x77;
                    prev_mask <<= 1;
                }
            }

            b = buffer[buffer_pos + 4];

            if test_86_ms_byte(b) && (prev_mask >> 1) <= 4 && (prev_mask >> 1) != 3 {
                let mut src = (u32::from(b) << 24)
                    | (u32::from(buffer[buffer_pos + 3]) << 16)
                    | (u32::from(buffer[buffer_pos + 2]) << 8)
                    | u32::from(buffer[buffer_pos + 1]);

                let mut dest;
                loop {
                    let pos = now_pos.wrapping_add(buffer_pos as u32).wrapping_add(5);
                    dest = if is_encoder {
                        src.wrapping_add(pos)
                    } else {
                        src.wrapping_sub(pos)
                    };

                    if prev_mask == 0 {
                        break;
                    }

                    let i = MASK_TO_BIT_NUMBER[(prev_mask >> 1) as usize];

                    b = (dest >> (24 - i * 8)) as u8;

                    if !test_86_ms_byte(b) {
                        break;
                    }

                    src = dest ^ ((1u32 << (32 - i * 8)) - 1);
                }

                buffer[buffer_pos + 4] = !(((dest >> 24) & 1).wrapping_sub(1)) as u8;
                buffer[buffer_pos + 3] = (dest >> 16) as u8;
                buffer[buffer_pos + 2] = (dest >> 8) as u8;
                buffer[buffer_pos + 1] = dest as u8;
                buffer_pos += 5;
                prev_mask = 0;
            } else {
                buffer_pos += 1;
                prev_mask |= 1;
                if test_86_ms_byte(b) {
                    prev_mask |= 0x10;
                }
            }
        }

        self.prev_mask = prev_mask;
        self.prev_pos = prev_pos;

        buffer_pos
    }
}

/// `lzma_bcj_x86_encode`: converts `buf`, whose first byte is at
/// `start_offset` in the file, in place; the number of bytes converted,
/// the rest needing more data after it.
pub fn bcj_x86_encode(start_offset: u32, buf: &mut [u8]) -> usize {
    X86::new().code(start_offset, true, buf)
}

/// `lzma_bcj_x86_decode`: the inverse of [`bcj_x86_encode`].
pub fn bcj_x86_decode(start_offset: u32, buf: &mut [u8]) -> usize {
    X86::new().code(start_offset, false, buf)
}
