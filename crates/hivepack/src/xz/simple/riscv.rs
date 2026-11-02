//! BCJ for RISC-V: port of `simple/riscv.c`. Unlike the other filters,
//! its encoder and decoder are two functions.

use crate::xz::common::{read32le, write32le};

/// `NOT_AUIPC_PAIR`: true if the AUIPC and the instruction after it are
/// not a pair whose address can be converted.
#[inline(always)]
fn not_auipc_pair(auipc: u32, inst2: u32) -> bool {
    ((auipc << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0
}

/// `NOT_SPECIAL_AUIPC`: true if the AUIPC is not one the encoder made
/// special.
#[inline(always)]
fn not_special_auipc(auipc: u32, inst2_rs1: u32) -> bool {
    (auipc.wrapping_sub(0x3117) << 18) >= (inst2_rs1 & 0x1D)
}

/// `read32be`.
fn read32be(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// `write32be`.
fn write32be(buf: &mut [u8], value: u32) {
    buf[..4].copy_from_slice(&value.to_be_bytes());
}

/// `riscv_encode`.
pub(crate) fn encode(now_pos: u32, buffer: &mut [u8]) -> usize {
    // Avoid using i + 8 <= size in the loop condition.
    if buffer.len() < 8 {
        return 0;
    }

    let size = buffer.len() - 8;

    let mut i = 0;
    while i <= size {
        let mut inst = u32::from(buffer[i]);

        if inst == 0xEF {
            // JAL
            let b1 = u32::from(buffer[i + 1]);
            if (b1 & 0x0D) == 0 {
                let b2 = u32::from(buffer[i + 2]);
                let b3 = u32::from(buffer[i + 3]);
                let pc = now_pos.wrapping_add(i as u32);

                let mut addr = ((b1 & 0xF0) << 8)
                    | ((b2 & 0x0F) << 16)
                    | ((b2 & 0x10) << 7)
                    | ((b2 & 0xE0) >> 4)
                    | ((b3 & 0x7F) << 4)
                    | ((b3 & 0x80) << 13);

                addr = addr.wrapping_add(pc);

                buffer[i + 1] = ((b1 & 0x0F) | ((addr >> 13) & 0xF0)) as u8;
                buffer[i + 2] = (addr >> 9) as u8;
                buffer[i + 3] = (addr >> 1) as u8;

                i += 4 - 2;
            }
        } else if (inst & 0x7F) == 0x17 {
            // AUIPC
            inst |= u32::from(buffer[i + 1]) << 8;
            inst |= u32::from(buffer[i + 2]) << 16;
            inst |= u32::from(buffer[i + 3]) << 24;

            if inst & 0xE80 != 0 {
                // AUIPC's rd doesn't equal x0 or x2.
                let inst2 = read32le(&buffer[i + 4..]);

                if not_auipc_pair(inst, inst2) {
                    i += 6 - 2;
                } else {
                    let mut addr = inst & 0xFFFF_F000;
                    addr = addr.wrapping_add((inst2 >> 20).wrapping_sub((inst2 >> 19) & 0x1000));

                    addr = addr.wrapping_add(now_pos.wrapping_add(i as u32));

                    inst = 0x17 | (2 << 7) | (inst2 << 12);

                    write32le(&mut buffer[i..], inst);
                    write32be(&mut buffer[i + 4..], addr);
                    i += 8 - 2;
                }
            } else {
                // AUIPC's rd equals x0 or x2.
                let fake_rs1 = inst >> 27;
                if not_special_auipc(inst, fake_rs1) {
                    i += 4 - 2;
                } else {
                    let fake_addr = read32le(&buffer[i + 4..]);

                    let fake_inst2 = (inst >> 12) | (fake_addr << 20);

                    inst = 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFF_F000);

                    write32le(&mut buffer[i..], inst);
                    write32le(&mut buffer[i + 4..], fake_inst2);
                    i += 8 - 2;
                }
            }
        }
        i += 2;
    }

    i
}

/// `riscv_decode`.
pub(crate) fn decode(now_pos: u32, buffer: &mut [u8]) -> usize {
    if buffer.len() < 8 {
        return 0;
    }

    let size = buffer.len() - 8;

    let mut i = 0;
    while i <= size {
        let mut inst = u32::from(buffer[i]);

        if inst == 0xEF {
            // JAL
            let b1 = u32::from(buffer[i + 1]);
            if (b1 & 0x0D) == 0 {
                let b2 = u32::from(buffer[i + 2]);
                let b3 = u32::from(buffer[i + 3]);
                let pc = now_pos.wrapping_add(i as u32);

                let mut addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);

                addr = addr.wrapping_sub(pc);

                buffer[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;

                buffer[i + 2] =
                    (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;

                buffer[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;

                i += 4 - 2;
            }
        } else if (inst & 0x7F) == 0x17 {
            // AUIPC
            inst |= u32::from(buffer[i + 1]) << 8;
            inst |= u32::from(buffer[i + 2]) << 16;
            inst |= u32::from(buffer[i + 3]) << 24;

            let mut converted = true;
            let mut inst2;
            if inst & 0xE80 != 0 {
                // AUIPC's rd doesn't equal x0 or x2.
                inst2 = read32le(&buffer[i + 4..]);

                if not_auipc_pair(inst, inst2) {
                    i += 6 - 2;
                    converted = false;
                } else {
                    let mut addr = inst & 0xFFFF_F000;
                    addr = addr.wrapping_add(inst2 >> 20);

                    inst = 0x17 | (2 << 7) | (inst2 << 12);
                    inst2 = addr;
                }
            } else {
                // AUIPC's rd equals x0 or x2.
                let inst2_rs1 = inst >> 27;

                if not_special_auipc(inst, inst2_rs1) {
                    i += 4 - 2;
                    converted = false;
                    inst2 = 0;
                } else {
                    let mut addr = read32be(&buffer[i + 4..]);

                    addr = addr.wrapping_sub(now_pos.wrapping_add(i as u32));

                    inst2 = (inst >> 12) | (addr << 20);

                    inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
                }
            }

            if converted {
                write32le(&mut buffer[i..], inst);
                write32le(&mut buffer[i + 4..], inst2);

                i += 8 - 2;
            }
        }
        i += 2;
    }

    i
}

/// `lzma_bcj_riscv_encode`: converts `buf`, whose first byte is at
/// `start_offset` in the file (rounded down to a multiple of two), in
/// place; the number of bytes converted.
pub fn bcj_riscv_encode(start_offset: u32, buf: &mut [u8]) -> usize {
    encode(start_offset & !1, buf)
}

/// `lzma_bcj_riscv_decode`: the inverse of [`bcj_riscv_encode`].
pub fn bcj_riscv_decode(start_offset: u32, buf: &mut [u8]) -> usize {
    decode(start_offset & !1, buf)
}
