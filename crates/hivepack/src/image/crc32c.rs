//! CRC-32C, the check VHDX puts on its headers and tables.
//!
//! Castagnoli's polynomial (0x1EDC6F41, reflected to 0x82F63B78), not the
//! one `deflate` and a GUID partition table use. A table of 256 entries,
//! built while compiling, and a byte at a time: what it checks is a header
//! of 4 KiB or a table of 64 KiB, so nothing faster is worth its code.

/// The table, as every reflected CRC builds it.
const TABLE: [u32; 256] = {
    const POLYNOMIAL: u32 = 0x82F6_3B78;
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// The CRC-32C of `bytes`, from the start value every user of it begins
/// with and complemented at the end, as the published check values are.
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc = (crc >> 8) ^ TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    /// The check value every CRC-32C is measured by, and two more that
    /// iSCSI's specification gives (RFC 3720, appendix B.4).
    #[test]
    fn the_published_check_values() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
        assert_eq!(crc32c(b""), 0);
    }
}
