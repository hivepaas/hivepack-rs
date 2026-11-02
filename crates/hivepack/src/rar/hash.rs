// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.
//! The hash of a file's data: UnRAR's `DataHash` (hash.cpp), and RAR 1.4's
//! checksum (`Checksum14`, crc.cpp).

use crate::crypto::Blake2sp;
use crate::deflate::crc32;
use crate::rar::crypt::{crc32_to_mac, digest_to_mac};

use crate::rar::headers::{HashType, HashValue};

/// `DataHash`, one computation of a file's hash.
pub enum DataHash {
    None,
    Rar14(u16),
    Crc32(u32),
    Blake2(Box<Blake2sp>),
}

impl DataHash {
    /// `DataHash::Init`.
    pub fn new(kind: HashType) -> DataHash {
        match kind {
            HashType::None => DataHash::None,
            HashType::Rar14 => DataHash::Rar14(0),
            // zlib's CRC-32 takes and gives the value UnRAR's has with its
            // 0xffffffff first and last: it starts from 0.
            HashType::Crc32 => DataHash::Crc32(0),
            HashType::Blake2 => DataHash::Blake2(Box::default()),
        }
    }

    /// `DataHash::Update`: more data.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            DataHash::None => {}
            DataHash::Rar14(sum) => *sum = checksum14(*sum, data),
            DataHash::Crc32(crc) => *crc = crc32(*crc, data),
            DataHash::Blake2(hash) => hash.update(data),
        }
    }

    /// `DataHash::Result`: the hash of the data so far. The computation can
    /// go on with more data.
    pub fn result(&self) -> HashValue {
        let mut value = HashValue::default();
        match self {
            DataHash::None => {}
            DataHash::Rar14(sum) => {
                value.kind = HashType::Rar14;
                value.crc32 = u32::from(*sum);
            }
            DataHash::Crc32(crc) => {
                value.kind = HashType::Crc32;
                value.crc32 = *crc;
            }
            DataHash::Blake2(hash) => {
                value.kind = HashType::Blake2;
                value.digest = hash.out();
            }
        }
        value
    }

    /// `DataHash::Cmp`, without a key: whether the hash so far is `value`.
    pub fn matches(&self, value: &HashValue) -> bool {
        same(&self.result(), value)
    }

    /// `DataHash::Cmp` with a key: RAR 5 keeps a keyed hash of an encrypted
    /// entry, so that the header does not say what the data's hash is.
    pub(crate) fn matches_keyed(&self, value: &HashValue, key: &[u8; 32]) -> bool {
        let mut result = self.result();
        match result.kind {
            HashType::Crc32 => result.crc32 = crc32_to_mac(result.crc32, key),
            HashType::Blake2 => result.digest = digest_to_mac(&result.digest, key),
            HashType::None | HashType::Rar14 => {}
        }
        same(&result, value)
    }
}

/// `HashValue::operator==`: no hash on either side is equal to anything,
/// and two of different kinds to nothing else.
fn same(a: &HashValue, b: &HashValue) -> bool {
    match (a.kind, b.kind) {
        (HashType::None, _) | (_, HashType::None) => true,
        (HashType::Rar14, HashType::Rar14) | (HashType::Crc32, HashType::Crc32) => {
            a.crc32 == b.crc32
        }
        (HashType::Blake2, HashType::Blake2) => a.digest == b.digest,
        _ => false,
    }
}

/// `Checksum14`: add each byte and rotate left by one.
fn checksum14(start: u16, data: &[u8]) -> u16 {
    data.iter().fold(start, |sum, &byte| {
        sum.wrapping_add(u16::from(byte)).rotate_left(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_data_hashes_as_unrar_says() {
        let empty = |kind| DataHash::new(kind);
        assert!(empty(HashType::Crc32).matches(&HashValue {
            kind: HashType::Crc32,
            ..HashValue::default()
        }));
        assert!(empty(HashType::Rar14).matches(&HashValue {
            kind: HashType::Rar14,
            ..HashValue::default()
        }));
        // HashValue::Init's digest of no data.
        let mut digest = [0u8; 32];
        let hex = b"dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f";
        for (byte, pair) in digest.iter_mut().zip(hex.chunks(2)) {
            let pair = std::str::from_utf8(pair).unwrap_or_default();
            *byte = u8::from_str_radix(pair, 16).unwrap_or_default();
        }
        assert!(empty(HashType::Blake2).matches(&HashValue {
            kind: HashType::Blake2,
            digest,
            ..HashValue::default()
        }));
    }

    #[test]
    fn a_hash_differs_from_another_value_and_kind() {
        for kind in [HashType::Rar14, HashType::Crc32, HashType::Blake2] {
            let mut hash = DataHash::new(kind);
            hash.update(b"data");
            let right = hash.result();
            assert_eq!(right.kind, kind);
            assert!(hash.matches(&right));
            let mut wrong = right;
            wrong.crc32 ^= 1;
            wrong.digest[31] ^= 1;
            assert!(!hash.matches(&wrong), "{kind:?}");
            for other in [HashType::Rar14, HashType::Crc32, HashType::Blake2] {
                if other != kind {
                    let value = HashValue {
                        kind: other,
                        ..right
                    };
                    assert!(!hash.matches(&value), "{kind:?} and {other:?}");
                }
            }
        }
    }

    #[test]
    fn no_hash_matches_anything() {
        let mut hash = DataHash::new(HashType::None);
        hash.update(b"data");
        assert!(hash.matches(&HashValue {
            crc32: 1,
            ..HashValue::default()
        }));
    }

    #[test]
    fn checksum14_rotates_after_adding() {
        assert_eq!(checksum14(0, &[1]), 2);
        assert_eq!(checksum14(0x8000, &[0]), 1);
        assert_eq!(checksum14(0xffff, &[1]), 0);
        assert_eq!(checksum14(0, &[0x80, 0]), 0x200);
    }
}
