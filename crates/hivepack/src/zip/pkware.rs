//! Traditional PKWARE encryption, ZipCrypto: port of `zip_pkware.c`.

use crate::deflate::crc32;

const PKWARE_KEY0: u32 = 305_419_896;
const PKWARE_KEY1: u32 = 591_751_049;
const PKWARE_KEY2: u32 = 878_082_192;

/// `zip_pkware_keys_t`: the three keys, which every byte changes.
#[derive(Clone, Copy, Default)]
pub(crate) struct PkwareKeys {
    key: [u32; 3],
}

impl PkwareKeys {
    fn update_keys(&mut self, b: u8) {
        self.key[0] = crc32(self.key[0] ^ 0xffff_ffff, &[b]) ^ 0xffff_ffff;
        self.key[1] = self.key[1]
            .wrapping_add(self.key[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        let b = (self.key[1] >> 24) as u8;
        self.key[2] = crc32(self.key[2] ^ 0xffff_ffff, &[b]) ^ 0xffff_ffff;
    }

    fn crypt_byte(&self) -> u8 {
        let tmp = (self.key[2] | 2) as u16;
        ((u32::from(tmp) * u32::from(tmp ^ 1)) >> 8) as u8
    }

    /// `_zip_pkware_keys_reset`.
    pub(crate) fn reset(&mut self) {
        self.key = [PKWARE_KEY0, PKWARE_KEY1, PKWARE_KEY2];
    }

    /// `_zip_pkware_encrypt`, in place.
    pub(crate) fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            let b = *byte;
            let tmp = self.crypt_byte();
            self.update_keys(b);
            *byte = b ^ tmp;
        }
    }

    /// `_zip_pkware_encrypt` with no output: the keys take in `data`.
    pub(crate) fn encrypt_keys(&mut self, data: &[u8]) {
        // during initialization, we're only interested in key updates
        for &b in data {
            self.update_keys(b);
        }
    }

    /// `_zip_pkware_decrypt`, in place.
    pub(crate) fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data {
            let b = *byte ^ self.crypt_byte();
            *byte = b;
            self.update_keys(b);
        }
    }

    /// `_zip_pkware_decrypt` with no output: the keys take in `data`.
    pub(crate) fn decrypt_keys(&mut self, data: &[u8]) {
        for &b in data {
            self.update_keys(b);
        }
    }

    /// Overwrites the keys (best effort, as `hivepack::crypto` clears its
    /// keys).
    pub(crate) fn clear(&mut self) {
        self.key = [0; 3];
        std::hint::black_box(&mut self.key);
    }
}
