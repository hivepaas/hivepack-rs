//! WinZip AES: port of `zip_winzip_aes.c`, the keys derived from the
//! password and salt, and AES in WinZip's counter mode with HMAC-SHA1 over
//! the encrypted data, on `hivepack-crypto`.

use hivepack_crypto::{AES_BLOCK_LENGTH, Aes, Hmac, HmacKey, SHA1_LENGTH, Sha1, pbkdf2};

use crate::error::{Error, ErrorCode, Result};
use crate::zip::em;
use crate::zipint::WINZIP_AES_PASSWORD_VERIFY_LENGTH;

const MAX_KEY_LENGTH: usize = 256;
const PBKDF2_ITERATIONS: u32 = 1000;

/// Four blocks of pad, as `hivepack-crypto` encrypts four at once.
const PAD_LENGTH: usize = 4 * AES_BLOCK_LENGTH;

/// `zip_winzip_aes_t`.
///
/// Differs from libzip: the pad is four blocks, the next four counter
/// values encrypted at once, where libzip encrypts one block at a time.
pub(crate) struct WinzipAes {
    aes: Aes,
    hmac: Hmac<Sha1>,
    counter: [u8; AES_BLOCK_LENGTH],
    pad: [u8; PAD_LENGTH],
    pad_offset: usize,
}

impl WinzipAes {
    /// `aes_crypt`: XORs `data` with the pad, the counter encrypted. The
    /// counter is incremented in its first eight bytes, little-endian, as
    /// libzip does.
    fn aes_crypt(&mut self, data: &mut [u8]) {
        for byte in data {
            if self.pad_offset == PAD_LENGTH {
                for block in self.pad.as_chunks_mut::<AES_BLOCK_LENGTH>().0 {
                    for digit in self.counter.iter_mut().take(8) {
                        *digit = digit.wrapping_add(1);
                        if *digit != 0 {
                            break;
                        }
                    }
                    *block = self.counter;
                }
                self.aes.encrypt4(&mut self.pad);
                self.pad_offset = 0;
            }
            *byte ^= self.pad[self.pad_offset];
            self.pad_offset += 1;
        }
    }

    /// `_zip_winzip_aes_new`: the keys of `password` and `salt` for
    /// `encryption_method`, and the password verifier.
    pub(crate) fn new(
        password: &[u8],
        salt: &[u8],
        encryption_method: u16,
    ) -> Result<(WinzipAes, [u8; WINZIP_AES_PASSWORD_VERIFY_LENGTH])> {
        // in bits
        let key_size: usize = match encryption_method {
            em::AES_128 => 128,
            em::AES_192 => 192,
            em::AES_256 => 256,
            _ => 0,
        };
        if key_size == 0 || password.is_empty() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        // in bytes
        let key_length = key_size / 8;

        let salt = salt
            .get(..key_length / 2)
            .ok_or(Error::new(ErrorCode::Inval, 0))?;

        let mut buffer = [0u8; 2 * (MAX_KEY_LENGTH / 8) + WINZIP_AES_PASSWORD_VERIFY_LENGTH];
        let derived = &mut buffer[..2 * key_length + WINZIP_AES_PASSWORD_VERIFY_LENGTH];
        pbkdf2::<Sha1>(password, salt, PBKDF2_ITERATIONS, derived);

        let aes = Aes::new(&derived[..key_length]).ok_or(Error::new(ErrorCode::Inval, 0))?;
        let hmac = Hmac::new(&HmacKey::new(&derived[key_length..2 * key_length]));
        let mut password_verify = [0u8; WINZIP_AES_PASSWORD_VERIFY_LENGTH];
        password_verify.copy_from_slice(&derived[2 * key_length..]);
        derived.fill(0);
        std::hint::black_box(&mut buffer);

        Ok((
            WinzipAes {
                aes,
                hmac,
                counter: [0; AES_BLOCK_LENGTH],
                pad: [0; PAD_LENGTH],
                pad_offset: PAD_LENGTH,
            },
            password_verify,
        ))
    }

    /// `_zip_winzip_aes_encrypt`: encrypts `data` in place, and takes it
    /// into the HMAC.
    pub(crate) fn encrypt(&mut self, data: &mut [u8]) {
        self.aes_crypt(data);
        self.hmac.update(data);
    }

    /// `_zip_winzip_aes_decrypt`: takes `data` into the HMAC, and decrypts
    /// it in place.
    pub(crate) fn decrypt(&mut self, data: &mut [u8]) {
        self.hmac.update(data);
        self.aes_crypt(data);
    }

    /// `_zip_winzip_aes_finish`: the HMAC of the encrypted data.
    pub(crate) fn finish(&self) -> [u8; SHA1_LENGTH] {
        self.hmac.out()
    }
}

impl Drop for WinzipAes {
    fn drop(&mut self) {
        self.pad.fill(0);
        self.counter.fill(0);
        std::hint::black_box(&mut self.pad);
    }
}
