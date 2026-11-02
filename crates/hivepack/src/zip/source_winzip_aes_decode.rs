//! The layer that decrypts WinZip AES: port of
//! `zip_source_winzip_aes_decode.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::winzip_aes::WinzipAes;
use crate::zip::zip::{Stat, em, stat};
use crate::zip::zipint::{
    HMAC_LENGTH, WINZIP_AES_MAX_HEADER_LENGTH, WINZIP_AES_PASSWORD_VERIFY_LENGTH, salt_length,
};

/// `struct winzip_aes`.
pub(crate) struct WinzipAesDecode {
    password: Vec<u8>,
    encryption_method: u16,

    data_length: u64,
    current_position: u64,

    aes_ctx: Option<Box<WinzipAes>>,
    hmac_verify_failed: Option<Error>,
    hmac_verified: bool,
}

/// The bytes around the encrypted data: the salt and password verifier
/// before it, the authentication code after it.
fn aux_length(encryption_method: u16) -> u64 {
    (WINZIP_AES_PASSWORD_VERIFY_LENGTH + salt_length(encryption_method) + HMAC_LENGTH) as u64
}

impl WinzipAesDecode {
    /// `zip_source_winzip_aes_decode`, on a lower source whose stat is
    /// `st`.
    pub(crate) fn new(
        password: &[u8],
        encryption_method: u16,
        st: &Stat<'_>,
    ) -> Result<WinzipAesDecode> {
        if !matches!(encryption_method, em::AES_128 | em::AES_192 | em::AES_256) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let aux_length = aux_length(encryption_method);
        if st.valid & stat::COMP_SIZE == 0 || st.comp_size < aux_length {
            return Err(Error::new(ErrorCode::OpNotSupp, 0));
        }
        Ok(WinzipAesDecode {
            password: password.to_vec(),
            encryption_method,
            data_length: st.comp_size - aux_length,
            current_position: 0,
            aes_ctx: None,
            hmac_verify_failed: None,
            hmac_verified: false,
        })
    }

    /// `decrypt_header`: the salt and password verifier, read with
    /// `lower`, and the keys derived from them.
    fn decrypt_header(&mut self, lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>) -> Result<()> {
        let mut header = [0u8; WINZIP_AES_MAX_HEADER_LENGTH];
        let salt_length = salt_length(self.encryption_method);
        let headerlen = WINZIP_AES_PASSWORD_VERIFY_LENGTH + salt_length;
        let n = lower(&mut header[..headerlen])?;
        if n != headerlen {
            return Err(Error::new(ErrorCode::Eof, 0));
        }

        let (aes_ctx, password_verification) =
            WinzipAes::new(&self.password, &header, self.encryption_method)?;
        if password_verification[..] != header[salt_length..headerlen] {
            return Err(Error::new(ErrorCode::WrongPasswd, 0));
        }
        self.aes_ctx = Some(Box::new(aes_ctx));
        Ok(())
    }

    /// `verify_hmac`: the authentication code after the data, read with
    /// `lower`, against the one computed, once.
    fn verify_hmac(&mut self, lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>) {
        if self.hmac_verified {
            return;
        }
        self.hmac_verified = true;

        let mut from_file = [0u8; HMAC_LENGTH];
        match lower(&mut from_file) {
            Ok(n) if n >= HMAC_LENGTH => {}
            // zip_error_set_from_source: the lower source's error, which a
            // read that stopped early keeps for the next one; none if it
            // only ended.
            Ok(_) => {
                self.hmac_verify_failed = Some(lower(&mut []).err().unwrap_or(Error::OK));
                return;
            }
            Err(e) => {
                self.hmac_verify_failed = Some(e);
                return;
            }
        }

        let Some(aes_ctx) = self.aes_ctx.take() else {
            self.hmac_verify_failed = Some(Error::new(ErrorCode::Internal, 0));
            return;
        };
        let computed = aes_ctx.finish();

        if from_file[..] != computed[..HMAC_LENGTH] {
            self.hmac_verify_failed = Some(Error::new(ErrorCode::Crc, 0));
        }
    }

    /// `ZIP_SOURCE_AT_EOF`.
    pub(crate) fn at_eof(&self) -> bool {
        self.current_position == self.data_length
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self, lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>) -> Result<()> {
        self.hmac_verify_failed = None;
        self.hmac_verified = false;
        self.decrypt_header(lower)?;
        self.current_position = 0;
        Ok(())
    }

    /// `ZIP_SOURCE_READ`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        let len = (data.len() as u64).min(self.data_length - self.current_position) as usize;

        let n = if len > 0 {
            let n = lower(&mut data[..len])?;
            if n == 0 {
                return Err(Error::new(ErrorCode::Eof, 0));
            }
            self.current_position += n as u64;
            match self.aes_ctx.as_mut() {
                Some(aes_ctx) => aes_ctx.decrypt(&mut data[..n]),
                None => return Err(Error::new(ErrorCode::Internal, 0)),
            }
            n
        } else {
            0
        };

        if self.current_position == self.data_length {
            self.verify_hmac(lower);
        }

        match self.hmac_verify_failed {
            _ if n > 0 => Ok(n),
            Some(e) => Err(e),
            None => Ok(0),
        }
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(
        &mut self,
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<()> {
        // For empty files, we should verify the HMAC even if no data has
        // been read.
        if self.current_position == self.data_length {
            self.verify_hmac(lower);
        }
        match self.hmac_verify_failed {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) -> Result<()> {
        st.encryption_method = em::NONE;
        st.valid |= stat::ENCRYPTION_METHOD;
        if st.valid & stat::COMP_SIZE != 0 {
            let aux_length = aux_length(self.encryption_method);
            if st.comp_size < aux_length {
                return Err(Error::new(ErrorCode::DataLength, 0));
            }
            st.comp_size -= aux_length;
        }
        Ok(())
    }
}

impl Drop for WinzipAesDecode {
    fn drop(&mut self) {
        self.password.fill(0);
        std::hint::black_box(&mut self.password);
    }
}
