//! The layer that encrypts with WinZip AES: port of
//! `zip_source_winzip_aes_encode.c`.

use crate::crypto::SHA1_LENGTH;

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::random::{RandomSource, secure_random};
use crate::zip::source_data::{FileAttributes, file_attributes};
use crate::zip::winzip_aes::WinzipAes;
use crate::zip::zip::{Stat, em, stat};
use crate::zip::zipint::{
    HMAC_LENGTH, Password, WINZIP_AES_MAX_HEADER_LENGTH, WINZIP_AES_PASSWORD_VERIFY_LENGTH,
    salt_length,
};

/// The bytes the header or the authentication code is read from.
const DATA_LENGTH: usize = if WINZIP_AES_MAX_HEADER_LENGTH > SHA1_LENGTH {
    WINZIP_AES_MAX_HEADER_LENGTH
} else {
    SHA1_LENGTH
};

/// `struct winzip_aes`.
pub(crate) struct WinzipAesEncode {
    password: Password,
    encryption_method: u16,

    data: [u8; DATA_LENGTH],
    /// how much of `data` is to be read, and how much was
    buffer: Option<(usize, usize)>,

    aes_ctx: Option<Box<WinzipAes>>,
    eof: bool,
    random: Option<RandomSource>,
}

impl WinzipAesEncode {
    /// `zip_source_winzip_aes_encode`.
    pub(crate) fn new(
        password: &[u8],
        encryption_method: u16,
        random: Option<RandomSource>,
    ) -> Result<WinzipAesEncode> {
        if !matches!(encryption_method, em::AES_128 | em::AES_192 | em::AES_256) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        Ok(WinzipAesEncode {
            password: Password::new(password),
            encryption_method,
            data: [0; DATA_LENGTH],
            buffer: None,
            aes_ctx: None,
            eof: false,
            random,
        })
    }

    /// `encrypt_header`: a random salt, the keys derived from it, and the
    /// password verifier after it.
    fn encrypt_header(&mut self) -> Result<()> {
        let salt_length = salt_length(self.encryption_method);
        if !secure_random(self.random.as_ref(), &mut self.data[..salt_length]) {
            return Err(Error::new(ErrorCode::Internal, 0));
        }
        let (aes_ctx, password_verify) = WinzipAes::new(
            &self.password,
            &self.data[..salt_length],
            self.encryption_method,
        )?;
        self.data[salt_length..salt_length + WINZIP_AES_PASSWORD_VERIFY_LENGTH]
            .copy_from_slice(&password_verify);
        self.aes_ctx = Some(Box::new(aes_ctx));
        self.buffer = Some((salt_length + WINZIP_AES_PASSWORD_VERIFY_LENGTH, 0));
        Ok(())
    }

    /// Reads what is left of `buffer` into `data`: `_zip_buffer_read`.
    fn read_buffer(&mut self, data: &mut [u8]) -> usize {
        let Some((len, read)) = self.buffer.as_mut() else {
            return 0;
        };
        let n = (*len - *read).min(data.len());
        data[..n].copy_from_slice(&self.data[*read..*read + n]);
        *read += n;
        if *read == *len {
            self.buffer = None;
        }
        n
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) -> Result<()> {
        self.eof = false;
        self.encrypt_header()
    }

    /// `ZIP_SOURCE_READ`: the salt and password verifier, the data
    /// encrypted, then its authentication code.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        let mut buffer_n = self.read_buffer(data);

        if self.eof {
            return Ok(buffer_n);
        }

        let rest = &mut data[buffer_n..];
        let ret = lower(rest)?;
        let Some(aes_ctx) = self.aes_ctx.as_mut() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        aes_ctx.encrypt(&mut rest[..ret]);

        if ret < rest.len() {
            self.eof = true;
            let mac = aes_ctx.finish();
            self.aes_ctx = None;
            self.data[..SHA1_LENGTH].copy_from_slice(&mac);
            self.buffer = Some((HMAC_LENGTH, 0));
            let rest_len = rest.len();
            buffer_n += self.read_buffer(&mut data[buffer_n + ret..buffer_n + rest_len]);
        }

        Ok(buffer_n + ret)
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        st.encryption_method = self.encryption_method;
        st.valid |= stat::ENCRYPTION_METHOD;
        if st.valid & stat::COMP_SIZE != 0 {
            st.comp_size += 12 + salt_length(self.encryption_method) as u64;
        }
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: version 5.1.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        FileAttributes {
            valid: file_attributes::VERSION_NEEDED,
            version_needed: 51,
            ..FileAttributes::default()
        }
    }
}

impl Drop for WinzipAesEncode {
    fn drop(&mut self) {
        self.data.fill(0);
        std::hint::black_box(&mut self.data);
    }
}
