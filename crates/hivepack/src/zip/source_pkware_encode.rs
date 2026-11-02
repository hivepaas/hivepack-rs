//! The layer that encrypts with ZipCrypto: port of
//! `zip_source_pkware_encode.c`.

use crate::zip::dirent::{DosTime, u2d_time};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::pkware::PkwareKeys;
use crate::zip::random::{RandomSource, secure_random};
use crate::zip::source_data::{FileAttributes, file_attributes, time_now};
use crate::zip::zip::{Stat, em, stat};
use crate::zip::zipint::{CRYPTO_PKWARE_HEADERLEN, GPBF_DATA_DESCRIPTOR, Password};

/// `struct trad_pkware`.
///
/// Its `ZIP_SOURCE_AT_EOF` and `ZIP_SOURCE_GET_DOS_TIME` are left out:
/// nothing asks them of the top of the stack `add_data` reads.
pub(crate) struct PkwareEncode {
    password: Password,
    keys: PkwareKeys,
    /// the encryption header, and how much of it was read
    buffer: Option<([u8; CRYPTO_PKWARE_HEADERLEN], usize)>,
    eof: bool,
    dostime: DosTime,
    random: Option<RandomSource>,
}

impl PkwareEncode {
    /// `zip_source_pkware_encode`, on a lower source whose MS-DOS time is
    /// `dostime` (`None` if it has none) and whose stat `lower_stat` gives,
    /// asked for only without a time.
    pub(crate) fn new(
        password: &[u8],
        dostime: Option<DosTime>,
        lower_stat: impl FnOnce() -> Result<Stat<'static>>,
        random: Option<RandomSource>,
    ) -> Result<PkwareEncode> {
        let dostime = match dostime {
            Some(dostime) => dostime,
            None => {
                let st = lower_stat()?;
                u2d_time(if st.valid & stat::MTIME != 0 {
                    st.mtime
                } else {
                    time_now()
                })?
            }
        };
        Ok(PkwareEncode {
            password: Password::new(password),
            keys: PkwareKeys::default(),
            buffer: None,
            eof: false,
            dostime,
            random,
        })
    }

    /// `encrypt_header`: the header from random bytes and the time (see
    /// appnote.iz, XIII. Decryption, Step 2, last paragraph), encrypted.
    fn encrypt_header(&mut self) -> Result<()> {
        let mut header = [0u8; CRYPTO_PKWARE_HEADERLEN];
        if !secure_random(
            self.random.as_ref(),
            &mut header[..CRYPTO_PKWARE_HEADERLEN - 1],
        ) {
            return Err(Error::new(ErrorCode::Internal, 0));
        }
        header[CRYPTO_PKWARE_HEADERLEN - 1] = (self.dostime.time >> 8) as u8;
        self.keys.encrypt(&mut header);
        self.buffer = Some((header, 0));
        Ok(())
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) -> Result<()> {
        self.eof = false;
        // initialize keys
        self.keys.reset();
        self.keys.encrypt_keys(&self.password);
        self.encrypt_header()
    }

    /// `ZIP_SOURCE_READ`: the header, then the data, encrypted.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        let mut buffer_n = 0;
        if let Some((header, read)) = self.buffer.as_mut() {
            // write header values to data
            buffer_n = (CRYPTO_PKWARE_HEADERLEN - *read).min(data.len());
            data[..buffer_n].copy_from_slice(&header[*read..*read + buffer_n]);
            *read += buffer_n;
            if *read == CRYPTO_PKWARE_HEADERLEN {
                self.buffer = None;
            }
        }

        if self.eof {
            return Ok(buffer_n);
        }

        let rest = &mut data[buffer_n..];
        let n = lower(rest)?;
        self.keys.encrypt(&mut rest[..n]);
        if n < rest.len() {
            self.eof = true;
        }
        Ok(buffer_n + n)
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) {
        self.buffer = None;
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        st.encryption_method = em::TRAD_PKWARE;
        st.valid |= stat::ENCRYPTION_METHOD;
        if st.valid & stat::COMP_SIZE != 0 {
            st.comp_size += CRYPTO_PKWARE_HEADERLEN as u64;
        }
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`: version 2.0, and a data
    /// descriptor.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        FileAttributes {
            valid: file_attributes::VERSION_NEEDED | file_attributes::GENERAL_PURPOSE_BIT_FLAGS,
            version_needed: 20,
            general_purpose_bit_flags: GPBF_DATA_DESCRIPTOR,
            general_purpose_bit_mask: GPBF_DATA_DESCRIPTOR,
            ..FileAttributes::default()
        }
    }
}

impl Drop for PkwareEncode {
    fn drop(&mut self) {
        self.keys.clear();
    }
}
