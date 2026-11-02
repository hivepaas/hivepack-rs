//! The layer that decrypts ZipCrypto: port of `zip_source_pkware_decode.c`.

use crate::zip::dirent::{DosTime, u2d_time};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::pkware::PkwareKeys;
use crate::zip::zip::{Stat, em, stat};
use crate::zip::zipint::CRYPTO_PKWARE_HEADERLEN;

/// `struct trad_pkware`.
pub(crate) struct PkwareDecode {
    password: Vec<u8>,
    keys: PkwareKeys,
}

impl PkwareDecode {
    /// `zip_source_pkware_decode`, on a lower source whose stat is `st`.
    pub(crate) fn new(password: &[u8], st: &Stat<'_>) -> Result<PkwareDecode> {
        if st.valid & stat::COMP_SIZE == 0 || st.comp_size < CRYPTO_PKWARE_HEADERLEN as u64 {
            return Err(Error::new(ErrorCode::OpNotSupp, 0));
        }
        Ok(PkwareDecode {
            password: password.to_vec(),
            keys: PkwareKeys::default(),
        })
    }

    /// `decrypt_header`: the encryption header, read with `lower`, checked
    /// against the high byte of the time or of the CRC, where the lower
    /// source's stat (`st`) and MS-DOS time (`dostime`) tell them.
    fn decrypt_header(
        &mut self,
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
        st: &Stat<'_>,
        dostime: Option<(u16, u16)>,
    ) -> Result<()> {
        let mut header = [0u8; CRYPTO_PKWARE_HEADERLEN];
        let n = lower(&mut header)?;
        if n != CRYPTO_PKWARE_HEADERLEN {
            return Err(Error::new(ErrorCode::Eof, 0));
        }

        self.keys.decrypt(&mut header);

        if st.valid & stat::CRC == 0 {
            // skip password validation
            return Ok(());
        }

        let dostime = match dostime {
            Some((time, date)) => DosTime { time, date },
            None => {
                if st.valid & stat::MTIME == 0 {
                    // no date available, skip password validation
                    return Ok(());
                }
                u2d_time(st.mtime)?
            }
        };

        // password verification - two ways:
        // - mtime - InfoZIP way, to avoid computing complete CRC before
        //   encrypting data
        // - CRC - old PKWare way
        let check = header[CRYPTO_PKWARE_HEADERLEN - 1];
        if u16::from(check) == dostime.time >> 8 || u32::from(check) == st.crc >> 24 {
            Ok(())
        } else {
            Err(Error::new(ErrorCode::WrongPasswd, 0))
        }
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(
        &mut self,
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
        st: &Stat<'_>,
        dostime: Option<(u16, u16)>,
    ) -> Result<()> {
        self.keys.reset();
        self.keys.decrypt_keys(&self.password);
        self.decrypt_header(lower, st, dostime)
    }

    /// `ZIP_SOURCE_READ`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        let n = lower(data)?;
        self.keys.decrypt(&mut data[..n]);
        Ok(n)
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) -> Result<()> {
        st.encryption_method = em::NONE;
        st.valid |= stat::ENCRYPTION_METHOD;
        if st.valid & stat::COMP_SIZE != 0 {
            if st.comp_size < CRYPTO_PKWARE_HEADERLEN as u64 {
                return Err(Error::new(ErrorCode::DataLength, 0));
            }
            st.comp_size -= CRYPTO_PKWARE_HEADERLEN as u64;
        }
        Ok(())
    }
}

impl Drop for PkwareDecode {
    fn drop(&mut self) {
        self.password.fill(0);
        std::hint::black_box(&mut self.password);
        self.keys.clear();
    }
}
