//! Port of `zip_get_encryption_implementation.c`: which encryption methods
//! are decrypted and encrypted, and the layers that do it.

use crate::zip::dirent::DosTime;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::random::RandomSource;
use crate::zip::source_data::FileAttributes;
use crate::zip::source_pkware_decode::PkwareDecode;
use crate::zip::source_pkware_encode::PkwareEncode;
use crate::zip::source_winzip_aes_decode::WinzipAesDecode;
use crate::zip::source_winzip_aes_encode::WinzipAesEncode;
use crate::zip::zip::{Stat, em};

/// The layer that decrypts an entry's data.
///
/// Differs from libzip: an enum of the decrypting sources, where libzip
/// returns the function that creates one.
pub(crate) enum Decrypt {
    Pkware(PkwareDecode),
    WinzipAes(WinzipAesDecode),
}

impl Decrypt {
    /// `_zip_get_encryption_implementation(em, ZIP_CODEC_DECODE)`, then the
    /// implementation called with `password` on a lower source whose stat
    /// is `st`. A method with none fails with `ZIP_ER_ENCRNOTSUPP`, then no
    /// password with `ZIP_ER_INVAL`.
    pub(crate) fn new(method: u16, password: Option<&[u8]>, st: &Stat<'_>) -> Result<Decrypt> {
        if !matches!(
            method,
            em::TRAD_PKWARE | em::AES_128 | em::AES_192 | em::AES_256
        ) {
            return Err(Error::new(ErrorCode::EncrNotSupp, 0));
        }
        let Some(password) = password else {
            return Err(Error::new(ErrorCode::Inval, 0));
        };
        match method {
            em::TRAD_PKWARE => Ok(Decrypt::Pkware(PkwareDecode::new(password, st)?)),
            em::AES_128 | em::AES_192 | em::AES_256 => Ok(Decrypt::WinzipAes(
                WinzipAesDecode::new(password, method, st)?,
            )),
            _ => Err(Error::new(ErrorCode::EncrNotSupp, 0)),
        }
    }

    /// `ZIP_SOURCE_OPEN`, with the lower source's stat and MS-DOS time,
    /// which ZipCrypto checks the password with.
    pub(crate) fn open(
        &mut self,
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
        st: &Stat<'_>,
        dostime: Option<(u16, u16)>,
    ) -> Result<()> {
        match self {
            Decrypt::Pkware(ctx) => ctx.open(lower, st, dostime),
            Decrypt::WinzipAes(ctx) => ctx.open(lower),
        }
    }

    /// `ZIP_SOURCE_READ`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        match self {
            Decrypt::Pkware(ctx) => ctx.read(data, lower),
            Decrypt::WinzipAes(ctx) => ctx.read(data, lower),
        }
    }

    /// `ZIP_SOURCE_CLOSE`: WinZip AES checks the authentication code.
    pub(crate) fn close(
        &mut self,
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<()> {
        match self {
            Decrypt::Pkware(_) => Ok(()),
            Decrypt::WinzipAes(ctx) => ctx.close(lower),
        }
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) -> Result<()> {
        match self {
            Decrypt::Pkware(ctx) => ctx.stat(st),
            Decrypt::WinzipAes(ctx) => ctx.stat(st),
        }
    }

    /// `ZIP_SOURCE_AT_EOF`: WinZip AES answers itself; ZipCrypto passes it
    /// to the lower source (`None`).
    pub(crate) fn at_eof(&self) -> Option<bool> {
        match self {
            Decrypt::Pkware(_) => None,
            Decrypt::WinzipAes(ctx) => Some(ctx.at_eof()),
        }
    }
}

/// The layer that encrypts an entry's data.
pub(crate) enum Encrypt {
    Pkware(PkwareEncode),
    WinzipAes(Box<WinzipAesEncode>),
}

impl Encrypt {
    /// The implementation of `_zip_get_encryption_implementation(em,
    /// ZIP_CODEC_ENCODE)` called with `password`, which fails with
    /// `ZIP_ER_INVAL` without one. ZipCrypto takes the lower source's
    /// MS-DOS time, `dostime`, or else the time of its stat.
    pub(crate) fn new(
        method: u16,
        password: Option<&[u8]>,
        dostime: Option<DosTime>,
        lower_stat: impl FnOnce() -> Result<Stat<'static>>,
        random: Option<RandomSource>,
    ) -> Result<Encrypt> {
        let Some(password) = password else {
            return Err(Error::new(ErrorCode::Inval, 0));
        };
        match method {
            em::TRAD_PKWARE => Ok(Encrypt::Pkware(PkwareEncode::new(
                password, dostime, lower_stat, random,
            )?)),
            _ => Ok(Encrypt::WinzipAes(Box::new(WinzipAesEncode::new(
                password, method, random,
            )?))),
        }
    }

    /// `ZIP_SOURCE_OPEN`: the header, from random bytes.
    pub(crate) fn open(&mut self) -> Result<()> {
        match self {
            Encrypt::Pkware(ctx) => ctx.open(),
            Encrypt::WinzipAes(ctx) => ctx.open(),
        }
    }

    /// `ZIP_SOURCE_READ`.
    pub(crate) fn read(
        &mut self,
        data: &mut [u8],
        lower: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<usize> {
        match self {
            Encrypt::Pkware(ctx) => ctx.read(data, lower),
            Encrypt::WinzipAes(ctx) => ctx.read(data, lower),
        }
    }

    /// `ZIP_SOURCE_CLOSE`.
    pub(crate) fn close(&mut self) {
        if let Encrypt::Pkware(ctx) = self {
            ctx.close();
        }
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat.
    pub(crate) fn stat(&self, st: &mut Stat<'_>) {
        match self {
            Encrypt::Pkware(ctx) => ctx.stat(st),
            Encrypt::WinzipAes(ctx) => ctx.stat(st),
        }
    }

    /// `ZIP_SOURCE_GET_FILE_ATTRIBUTES`, before those of the lower source
    /// are merged in.
    pub(crate) fn file_attributes(&self) -> FileAttributes {
        match self {
            Encrypt::Pkware(ctx) => ctx.file_attributes(),
            Encrypt::WinzipAes(ctx) => ctx.file_attributes(),
        }
    }
}

/// `zip_encryption_method_supported`: whether entries encrypted with
/// `method` can be read, or with `encode`, written.
pub fn encryption_method_supported(method: u16, encode: bool) -> bool {
    let _ = encode;
    matches!(
        method,
        em::NONE | em::TRAD_PKWARE | em::AES_128 | em::AES_192 | em::AES_256
    )
}
