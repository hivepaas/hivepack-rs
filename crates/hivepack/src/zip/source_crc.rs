//! The layer that checks the CRC-32 and the length of what is read: port
//! of `zip_source_crc.c`; when writing, it computes them.

use crate::deflate::crc32;

use crate::zip::error::{
    Detail, Error, ErrorCode, MAX_DETAIL_INDEX, Result, make_detail_with_index,
};
use crate::zip::zip::{Stat, stat};

/// `struct crc_context`.
pub(crate) struct Crc {
    /// whether to check CRC on EOF and return error on mismatch
    validate: bool,
    /// whether CRC was computed for complete file
    crc_complete: bool,
    pub(crate) error: Error,
    size: u64,
    /// current reading position
    position: u64,
    /// how far we've computed the CRC
    crc_position: u64,
    crc: u32,
}

impl Crc {
    /// Port of `zip_source_crc_create` and `crc_context_new`.
    pub(crate) fn new(validate: bool) -> Crc {
        let mut crc = Crc {
            validate,
            crc_complete: false,
            error: Error::OK,
            size: 0,
            position: 0,
            crc_position: 0,
            crc: 0,
        };
        crc.read_init();
        crc
    }

    /// `crc_context_read_init`.
    fn read_init(&mut self) {
        self.position = 0;
        self.crc_complete = false;
        self.crc_position = 0;
        self.crc = crc32(0, &[]);
        self.size = 0;
    }

    /// `ZIP_SOURCE_OPEN`.
    pub(crate) fn open(&mut self) {
        self.read_init();
    }

    /// `ZIP_SOURCE_READ`, once the lower source has read `n` bytes into
    /// `data`; at its end, the CRC and the length are checked against
    /// `lower_stat`.
    pub(crate) fn read(
        &mut self,
        data: &[u8],
        n: Result<usize>,
        lower_stat: impl FnOnce() -> Stat<'static>,
    ) -> Result<usize> {
        let n = match n {
            Ok(n) => n,
            Err(e) => {
                self.error = e;
                return Err(e);
            }
        };

        if n == 0 {
            return self.validate_crc(lower_stat).map(|()| 0);
        }

        // We can only compute the CRC data in the correct order. So we
        // update the CRC for data read this time that starts at
        // ctx->crc_position.
        let n64 = n as u64;
        if !self.crc_complete
            && self.position <= self.crc_position
            && self.crc_position < self.position + n64
        {
            let from = (self.crc_position - self.position) as usize;
            self.crc = crc32(self.crc, &data[from..n]);
            self.crc_position += (n - from) as u64;
        }
        self.position += n64;
        Ok(n)
    }

    /// `ZIP_SOURCE_CLOSE`: the CRC is checked if the lower source is at its
    /// end, as `at_eof` tells.
    pub(crate) fn close(
        &mut self,
        at_eof: Result<bool>,
        lower_stat: impl FnOnce() -> Stat<'static>,
    ) -> Result<()> {
        match at_eof {
            Err(e) => {
                self.error = e;
                Err(e)
            }
            Ok(true) => self.validate_crc(lower_stat),
            Ok(false) => Ok(()),
        }
    }

    /// Whether the CRC is complete, which is what changes the stat. Not in
    /// libzip.
    pub(crate) fn complete(&self) -> bool {
        self.crc_complete
    }

    /// `ZIP_SOURCE_STAT`, on the lower source's stat: once the CRC is
    /// complete, it and the length read, which must be the length the
    /// lower source says (`ZIP_ER_DATA_LENGTH`).
    pub(crate) fn stat(&self, st: &mut Stat<'_>) -> Result<()> {
        if self.crc_complete {
            stat_complete(st, self.size, self.crc)?;
        }
        Ok(())
    }

    /// Port of `validate_crc`.
    fn validate_crc(&mut self, lower_stat: impl FnOnce() -> Stat<'static>) -> Result<()> {
        self.size = self.position;
        // The lower sources' stat cannot fail.
        let st = if self.validate {
            lower_stat()
        } else {
            Stat::default()
        };

        if self.crc_position == self.position {
            self.crc_complete = true;
            if self.validate && st.valid & stat::CRC != 0 && st.crc != self.crc {
                self.error = Error::new(ErrorCode::Crc, 0);
                return Err(self.error);
            }
        }

        if self.validate && st.valid & stat::SIZE != 0 && st.size != self.size {
            // We don't have the index here, but the caller should know which
            // file they are reading from.
            self.error = Error::new(
                ErrorCode::Incons,
                make_detail_with_index(Detail::InvalidFileLength, MAX_DETAIL_INDEX),
            );
            return Err(self.error);
        }
        Ok(())
    }
}

/// The stat once the CRC of data of `size` bytes is complete, `crc`, on the
/// lower source's: what [`Crc::stat`] gives then. Not in libzip, where it is
/// in `ZIP_SOURCE_STAT`: also what the data of blocks compressed in threads
/// gives (`close_threads.rs`).
pub(crate) fn stat_complete(st: &mut Stat<'_>, size: u64, crc: u32) -> Result<()> {
    if st.valid & stat::SIZE != 0 && st.size != size {
        return Err(Error::new(ErrorCode::DataLength, 0));
    }
    // TODO in libzip: Set comp_size, comp_method,
    // encryption_method? After all, this only works for
    // uncompressed data.
    st.size = size;
    st.crc = crc;
    st.comp_size = size;
    st.comp_method = crate::zip::zip::cm::STORE;
    st.encryption_method = crate::zip::zip::em::NONE;
    st.valid |=
        stat::SIZE | stat::CRC | stat::COMP_SIZE | stat::COMP_METHOD | stat::ENCRYPTION_METHOD;
    Ok(())
}
