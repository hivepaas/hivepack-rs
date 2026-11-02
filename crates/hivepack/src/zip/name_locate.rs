//! Port of `zip_name_locate.c`.

use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::hash::c_string;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::string::{ZipString, string_get};
use crate::zip::zip::Flags;

impl<R: ReadAt> Archive<R> {
    /// The index of the first entry named `fname`: port of
    /// `zip_name_locate`.
    ///
    /// Names are compared as C strings, up to their first NUL byte. Unless
    /// `flags` say it is UTF-8 or raw, `fname` is converted as names are
    /// (from CP437 if it is guessed to be that). With
    /// [`Flags::NOCASE`] the comparison ignores ASCII case, with
    /// [`Flags::NODIR`] it ignores the directories of the entries' names,
    /// and with either, or [`Flags::ENC_RAW`] or [`Flags::ENC_STRICT`], the
    /// names are read with those flags and compared one by one.
    pub fn name_locate(&self, fname: &[u8], flags: Flags) -> Result<u64> {
        let fname = c_string(fname);
        if fname.len() > usize::from(u16::MAX) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let converted;
        let mut fname = fname;
        if !flags.intersects(Flags::ENC_UTF_8 | Flags::ENC_RAW) && !fname.is_empty() {
            converted = ZipString::new(fname, flags)?;
            fname = string_get(converted.as_ref(), Flags::NONE);
        }

        if flags.intersects(Flags::NOCASE | Flags::NODIR | Flags::ENC_RAW | Flags::ENC_STRICT) {
            // can't use hash table
            let fname = c_string(fname);
            for i in 0..self.entry.len() as u64 {
                // newly added (partially filled) entry or error
                let Ok(fn_) = self.get_name(i, flags) else {
                    continue;
                };
                let mut fn_ = c_string(fn_);
                if flags.intersects(Flags::NODIR)
                    && let Some(p) = fn_.iter().rposition(|&b| b == b'/')
                {
                    fn_ = &fn_[p + 1..];
                }
                let same = if flags.intersects(Flags::NOCASE) {
                    fname.eq_ignore_ascii_case(fn_)
                } else {
                    fname == fn_
                };
                if same {
                    return Ok(i);
                }
            }
            return Err(Error::new(ErrorCode::NoEntry, 0));
        }

        self.names.lookup(fname, flags)
    }
}
