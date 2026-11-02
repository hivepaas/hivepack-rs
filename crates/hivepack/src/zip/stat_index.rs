//! Port of `zip_stat_index.c`.

use crate::zip::dirent::{CM_DEFAULT, DosTime, d2u_time};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::{Flags, Stat, cm, stat};
use crate::zip::zipint::changed;

impl<R: ReadAt> Archive<R> {
    /// What the central directory says about entry `index`, with its
    /// changes unless [`Flags::UNCHANGED`] is given: port of
    /// `zip_stat_index`. The CRC is not valid for WinZip AES entries of
    /// version 2 (AE-2). The time is taken as UTC (see
    /// [`Archive::file_get_dos_time`] for the time as stored).
    pub fn stat_index(&self, index: u64, flags: Flags) -> Result<Stat<'_>> {
        let de = self.get_dirent(index, flags)?;
        let name = self.get_name(index, flags)?;

        let entry = &self.entry[index as usize];
        if !flags.intersects(Flags::UNCHANGED)
            && let Some(source) = &entry.source
        {
            let Ok(mut st) = source.stat() else {
                return Err(Error::new(ErrorCode::Changed, 0));
            };

            if de.comp_method == CM_DEFAULT {
                if st.valid & stat::COMP_METHOD == 0 || st.comp_method == cm::STORE {
                    st.valid &= !(stat::COMP_SIZE | stat::COMP_METHOD);
                }
            } else {
                if st.valid & stat::COMP_METHOD != 0 && i32::from(st.comp_method) != de.comp_method
                {
                    st.valid &= !stat::COMP_SIZE;
                }
                st.valid |= stat::COMP_METHOD;
                st.comp_method = de.comp_method as u16;
            }

            if st.valid & (stat::COMP_METHOD | stat::SIZE) == stat::COMP_METHOD | stat::SIZE
                && st.comp_method == cm::STORE
            {
                st.valid |= stat::COMP_SIZE;
                st.comp_size = st.size;
            }

            if entry.changed(changed::LAST_MOD) {
                st.mtime = de.get_last_mod_mtime();
                st.valid |= stat::MTIME;
            }
            return Ok(self.stat_finish(st, index, name, flags));
        }

        let mut st = Stat {
            crc: de.crc,
            size: de.uncomp_size,
            mtime: de.get_last_mod_mtime(),
            comp_size: de.comp_size,
            comp_method: de.comp_method as u16,
            encryption_method: de.encryption_method,
            valid: (if de.crc_valid { stat::CRC } else { 0 })
                | stat::SIZE
                | stat::MTIME
                | stat::COMP_SIZE
                | stat::COMP_METHOD
                | stat::ENCRYPTION_METHOD,
            ..Stat::default()
        };
        if self.entry[index as usize].changed(changed::COMP_METHOD) {
            st.valid &= !stat::COMP_SIZE;
        }

        Ok(self.stat_finish(st, index, name, flags))
    }

    /// The end of `zip_stat_index`: torrentzip's method and time, and the
    /// index and name.
    fn stat_finish<'a>(
        &self,
        mut st: Stat<'static>,
        index: u64,
        name: &'a [u8],
        flags: Flags,
    ) -> Stat<'a> {
        if self.want_torrentzip() && !flags.intersects(Flags::UNCHANGED) {
            st.comp_method = cm::DEFLATE;
            st.mtime = d2u_time(DosTime {
                time: 0xbc00,
                date: 0x2198,
            });
            st.valid |= stat::MTIME | stat::COMP_METHOD;
            st.valid &= !stat::COMP_SIZE;
        }

        let mut st: Stat<'a> = st;
        st.index = index;
        st.name = Some(name);
        st.valid |= stat::INDEX | stat::NAME;
        st
    }

    /// The modification time of entry `index` as stored, in MS-DOS format:
    /// `(time, date)`.
    pub fn file_get_dos_time(&self, index: u64, flags: Flags) -> Result<(u16, u16)> {
        let de = self.get_dirent(index, flags)?;
        Ok((de.last_mod.time, de.last_mod.date))
    }
}
