//! The sources that read an entry's data, as read or new: port of
//! `zip_source_zip_new.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Detail, Error, ErrorCode, Result};
use crate::zip::get_encryption_implementation::Decrypt;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::source_compress::Decompress;
use crate::zip::source_crc::Crc;
use crate::zip::source_data::{
    FileAttributes, GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK, file_attributes,
};
use crate::zip::source_stack::{Layer, Stack};
use crate::zip::source_window::{Lower, UpperWindow, Window};
use crate::zip::zip::{Flags, OpenFlags, Stat, cm, em, stat};

impl<R: ReadAt> Archive<R> {
    /// The stack of sources that reads entry `srcidx` from byte `start`,
    /// `len` bytes of it (or to its end if `len` is -1): decompressed unless
    /// `flags` has [`Flags::COMPRESSED`], with its CRC checked when all of
    /// it is read. Port of `zip_source_zip_file_create`. An encrypted
    /// entry is decrypted with `password`, or else the archive's default
    /// password.
    pub(crate) fn source_zip_file_create(
        &self,
        srcidx: u64,
        flags: Flags,
        start: u64,
        len: i64,
        password: Option<&[u8]>,
    ) -> Result<Stack<'_, R>> {
        if srcidx >= self.entry.len() as u64 || len < -1 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let mut flags = flags;
        if flags.intersects(Flags::ENCRYPTED) {
            flags = flags | Flags::COMPRESSED;
        }

        let entry = &self.entry[srcidx as usize];
        let mut changed_data = false;
        if !flags.intersects(Flags::UNCHANGED) {
            if entry.data_changed() {
                // A source of new data can always be read again.
                if flags.intersects(Flags::COMPRESSED) {
                    return Err(Error::new(ErrorCode::Changed, 0));
                }
                changed_data = true;
            } else if entry.deleted {
                return Err(Error::new(ErrorCode::Changed, 0));
            }
        }

        let stat_flags = if changed_data {
            flags
        } else {
            flags | Flags::UNCHANGED
        };
        let st: Stat<'static> = match self.stat_index(srcidx, stat_flags) {
            Ok(st) => Stat { name: None, ..st },
            Err(_) => return Err(Error::new(ErrorCode::Internal, 0)),
        };

        if (start > 0 || len >= 0) && flags.intersects(Flags::COMPRESSED) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        // Check for overflow of end.
        if len > 0 && start > 0 && start.checked_add(len as u64).is_none() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let have_size = st.valid & stat::SIZE != 0;
        if have_size {
            // Check that start and end are within the size of the file.
            if start > st.size || (len > 0 && start + len as u64 > st.size) {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
        }

        let data_len: i64 = if len == -1 {
            if have_size {
                if st.size - start > i64::MAX as u64 {
                    return Err(Error::new(ErrorCode::Inval, 0));
                }
                (st.size - start) as i64
            } else {
                -1
            }
        } else {
            len
        };
        let partial_data = if have_size {
            (data_len as u64) < st.size
        } else {
            true
        };

        let encrypted = st.valid & stat::ENCRYPTION_METHOD != 0 && st.encryption_method != em::NONE;
        let needs_decrypt = !flags.intersects(Flags::ENCRYPTED) && encrypted;
        let compressed = st.valid & stat::COMP_METHOD != 0 && st.comp_method != cm::STORE;
        let needs_decompress = !flags.intersects(Flags::COMPRESSED) && compressed;
        // when reading the whole file, check for CRC errors
        let needs_crc = (!flags.intersects(Flags::COMPRESSED) || !compressed)
            && !partial_data
            && st.valid & stat::CRC != 0;

        let password = password.or(self.default_password.as_deref());
        if needs_decrypt && password.is_none() {
            return Err(Error::new(ErrorCode::NoPasswd, 0));
        }

        let de = self.get_dirent(srcidx, flags)?;
        let attributes = file_attributes_from_dirent(de);
        let dostime = Some((de.last_mod.time, de.last_mod.date));
        // Where the local header is, from the entry as read, as
        // `_zip_file_get_offset` finds it when the window opens: an entry
        // with changes has the offset it is written at once closed.
        let header = entry.orig.as_ref().map(|o| o.offset);

        let have_comp_size = st.valid & stat::COMP_SIZE != 0;
        let empty_data = if needs_decrypt || needs_decompress {
            have_comp_size && st.comp_size == 0
        } else {
            have_size && st.size == 0
        };
        // An entry with no data is read from an empty buffer, as if its data
        // had been changed.
        let lower = match (&entry.source, changed_data) {
            _ if empty_data => Lower::Empty,
            (Some(source), true) => Lower::Data {
                source: source.clone(),
                offset: 0,
            },
            _ => Lower::Archive(self.src.view()),
        };
        let changed_data = changed_data || empty_data;

        let window = if partial_data && !needs_decrypt && !needs_decompress {
            if start + data_len as u64 > st.comp_size {
                return Err(Error::incons_at(Detail::StoredSizeMismatch, srcidx));
            }
            let mut st2 = Stat {
                comp_method: cm::STORE,
                valid: stat::COMP_METHOD,
                ..Stat::default()
            };
            if data_len >= 0 {
                st2.size = data_len as u64;
                st2.comp_size = data_len as u64;
                st2.valid |= stat::SIZE | stat::COMP_SIZE;
            }
            if st.valid & stat::MTIME != 0 {
                st2.mtime = st.mtime;
                st2.valid |= stat::MTIME;
            }
            let source_archive = match changed_data {
                false => Some(header.ok_or(Error::new(ErrorCode::Internal, 0))?),
                true => None,
            };
            Window::new(
                &lower,
                start,
                data_len,
                &st2,
                stat::NAME,
                attributes,
                dostime,
                source_archive,
            )?
        } else if !changed_data {
            // this branch is executed only for archive sources; we know that
            // stat data come from the archive too, so it's safe to assume
            // that st has a comp_size specified
            if st.comp_size > i64::MAX as u64 {
                return Err(Error::new(ErrorCode::Inval, 0));
            }
            Window::new(
                &lower,
                0,
                st.comp_size as i64,
                &st,
                stat::NAME,
                attributes,
                dostime,
                Some(header.ok_or(Error::new(ErrorCode::Internal, 0))?),
            )?
        } else {
            // reading the whole changed data, or from a zero-sized source
            // buffer created above
            Window::new(
                &lower,
                0,
                data_len,
                &st,
                stat::NAME,
                attributes,
                dostime,
                None,
            )?
        };

        let decrypt = if needs_decrypt {
            let mut st_window = lower.stat();
            window.stat(&mut st_window);
            Some(Layer::new(Decrypt::new(
                st.encryption_method,
                password,
                &st_window,
            )?))
        } else {
            None
        };

        let decompress = if needs_decompress {
            let check_consistency = self.open_flags.intersects(OpenFlags::CHECKCONS);
            Some(Layer::new(Decompress::new(
                st.comp_method,
                check_consistency,
                have_comp_size.then_some(st.comp_size),
            )?))
        } else {
            None
        };

        let crc = needs_crc.then(|| Layer::new(Crc::new(true)));

        let mut stack = Stack {
            lower,
            window: Layer::new(window),
            decrypt,
            decompress,
            crc,
            partial: None,
            index: srcidx,
        };

        // The part of the data asked for, a window on top of the
        // decompressed data.
        if partial_data && (needs_decrypt || needs_decompress) {
            let upper = UpperWindow::new(stack.size_below_partial(), start, data_len)?;
            stack.partial = Some(Layer::new(upper));
        }

        Ok(stack)
    }
}

/// What an entry's header says about its file, as a source of its data
/// gives it: port of `_zip_file_attributes_from_dirent`.
fn file_attributes_from_dirent(de: &Dirent) -> FileAttributes {
    FileAttributes {
        valid: file_attributes::ASCII
            | file_attributes::HOST_SYSTEM
            | file_attributes::EXTERNAL_FILE_ATTRIBUTES
            | file_attributes::GENERAL_PURPOSE_BIT_FLAGS,
        ascii: de.int_attrib & 1 != 0,
        host_system: (de.version_madeby >> 8) as u8,
        external_file_attributes: de.ext_attrib,
        general_purpose_bit_flags: de.bitflags,
        general_purpose_bit_mask: GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK,
        ..FileAttributes::default()
    }
}
