//! Reading and changing extra fields: port of `zip_extra_field_api.c`.

use crate::zip::dirent::Dirent;
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::extra_field::ExtraField;
use crate::zip::open::Archive;
use crate::zip::source::ReadAt;
use crate::zip::zip::Flags;
use crate::zip::zipint::{EF_BOTH, EF_CENTRAL, EXTRA_FIELD_ALL, changed, ef_is_internal};

impl<R: ReadAt> Archive<R> {
    /// Extra field number `ef_idx` of entry `idx`, counted through those of
    /// the central directory, then those of the local header, as `flags`
    /// ask ([`Flags::CENTRAL`], [`Flags::LOCAL`] or both): its header id and
    /// data. Port of `zip_file_extra_field_get`. The fields libzip reads
    /// itself (Zip64, the Info-ZIP UTF-8 name and comment, WinZip AES) are
    /// not among them.
    pub fn file_extra_field_get(
        &self,
        idx: u64,
        ef_idx: u16,
        flags: Flags,
    ) -> Result<(u16, &[u8])> {
        self.file_extra_field_get_impl(idx, ef_idx, None, flags)
    }

    /// Extra field number `ef_idx` among those of entry `idx` with header id
    /// `ef_id`: port of `zip_file_extra_field_get_by_id`.
    pub fn file_extra_field_get_by_id(
        &self,
        idx: u64,
        ef_id: u16,
        ef_idx: u16,
        flags: Flags,
    ) -> Result<&[u8]> {
        self.file_extra_field_get_impl(idx, ef_idx, Some(ef_id), flags)
            .map(|(_, data)| data)
    }

    /// The number of extra fields of entry `idx`: port of
    /// `zip_file_extra_fields_count`.
    pub fn file_extra_fields_count(&self, idx: u64, flags: Flags) -> Result<i16> {
        self.count_impl(idx, -1, flags)
    }

    /// The number of extra fields of entry `idx` with header id `ef_id`:
    /// port of `zip_file_extra_fields_count_by_id`.
    pub fn file_extra_fields_count_by_id(&self, idx: u64, ef_id: u16, flags: Flags) -> Result<i16> {
        self.count_impl(idx, i32::from(ef_id), flags)
    }

    fn count_impl(&self, idx: u64, id: i32, flags: Flags) -> Result<i16> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.get_dirent(idx, flags)?;
        if flags.intersects(Flags::LOCAL) {
            self.read_local_ef(idx)?;
        }
        Ok(self.get_dirent(idx, flags)?.extra_fields.count(id, flags))
    }

    /// Deletes extra field number `ef_idx` of entry `idx`, counted through
    /// the fields of the local header or the central directory, as `flags`
    /// ask, or all of them with [`EXTRA_FIELD_ALL`]: port of
    /// `zip_file_extra_field_delete`. With both, only all can be deleted.
    pub fn file_extra_field_delete(&mut self, idx: u64, ef_idx: u16, flags: Flags) -> Result<()> {
        self.extra_field_delete_impl(idx, EXTRA_FIELD_ALL, ef_idx, flags, true)
    }

    /// Deletes extra field number `ef_idx` among those of entry `idx` with
    /// header id `ef_id`, or all of them with [`EXTRA_FIELD_ALL`]: port of
    /// `zip_file_extra_field_delete_by_id`.
    pub fn file_extra_field_delete_by_id(
        &mut self,
        idx: u64,
        ef_id: u16,
        ef_idx: u16,
        flags: Flags,
    ) -> Result<()> {
        self.extra_field_delete_impl(idx, ef_id, ef_idx, flags, false)
    }

    fn extra_field_delete_impl(
        &mut self,
        idx: u64,
        ef_id: u16,
        ef_idx: u16,
        flags: Flags,
        any_id: bool,
    ) -> Result<()> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        if flags.contains(EF_BOTH) && ef_idx != EXTRA_FIELD_ALL {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        self.get_dirent(idx, Flags::NONE)?;

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        // Since torrentzip does not allow extra fields, allow deleting all
        // of them (zip_file_extra_field_delete). Also, this is used
        // internally by zip_file_replace().
        if self.want_torrentzip()
            && (!any_id || ef_idx != EXTRA_FIELD_ALL || !flags.contains(EF_BOTH))
        {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        self.file_extra_field_prepare_for_change(idx)?;

        if let Some(de) = self.entry[idx as usize].changes.as_deref_mut() {
            de.extra_fields.delete_by_id(ef_id, ef_idx, flags);
        }
        Ok(())
    }

    /// Sets extra field number `ef_idx` with header id `ef_id` of entry
    /// `idx` to `data`, in the local header or the central directory or
    /// both, as `flags` ask, or adds one at the end with
    /// [`EXTRA_FIELD_NEW`](crate::zip::EXTRA_FIELD_NEW): port of `zip_file_extra_field_set`. The fields
    /// libzip writes itself (Zip64, the Info-ZIP UTF-8 name and comment,
    /// WinZip AES) cannot be set.
    pub fn file_extra_field_set(
        &mut self,
        idx: u64,
        ef_id: u16,
        ef_idx: u16,
        data: &[u8],
        flags: Flags,
    ) -> Result<()> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let Ok(_) = u16::try_from(data.len()) else {
            // Differs from libzip, which takes the length as a zip_uint16_t.
            return Err(Error::new(ErrorCode::Inval, 0));
        };

        self.get_dirent(idx, Flags::NONE)?;

        if self.is_rdonly() {
            return Err(Error::new(ErrorCode::RdOnly, 0));
        }
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::NotAllowed, 0));
        }

        if ef_is_internal(ef_id) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        self.file_extra_field_prepare_for_change(idx)?;

        match self.entry[idx as usize].changes.as_deref_mut() {
            Some(de) => de.extra_fields.set(flags, ef_id, ef_idx, data),
            None => Err(Error::new(ErrorCode::Internal, 0)),
        }
    }

    /// Gives entry `idx` a dirent of changes with the extra fields of both
    /// headers, to be changed: port of
    /// `_zip_file_extra_field_prepare_for_change`.
    fn file_extra_field_prepare_for_change(&mut self, idx: u64) -> Result<()> {
        if idx >= self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Inval, 0));
        }

        let e = &self.entry[idx as usize];
        if e.changed(changed::EXTRA_FIELD) {
            return Ok(());
        }

        if e.orig.is_some() {
            self.read_local_ef(idx)?;
        }

        let e = &mut self.entry[idx as usize];
        let changes = e
            .changes
            .get_or_insert_with(|| Box::new(Dirent::clone_changes(e.orig.as_deref())));
        changes.changed |= changed::EXTRA_FIELD;
        Ok(())
    }

    /// Port of `_zip_file_extra_field_get`. The field is found first, then
    /// borrowed, as the local header may have to be read in between.
    fn file_extra_field_get_impl(
        &self,
        idx: u64,
        mut ef_idx: u16,
        ef_id: Option<u16>,
        flags: Flags,
    ) -> Result<(u16, &[u8])> {
        if !flags.intersects(EF_BOTH) {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        let de = self.get_dirent(idx, flags)?;

        let mut found = None;
        if flags.intersects(EF_CENTRAL) {
            found = get_one(&de.extra_fields.central, &mut ef_idx, ef_id).map(|at| (false, at));
        }
        if found.is_none() && flags.intersects(Flags::LOCAL) {
            self.read_local_ef(idx)?;
            let de = self.get_dirent(idx, flags)?;
            found = get_one(
                de.extra_fields.local.get().map_or(&[][..], Vec::as_slice),
                &mut ef_idx,
                ef_id,
            )
            .map(|at| (true, at));
        }

        let Some((local, at)) = found else {
            return Err(Error::new(ErrorCode::NoEntry, 0));
        };
        let de = self.get_dirent(idx, flags)?;
        let fields = if local {
            de.extra_fields.local.get().map_or(&[][..], Vec::as_slice)
        } else {
            &de.extra_fields.central
        };
        let ef = &fields[at];
        Ok((ef.id, &ef.data))
    }
}

/// The position of field number `*idx` with header id `id` (any, if
/// `None`), counting down `*idx` past the others: port of
/// `_zip_file_extra_field_get_one`.
fn get_one(ef: &[ExtraField], idx: &mut u16, id: Option<u16>) -> Option<usize> {
    for (at, ef) in ef.iter().enumerate() {
        if id.is_none_or(|id| ef.id == id) {
            if *idx == 0 {
                return Some(at);
            }
            *idx -= 1;
        }
    }
    None
}
