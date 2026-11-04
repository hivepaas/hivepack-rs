//! Writing an archive with its changes: port of `zip_close.c`, for entries
//! whose data is kept as it is, to an output that can clone what is kept
//! or one that cannot.
//!
//! In torrentzip format ([`ArchiveFlags::WANT_TORRENTZIP`]), the entries
//! are sorted by name, ignoring ASCII case, and written without times,
//! extra fields or comments, and the archive comment is the signature with
//! the CRC-32 of the central directory.

use std::cmp::Ordering;
use std::io::{Seek, Write};

use crate::zip::buffer::Buffer;
use crate::zip::dirent::{Dirent, DosTime, cm_actual, u2d_time};
use crate::zip::error::{Error, ErrorCode, Result};
use crate::zip::extra_field::read_local_ef;
use crate::zip::file_get_offset::file_get_offset;
use crate::zip::get_encryption_implementation::{Decrypt, Encrypt, encryption_method_supported};
use crate::zip::hash::c_string;
use crate::zip::io_util::read;
use crate::zip::open::Archive;
use crate::zip::random::RandomSource;
use crate::zip::source::{ReadAhead, ReadAt, Source, Whence};
use crate::zip::source_compress::{Compress, Decompress, maximum_compressed_size};
use crate::zip::source_crc::Crc;
use crate::zip::source_data::time_now;
use crate::zip::source_stack::{Base, Layer, WriteStack};
use crate::zip::source_write::{Forward, Output};
use crate::zip::zip::{ArchiveFlags, Flags, OpenFlags, cm, em, stat};
use crate::zip::zipint::{
    BUFSIZE, DATADES_MAGIC, Entry, FL_DATA_FOLLOWS, FL_FORCE_ZIP64, GPBF_DATA_DESCRIPTOR,
    MAX_DATA_DESCRIPTOR_LENGTH, changed,
};

/// What [`Archive::close_to`] did: what libzip's `zip_close` does to the
/// archive's file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// Nothing changed, so nothing was written: the archive stays as it is.
    Unchanged,
    /// No entries are left, so nothing was written: libzip removes the
    /// archive, unless it is told to keep it
    /// ([`ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE`]).
    Removed,
    /// The archive was written, with its changes.
    Written,
}

impl<R: ReadAt> Archive<R> {
    /// Writes the archive with its changes to `out`, from its position:
    /// port of `zip_close`. The entries that are not deleted are written in
    /// order, each with a new local header and its data copied, then the
    /// central directory, with the Zip64 end of central directory record
    /// when the count of entries, the offset or the size of the directory
    /// need it. Nothing is written if nothing changed, or if no entries are
    /// left (see [`Closed`]).
    ///
    /// Differs from libzip:
    /// - The archive is written to `out` in whole, as libzip writes to a
    ///   source that cannot clone the data it keeps
    ///   (`ZIP_SOURCE_BEGIN_WRITE_CLONING`; see
    ///   [`Archive::close_to_cloning`]), and offsets in `out` count from
    ///   where it was when given.
    /// - The archive stays open. libzip discards it once written; on
    ///   failure, both leave it as it was then, and `out` has what was
    ///   written up to the error.
    pub fn close_to<W: Write + Seek>(&mut self, out: W) -> Result<Closed> {
        self.close_impl(out, None::<fn(u64) -> bool>)
    }

    /// Writes the archive with its changes to `out`, which only goes forwards: to a
    /// pipe, or an upload, with no more of it held than a piece of an entry. Otherwise
    /// the same as [`Archive::close_to`], but for what such an archive has to differ
    /// in. libzip has no such way.
    ///
    /// - An entry that is compressed or encrypted here has no CRC or sizes in its
    ///   local header, and a data descriptor after its data, which ZIP readers take
    ///   from the central directory. A reader that goes through an archive from its
    ///   start, not looking at the central directory, may not know where a stored one
    ///   ends. An entry copied as it is keeps its sizes in its header.
    /// - An entry of a source that does not say its size, or that may come to 4 GiB,
    ///   has the Zip64 extra field whatever it comes to.
    /// - Its time is the one its source said when it was first read.
    ///
    /// Torrentzip's format has no data descriptors: it is refused with
    /// [`ErrorCode::Inval`].
    pub fn close_to_stream<W: Write>(&mut self, out: W) -> Result<Closed> {
        if self.want_torrentzip() {
            return Err(Error::new(ErrorCode::Inval, 0));
        }
        self.close_with(Forward::new(out), None::<fn(u64) -> bool>, true)
    }

    /// Writes the archive with its changes to `out`, which must be at its
    /// start, as libzip writes to a source that can clone (a buffer, or a
    /// file on a file system with reflinks): the start of the archive up
    /// to the first entry that changed, or to the end of the data if none
    /// did, is kept as it is, copied here from the source, and only what
    /// follows is written. `can_clone` is asked whether that length can be
    /// kept, as libzip asks the source with
    /// `zip_source_begin_write_cloning`; if not, or in torrentzip format,
    /// the archive is written in whole, as [`Archive::close_to`] writes
    /// it. Otherwise the same as `close_to`.
    pub fn close_to_cloning<W: Write + Seek>(
        &mut self,
        out: W,
        can_clone: impl FnOnce(u64) -> bool,
    ) -> Result<Closed> {
        self.close_impl(out, Some(can_clone))
    }

    fn close_impl<W: Write + Seek, F: FnOnce(u64) -> bool>(
        &mut self,
        out: W,
        can_clone: Option<F>,
    ) -> Result<Closed> {
        self.close_with(out, can_clone, false)
    }

    /// Port of `zip_close`, cloning what is kept if `can_clone` is given, and going
    /// only forwards if `stream`.
    fn close_with<W: Write + Seek, F: FnOnce(u64) -> bool>(
        &mut self,
        out: W,
        can_clone: Option<F>,
        stream: bool,
    ) -> Result<Closed> {
        let (changed, survivors) = self.changed();

        if survivors == 0
            && !self
                .ch_flags
                .intersects(ArchiveFlags::CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE)
        {
            // don't create zip files with no entries
            return Ok(
                if self.open_flags.intersects(OpenFlags::TRUNCATE) || changed {
                    Closed::Removed
                } else {
                    Closed::Unchanged
                },
            );
        }

        // Always write empty archive if we are told to keep it, otherwise it
        // wouldn't be created if the file doesn't already exist.
        if !changed && survivors > 0 {
            return Ok(Closed::Unchanged);
        }

        if survivors > self.entry.len() as u64 {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        let mut unchanged_offset = u64::MAX;
        // create list of files with index into original archive
        let mut filelist = Vec::new();
        for (i, entry) in self.entry.iter().enumerate() {
            if let Some(orig) = &entry.orig
                && entry.has_changes()
            {
                unchanged_offset = unchanged_offset.min(orig.offset);
            }
            if entry.deleted {
                continue;
            }
            if filelist.len() as u64 >= survivors {
                return Err(Error::new(ErrorCode::Internal, 0));
            }
            filelist.push(i);
        }
        if (filelist.len() as u64) < survivors {
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        if self.want_torrentzip() && survivors > 1 {
            let names: Vec<Option<Vec<u8>>> = filelist
                .iter()
                .map(|&i| {
                    self.get_name(i as u64, Flags::NONE)
                        .ok()
                        .map(|name| c_string(name).to_vec())
                })
                .collect();
            let mut order: Vec<usize> = (0..filelist.len()).collect();
            // glibc's qsort sorts these stably.
            order.sort_by(|&a, &b| torrentzip_compare_names(&names[a], &names[b]));
            filelist = order.into_iter().map(|j| filelist[j]).collect();
        }

        let unchanged_offset = match can_clone {
            Some(can_clone) if !self.want_torrentzip() => {
                let mut unchanged_offset = unchanged_offset;
                if unchanged_offset == u64::MAX {
                    // we're keeping all file data, find the end of the last
                    // one
                    let mut last_index = None;
                    unchanged_offset = 0;
                    for (i, entry) in self.entry.iter().enumerate() {
                        if let Some(orig) = &entry.orig
                            && orig.offset >= unchanged_offset
                        {
                            unchanged_offset = orig.offset;
                            last_index = Some(i);
                        }
                    }
                    if let Some(last_index) = last_index {
                        unchanged_offset = self.file_get_end(last_index as u64)?;
                    }
                }
                // cloning not supported, need to copy everything
                if unchanged_offset > 0 && !can_clone(unchanged_offset) {
                    0
                } else {
                    unchanged_offset
                }
            }
            _ => 0,
        };

        let mut out = Output::new(out);
        out.stream = stream;
        if unchanged_offset > 0 {
            // The clone: the start of the archive as it is.
            let mut src = self.src.view();
            src.seek(0, Whence::Set)?;
            copy_data(&mut src, &mut out, unchanged_offset, &mut Vec::new())?;
        }
        // Local headers and data, read in order, usually: with a read ahead shared
        // by the entries, and a buffer, these are not a few system calls and an
        // allocation for each.
        let mut ahead = None;
        let mut buf = Vec::new();
        for &i in &filelist {
            if self.entry[i]
                .orig
                .as_ref()
                .is_some_and(|orig| orig.offset < unchanged_offset)
            {
                // already implicitly copied by cloning
                continue;
            }
            self.write_entry(i, &mut out, &mut ahead, &mut buf)?;
        }

        write_cdir(self, &filelist, &mut out)?;
        out.commit_write()?;
        Ok(Closed::Written)
    }

    /// The loop body of `zip_close`: writes entry `i`, its local header and
    /// its data, and keeps where in its dirent of changes.
    pub(crate) fn write_entry<W: Write + Seek>(
        &mut self,
        i: usize,
        out: &mut Output<W>,
        ahead: &mut Option<ReadAhead>,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        let want_torrentzip = self.want_torrentzip();
        let entry = &self.entry[i];
        let new_data = entry.data_changed()
            || entry.changed(changed::COMP_METHOD)
            || entry.changed(changed::ENCRYPTION_METHOD)
            || (want_torrentzip && !self.is_torrentzip());

        // create new local directory entry
        let entry = &mut self.entry[i];
        let data_changed = entry.data_changed();
        match (entry.changes.as_deref_mut(), entry.orig.as_deref()) {
            (None, orig) => entry.changes = Some(Box::new(Dirent::clone_changes(orig))),
            (Some(changes), Some(orig)) => changes.merge(orig, data_changed),
            (Some(_), None) => {}
        }

        let mut src = self.src.view_with(ahead.take());
        src.ensure_read_ahead();
        read_local_ef(&self.entry[i], &mut src)?;
        *ahead = src.take_read_ahead();

        if want_torrentzip && let Some(changes) = self.entry[i].changes.as_deref_mut() {
            changes.torrentzip_normalize();
        }

        if new_data {
            // The dirent is changed apart, and put back: the entry's
            // source is read through the archive meanwhile.
            let Some(mut de) = self.entry[i].changes.as_deref().cloned() else {
                return Err(Error::new(ErrorCode::Internal, 0));
            };
            de.offset = out.tell_write()?;

            let base = match &self.entry[i].source {
                Some(source) => Base::data(source.clone()),
                None => Base::Entry(Box::new(self.source_zip_file_create(
                    i as u64,
                    Flags::UNCHANGED,
                    0,
                    -1,
                    None,
                )?)),
            };
            let check_consistency = self.open_flags.intersects(OpenFlags::CHECKCONS);
            // add_data writes dirent
            let added = add_data(
                base,
                &mut de,
                out,
                want_torrentzip,
                check_consistency,
                self.default_password.as_deref(),
                self.random.as_ref(),
            );
            if let Some(changes) = self.entry[i].changes.as_deref_mut() {
                *changes = de;
            }
            return added;
        }

        let Archive { src, entry, .. } = self;
        let Entry { orig, changes, .. } = &mut entry[i];
        let Some(de) = changes.as_deref_mut() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };

        de.offset = out.tell_write()?;

        if de.encryption_method != em::TRAD_PKWARE {
            // when copying data, all sizes are known -> no data descriptor
            // needed, except for PKWare encryption, where removing the data
            // descriptor breaks password validation
            de.bitflags &= !GPBF_DATA_DESCRIPTOR;
        }
        de.write(out, Flags::LOCAL, want_torrentzip)?;

        // _zip_file_get_offset
        let Some(orig) = orig.as_deref() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        let mut src = src.view_with(ahead.take());
        src.ensure_read_ahead();
        let offset = file_get_offset(&mut src, orig.offset)?;
        src.seek(offset as i64, Whence::Set)?;
        copy_data(&mut src, out, de.comp_size, buf)?;
        *ahead = src.take_read_ahead();

        if de.bitflags & GPBF_DATA_DESCRIPTOR != 0 {
            write_data_descriptor(out, de, de.needs_zip64(Flags::NONE))?;
        }
        Ok(())
    }

    /// Writes the new entry `i`, its local header and the data `reader` gives,
    /// read once from its start, of which `stat` and `attributes` tell what is
    /// known beforehand: what [`Writer`](crate::zip::Writer) writes an entry with,
    /// as [`Archive::write_entry`] writes one of new data. Not in libzip.
    pub(crate) fn write_reader<W: Write + Seek>(
        &mut self,
        i: usize,
        reader: &mut dyn std::io::Read,
        stat: crate::zip::zip::Stat<'static>,
        attributes: crate::zip::source_data::FileAttributes,
        out: &mut Output<W>,
    ) -> Result<()> {
        let Some(mut de) = self.entry[i].changes.as_deref().cloned() else {
            return Err(Error::new(ErrorCode::Internal, 0));
        };
        de.offset = out.tell_write()?;
        let base: Base<'_, R> = Base::Reader {
            reader,
            stat,
            attributes,
            layer: crate::zip::source_stack::Layer::new(0),
        };
        let added = add_data(
            base,
            &mut de,
            out,
            false,
            self.open_flags.intersects(OpenFlags::CHECKCONS),
            self.default_password.as_deref(),
            self.random.as_ref(),
        );
        if let Some(changes) = self.entry[i].changes.as_deref_mut() {
            *changes = de;
        }
        added
    }

    /// Writes the central directory of the entries `filelist`, which are
    /// written: what [`Writer`](crate::zip::Writer) ends with.
    pub(crate) fn write_cdir_of<W: Write + Seek>(
        &mut self,
        filelist: &[usize],
        out: &mut Output<W>,
    ) -> Result<()> {
        write_cdir(self, filelist, out)?;
        out.commit_write()
    }

    /// Whether anything changed, and how many entries are not deleted:
    /// port of `_zip_changed`.
    pub(crate) fn changed(&self) -> (bool, u64) {
        let mut changed = self.comment_changed || (self.want_torrentzip() && !self.is_torrentzip());
        let mut survivors = 0;
        for entry in &self.entry {
            if entry.has_changes() {
                changed = true;
            }
            if !entry.deleted {
                survivors += 1;
            }
        }
        (changed, survivors)
    }
}

/// The order of names in a torrentzipped archive, ignoring ASCII case,
/// those that cannot be read first: port of `torrentzip_compare_names`,
/// with `strcasecmp`.
fn torrentzip_compare_names(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a), Some(b)) => a
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase)),
    }
}

/// Writes the local header of `de`, the data of `src` through the layers
/// that decrypt (with `default_password`), decompress, compute the CRC,
/// compress and encrypt it (with the entry's password or the default one,
/// and random bytes from `random`) as `de` asks, and the data descriptor
/// if it has one, and fills in what the data tells: port of `add_data`.
/// The header is written again once the sizes are known, if they changed
/// it.
fn add_data<R: ReadAt + ?Sized, W: Write + Seek>(
    src: Base<'_, R>,
    de: &mut Dirent,
    out: &mut Output<W>,
    want_torrentzip: bool,
    check_consistency: bool,
    default_password: Option<&[u8]>,
    random: Option<&RandomSource>,
) -> Result<()> {
    let mut st = src.stat()?;

    de.bitflags &= !GPBF_DATA_DESCRIPTOR;

    if st.valid & stat::COMP_METHOD == 0 {
        st.valid |= stat::COMP_METHOD;
        st.comp_method = cm::STORE;
    }

    if de.changed & changed::COMP_METHOD == 0 && st.comp_method != cm::STORE {
        de.comp_method = i32::from(st.comp_method);
    } else if de.comp_method == i32::from(cm::STORE) && st.valid & stat::SIZE != 0 {
        st.valid |= stat::COMP_SIZE;
        st.comp_size = st.size;
    } else {
        // we'll recompress
        st.valid &= !stat::COMP_SIZE;
    }

    if st.valid & stat::ENCRYPTION_METHOD == 0 {
        st.valid |= stat::ENCRYPTION_METHOD;
        st.encryption_method = em::NONE;
    }

    let mut flags = Flags::LOCAL;

    if st.valid & stat::CRC != 0 {
        de.crc = st.crc;
    }

    if st.valid & stat::SIZE == 0 {
        // TODO in libzip: not valid for torrentzip
        flags = flags | FL_FORCE_ZIP64;
    } else {
        de.uncomp_size = st.size;

        if st.valid & stat::COMP_SIZE == 0 {
            let compression_method = cm_actual(de.comp_method);
            let max_compressed_size = if compression_method == cm::STORE {
                st.size
            } else {
                maximum_compressed_size(compression_method, st.size).unwrap_or(u64::MAX)
            };
            if max_compressed_size > 0xffff_ffff {
                // TODO in libzip: not valid for torrentzip
                flags = flags | FL_FORCE_ZIP64;
            }
        } else {
            de.comp_size = st.comp_size;
        }
    }

    let mut have_dos_time = false;
    let mut mtime_before_copy = 0;
    if de.changed & changed::LAST_MOD == 0 {
        match src.dos_time()? {
            Some((time, date)) => {
                de.last_mod = DosTime { time, date };
                have_dos_time = true;
            }
            None => {
                mtime_before_copy = if st.valid & stat::MTIME != 0 {
                    st.mtime
                } else {
                    time_now()
                };
                de.last_mod = u2d_time(mtime_before_copy)?;
            }
        }
    }

    let offstart = out.tell_write()?;

    let needs_recompress = want_torrentzip || st.comp_method != cm_actual(de.comp_method);
    let needs_decompress = needs_recompress && st.comp_method != cm::STORE;
    // in these cases we can compute the CRC ourselves, so we do
    let needs_crc = st.comp_method == cm::STORE || needs_decompress;
    let needs_compress = needs_recompress && de.comp_method != i32::from(cm::STORE);

    let needs_reencrypt = needs_recompress
        || de.changed & changed::PASSWORD != 0
        || de.encryption_method != st.encryption_method;
    let needs_decrypt = needs_reencrypt && st.encryption_method != em::NONE;
    let needs_encrypt = needs_reencrypt && de.encryption_method != em::NONE;

    if !needs_decrypt
        && st.encryption_method == em::TRAD_PKWARE
        && de.changed & changed::LAST_MOD != 0
    {
        // PKWare encryption uses the last modification time for password
        // verification, therefore we can't change it without
        // re-encrypting. Ignoring the requested modification time change
        // seems more sensible than failing to close the archive.
        de.changed &= !changed::LAST_MOD;
    }

    let decrypt = match needs_decrypt {
        true => Some(Layer::new(Decrypt::new(
            st.encryption_method,
            default_password,
            &src.stat()?,
        )?)),
        false => None,
    };
    let decompress = match needs_decompress {
        true => Some(Layer::new(Decompress::new(
            st.comp_method,
            check_consistency,
        )?)),
        false => None,
    };
    let crc = needs_crc.then(|| Layer::new(Crc::new(false)));
    let compress = match needs_compress {
        true => Some(Layer::new(Compress::new(
            de.comp_method,
            de.compression_level,
        )?)),
        false => None,
    };
    let mut src_final = WriteStack {
        base: src,
        decrypt,
        decompress,
        crc,
        compress,
        encrypt: None,
    };

    if needs_encrypt {
        let password = de.password.as_deref().or(default_password);
        if !encryption_method_supported(de.encryption_method, true) {
            return Err(Error::new(ErrorCode::EncrNotSupp, 0));
        }
        let mut dostime = None;
        if de.encryption_method == em::TRAD_PKWARE {
            de.bitflags |= GPBF_DATA_DESCRIPTOR;
            // PKWare encryption uses last_mod, make sure it gets the right
            // value.
            if de.changed & changed::LAST_MOD != 0 {
                dostime = Some(de.last_mod);
            }
        }
        // zip_source_get_dos_time failing is as if there were no time.
        let dostime = dostime.or_else(|| {
            src_final
                .dos_time_below_encrypt()
                .ok()
                .flatten()
                .map(|(time, date)| DosTime { time, date })
        });
        let encrypt = Encrypt::new(
            de.encryption_method,
            password,
            dostime,
            || src_final.stat_below_encrypt(),
            random.cloned(),
        )?;
        src_final.encrypt = Some(Layer::new(encrypt));
    }

    let force_zip64 = flags.intersects(FL_FORCE_ZIP64);
    if !want_torrentzip {
        let attributes = src_final.file_attributes()?;
        de.apply_attributes(&attributes, force_zip64);
    }

    if out.stream {
        return add_data_forwards(src_final, de, out, flags, force_zip64);
    }

    // as long as we don't support non-seekable output, clear data
    // descriptor bit
    let is_zip64 = de.write(out, flags, want_torrentzip)?;

    let offdata = out.tell_write()?;

    let mut ret = copy_source(&mut src_final, out);

    let st = src_final.stat();
    if let Err(e) = st {
        ret = Err(e);
    }

    let attributes = if want_torrentzip {
        None
    } else {
        match src_final.file_attributes() {
            Ok(attributes) => Some(attributes),
            Err(e) => {
                ret = Err(e);
                None
            }
        }
    };

    drop(src_final);
    ret?;
    let st = st?;

    let offend = out.tell_write()?;

    if st.valid & (stat::COMP_METHOD | stat::CRC | stat::SIZE)
        != stat::COMP_METHOD | stat::CRC | stat::SIZE
    {
        return Err(Error::new(ErrorCode::Internal, 0));
    }

    let mut dirent_changed = cm_actual(de.comp_method) != st.comp_method
        || de.crc != st.crc
        || de.uncomp_size != st.size
        || de.comp_size != offend - offdata;
    de.comp_method = i32::from(st.comp_method);
    de.crc = st.crc;
    de.uncomp_size = st.size;
    de.comp_size = offend - offdata;

    if let Some(attributes) = attributes {
        dirent_changed |= de.apply_attributes(&attributes, force_zip64);

        if de.changed & changed::LAST_MOD == 0
            && !have_dos_time
            && st.valid & stat::MTIME != 0
            && st.mtime != mtime_before_copy
        {
            de.last_mod = u2d_time(st.mtime)?;
            dirent_changed = true;
        }
    }

    if dirent_changed {
        out.seek_write(offstart)?;

        if de.write(out, flags, want_torrentzip)? != is_zip64 {
            // Zip64 mismatch between preliminary file header written
            // before data and final file header written afterwards
            return Err(Error::new(ErrorCode::Internal, 0));
        }

        out.seek_write(offend)?;
    }

    if de.bitflags & GPBF_DATA_DESCRIPTOR != 0 {
        write_data_descriptor(out, de, is_zip64)?;
    }

    Ok(())
}

/// The rest of [`add_data`] where `out` goes only forwards: the local header cannot
/// be written again, so it says nothing the data tells, but for the method. Compressing
/// gives way to storing only in the first read, of data that fits in it, so that read
/// is made before the header is written; under encryption it does not give way.
fn add_data_forwards<R: ReadAt + ?Sized, W: Write + Seek>(
    mut src: WriteStack<'_, R>,
    de: &mut Dirent,
    out: &mut Output<W>,
    flags: Flags,
    force_zip64: bool,
) -> Result<()> {
    let mut buf = vec![0; BUFSIZE];
    // What encrypts it gives its own header first, which says nothing of the method.
    if src.encrypt.is_some()
        && let Some(compress) = &mut src.compress
    {
        compress.ctx.keep_compressing();
    }
    src.open()?;
    let mut flags = flags | FL_DATA_FOLLOWS;
    // Sizes known may say so, where the flag was not set for them.
    if de.needs_zip64(Flags::NONE) {
        flags = flags | FL_FORCE_ZIP64;
    }
    let copied = (|| {
        let first = src.read(&mut buf)?;
        let st = src.stat()?;
        de.comp_method = if st.valid & stat::COMP_METHOD != 0 {
            i32::from(st.comp_method)
        } else {
            i32::from(cm_actual(de.comp_method))
        };
        // What it asks of a reader goes by the method.
        de.apply_attributes(&src.file_attributes()?, force_zip64);
        de.bitflags |= GPBF_DATA_DESCRIPTOR;
        let is_zip64 = de.write(out, flags, false)?;
        let offdata = out.tell_write()?;
        let mut n = first;
        while n > 0 {
            out.write(&buf[..n])?;
            n = src.read(&mut buf)?;
        }
        Ok::<_, Error>((is_zip64, offdata))
    })();
    let _ = src.close();
    let (is_zip64, offdata) = copied?;
    let offend = out.tell_write()?;

    let st = src.stat()?;
    if st.valid & (stat::COMP_METHOD | stat::CRC | stat::SIZE)
        != stat::COMP_METHOD | stat::CRC | stat::SIZE
    {
        return Err(Error::new(ErrorCode::Internal, 0));
    }
    de.comp_method = i32::from(st.comp_method);
    de.crc = st.crc;
    de.uncomp_size = st.size;
    de.comp_size = offend - offdata;
    if !is_zip64 && de.needs_zip64(Flags::NONE) {
        // It came to more than its source said it could.
        return Err(Error::new(ErrorCode::Internal, 0));
    }
    let attributes = src.file_attributes()?;
    de.apply_attributes(&attributes, force_zip64);
    de.bitflags |= GPBF_DATA_DESCRIPTOR;
    if de.winzip_aes_version() == 2 {
        de.crc = 0;
    }
    write_data_descriptor(out, de, is_zip64)
}

/// Reads all of `src` into `out`, opening and closing it: port of
/// `copy_source`. Closing fails nothing.
fn copy_source<R: ReadAt + ?Sized, W: Write + Seek>(
    src: &mut WriteStack<'_, R>,
    out: &mut Output<W>,
) -> Result<()> {
    src.open()?;

    let mut buf = vec![0; BUFSIZE];
    let mut ret = Ok(());
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = out.write(&buf[..n]) {
                    ret = Err(e);
                    break;
                }
            }
            Err(e) => {
                ret = Err(e);
                break;
            }
        }
    }

    let _ = src.close();
    ret
}

/// Copies `len` bytes from `src` to `out`: port of `copy_data`.
fn copy_data<R: ReadAt + ?Sized, W: Write + Seek>(
    src: &mut Source<&R>,
    out: &mut Output<W>,
    len: u64,
    buf: &mut Vec<u8>,
) -> Result<()> {
    if len > 0 && buf.is_empty() {
        buf.resize(BUFSIZE, 0);
    }
    let mut len = len;
    while len > 0 {
        let n = len.min(BUFSIZE as u64) as usize;
        read(src, &mut buf[..n])?;
        out.write(&buf[..n])?;
        len -= n as u64;
    }
    Ok(())
}

/// Port of `write_cdir`.
fn write_cdir<R: ReadAt, W: Write + Seek>(
    za: &mut Archive<R>,
    filelist: &[usize],
    out: &mut Output<W>,
) -> Result<()> {
    za.cdir_write(filelist, out)?;
    Ok(())
}

/// Writes the data descriptor of `de`, with 64-bit sizes if `is_zip64`:
/// port of `write_data_descriptor`.
fn write_data_descriptor<W: Write + Seek>(
    out: &mut Output<W>,
    de: &Dirent,
    is_zip64: bool,
) -> Result<()> {
    let mut buffer = Buffer::with_size(MAX_DATA_DESCRIPTOR_LENGTH as usize);

    buffer.put(DATADES_MAGIC);
    buffer.put_32(de.crc);
    if is_zip64 {
        buffer.put_64(de.comp_size);
        buffer.put_64(de.uncomp_size);
    } else {
        buffer.put_32(de.comp_size as u32);
        buffer.put_32(de.uncomp_size as u32);
    }

    if !buffer.ok() {
        return Err(Error::new(ErrorCode::Internal, 0));
    }
    let len = buffer.offset() as usize;
    out.write(&buffer.data()[..len])
}
