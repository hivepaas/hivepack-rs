//! Opens the input as a ZIP archive with hivepack::zip, leniently and with
//! `ZIP_CHECKCONS`, asks everything the reading API answers about each
//! entry, and reads each entry's data, decompressed and raw, in pieces, and
//! decrypted with the password "foo", which some of the recorded archives
//! are encrypted with. A panic is a bug. libzip is not built here:
//! `crates/hivepack/tests/zip_oracle.rs` compares the answers with it through the
//! oracle.

#![no_main]

use hivepack::zip::{Archive, ArchiveFlags, Flags, OpenFlags, ReadAt, em};
use libfuzzer_sys::fuzz_target;

/// Reads entry `i` to its end, in pieces of growing sizes, and closes it.
fn read_all<R: ReadAt>(za: &Archive<R>, i: u64, flags: Flags, password: Option<&[u8]>) {
    let Ok(mut zf) = za.fopen_index_encrypted(i, flags, password) else { return };
    let mut buf = vec![0u8; 70_000];
    let mut piece = 1;
    // A bound on the work: the data of an entry can be large.
    for _ in 0..200 {
        match zf.fread(&mut buf[..piece]) {
            Ok(0) | Err(_) => break,
            Ok(_) => piece = (piece * 3).min(buf.len()),
        }
    }
    let _ = zf.fclose();
}

fuzz_target!(|data: &[u8]| {
    for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
        let Ok(za) = Archive::open(data, flags) else { continue };
        let _ = za.get_archive_flag(ArchiveFlags::IS_TORRENTZIP, Flags::NONE);
        let _ = za.get_archive_comment(Flags::NONE);
        let _ = za.get_archive_comment(Flags::ENC_STRICT);
        for i in 0..za.get_num_entries(Flags::NONE) {
            for flags in [Flags::NONE, Flags::ENC_RAW, Flags::ENC_STRICT] {
                let _ = za.get_name(i, flags);
                let _ = za.file_get_comment(i, flags);
            }
            let _ = za.stat_index(i, Flags::NONE);
            let _ = za.file_get_external_attributes(i, Flags::NONE);
            for flags in [Flags::CENTRAL, Flags::LOCAL, Flags::CENTRAL | Flags::LOCAL] {
                let count = za.file_extra_fields_count(i, flags).unwrap_or(0);
                for j in 0..count.max(0) as u16 + 1 {
                    let _ = za.file_extra_field_get(i, j, flags);
                }
            }
            let _ = za.file_get_offset(i);
            for flags in [Flags::NONE, Flags::COMPRESSED] {
                read_all(&za, i, flags, None);
            }
            if za.stat_index(i, Flags::NONE).is_ok_and(|st| st.encryption_method != em::NONE) {
                read_all(&za, i, Flags::NONE, Some(b"foo"));
            }
            if let Ok(name) = za.get_name(i, Flags::NONE) {
                let name = name.to_vec();
                for flags in [Flags::NONE, Flags::NOCASE, Flags::NODIR, Flags::ENC_RAW, Flags::ENC_STRICT, Flags::ENC_CP437] {
                    let _ = za.name_locate(&name, flags);
                }
            }
        }
    }
});
