//! hivepack::wim on any input: the archive's header, its table of
//! resources, the XML that names its images, and every image's tree walked
//! whole with each file read.
//!
//! Everything is done twice and the two must agree: what an archive holds
//! does not depend on the order it was asked for. A panic is a bug, and so
//! is a disagreement.
//!
//! The caps are what keep a crafted archive from being answered for ever:
//! up to 8 images, 4096 entries of each and 4 MiB of data altogether,
//! which the reader's own limits (a tree of at most 2^22 entries, 256 MiB
//! of metadata, a depth of 1024) sit inside.

#![no_main]

use std::io::Cursor;

use hivepack::wim::{Entry, Wim};
use libfuzzer_sys::fuzz_target;

const MOST_IMAGES: usize = 8;
const MOST_ENTRIES: usize = 4096;
const MOST_DATA: usize = 4 << 20;

/// What one image holds: every entry as it reads, with what each file
/// holds or why it would not read.
fn image(wim: &mut Wim<Cursor<&[u8]>>, index: u32) -> Vec<(String, u64, Vec<u8>, Option<String>)> {
    let entries = match wim.entries(index) {
        Ok(entries) => entries,
        Err(e) => return vec![(String::new(), 0, Vec::new(), Some(e.to_string()))],
    };
    let mut found = Vec::new();
    let mut read = 0usize;
    for entry in entries.iter().take(MOST_ENTRIES) {
        let mut body = Vec::new();
        let mut ended = None;
        if entry.is_file() && read < MOST_DATA {
            match wim.read(entry) {
                Ok(bytes) => {
                    read += bytes.len();
                    body = bytes;
                }
                Err(e) => ended = Some(e.to_string()),
            }
        }
        found.push((entry.path.clone(), entry.size, body, ended));
        let _ = look(entry);
    }
    found
}

/// Every field of an entry, touched so that none of them can panic on its
/// own.
fn look(entry: &Entry) -> String {
    format!(
        "{} {} {:?} {} {:?} {:?} {:?} {:?} {:?} {} {} {} {} {:#x} {:?} {:?} {:?} {}",
        entry.path,
        entry.name,
        entry.short_name,
        entry.size,
        entry.hash,
        entry.created,
        entry.accessed,
        entry.modified,
        entry.unix_mode,
        entry.read_only,
        entry.hidden,
        entry.system,
        entry.archive,
        entry.attributes,
        entry.reparse_tag,
        entry.hard_link_group,
        entry.is_reparse_point(),
        entry.extra_streams,
    )
}

/// What the whole archive holds, as it reads.
fn whole(data: &[u8]) -> Option<Vec<Vec<(String, u64, Vec<u8>, Option<String>)>>> {
    let mut wim = Wim::open(Cursor::new(data)).ok()?;
    let _ = (wim.compression(), wim.chunk_size(), wim.resources());
    let images: Vec<u32> = wim
        .images()
        .iter()
        .take(MOST_IMAGES)
        .map(|image| image.index)
        .collect();
    Some(images.into_iter().map(|index| image(&mut wim, index)).collect())
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(whole(data), whole(data));
});
