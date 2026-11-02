//! hivepack::udf on any image: the input describes it sparsely, so that a
//! few kilobytes reach the anchors at sector 256 and past. Its first byte
//! picks the sector size (512 to 4096) and whether hidden entries are
//! listed; its next three, the number of sectors (up to 2^16); then come
//! sectors, each its number (32 bits), how many bytes it has (16 bits) and
//! those, the rest zeros. Absent sectors are zeros, and later ones replace
//! earlier ones.
//!
//! The volume is mounted and walked twice: every directory listed, every
//! node's attributes, every link's target, up to 1 MiB of every file, and
//! the first 16 names of each directory looked up in it. Both walks must
//! give the same transcript, each name looked up must be found when its
//! directory reads whole, and a panic is a bug (`crates/udf/tests` compares
//! the answers with Linux).

#![no_main]

#[path = "udf_image.rs"]
mod udf_image;

use std::io::Read;

use hivepack::udf::{Node, Options, Udf, VType};
use libfuzzer_sys::fuzz_target;
use udf_image::Sparse;

const MAX_DATA: usize = 1 << 20;
const MAX_NODES: usize = 4096;
/// The entries of a directory looked up: each reads the whole directory.
const MAX_LOOKUPS: usize = 16;

/// The volume, walked: one line per thing seen.
fn walk(data: &[u8]) -> Vec<String> {
    let Some(image) = Sparse::new(data) else {
        return Vec::new();
    };
    let options = Options {
        sector_size: Some(image.sector_size as u32),
        unhide: data[0] & 4 != 0,
        ..Options::default()
    };
    let mut udf = match Udf::with_options(image, &options) {
        Ok(udf) => udf,
        Err(e) => return vec![e.to_string()],
    };
    let mut out = vec![format!("{:?}", udf.volume())];
    let mut dirs: Vec<Node> = vec![udf.root().clone()];
    let mut seen = 0;
    while let Some(dir) = dirs.pop() {
        let mut entries = Vec::new();
        let mut whole = true;
        match udf.read_dir(&dir) {
            Ok(list) => {
                for entry in list {
                    match entry {
                        Ok(entry) => entries.push(entry),
                        Err(e) => {
                            out.push(e.to_string());
                            whole = false;
                        }
                    }
                }
            }
            Err(e) => {
                out.push(e.to_string());
                continue;
            }
        }
        for (i, entry) in entries.into_iter().enumerate() {
            out.push(format!("{entry:?}"));
            if whole && i < MAX_LOOKUPS {
                let found = udf.lookup(&dir, &entry.name);
                assert!(!matches!(found, Ok(None)), "{entry:?} listed but not found");
            }
            if entry.is_parent() {
                continue;
            }
            seen += 1;
            if seen > MAX_NODES {
                return out;
            }
            let node = match udf.node(entry.icb) {
                Ok(node) => node,
                Err(e) => {
                    out.push(e.to_string());
                    continue;
                }
            };
            out.push(format!("{:?}", udf.stat(&node)));
            match node.kind() {
                VType::VDIR => dirs.push(node),
                VType::VLNK => out.push(format!("{:?}", udf.read_link(&node))),
                VType::VREG => {
                    let mut buf = Vec::new();
                    let r = udf.file(&node).take(MAX_DATA as u64).read_to_end(&mut buf);
                    out.push(format!("{} {:?}", buf.len(), r.map_err(|e| e.to_string())));
                }
                _ => {}
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(walk(data), walk(data));
});
