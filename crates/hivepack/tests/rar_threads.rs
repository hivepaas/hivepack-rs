//! RAR 5's blocks decoded in threads (`Extract::threads`): what comes out of
//! every entry is what one thread gives, byte for byte, with the same hash
//! check, the same errors and the same exit code: on the archives at hand,
//! whole and with bytes of their data changed, and on data that is not
//! RAR's, as the `rar_unpack` target fuzzes it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

#[path = "rar_support/patch.rs"]
#[allow(dead_code)]
mod patch;

use std::path::{Path, PathBuf};

use hivepack::rar::{Archive, Extract};

/// What comes out of each entry of `data`, with `threads`: its bytes, and
/// whether it is broken; then what went wrong, and the exit code.
fn read(data: &[u8], password: &str, threads: u32) -> String {
    let Ok(mut arc) = Archive::open_with_password(data, true, password) else {
        return "does not open".into();
    };
    let mut extract = Extract::new();
    extract.threads = threads;
    extract.threads_from = 0;
    let mut out = String::new();
    for _ in 0..10_000 {
        let size = match arc.read_header() {
            Ok(size) => size,
            Err(e) => {
                out.push_str(&format!("header: {e}\n"));
                break;
            }
        };
        let mut bytes = Vec::new();
        let go = extract.current_file(&mut arc, size, &mut |data| {
            bytes.extend_from_slice(data);
            Ok(())
        });
        // FNV-1a.
        let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
        out.push_str(&format!(
            "{} bytes {hash:x}, broken {}\n",
            bytes.len(),
            extract.broken_file
        ));
        match go {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => {
                out.push_str(&format!("error: {e}\n"));
                break;
            }
        }
    }
    out.push_str(&format!("{:?}", arc.exit_code()));
    out
}

fn the_same(label: &str, data: &[u8], password: &str) {
    let one = read(data, password, 1);
    for threads in [2, 3, 8] {
        assert_eq!(
            read(data, password, threads),
            one,
            "{label} with {threads} threads"
        );
    }
}

fn walk(folder: &Path, found: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else if path.extension().is_some_and(|e| e == "rar") {
            found.push(path);
        }
    }
}

/// The repository's archives, and the other projects' when fetched.
fn archives() -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rar"),
        &mut found,
    );
    let root = support::testdata();
    for set in [
        "libarchive-rar",
        "rarfile-tests",
        "junrar-tests",
        "unrar-rs-tests",
    ] {
        walk(&root.join(set), &mut found);
    }
    found.sort();
    found
}

#[test]
fn archives_come_out_the_same() {
    for path in archives() {
        let data = std::fs::read(&path).unwrap();
        the_same(&path.to_string_lossy(), &data, "hivepack");
    }
}

/// Bytes of the packed data changed, one at a time, here and there: damage
/// takes the blocks elsewhere than their headers say, breaks tables, and
/// runs past the data's end.
#[test]
fn damaged_archives_come_out_the_same() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/rar");
    for name in [
        "rar5-m1.rar",
        "rar5-m3.rar",
        "rar5-m5.rar",
        "rar5-m3-solid.rar",
    ] {
        let data = std::fs::read(root.join(name)).unwrap();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..24 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let mut damaged = data.clone();
            // Past the headers at the start, before the end's.
            let at = 2000 + (seed as usize) % (data.len() - 4000);
            damaged[at] ^= 1 << (seed >> 61);
            if round % 3 == 0 {
                damaged.truncate(at + 1);
            }
            the_same(&format!("{name}, byte {at}, round {round}"), &damaged, "");
        }
    }
}

/// What the `rar_unpack` target makes of bytes: RAR 5 and 7's algorithm,
/// long distances, every filter, damaged anywhere.
#[test]
fn packed_data_of_any_bytes_comes_out_the_same() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for round in 0..300 {
        let len = 64 + round * 37 % 5000;
        let mut input = Vec::with_capacity(len);
        for _ in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            input.push(seed as u8);
        }
        // RAR 5's algorithm.
        input[0] |= 1;
        input[0] &= !0x10;
        let data = patch::with_packed_data(&input);
        the_same(&format!("round {round}"), &data, "");
    }
}
