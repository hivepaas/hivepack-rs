//! hivepack::open on any input: after a first byte that picks a name (none,
//! or one ending in `.lzma`), the bytes are a file, opened through its
//! layers with the X25519 identity of the files `crates/hivepack/tests/open_age.rs`
//! records, under small limits (four layers, 16 MiB zstd windows, 64 MiB
//! for liblzma), and up to 4 MiB of what is under them read.
//!
//! The file is opened three times by one opener, the later times with the
//! file keys kept from the first, and read in pieces of different sizes:
//! each must find the same layers and container, and end the same way,
//! with the same data, or, after a failure, data of which one is the start
//! of the other: what libzstd gives out before an error depends on the
//! size of its output buffer. Opened again with three threads, which
//! decode xz's Blocks, bzip2's streams and blocks and pbzx's chunks, it
//! must end the same way, with the same data or its start. A panic is a
//! bug.

#![no_main]

use std::io::{Cursor, Read};

use hivepack::age::{BoxedIdentity, X25519Identity};
use hivepack::Threads;
use hivepack::open::{Limits, Opener};
use libfuzzer_sys::fuzz_target;

const KEY: &str = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";

const MAX_DATA: usize = 4 << 20;

/// What an open found, the data read, and how it ended.
fn read<F: FnMut() -> std::io::Result<Cursor<Vec<u8>>>>(
    opener: &mut Opener<F>,
    mut seed: u64,
) -> (String, Vec<u8>, String) {
    let mut opened = match opener.open() {
        Ok(opened) => opened,
        Err(e) => return (String::new(), Vec::new(), e.to_string()),
    };
    let found = format!("{:?} {:?}", opened.layers(), opened.container());
    let mut out = Vec::new();
    while out.len() < MAX_DATA {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let mut buf = vec![0; (1 + (seed >> 47) as usize).min(MAX_DATA - out.len())];
        match opened.read(&mut buf) {
            Ok(0) => return (found, out, "end".into()),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (found, out, e.to_string()),
        }
    }
    (found, out, "-".into())
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, file)) = data.split_first() else {
        return;
    };
    let mut limits = Limits::default();
    limits.max_layers = 4;
    limits.zstd_window_log_max = 24;
    limits.xz_memlimit = 64 << 20;
    let identities: Vec<BoxedIdentity> = vec![Box::new(X25519Identity::parse(KEY).unwrap())];
    let mut opener = Opener::new(|| Ok(Cursor::new(file.to_vec())))
        .identities(identities)
        .limits(limits);
    if mode & 1 == 1 {
        opener = opener.name("archive.tar.lzma");
    }
    let seed = file.iter().take(8).fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let first = read(&mut opener, seed);
    let mut threaded = Opener::new(|| Ok(Cursor::new(file.to_vec())))
        .identities(vec![Box::new(X25519Identity::parse(KEY).unwrap())])
        .limits(limits)
        .threads(Threads::of(3));
    if mode & 1 == 1 {
        threaded = threaded.name("archive.tar.lzma");
    }
    let threaded = read(&mut threaded, seed.rotate_left(29));
    for again in [read(&mut opener, !seed), read(&mut opener, seed.rotate_left(17)), threaded] {
        assert_eq!((&again.0, &again.2), (&first.0, &first.2));
        if first.2 == "end" || first.2 == "-" {
            assert!(again.1 == first.1);
        } else {
            let n = again.1.len().min(first.1.len());
            assert!(again.1[..n] == first.1[..n]);
        }
    }
});
