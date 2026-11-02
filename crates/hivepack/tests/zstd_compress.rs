//! Compresses every file of the test data with the port and with libzstd
//! 1.5.7, through the same one-call API (`ZSTD_compressCCtx`), each with
//! one context used again for every frame, and compares the frames byte
//! for byte; then decodes the port's frame back with the port.
//!
//! At every level, both contexts compressing the same frames in the same
//! order.
//! Then again through `compress2`, with the blocks split after their
//! sequences (`ZSTD_c_splitAfterSequences`).
//! Then every file twice over with long distance matching, through
//! `ZSTD_compress2`.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use hivepack::zstd::{CCtx, CParameter as P, ParamSwitch};
use support::{Kind, Problems, Set};
use zstd::zstd_safe::{self, CParameter as C};

const LEVELS: [i32; 18] = [
    -5, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13, 16, 18, 19, 22,
];

fn sets() -> Vec<Set> {
    support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.present())
        // Benchmark inputs are too large for the tests; sources, tools and
        // other formats' vectors are not data.
        .filter(|set| {
            !matches!(
                set.kind,
                Kind::Bench | Kind::Source | Kind::Tool | Kind::Archives | Kind::Vectors
            )
        })
        .collect()
}

/// The two contexts, used again for every frame.
struct Contexts {
    libzstd: zstd_safe::CCtx<'static>,
    port: CCtx,
    /// Through `compress2`, with the block splitter after the sequences
    /// on, rather than in one call.
    split: bool,
}

impl Contexts {
    fn new() -> Self {
        Contexts {
            libzstd: zstd_safe::CCtx::create(),
            port: CCtx::new(),
            split: false,
        }
    }

    /// Contexts that split blocks after their sequences, through
    /// `compress2`.
    fn splitting() -> Self {
        let mut contexts = Contexts::new();
        contexts
            .libzstd
            .set_parameter(C::UseBlockSplitter(zstd_safe::ParamSwitch::Enable))
            .expect("libzstd sets it");
        contexts
            .port
            .set_parameter(P::SplitAfterSequences(ParamSwitch::Enable))
            .expect("the port sets it");
        contexts.split = true;
        contexts
    }

    /// `data` at `level` into `dst`, with the port.
    fn port_compress(
        &mut self,
        dst: &mut [u8],
        data: &[u8],
        level: i32,
    ) -> hivepack::zstd::Result<usize> {
        if !self.split {
            return self.port.compress(dst, data, level);
        }
        self.port.set_parameter(P::CompressionLevel(level))?;
        self.port.compress2(dst, data)
    }

    /// `data` at `level` into `dst`, with libzstd.
    fn libzstd_compress(
        &mut self,
        dst: &mut [u8],
        data: &[u8],
        level: i32,
    ) -> Result<usize, usize> {
        if !self.split {
            return self.libzstd.compress(dst, data, level);
        }
        self.libzstd.set_parameter(C::CompressionLevel(level))?;
        self.libzstd.compress2(dst, data)
    }
}

/// Compresses `data` with both, compares, and decodes back.
fn compare(
    problems: &mut Problems,
    cctx: &mut Contexts,
    name: &str,
    data: &[u8],
    level: i32,
) -> bool {
    // On big-endian machines libzstd's block splitter, which the strategies
    // from `greedy` up (from level 4) use on full blocks, hashes pairs of
    // bytes in the machine's order and splits elsewhere; the port gives
    // the same frames everywhere.
    if cfg!(target_endian = "big") && level >= 4 && data.len() >= 128 << 10 {
        return false;
    }
    let bound = hivepack::zstd::compress_bound(data.len()).expect("a bound");
    let mut got = vec![0u8; bound];
    let size = match cctx.port_compress(&mut got, data, level) {
        Ok(size) => size,
        Err(error) => {
            problems.add(format!("{name} at level {level}: {error}"));
            return false;
        }
    };
    let mut want = vec![0u8; bound];
    let want_size = cctx
        .libzstd_compress(&mut want, data, level)
        .expect("libzstd compresses");
    want.truncate(want_size);
    if got[..size] != want[..] {
        let at = got[..size]
            .iter()
            .zip(&want)
            .position(|(a, b)| a != b)
            .unwrap_or(size.min(want.len()));
        problems.add(format!(
            "{name} at level {level}: {size} bytes, libzstd {}, first difference at {at}",
            want.len()
        ));
        return true;
    }
    let mut back = vec![0u8; data.len()];
    match hivepack::zstd::decompress(&mut back, &got[..size]) {
        Ok(n) if back[..n] == *data => {}
        other => problems.add(format!(
            "{name} at level {level}: does not decode back ({:?})",
            other.map(|_| ())
        )),
    }
    true
}

#[test]
fn every_test_file_compresses_as_libzstd_compresses_it() {
    let mut problems = Problems::default();
    let mut cctx = Contexts::new();
    let mut count = 0;
    for set in sets() {
        for (i, file) in set.list().iter().enumerate() {
            let data = set.read(file);
            let name = format!("{}/{}", set.name, file.display());
            // Two levels per file, all of them across the files.
            for level in [LEVELS[i % LEVELS.len()], LEVELS[(i + 3) % LEVELS.len()]] {
                count += usize::from(compare(&mut problems, &mut cctx, &name, &data, level));
            }
        }
    }
    eprintln!("compared {count} frames");
    // The committed sets alone have more than 300 files; on big-endian
    // machines the levels from 4 are left out for large files (see
    // `compare`).
    let least = if cfg!(target_endian = "big") {
        300
    } else {
        500
    };
    assert!(count > least, "only {count} frames compared");
    problems.check();
}

/// The block splitter after the sequences, on for every strategy, through
/// `compress2`: one level per file, all of them across the files.
#[test]
fn every_test_file_splits_its_blocks_as_libzstd_splits_them() {
    let mut problems = Problems::default();
    let mut cctx = Contexts::splitting();
    let mut count = 0;
    for set in sets() {
        for (i, file) in set.list().iter().enumerate() {
            let data = set.read(file);
            let name = format!("{}/{} (split)", set.name, file.display());
            let level = LEVELS[(i + 7) % LEVELS.len()];
            count += usize::from(compare(&mut problems, &mut cctx, &name, &data, level));
        }
    }
    eprintln!("compared {count} frames");
    let least = if cfg!(target_endian = "big") {
        150
    } else {
        250
    };
    assert!(count > least, "only {count} frames compared");
    problems.check();
}

/// Every file of the test data twice over, with long distance matching on,
/// through `ZSTD_compress2`: the second copy is one long match with the
/// first. One level per file, all of them across the files; every other
/// file with small parameters, so that it finds more.
#[test]
fn every_test_file_twice_compresses_with_long_distance_matching_as_libzstd() {
    use hivepack::zstd::{CParameter as P, ParamSwitch};
    use zstd_safe::CParameter as C;
    let mut problems = Problems::default();
    let mut cctx = Contexts::new();
    let set_both = |cctx: &mut Contexts, (p, c): (P, C)| {
        cctx.port.set_parameter(p).expect("the port takes it");
        cctx.libzstd.set_parameter(c).expect("libzstd takes it");
    };
    set_both(
        &mut cctx,
        (
            P::EnableLongDistanceMatching(ParamSwitch::Enable),
            C::EnableLongDistanceMatching(true),
        ),
    );
    let mut count = 0;
    for set in sets() {
        for (i, file) in set.list().iter().enumerate() {
            let mut data = set.read(file);
            data.extend_from_within(..);
            let name = format!("{}/{} twice", set.name, file.display());
            let level = LEVELS[(i + 5) % LEVELS.len()];
            let (min_match, hash_rate_log) = if i % 2 == 0 { (16, 4) } else { (0, 0) };
            set_both(
                &mut cctx,
                (P::CompressionLevel(level), C::CompressionLevel(level)),
            );
            set_both(
                &mut cctx,
                (P::LdmMinMatch(min_match), C::LdmMinMatch(min_match)),
            );
            set_both(
                &mut cctx,
                (
                    P::LdmHashRateLog(hash_rate_log),
                    C::LdmHashRateLog(hash_rate_log),
                ),
            );
            // On big-endian machines, see `compare`.
            if cfg!(target_endian = "big") && level >= 4 && data.len() >= 128 << 10 {
                continue;
            }
            let bound = hivepack::zstd::compress_bound(data.len()).expect("a bound");
            let mut got = vec![0u8; bound];
            let size = match cctx.port.compress2(&mut got, &data) {
                Ok(size) => size,
                Err(error) => {
                    problems.add(format!("{name} at level {level}: {error}"));
                    continue;
                }
            };
            let mut want = vec![0u8; bound];
            let want_size = cctx
                .libzstd
                .compress2(&mut want[..], &data)
                .expect("libzstd compresses");
            count += 1;
            if got[..size] != want[..want_size] {
                problems.add(format!(
                    "{name} at level {level}: {size} bytes, libzstd {want_size}"
                ));
                continue;
            }
            let mut back = vec![0u8; data.len()];
            match hivepack::zstd::decompress(&mut back, &got[..size]) {
                Ok(n) if back[..n] == *data => {}
                other => problems.add(format!(
                    "{name} at level {level}: does not decode back ({:?})",
                    other.map(|_| ())
                )),
            }
        }
    }
    eprintln!("compared {count} frames");
    assert!(count > 200, "only {count} frames compared");
    problems.check();
}

#[test]
fn small_inputs_compress_as_libzstd_compresses_them() {
    // Every size up to 300 bytes, of one byte repeated and of text, where
    // blocks are raw, RLE, or too small to compress; in one call, and with
    // the block splitter after the sequences.
    let mut problems = Problems::default();
    let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod \
        tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis \
        nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute \
        irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla.";
    for mut cctx in [Contexts::new(), Contexts::splitting()] {
        let split = if cctx.split { " (split)" } else { "" };
        for len in 0..=300 {
            for level in LEVELS {
                let data = vec![b'a'; len];
                compare(
                    &mut problems,
                    &mut cctx,
                    &format!("{len} a{split}"),
                    &data,
                    level,
                );
                let data: Vec<u8> = text.iter().copied().cycle().take(len).collect();
                compare(
                    &mut problems,
                    &mut cctx,
                    &format!("{len} of text{split}"),
                    &data,
                    level,
                );
            }
        }
    }
    problems.check();
}

#[test]
fn compression_fails_as_libzstd_fails() {
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut cctx = CCtx::new();
    for capacity in [0, 1, 5, 17, 18, 21, 100, 1000] {
        let mut want = vec![0u8; capacity];
        let want = zstd::zstd_safe::compress(&mut want[..], &data, 1)
            .map_err(|code| zstd::zstd_safe::get_error_name(code).to_string());
        let mut got = vec![0u8; capacity];
        let got = cctx
            .compress(&mut got, &data, 1)
            .map_err(|error| error.code().message().to_string());
        assert_eq!(got, want, "room for {capacity} bytes");
    }
    // Levels beyond the bounds are clamped, as libzstd clamps them.
    for level in [i32::MIN, -1_000_000, 1_000_000] {
        let mut want = vec![0u8; 1 << 16];
        let want =
            zstd::zstd_safe::compress(&mut want[..], &data, level).map(|n| want[..n].to_vec());
        let mut got = vec![0u8; 1 << 16];
        let got = cctx
            .compress(&mut got, &data, level)
            .map(|n| got[..n].to_vec());
        match (got, want) {
            (Ok(got), Ok(want)) => assert_eq!(got, want, "level {level}"),
            (got, want) => panic!("level {level}: port {got:?}, libzstd {want:?}"),
        }
    }
    assert_eq!(hivepack::zstd::default_c_level(), 3);
    assert_eq!(
        hivepack::zstd::max_c_level(),
        zstd::zstd_safe::max_c_level()
    );
    assert_eq!(
        hivepack::zstd::min_c_level(),
        zstd::zstd_safe::min_c_level()
    );
}
