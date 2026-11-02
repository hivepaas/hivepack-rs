//! Decompresses every file in the test data with the port and with libzstd
//! 1.5.7, through the same one-call API, and compares: the output must be
//! identical, and a failure must be the same error.
//!
//! libzstd is called as `ZSTD_decompressDCtx` (and `_usingDict`,
//! `_usingDDict`) with the same output capacity the port gets. The frame
//! information functions (`ZSTD_getFrameContentSize`,
//! `ZSTD_findFrameCompressedSize`, ...) are compared on every file too.
//!
//! The port behaves as libzstd does on 64-bit little-endian machines. On
//! others libzstd itself differs: on 32-bit ones it takes windows up to
//! 2^30 only, and both there and on big-endian ones it checks damaged
//! Huffman input with other loops. There only what libzstd decodes is
//! compared.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::path::Path;

use support::{Kind, Problems, Set};
use zstd::zstd_safe;

/// How much output to allow: what libzstd says the frames decode to, or a
/// bound on it, capped; the same for both sides.
fn capacity(src: &[u8]) -> usize {
    const CAP: u64 = 64 << 20;
    match zstd_safe::find_decompressed_size(src) {
        Ok(Some(size)) if size <= CAP => size as usize,
        _ => match zstd_safe::decompress_bound(src) {
            Ok(bound) if bound <= CAP => bound as usize,
            _ => 1 << 20,
        },
    }
}

/// Whether libzstd here behaves as the port does everywhere.
const SAME_AS_LIBZSTD: bool = cfg!(all(target_pointer_width = "64", target_endian = "little"));

/// An outcome, comparable across the two: the output, or the error's name.
#[derive(PartialEq, Eq)]
enum Outcome {
    Decoded(Vec<u8>),
    Failed(String),
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Decoded(output) => write!(f, "{} bytes", output.len()),
            Outcome::Failed(name) => write!(f, "error: {name}"),
        }
    }
}

enum Dict<'a> {
    None,
    /// Raw dictionary bytes, read anew for each frame.
    Raw(&'a [u8]),
    /// Prepared once.
    Prepared(&'a [u8]),
}

fn libzstd(src: &[u8], dict: &Dict<'_>) -> Outcome {
    let mut out = Vec::with_capacity(capacity(src));
    let mut dctx = zstd_safe::DCtx::create();
    let result = match dict {
        Dict::None => dctx.decompress(&mut out, src),
        Dict::Raw(dict) => dctx.decompress_using_dict(&mut out, src, dict),
        Dict::Prepared(dict) => {
            let ddict = zstd_safe::DDict::create(dict);
            dctx.decompress_using_ddict(&mut out, src, &ddict)
        }
    };
    match result {
        Ok(size) => {
            out.truncate(size);
            Outcome::Decoded(out)
        }
        Err(code) => Outcome::Failed(zstd_safe::get_error_name(code).to_string()),
    }
}

fn port(src: &[u8], dict: &Dict<'_>) -> Outcome {
    let mut out = vec![0; capacity(src)];
    let mut dctx = hivepack::zstd::DCtx::new();
    let result = match dict {
        Dict::None => dctx.decompress(&mut out, src),
        Dict::Raw(dict) => dctx.decompress_using_dict(&mut out, src, dict),
        Dict::Prepared(dict) => match hivepack::zstd::DDict::new(dict) {
            Ok(ddict) => dctx.decompress_using_ddict(&mut out, src, &ddict),
            // libzstd's DDict creation returns NULL, and a NULL DDict means
            // no dictionary.
            Err(_) => dctx.decompress(&mut out, src),
        },
    };
    match result {
        Ok(size) => {
            out.truncate(size);
            Outcome::Decoded(out)
        }
        Err(error) => Outcome::Failed(error.code().message().to_string()),
    }
}

/// The frame information libzstd and the port give, as text.
fn info_libzstd(src: &[u8]) -> String {
    let fcs = match zstd_safe::get_frame_content_size(src) {
        Ok(Some(size)) => format!("{size}"),
        Ok(None) => "unknown".into(),
        Err(_) => "error".into(),
    };
    let fds = match zstd_safe::find_decompressed_size(src) {
        Ok(Some(size)) => format!("{size}"),
        Ok(None) => "unknown".into(),
        Err(_) => "error".into(),
    };
    let ffcs = match zstd_safe::find_frame_compressed_size(src) {
        Ok(size) => format!("{size}"),
        Err(code) => zstd_safe::get_error_name(code).to_string(),
    };
    let bound = match zstd_safe::decompress_bound(src) {
        Ok(bound) => format!("{bound}"),
        // zstd-safe calls every value ZSTD_isError flags an error, so bounds
        // within 120 of 2^64 come back here; libzstd's only error is
        // ZSTD_CONTENTSIZE_ERROR.
        Err(raw) if raw as u64 != u64::MAX - 1 => format!("{raw}"),
        Err(_) => "error".into(),
    };
    let dict_id = zstd_safe::get_dict_id_from_frame(src).map_or(0, |id| id.get());
    format!("fcs {fcs} fds {fds} ffcs {ffcs} bound {bound} dict {dict_id}")
}

fn info_port(src: &[u8]) -> String {
    use hivepack::zstd::ContentSize;
    let show = |size| match size {
        ContentSize::Known(size) => format!("{size}"),
        ContentSize::Unknown => "unknown".into(),
        ContentSize::Error => "error".into(),
    };
    let ffcs = match hivepack::zstd::find_frame_compressed_size(src) {
        Ok(size) => format!("{size}"),
        Err(error) => error.code().message().to_string(),
    };
    let bound = match hivepack::zstd::decompress_bound(src) {
        Some(bound) => format!("{bound}"),
        None => "error".into(),
    };
    format!(
        "fcs {} fds {} ffcs {ffcs} bound {bound} dict {}",
        show(hivepack::zstd::get_frame_content_size(src)),
        show(hivepack::zstd::find_decompressed_size(src)),
        hivepack::zstd::get_dict_id_from_frame(src)
    )
}

/// Compares one input both ways, noting any difference.
fn compare(problems: &mut Problems, name: &str, src: &[u8], dict: &Dict<'_>) {
    let want = libzstd(src, dict);
    if !SAME_AS_LIBZSTD && !matches!(want, Outcome::Decoded(_)) {
        return;
    }
    let got = port(src, dict);
    if got != want {
        problems.add(format!("{name}: libzstd {want:?}, port {got:?}"));
    }
    if !SAME_AS_LIBZSTD {
        return;
    }
    let (want, got) = (info_libzstd(src), info_port(src));
    if got != want {
        problems.add(format!("{name}: libzstd {want}, port {got}"));
    }
}

fn sets() -> Vec<Set> {
    support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.present())
        .collect()
}

/// The files of a set that are inputs to decode: frames, damaged frames, or
/// anything a fuzzer found.
fn decodable(set: &Set) -> Vec<std::path::PathBuf> {
    match set.kind {
        Kind::Frames | Kind::BadFrames | Kind::DictFrames => set.frames(),
        Kind::Fuzz => set.list(),
        _ => Vec::new(),
    }
}

#[test]
fn every_test_file_decodes_as_libzstd_decodes_it() {
    let mut problems = Problems::default();
    let mut count = 0;
    for set in sets() {
        if set.kind == Kind::DictFrames {
            continue;
        }
        let dictionary = set.dictionary.as_ref().map(|d| set.read(Path::new(d)));
        for file in decodable(&set) {
            let src = set.read(&file);
            let name = format!("{}/{}", set.name, file.display());
            match &dictionary {
                None => compare(&mut problems, &name, &src, &Dict::None),
                Some(dictionary) => {
                    compare(&mut problems, &name, &src, &Dict::Raw(dictionary));
                    compare(
                        &mut problems,
                        &format!("{name} (DDict)"),
                        &src,
                        &Dict::Prepared(dictionary),
                    );
                }
            }
            count += 1;
        }
    }
    eprintln!("compared {count} files");
    // The committed sets alone have 306.
    assert!(count > 200);
    problems.check();
}

#[test]
fn frames_decode_with_the_dictionary_they_name_as_libzstd_does() {
    let mut problems = Problems::default();
    for set in sets().into_iter().filter(|s| s.kind == Kind::DictFrames) {
        let dictionaries: Vec<Vec<u8>> = set
            .list()
            .into_iter()
            .filter(|f| f.extension() == Some("dict".as_ref()))
            .map(|f| set.read(&f))
            .collect();
        for file in set.frames() {
            let src = set.read(&file);
            let wanted = hivepack::zstd::get_dict_id_from_frame(&src);
            let dictionary = dictionaries
                .iter()
                .find(|d| hivepack::zstd::get_dict_id_from_dict(d) == wanted);
            let name = format!("{}/{}", set.name, file.display());
            match dictionary {
                Some(dictionary) => {
                    compare(&mut problems, &name, &src, &Dict::Raw(dictionary));
                    compare(
                        &mut problems,
                        &format!("{name} (DDict)"),
                        &src,
                        &Dict::Prepared(dictionary),
                    );
                }
                None => compare(&mut problems, &name, &src, &Dict::None),
            }
        }
    }
    problems.check();
}

#[test]
fn inputs_compressed_by_libzstd_decode_back() {
    let mut problems = Problems::default();
    for set in sets().into_iter().filter(|s| s.kind == Kind::Inputs) {
        for file in set.list() {
            let input = set.read(&file);
            for level in [-5, 1, 3, 19] {
                let frame = zstd::bulk::compress(&input, level).expect("libzstd compresses");
                let mut out = vec![0; input.len()];
                match hivepack::zstd::decompress(&mut out, &frame) {
                    Ok(size) if out[..size] == input[..] => {}
                    other => problems.add(format!(
                        "{}/{} level {level}: {other:?}",
                        set.name,
                        file.display()
                    )),
                }
            }
        }
    }
    problems.check();
}
