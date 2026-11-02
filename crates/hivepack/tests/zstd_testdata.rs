//! Checks the test data against libzstd 1.5.7, the release this crate ports.
//!
//! `testdata/manifest.json` says what each file is: a frame that decodes (to
//! a known original, when there is one), a frame that must fail, an input to
//! compress, or a dictionary. These tests make sure libzstd agrees, so the
//! port's own tests can rely on the same manifest. They also check that the
//! `zstd` crate used as the reference builds exactly that release: it must
//! compress zstd's regression data to the sizes zstd's own harness records.

#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use support::{Kind, Outcome, Problems, Set};
use zstd::zstd_safe::{self, DCtx};

/// Decodes every frame in `input`, as the zstd command line does.
fn decode(input: &[u8], dictionary: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let mut context = DCtx::create();
    if let Some(dictionary) = dictionary {
        context
            .load_dictionary(dictionary)
            .map_err(|code| io::Error::other(zstd_safe::get_error_name(code)))?;
    }
    let mut decoder = zstd::stream::read::Decoder::with_context(input, &mut context);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}

/// `ZSTD_compress`, the "compress simple" method of zstd's regression tests.
fn compress(input: &[u8], level: i32) -> Vec<u8> {
    let mut output = Vec::with_capacity(zstd_safe::compress_bound(input.len()));
    zstd_safe::compress(&mut output, input, level)
        .unwrap_or_else(|code| panic!("compress: {}", zstd_safe::get_error_name(code)));
    output
}

fn sets(kind: Kind) -> Vec<Set> {
    support::manifest()
        .sets
        .into_iter()
        .filter(|set| set.kind == kind && set.present())
        .collect()
}

#[test]
fn the_reference_is_the_release_we_port() {
    let manifest = support::manifest();
    assert_eq!(
        zstd_safe::version_string(),
        hivepack::zstd::UPSTREAM_VERSION
    );
    assert_eq!(manifest.upstream.version, hivepack::zstd::UPSTREAM_VERSION);
}

#[test]
fn every_set_names_its_source_and_license() {
    let mut names = BTreeMap::new();
    for set in support::manifest().sets {
        assert!(
            !set.source.is_empty() && !set.license.is_empty(),
            "{}",
            set.name
        );
        assert!(
            set.path.is_some() as u8 + set.fetch.is_some() as u8 + set.generate.is_some() as u8
                == 1,
            "{} needs exactly one of path, fetch and generate",
            set.name
        );
        if let Some(path) = &set.path {
            // Each committed source keeps its license file next to its data.
            let top = path.split('/').next().expect("path");
            let license = support::repository()
                .join("testdata")
                .join(top)
                .join("LICENSE");
            assert!(
                license.exists(),
                "{}: {} missing",
                set.name,
                license.display()
            );
        }
        assert!(
            names.insert(set.name.clone(), ()).is_none(),
            "{} twice",
            set.name
        );
    }
}

#[test]
fn frames_decode_to_their_originals() {
    let mut problems = Problems::default();
    let mut count = 0;
    for set in sets(Kind::Frames) {
        let dictionary = set.dictionary.as_ref().map(|d| set.read(Path::new(d)));
        for frame in set.frames() {
            count += 1;
            let result = decode(&set.read(&frame), dictionary.as_deref());
            let name = format!("{}/{}", set.name, frame.display());
            match (set.expected(&frame).unwrap_or(Outcome::Decodes), result) {
                (Outcome::Decodes, Ok(output)) => {
                    if let Some(original) = set.original(&frame)
                        && original != output
                    {
                        problems.add(format!(
                            "{name}: decodes to {} bytes that differ from the original",
                            output.len()
                        ));
                    }
                }
                (Outcome::Decodes, Err(error)) => problems.add(format!("{name}: fails: {error}")),
                (Outcome::Fails, Ok(_)) => {
                    problems.add(format!("{name}: decodes, but the manifest says it fails"))
                }
                (Outcome::Fails, Err(_)) => {}
            }
        }
    }
    assert!(count > 0);
    problems.check();
}

#[test]
fn bad_frames_fail() {
    let mut problems = Problems::default();
    for set in sets(Kind::BadFrames) {
        for frame in set.frames() {
            let result = decode(&set.read(&frame), None);
            let name = format!("{}/{}", set.name, frame.display());
            match (set.expected(&frame).unwrap_or(Outcome::Fails), result) {
                (Outcome::Fails, Ok(output)) => {
                    problems.add(format!("{name}: decodes to {} bytes", output.len()));
                }
                (Outcome::Decodes, Err(error)) => problems.add(format!("{name}: fails: {error}")),
                _ => {}
            }
        }
    }
    problems.check();
}

#[test]
fn inputs_round_trip() {
    let mut problems = Problems::default();
    for set in sets(Kind::Inputs) {
        for file in set.list() {
            let input = set.read(&file);
            for level in [-5, 1, 3, 19] {
                match decode(&compress(&input, level), None) {
                    Ok(output) if output == input => {}
                    Ok(_) => problems.add(format!(
                        "{}/{} level {level}: round trip differs",
                        set.name,
                        file.display()
                    )),
                    Err(error) => problems.add(format!(
                        "{}/{} level {level}: {error}",
                        set.name,
                        file.display()
                    )),
                }
            }
        }
    }
    problems.check();
}

#[test]
fn dictionaries_round_trip() {
    let mut problems = Problems::default();
    for set in sets(Kind::Dictionaries) {
        for dictionary in set.list() {
            let key = dictionary.to_string_lossy();
            let inputs = set
                .inputs
                .get(key.as_ref())
                .unwrap_or_else(|| panic!("{key}: no inputs"));
            let dictionary = set.read(&dictionary);
            for input in inputs {
                let data = std::fs::read(support::repository().join("testdata").join(input))
                    .expect("input");
                for level in [1, 3, 19] {
                    let compressed = zstd::bulk::Compressor::with_dictionary(level, &dictionary)
                        .and_then(|mut c| c.compress(&data))
                        .expect("compresses with the dictionary");
                    match decode(&compressed, Some(&dictionary)) {
                        Ok(output) if output == data => {}
                        other => {
                            problems.add(format!("{key} with {input} level {level}: {other:?}"))
                        }
                    }
                }
            }
        }
    }
    problems.check();
}

#[test]
fn frames_decode_with_the_dictionary_they_name() {
    let mut problems = Problems::default();
    for set in sets(Kind::DictFrames) {
        let mut dictionaries = BTreeMap::new();
        for file in set.list() {
            if file.extension() == Some("dict".as_ref()) {
                let dictionary = set.read(&file);
                let id =
                    zstd_safe::get_dict_id_from_dict(&dictionary).expect("dictionary has an id");
                dictionaries.insert(id, dictionary);
            }
        }
        assert!(!dictionaries.is_empty(), "{}", set.name);
        for frame in set.frames() {
            let input = set.read(&frame);
            let dictionary =
                zstd_safe::get_dict_id_from_frame(&input).and_then(|id| dictionaries.get(&id));
            let name = format!("{}/{}", set.name, frame.display());
            match (
                set.expected(&frame).unwrap_or(Outcome::Decodes),
                decode(&input, dictionary.map(Vec::as_slice)),
            ) {
                (Outcome::Decodes, Err(error)) => problems.add(format!("{name}: fails: {error}")),
                (Outcome::Fails, Ok(_)) => {
                    problems.add(format!("{name}: decodes, but the manifest says it fails"))
                }
                _ => {}
            }
        }
    }
    problems.check();
}

/// `level N` rows of the "compress simple" method in zstd's
/// `tests/regression/results.csv`, by dataset.
fn regression_sizes() -> BTreeMap<String, Vec<(i32, usize)>> {
    let path = support::repository().join("testdata/zstd/regression/results.csv");
    let text = std::fs::read_to_string(path).expect("results.csv");
    let mut sizes: BTreeMap<String, Vec<(i32, usize)>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let [data, config, method, size] = fields[..] else {
            continue;
        };
        if method != "compress simple" {
            continue;
        }
        if let Some(level) = config.strip_prefix("level ").and_then(|l| l.parse().ok()) {
            sizes
                .entry(data.to_string())
                .or_default()
                .push((level, size.parse().expect("size")));
        }
    }
    sizes
}

#[test]
fn the_reference_compresses_regression_data_to_the_recorded_sizes() {
    let sizes = regression_sizes();
    let mut problems = Problems::default();
    let mut checked = 0;
    for set in sets(Kind::Frames) {
        for (frame, dataset) in &set.regression {
            let data =
                decode(&set.read(&PathBuf::from(frame)), None).expect("regression data decodes");
            for &(level, want) in sizes
                .get(dataset)
                .unwrap_or_else(|| panic!("{dataset} not in results.csv"))
            {
                checked += 1;
                let got = compress(&data, level).len();
                if got != want {
                    problems.add(format!(
                        "{dataset} level {level}: {got} bytes, results.csv says {want}"
                    ));
                }
            }
        }
    }
    if checked == 0 {
        eprintln!("skipping: zstd-regression-data not fetched");
    }
    problems.check();
}
