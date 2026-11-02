//! Comparison with the LZMA SDK's 7z decoder (7-Zip 26.05) through
//! `tools/7z-oracle`, file by file: what `SzArEx_Open` returns and lists,
//! what `SzAr_DecodeFolder` and `SzArEx_Extract` return, and hashes of what
//! they give, on archives 7-Zip makes with every method and filter the SDK
//! decodes, and on those archives damaged.
//!
//! - With the oracle and `7zz` built by `scripts/testdata.py`, generated
//!   archives are compared directly. `SEVENZ_ORACLE_SEED=<n>` makes other
//!   ones, and `SEVENZ_ORACLE_COUNT=<n>` more damaged ones of each;
//!   `SEVENZ_ORACLE_DUMP=<file>` keeps the last archive, to replay one that
//!   fails.
//! - Everywhere, `testdata/oracle/7z.txt` replays small archives and the
//!   answers the SDK gave for them. `cargo test -p hivepack --all-features --test sevenz_oracle
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "sevenz_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use hivepack::sevenz::{Archive, Error, Options};
use support::{
    Oracle, Rng, damaged, fnv64, hex, make_archive, scratch, seven_zip, unhex, write_files,
};

fn recorded_path() -> PathBuf {
    support::repository().join("testdata/oracle/7z.txt")
}

/// The archive opened with no limit but the SDK's, the machine's.
fn open(archive: &[u8]) -> Result<Archive<Cursor<&[u8]>>, Error> {
    let options = Options {
        memory_limit: u64::MAX,
        decoder_memory_limit: u64::MAX,
        ..Options::default()
    };
    Archive::open_with(Cursor::new(archive), &options)
}

fn number(res: Result<(), Error>) -> i32 {
    res.err().map_or(0, Error::number)
}

/// The port's answer for an archive, in the oracle's format.
fn answer(archive: &[u8]) -> String {
    let mut a = match open(archive) {
        Ok(a) => a,
        Err(e) => return e.number().to_string(),
    };
    let mut text = format!("0 {} {}", a.len(), a.folders());
    for e in a.entries() {
        let _ = write!(text, " f:{}", e.index);
        match e.folder {
            Some(f) => {
                let _ = write!(text, ":{f}");
            }
            None => text.push_str(":-"),
        }
        let _ = write!(text, ":{}:{}", u8::from(e.is_dir), e.size);
        match e.crc {
            Some(v) => {
                let _ = write!(text, ":{v:08x}");
            }
            None => text.push_str(":-"),
        }
        match e.attributes {
            Some(v) => {
                let _ = write!(text, ":{v:08x}");
            }
            None => text.push_str(":-"),
        }
        for time in [e.mtime, e.ctime] {
            match time {
                Some(v) => {
                    let _ = write!(text, ":{v}");
                }
                None => text.push_str(":-"),
            }
        }
        text.push(':');
        if e.name_utf16.is_empty() {
            text.push('-');
        }
        for unit in &e.name_utf16 {
            let _ = write!(text, "{unit:04x}");
        }
    }
    for fo in 0..a.folders() {
        match a.decode_folder(fo) {
            Ok(data) => {
                let _ = write!(text, " d:{fo}:0:{:016x}", fnv64(&data));
            }
            Err(e) => {
                let _ = write!(text, " d:{fo}:{}:-", e.number());
            }
        }
    }
    for i in 0..a.len() {
        match a.extract(i) {
            Ok(data) => {
                let _ = write!(text, " x:{i}:0:{}:{:016x}", data.len(), fnv64(&data));
            }
            Err(e) => {
                let _ = write!(text, " x:{i}:{}:-:-", e.number());
            }
        }
    }
    text
}

/// The port's answer against the SDK's. Where the SDK answers
/// `SZ_ERROR_UNSUPPORTED` (4), the port may do more: it reads what 7-Zip's
/// program reads, which `tests/methods.rs` checks.
fn assert_same(got: &str, want: &str, context: &str) {
    if want == "4" {
        return;
    }
    let (g, w): (Vec<&str>, Vec<&str>) = (got.split(' ').collect(), want.split(' ').collect());
    assert_eq!(g.len(), w.len(), "{context}: {got} against {want}");
    for (g, w) in g.iter().zip(&w) {
        let mut parts = w.split(':');
        let kind = parts.next();
        if matches!(kind, Some("d" | "x")) && parts.nth(1) == Some("4") {
            continue;
        }
        assert_eq!(g, w, "{context}");
    }
}

/// The files read one after another give what `extract` gives; where it
/// fails, reading fails too, by the end of the folder at the latest.
fn check_files(archive: &[u8]) {
    let Ok(mut a) = open(archive) else {
        return;
    };
    let extracted: Vec<_> = (0..a.len()).map(|i| a.extract(i)).collect();
    let mut files = a.files();
    let mut failed = None;
    let mut i = 0;
    loop {
        match files.next() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                failed = Some(e);
                break;
            }
        }
        let mut data = Vec::new();
        match files.read_to_end(&mut data) {
            Ok(_) => assert!(
                match &extracted[i] {
                    // Before an error further in its folder, a file reads
                    // well when `extract` fails.
                    Ok(want) => *want == data,
                    Err(_) => true,
                },
                "file {i} differs"
            ),
            Err(e) => {
                failed = Some(
                    e.get_ref()
                        .and_then(|e| e.downcast_ref::<Error>())
                        .copied()
                        .unwrap(),
                );
                break;
            }
        }
        i += 1;
    }
    let any_err = extracted.iter().find_map(|r| r.as_ref().err().copied());
    assert_eq!(
        failed.is_some(),
        any_err.is_some(),
        "reading gave {failed:?}, extract {any_err:?}"
    );
}

/// What 7-Zip's options make: each method and filter the SDK decodes, solid
/// or not, its header compressed or not.
const OPTIONS: &[&str] = &[
    "-m0=Copy",
    "-m0=Copy -mhc=off",
    "-m0=LZMA",
    "-m0=LZMA -mhc=off",
    "-m0=LZMA -ms=off",
    "-m0=LZMA:d=64k:lc=0:lp=2:pb=0 -mhc=off",
    "-m0=LZMA:d=4k:fb=5:a=0",
    "-m0=LZMA:eos -mhc=off",
    "-m0=LZMA:lc=5:lp=3 -mhc=off",
    "-m0=LZMA:lc=8:lp=4:pb=4:d=64k",
    "-m0=LZMA:lc=4:lp=1:d=4k:eos -mhc=off",
    "-m0=LZMA2",
    "-m0=LZMA2 -ms=off -mhc=off",
    "-m0=LZMA2:d=64k:lc=1:lp=1:pb=3",
    "-m0=PPMd",
    "-m0=PPMd:mem=64k:o=2 -mhc=off",
    "-m0=PPMd:mem=64k:o=32",
    "-m0=PPMd:mem=1m:o=6 -ms=off",
    "-m0=BCJ -m1=LZMA",
    "-m0=BCJ -m1=LZMA2 -mhc=off",
    "-m0=BCJ -m1=Copy",
    "-m0=BCJ -m1=PPMd:mem=1m",
    "-m0=ARM -m1=LZMA",
    "-m0=ARMT -m1=LZMA2",
    "-m0=ARM64 -m1=LZMA",
    "-m0=ARM64:a=4096 -m1=LZMA2 -mhc=off",
    "-m0=PPC -m1=LZMA",
    "-m0=SPARC -m1=LZMA2",
    "-m0=IA64 -m1=LZMA",
    "-m0=RISCV -m1=LZMA",
    "-m0=RISCV:a=4096 -m1=LZMA2",
    "-m0=Delta:1 -m1=LZMA",
    "-m0=Delta:4 -m1=LZMA2",
    "-m0=Delta:256 -m1=Copy",
    "-m0=BCJ2 -m1=LZMA:d=1m -m2=LZMA:d=64k:lc=0:lp=2 -m3=LZMA:d=64k:lc=0:lp=2 -mb0s0:1 -mb0s1:2 -mb0s2:3",
    "-m0=BCJ2 -m1=LZMA2 -m2=LZMA:d=64k -m3=Copy -mb0s0:1 -mb0s1:2 -mb0s2:3 -mhc=off",
    "-m0=BCJ2 -m1=PPMd:mem=1m -m2=LZMA -m3=LZMA -mb0s0:1 -mb0s1:2 -mb0s2:3",
    "-mx=1",
    "-mx=9 -mhe=off",
    "-mqs=on -ms=4k",
    "-mtc=on -mta=on",
    "-mtm=off -mtc=off -mta=off -mhc=off",
];

fn ask(oracle: &mut Oracle, dir: &Path, archive: &[u8]) -> String {
    let path = dir.join("asked.7z");
    std::fs::write(&path, archive).expect("the archive written");
    oracle.ask(&path)
}

#[test]
fn port_matches_the_sdk() {
    let (Some(mut oracle), Some(tool)) = (Oracle::spawn(), seven_zip()) else {
        return;
    };
    let dir = scratch("oracle");
    let env = |name: &str| std::env::var(name).ok().and_then(|s| s.parse::<u64>().ok());
    let mut rng = Rng(env("SEVENZ_ORACLE_SEED").unwrap_or(0x5eed_7a01));
    let count = env("SEVENZ_ORACLE_COUNT").unwrap_or(12);
    let dump = std::env::var_os("SEVENZ_ORACLE_DUMP");
    let mut checked = 0;
    for options in OPTIONS {
        let files = 1 + rng.below(8) as usize;
        write_files(&mut rng, &dir, files, 200_000);
        let archive = make_archive(&tool, &dir, "files", options);
        for round in 0..=count {
            let bytes = if round == 0 {
                archive.clone()
            } else {
                damaged(&mut rng, &archive)
            };
            if let Some(path) = &dump {
                std::fs::write(path, &bytes).expect("the dump");
            }
            let want = ask(&mut oracle, &dir, &bytes);
            let got = answer(&bytes);
            assert_same(&got, &want, &format!("{options}, round {round}"));
            if round == 0 {
                // Each folder and file: x:INDEX:RESULT:... and d:FOLDER:RESULT:...
                let failed = want.split(' ').any(|field| {
                    let mut parts = field.split(':');
                    matches!(parts.next(), Some("d" | "x")) && parts.nth(1) != Some("0")
                });
                assert!(!failed, "{options}: the SDK fails: {want:.300}");
            }
            check_files(&bytes);
            checked += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("{checked} archives compared with the SDK");
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/7z.txt");
    let mut checked = 0;
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let (archive, want) = line.split_once('\t').expect("archive and answer");
        let archive = unhex(archive);
        assert_same(
            &answer(&archive),
            want,
            &hex(&archive[..archive.len().min(64)]),
        );
        check_files(&archive);
        checked += 1;
    }
    assert!(checked > 100, "only {checked} recorded answers");
}

#[test]
#[ignore = "rewrites testdata/oracle/7z.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let tool = seven_zip().expect("7zz is built");
    let dir = scratch("record");
    let mut rng = Rng(0x5eed_7a02);
    let mut text = String::from(
        "# Answers from the LZMA SDK's 7z decoder (7-Zip 26.05, tools/7z-oracle), replayed by crates/7z/tests/oracle.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test sevenz_oracle record_oracle_answers -- --ignored\n",
    );
    for options in OPTIONS {
        let files = 1 + rng.below(4) as usize;
        write_files(&mut rng, &dir, files, 1500);
        let archive = make_archive(&tool, &dir, "files", options);
        for round in 0..4 {
            let bytes = if round == 0 {
                archive.clone()
            } else {
                damaged(&mut rng, &archive)
            };
            let reply = ask(&mut oracle, &dir, &bytes);
            let _ = writeln!(text, "{}\t{reply}", hex(&bytes));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(recorded_path().parent().expect("folder")).expect("folder");
    std::fs::write(recorded_path(), text).expect("written");
}

#[test]
fn numbers_are_the_sdk_s() {
    assert_eq!(number(Err(Error::Data)), 1);
    assert_eq!(number(Err(Error::Archive)), 16);
    assert_eq!(number(Err(Error::NoArchive)), 17);
    assert_eq!(number(Ok(())), 0);
}

#[test]
fn the_decoder_memory_limit_holds() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("limit");
    let mut rng = Rng(0x5eed_7a03);
    write_files(&mut rng, &dir, 3, 200_000);
    let archive = make_archive(&tool, &dir, "files", "-m0=PPMd:mem=1m -mhc=off");
    let _ = std::fs::remove_dir_all(&dir);
    let open = |decoder_memory_limit| {
        let options = Options {
            decoder_memory_limit,
            ..Options::default()
        };
        Archive::open_with(Cursor::new(&archive), &options).expect("it opens")
    };
    let first_failure = |a: &mut Archive<Cursor<&Vec<u8>>>| {
        let mut files = a.files();
        loop {
            match files.next() {
                Ok(Some(_)) => {}
                Ok(None) => return None,
                Err(e) => return Some(e),
            }
        }
    };
    // PPMd's model is exactly 1 MiB.
    assert_eq!(first_failure(&mut open(1 << 20)), None);
    let mut a = open((1 << 20) - 1);
    assert_eq!(first_failure(&mut a), Some(Error::Mem));
    assert_eq!(a.decode_folder(0).err(), Some(Error::Mem));
}
