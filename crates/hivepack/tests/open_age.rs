//! Opening files that age v1.3.2 encrypts, through `tools/age-oracle`:
//! tar archives and plain data, compressed or not, to a passphrase or an
//! X25519 key, armored or not, and age inside age. Each opens to what is
//! under it, asks for a passphrase once however often it is opened, and
//! extracts; a wrong passphrase, no key, a refused prompt and a file
//! encrypted again between opens each fail with their reason.
//!
//! - With the oracle built, age encrypts the files afresh.
//! - Everywhere, `testdata/oracle/open.txt` holds files age encrypted
//!   earlier. `cargo test -p hivepack --all-features --test open_age record_oracle_answers
//!   -- --ignored` rewrites it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "open_support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hivepack::age::{
    BoxedIdentity, LazyScryptIdentity, PassphraseFor, PassphrasePrompt, X25519Identity,
};
use hivepack::open::{Container, Error, Layer, Opener};
use support::{Oracle, Scratch, gzip, hex, repository, small_tar, unhex, xz, zstd};

const KEY: &str = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";

/// "password", at a work factor that keeps the tests quick.
const PASSPHRASE: &str = "p:70617373776f7264:10";

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/open.txt")
}

/// An age file, and what it was asked to encrypt.
struct AgeFile {
    recipients: String,
    plaintext: Vec<u8>,
    file: Vec<u8>,
}

fn request(recipients: &str, armor: bool, plaintext: &[u8]) -> String {
    format!(
        "encrypt {recipients} {} {}",
        u8::from(armor),
        hex(plaintext)
    )
}

/// The files the tests open, encrypted by `encrypt`: the first two of the
/// same plaintext to the same passphrase.
fn make_files(mut encrypt: impl FnMut(&str) -> String) -> Vec<(String, String)> {
    let key = X25519Identity::parse(KEY).unwrap().recipient();
    let tar = small_tar();
    let notes = b"Notes, not an archive.\n".repeat(20);
    let mut requests = vec![
        request(PASSPHRASE, false, &zstd(&tar)),
        request(PASSPHRASE, false, &zstd(&tar)),
        request(PASSPHRASE, true, &gzip(&tar)),
        request(&key, false, &xz(&tar)),
        request(&key, true, &tar),
        request(&key, false, &zstd(&notes)),
    ];
    let mut answers: Vec<(String, String)> = Vec::new();
    for request in requests.drain(..) {
        let answer = encrypt(&request);
        answers.push((request, answer));
    }
    // age inside age: to the key, compressed, then to the passphrase.
    let inner = request(&key, false, &tar);
    let inner_file = unhex(encrypt(&inner).strip_prefix("ok ").unwrap());
    let outer = request(PASSPHRASE, false, &zstd(&inner_file));
    let answer = encrypt(&outer);
    answers.push((outer, answer));
    answers
}

fn parse(request: &str, answer: &str) -> AgeFile {
    let words: Vec<&str> = request.split(' ').collect();
    assert_eq!(words.len(), 4, "{request:.100}");
    AgeFile {
        recipients: words[1].to_string(),
        plaintext: unhex(words[3]),
        file: unhex(answer.strip_prefix("ok ").expect("an age file")),
    }
}

/// A prompt that answers `passphrase`, and counts the times it is asked.
fn prompt(passphrase: &'static str, count: &Arc<AtomicUsize>) -> PassphrasePrompt {
    let count = count.clone();
    Arc::new(move |what| {
        assert_eq!(what, PassphraseFor::File);
        count.fetch_add(1, Ordering::SeqCst);
        Ok(passphrase.as_bytes().to_vec())
    })
}

fn identities(prompt: PassphrasePrompt) -> Vec<BoxedIdentity> {
    vec![
        Box::new(X25519Identity::parse(KEY).unwrap()),
        Box::new(LazyScryptIdentity::new(prompt)),
    ]
}

/// Layers, container and data of `file`, opened with the identities.
fn open(
    file: &[u8],
    prompts: &Arc<AtomicUsize>,
) -> Result<(Vec<Layer>, Container, Vec<u8>), Error> {
    let mut opener =
        Opener::new(|| Ok(Cursor::new(file))).identities(identities(prompt("password", prompts)));
    let mut opened = opener.open()?;
    let mut data = Vec::new();
    opened.read_to_end(&mut data)?;
    Ok((opened.layers().to_vec(), opened.container(), data))
}

fn check(files: &[AgeFile]) {
    for f in files {
        // What is under the age layer, opened by itself.
        let (mut layers, container, data) = open(&f.plaintext, &Arc::default()).unwrap();
        layers.insert(0, Layer::Age);
        let prompts = Arc::new(AtomicUsize::new(0));
        let mut opener = Opener::new(|| Ok(Cursor::new(&f.file[..])))
            .identities(identities(prompt("password", &prompts)));
        for _ in 0..3 {
            let mut opened = opener.open().unwrap();
            assert_eq!(opened.layers(), layers, "{}", f.recipients);
            assert_eq!(opened.container(), container);
            let mut got = Vec::new();
            opened.read_to_end(&mut got).unwrap();
            assert!(got == data);
        }
        // A passphrase asked for once, for each layer that needs one.
        let scrypt = layers.iter().filter(|&&l| l == Layer::Age).count() > 1
            || f.recipients.starts_with("p:");
        assert_eq!(
            prompts.load(Ordering::SeqCst),
            usize::from(scrypt),
            "{}",
            f.recipients
        );
    }
    // Each kind of file is there.
    let kinds: Vec<_> = files
        .iter()
        .map(|f| open(&f.file, &Arc::default()).unwrap())
        .map(|(layers, container, _)| (layers, container))
        .collect();
    for want in [
        (vec![Layer::Age, Layer::Zstd], Container::Tar),
        (vec![Layer::Age, Layer::Gzip], Container::Tar),
        (vec![Layer::Age, Layer::Xz], Container::Tar),
        (vec![Layer::Age], Container::Tar),
        (vec![Layer::Age, Layer::Zstd], Container::Data),
        (vec![Layer::Age, Layer::Zstd, Layer::Age], Container::Tar),
    ] {
        assert!(kinds.contains(&want), "no {want:?} in {kinds:?}");
    }
    failures(&files[0], &files[1]);
    extracts(&files[0]);
}

/// `a` and `b`, the same plaintext encrypted twice to the passphrase.
fn failures(a: &AgeFile, b: &AgeFile) {
    assert!(a.recipients.starts_with("p:") && a.plaintext == b.plaintext);
    // A wrong passphrase.
    let mut opener = Opener::new(|| Ok(Cursor::new(&a.file[..])))
        .identities(identities(prompt("wrong", &Arc::default())));
    match opener.open() {
        Err(Error::Age(hivepack::age::Error::Header(m))) => assert_eq!(m, "incorrect passphrase"),
        other => panic!("{other:?}"),
    }
    // No key: the stanzas tell what the file needs.
    let mut opener = Opener::new(|| Ok(Cursor::new(&a.file[..])))
        .identities(vec![Box::new(X25519Identity::parse(KEY).unwrap())]);
    match opener.open() {
        Err(Error::Age(hivepack::age::Error::NoMatch(m))) => assert_eq!(m.stanza_types, ["scrypt"]),
        other => panic!("{other:?}"),
    }
    // The person did not give one.
    let refused: PassphrasePrompt = Arc::new(|_| Err("cancelled".into()));
    let mut opener = Opener::new(|| Ok(Cursor::new(&a.file[..]))).identities(identities(refused));
    match opener.open() {
        Err(Error::Age(hivepack::age::Error::Header(m))) => {
            assert_eq!(m, "could not read passphrase: cancelled")
        }
        other => panic!("{other:?}"),
    }
    // A work factor past the limit: 2^10 here, as the passphrase asks.
    let mut lazy = LazyScryptIdentity::new(prompt("password", &Arc::default()));
    lazy.set_max_work_factor(9);
    let mut opener = Opener::new(|| Ok(Cursor::new(&a.file[..]))).identities(vec![Box::new(lazy)]);
    match opener.open() {
        Err(Error::Age(hivepack::age::Error::Header(m))) => {
            assert_eq!(m, "scrypt work factor too large: 10")
        }
        other => panic!("{other:?}"),
    }
    // Encrypted again between two opens: another file key.
    let mut next = 0;
    let mut opener = Opener::new(|| {
        next += 1;
        Ok(Cursor::new(if next == 1 {
            &a.file[..]
        } else {
            &b.file[..]
        }))
    })
    .identities(identities(prompt("password", &Arc::default())));
    opener.open().unwrap();
    assert!(matches!(opener.open(), Err(Error::Changed)));
}

/// `f`, a tar archive under its layers, extracted with one prompt.
fn extracts(f: &AgeFile) {
    let scratch = Scratch::new();
    let prompts = Arc::new(AtomicUsize::new(0));
    let mut opener = Opener::new(|| Ok(Cursor::new(&f.file[..])))
        .identities(identities(prompt("password", &prompts)));
    assert_eq!(opener.open().unwrap().container(), Container::Tar);
    let out = scratch.path().join("out");
    hivepack::extract::extract_tar(
        || Ok(opener.open()?),
        &out,
        &hivepack::extract::Options::default(),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(out.join("docs/notes.txt")).unwrap(),
        b"Hello from inside the layers.\n"
    );
    assert_eq!(prompts.load(Ordering::SeqCst), 1);
}

#[test]
fn opens_what_age_encrypts() {
    let Some(mut oracle) = Oracle::spawn("age-oracle") else {
        return;
    };
    let files: Vec<AgeFile> = make_files(|r| oracle.ask(r))
        .iter()
        .map(|(request, answer)| parse(request, answer))
        .collect();
    check(&files);
}

#[test]
fn opens_recorded_files() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/open.txt");
    let files: Vec<AgeFile> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let (request, answer) = line.split_once('\t').expect("request, tab, answer");
            parse(request, answer)
        })
        .collect();
    check(&files);
}

#[test]
#[ignore = "rewrites testdata/oracle/open.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("age-oracle").expect("the oracle is built");
    let mut text = String::from(
        "# Files age v1.3.2 encrypted (tools/age-oracle), opened by crates/open/tests/age.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --test open_age record_oracle_answers -- --ignored\n",
    );
    for (request, answer) in make_files(|r| oracle.ask(r)) {
        let _ = writeln!(text, "{request}\t{answer}");
    }
    std::fs::write(recorded_path(), text).expect("written");
}
