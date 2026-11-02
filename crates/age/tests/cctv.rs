//! C2SP's CCTV test vectors for age (`c2sp.org/CCTV/age`, the set age
//! v1.3.2 tests itself with), fetched by `scripts/testdata.py` into the
//! `cctv-age` set. Each vector is a file with the outcome it must have:
//! success, or a header, armor, payload or HMAC failure, or no match; and
//! the SHA-256 of all the plaintext given out, even when it fails later.
//!
//! As age's own `testkit_test.go` does, an armored vector is read through
//! the armor reader, and the outcome is told from the error's type. Each
//! vector is also read through `decrypt_file`, which finds the armor
//! itself, as `age --decrypt` does.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufReader, Read};
use std::path::PathBuf;

use hivepack_age::{
    ArmoredReader, Error, HybridIdentity, Identity, ScryptIdentity, X25519Identity, decrypt,
    decrypt_file,
};
use hivepack_crypto::Sha256;
use hivepack_deflate::{Flush, InBuffer, Inflate, OutBuffer, Status};

fn testdata() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/testdata"))
}

/// The folder of vectors, or `None` with a note when the set is missing.
/// CI lists the `core` group in `HIVEPACK_TESTDATA_REQUIRED`, and then a
/// missing set fails the test.
fn vectors() -> Option<PathBuf> {
    let set = testdata().join("cctv-age");
    if !set.join(".complete").exists() {
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == "core"),
            "the CCTV vectors are missing: run `python3 scripts/testdata.py fetch`"
        );
        eprintln!("skipping: the CCTV vectors are not fetched (scripts/testdata.py fetch)");
        return None;
    }
    let module = std::fs::read_dir(set.join("c2sp.org/CCTV"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    Some(module.join("testdata"))
}

fn inflate(data: &[u8]) -> Vec<u8> {
    let mut z = Inflate::new(15).unwrap();
    let mut input = InBuffer::new(data);
    let mut chunk = vec![0; 1 << 20];
    let mut all = Vec::new();
    loop {
        let mut output = OutBuffer::new(&mut chunk);
        let status = z.inflate(&mut output, &mut input, Flush::NoFlush).unwrap();
        let n = output.pos;
        all.extend_from_slice(&chunk[..n]);
        if status == Status::StreamEnd {
            return all;
        }
    }
}

struct Vector {
    expect: String,
    payload: Option<String>,
    identities: Vec<Box<dyn Identity>>,
    armored: bool,
    file: Vec<u8>,
}

fn parse_vector(contents: &[u8]) -> Vector {
    let mut v = Vector {
        expect: String::new(),
        payload: None,
        identities: Vec::new(),
        armored: false,
        file: Vec::new(),
    };
    let mut rest = contents;
    let mut compressed = false;
    loop {
        let at = rest
            .iter()
            .position(|&c| c == b'\n')
            .expect("a header line");
        let line = std::str::from_utf8(&rest[..at]).unwrap();
        rest = &rest[at + 1..];
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(": ").unwrap_or((line, ""));
        match key {
            "expect" => v.expect = value.to_string(),
            "payload" => v.payload = Some(value.to_string()),
            "identity" if value.starts_with("AGE-SECRET-KEY-PQ-1") => v
                .identities
                .push(Box::new(HybridIdentity::parse(value).unwrap())),
            "identity" => v
                .identities
                .push(Box::new(X25519Identity::parse(value).unwrap())),
            "passphrase" => v
                .identities
                .push(Box::new(ScryptIdentity::new(value.as_bytes()).unwrap())),
            "armored" => v.armored = true,
            "compressed" => {
                assert_eq!(value, "zlib");
                compressed = true;
            }
            "file key" | "comment" => {}
            _ => panic!("unknown header key {key}"),
        }
    }
    v.file = if compressed {
        inflate(rest)
    } else {
        rest.to_vec()
    };
    v
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.out().iter().map(|b| format!("{b:02x}")).collect()
}

/// The outcome the vectors name for an error.
fn outcome(error: &Error) -> &'static str {
    match error {
        Error::Header(_) => "header failure",
        Error::NoMatch(_) => "no match",
        Error::HeaderMac => "HMAC failure",
        Error::Armor(_) => "armor failure",
        Error::Payload(_) => "payload failure",
        Error::Io(_) => "I/O error",
    }
}

/// Reads all of `r`: the outcome, and the plaintext given out before it.
fn read_all(mut r: impl Read) -> (&'static str, Vec<u8>) {
    let mut out = Vec::new();
    let mut buf = [0; 10_000];
    loop {
        match r.read(&mut buf) {
            Ok(0) => return ("success", out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (outcome(&Error::from(e)), out),
        }
    }
}

/// The outcome and plaintext of decrypting with `open`.
fn run<R: Read>(
    v: &Vector,
    open: impl FnOnce(&[&dyn Identity]) -> Result<R, Error>,
) -> (&'static str, Vec<u8>, String) {
    let identities: Vec<&dyn Identity> = v.identities.iter().map(|i| i.as_ref()).collect();
    match open(&identities) {
        Err(e) => (outcome(&e), Vec::new(), e.to_string()),
        Ok(r) => {
            let (outcome, out) = read_all(r);
            (outcome, out, String::new())
        }
    }
}

#[test]
fn port_decrypts_every_vector_as_expected() {
    let Some(folder) = vectors() else {
        return;
    };
    let mut names: Vec<_> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut checked = 0;
    let mut problems = Vec::new();
    for name in &names {
        let v = parse_vector(&std::fs::read(folder.join(name)).unwrap());
        checked += 1;

        // As age's testkit_test.go: the armor reader when the vector says.
        let (got, out, message) = if v.armored {
            run(&v, |ids| {
                decrypt(BufReader::new(ArmoredReader::new(&v.file[..])), ids)
            })
        } else {
            run(&v, |ids| decrypt(&v.file[..], ids))
        };
        if got != v.expect {
            problems.push(format!(
                "{name}: expected {}, got {got} {message}",
                v.expect
            ));
            continue;
        }
        if let Some(payload) = &v.payload
            && &sha256_hex(&out) != payload
        {
            problems.push(format!(
                "{name}: payload hash, {} bytes given out",
                out.len()
            ));
        }

        // As `age --decrypt`: the armor found from the file's first line.
        // A file with garbage before its armor is not seen as armored, and
        // fails as a header instead.
        let (got_file, out_file, _) = run(&v, |ids| decrypt_file(&v.file[..], ids));
        let same = got_file == got && out_file == out;
        let garbage_first = got == "armor failure" && got_file == "header failure";
        if !same && !garbage_first {
            problems.push(format!(
                "{name}: decrypt_file gave {got_file} after {} bytes, decrypt {got} after {}",
                out_file.len(),
                out.len()
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(checked >= 147, "only {checked} vectors checked");
    eprintln!("{checked} vectors checked");
}
