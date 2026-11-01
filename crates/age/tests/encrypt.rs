//! Writing age files, compared with age v1.3.2 itself through
//! `tools/age-oracle`: given the same random bytes, in the same order, the port
//! must write the file age writes, byte for byte, armored or not, to X25519 keys
//! or a passphrase, whatever pieces the plaintext comes in, and refuse what age
//! refuses.
//!
//! - With the oracle built, requests are compared with age directly.
//! - Everywhere, including where it is not built (Windows, and the emulated
//!   i686 and s390x jobs), `testdata/oracle/age-encrypt.txt` replays the SHA-256
//!   of age's answers to the first of the same requests, which the test makes
//!   again by number. `cargo test -p hivepack-age --test encrypt
//!   record_oracle_answers -- --ignored` rewrites that file.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hivepack_age::{
    ArmoredReader, ArmoredWriter, EncryptError, Identity, RandomSource, Recipient, ScryptIdentity,
    ScryptRecipient, X25519Identity, X25519Recipient, decrypt_file, encrypt,
};
use hivepack_crypto::Sha256;
use support::{Oracle, Rng, hex, repository, unhex};

const KEYS: [&str; 4] = [
    "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0",
    "AGE-SECRET-KEY-1W0YVT58DJ29ACF8AJECG9HK66C9Y5UWVWJDJNFYRF9VX8LA8E3ZQPQR8XW",
    "AGE-SECRET-KEY-1LP5327FL4GTJFS9AMV3RL6R8C6VDK8ELLN0FVSNMY7ECDHY9YEMQCEYHJ2",
    "AGE-SECRET-KEY-1K9MV3MGWR4DR6ZDMHWWT9YU2H4C6T0MVVYN8VVX09FQ72PNJYWRQCQ369K",
];

/// Curve25519 points of low order, 0 and 1, which age refuses to encrypt to.
const LOW_ORDER: [&str; 2] = [
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z",
    "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj7vrya",
];

/// How many requests go in the recorded file.
const RECORDED: u64 = 300;

fn recorded_path() -> PathBuf {
    repository().join("testdata/oracle/age-encrypt.txt")
}

fn sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.out())
}

/// Bytes: random, or all zeros.
fn bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    if rng.below(4) == 0 {
        vec![0; len]
    } else {
        (0..len).map(|_| rng.next() as u8).collect()
    }
}

/// A plaintext length around the 64 KiB chunks, or small, or anything up to two
/// chunks and a bit.
fn length(rng: &mut Rng) -> usize {
    const CHUNK: usize = 64 * 1024;
    match rng.below(3) {
        0 => {
            let base = CHUNK * rng.below(3) as usize;
            let near = rng.pick(&[0, 1, 2, 47, 48, 49]);
            if rng.below(2) == 0 {
                base.saturating_sub(near)
            } else {
                base + near
            }
        }
        1 => rng.below(300) as usize,
        _ => rng.below(140_000) as usize,
    }
}

fn recipient_of(key: &str) -> String {
    X25519Identity::parse(key).unwrap().recipient()
}

/// The request numbered `n`, made again the same from its number.
fn request(n: u64) -> String {
    let mut rng = Rng((n + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let passphrase = |rng: &mut Rng| {
        let len = rng.below(20) as usize;
        let log_n = 1 + rng.below(4);
        let pass = if len == 0 {
            "-".to_string()
        } else {
            hex(&bytes(rng, len))
        };
        format!("p:{pass}:{log_n}")
    };
    let spec = match rng.below(10) {
        // A passphrase.
        0..=2 => passphrase(&mut rng),
        // Recipients that cannot be mixed.
        3 => {
            let other = if rng.below(2) == 0 {
                passphrase(&mut rng)
            } else {
                recipient_of(KEYS[0])
            };
            if rng.below(2) == 0 {
                format!("{},{other}", passphrase(&mut rng))
            } else {
                format!("{other},{}", passphrase(&mut rng))
            }
        }
        // A point of low order among the keys, or something that is no key.
        4 => {
            let other = rng.pick(&LOW_ORDER[..]);
            let other = if rng.below(4) == 0 {
                "age1notakey"
            } else {
                other
            };
            format!("{},{other}", recipient_of(KEYS[0]))
        }
        // X25519 keys.
        _ => {
            let mut to: Vec<String> = KEYS
                .iter()
                .filter(|_| rng.below(2) == 0)
                .map(|k| recipient_of(k))
                .collect();
            if to.is_empty() {
                to.push(recipient_of(KEYS[1]));
            }
            to.join(",")
        }
    };
    let len = length(&mut rng);
    let plaintext = bytes(&mut rng, len);
    let plaintext = if plaintext.is_empty() {
        "-".to_string()
    } else {
        hex(&plaintext)
    };
    // The file key, the nonce, and up to 32 bytes for each recipient, and a
    // label; more than any file takes.
    let random = bytes(&mut rng, 256);
    let armored = rng.below(3) == 0;
    format!(
        "encryptwith {} {spec} {} {plaintext}",
        hex(&random),
        u8::from(armored)
    )
}

/// A source that gives `bytes`, and how many of them were taken.
fn counting_source(bytes: Vec<u8>) -> (RandomSource, Arc<Mutex<usize>>) {
    let taken = Arc::new(Mutex::new(0));
    let counter = taken.clone();
    let source: RandomSource = Arc::new(move |out: &mut [u8]| {
        let mut at = counter.lock().unwrap();
        let end = *at + out.len();
        out.copy_from_slice(
            bytes
                .get(*at..end)
                .ok_or_else(|| io::Error::other("out of random bytes"))?,
        );
        *at = end;
        Ok(())
    });
    (source, taken)
}

/// Writes `data` to `w` in pieces of random sizes, some of them empty.
fn write_in_pieces<W: Write>(w: &mut W, mut data: &[u8], rng: &mut Rng) {
    while !data.is_empty() {
        let n = (rng.below(100_000) as usize).min(data.len());
        assert_eq!(w.write(&data[..n]).unwrap(), n);
        data = &data[n..];
    }
}

fn file_of(
    recipients: &[&dyn Recipient],
    armored: bool,
    plaintext: &[u8],
    source: &RandomSource,
    rng: &mut Rng,
) -> Result<Vec<u8>, EncryptError> {
    if armored {
        let mut w = encrypt(ArmoredWriter::new(Vec::new()), recipients, Some(source))?;
        write_in_pieces(&mut w, plaintext, rng);
        Ok(w.finish().unwrap().finish().unwrap())
    } else {
        let mut w = encrypt(Vec::new(), recipients, Some(source))?;
        write_in_pieces(&mut w, plaintext, rng);
        Ok(w.finish().unwrap())
    }
}

/// The port's answer to an `encryptwith` request, as the oracle words it.
fn answer(request: &str, rng: &mut Rng) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let ["encryptwith", random, spec, armored, plaintext] = words[..] else {
        panic!("unknown request {request:.100}");
    };
    let mut recipients: Vec<Box<dyn Recipient>> = Vec::new();
    for s in spec.split(',') {
        if let Some(p) = s.strip_prefix("p:") {
            let (pass, log_n) = p.split_once(':').unwrap();
            let Ok(mut r) = ScryptRecipient::new(&unhex(pass)) else {
                return "err".into();
            };
            r.set_work_factor(log_n.parse().unwrap());
            recipients.push(Box::new(r));
        } else {
            let Ok(r) = X25519Recipient::parse(s) else {
                return "err".into();
            };
            recipients.push(Box::new(r));
        }
    }
    let recipients: Vec<&dyn Recipient> = recipients.iter().map(|r| r.as_ref()).collect();
    let (source, taken) = counting_source(unhex(random));
    match file_of(&recipients, armored == "1", &unhex(plaintext), &source, rng) {
        Ok(file) => format!("ok {} {}", hex(&file), taken.lock().unwrap()),
        Err(EncryptError::Recipient(_)) => "err".into(),
        Err(e) => panic!("{e} on {request:.300}"),
    }
}

#[test]
fn port_writes_what_age_writes() {
    let Some(mut oracle) = Oracle::spawn("age-oracle") else {
        return;
    };
    let mut rng = Rng(0xa9e_e001);
    let (mut written, mut refused) = (0, 0);
    for n in 0..1200 {
        let request = request(n);
        let want = oracle.ask(&request);
        let got = answer(&request, &mut rng);
        assert!(
            got == want,
            "request {n}: {request:.300}\n{got:.300}\n{want:.300}"
        );
        if want == "err" {
            refused += 1;
        } else {
            written += 1;
        }
    }
    eprintln!("{written} files written, {refused} refused");
    assert!(written > 800 && refused > 100, "{written} and {refused}");
}

#[test]
fn port_matches_recorded_answers() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/age-encrypt.txt");
    let mut rng = Rng(0xa9e_e003);
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (n, want) = line.split_once('\t').expect("number, tab, answer");
        let got = answer(&request(n.parse().unwrap()), &mut rng);
        assert_eq!(sha256(got.as_bytes()), want, "request {n}");
        checked += 1;
    }
    assert_eq!(checked, RECORDED);
}

#[test]
#[ignore = "rewrites testdata/oracle/age-encrypt.txt from the oracle"]
fn record_oracle_answers() {
    let mut oracle = Oracle::spawn("age-oracle").expect("the oracle is built");
    let mut text = String::from(
        "# The SHA-256 of age v1.3.2's answers (tools/age-oracle) to the requests\n\
         # crates/age/tests/encrypt.rs makes by number, which it replays.\n\
         # Regenerate with: cargo test -p hivepack-age --test encrypt record_oracle_answers -- --ignored\n",
    );
    for n in 0..RECORDED {
        let reply = oracle.ask(&request(n));
        let _ = writeln!(text, "{n}\t{}", sha256(reply.as_bytes()));
    }
    std::fs::write(recorded_path(), text).expect("written");
}

#[test]
fn recipients_parse_as_in_age() {
    let Some(mut oracle) = Oracle::spawn("age-oracle") else {
        return;
    };
    let good = recipient_of(KEYS[0]);
    let mut texts = vec![
        good.clone(),
        good.to_uppercase(),
        LOW_ORDER[0].to_string(),
        // 31 bytes in the key.
        "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqar9jk6".to_string(),
        "age1".to_string(),
        "not a key".to_string(),
        KEYS[0].to_string(),
    ];
    let mut rng = Rng(0xa9e_e004);
    for _ in 0..200 {
        let mut text = good.clone().into_bytes();
        let at = rng.below(text.len() as u64) as usize;
        text[at] = rng.pick(b"qpzry9x8gf2tvdw0s3jn54khce6mua7lQ1 ");
        texts.push(String::from_utf8(text).unwrap());
    }
    for text in texts {
        let got = match X25519Recipient::parse(&text) {
            Ok(r) => format!("ok {}", hex(r.to_string().as_bytes())),
            Err(_) => "err".to_string(),
        };
        let want = oracle.ask(&format!("recipient {}", hex(text.as_bytes())));
        assert_eq!(got, want, "{text}");
    }
}

/// With the system's random bytes: two files of the same plaintext differ, and
/// the port, and age where it is built, decrypt them.
#[cfg(unix)]
#[test]
fn files_with_the_systems_random_bytes_decrypt() {
    let key = X25519Identity::parse(KEYS[0]).unwrap();
    let to = X25519Recipient::parse(&key.recipient()).unwrap();
    let plaintext = vec![7u8; 100_000];
    let write = || {
        let mut w = encrypt(Vec::new(), &[&to as &dyn Recipient], None).unwrap();
        w.write_all(&plaintext).unwrap();
        w.finish().unwrap()
    };
    let (one, two) = (write(), write());
    assert_ne!(one, two);
    for file in [&one, &two] {
        let mut out = Vec::new();
        decrypt_file(&file[..], &[&key as &dyn Identity])
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, plaintext);
    }
    if let Some(mut oracle) = Oracle::spawn("age-oracle") {
        let reply = oracle.ask(&format!("decrypt {} {}", KEYS[0], hex(&one)));
        assert!(reply.starts_with("success 100000 "), "{reply}");
    }
}

fn a_key() -> X25519Recipient {
    X25519Recipient::parse(&recipient_of(KEYS[0])).unwrap()
}

#[test]
fn a_source_that_fails_writes_nothing() {
    let failing: RandomSource = Arc::new(|_: &mut [u8]| Err(io::Error::other("no randomness")));
    let key = a_key();
    let mut out = Vec::new();
    let got = encrypt(&mut out, &[&key as &dyn Recipient], Some(&failing));
    assert!(matches!(got, Err(EncryptError::Random(_))));
    assert!(out.is_empty());

    // Failing at the last it is asked for, the nonce.
    let (source, _) = counting_source(vec![1; 16 + 32 + 15]);
    let got = encrypt(&mut out, &[&key as &dyn Recipient], Some(&source));
    assert!(matches!(got, Err(EncryptError::Random(_))));
    assert!(out.is_empty());
}

#[test]
fn no_recipients_are_refused() {
    let (source, _) = counting_source(vec![1; 64]);
    let mut out = Vec::new();
    let got = encrypt(&mut out, &[], Some(&source));
    assert!(matches!(got, Err(EncryptError::Recipient(m)) if m == "no recipients specified"));
    assert!(out.is_empty());
}

#[test]
fn a_passphrase_is_a_files_only_recipient() {
    let (source, _) = counting_source(vec![1; 256]);
    let mut pass = ScryptRecipient::new(b"password").unwrap();
    pass.set_work_factor(1);
    let key = a_key();
    let got = encrypt(
        Vec::new(),
        &[&pass as &dyn Recipient, &key as &dyn Recipient],
        Some(&source),
    );
    assert!(
        matches!(got, Err(EncryptError::Recipient(ref m)) if m.starts_with("incompatible recipients: ")),
        "{got:?}"
    );
    assert!(ScryptRecipient::new(b"").is_err());
}

#[test]
fn a_work_factor_out_of_range_is_brought_in() {
    let mut pass = ScryptRecipient::new(b"password").unwrap();
    pass.set_work_factor(0);
    let (source, _) = counting_source(vec![1; 256]);
    let mut w = encrypt(Vec::new(), &[&pass as &dyn Recipient], Some(&source)).unwrap();
    w.write_all(b"data").unwrap();
    let file = w.finish().unwrap();
    assert!(file.windows(2).any(|w| w == b" 1"), "work factor 1");
    let mut identity = ScryptIdentity::new(b"password").unwrap();
    identity.set_max_work_factor(1);
    let mut out = Vec::new();
    decrypt_file(&file[..], &[&identity as &dyn Identity])
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, b"data");
}

#[test]
fn a_file_not_finished_does_not_decrypt() {
    let key = X25519Identity::parse(KEYS[0]).unwrap();
    let to = a_key();
    for len in [10, 64 * 1024, 64 * 1024 + 1, 200_000] {
        let (source, _) = counting_source(vec![9; 64]);
        let mut out = Vec::new();
        let mut w = encrypt(&mut out, &[&to as &dyn Recipient], Some(&source)).unwrap();
        w.write_all(&vec![5; len]).unwrap();
        drop(w);
        let mut plain = Vec::new();
        let got = decrypt_file(&out[..], &[&key as &dyn Identity])
            .map_err(|e| e.to_string())
            .and_then(|mut r| r.read_to_end(&mut plain).map_err(|e| e.to_string()));
        assert!(got.is_err(), "{len} bytes read as a whole file");
    }
}

/// Takes `room` bytes, then fails once, then would take anything again: what
/// fails later is the writer's memory of it.
#[derive(Debug)]
struct FailsOnce {
    room: usize,
    failed: bool,
}

impl FailsOnce {
    fn new(room: usize) -> FailsOnce {
        FailsOnce {
            room,
            failed: false,
        }
    }
}

impl Write for FailsOnce {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.room == 0 && !self.failed {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "the disk is full",
            ));
        }
        if self.failed {
            return Ok(buf.len());
        }
        let n = buf.len().min(self.room);
        self.room -= n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_destination_that_fails_stays_failed() {
    let to = a_key();

    // In the header.
    let (source, _) = counting_source(vec![9; 64]);
    let dst = FailsOnce::new(10);
    let got = encrypt(dst, &[&to as &dyn Recipient], Some(&source));
    assert!(matches!(got, Err(EncryptError::Io(_))));

    // In the payload: later writes and the end give the same failure.
    let (source, _) = counting_source(vec![9; 64]);
    let dst = FailsOnce::new(1000);
    let mut w = encrypt(dst, &[&to as &dyn Recipient], Some(&source)).unwrap();
    let e = w.write_all(&vec![1; 70_000]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::StorageFull);
    let e = w.write(b"more").unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::StorageFull);
    assert_eq!(e.to_string(), "the disk is full");
    assert_eq!(w.flush().unwrap_err().kind(), io::ErrorKind::StorageFull);
    assert_eq!(w.finish().unwrap_err().kind(), io::ErrorKind::StorageFull);

    // Through the armor.
    let mut a = ArmoredWriter::new(FailsOnce::new(40));
    assert_eq!(
        a.write(&[1; 480]).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(
        a.write(&[1; 480]).unwrap_err().kind(),
        io::ErrorKind::StorageFull
    );
    assert_eq!(a.finish().unwrap_err().kind(), io::ErrorKind::StorageFull);
}

#[test]
fn the_armor_reads_back_at_every_length() {
    for len in (0..200).chain([479, 480, 481]) {
        let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let mut rng = Rng(0xa9e_e005 + len as u64);
        let mut a = ArmoredWriter::new(Vec::new());
        write_in_pieces(&mut a, &data, &mut rng);
        let file = a.finish().unwrap();
        for line in file.split(|&c| c == b'\n') {
            assert!(line.len() <= 64 || line.starts_with(b"-----"), "{line:?}");
        }
        let mut out = Vec::new();
        ArmoredReader::new(&file[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, data, "{len}");
    }
}
