//! PPMd entries (method 98), which libzip does not read: the port reads
//! them with `ppmd8.rs`, the port of 7-Zip's PPMd var.I, as 7-Zip's ZIP
//! handler does. `src/ppmd8_oracle.rs` compares the model with 7-Zip's
//! `Ppmd8.c`; here are whole archives:
//! - made by `7zz` at several orders, memory sizes and restore methods,
//!   plain and encrypted, read back as the files they were made of;
//! - those damaged, refused where `7zz t` refuses them;
//! - libarchive's PPMd test archives, read, and the two that crashed it
//!   refused.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hivepack::deflate::crc32;
use hivepack::zip::{Archive, ErrorCode, Flags, OpenFlags, cm};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `folder` of the cache `scripts/testdata.py` fills, if it made it; CI
/// lists `group` in `HIVEPACK_TESTDATA_REQUIRED` where it does, and then a
/// missing one fails the test.
fn testdata(folder: &str, group: &str) -> Option<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let folder = cache.join(folder);
    if folder.join(".complete").exists() {
        return Some(folder);
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == group),
        "{} is missing: run `python3 scripts/testdata.py fetch --group {group}`",
        folder.display()
    );
    eprintln!(
        "skipping: {} is not there (scripts/testdata.py fetch --group {group})",
        folder.display()
    );
    None
}

/// A folder of the system's temporary one, emptied.
fn scratch(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("hivepack-zip-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// xorshift64*, so that failures can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const WORDS: [&str; 20] = [
    "the", "of", "archive", "entry", "and", "PPMd", "model", "context", "a", "to", "is", "data",
    "symbol", "order", "in", "memory", "\n", "zip", ", ", "range",
];

/// Files of a few kinds, to wear the model differently: text, text with
/// noise in it (which fills the model's memory quickest), runs, records,
/// and the smallest.
fn files(rng: &mut Rng) -> Vec<(String, Vec<u8>)> {
    let mut text = Vec::new();
    while text.len() < 100_000 {
        text.extend_from_slice(WORDS[rng.below(WORDS.len() as u64) as usize].as_bytes());
        text.push(b' ');
    }
    let mut noisy = Vec::new();
    while noisy.len() < 300_000 {
        if rng.below(4) == 0 {
            let n = 1 + rng.below(40);
            noisy.extend((0..n).map(|_| rng.next() as u8));
        } else {
            noisy.extend_from_slice(WORDS[rng.below(WORDS.len() as u64) as usize].as_bytes());
        }
    }
    let mut runs = Vec::new();
    while runs.len() < 100_000 {
        let b = rng.below(3) as u8;
        runs.extend(std::iter::repeat_n(b, 1 + rng.below(500) as usize));
    }
    let mut records = Vec::new();
    for i in 0u32..10_000 {
        records.extend_from_slice(&i.to_le_bytes());
        records.extend_from_slice(b"rec:");
        records.push(rng.below(16) as u8);
    }
    vec![
        ("text".into(), text),
        ("noisy".into(), noisy),
        ("runs".into(), runs),
        ("records".into(), records),
        ("one".into(), b"x".to_vec()),
        ("empty".into(), Vec::new()),
    ]
}

/// The archive `7zz` makes of `files`, in the folder `f` of `dir`, with
/// `options`.
fn seven_zip_archive(
    tool: &Path,
    dir: &Path,
    files: &[(String, Vec<u8>)],
    options: &str,
) -> Vec<u8> {
    let folder = dir.join("f");
    let _ = std::fs::remove_dir_all(&folder);
    std::fs::create_dir_all(&folder).unwrap();
    for (name, data) in files {
        std::fs::write(folder.join(name), data).unwrap();
    }
    let out = dir.join("made.zip");
    let _ = std::fs::remove_file(&out);
    let status = Command::new(tool)
        .current_dir(dir)
        .args(["a", "-tzip", "-bd", "-bso0", "-bsp0", "-y"])
        .args(options.split_whitespace())
        .arg(&out)
        .arg("f")
        .stdout(Stdio::null())
        .status()
        .expect("7zz starts");
    assert!(status.success(), "7zz failed with {options}");
    std::fs::read(&out).unwrap()
}

/// Whether `7zz t` finds the archive `zip` sound.
fn seven_zip_tests(tool: &Path, dir: &Path, zip: &[u8], password: &str) -> bool {
    let path = dir.join("tested.zip");
    std::fs::write(&path, zip).unwrap();
    Command::new(tool)
        .args(["t", "-bd", "-bso0", "-bse0", "-bsp0"])
        .arg(format!("-p{password}"))
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("7zz starts")
        .success()
}

/// An entry read in pieces of growing sizes: the data, or the error.
fn read_entry<R: hivepack::zip::ReadAt>(
    za: &Archive<R>,
    index: u64,
) -> hivepack::zip::Result<Vec<u8>> {
    let mut zf = za.fopen_index(index, Flags::NONE)?;
    let mut data = Vec::new();
    let mut buf = vec![0; 100_000];
    let mut piece = 1;
    loop {
        let n = zf.fread(&mut buf[..piece])?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        piece = (piece * 2 + 1).min(buf.len());
    }
    zf.fclose()?;
    Ok(data)
}

/// Every file of an archive, by name, with its method: the data, or the
/// error.
type Entries = Vec<(String, u16, hivepack::zip::Result<Vec<u8>>)>;

fn read_all(
    zip: &[u8],
    flags: OpenFlags,
    password: Option<&[u8]>,
) -> hivepack::zip::Result<Entries> {
    let mut za = Archive::open(zip, flags)?;
    za.set_default_password(password);
    let mut entries = Vec::new();
    for i in 0..za.get_num_entries(Flags::NONE) {
        let st = za.stat_index(i, Flags::NONE)?;
        let name = String::from_utf8_lossy(st.name.unwrap_or_default()).into_owned();
        if name.ends_with('/') {
            continue;
        }
        let method = st.comp_method;
        entries.push((name, method, read_entry(&za, i)));
    }
    Ok(entries)
}

#[test]
fn reads_7zip_ppmd_archives() {
    let Some(tool) = testdata("7zz", "generated").map(|f| f.join("7zz")) else {
        return;
    };
    let dir = scratch("ppmd-made");
    let mut rng = Rng(0x9800_0001);
    let files = files(&mut rng);
    for options in [
        // Level 5: order 8, restarting the model when its memory runs out.
        "-mm=PPMd",
        // Level 1: order 4 and 1 MiB.
        "-mm=PPMd -mx=1",
        // Level 9: order 12, cutting the model off.
        "-mm=PPMd -mx=9",
        "-mm=PPMd -mo=2 -mmem=1m",
        "-mm=PPMd -mo=16 -mmem=1m",
        "-mm=PPMd -mx=9 -mo=16 -mmem=1m",
        "-mm=PPMd -mx=7 -mo=6 -mmem=3m",
        "-mm=PPMd -mo=3 -mmem=256m",
        "-mm=PPMd -pSecret -mem=AES256",
        "-mm=PPMd -mx=9 -pSecret -mem=ZipCrypto",
    ] {
        let zip = seven_zip_archive(&tool, &dir, &files, options);
        let password = options.contains("-p").then_some(&b"Secret"[..]);
        // Decoding is slow unoptimized: without ZIP_CHECKCONS once.
        let all_flags = [OpenFlags::CHECKCONS, OpenFlags(0)];
        let flags_used = if options == "-mm=PPMd" {
            &all_flags[..]
        } else {
            &all_flags[..1]
        };
        for &flags in flags_used {
            let entries = read_all(&zip, flags, password).unwrap();
            assert_eq!(entries.len(), files.len(), "{options}");
            let mut ppmd = 0;
            for (name, method, data) in entries {
                let (_, want) = files
                    .iter()
                    .find(|(n, _)| format!("f/{n}") == name)
                    .unwrap();
                let data = data.unwrap_or_else(|e| panic!("{name} with {options}: {e}"));
                assert!(data == *want, "{name} with {options}: {} bytes", data.len());
                ppmd += usize::from(method == cm::PPMD);
            }
            // The empty file and the one of a byte are stored.
            assert!(ppmd >= files.len() - 2, "{options}: {ppmd} PPMd entries");
        }
    }
    // Through std::io::Read too, and raw.
    let zip = seven_zip_archive(&tool, &dir, &files[..1], "-mm=PPMd");
    let za = Archive::open(&zip[..], OpenFlags::CHECKCONS).unwrap();
    let mut got = Vec::new();
    za.fopen(b"f/text", Flags::NONE)
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    assert!(got == files[0].1);
    let mut raw = Vec::new();
    za.fopen_index(0, Flags::COMPRESSED)
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_eq!(
        raw.len() as u64,
        za.stat_index(0, Flags::NONE).unwrap().comp_size
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Where the data of the first PPMd entry of `zip`, one `7zz` made,
/// starts, and its length.
fn ppmd_data(zip: &[u8]) -> (usize, usize) {
    let u16_at = |at: usize| u16::from_le_bytes([zip[at], zip[at + 1]]);
    let mut at = 0;
    loop {
        assert_eq!(&zip[at..at + 4], b"PK\x03\x04");
        let comp_size = u32::from_le_bytes(zip[at + 18..at + 22].try_into().unwrap()) as usize;
        let start = at + 30 + usize::from(u16_at(at + 26)) + usize::from(u16_at(at + 28));
        if u16_at(at + 8) == cm::PPMD {
            return (start, comp_size);
        }
        at = start + comp_size;
    }
}

#[test]
fn damaged_ppmd_entries_fail_where_7zip_fails() {
    let Some(tool) = testdata("7zz", "generated").map(|f| f.join("7zz")) else {
        return;
    };
    let dir = scratch("ppmd-damaged");
    let mut rng = Rng(0x9800_0002);
    let text = files(&mut rng).swap_remove(0);
    let short = (text.0, text.1[..20_000].to_vec());
    let mut checked = [0; 2];
    for options in ["-mm=PPMd -mo=6 -mmem=1m", "-mm=PPMd -mx=9 -mo=16 -mmem=1m"] {
        let zip = seven_zip_archive(&tool, &dir, std::slice::from_ref(&short), options);
        let (start, len) = ppmd_data(&zip);
        for case in 0..60 {
            let mut damaged = zip.clone();
            // The parameters, the range coder's first bytes, its last, or
            // anywhere.
            let at = start
                + match case % 4 {
                    0 => rng.below(2) as usize,
                    1 => 2 + rng.below(4) as usize,
                    2 => len - 1 - rng.below(4) as usize,
                    _ => rng.below(len as u64) as usize,
                };
            damaged[at] ^= 1 << rng.below(8);
            let sound = seven_zip_tests(&tool, &dir, &damaged, "");
            let read = read_all(&damaged, OpenFlags::CHECKCONS, None).unwrap();
            let (_, _, data) = read.iter().find(|(_, m, _)| *m == cm::PPMD).unwrap();
            assert_eq!(
                data.is_ok(),
                sound,
                "{options}, byte {} of {len}: {:?}",
                at - start,
                data.as_ref().err()
            );
            if let Ok(data) = data {
                assert!(*data == short.1);
            }
            checked[usize::from(sound)] += 1;
        }
    }
    assert!(checked[0] > 60, "only {} refused", checked[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An archive of one PPMd entry named "p", with `stream` as its data and
/// the CRC and size of `data`.
fn archive(stream: &[u8], data: &[u8]) -> Vec<u8> {
    let crc = crc32(0, data);
    let mut header = Vec::new();
    for (v, n) in [(63u32, 2), (0, 2), (98, 2), (0, 2), (0x5b21, 2), (crc, 4)] {
        header.extend_from_slice(&v.to_le_bytes()[..n]);
    }
    header.extend_from_slice(&(stream.len() as u32).to_le_bytes());
    header.extend_from_slice(&(data.len() as u32).to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(b"p");
    zip.extend_from_slice(stream);
    let cd_offset = zip.len() as u32;
    zip.extend_from_slice(b"PK\x01\x02\x3f\x03");
    zip.extend_from_slice(&header);
    zip.extend_from_slice(&[0; 12]); // extra and comment lengths, disk, attributes
    zip.extend_from_slice(&0u32.to_le_bytes()); // the local header's offset
    zip.extend_from_slice(b"p");
    let cd_size = zip.len() as u32 - cd_offset;
    zip.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    zip.extend_from_slice(&cd_size.to_le_bytes());
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

/// The one entry of `zip`: the data, or the error's code.
fn read_one(zip: &[u8], flags: OpenFlags) -> Result<Vec<u8>, ErrorCode> {
    let za = Archive::open(zip, flags).map_err(|e| e.code())?;
    read_entry(&za, 0).map_err(|e| e.code())
}

/// "hello hello hello" at order 6 with 16 MiB, made by 7-Zip's
/// `Ppmd8_EncodeSymbol` (`tools/7z-oracle`), after its parameters.
const HELLO: [u8; 12] = [
    0x67, 0xfb, 0x83, 0x54, 0xd7, 0x35, 0x97, 0x58, 0xaf, 0xc0, 0x4f, 0x00,
];

fn hello(params: u16) -> Vec<u8> {
    let mut stream = params.to_le_bytes().to_vec();
    stream.extend_from_slice(&HELLO);
    stream
}

#[test]
fn checks_ppmd_parameters_and_ends() {
    let data = b"hello hello hello";
    // Order 6, 16 MiB, restarting: 5 | 15 << 4.
    let params = 5 | 15 << 4;
    assert_eq!(
        read_one(&archive(&hello(params), data), OpenFlags::CHECKCONS),
        Ok(data.to_vec())
    );

    // An order of 1, and a restore method past 2: data errors; 2 (freezing
    // the model): not supported, as by 7-Zip.
    assert_eq!(
        read_one(&archive(&hello(params & !0xF), data), OpenFlags(0)),
        Err(ErrorCode::CompressedData)
    );
    assert_eq!(
        read_one(&archive(&hello(params | 3 << 12), data), OpenFlags(0)),
        Err(ErrorCode::CompressedData)
    );
    assert_eq!(
        read_one(&archive(&hello(params | 2 << 12), data), OpenFlags(0)),
        Err(ErrorCode::CompNotSupp)
    );

    // One byte of the parameters, and the parameters alone. (No data at all
    // is libzip's ZIP_ER_INVAL, for every method.)
    for stream in [&[0xF5][..], &[0xF5, 0x00]] {
        assert_eq!(
            read_one(&archive(stream, data), OpenFlags(0)),
            Err(ErrorCode::CompressedData),
            "{stream:?}"
        );
    }

    // Cut short anywhere: an error, never the data.
    let stream = hello(params);
    for cut in 2..stream.len() {
        assert!(
            read_one(&archive(&stream[..cut], data), OpenFlags(0)).is_err(),
            "{cut}"
        );
    }

    // Bytes after the marker: refused with ZIP_CHECKCONS only, as after
    // the other methods' data.
    let mut longer = stream.clone();
    longer.extend_from_slice(b"junk");
    assert_eq!(
        read_one(&archive(&longer, data), OpenFlags(0)),
        Ok(data.to_vec())
    );
    assert_eq!(
        read_one(&archive(&longer, data), OpenFlags::CHECKCONS),
        Err(ErrorCode::Incons)
    );

    // A wrong CRC: the data, then the error.
    assert_eq!(
        read_one(&archive(&stream, b"hello hello hellO"), OpenFlags(0)),
        Err(ErrorCode::Crc)
    );
}

#[test]
fn damaged_ppmd_entries_do_not_panic() {
    let mut rng = Rng(0x9800_0003);
    let data = b"hello hello hello";
    for _ in 0..3000 {
        let mut stream = hello(5 | (rng.below(4) as u16) << 4);
        stream.extend((0..rng.below(64)).map(|_| rng.next() as u8));
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(stream.len() as u64) as usize;
            match rng.below(3) {
                0 => stream[at] ^= 1 << rng.below(8),
                1 => stream.truncate(at.max(2)),
                _ => stream.insert(at, rng.next() as u8),
            }
        }
        for flags in [OpenFlags(0), OpenFlags::CHECKCONS] {
            let _ = read_one(&archive(&stream, data), flags);
        }
    }
}

#[test]
fn reads_libarchive_ppmd_archives() {
    let Some(folder) = testdata("libarchive-zip-ppmd", "core") else {
        return;
    };
    let read = |name: &str, password: Option<&[u8]>| {
        let zip = std::fs::read(folder.join(name)).unwrap();
        // Not with ZIP_CHECKCONS: libarchive writes local headers that do
        // not match the central directory.
        read_all(&zip, OpenFlags(0), password).unwrap()
    };
    // As libarchive's test_read_format_zip.c reads them.
    for (name, want) in [
        ("zip_ppmd8.zipx", &[("vimrc", 0xBA8E_3BAA)][..]),
        (
            "zip_ppmd8_multi.zipx",
            &[
                ("smartd.conf", 0x8DD7_379E),
                ("ts.conf", 0x7AE5_9B31),
                ("vimrc", 0xBA8E_3BAA),
            ],
        ),
    ] {
        let entries = read(name, None);
        assert_eq!(entries.len(), want.len(), "{name}");
        for ((got, method, data), (want, crc)) in entries.into_iter().zip(want) {
            assert_eq!(got, *want, "{name}");
            assert_eq!(method, cm::PPMD, "{name}");
            assert_eq!(crc32(0, &data.unwrap()), *crc, "{name}: {got}");
        }
    }
    // Encrypted with WinZip's AES.
    let entries = read("zip_winzip_aes256_large_ppmd.zip", Some(b"password"));
    assert!(entries.len() > 1);
    for (name, method, data) in entries {
        assert_eq!(method, cm::PPMD, "{name}");
        data.unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    let entries = read(
        "zip_ppmd8_aes256_streaming.zipx",
        Some(b"test_password_zipx"),
    );
    let [(_, method, data)] = &entries[..] else {
        panic!("{} entries", entries.len());
    };
    assert_eq!(*method, cm::PPMD);
    let data = data.as_ref().unwrap();
    assert!(data.starts_with(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz\n"));
    assert!(data.ends_with(b"Sixty zippers were quickly picked from the bag.\n"));
    // Those that crashed libarchive: an error.
    for name in ["zip_ppmd8_crash_1.zipx", "zip_ppmd8_crash_2.zipx"] {
        let zip = std::fs::read(folder.join(name)).unwrap();
        let refused = match read_all(&zip, OpenFlags(0), None) {
            Err(_) => true,
            Ok(entries) => entries.iter().any(|(_, _, data)| data.is_err()),
        };
        assert!(refused, "{name}");
    }
}
