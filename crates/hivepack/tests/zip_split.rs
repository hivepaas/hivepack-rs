//! Split archives, which libzip refuses with `ZIP_ER_MULTIDISK`: read from
//! their volumes, joined by `Volumes`.
//!
//! - Info-ZIP's (`testdata/zip-split`, made by `zip -s 64k`): plain, Zip64
//!   and ZipCrypto, read back to the files they were made of.
//! - Archives `7zz` makes, split here as Info-ZIP splits them, at volume
//!   sizes that cut local headers, data, central directory records and the
//!   end record's neighbours: read back to the files, where `7zz t` must
//!   find the same volumes sound.
//! - 7-Zip's `.zip.001` volumes, which cut an archive of one disk.
//! - A volume missing, or the last alone: `ZIP_ER_MULTIDISK`, as libzip.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hivepack::deflate::crc32;
use hivepack::zip::{Archive, Closed, ErrorCode, Flags, OpenFlags, ReadAt, Volumes, volume_paths};

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `7zz`, if `scripts/testdata.py` built it; CI lists the `generated`
/// group in `HIVEPACK_TESTDATA_REQUIRED` where it does, and then a missing
/// one fails the test.
fn seven_zip() -> Option<PathBuf> {
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"));
    let folder = cache.join("7zz");
    if folder.join(".complete").exists() {
        return Some(folder.join("7zz"));
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == "generated"),
        "7zz is missing: run `python3 scripts/testdata.py fetch --group generated`"
    );
    eprintln!("skipping: 7zz is not built (scripts/testdata.py fetch --group generated)");
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

/// Every file of an archive, by name: its data, read to its end (which
/// checks its CRC-32 and length).
fn read_files<R: ReadAt>(za: &Archive<R>) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for i in 0..za.get_num_entries(Flags::NONE) {
        let name = String::from_utf8_lossy(za.get_name(i, Flags::NONE).unwrap()).into_owned();
        if name.ends_with('/') {
            continue;
        }
        let mut zf = za
            .fopen_index(i, Flags::NONE)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut data = Vec::new();
        let mut buf = vec![0; 7_000];
        loop {
            let n = zf.fread(&mut buf).unwrap_or_else(|e| panic!("{name}: {e}"));
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        zf.fclose().unwrap();
        files.push((name, data));
    }
    files
}

#[test]
fn reads_info_zip_split_archives() {
    let folder = repository().join("testdata/zip-split");
    let contents = std::fs::read_to_string(folder.join("contents.txt")).unwrap();
    let contents: Vec<(&str, usize, u32)> = contents
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let [name, size, crc] = l.split('\t').collect::<Vec<_>>()[..] else {
                panic!("{l}");
            };
            (
                name,
                size.parse().unwrap(),
                u32::from_str_radix(crc, 16).unwrap(),
            )
        })
        .collect();
    for (name, volumes, password, only) in [
        ("infozip.zip", 3, None, None),
        // libzip finds the local headers of `zip -fz` unlike the central
        // directory's (ZIP_ER_INCONS, ZIP_ER_DETAIL_ENTRY_HEADER_MISMATCH),
        // split or not: not read with ZIP_CHECKCONS.
        ("infozip64.zip", 3, None, None),
        (
            "infozip-crypt.zip",
            2,
            Some(&b"secret"[..]),
            Some(
                &[
                    "f/text.txt",
                    "f/noise.bin",
                    "f/sub/empty",
                    "f/sub/small.txt",
                ][..],
            ),
        ),
    ] {
        let paths = volume_paths(&folder.join(name));
        assert_eq!(paths.len(), volumes, "{name}");
        let checkcons = if name == "infozip64.zip" {
            OpenFlags::RDONLY
        } else {
            OpenFlags::RDONLY | OpenFlags::CHECKCONS
        };
        for flags in [OpenFlags::RDONLY, checkcons] {
            let mut za = Archive::open(Volumes::open(folder.join(name)).unwrap(), flags)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            za.set_default_password(password);
            let mut got = read_files(&za);
            got.sort();
            let mut want: Vec<_> = contents
                .iter()
                .filter(|(n, _, _)| only.is_none_or(|only| only.contains(n)))
                .collect();
            want.sort();
            assert_eq!(got.len(), want.len(), "{name}");
            for ((got, data), (want, size, crc)) in got.iter().zip(&want) {
                assert_eq!(got, want, "{name}");
                assert_eq!(data.len(), *size, "{name}: {got}");
                assert_eq!(crc32(0, data), *crc, "{name}: {got}");
            }
        }
        // The last volume alone, as libzip reads it, and the volumes
        // without the first.
        let last = std::fs::File::open(folder.join(name)).unwrap();
        assert_eq!(
            Archive::open(last, OpenFlags::RDONLY)
                .err()
                .map(|e| e.code()),
            Some(ErrorCode::MultiDisk),
            "{name}"
        );
        let parts: Vec<_> = paths[1..]
            .iter()
            .map(|p| std::fs::File::open(p).unwrap())
            .collect();
        assert_eq!(
            Archive::open(Volumes::new(parts).unwrap(), OpenFlags::RDONLY)
                .err()
                .map(|e| e.code()),
            Some(ErrorCode::MultiDisk),
            "{name}"
        );
    }
}

/// Files of a few kinds, some large enough to cross volumes.
fn test_files(rng: &mut Rng) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for i in 0..12 {
        let len = match i % 4 {
            0 => rng.below(40) as usize,
            1 => rng.below(3_000) as usize,
            _ => rng.below(30_000) as usize,
        };
        let data: Vec<u8> = if i % 3 == 0 {
            (0..len).map(|_| rng.next() as u8).collect()
        } else {
            (0..len).map(|j| b"split volumes "[(j + i) % 14]).collect()
        };
        files.push((format!("f/file-{i:02}.bin"), data));
    }
    files
}

/// The archive `7zz` makes of `files`, in the folder `f` of `dir`.
fn seven_zip_archive(
    tool: &Path,
    dir: &Path,
    files: &[(String, Vec<u8>)],
    options: &str,
) -> Vec<u8> {
    for (name, data) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
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

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

/// The volumes being written: each new piece goes on the last, which is
/// full at `size` bytes.
struct Layout {
    size: usize,
    volumes: Vec<Vec<u8>>,
}

impl Layout {
    /// Puts `bytes` on the volumes, whole on one (on the next if they do not
    /// fit on this one) or, if not `whole`, cut where the volumes are full.
    /// Returns where they start: the volume's number and the offset in it.
    fn put(&mut self, bytes: &[u8], whole: bool) -> (usize, usize) {
        let last = self.volumes.len() - 1;
        if whole
            && !self.volumes[last].is_empty()
            && self.volumes[last].len() + bytes.len() > self.size
        {
            self.volumes.push(Vec::new());
        }
        let start = (
            self.volumes.len() - 1,
            self.volumes[self.volumes.len() - 1].len(),
        );
        if whole {
            self.volumes.last_mut().unwrap().extend_from_slice(bytes);
            return start;
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let room = self.size.saturating_sub(self.volumes.last().unwrap().len());
            if room == 0 {
                self.volumes.push(Vec::new());
                continue;
            }
            let n = room.min(rest.len());
            self.volumes
                .last_mut()
                .unwrap()
                .extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        }
        start
    }
}

/// `zip`, an archive of one disk without Zip64 records or a comment, split
/// into volumes of at most `size` bytes as Info-ZIP's `zip -s` splits it:
/// the split signature first (if `signature`); the data of the entries cut
/// where a volume is full, but each header whole on one volume; each local
/// header's offset from the start of its volume, with the volume's number,
/// in its central directory record; and the end of central directory
/// record with the number of the last volume, of the one the central
/// directory starts on and of its records on the last.
fn split(zip: &[u8], size: usize, signature: bool) -> Vec<Vec<u8>> {
    let eocd = zip.len() - 22;
    assert_eq!(
        &zip[eocd..eocd + 4],
        b"PK\x05\x06",
        "an archive without a comment"
    );
    let entries = usize::from(u16_at(zip, eocd + 10));
    let cd = u32_at(zip, eocd + 16) as usize;
    let mut records = Vec::new();
    let mut at = cd;
    for _ in 0..entries {
        assert_eq!(&zip[at..at + 4], b"PK\x01\x02");
        let len = 46
            + usize::from(u16_at(zip, at + 28))
            + usize::from(u16_at(zip, at + 30))
            + usize::from(u16_at(zip, at + 32));
        records.push(zip[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(at, eocd);

    let mut layout = Layout {
        size,
        volumes: vec![Vec::new()],
    };
    if signature {
        layout.put(b"PK\x07\x08", true);
    }
    // The local headers and data, in order, where they are now.
    let mut locals: Vec<usize> = records.iter().map(|r| u32_at(r, 42) as usize).collect();
    locals.sort_unstable();
    let mut placed = std::collections::HashMap::new();
    for (i, &local) in locals.iter().enumerate() {
        assert_eq!(&zip[local..local + 4], b"PK\x03\x04");
        let header =
            30 + usize::from(u16_at(zip, local + 26)) + usize::from(u16_at(zip, local + 28));
        let end = locals.get(i + 1).copied().unwrap_or(cd);
        placed.insert(local, layout.put(&zip[local..local + header], true));
        layout.put(&zip[local + header..end], false);
    }
    let mut cd_start = None;
    let mut starts = Vec::new();
    for mut record in records {
        let (disk, offset) = placed[&(u32_at(&record, 42) as usize)];
        record[34..36].copy_from_slice(&(disk as u16).to_le_bytes());
        record[42..46].copy_from_slice(&(offset as u32).to_le_bytes());
        let start = layout.put(&record, true);
        cd_start.get_or_insert(start);
        starts.push(start.0);
    }
    let mut end = zip[eocd..].to_vec();
    let (eocd_disk, _) = layout.put(&end, true);
    let (cd_disk, cd_offset) =
        cd_start.unwrap_or((eocd_disk, layout.volumes[eocd_disk].len() - 22));
    let on_last = starts.iter().filter(|&&disk| disk == eocd_disk).count();
    end[4..6].copy_from_slice(&(eocd_disk as u16).to_le_bytes());
    end[6..8].copy_from_slice(&(cd_disk as u16).to_le_bytes());
    end[8..10].copy_from_slice(&(on_last as u16).to_le_bytes());
    end[16..20].copy_from_slice(&(cd_offset as u32).to_le_bytes());
    let last = layout.volumes.last_mut().unwrap();
    let at = last.len() - 22;
    last[at..].copy_from_slice(&end);
    layout.volumes
}

/// The volumes of `split`, then cut again anywhere, headers too: what no
/// writer makes, but what reading the volumes as one byte space reads all
/// the same. Each volume is cut in two where `rng` says, the numbers and
/// offsets made for the volumes that result.
fn split_anywhere(zip: &[u8], size: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    let mut data = b"PK\x07\x08".to_vec();
    data.extend_from_slice(zip);
    let eocd = data.len() - 22;
    let starts: Vec<usize> = (0..)
        .map(|k| {
            k * size
                + if k == 0 {
                    0
                } else {
                    rng.below(size as u64 / 2 + 1) as usize
                }
        })
        .take_while(|&start| start <= eocd)
        .collect();
    let disk = |at: usize| starts.partition_point(|&start| start <= at) - 1;
    let last = starts.len() - 1;
    let entries = usize::from(u16_at(&data, eocd + 10));
    let cd = 4 + u32_at(&data, eocd + 16) as usize;
    let mut at = cd;
    let mut on_last = 0u16;
    for _ in 0..entries {
        let local = 4 + u32_at(&data, at + 42) as usize;
        let local_disk = disk(local);
        data[at + 34..at + 36].copy_from_slice(&(local_disk as u16).to_le_bytes());
        data[at + 42..at + 46]
            .copy_from_slice(&((local - starts[local_disk]) as u32).to_le_bytes());
        on_last += u16::from(disk(at) == last);
        at += 46
            + usize::from(u16_at(&data, at + 28))
            + usize::from(u16_at(&data, at + 30))
            + usize::from(u16_at(&data, at + 32));
    }
    data[eocd + 4..eocd + 6].copy_from_slice(&(last as u16).to_le_bytes());
    data[eocd + 6..eocd + 8].copy_from_slice(&(disk(cd) as u16).to_le_bytes());
    data[eocd + 8..eocd + 10].copy_from_slice(&on_last.to_le_bytes());
    data[eocd + 16..eocd + 20].copy_from_slice(&((cd - starts[disk(cd)]) as u32).to_le_bytes());
    (0..starts.len())
        .map(|i| data[starts[i]..starts.get(i + 1).copied().unwrap_or(data.len())].to_vec())
        .collect()
}

/// Writes `parts` as `name.z01`, `name.z02`, …, `name.zip` in `dir`,
/// removing what was there, and returns the path of the last.
fn write_volumes(dir: &Path, name: &str, parts: &[Vec<u8>]) -> PathBuf {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            std::fs::remove_file(path).unwrap();
        }
    }
    for (i, part) in parts.iter().enumerate() {
        let path = if i + 1 == parts.len() {
            dir.join(format!("{name}.zip"))
        } else {
            dir.join(format!("{name}.z{:02}", i + 1))
        };
        std::fs::write(path, part).unwrap();
    }
    dir.join(format!("{name}.zip"))
}

/// Whether `7zz t` finds the archive at `path` (with its volumes) sound,
/// with the password "Secret" for what is encrypted.
fn seven_zip_tests(tool: &Path, path: &Path) -> bool {
    Command::new(tool)
        .args(["t", "-bd", "-bso0", "-bse0", "-bsp0", "-pSecret"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("7zz starts")
        .success()
}

#[test]
fn reads_split_archives_as_7zip_does() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("split-made");
    let volumes = dir.join("volumes");
    std::fs::create_dir_all(&volumes).unwrap();
    let mut rng = Rng(0x5011_0001);
    let files = test_files(&mut rng);
    let mut want = files.clone();
    want.sort();
    for options in ["-mm=Deflate", "-mm=Copy", "-mm=BZip2 -pSecret"] {
        let zip = seven_zip_archive(&tool, &dir, &files, options);
        let password = options.contains("-p").then_some(&b"Secret"[..]);
        let cd = u32_at(&zip, zip.len() - 6) as usize;
        let mut sizes = vec![zip.len() / 2, zip.len() - 30, cd, cd + 50, zip.len() - 22];
        for _ in 0..16 {
            sizes.push(37 + rng.below(zip.len() as u64 / 3) as usize);
        }
        for (case, &size) in sizes.iter().enumerate() {
            let signature = case % 3 != 2;
            let parts = split(&zip, size.max(1), signature);
            let path = write_volumes(&volumes, "s", &parts);
            assert!(
                seven_zip_tests(&tool, &path),
                "7zz refuses {options} in volumes of {size}"
            );
            for flags in [OpenFlags::RDONLY, OpenFlags::RDONLY | OpenFlags::CHECKCONS] {
                let mut za = Archive::open(Volumes::open(&path).unwrap(), flags)
                    .unwrap_or_else(|e| panic!("{options} in volumes of {size}: {e}"));
                za.set_default_password(password);
                let mut got = read_files(&za);
                got.sort();
                assert!(got == want, "{options} in volumes of {size}");
            }
            // Cut anywhere, headers too.
            let anywhere = split_anywhere(&zip, size.max(2), &mut rng);
            let mut za = Archive::open(Volumes::new(anywhere).unwrap(), OpenFlags::CHECKCONS)
                .unwrap_or_else(|e| panic!("{options} cut anywhere at {size}: {e}"));
            za.set_default_password(password);
            let mut got = read_files(&za);
            got.sort();
            assert!(got == want, "{options} cut anywhere at {size}");
            if parts.len() > 2 {
                // A volume missing, and two swapped.
                let mut missing = parts.clone();
                missing.remove(1 + rng.below(parts.len() as u64 - 2) as usize);
                assert_eq!(
                    Archive::open(Volumes::new(missing).unwrap(), OpenFlags::RDONLY)
                        .err()
                        .map(|e| e.code()),
                    Some(ErrorCode::MultiDisk)
                );
                let mut swapped = parts.clone();
                swapped.swap(0, 1);
                if let Ok(mut za) = Archive::open(Volumes::new(swapped).unwrap(), OpenFlags::RDONLY)
                {
                    za.set_default_password(password);
                    let any_fails = (0..za.get_num_entries(Flags::NONE)).any(|i| {
                        let Ok(mut zf) = za.fopen_index(i, Flags::NONE) else {
                            return true;
                        };
                        let mut buf = vec![0; 1 << 16];
                        loop {
                            match zf.fread(&mut buf) {
                                Ok(0) => return false,
                                Ok(_) => {}
                                Err(_) => return true,
                            }
                        }
                    });
                    assert!(any_fails, "{options} in volumes of {size}, swapped");
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reads_7zip_volumes() {
    let Some(tool) = seven_zip() else {
        return;
    };
    let dir = scratch("split-7z");
    let mut rng = Rng(0x5011_0002);
    let files = test_files(&mut rng);
    let mut want = files.clone();
    want.sort();
    for (name, data) in &files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }
    let status = Command::new(&tool)
        .current_dir(&dir)
        .args([
            "a", "-tzip", "-bd", "-bso0", "-bsp0", "-y", "-v5k", "v.zip", "f",
        ])
        .stdout(Stdio::null())
        .status()
        .expect("7zz starts");
    assert!(status.success());
    let paths = volume_paths(&dir.join("v.zip.002"));
    assert!(paths.len() > 2, "{} volumes", paths.len());
    let za = Archive::open(
        Volumes::open(dir.join("v.zip.001")).unwrap(),
        OpenFlags::CHECKCONS,
    )
    .unwrap();
    let mut got = read_files(&za);
    got.sort();
    assert!(got == want);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn joins_split_archives() {
    // Written again, a split archive is an archive of one disk.
    let folder = repository().join("testdata/zip-split");
    for name in ["infozip.zip", "infozip64.zip"] {
        let mut za =
            Archive::open(Volumes::open(folder.join(name)).unwrap(), OpenFlags(0)).unwrap();
        let mut want = read_files(&za);
        want.sort();
        // A change, so that the archive is written.
        za.set_archive_comment(b"joined").unwrap();
        let mut out = Cursor::new(Vec::new());
        assert_eq!(za.close_to(&mut out).unwrap(), Closed::Written);
        let joined = out.into_inner();
        let za = Archive::open(joined.as_slice(), OpenFlags::CHECKCONS).unwrap();
        let mut got = read_files(&za);
        got.sort();
        assert!(got == want, "{name}");
    }
}

#[test]
fn checks_the_disks_of_split_archives() {
    let folder = repository().join("testdata/zip-split");
    let paths = volume_paths(&folder.join("infozip.zip"));
    let parts: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let open = |parts: &[Vec<u8>]| {
        Archive::open(Volumes::new(parts.to_vec()).unwrap(), OpenFlags::RDONLY)
            .map(|_| ())
            .map_err(|e| (e.code(), e.detail().map(|(detail, _)| detail)))
    };
    assert_eq!(open(&parts), Ok(()));
    let last = parts.len() - 1;
    let eocd = parts[last].len() - 22;
    let cd = u32_at(&parts[last], eocd + 16) as usize;

    // The central directory on a disk after the last.
    let mut wrong = parts.clone();
    wrong[last][eocd + 6] = 3;
    assert_eq!(
        open(&wrong),
        Err((ErrorCode::Incons, Some(hivepack::zip::Detail::CdirInvalid)))
    );
    // More records on the last disk than in all.
    let mut wrong = parts.clone();
    wrong[last][eocd + 8] = 8;
    assert_eq!(
        open(&wrong),
        Err((
            ErrorCode::Incons,
            Some(hivepack::zip::Detail::CdirWrongEntriesCount)
        ))
    );
    // An entry on a disk past the last.
    let mut wrong = parts.clone();
    let record = if u16_at(&parts[last], eocd + 6) as usize == last {
        cd
    } else {
        panic!("the central directory starts on another volume");
    };
    wrong[last][record + 34] = 9;
    assert_eq!(
        open(&wrong),
        Err((ErrorCode::Incons, Some(hivepack::zip::Detail::CdirInvalid)))
    );
}
