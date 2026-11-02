//! ziptool, with the commands libzip's tests add to it (ziptool_regress):
//! port of libzip's `src/ziptool.c` and `regress/programs/ziptool_regress.c`,
//! The output is libzip's, word for word, so that libzip's tests can run
//! on the port.
//!
//! Differs from libzip: `ziptool_regress_nonrandom`, ziptool built with
//! random bytes that are all zeros so that encrypting is repeatable, is
//! this program with `HIVEPACK_ZIPTOOL_NONRANDOM` set.

use std::io::Write;
use std::process::ExitCode;

use std::sync::Arc;

use hivepack::zip::{
    Archive, ArchiveFlags, BufferSource, DataSource, Error, ErrorCode, FileSource, Flags,
    OpenFlags, Stat, ZipFile, ZipFileSource, cm, em, stat,
};
use ziptool::{
    Getopt, Src, strtoull, zip_close, zip_close_in_memory, zip_open, zip_open_in_memory,
};

/// The state of the C program's globals.
struct Tool {
    za: Archive<Src>,
    stat_flags: Flags,
    hex_encoded_filenames: bool,
    /// the archives `add_from_zip` opened (`z_in`)
    z_in: Vec<Arc<Archive<Src>>>,
    /// the entries opened by `fopen`, each from a copy of the archive as it
    /// was then: libzip's open entries read what they were opened on,
    /// whatever is changed afterwards
    z_files: Vec<ZipFile<'static, Src>>,
    out: std::io::Stdout,
}

/// A command: its name, how many arguments it takes, and what it does.
type Command = (
    &'static str,
    usize,
    fn(&mut Tool, &[String]) -> Result<(), ()>,
);

/// `dispatch_table`, with `DISPATCH_REGRESS`: the commands that read, and
/// those that change the archive without new data.
const DISPATCH_TABLE: &[Command] = &[
    ("add", 2, add),
    ("add_dir", 1, add_dir),
    ("add_file", 4, add_file),
    ("add_from_zip", 5, add_from_zip),
    ("cat", 1, cat),
    ("cat_partial", 3, cat_partial),
    ("count_extra", 2, count_extra),
    ("count_extra_by_id", 3, count_extra_by_id),
    ("delete", 1, delete),
    ("delete_extra", 3, delete_extra),
    ("delete_extra_by_id", 4, delete_extra_by_id),
    ("get_archive_comment", 0, get_archive_comment),
    ("get_archive_flag", 1, get_archive_flag),
    ("get_extra", 3, get_extra),
    ("get_extra_by_id", 4, get_extra_by_id),
    ("get_file_comment", 1, get_file_comment),
    ("get_num_entries", 1, get_num_entries),
    ("name_locate", 2, name_locate),
    ("rename", 2, zrename),
    ("replace_file_contents", 2, replace_file_contents),
    ("set_archive_comment", 1, set_archive_comment),
    ("set_archive_flag", 2, set_archive_flag),
    ("set_extra", 5, set_extra),
    ("set_file_comment", 2, set_file_comment),
    ("set_file_compression", 3, set_file_compression),
    ("set_file_dostime", 3, set_file_dostime),
    ("set_file_mtime", 2, set_file_mtime),
    ("set_file_encryption", 3, set_file_encryption),
    ("set_file_mtime_all", 1, set_file_mtime_all),
    ("set_password", 1, set_password),
    ("stat", 1, zstat),
    ("add_nul", 2, add_nul),
    ("extract_as", 2, extract_as),
    ("fopen", 1, regress_fopen),
    ("fread", 2, regress_fread),
    ("unchange", 1, unchange_one),
    ("unchange_all", 0, unchange_all),
];

/// A name as C sees it: up to its first NUL byte.
fn c_string(name: &[u8]) -> &[u8] {
    &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())]
}

impl Tool {
    fn print(&mut self, bytes: &[u8]) {
        let _ = self.out.write_all(bytes);
    }

    /// `encode_filename`: the name as a C string, without the `\r` of
    /// `\r\n`, or in hexadecimal with `-x`.
    fn encode_filename(&self, name: &[u8]) -> Vec<u8> {
        let name = c_string(name);
        if self.hex_encoded_filenames {
            return name
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect();
        }
        let mut out = Vec::with_capacity(name.len());
        let mut i = 0;
        while i < name.len() {
            if name[i] == b'\r' && name.get(i + 1) == Some(&b'\n') {
                i += 1;
                continue;
            }
            out.push(name[i]);
            i += 1;
        }
        out
    }

    /// `decode_filename`: from hexadecimal with `-x`.
    fn decode_filename(&self, name: &str) -> Vec<u8> {
        if !self.hex_encoded_filenames {
            return name.as_bytes().to_vec();
        }
        let hex2bin = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            _ => c.wrapping_sub(b'a').wrapping_add(10),
        };
        name.as_bytes()
            .chunks(2)
            .map(|p| (hex2bin(p[0]) << 4) | hex2bin(*p.get(1).unwrap_or(&b'0')))
            .collect()
    }

    /// `cat_impl_backend`: `len` bytes of entry `idx` from `start` (all of
    /// it if `len` is 0, the rest if it is `None`), written to `out`.
    fn cat_impl_backend(
        &mut self,
        idx: u64,
        start: u64,
        len: Option<u64>,
        out: &mut dyn Write,
    ) -> Result<(), ()> {
        let mut len = len;
        // we can't pass 0 as a len to zip_source_zip_create because it will
        // try to give us compressed data
        if len == Some(0) {
            match self.za.stat_index(idx, self.stat_flags) {
                Ok(sb) if sb.valid & stat::SIZE == 0 => {
                    eprintln!("can't cat file at index '{idx}' with unknown size");
                    return Err(());
                }
                Ok(sb) => len = Some(sb.size),
                Err(e) => {
                    eprintln!("zip_stat_index failed on '{idx}' failed: {e}");
                    return Err(());
                }
            }
        }
        // zip_source_zip_file_create takes the length as a zip_int64_t:
        // -1, as strtoull reads "-1", is the rest of the data.
        let len = len.filter(|&l| l != u64::MAX);
        let mut zf = match self.za.fopen_index_range(idx, Flags::NONE, start, len) {
            Ok(zf) => zf,
            Err(e) => {
                // zip_source_zip_file_create leaves the error it is given
                // unset when the method has no algorithm, or the
                // encrypted data is shorter than its header.
                let e = if matches!(e.code(), ErrorCode::CompNotSupp | ErrorCode::OpNotSupp) {
                    Error::new(ErrorCode::Ok, 0)
                } else {
                    e
                };
                eprintln!("can't open file at index '{idx}': {e}");
                return Err(());
            }
        };
        let mut buf = vec![0; 8192];
        loop {
            match zf.fread(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = out.write_all(&buf[..n]) {
                        eprintln!("can't write file contents: {e}");
                        return Err(());
                    }
                }
                Err(e) => {
                    eprintln!("can't read file at index '{idx}': {e}");
                    return Err(());
                }
            }
        }
        if let Err(e) = zf.fclose() {
            eprintln!("can't close file at index '{idx}': {e}");
            return Err(());
        }
        Ok(())
    }
}

fn cat(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // output file contents to stdout
    let idx = strtoull(&argv[0]);
    let mut out = std::io::stdout();
    t.cat_impl_backend(idx, 0, Some(0), &mut out)
}

fn cat_partial(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // output partial file contents to stdout
    let idx = strtoull(&argv[0]);
    let start = strtoull(&argv[1]);
    let len = strtoull(&argv[2]);
    let mut out = std::io::stdout();
    t.cat_impl_backend(idx, start, Some(len), &mut out)
}

fn count_extra(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let ceflags = get_flags(&argv[1]);
    match t.za.file_extra_fields_count(idx, ceflags) {
        Ok(count) => {
            t.print(format!("Extra field count: {count}\n").as_bytes());
            Ok(())
        }
        Err(e) => {
            eprintln!("can't get extra field count for file at index '{idx}': {e}");
            Err(())
        }
    }
}

fn count_extra_by_id(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let eid = strtoull(&argv[1]) as u16;
    let ceflags = get_flags(&argv[2]);
    match t.za.file_extra_fields_count_by_id(idx, eid, ceflags) {
        Ok(count) => {
            t.print(format!("Extra field count: {count}\n").as_bytes());
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "can't get extra field count for file at index '{idx}' and for id '{eid}': {e}"
            );
            Err(())
        }
    }
}

fn extract_as(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let mut fp = match std::fs::File::create(&argv[1]) {
        Ok(fp) => fp,
        Err(e) => {
            eprint!("can't open output file '{}': {e}", argv[1]);
            return Err(());
        }
    };
    t.cat_impl_backend(idx, 0, None, &mut fp)
}

fn regress_fopen(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    if t.z_files.len() >= 16 {
        eprintln!("too many open files");
        return Err(());
    }
    let name = t.decode_filename(&argv[0]);
    let za: &'static Archive<Src> = Box::leak(Box::new(t.za.clone()));
    match za.fopen(&name, Flags::NONE) {
        Ok(zf) => {
            t.print(format!("opened '{}' as file {}\n", argv[0], t.z_files.len()).as_bytes());
            t.z_files.push(zf);
            Ok(())
        }
        Err(e) => {
            eprintln!("can't open entry '{}' from input archive: {e}", argv[0]);
            Err(())
        }
    }
}

fn regress_fread(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let file_idx = strtoull(&argv[0]);
    let mut length = strtoull(&argv[1]);
    let Some(f) = t.z_files.get_mut(file_idx as usize) else {
        eprintln!("trying to read from invalid opened file");
        return Err(());
    };
    let mut buf = vec![0; 8192];
    while length > 0 {
        let to_read = length.min(buf.len() as u64) as usize;
        let n = match f.fread(&mut buf[..to_read]) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("can't read opened file {file_idx}: {e}");
                return Err(());
            }
        };
        if n == 0 {
            break;
        }
        let _ = t.out.write_all(&buf[..n]);
        length -= n as u64;
    }
    Ok(())
}

fn add(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let zs = BufferSource::new(argv[1].as_bytes().to_vec());
    let name = t.decode_filename(&argv[0]);
    t.za.file_add(&name, zs, Flags::NONE)
        .map(|_| ())
        .map_err(|e| {
            eprintln!("can't add file '{}': {e}", argv[0]);
        })
}

fn add_dir(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // add directory
    let name = t.decode_filename(&argv[0]);
    t.za.dir_add(&name, Flags::NONE).map(|_| ()).map_err(|e| {
        eprintln!("can't add directory '{}': {e}", argv[0]);
    })
}

fn add_file(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let start = strtoull(&argv[2]);
    let len = strtoull(&argv[3]) as i64;
    let name = t.decode_filename(&argv[0]);
    if argv[1] == "/dev/stdin" {
        // zip_source_filep on standard input, which is read as it comes.
        let mut data = Vec::new();
        if let Err(e) = std::io::Read::read_to_end(&mut std::io::stdin(), &mut data) {
            eprintln!("can't create zip_source from stdin: {e}");
            return Err(());
        }
        let data = data.get(start as usize..).unwrap_or_default().to_vec();
        let data = match len {
            len if len > 0 => data[..data.len().min(len as usize)].to_vec(),
            _ => data,
        };
        return t
            .za
            .file_add(&name, StreamSource { data }, Flags::NONE)
            .map(|_| ())
            .map_err(|e| {
                eprintln!("can't add file '{}': {e}", argv[0]);
            });
    }
    // zip_source_file_create: -1 is to the end, -2 (ZIP_LENGTH_UNCHECKED)
    // to the end when read, and other lengths below 0 are refused.
    let zs = match len {
        -1 => FileSource::new(&argv[1], start, None),
        -2 => FileSource::unchecked(&argv[1], start),
        len if len < 0 => Err(Error::new(ErrorCode::Inval, 0)),
        len => FileSource::new(&argv[1], start, Some(len as u64)),
    };
    let zs = match zs {
        Ok(zs) => zs,
        Err(e) => {
            eprintln!("can't create zip_source from file: {e}");
            return Err(());
        }
    };
    t.za.file_add(&name, zs, Flags::NONE)
        .map(|_| ())
        .map_err(|e| {
            eprintln!("can't add file '{}': {e}", argv[0]);
        })
}

/// Data read from a stream, as `zip_source_filep` reads a pipe: its size
/// not known, and its time now.
struct StreamSource {
    data: Vec<u8>,
}

impl DataSource for StreamSource {
    fn stat(&self) -> hivepack::zip::Result<Stat<'static>> {
        Ok(Stat {
            valid: stat::MTIME,
            mtime: BufferSource::new(Vec::new()).stat()?.mtime,
            ..Stat::default()
        })
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack::zip::Result<usize> {
        let start = (offset as usize).min(self.data.len());
        let n = buf.len().min(self.data.len() - start);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
}

fn add_from_zip(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // add from another zip file
    let idx = strtoull(&argv[2]);
    let start = strtoull(&argv[3]);
    let len = strtoull(&argv[4]) as i64;
    let z_in = match zip_open(&argv[1], OpenFlags::CHECKCONS, 0, 0) {
        Ok(z_in) => Arc::new(z_in),
        Err(e) => {
            // zip_error_init_with_code
            let e = Error::new(e.code(), e.system());
            eprintln!("can't open zip archive '{}': {e}", argv[1]);
            return Err(());
        }
    };
    let flags = if start == 0 && len == -1 {
        Flags::COMPRESSED
    } else {
        Flags::NONE
    };
    let source = match len {
        -1 => ZipFileSource::new(Arc::clone(&z_in), idx, flags, start, None),
        len if len < 0 => Err(Error::new(ErrorCode::Inval, 0)),
        len => ZipFileSource::new(Arc::clone(&z_in), idx, flags, start, Some(len as u64)),
    };
    let zs = match source {
        Ok(zs) => zs,
        Err(e) => {
            eprintln!(
                "error creating file source from '{}' index '{idx}': {e}",
                argv[1]
            );
            return Err(());
        }
    };
    let name = t.decode_filename(&argv[0]);
    if let Err(e) = t.za.file_add(&name, zs, Flags::NONE) {
        eprintln!("can't add file '{}': {e}", argv[0]);
        return Err(());
    }
    t.z_in.push(z_in);
    Ok(())
}

/// `source_nul`: `length` NUL bytes, of which only the size is known.
struct NulSource {
    length: u64,
}

impl DataSource for NulSource {
    fn stat(&self) -> hivepack::zip::Result<Stat<'static>> {
        Ok(Stat {
            valid: stat::SIZE,
            size: self.length,
            ..Stat::default()
        })
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> hivepack::zip::Result<usize> {
        let n = (buf.len() as u64).min(self.length.saturating_sub(offset)) as usize;
        buf[..n].fill(0);
        Ok(n)
    }
}

fn add_nul(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let length = strtoull(&argv[1]);
    let name = argv[0].as_bytes().to_vec();
    t.za.file_add(&name, NulSource { length }, Flags::NONE)
        .map(|_| ())
        .map_err(|e| {
            eprintln!("can't add file '{}': {e}", argv[0]);
        })
}

fn replace_file_contents(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // replace file contents with data from command line
    let idx = strtoull(&argv[0]);
    let s = BufferSource::new(argv[1].as_bytes().to_vec());
    t.za.file_replace(idx, s, Flags::NONE).map_err(|e| {
        eprintln!("error replacing file data: {e}");
    })
}

/// `get_compression_method`: the methods this build compresses with, and
/// `unknown`; anything else is stored.
fn get_compression_method(arg: &str) -> i32 {
    match arg.to_ascii_lowercase().as_str() {
        "default" => cm::DEFAULT,
        "store" => i32::from(cm::STORE),
        "deflate" => i32::from(cm::DEFLATE),
        "bzip2" => i32::from(cm::BZIP2),
        "lzma" => i32::from(cm::LZMA),
        "xz" => i32::from(cm::XZ),
        "zstd" => i32::from(cm::ZSTD),
        "unknown" => 100,
        // TODO in libzip: error handling
        _ => 0,
    }
}

fn set_file_compression(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let method = get_compression_method(&argv[1]);
    let flags = strtoull(&argv[2]) as u32;
    t.za.set_file_compression(idx, method, flags).map_err(|e| {
        eprintln!(
            "can't set file compression method at index '{idx}' to '{}', flags '{flags}': {e}",
            argv[1]
        );
    })
}

fn delete(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    t.za.delete(idx).map_err(|e| {
        eprintln!("can't delete file at index '{idx}': {e}");
    })
}

fn delete_extra(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let eid = strtoull(&argv[1]) as u16;
    let geflags = get_flags(&argv[2]);
    t.za.file_extra_field_delete(idx, eid, geflags).map_err(|e| {
        eprintln!(
            "can't delete extra field data for file at index '{idx}', extra field id '{eid}': {e}"
        );
    })
}

fn delete_extra_by_id(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let eid = strtoull(&argv[1]) as u16;
    let eidx = strtoull(&argv[2]) as u16;
    let geflags = get_flags(&argv[3]);
    t.za.file_extra_field_delete_by_id(idx, eid, eidx, geflags).map_err(|e| {
        eprintln!(
            "can't delete extra field data for file at index '{idx}', extra field id '{eid}', extra field idx '{eidx}': {e}"
        );
    })
}

fn zrename(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let name = t.decode_filename(&argv[1]);
    t.za.file_rename(idx, &name, Flags::NONE).map_err(|e| {
        eprintln!("can't rename file at index '{idx}' to '{}': {e}", argv[1]);
    })
}

fn set_extra(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let eid = strtoull(&argv[1]) as u16;
    let eidx = strtoull(&argv[2]) as u16;
    let geflags = get_flags(&argv[3]);
    let efdata = argv[4].as_bytes();
    t.za.file_extra_field_set(idx, eid, eidx, efdata, geflags)
        .map_err(|e| {
            eprintln!(
                "can't set extra field data for file at index '{idx}', extra field id '{eid}', index '{eidx}': {e}"
            );
        })
}

fn set_archive_comment(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    t.za.set_archive_comment(argv[0].as_bytes()).map_err(|e| {
        eprintln!("can't set archive comment to '{}': {e}", argv[0]);
    })
}

fn get_encryption_method(arg: &str) -> u16 {
    match arg.to_ascii_lowercase().as_str() {
        "none" => em::NONE,
        "pkware" => em::TRAD_PKWARE,
        "aes-128" => em::AES_128,
        "aes-192" => em::AES_192,
        "aes-256" => em::AES_256,
        "unknown" => 100,
        // TODO in libzip: error handling
        _ => u16::MAX,
    }
}

fn set_file_encryption(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let method = get_encryption_method(&argv[1]);
    let password = Some(argv[2].as_bytes()).filter(|p| !p.is_empty());
    t.za.file_set_encryption(idx, method, password)
        .map_err(|e| {
            eprintln!(
                "can't set file encryption method at index '{idx}' to '{}': {e}",
                argv[1]
            );
        })
}

fn set_password(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // set default password
    t.za.set_default_password(Some(argv[0].as_bytes()));
    Ok(())
}

fn set_archive_flag(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let Some(flag) = parse_archive_flag(&argv[0]) else {
        eprintln!("invalid archive flag '{}'", argv[0]);
        return Err(());
    };
    let value = ["1", "true", "yes"]
        .iter()
        .any(|v| argv[1].eq_ignore_ascii_case(v));
    t.za.set_archive_flag(flag, value).map_err(|e| {
        eprintln!(
            "can't set archive flag '{}' to {}: {e}",
            argv[0],
            u8::from(value)
        );
    })
}

fn set_file_comment(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    t.za.file_set_comment(idx, argv[1].as_bytes(), Flags::NONE)
        .map_err(|e| {
            eprintln!(
                "can't set file comment at index '{idx}' to '{}': {e}",
                argv[1]
            );
        })
}

fn set_file_dostime(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // set file last modification time (mtime) directly
    let idx = strtoull(&argv[0]);
    let dostime = strtoull(&argv[1]) as u16;
    let dosdate = strtoull(&argv[2]) as u16;
    t.za.file_set_dostime(idx, dostime, dosdate, Flags::NONE)
        .map_err(|e| {
            eprintln!("can't set file dostime at index '{idx}' to '{dostime}'/'{dosdate}': {e}");
        })
}

fn set_file_mtime(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // set file last modification time (mtime)
    let idx = strtoull(&argv[0]);
    let mtime = strtoull(&argv[1]) as i64;
    t.za.file_set_mtime(idx, mtime, Flags::NONE).map_err(|e| {
        eprintln!("can't set file mtime at index '{idx}' to '{mtime}': {e}");
    })
}

fn set_file_mtime_all(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // set last modification time (mtime) for all files
    let mtime = strtoull(&argv[0]) as i64;
    for idx in 0..t.za.get_num_entries(Flags::NONE) {
        if let Err(e) = t.za.file_set_mtime(idx, mtime, Flags::NONE) {
            eprintln!("can't set file mtime at index '{idx}' to '{mtime}': {e}");
            return Err(());
        }
    }
    Ok(())
}

fn unchange_all(t: &mut Tool, _argv: &[String]) -> Result<(), ()> {
    // zip_unchange_all cannot fail here: "can't revert changes to archive"
    t.za.unchange_all();
    Ok(())
}

fn unchange_one(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    t.za.unchange(idx).map_err(|e| {
        // libzip prints no newline here.
        eprint!("can't revert changes for entry {idx}: {e}");
    })
}

fn get_archive_comment(t: &mut Tool, _argv: &[String]) -> Result<(), ()> {
    // get archive comment
    let comment = t.za.get_archive_comment(Flags::NONE);
    if comment.is_empty() {
        t.print(b"No archive comment\n");
    } else {
        // printf("%.*s"): the encoded name, as long as the comment.
        let mut line = b"Archive comment: ".to_vec();
        let encoded = t.encode_filename(comment);
        line.extend_from_slice(&encoded[..encoded.len().min(comment.len())]);
        line.push(b'\n');
        t.print(&line);
    }
    Ok(())
}

fn get_archive_flag(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let Some(flag) = parse_archive_flag(&argv[0]) else {
        eprintln!("invalid archive flag '{}'", argv[0]);
        return Err(());
    };
    let value = u8::from(t.za.get_archive_flag(flag, Flags::NONE));
    t.print(format!("{value}\n").as_bytes());
    Ok(())
}

/// The extra field line of `get_extra` and `get_extra_by_id`.
fn extra_line(id: u16, data: &[u8]) -> Vec<u8> {
    let mut line = format!("Extra field 0x{id:04x}: len {}", data.len());
    if !data.is_empty() {
        line.push_str(", data 0x");
        for b in data {
            line.push_str(&format!("{b:02x}"));
        }
    }
    line.push('\n');
    line.into_bytes()
}

fn get_extra(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // get extra field data
    let idx = strtoull(&argv[0]);
    let eidx = strtoull(&argv[1]) as u16;
    let geflags = get_flags(&argv[2]);
    match t.za.file_extra_field_get(idx, eidx, geflags) {
        Ok((id, data)) => {
            let line = extra_line(id, data);
            t.print(&line);
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "can't get extra field data for file at index {idx}, extra field {eidx}, flags {}: {e}",
                geflags.0
            );
            Err(())
        }
    }
}

fn get_extra_by_id(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let eid = strtoull(&argv[1]) as u16;
    let eidx = strtoull(&argv[2]) as u16;
    let geflags = get_flags(&argv[3]);
    match t.za.file_extra_field_get_by_id(idx, eid, eidx, geflags) {
        Ok(data) => {
            let line = extra_line(eid, data);
            t.print(&line);
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "can't get extra field data for file at index {idx}, extra field id {eid}, ef index {eidx}, flags {}: {e}",
                geflags.0
            );
            Err(())
        }
    }
}

fn get_file_comment(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // get file comment
    let idx = strtoull(&argv[0]);
    let name =
        t.za.get_name(idx, Flags::NONE)
            .map(|n| c_string(n).to_vec())
            .unwrap_or_else(|_| b"(null)".to_vec());
    match t.za.file_get_comment(idx, Flags::NONE) {
        Err(e) => {
            eprintln!(
                "can't get comment for '{}': {e}",
                String::from_utf8_lossy(&name)
            );
            Err(())
        }
        Ok([]) => {
            let mut line = b"No comment for '".to_vec();
            line.extend_from_slice(&name);
            line.extend_from_slice(b"'\n");
            t.print(&line);
            Ok(())
        }
        Ok(comment) => {
            let mut line = b"File comment for '".to_vec();
            line.extend_from_slice(&name);
            line.extend_from_slice(b"': ");
            line.extend_from_slice(comment);
            line.push(b'\n');
            t.print(&line);
            Ok(())
        }
    }
}

fn get_num_entries(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    // get number of entries in archive
    let flags = get_flags(&argv[0]);
    let count = t.za.get_num_entries(flags);
    let entries = if count == 1 { "y" } else { "ies" };
    t.print(format!("{count} entr{entries} in archive\n").as_bytes());
    Ok(())
}

fn name_locate(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let flags = get_flags(&argv[1]);
    let name = t.decode_filename(&argv[0]);
    match t.za.name_locate(&name, flags) {
        Ok(idx) => t.print(
            format!(
                "name '{}' using flags '{}' found at index {idx}\n",
                argv[0], argv[1]
            )
            .as_bytes(),
        ),
        Err(_) => eprintln!(
            "can't find entry with name '{}' using flags '{}'",
            argv[0], argv[1]
        ),
    }
    Ok(())
}

fn zstat(t: &mut Tool, argv: &[String]) -> Result<(), ()> {
    let idx = strtoull(&argv[0]);
    let sb = match t.za.stat_index(idx, t.stat_flags) {
        Ok(sb) => sb,
        Err(e) => {
            eprintln!("zip_stat_index failed on '{idx}' failed: {e}");
            return Err(());
        }
    };

    let mut text = Vec::new();
    if sb.valid & stat::NAME != 0 {
        text.extend_from_slice(b"name: '");
        text.extend_from_slice(&t.encode_filename(sb.name.unwrap_or_default()));
        text.extend_from_slice(b"'\n");
    }
    let mut line = |s: String| text.extend_from_slice(s.as_bytes());
    if sb.valid & stat::INDEX != 0 {
        line(format!("index: '{}'\n", sb.index));
    }
    if sb.valid & stat::SIZE != 0 {
        line(format!("size: '{}'\n", sb.size));
    }
    if sb.valid & stat::COMP_SIZE != 0 {
        line(format!("compressed size: '{}'\n", sb.comp_size));
    }
    if sb.valid & stat::MTIME != 0 {
        line(format!("mtime: '{}'\n", strftime(sb.mtime)));
    }
    if sb.valid & stat::CRC != 0 {
        line(format!("crc: '{:x}'\n", sb.crc));
    }
    if sb.valid & stat::COMP_METHOD != 0 {
        line(format!("compression method: '{}'\n", sb.comp_method));
    }
    if sb.valid & stat::ENCRYPTION_METHOD != 0 {
        line(format!("encryption method: '{}'\n", sb.encryption_method));
    }
    if sb.valid & stat::FLAGS != 0 {
        line(format!("flags: '{}'\n", sb.flags));
    }
    line("\n".to_string());
    t.print(&text);
    Ok(())
}

/// `strftime("%a %b %d %Y %H:%M:%S", localtime(mtime))`, in UTC, the time
/// zone hivepack::zip takes MS-DOS times in, so that the fields are those
/// stored, as libzip's round trip through `mktime` and `localtime` gives
/// them.
fn strftime(mtime: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = mtime.div_euclid(86400);
    let secs = mtime.rem_euclid(86400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{} {} {:02} {} {:02}:{:02}:{:02}",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        day,
        year,
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// `get_flags`: the flags named by the letters of `arg`.
fn get_flags(arg: &str) -> Flags {
    let mut flags = Flags::NONE;
    for (c, flag) in [
        ('C', Flags::NOCASE),
        ('c', Flags::CENTRAL),
        ('d', Flags::NODIR),
        ('l', Flags::LOCAL),
        ('u', Flags::UNCHANGED),
        ('8', Flags::ENC_UTF_8),
        ('4', Flags::ENC_CP437),
        ('r', Flags::ENC_RAW),
        ('s', Flags::ENC_STRICT),
    ] {
        if arg.contains(c) {
            flags = flags | flag;
        }
    }
    flags
}

/// `parse_archive_flag`.
fn parse_archive_flag(arg: &str) -> Option<ArchiveFlags> {
    match arg.to_ascii_lowercase().as_str() {
        "rdonly" => Some(ArchiveFlags::RDONLY),
        "is-torrentzip" => Some(ArchiveFlags::IS_TORRENTZIP),
        // ZIP_AFL_WANT_TORRENTZIP and
        // ZIP_AFL_CREATE_OR_KEEP_FILE_FOR_EMPTY_ARCHIVE, for writing.
        "want-torrentzip" => Some(ArchiveFlags(8)),
        "create-or-keep-file-for-empty-archive" => Some(ArchiveFlags(16)),
        _ => None,
    }
}

/// `dispatch`: runs the command at the start of `argv`, and returns how
/// many arguments it took.
fn dispatch(t: &mut Tool, argv: &[String]) -> Option<usize> {
    let Some(&(name, count, function)) =
        DISPATCH_TABLE.iter().find(|(name, _, _)| *name == argv[0])
    else {
        eprintln!("unknown command '{}'", argv[0]);
        return None;
    };
    let args = &argv[1..];
    if args.len() < count {
        eprintln!(
            "not enough arguments for command '{name}': {} available, {count} needed",
            args.len()
        );
        return None;
    }
    function(t, &args[..count]).ok().map(|()| 1 + count)
}

fn usage(prg: &str, reason: &str) -> ExitCode {
    eprintln!(
        "usage: {prg} [-ceghnrst] [-Himx] [-F fragment-size] [-l len] [-o offset] archive command1 [args] [command2 [args] ...]"
    );
    eprintln!("{reason}");
    ExitCode::from(1)
}

/// `get_stdin_commands`: the words of the first line of standard input.
fn stdin_commands() -> Vec<String> {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.split([' ', '\n'])
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let prg = argv.first().cloned().unwrap_or_else(|| "ziptool".into());
    let mut flags = OpenFlags(0);
    let mut stat_flags = Flags::NONE;
    let mut hex_encoded_filenames = false;
    let mut in_memory = false;
    let mut commands_from_stdin = false;
    let (mut len, mut offset, mut fragment_size) = (0, 0, 0);

    let mut getopt = Getopt::new(&argv);
    while let Some(option) = getopt.next("ceghl:no:rstF:Himx") {
        match option {
            Ok(('c', _)) => flags = flags | OpenFlags::CHECKCONS,
            Ok(('e', _)) => flags = flags | OpenFlags::EXCL,
            Ok(('g', _)) => stat_flags = Flags::ENC_GUESS,
            Ok(('l', value)) => len = strtoull(&value.unwrap_or_default()),
            Ok(('n', _)) => flags = flags | OpenFlags::CREATE,
            Ok(('o', value)) => offset = strtoull(&value.unwrap_or_default()),
            Ok(('r', _)) => stat_flags = Flags::ENC_RAW,
            Ok(('s', _)) => stat_flags = Flags::ENC_STRICT,
            Ok(('t', _)) => flags = flags | OpenFlags::TRUNCATE,
            Ok(('i', _)) => commands_from_stdin = true,
            Ok(('m', _)) => in_memory = true,
            Ok(('x', _)) => hex_encoded_filenames = true,
            // The fragment size of in-memory archives, which decides what
            // closing can clone.
            Ok(('F', value)) => fragment_size = strtoull(&value.unwrap_or_default()),
            Ok((c, _)) | Err(c) => return usage(&prg, &format!("invalid option -{c}")),
        }
    }

    let mut arg = getopt.optind;
    if arg + 1 >= argv.len() && !commands_from_stdin {
        return usage(&prg, "too few arguments");
    }
    let Some(archive) = argv.get(arg).cloned() else {
        return usage(&prg, "too few arguments");
    };
    arg += 1;

    // if no flags were given, ZIP_CREATE
    if flags.0 == 0 {
        flags = OpenFlags::CREATE;
    }

    let opened = if in_memory {
        zip_open_in_memory(&archive, flags).map(|(za, data)| (za, Some(data)))
    } else {
        zip_open(&archive, flags, offset, len).map(|za| (za, None))
    };
    let (za, memory) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            eprintln!("can't open zip archive '{archive}': {e}");
            return ExitCode::from(1);
        }
    };
    let mut za = za;
    if std::env::var_os("HIVEPACK_ZIPTOOL_NONRANDOM").is_some() {
        // zip_secure_nonrandom
        za.set_random_source(Some(std::sync::Arc::new(|buffer: &mut [u8]| {
            buffer.fill(0);
            Ok(())
        })));
    }
    let mut tool = Tool {
        za,
        stat_flags,
        hex_encoded_filenames,
        z_in: Vec::new(),
        z_files: Vec::new(),
        out: std::io::stdout(),
    };

    let commands = if commands_from_stdin {
        stdin_commands()
    } else {
        argv[arg..].to_vec()
    };
    let mut err = false;
    let mut at = 0;
    while at < commands.len() {
        match dispatch(&mut tool, &commands[at..]) {
            Some(taken) => at += taken,
            None => {
                err = true;
                break;
            }
        }
    }

    // PRECLOSE_REGRESS: the entries fopen opened are closed.
    for zf in tool.z_files.drain(..) {
        if zf.fclose().is_err() {
            err = true;
        }
    }
    let _ = tool.out.flush();

    let closed = match &memory {
        Some(data) => zip_close_in_memory(&mut tool.za, &archive, data, fragment_size),
        None => zip_close(&mut tool.za, &archive).map(Ok),
    };
    match closed {
        Err(e) => {
            eprintln!("can't close zip archive '{archive}': {e}");
            return ExitCode::from(1);
        }
        // ziptool_post_close
        Ok(Err(text)) => {
            eprintln!("{text}");
            err = true;
        }
        Ok(Ok(())) => {}
    }
    ExitCode::from(u8::from(err))
}
