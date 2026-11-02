//! What ziptool and tryopen share: archives opened and closed as libzip's
//! programs open and close them, and their options parsed as `getopt`
//! parses them.

use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Cursor, Write};
use std::sync::Arc;

use hivepack::zip::{Archive, Closed, Error, ErrorCode, OpenFlags, ReadAt};

/// `ENOENT`, which libzip's file source gives for a file that is not
/// there.
const ENOENT: i32 = 2;

/// What an archive is read from: a part of a file (`zip_source_file_create`
/// with a start and a length), all of it in memory (ziptool_regress's
/// `-m`), or a file that is not there. Shared, so that an archive can be
/// cloned.
#[derive(Clone)]
pub enum Src {
    File {
        file: Arc<File>,
        start: u64,
        len: u64,
    },
    Memory(Arc<Vec<u8>>),
    /// Its length fails with `ENOENT`, as libzip's file source's does, so
    /// that `ZIP_CREATE` makes an empty archive.
    Missing,
}

impl ReadAt for Src {
    fn size(&self) -> io::Result<u64> {
        match self {
            Src::File { len, .. } => Ok(*len),
            Src::Memory(data) => Ok(data.len() as u64),
            Src::Missing => Err(io::Error::from_raw_os_error(ENOENT)),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Src::File { file, start, len } => {
                let n = (buf.len() as u64).min(len.saturating_sub(offset)) as usize;
                ReadAt::read_at(&**file, start + offset, &mut buf[..n])
            }
            Src::Memory(data) => data.as_slice().read_at(offset, buf),
            Src::Missing => Ok(0),
        }
    }

    fn accept_empty(&self) -> bool {
        matches!(self, Src::Memory(_))
    }
}

/// The text `strerror` gives for the error of a system call.
pub fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    match text.rfind(" (os error ") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

/// `errno` of a failed system call, or 0.
fn errno(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Opens `path` as `zip_open` does, or `zip_source_file_create` with
/// `start` and `len` (0: to the end) and then `zip_open_from_source`. Only
/// an archive of a whole file can be written, as libzip's file source
/// writes only those: one of part of a file is opened read-only.
pub fn zip_open(path: &str, flags: OpenFlags, start: u64, len: u64) -> Result<Archive<Src>, Error> {
    let partial = start != 0 || len != 0;
    let flags = if partial {
        flags | OpenFlags::RDONLY
    } else {
        flags
    };
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if partial {
                return Err(Error::new(ErrorCode::Read, ENOENT));
            }
            return Archive::open(Src::Missing, flags);
        }
        Err(e) => return Err(Error::new(ErrorCode::Open, errno(&e))),
    };
    let size = file
        .metadata()
        .map_err(|e| Error::new(ErrorCode::Read, errno(&e)))?
        .len();
    if start > size || (len > 0 && start + len > size) {
        return Err(Error::new(ErrorCode::Inval, 0));
    }
    let len = if len == 0 { size - start } else { len };
    Archive::open(
        Src::File {
            file: Arc::new(file),
            start,
            len,
        },
        flags,
    )
}

/// Opens `path` read into memory: ziptool_regress's `read_to_memory`. A
/// file that is not there is an empty buffer. Also gives the buffer, which
/// is written back if the archive is not changed.
pub fn zip_open_in_memory(
    path: &str,
    flags: OpenFlags,
) -> Result<(Archive<Src>, Arc<Vec<u8>>), Error> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::new(ErrorCode::Open, errno(&e))),
    };
    let data = Arc::new(data);
    let za = Archive::open(Src::Memory(Arc::clone(&data)), flags)?;
    Ok((za, data))
}

/// `zip_close` on the file source of `path`: the archive written to a
/// temporary file next to it, `<path>.XXXXXX.part`, which then takes its
/// place with its permissions, or the file removed. The archive is written
/// in memory first, so that nothing is made where libzip makes nothing.
pub fn zip_close(za: &mut Archive<Src>, path: &str) -> Result<(), Error> {
    let mut out = Cursor::new(Vec::new());
    match za.close_to(&mut out)? {
        Closed::Unchanged => Ok(()),
        Closed::Removed => match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(Error::new(ErrorCode::Remove, errno(&e)))
            }
            _ => Ok(()),
        },
        Closed::Written => {
            let permissions = std::fs::metadata(path).ok().map(|m| m.permissions());
            let (temp, mut file) = create_temp(path)?;
            let written = file
                .write_all(out.get_ref())
                .and_then(|()| file.flush())
                .map_err(|e| Error::new(ErrorCode::Write, errno(&e)));
            drop(file);
            let renamed = written.and_then(|()| {
                if let Some(permissions) = permissions {
                    let _ = std::fs::set_permissions(&temp, permissions);
                }
                std::fs::rename(&temp, path).map_err(|e| Error::new(ErrorCode::Rename, errno(&e)))
            });
            if renamed.is_err() {
                let _ = std::fs::remove_file(&temp);
            }
            renamed
        }
    }
}

/// A new file `<path>.XXXXXX.part`, the X random letters and digits, as
/// libzip's `create_temp_file` makes it.
fn create_temp(path: &str) -> Result<(String, File), Error> {
    loop {
        let mut value = RandomState::new().build_hasher().finish() as u32;
        let mut name = format!("{path}.");
        for _ in 0..6 {
            let digit = (value % 36) as u8;
            name.push(char::from(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            }));
            value /= 36;
        }
        name.push_str(".part");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&name)
        {
            Ok(file) => return Ok((name, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::new(ErrorCode::TmpOpen, errno(&e))),
        }
    }
}

/// Whether libzip's buffer source of `len` bytes, in fragments of
/// `fragment_size` (one if 0), can clone its first `offset` bytes, as
/// `buffer_clone` decides: not past its end, nor where more of the
/// fragment it ends in would be left over than it keeps.
pub fn buffer_can_clone(len: u64, fragment_size: u64, offset: u64) -> bool {
    if offset == 0 {
        return true;
    }
    if offset > len {
        return false;
    }
    let fragment_size = if fragment_size == 0 {
        len
    } else {
        fragment_size
    };
    let nfragments = len.div_ceil(fragment_size);
    let length = |i: u64| fragment_size.min(len - i * fragment_size);
    let mut fragment = (offset / fragment_size).min(nfragments - 1);
    let mut fragment_offset = offset - fragment * fragment_size;
    if fragment_offset == 0 {
        // We can't be at beginning of fragment zero if offset > 0.
        fragment -= 1;
        fragment_offset = length(fragment);
    }
    length(fragment) - fragment_offset <= offset
}

/// `zip_close` on the buffer source of the in-memory archive opened from
/// `path` as `original`, in fragments of `fragment_size` bytes (`-F`),
/// which clones what it keeps where it can, then `ziptool_post_close`:
/// the archive written to the file, the buffer as it was if nothing
/// changed, or the file removed.
pub fn zip_close_in_memory(
    za: &mut Archive<Src>,
    path: &str,
    original: &[u8],
    fragment_size: u64,
) -> Result<Result<(), String>, Error> {
    let mut out = Cursor::new(Vec::new());
    let len = original.len() as u64;
    let closed = za.close_to_cloning(&mut out, |offset| {
        buffer_can_clone(len, fragment_size, offset)
    })?;
    let data = match closed {
        Closed::Written => out.into_inner(),
        Closed::Unchanged => original.to_vec(),
        Closed::Removed => {
            return Ok(match std::fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    Err(format!("unlink failed: {}", strerror(&e)))
                }
                _ => Ok(()),
            });
        }
    };
    let mut fp = match File::create(path) {
        Ok(fp) => fp,
        Err(e) => return Ok(Err(format!("fopen failed: {}", strerror(&e)))),
    };
    if let Err(e) = fp.write_all(&data) {
        return Ok(Err(format!("fwrite failed: {}", strerror(&e))));
    }
    Ok(Ok(()))
}

/// The options before the first operand, as `getopt` returns them:
/// grouped (`-cs`), with their argument attached or next (`-l 5`, `-l5`),
/// and `--` ending them.
pub struct Getopt<'a> {
    args: &'a [String],
    /// the index of the first operand, once the options are read
    pub optind: usize,
    pos: usize,
}

impl<'a> Getopt<'a> {
    pub fn new(args: &'a [String]) -> Getopt<'a> {
        Getopt {
            args,
            optind: 1,
            pos: 0,
        }
    }

    /// The next option and its argument, `Err` with the character for one
    /// not in `optstring` (or missing its argument), or `None` at the
    /// first operand.
    pub fn next(&mut self, optstring: &str) -> Option<Result<(char, Option<String>), char>> {
        if self.pos == 0 {
            let arg = self.args.get(self.optind)?;
            if arg == "--" {
                self.optind += 1;
                return None;
            }
            if !arg.starts_with('-') || arg.len() == 1 {
                return None;
            }
            self.pos = 1;
        }
        let arg = &self.args[self.optind];
        let c = arg[self.pos..].chars().next()?;
        self.pos += c.len_utf8();
        let at_end = self.pos >= arg.len();
        let Some(spec) = optstring.find(c).filter(|_| c != ':') else {
            if at_end {
                self.optind += 1;
                self.pos = 0;
            }
            return Some(Err(c));
        };
        if optstring[spec + 1..].starts_with(':') {
            let value = if !at_end {
                Some(arg[self.pos..].to_string())
            } else {
                self.optind += 1;
                self.args.get(self.optind).cloned()
            };
            self.optind += 1;
            self.pos = 0;
            return Some(value.map(|v| (c, Some(v))).ok_or(c));
        }
        if at_end {
            self.optind += 1;
            self.pos = 0;
        }
        Some(Ok((c, None)))
    }
}

/// `strtoull(text, NULL, 10)`: the leading digits, 0 if none, and, after
/// a minus sign, their negation modulo 2^64, as C's.
pub fn strtoull(text: &str) -> u64 {
    let text = text.trim_start();
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let value = if digits.is_empty() {
        0
    } else {
        digits.parse().unwrap_or(u64::MAX)
    };
    if negative {
        value.wrapping_neg()
    } else {
        value
    }
}
