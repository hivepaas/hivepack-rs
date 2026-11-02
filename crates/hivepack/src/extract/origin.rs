//! Marks of origin: where a file came from, which the system checks before
//! opening or running it. A downloaded archive has one (Windows' Mark of
//! the Web, a `Zone.Identifier` stream; macOS's `com.apple.quarantine`
//! attribute), and the files extracted from it must have it too, or
//! extracting is a way around the check, as 7-Zip's CVE-2025-0411 was.
//!
//! The mark is written by handle, as everything else here: on Windows the
//! stream is opened from the file's own handle, on macOS the attribute is
//! set on the file's descriptor.

use std::io;
use std::path::Path;

/// A mark of origin, carried from an archive to every file extracted from
/// it (see [`Options::origin`](crate::extract::Options::origin)). [`Origin::of`]
/// reads the one an archive has.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Origin {
    /// Windows' Mark of the Web: what a `Zone.Identifier` stream holds,
    /// such as `[ZoneTransfer]` and `ZoneId=3`. Written on every file
    /// extracted, as it is.
    ZoneIdentifier(Vec<u8>),
    /// macOS's quarantine: what a `com.apple.quarantine` extended
    /// attribute holds. Written on every file extracted and every
    /// directory created, as an app is a directory, as it is.
    Quarantine(Vec<u8>),
}

/// Shows which mark, and how long it is.
impl std::fmt::Debug for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, value) = match self {
            Origin::ZoneIdentifier(value) => ("ZoneIdentifier", value),
            Origin::Quarantine(value) => ("Quarantine", value),
        };
        write!(f, "{kind}({:?})", String::from_utf8_lossy(value))
    }
}

/// Windows' number for the internet's zone.
const ZONE_INTERNET: u8 = 3;

/// The name of macOS's quarantine attribute.
#[cfg(target_os = "macos")]
const QUARANTINE: &str = "com.apple.quarantine";

impl Origin {
    /// The mark the file at `path` has: on Windows its `Zone.Identifier`
    /// stream, on macOS its quarantine attribute; `None` if it has none,
    /// and on other systems, which have no mark.
    pub fn of(path: &Path) -> io::Result<Option<Origin>> {
        read(path)
    }

    /// The mark without the addresses a download left in it, as what is
    /// extracted may be passed on, and they say where its user has been. Windows'
    /// keeps only its zone: `HostUrl` and `ReferrerUrl` go. A stream with no zone that can be read says the
    /// internet, as a mark must not be lost by being odd. macOS's holds no address.
    pub fn without_addresses(self) -> Origin {
        match self {
            Origin::ZoneIdentifier(value) => {
                let zone = String::from_utf8_lossy(&value)
                    .lines()
                    .filter_map(|line| line.trim().split_once('='))
                    .find(|(name, _)| name.trim().eq_ignore_ascii_case("ZoneId"))
                    .and_then(|(_, zone)| zone.trim().parse::<u8>().ok())
                    .unwrap_or(ZONE_INTERNET);
                Origin::ZoneIdentifier(format!("[ZoneTransfer]\r\nZoneId={zone}\r\n").into_bytes())
            }
            quarantine => quarantine,
        }
    }

    /// Whether this system can write the mark: an error, before anything
    /// is written, if not.
    pub(crate) fn check_supported(&self) -> io::Result<()> {
        let supported = match self {
            Origin::ZoneIdentifier(_) => cfg!(windows),
            Origin::Quarantine(_) => cfg!(target_os = "macos"),
        };
        if supported {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this system cannot carry this mark of origin",
            ))
        }
    }

    /// Writes the mark on `file`, just created: the stream on Windows, the
    /// attribute on macOS. Directories get only macOS's.
    pub(crate) fn write_file(&self, file: &std::fs::File) -> io::Result<()> {
        write(self, file)
    }

    /// Writes the mark on the directory `dir`, just created, where the
    /// system marks directories: macOS.
    pub(crate) fn write_dir(&self, dir: &cap_std::fs::Dir) -> io::Result<()> {
        write_dir(self, dir)
    }
}

#[cfg(windows)]
fn read(path: &Path) -> io::Result<Option<Origin>> {
    // The stream, by the absolute path: `a:Zone.Identifier` alone would be
    // a path on drive A.
    let mut stream = std::path::absolute(path)?.into_os_string();
    stream.push(":Zone.Identifier");
    match std::fs::read(&stream) {
        Ok(value) => Ok(Some(Origin::ZoneIdentifier(value))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn write(origin: &Origin, file: &std::fs::File) -> io::Result<()> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use std::io::Write;
    let Origin::ZoneIdentifier(value) = origin else {
        return Ok(());
    };
    // The stream, opened from the file's own handle (`:Zone.Identifier`
    // relative to it), so that no path is resolved again.
    let base = cap_std::fs::Dir::from_std_file(file.try_clone()?);
    let mut options = cap_std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    options.follow(FollowSymlinks::No);
    let mut stream = base.open_with(":Zone.Identifier", &options)?;
    stream.write_all(value)?;
    stream.flush()
}

#[cfg(target_os = "macos")]
fn read(path: &Path) -> io::Result<Option<Origin>> {
    let file = std::fs::File::open(path)?;
    let mut value = Vec::with_capacity(256);
    loop {
        match rustix::fs::fgetxattr(
            &file,
            QUARANTINE,
            rustix::buffer::spare_capacity(&mut value),
        ) {
            Ok(_) => return Ok(Some(Origin::Quarantine(value))),
            Err(rustix::io::Errno::NOATTR) => return Ok(None),
            // A value longer than the room given: give more.
            Err(rustix::io::Errno::RANGE) if value.capacity() < 1 << 16 => {
                value.reserve(value.capacity() * 2);
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(target_os = "macos")]
fn write(origin: &Origin, file: &std::fs::File) -> io::Result<()> {
    let Origin::Quarantine(value) = origin else {
        return Ok(());
    };
    rustix::fs::fsetxattr(file, QUARANTINE, value, rustix::fs::XattrFlags::empty())?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_dir(origin: &Origin, dir: &cap_std::fs::Dir) -> io::Result<()> {
    let Origin::Quarantine(value) = origin else {
        return Ok(());
    };
    rustix::fs::fsetxattr(dir, QUARANTINE, value, rustix::fs::XattrFlags::empty())?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_dir(_origin: &Origin, _dir: &cap_std::fs::Dir) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn read(_path: &Path) -> io::Result<Option<Origin>> {
    Ok(None)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn write(_origin: &Origin, _file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod address_tests {
    use super::*;

    fn zone(stream: &str) -> Origin {
        Origin::ZoneIdentifier(stream.as_bytes().to_vec()).without_addresses()
    }

    fn only(zone: u8) -> Origin {
        Origin::ZoneIdentifier(format!("[ZoneTransfer]\r\nZoneId={zone}\r\n").into_bytes())
    }

    #[test]
    fn a_download_keeps_its_zone_and_loses_its_addresses() {
        let stream = "[ZoneTransfer]\r\nZoneId=3\r\n\
                      ReferrerUrl=https://example.com/page\r\n\
                      HostUrl=https://example.com/a.zip\r\n";
        assert_eq!(zone(stream), only(3));
    }

    #[test]
    fn the_zone_is_kept_whatever_it_is_and_however_it_is_written() {
        assert_eq!(zone("[ZoneTransfer]\nZoneId=4\n"), only(4));
        assert_eq!(zone("[zonetransfer]\r\n zoneid = 2 \r\n"), only(2));
    }

    #[test]
    fn a_mark_with_no_zone_that_can_be_read_stays_the_internet() {
        for stream in [
            "",
            "[ZoneTransfer]\r\n",
            "ZoneId=many",
            "ZoneId=999",
            "\u{fffd}",
        ] {
            assert_eq!(zone(stream), only(ZONE_INTERNET), "{stream:?}");
        }
    }

    #[test]
    fn a_quarantine_stays_as_it_is() {
        let mark = Origin::Quarantine(b"0083;65a1;Safari;".to_vec());
        assert_eq!(mark.clone().without_addresses(), mark);
    }
}
