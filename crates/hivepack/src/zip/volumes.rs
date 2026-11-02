//! Not in libzip: the volumes of a split archive, read as one source.
//!
//! A split archive [APPNOTE 8.5] is one archive's bytes cut into volumes
//! ("disks") of a size chosen when it was written: `name.z01`, `name.z02`,
//! …, then `name.zip`, the last, which holds the end of central directory
//! record. Its offsets count from the start of the volume they are on,
//! each with the volume's number beside it. [`Volumes`] joins the volumes
//! end to end and tells [`Archive::open`](crate::zip::Archive::open) where each
//! starts (`ReadAt::volume_starts`), and the archive's disk numbers are read
//! as those volumes. 7-Zip's split archives (`name.zip.001`, `name.zip.002`,
//! …) are an archive cut where 7-Zip chose, with nothing in it saying so:
//! joined the same way, they are an archive of one disk.

use std::io;
use std::path::{Path, PathBuf};

use crate::zip::source::ReadAt;

/// The volumes of a split archive, read as one source.
///
/// ```no_run
/// use hivepack::zip::{Archive, Flags, OpenFlags, Volumes};
///
/// // name.z01, name.z02, …, then name.zip.
/// let volumes = Volumes::open("name.zip")?;
/// let za = Archive::open(volumes, OpenFlags::RDONLY)?;
/// for i in 0..za.get_num_entries(Flags::NONE) {
///     println!("{}", String::from_utf8_lossy(za.get_name(i, Flags::NONE)?));
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Volumes<R> {
    parts: Vec<R>,
    /// Where each volume starts, then where the last ends.
    starts: Vec<u64>,
}

impl<R: ReadAt> Volumes<R> {
    /// The volumes `parts`, in order: the first volume first, the one with
    /// the end of central directory record last. Their lengths are read
    /// now, as a source's length is read when an archive is opened.
    pub fn new(parts: Vec<R>) -> io::Result<Volumes<R>> {
        let mut starts = Vec::with_capacity(parts.len() + 1);
        let mut end = 0u64;
        starts.push(end);
        for part in &parts {
            end = end
                .checked_add(part.size()?)
                .ok_or_else(|| io::Error::other("the volumes are longer than 2^64 bytes"))?;
            starts.push(end);
        }
        Ok(Volumes { parts, starts })
    }

    /// The volumes, in order.
    pub fn parts(&self) -> &[R] {
        &self.parts
    }

    /// The volumes, given back.
    pub fn into_parts(self) -> Vec<R> {
        self.parts
    }
}

impl Volumes<std::fs::File> {
    /// The volumes of the split archive at `path`, opened: those
    /// [`volume_paths`] finds.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Volumes<std::fs::File>> {
        let parts = volume_paths(path.as_ref())
            .iter()
            .map(std::fs::File::open)
            .collect::<io::Result<Vec<_>>>()?;
        Volumes::new(parts)
    }
}

impl<R: ReadAt> ReadAt for Volumes<R> {
    fn size(&self) -> io::Result<u64> {
        Ok(self.starts.last().copied().unwrap_or(0))
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        // The volume `offset` is in: the last that starts at or before it.
        let mut part = self.starts.partition_point(|&start| start <= offset);
        let mut done = 0;
        while done < buf.len() && part > 0 && part < self.starts.len() {
            let index = part - 1;
            let at = offset + done as u64 - self.starts[index];
            let left = self.starts[part] - self.starts[index] - at;
            let want = (buf.len() - done).min(usize::try_from(left).unwrap_or(usize::MAX));
            let n = self.parts[index].read_at(at, &mut buf[done..done + want])?;
            done += n;
            if n < want {
                // A volume shorter than it was: the end.
                break;
            }
            part += 1;
        }
        Ok(done)
    }

    fn volume_starts(&self) -> Option<&[u64]> {
        Some(&self.starts[..self.starts.len() - 1])
    }
}

/// The paths of the volumes of the split archive at `path`, in order, as
/// far as they are there:
///
/// - for `name.zip`, or any of its volumes `name.z01`, `name.z02`, …:
///   `name.z01`, `name.z02` and on while they are there (as Info-ZIP's
///   `zip -s` and PKZIP name them, with two digits or more), then
///   `name.zip`;
/// - for `name.zipx` or `name.zx01`, …: `name.zx01`, `name.zx02`, …, then
///   `name.zipx`, as WinZip names them;
/// - for `name.001`, `name.002`, … (7-Zip's `name.zip.001`): every volume
///   from `name.001` on, with as many digits, while they are there;
/// - for any other path, the path alone.
///
/// The names keep the case of the extension given, as 7-Zip looks for
/// them: `NAME.ZIP` goes with `NAME.Z01`.
pub fn volume_paths(path: &Path) -> Vec<PathBuf> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return vec![path.to_path_buf()];
    };
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return vec![path.to_path_buf()];
    };
    let sibling = |name: String| path.with_file_name(name);
    let upper = ext.starts_with(|c: char| c.is_ascii_uppercase());
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());

    // 7-Zip's volumes: every one from the first.
    if ext.len() >= 3 && digits(ext) {
        return (1u64..)
            .map(|i| sibling(format!("{stem}.{i:0width$}", width = ext.len())))
            .take_while(|p| p.is_file())
            .collect();
    }

    let lower = ext.to_ascii_lowercase();
    let (prefix, last) = if lower == "zip" {
        ("z", ext.to_string())
    } else if lower == "zipx" {
        ("zx", ext.to_string())
    } else if let Some(n) = lower.strip_prefix("zx")
        && n.len() >= 2
        && digits(n)
    {
        ("zx", if upper { "ZIPX" } else { "zipx" }.to_string())
    } else if let Some(n) = lower.strip_prefix('z')
        && n.len() >= 2
        && digits(n)
    {
        ("z", if upper { "ZIP" } else { "zip" }.to_string())
    } else {
        return vec![path.to_path_buf()];
    };
    let prefix = if upper {
        prefix.to_ascii_uppercase()
    } else {
        prefix.to_string()
    };
    let mut paths: Vec<PathBuf> = (1u64..)
        .map(|i| sibling(format!("{stem}.{prefix}{i:02}")))
        .take_while(|p| p.is_file())
        .collect();
    paths.push(sibling(format!("{stem}.{last}")));
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_across_volumes() {
        let parts = vec![b"abc".to_vec(), Vec::new(), b"defg".to_vec(), b"h".to_vec()];
        let volumes = Volumes::new(parts).unwrap();
        assert_eq!(volumes.size().unwrap(), 8);
        assert_eq!(volumes.volume_starts(), Some(&[0, 3, 3, 7][..]));
        for start in 0..=9 {
            for len in 0..=9 {
                let mut buf = vec![0; len];
                let n = volumes.read_at(start, &mut buf).unwrap();
                let want = &b"abcdefgh"[(start as usize).min(8)..];
                let want = &want[..want.len().min(len)];
                assert_eq!(&buf[..n], want, "{start} {len}");
            }
        }
        let none = Volumes::new(Vec::<Vec<u8>>::new()).unwrap();
        assert_eq!(none.size().unwrap(), 0);
        assert_eq!(none.read_at(0, &mut [0; 4]).unwrap(), 0);
        assert_eq!(none.volume_starts(), Some(&[][..]));
    }

    #[test]
    fn finds_the_volumes_by_name() {
        let dir = std::env::temp_dir().join(format!("hivepack-zip-volumes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in [
            "a.z01",
            "a.z02",
            "a.zip",
            "b.zip",
            "C.Z01",
            "C.ZIP",
            "d.zx01",
            "d.zx02",
            "d.zx03",
            "d.zipx",
            "e.zip.001",
            "e.zip.002",
            "e.zip.003",
            "e.zip.005",
        ] {
            std::fs::write(dir.join(name), name).unwrap();
        }
        let names = |given: &str| -> Vec<String> {
            volume_paths(&dir.join(given))
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(names("a.zip"), ["a.z01", "a.z02", "a.zip"]);
        assert_eq!(names("a.z02"), ["a.z01", "a.z02", "a.zip"]);
        assert_eq!(names("b.zip"), ["b.zip"]);
        assert_eq!(names("C.ZIP"), ["C.Z01", "C.ZIP"]);
        assert_eq!(names("C.Z01"), ["C.Z01", "C.ZIP"]);
        assert_eq!(names("d.zipx"), ["d.zx01", "d.zx02", "d.zx03", "d.zipx"]);
        assert_eq!(names("d.zx01"), ["d.zx01", "d.zx02", "d.zx03", "d.zipx"]);
        assert_eq!(names("e.zip.002"), ["e.zip.001", "e.zip.002", "e.zip.003"]);
        assert_eq!(names("f.tar"), ["f.tar"]);
        assert_eq!(names("noext"), ["noext"]);
        let volumes = Volumes::open(dir.join("d.zx02")).unwrap();
        assert_eq!(volumes.parts().len(), 4);
        assert_eq!(volumes.size().unwrap(), 6 * 3 + 6);
        assert!(Volumes::open(dir.join("missing.zip")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
