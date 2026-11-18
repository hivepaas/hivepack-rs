//! Extracting NTFS file systems that hivepack::ntfs reads: the image
//! `mkntfs` and `ntfs-3g` build in `ntfs_support`, taken out again and
//! compared with the bytes that went into it.
//!
//! The file that matters most here is the compressed one. The library
//! underneath hands back LZNT1 bytes as if they were the file's, with no
//! error at all (`docs/ntfs.md` measures it), so an extractor that did not
//! stop would write a file that is not the one in the image — quietly, and
//! for every compressed file on a Windows volume. These tests hold it to
//! refusing: nothing of that file lands, and by default the extraction
//! stops before the destination is even made.

#![cfg(all(feature = "ntfs", feature = "extract", feature = "image"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "ntfs_support/mod.rs"]
mod build;
#[path = "extract_support/mod.rs"]
mod support;

use std::io;
use std::path::Path;

use build::{image_or_say, sparse};
use hivepack::extract::{
    Entry as Given, ErrorKind, Links, OnRefused, Options, Sink, Summary, extract_ntfs,
    extract_ntfs_to,
};
use hivepack::ntfs::{Error as NtfsError, Ntfs};
use support::{Scratch, listing, options};

/// The folders of the image, which are folders and not files.
const FOLDERS: [&str; 5] = ["comp", "dir", "dir/sub", "frag", "many"];

fn extract(
    image: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let fs = Ntfs::open(image).unwrap();
    extract_ntfs(&fs, out, options)
}

/// What the skipped entries were refused for, to say in a failure.
fn why(summary: &Summary) -> Vec<String> {
    summary
        .skipped
        .iter()
        .map(|e| {
            let name = e.name.as_deref().map(String::from_utf8_lossy);
            format!("{name:?}: {:?}", e.kind)
        })
        .collect()
}

/// Every file of the image comes out holding the bytes that went in, every
/// folder comes out a folder, and the one file that cannot be read whole
/// is the only thing left out.
#[test]
fn a_tree_comes_out_as_it_went_in() {
    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();
    let out = s.out();
    // The compressed file is refused, which the next test is about;
    // skipping it is what lets the rest come out.
    let summary = extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();

    for (path, want) in &built.files {
        if path == "comp/squashy.txt" {
            continue;
        }
        let got = std::fs::read(out.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(got.len(), want.len(), "{path} came out another length");
        assert!(got == *want, "{path} came out as other bytes");
    }
    for folder in FOLDERS {
        assert!(out.join(folder).is_dir(), "{folder} is not a folder");
    }

    // Nothing else was left out, and that one for being compressed.
    assert_eq!(summary.skipped.len(), 1, "{:?}", why(&summary));
    assert!(
        matches!(
            summary.skipped[0].kind,
            ErrorKind::Ntfs(NtfsError::Compressed)
        ),
        "{:?}",
        why(&summary)
    );
    // Every file but that one — the second name for `plain.txt` among
    // them, which holds no bytes of its own — and every folder.
    assert_eq!(
        summary.files as usize,
        built.files.len() - 1,
        "{summary:?}, {:?}",
        why(&summary)
    );
    assert_eq!(summary.directories as usize, FOLDERS.len(), "{summary:?}");
    let bytes: u64 = built
        .files
        .iter()
        .filter(|(path, _)| *path != "comp/squashy.txt" && *path != "hardlink.txt")
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    assert_eq!(summary.bytes, bytes, "{summary:?}");
    // Nothing was invented: what came out is what went in, and the folders.
    for path in listing(&out) {
        let path = path.trim_end_matches('/').to_string();
        assert!(
            built.files.contains_key(&path) || FOLDERS.contains(&path.as_str()),
            "{path} came out and was never written"
        );
    }
}

/// The compressed file: refused, not written. The library would hand back
/// the compressed bytes here, so writing them is the failure this test is
/// against — and by default nothing is written at all, as the tree is
/// walked before the destination is made.
#[test]
fn a_compressed_file_is_refused_rather_than_written() {
    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();

    // The premise: NTFS really did compress it, or there is nothing here
    // to refuse.
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("comp/squashy.txt").unwrap().unwrap();
    assert!(
        entry.compressed,
        "nothing in the image is compressed, so this test proves nothing"
    );

    // Skipped: its folder comes out, and it does not.
    let out = s.out();
    let summary = extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert!(out.join("comp").is_dir(), "the folder did not come out");
    assert!(
        !out.join("comp/squashy.txt").exists(),
        "a compressed file was written: {:?}",
        listing(&out)
    );
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, ErrorKind::Ntfs(NtfsError::Compressed))),
        "wanted it refused for being compressed, got {:?}",
        why(&summary)
    );

    // And stopping, which is the default: the extraction fails with that
    // reason, before anything is written.
    let stop = s.path().join("stop");
    let e = extract(&built.image, &stop, &options(|_| {})).unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::Ntfs(NtfsError::Compressed)),
        "{e}"
    );
    assert!(
        !stop.exists(),
        "the destination was made although the extraction stopped"
    );
}

/// Two names of one record: a hard link to the first, as every other
/// backend gives one, and a copy where that is asked for.
#[test]
#[cfg(unix)]
fn two_names_of_one_file_become_one_file() {
    use std::os::unix::fs::MetadataExt;

    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();
    let out = s.out();
    extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();

    let one = std::fs::metadata(out.join("plain.txt")).unwrap();
    let two = std::fs::metadata(out.join("hardlink.txt")).unwrap();
    assert_eq!(
        (one.dev(), one.ino()),
        (two.dev(), two.ino()),
        "the two names are not one file"
    );
    assert_eq!(one.nlink(), 2, "the file says how many names it has");

    // Asked for as files, they are two files holding the same bytes.
    let copies = s.path().join("copies");
    extract(
        &built.image,
        &copies,
        &options(|o| {
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
        }),
    )
    .unwrap();
    let one = std::fs::metadata(copies.join("plain.txt")).unwrap();
    let two = std::fs::metadata(copies.join("hardlink.txt")).unwrap();
    assert_ne!((one.dev(), one.ino()), (two.dev(), two.ino()));
    assert_eq!(
        std::fs::read(copies.join("hardlink.txt")).unwrap(),
        built.files["plain.txt"]
    );
}

/// A hole comes out as the zeros it stands for, and a file in a hundred
/// pieces comes out in the order its runs are in.
#[test]
fn what_is_not_one_stretch_of_disk_comes_out_whole() {
    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();
    let out = s.out();
    extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();

    assert_eq!(std::fs::read(out.join("sparse.bin")).unwrap(), sparse());
    let fragmented = std::fs::read(out.join("frag/target.bin")).unwrap();
    assert_eq!(fragmented.len(), built.files["frag/target.bin"].len());
    assert!(
        fragmented == built.files["frag/target.bin"],
        "the fragmented file came out in another order"
    );
}

/// NTFS keeps names as UTF-16, and what comes out is their characters.
#[test]
fn a_name_that_is_not_ascii_comes_out_as_its_characters() {
    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();
    let out = s.out();
    extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert!(
        out.join("tên-việt.txt").is_file(),
        "{:?}",
        listing(&out)
            .into_iter()
            .filter(|p| !p.starts_with("many/"))
            .collect::<Vec<_>>()
    );
}

/// The stream beside a file is not the file, and is not written: what comes
/// out under `ads.txt` is the file's own data, and nothing comes out beside
/// it.
#[test]
fn the_stream_beside_a_file_is_not_written() {
    let Some(built) = image_or_say() else {
        return;
    };
    let s = Scratch::new();
    let out = s.out();
    extract(
        &built.image,
        &out,
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(std::fs::read(out.join("ads.txt")).unwrap(), b"main data\n");
    for path in listing(&out) {
        assert!(
            !path.contains(':') && !path.contains("extra"),
            "{path} came out, and a stream is not a file"
        );
    }
}

/// What a sink is given: the same entries, in the same order, as the folder
/// gets — with the hard link given as one, since what a sink was given
/// cannot be read back to copy.
#[derive(Default)]
struct Recorder {
    /// Each path, and how many bytes came with it.
    written: Vec<(String, u64)>,
    folders: Vec<String>,
    links: Vec<(String, String)>,
    at: u64,
}

impl Sink for Recorder {
    fn directory(&mut self, entry: &Given<'_>) -> io::Result<()> {
        self.folders.push(entry.path.join("/"));
        Ok(())
    }

    fn start_file(&mut self, entry: &Given<'_>) -> io::Result<()> {
        self.written.push((entry.path.join("/"), 0));
        self.at = 0;
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.at += data.len() as u64;
        Ok(())
    }

    fn finish_file(&mut self) -> io::Result<()> {
        if let Some(last) = self.written.last_mut() {
            last.1 = self.at;
        }
        Ok(())
    }

    fn discard_file(&mut self) {
        self.written.pop();
    }

    fn symlink(&mut self, _entry: &Given<'_>, _target: &str) -> io::Result<()> {
        unreachable!("an NTFS file system has no symbolic links to give")
    }

    fn hard_link(&mut self, entry: &Given<'_>, target: &[String]) -> io::Result<()> {
        self.links.push((entry.path.join("/"), target.join("/")));
        Ok(())
    }
}

#[test]
fn a_sink_is_given_what_the_folder_would_get() {
    let Some(built) = image_or_say() else {
        return;
    };
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let mut recorder = Recorder::default();
    let options = options(|o| o.on_refused = OnRefused::Skip);
    let summary = extract_ntfs_to(&fs, &mut recorder, &options).unwrap();

    // The folders, and the files with the bytes each held.
    let mut folders = recorder.folders.clone();
    folders.sort();
    assert_eq!(folders, FOLDERS);

    // One hard link, between the two names of the one record. **Which of
    // them is the file and which the link is the directory's order, not
    // the volume's**: the first name met is the file, and an NTFS index is
    // sorted, so here `hardlink.txt` comes before `plain.txt` and is the
    // one written. Nothing in the format makes it the other way round, so
    // the test asks for the pair and not for a direction.
    assert_eq!(recorder.links.len(), 1, "{:?}", recorder.links);
    let (link, target) = &recorder.links[0];
    let mut names = [link.as_str(), target.as_str()];
    names.sort();
    assert_eq!(names, ["hardlink.txt", "plain.txt"]);

    for (path, want) in &built.files {
        // The compressed one is refused, and the second name of the record
        // was given as a link rather than as bytes.
        if path == "comp/squashy.txt" || path == link {
            continue;
        }
        let given = recorder
            .written
            .iter()
            .find(|(given, _)| given == path)
            .unwrap_or_else(|| panic!("{path} was not given to the sink"));
        assert_eq!(given.1, want.len() as u64, "{path}");
    }
    // And the file it names was given before it.
    assert!(
        recorder.written.iter().any(|(given, _)| given == target),
        "the hard link's target was not given to the sink"
    );
    // And the summary is the folder's: files, folders, bytes.
    assert_eq!(
        summary.files as usize,
        recorder.written.len() + recorder.links.len()
    );
    assert_eq!(summary.directories as usize, folders.len());
}
