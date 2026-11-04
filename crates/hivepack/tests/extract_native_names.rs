//! `Options::name_rules` and `Options::on_unnamable`: names by this system's
//! rules, or every system's; the entries whose names a system cannot take asked
//! about once, before anything is written, and left out or renamed; and
//! `Options::links_outside`, a link leading outside left out.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::sync::{Arc, Mutex};

use hivepack::extract::{
    ErrorKind, Links, NameError, NameRules, OnRefused, OnUnnamable, Options, Sink, check_name_for,
    extract_zip_to,
};
use hivepack::zip::{Archive, OpenFlags};
use support::{Entry, Scratch, extract, listing, zip};

/// Options by every system's rules, as Windows and macOS have them anywhere,
/// that answer `answer` and keep what they are asked.
fn asking(answer: OnUnnamable) -> (Options, Arc<Mutex<Vec<Vec<String>>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let kept = asked.clone();
    let mut options = Options::default();
    options.name_rules = NameRules::Portable;
    options.on_unnamable = Some(Arc::new(move |errors: &[hivepack::extract::Error]| {
        let names = errors
            .iter()
            .map(|e| String::from_utf8_lossy(e.name.as_deref().unwrap_or_default()).into_owned())
            .collect();
        kept.lock().unwrap().push(names);
        answer
    }));
    (options, asked)
}

/// An archive of a good file, names Windows cannot take, two names Windows and
/// macOS take for one, and a folder spelled two ways.
fn awkward() -> Vec<u8> {
    zip(&[
        Entry::File(b"good.txt", b"ok"),
        Entry::File(b"a:b.txt", b"colon"),
        Entry::File(b"aux.txt", b"device"),
        Entry::File(b"what?.txt", b"question"),
        Entry::File(b"ends. ", b"end"),
        Entry::File(b"README", b"upper"),
        Entry::File(b"readme", b"lower"),
        Entry::File(b"Docs/a.txt", b"a"),
        Entry::File(b"docs/b.txt", b"b"),
    ])
}

#[test]
fn rules_are_the_system_s_or_every_one_s() {
    let native = NameRules::Native;
    let portable = NameRules::Portable;
    for name in [
        &b"a:b.txt"[..],
        b"aux.txt",
        b"what?.txt",
        b"ends. ",
        b"a\\b",
    ] {
        assert_eq!(
            check_name_for(name, native).is_ok(),
            !cfg!(windows),
            "{}",
            String::from_utf8_lossy(name)
        );
        let refused = check_name_for(name, portable).unwrap_err();
        assert!(refused.is_unnamable(), "{refused}");
    }
    // What leads outside, everywhere, and never as a name only unnamable.
    for (name, error) in [
        (&b"../x"[..], NameError::Dot),
        (b"/etc/passwd", NameError::Absolute),
        (b"a//b", NameError::Empty),
    ] {
        for rules in [native, portable] {
            assert_eq!(check_name_for(name, rules), Err(error));
            assert!(!error.is_unnamable());
        }
    }
    // Windows' separator and stream climb there.
    assert_eq!(check_name_for(b"a\\..\\x", portable), Err(NameError::Dot));
    assert_eq!(check_name_for(b"a.txt:..", portable), Err(NameError::Dot));
    // Control characters, on every system.
    assert_eq!(check_name_for(b"a\nb", native), Err(NameError::Control));
}

/// On Linux and the BSDs, what their file systems take extracts as it is: names
/// Windows refuses, and two names that differ only in case.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn this_system_s_names_extract_as_they_are() {
    let scratch = Scratch::new();
    let summary = extract(&awkward(), &scratch.out(), &Options::default()).unwrap();
    assert_eq!(summary.files, 9);
    assert_eq!(
        listing(&scratch.out()),
        [
            "Docs/",
            "Docs/a.txt",
            "README",
            "a:b.txt",
            "aux.txt",
            "docs/",
            "docs/b.txt",
            "ends. ",
            "good.txt",
            "readme",
            "what?.txt"
        ]
    );
    // What climbs still stops it, and writes nothing.
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"good.txt", b"ok"),
        Entry::File(b"../evil", b"x"),
    ]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Name(NameError::Dot)));
    assert!(!scratch.out().exists());
}

#[test]
fn unnamable_names_are_asked_about_once() {
    let scratch = Scratch::new();
    let (options, asked) = asking(OnUnnamable::Stop);
    let error = extract(&awkward(), &scratch.out(), &options).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Name(NameError::Colon)),
        "{error}"
    );
    assert!(!scratch.out().exists());
    assert_eq!(
        *asked.lock().unwrap(),
        [[
            "a:b.txt",
            "aux.txt",
            "what?.txt",
            "ends. ",
            "readme",
            "docs/b.txt"
        ]]
    );
}

#[test]
fn unnamable_names_can_be_left_out() {
    let scratch = Scratch::new();
    let (options, asked) = asking(OnUnnamable::Skip);
    let summary = extract(&awkward(), &scratch.out(), &options).unwrap();
    assert_eq!(asked.lock().unwrap().len(), 1);
    assert_eq!(
        listing(&scratch.out()),
        ["Docs/", "Docs/a.txt", "README", "good.txt"]
    );
    assert_eq!(summary.skipped.len(), 6);
    assert!(summary.renamed.is_empty());
}

#[test]
fn unnamable_names_can_be_renamed() {
    let scratch = Scratch::new();
    let (options, _) = asking(OnUnnamable::Rename);
    let summary = extract(&awkward(), &scratch.out(), &options).unwrap();
    assert_eq!(
        listing(&scratch.out()),
        [
            "Docs/",
            "Docs/a.txt",
            "Docs/b.txt",
            "README",
            "_aux.txt",
            "a_b.txt",
            "ends__",
            "good.txt",
            "readme (2)",
            "what_.txt"
        ]
    );
    let given: Vec<(String, String)> = summary
        .renamed
        .iter()
        .map(|r| {
            (
                String::from_utf8_lossy(r.error.name.as_deref().unwrap()).into_owned(),
                r.to.join("/"),
            )
        })
        .collect();
    assert_eq!(
        given,
        [
            ("a:b.txt".into(), "a_b.txt".into()),
            ("aux.txt".into(), "_aux.txt".into()),
            ("what?.txt".into(), "what_.txt".into()),
            ("ends. ".into(), "ends__".into()),
            ("readme".into(), "readme (2)".into()),
            ("docs/b.txt".into(), "Docs/b.txt".into()),
        ]
    );
    assert_eq!(
        std::fs::read(scratch.out().join("readme (2)")).unwrap(),
        b"lower"
    );
    assert!(summary.skipped.is_empty());
}

#[test]
fn a_renamed_name_is_not_one_that_is_there() {
    let scratch = Scratch::new();
    let (options, _) = asking(OnUnnamable::Rename);
    let data = zip(&[
        Entry::File(b"a_b.txt", b"there"),
        Entry::File(b"a:b.txt", b"renamed"),
    ]);
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(summary.renamed[0].to, ["a_b (2).txt"]);
    assert_eq!(
        std::fs::read(scratch.out().join("a_b.txt")).unwrap(),
        b"there"
    );
}

#[test]
fn what_climbs_is_never_asked_about() {
    let scratch = Scratch::new();
    let (options, asked) = asking(OnUnnamable::Rename);
    let data = zip(&[
        Entry::File(b"a:b.txt", b"x"),
        Entry::File(b"../evil", b"evil"),
    ]);
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Name(NameError::Dot)));
    // Asked of the name it could take, not of the one that climbs; and stopped,
    // before anything is written.
    assert_eq!(*asked.lock().unwrap(), [["a:b.txt"]]);
    assert!(!scratch.out().exists());
}

/// A link that leads outside is left out with `links_outside`, and the rest
/// extracted; without it, it stops as before.
#[cfg(unix)]
#[test]
fn a_link_that_leads_outside_can_be_left_out() {
    let data = zip(&[
        Entry::File(b"good.txt", b"ok"),
        Entry::Mode(b"out", b"/etc", 0o120_777),
        Entry::Mode(b"up", b"../..", 0o120_777),
        Entry::Mode(b"in", b"good.txt", 0o120_777),
    ]);
    let mut options = Options::default();
    options.links = Links::Inside;
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::LinkTarget(_)), "{error}");
    options.links_outside = OnRefused::Skip;
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(listing(&scratch.out()), ["good.txt", "in"]);
    assert_eq!(summary.links, 1);
    let left: Vec<&[u8]> = summary
        .skipped
        .iter()
        .map(|e| e.name.as_deref().unwrap())
        .collect();
    assert_eq!(left, [&b"out"[..], b"up"]);
}

/// What a sink is given: the paths of its files.
#[derive(Default)]
struct Names(Vec<String>);

impl Sink for Names {
    fn directory(&mut self, _: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        Ok(())
    }
    fn start_file(&mut self, entry: &hivepack::extract::Entry<'_>) -> std::io::Result<()> {
        self.0.push(entry.path.join("/"));
        Ok(())
    }
    fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn finish_file(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn discard_file(&mut self) {}
    fn symlink(&mut self, _: &hivepack::extract::Entry<'_>, _: &str) -> std::io::Result<()> {
        Ok(())
    }
    fn hard_link(&mut self, _: &hivepack::extract::Entry<'_>, _: &[String]) -> std::io::Result<()> {
        Ok(())
    }
}

/// A sink takes two names that differ only in case, on every system: what it
/// makes is an archive, which holds both, not a folder.
#[test]
fn a_sink_takes_names_that_differ_only_in_case() {
    let data = zip(&[
        Entry::File(b"README", b"upper"),
        Entry::File(b"readme", b"lower"),
    ]);
    let archive = Archive::open(&data[..], OpenFlags::CHECKCONS).unwrap();
    let mut names = Names::default();
    extract_zip_to(&archive, &mut names, &Options::default()).unwrap();
    assert_eq!(names.0, ["README", "readme"]);
    // By every system's rules, they are one.
    let mut options = Options::default();
    options.name_rules = NameRules::Portable;
    let mut names = Names::default();
    let error = extract_zip_to(&archive, &mut names, &options).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
        "{error}"
    );
}

/// On Windows and macOS, whose file systems take two names that differ only in
/// case for one, as the destination is found to, they are asked about by this
/// system's rules too.
#[cfg(any(windows, target_os = "macos"))]
#[test]
fn names_one_where_extracted_are_asked_about() {
    let data = zip(&[
        Entry::File(b"README", b"upper"),
        Entry::File(b"readme", b"lower"),
    ]);
    let (mut options, asked) = asking(OnUnnamable::Rename);
    options.name_rules = NameRules::Native;
    let scratch = Scratch::new();
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(*asked.lock().unwrap(), [["readme"]]);
    assert_eq!(summary.renamed[0].to, ["readme (2)"]);
}
