//! libzip's own tests, `regress/*.test`, run on the port: each is a script
//! for nihtest, which copies the test's files into a fresh folder, runs a
//! program there, and compares its exit status, standard output and
//! standard error with those the script gives.
//!
//! The programs are this crate's `ziptool`, which stands for libzip's
//! `ziptool_regress`, and `tryopen`. A test that uses a command the port's
//! ziptool has not got yet (adding data, compression, encryption), needs a
//! feature hivepack::zip has not got (`FTS`), or runs
//! another of libzip's test programs, is skipped and counted. Each file a
//! test gives must hold what it says afterwards, or be gone where it says
//! `{}`, and no other file may be left in the folder. The tests come from the libzip 1.12.1
//! release that `scripts/testdata.py fetch --group generated` fetches; without
//! it the test notes that and passes, unless `HIVEPACK_TESTDATA_REQUIRED`
//! names the group.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The commands of the port's ziptool, with how many arguments each takes.
const COMMANDS: &[(&str, usize)] = &[
    ("add", 2),
    ("add_dir", 1),
    ("add_file", 4),
    ("add_from_zip", 5),
    ("add_nul", 2),
    ("cat", 1),
    ("cat_partial", 3),
    ("count_extra", 2),
    ("count_extra_by_id", 3),
    ("delete", 1),
    ("delete_extra", 3),
    ("delete_extra_by_id", 4),
    ("extract_as", 2),
    ("fopen", 1),
    ("fread", 2),
    ("get_archive_comment", 0),
    ("get_archive_flag", 1),
    ("get_extra", 3),
    ("get_extra_by_id", 4),
    ("get_file_comment", 1),
    ("get_num_entries", 1),
    ("name_locate", 2),
    ("rename", 2),
    ("replace_file_contents", 2),
    ("set_archive_comment", 1),
    ("set_archive_flag", 2),
    ("set_extra", 5),
    ("set_file_comment", 2),
    ("set_file_compression", 3),
    ("set_file_dostime", 3),
    ("set_file_mtime", 2),
    ("set_file_encryption", 3),
    ("set_file_mtime_all", 1),
    ("set_password", 1),
    ("stat", 1),
    ("unchange", 1),
    ("unchange_all", 0),
];

/// The tests that wait for what the port cannot do yet, and why.
const WAITING: &[(&str, &str)] = &[];

/// What a file of a test holds: nothing (`{}`, no file), the lines given
/// in the script (`<inline>`), or a file of libzip's.
#[derive(Clone, PartialEq)]
enum Content {
    None,
    Inline(Vec<u8>),
    File(String),
}

/// A test, as its script describes it.
#[derive(Default)]
struct Test {
    program: Option<String>,
    arguments: Vec<String>,
    ret: i32,
    /// (name in the test folder, what it holds before, what it must hold
    /// after: the same if not given)
    files: Vec<(String, Content, Option<Content>)>,
    stdin: Vec<String>,
    stdout: Vec<String>,
    stderr: Vec<String>,
    /// why the port cannot run it, if it cannot
    skip: Option<String>,
}

/// The words of an `arguments` line, with double quotes grouping, and in
/// them `\n`, `\r` and `\t` for those characters and a backslash before
/// any other for it.
fn words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            '\\' if quoted => match chars.next() {
                Some('n') => word.push('\n'),
                Some('r') => word.push('\r'),
                Some('t') => word.push('\t'),
                Some(other) => word.push(other),
                None => {}
            },
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

fn parse(text: &str) -> Test {
    let mut test = Test::default();
    let mut lines = text.lines();
    let inline = |lines: &mut std::str::Lines<'_>| -> Vec<String> {
        lines
            .by_ref()
            .take_while(|l| *l != "end-of-inline-data")
            .map(String::from)
            .collect()
    };
    while let Some(line) = lines.next() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (directive, rest) = line.split_once(' ').unwrap_or((line, ""));
        match directive {
            "description" => {}
            "program" => test.program = Some(rest.to_string()),
            "arguments" => test.arguments = words(rest),
            "return" => test.ret = rest.trim().parse().unwrap(),
            "file" => {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                let mut content = |part: &str| match part {
                    "{}" => Content::None,
                    // The lines of the script, each ending in a newline.
                    "<inline>" => Content::Inline(
                        inline(&mut lines)
                            .iter()
                            .flat_map(|l| format!("{l}\n").into_bytes())
                            .collect(),
                    ),
                    file => Content::File(file.into()),
                };
                let before = content(parts[1]);
                let after = parts.get(2).map(|p| content(p));
                test.files.push((parts[0].into(), before, after));
            }
            // WinZip AES, which needs a crypto library in libzip, bzip2,
            // and LZMA and XZ.
            "features"
                if matches!(
                    rest,
                    "HAVE_CRYPTO" | "HAVE_LIBBZ2" | "HAVE_LIBLZMA" | "HAVE_LIBZSTD"
                ) => {}
            "stdin" if rest.is_empty() => test.stdin = inline(&mut lines),
            "stdout" if rest.is_empty() => test.stdout = inline(&mut lines),
            "stderr" if rest.is_empty() => test.stderr = inline(&mut lines),
            other => {
                test.skip.get_or_insert(format!("{other} {rest}"));
            }
        }
    }
    test
}

/// Why the port cannot run `test`, if it cannot.
fn unsupported(test: &Test) -> Option<String> {
    if let Some(skip) = &test.skip {
        return Some(skip.clone());
    }
    match test.program.as_deref() {
        Some("tryopen") => None,
        None | Some("ziptool_regress_nonrandom") => {
            let mut i = 0;
            let args = &test.arguments;
            while i < args.len() && args[i].starts_with('-') {
                if args[i] == "--" {
                    i += 1;
                    break;
                }
                if args[i].contains('H') {
                    return Some("a source with holes".into());
                }
                if args[i].ends_with('l') || args[i].ends_with('o') || args[i].ends_with('F') {
                    i += 1;
                }
                i += 1;
            }
            i += 1; // the archive
            let commands: Vec<String> = if args
                .iter()
                .take(i)
                .any(|a| a.starts_with('-') && a.contains('i'))
            {
                test.stdin
                    .iter()
                    .flat_map(|l| l.split_whitespace().map(String::from).collect::<Vec<_>>())
                    .collect()
            } else {
                args[i.min(args.len())..].to_vec()
            };
            let mut j = 0;
            while j < commands.len() {
                match COMMANDS.iter().find(|(name, _)| *name == commands[j]) {
                    Some((_, count)) => j += 1 + count,
                    None => return Some(format!("command {}", commands[j])),
                }
            }
            None
        }
        Some(other) => Some(format!("program {other}")),
    }
}

/// `default-stderr-replace`: the program's name at the start of a line,
/// `^([A-Z]:)?[^ :]*: `, removed.
fn strip_program(line: &str) -> String {
    let mut rest = line;
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_uppercase() && bytes[1] == b':' {
        rest = &rest[2..];
    }
    let end = rest.find([' ', ':']).unwrap_or(rest.len());
    if rest[end..].starts_with(": ") {
        rest[end + 2..].to_string()
    } else {
        line.to_string()
    }
}

/// Runs `test` in `folder`: `Err` with what differs.
fn run(test: &Test, regress: &Path, extracted: &Path, folder: &Path) -> Result<(), String> {
    // What a file of libzip's holds: in regress/, regress/data/, or among
    // the archives extracted for the tests.
    let read = |file: &str| -> Result<Vec<u8>, String> {
        [
            regress.join(file),
            regress.join("data").join(file),
            extracted.join(file),
        ]
        .into_iter()
        .find(|p| p.is_file())
        .map(|p| std::fs::read(p).unwrap())
        .ok_or(format!("no file {file}"))
    };
    for (name, before, _) in &test.files {
        match before {
            Content::None => {}
            Content::Inline(data) => std::fs::write(folder.join(name), data).unwrap(),
            Content::File(file) => std::fs::write(folder.join(name), read(file)?).unwrap(),
        }
    }
    let program = match test.program.as_deref() {
        Some("tryopen") => env!("CARGO_BIN_EXE_tryopen"),
        _ => env!("CARGO_BIN_EXE_ziptool"),
    };
    let mut command = Command::new(program);
    // The port's ziptool_regress_nonrandom.
    if test.program.as_deref() == Some("ziptool_regress_nonrandom") {
        command.env("HIVEPACK_ZIPTOOL_NONRANDOM", "1");
    }
    let mut child = command
        .args(&test.arguments)
        .current_dir(folder)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        for line in &test.stdin {
            let _ = writeln!(stdin, "{line}");
        }
    }
    let output = child.wait_with_output().unwrap();

    let mut problems = Vec::new();
    let code = output.status.code().unwrap_or(-1);
    if code != test.ret {
        problems.push(format!("exit status {code}, not {}", test.ret));
    }
    // nihtest compares lines, so a last line ends with or without one.
    let stdout: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(String::from)
        .collect();
    if stdout != test.stdout {
        problems.push(format!(
            "stdout:\n{}\nnot:\n{}",
            stdout.join("\n"),
            test.stdout.join("\n")
        ));
    }
    let stderr: Vec<String> = String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(strip_program)
        .collect();
    if stderr != test.stderr {
        problems.push(format!(
            "stderr:\n{}\nnot:\n{}",
            stderr.join("\n"),
            test.stderr.join("\n")
        ));
    }
    for (name, before, after) in &test.files {
        let want = match after.as_ref().unwrap_or(before) {
            Content::None => None,
            Content::Inline(data) => Some(data.clone()),
            Content::File(file) => Some(read(file)?),
        };
        // nihtest.conf's comparators: an archive written as one with the
        // same name is compared with `zipcmp -pv`; one written as `.nzip`
        // must differ from the `.zip` (`files_differ`: encrypted with random
        // bytes, not as without them); anything else byte for byte.
        if let (Content::File(expected), Some(want)) = (after.as_ref().unwrap_or(before), &want)
            && name.ends_with(".nzip")
            && expected.ends_with(".zip")
        {
            if std::fs::read(folder.join(name)).ok().as_ref() == Some(want) {
                problems.push(format!("{name} does not differ from {expected}"));
            }
            continue;
        }
        if let (Content::File(expected), Some(_)) = (after.as_ref().unwrap_or(before), &want)
            && name.ends_with(".zip")
            && expected.ends_with(".zip")
            && folder.join(name).is_file()
        {
            let expected_path = [
                regress.join(expected),
                regress.join("data").join(expected),
                extracted.join(expected),
            ]
            .into_iter()
            .find(|p| p.is_file())
            .ok_or(format!("no file {expected}"))?;
            let zipcmp = Command::new(env!("CARGO_BIN_EXE_zipcmp"))
                .arg("-pv")
                .arg(&expected_path)
                .arg(folder.join(name))
                .output()
                .unwrap();
            if !zipcmp.status.success() {
                problems.push(format!(
                    "{name} differs:\n{}",
                    String::from_utf8_lossy(&zipcmp.stdout)
                ));
            }
            continue;
        }
        let got = std::fs::read(folder.join(name)).ok();
        if got != want {
            problems.push(match (&got, &want) {
                (None, _) => format!("{name} is not there"),
                (_, None) => format!("{name} is there"),
                _ => format!("{name} differs"),
            });
        }
    }
    for entry in std::fs::read_dir(folder).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if !test.files.iter().any(|(listed, _, _)| *listed == name) {
            problems.push(format!("{name} is left"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

/// The archives libzip's build extracts from `data/manyfiles-zip.zip` and
/// `data/bigzero-zip.zip`, extracted here with hivepack::zip.
fn extract_generated(regress: &Path, to: &Path) {
    use std::io::Read;

    use hivepack::zip::{Archive, Flags, OpenFlags};

    std::fs::create_dir_all(to).unwrap();
    for name in ["manyfiles-zip.zip", "bigzero-zip.zip"] {
        let file = std::fs::File::open(regress.join("data").join(name)).unwrap();
        let za = Archive::open(file, OpenFlags::CHECKCONS).unwrap();
        for i in 0..za.get_num_entries(Flags::NONE) {
            let entry = String::from_utf8(za.get_name(i, Flags::NONE).unwrap().to_vec()).unwrap();
            let mut data = Vec::new();
            za.fopen_index(i, Flags::NONE)
                .unwrap()
                .read_to_end(&mut data)
                .unwrap();
            std::fs::write(to.join(entry), data).unwrap();
        }
    }
}

fn regress_folder() -> Option<PathBuf> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cache = std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository.join("target/testdata"));
    let regress = cache.join("libzip-1.12.1-source/libzip-1.12.1/regress");
    if regress.is_dir() {
        return Some(regress);
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == "generated"),
        "libzip's tests are missing: run `python3 scripts/testdata.py fetch --group generated`"
    );
    eprintln!(
        "skipping: libzip's tests are not fetched (scripts/testdata.py fetch --group generated)"
    );
    None
}

#[test]
fn libzip_tests_pass() {
    let Some(regress) = regress_folder() else {
        return;
    };
    let mut names: Vec<PathBuf> = std::fs::read_dir(&regress)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "test"))
        .collect();
    names.sort();

    let scratch =
        std::env::temp_dir().join(format!("hivepack-ziptool-regress-{}", std::process::id()));
    let extracted = scratch.join("extracted");
    extract_generated(&regress, &extracted);
    let (mut passed, mut skipped, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    for path in &names {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let test = parse(&std::fs::read_to_string(path).unwrap());
        if let Some((_, why)) = WAITING.iter().find(|(waiting, _)| *waiting == name) {
            skipped.push(format!("{name}: {why}"));
            continue;
        }
        if let Some(why) = unsupported(&test) {
            skipped.push(format!("{name}: {why}"));
            continue;
        }
        let folder = scratch.join(&name);
        std::fs::create_dir_all(&folder).unwrap();
        match run(&test, &regress, &extracted, &folder) {
            Ok(()) => passed.push(name),
            Err(why) => failed.push(format!("{name}:\n{why}")),
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);

    eprintln!(
        "{} of libzip's tests pass, {} are skipped",
        passed.len(),
        skipped.len()
    );
    // Why, by kind: the first word of each reason.
    let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
    for reason in &skipped {
        let why = reason.split_once(": ").map_or("", |(_, why)| why);
        *kinds
            .entry(why.split(' ').next().unwrap_or(""))
            .or_default() += 1;
    }
    eprintln!("skipped: {kinds:?}");
    assert!(
        failed.is_empty(),
        "{} failed:\n\n{}",
        failed.len(),
        failed.join("\n\n")
    );
    assert!(passed.len() >= 60, "only {} ran", passed.len());
}
