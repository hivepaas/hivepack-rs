//! The port against Linux's udf file system: testdata/udf holds images
//! that tools/udf-images/make.sh makes with mkudffs and genisoimage and
//! fills through Linux, with what Linux reads of each mounted (answer.py).
//! The port must read the same, but where NetBSD and Linux differ, which
//! `differences` gives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "udf_support/mod.rs"]
mod support;

use std::fs;

use support::{linux_options, repository, transcript, xz_decode};

/// Where NetBSD reads otherwise than Linux, by image: what the port
/// gives instead of Linux's line, for the lines that differ.
fn differences(_name: &str, linux: &str) -> String {
    linux.to_string()
}

/// What differs between the port's transcript of the image and Linux's.
fn check(dir: &std::path::Path, name: &str) -> Option<String> {
    let image = xz_decode(&fs::read(dir.join(format!("{name}.udf.xz"))).unwrap());
    let linux = fs::read_to_string(dir.join(format!("{name}.txt"))).unwrap();
    if linux.starts_with('#') {
        // Linux does not mount it: the port's transcript, for now.
        println!("{name}: {:?}", transcript(image, &linux_options()));
        return None;
    }
    let expected = differences(name, &linux);
    match transcript(image, &linux_options()) {
        Ok(got) if got == expected => None,
        Ok(got) => {
            let diff: Vec<_> = expected
                .lines()
                .zip(got.lines())
                .filter(|(a, b)| a != b)
                .take(5)
                .map(|(a, b)| format!("  linux {a}\n  port  {b}"))
                .collect();
            Some(format!(
                "{name}: {} lines, {} expected\n{}",
                got.lines().count(),
                expected.lines().count(),
                diff.join("\n")
            ))
        }
        Err(e) => Some(format!("{name}: {e}")),
    }
}

#[test]
fn reads_what_linux_reads() {
    let dir = repository().join("testdata/udf");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            e.unwrap()
                .file_name()
                .to_str()?
                .strip_suffix(".udf.xz")
                .map(str::to_string)
        })
        .collect();
    names.sort();
    assert!(names.len() >= 27, "{names:?}");
    // The images four at a time: a debug build decompresses and hashes
    // them slowly, and each takes 64 MiB.
    let mut failures = Vec::new();
    for chunk in names.chunks(4) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|name| scope.spawn(|| check(&dir, name)))
                .collect();
            failures.extend(handles.into_iter().filter_map(|h| h.join().unwrap()));
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
