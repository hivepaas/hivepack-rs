//! The test files of XZ Utils, `tests/files` in its release, decoded as its
//! `tests/test_files.sh` decodes them with `xz -dc`: each file named
//! `good-*` decodes, each `bad-*` and `unsupported-*` does not. Each is
//! decoded in one call and a byte at a time, with the same results. The
//! .lzma files, which `test_files.sh` leaves out, too.
//!
//! The files come with the release sources, in the `generated` group of
//! `scripts/testdata.py`. The oracle tests compare the decoders on them
//! with liblzma's, call by call.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "xz_support/mod.rs"]
mod support;

use hivepack::xz::{
    Action, CONCATENATED, Error, InBuffer, OutBuffer, Status, Stream, TELL_UNSUPPORTED_CHECK,
};
use support::cache;

/// How a file ends: the output, the result that ended it and the input
/// left unread, and whether `LZMA_UNSUPPORTED_CHECK` was returned on the
/// way.
#[derive(Debug, PartialEq)]
struct Outcome {
    output: Vec<u8>,
    end: Result<Status, Error>,
    unread: usize,
    unsupported_check: bool,
}

/// The decoder `xz -dc` takes for a file named `name`: the .xz decoder with
/// concatenated Streams, the .lz decoder with concatenated members, or the
/// LZMA_Alone decoder.
fn decoder(name: &str) -> Stream {
    if name.ends_with(".lz") {
        Stream::lzip_decoder(u64::MAX, CONCATENATED).unwrap()
    } else if name.ends_with(".lzma") {
        Stream::alone_decoder(u64::MAX).unwrap()
    } else {
        Stream::stream_decoder(u64::MAX, CONCATENATED | TELL_UNSUPPORTED_CHECK).unwrap()
    }
}

/// `data` decoded as `xz -dc` decodes the file `name`, offering `piece`
/// bytes of input and of output space at a time.
fn decode(name: &str, data: &[u8], piece: usize) -> Outcome {
    let mut strm = decoder(name);
    let mut output = Vec::new();
    let mut unsupported_check = false;
    let mut in_pos = 0;
    loop {
        let end = (in_pos + piece).min(data.len());
        let mut input = InBuffer {
            src: &data[..end],
            pos: in_pos,
        };
        let mut space = vec![0; piece];
        let mut out = OutBuffer::new(&mut space);
        // LZMA_FINISH once all the input is offered: with it the input
        // must not change from call to call.
        let action = if end == data.len() {
            Action::Finish
        } else {
            Action::Run
        };
        let ret = strm.code(&mut out, &mut input, action);
        in_pos = input.pos;
        let written = out.pos;
        output.extend_from_slice(&space[..written]);
        match ret {
            Ok(Status::Ok) => {}
            Ok(Status::UnsupportedCheck) => unsupported_check = true,
            end => {
                return Outcome {
                    output,
                    end,
                    unread: data.len() - in_pos,
                    unsupported_check,
                };
            }
        }
    }
}

/// Whether `xz -dc` succeeds: the end of the stream, and nothing after it
/// but in .lz files, which may have data after their members.
fn succeeds(name: &str, outcome: &Outcome) -> bool {
    outcome.end == Ok(Status::StreamEnd) && (outcome.unread == 0 || name.ends_with(".lz"))
}

#[test]
fn xz_utils_test_files() {
    let folder = cache().join("xz-5.8.4-source/xz-5.8.4/tests/files");
    let Ok(entries) = std::fs::read_dir(&folder) else {
        let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
        assert!(
            !required.split(',').any(|g| g == "all" || g == "generated"),
            "the XZ Utils sources are missing: run `python3 scripts/testdata.py fetch --group generated`"
        );
        eprintln!(
            "skipping: the XZ Utils sources are not fetched (scripts/testdata.py fetch --group generated)"
        );
        return;
    };
    let mut names: Vec<String> = entries
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".xz") || n.ends_with(".lz") || n.ends_with(".lzma"))
        .collect();
    names.sort();
    assert!(names.len() > 90, "only {} test files", names.len());

    for name in &names {
        let data = std::fs::read(folder.join(name)).unwrap();
        let whole = decode(name, &data, data.len() + (1 << 20));
        let bytes = decode(name, &data, 1);
        if name == "good-known_size-with_eopm.lzma" {
            // liblzma forgets between calls that the end of payload marker
            // may follow the known size, and refuses the marker when the
            // input ends inside it (docs/xz.md). So does the port.
            assert_eq!(bytes.end, Err(Error::Data), "{name} a byte at a time");
            assert_eq!(bytes.output, whole.output, "{name} a byte at a time");
        } else {
            assert_eq!(bytes, whole, "{name} a byte at a time");
        }
        if name.starts_with("good-") {
            assert!(succeeds(name, &whole), "{name}: {whole:?}");
            assert!(!whole.unsupported_check, "{name}");
        } else if name == "unsupported-check.xz" {
            // xz -dc warns and exits with status 2, and decodes all.
            assert!(succeeds(name, &whole), "{name}: {whole:?}");
            assert!(whole.unsupported_check, "{name}");
        } else {
            assert!(!succeeds(name, &whole), "{name}: {whole:?}");
        }
    }
}
