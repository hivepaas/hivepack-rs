//! zlib's own coverage test of inflate, `test/infcover.c` from zlib 1.3.2,
//! ported: the same inputs, given the same way, with the same expected
//! results and messages.
//!
//! Left out: what needs zlib's memory hooks to force allocation failures,
//! or a stream that was never initialised, neither of which the port has;
//! `inflateBack`, which is not ported; and the version check of
//! `inflateInit_`.

// Helpers outside #[test] functions unwrap too: a failure there is a test
// failure.
#![allow(clippy::unwrap_used, clippy::panic)]

use hivepack::deflate::{Flush, GzHeader, InBuffer, Inflate, OutBuffer, Result, Status};

/// zlib's return code for a result.
fn code(ret: Result<Status>) -> i32 {
    match ret {
        Ok(Status::Ok) => 0,
        Ok(Status::StreamEnd) => 1,
        Ok(Status::NeedDict) => 2,
        Err(e) => e.code().number(),
    }
}

const Z_OK: i32 = 0;
const Z_STREAM_END: i32 = 1;
const Z_NEED_DICT: i32 = 2;
const Z_STREAM_ERROR: i32 = -2;
const Z_DATA_ERROR: i32 = -3;
const Z_BUF_ERROR: i32 = -5;
/// infcover's "don't care".
const ANY: i32 = 9;

/// Bytes from a string of hexadecimal numbers separated by spaces: `h2b`.
fn h2b(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect()
}

/// Decompresses `hex` with window bits `win`, giving it `step` bytes at a
/// time (all at once for 0) and `len` bytes of output space per call. The
/// first call must return `err`. With a window of 47, the gzip header is
/// asked for too.
///
/// Port of `inf`, `test/infcover.c`.
fn inf(hex: &str, what: &str, step: usize, win: i32, len: usize, err: i32) {
    let Ok(mut strm) = Inflate::new(win) else {
        // zlib's inf() gives up quietly when the window is refused.
        assert_eq!(err, Z_STREAM_ERROR, "{what}");
        return;
    };
    let mut out = vec![0; len];
    if win == 47 {
        strm.get_header(GzHeader::new(len, len, len)).unwrap();
    }
    let input = h2b(hex);
    let step = if step == 0 || step > input.len() {
        input.len()
    } else {
        step
    };
    let mut pos = 0;
    let mut avail = step;
    let mut err = err;
    loop {
        let mut output = OutBuffer::new(&mut out);
        let mut source = InBuffer {
            src: &input[..pos + avail],
            pos,
        };
        let ret = code(strm.inflate(&mut output, &mut source, Flush::NoFlush));
        assert!(
            err == ANY || ret == err,
            "{what}: returned {ret}, expected {err}"
        );
        pos = source.pos;
        if ret != Z_OK && ret != Z_BUF_ERROR && ret != Z_NEED_DICT {
            break;
        }
        if ret == Z_NEED_DICT {
            assert_eq!(
                code(strm.set_dictionary(&input[..1]).map(|()| Status::Ok)),
                Z_DATA_ERROR
            );
            // infcover forces a memory error here, then puts the stream
            // back in DICT.
            assert_eq!(code(strm.set_dictionary(&[]).map(|()| Status::Ok)), Z_OK);
            let mut output = OutBuffer::new(&mut out);
            let mut source = InBuffer {
                src: &input[..pos],
                pos,
            };
            assert_eq!(
                code(strm.inflate(&mut output, &mut source, Flush::NoFlush)),
                Z_BUF_ERROR
            );
        }
        // inflateCopy, then inflateEnd on the copy.
        drop(strm.clone());
        err = ANY; // don't care next time around
        avail = step.min(input.len() - pos);
        if avail == 0 {
            break;
        }
    }
    strm.reset2(-8).unwrap();
}

/// Decompresses `hex` all at once with `Flush::Trees`, as a raw stream, or
/// as gzip or zlib if `err` is negative; if `err` is not zero it must fail
/// with the message `id`.
///
/// Port of `try`, `test/infcover.c`, without the half for `inflateBack`.
fn try_(hex: &str, id: &str, err: i32) {
    let input = h2b(hex);
    let size = input.len() << 3;
    let mut out = vec![0; size];
    let mut strm = Inflate::new(if err < 0 { 47 } else { -15 }).unwrap();
    let mut source = InBuffer::new(&input);
    let mut ret;
    loop {
        let mut output = OutBuffer::new(&mut out);
        ret = strm.inflate(&mut output, &mut source, Flush::Trees);
        let full = output.pos == size;
        let c = code(ret);
        assert!(c != Z_STREAM_ERROR && c != -4, "{id}");
        if c == Z_DATA_ERROR || c == Z_NEED_DICT {
            break;
        }
        if !(source.pos < input.len() || full) {
            break;
        }
    }
    if err != 0 {
        let e = ret.unwrap_err();
        assert_eq!(e.code().number(), Z_DATA_ERROR, "{id}");
        assert_eq!(e.msg(), Some(id));
        assert_eq!(strm.msg(), Some(id));
    }
}

/// `cover_support`: the functions before inflate().
#[test]
fn support() {
    let mut strm = Inflate::new_default();
    strm.prime(5, 31).unwrap();
    strm.prime(-1, 0).unwrap();
    assert_eq!(
        code(strm.set_dictionary(&[]).map(|()| Status::Ok)),
        Z_STREAM_ERROR
    );

    inf("63 0", "force window allocation", 0, -15, 1, Z_OK);
    inf("63 18 5", "force window replacement", 0, -8, 259, Z_OK);
    inf(
        "63 18 68 30 d0 0 0",
        "force split window update",
        4,
        -8,
        259,
        Z_OK,
    );
    inf("3 0", "use fixed blocks", 0, -15, 1, Z_STREAM_END);
    inf("", "bad window size", 0, 1, 0, Z_STREAM_ERROR);
}

/// `cover_wrap`: the zlib and gzip headers and trailers, and the code
/// after inflate().
#[test]
fn wrap() {
    inf("1f 8b 0 0", "bad gzip method", 0, 31, 0, Z_DATA_ERROR);
    inf("1f 8b 8 80", "bad gzip flags", 0, 31, 0, Z_DATA_ERROR);
    inf("77 85", "bad zlib method", 0, 15, 0, Z_DATA_ERROR);
    inf("8 99", "set window size from header", 0, 0, 0, Z_OK);
    inf("78 9c", "bad zlib window size", 0, 8, 0, Z_DATA_ERROR);
    inf(
        "78 9c 63 0 0 0 1 0 1",
        "check adler32",
        0,
        15,
        1,
        Z_STREAM_END,
    );
    inf(
        "1f 8b 8 1e 0 0 0 0 0 0 1 0 0 0 0 0 0",
        "bad header crc",
        0,
        47,
        1,
        Z_DATA_ERROR,
    );
    inf(
        "1f 8b 8 2 0 0 0 0 0 0 1d 26 3 0 0 0 0 0 0 0 0 0",
        "check gzip length",
        0,
        47,
        0,
        Z_STREAM_END,
    );
    inf("78 90", "bad zlib header check", 0, 47, 0, Z_DATA_ERROR);
    inf("8 b8 0 0 0 1", "need dictionary", 0, 8, 0, Z_NEED_DICT);
    inf("78 9c 63 0", "compute adler32", 0, 15, 1, Z_OK);

    // infcover first forces memory errors here, which the port cannot.
    let mut strm = Inflate::new(-8).unwrap();
    strm.set_dictionary(&[0; 257]).unwrap();
    strm.prime(16, 0).unwrap();
    let mut source = InBuffer::new(b"\x80\0");
    assert_eq!(
        code(strm.sync(&mut source).map(|()| Status::Ok)),
        Z_DATA_ERROR
    );
    let mut out = [0; 1];
    let ret = strm.inflate(
        &mut OutBuffer::new(&mut out),
        &mut InBuffer::new(&[]),
        Flush::NoFlush,
    );
    assert_eq!(code(ret), Z_STREAM_ERROR);
    let mut source = InBuffer::new(b"\0\0\xff\xff");
    strm.sync(&mut source).unwrap();
    assert_eq!(source.pos, 4);
    let _ = strm.sync_point();
    drop(strm.clone());
    assert_eq!(
        code(strm.undermine(true).map(|()| Status::Ok)),
        Z_DATA_ERROR
    );
    let _ = strm.mark();
}

/// `cover_inflate`: the deflate data cases.
#[test]
fn deflate_data() {
    try_("0 0 0 0 0", "invalid stored block lengths", 1);
    try_("3 0", "fixed", 0);
    try_("6", "invalid block type", 1);
    try_("1 1 0 fe ff 0", "stored", 0);
    try_("fc 0 0", "too many length or distance symbols", 1);
    try_("4 0 fe ff", "invalid code lengths set", 1);
    try_("4 0 24 49 0", "invalid bit length repeat", 1);
    try_("4 0 24 e9 ff ff", "invalid bit length repeat", 1);
    try_("4 0 24 e9 ff 6d", "invalid code -- missing end-of-block", 1);
    try_(
        "4 80 49 92 24 49 92 24 71 ff ff 93 11 0",
        "invalid literal/lengths set",
        1,
    );
    try_(
        "4 80 49 92 24 49 92 24 f b4 ff ff c3 84",
        "invalid distances set",
        1,
    );
    try_(
        "4 c0 81 8 0 0 0 0 20 7f eb b 0 0",
        "invalid literal/length code",
        1,
    );
    try_("2 7e ff ff", "invalid distance code", 1);
    try_(
        "c c0 81 0 0 0 0 0 90 ff 6b 4 0",
        "invalid distance too far back",
        1,
    );

    // also trailer mismatch just in inflate()
    try_(
        "1f 8b 8 0 0 0 0 0 0 0 3 0 0 0 0 1",
        "incorrect data check",
        -1,
    );
    try_(
        "1f 8b 8 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 1",
        "incorrect length check",
        -1,
    );
    try_("5 c0 21 d 0 0 0 80 b0 fe 6d 2f 91 6c", "pull 17", 0);
    try_(
        "5 e0 81 91 24 cb b2 2c 49 e2 f 2e 8b 9a 47 56 9f fb fe ec d2 ff 1f",
        "long code",
        0,
    );
    try_("ed c0 1 1 0 0 0 40 20 ff 57 1b 42 2c 4f", "length extra", 0);
    try_(
        "ed cf c1 b1 2c 47 10 c4 30 fa 6f 35 1d 1 82 59 3d fb be 2e 2a fc f c",
        "long distance and extra",
        0,
    );
    try_(
        "ed c0 81 0 0 0 0 80 a0 fd a9 17 a9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
         0 0 0 0 0 6",
        "window end",
        0,
    );
    inf(
        "2 8 20 80 0 3 0",
        "inflate_fast TYPE return",
        0,
        -15,
        258,
        Z_STREAM_END,
    );
    inf("63 18 5 40 c 0", "window wrap", 3, -8, 300, Z_OK);
}

/// `cover_fast`: the rest of inffast.c's decoding and window copying.
#[test]
fn fast() {
    inf(
        "e5 e0 81 ad 6d cb b2 2c c9 01 1e 59 63 ae 7d ee fb 4d fd b5 35 41 68 ff 7f 0f 0 0 0",
        "fast length extra bits",
        0,
        -8,
        258,
        Z_DATA_ERROR,
    );
    inf(
        "25 fd 81 b5 6d 59 b6 6a 49 ea af 35 6 34 eb 8c b9 f6 b9 1e ef 67 49 50 fe ff ff 3f 0 0",
        "fast distance extra bits",
        0,
        -8,
        258,
        Z_DATA_ERROR,
    );
    inf(
        "3 7e 0 0 0 0 0",
        "fast invalid distance code",
        0,
        -8,
        258,
        Z_DATA_ERROR,
    );
    inf(
        "1b 7 0 0 0 0 0",
        "fast invalid literal/length code",
        0,
        -8,
        258,
        Z_DATA_ERROR,
    );
    inf(
        "d c7 1 ae eb 38 c 4 41 a0 87 72 de df fb 1f b8 36 b1 38 5d ff ff 0",
        "fast 2nd level codes and too far back",
        0,
        -8,
        258,
        Z_DATA_ERROR,
    );
    inf(
        "63 18 5 8c 10 8 0 0 0 0",
        "very common case",
        0,
        -8,
        259,
        Z_OK,
    );
    inf(
        "63 60 60 18 c9 0 8 18 18 18 26 c0 28 0 29 0 0 0",
        "contiguous and wrap around window",
        6,
        -8,
        259,
        Z_OK,
    );
    inf(
        "63 0 3 0 0 0 0 0",
        "copy direct from output",
        0,
        -8,
        259,
        Z_STREAM_END,
    );
}
