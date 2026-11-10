//! Compresses the input with hivepack::deflate's port of libdeflate's
//! compressor, at a level its first byte picks, and checks the stream: it
//! inflates back to the input with hivepack's own `Inflate`; it is the same
//! when compressed again with the same compressor, and with a new one; it
//! does not fit in a buffer one byte shorter; and in a buffer of a size the
//! second byte picks, it fits as the same stream or not at all. As a part
//! of a stream (`deflate_compress_part`), it is the same stream but for one
//! bit, BFINAL, and a sync marker after it, and that part twice, then the
//! stream, inflates to the input three times. A panic or a difference is a
//! bug.
//!
//! libdeflate itself is not linked here: `crates/hivepack/tests/deflate_libdeflate.rs`
//! compares the port with it, byte for byte, through its oracle.

#![no_main]

use hivepack::deflate::{Compressor, Flush, InBuffer, Inflate, OutBuffer, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((&room, input)) = rest.split_first() else { return };
    // -1 (the default, 6) to 12.
    let level = i32::from(mode % 14) - 1;
    let Some(mut compressor) = Compressor::new(level) else { panic!("level {level}") };

    let mut out = vec![0u8; compressor.deflate_compress_bound(input.len())];
    let size = compressor.deflate_compress(input, &mut out);
    assert!(size > 0, "level {level}: the bound is too small");
    let stream = &out[..size];

    let mut inflate = Inflate::new(-15).expect("raw inflate");
    let mut back = vec![0u8; input.len() + 1];
    let mut output = OutBuffer::new(&mut back);
    let mut source = InBuffer::new(stream);
    assert_eq!(inflate.inflate(&mut output, &mut source, Flush::Finish), Ok(Status::StreamEnd));
    let written = output.pos;
    assert_eq!(source.pos, size, "level {level}: bytes after the stream");
    assert!(&back[..written] == input, "level {level}: inflates to other bytes");

    // Again, with the same compressor and a new one.
    let mut again = vec![0u8; out.len()];
    assert_eq!(compressor.deflate_compress(input, &mut again), size);
    assert!(again[..size] == *stream);
    let Some(mut fresh) = Compressor::new(level) else { panic!("level {level}") };
    assert_eq!(fresh.deflate_compress(input, &mut again), size);
    assert!(again[..size] == *stream);

    // One byte short, and a size between none and the stream's.
    let mut short = vec![0u8; size - 1];
    assert_eq!(compressor.deflate_compress(input, &mut short), 0, "level {level}");
    let mut some = vec![0u8; usize::from(room) * size / 255];
    match compressor.deflate_compress(input, &mut some) {
        0 => {}
        n => assert!(n == size && some[..n] == *stream, "level {level}"),
    }

    // As a part: the stream, its BFINAL cleared, and a sync marker.
    let mut part = vec![0u8; compressor.deflate_compress_part_bound(input.len())];
    let part_size = compressor.deflate_compress_part(input, &mut part);
    assert!(part_size > 0, "level {level}: the part's bound is too small");
    let part = &part[..part_size];
    assert!(part.ends_with(&[0, 0, 0xFF, 0xFF]), "level {level}");
    if input.is_empty() {
        assert_eq!(part, [0, 0, 0, 0xFF, 0xFF]);
    } else {
        assert!(part_size - size == 4 || part_size - size == 5, "level {level}");
        let differ: Vec<u8> =
            stream.iter().zip(part).map(|(a, b)| a ^ b).filter(|&x| x != 0).collect();
        assert!(differ.len() == 1 && differ[0].is_power_of_two(), "level {level}: {differ:?}");
    }
    let mut joined = part.to_vec();
    joined.extend_from_slice(part);
    joined.extend_from_slice(stream);
    let mut inflate = Inflate::new(-15).expect("raw inflate");
    let mut back = vec![0u8; 3 * input.len() + 1];
    let mut output = OutBuffer::new(&mut back);
    let mut source = InBuffer::new(&joined);
    assert_eq!(inflate.inflate(&mut output, &mut source, Flush::Finish), Ok(Status::StreamEnd));
    let written = output.pos;
    assert_eq!(source.pos, joined.len(), "level {level}: bytes after the parts");
    assert_eq!(written, 3 * input.len(), "level {level}");
    for third in back[..written].chunks(input.len().max(1)) {
        assert!(third == input, "level {level}: the parts inflate to other bytes");
    }
});
