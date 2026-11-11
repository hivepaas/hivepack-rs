//! hivepack::lzo on any input: the rest of the input, after four bytes
//! that pick two output sizes, decoded as an LZO1X block into outputs of
//! both sizes, and of the smaller twice, filled differently. There is no
//! LZO compressor in Rust to compare with here, and liblzo2 is not linked
//! (`crates/hivepack/tests/lzo_oracle.rs` compares the port with it);
//! what is checked is that the decoder never panics, and that the outputs
//! agree: the same result with the same size, a block that fits in the
//! larger output fitting in the smaller one if it is large enough and
//! failing with `OutputOverrun` if not, the same bytes written, and
//! nothing written past what was decoded.

#![no_main]

use hivepack::lzo::{Error, decompress};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Up to 256 KiB, past SquashFS's default block, and up to 16 KiB more.
    let small = (usize::from(data[0]) | usize::from(data[1]) << 8 | usize::from(data[2]) << 16)
        % (256 << 10);
    let large = small + usize::from(data[3]) * 64;
    let input = &data[4..];

    let mut a = vec![0x55; small];
    let mut b = vec![0xaa; small];
    let mut c = vec![0x55; large];
    let ra = decompress(input, &mut a);
    let rb = decompress(input, &mut b);
    let rc = decompress(input, &mut c);
    assert_eq!(ra, rb);

    // The bytes written into the smaller output: where the two fills
    // agree, from the start, and nothing past them.
    let written = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    assert!(a[written..].iter().all(|&x| x == 0x55));
    assert!(b[written..].iter().all(|&x| x == 0xaa));
    // The larger output starts with the same bytes.
    assert_eq!(a[..written], c[..written]);

    match (ra, rc) {
        (Ok(n), _) => {
            assert_eq!(rc, Ok(n));
            assert_eq!(written, n);
            assert!(c[n..].iter().all(|&x| x == 0x55));
        }
        // With more room, the larger output decodes further, to the same
        // end or past the smaller one's size.
        (Err(Error::OutputOverrun), Ok(n)) => assert!(n > small),
        (Err(Error::OutputOverrun), Err(_)) => {}
        // Any other error comes where the output still had room: the
        // larger output stops there too.
        (Err(e), _) => assert_eq!(rc, Err(e)),
    }
    if let Ok(n) = rc {
        assert!(c[n..].iter().all(|&x| x == 0x55));
    }
});
