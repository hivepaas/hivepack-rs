//! LZ4 frames of independent blocks compressed in threads
//! (`lz4::EncoderMt`): the frame the port's `compress_frame` makes with the
//! same preferences, byte for byte, whatever the threads and however the
//! input is written; read back by liblz4.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "lz4_support/mod.rs"]
mod support;

use std::io::{Read, Write};

use hivepack::Threads;
use hivepack::lz4::frame::{
    BlockMode, BlockSizeId, FrameInfo, Preferences, compress_frame, compress_frame_bound,
};
use hivepack::lz4::{EncoderMt, MtOptions};
use support::{Rng, input};

/// What `compress_frame` makes of `data` with `options`' preferences.
fn one_frame(data: &[u8], options: &MtOptions) -> Vec<u8> {
    let prefs = Preferences {
        frame_info: FrameInfo {
            block_size_id: options.block_size,
            block_mode: BlockMode::Independent,
            content_checksum: options.content_checksum,
            block_checksum: options.block_checksum,
            ..FrameInfo::default()
        },
        compression_level: options.level,
        ..Preferences::default()
    };
    let mut out = vec![0; compress_frame_bound(data.len(), Some(&prefs))];
    let n = compress_frame(&mut out, data, Some(&prefs)).unwrap();
    out.truncate(n);
    out
}

/// `data` through an `EncoderMt` with `options`, written in pieces of sizes
/// from `rng`, or whole without one.
fn in_threads(data: &[u8], options: &MtOptions, rng: Option<&mut Rng>) -> Vec<u8> {
    let mut encoder = EncoderMt::new(Vec::new(), options).unwrap();
    match rng {
        None => encoder.write_all(data).unwrap(),
        Some(rng) => {
            let mut rest = data;
            while !rest.is_empty() {
                let n = (1 + rng.below(200_000) as usize).min(rest.len());
                encoder.write_all(&rest[..n]).unwrap();
                rest = &rest[n..];
            }
        }
    }
    assert_eq!(encoder.total_in(), data.len() as u64);
    encoder.finish().unwrap()
}

#[test]
fn the_frame_compress_frame_makes_whatever_the_threads() {
    let mut rng = Rng(0x1d4_0001);
    let block = 64 << 10;
    let sizes = [
        0,
        1,
        1000,
        block - 1,
        block,
        block + 1,
        7 * block / 2,
        9 * block,
    ];
    for level in [-3, 0, 1, 3, 9, 12] {
        for (content_checksum, block_checksum) in [(true, false), (false, true), (false, false)] {
            for &size in &sizes {
                let data = input(&mut rng, size);
                let base = MtOptions {
                    level,
                    block_size: BlockSizeId::Max64Kb,
                    content_checksum,
                    block_checksum,
                    ..MtOptions::default()
                };
                let want = one_frame(&data, &base);
                for threads in [Threads::One, Threads::of(2), Threads::of(8)] {
                    let options = MtOptions { threads, ..base };
                    let what = format!(
                        "level {level}, {size} bytes, {threads:?}, checksums {content_checksum} {block_checksum}"
                    );
                    assert!(in_threads(&data, &options, None) == want, "{what}");
                    assert!(
                        in_threads(&data, &options, Some(&mut rng)) == want,
                        "{what}, in pieces"
                    );
                }
            }
        }
    }
}

#[test]
fn blocks_of_4_mb_as_lz4_writes_read_back_by_liblz4() {
    let mut rng = Rng(0x1d4_0002);
    let data = input(&mut rng, (10 << 20) + 12_345);
    let options = MtOptions {
        threads: Threads::of(4),
        ..MtOptions::default()
    };
    let made = in_threads(&data, &options, None);
    assert!(made == one_frame(&data, &options));
    let mut back = Vec::new();
    lz4::Decoder::new(&made[..])
        .unwrap()
        .read_to_end(&mut back)
        .unwrap();
    assert!(back == data, "liblz4");
    let mut back = Vec::new();
    hivepack::lz4::Decoder::new(&made[..])
        .read_to_end(&mut back)
        .unwrap();
    assert!(back == data, "the port");
}

#[test]
fn a_memory_limit_lowers_the_threads_not_the_frame() {
    let options = MtOptions {
        threads: Threads::of(8),
        ..MtOptions::default()
    };
    let one = options.memory_usage(1);
    let per_thread = options.memory_usage(2) - one;
    assert_eq!(options.threads_used(), 8);
    let limited = MtOptions {
        memory_limit: one + 2 * per_thread,
        ..options
    };
    assert_eq!(limited.threads_used(), 3);
    let none = MtOptions {
        memory_limit: 1,
        ..options
    };
    assert_eq!(none.threads_used(), 1, "one always allowed");
    let mut rng = Rng(0x1d4_0003);
    let data = input(&mut rng, 9 << 20);
    assert!(in_threads(&data, &limited, None) == in_threads(&data, &options, None));
}

#[test]
fn the_default_block_size_is_refused() {
    let options = MtOptions {
        block_size: BlockSizeId::Default,
        ..MtOptions::default()
    };
    assert!(EncoderMt::new(Vec::new(), &options).is_err());
}
