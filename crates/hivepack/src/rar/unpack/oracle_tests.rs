// hivepack::rar: a port of UnRAR 7.3.2 to Rust. UnRAR's license says:
//
// UnRAR source code may be used in any software to handle RAR archives
// without limitations free of charge, but cannot be used to develop RAR
// (WinRAR) compatible archiver and to re-create RAR compression algorithm,
// which is proprietary. Distribution of modified UnRAR source code in
// separate form or as a part of other software is permitted, provided that
// full text of this paragraph, starting from "UnRAR source code" words, is
// included in license, or in documentation if license is not available, and
// in source code comments of resulting package.

//! The filters compared directly with UnRAR's. No archive at hand has RAR 3's
//! Itanium, RGB or audio filters, whose code nothing can make up, and damage
//! only rarely gets a filter over data worth filtering: the `filter3` and
//! `filter5` requests give the same bytes to `RarVM::Execute` and
//! `Unpack::ApplyFilter`. These are inside the crate, as the filters are.

// The oracle runs on Linux, and the rest only replays what is recorded.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[path = "../../../tests/rar_support/mod.rs"]
pub(crate) mod support;

use std::fmt::Write as _;

use crate::rar::error::Error;

use support::{Oracle, Rng, fnv64, hex, unhex};

use super::Filter;
use super::UnpIo;
use super::Unpack;
use super::filters::{Program, RarVm, StandardFilter, VM_MEMSIZE};

fn standard_filter(kind: u32) -> StandardFilter {
    match kind {
        1 => StandardFilter::E8,
        2 => StandardFilter::E8E9,
        3 => StandardFilter::Itanium,
        4 => StandardFilter::Rgb,
        5 => StandardFilter::Audio,
        _ => StandardFilter::Delta,
    }
}

/// The port's answer to a `filter3` or `filter5` request, in the oracle's words.
fn answer(request: &str) -> String {
    let words: Vec<&str> = request.split(' ').collect();
    let number = |i: usize| -> u32 { words[i].parse().expect("a number") };
    let mut out = words[0].to_string();
    if words[0] == "filter3" {
        let mut vm = RarVm::new();
        let data = unhex(words[6]);
        vm.set_memory(0, &data);
        let mut prg = Program::new();
        prg.kind = standard_filter(number(1));
        prg.init_r[0] = number(2);
        prg.init_r[1] = number(3);
        prg.init_r[4] = number(4);
        prg.init_r[6] = number(5);
        vm.execute(&mut prg);
        let from = prg.filtered_data.expect("a filter");
        let _ = write!(
            out,
            " size={:x} at={from:x} fnv={:x} mem={:x}",
            prg.filtered_data_size,
            fnv64(vm.memory(from, prg.filtered_data_size as usize)),
            fnv64(vm.memory(0, VM_MEMSIZE + 4)),
        );
    } else {
        assert_eq!(words[0], "filter5", "{request:.80}");
        let mut data = unhex(words[4]);
        let mut unpack = Unpack::new();
        unpack.written_file_size = i64::from(number(3));
        let filter = Filter {
            kind: number(1) as u8,
            channels: number(2) as u8,
            next_window: false,
            block_start: 0,
            block_length: data.len() as u32,
        };
        let done = unpack.apply_filter_for_test(&mut data, &filter);
        match done {
            None => out += " none",
            Some(output) => {
                let _ = write!(out, " fnv={:x}", fnv64(output));
            }
        }
    }
    out
}

/// Bytes a filter has something to do with: the filter's own marks, small
/// addresses and repeats, or anything.
fn input(rng: &mut Rng, size: usize) -> Vec<u8> {
    let style = rng.below(4);
    let mut data = vec![0u8; size];
    let mut last = 0u8;
    let mut bundle_at = 0;
    for byte in &mut data {
        *byte = match style {
            0 => rng.next() as u8,
            1 => match rng.below(6) {
                0 => 0xe8,
                1 => 0xe9,
                2 => 0xeb,
                3 => 0xff,
                _ => rng.below(8) as u8,
            },
            // Itanium's bundles: a template, and the rest mostly set, which
            // says a branch often enough in each of its three slots.
            2 => {
                bundle_at = (bundle_at + 1) % 16;
                if bundle_at == 1 {
                    0x10 + rng.below(16) as u8
                } else if rng.below(4) == 0 {
                    rng.next() as u8
                } else {
                    0x55 << rng.below(2)
                }
            }
            // Smooth, as sound and pictures are.
            _ => {
                last = last.wrapping_add(rng.below(9) as u8).wrapping_sub(4);
                last
            }
        };
    }
    data
}

fn sizes(rng: &mut Rng) -> usize {
    *[
        0, 1, 3, 4, 5, 8, 16, 20, 21, 22, 37, 64, 256, 1000, 4096, 70_000,
    ]
    .get(rng.below(16) as usize)
    .unwrap_or(&64)
}

fn requests(count: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng(seed);
    let mut requests = Vec::new();
    for _ in 0..count {
        let size = sizes(&mut rng);
        let data = input(&mut rng, size);
        let kind = 1 + rng.below(6);
        // Audio's weights take long to go as far as they can.
        let (size, data) = if kind == 5 && rng.below(8) == 0 {
            let size = 0x1_0000 + rng.below(0x1_0000) as usize;
            let style = rng.below(4);
            let level = rng.below(64) as u8 + 1;
            let mut sound = vec![0u8; size];
            let mut last = 0u8;
            for (i, byte) in sound.iter_mut().enumerate() {
                *byte = match style {
                    0 => {
                        last = last.wrapping_add(rng.below(5) as u8).wrapping_sub(2);
                        last
                    }
                    1 => level,
                    2 if i % 2 == 0 => level,
                    2 => level.wrapping_neg(),
                    _ => ((i / 16) as u8).wrapping_mul(level),
                };
            }
            (size, sound)
        } else {
            (size, data)
        };
        let r0 = match rng.below(5) {
            0 => rng.below(4),
            1 => 1 + rng.below(8),
            2 => 3 + rng.below(1 + size as u64),
            3 => 1024 + rng.below(4),
            _ => rng.below(300),
        };
        let r1 = rng.below(4);
        // What was given, usually.
        let r4 = match rng.below(8) {
            0 => rng.below(0x8_0000),
            1 => size as u64 + rng.below(64),
            _ => size as u64,
        };
        let r6 = match rng.below(3) {
            0 => rng.below(1 << 16),
            1 => rng.below(1 << 32),
            _ => (1 << 24) - rng.below(1 << 12),
        };
        requests.push(format!(
            "filter3 {kind} {r0} {r1} {r4} {r6} {}",
            if data.is_empty() {
                "-".to_string()
            } else {
                hex(&data)
            }
        ));

        // UnRAR only applies a filter to something.
        let size = sizes(&mut rng).max(1);
        let data = input(&mut rng, size);
        let kind = rng.below(8);
        let channels = 1 + rng.below(32);
        let written = match rng.below(3) {
            0 => rng.below(1 << 16),
            1 => rng.below(1 << 31),
            _ => (1 << 24) - rng.below(1 << 12),
        };
        requests.push(format!(
            "filter5 {kind} {channels} {written} {}",
            hex(&data)
        ));
    }
    requests
}

/// Input in the pieces the oracle gives it in, each one ready before it is
/// asked for, as the oracle's `feed` does.
struct Pieces<'a> {
    data: &'a [u8],
    ready: usize,
    at: usize,
}

impl Pieces<'_> {
    fn feed(&mut self) {
        if self.ready == 0 && self.at < self.data.len() {
            self.ready = (self.data.len() - self.at).min(0x4000);
            self.at += self.ready;
        }
    }
}

impl UnpIo for Pieces<'_> {
    fn unp_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Error> {
        let size = self.ready;
        buf[..size].copy_from_slice(&self.data[self.at - size..self.at]);
        self.ready = 0;
        Ok(Some(size))
    }

    fn unp_write(&mut self, _data: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// The port's answer to a `ppm` request.
fn answer_ppm(count: u64, heap: u32, data: &[u8]) -> String {
    let mut io = Pieces {
        data,
        ready: 0,
        at: 0,
    };
    let mut unpack = Unpack::new();
    io.feed();
    unpack.unp_read_buf30(&mut io).expect("no errors from here");
    io.feed();
    let mut model = unpack.ppm.take().expect("a model");
    if !model.decode_init(&mut unpack, &mut io).expect("memory") {
        return "ppm noinit".to_string();
    }
    model.set_heap_for_test(heap);
    model.start_again_for_test().expect("memory");
    let (mut done, mut h, mut restarts) = (0u64, 0xcbf2_9ce4_8422_2325u64, 0u64);
    while done < count {
        io.feed();
        let ch = model.decode_char(&mut unpack, &mut io).expect("memory");
        if ch == -1 {
            if io.at >= data.len() {
                break;
            }
            io.feed();
            model.init_decoder(&mut unpack, &mut io).expect("no errors");
            model.start_again_for_test().expect("memory");
            restarts += 1;
            continue;
        }
        h = (h ^ u64::from(ch as u8)).wrapping_mul(0x0100_0000_01b3);
        done += 1;
    }
    format!("ppm symbols={done:x} restarts={restarts:x} fnv={h:x}")
}

/// Bytes for the range coder: random ones take a wide path through the model
/// and zeros what it finds most likely, which makes long contexts.
fn ppm_input(rng: &mut Rng, size: usize) -> Vec<u8> {
    let order = rng.below(32) as u8;
    let memory = rng.below(3) as u8;
    // A block that resets: order and flags, then the memory in MB less one.
    let mut input = vec![0x80 | 0x20 | order, memory];
    let style = rng.below(3);
    while input.len() < size {
        let run = match style {
            0 => size,
            1 => 64 + rng.below(1024) as usize,
            _ => 1024 + rng.below(16384) as usize,
        };
        if style != 0 && rng.below(2) == 0 {
            input.resize(input.len() + run, 0);
        } else {
            for _ in 0..run {
                input.push(rng.next() as u8);
            }
        }
    }
    input.truncate(size);
    input
}

// The model filling its memory, gluing free blocks and starting again.
#[cfg(target_os = "linux")]
#[test]
fn ppm_model_is_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let count = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse::<usize>().ok())
        .map_or(12, |n| n.max(1));
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0008);
    let mut rng = Rng(seed);
    let heaps = [4096, 4800, 6000, 8192, 12288, 16384, 32768, 65536, 131072];
    let symbols = 400_000;
    for i in 0..count {
        let heap: u32 = rng.pick(&heaps);
        let size = 1024 + rng.below(1 << 17) as usize;
        let input = ppm_input(&mut rng, size);
        let want = oracle.ask(&format!("ppm {symbols} {heap} {}", hex(&input)));
        assert_eq!(
            answer_ppm(symbols, heap, &input),
            want,
            "stream {i} of {seed:x}"
        );
    }
    // PPMd as it really is, as far as the model lasts.
    for stream in real_ppm_streams() {
        for heap in heaps {
            let want = oracle.ask(&format!("ppm {symbols} {heap} {}", hex(&stream)));
            assert_eq!(answer_ppm(symbols, heap, &stream), want, "heap {heap}");
        }
    }
}

/// The packed data of the entries of libarchive's RAR 4 archives that start
/// with a PPMd block.
fn real_ppm_streams() -> Vec<Vec<u8>> {
    let mut streams: Vec<Vec<u8>> = Vec::new();
    for (_, data) in support::libarchive_archives() {
        if !data.starts_with(b"Rar!\x1a\x07\x00") {
            continue;
        }
        let mut at = 7;
        while at + 11 <= data.len() {
            let kind = data[at + 2];
            let flags = u16::from_le_bytes([data[at + 3], data[at + 4]]);
            let size = usize::from(u16::from_le_bytes([data[at + 5], data[at + 6]]));
            if size < 7 {
                break;
            }
            let add = if flags & 0x8000 != 0 {
                u32::from_le_bytes([data[at + 7], data[at + 8], data[at + 9], data[at + 10]])
                    as usize
            } else {
                0
            };
            if kind == 0x74 && flags & 7 == 0 && at + size + add <= data.len() && add > 4 {
                let packed = &data[at + size..at + size + add];
                let ppmd = packed[0] & 0xa0 == 0xa0 && data.get(at + 24) == Some(&29);
                if ppmd
                    && packed.len() > 1000
                    && !streams.iter().any(|s| s[..1000] == packed[..1000])
                {
                    streams.push(packed.to_vec());
                }
            }
            at += size + add;
        }
    }
    streams
}

#[cfg(target_os = "linux")]
#[test]
fn filters_are_unrars() {
    let Some(mut oracle) = Oracle::spawn() else {
        return;
    };
    let count = std::env::var("HIVEPACK_RAR_DAMAGED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(1500);
    let seed = std::env::var("HIVEPACK_RAR_SEED")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0x4152_0006);
    for request in requests(count, seed) {
        let want = oracle.ask(&request);
        assert_eq!(answer(&request), want, "{request:.300}");
    }
}

fn recorded_path() -> std::path::PathBuf {
    support::repository().join("testdata/oracle/rar-filters.txt")
}

/// Small enough to keep: what has no large input.
fn recorded_requests() -> Vec<String> {
    requests(400, 0x4152_0007)
        .into_iter()
        .filter(|request| request.len() < 3000)
        .collect()
}

// Where neither the oracle nor anything it needs is.
#[test]
fn filters_as_recorded() {
    let text = std::fs::read_to_string(recorded_path()).expect("testdata/oracle/rar-filters.txt");
    let mut checked = 0;
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (request, want) = line.split_once('\t').expect("request, tab, answer");
        assert_eq!(answer(request), want, "{request:.300}");
        checked += 1;
    }
    assert!(checked > 100, "only {checked} recorded answers");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "rewrites testdata/oracle/rar-filters.txt from the oracle"]
fn record_filter_answers() {
    let mut oracle = Oracle::spawn().expect("the oracle is built");
    let mut text = String::from(
        "# Answers from UnRAR 7.3.2 (tools/rar-oracle), replayed by crates/rar/src/unpack/oracle_tests.rs.\n\
         # Regenerate with: cargo test -p hivepack --all-features --lib record_filter_answers -- --ignored\n",
    );
    for request in recorded_requests() {
        let reply = oracle.ask(&request);
        let _ = writeln!(text, "{request}\t{reply}");
    }
    std::fs::write(recorded_path(), text).expect("written");
}
