//! Decompression contexts used for several calls in a row, with parameters
//! and dictionaries, against libzstd 1.5.7 doing the same.
//!
//! The state carried between calls matters: the dictionary loaded or
//! referenced, how long it is used, and whether libzstd thinks it is still
//! in the processor's cache, which picks the sequence loop and so which
//! error a damaged frame reports. Frames come from libzstd's compressor with
//! random parameters and dictionaries, some damaged, cut short, with
//! skippable frames between them or garbage after.
//!
//! Only on 64-bit little-endian machines, where libzstd behaves as the port
//! does everywhere: elsewhere it checks damaged input with other loops, and
//! hashes dictionary IDs in another byte order.

#![cfg(all(target_pointer_width = "64", target_endian = "little"))]
#![allow(clippy::expect_used, clippy::panic)]

#[path = "zstd_support/mod.rs"]
mod support;

use std::sync::Arc;

use support::{Pieces, Rng, skippable_frame, stream_both};
use zstd::zstd_safe::{self, CParameter, DParameter, FrameFormat, ResetDirective};

/// Dictionary IDs that XXH64 puts in slot 50 or 51 of libzstd's DDict hash
/// set, next to ID 0's slot 52: a search for one of them can end at a
/// raw-content DDict, which libzstd takes for an empty slot and returns.
/// The last three move to slots 114 and 115 when the set grows to 128.
const IDS_NEAR_ZERO: [u32; 6] = [0x1002b, 0x1003d, 0x10074, 0x10009, 0x1000d, 0x10065];

/// IDs in slots 11 to 17: enough to make the set grow to 128 slots, with
/// searches running into each other.
///
/// Every trained dictionary gets an ID from these two lists. The DDicts in
/// the set then sit in slots 11 to 34, 50 to 56 and 114 to 116 at most, so
/// that no search reaches the last slot, from where libzstd 1.5.7 steps
/// past the end of the table.
const IDS_CLUSTERED: [u32; 24] = [
    0x10015, 0x1001b, 0x10025, 0x1002d, 0x10056, 0x10058, 0x10061, 0x10064, 0x10066, 0x10075,
    0x1008d, 0x10095, 0x1009c, 0x100a0, 0x100d3, 0x100da, 0x100dc, 0x100e5, 0x1010f, 0x10123,
    0x10126, 0x1013d, 0x10155, 0x10161,
];

/// `dict`, a zstd dictionary, with its ID changed to `id`.
fn with_dict_id(dict: &[u8], id: u32) -> Vec<u8> {
    let mut dict = dict.to_vec();
    dict[4..8].copy_from_slice(&id.to_le_bytes());
    dict
}

/// The dictionaries one test case can use.
struct Dicts {
    /// The dictionary bytes: a trained zstd dictionary or raw content.
    raw: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug)]
enum Call {
    /// `ZSTD_decompressDCtx`, with whatever the context holds.
    Plain,
    /// `ZSTD_decompressStream`, with whatever the context holds.
    Stream,
    /// `ZSTD_decompress_usingDict`
    UsingDict(usize),
    /// `ZSTD_decompress_usingDDict`
    UsingDDict(usize),
    /// `ZSTD_DCtx_loadDictionary`, then `ZSTD_decompressDCtx`.
    Load(usize),
    /// `ZSTD_DCtx_refPrefix`, then `ZSTD_decompressDCtx`.
    Prefix(usize),
    /// `ZSTD_DCtx_refDDict`, then `ZSTD_decompressDCtx`.
    RefDDict(usize),
}

fn outcome_libzstd(result: Result<usize, usize>, out: &mut Vec<u8>) -> String {
    match result {
        Ok(size) => {
            out.truncate(size);
            format!("ok {size} {:016x}", hivepack_hash(out))
        }
        Err(code) => format!("err {}", zstd_safe::get_error_name(code)),
    }
}

fn outcome_port(result: hivepack::zstd::Result<usize>, out: &[u8]) -> String {
    match result {
        Ok(size) => format!("ok {size} {:016x}", hivepack_hash(&out[..size])),
        Err(error) => format!("err {}", error.code().message()),
    }
}

/// Streams `src` on both contexts in random pieces (see
/// [`stream_both`]), then leaves both where the next call can start: after
/// an error the `zstd` crate refuses to go on until the context is reset,
/// and a frame cut short leaves the stream inside it, where the dictionary
/// cannot change. Returns how the stream ended.
fn stream(
    c: &mut zstd_safe::DCtx<'_>,
    p: &mut hivepack::zstd::DCtx,
    src: &[u8],
    capacity: usize,
    rng: &mut Rng,
) -> Result<String, String> {
    let pieces = match rng.range(0, 3) {
        0 => Pieces::Whole,
        1 => Pieces::Stable(rng.next()),
        _ => Pieces::Random(rng.next()),
    };
    let outcome =
        stream_both(c, p, src, capacity, pieces).map_err(|e| format!("{pieces:?}: {e}"))?;
    if !outcome.starts_with("ok") {
        c.reset(ResetDirective::SessionOnly)
            .expect("libzstd resets");
        p.reset(hivepack::zstd::ResetDirective::SessionOnly)
            .expect("port resets");
    }
    Ok(outcome)
}

/// FNV-1a, to compare outputs briefly.
fn hivepack_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[test]
fn contexts_used_many_times_behave_as_libzstd() {
    let mut rng = Rng(0x5EED_0010);
    let mut cases = 0;
    let mut calls = 0;
    for case in 0..400 {
        // Dictionaries: trained from samples, raw content, or none. Some
        // cases reference many, which makes libzstd's DDict set grow.
        let many = rng.chance(6);
        let base = rng.data_between(2000, 20_000, &[]);
        let mut ids = IDS_NEAR_ZERO.to_vec();
        ids.extend_from_slice(&IDS_CLUSTERED);
        rng.shuffle(&mut ids);
        let mut dicts = Dicts { raw: Vec::new() };
        if many {
            let trained = rng.trained_dict(&base).expect("trains a dictionary");
            for _ in 0..rng.range(17, 26) {
                dicts
                    .raw
                    .push(with_dict_id(&trained, ids.pop().expect("an ID")));
            }
            if rng.chance(2) {
                dicts.raw.push(rng.raw_dict(&base));
            }
            rng.shuffle(&mut dicts.raw);
        } else {
            for _ in 0..rng.range(0, 3) {
                let trained = if rng.chance(2) {
                    rng.trained_dict(&base)
                } else {
                    None
                };
                dicts.raw.push(match trained {
                    Some(trained) => with_dict_id(&trained, ids.pop().expect("an ID")),
                    None => rng.raw_dict(&base),
                });
            }
        }

        // Frames, all with one dictionary (or none).
        let magicless = rng.chance(8);
        let frame_dict = if dicts.raw.is_empty() {
            None
        } else {
            Some(rng.range(0, dicts.raw.len() as u64 - 1) as usize)
        };
        let mut src = Vec::new();
        let mut total = 0usize;
        for _ in 0..rng.range(1, 4) {
            let data = rng.data_between(0, 300_000, &base);
            let mut cctx = zstd_safe::CCtx::create();
            let level = [-3, 1, 3, 6, 12, 19][rng.range(0, 5) as usize];
            let set = |cctx: &mut zstd_safe::CCtx<'_>, param| {
                cctx.set_parameter(param).expect("parameter")
            };
            set(&mut cctx, CParameter::CompressionLevel(level));
            set(&mut cctx, CParameter::ChecksumFlag(rng.chance(2)));
            set(&mut cctx, CParameter::ContentSizeFlag(!rng.chance(4)));
            set(&mut cctx, CParameter::DictIdFlag(!rng.chance(4)));
            if rng.chance(3) {
                set(&mut cctx, CParameter::WindowLog(rng.range(10, 24) as u32));
            }
            if magicless {
                set(&mut cctx, CParameter::Format(FrameFormat::Magicless));
            }
            if let Some(d) = frame_dict {
                cctx.load_dictionary(&dicts.raw[d])
                    .expect("dictionary loads");
            }
            let mut frame = Vec::with_capacity(zstd_safe::compress_bound(data.len()));
            cctx.compress2(&mut frame, &data).expect("compresses");
            if !magicless && rng.chance(5) {
                src.extend_from_slice(&skippable_frame(
                    rng.range(0, 15) as u32,
                    &rng.data_between(0, 100, &[]),
                ));
            }
            src.extend_from_slice(&frame);
            total += data.len();
        }
        match rng.range(0, 9) {
            0 => {
                let at = rng.range(0, src.len() as u64 - 1) as usize;
                src[at] ^= 1 << rng.range(0, 7);
            }
            1 => src.truncate(rng.range(0, src.len() as u64 - 1) as usize),
            2 => src.extend_from_slice(&rng.data_between(1, 20, &[])),
            _ => {}
        }
        let capacity = match rng.range(0, 3) {
            0 => total.saturating_sub(rng.range(1, 10) as usize),
            1 => total + rng.range(0, 300_000) as usize,
            _ => total,
        };

        let c_ddicts: Vec<zstd_safe::DDict<'static>> = dicts
            .raw
            .iter()
            .map(|d| zstd_safe::DDict::create(d))
            .collect();
        let p_ddicts: Vec<Option<Arc<hivepack::zstd::DDict>>> = dicts
            .raw
            .iter()
            .map(|d| hivepack::zstd::DDict::new(d).ok().map(Arc::new))
            .collect();

        // The same contexts on both sides.
        let mut c = zstd_safe::DCtx::create();
        let mut p = hivepack::zstd::DCtx::new();
        if magicless {
            c.set_parameter(DParameter::Format(FrameFormat::Magicless))
                .expect("format");
            p.set_parameter(hivepack::zstd::DParameter::Format(
                hivepack::zstd::Format::Zstd1Magicless,
            ))
            .expect("format");
        }
        let ignore_checksum = rng.chance(6);
        c.set_parameter(DParameter::ForceIgnoreChecksum(ignore_checksum))
            .expect("checksum");
        p.set_parameter(hivepack::zstd::DParameter::ForceIgnoreChecksum(
            ignore_checksum,
        ))
        .expect("checksum");
        let multiple = many || rng.chance(4);
        c.set_parameter(DParameter::RefMultipleDDicts(multiple))
            .expect("multiple");
        p.set_parameter(hivepack::zstd::DParameter::RefMultipleDDicts(multiple))
            .expect("multiple");
        // Whether libzstd's DDict set holds anything.
        let mut set_used = false;
        if many {
            let mut order: Vec<usize> = (0..dicts.raw.len()).collect();
            rng.shuffle(&mut order);
            for d in order {
                c.ref_ddict(&c_ddicts[d]).expect("libzstd references");
                p.ref_ddict(p_ddicts[d].clone()).expect("port references");
            }
            set_used = true;
        }

        // Whether the zstd crate's context streamed since its last reset: its
        // one-call functions then reset the session after they run.
        let mut streamed = false;
        for step in 0..rng.range(1, 6) {
            let pick = |rng: &mut Rng| rng.range(0, dicts.raw.len().max(1) as u64 - 1) as usize;
            // Load, Prefix and RefDDict decode by streaming as often.
            let streaming = rng.chance(2);
            let call = if dicts.raw.is_empty() {
                if streaming { Call::Stream } else { Call::Plain }
            } else {
                match rng.range(0, 5) {
                    0 if streaming => Call::Stream,
                    0 => Call::Plain,
                    1 => Call::UsingDict(pick(&mut rng)),
                    2 => Call::UsingDDict(pick(&mut rng)),
                    // libzstd 1.5.7 frees a loaded dictionary or prefix while
                    // still decoding with it when a frame names one in the
                    // set (see select_frame_ddict), so neither is used once
                    // the set holds something: there is nothing to compare.
                    3 | 4 if set_used => Call::RefDDict(pick(&mut rng)),
                    3 => Call::Load(pick(&mut rng)),
                    4 => Call::Prefix(pick(&mut rng)),
                    _ => Call::RefDDict(pick(&mut rng)),
                }
            };
            if let Call::RefDDict(_) = call {
                set_used |= multiple;
            }
            let mut c_out = Vec::with_capacity(capacity);
            let mut p_out = vec![0u8; capacity];
            let mut decode = |c: &mut zstd_safe::DCtx<'_>,
                              p: &mut hivepack::zstd::DCtx,
                              rng: &mut Rng,
                              c_out: &mut Vec<u8>,
                              p_out: &mut Vec<u8>| {
                if streaming {
                    streamed = true;
                    let outcome = stream(c, p, &src, capacity, rng).unwrap_or_else(|problem| {
                        panic!("case {case}, call {step}: {call:?}: {problem}")
                    });
                    (outcome.clone(), outcome)
                } else {
                    (
                        outcome_libzstd(c.decompress(c_out, &src), c_out),
                        outcome_port(p.decompress(p_out, &src), p_out),
                    )
                }
            };
            let (want, got) = match call {
                Call::Stream => decode(&mut c, &mut p, &mut rng, &mut c_out, &mut p_out),
                Call::Plain => (
                    outcome_libzstd(c.decompress(&mut c_out, &src), &mut c_out),
                    outcome_port(p.decompress(&mut p_out, &src), &p_out),
                ),
                Call::UsingDict(d) => (
                    outcome_libzstd(
                        c.decompress_using_dict(&mut c_out, &src, &dicts.raw[d]),
                        &mut c_out,
                    ),
                    outcome_port(
                        p.decompress_using_dict(&mut p_out, &src, &dicts.raw[d]),
                        &p_out,
                    ),
                ),
                Call::UsingDDict(d) => (
                    outcome_libzstd(
                        c.decompress_using_ddict(&mut c_out, &src, &c_ddicts[d]),
                        &mut c_out,
                    ),
                    match &p_ddicts[d] {
                        Some(ddict) => {
                            outcome_port(p.decompress_using_ddict(&mut p_out, &src, ddict), &p_out)
                        }
                        // A DDict libzstd could not create is NULL: no
                        // dictionary.
                        None => outcome_port(p.decompress(&mut p_out, &src), &p_out),
                    },
                ),
                Call::Load(d) => {
                    c.load_dictionary(&dicts.raw[d]).expect("libzstd loads");
                    p.load_dictionary(&dicts.raw[d]).expect("port loads");
                    decode(&mut c, &mut p, &mut rng, &mut c_out, &mut p_out)
                }
                Call::Prefix(d) => {
                    c.ref_prefix(&dicts.raw[d]).expect("libzstd prefix");
                    p.ref_prefix(&dicts.raw[d]).expect("port prefix");
                    decode(&mut c, &mut p, &mut rng, &mut c_out, &mut p_out)
                }
                Call::RefDDict(d) => {
                    c.ref_ddict(&c_ddicts[d]).expect("libzstd references");
                    p.ref_ddict(p_ddicts[d].clone()).expect("port references");
                    decode(&mut c, &mut p, &mut rng, &mut c_out, &mut p_out)
                }
            };
            let streams = match call {
                Call::Stream => true,
                Call::Load(_) | Call::Prefix(_) | Call::RefDDict(_) => streaming,
                _ => false,
            };
            if !streams && streamed {
                // As the zstd crate does after a one-call decompression.
                p.reset(hivepack::zstd::ResetDirective::SessionOnly)
                    .expect("port resets");
                streamed = false;
            }
            assert_eq!(
                got, want,
                "case {case}, call {step}: {call:?} (magicless {magicless}, multiple {multiple}, \
                 many {many})"
            );
            calls += 1;
        }
        cases += 1;
    }
    eprintln!("{cases} cases, {calls} calls");
}

#[test]
fn frames_find_their_dictionary_in_the_set_as_in_libzstd() {
    let mut rng = Rng(0x5EED_0020);
    let base = rng.data_between(20_000, 20_000, &[]);
    let trained = rng.trained_dict(&base).expect("trains a dictionary");
    let raw = rng.raw_dict(&base);
    let mut calls = 0;
    for case in 0..1500 {
        // The DDicts referenced: some of the IDs next to ID 0's slot, often
        // the raw one, sometimes enough others to make the set grow; in any
        // order.
        let mut ids = IDS_NEAR_ZERO.to_vec();
        rng.shuffle(&mut ids);
        ids.truncate(rng.range(0, 6) as usize);
        if rng.chance(3) {
            let mut clustered = IDS_CLUSTERED.to_vec();
            rng.shuffle(&mut clustered);
            clustered.truncate(rng.range(16, 24) as usize);
            ids.extend_from_slice(&clustered);
        }
        let mut dicts: Vec<Vec<u8>> = ids.iter().map(|&id| with_dict_id(&trained, id)).collect();
        if !rng.chance(4) {
            dicts.push(raw.clone());
        }
        rng.shuffle(&mut dicts);
        if dicts.is_empty() {
            continue;
        }

        // A frame or two naming one of the IDs next to 0's slot, referenced
        // or not, or another, or no ID.
        let frame_dict = match rng.range(0, 4) {
            0..=1 => with_dict_id(&trained, IDS_NEAR_ZERO[rng.range(0, 5) as usize]),
            2 => with_dict_id(&trained, IDS_CLUSTERED[rng.range(0, 23) as usize]),
            _ => raw.clone(),
        };
        let mut src = Vec::new();
        let mut total = 0;
        for _ in 0..rng.range(1, 2) {
            let data = rng.data_between(100, 5000, &base);
            let mut cctx = zstd_safe::CCtx::create();
            cctx.set_parameter(CParameter::ChecksumFlag(true))
                .expect("parameter");
            cctx.load_dictionary(&frame_dict).expect("dictionary loads");
            let mut frame = Vec::with_capacity(zstd_safe::compress_bound(data.len()));
            cctx.compress2(&mut frame, &data).expect("compresses");
            src.extend_from_slice(&frame);
            total += data.len();
        }

        let c_ddicts: Vec<zstd_safe::DDict<'static>> =
            dicts.iter().map(|d| zstd_safe::DDict::create(d)).collect();
        let p_ddicts: Vec<Arc<hivepack::zstd::DDict>> = dicts
            .iter()
            .map(|d| Arc::new(hivepack::zstd::DDict::new(d).expect("DDict")))
            .collect();
        let mut c = zstd_safe::DCtx::create();
        let mut p = hivepack::zstd::DCtx::new();
        c.set_parameter(DParameter::RefMultipleDDicts(true))
            .expect("multiple");
        p.set_parameter(hivepack::zstd::DParameter::RefMultipleDDicts(true))
            .expect("multiple");
        for d in 0..dicts.len() {
            c.ref_ddict(&c_ddicts[d]).expect("libzstd references");
            p.ref_ddict(Some(p_ddicts[d].clone()))
                .expect("port references");
        }

        // Each call can leave the context with another dictionary for the
        // next. No dictionary is loaded: see the other test.
        let mut streamed = false;
        for step in 0..rng.range(2, 5) {
            let d = rng.range(0, dicts.len() as u64 - 1) as usize;
            let call = match rng.range(0, 5) {
                0 => Call::UsingDDict(d),
                1 => Call::RefDDict(d),
                2 | 3 => Call::Stream,
                _ => Call::Plain,
            };
            let mut c_out = Vec::with_capacity(total);
            let mut p_out = vec![0u8; total];
            if let Call::RefDDict(d) = call {
                c.ref_ddict(&c_ddicts[d]).expect("libzstd references");
                p.ref_ddict(Some(p_ddicts[d].clone()))
                    .expect("port references");
            }
            let (want, got) = match call {
                Call::Stream => {
                    streamed = true;
                    let outcome = stream(&mut c, &mut p, &src, total, &mut rng)
                        .unwrap_or_else(|problem| panic!("case {case}, call {step}: {problem}"));
                    (outcome.clone(), outcome)
                }
                Call::UsingDDict(d) => (
                    outcome_libzstd(
                        c.decompress_using_ddict(&mut c_out, &src, &c_ddicts[d]),
                        &mut c_out,
                    ),
                    outcome_port(
                        p.decompress_using_ddict(&mut p_out, &src, &p_ddicts[d]),
                        &p_out,
                    ),
                ),
                _ => (
                    outcome_libzstd(c.decompress(&mut c_out, &src), &mut c_out),
                    outcome_port(p.decompress(&mut p_out, &src), &p_out),
                ),
            };
            if !matches!(call, Call::Stream) && streamed {
                // As the zstd crate does after a one-call decompression.
                p.reset(hivepack::zstd::ResetDirective::SessionOnly)
                    .expect("port resets");
                streamed = false;
            }
            assert_eq!(got, want, "case {case}, call {step}: {call:?}");
            calls += 1;
        }
    }
    eprintln!("{calls} calls");
}
