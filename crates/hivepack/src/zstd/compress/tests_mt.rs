//! Multithreaded compression (`compress/zstdmt_compress.rs`): frames with
//! the indices lowered as often as they can be, in each job and in the
//! window of long distance matching, which goes over the whole input, must
//! not change; and are libzstd's. `tests/compress_mt.rs` compares the
//! frames of many more parameters and calls with libzstd's.

use std::sync::atomic::Ordering;

use crate::zstd::compress::zstd_compress::{CCtx, CParameter, zstd_compress_bound};
use crate::zstd::compress::zstd_compress_internal::{
    OVERFLOW_CORRECT_FREQUENTLY, ParamSwitch, Strategy,
};
use crate::zstd::compress::zstdmt_compress::MT_OVERFLOW_CORRECTIONS;
use crate::zstd::decompress::zstd_decompress::decompress;
use crate::zstd::oracle::Rng;
use zstd::zstd_safe;

/// The strategy's number for libzstd.
fn c_strategy(strategy: Strategy) -> zstd_safe::Strategy {
    use zstd_safe::Strategy as S;
    match strategy {
        Strategy::Fast => S::ZSTD_fast,
        Strategy::Dfast => S::ZSTD_dfast,
        Strategy::Greedy => S::ZSTD_greedy,
        Strategy::Lazy => S::ZSTD_lazy,
        Strategy::Lazy2 => S::ZSTD_lazy2,
        Strategy::Btlazy2 => S::ZSTD_btlazy2,
        Strategy::Btopt => S::ZSTD_btopt,
        Strategy::Btultra => S::ZSTD_btultra,
        Strategy::Btultra2 => S::ZSTD_btultra2,
    }
}

/// With workers, and the indices lowered as soon as they can be (libzstd's
/// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY`, which the jobs take from the
/// caller's thread), every strategy gives the same frames, which are
/// libzstd's; with long distance matching for half, whose window over the
/// whole input lowers its own indices. Small windows and tables, so that
/// they are lowered within each job; jobs of the smallest size.
#[test]
fn lowering_the_indices_with_workers_changes_no_frame() {
    let mut rng = Rng::new(0x5EED_4D54);
    let mut problems = Vec::new();
    let before = MT_OVERFLOW_CORRECTIONS.load(Ordering::Relaxed);
    let strategies = [
        (1, None),
        (3, None),
        (5, Some(Strategy::Greedy)),
        (7, Some(Strategy::Lazy2)),
        (12, Some(Strategy::Btlazy2)),
        (16, Some(Strategy::Btopt)),
        (19, Some(Strategy::Btultra2)),
    ];
    for (i, (level, strategy)) in strategies.into_iter().enumerate() {
        // On big-endian machines libzstd's block splitter, which the
        // strategies from greedy up use, splits elsewhere: their frames are
        // compared with the port's own only.
        let like_libzstd = !(cfg!(target_endian = "big") && i >= 2);
        let opt = strategy.is_some_and(|strategy| strategy >= Strategy::Btopt);
        let len = if cfg!(debug_assertions) && opt {
            rng.range(600_000, 800_000)
        } else {
            rng.range(600_000, 1_300_000)
        } as usize;
        let data = rng.lz_data(len);
        let window_log = rng.range(10, 16) as u32;
        let chain_log = rng.range(6, 14) as u32;
        let ldm = i % 2 == 1;
        let overlap_log = rng.range(0, 9) as i32;
        let min_match = if opt { 3 } else { 0 };
        let row = if i == 2 {
            ParamSwitch::Enable
        } else {
            ParamSwitch::Disable
        };
        let params = |cctx: &mut CCtx| {
            for parameter in [
                CParameter::CompressionLevel(level),
                CParameter::Strategy(strategy),
                CParameter::WindowLog(window_log),
                CParameter::ChainLog(chain_log),
                CParameter::MinMatch(min_match),
                CParameter::UseRowMatchFinder(row),
                CParameter::EnableLongDistanceMatching(if ldm {
                    ParamSwitch::Enable
                } else {
                    ParamSwitch::Disable
                }),
                CParameter::LdmMinMatch(16),
                CParameter::LdmHashRateLog(2),
                CParameter::LdmHashLog(12),
                CParameter::JobSize(512 << 10),
                CParameter::OverlapLog(overlap_log),
                CParameter::ChecksumFlag(true),
                CParameter::NbWorkers(1 + i as u32 % 4),
            ] {
                cctx.set_parameter(parameter)
                    .map_err(|error| format!("{error:?}"))?;
            }
            Ok::<(), String>(())
        };
        let frames: Vec<Result<Vec<u8>, String>> = [false, true]
            .into_iter()
            .map(|frequently| {
                OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(frequently));
                let mut cctx = CCtx::new();
                params(&mut cctx)?;
                let mut dst = vec![0u8; zstd_compress_bound(len).unwrap_or(0)];
                let size = cctx
                    .compress2(&mut dst, &data)
                    .map_err(|error| format!("{error:?}"))?;
                dst.truncate(size);
                Ok(dst)
            })
            .collect();
        OVERFLOW_CORRECT_FREQUENTLY.with(|flag| flag.set(false));

        // libzstd's frame, without.
        let want = like_libzstd.then(|| {
            use zstd_safe::CParameter as C;
            let mut c = zstd_safe::CCtx::create();
            let mut list = vec![
                C::CompressionLevel(level),
                C::WindowLog(window_log),
                C::ChainLog(chain_log),
                C::MinMatch(min_match),
                C::UseRowMatchFinder(if i == 2 {
                    zstd_safe::ParamSwitch::Enable
                } else {
                    zstd_safe::ParamSwitch::Disable
                }),
                C::EnableLongDistanceMatching(ldm),
                C::LdmMinMatch(16),
                C::LdmHashRateLog(2),
                C::LdmHashLog(12),
                C::JobSize(512 << 10),
                C::OverlapSizeLog(overlap_log as u32),
                C::ChecksumFlag(true),
                C::NbWorkers(3),
            ];
            if let Some(strategy) = strategy {
                list.push(C::Strategy(c_strategy(strategy)));
            }
            for parameter in list {
                c.set_parameter(parameter).expect("libzstd sets it");
            }
            let mut dst = vec![0u8; zstd_safe::compress_bound(len)];
            let size = c
                .compress2(&mut dst[..], &data)
                .expect("libzstd compresses");
            dst.truncate(size);
            dst
        });
        match (&frames[0], &frames[1]) {
            (Ok(without), Ok(with)) => {
                if want.as_ref().is_some_and(|want| without != want) {
                    problems.push(format!("level {level}, {strategy:?}: not libzstd's frame"));
                }
                if without != with {
                    problems.push(format!(
                        "level {level}, {strategy:?}, window log {window_log}, long distance \
                         matching {ldm}: the indices lowered change the frame"
                    ));
                }
                let mut back = vec![0u8; len];
                if decompress(&mut back, with).ok() != Some(len) || back != data {
                    problems.push(format!("level {level}: does not decode back"));
                }
            }
            other => problems.push(format!("level {level}: {other:?}")),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    let corrections = MT_OVERFLOW_CORRECTIONS.load(Ordering::Relaxed) - before;
    eprintln!("{corrections} corrections in the jobs and long distance matching");
    assert!(corrections > 100, "only {corrections} corrections");
}
