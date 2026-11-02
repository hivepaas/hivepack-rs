//! Streams the input through the port and libzstd with the same
//! parameters, in the same pieces, with the same directives and the same
//! room for output, all picked by its first 8 bytes, and checks that every
//! call returns the same, moves as far and writes the same, and that the
//! port decodes the frame back, and that `ZSTD_getFrameProgression` says
//! the same after every call. A third of the time with a dictionary
//! from the start of the input, loaded, a prefix or a `CDict`, attached,
//! copied in or loaded again. A quarter of the time with a target size
//! for compressed blocks (`ZSTD_c_targetCBlockSize`).
//!
//! A quarter of the time with worker threads (`ZSTD_c_nbWorkers`), a
//! different number on each side, and their job size, overlap and
//! synchronization points: how much each call takes and writes then
//! depends on the threads, but not the frame. Then each side goes through
//! the same steps on its own, each step's calls repeated until it is done,
//! and the frames must be the same; the port's frame progression and what
//! it has to flush now are asked after every call. A panic or a difference
//! is a bug.

#![no_main]

use std::sync::Arc;

use hivepack::zstd::{
    CCtx, CDict, CParameter as P, DCtx, DictAttachPref, EndDirective, ParamSwitch,
    Strategy,
};
use libfuzzer_sys::fuzz_target;
use zstd::zstd_safe::{self, CParameter as C, zstd_sys::ZSTD_EndDirective};

/// Calls more than this mean no progress.
const MAX_CALLS: usize = 100_000;

/// xorshift64*, seeded by the input.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A piece size: mostly small, sometimes a few blocks.
    fn piece(&mut self) -> usize {
        let bits = self.next();
        let size = match bits % 4 {
            0 => (bits >> 8) % 16,
            1 => (bits >> 8) % 1000,
            2 => (bits >> 8) % 20_000,
            _ => (bits >> 8) % 300_000,
        };
        size as usize
    }
}

fn name(code: usize) -> String {
    zstd_safe::get_error_name(code).to_string()
}

/// A step with workers: input up to `end` with `directive`, its calls
/// repeated until it is done, each with `room` bytes of output (or, with a
/// stable output buffer, the rest of it).
struct Step {
    end: usize,
    directive: EndDirective,
    room: usize,
}

/// Each step's calls, through `call(output, out_pos, input, directive)`
/// returning the result, the input read and where the output stops: the
/// frame written, and the error that stopped it, if any.
fn drive(
    steps: &[Step],
    src: &[u8],
    stable_room: Option<usize>,
    mut call: impl FnMut(&mut [u8], usize, &[u8], EndDirective) -> (Result<usize, String>, usize, usize),
) -> (Vec<u8>, Result<(), String>) {
    let mut frame = Vec::new();
    let mut stable = vec![0u8; stable_room.unwrap_or(0)];
    let mut taken = 0;
    for step in steps {
        let mut done = false;
        for _ in 0..MAX_CALLS {
            let mut fresh = vec![0u8; step.room];
            let (dst, out_pos) = if stable_room.is_some() {
                (&mut stable[..], frame.len())
            } else {
                (&mut fresh[..], 0)
            };
            let (result, read, wrote) = call(dst, out_pos, &src[taken..step.end], step.directive);
            frame.extend_from_slice(&dst[out_pos..wrote]);
            taken += read;
            let remaining = match result {
                Ok(remaining) => remaining,
                Err(error) => return (frame, Err(error)),
            };
            if taken == step.end && (step.directive == EndDirective::Continue || remaining == 0) {
                done = true;
                break;
            }
            if (read, wrote) == (0, out_pos) {
                std::thread::yield_now();
            }
        }
        if !done {
            return (frame, Err("no end".into()));
        }
    }
    (frame, Ok(()))
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }
    let (head, src) = input.split_at(8);
    let level =
        [-100, -5, -1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 16, 19, 22][usize::from(head[0]) % 16];
    let window_log = 10 + u32::from(head[1] % 12);
    let stable_out = head[2] & 1 != 0;
    let checksum = head[2] & 2 != 0;
    let max_block = [0, 1024, 4096, 65_536][usize::from(head[2] >> 2) % 4];
    let ldm = head[2] & 16 != 0;
    let workers = head[0] & 0x30 == 0x30;
    let mut rng = Rng(u64::from(u32::from_le_bytes([head[3], head[4], head[5], head[6]])) | 1);

    let mut parameters = vec![
        (P::CompressionLevel(level), C::CompressionLevel(level)),
        (P::ChecksumFlag(checksum), C::ChecksumFlag(checksum)),
        (
            P::StableOutBuffer(stable_out),
            C::StableOutBuffer(stable_out),
        ),
        (P::MaxBlockSize(max_block), C::MaxBlockSize(max_block)),
    ];
    // Long distance matching needs a window set: it would take 2^27 bytes.
    if head[7] & 1 != 0 || ldm {
        parameters.push((P::WindowLog(window_log), C::WindowLog(window_log)));
    }
    if ldm {
        // Small parameters, so that it finds matches in small inputs; some
        // left to the library.
        parameters.push((
            P::EnableLongDistanceMatching(ParamSwitch::Enable),
            C::EnableLongDistanceMatching(true),
        ));
        let pick = head[2] >> 5;
        if pick & 1 != 0 {
            let value = 4 + (rng.next() % 61) as u32;
            parameters.push((P::LdmMinMatch(value), C::LdmMinMatch(value)));
        }
        if pick & 2 != 0 {
            let value = (rng.next() % 5) as u32;
            parameters.push((P::LdmHashRateLog(value), C::LdmHashRateLog(value)));
        }
        if pick & 4 != 0 {
            let value = 6 + (rng.next() % 15) as u32;
            parameters.push((P::LdmHashLog(value), C::LdmHashLog(value)));
            let value = 1 + (rng.next() % 8) as u32;
            parameters.push((P::LdmBucketSizeLog(value), C::LdmBucketSizeLog(value)));
        }
    }
    {
        use zstd_safe::Strategy as S;
        let strategies = [
            (Strategy::Fast, S::ZSTD_fast),
            (Strategy::Dfast, S::ZSTD_dfast),
            (Strategy::Greedy, S::ZSTD_greedy),
            (Strategy::Lazy, S::ZSTD_lazy),
            (Strategy::Lazy2, S::ZSTD_lazy2),
            (Strategy::Btlazy2, S::ZSTD_btlazy2),
            (Strategy::Btopt, S::ZSTD_btopt),
            (Strategy::Btultra, S::ZSTD_btultra),
            (Strategy::Btultra2, S::ZSTD_btultra2),
        ];
        let pick = usize::from(head[7] >> 1 & 7) + 8 * usize::from(head[2] >> 7);
        if let Some(&(p, c)) = strategies.get(pick) {
            parameters.push((P::Strategy(Some(p)), C::Strategy(c)));
        }
    }
    if rng.next() % 4 == 0 {
        // The optimal parser's 3-byte hash table.
        parameters.push((P::MinMatch(3), C::MinMatch(3)));
    }
    if rng.next() % 4 == 0 {
        // A target size for compressed blocks: below the smallest, raised
        // to it, the smallest, small ones and the largest.
        let target = [1, 1340, 2000, 4096, 20_000, 131_072][(rng.next() % 6) as usize];
        parameters.push((P::TargetCBlockSize(target), C::TargetCBlockSize(target)));
    }
    let switches = [
        (ParamSwitch::Auto, zstd_safe::ParamSwitch::Auto),
        (ParamSwitch::Enable, zstd_safe::ParamSwitch::Enable),
        (ParamSwitch::Disable, zstd_safe::ParamSwitch::Disable),
    ];
    let (p_row, c_row) = switches[usize::from(head[7] >> 4) % 3];
    parameters.push((P::UseRowMatchFinder(p_row), C::UseRowMatchFinder(c_row)));
    // The block splitter after the sequences.
    let (p_split, c_split) = switches[usize::from(head[2] >> 4) % 3];
    parameters.push((
        P::SplitAfterSequences(p_split),
        C::UseBlockSplitter(c_split),
    ));
    if workers {
        // A number of workers on each side, the job size (raised to the
        // smallest but for 0), the overlap, and synchronization points.
        let count = 1 + u32::from(head[0] >> 6);
        parameters.push((P::NbWorkers(count), C::NbWorkers(5 - count)));
        // The default job size is up to 1 GB at the strongest level and
        // with long distance matching, and libzstd's round buffer 4 times
        // that: then a small one.
        let job_size = [0, 1, 1 << 19, 1 << 20][(rng.next() % 4) as usize];
        let job_size = if job_size == 0 && (ldm || level > 19) {
            1
        } else {
            job_size
        };
        parameters.push((P::JobSize(job_size), C::JobSize(job_size)));
        let overlap = (rng.next() % 10) as u32;
        parameters.push((P::OverlapLog(overlap as i32), C::OverlapSizeLog(overlap)));
        let rsyncable = rng.next() % 2 == 0;
        parameters.push((P::Rsyncable(rsyncable), C::RSyncable(rsyncable)));
    }

    // A dictionary, a third of the time: the start of the input, copied
    // apart (libzstd takes a dictionary that ends where the input starts
    // in memory as part of the input's segment), behind the dictionary
    // magic number sometimes; loaded, a prefix, or a CDict, attached as
    // libzstd decides or forced to attach, copy or load.
    let dict_pick = rng.next();
    let mut dict = Vec::new();
    let mut src = src;
    if dict_pick % 3 == 0 {
        let dict_len = ((dict_pick >> 8) % 70_000) as usize % (src.len() + 1);
        dict.reserve(dict_len + 8 + 64);
        if dict_pick >> 32 & 7 == 0 {
            dict.extend_from_slice(&0xEC30_A437u32.to_le_bytes());
        }
        dict.extend_from_slice(&src[..dict_len]);
        src = &src[dict_len..];
        let (pp, cp) = match dict_pick >> 40 & 7 {
            0..=2 => (
                DictAttachPref::DefaultAttach,
                zstd_safe::DictAttachPref::DefaultAttach,
            ),
            3 => (
                DictAttachPref::ForceAttach,
                zstd_safe::DictAttachPref::ForceAttach,
            ),
            4..=5 => (
                DictAttachPref::ForceCopy,
                zstd_safe::DictAttachPref::ForceCopy,
            ),
            _ => (
                DictAttachPref::ForceLoad,
                zstd_safe::DictAttachPref::ForceLoad,
            ),
        };
        parameters.push((P::ForceAttachDict(pp), C::ForceAttachDict(cp)));
    }
    let dict_way = dict_pick >> 48 & 3;
    let cdict_level = [1, 3, 7, 19][(dict_pick >> 52 & 3) as usize];
    let c_cdict = (!dict.is_empty() && dict_way == 2)
        .then(|| zstd_safe::CDict::try_create(&dict, cdict_level))
        .flatten();
    let p_cdict = (!dict.is_empty() && dict_way == 2)
        .then(|| CDict::new(&dict, cdict_level).ok().map(Arc::new))
        .flatten();
    assert!(
        c_cdict.is_some() == p_cdict.is_some(),
        "one makes a CDict, the other not"
    );

    let mut c = zstd_safe::CCtx::create();
    let mut p = CCtx::new();
    for (pp, cp) in parameters {
        let want = c.set_parameter(cp).map(|_| ()).map_err(name);
        let got = p
            .set_parameter(pp)
            .map_err(|error| error.code().message().to_string());
        assert!(
            want == got,
            "setting {pp:?}: libzstd {want:?}, port {got:?}"
        );
    }
    if !dict.is_empty() {
        let (want, got) = match (dict_way, &c_cdict, &p_cdict) {
            (2, Some(c_cdict), p_cdict) => (
                c.ref_cdict(c_cdict).map(|_| ()).map_err(name),
                p.ref_cdict(p_cdict.clone())
                    .map_err(|error| error.code().message().to_string()),
            ),
            (1, ..) => (
                c.ref_prefix(&dict).map(|_| ()).map_err(name),
                p.ref_prefix(&dict)
                    .map_err(|error| error.code().message().to_string()),
            ),
            _ => (
                c.load_dictionary(&dict).map(|_| ()).map_err(name),
                p.load_dictionary(&dict)
                    .map_err(|error| error.code().message().to_string()),
            ),
        };
        assert!(
            want == got,
            "the dictionary: libzstd {want:?}, port {got:?}"
        );
    }
    let prefix = dict_way == 1;

    // With a stable output buffer, one buffer whose room stays the same.
    let room = hivepack::zstd::compress_bound(src.len()).unwrap_or(0) + 64;
    let (mut c_stable, mut p_stable) = if stable_out {
        (vec![0u8; room], vec![0u8; room])
    } else {
        (Vec::new(), Vec::new())
    };
    if workers {
        // The steps, the same for both: pieces with their directives, the
        // last one the end, and the room for output.
        let mut steps = Vec::new();
        let mut end = 0;
        loop {
            end = (end + rng.piece()).min(src.len());
            let directive = if end == src.len() && rng.next() % 4 != 0 {
                EndDirective::End
            } else if rng.next() % 8 == 0 {
                EndDirective::Flush
            } else {
                EndDirective::Continue
            };
            steps.push(Step {
                end,
                directive,
                room: 1 + rng.piece(),
            });
            if directive == EndDirective::End {
                break;
            }
        }
        let stable_room = stable_out.then_some(room);
        let (want, want_end) = drive(&steps, src, stable_room, |dst, out_pos, piece, directive| {
            let c_directive = match directive {
                EndDirective::Continue => ZSTD_EndDirective::ZSTD_e_continue,
                EndDirective::Flush => ZSTD_EndDirective::ZSTD_e_flush,
                EndDirective::End => ZSTD_EndDirective::ZSTD_e_end,
            };
            let mut output = zstd_safe::OutBuffer::around_pos(dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(piece);
            let result = c.compress_stream2(&mut output, &mut input, c_directive);
            (result.map_err(name), input.pos(), output.pos())
        });
        let (got, got_end) = drive(&steps, src, stable_room, |dst, out_pos, piece, directive| {
            let mut output = hivepack::zstd::OutBuffer { dst, pos: out_pos };
            let mut input = hivepack::zstd::InBuffer::new(piece);
            let result = p.compress_stream2(&mut output, &mut input, directive);
            let fp = p.get_frame_progression();
            assert!(
                fp.consumed <= fp.ingested && fp.flushed <= fp.produced,
                "with workers: frame progression {fp:?}"
            );
            assert!(p.to_flush_now() as u64 <= fp.produced - fp.flushed);
            (
                result.map_err(|error| error.code().message().to_string()),
                input.pos,
                output.pos,
            )
        });
        assert!(
            want_end == got_end,
            "with workers: libzstd {want_end:?}, port {got_end:?}"
        );
        if want_end.is_ok() {
            assert!(want == got, "with workers: the frames differ");
            let mut back = vec![0u8; src.len()];
            let mut dctx = DCtx::new();
            let size = if prefix {
                dctx.ref_prefix(&dict)
                    .and_then(|()| dctx.decompress(&mut back, &got))
            } else {
                dctx.decompress_using_dict(&mut back, &got, &dict)
            }
            .expect("the frame decodes");
            assert!(back[..size] == *src, "with workers: does not decode back");
        }
        return;
    }

    let mut stable_pos = 0;
    let mut frame = Vec::new();
    let mut taken = 0;
    for call in 0..MAX_CALLS {
        let in_end = (taken + rng.piece()).min(src.len());
        let directive = if in_end == src.len() && rng.next() % 4 != 0 {
            EndDirective::End
        } else if rng.next() % 8 == 0 {
            EndDirective::Flush
        } else {
            EndDirective::Continue
        };
        let c_directive = match directive {
            EndDirective::Continue => ZSTD_EndDirective::ZSTD_e_continue,
            EndDirective::Flush => ZSTD_EndDirective::ZSTD_e_flush,
            EndDirective::End => ZSTD_EndDirective::ZSTD_e_end,
        };
        let (mut c_fresh, mut p_fresh, out_pos) = if stable_out {
            (Vec::new(), Vec::new(), stable_pos)
        } else {
            let size = rng.piece();
            (vec![0u8; size], vec![0u8; size], 0)
        };
        let (c_dst, p_dst) = if stable_out {
            (&mut c_stable[..], &mut p_stable[..])
        } else {
            (&mut c_fresh[..], &mut p_fresh[..])
        };
        let piece = &src[taken..in_end];

        let (want, ci, co) = {
            let mut output = zstd_safe::OutBuffer::around_pos(&mut *c_dst, out_pos);
            let mut input = zstd_safe::InBuffer::around(piece);
            let result = c.compress_stream2(&mut output, &mut input, c_directive);
            (result.map_err(name), input.pos(), output.pos())
        };
        let (got, pi, po) = {
            let mut output = hivepack::zstd::OutBuffer {
                dst: &mut *p_dst,
                pos: out_pos,
            };
            let mut input = hivepack::zstd::InBuffer::new(piece);
            let result = p.compress_stream2(&mut output, &mut input, directive);
            (result, input.pos, output.pos)
        };
        let got = got.map_err(|error| error.code().message().to_string());
        assert!(
            (&want, ci, co) == (&got, pi, po),
            "call {call} ({directive:?}): libzstd {want:?} read {ci} wrote to {co}, \
             port {got:?} read {pi} wrote to {po}"
        );
        assert!(
            c_dst[out_pos..co] == p_dst[out_pos..po],
            "call {call}: the output differs"
        );
        let (c_fp, p_fp) = (c.get_frame_progression(), p.get_frame_progression());
        assert!(
            (c_fp.ingested, c_fp.consumed, c_fp.produced, c_fp.flushed)
                == (p_fp.ingested, p_fp.consumed, p_fp.produced, p_fp.flushed)
                && (c_fp.currentJobID, c_fp.nbActiveWorkers)
                    == (p_fp.current_job_id, p_fp.nb_active_workers),
            "call {call}: frame progression: libzstd {c_fp:?}, port {p_fp:?}"
        );
        frame.extend_from_slice(&c_dst[out_pos..co]);
        if stable_out {
            stable_pos = co;
        }
        taken += ci;
        match want {
            Err(_) => return,
            Ok(0) if directive == EndDirective::End => {
                let mut back = vec![0u8; src.len()];
                let mut dctx = DCtx::new();
                let size = if prefix {
                    dctx.ref_prefix(&dict)
                        .and_then(|()| dctx.decompress(&mut back, &frame))
                } else {
                    dctx.decompress_using_dict(&mut back, &frame, &dict)
                }
                .expect("the frame decodes");
                assert!(back[..size] == *src, "does not decode back");
                return;
            }
            Ok(_) => {}
        }
    }
    panic!("no end after {MAX_CALLS} calls");
});
