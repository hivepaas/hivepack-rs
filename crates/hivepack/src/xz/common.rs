//! What the coders share: port of `common/common.{h,c}`, with the return
//! codes and actions of `api/lzma/base.h`.
//!
//! liblzma chains its coders through `lzma_next_coder`, a structure of
//! function pointers and a `void *` to the coder's data. The port chains
//! them as boxed [`NextCoder`] trait objects, whose optional functions
//! (`get_check`, `memconfig`, `get_progress`) are default methods that
//! say they are not there.

/// `lzma_ret`, with the same numbers. The public API turns it into a
/// [`Status`](crate::xz::Status) or an [`Error`](crate::xz::Error).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Ret {
    Ok = 0,
    StreamEnd = 1,
    NoCheck = 2,
    UnsupportedCheck = 3,
    GetCheck = 4,
    MemError = 5,
    MemlimitError = 6,
    FormatError = 7,
    OptionsError = 8,
    DataError = 9,
    BufError = 10,
    ProgError = 11,
    /// `LZMA_TIMED_OUT` (`LZMA_RET_INTERNAL1`): a threaded coder's timeout
    /// was reached, which `lzma_code` returns as LZMA_OK.
    TimedOut = 101,
}

/// `lzma_action`, with the same numbers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Action {
    /// `LZMA_RUN`: continue coding.
    #[default]
    Run = 0,
    /// `LZMA_SYNC_FLUSH`: make all the input available as output.
    SyncFlush = 1,
    /// `LZMA_FULL_FLUSH`: finish encoding of the current Block.
    FullFlush = 2,
    /// `LZMA_FINISH`: finish the coding operation.
    Finish = 3,
    /// `LZMA_FULL_BARRIER`: finish encoding of the current Block, as
    /// `FullFlush` does, but let the encoder go on in another thread.
    FullBarrier = 4,
}

/// `LZMA_ACTION_MAX`.
pub(crate) const ACTION_MAX: usize = Action::FullBarrier as usize;

/// `LZMA_BUFFER_SIZE`: the size of temporary buffers needed in some
/// filters.
pub(crate) const BUFFER_SIZE: usize = 4096;

/// `LZMA_MEMUSAGE_BASE`: the starting value for memory usage estimates.
pub(crate) const MEMUSAGE_BASE: u64 = 1 << 15;

/// `LZMA_VLI_MAX`.
pub(crate) const VLI_MAX: u64 = u64::MAX / 2;

/// `LZMA_VLI_UNKNOWN`.
pub(crate) const VLI_UNKNOWN: u64 = u64::MAX;

/// `LZMA_VLI_BYTES_MAX`.
pub(crate) const VLI_BYTES_MAX: usize = 9;

/// `LZMA_FILTER_RESERVED_START`: the start of the internal Filter ID
/// space, which may never be used in Streams.
pub(crate) const FILTER_RESERVED_START: u64 = 1 << 62;

/// `lzma_vli_is_valid`.
pub(crate) fn vli_is_valid(vli: u64) -> bool {
    vli <= VLI_MAX || vli == VLI_UNKNOWN
}

// The flags of lzma_stream_decoder() and lzma_auto_decoder():
// LZMA_TELL_NO_CHECK and the others.
pub const TELL_NO_CHECK: u32 = 0x01;
pub const TELL_UNSUPPORTED_CHECK: u32 = 0x02;
pub const TELL_ANY_CHECK: u32 = 0x04;
pub const CONCATENATED: u32 = 0x08;
pub const IGNORE_CHECK: u32 = 0x10;
pub const FAIL_FAST: u32 = 0x20;

/// `LZMA_SUPPORTED_FLAGS`.
pub(crate) const SUPPORTED_FLAGS: u32 = TELL_NO_CHECK
    | TELL_UNSUPPORTED_CHECK
    | TELL_ANY_CHECK
    | IGNORE_CHECK
    | CONCATENATED
    | FAIL_FAST;

/// `lzma_bufcpy`: copies as much of `input[*in_pos..]` as fits into
/// `output[*out_pos..]`, and returns how much it copied.
pub(crate) fn bufcpy(
    input: &[u8],
    in_pos: &mut usize,
    output: &mut [u8],
    out_pos: &mut usize,
) -> usize {
    let copy_size = (input.len() - *in_pos).min(output.len() - *out_pos);
    output[*out_pos..*out_pos + copy_size].copy_from_slice(&input[*in_pos..*in_pos + copy_size]);
    *in_pos += copy_size;
    *out_pos += copy_size;
    copy_size
}

/// `lzma_next_coder`: a coder of the chain, from the input of `code`
/// (`in`, `in_pos`, `in_size`) to its output (`out`, `out_pos`,
/// `out_size`). The input is `input[*in_pos..]` and the output
/// `output[*out_pos..]`.
///
/// Differs from liblzma: `Send`, so that a [`Stream`](crate::xz::Stream) is,
/// as an `lzma_stream` may be used from any thread.
pub(crate) trait NextCoder: Send {
    /// `code`.
    fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret;

    /// `get_check`, or `None` where the coder has none.
    fn get_check(&self) -> Option<crate::xz::check::Check> {
        None
    }

    /// `memconfig`: the memory usage and the old limit, and a new limit
    /// set if `new_memlimit` is not zero; `None` where the coder has none.
    fn memconfig(
        &mut self,
        _memusage: &mut u64,
        _old_memlimit: &mut u64,
        _new_memlimit: u64,
    ) -> Option<Ret> {
        None
    }

    /// `get_progress`, or `None` where the coder has none.
    fn get_progress(&self) -> Option<(u64, u64)> {
        None
    }

    /// This coder as an LZ encoder, if it is one: what
    /// `lzma_next_coder_init()` keeps for the encoder of the next Block.
    /// The other coders are small, and are made anew.
    fn into_lz_encoder(self: Box<Self>) -> Option<Box<crate::xz::lz_encoder::LzEncCoder>> {
        None
    }
}

/// The state of `lzma_internal`: what the next call to `lzma_code()`
/// accepts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sequence {
    Run,
    SyncFlush,
    FullFlush,
    Finish,
    FullBarrier,
    End,
    Error,
}

/// `lzma_internal`: the coder of a stream, and what `lzma_code()` checks
/// before calling it.
pub(crate) struct Internal {
    /// The actual coder that should do something useful.
    pub(crate) next: Box<dyn NextCoder>,
    /// Track the state of the coder. This is used to validate arguments so
    /// that the actual coders can rely on e.g. that LZMA_SYNC_FLUSH is
    /// used on every call to lzma_code until next.code has returned
    /// LZMA_STREAM_END.
    sequence: Sequence,
    /// A copy of lzma_stream avail_in. This is used to verify that the
    /// amount of input doesn't change once e.g. LZMA_FINISH has been used.
    avail_in: usize,
    /// Indicates which lzma_action values are allowed by next.code.
    pub(crate) supported_actions: [bool; ACTION_MAX + 1],
    /// If true, lzma_code will return LZMA_BUF_ERROR if no progress was
    /// made (no input consumed and no output produced by next.code).
    allow_buf_error: bool,
    pub(crate) total_in: u64,
    pub(crate) total_out: u64,
}

impl Internal {
    /// `lzma_strm_init`, with the coder that the initialization made.
    pub(crate) fn new(next: Box<dyn NextCoder>, supported_actions: &[Action]) -> Internal {
        let mut actions = [false; ACTION_MAX + 1];
        for &action in supported_actions {
            actions[action as usize] = true;
        }
        Internal {
            next,
            sequence: Sequence::Run,
            avail_in: 0,
            supported_actions: actions,
            allow_buf_error: false,
            total_in: 0,
            total_out: 0,
        }
    }

    /// `lzma_code`, on `input[*in_pos..]` and `output[*out_pos..]`.
    pub(crate) fn code(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        output: &mut [u8],
        out_pos: &mut usize,
        action: Action,
    ) -> Ret {
        // Sanity checks
        if !self.supported_actions[action as usize] {
            return Ret::ProgError;
        }
        let avail_in = input.len() - *in_pos;

        match self.sequence {
            Sequence::Run => match action {
                Action::Run => {}
                Action::SyncFlush => self.sequence = Sequence::SyncFlush,
                Action::FullFlush => self.sequence = Sequence::FullFlush,
                Action::Finish => self.sequence = Sequence::Finish,
                Action::FullBarrier => self.sequence = Sequence::FullBarrier,
            },
            // The same action must be used until we return
            // LZMA_STREAM_END, and the amount of input must not change.
            Sequence::SyncFlush => {
                if action != Action::SyncFlush || self.avail_in != avail_in {
                    return Ret::ProgError;
                }
            }
            Sequence::FullFlush => {
                if action != Action::FullFlush || self.avail_in != avail_in {
                    return Ret::ProgError;
                }
            }
            Sequence::Finish => {
                if action != Action::Finish || self.avail_in != avail_in {
                    return Ret::ProgError;
                }
            }
            Sequence::FullBarrier => {
                if action != Action::FullBarrier || self.avail_in != avail_in {
                    return Ret::ProgError;
                }
            }
            Sequence::End => return Ret::StreamEnd,
            Sequence::Error => return Ret::ProgError,
        }

        let (in_start, out_start) = (*in_pos, *out_pos);
        let mut ret = self.next.code(input, in_pos, output, out_pos, action);
        let (in_used, out_used) = (*in_pos - in_start, *out_pos - out_start);
        self.total_in += in_used as u64;
        self.total_out += out_used as u64;
        self.avail_in = input.len() - *in_pos;

        match ret {
            Ret::Ok => {
                // Don't return LZMA_BUF_ERROR when it happens the first
                // time. This is to avoid returning LZMA_BUF_ERROR when
                // avail_out was zero but still there was no more data
                // left to written to next_out.
                if out_used == 0 && in_used == 0 {
                    if self.allow_buf_error {
                        ret = Ret::BufError;
                    } else {
                        self.allow_buf_error = true;
                    }
                } else {
                    self.allow_buf_error = false;
                }
            }
            Ret::TimedOut => {
                self.allow_buf_error = false;
                ret = Ret::Ok;
            }
            Ret::StreamEnd => {
                if matches!(
                    self.sequence,
                    Sequence::SyncFlush | Sequence::FullFlush | Sequence::FullBarrier
                ) {
                    self.sequence = Sequence::Run;
                } else {
                    self.sequence = Sequence::End;
                }
                self.allow_buf_error = false;
            }
            // Something else than LZMA_OK, but not a fatal error, that is,
            // coding may be continued (except if ISEQ_END).
            Ret::NoCheck | Ret::UnsupportedCheck | Ret::GetCheck | Ret::MemlimitError => {
                self.allow_buf_error = false;
            }
            // All the other errors are fatal; coding cannot be continued.
            _ => self.sequence = Sequence::Error,
        }
        ret
    }

    /// `lzma_get_check`: LZMA_CHECK_NONE if the coder cannot know it.
    pub(crate) fn get_check(&self) -> crate::xz::check::Check {
        self.next
            .get_check()
            .unwrap_or(crate::xz::check::Check::NONE)
    }

    /// `lzma_memusage` and `lzma_memlimit_get`: zero where the coder cannot
    /// tell.
    pub(crate) fn memconfig_get(&mut self) -> (u64, u64) {
        let (mut memusage, mut old_memlimit) = (0, 0);
        match self.next.memconfig(&mut memusage, &mut old_memlimit, 0) {
            Some(Ret::Ok) => (memusage, old_memlimit),
            _ => (0, 0),
        }
    }

    /// `lzma_memlimit_set`.
    pub(crate) fn memlimit_set(&mut self, new_memlimit: u64) -> Ret {
        let (mut memusage, mut old_memlimit) = (0, 0);
        // Zero is a special value that cannot be used as an actual limit.
        // If 0 was specified, use 1 instead.
        let new_memlimit = new_memlimit.max(1);
        self.next
            .memconfig(&mut memusage, &mut old_memlimit, new_memlimit)
            .unwrap_or(Ret::ProgError)
    }

    /// `lzma_get_progress`.
    pub(crate) fn get_progress(&self) -> (u64, u64) {
        self.next
            .get_progress()
            .unwrap_or((self.total_in, self.total_out))
    }
}

/// `read32le`.
pub(crate) fn read32le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// `read64le`.
pub(crate) fn read64le(buf: &[u8]) -> u64 {
    u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

/// `write32le`.
pub(crate) fn write32le(buf: &mut [u8], value: u32) {
    buf[..4].copy_from_slice(&value.to_le_bytes());
}
