//! Constants shared by the compressor and the decompressor: port of the
//! parts of `bzlib.h` and `bzlib_private.h` that are not the stream
//! structures, which `compress.rs` and `decompress.rs` hold.

/// `BZ_VERSION`, as `BZ2_bzlibVersion()` gives it.
pub(crate) const BZ_VERSION: &str = "1.0.8, 13-Jul-2019";

// The return codes of `bzlib.h`, as numbers, for the code that follows the
// C; the public API turns them into `Status` and `Error`.
pub(crate) const BZ_OK: i32 = 0;
pub(crate) const BZ_RUN_OK: i32 = 1;
pub(crate) const BZ_FLUSH_OK: i32 = 2;
pub(crate) const BZ_FINISH_OK: i32 = 3;
pub(crate) const BZ_STREAM_END: i32 = 4;
pub(crate) const BZ_SEQUENCE_ERROR: i32 = -1;
pub(crate) const BZ_PARAM_ERROR: i32 = -2;
pub(crate) const BZ_MEM_ERROR: i32 = -3;
pub(crate) const BZ_DATA_ERROR: i32 = -4;
pub(crate) const BZ_DATA_ERROR_MAGIC: i32 = -5;

// Header bytes.
pub(crate) const BZ_HDR_B: u8 = 0x42;
pub(crate) const BZ_HDR_Z: u8 = 0x5a;
pub(crate) const BZ_HDR_H: u8 = 0x68;
pub(crate) const BZ_HDR_0: u8 = 0x30;

// Constants for the back end.
pub(crate) const BZ_MAX_ALPHA_SIZE: usize = 258;
pub(crate) const BZ_MAX_CODE_LEN: usize = 23;

pub(crate) const BZ_RUNA: i32 = 0;
pub(crate) const BZ_RUNB: i32 = 1;

pub(crate) const BZ_N_GROUPS: usize = 6;
pub(crate) const BZ_G_SIZE: i32 = 50;
pub(crate) const BZ_N_ITERS: i32 = 4;

pub(crate) const BZ_MAX_SELECTORS: usize = 2 + (900000 / BZ_G_SIZE as usize);

// States and modes for compression.
pub(crate) const BZ_M_IDLE: i32 = 1;
pub(crate) const BZ_M_RUNNING: i32 = 2;
pub(crate) const BZ_M_FLUSHING: i32 = 3;
pub(crate) const BZ_M_FINISHING: i32 = 4;

pub(crate) const BZ_S_OUTPUT: i32 = 1;
pub(crate) const BZ_S_INPUT: i32 = 2;

pub(crate) const BZ_N_RADIX: i32 = 2;
pub(crate) const BZ_N_QSORT: i32 = 12;
pub(crate) const BZ_N_SHELL: i32 = 18;
pub(crate) const BZ_N_OVERSHOOT: i32 = BZ_N_RADIX + BZ_N_QSORT + BZ_N_SHELL + 2;

// States for decompression.
pub(crate) const BZ_X_IDLE: i32 = 1;
pub(crate) const BZ_X_OUTPUT: i32 = 2;

pub(crate) const BZ_X_MAGIC_1: i32 = 10;
pub(crate) const BZ_X_MAGIC_2: i32 = 11;
pub(crate) const BZ_X_MAGIC_3: i32 = 12;
pub(crate) const BZ_X_MAGIC_4: i32 = 13;
pub(crate) const BZ_X_BLKHDR_1: i32 = 14;
pub(crate) const BZ_X_BLKHDR_2: i32 = 15;
pub(crate) const BZ_X_BLKHDR_3: i32 = 16;
pub(crate) const BZ_X_BLKHDR_4: i32 = 17;
pub(crate) const BZ_X_BLKHDR_5: i32 = 18;
pub(crate) const BZ_X_BLKHDR_6: i32 = 19;
pub(crate) const BZ_X_BCRC_1: i32 = 20;
pub(crate) const BZ_X_BCRC_2: i32 = 21;
pub(crate) const BZ_X_BCRC_3: i32 = 22;
pub(crate) const BZ_X_BCRC_4: i32 = 23;
pub(crate) const BZ_X_RANDBIT: i32 = 24;
pub(crate) const BZ_X_ORIGPTR_1: i32 = 25;
pub(crate) const BZ_X_ORIGPTR_2: i32 = 26;
pub(crate) const BZ_X_ORIGPTR_3: i32 = 27;
pub(crate) const BZ_X_MAPPING_1: i32 = 28;
pub(crate) const BZ_X_MAPPING_2: i32 = 29;
pub(crate) const BZ_X_SELECTOR_1: i32 = 30;
pub(crate) const BZ_X_SELECTOR_2: i32 = 31;
pub(crate) const BZ_X_SELECTOR_3: i32 = 32;
pub(crate) const BZ_X_CODING_1: i32 = 33;
pub(crate) const BZ_X_CODING_2: i32 = 34;
pub(crate) const BZ_X_CODING_3: i32 = 35;
pub(crate) const BZ_X_MTF_1: i32 = 36;
pub(crate) const BZ_X_MTF_2: i32 = 37;
pub(crate) const BZ_X_MTF_3: i32 = 38;
pub(crate) const BZ_X_MTF_4: i32 = 39;
pub(crate) const BZ_X_MTF_5: i32 = 40;
pub(crate) const BZ_X_MTF_6: i32 = 41;
pub(crate) const BZ_X_ENDHDR_2: i32 = 42;
pub(crate) const BZ_X_ENDHDR_3: i32 = 43;
pub(crate) const BZ_X_ENDHDR_4: i32 = 44;
pub(crate) const BZ_X_ENDHDR_5: i32 = 45;
pub(crate) const BZ_X_ENDHDR_6: i32 = 46;
pub(crate) const BZ_X_CCRC_1: i32 = 47;
pub(crate) const BZ_X_CCRC_2: i32 = 48;
pub(crate) const BZ_X_CCRC_3: i32 = 49;
pub(crate) const BZ_X_CCRC_4: i32 = 50;

// Constants for the fast MTF decoder.
pub(crate) const MTFA_SIZE: i32 = 4096;
pub(crate) const MTFL_SIZE: i32 = 16;
