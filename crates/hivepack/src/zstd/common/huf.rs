//! Huffman coding constants: port of the parts of `common/huf.h` the port
//! needs so far.

/// `HUF_BLOCKSIZE_MAX`: the largest input of one Huffman-compressed block.
pub(crate) const HUF_BLOCKSIZE_MAX: usize = 128 * 1024;
/// `HUF_TABLELOG_MAX`: the largest table log at run time.
pub(crate) const HUF_TABLELOG_MAX: u32 = 12;
/// `HUF_TABLELOG_DEFAULT`
pub(crate) const HUF_TABLELOG_DEFAULT: u32 = 11;
/// `HUF_SYMBOLVALUE_MAX`
pub(crate) const HUF_SYMBOLVALUE_MAX: u32 = 255;
/// `HUF_TABLELOG_ABSOLUTEMAX`
pub(crate) const HUF_TABLELOG_ABSOLUTEMAX: u32 = 12;

/// `HUF_flags_e`: options of the Huffman functions, as bits.
///
/// The port behaves as libzstd does on a 64-bit little-endian machine whose
/// processor libzstd's builds use fully (BMI2 on x86-64): only
/// [`HUF_FLAGS_DISABLE_FAST`] changes what decoding does. The others are
/// accepted and have no effect on results.
pub(crate) const HUF_FLAGS_BMI2: i32 = 1 << 0;
/// `HUF_flags_optimalDepth` (compression)
pub(crate) const HUF_FLAGS_OPTIMAL_DEPTH: i32 = 1 << 1;
/// `HUF_flags_preferRepeat` (compression)
pub(crate) const HUF_FLAGS_PREFER_REPEAT: i32 = 1 << 2;
/// `HUF_flags_suspectUncompressible` (compression)
pub(crate) const HUF_FLAGS_SUSPECT_UNCOMPRESSIBLE: i32 = 1 << 3;
/// `HUF_flags_disableAsm`: libzstd's assembly loop and its C fast loop give
/// the same results, and the port has only the latter.
pub(crate) const HUF_FLAGS_DISABLE_ASM: i32 = 1 << 4;
/// `HUF_flags_disableFast`: decode 4-stream blocks without the fast loop.
pub(crate) const HUF_FLAGS_DISABLE_FAST: i32 = 1 << 5;
