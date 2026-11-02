//! `PREFETCH_L1` of `common/compiler.h`: a hint that a piece of a table is
//! about to be read, so that the processor brings it into its first-level
//! cache meanwhile. Only the encoder's row match finder uses it, where
//! libzstd does (`zstd_lazy.c`).
//!
//! With the `unsafe-fast` feature, on aarch64 and x86-64, it is the
//! instruction libzstd's macro gives there: `prfm pldl1keep` and
//! `prefetcht0`. Elsewhere, and without the feature, it does nothing, and
//! [`PREFETCH`] is false: the match finder then keeps the order of work that
//! is faster without it. This module's two blocks are the encoder's only
//! `unsafe` code. See `docs/unsafe.md`.
//!
//! Stable Rust has no safe prefetch: `core::arch`'s and inline assembly
//! need `unsafe`, and `std::hint::prefetch_read`, which does not, is still
//! unstable (`hint_prefetch`).

#![cfg_attr(feature = "zstd-unsafe-fast", allow(unsafe_code))]

/// Whether [`prefetch_l1`] prefetches.
pub(crate) const PREFETCH: bool = cfg!(all(
    feature = "zstd-unsafe-fast",
    not(miri),
    any(target_arch = "aarch64", target_arch = "x86_64")
));

/// `PREFETCH_L1(table + at)`: the cache line of `table[at]` brought into the
/// first-level cache, where [`PREFETCH`] is true. `at` may be past the end
/// of `table`: nothing is read.
#[inline(always)]
pub(crate) fn prefetch_l1<T>(table: &[T], at: usize) {
    // The address only: computing it reads nothing, and is safe.
    let address = table.as_ptr().wrapping_add(at);
    // `nomem`: the hint reads nothing the program sees, and may move.
    #[cfg(all(feature = "zstd-unsafe-fast", not(miri), target_arch = "aarch64"))]
    #[allow(clippy::pointers_in_nomem_asm_block)]
    // SAFETY: `prfm` is a hint. It reads nothing into a register, writes
    // nothing, and never faults, whatever the address, mapped or not
    // (Arm Architecture Reference Manual, "Prefetch memory": a PRFM to an
    // address that would fault does nothing). It touches no register but
    // its operand, and neither the stack nor the flags.
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{address}]",
            address = in(reg) address,
            options(nostack, nomem, preserves_flags),
        );
    }
    #[cfg(all(feature = "zstd-unsafe-fast", not(miri), target_arch = "x86_64"))]
    // SAFETY: `prefetcht0` is a hint too, which never faults, whatever the
    // address (Intel SDM, PREFETCHh: "does not affect program behavior").
    // `_mm_prefetch` is `unsafe` for its raw pointer only; the SSE it needs
    // is always there on x86-64.
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(
            address.cast::<i8>(),
        );
    }
    #[cfg(not(all(
        feature = "zstd-unsafe-fast",
        not(miri),
        any(target_arch = "aarch64", target_arch = "x86_64")
    )))]
    let _ = address;
}

#[cfg(test)]
mod tests {
    use super::prefetch_l1;

    /// A prefetch takes any address, in the table, past its end, far past
    /// it, or wrapped around, and changes nothing.
    #[test]
    fn prefetches_take_any_address() {
        let table = [7u32; 16];
        for at in [
            0,
            15,
            16,
            1 << 20,
            usize::MAX >> 12,
            usize::MAX / 8,
            usize::MAX,
        ] {
            prefetch_l1(&table, at);
        }
        prefetch_l1::<u8>(&[], 1 << 30);
        assert_eq!(table, [7; 16]);
    }
}
