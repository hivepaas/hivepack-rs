//! macOS: the pages the system has free, holding files' data, or
//! purgeable, as Activity Monitor counts the memory not used.
//!
//! macOS puts no limit on an app's memory as Linux's control groups and
//! Windows' job objects do, and does not enforce `ulimit -v`: short of
//! memory, it compresses pages and swaps them out. So the system's figure
//! is the only one; the app's own memory, compressed or swapped, can still
//! grow past it, slower.
//!
//! The calls to the system take `unsafe` code, each with what makes it
//! sound: they are given the host's port, and a struct of the system's own
//! type, whose size in integers is given with it. See `docs/unsafe.md`.

#![allow(unsafe_code)]

use std::sync::OnceLock;

use super::{Available, Bound};

pub(super) fn available() -> Option<Available> {
    let bytes = pages_available()?;
    Some(Available {
        bytes,
        bound: Bound::System,
        thread_overhead: 0,
    })
}

/// The host's port, asked for once: each call adds a reference to it.
// libc points to the mach2 crate for `mach_host_self`, which declares the
// same function.
#[allow(deprecated)]
fn host() -> libc::mach_port_t {
    static HOST: OnceLock<libc::mach_port_t> = OnceLock::new();
    // SAFETY: no arguments; it returns a send right to the host's port, or
    // MACH_PORT_NULL, which `host_statistics64` refuses.
    *HOST.get_or_init(|| unsafe { libc::mach_host_self() })
}

/// Free pages, file-backed pages (`external_page_count`: files' data,
/// which the system drops before it compresses anything) and purgeable
/// ones (which apps marked as theirs to lose), in bytes. Speculative pages,
/// read ahead from files, are counted in the free ones already. Inactive
/// pages of apps are not counted: to take them, the system compresses or
/// swaps them.
fn pages_available() -> Option<u64> {
    // SAFETY: a struct of integers, for which all zeros is a valid value.
    let mut stat: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    // SAFETY: the host's port; a vm_statistics64 to write, and its size in
    // integers, as HOST_VM_INFO64 takes them. An older system writes fewer
    // fields, and says how many in `count`.
    let got = unsafe {
        libc::host_statistics64(
            host(),
            libc::HOST_VM_INFO64,
            (&raw mut stat).cast(),
            &mut count,
        )
    };
    if got != libc::KERN_SUCCESS {
        return None;
    }
    // SAFETY: a name the system knows, which reads a number.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = u64::try_from(page).ok().filter(|&page| page > 0)?;
    let pages = u64::from(stat.free_count)
        + u64::from(stat.external_page_count)
        + u64::from(stat.purgeable_count);
    Some(pages.saturating_mul(page))
}
