//! How much memory the program may still take, and a budget to choose the
//! threads of coders under it.
//!
//! Each coder of hivepack that uses threads takes a limit on its memory, and
//! tells what a number of threads takes (see `docs/memory.md`); what it does
//! not know is how much there is to take. [`available`] measures it: the
//! memory the system has free now, and no more than what the limits put on
//! the program leave it, with the bound that applied. A [`Budget`] shares a
//! part of it between the jobs that run at once: each asks for the most
//! threads whose memory fits what is left ([`Budget::hold_threads`]), and
//! holds that memory until it is done.
//!
//! Nothing in hivepack calls this module: an application measures, chooses
//! the part it gives its jobs (packwing gives half of what is available),
//! and hands the threads and bytes to its coders. `docs/memory.md` has an
//! example for each coder.
//!
//! What is measured, by system:
//!
//! | System | [`Bound::System`] | Other bounds |
//! |---|---|---|
//! | Linux | `MemAvailable` in `/proc/meminfo` | [`Bound::ControlGroup`]: each control group the program is in, from its own up, that has a limit (`memory.max`, or version 1's `memory.limit_in_bytes`), less what the group holds of it, its page cache that can be dropped left out; [`Bound::Ulimit`]: `ulimit -v` and `ulimit -d` (`RLIMIT_AS`, `RLIMIT_DATA`), less what the program holds of each |
//! | Windows | the available physical memory (`GlobalMemoryStatusEx`) | [`Bound::JobObject`]: the limits of the job object the program is in, for each process (less what it has committed) and for the job (less the most it has committed) |
//! | macOS | the pages free, holding files' data, or purgeable (`host_statistics64`) | none: macOS puts no limit on an app's memory, and compresses and swaps short of it |
//!
//! Other systems are not measured: [`available`] is `None` there.
//!
//! ```
//! use hivepack::memory::{self, Budget};
//!
//! // Half of what is available now: the application's choice.
//! let budget = Budget::of_available(1, 2).unwrap_or_else(|| Budget::new(1 << 30));
//! // A coder that takes 100 MiB, and 20 MiB for each thread.
//! let need = |threads: u32| (100 << 20) + u64::from(threads) * (20 << 20);
//! let (threads, held) = budget.hold_threads(8, need);
//! assert!((1..=8).contains(&threads));
//! assert!(held.bytes() >= need(threads));
//! // The coder runs with `threads`, under a limit of `held.bytes()`;
//! // what is held is given back when `held` is dropped.
//! drop(held);
//! assert_eq!(budget.held(), 0);
//! # let _ = memory::available();
//! ```
//!
//! The system calls behind [`available`] take `unsafe` code on Windows and
//! macOS, in `windows.rs` and `macos.rs`, each call with what makes it sound
//! (`docs/unsafe.md`). The rest of the module, Linux's measures included,
//! forbids it.

mod budget;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub use budget::{Budget, Held};

/// What bounded the figure [`available`] gave: the least of all that apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bound {
    /// The memory the system has free, or can free without swapping.
    System,
    /// A Linux control group's limit, of the program's own group or of one
    /// it is in: a container's, or systemd's (a slice's or a scope's
    /// `MemoryMax=`).
    ControlGroup,
    /// `ulimit -v` or `ulimit -d`: the limit on the program's address space
    /// or on its data.
    Ulimit,
    /// The limits of the Windows job object the program is in, for each of
    /// its processes or for all of them.
    JobObject,
}

/// How much memory the program may still take, as [`available`] measures it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Available {
    /// The bytes it may still take now.
    pub bytes: u64,
    /// What bounded them.
    pub bound: Bound,
    /// The bytes each thread more takes of what is bounded, besides what it
    /// allocates: under `ulimit -v` on Linux, a thread's stack (2 MiB, Rust's
    /// default) and the arena glibc's allocator may reserve for it (64 MiB
    /// on 64-bit systems, 1 MiB on 32-bit ones; none with other C
    /// libraries); under `ulimit -d` alone, its stack. 0 elsewhere, where the
    /// pages a thread does not touch take nothing. [`Budget::of_available`]
    /// counts it for each thread.
    pub thread_overhead: u64,
}

/// How much memory the program may still take now: the least of what the
/// system has free and of what each limit put on the program leaves it, and
/// which of them that is. `None` on a system it is not measured on, or where
/// nothing could be read (Linux without `/proc`). See the
/// [module](self)'s table for what each system counts.
///
/// It is measured each time, and changes with what the program and others
/// take. Memory the program has taken and freed may stay with its allocator,
/// and is not counted as available again.
pub fn available() -> Option<Available> {
    #[cfg(target_os = "linux")]
    return linux::available();
    #[cfg(target_os = "macos")]
    return macos::available();
    #[cfg(windows)]
    return windows::available();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return None;
}

/// The least of `figures`, the first of equals: the system's, given first,
/// stays the bound unless a limit is below it.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
fn least(figures: impl IntoIterator<Item = Option<(u64, Bound)>>) -> Option<(u64, Bound)> {
    figures
        .into_iter()
        .flatten()
        .fold(None, |least, (bytes, bound)| match least {
            Some((l, _)) if l <= bytes => least,
            _ => Some((bytes, bound)),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_least_and_the_first_of_equals() {
        assert_eq!(least([]), None);
        assert_eq!(least([None, None]), None);
        assert_eq!(
            least([Some((8, Bound::System)), None, Some((5, Bound::Ulimit))]),
            Some((5, Bound::Ulimit))
        );
        assert_eq!(
            least([Some((5, Bound::System)), Some((5, Bound::ControlGroup))]),
            Some((5, Bound::System))
        );
    }

    #[test]
    fn something_is_available_where_it_is_measured() {
        let measured = available();
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            let measured = measured.expect("measured");
            assert!(measured.bytes > 0, "{measured:?}");
        } else {
            assert_eq!(measured, None);
        }
    }
}
