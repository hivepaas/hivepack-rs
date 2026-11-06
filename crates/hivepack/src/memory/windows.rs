//! Windows: the available physical memory, and what the limits of the job
//! object the program is in leave it.
//!
//! The calls to the system take `unsafe` code, each with what makes it
//! sound: they are given the current process's pseudo-handle, no handle
//! (the program's own job), and structs of the system's own types, whose
//! sizes are given with them. See `docs/unsafe.md`.

#![allow(unsafe_code)]

use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::{Available, Bound, least};

pub(super) fn available() -> Option<Available> {
    let system = system_available().map(|bytes| (bytes, Bound::System));
    let job = job_left().map(|bytes| (bytes, Bound::JobObject));
    let (bytes, bound) = least([system, job])?;
    // A thread's stack is reserved, not committed: the job's limits count
    // what is committed, a few pages of it.
    Some(Available {
        bytes,
        bound,
        thread_overhead: 0,
    })
}

/// The physical memory available now (`ullAvailPhys`): free, and on the
/// standby list, which the system gives back without paging anything out.
fn system_available() -> Option<u64> {
    let size = u32::try_from(size_of::<MEMORYSTATUSEX>()).ok()?;
    let mut status = MEMORYSTATUSEX {
        dwLength: size,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    // SAFETY: a MEMORYSTATUSEX to write, its size in `dwLength` as the call
    // asks.
    let got = unsafe { GlobalMemoryStatusEx(&mut status) };
    (got != 0).then_some(status.ullAvailPhys)
}

/// What the program may still take under its job object's limits: the
/// least of what the limit for each process leaves this one (less what it
/// has committed, `PrivateUsage`), and what the limit for the job leaves
/// its processes (less the most they have committed at once, no less than
/// what they hold). `None` outside a job, or where it has no limit on
/// memory. A job the program's job is in is not read: Windows tells only
/// the program's own.
fn job_left() -> Option<u64> {
    let mut in_job = 0;
    // SAFETY: the current process's pseudo-handle, which needs no closing;
    // no job handle, for any job; and a BOOL to write.
    let asked = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) };
    if asked == 0 || in_job == 0 {
        return None;
    }
    // SAFETY: a struct of integers, for which all zeros is a valid value.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).ok()?;
    // SAFETY: no handle is the job of the calling process; the struct is
    // the class's, of the size given, and no length is asked back.
    let read = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            size,
            std::ptr::null_mut(),
        )
    };
    if read == 0 {
        return None;
    }
    let flags = info.BasicLimitInformation.LimitFlags;
    let process = (flags & JOB_OBJECT_LIMIT_PROCESS_MEMORY != 0).then(|| {
        let committed = committed().unwrap_or(0);
        info.ProcessMemoryLimit.saturating_sub(committed) as u64
    });
    let job = (flags & JOB_OBJECT_LIMIT_JOB_MEMORY != 0)
        .then(|| info.JobMemoryLimit.saturating_sub(info.PeakJobMemoryUsed) as u64);
    match (process, job) {
        (Some(p), Some(j)) => Some(p.min(j)),
        (p, j) => p.or(j),
    }
}

/// The memory this process has committed (`PrivateUsage`), which the job's
/// limit for each process counts.
fn committed() -> Option<usize> {
    // SAFETY: a struct of integers, for which all zeros is a valid value.
    let mut counters: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS_EX>()).ok()?;
    counters.cb = size;
    // SAFETY: the current process's pseudo-handle, and the extended
    // counters, which the call takes in place of the plain ones when their
    // size says so.
    let got = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&raw mut counters).cast::<PROCESS_MEMORY_COUNTERS>(),
            size,
        )
    };
    (got != 0).then_some(counters.PrivateUsage)
}
