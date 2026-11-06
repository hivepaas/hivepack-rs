//! On Windows, in a job object that lets each of its processes take
//! 600 MB, `hivepack::memory::available` is no more than that, and bound
//! by the job. Alone in its file, as the test puts its own process in the
//! job, for good.

#![cfg(windows)]
// The helper outside the #[test] function expects too: a failure there is
// a test failure.
#![allow(clippy::expect_used)]
// The job object is made and joined through the system's calls: `unsafe`
// in a test, outside the library.
#![allow(unsafe_code)]

use hivepack::memory::{self, Bound, Budget};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

const LIMIT: usize = 600 << 20;

/// Puts this process in a new job whose processes may each take `bytes`.
fn into_a_job_of(bytes: usize) {
    // SAFETY: no attributes, no name.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    assert!(!job.is_null(), "a job object");
    // SAFETY: a struct of integers, for which all zeros is a valid value.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.ProcessMemoryLimit = bytes;
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).expect("its size");
    // SAFETY: the job just made, and the class's struct and its size.
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            size,
        )
    };
    assert_ne!(set, 0, "the job's limit");
    // SAFETY: the job, and this process's pseudo-handle.
    let assigned = unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) };
    assert_ne!(assigned, 0, "this process in the job");
}

#[test]
fn in_a_job_no_more_than_its_limit() {
    let before = memory::available().expect("measured");
    into_a_job_of(LIMIT);
    let available = memory::available().expect("measured");
    assert!(
        available.bytes > 0 && available.bytes < LIMIT as u64,
        "{available:?}"
    );
    if before.bytes > LIMIT as u64 {
        assert_eq!(available.bound, Bound::JobObject, "{available:?}");
    }
    assert_eq!(available.thread_overhead, 0);
    // A budget of half of it holds no more than that for threads that fit.
    let budget = Budget::of_available(1, 2).expect("measured");
    assert!(budget.bytes() <= LIMIT as u64 / 2);
    let (threads, held) = budget.hold_threads(64, |n| u64::from(n) * (20 << 20));
    assert!((1..=15).contains(&threads), "{threads}");
    assert!(held.bytes() <= budget.bytes());
}
