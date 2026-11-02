//! Port of `common/pool.c`: the pool of worker threads that multithreaded
//! compression hands its jobs to. `common/threading.c`, libzstd's wrapper
//! over pthreads and Windows threads, is `std::thread` and `std::sync`.
//!
//! Only what `zstdmt_compress.c` uses: a pool made for a number of
//! threads (`POOL_create_advanced`, with a queue of size 0), resized
//! (`POOL_resize`), given a job only when a thread is free to take it
//! (`POOL_tryAdd`), and freed once its jobs are done (`POOL_free`). Shared
//! between contexts, it is `ZSTD_threadPool`
//! ([`ThreadPool`](crate::zstd::ThreadPool)).
//!
//! Differs from libzstd: libzstd's queue of size 0 is a ring of one slot;
//! here a queue that holds at most one job for the same reason. A job is a
//! value the pool's function runs, as libzstd's is the argument of its
//! function pointer, and a job refused comes back to the caller.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use crate::zstd::common::error_private::{Result, error};

/// The pool's state, behind its mutex (`queueMutex`).
struct PoolState<J> {
    /// The jobs added and not taken yet (`queue`): at most one.
    queue: VecDeque<J>,
    /// `numThreadsBusy`: the threads running a job.
    busy: usize,
    /// `threadLimit`: how many threads may run jobs; the pool may have
    /// more, left over from a larger size.
    thread_limit: usize,
    /// `shutdown`: the pool is being freed.
    shutdown: bool,
}

/// What the pool and its threads share.
struct PoolShared<J> {
    state: Mutex<PoolState<J>>,
    /// `queuePopCond`: signaled when a job is added, when a thread is free
    /// again, and at shutdown.
    pop_cond: Condvar,
    /// `POOL_function`: what runs a job.
    function: fn(J, BusyTicket<J>),
}

impl<J> PoolShared<J> {
    fn lock(&self) -> MutexGuard<'_, PoolState<J>> {
        // A thread that panicked while holding the lock leaves the state
        // consistent: every change under it is a single assignment.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What a job holds while its thread counts as busy: the thread is free
/// again for the pool once the ticket is released, or dropped.
///
/// Differs from libzstd: libzstd's thread marks itself free once the job
/// function has returned, just after the job has signaled that it is
/// done; here the job lets its thread go first (see
/// [`BusyTicket::release`]), so that the caller, told the job is done,
/// finds a thread free for the next one instead of trying again until the
/// thread gets there. Only which call hands the next job over changes, not
/// the jobs.
pub(crate) struct BusyTicket<J> {
    shared: Option<Arc<PoolShared<J>>>,
}

impl<J> BusyTicket<J> {
    /// The thread is free for the next job from now on.
    pub(crate) fn release(&mut self) {
        if let Some(shared) = self.shared.take() {
            let mut state = shared.lock();
            state.busy -= 1;
            // A job may wait for a thread.
            shared.pop_cond.notify_one();
        }
    }
}

impl<J> Drop for BusyTicket<J> {
    fn drop(&mut self) {
        self.release();
    }
}

/// `POOL_ctx`: worker threads, and the job waiting for one.
pub(crate) struct Pool<J: Send + 'static> {
    shared: Arc<PoolShared<J>>,
    /// `threads`: every thread made, `threadCapacity` of them; behind a
    /// mutex of its own, for a pool that contexts share and resize.
    threads: Mutex<Vec<JoinHandle<()>>>,
}

/// `POOL_thread`: takes the jobs added, one at a time, while the pool
/// allows this thread to run one; ends at shutdown, once no job is left
/// that it may take.
fn pool_thread<J>(shared: &Arc<PoolShared<J>>) {
    loop {
        let job = {
            let mut state = shared.lock();
            // Wait for a job, and for the pool to allow one more thread.
            while state.queue.is_empty() || state.busy >= state.thread_limit {
                if state.shutdown {
                    // Even with a job left: enough threads stay to run it.
                    return;
                }
                state = shared
                    .pop_cond
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            let Some(job) = state.queue.pop_front() else {
                continue;
            };
            state.busy += 1;
            job
        };
        (shared.function)(
            job,
            BusyTicket {
                shared: Some(shared.clone()),
            },
        );
    }
}

impl<J: Send + 'static> Pool<J> {
    /// `POOL_create_advanced(numThreads, 0, ...)`: a pool of `num_threads`
    /// threads, at least one, started at once, whose jobs `function` runs.
    /// Fails with `MemoryAllocation` when a thread cannot be started, as
    /// libzstd fails to make the pool.
    pub(crate) fn new(num_threads: usize, function: fn(J, BusyTicket<J>)) -> Result<Pool<J>> {
        let pool = Pool {
            shared: Arc::new(PoolShared {
                state: Mutex::new(PoolState {
                    queue: VecDeque::new(),
                    busy: 0,
                    thread_limit: 0,
                    shutdown: false,
                }),
                pop_cond: Condvar::new(),
                function,
            }),
            threads: Mutex::new(Vec::new()),
        };
        pool.resize(num_threads)?;
        Ok(pool)
    }

    /// `POOL_resize`: `num_threads` threads allowed to run jobs; more made
    /// if the pool has fewer, none stopped if it has more.
    pub(crate) fn resize(&self, num_threads: usize) -> Result<()> {
        let num_threads = num_threads.max(1);
        let mut threads = self.threads.lock().unwrap_or_else(PoisonError::into_inner);
        while threads.len() < num_threads {
            let shared = self.shared.clone();
            let thread = std::thread::Builder::new()
                .name("hivepack-zstd".into())
                .spawn(move || pool_thread(&shared));
            match thread {
                Ok(thread) => threads.push(thread),
                Err(_) => return error!(MemoryAllocation),
            }
        }
        let mut state = self.shared.lock();
        state.thread_limit = num_threads;
        // Threads beyond the old limit may now take a job waiting.
        self.shared.pop_cond.notify_all();
        Ok(())
    }

    /// `POOL_tryAdd`: hands `job` over if a thread is free to run it at
    /// once (`isQueueFull` with a queue of size 0: no thread free, or a
    /// job waiting already); gives it back otherwise.
    pub(crate) fn try_add(&self, job: J) -> core::result::Result<(), J> {
        let mut state = self.shared.lock();
        if state.busy >= state.thread_limit || !state.queue.is_empty() {
            return Err(job);
        }
        state.queue.push_back(job);
        self.shared.pop_cond.notify_one();
        Ok(())
    }
}

impl<J: Send + 'static> Drop for Pool<J> {
    /// `POOL_free`: shuts the threads down once the jobs added are taken,
    /// and waits for them to end.
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.shutdown = true;
        }
        self.shared.pop_cond.notify_all();
        let threads = self
            .threads
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        for thread in threads.drain(..) {
            // A thread that panicked has nothing more to clean up.
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BusyTicket, Pool};
    use std::sync::{Arc, Barrier};

    type Job = (Arc<Barrier>, Arc<std::sync::atomic::AtomicUsize>);

    fn run((gate, ran): Job, _ticket: BusyTicket<Job>) {
        gate.wait();
        ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn jobs_go_to_free_threads_only() {
        let pool = Pool::new(2, run).expect("a pool");
        let gate = Arc::new(Barrier::new(3));
        let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..2 {
            let mut job = (gate.clone(), ran.clone());
            // A job waiting in the queue refuses the next one, until a
            // thread takes it.
            while let Err(refused) = pool.try_add(job) {
                job = refused;
                std::thread::yield_now();
            }
        }
        // Both threads are busy, or a job waits: the third is refused.
        assert!(pool.try_add((gate.clone(), ran.clone())).is_err());
        gate.wait();
        drop(pool);
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
