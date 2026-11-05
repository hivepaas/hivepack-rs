//! Jobs done in threads, their results taken in the order the jobs were
//! given: 7z's LZMA2 blocks, compressed by the writer and decompressed by a
//! folder's decoder, and ZIP entries compressed ahead of the one written.
//! Not from the LZMA SDK, which has no threads in its 7z decoder, nor from
//! libzip, which has none.
//!
//! Threads are made as jobs wait for them, up to the most allowed, so that
//! what has one job only never makes one. With at most one, each job is done
//! on the caller's thread when it is given.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

/// What a thread does with a job, with what it keeps from one job to the
/// next.
pub(crate) type Work<S, J, O> = fn(&mut S, J) -> O;

/// A job's number, and the job.
type Numbered<T> = (u64, T);

/// Jobs, done in up to `most` threads, their results taken in order.
pub(crate) struct Workers<S, J, O> {
    work: Work<S, J, O>,
    /// What the threads are named.
    name: &'static str,
    /// The result of a job whose thread panicked.
    lost: fn() -> O,
    most: usize,
    /// What the caller's thread keeps, for the jobs it does.
    own: S,
    jobs: Option<Sender<Numbered<J>>>,
    queue: Arc<Mutex<Receiver<Numbered<J>>>>,
    done_tx: Sender<Numbered<Option<O>>>,
    done: Receiver<Numbered<Option<O>>>,
    /// Tells the threads to start no other job.
    stop: Arc<AtomicBool>,
    threads: usize,
    given: u64,
    taken: u64,
    /// Results that came before the one taken next.
    early: BTreeMap<u64, Option<O>>,
}

impl<S, J, O> Workers<S, J, O>
where
    S: Default + Send + 'static,
    J: Send + 'static,
    O: Send + 'static,
{
    /// Jobs done by `work`, in up to `most` threads named `name`.
    pub(crate) fn new(most: u32, name: &'static str, work: Work<S, J, O>, lost: fn() -> O) -> Self {
        let (jobs, queue) = channel();
        let (done_tx, done) = channel();
        Workers {
            work,
            name,
            lost,
            most: most.max(1) as usize,
            own: S::default(),
            jobs: Some(jobs),
            queue: Arc::new(Mutex::new(queue)),
            done_tx,
            done,
            stop: Arc::new(AtomicBool::new(false)),
            threads: 0,
            given: 0,
            taken: 0,
            early: BTreeMap::new(),
        }
    }

    /// The most threads.
    #[cfg_attr(not(feature = "sevenz"), allow(dead_code))]
    pub(crate) fn most(&self) -> usize {
        self.most
    }

    /// The threads made.
    #[cfg(test)]
    pub(crate) fn threads(&self) -> usize {
        self.threads
    }

    /// The jobs given whose results are not taken.
    pub(crate) fn pending(&self) -> usize {
        (self.given - self.taken) as usize
    }

    /// Gives a job to a thread, made if all are busy and there may be more.
    pub(crate) fn give(&mut self, job: J) {
        if self.most <= 1 {
            return self.do_here(job);
        }
        // A thread for each job waiting, up to the most.
        let busy = self.pending() >= self.threads;
        if self.threads < self.most && busy && !self.spawn() && self.threads == 0 {
            return self.do_here(job);
        }
        let number = self.given;
        match &self.jobs {
            Some(jobs) => match jobs.send((number, job)) {
                Ok(()) => self.given += 1,
                Err(back) => self.do_here(back.0.1),
            },
            None => self.do_here(job),
        }
    }

    /// Does a job on the caller's thread, now: for one that has nothing to
    /// gain from another.
    pub(crate) fn do_here(&mut self, job: J) {
        let work = self.work;
        let out = catch_unwind(AssertUnwindSafe(|| work(&mut self.own, job))).ok();
        if out.is_none() {
            self.own = S::default();
        }
        self.early.insert(self.given, out);
        self.given += 1;
    }

    /// Another thread; whether it could be made.
    fn spawn(&mut self) -> bool {
        let queue = Arc::clone(&self.queue);
        let done = self.done_tx.clone();
        let stop = Arc::clone(&self.stop);
        let work = self.work;
        let made = std::thread::Builder::new()
            .name(self.name.into())
            .spawn(move || serve::<S, J, O>(&queue, &done, &stop, work));
        if made.is_ok() {
            self.threads += 1;
        }
        made.is_ok()
    }

    /// The result of the oldest job not taken, waited for; none if every
    /// result is taken.
    pub(crate) fn take(&mut self) -> Option<O> {
        if self.taken == self.given {
            return None;
        }
        loop {
            if let Some(out) = self.early.remove(&self.taken) {
                self.taken += 1;
                return Some(out.unwrap_or_else(self.lost));
            }
            match self.done.recv() {
                Ok((number, out)) => {
                    self.early.insert(number, out);
                }
                // Not while `done_tx` is held.
                Err(_) => {
                    self.taken += 1;
                    return Some((self.lost)());
                }
            }
        }
    }
}

/// A thread's loop: jobs until there are none, or it is told to stop. A job
/// that panics is given back as none, what the thread kept dropped.
fn serve<S: Default, J, O>(
    queue: &Mutex<Receiver<Numbered<J>>>,
    done: &Sender<Numbered<Option<O>>>,
    stop: &AtomicBool,
    work: Work<S, J, O>,
) {
    let mut state = S::default();
    loop {
        let next = {
            let queue = queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            queue.recv()
        };
        let Ok((number, job)) = next else {
            return;
        };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let out = catch_unwind(AssertUnwindSafe(|| work(&mut state, job))).ok();
        if out.is_none() {
            state = S::default();
        }
        if done.send((number, out)).is_err() {
            return;
        }
    }
}

/// The threads end once the job each is on is done, without being waited
/// for: what they make is no longer wanted.
impl<S, J, O> Drop for Workers<S, J, O> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.jobs = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn square(count: &mut u32, n: u64) -> (u64, u32) {
        *count += 1;
        if n == 13 {
            #[allow(clippy::panic)]
            {
                panic!("thirteen");
            }
        }
        (n * n, *count)
    }

    fn lost() -> (u64, u32) {
        (u64::MAX, 0)
    }

    #[test]
    fn in_order_whatever_the_threads() {
        for most in [1, 2, 8] {
            let mut workers = Workers::new(most, "test", square, lost);
            let mut got = Vec::new();
            for n in 0..40u64 {
                workers.give(n);
                if workers.pending() >= workers.most() {
                    got.extend(workers.take().map(|(sq, _)| sq));
                }
            }
            while let Some((sq, _)) = workers.take() {
                got.push(sq);
            }
            let want: Vec<u64> = (0..40u64)
                .map(|n| if n == 13 { u64::MAX } else { n * n })
                .collect();
            assert_eq!(got, want, "{most} threads");
            assert!(workers.threads <= most as usize);
        }
    }

    #[test]
    fn one_job_makes_no_thread() {
        let mut workers = Workers::new(8, "test", square, lost);
        workers.do_here(3);
        assert_eq!(workers.take(), Some((9, 1)));
        assert_eq!(workers.take(), None);
        assert_eq!(workers.threads, 0);
    }
}
