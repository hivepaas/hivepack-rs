//! A budget of memory shared between jobs, and what each holds of it.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Memory shared between the jobs that run at once, to choose their threads
/// under it: each takes the most threads whose memory fits what is left
/// ([`Budget::hold_threads`]), and holds that memory until it is done.
///
/// A budget is a handle: its clones share one account, so it can be given
/// to each job, or put in a `static`, an `Arc` or a field. A job's [`Held`]
/// gives its memory back when it is dropped, from any thread.
///
/// It counts what the jobs say they need, from the coders' estimates, not
/// what they take: as the estimates are upper bounds, jobs at once take no
/// more than the budget, and each of them less than it holds. What else the
/// program takes is not counted: give the jobs a part of what is available,
/// not all of it.
#[derive(Clone)]
pub struct Budget {
    account: Arc<Mutex<Account>>,
}

#[derive(Debug)]
struct Account {
    /// The budget's bytes.
    bytes: u64,
    /// What the jobs hold of it now.
    held: u64,
    /// What each thread takes besides what a job says it needs.
    thread_overhead: u64,
}

impl Budget {
    /// A budget of `bytes`, none of it held.
    pub fn new(bytes: u64) -> Budget {
        Budget {
            account: Arc::new(Mutex::new(Account {
                bytes,
                held: 0,
                thread_overhead: 0,
            })),
        }
    }

    /// A budget of `numerator / denominator` of what is
    /// [available](super::available) now, with its threads' overhead
    /// ([`Available::thread_overhead`](super::Available::thread_overhead)):
    /// `Budget::of_available(1, 2)` is half of it. `None` where nothing is
    /// measured, or `denominator` is 0.
    pub fn of_available(numerator: u64, denominator: u64) -> Option<Budget> {
        if denominator == 0 {
            return None;
        }
        let available = super::available()?;
        let part = u128::from(available.bytes) * u128::from(numerator) / u128::from(denominator);
        let bytes = u64::try_from(part).unwrap_or(u64::MAX);
        Some(Budget::new(bytes).with_thread_overhead(available.thread_overhead))
    }

    /// The same budget, each thread counted as taking `bytes` more than a
    /// job says it needs: what a thread takes of a bound that counts what
    /// it reserves, as `ulimit -v` counts its stack. 0 by default.
    pub fn with_thread_overhead(self, bytes: u64) -> Budget {
        self.lock().thread_overhead = bytes;
        self
    }

    /// The budget's bytes.
    pub fn bytes(&self) -> u64 {
        self.lock().bytes
    }

    /// Sets the budget's bytes, as measured again, for one that lasts. What
    /// is held stays held, and is given back as before.
    pub fn set_bytes(&self, bytes: u64) {
        self.lock().bytes = bytes;
    }

    /// What the jobs hold of it now.
    pub fn held(&self) -> u64 {
        self.lock().held
    }

    /// What is left of it now, for the next job: 0 where what is held is
    /// more.
    pub fn left(&self) -> u64 {
        let account = self.lock();
        account.bytes.saturating_sub(account.held)
    }

    /// The most threads, `wanted` or fewer, whose memory fits what is left
    /// of the budget, and that memory, held until the [`Held`] is dropped.
    /// `need(n)` is the memory of `n` threads, a coder's estimate: it must
    /// not shrink as `n` grows, as none of hivepack's do. Each thread is
    /// counted with its overhead ([`Budget::with_thread_overhead`]) besides.
    ///
    /// One thread is always given, holding what it needs, even where that
    /// is more than is left, as the coders allow one under their limits:
    /// what to do where one does not fit (wait, lower a level, refuse the
    /// job) is the caller's to choose, which [`Budget::left`] tells
    /// beforehand. `wanted` of 0 is taken for 1.
    pub fn hold_threads(&self, wanted: u32, need: impl Fn(u32) -> u64) -> (u32, Held) {
        let mut account = self.lock();
        let overhead = account.thread_overhead;
        let need = |n: u32| need(n).saturating_add(u64::from(n).saturating_mul(overhead));
        let left = account.bytes.saturating_sub(account.held);
        let threads = threads_within(wanted, left, &need);
        let bytes = need(threads);
        account.held = account.held.saturating_add(bytes);
        drop(account);
        let held = Held {
            bytes,
            account: Arc::clone(&self.account),
        };
        (threads, held)
    }

    /// `bytes` held, if they fit what is left of the budget, until the
    /// [`Held`] is dropped: for memory a job takes a piece at a time, each
    /// given back as it is done with, where [`Budget::hold_threads`] holds what
    /// its threads need for all of it at once. `None` where they do not fit,
    /// and nothing held then: the job waits for its own pieces to be given
    /// back, or goes on without one more.
    pub fn try_hold(&self, bytes: u64) -> Option<Held> {
        let mut account = self.lock();
        let left = account.bytes.saturating_sub(account.held);
        if bytes > left {
            return None;
        }
        account.held = account.held.saturating_add(bytes);
        drop(account);
        Some(Held {
            bytes,
            account: Arc::clone(&self.account),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Account> {
        lock(&self.account)
    }
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let account = self.lock();
        f.debug_struct("Budget")
            .field("bytes", &account.bytes)
            .field("held", &account.held)
            .field("thread_overhead", &account.thread_overhead)
            .finish()
    }
}

/// The account, whose numbers stay whole even if a thread panicked holding
/// it: each change to it is one assignment.
fn lock(account: &Mutex<Account>) -> MutexGuard<'_, Account> {
    account.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The most threads, `wanted` or fewer, whose `need` is within `left`; one
/// if none is.
fn threads_within(wanted: u32, left: u64, need: &dyn Fn(u32) -> u64) -> u32 {
    // What threads need grows with their number: the most that fit are
    // found by halving.
    let (mut fits, mut over) = (1u32, u64::from(wanted.max(1)) + 1);
    while over - u64::from(fits) > 1 {
        let mid = fits + u32::try_from((over - u64::from(fits)) / 2).unwrap_or(0);
        if need(mid) <= left {
            fits = mid;
        } else {
            over = u64::from(mid);
        }
    }
    fits
}

/// Memory a job holds of a [`Budget`], given back when it is dropped.
#[must_use = "the memory is given back when this is dropped"]
pub struct Held {
    bytes: u64,
    account: Arc<Mutex<Account>>,
}

impl Held {
    /// The bytes held: what the threads given need, with their overhead.
    /// A coder's limit takes it, as `memory_limit`.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut account = lock(&self.account);
        account.held = account.held.saturating_sub(self.bytes);
    }
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Held").field("bytes", &self.bytes).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn as_many_threads_as_fit_and_never_none() {
        let need = |n: u32| 100 * MIB + u64::from(n) * 200 * MIB;
        assert_eq!(threads_within(32, 1100 * MIB, &need), 5);
        assert_eq!(threads_within(4, 1100 * MIB, &need), 4);
        assert_eq!(threads_within(5, 1100 * MIB, &need), 5);
        assert_eq!(threads_within(6, 1100 * MIB, &need), 5);
        assert_eq!(threads_within(32, 10 * MIB, &need), 1);
        assert_eq!(threads_within(0, 10_000 * MIB, &need), 1);
        assert_eq!(threads_within(1, u64::MAX, &need), 1);
        assert_eq!(threads_within(u32::MAX, u64::MAX, &|_| 0), u32::MAX);
        assert_eq!(threads_within(u32::MAX, 0, &|n| u64::from(n)), 1);
        // Steps, as zstd's job table grows by powers of 2.
        let steps = |n: u32| u64::from(n.next_power_of_two()) * MIB;
        assert_eq!(threads_within(100, 16 * MIB, &steps), 16);
        assert_eq!(threads_within(100, 31 * MIB, &steps), 16);
    }

    #[test]
    fn holds_what_its_threads_need_and_gives_it_back() {
        let budget = Budget::new(1000 * MIB);
        let need = |n: u32| u64::from(n) * 300 * MIB;
        let (threads, a) = budget.hold_threads(8, need);
        assert_eq!((threads, a.bytes()), (3, 900 * MIB));
        assert_eq!((budget.held(), budget.left()), (900 * MIB, 100 * MIB));
        // Too little is left for one: one is given all the same.
        let (threads, b) = budget.hold_threads(8, need);
        assert_eq!((threads, b.bytes()), (1, 300 * MIB));
        assert_eq!((budget.held(), budget.left()), (1200 * MIB, 0));
        drop(a);
        assert_eq!(budget.held(), 300 * MIB);
        let (threads, c) = budget.hold_threads(8, need);
        assert_eq!(threads, 2);
        drop((b, c));
        assert_eq!(budget.held(), 0);
        assert_eq!(budget.hold_threads(0, need).0, 1);
        assert_eq!(budget.held(), 0);
    }

    #[test]
    fn counts_each_threads_overhead() {
        let budget = Budget::new(1000 * MIB).with_thread_overhead(66 * MIB);
        let (threads, held) = budget.hold_threads(16, |n| u64::from(n) * 100 * MIB);
        // 6 threads take 600 MiB and 396 MiB of overhead.
        assert_eq!((threads, held.bytes()), (6, 996 * MIB));
    }

    #[test]
    fn clones_share_one_account() {
        let budget = Budget::new(100 * MIB);
        let other = budget.clone();
        let (_, held) = other.hold_threads(1, |_| 40 * MIB);
        assert_eq!(budget.left(), 60 * MIB);
        budget.set_bytes(50 * MIB);
        assert_eq!(other.left(), 10 * MIB);
        drop(held);
        assert_eq!((budget.bytes(), budget.held()), (50 * MIB, 0));
        assert_eq!(
            format!("{budget:?}"),
            format!(
                "Budget {{ bytes: {}, held: 0, thread_overhead: 0 }}",
                50 * MIB
            )
        );
    }

    #[test]
    fn jobs_at_once_hold_no_more_than_the_budget() {
        let budget = Budget::new(64 * MIB);
        let most = Arc::new(Mutex::new(0u64));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let (budget, most) = (budget.clone(), Arc::clone(&most));
                scope.spawn(move || {
                    for _ in 0..200 {
                        let (threads, held) = budget.hold_threads(4, |n| u64::from(n) * MIB);
                        assert!((1..=4).contains(&threads));
                        assert_eq!(held.bytes(), u64::from(threads) * MIB);
                        let now = budget.held();
                        let mut most = most.lock().unwrap();
                        *most = (*most).max(now);
                    }
                });
            }
        });
        assert_eq!(budget.held(), 0);
        // Each job holds 4 MiB at most, so one that asks finds at least the
        // 4 MiB the 15 others leave: none takes a thread past the budget.
        assert!(*most.lock().unwrap() <= 64 * MIB);
    }

    #[test]
    fn of_available_is_a_part_of_it() {
        let Some(available) = super::super::available() else {
            assert!(Budget::of_available(1, 2).is_none());
            return;
        };
        let half = Budget::of_available(1, 2).unwrap();
        // Measured twice: it moves a little between the two.
        assert!(half.bytes() <= available.bytes / 2 + available.bytes / 4);
        assert!(half.bytes() > 0);
        assert!(Budget::of_available(1, 0).is_none());
        assert_eq!(half.held(), 0);
    }

    #[test]
    fn a_hold_is_what_fits_or_nothing() {
        let budget = Budget::new(10 * MIB);
        let threads = budget.hold_threads(1, |_| 4 * MIB).1;
        let piece = budget.try_hold(5 * MIB).unwrap();
        assert_eq!((piece.bytes(), budget.held()), (5 * MIB, 9 * MIB));
        // Past what is left: nothing held.
        assert!(budget.try_hold(2 * MIB).is_none());
        assert_eq!(budget.held(), 9 * MIB);
        let last = budget.try_hold(MIB).unwrap();
        assert_eq!(budget.left(), 0);
        drop(piece);
        drop(threads);
        assert_eq!(budget.held(), MIB);
        drop(last);
        assert_eq!(budget.held(), 0);
        assert!(budget.try_hold(11 * MIB).is_none());
    }
}
