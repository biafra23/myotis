//! Cooperative request lifetime, shared by async reads and synchronous EVM work.
//!
//! A timeout cancels the operation and then drains its started blocking jobs.
//! Permits belong to jobs, never to the caller's patience: a call waits for a
//! free execution slot only briefly and only while its operation is live (see
//! [`blocking`]). Indivisible native work (proof verification, precompiles,
//! filesystem calls) is not preempted.
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify, Semaphore, SemaphorePermit};

pub const REQUEST_BUDGET: Duration = Duration::from_secs(90);

/// Native executions running at once, each on its own Tokio blocking thread.
pub const BLOCKING_SLOTS_MAX: usize = 8;
/// How long a call waits for a free slot before it is refused. Well under
/// what a wallet gives a call (Terminal Wallet gives up at 10 s, #532) and
/// far beyond a token-balance `eth_call`, so a polling burst drains instead
/// of failing, while a cap held by long runs still refuses within seconds.
pub const BLOCKING_WAIT: Duration = Duration::from_secs(5);
/// Calls that may wait at once; past that the refusal is immediate, so a
/// flood never stacks up waiters (and the closures they carry) for the whole
/// wait before failing anyway.
pub const BLOCKING_WAITERS_MAX: usize = 32;

static BLOCKING_SLOTS: Semaphore = Semaphore::const_new(BLOCKING_SLOTS_MAX);
static BLOCKING_WAITERS: Semaphore = Semaphore::const_new(BLOCKING_WAITERS_MAX);

/// Submission metadata supplied by the native scheduler before entering the C ABI.
#[derive(Clone)]
pub struct Submission {
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
}
thread_local! { static SUBMISSION: std::cell::RefCell<Option<Submission>> = const { std::cell::RefCell::new(None) }; }

pub fn submitted<T>(submission: Submission, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Submission>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUBMISSION.with(|s| {
                s.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(SUBMISSION.with(|s| s.replace(Some(submission))));
    f()
}

tokio::task_local! { static CURRENT: Arc<Operation>; }

pub struct Operation {
    deadline: Instant,
    submission: Option<Submission>,
    cancelled: watch::Sender<bool>,
    shutdown: watch::Receiver<bool>,
    parent: Option<Arc<Operation>>,
    active: AtomicBool,
    workers: AtomicUsize,
    drained: Notify,
}

impl Operation {
    fn new(shutdown: watch::Receiver<bool>, budget: Duration) -> Arc<Self> {
        let parent = CURRENT.try_with(Arc::clone).ok();
        let submission = SUBMISSION.with(|s| s.borrow().clone());
        let deadline = Instant::now() + budget;
        let deadline = submission
            .as_ref()
            .map_or(deadline, |s| deadline.min(s.deadline));
        Arc::new(Self {
            deadline: parent
                .as_ref()
                .map_or(deadline, |p| deadline.min(p.deadline)),
            submission,
            cancelled: watch::channel(false).0,
            shutdown,
            parent,
            active: AtomicBool::new(true),
            workers: AtomicUsize::new(0),
            drained: Notify::new(),
        })
    }

    pub fn current() -> Option<Arc<Self>> {
        CURRENT.try_with(Arc::clone).ok()
    }

    pub fn check(&self) -> Result<(), String> {
        if self
            .submission
            .as_ref()
            .is_some_and(|s| s.cancelled.load(Ordering::Acquire))
        {
            return Err("request cancelled".into());
        }
        if *self.shutdown.borrow() || *self.cancelled.borrow() {
            return Err("request cancelled".into());
        }
        if Instant::now() >= self.deadline {
            return Err("request deadline exceeded".into());
        }
        if let Some(parent) = &self.parent {
            parent.check()?;
        }
        Ok(())
    }

    fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    /// Also wraps writer-lock/send waits, not just peer response timeouts.
    pub async fn wait<T>(&self, future: impl Future<Output = T>) -> Result<T, String> {
        self.check()?;
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                _ = tokio::time::sleep(Duration::from_millis(10)) => self.check()?,
                // Ready is a committed result, including side effects. A late
                // cancellation must not replace it with a false failure.
                value = &mut future => return Ok(value),
            }
        }
    }

    pub async fn settled(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.active.load(Ordering::Acquire) && self.workers.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    async fn drain(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.workers.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct CancelOnDrop(Arc<Operation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
        self.0.active.store(false, Ordering::Release);
        self.0.drained.notify_waiters();
    }
}

struct Worker(Arc<Operation>);
impl Worker {
    fn new(op: Arc<Operation>) -> Self {
        let mut current = Some(&op);
        while let Some(o) = current {
            o.workers.fetch_add(1, Ordering::AcqRel);
            current = o.parent.as_ref();
        }
        Self(op)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let mut current = Some(&self.0);
        while let Some(o) = current {
            if o.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
                o.drained.notify_waiters();
            }
            current = o.parent.as_ref();
        }
    }
}

pub async fn run<T>(
    shutdown: watch::Receiver<bool>,
    budget: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    run_operation(Operation::new(shutdown, budget), future).await
}

pub async fn run_registered<T>(
    registry: &Mutex<Vec<Weak<Operation>>>,
    shutdown: watch::Receiver<bool>,
    budget: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let op = Operation::new(shutdown, budget);
    {
        let mut registry = registry
            .lock()
            .map_err(|_| "request registry unavailable".to_string())?;
        op.check()?;
        registry.retain(|o| o.strong_count() > 0);
        registry.push(Arc::downgrade(&op));
    }
    run_operation(op, future).await
}

async fn run_operation<T>(
    op: Arc<Operation>,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let guard = CancelOnDrop(Arc::clone(&op));
    let result = CURRENT
        .scope(Arc::clone(&op), op.wait(future))
        .await
        .and_then(|r| r);
    drop(guard);
    op.drain().await;
    result
}

/// No unbounded Tokio blocking queue: a job reaches `spawn_blocking` only
/// with one of the [`BLOCKING_SLOTS_MAX`] slots in hand, so the pool's own
/// queue never grows. A call that finds every slot taken waits its turn —
/// FIFO, at most [`BLOCKING_WAIT`], and only while its operation is live —
/// and is refused (`native execution busy`) when the wait runs out, or at
/// once when [`BLOCKING_WAITERS_MAX`] calls are already waiting: a wallet's
/// polling burst drains, a genuine overload still fails fast. Before, a
/// burst of 8–15 `eth_call`s in one second (MetaMask polling token balances
/// for several accounts) had every call past the eighth refused and retried.
/// A started job owns both its permit and its accounting guard until the
/// closure returns, even if its future is dropped.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let op = Operation::current();
    let permit = acquire_slot(op.as_deref(), BLOCKING_WAIT).await?;
    let worker = op.map(Worker::new);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _worker = worker;
        f()
    })
    .await
    .map_err(|e| format!("native task join error: {e}"))
}

/// A slot now, or after a bounded FIFO wait, or the busy refusal. A released
/// slot goes to the longest waiter, never to a newcomer's `try_acquire`, so
/// the line keeps its order. The wait returns as soon as `op` is cancelled
/// or expires, and a refused or cancelled call leaves the line at once. A
/// cancelled or expired `op` never gets a slot, whichever side of the wait
/// the cancellation lands on. Every slow-path outcome logs at debug with the
/// time waited (`evm slot: …`): the wait is latency a call's own cost log
/// cannot attribute, and a refusal was loud before, so slot pressure stays
/// visible either way.
async fn acquire_slot(
    op: Option<&Operation>,
    wait: Duration,
) -> Result<SemaphorePermit<'static>, String> {
    let check = || op.map_or(Ok(()), Operation::check);
    check()?;
    if let Ok(permit) = BLOCKING_SLOTS.try_acquire() {
        return Ok(permit);
    }
    // Calls in the line besides this one (while this one holds a ticket).
    let others = |ticketed: bool| {
        let in_line = BLOCKING_WAITERS_MAX - BLOCKING_WAITERS.available_permits();
        in_line.saturating_sub(usize::from(ticketed))
    };
    let Ok(_ticket) = BLOCKING_WAITERS.try_acquire() else {
        tracing::debug!(waiting = others(false), "evm slot: line full, refused at once");
        return Err(format!(
            "native execution busy: {BLOCKING_SLOTS_MAX} running, {BLOCKING_WAITERS_MAX} waiting"
        ));
    };
    let queued = Instant::now();
    let acquire = tokio::time::timeout(wait, BLOCKING_SLOTS.acquire());
    let acquired = match op {
        Some(o) => o.wait(acquire).await?,
        None => acquire.await,
    };
    let waited_ms = u64::try_from(queued.elapsed().as_millis()).unwrap_or(u64::MAX);
    let permit = match acquired {
        Ok(Ok(permit)) => permit,
        // The static semaphore is never closed; refuse rather than panic.
        Ok(Err(_)) => return Err("native execution busy: slots closed".to_string()),
        Err(_) => {
            tracing::debug!(
                waited_ms,
                waiting = others(true),
                "evm slot: no slot freed within the wait, refused"
            );
            return Err(format!(
                "native execution busy: no slot freed within {}s",
                wait.as_secs()
            ))
        }
    };
    tracing::debug!(
        waited_ms,
        waiting = others(true),
        "evm slot: waited for a free execution slot"
    );
    // The wait checks every 10 ms; a cancellation inside the last tick, before
    // the slot landed, must not start a job.
    check()?;
    Ok(permit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_submission_never_polls_work() {
        let touched = AtomicBool::new(false);
        let submission = Submission {
            deadline: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let op = submitted(submission, || {
            Operation::new(watch::channel(false).1, REQUEST_BUDGET)
        });
        let result = run_operation(op, async {
            touched.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap_err(), "request deadline exceeded");
        assert!(!touched.load(Ordering::Relaxed));
    }

    #[test]
    fn the_evm_call_breakdown_names_an_expired_request_as_one() {
        // #532 (PR #536 review): `OracleError::kind` tells a deadline apart
        // from other cancellations by this module's exact wording, which the
        // EVM crate cannot import (the crates depend the other way). Reword
        // the message here and this fails, instead of every timeout quietly
        // logging as a plain cancellation.
        let reason = |deadline: Instant, cancelled: bool| {
            let submission = Submission { deadline, cancelled: Arc::new(AtomicBool::new(cancelled)) };
            let op = submitted(submission, || Operation::new(watch::channel(false).1, REQUEST_BUDGET));
            op.check().unwrap_err()
        };
        let kind = |reason: String| myotis_evm::OracleError::Cancelled { reason }.kind();
        assert_eq!(kind(reason(Instant::now(), false)), "request deadline exceeded");
        assert_eq!(kind(reason(Instant::now() + REQUEST_BUDGET, true)), "request cancelled");
    }

    #[tokio::test]
    async fn ready_result_survives_cancellation_during_commit() {
        let (shutdown, receiver) = watch::channel(false);
        let committed = AtomicBool::new(false);
        let result = run(receiver, REQUEST_BUDGET, async {
            committed.store(true, Ordering::Release);
            shutdown.send_replace(true);
            Ok("committed transaction hash")
        })
        .await;
        assert!(committed.load(Ordering::Acquire));
        assert_eq!(result.unwrap(), "committed transaction hash");
    }

    #[tokio::test]
    async fn ready_error_is_not_replaced_by_late_cancellation() {
        let (shutdown, receiver) = watch::channel(false);
        let result: Result<(), String> = run(receiver, REQUEST_BUDGET, async {
            shutdown.send_replace(true);
            Err("verified execution reverted".into())
        })
        .await;
        assert_eq!(result.unwrap_err(), "verified execution reverted");
    }

    #[tokio::test]
    async fn cancelled_submission_never_polls_work() {
        let touched = AtomicBool::new(false);
        let op = submitted(
            Submission {
                deadline: Instant::now() + REQUEST_BUDGET,
                cancelled: Arc::new(AtomicBool::new(true)),
            },
            || Operation::new(watch::channel(false).1, REQUEST_BUDGET),
        );
        let result = run_operation(op, async {
            touched.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap_err(), "request cancelled");
        assert!(!touched.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn shutdown_with_live_receiver_refuses_new_work() {
        let (shutdown, receiver) = watch::channel(false);
        shutdown.send_replace(true);
        let result = run(receiver, REQUEST_BUDGET, async { Ok(42) }).await;
        assert_eq!(result.unwrap_err(), "request cancelled");
    }

    #[tokio::test]
    async fn registered_custom_budget_refuses_expired_setup() {
        let registry = Mutex::new(Vec::new());
        let touched = AtomicBool::new(false);
        let result = run_registered(&registry, watch::channel(false).1, Duration::ZERO, async {
            touched.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await;
        assert_eq!(result.unwrap_err(), "request deadline exceeded");
        assert!(!touched.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn child_worker_is_counted_against_parent_until_actual_drop() {
        let parent = Operation::new(watch::channel(false).1, REQUEST_BUDGET);
        let child = CURRENT
            .scope(Arc::clone(&parent), async {
                Operation::new(watch::channel(false).1, Duration::from_secs(180))
            })
            .await;
        assert!(child.deadline <= parent.deadline);
        let worker = Worker::new(Arc::clone(&child));
        assert_eq!(parent.workers.load(Ordering::Acquire), 1);
        assert_eq!(child.workers.load(Ordering::Acquire), 1);
        child.cancel();
        assert_eq!(parent.workers.load(Ordering::Acquire), 1);
        assert!(parent.check().is_ok()); // an ENS attempt does not cancel AUTO
        drop(worker);
        assert_eq!(parent.workers.load(Ordering::Acquire), 0);
        assert_eq!(child.workers.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn parent_cancellation_reaches_child_and_registered_scope_settles() {
        let registry = Mutex::new(Vec::new());
        let (shutdown, receiver) = watch::channel(false);
        let result = run_registered(&registry, receiver, REQUEST_BUDGET, async {
            let current = Operation::current().unwrap();
            let child = Operation::new(shutdown.subscribe(), REQUEST_BUDGET);
            current.cancel();
            child.check().map(|()| 42)
        })
        .await;
        assert_eq!(result.unwrap_err(), "request cancelled");
        for operation in registry.lock().unwrap().iter().filter_map(Weak::upgrade) {
            assert!(!operation.active.load(Ordering::Acquire));
            assert_eq!(operation.workers.load(Ordering::Acquire), 0);
        }
    }

    /// The slot tests share the process-wide semaphores: one at a time, so
    /// the slots one test holds never show up as another test's refusal.
    static SLOT_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn hold_every_slot() -> SemaphorePermit<'static> {
        BLOCKING_SLOTS
            .acquire_many(BLOCKING_SLOTS_MAX as u32)
            .await
            .expect("the static semaphore is never closed")
    }

    #[tokio::test]
    async fn a_burst_past_the_slot_cap_waits_its_turn_instead_of_failing() {
        let _serial = SLOT_TESTS.lock().await;
        // Three times the cap, all at once: a wallet polling token balances
        // for several accounts fires 8–15 eth_calls within one second.
        const BURST: usize = 3 * BLOCKING_SLOTS_MAX;
        let running = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let calls: Vec<_> = (0..BURST)
            .map(|i| {
                let running = Arc::clone(&running);
                let high_water = Arc::clone(&high_water);
                tokio::spawn(async move {
                    blocking(move || {
                        let now = running.fetch_add(1, Ordering::AcqRel) + 1;
                        high_water.fetch_max(now, Ordering::AcqRel);
                        std::thread::sleep(Duration::from_millis(30));
                        running.fetch_sub(1, Ordering::AcqRel);
                        i
                    })
                    .await
                })
            })
            .collect();
        for (i, call) in calls.into_iter().enumerate() {
            assert_eq!(call.await.unwrap(), Ok(i), "call {i} was refused");
        }
        let took = started.elapsed();
        assert!(took < BLOCKING_WAIT, "{took:?}");
        // Three rounds of 30 ms through eight slots: a cap that admitted the
        // whole burst at once would be done in one, and would prove nothing.
        assert!(took >= Duration::from_millis(60), "{took:?}: the burst never queued");
        // The cap itself held: never more than the slots on blocking threads.
        let peak = high_water.load(Ordering::Acquire);
        assert!(peak <= BLOCKING_SLOTS_MAX, "{peak} ran at once");
        assert_eq!(BLOCKING_SLOTS.available_permits(), BLOCKING_SLOTS_MAX);
        assert_eq!(BLOCKING_WAITERS.available_permits(), BLOCKING_WAITERS_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn with_every_slot_held_past_the_wait_the_refusal_still_fires() {
        let _serial = SLOT_TESTS.lock().await;
        let held = hold_every_slot().await;
        let ran = Arc::new(AtomicBool::new(false));
        let started = tokio::time::Instant::now();
        // Under a request operation, as every production caller runs: the
        // wait goes through `Operation::wait`, not the bare timeout.
        let err = {
            let ran = Arc::clone(&ran);
            run(watch::channel(false).1, REQUEST_BUDGET, async move {
                blocking(move || ran.store(true, Ordering::Release)).await
            })
            .await
            .unwrap_err()
        };
        // The paused clock jumps from timer to timer (the wait's 10 ms checks,
        // then the bound): the call waited BLOCKING_WAIT, while the 90 s
        // request budget, on the wall clock, was nowhere near.
        let waited = started.elapsed();
        assert!(waited >= BLOCKING_WAIT, "{waited:?}");
        assert!(waited < BLOCKING_WAIT + Duration::from_secs(1), "{waited:?}");
        assert!(err.starts_with("native execution busy"), "{err}");
        assert!(!ran.load(Ordering::Acquire));
        // The refused call left the line.
        assert_eq!(BLOCKING_WAITERS.available_permits(), BLOCKING_WAITERS_MAX);
        drop(held);
        assert_eq!(blocking(|| 7).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn with_the_waiting_line_full_the_refusal_is_immediate() {
        let _serial = SLOT_TESTS.lock().await;
        let held = hold_every_slot().await;
        let waiting: Vec<_> = (0..BLOCKING_WAITERS_MAX)
            .map(|i| tokio::spawn(blocking(move || i)))
            .collect();
        // Spawned tasks run on yield; let every one of them join the line.
        tokio::time::timeout(Duration::from_secs(5), async {
            while BLOCKING_WAITERS.available_permits() > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every waiter took its place in the line");
        let started = Instant::now();
        let err = blocking(|| ()).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1), "a full line refuses at once");
        assert!(err.starts_with("native execution busy") && err.contains("waiting"), "{err}");
        drop(held);
        // The line drains: every queued call is served.
        for (i, call) in waiting.into_iter().enumerate() {
            assert_eq!(call.await.unwrap(), Ok(i));
        }
        assert_eq!(BLOCKING_WAITERS.available_permits(), BLOCKING_WAITERS_MAX);
    }

    #[tokio::test]
    async fn a_call_waiting_for_a_slot_stops_when_its_request_is_cancelled() {
        let _serial = SLOT_TESTS.lock().await;
        let _held = hold_every_slot().await;
        let (shutdown, receiver) = watch::channel(false);
        let ran = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let result = run(receiver, REQUEST_BUDGET, async {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                shutdown.send_replace(true);
            });
            let ran = Arc::clone(&ran);
            blocking(move || ran.store(true, Ordering::Release)).await
        })
        .await;
        assert_eq!(result.unwrap_err(), "request cancelled");
        assert!(started.elapsed() < BLOCKING_WAIT, "cancelled, not timed out");
        assert!(!ran.load(Ordering::Acquire));
        // The cancelled call left the line.
        assert_eq!(BLOCKING_WAITERS.available_permits(), BLOCKING_WAITERS_MAX);
    }

    #[tokio::test]
    async fn the_line_is_served_in_arrival_order() {
        let _serial = SLOT_TESTS.lock().await;
        // Every slot held as its own permit, so one can be let go on its own.
        let mut held = Vec::new();
        for _ in 0..BLOCKING_SLOTS_MAX {
            held.push(BLOCKING_SLOTS.acquire().await.expect("never closed"));
        }
        const LINE: usize = 6;
        let served = Arc::new(Mutex::new(Vec::new()));
        let waiting: Vec<_> = (0..LINE)
            .map(|i| {
                let served = Arc::clone(&served);
                tokio::spawn(blocking(move || served.lock().unwrap().push(i)))
            })
            .collect();
        // Spawned tasks run, and so join the line, in spawn order.
        tokio::time::timeout(Duration::from_secs(5), async {
            while BLOCKING_WAITERS.available_permits() > BLOCKING_WAITERS_MAX - LINE {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("every waiter took its place in the line");
        // One slot flows through the whole line: a released slot goes to the
        // longest waiter, whose job hands it on when it returns.
        drop(held.pop());
        for call in waiting {
            call.await.unwrap().unwrap();
        }
        assert_eq!(*served.lock().unwrap(), (0..LINE).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn a_slot_that_lands_after_a_cancellation_starts_no_job() {
        let _serial = SLOT_TESTS.lock().await;
        let held = hold_every_slot().await;
        let (shutdown, receiver) = watch::channel(false);
        let ran = Arc::new(AtomicBool::new(false));
        let call = {
            let ran = Arc::clone(&ran);
            tokio::spawn(run(receiver, REQUEST_BUDGET, async move {
                blocking(move || ran.store(true, Ordering::Release)).await
            }))
        };
        // Let the call join the line …
        tokio::time::timeout(Duration::from_secs(5), async {
            while BLOCKING_WAITERS.available_permits() == BLOCKING_WAITERS_MAX {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the call joined the line");
        // … then cancel it and free the slots in the same instant: the permit
        // lands on the waiter before its wait's next 10 ms check can run
        // (the paused clock never advances between these two lines and the
        // call's next poll).
        shutdown.send_replace(true);
        drop(held);
        assert_eq!(call.await.unwrap().unwrap_err(), "request cancelled");
        assert!(!ran.load(Ordering::Acquire), "a cancelled request started a job");
        assert_eq!(BLOCKING_SLOTS.available_permits(), BLOCKING_SLOTS_MAX);
        assert_eq!(BLOCKING_WAITERS.available_permits(), BLOCKING_WAITERS_MAX);
    }
}
