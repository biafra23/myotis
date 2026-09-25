//! Cooperative request lifetime, shared by async reads and synchronous EVM work.
//!
//! A timeout cancels the operation and then drains its started blocking jobs.
//! Permits belong to jobs, never to the caller's patience. Indivisible native
//! work (proof verification, precompiles, filesystem calls) is not preempted.
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Notify, Semaphore};

pub const REQUEST_BUDGET: Duration = Duration::from_secs(90);
static BLOCKING_SLOTS: Semaphore = Semaphore::const_new(8);

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

/// No unbounded Tokio blocking queue. A started job owns both its permit and
/// its accounting guard until the closure returns, even if its future is dropped.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let permit = BLOCKING_SLOTS
        .try_acquire()
        .map_err(|_| "native execution busy".to_string())?;
    let op = Operation::current();
    if let Some(o) = &op {
        o.check()?;
    }
    let worker = op.map(Worker::new);
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _worker = worker;
        f()
    })
    .await
    .map_err(|e| format!("native task join error: {e}"))
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
}
