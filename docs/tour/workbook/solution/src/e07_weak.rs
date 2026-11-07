//! Exercise 7: a background worker that must not keep its owner alive (Weak).
//! Modelled on `ensure_log_index_appender` in myotis-net/src/el/reader.rs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Service {
    pub ticks: AtomicU64,
}

/// Spawn a thread that every `period` upgrades a `Weak<Service>`, increments
/// `ticks`, and drops the upgraded `Arc` again before sleeping. When `upgrade`
/// fails (the last strong owner is gone) the thread returns the number of
/// ticks it performed. The thread must never hold a strong `Arc` while asleep.
pub fn spawn_ticker(svc: &Arc<Service>, period: Duration) -> JoinHandle<u64> {
    //@begin
    let weak: Weak<Service> = Arc::downgrade(svc);
    std::thread::spawn(move || {
        let mut done = 0;
        loop {
            {
                let Some(s) = weak.upgrade() else { return done };
                s.ticks.fetch_add(1, Ordering::Relaxed);
                done += 1;
            } // <- the temporary Arc `s` is dropped here
            std::thread::sleep(period);
        }
    })
    //@end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_stops_when_the_owner_drops() {
        let svc = Arc::new(Service { ticks: AtomicU64::new(0) });
        let h = spawn_ticker(&svc, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(60));
        assert!(svc.ticks.load(Ordering::Relaxed) > 0);
        assert_eq!(Arc::weak_count(&svc), 1, "the worker holds exactly one Weak");
        drop(svc); // the last strong owner
        let n = h.join().unwrap(); // returns: upgrade() now fails
        assert!(n > 0);
    }
}
