//! Exercise 6: an RAII drop guard (Drop, Arc, Mutex).
//! Modelled on `PendingGuard` in myotis-net/src/el/peer.rs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Pending = Arc<Mutex<HashMap<u64, String>>>;

/// Registers a pending request and removes it again when dropped, unless
/// `disarm` was called. Cleanup then happens on EVERY exit path: normal
/// return, early `return`, `?`, or a panic that unwinds.
pub struct PendingGuard {
    pending: Pending,
    id: u64,
    armed: bool,
}

impl PendingGuard {
    /// Insert `what` under `id` and return an armed guard. The guard keeps its
    /// own `Arc` clone of the map.
    pub fn register(pending: &Pending, id: u64, what: &str) -> PendingGuard {
        todo!("your code here")
    }

    /// The request completed through another path: keep the entry.
    pub fn disarm(&mut self) {
        todo!("your code here")
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        todo!("your code here")
    }
}

/// Registers request `id`, then fails half-way with `?` when `fail` is true.
pub fn request(pending: &Pending, id: u64, fail: bool) -> Result<(), String> {
    let mut guard = PendingGuard::register(pending, id, "GetBlockHeaders");
    let check: Result<(), String> = if fail { Err("peer closed".into()) } else { Ok(()) };
    check?; // an early return: the guard still runs
    guard.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_guard_removes_its_entry() {
        let p: Pending = Arc::default();
        {
            let _g = PendingGuard::register(&p, 1, "a");
            assert_eq!(p.lock().unwrap().len(), 1);
        } // <- _g dropped here
        assert!(p.lock().unwrap().is_empty());
    }

    #[test]
    fn early_return_cleans_up_and_success_keeps() {
        let p: Pending = Arc::default();
        assert!(request(&p, 7, true).is_err());
        assert!(!p.lock().unwrap().contains_key(&7), "the ? path must clean up");
        request(&p, 8, false).unwrap();
        assert!(p.lock().unwrap().contains_key(&8), "disarmed: entry kept");
    }

    #[test]
    fn guard_holds_its_own_arc() {
        let p: Pending = Arc::default();
        let g = PendingGuard::register(&p, 3, "x");
        assert_eq!(Arc::strong_count(&p), 2);
        drop(g);
        assert_eq!(Arc::strong_count(&p), 1);
    }
}
