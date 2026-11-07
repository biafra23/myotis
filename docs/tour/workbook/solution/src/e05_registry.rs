//! Exercise 5: a thread-safe registry (Mutex, atomics, Arc, lock scope).
//! Modelled on the handle map in myotis-engine/src/host.rs (`spin_up`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

pub struct Config {
    pub name: String,
}

pub enum Entry {
    Created(Arc<Config>),
    Running(Arc<Config>, u64),
}

pub struct Registry {
    handles: Mutex<HashMap<i64, Entry>>,
    next_id: AtomicI64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Registry {
        //@begin
        Registry { handles: Mutex::new(HashMap::new()), next_id: AtomicI64::new(1) }
        //@end
    }

    /// Store `cfg` as `Created` under a fresh id (1, 2, 3, …) and return it.
    /// Must be safe to call from many threads at once through `&self`.
    pub fn create(&self, cfg: Config) -> i64 {
        //@begin
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(id, Entry::Created(Arc::new(cfg)));
        id
        //@end
    }

    /// 1. Under the lock, copy the `Arc<Config>` out of a `Created` entry
    ///    (return `false` for an unknown id or any other state).
    /// 2. RELEASE the lock, then call `slow_start(&config)`: it may take seconds,
    ///    and other threads must not wait for it.
    /// 3. Re-lock and publish `Running(config, started)` only if the entry is
    ///    still `Created` (another thread may have stopped it meanwhile).
    pub fn start(&self, id: i64, slow_start: impl FnOnce(&Config) -> u64) -> bool {
        //@begin
        let config = {
            let map = self.handles.lock().unwrap();
            match map.get(&id) {
                Some(Entry::Created(c)) => Arc::clone(c),
                _ => return false,
            }
        }; // <- the guard is dropped here: the lock is free during slow_start
        let started = slow_start(&config);
        let mut map = self.handles.lock().unwrap();
        match map.get(&id) {
            Some(Entry::Created(_)) => {
                map.insert(id, Entry::Running(config, started));
                true
            }
            _ => false,
        }
        //@end
    }

    pub fn is_running(&self, id: i64) -> bool {
        matches!(self.handles.lock().unwrap().get(&id), Some(Entry::Running(..)))
    }

    /// Remove the entry whatever its state and return its config.
    pub fn stop(&self, id: i64) -> Option<Arc<Config>> {
        //@begin
        match self.handles.lock().unwrap().remove(&id)? {
            Entry::Created(c) | Entry::Running(c, _) => Some(c),
        }
        //@end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_across_threads() {
        let reg = Registry::new();
        let mut ids: Vec<i64> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|i| { let reg = &reg; s.spawn(move || reg.create(Config { name: format!("c{i}") })) })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        ids.sort();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
    }

    #[test]
    fn slow_start_runs_without_the_lock() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "mainnet".into() });
        let ok = reg.start(id, |cfg| {
            assert_eq!(cfg.name, "mainnet");
            assert!(reg.handles.try_lock().is_ok(), "the map lock is still held during slow_start");
            42
        });
        assert!(ok);
        assert!(reg.is_running(id));
        assert!(!reg.start(id, |_| 0), "already running");
    }

    #[test]
    fn stop_during_start_wins() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "gnosis".into() });
        let ok = reg.start(id, |_| {
            reg.stop(id); // a racing stop()
            1
        });
        assert!(!ok, "must not resurrect a stopped entry");
        assert!(!reg.is_running(id));
        assert!(reg.stop(id).is_none());
    }
}
