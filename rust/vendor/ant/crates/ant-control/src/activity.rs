//! Live registry of in-flight gateway HTTP requests.
//!
//! The HTTP gateway (`ant-gateway`) registers every retrieval request
//! it accepts here, updates the progress fields as `Progress` acks
//! stream back from the daemon, and removes the entry when the
//! response body has finished draining. The daemon's status publisher
//! (`ant-p2p`) reads a snapshot on every `StatusSnapshot` tick so
//! `antop` can show what the gateway is currently working on.
//!
//! The registry is intentionally defined here rather than in
//! `ant-gateway` so `ant-p2p` can take an `Arc<GatewayActivity>` in
//! its [`crate::ControlCommand`]-shaped configuration without
//! introducing a circular crate dependency. (`ant-p2p` already
//! depends on `ant-control` for the wire types; `ant-gateway` does
//! too.)
//!
//! Lock granularity: a single `Mutex<Inner>`. The hot operation is
//! `update` from the gateway's `Progress`-ack loop; we never hold
//! the lock across an `.await`. With a couple of hundred concurrent
//! requests at most the contention is well below what a `tokio` mpsc
//! would impose, and the readback path (`snapshot`) takes the same
//! lock once per status tick.

use crate::protocol::{GatewayRequestInfo, GatewayRequestKind};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

/// Shared handle the gateway and the status publisher both clone. Owns
/// the registry and the next-id counter; cheap to clone.
#[derive(Debug, Default)]
pub struct GatewayActivity {
    next_id: AtomicU64,
    inner: Mutex<HashMap<u64, Entry>>,
}

#[derive(Debug, Clone)]
struct Entry {
    kind: GatewayRequestKind,
    path: String,
    started_at_unix: u64,
    chunks_done: u64,
    total_chunks_estimate: u64,
    chunks_in_flight: u32,
    bytes_done: u64,
}

impl GatewayActivity {
    /// Build an empty registry. The daemon constructs exactly one and
    /// shares the `Arc` with both the gateway handle and the status
    /// publisher.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a new in-flight request. Returns a guard that will
    /// remove the entry when dropped, plus a [`GatewayActivityHandle`]
    /// the gateway uses to push progress updates without re-acquiring
    /// the registry lock against the wrong entry.
    pub fn begin(self: &Arc<Self>, kind: GatewayRequestKind, path: String) -> ActiveRequestGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let started_at_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let entry = Entry {
            kind,
            path,
            started_at_unix,
            chunks_done: 0,
            total_chunks_estimate: 0,
            chunks_in_flight: 0,
            bytes_done: 0,
        };
        self.inner
            .lock()
            .expect("activity mutex poisoned")
            .insert(id, entry);
        ActiveRequestGuard {
            id,
            registry: Arc::downgrade(self),
        }
    }

    /// Snapshot the current entries in stable order (oldest first by
    /// `started_at_unix`, then by id to break ties deterministically).
    /// Called by the status publisher on every tick.
    pub fn snapshot(&self) -> Vec<GatewayRequestInfo> {
        let map = self.inner.lock().expect("activity mutex poisoned");
        let mut entries: Vec<(u64, Entry)> = map.iter().map(|(id, e)| (*id, e.clone())).collect();
        drop(map);
        entries.sort_by_key(|(id, e)| (e.started_at_unix, *id));
        entries
            .into_iter()
            .map(|(_, e)| GatewayRequestInfo {
                kind: e.kind,
                path: e.path,
                started_at_unix: e.started_at_unix,
                chunks_done: e.chunks_done,
                total_chunks_estimate: e.total_chunks_estimate,
                chunks_in_flight: e.chunks_in_flight,
                bytes_done: e.bytes_done,
            })
            .collect()
    }

    /// Number of currently-active requests, for tests and assertions.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("activity mutex poisoned").len()
    }

    /// `true` when no request is currently registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn update<F: FnOnce(&mut Entry)>(&self, id: u64, f: F) {
        if let Some(entry) = self
            .inner
            .lock()
            .expect("activity mutex poisoned")
            .get_mut(&id)
        {
            f(entry);
        }
    }

    fn remove(&self, id: u64) {
        self.inner
            .lock()
            .expect("activity mutex poisoned")
            .remove(&id);
    }
}

/// RAII guard returned by [`GatewayActivity::begin`]. Removes the
/// entry from the registry on drop, so a panicking handler can't
/// leak ghost rows in `antop`. Cloning the guard (via the
/// [`Self::handle`] accessor) is intentionally indirect: the *guard*
/// is unique-ownership of the registry slot, but the *handle* is a
/// cheap reference for the streaming-body loop to push updates from.
pub struct ActiveRequestGuard {
    id: u64,
    registry: Weak<GatewayActivity>,
}

impl ActiveRequestGuard {
    /// Update the request's instantaneous progress fields. The gateway
    /// streaming-body loop calls this on every `Progress` ack from the
    /// daemon. A no-op if the registry has been dropped (process
    /// shutdown).
    pub fn update(
        &self,
        chunks_done: u64,
        total_chunks_estimate: u64,
        chunks_in_flight: u32,
        bytes_done: u64,
    ) {
        if let Some(reg) = self.registry.upgrade() {
            reg.update(self.id, |entry| {
                entry.chunks_done = chunks_done;
                entry.total_chunks_estimate = total_chunks_estimate;
                entry.chunks_in_flight = chunks_in_flight;
                entry.bytes_done = bytes_done;
            });
        }
    }

    /// Cheap, owned handle to the same registry slot. Used when the
    /// guard's lifetime is tied to a `Drop` boundary (the handler
    /// frame) but updates need to keep flowing from a body stream
    /// that outlives the handler frame. The handle does *not* extend
    /// the registry slot's lifetime — when the guard drops, the slot
    /// is removed and the handle's `update` calls become no-ops.
    #[must_use]
    pub fn handle(&self) -> GatewayActivityHandle {
        GatewayActivityHandle {
            id: self.id,
            registry: self.registry.clone(),
        }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        if let Some(reg) = self.registry.upgrade() {
            reg.remove(self.id);
        }
    }
}

/// Cheap, `Send`-able update channel into a single registry slot.
///
/// Cloned into the streaming-body unfold state so updates keep
/// flowing while the handler frame's [`ActiveRequestGuard`] holds
/// the slot alive.
#[derive(Clone)]
pub struct GatewayActivityHandle {
    id: u64,
    registry: Weak<GatewayActivity>,
}

impl GatewayActivityHandle {
    /// Same semantics as [`ActiveRequestGuard::update`].
    pub fn update(
        &self,
        chunks_done: u64,
        total_chunks_estimate: u64,
        chunks_in_flight: u32,
        bytes_done: u64,
    ) {
        if let Some(reg) = self.registry.upgrade() {
            reg.update(self.id, |entry| {
                entry.chunks_done = chunks_done;
                entry.total_chunks_estimate = total_chunks_estimate;
                entry.chunks_in_flight = chunks_in_flight;
                entry.bytes_done = bytes_done;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_inserts_entry_with_zero_progress() {
        let reg = GatewayActivity::new();
        let _g = reg.begin(GatewayRequestKind::Bytes, "abcdef".into());
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].kind, GatewayRequestKind::Bytes);
        assert_eq!(snap[0].path, "abcdef");
        assert_eq!(snap[0].chunks_done, 0);
        assert_eq!(snap[0].chunks_in_flight, 0);
    }

    #[test]
    fn drop_removes_entry() {
        let reg = GatewayActivity::new();
        {
            let _g = reg.begin(GatewayRequestKind::Bzz, "/index.html".into());
            assert_eq!(reg.len(), 1);
        }
        assert!(reg.is_empty());
    }

    #[test]
    fn update_propagates_to_snapshot() {
        let reg = GatewayActivity::new();
        let g = reg.begin(GatewayRequestKind::Bytes, "ref".into());
        let h = g.handle();
        h.update(42, 100, 8, 4096 * 42);
        let snap = reg.snapshot();
        assert_eq!(snap[0].chunks_done, 42);
        assert_eq!(snap[0].total_chunks_estimate, 100);
        assert_eq!(snap[0].chunks_in_flight, 8);
        assert_eq!(snap[0].bytes_done, 4096 * 42);
    }

    /// Multiple concurrent requests appear in stable `started_at` /
    /// `id` order so `antop` rows don't jitter between ticks.
    #[test]
    fn snapshot_is_stably_ordered() {
        let reg = GatewayActivity::new();
        let _a = reg.begin(GatewayRequestKind::Bytes, "a".into());
        let _b = reg.begin(GatewayRequestKind::Bzz, "b".into());
        let _c = reg.begin(GatewayRequestKind::Chunk, "c".into());
        let s1 = reg.snapshot();
        let s2 = reg.snapshot();
        assert_eq!(s1.len(), 3);
        assert_eq!(
            s1.iter().map(|e| e.path.clone()).collect::<Vec<_>>(),
            s2.iter().map(|e| e.path.clone()).collect::<Vec<_>>(),
        );
    }
}
