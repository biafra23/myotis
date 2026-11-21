//! Coalesce duplicate pushes of the same chunk.
//!
//! The same chunk can be pushed many times in a row. A live broadcast
//! uploads one file per segment, and with redundancy every upload also
//! pushes dispersed replica SOCs of its manifest nodes, one of which is
//! byte-identical in every segment's manifest. Measured on mainnet
//! (2026-10-12), that one replica SOC was re-pushed with every 2 s
//! segment: four segments in flight raced four copies of it, each with
//! its own stamp, storers refused the older ones ("overwriting chunk
//! with newer timestamp", over a thousand times in 30 minutes), and as
//! its neighbourhood had no reachable deep storer each copy also waited
//! out the SOC push patience: every segment took ~30 s to publish.
//!
//! [`PushDedup`] gives a push two shortcuts, both keyed on the chunk's
//! address, its bytes (a SOC can be rewritten in place with new content,
//! and that must still go out) *and* the postage batch it is to be
//! stamped with (a re-upload under another batch, e.g. a newly bought
//! one to extend the content's lifetime, must really be stamped with
//! that batch, and a push under one batch must not inherit another
//! batch's failure):
//!
//! * **in flight**: a push of something already being pushed waits for
//!   that push and gets its answer, instead of racing it with another
//!   stamp (bee's pusher keeps the same `inflight` set);
//! * **recently stored**: a push of something stored within [`RECENT_TTL`]
//!   is answered at once, without a new stamp or network round.
//!
//! Strict (deep-placement-required) and pre-stamped pushes don't use it:
//! a repair re-push must really go out, and a caller-supplied stamp is
//! the caller's to send.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ant_control::ControlAck;
use tokio::sync::oneshot;

/// How long a stored chunk is answered from memory.
pub const RECENT_TTL: Duration = Duration::from_mins(10);

/// Bound on the recently-stored memory (oldest entries go first).
const RECENT_MAX: usize = 100_000;

/// What identifies a push for deduplication: a hash of the chunk's
/// address, the postage batch it is stamped with and its wire bytes.
pub type PushKey = [u8; 32];

/// The key for a push of `address` carrying `wire`, stamped with
/// `batch_id`.
#[must_use]
pub fn push_key(address: &[u8; 32], batch_id: &[u8; 32], wire: &[u8]) -> PushKey {
    let mut input = Vec::with_capacity(64 + wire.len());
    input.extend_from_slice(address);
    input.extend_from_slice(batch_id);
    input.extend_from_slice(wire);
    ant_crypto::keccak256(&input)
}

#[derive(Default)]
struct Inner {
    inflight: HashMap<PushKey, Vec<oneshot::Sender<ControlAck>>>,
    recent: HashMap<PushKey, Instant>,
}

/// Node-wide record of pushes in flight and recently stored.
#[derive(Default)]
pub struct PushDedup {
    inner: Mutex<Inner>,
}

/// What [`PushDedup::begin`] decided.
pub enum Begin {
    /// Push it: give the push this ack (it reaches every waiter).
    Push(oneshot::Sender<ControlAck>),
    /// Already answered or attached to a push in flight; nothing to do.
    Handled,
}

impl PushDedup {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start a push of `key` answering `ack` (`reference` is what a
    /// success reports). Returns [`Begin::Handled`] when it was recently
    /// stored (answered now) or is in flight (answered with that push's
    /// result); otherwise the caller pushes with the returned ack.
    pub fn begin(
        self: &Arc<Self>,
        key: PushKey,
        reference: [u8; 32],
        ack: oneshot::Sender<ControlAck>,
    ) -> Begin {
        let mut inner = self.lock();
        let now = Instant::now();
        if inner
            .recent
            .get(&key)
            .is_some_and(|&at| now.duration_since(at) < RECENT_TTL)
        {
            drop(inner);
            let _ = ack.send(ControlAck::ChunkUploaded {
                reference: format!("0x{}", hex::encode(reference)),
            });
            return Begin::Handled;
        }
        if let Some(waiters) = inner.inflight.get_mut(&key) {
            waiters.push(ack);
            return Begin::Handled;
        }
        inner.inflight.insert(key, vec![ack]);
        drop(inner);

        let (tx, rx) = oneshot::channel::<ControlAck>();
        let this = Arc::clone(self);
        tokio::spawn(async move { this.forward(key, rx).await });
        Begin::Push(tx)
    }

    /// Wait for the push's answer and hand it to every waiter. If every
    /// waiter goes away first, drop the push's ack, so the push (which
    /// watches its ack) stops instead of spending credit for nobody.
    async fn forward(self: Arc<Self>, key: PushKey, mut rx: oneshot::Receiver<ControlAck>) {
        let reply = loop {
            tokio::select! {
                r = &mut rx => break r.ok(),
                () = tokio::time::sleep(Duration::from_secs(1)) => {
                    // Decide abandonment and release the entry under one
                    // lock hold, so a `begin` can't attach to an entry
                    // already judged abandoned and be told "push
                    // abandoned" for a live request.
                    let mut inner = self.lock();
                    let abandoned = inner
                        .inflight
                        .get(&key)
                        .is_none_or(|w| w.iter().all(oneshot::Sender::is_closed));
                    if abandoned {
                        inner.inflight.remove(&key);
                        return;
                    }
                }
            }
        };
        let waiters = {
            let mut inner = self.lock();
            let waiters = inner.inflight.remove(&key).unwrap_or_default();
            if matches!(reply, Some(ControlAck::ChunkUploaded { .. })) {
                if inner.recent.len() >= RECENT_MAX {
                    let now = Instant::now();
                    inner
                        .recent
                        .retain(|_, at| now.duration_since(*at) < RECENT_TTL);
                    if inner.recent.len() >= RECENT_MAX {
                        inner.recent.clear();
                    }
                }
                inner.recent.insert(key, Instant::now());
            }
            waiters
        };
        let reply = reply.unwrap_or_else(|| ControlAck::Error {
            message: "push abandoned".into(),
        });
        for w in waiters {
            let _ = w.send(reply.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uploaded(r: &ControlAck) -> bool {
        matches!(r, ControlAck::ChunkUploaded { .. })
    }

    #[tokio::test]
    async fn a_duplicate_waits_for_the_push_in_flight_and_shares_its_answer() {
        let dedup = Arc::new(PushDedup::default());
        let key = push_key(&[1u8; 32], &[0u8; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let (b_tx, b_rx) = oneshot::channel();
        let Begin::Push(push) = dedup.begin(key, [1u8; 32], a_tx) else {
            panic!("the first push goes out");
        };
        assert!(
            matches!(dedup.begin(key, [1u8; 32], b_tx), Begin::Handled),
            "the second waits"
        );
        push.send(ControlAck::ChunkUploaded {
            reference: "0x01".into(),
        })
        .unwrap();
        assert!(uploaded(&a_rx.await.unwrap()));
        assert!(
            uploaded(&b_rx.await.unwrap()),
            "the waiter gets the same answer"
        );
    }

    #[tokio::test]
    async fn a_recently_stored_chunk_is_answered_without_a_push() {
        let dedup = Arc::new(PushDedup::default());
        let key = push_key(&[2u8; 32], &[0u8; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let Begin::Push(push) = dedup.begin(key, [2u8; 32], a_tx) else {
            panic!()
        };
        push.send(ControlAck::ChunkUploaded {
            reference: "0x02".into(),
        })
        .unwrap();
        a_rx.await.unwrap();
        let (b_tx, b_rx) = oneshot::channel();
        assert!(matches!(dedup.begin(key, [2u8; 32], b_tx), Begin::Handled));
        assert!(uploaded(&b_rx.await.unwrap()));
        // Same address, different bytes (a SOC rewritten in place): pushed.
        let (c_tx, _c_rx) = oneshot::channel();
        assert!(matches!(
            dedup.begin(
                push_key(&[2u8; 32], &[0u8; 32], b"new content"),
                [2u8; 32],
                c_tx
            ),
            Begin::Push(_)
        ));
    }

    #[tokio::test]
    async fn a_failed_push_is_not_remembered() {
        let dedup = Arc::new(PushDedup::default());
        let key = push_key(&[3u8; 32], &[0u8; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let Begin::Push(push) = dedup.begin(key, [3u8; 32], a_tx) else {
            panic!()
        };
        push.send(ControlAck::Error {
            message: "no".into(),
        })
        .unwrap();
        assert!(!uploaded(&a_rx.await.unwrap()));
        let (b_tx, _b_rx) = oneshot::channel();
        assert!(
            matches!(dedup.begin(key, [3u8; 32], b_tx), Begin::Push(_)),
            "retried for real"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_push_nobody_waits_for_is_released() {
        let dedup = Arc::new(PushDedup::default());
        let key = push_key(&[4u8; 32], &[0u8; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let Begin::Push(mut push) = dedup.begin(key, [4u8; 32], a_tx) else {
            panic!()
        };
        drop(a_rx);
        tokio::time::timeout(Duration::from_secs(5), push.closed())
            .await
            .expect("the push's ack closes once every waiter is gone");
    }

    #[tokio::test]
    async fn a_push_under_another_batch_is_not_coalesced() {
        let dedup = Arc::new(PushDedup::default());
        let addr = [5u8; 32];
        let under_a = push_key(&addr, &[0xa; 32], b"wire");
        let under_b = push_key(&addr, &[0xb; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let Begin::Push(push) = dedup.begin(under_a, addr, a_tx) else {
            panic!()
        };
        // In flight under A: B still goes out on its own.
        let (b_tx, _b_rx) = oneshot::channel();
        assert!(matches!(dedup.begin(under_b, addr, b_tx), Begin::Push(_)));
        push.send(ControlAck::ChunkUploaded {
            reference: "0x05".into(),
        })
        .unwrap();
        a_rx.await.unwrap();
        // Stored under A a moment ago: a push under C is still stamped.
        let (c_tx, _c_rx) = oneshot::channel();
        assert!(matches!(
            dedup.begin(push_key(&addr, &[0xc; 32], b"wire"), addr, c_tx),
            Begin::Push(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_push_releases_its_entry_for_the_next_one() {
        let dedup = Arc::new(PushDedup::default());
        let key = push_key(&[6u8; 32], &[0u8; 32], b"wire");
        let (a_tx, a_rx) = oneshot::channel();
        let Begin::Push(mut push) = dedup.begin(key, [6u8; 32], a_tx) else {
            panic!()
        };
        drop(a_rx);
        tokio::time::timeout(Duration::from_secs(5), push.closed())
            .await
            .unwrap();
        assert!(
            !dedup.lock().inflight.contains_key(&key),
            "the abandoned entry is gone with the decision"
        );
        // A later request is a push of its own, not a waiter on the
        // abandoned one.
        let (b_tx, _b_rx) = oneshot::channel();
        assert!(matches!(dedup.begin(key, [6u8; 32], b_tx), Begin::Push(_)));
    }
}
