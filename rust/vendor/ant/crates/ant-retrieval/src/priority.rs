//! Head-of-window retrieval priority for the streaming joiner (issue #46).
//!
//! The streaming joiner ([`crate::join_to_sender_range`]) hands bytes to
//! its consumer strictly in document order, but fetches up to
//! [`FETCH_FANOUT`](crate::joiner) sibling subtrees at once, and a
//! sibling that has finished frees its slot for the next one whether or
//! not the merger has reached it yet. So while the chunk the consumer is
//! waiting for is slow (a starved credit wait, a retry, a slow peer), the
//! other slots keep pulling in the rest of the file. On a cold node every
//! fetch competes for the same peer credit and the same per-request
//! permits, the chunk at the head gets no more of either than one a
//! megabyte ahead of it, and a download spends most of its time stalled
//! near byte 0 and then delivers almost everything at once.
//!
//! This module tells the fetcher where a chunk sits relative to the
//! consumer, so [`crate::RoutingFetcher`] can serve the head first:
//!
//! - A [`ReadHead`] is the consumer's position in one streaming request:
//!   the file offset of the next byte the joiner has not yet handed to
//!   the request's output channel. The joiner advances it as it sends.
//! - Every data-chunk fetch of the streaming joiner runs with its chunk's
//!   file offset in scope ([`at_offset`]). The chunk is at the **head**
//!   when it starts less than [`HEAD_WINDOW`] past the read head;
//!   otherwise it is **look-ahead** ([`Priority`]).
//!
//! Both live in task-locals, set by the joiner around the whole join and
//! around each data-chunk fetch, so every fetch made for that chunk
//! (the direct fetch, its hedges, a Reed-Solomon recovery sweep it
//! triggers) is ranked the same way without the [`crate::ChunkFetcher`]
//! trait or the decoder having to carry it. A fetch made outside a
//! streaming join (buffered joins, manifest walks, feeds, roots, the
//! chunk API) has no position: [`Priority::Unranked`], and the fetcher
//! treats it exactly as before.
//!
//! The rank is read afresh at every decision the fetcher makes, so a
//! look-ahead fetch that is still waiting when the consumer catches up
//! with it is served as the head from its next decision on (its next
//! credit check, at most [`crate::OVERDRAFT_REFRESH`] away). A
//! look-ahead fetch queued for its request's permit keeps its place in
//! that queue and is woken by the read head itself the moment it
//! becomes the head ([`until_head`]), with no polling.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// How far past the read head a chunk may start and still count as the
/// head of the window: 16 chunks, one [`FETCH_FANOUT`](crate::joiner)'s
/// worth. More than the single chunk the consumer is blocked on, so the
/// next few chunks are already being served first by the time the head
/// reaches them (a waiting fetch notices its new rank only at its next
/// credit check, up to [`crate::OVERDRAFT_REFRESH`] later); small enough
/// that, with several downloads running, the heads stay a small share
/// of everything in flight.
pub const HEAD_WINDOW: u64 = 16 * 4096;

/// The consumer's read position in one streaming join: the file offset
/// of the next byte not yet handed to the output channel. Cheap to
/// clone; clones share the position.
#[derive(Debug, Clone)]
pub struct ReadHead(Arc<HeadInner>);

#[derive(Debug, Default)]
struct HeadInner {
    position: AtomicU64,
    /// Look-ahead fetches waiting to become the head, keyed by the read
    /// position at which they do (and a tiebreak id). Only touched
    /// synchronously, never held across an `.await`.
    waiters: Mutex<Waiters>,
}

#[derive(Debug, Default)]
struct Waiters {
    next_id: u64,
    by_position: BTreeMap<(u64, u64), tokio::sync::oneshot::Sender<()>>,
}

impl ReadHead {
    /// A read head at file offset `start` (`0`, or a range's first byte).
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self(Arc::new(HeadInner {
            position: AtomicU64::new(start),
            waiters: Mutex::default(),
        }))
    }

    /// The consumer has been handed `bytes` more. Wakes exactly the
    /// waiters ([`ReadHead::until_head`]) this move makes the head.
    pub fn advance(&self, bytes: u64) {
        let position = self
            .0
            .position
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        let ready = {
            let mut waiters = self.0.waiters.lock().expect("read head waiters poisoned");
            let later = waiters
                .by_position
                .split_off(&(position.saturating_add(1), 0));
            std::mem::replace(&mut waiters.by_position, later)
        };
        for (_, tx) in ready {
            let _ = tx.send(());
        }
    }

    /// The file offset of the next byte the consumer needs.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.0.position.load(Ordering::Relaxed)
    }

    /// Resolves once a chunk at file offset `offset` ranks as
    /// [`Priority::Head`]: at once if it already does, else when
    /// [`ReadHead::advance`] moves the read head to within
    /// [`HEAD_WINDOW`] of it. Wakes once, on that advance, not on a
    /// timer. Dropping the future unregisters it.
    pub async fn until_head(&self, offset: u64) {
        // Head once `offset < position + HEAD_WINDOW`.
        let needed = offset.saturating_add(1).saturating_sub(HEAD_WINDOW);
        let (rx, key) = {
            // Registered under the lock `advance` drains under, so an
            // advance either is seen by the check or drains the entry.
            let mut waiters = self.0.waiters.lock().expect("read head waiters poisoned");
            if self.position() >= needed {
                return;
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            let key = (needed, waiters.next_id);
            waiters.next_id += 1;
            waiters.by_position.insert(key, tx);
            (rx, key)
        };
        struct Unregister<'a>(&'a HeadInner, (u64, u64));
        impl Drop for Unregister<'_> {
            fn drop(&mut self) {
                if let Ok(mut waiters) = self.0.waiters.lock() {
                    waiters.by_position.remove(&self.1);
                }
            }
        }
        let _unregister = Unregister(&self.0, key);
        let _ = rx.await;
    }

    /// Rank of a chunk that starts at file offset `offset`.
    #[must_use]
    pub fn rank(&self, offset: u64) -> Priority {
        if offset < self.position().saturating_add(HEAD_WINDOW) {
            Priority::Head
        } else {
            Priority::LookAhead
        }
    }
}

/// Where the fetch running on the current task sits relative to its
/// consumer; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// Not part of a streaming join: no consumer position to rank
    /// against. Served exactly as before issue #46.
    Unranked,
    /// Within [`HEAD_WINDOW`] of the read head: what the consumer needs
    /// next. May use every peer's full overdraft limit, and skips the
    /// per-request permit queue.
    Head,
    /// Further ahead. Leaves each peer
    /// [`HEAD_CREDIT_RESERVE`](crate::accounting::HEAD_CREDIT_RESERVE) of
    /// credit for head fetches, and waits its turn for a per-request
    /// permit.
    LookAhead,
}

tokio::task_local! {
    static READ_HEAD: ReadHead;
    static CHUNK_OFFSET: u64;
}

/// Run `fut` (a whole streaming join) with `head` as its read head.
pub(crate) async fn with_read_head<F: Future>(head: ReadHead, fut: F) -> F::Output {
    READ_HEAD.scope(head, fut).await
}

/// Run `fut` (every fetch for the data chunk at file offset `offset`)
/// with that offset in scope.
pub(crate) async fn at_offset<F: Future>(offset: u64, fut: F) -> F::Output {
    CHUNK_OFFSET.scope(offset, fut).await
}

/// Resolves once the fetch running on the current task ranks as
/// [`Priority::Head`] (see [`ReadHead::until_head`]). Never resolves for
/// an unranked fetch. Captures the task's position when called, so the
/// returned future may be polled anywhere.
pub(crate) fn until_head() -> impl Future<Output = ()> + Send + 'static {
    let slot = CHUNK_OFFSET
        .try_with(|o| *o)
        .ok()
        .and_then(|offset| READ_HEAD.try_with(|head| (head.clone(), offset)).ok());
    async move {
        match slot {
            Some((head, offset)) => head.until_head(offset).await,
            None => std::future::pending().await,
        }
    }
}

/// Rank of the fetch running on the current task right now.
#[must_use]
pub fn current() -> Priority {
    let Ok(offset) = CHUNK_OFFSET.try_with(|o| *o) else {
        return Priority::Unranked;
    };
    READ_HEAD
        .try_with(|head| head.rank(offset))
        .unwrap_or(Priority::Unranked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rank_follows_the_read_head() {
        assert_eq!(current(), Priority::Unranked);
        let head = ReadHead::new(0);
        let h = head.clone();
        with_read_head(head.clone(), async move {
            // An offset without a read head, or a read head without an
            // offset, is unranked.
            assert_eq!(current(), Priority::Unranked);
            at_offset(0, async {
                assert_eq!(current(), Priority::Head);
            })
            .await;
            at_offset(HEAD_WINDOW - 1, async {
                assert_eq!(current(), Priority::Head);
            })
            .await;
            at_offset(HEAD_WINDOW, async {
                assert_eq!(current(), Priority::LookAhead);
                // The consumer catches up: the same fetch is now the head.
                h.advance(4096);
                assert_eq!(current(), Priority::Head);
            })
            .await;
        })
        .await;
        at_offset(0, async {
            assert_eq!(current(), Priority::Unranked);
        })
        .await;
        assert_eq!(head.position(), 4096);
    }

    /// A waiter wakes on the advance that makes it the head, not
    /// before; a dropped waiter unregisters.
    #[tokio::test]
    async fn until_head_wakes_on_the_advance_that_makes_it_head() {
        let head = ReadHead::new(0);
        let offset = 3 * HEAD_WINDOW;
        let waiter = tokio::spawn({
            let head = head.clone();
            async move { head.until_head(offset).await }
        });
        let dropped = tokio::spawn({
            let head = head.clone();
            async move { head.until_head(10 * HEAD_WINDOW).await }
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // One byte short of the head window: still waiting.
        head.advance(2 * HEAD_WINDOW);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(!waiter.is_finished());
        assert_eq!(head.0.waiters.lock().unwrap().by_position.len(), 2);
        head.advance(1);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("woken by the advance")
            .unwrap();
        dropped.abort();
        let _ = dropped.await;
        assert!(head.0.waiters.lock().unwrap().by_position.is_empty());
        // Already the head: resolves at once.
        head.until_head(offset).await;
    }
}
