//! A stream muxer whose graceful close gives up after a bound (issue #83).
//!
//! `Swarm::close_connection` (and `disconnect_peer_id`) doesn't drop the
//! connection: libp2p-swarm's connection task awaits the muxer's close —
//! for yamux, sending `GoAway` and flushing everything still queued — and
//! only then emits `ConnectionClosed`. On a half-open link (socket reaped
//! during an OS suspension, NAT mapping gone) whose TCP send buffer is
//! already full of in-flight stream data, that flush can't make progress
//! until the kernel gives up retransmitting (~15 min on Linux). Until then
//! there is no `ConnectionClosed`, so none of its teardown runs: the peer
//! stays in `bzz_peers`, routing and accounting, and the top-up never
//! redials it. That is exactly the connection the liveness pass closes.
//!
//! [`BoundedClose`] lets the close try for [`CLOSE_TIMEOUT`] and then
//! reports it done, so the connection task drops the muxer (closing the
//! socket) and the swarm emits `ConnectionClosed`. A healthy close
//! finishes well inside the bound and is unaffected.

use libp2p::core::muxing::{StreamMuxer, StreamMuxerEvent};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tracing::debug;

/// How long a graceful muxer close may take before the connection is
/// dropped anyway.
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wraps a [`StreamMuxer`]; see the module docs.
pub(crate) struct BoundedClose<M> {
    inner: M,
    timeout: Duration,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<M> BoundedClose<M> {
    pub(crate) fn new(inner: M) -> Self {
        Self::with_timeout(inner, CLOSE_TIMEOUT)
    }

    pub(crate) fn with_timeout(inner: M, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: None,
        }
    }
}

impl<M: StreamMuxer + Unpin> StreamMuxer for BoundedClose<M> {
    type Substream = M::Substream;
    type Error = M::Error;

    fn poll_inbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Pin::new(&mut self.inner).poll_inbound(cx)
    }

    fn poll_outbound(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        Pin::new(&mut self.inner).poll_outbound(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Poll::Ready(r) = Pin::new(&mut self.inner).poll_close(cx) {
            return Poll::Ready(r);
        }
        let timeout = self.timeout;
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
        if deadline.as_mut().poll(cx).is_ready() {
            debug!(
                target: "ant_p2p",
                ?timeout,
                "muxer close didn't flush in time (dead link?); dropping the connection",
            );
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::muxing::StreamMuxerExt;

    /// A muxer whose close never completes, like yamux flushing into a
    /// full send buffer on a dead link.
    struct StuckClose;

    impl StreamMuxer for StuckClose {
        type Substream = futures::io::Cursor<Vec<u8>>;
        type Error = std::io::Error;
        fn poll_inbound(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<Self::Substream, Self::Error>> {
            Poll::Pending
        }
        fn poll_outbound(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<Self::Substream, Self::Error>> {
            Poll::Pending
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
        fn poll(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn a_stuck_close_finishes_after_the_bound() {
        let bound = Duration::from_millis(200);
        let started = std::time::Instant::now();
        BoundedClose::with_timeout(StuckClose, bound)
            .close()
            .await
            .unwrap();
        let took = started.elapsed();
        assert!(took >= bound && took < bound * 10, "{took:?}");
    }
}
