//! Per-handle network traffic accounting: how many bytes one network's stack
//! sent and received, split by layer (EL = RLPx + discv4, CL = libp2p + discv5).
//!
//! A [`TrafficMeter`] is created with a [`crate::ChainConfig`] and shared by
//! every socket that stack opens, so a host running several networks sees each
//! one's own figures. What is counted, and where:
//!
//! - **RLPx** (EL, TCP): every handshake and frame byte, at the stream
//!   (`el::rlpx::transport`).
//! - **discv4** (EL, UDP): every datagram's payload (`el::discv4`).
//! - **libp2p TCP** (CL): every byte on the raw socket, below noise and the
//!   muxer, so the handshakes and framing are in ([`CountingStream`]).
//! - **libp2p QUIC** (CL): the stream payload above QUIC — QUIC's own packet
//!   overhead and TLS handshake are not visible from libp2p
//!   ([`CountingMuxer`]).
//! - **discv5** (CL, UDP): the `discv5` crate counts only PROCESS-wide
//!   (`discv5::Discv5::metrics`); its growth is handed out to the meters
//!   whose discovery is running, evenly ([`Discv5Share`]). Exact with one
//!   network running, an even split with several.
//!
//! Not counted: IP/TCP/UDP headers, EIP-1459 DNS lookups, and Tor (Arti's
//! circuits and directory traffic are not visible to the engine) — see
//! docs/data-usage.md.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

/// One direction pair of byte counters. Monotonic; never reset.
#[derive(Debug, Default)]
pub struct ByteCounter {
    rx: AtomicU64,
    tx: AtomicU64,
}

impl ByteCounter {
    /// Count `n` received bytes.
    pub fn add_rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Count `n` sent bytes.
    pub fn add_tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// `(received, sent)` so far.
    pub fn snapshot(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }
}

/// One network stack's traffic, by layer.
#[derive(Debug, Default)]
pub struct TrafficMeter {
    /// Execution layer: RLPx sessions and discv4.
    pub el: ByteCounter,
    /// Consensus layer: libp2p (TCP + QUIC) and discv5.
    pub cl: ByteCounter,
}

/// A plain copy of a [`TrafficMeter`] at one moment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub el_rx: u64,
    pub el_tx: u64,
    pub cl_rx: u64,
    pub cl_tx: u64,
}

impl TrafficSnapshot {
    pub fn rx(&self) -> u64 {
        self.el_rx.saturating_add(self.cl_rx)
    }

    pub fn tx(&self) -> u64 {
        self.el_tx.saturating_add(self.cl_tx)
    }
}

impl TrafficMeter {
    pub fn new() -> Arc<TrafficMeter> {
        Arc::new(TrafficMeter::default())
    }

    /// The meter's totals, with discv5's process-wide growth handed out first
    /// so the CL figure is current.
    pub fn snapshot(&self) -> TrafficSnapshot {
        flush_discv5();
        let (el_rx, el_tx) = self.el.snapshot();
        let (cl_rx, cl_tx) = self.cl.snapshot();
        TrafficSnapshot { el_rx, el_tx, cl_rx, cl_tx }
    }
}

// ---- discv5: process-wide counters, shared out ----------------------------

struct Discv5Ledger {
    /// discv5's global `(recv, sent)` at the last flush.
    seen: (u64, u64),
    /// Meters whose discv5 is running right now.
    live: Vec<Weak<TrafficMeter>>,
}

static DISCV5: Mutex<Discv5Ledger> = Mutex::new(Discv5Ledger { seen: (0, 0), live: Vec::new() });

fn discv5_totals() -> (u64, u64) {
    let m = discv5::Discv5::metrics();
    (m.bytes_recv as u64, m.bytes_sent as u64)
}

/// Hand discv5's growth since the last flush to the live meters, evenly (the
/// remainder to the first). Growth with no live meter — a discv5 the engine
/// did not start (tools, roost) — is dropped.
fn flush_discv5_locked(ledger: &mut Discv5Ledger) {
    share_growth(ledger, discv5_totals());
}

/// [`flush_discv5_locked`] against given totals (`(recv, sent)`).
fn share_growth(ledger: &mut Discv5Ledger, now: (u64, u64)) {
    let d_rx = now.0.saturating_sub(ledger.seen.0);
    let d_tx = now.1.saturating_sub(ledger.seen.1);
    ledger.seen = now;
    ledger.live.retain(|w| w.strong_count() > 0);
    let live: Vec<Arc<TrafficMeter>> = ledger.live.iter().filter_map(Weak::upgrade).collect();
    if live.is_empty() || (d_rx == 0 && d_tx == 0) {
        return;
    }
    let n = live.len() as u64;
    for (i, m) in live.iter().enumerate() {
        let (mut rx, mut tx) = (d_rx / n, d_tx / n);
        if i == 0 {
            rx += d_rx % n;
            tx += d_tx % n;
        }
        m.cl.rx.fetch_add(rx, Ordering::Relaxed);
        m.cl.tx.fetch_add(tx, Ordering::Relaxed);
    }
}

fn flush_discv5() {
    let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
    flush_discv5_locked(&mut ledger);
}

/// Held for as long as one meter's discv5 runs: on creation the meter joins
/// the share of discv5's process-wide traffic, on drop it leaves. Both flush
/// first, so bytes from before the change go to the meters live then.
pub struct Discv5Share {
    meter: Weak<TrafficMeter>,
}

impl Discv5Share {
    pub fn join(meter: &Arc<TrafficMeter>) -> Discv5Share {
        let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
        flush_discv5_locked(&mut ledger);
        ledger.live.push(Arc::downgrade(meter));
        Discv5Share { meter: Arc::downgrade(meter) }
    }
}

impl Drop for Discv5Share {
    fn drop(&mut self) {
        let mut ledger = DISCV5.lock().unwrap_or_else(|e| e.into_inner());
        flush_discv5_locked(&mut ledger);
        if let Some(i) = ledger.live.iter().position(|w| w.ptr_eq(&self.meter)) {
            ledger.live.swap_remove(i);
        }
    }
}

// ---- libp2p: a counting stream and a counting muxer ------------------------

/// A `futures` byte stream that counts what passes through it into one
/// [`ByteCounter`] of a meter. Wraps libp2p's raw TCP socket (below noise) and
/// each QUIC substream.
pub struct CountingStream<S> {
    inner: S,
    meter: Arc<TrafficMeter>,
    layer: fn(&TrafficMeter) -> &ByteCounter,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, meter: Arc<TrafficMeter>, layer: fn(&TrafficMeter) -> &ByteCounter) -> Self {
        CountingStream { inner, meter, layer }
    }

    fn counter(&self) -> &ByteCounter {
        (self.layer)(&self.meter)
    }
}

impl<S: futures::AsyncRead + Unpin> futures::AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_rx(n);
        }
        poll
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_rx(n);
        }
        poll
    }
}

impl<S: futures::AsyncWrite + Unpin> futures::AsyncWrite for CountingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_tx(n);
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = poll {
            self.counter().add_tx(n);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// A libp2p [`StreamMuxer`](libp2p::core::muxing::StreamMuxer) whose substreams
/// count their payload — for QUIC, whose socket libp2p does not expose.
pub struct CountingMuxer<M> {
    inner: M,
    meter: Arc<TrafficMeter>,
}

impl<M> CountingMuxer<M> {
    pub fn new(inner: M, meter: Arc<TrafficMeter>) -> Self {
        CountingMuxer { inner, meter }
    }
}

impl<M> libp2p::core::muxing::StreamMuxer for CountingMuxer<M>
where
    M: libp2p::core::muxing::StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = CountingStream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Self::Substream, Self::Error>> {
        let meter = Arc::clone(&self.meter);
        Pin::new(&mut self.inner)
            .poll_inbound(cx)
            .map_ok(|s| CountingStream::new(s, meter, cl))
    }

    fn poll_outbound(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<Self::Substream, Self::Error>> {
        let meter = Arc::clone(&self.meter);
        Pin::new(&mut self.inner)
            .poll_outbound(cx)
            .map_ok(|s| CountingStream::new(s, meter, cl))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<libp2p::core::muxing::StreamMuxerEvent, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// The CL layer's counter, for [`CountingStream::new`].
pub fn cl(m: &TrafficMeter) -> &ByteCounter {
    &m.cl
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn counting_stream_counts_both_directions_into_its_layer() {
        futures::executor::block_on(async {
            let meter = TrafficMeter::new();
            let mut out = CountingStream::new(futures::io::Cursor::new(Vec::new()), Arc::clone(&meter), cl);
            out.write_all(b"hello").await.unwrap();
            out.flush().await.unwrap();
            let mut inn = CountingStream::new(futures::io::Cursor::new(b"abc".to_vec()), Arc::clone(&meter), cl);
            let mut back = Vec::new();
            inn.read_to_end(&mut back).await.unwrap();
            let (rx, tx) = meter.cl.snapshot();
            assert_eq!((tx, rx), (5, 3));
            assert_eq!(meter.el.snapshot(), (0, 0));
        });
    }

    #[test]
    fn discv5_growth_is_shared_by_the_live_meters_only() {
        let a = TrafficMeter::new();
        let b = TrafficMeter::new();
        let mut ledger = Discv5Ledger { seen: (100, 50), live: vec![Arc::downgrade(&a)] };
        // a alone.
        share_growth(&mut ledger, (110, 54));
        // b joins: an even split, the remainder to the first.
        ledger.live.push(Arc::downgrade(&b));
        share_growth(&mut ledger, (117, 56));
        assert_eq!(a.cl.snapshot(), (10 + 4, 4 + 1));
        assert_eq!(b.cl.snapshot(), (3, 1));
        // b is gone (dropped): its share goes back to a.
        drop(b);
        share_growth(&mut ledger, (118, 56));
        assert_eq!(a.cl.snapshot(), (15, 5));
        assert_eq!(ledger.live.len(), 1);
        // Nobody live: growth goes nowhere, but is consumed.
        ledger.live.clear();
        share_growth(&mut ledger, (200, 60));
        assert_eq!(a.cl.snapshot(), (15, 5));
        assert_eq!(ledger.seen, (200, 60));
    }
}
