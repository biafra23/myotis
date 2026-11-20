//! Outbound bee `/swarm/pseudosettle/1.0.0/pseudosettle` driver.
//!
//! # Why this exists
//!
//! Bee tracks per-peer **debt** for every chunk it serves us. The disconnect
//! threshold for a light-mode peer (we declare `full_node: false` in the
//! handshake) is `lightDisconnectLimit ≈ 1.69M units` on a default-config
//! mainnet node. At a typical chunk price of `~150_000 units`, that's about
//! **11 chunks per peer before bee rejects further requests with
//! `ErrDisconnectThresholdExceeded`** and blocklists our overlay locally.
//!
//! For a one-shot small file the burst stays under the limit, but a streaming
//! `/bzz` of a 50 MiB media file fans out to ~15k chunk fetches — many of
//! them concentrated on the few peers closest to the file's neighbourhood.
//! Without a way to reset that debt, those hot peers reject us long before
//! the download finishes; without `pseudosettle` the only recovery is to
//! redial fresh peers, which is the peer-set thrash we observed during the
//! 0.3.0 streaming regression.
//!
//! # The protocol (bee 2.7.x and 2.8.0)
//!
//! Pseudosettle is unchanged between bee 2.6 → 2.7.x → 2.8.0. The 2.8
//! release reshapes the BZZ handshake (handshake `15.0.0`, new signed
//! preimage) but leaves the per-peer `PaymentSent` / `PaymentReceived`
//! flow we depend on here alone.
//!
//! `pseudosettle` is bee's free **time-based debt refresh** mechanism. The
//! exchange is symmetric (either peer can dial), single round-trip, no
//! negotiation:
//!
//! ```text
//! dialer → listener : varint + Headers pb (empty)        // bee headers preamble
//! listener → dialer : varint + Headers pb (empty)
//! dialer → listener : varint + Payment{ amount: bytes }  // big-endian big.Int
//! listener → dialer : varint + PaymentAck{ amount, timestamp }
//! ```
//!
//! The listener (bee, here) clamps `amount` to
//! `min(attempted, lightRefreshRate * (now - lastTimestamp), our_debt)` and
//! returns the accepted figure plus its current Unix timestamp in seconds.
//! That's all that's needed to clear our debt up to the refresh-rate budget
//! since the previous successful settle.
//!
//! See `bee/pkg/settlement/pseudosettle/pseudosettle.go::Pay` for the bee
//! dialer reference and `::handler` for the listener.
//!
//! # What this module does
//!
//! Three pieces:
//!
//! 1. **Inbound drain** ([`run_inbound`]). Bee's `pseudosettle.Protocol`
//!    declares a `ConnectIn`/`ConnectOut` callback that runs `init`, which in
//!    turn registers us in their per-peer `s.peers` map *before any
//!    pseudosettle stream is opened*. So bee never actually dials us for
//!    pseudosettle in normal operation (we're the consumer, not the
//!    forwarder). On the off chance that some peer does, we drain and
//!    NAK-with-zero so they don't get billed for nothing. This is purely
//!    defensive; the steady-state rate of inbound pseudosettle is ~zero.
//!
//! 2. **Outbound refresh** ([`refresh_peer`]). Opens the pseudosettle
//!    stream, exchanges headers, sends a `Payment` with our intended
//!    refresh amount, reads the `PaymentAck`. Returns the accepted amount
//!    and the bee-side timestamp, or an error on stream / framing failure.
//!
//! 3. **Driver task** ([`run_driver`]). A background tokio task that
//!    follows bee's dialer rules (`Accounting.settle`, `pseudosettle.Pay`):
//!    it refreshes a peer only when the accounting mirror says we owe it
//!    enough to be worth it ([`Accounting::refresh_due`]), one refresh per
//!    peer at a time, [`MIN_REFRESH_INTERVAL`] after the previous one
//!    completed, bounded by [`MAX_INFLIGHT_REFRESHES`] with no queue behind
//!    the bound, and backs off after a failure. See [`run_driver`] for why
//!    each rule matters (issue #129).

use crate::sinks::{HEADERS_MAX, STREAM_TIMEOUT};
use ant_retrieval::accounting::{Accounting, HotHint};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::StreamExt;
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::{Control, IncomingStreams};
use libp2p_swarm::Stream;
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Semaphore};
use tracing::{debug, info, trace, warn};

/// bee `pkg/settlement/pseudosettle`. One protocol, one stream version,
/// matches bee 2.6 → 2.7.x.
pub const PROTOCOL_PSEUDOSETTLE: &str = "/swarm/pseudosettle/1.0.0/pseudosettle";

/// Bee's `lightRefreshRate` in accounting units per second
/// (`refreshRate / lightFactor` with `refreshRate = 4_500_000` and
/// `lightFactor = 10`). Sets the upper bound on how much debt one
/// pseudosettle can clear, since bee clamps `amount` to
/// `lightRefreshRate * elapsed_seconds`. We send
/// `amount = lightRefreshRate * MAX_REFRESH_WINDOW_SECS`; bee will then
/// clamp to the actual elapsed.
pub const LIGHT_REFRESH_RATE_UNITS_PER_SEC: u64 = 450_000;

/// How often [`run_driver`] wakes to start the refreshes that are due.
/// Bee settles synchronously from `PrepareCredit` / `creditAction.Apply`
/// (`pkg/accounting/accounting.go::settle()`), the moment a debit takes
/// the debt past its trigger; the 100 ms tick keeps our scheduling
/// latency to the same order. A `HotHint` from the mirror (fired when a
/// peer's debt crosses [`ant_retrieval::accounting::HOT_DEBT_THRESHOLD`])
/// registers the peer with the driver; whether a refresh is due is read
/// from the mirror on the tick.
const REFRESH_TICK: Duration = Duration::from_millis(100);

/// Minimum spacing between the *completion* of one pseudosettle to a
/// peer and the start of the next (bee's dialer waits until "last
/// refreshment finished at least 1000 milliseconds ago",
/// `Accounting.settle`). Bee answers with its Unix second `T` and refuses
/// a second refresh in the same second (`peerAllowance`:
/// `ErrSettlementTooSoon`, stream reset). Starting a full second after
/// the ack arrived means the next request reaches bee after `T + 1`
/// whatever the latency, so it is never refused for being too soon.
/// Measuring from dispatch instead (as before issue #129) let a slow
/// refresh and the next one land in the same second.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Back-off before retrying a peer whose refresh failed, doubled per
/// consecutive failure up to [`MAX_FAILED_REFRESH_BACKOFF`]. Measured on
/// mainnet (issue #129), a failure is almost always a connection that is
/// closing or that bee no longer serves: bee resets every stream on a
/// connection it hasn't registered, e.g. after our reconnect raced its
/// teardown of the old one (`peers.addIfNotExists` → "peer already
/// exists"). Retrying such a peer every second only adds failures. Bee
/// itself disconnects a peer whose refresh failed
/// (`NotifyRefreshmentSent`: blocklist for 1 s).
const FAILED_REFRESH_BACKOFF: Duration = Duration::from_secs(1);

/// Cap on the [`FAILED_REFRESH_BACKOFF`] doubling.
const MAX_FAILED_REFRESH_BACKOFF: Duration = Duration::from_secs(16);

/// Maximum window we ever ask bee to clear in a single pseudosettle.
/// Mostly cosmetic — bee clamps internally — but keeps the wire amount
/// from looking absurd in their debug logs and avoids accidentally hitting
/// any future server-side sanity check.
const MAX_REFRESH_WINDOW_SECS: u64 = 60;

/// Concurrent outbound pseudosettle attempts. Each one opens a fresh
/// libp2p stream and waits up to [`STREAM_TIMEOUT`] for the round trip,
/// so a hard cap protects the libp2p control's stream queue from a
/// gateway burst that touches hundreds of new peers in a few seconds.
/// At ~250 ms RTT/refresh, 32 in flight gives ~128 refreshes per second,
/// enough for every indebted peer of a 100-peer set once a second. A due
/// refresh that finds no free slot waits for the next tick (most indebted
/// peer first) rather than queueing behind the cap.
const MAX_INFLIGHT_REFRESHES: usize = 32;

/// Bound on the "I just fetched from X" channel into the driver. A
/// notification only registers the peer with the driver; with the
/// accounting mirror attached (as in the daemon) it does not make a
/// refresh due — only the mirror's debt does
/// ([`Accounting::refresh_due`], read every tick). Without a mirror a
/// notified peer is refreshed on the interval. Drops on backpressure:
/// with a mirror a dropped notification changes nothing (an indebted
/// peer is picked up from `refresh_due` anyway); without one it delays
/// that peer's refreshes until its next notification.
pub const NOTIFY_CHANNEL_CAP: usize = 1024;

/// Bound on the hot-hint channel into the driver. Hot hints are rare
/// (only fire on debt-threshold crossings), so a smaller cap is fine.
/// Like a notification, a hint only registers the peer; whether a
/// refresh is due is read from the mirror on the next tick, so a hint
/// dropped on backpressure costs nothing.
pub const HOT_HINT_CHANNEL_CAP: usize = 256;

/// Bee's `pseudosettle.proto::Payment { bytes Amount = 1 }`.
#[derive(Clone, PartialEq, Message)]
struct PaymentPb {
    #[prost(bytes = "vec", tag = "1")]
    amount: Vec<u8>,
}

/// Bee's `pseudosettle.proto::PaymentAck { bytes Amount = 1; int64 Timestamp = 2 }`.
#[derive(Clone, PartialEq, Message)]
struct PaymentAckPb {
    #[prost(bytes = "vec", tag = "1")]
    amount: Vec<u8>,
    #[prost(int64, tag = "2")]
    timestamp: i64,
}

/// Bee's `internal/headers/pb.Headers` is a `repeated Header` — but we never
/// set any so the encoded message is always zero bytes long, and a single
/// 0 length-prefix byte on the wire suffices.
async fn write_empty_headers<W: AsyncWriteExt + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[0u8]).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-delimited message off the stream. Mirrors the helper in
/// `sinks.rs` but lives here to keep the pseudosettle driver self-contained.
async fn read_delimited<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    let len = read_varint_len(r).await?;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (cap {max})"),
        ));
    }
    // Grows with the bytes that arrive, not the declared `len`, so a peer
    // can't pin the cap per stream by declaring a frame and stalling (#203).
    ant_retrieval::frame::read_frame_body(r, len).await
}

async fn read_varint_len<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<usize> {
    let mut byte = [0u8; 1];
    let mut acc: Vec<u8> = Vec::with_capacity(10);
    loop {
        r.read_exact(&mut byte).await?;
        acc.push(byte[0]);
        match unsigned_varint::decode::u64(&acc) {
            Ok((v, [])) => {
                return usize::try_from(v).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "varint overflow")
                });
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid varint framing",
                ));
            }
            Err(unsigned_varint::decode::Error::Insufficient) => {
                if acc.len() > 10 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint too long",
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varint: {e}"),
                ));
            }
        }
    }
}

async fn write_delimited<W, M>(w: &mut W, msg: &M) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    M: Message,
{
    let mut buf = Vec::with_capacity(msg.encoded_len() + 10);
    msg.encode_length_delimited(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Outcome of one pseudosettle round trip.
#[derive(Debug, Clone, Copy)]
pub struct RefreshOk {
    /// Amount bee accepted (`<= attempted`). At most
    /// `lightRefreshRate * elapsed`, often less when our debt with this
    /// peer is below the time-based budget.
    pub accepted: u64,
    /// Bee-side Unix timestamp from the `PaymentAck`. Returned for
    /// optional logging; the driver uses local wall-clock to schedule the
    /// next attempt.
    #[allow(dead_code)]
    pub timestamp: i64,
}

/// Open a pseudosettle stream to `peer`, refresh up to
/// `LIGHT_REFRESH_RATE_UNITS_PER_SEC * MAX_REFRESH_WINDOW_SECS` units of
/// debt. Returns the accepted amount on success.
pub async fn refresh_peer(control: &mut Control, peer: PeerId) -> std::io::Result<RefreshOk> {
    let proto = StreamProtocol::new(PROTOCOL_PSEUDOSETTLE);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| std::io::Error::other(format!("open stream: {e}")))?;

    // bee-headers preamble: dialer writes first, then reads. We never set
    // headers; bee responds with the same.
    write_empty_headers(&mut stream)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("write headers: {e}")))?;
    let _their_headers = read_delimited(&mut stream, HEADERS_MAX)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("read headers: {e}")))?;

    // We send the maximum amount we'd refresh in any one interval. Bee
    // clamps to `min(attempted, lightRefreshRate * elapsed, peer_debt)`
    // and returns the accepted figure, so over-asking is safe and never
    // wasteful.
    let amount: u64 = LIGHT_REFRESH_RATE_UNITS_PER_SEC.saturating_mul(MAX_REFRESH_WINDOW_SECS);
    let amount_bytes = big_int_be_bytes(amount);
    let payment = PaymentPb {
        amount: amount_bytes,
    };
    write_delimited(&mut stream, &payment)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("write payment: {e}")))?;

    let ack_bytes = read_delimited(&mut stream, 256)
        .await
        .map_err(|e| std::io::Error::new(e.kind(), format!("read ack: {e}")))?;
    let ack = PaymentAckPb::decode(ack_bytes.as_slice()).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("decode ack: {e}"))
    })?;
    let accepted = parse_be_u64(&ack.amount).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PaymentAck.amount overflows u64",
        )
    })?;

    // Half-close so bee's `stream.FullClose()` returns promptly. Drop on
    // error path is fine — yamux sends a Reset, bee handles it.
    let _ = stream.close().await;

    Ok(RefreshOk {
        accepted,
        timestamp: ack.timestamp,
    })
}

/// Encode a non-negative `u64` as the big-endian unsigned bytes that
/// Go's `big.Int.SetBytes` decodes back to the same value. Strips
/// leading zeroes, so `0 → []` and `1 → [0x01]`.
fn big_int_be_bytes(v: u64) -> Vec<u8> {
    if v == 0 {
        return Vec::new();
    }
    let buf = v.to_be_bytes();
    let first_nonzero = buf.iter().position(|b| *b != 0).unwrap_or(buf.len() - 1);
    buf[first_nonzero..].to_vec()
}

/// Decode big-endian unsigned bytes as a `u64`. Returns `None` if longer
/// than 8 bytes (i.e. the value exceeds `u64::MAX`). Bee always sends
/// values bounded by `lightRefreshRate * MAX_REFRESH_WINDOW_SECS`, well
/// inside `u64`, so this never realistically overflows.
fn parse_be_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut padded = [0u8; 8];
    padded[8 - bytes.len()..].copy_from_slice(bytes);
    Some(u64::from_be_bytes(padded))
}

/// Inbound drain. We never expect to see traffic here in steady state
/// (bee only opens this stream when it would *receive* a refresh from us,
/// and as a light node we never originate a refresh inbound), but if
/// some peer does we read the Payment, ack zero, and close. NAK-with-zero
/// keeps their accounting consistent — they treat zero acceptance the
/// same as "settlement too soon" and don't disconnect.
pub async fn run_inbound(mut incoming: IncomingStreams) {
    while let Some((peer_id, stream)) = incoming.next().await {
        tokio::spawn(async move {
            match tokio::time::timeout(STREAM_TIMEOUT, drain_inbound(stream)).await {
                Ok(Ok(())) => trace!(
                    target: "ant_p2p::pseudosettle",
                    %peer_id,
                    "inbound drained",
                ),
                Ok(Err(e)) => debug!(
                    target: "ant_p2p::pseudosettle",
                    %peer_id,
                    "inbound drain failed: {e}",
                ),
                Err(_) => warn!(
                    target: "ant_p2p::pseudosettle",
                    %peer_id,
                    "inbound stream timed out after {}s",
                    STREAM_TIMEOUT.as_secs(),
                ),
            }
        });
    }
}

async fn drain_inbound(mut stream: Stream) -> std::io::Result<()> {
    // Headers preamble (we're the listener for inbound, so read first).
    let _their_headers = read_delimited(&mut stream, HEADERS_MAX).await?;
    write_empty_headers(&mut stream).await?;
    // Read the Payment so bee's writer unblocks; we don't actually
    // credit anything — we have no accounting state of our own, so the
    // refund is a no-op on our side.
    let _payment = read_delimited(&mut stream, 256).await?;
    // ACK zero with the current timestamp: bee's dialer-side check
    // accepts a zero amount as "we wouldn't take any of this", marks the
    // settlement attempt as concluded, and moves on without flagging us.
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let ack = PaymentAckPb {
        amount: Vec::new(),
        timestamp,
    };
    write_delimited(&mut stream, &ack).await?;
    let _ = stream.close().await;
    Ok(())
}

/// Per-peer state held by the driver. Tracking the last refresh
/// at all means we can space refreshes correctly even when the
/// fetcher streams hundreds of "I just used peer X" notifications in
/// quick succession.
#[derive(Debug, Clone, Copy)]
struct PeerState {
    /// A refresh to this peer is in flight (bee's `refreshOngoing`): at
    /// most one at a time, so two can't reach bee in the same second.
    in_flight: bool,
    /// Earliest time the next refresh may start: [`MIN_REFRESH_INTERVAL`]
    /// after the previous one *completed* (bee's
    /// `refreshTimestampMilliseconds`, set when the refresh concludes),
    /// or the failure back-off.
    next_at: Option<Instant>,
    /// Consecutive failed refreshes, for the [`FAILED_REFRESH_BACKOFF`]
    /// doubling. Reset by any answered refresh.
    failures: u32,
    /// Last time the fetcher said it succeeded with this peer (or the
    /// mirror said we owe it). Drives pruning: peers we haven't used in a
    /// while drop out of the active set once they leave the routing set.
    last_used: Instant,
}

impl PeerState {
    fn new(now: Instant) -> Self {
        Self {
            in_flight: false,
            next_at: None,
            failures: 0,
            last_used: now,
        }
    }

    /// Whether a refresh may start now. `debt` is what the accounting
    /// mirror says a refresh would clear when one is due by debt
    /// ([`Accounting::refresh_due`]), `None` when it isn't; with no
    /// mirror attached (`has_mirror == false`) every notified peer is
    /// refreshed on the interval, as before the mirror existed.
    fn due(&self, now: Instant, has_mirror: bool, debt: Option<u64>) -> bool {
        !self.in_flight
            && self.next_at.is_none_or(|at| now >= at)
            && (!has_mirror || debt.is_some())
    }

    /// Record the end of a refresh: the next one may start
    /// [`MIN_REFRESH_INTERVAL`] from now, or after the back-off when it
    /// failed.
    fn finish(&mut self, now: Instant, answered: bool) {
        self.in_flight = false;
        if answered {
            self.failures = 0;
            self.next_at = Some(now + MIN_REFRESH_INTERVAL);
        } else {
            self.failures = self.failures.saturating_add(1);
            let backoff = FAILED_REFRESH_BACKOFF
                .saturating_mul(1 << (self.failures - 1).min(4))
                .min(MAX_FAILED_REFRESH_BACKOFF);
            self.next_at = Some(now + backoff);
        }
    }
}

/// Outcome of one dispatched refresh, reported back to the driver loop.
#[derive(Debug, Clone, Copy)]
enum Outcome {
    /// Bee answered with a `PaymentAck` for this many units.
    Accepted(u64),
    /// The stream failed before an ack (open, headers, reset — bee resets
    /// the stream on a refusal such as `ErrSettlementTooSoon`).
    Failed,
    /// No ack within [`STREAM_TIMEOUT`].
    TimedOut,
}

/// Aggregate counters surfaced periodically by the driver so an
/// operator can confirm pseudosettle is functioning without turning on
/// per-peer trace logging. Cumulative since process start.
#[derive(Debug, Default, Clone, Copy)]
struct DriverMetrics {
    /// Refreshes bee acknowledged with a non-zero amount.
    accepted: u64,
    /// Refreshes bee acknowledged with zero: it saw no debt to clear.
    /// (Bee's refusals proper, such as `ErrSettlementTooSoon`, reset the
    /// stream and count as `failed`.)
    accepted_zero: u64,
    /// Sum of `accepted` units across all acknowledged refreshes.
    units_accepted: u128,
    /// Refreshes that errored before reaching a `PaymentAck` — most
    /// commonly because the peer disconnected, or bee reset the stream.
    failed: u64,
    /// Refreshes that hit [`STREAM_TIMEOUT`] before completing.
    timed_out: u64,
}

impl DriverMetrics {
    fn record(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Accepted(0) => self.accepted_zero += 1,
            Outcome::Accepted(units) => {
                self.accepted += 1;
                self.units_accepted = self.units_accepted.saturating_add(u128::from(units));
            }
            Outcome::Failed => self.failed += 1,
            Outcome::TimedOut => self.timed_out += 1,
        }
    }

    fn attempts(&self) -> u64 {
        self.accepted + self.accepted_zero + self.failed + self.timed_out
    }
}

/// Pick the refreshes to start this tick, most indebted peer first, at
/// most `permits` of them, and mark them in flight. A peer that is due
/// but doesn't get a permit stays due and is reconsidered on the next
/// tick; nothing queues behind the in-flight cap, so a refresh never
/// starts late against a peer that has gone or a debt that has changed.
fn pick_refreshes(
    state: &mut HashMap<PeerId, PeerState>,
    live: &HashSet<PeerId>,
    debts: &HashMap<PeerId, u64>,
    has_mirror: bool,
    now: Instant,
    permits: usize,
) -> Vec<PeerId> {
    let mut due: Vec<(u64, PeerId)> = state
        .iter()
        .filter(|(peer, s)| {
            live.contains(*peer) && s.due(now, has_mirror, debts.get(*peer).copied())
        })
        .map(|(peer, _)| (debts.get(peer).copied().unwrap_or(0), *peer))
        .collect();
    due.sort_unstable_by_key(|(debt, _)| std::cmp::Reverse(*debt));
    due.truncate(permits);
    due.into_iter()
        .map(|(_, peer)| {
            if let Some(s) = state.get_mut(&peer) {
                s.in_flight = true;
            }
            peer
        })
        .collect()
}

/// Run the driver loop forever. Reads from `notify_rx` (peers we've
/// just fetched chunks from) and `hot_rx` (peers whose mirrored debt
/// crossed the hot threshold), and every [`REFRESH_TICK`] starts a
/// [`refresh_peer`] for each peer a refresh is due to.
///
/// The rules are bee's dialer side (`Accounting.settle`,
/// `pseudosettle.Pay`):
///
/// - **Only when owed.** With the accounting mirror attached, a refresh
///   is due only once the mirror's debt to the peer reaches bee's settle
///   trigger ([`Accounting::refresh_due`]). Bee answers a refresh with
///   `min(asked, elapsed × lightRefreshRate, our debt)` and restarts the
///   peer's allowance clock even when that is zero, so refreshing a peer
///   we owe nothing wastes a stream and the allowance it had built up.
/// - **One at a time, a second apart.** At most one refresh per peer is
///   in flight, and the next starts [`MIN_REFRESH_INTERVAL`] after the
///   previous one completed. Bee refuses a second refresh within the
///   same Unix second (`ErrSettlementTooSoon`) by resetting the stream.
/// - **No backlog.** A refresh starts only with a free in-flight permit
///   ([`MAX_INFLIGHT_REFRESHES`]); the most indebted due peers go first,
///   the rest wait for the next tick instead of queueing.
/// - **Back off after a failure** ([`FAILED_REFRESH_BACKOFF`], doubling),
///   so a connection bee no longer serves isn't hit every second.
///
/// `notify_rx` and `hot_rx` only register peers; with the mirror
/// attached they never schedule a refresh by themselves. That makes the
/// mirror's accuracy load-bearing: bee clamps each refresh to its own
/// view of our debt, so a refresh clears debt the mirror missed too, but
/// only once the *mirrored* debt to that peer reaches the trigger. Debt
/// bee applied and the mirror never recorded (a request dropped after
/// bee wrote the delivery) is cleared only when that happens. Every
/// billable request must therefore record its debit even when it is
/// abandoned. There are three billable request sites, and all do: the
/// `RoutingFetcher`'s retrieval hands losing hedges *and* requests still
/// in flight when its caller drops the fetch (an outer timeout, a client
/// gone) to its loser drain (`InFlight` in `ant-retrieval`'s
/// `fetcher.rs`); the verify leaf probe waits out a timed-out request
/// (`probe_draining_late_delivery` in `behaviour.rs`); and pushsync
/// (`RoutingFetcher::push_stamped_chunk`) debits every receipt it reads,
/// shallow ones included, and hands pushes still in flight when it
/// returns or is dropped to a drain that debits late receipts
/// (`PushInFlight`). An attempt that errors, or hits its own pushsync
/// timeout, before a receipt is read records nothing.
///
/// `peers_rx` carries the routing-table snapshot — the peers we've
/// completed the BZZ handshake with and can actually open substreams
/// to. The driver consults it every tick and skips refreshes for
/// peers that are no longer in the snapshot, so long-lived gateway
/// load (where the routing set churns through thousands of peers per
/// hour) doesn't spend refreshes on `no addresses for peer` errors.
pub async fn run_driver(
    control: Control,
    mut notify_rx: mpsc::Receiver<PeerId>,
    mut hot_rx: mpsc::Receiver<HotHint>,
    peers_rx: watch::Receiver<Vec<(PeerId, [u8; 32])>>,
    accounting: Option<Arc<Accounting>>,
) {
    let mut state: HashMap<PeerId, PeerState> = HashMap::new();
    let semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT_REFRESHES));
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<(PeerId, Outcome)>();
    let mut tick = tokio::time::interval(REFRESH_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut metrics = DriverMetrics::default();
    // Log a summary roughly once per minute. A peer is refreshed at most
    // once a second, and only while the mirror says we owe it (see the
    // rules above), so a busy fetch from ~150 indebted peers is at most a
    // few thousand events per summary — granular enough to spot a
    // regression, sparse enough to keep the log file readable.
    let summary_every = Duration::from_mins(1);
    let mut last_summary = Instant::now();
    let mut last_metrics = DriverMetrics::default();

    let touch = |state: &mut HashMap<PeerId, PeerState>, peer: PeerId, now: Instant| {
        state
            .entry(peer)
            .and_modify(|s| s.last_used = now)
            .or_insert_with(|| PeerState::new(now));
    };

    loop {
        tokio::select! {
            biased;
            Some((peer, outcome)) = done_rx.recv() => {
                metrics.record(outcome);
                let now = Instant::now();
                if let Some(s) = state.get_mut(&peer) {
                    s.finish(now, matches!(outcome, Outcome::Accepted(_)));
                }
            }
            recv = notify_rx.recv() => {
                let Some(peer) = recv else {
                    debug!(target: "ant_p2p::pseudosettle", "notify channel closed; driver exiting");
                    return;
                };
                touch(&mut state, peer, Instant::now());
            }
            Some(hint) = hot_rx.recv() => {
                // A hot hint only says "this peer's debt just went up";
                // whether a refresh is due is read from the mirror on the
                // next tick (at most `REFRESH_TICK` away).
                touch(&mut state, hint.peer, Instant::now());
            }
            _ = tick.tick() => {
                let now = Instant::now();
                // Drain the notify queues opportunistically — if the
                // fetcher is hot and the receive futures above keep
                // losing the select race, this catches up so we don't
                // starve out new peers indefinitely.
                while let Ok(peer) = notify_rx.try_recv() {
                    touch(&mut state, peer, now);
                }
                while let Ok(hint) = hot_rx.try_recv() {
                    touch(&mut state, hint.peer, now);
                }
                // What the mirror says is owed, per peer, right now.
                let debts = accounting
                    .as_ref()
                    .map(|acc| acc.refresh_due())
                    .unwrap_or_default();
                for peer in debts.keys() {
                    touch(&mut state, *peer, now);
                }
                // Snapshot the live routing set once per tick. Reading
                // the watch is cheap (Arc clone of the inner Vec), and
                // collecting into a `HashSet<PeerId>` makes the
                // per-peer membership check below O(1).
                let live: HashSet<PeerId> = peers_rx
                    .borrow()
                    .iter()
                    .map(|(p, _)| *p)
                    .collect();

                // Drop peers we haven't seen on the routing watch for
                // a while. Without this filter the gateway-style load
                // (BZZ-streaming a big file pulls chunks from peers
                // that subsequently disconnect) leaves thousands of
                // stale entries. A refresh in flight keeps its entry
                // until it reports back.
                state.retain(|peer, s| {
                    if live.contains(peer) || s.in_flight {
                        return true;
                    }
                    // Off the routing set: if it comes back, it's a new
                    // connection, which bee serves afresh, so the failure
                    // back-off doesn't carry over (the interval does).
                    s.failures = 0;
                    s.next_at = s.next_at.map(|at| at.min(now + MIN_REFRESH_INTERVAL));
                    // Brief grace period so a peer that flapped the
                    // connection between the fetcher's notify and
                    // this tick still gets one shot at a refresh —
                    // libp2p frequently closes and re-opens the same
                    // connection in <100 ms during yamux idle resets.
                    now.duration_since(s.last_used) < Duration::from_secs(5)
                });

                let picked = pick_refreshes(
                    &mut state,
                    &live,
                    &debts,
                    accounting.is_some(),
                    now,
                    semaphore.available_permits(),
                );
                for peer in picked {
                    let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                        // Can't happen (we picked at most the free
                        // permits and nothing else takes them); undo.
                        if let Some(s) = state.get_mut(&peer) {
                            s.in_flight = false;
                        }
                        continue;
                    };
                    let mut control = control.clone();
                    let accounting = accounting.clone();
                    let done_tx = done_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let result = tokio::time::timeout(
                            STREAM_TIMEOUT,
                            refresh_peer(&mut control, peer),
                        )
                        .await;
                        let outcome = match result {
                            Ok(Ok(ok)) => {
                                if ok.accepted > 0 {
                                    if let Some(acc) = accounting.as_ref() {
                                        acc.credit(peer, ok.accepted);
                                    }
                                }
                                trace!(
                                    target: "ant_p2p::pseudosettle",
                                    %peer,
                                    accepted = ok.accepted,
                                    timestamp = ok.timestamp,
                                    "refresh ok",
                                );
                                Outcome::Accepted(ok.accepted)
                            }
                            Ok(Err(e)) => {
                                debug!(
                                    target: "ant_p2p::pseudosettle",
                                    %peer,
                                    "refresh failed: {e}",
                                );
                                Outcome::Failed
                            }
                            Err(_) => {
                                debug!(
                                    target: "ant_p2p::pseudosettle",
                                    %peer,
                                    "refresh timed out after {}s",
                                    STREAM_TIMEOUT.as_secs(),
                                );
                                Outcome::TimedOut
                            }
                        };
                        let _ = done_tx.send((peer, outcome));
                    });
                }

                // Periodic summary. Only emit when we've actually done
                // something this window, otherwise an idle daemon would
                // fill its log with empty status lines.
                if now.duration_since(last_summary) >= summary_every {
                    let snap = metrics;
                    let delta = |f: fn(&DriverMetrics) -> u64| f(&snap).saturating_sub(f(&last_metrics));
                    let delta_units = snap
                        .units_accepted
                        .saturating_sub(last_metrics.units_accepted);
                    if snap.attempts() > last_metrics.attempts() {
                        info!(
                            target: "ant_p2p::pseudosettle",
                            active_peers = state.len(),
                            accepted = delta(|m| m.accepted),
                            accepted_zero = delta(|m| m.accepted_zero),
                            failed = delta(|m| m.failed),
                            timed_out = delta(|m| m.timed_out),
                            units_accepted = delta_units as u64,
                            "refresh summary (last {}s)",
                            summary_every.as_secs(),
                        );
                    }
                    last_summary = now;
                    last_metrics = snap;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_int_be_round_trip() {
        for v in [
            0u64,
            1,
            0xff,
            0x100,
            12345,
            450_000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let bytes = big_int_be_bytes(v);
            let parsed = parse_be_u64(&bytes).unwrap();
            assert_eq!(parsed, v, "round trip {v}");
            // bee's encoding has no leading zeroes (or empty for zero).
            if v != 0 {
                assert_ne!(bytes[0], 0, "leading zero for {v}");
            } else {
                assert!(bytes.is_empty(), "zero must encode empty");
            }
        }
    }

    use libp2p::swarm::SwarmEvent;
    use libp2p::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
    use std::sync::Mutex;

    /// Bee's pseudosettle listener (`pseudosettle.go::handler`) reduced to
    /// what the driver can observe: it accepts
    /// `min(asked, (now − last) × lightRefreshRate, debt)` with `now` in
    /// Unix seconds, refuses a second refresh in the same second by
    /// resetting the stream (`ErrSettlementTooSoon`), and restarts its
    /// allowance clock on every refresh it answers, zero included.
    #[derive(Default)]
    struct FakeBee {
        /// What bee thinks we owe it.
        debt: u64,
        /// Unix second of the last answered refresh (0: never).
        last_ts: u64,
        /// Amount of every answered refresh, in order.
        acks: Vec<u64>,
        /// Refreshes refused for arriving in the same second.
        too_soon: u32,
        /// Streams opened to it.
        streams: u32,
        in_flight: u32,
        max_in_flight: u32,
        /// Reset every stream before the headers (a connection bee hasn't
        /// registered: `overlay address for peer not found`).
        reset_all: bool,
        /// Delay before answering the headers (a slow peer).
        delay: Duration,
    }

    fn unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn serve_fake_bee(mut stream: Stream, bee: Arc<Mutex<FakeBee>>) {
        let (reset_all, delay) = {
            let mut b = bee.lock().unwrap();
            b.streams += 1;
            b.in_flight += 1;
            b.max_in_flight = b.max_in_flight.max(b.in_flight);
            (b.reset_all, b.delay)
        };
        let done = |bee: &Arc<Mutex<FakeBee>>| bee.lock().unwrap().in_flight -= 1;
        if reset_all {
            done(&bee);
            return; // dropped: the dialer sees the stream end
        }
        tokio::time::sleep(delay).await;
        if read_delimited(&mut stream, HEADERS_MAX).await.is_err()
            || write_empty_headers(&mut stream).await.is_err()
        {
            done(&bee);
            return;
        }
        let Ok(raw) = read_delimited(&mut stream, 256).await else {
            done(&bee);
            return;
        };
        let asked = parse_be_u64(&PaymentPb::decode(raw.as_slice()).unwrap().amount).unwrap();
        let ack = {
            let mut b = bee.lock().unwrap();
            let now = unix_secs();
            if now == b.last_ts {
                b.too_soon += 1;
                None
            } else {
                let allowance = now
                    .saturating_sub(b.last_ts)
                    .saturating_mul(LIGHT_REFRESH_RATE_UNITS_PER_SEC);
                let accepted = asked.min(allowance).min(b.debt);
                b.debt -= accepted;
                b.last_ts = now;
                b.acks.push(accepted);
                Some(PaymentAckPb {
                    amount: big_int_be_bytes(accepted),
                    timestamp: now as i64,
                })
            }
        };
        if let Some(ack) = ack {
            let _ = write_delimited(&mut stream, &ack).await;
            let _ = stream.close().await;
        }
        done(&bee);
    }

    fn stream_swarm() -> Swarm<libp2p_stream::Behaviour> {
        SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| libp2p_stream::Behaviour::default())
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    }

    /// A fake bee peer connected to a node running the real [`run_driver`],
    /// wired as `behaviour.rs` wires it: the accounting mirror's hot hints
    /// feed the driver. Returns the mirror, the bee's peer id and state.
    async fn driver_against_fake_bee(
        bee: FakeBee,
    ) -> (Arc<Accounting>, PeerId, Arc<Mutex<FakeBee>>) {
        let bee = Arc::new(Mutex::new(bee));
        let mut bee_swarm = stream_swarm();
        let bee_peer = *bee_swarm.local_peer_id();
        let mut incoming = bee_swarm
            .behaviour()
            .new_control()
            .accept(StreamProtocol::new(PROTOCOL_PSEUDOSETTLE))
            .unwrap();
        bee_swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr: Multiaddr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = bee_swarm.select_next_some().await {
                break address;
            }
        };
        tokio::spawn(async move {
            loop {
                bee_swarm.select_next_some().await;
            }
        });
        let served = bee.clone();
        tokio::spawn(async move {
            while let Some((_, stream)) = incoming.next().await {
                tokio::spawn(serve_fake_bee(stream, served.clone()));
            }
        });

        let mut node = stream_swarm();
        let control = node.behaviour().new_control();
        node.dial(addr).unwrap();
        loop {
            if let SwarmEvent::ConnectionEstablished { .. } = node.select_next_some().await {
                break;
            }
        }
        tokio::spawn(async move {
            loop {
                node.select_next_some().await;
            }
        });

        let (notify_tx, notify_rx) = mpsc::channel(NOTIFY_CHANNEL_CAP);
        let (hot_tx, hot_rx) = mpsc::channel(HOT_HINT_CHANNEL_CAP);
        let accounting = Arc::new(Accounting::new().with_hot_hint(hot_tx));
        let mirror = accounting.clone();
        let (peers_tx, peers_rx) = watch::channel(vec![(bee_peer, [0u8; 32])]);
        tokio::spawn(async move {
            run_driver(control, notify_rx, hot_rx, peers_rx, Some(accounting)).await;
            drop((notify_tx, peers_tx));
        });
        (mirror, bee_peer, bee)
    }

    /// Issue #129: a refresh only when the mirror says we owe the peer,
    /// one at a time. On `main` the driver refreshed every tracked peer
    /// every 1.1 s from dispatch, owed or not: against a slow peer two
    /// refreshes overlapped, and once the debt was paid every further
    /// refresh was answered with zero (and restarted bee's allowance
    /// clock). Here the one debt is cleared by one refresh and nothing
    /// else is sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refreshes_only_what_is_owed_one_at_a_time() {
        let bee = FakeBee {
            debt: 1_200_000,
            delay: Duration::from_millis(1_500),
            ..FakeBee::default()
        };
        let (accounting, bee_peer, bee) = driver_against_fake_bee(bee).await;
        accounting.debit(bee_peer, 1_200_000);

        tokio::time::sleep(Duration::from_secs(6)).await;
        let b = bee.lock().unwrap();
        assert_eq!(b.max_in_flight, 1, "refreshes to one peer overlapped");
        assert_eq!(b.too_soon, 0, "a refresh was refused as too soon");
        assert_eq!(b.acks, vec![1_200_000], "refreshes answered: {:?}", b.acks);
        assert_eq!(accounting.debug_snapshot(&bee_peer), Some((0, 0)));
    }

    /// Issue #129: a failing peer is backed off, not hit every 1.1 s.
    /// Bee resets every stream on a connection it hasn't registered;
    /// `main` kept refreshing such a peer every 1.1 s (5–6 attempts in
    /// 6.5 s). Doubling from 1 s, the driver tries at ~0, 1, 3 s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_refreshes_back_off() {
        let bee = FakeBee {
            reset_all: true,
            ..FakeBee::default()
        };
        let (accounting, bee_peer, bee) = driver_against_fake_bee(bee).await;
        accounting.debit(bee_peer, 1_200_000);

        tokio::time::sleep(Duration::from_millis(6_500)).await;
        let streams = bee.lock().unwrap().streams;
        assert!(
            (2..=4).contains(&streams),
            "{streams} refresh attempts on a failing peer in 6.5 s"
        );
    }

    /// The bee rules don't starve a steadily indebted peer: debt growing
    /// at 1 M units/s (faster than the 450 k/s refresh rate) is refreshed
    /// every second, never refused as too soon, never answered with zero,
    /// and the refresh keeps up with bee's allowance.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sustained_debt_is_refreshed_every_second() {
        let (accounting, bee_peer, bee) = driver_against_fake_bee(FakeBee::default()).await;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            bee.lock().unwrap().debt += 100_000;
            accounting.debit(bee_peer, 100_000);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let b = bee.lock().unwrap();
        assert_eq!(b.too_soon, 0, "a refresh was refused as too soon");
        assert!(
            !b.acks.contains(&0),
            "a refresh was answered with zero: {:?}",
            b.acks
        );
        assert!(
            b.acks.len() >= 3,
            "only {} refreshes in 5 s: {:?}",
            b.acks.len(),
            b.acks
        );
        // First refresh: bee's clock starts at 0, so the whole debt;
        // then up to one or two seconds of allowance each.
        let accepted: u64 = b.acks.iter().sum();
        assert!(
            accepted >= 2_500_000,
            "accepted {accepted} of ~5 M: {:?}",
            b.acks
        );
    }

    #[test]
    fn peer_state_spaces_from_completion_and_backs_off() {
        let t0 = Instant::now();
        let mut s = PeerState::new(t0);
        assert!(s.due(t0, true, Some(1)));
        assert!(!s.due(t0, true, None), "nothing owed, nothing due");
        assert!(s.due(t0, false, None), "without a mirror: on the interval");
        s.in_flight = true;
        assert!(
            !s.due(t0 + Duration::from_secs(5), true, Some(1)),
            "one at a time"
        );
        // Completed 2 s after it started: the next one is a second after
        // the completion, not after the start.
        let done = t0 + Duration::from_secs(2);
        s.finish(done, true);
        assert!(!s.due(done + Duration::from_millis(999), true, Some(1)));
        assert!(s.due(done + MIN_REFRESH_INTERVAL, true, Some(1)));
        // Failures double the back-off up to the cap; an answer resets it.
        let mut at = done;
        for expect in [1, 2, 4, 8, 16, 16] {
            s.finish(at, false);
            let wait = Duration::from_secs(expect);
            let just_before = (at + wait).checked_sub(Duration::from_millis(1)).unwrap();
            assert!(!s.due(just_before, true, Some(1)));
            assert!(s.due(at + wait, true, Some(1)));
            at += wait;
        }
        s.finish(at, true);
        assert!(s.due(at + MIN_REFRESH_INTERVAL, true, Some(1)));
    }

    #[test]
    fn picks_most_indebted_live_due_peers_up_to_the_free_permits() {
        let now = Instant::now();
        let peers: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
        let mut state: HashMap<PeerId, PeerState> =
            peers.iter().map(|p| (*p, PeerState::new(now))).collect();
        let live: HashSet<PeerId> = peers[..3].iter().copied().collect();
        let debts: HashMap<PeerId, u64> = [
            (peers[0], 500_000),
            (peers[1], 900_000),
            (peers[3], 2_000_000), // not live
        ]
        .into_iter()
        .collect();
        // peers[2] is live but owes nothing.
        assert_eq!(
            pick_refreshes(&mut state, &live, &debts, true, now, 1),
            vec![peers[1]]
        );
        assert!(state[&peers[1]].in_flight);
        assert_eq!(
            pick_refreshes(&mut state, &live, &debts, true, now, 8),
            vec![peers[0]],
            "in-flight and nothing-owed peers are skipped"
        );
        assert_eq!(
            pick_refreshes(&mut state, &live, &debts, true, now, 8),
            Vec::<PeerId>::new()
        );
    }

    #[test]
    fn parse_be_u64_rejects_oversize() {
        assert!(parse_be_u64(&[0u8; 9]).is_none());
        assert_eq!(parse_be_u64(&[]), Some(0));
        assert_eq!(parse_be_u64(&[0x01]), Some(1));
        assert_eq!(parse_be_u64(&[0x01, 0x00]), Some(256));
    }
}
