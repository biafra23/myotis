//! Pushsync-side settlement hook.
//!
//! # Why this exists
//!
//! `RoutingFetcher::push_stamped_chunk` opens a `/swarm/pushsync/1.3.1/pushsync`
//! stream to the closest peer for each chunk we upload. Bee runs accounting
//! on its end of that stream: every chunk we push adds `chunk_price` PLUR to
//! the receiver's view of *our* outbound debt to *them*
//! (`pkg/accounting/accounting.go::Debit`). When that debt crosses bee's
//! `paymentThreshold` (13.5 M PLUR full-mode, 1.35 M PLUR light-mode), bee
//! either accepts a few more chunks under `paymentTolerance` or silently
//! RST's the next pushsync stream. Without us settling the debt with a
//! [`/swarm/swap/1.0.0/swap`](crate::pushsync) cheque before we cross the
//! line, every peer eventually freezes us out — exactly the behaviour
//! observed in production on 2026-05-08 when the GGUF upload stalled at
//! ~20K successful chunks across the whole peer set (≈ 200 chunks per
//! peer ≈ bee's `paymentTolerance` envelope).
//!
//! # What this trait does
//!
//! Decouples the pushsync hot path from the accounting / SWAP code. The
//! fetcher knows nothing about chequebooks, EIP-712, libp2p swap streams,
//! or chain ids. Like bee's pushsync client (`pushToClosest`, which runs
//! `accounting.PrepareCredit` before every push and skips the peer on
//! `ErrOverdraft`), it asks [`PushsyncSettlement::prepare_credit`] for
//! credit with a peer *before* it pushes to it (issue #128):
//!
//! - `None` means the push would take our debt to that peer past its
//!   disconnect limit, so the fetcher skips the peer for this chunk for
//!   [`OVERDRAFT_REFRESH`](crate::accounting::OVERDRAFT_REFRESH) and
//!   pushes to the next-closest one instead. Pushing anyway is what got
//!   busy peers to disconnect or blocklist us (bee's `debitAction.Apply`).
//! - `Some(credit)` reserves the price. Once a receipt is read — deep or
//!   shallow, from the winner or from a hedge drained after the walk
//!   returned, since the storer debits us for each receipt it writes —
//!   the fetcher calls [`PushCredit::apply`] (bee's `Action.Apply`); a
//!   push that ends without one drops it, which releases the reservation
//!   (bee's `Action.Cleanup`).
//!
//! The implementation in `ant-p2p::push_pseudosettle` reserves in the
//! shared [`Accounting`](crate::accounting::Accounting) mirror — bee's
//! one balance per peer for every protocol — which settles it like
//! retrieval debt: the free pseudosettle refresh first, then, with a
//! payer installed (a funded chequebook with `swap-enable` on), a cheque
//! priced `units × exchange + deduction` once the debt reaches the
//! early-payment threshold (issue #127).
//!
//! # Failure mode
//!
//! Settlement is best-effort. A failed payment (peer disconnect
//! mid-stream, swap protocol Reset, timeout) does NOT fail the upload;
//! the mirror keeps the debt, backs off for
//! [`FAILED_SETTLEMENT_INTERVAL`](crate::accounting::FAILED_SETTLEMENT_INTERVAL)
//! and leaves it to the refresh meanwhile.
//!
//! # Live integration
//!
//! [`RoutingFetcher::with_pushsync_settlement`](crate::RoutingFetcher::with_pushsync_settlement)
//! installs an `Arc<dyn PushsyncSettlement>`. `None` (the default) keeps
//! the legacy "push without settlement" behaviour for tests and for the
//! ultra-light read-only build.

use libp2p::PeerId;

/// Bee's `pkg/pricer/pricer.go::PeerPrice`:
///
/// ```text
/// price = (MaxPO - proximity(peer, chunk) + 1) * basePrice
/// ```
///
/// where `MaxPO = 31` and `basePrice = 10_000` PLUR. This is the same
/// constant used by [`crate::accounting::Accounting::peer_price`] on the
/// retrieval side; we re-export the calculation here so callers don't
/// have to construct an `Accounting` just to learn the price.
///
/// Returns the chunk price in PLUR for `peer` retrieving / pushing
/// `chunk_addr`.
#[must_use]
pub fn peer_chunk_price(peer_overlay: &[u8; 32], chunk_addr: &[u8; 32]) -> u64 {
    crate::accounting::Accounting::peer_price(peer_overlay, chunk_addr)
}

/// A reservation of credit for one push, from
/// [`PushsyncSettlement::prepare_credit`]: bee's `accounting.Action`.
/// [`PushCredit::apply`] records the debit once the peer has written a
/// receipt; dropping it unapplied releases the reservation.
pub struct PushCredit(Box<dyn PushCreditAction>);

impl PushCredit {
    /// Wrap an implementation's reservation.
    #[must_use]
    pub fn new(action: impl PushCreditAction + 'static) -> Self {
        Self(Box::new(action))
    }

    /// The peer wrote a receipt (deep or shallow): record the debit.
    pub fn apply(self) {
        self.0.apply();
    }
}

/// What a [`PushCredit`] does on [`PushCredit::apply`]. Dropping the
/// action unapplied must release whatever it reserved.
pub trait PushCreditAction: Send {
    /// Record the reserved debit.
    fn apply(self: Box<Self>);
}

impl PushCreditAction for crate::accounting::DebitGuard {
    fn apply(self: Box<Self>) {
        (*self).apply();
    }
}

/// Settlement hook for pushsync.
///
/// Implemented by `ant-p2p::push_pseudosettle::PushPseudosettle`. The
/// fetcher holds an `Arc<dyn PushsyncSettlement>`, calls
/// [`Self::prepare_credit`] before every push and applies the credit for
/// every receipt it reads (deep or shallow). A payment, when one is due,
/// runs in the background (the mirror's settle step), never on the push
/// path.
///
/// Settlement itself is best-effort: a failed payment doesn't fail the
/// upload. Only the credit check gates a push, as in bee.
pub trait PushsyncSettlement: Send + Sync {
    /// Bee's `PrepareCredit` for one push of `price` (the chunk price in
    /// PLUR, [`peer_chunk_price`] of the peer's overlay vs the chunk
    /// address) to `peer`. `None`: the push would cross the peer's
    /// disconnect limit, so don't push to it now. `Some`: the price is
    /// reserved until the returned credit is applied or dropped.
    fn prepare_credit(&self, peer: PeerId, price: u64) -> Option<PushCredit>;

    /// Drop all settlement state for `peer`, called from the swarm's
    /// `ConnectionClosed` handler. Bee's accounting resets per peer
    /// connection (`notifyPeerConnect`), so we must too — otherwise a
    /// reconnected peer carries over a phantom debt.
    fn forget(&self, peer: &PeerId);
}
