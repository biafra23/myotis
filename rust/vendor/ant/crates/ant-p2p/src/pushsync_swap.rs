//! Outbound SWAP settlement: the node's cheque payer.
//!
//! # What this does
//!
//! [`PushsyncSwap`] pays peers with EIP-712 `/swarm/swap/1.0.0/swap`
//! cheques drawn on the node's chequebook, the way bee's
//! `swapprotocol.EmitCheque` does: it reads the recipient's `exchange` /
//! `deduction` response headers, refuses rates above bee's price oracle,
//! pays `units × exchange + deduction` PLUR and never issues past
//! `deposit − total issued` (bee's `AvailableBalance`). It is the
//! [`RetrievalPayment`] of the shared `ant_retrieval::accounting`
//! mirror, which holds one balance per peer for downloads *and* uploads
//! (as bee's accounting does) and decides when to pay; see
//! [`PushsyncSwap`].
//!
//! # History
//!
//! Until issue #127 the pushsync side kept its own debt counter here and
//! emitted cheques for `debt` *PLUR* whenever it crossed 675 K, ignoring
//! the exchange rate: bee credited about 1/100 000 of the debt, so
//! uploads really settled by the free refresh alone. Pushsync debt now
//! goes into the shared mirror (`push_pseudosettle::PushPseudosettle`)
//! and is paid by the same payer, priced like bee, under the same
//! `swap-enable` switch.
//!
//! # Glossary
//!
//! - **Beneficiary**: 20-byte EOA recovered from the peer's BZZ
//!   handshake signature (`HandshakeInfo::remote_eth_address`). It's
//!   the address bee credits when it cashes our cheque.
//! - **Cumulative payout**: the running total of PLUR our chequebook
//!   has authorised paying to this beneficiary across our entire
//!   relationship. EIP-712 cheques are cumulative — cheque N+1 has
//!   `cumulative = cheque N's cumulative + delta`. Bee accepts the
//!   highest cumulative it sees and ignores duplicates / older ones.
//!
//! # Wiring
//!
//! `antd` and `ant-ffi` build one [`PushsyncSwap`] per chequebook
//! (`--chequebook` / `--swap-key`, or the FFI's settlement setup). The
//! swarm loop populates [`PeerEthMap`] in the BZZ-handshake-success
//! branch and installs the service as the accounting payer while the
//! node's `swap-enable` switch is on and the chequebook has funds.

use crate::swap::{
    await_processed, issue_cheque, open_settlement, write_cheque, OutboundLedger, PendingWrite,
    SettlementRates, SwapError,
};
use ant_crypto::SECP256K1_SECRET_LEN;
use ant_retrieval::accounting::RetrievalPayment;
use ant_retrieval::PushsyncSettlement;
use libp2p::PeerId;
use libp2p_stream::Control;
use primitive_types::U256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::info;

/// How long one SWAP payment may take, from opening the swap stream to
/// the recipient finishing with the cheque: bee's
/// `swapprotocol.EmitCheque` timeout.
pub const RETRIEVAL_PAYMENT_TIMEOUT: Duration = Duration::from_secs(5);

/// What SWAP payments may spend, and at which rates: for downloads
/// (issue #121) and uploads (issue #127) alike, since both settle from
/// the one accounting mirror. (The `Retrieval` in the name predates
/// #127.) Read from the chain by the entry points
/// (`ant_chain::chequebook_store::watch_retrieval_funds`) and installed
/// with [`PushsyncSwap::set_retrieval_policy`]; without one, the node
/// stays on the free pseudosettle tier.
///
/// Bee pays a peer `units × exchange + deduction` PLUR, with both rates
/// read from the recipient's swap response headers and required to equal
/// its own price oracle's. Ant takes the oracle's values as ceilings, so
/// a peer can't name its own price.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrievalSwapPolicy {
    /// xBZZ ever deposited into the chequebook and not withdrawn, in
    /// PLUR (balance + `totalPaidOut`). Every cheque issued so far (the
    /// outbound ledger's total) comes off it, as in bee's
    /// `AvailableBalance`: cheques never exceed the chequebook, which is
    /// bee's only cap too. Once it's spent, debt settles with the free
    /// refresh alone.
    pub deposited_plur: U256,
    /// Highest `exchange` header accepted, PLUR per accounting unit.
    pub max_exchange_rate: U256,
    /// Highest `deduction` header accepted, PLUR.
    pub max_deduction: U256,
}

/// Shared `peer_id -> ethereum_address` registry, populated by the
/// BZZ-handshake handler and consumed by [`PushsyncSwap`] to find the
/// cheque beneficiary for a libp2p peer. Held behind an `Arc<RwLock>`
/// so the handshake handler can write while concurrent payments read.
///
/// Each entry also carries a *session*: a process-unique number assigned
/// at every handshake and dropped with the entry when the peer's
/// connection closes. A payment notes the session before it sends a
/// cheque and checks it again once the cheque stream has ended, so a
/// connection that closed (or was replaced) meanwhile is seen even though
/// the stream itself can't tell (see [`PushsyncSwap`]'s delivery check).
///
/// The map is intentionally tiny — one 20-byte EOA per peer, peers
/// churn but never accumulate beyond `state.bzz_peers.len() ~= 100` in
/// our peer set: `forget(peer)` from `ConnectionClosed` drops the entry,
/// and a reconnecting peer re-records its EOA under a new session.
#[derive(Default, Clone)]
pub struct PeerEthMap {
    inner: Arc<RwLock<HashMap<PeerId, PeerSession>>>,
}

/// A handshaken peer's EOA and its session number.
type PeerSession = ([u8; 20], u64);

/// Source of [`PeerEthMap`] sessions.
static NEXT_PEER_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl PeerEthMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `eth_address` for `peer` under a new session. Called from
    /// the swarm's `record_handshake` site immediately after a successful
    /// BZZ handshake, where `eth_address =
    /// HandshakeInfo::remote_eth_address`. Overwrites any previous value
    /// silently — bee assumes a stable `(peer_id, eoa)` pairing per
    /// session, and so do we.
    pub fn record(&self, peer: PeerId, eth_address: [u8; 20]) {
        let session = NEXT_PEER_SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut g) = self.inner.write() {
            g.insert(peer, (eth_address, session));
        }
    }

    /// Start a new session for `peer`, keeping its EOA. Called from the
    /// swarm's `ConnectionClosed` handler when one of the peer's
    /// connections closes while another stays open: a cheque stream may
    /// have run on the closed one (it can't be told which), so a payment
    /// in flight must see that its connection may be gone, while the
    /// peer itself stays handshaken. No-op for a peer with no entry.
    pub fn renew_session(&self, peer: &PeerId) {
        if let Ok(mut g) = self.inner.write() {
            if let Some(entry) = g.get_mut(peer) {
                entry.1 = NEXT_PEER_SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Drop `peer`'s entry. Called from the swarm's `ConnectionClosed`
    /// handler so a reconnected peer doesn't carry over a stale EOA, and
    /// so a payment in flight sees that its connection is gone.
    pub fn forget(&self, peer: &PeerId) {
        if let Ok(mut g) = self.inner.write() {
            g.remove(peer);
        }
    }

    /// Look up `peer`'s 20-byte EOA. Returns `None` if the peer's BZZ
    /// handshake hasn't completed yet (rare — the fetcher only picks
    /// from peers it has handshaken) or if the entry has been
    /// evicted by [`Self::forget`].
    #[must_use]
    pub fn get(&self, peer: &PeerId) -> Option<[u8; 20]> {
        self.inner.read().ok()?.get(peer).map(|(eoa, _)| *eoa)
    }

    /// `peer`'s EOA and its current session, if it is connected and
    /// handshaken.
    #[must_use]
    pub fn session(&self, peer: &PeerId) -> Option<([u8; 20], u64)> {
        self.inner.read().ok()?.get(peer).copied()
    }
}

/// Configuration for the outbound SWAP settlement subsystem. Built
/// once at `antd` startup from CLI flags / env, stored on
/// [`crate::RunConfig`], and threaded into the swarm loop where it
/// becomes an `Arc<PushsyncSwap>` shared by every `RoutingFetcher`.
#[derive(Clone)]
pub struct PushsyncSwapConfig {
    /// 20-byte chequebook contract address — owns the BZZ that gets
    /// cashed out. The chequebook's `issuer()` view must return the
    /// EOA derived from `swap_secret`; otherwise bee rejects every
    /// cheque ("invalid issuer signature" on the EIP-712 verification).
    pub chequebook: [u8; 20],
    /// 32-byte secp256k1 secret of the chequebook's issuer EOA. Same
    /// key bee derives at `m/44'/60'/0'/0/0` in its default setup; we
    /// reuse the convention that `WALLET_PRIVATE_KEY` is also the
    /// chequebook owner.
    pub swap_secret: [u8; SECP256K1_SECRET_LEN],
    /// Chain id used for EIP-712 cheque domain separator — bee's
    /// chequebook code is hard-coded to expect `chainId = 100` on
    /// Gnosis mainnet. See `ant_chain::chequebook::eip712_domain_separator`.
    pub chain_id: u64,
    /// Where the outbound cumulative-payout ledger lives on disk.
    /// Restart-safe: the cumulative for each beneficiary is loaded
    /// from this file so we never re-issue an already-emitted cheque
    /// amount (bee would treat a duplicate as a redundant accept,
    /// not a regression, but it wastes a stream).
    pub outbound_ledger_path: PathBuf,
    /// Optional lookup helper threaded from the swarm loop so we can
    /// recover a peer's cheque beneficiary EOA from its libp2p
    /// `PeerId`.
    pub peer_eth: PeerEthMap,
}

impl PushsyncSwapConfig {
    /// Build a config.
    #[must_use]
    pub fn new(
        chequebook: [u8; 20],
        swap_secret: [u8; SECP256K1_SECRET_LEN],
        chain_id: u64,
        outbound_ledger_path: PathBuf,
        peer_eth: PeerEthMap,
    ) -> Self {
        Self {
            chequebook,
            swap_secret,
            chain_id,
            outbound_ledger_path,
            peer_eth,
        }
    }
}

/// State the payer needs. Held behind an `Arc` so the service can be
/// shared by the node loop (which installs it as the accounting payer)
/// and the payments in flight.
struct EmitCore {
    cfg: PushsyncSwapConfig,
    outbound_ledger: OutboundLedger,
    /// `libp2p_stream::Control` clone used to open `/swarm/swap/...`
    /// streams. Cloning `Control` is cheap (`Arc` underneath); each
    /// payment clones it again before calling `open_stream`.
    control: Mutex<Control>,
    /// The funds and rates payments may use; `None` pays nothing (debt
    /// is then settled by the free pseudosettle refresh alone).
    retrieval: Mutex<Option<RetrievalSwapPolicy>>,
    // Issuing is serialised by the ledger's `beneficiary_lock` (two
    // cheques to one peer can't build on the same previous cumulative;
    // bee's `chequebook.Issue` lock) and `funds_gate` (two payments can't
    // pass the funds check on the same funds). Both live with the
    // ledger's state, so they also cover an old service and a new one on
    // the same chequebook (PR #126 R3-M1).
}

/// Live SWAP settlement service: the node's one cheque payer. One per
/// process; installed in the node's accounting as its
/// [`RetrievalPayment`] while `swap-enable` is on and the chequebook has
/// funds (see `behaviour::sync_retrieval_payment`).
///
/// Bee keeps one balance per peer for every protocol, and so does Ant:
/// retrieval debits and pushsync debits both land in the shared
/// `ant_retrieval::accounting::Accounting` mirror (pushsync through
/// `push_pseudosettle::PushPseudosettle`). That mirror settles them the
/// way bee's `Accounting.settle` does: the free pseudosettle refresh
/// first, then a cheque from this service once the debt reaches the
/// early-payment threshold. So uploads and downloads pay through the
/// same code, at the same rate, under the same switch (issue #127).
pub struct PushsyncSwap {
    core: Arc<EmitCore>,
}

/// How long after a cheque stream ends the payer watches the peer's
/// connection before it counts the cheque as delivered.
///
/// Bee's swap handler closes the stream with `FullClose` only after
/// `ReceiveCheque` succeeded, and resets it on any failure. But
/// rust-yamux reports a stream reset, and every stream of a connection
/// that dropped, as a plain end of stream (`Ok(0)`), so the stream alone
/// can't tell an accepted cheque from a refused or lost one. What the
/// payer *can* see is the connection: the swarm loop drops the peer's
/// [`PeerEthMap`] session when its last connection closes, and renews it
/// when any one of several connections closes (it can't tell which one
/// carried the cheque stream). A session that is gone or replaced within
/// this window counts the cheque as undelivered — so a dial-race
/// duplicate closing in the window voids a cheque that went out on the
/// surviving connection too (the mirror stays up; the next cheque pays
/// those units again, and bee credits them). The
/// window covers the swarm loop handling the close after the stream task
/// woke; in the paid runs on PR #126 the two resets showed up in the same
/// millisecond as the stream end.
pub const DELIVERY_GRACE: Duration = Duration::from_millis(100);

impl EmitCore {
    fn control_clone(&self) -> Control {
        self.control
            .lock()
            .expect("pushsync_swap control mutex")
            .clone()
    }

    fn retrieval_policy(&self) -> Option<RetrievalSwapPolicy> {
        match self.retrieval.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        }
    }

    /// PLUR the chequebook can still put into cheques under `policy`:
    /// the deposit less every cheque issued (bee's `AvailableBalance`).
    fn available(&self, policy: &RetrievalSwapPolicy) -> U256 {
        policy
            .deposited_plur
            .saturating_sub(self.outbound_ledger.total_issued())
    }

    /// Record `beneficiary`'s cheque at `new_cumulative` (worth `amount`)
    /// as issued if the funds left cover it, or refuse. Check and record
    /// are one step, so concurrent payments can't overdraw. The record is
    /// in memory on return; the cheque may go out once the returned write
    /// is durable. No file I/O happens under the funds gate (issue #140).
    fn issue_within_funds(
        &self,
        policy: &RetrievalSwapPolicy,
        beneficiary: &[u8; 20],
        new_cumulative: U256,
        amount: U256,
    ) -> Result<PendingWrite, SwapError> {
        let _gate = self.outbound_ledger.funds_gate();
        let left = self.available(policy);
        if left < amount {
            return Err(SwapError::Rejected(format!(
                "chequebook credit exhausted: cheque of {amount} PLUR, {left} left",
            )));
        }
        Ok(self
            .outbound_ledger
            .stage_issued(beneficiary, new_cumulative))
    }

    /// Whether every connection to `peer` was still up
    /// [`DELIVERY_GRACE`] after the cheque stream ended: `session` is the
    /// peer's [`PeerEthMap`] session from before the cheque was sent.
    /// Fails if the session is gone (the peer's last connection closed)
    /// *or* renewed — and the swarm loop renews it when *any* of the
    /// peer's connections closes, not only the one the cheque went out on
    /// (it can't tell which carried the stream; PR #133 R2-F1). So a
    /// dial-race duplicate or a liveness-closed dead connection closing
    /// in the window counts a cheque delivered on the surviving
    /// connection as undelivered: the debt mirror isn't lowered and the
    /// next cheque pays those units again (no overpayment, since the
    /// ledger's cumulative already holds the cheque).
    async fn connection_held(&self, peer: PeerId, session: u64) -> Result<(), SwapError> {
        tokio::time::sleep(DELIVERY_GRACE).await;
        match self.cfg.peer_eth.session(&peer) {
            Some((_, now)) if now == session => Ok(()),
            _ => Err(SwapError::Rejected(
                "a connection to the peer closed as the cheque stream ended (the one it went \
                 out on or a duplicate; a reset can't be told from bee's FullClose), so the \
                 cheque is not counted as delivered"
                    .into(),
            )),
        }
    }

    /// Pay `units` of accounting debt to `peer` — retrieval and pushsync
    /// debt alike, from the shared accounting mirror: bee's `swap.Pay` →
    /// `swapprotocol.EmitCheque`. Reads the recipient's rates, checks them
    /// against the policy, records a cheque for the previous cumulative
    /// plus `units × rate + deduction` if the funds left cover it, sends
    /// it and waits until the recipient has finished with it. Returns the
    /// PLUR paid.
    ///
    /// `Ok` only when the stream ended and all of the peer's connections
    /// held for [`DELIVERY_GRACE`] afterwards; the caller then lowers its debt
    /// mirror by `units`, which is what bee credits for the cheque
    /// (`(paid − deduction) / exchange`). A cheque that was recorded but
    /// then failed, timed out, or saw any of the peer's connections close
    /// within the grace (see [`Self::connection_held`]) stays issued
    /// liability in the ledger (the next cheque to the beneficiary builds
    /// on it, so nothing is paid twice), but lowers no debt. Every cheque
    /// recorded is logged with its amount, whatever its outcome, so the
    /// log adds up to the ledger.
    ///
    /// The whole payment must finish by `deadline` (bee's 5 s
    /// `EmitCheque` timeout); past it the cheque counts as undelivered.
    async fn pay(
        &self,
        peer: PeerId,
        units: u64,
        deadline: tokio::time::Instant,
    ) -> Result<U256, SwapError> {
        let timed_out = || {
            SwapError::Rejected(format!(
                "timed out after {}s",
                RETRIEVAL_PAYMENT_TIMEOUT.as_secs()
            ))
        };
        let policy = self
            .retrieval_policy()
            .ok_or_else(|| SwapError::Rejected("SWAP payments are off".into()))?;
        // A ledger whose file couldn't be read doesn't know what this
        // chequebook already owes: no cheques until it does.
        self.outbound_ledger
            .ensure_readable()
            .map_err(|e| SwapError::Rejected(format!("outbound ledger unreadable: {e}")))?;
        // Nor one whose figures were lost: cheques peers refuse would get
        // the node disconnected by the peers it pays (PR #126 R4-M1).
        if let Some(why) = self.outbound_ledger.lost_figures() {
            return Err(SwapError::Rejected(why));
        }
        // Most this payment can cost; refuse before touching the network
        // when even that isn't covered.
        let most = SettlementRates {
            exchange_rate: policy.max_exchange_rate,
            deduction: policy.max_deduction,
        }
        .cheque_amount(units)
        .ok_or_else(|| SwapError::Rejected("cheque amount overflow".into()))?;
        if self.available(&policy) < most {
            return Err(SwapError::Rejected(format!(
                "chequebook credit exhausted: {} PLUR left",
                self.available(&policy)
            )));
        }
        let (beneficiary, session) = self
            .cfg
            .peer_eth
            .session(&peer)
            .ok_or_else(|| SwapError::Rejected("no eoa for peer".into()))?;
        let lock = self.outbound_ledger.beneficiary_lock(beneficiary);
        let _issuing = tokio::time::timeout_at(deadline, lock.lock())
            .await
            .map_err(|_| timed_out())?;
        let mut control = self.control_clone();
        let (mut stream, rates) =
            tokio::time::timeout_at(deadline, open_settlement(&mut control, peer))
                .await
                .map_err(|_| timed_out())??;
        check_rates(&rates, &policy)?;
        let amount = rates
            .cheque_amount(units)
            .ok_or_else(|| SwapError::Rejected("cheque amount overflow".into()))?;
        let new_cum = self
            .outbound_ledger
            .cumulative_for(&beneficiary)
            .checked_add(amount)
            .ok_or_else(|| SwapError::Rejected("cumulative overflow".into()))?;
        let signed = issue_cheque(
            &self.cfg.swap_secret,
            self.cfg.chequebook,
            beneficiary,
            new_cum,
            self.cfg.chain_id,
        )?;
        // Recorded as issued before a byte is written, and never taken
        // back: if this future is dropped (timeout) or the write fails
        // halfway, the recipient may still hold the cheque. The ledger's
        // total is the chequebook's liability, and it never outgrows the
        // deposit; the next cheque to this beneficiary builds on it, so
        // nothing is paid twice either. Nothing is sent before the record
        // is on disk, so a crash can't forget a cheque a peer holds; if
        // it can't be written the cheque isn't sent (it stays issued in
        // memory, and the next cheque to the peer covers it).
        let pending = self.issue_within_funds(&policy, &beneficiary, new_cum, amount)?;
        let delivered = tokio::time::timeout_at(deadline, async {
            pending.durable().await.map_err(|e| {
                SwapError::Rejected(format!(
                    "not sent: the outbound ledger can't record the cheque on disk: {e}"
                ))
            })?;
            write_cheque(&mut stream, &signed).await?;
            await_processed(stream).await?;
            self.connection_held(peer, session).await
        })
        .await
        .unwrap_or_else(|_| Err(timed_out()));
        info!(
            target: "ant_p2p::pushsync_swap",
            %peer,
            delivered = delivered.is_ok(),
            beneficiary = %hex::encode(beneficiary),
            units,
            plur = %amount,
            exchange_rate = %rates.exchange_rate,
            deduction = %rates.deduction,
            new_cumulative = %new_cum,
            "emitted SWAP cheque{}",
            match &delivered {
                Ok(()) => String::new(),
                Err(e) => format!(" (issued, not counted as delivered: {e})"),
            },
        );
        delivered.map(|()| amount)
    }
}

/// Refuse rates a peer names above the policy's ceilings (bee refuses
/// any that differ from its oracle: `ErrNegotiateRate`,
/// `ErrNegotiateDeduction`), and a zero rate, which would credit nothing.
fn check_rates(rates: &SettlementRates, policy: &RetrievalSwapPolicy) -> Result<(), SwapError> {
    if rates.exchange_rate.is_zero() || rates.exchange_rate > policy.max_exchange_rate {
        return Err(SwapError::Rejected(format!(
            "peer's exchange rate {} PLUR/unit is outside 1..={}",
            rates.exchange_rate, policy.max_exchange_rate
        )));
    }
    if rates.deduction > policy.max_deduction {
        return Err(SwapError::Rejected(format!(
            "peer's deduction {} PLUR is above {}",
            rates.deduction, policy.max_deduction
        )));
    }
    Ok(())
}

impl PushsyncSwap {
    /// Build the service. Loads the chequebook's outbound
    /// cumulative-payout section from `outbound_ledger_path`; a missing
    /// file starts empty. A file that exists but can't be read leaves
    /// the service refusing to issue cheques until a read succeeds,
    /// rather than restarting the chequebook's cumulatives from zero
    /// (see [`OutboundLedger`]).
    #[must_use]
    pub fn new(cfg: PushsyncSwapConfig, control: Control) -> Self {
        let outbound_ledger =
            OutboundLedger::open(Some(cfg.outbound_ledger_path.clone()), cfg.chequebook);
        Self {
            core: Arc::new(EmitCore {
                cfg,
                outbound_ledger,
                control: Mutex::new(control),
                retrieval: Mutex::new(None),
            }),
        }
    }

    /// Cumulative payout we've ever emitted to `beneficiary` — bee's
    /// view should match this exactly modulo cheques in flight. Used
    /// by smoke tests and (future) `antctl swap snapshot`.
    #[must_use]
    pub fn cumulative_for(&self, beneficiary: &[u8; 20]) -> U256 {
        self.core.outbound_ledger.cumulative_for(beneficiary)
    }

    /// Borrow the underlying outbound ledger, e.g. for diagnostic
    /// dumping.
    #[must_use]
    pub fn outbound_ledger(&self) -> &OutboundLedger {
        &self.core.outbound_ledger
    }

    /// Clone of the chequebook address, so callers who hold an
    /// `Arc<PushsyncSwap>` (e.g. an HTTP handler for `GET
    /// /chequebook/address`) can reach it without bypassing the
    /// abstraction.
    #[must_use]
    pub fn chequebook(&self) -> [u8; 20] {
        self.core.cfg.chequebook
    }

    /// Install (`Some`) or remove (`None`) the payment policy: the funds
    /// and rates cheques may use, for downloads and uploads alike.
    pub fn set_retrieval_policy(&self, policy: Option<RetrievalSwapPolicy>) {
        match self.core.retrieval.lock() {
            Ok(mut g) => *g = policy,
            Err(p) => *p.into_inner() = policy,
        }
    }

    /// Whether this service pays debt now: a policy is installed, the
    /// outbound ledger is readable (so what the chequebook already owes
    /// is known; this retries a failed read), its figures weren't lost to
    /// a moved-aside file without an operator confirming the liability
    /// since ([`crate::swap::OutboundLedger::lost_figures`]), and the
    /// chequebook has funds left under the policy.
    #[must_use]
    pub fn pays_retrieval(&self) -> bool {
        self.core.retrieval_policy().is_some_and(|p| {
            self.core.outbound_ledger.ensure_readable().is_ok()
                && self.core.outbound_ledger.lost_figures().is_none()
                && !self.core.available(&p).is_zero()
        })
    }
}

#[async_trait::async_trait]
impl RetrievalPayment for PushsyncSwap {
    async fn pay(&self, peer: PeerId, amount: u64) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + RETRIEVAL_PAYMENT_TIMEOUT;
        self.core
            .pay(peer, amount, deadline)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// Wrapper that the swarm loop drops into a `Box<dyn PushsyncSettlement>`-
/// shaped slot when nothing settles pushsync. Counts nothing and emits
/// nothing — useful for diagnostics.
#[derive(Default)]
pub struct NoopPushsyncSettlement;

impl PushsyncSettlement for NoopPushsyncSettlement {
    fn prepare_credit(&self, _peer: PeerId, _price: u64) -> Option<ant_retrieval::PushCredit> {
        Some(ant_retrieval::PushCredit::new(NoCredit))
    }
    fn forget(&self, _peer: &PeerId) {}
}

/// [`NoopPushsyncSettlement`]'s credit: reserves and records nothing.
struct NoCredit;

impl ant_retrieval::PushCreditAction for NoCredit {
    fn apply(self: Box<Self>) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::random_secp256k1_secret;

    #[test]
    fn peer_eth_map_record_get_forget() {
        let m = PeerEthMap::new();
        let p = PeerId::random();
        let eoa = [0xabu8; 20];
        assert!(m.get(&p).is_none());
        m.record(p, eoa);
        assert_eq!(m.get(&p), Some(eoa));
        m.forget(&p);
        assert!(m.get(&p).is_none());
    }

    /// Every handshake starts a new session, and a closed connection
    /// drops it: what the payer's delivery check compares.
    #[test]
    fn peer_eth_sessions_change_with_the_connection() {
        let m = PeerEthMap::new();
        let p = PeerId::random();
        assert!(m.session(&p).is_none());
        m.record(p, [1; 20]);
        let (eoa, first) = m.session(&p).unwrap();
        assert_eq!(eoa, [1; 20]);
        assert_eq!(m.session(&p).unwrap().1, first, "stable while connected");
        m.forget(&p);
        assert!(m.session(&p).is_none());
        m.record(p, [1; 20]);
        assert_ne!(
            m.session(&p).unwrap().1,
            first,
            "a reconnect is a new session"
        );
    }

    /// A cheque whose stream ended counts as delivered only if the
    /// connection it went out on is still up after [`DELIVERY_GRACE`]: a
    /// yamux reset and a dropped connection both read as end of stream,
    /// like bee's `FullClose`, so a disconnect at that moment (the two
    /// "processed" cheques on PR #126's paid runs) must not lower the
    /// debt mirror.
    #[tokio::test]
    async fn a_cheque_whose_connection_drops_is_not_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let svc = Arc::new(service(dir.path()));
        let peer = PeerId::random();
        let eth = svc.core.cfg.peer_eth.clone();

        eth.record(peer, [7; 20]);
        let (_, session) = eth.session(&peer).unwrap();
        assert!(svc.core.connection_held(peer, session).await.is_ok());

        // The connection closes as the stream ends.
        let check = tokio::spawn({
            let svc = svc.clone();
            async move { svc.core.connection_held(peer, session).await }
        });
        tokio::time::sleep(DELIVERY_GRACE / 2).await;
        eth.forget(&peer);
        assert!(check.await.unwrap().is_err(), "disconnected: not delivered");

        // ... or is replaced by a new one before the grace is over.
        eth.record(peer, [7; 20]);
        let (_, session) = eth.session(&peer).unwrap();
        let check = tokio::spawn({
            let svc = svc.clone();
            async move { svc.core.connection_held(peer, session).await }
        });
        tokio::time::sleep(DELIVERY_GRACE / 2).await;
        eth.forget(&peer);
        eth.record(peer, [7; 20]);
        assert!(check.await.unwrap().is_err(), "reconnected: not delivered");

        // ... or one of the peer's two connections closes (it may be the
        // one the cheque went out on): the peer stays, keeping its EOA,
        // but the cheque doesn't count (PR #133 R2-F1).
        let (_, session) = eth.session(&peer).unwrap();
        let check = tokio::spawn({
            let svc = svc.clone();
            async move { svc.core.connection_held(peer, session).await }
        });
        tokio::time::sleep(DELIVERY_GRACE / 2).await;
        eth.renew_session(&peer);
        assert!(
            check.await.unwrap().is_err(),
            "a duplicate closed: not delivered"
        );
        assert_eq!(eth.get(&peer), Some([7; 20]), "the peer keeps its EOA");
        let (_, session) = eth.session(&peer).unwrap();
        assert!(svc.core.connection_held(peer, session).await.is_ok());

        // Gone before the cheque: no session to pay against.
        eth.forget(&peer);
        svc.set_retrieval_policy(Some(policy(1_000_000_000)));
        let err = svc
            .core
            .pay(peer, 1, deadline())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no eoa"), "{err}");
    }

    fn service(dir: &std::path::Path) -> PushsyncSwap {
        service_for(dir, [0xcb; 20])
    }

    fn service_for(dir: &std::path::Path, chequebook: [u8; 20]) -> PushsyncSwap {
        PushsyncSwap::new(
            PushsyncSwapConfig::new(
                chequebook,
                random_secp256k1_secret(),
                100,
                dir.join("out.json"),
                PeerEthMap::new(),
            ),
            libp2p_stream::Behaviour::default().new_control(),
        )
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + RETRIEVAL_PAYMENT_TIMEOUT
    }

    fn policy(deposited: u64) -> RetrievalSwapPolicy {
        RetrievalSwapPolicy {
            deposited_plur: U256::from(deposited),
            max_exchange_rate: U256::from(100_000u64),
            max_deduction: U256::from(100u64),
        }
    }

    /// Retrieval cheques (issue #121) never take the chequebook's
    /// liability past its deposit: every cheque already issued, pushsync
    /// ones included, comes off it (bee's `AvailableBalance`), and the
    /// check holds across beneficiaries.
    #[test]
    fn retrieval_cheques_stay_within_the_deposit() {
        let dir = tempfile::tempdir().unwrap();
        let svc = service(dir.path());
        assert!(!svc.pays_retrieval(), "no funds known: free tier");
        svc.set_retrieval_policy(Some(policy(1_000)));
        assert!(svc.pays_retrieval());

        let (a, b) = ([0xaa; 20], [0xbb; 20]);
        // A pushsync cheque issued earlier counts against the deposit.
        svc.outbound_ledger()
            .record_issued(&a, U256::from(300u64))
            .unwrap();
        let p = policy(1_000);
        svc.core
            .issue_within_funds(&p, &b, U256::from(600u64), U256::from(600u64))
            .unwrap()
            .wait()
            .unwrap();
        let refused = svc
            .core
            .issue_within_funds(&p, &a, U256::from(400u64), U256::from(101u64))
            .unwrap_err();
        assert!(refused.to_string().contains("exhausted"), "{refused}");
        assert_eq!(svc.outbound_ledger().cumulative_for(&a), U256::from(300u64));
        svc.core
            .issue_within_funds(&p, &a, U256::from(400u64), U256::from(100u64))
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(svc.outbound_ledger().total_issued(), U256::from(1_000u64));
        assert!(
            !svc.pays_retrieval(),
            "deposit spent: back to the free tier"
        );
        svc.set_retrieval_policy(None);
        assert!(!svc.pays_retrieval());
    }

    /// A new chequebook on the same data dir (PR #126 R1-F1) neither
    /// builds its cheques on the old one's cumulatives nor counts the old
    /// one's cheques against its own deposit.
    #[test]
    fn a_new_chequebook_does_not_inherit_the_old_ones_cheques() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [0xbb; 20];
        {
            let old = service_for(dir.path(), [0xa1; 20]);
            old.outbound_ledger()
                .record_issued(&peer, U256::from(1_500u64))
                .unwrap();
        }
        let new = service_for(dir.path(), [0xb2; 20]);
        assert_eq!(new.cumulative_for(&peer), U256::zero());
        new.set_retrieval_policy(Some(policy(1_000)));
        assert!(new.pays_retrieval(), "the new deposit is untouched");
        drop(new);
        let old = service_for(dir.path(), [0xa1; 20]);
        assert_eq!(old.cumulative_for(&peer), U256::from(1_500u64));
    }

    /// Two services on one chequebook (settlement disabled and
    /// re-enabled while the old one finishes) check and spend the same
    /// funds under one gate (PR #126 R3-M1): racing retrieval cheques
    /// from both never take the liability past the deposit.
    #[test]
    fn two_services_on_one_chequebook_never_overdraw_together() {
        let dir = tempfile::tempdir().unwrap();
        let old = Arc::new(service(dir.path()));
        let new = Arc::new(service(dir.path()));
        let p = policy(1_000);
        let paid = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for i in 0..40u8 {
                let svc = if i % 2 == 0 { old.clone() } else { new.clone() };
                let paid = &paid;
                s.spawn(move || {
                    let b = [i; 20];
                    if let Ok(w) =
                        svc.core
                            .issue_within_funds(&p, &b, U256::from(100u64), U256::from(100u64))
                    {
                        w.wait().unwrap();
                        paid.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(paid.into_inner(), 10);
        assert_eq!(old.outbound_ledger().total_issued(), U256::from(1_000u64));
        assert_eq!(new.outbound_ledger().total_issued(), U256::from(1_000u64));
    }

    /// While the outbound ledger can't be read, the service doesn't
    /// claim to pay retrieval (PR #126 R3-M2): the node reports the free
    /// tier instead of installing a payer whose every cheque fails, and
    /// switches back once the file reads again.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_ledger_does_not_pay_retrieval() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        std::fs::write(&path, b"{}").unwrap();
        let set_mode = |m| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(m));
        set_mode(0o000).unwrap();
        if std::fs::read(&path).is_ok() {
            // Running as root: permissions don't fake a failed read.
            set_mode(0o600).unwrap();
            return;
        }
        let svc = service(dir.path());
        svc.set_retrieval_policy(Some(policy(1_000)));
        assert!(!svc.pays_retrieval());
        set_mode(0o600).unwrap();
        assert!(svc.pays_retrieval());
    }

    /// A ledger moved aside as unparseable lost what the chequebook owes
    /// (PR #126 R4-M1): downloads and uploads stay on the free tier — no
    /// payer (the one payer serves both since #127), and a payment that
    /// races in is refused before any stream opens — even after a
    /// restart, until the operator confirms the liability. The ledger
    /// itself still records.
    #[tokio::test]
    async fn a_lost_ledger_keeps_retrieval_off_until_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let svc = service(dir.path());
        svc.set_retrieval_policy(Some(policy(1_000_000)));
        assert!(!svc.pays_retrieval());
        let err = svc
            .core
            .pay(PeerId::random(), 1, deadline())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("confirm"), "{err}");
        svc.outbound_ledger()
            .record_issued(&[0x11; 20], U256::from(5u64))
            .unwrap();
        drop(svc);

        let svc = service(dir.path());
        svc.set_retrieval_policy(Some(policy(1_000_000)));
        assert!(!svc.pays_retrieval(), "a restart doesn't clear it");
        assert!(crate::swap::confirm_cheque_liability(&path, [0xcb; 20]).unwrap());
        assert!(svc.pays_retrieval());
    }

    /// A peer can't name its own price: rates above the oracle's are
    /// refused (bee: `ErrNegotiateRate`/`ErrNegotiateDeduction`), and so
    /// is a zero rate, which would credit nothing.
    #[test]
    fn retrieval_rates_above_the_oracle_are_refused() {
        let p = policy(1_000);
        let rates = |exchange: u64, deduction: u64| SettlementRates {
            exchange_rate: U256::from(exchange),
            deduction: U256::from(deduction),
        };
        assert!(check_rates(&rates(100_000, 100), &p).is_ok());
        assert!(check_rates(&rates(100_000, 0), &p).is_ok());
        assert!(check_rates(&rates(100_001, 100), &p).is_err());
        assert!(check_rates(&rates(100_000, 101), &p).is_err());
        assert!(check_rates(&rates(0, 0), &p).is_err());
    }
}
