//! The EVM bridge: `eth_call` over verified state.
//!
//! [`myotis_evm`] is sans-I/O and its [`SnapStateOracle`] is synchronous. This
//! module is the I/O half: [`PoolOracle`] implements that trait over the snap
//! peer pool, bridging each verified fetch to the async network via
//! [`Handle::block_on`], and
//! [`ElReader::eth_call_overridden`](crate::el::reader::ElReader) drives the
//! `revm` executor on a blocking thread so that bridge never nests a
//! `block_on` inside a runtime worker.
//!
//! Every fetch pins to the executor-supplied `state_root` (the call's anchor:
//! the verified head's, or the beacon-finalized block's for [`ReadAnchor::Finalized`]),
//! so all reads in one call see a single consistent block. Verification is
//! verify-on-fetch: `snap_get_account`/`snap_get_storage` MPT-verify against that
//! root and `snap_get_bytecode` checks `keccak(code) == code_hash`, so a peer can
//! never inject unverified state — a peer that fails to prove is skipped, and if
//! none can prove, the fetch fails closed with [`OracleError`].
//!
//! Deferred to EL-C-3 (dispatch fairness): this path does not yet record snap
//! peer served/failure reputation (a peer that fails only `eth_call` fetches isn't
//! deprioritised via this loop), nor does it batch/parallelise fetches. Also note
//! that `revm` executes attacker-influenceable calldata on a blocking thread; under
//! the workspace's `panic = "abort"` a panic inside `revm` would abort — a residual
//! DoS surface that `catch_unwind` can't cover, tracked against the panic strategy.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::runtime::Handle;

use super::reader::{hedged_race, RaceOutcome, HEDGE_DELAY};

use myotis_core::header::BlockHeader;
use myotis_core::trie::{AccountLeaf, EMPTY_TRIE_ROOT};
use myotis_evm::{
    BlockContext, BytecodeCache, EvmError, OracleAccount, OracleError, SnapStateOracle,
    StateProofCache, U256,
};

use crate::el::peer::ManagedPeer;
use crate::el::readstats::{AccountFact, ReadStats};
use crate::el::snap::fetch::AccountOutcome;

/// The outcome of an `eth_call`. Mirrors the Java engine's contract, which
/// returns bytes on success and treats every other outcome (revert, halt,
/// unavailable) as "no answer" at the RPC layer — the host maps `Revert`/
/// `Unavailable` to a JSON-RPC null, `Success` to the return data.
#[derive(Debug, Clone)]
pub enum CallOutcome {
    /// The call returned this data.
    Success(Vec<u8>),
    /// The call reverted with this raw data (Solidity `Error(string)` is behind
    /// the `0x08c379a0` selector).
    Revert(Vec<u8>),
    /// The call could not be executed/verified (out of gas, halt, state
    /// unavailable, unsupported fork/chain). The string is diagnostic.
    Unavailable(String),
    /// The call can NEVER be answered on this build ([`EvmError::is_refusal`] —
    /// e.g. an Amsterdam block whose header has no slot number): the host
    /// serves a permanent error (-32602), never the retryable `Unavailable`.
    Refused(String),
}

impl CallOutcome {
    /// The executor's verdict: a revert keeps its payload (a verified answer),
    /// a refusal stays permanent, and anything else is the retryable
    /// `Unavailable`. One mapping for every call shape.
    pub fn from_executor(joined: Result<Vec<u8>, EvmError>) -> CallOutcome {
        match joined {
            Ok(bytes) => CallOutcome::Success(bytes),
            Err(EvmError::Reverted { data }) => CallOutcome::Revert(data),
            Err(e) if e.is_refusal() => CallOutcome::Refused(e.to_string()),
            Err(e) => CallOutcome::Unavailable(e.to_string()),
        }
    }
}

/// Which verified block a read is anchored at: the block an `eth_call` runs
/// against, or the state root an account / storage / code proof is verified
/// against (ABI ≥ 32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAnchor {
    /// The beacon OPTIMISTIC head — the `latest` (and `pending`/`safe`) tag.
    Head,
    /// The beacon FINALIZED execution block — the `finalized` tag: older and
    /// never reorged, but a state peers may already have pruned, so it can be
    /// unservable while the head serves. Never downgraded to the head: the
    /// caller asked for finality (CLAUDE.md §Trust — applied or refused).
    Finalized,
}

impl ReadAnchor {
    /// The anchor for a `finalized: bool` selector (the ENS entry points').
    pub fn for_finalized(finalized: bool) -> ReadAnchor {
        if finalized {
            ReadAnchor::Finalized
        } else {
            ReadAnchor::Head
        }
    }
}

/// A call's outcome plus the block it actually ran against (#382, #465): a
/// host that asked for `finalized` can see which block answered, and one that
/// asked for `latest` learns the head it got.
#[derive(Debug, Clone)]
pub struct CallAnswer {
    pub outcome: CallOutcome,
    pub block_number: u64,
    /// Ran against the beacon-FINALIZED block (the `verified` of
    /// `ens_record_json`).
    pub finalized: bool,
}

/// The outcome of an `estimateGas`. A REVERT is a verified chain answer (the
/// transaction being estimated cannot succeed) and carries its raw payload so
/// the host can serve the standard JSON-RPC code-3 `execution reverted` error;
/// `Unavailable` maps to the retryable null/-32000, like the Java engine.
#[derive(Debug, Clone)]
pub enum GasOutcome {
    /// The gas-limit estimate (already buffered by the executor).
    Estimate(u64),
    /// The estimated transaction reverted with this raw data (Solidity
    /// `Error(string)` is behind the `0x08c379a0` selector).
    Revert(Vec<u8>),
    /// No estimate (halt / state unavailable). The string is diagnostic.
    Unavailable(String),
    /// Never answerable on this build — permanent, as [`CallOutcome::Refused`].
    Refused(String),
}

impl GasOutcome {
    /// The executor's verdict, mapped exactly as [`CallOutcome::from_executor`].
    pub fn from_executor(joined: Result<u64, EvmError>) -> GasOutcome {
        match joined {
            Ok(gas) => GasOutcome::Estimate(gas),
            // The typed error survives to here — don't stringify the revert
            // payload away: it is the verified answer the host must serve.
            Err(EvmError::Reverted { data }) => GasOutcome::Revert(data),
            Err(e) if e.is_refusal() => GasOutcome::Refused(e.to_string()),
            Err(e) => GasOutcome::Unavailable(e.to_string()),
        }
    }
}

/// The outcome of an ENS forward resolution. `block_number` is the verified head
/// the resolution ran against. A hard failure (state unavailable, invalid name)
/// travels the `Err(String)` channel instead, like the other reads.
#[derive(Debug, Clone)]
pub enum EnsOutcome {
    /// The name resolved to this address record.
    Resolved { address: [u8; 20], block_number: u64 },
    /// Successfully determined that the name has NO address record (absent name,
    /// zero-address record, or a non-wildcard ancestor resolver).
    NoRecord { block_number: u64 },
    /// The name resolves OFFCHAIN (ERC-3668 `OffchainLookup`) — the record exists
    /// but needs a CCIP-Read gateway, which this engine doesn't drive yet
    /// (EL-C-5-3). Distinguishable from `NoRecord` by design.
    Offchain { block_number: u64 },
}

/// Which state root an ENS query resolves against (the Java `EnsRoot` twin —
/// this engine has no PEER_HEAD mode; its non-finalized root is the
/// beacon-anchored OPTIMISTIC head, strictly stronger than a peer-claimed head).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsRootMode {
    /// Try the beacon-FINALIZED root first; fall back to the optimistic head if
    /// the finalized attempt errors or finds no record (Java AUTO-ladder parity).
    Auto,
    /// The beacon-FINALIZED root only — a failure is an error, never a silent
    /// downgrade.
    Finalized,
    /// The beacon-anchored optimistic head only (the Java `PEER_HEAD` twin —
    /// "don't wait for finality"; here it is still beacon-anchored, not
    /// peer-claimed). Reports `verified=false`.
    Optimistic,
}

/// One ENS query — every record type the resolver serves (EL-C-5-2).
#[derive(Debug, Clone)]
pub enum EnsQuery {
    /// Forward `name → address` (the EL-C-5-1 read, now root-aware).
    Addr { name: String },
    /// `text(bytes32,string)`.
    Text { name: String, key: String },
    /// `contenthash(bytes32)`.
    Contenthash { name: String },
    /// ENSIP-9 `addr(bytes32,uint256)`.
    Multicoin { name: String, coin_type: u64 },
    /// `pubkey(bytes32)`.
    Pubkey { name: String },
    /// `ABI(bytes32,uint256)`.
    Abi { name: String, content_types: u64 },
    /// `dnsRecord(bytes32,bytes,uint16)` (the Java engine's signature).
    DnsRecord { name: String, dns_name: String, resource: u16 },
    /// `interfaceImplementer(bytes32,bytes4)`.
    Interface { name: String, interface_id: [u8; 4] },
    /// Reverse `address → name`, forward-verified.
    Reverse { address: [u8; 20] },
}

/// A resolved record value, shaped per query type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsRecordValue {
    /// `Addr` / `Interface` answers.
    Address([u8; 20]),
    /// `Text` answers.
    Text(String),
    /// `Contenthash` / `Multicoin` / `DnsRecord` answers (raw bytes).
    Bytes(Vec<u8>),
    /// `Pubkey` answers.
    Pubkey { x: [u8; 32], y: [u8; 32] },
    /// `Abi` answers.
    Abi { content_type: u64, data: Vec<u8> },
    /// `Reverse` answers (the forward-verified primary name).
    Name(String),
}

/// The outcome of an [`EnsQuery`]. `verified` = the resolution ran against the
/// beacon-FINALIZED root (the API's meaning of "verified"); the optimistic-head
/// path reports `false`.
#[derive(Debug, Clone)]
pub enum EnsQueryOutcome {
    /// The record resolved to this value.
    Value { value: EnsRecordValue, block_number: u64, verified: bool },
    /// Successfully determined there is no record.
    NoRecord { block_number: u64, verified: bool },
    /// The record resolves OFFCHAIN (ERC-3668): the host must drive a CCIP-Read
    /// gateway round with the carried tuple, then re-enter via the callback
    /// (`method:"ccipCallback"`). `lookup` is `None` when the revert's tuple was
    /// unparseable (still distinguishable from `NoRecord`); `wrapped` = the
    /// revert came from inside the ENSIP-10 `resolve()` wrap.
    Offchain {
        block_number: u64,
        verified: bool,
        lookup: Option<Box<myotis_evm::OffchainLookup>>,
        wrapped: bool,
    },
}

/// Build a [`BlockContext`] from a verified head header. `chain_id` comes from the
/// chain config (the header carries no chain id). The EIP-7843 slot number is
/// carried as decoded; the executor refuses an Amsterdam block without one.
pub fn block_context(header: &BlockHeader, chain_id: u64) -> Result<BlockContext, String> {
    let coinbase: [u8; 20] = header
        .beneficiary
        .as_slice()
        .try_into()
        .map_err(|_| "header beneficiary is not 20 bytes".to_string())?;
    let base_fee_per_gas = match header.base_fee_per_gas.as_deref() {
        Some(bytes) => be_to_u64(bytes),
        None => 0, // pre-London
    };
    Ok(BlockContext {
        state_root: header.state_root,
        block_number: header.number,
        timestamp: header.timestamp,
        base_fee_per_gas,
        coinbase,
        prev_randao: header.mix_hash_or_prev_randao,
        chain_id,
        gas_limit: header.gas_limit,
        slot_number: header.slot_number,
    })
}

/// Map a proof-verified account leaf to the oracle's account shape; `None` when
/// the balance scalar is oversized (an adversarial leaf can't reach here, but
/// stay panic-free).
fn leaf_account(leaf: &AccountLeaf) -> Option<OracleAccount> {
    Some(OracleAccount {
        nonce: leaf.nonce,
        balance: u256_be(&leaf.balance)?,
        code_hash: leaf.code_hash,
        storage_root: leaf.storage_root,
    })
}

/// A minimal big-endian scalar → `u64`, saturating rather than panicking. Base
/// fee never approaches `u64::MAX` on mainnet; a longer/oversized scalar (which a
/// proof-verified header can't produce) saturates instead of aborting.
fn be_to_u64(bytes: &[u8]) -> u64 {
    if bytes.len() > 8 {
        return u64::MAX;
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    u64::from_be_bytes(buf)
}

/// A minimal big-endian scalar → `U256`. `None` if longer than 32 bytes (a
/// proof-verified account/storage scalar never is — this only guards against a
/// panic on adversarial input).
pub(crate) fn u256_be(bytes: &[u8]) -> Option<U256> {
    if bytes.len() > 32 {
        None
    } else {
        Some(U256::from_be_slice(bytes))
    }
}

/// A [`SnapStateOracle`] over a fixed snapshot of snap peers, bridging the sync
/// trait to the async snap fetch path. Created per `eth_call`.
pub struct PoolOracle {
    operation: Option<Arc<super::request::Operation>>,
    peers: Vec<Arc<ManagedPeer>>,
    handle: Handle,
    /// Snap-quality reputation sink (None in tests): serves confirm a peer,
    /// failures count toward DENIED — the same sinks the block path feeds, so
    /// eth_call fetch outcomes shape the next run's dial order too (EL-C-3).
    quality: Option<crate::el::pool::SnapQualitySink>,
    /// Per-call memo of fetched account leaves (keyed by address; the state root
    /// is fixed for the call). Dedups the account fetch that both `fetch_account`
    /// and every `fetch_storage` on the same contract need. `Some(None)` caches a
    /// proven absence.
    leaf_memo: Mutex<HashMap<[u8; 20], Option<AccountLeaf>>>,
    /// The reader's read-fetch shadow cache: every verified fetch this oracle
    /// makes — including the prefetch wave's — is reported with its wall-clock
    /// cost so `read_stats_json` covers the EVM path too.
    stats: Arc<ReadStats>,
    /// The order this call's hedged reads ask `peers` in, as indices into
    /// `peers`. It starts as the pool's ladder and adapts WITHIN the call (see
    /// [`next_order`]), so a dead first peer costs one hedge delay per call
    /// instead of one per state read. The pool's bench, fed by the same races,
    /// only reorders the NEXT call's snapshot, and even an eviction does not
    /// take the peer out of this one.
    order: Mutex<Vec<usize>>,
    /// The call runs against the beacon-FINALIZED state root (the `finalized`
    /// tag; #465, #366). Two things follow, both as for the reader's own
    /// finalized state reads: a peer answering a fetch with an empty proof
    /// does not hold a root it is not obliged to hold — no strike, no
    /// witnessed failure (`record_race`, the prefetch wave) — and the shadow
    /// cache, which measures head traffic, is not fed.
    finalized: bool,
}

/// This call's ask order after one hedged race over `asked` (the order that
/// race used): the winner first, then every peer the race did not judge in its
/// current order, then the peers that lost it (missed or outpaced), also in
/// their current order. Pure, and keyed by peer id rather than by position, so
/// a race that ran on an older order still applies cleanly.
fn next_order<T>(order: &[usize], asked: &[usize], out: &RaceOutcome<T>) -> Vec<usize> {
    let winner = out.accepted.as_ref().and_then(|(pos, _)| asked.get(*pos).copied());
    let losers: Vec<usize> = out
        .missed
        .iter()
        .chain(&out.outpaced)
        .filter_map(|pos| asked.get(*pos).copied())
        .collect();
    let winner = winner.filter(|w| order.contains(w));
    let mut next = Vec::with_capacity(order.len());
    next.extend(winner);
    next.extend(order.iter().copied().filter(|i| Some(*i) != winner && !losers.contains(i)));
    next.extend(order.iter().copied().filter(|i| Some(*i) != winner && losers.contains(i)));
    next
}

impl PoolOracle {
    pub fn new(
        peers: Vec<Arc<ManagedPeer>>,
        handle: Handle,
        quality: Option<crate::el::pool::SnapQualitySink>,
        stats: Arc<ReadStats>,
        finalized: bool,
    ) -> PoolOracle {
        let order = Mutex::new((0..peers.len()).collect());
        PoolOracle {
            operation: super::request::Operation::current(),
            peers,
            handle,
            quality,
            leaf_memo: Mutex::new(HashMap::new()),
            stats,
            order,
            finalized,
        }
    }

    /// Shadow-cache bookkeeping for one verified account fetch (`None` = a
    /// verified absence) that started at `started`.
    fn note_account(
        &self,
        address: [u8; 20],
        state_root: &[u8; 32],
        leaf: Option<&AccountLeaf>,
        started: std::time::Instant,
    ) {
        if self.finalized {
            return; // the shadow cache measures head traffic (see `finalized`)
        }
        self.stats.observe_account(
            address,
            *state_root,
            AccountFact::from_leaf(leaf),
            started.elapsed(),
        );
    }

    /// Shadow-cache bookkeeping for one verified slot fetch.
    fn note_storage(
        &self,
        address: [u8; 20],
        position: [u8; 32],
        state_root: &[u8; 32],
        storage_root: [u8; 32],
        value: U256,
        started: std::time::Instant,
    ) {
        if self.finalized {
            return;
        }
        self.stats.observe_storage(
            address,
            position,
            *state_root,
            storage_root,
            value.to_be_bytes::<32>(),
            started.elapsed(),
        );
    }

    fn wait<T>(&self, future: impl std::future::Future<Output = T>) -> Result<T, OracleError> {
        self.handle.block_on(async {
            match &self.operation {
                Some(op) => op.wait(future).await.map_err(|reason| OracleError::Cancelled { reason }),
                None => Ok(future.await),
            }
        })
    }

    /// Feed one hedged race into the reputation sink: the winner served, every
    /// miss failed, and every attempt the winner outpaced reported as outpaced
    /// (benched; a repeat before the peer serves again is a failure). The same
    /// rules as `ElReader::hedged_read`, including its excuse: on a
    /// `finalized` call a miss answered with an empty proof is the peer not
    /// holding a root it is not obliged to hold, and is banked nowhere.
    async fn record_race<T>(
        quality: &Option<crate::el::pool::SnapQualitySink>,
        peers: &[Arc<ManagedPeer>],
        out: &RaceOutcome<T>,
        finalized: bool,
    ) {
        debug_assert!(out.indices().all(|i| i < peers.len()), "race indices must index its own peer slice");
        let Some(q) = quality else { return };
        // A miss is WITNESSED only when another peer served the same read; a
        // whole-pool failure is banked live but persisted nowhere (#465 — the
        // same cold-pool storm that struck the block read hits these).
        let witnessed = out.accepted.is_some();
        let excused = |idx: usize| {
            finalized
                && out.errors.iter().any(|(i, e)| {
                    *i == idx && crate::el::snap::fetch::is_unknown_root_error(e)
                })
        };
        for idx in &out.missed {
            if excused(*idx) {
                continue;
            }
            q.failed(peers[*idx].addr(), witnessed).await;
        }
        for idx in &out.outpaced {
            q.outpaced(peers[*idx].addr()).await;
        }
        if let Some((idx, _)) = &out.accepted {
            q.served(peers[*idx].addr()).await;
        }
    }

    /// The peers in this call's current ask order, with the ids that order
    /// uses (see `order`).
    fn ladder(&self) -> (Vec<usize>, Vec<Arc<ManagedPeer>>) {
        let asked = self.order.lock().unwrap().clone();
        let peers = asked.iter().map(|&i| Arc::clone(&self.peers[i])).collect();
        (asked, peers)
    }

    /// Adapt this call's ask order to one race that asked in order `asked`.
    fn learn_order<T>(&self, asked: &[usize], out: &RaceOutcome<T>) {
        let mut order = self.order.lock().unwrap();
        let next = next_order(&order, asked, out);
        *order = next;
    }

    /// The proof-verified account leaf at `address`, or `None` when proven absent.
    /// Memoised per call. `Err` only when no peer could prove it.
    fn leaf(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<AccountLeaf>, OracleError> {
        self.check_request()?;
        if let Some(cached) = self.leaf_memo.lock().unwrap().get(&address) {
            return Ok(cached.clone());
        }
        // No lock held across the network fetch.
        let quality = self.quality.clone();
        let started = std::time::Instant::now();
        let (asked, peers) = self.ladder();
        let peers = &peers;
        let fetched = self.wait(async {
            // Hedged across the call's peers (reader::hedged_race). An eth_call
            // makes several state reads, and a silent first peer used to hold
            // EACH of them for a full request timeout — the main source of
            // multi-second eth_call latency on a flaky pool. Any proof-verified
            // answer ends the race; a bad proof or transport error is a miss.
            // The call's ask order learns from each race (see `order`).
            let out = hedged_race(
                peers,
                HEDGE_DELAY,
                |peer: Arc<ManagedPeer>| async move {
                    peer.snap_get_account(state_root, &address).await
                },
                |_: &AccountOutcome| true,
            )
            .await;
            Self::record_race(&quality, peers, &out, self.finalized).await;
            self.learn_order(&asked, &out);
            out.accepted.map(|(_, outcome)| match outcome {
                AccountOutcome::Present(leaf) => Some(leaf),
                AccountOutcome::Absent => None,
            })
        })?;
        match fetched {
            Some(leaf) => {
                self.note_account(address, state_root, leaf.as_ref(), started);
                self.leaf_memo.lock().unwrap().insert(address, leaf.clone());
                Ok(leaf)
            }
            None => Err(OracleError::StateUnavailable {
                state_root: *state_root,
                address,
                slot: None,
            }),
        }
    }
}

impl SnapStateOracle for PoolOracle {
    fn check_request(&self) -> Result<(), OracleError> {
        match &self.operation {
            Some(op) => op.check().map_err(|reason| OracleError::Cancelled { reason }),
            None => Ok(()),
        }
    }

    fn fetch_account(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<OracleAccount>, OracleError> {
        match self.leaf(state_root, address)? {
            Some(leaf) => leaf_account(&leaf)
                .ok_or_else(|| OracleError::InvalidProof {
                    state_root: *state_root,
                    address,
                    detail: format!(
                        "account balance scalar too long ({} bytes)",
                        leaf.balance.len()
                    ),
                })
                .map(Some),
            None => Ok(None),
        }
    }

    /// Best-effort batch warm-up (EL-C-3-2; the Java `fetchBatch` +
    /// `prefetchInParallel` twin adapted to this transport): chunk the account
    /// items at 64 path-sets, pin each chunk to ONE peer per attempt (rotating
    /// on retry — failed items get up to 3 attempts across peers, Java
    /// `DEFAULT_MAX_ATTEMPTS`), run ALL chunks concurrently under one
    /// per-REQUEST 48-permit semaphore (Java `PREFETCH_MAX_IN_FLIGHT` — bounds
    /// wire requests, not items, so a 1000-slot item can't flood a peer), and
    /// bound the WHOLE wave at 30 s (Java `PREFETCH_WAVE_TIMEOUT_SEC`).
    /// Verified results go straight into the cross-call sinks (and the account
    /// leaf memo, so the serial fallback needn't re-fetch). Failures are silent
    /// per item; the per-item path re-fetches whatever is missing. Note: unlike
    /// Java's one-getTrieNodes-per-chunk framing, this transport sends one
    /// request per account/slot — the win is concurrency, not fewer messages.
    fn prefetch_batch(
        &self,
        state_root: &[u8; 32],
        accounts: &[([u8; 20], Vec<U256>)],
        code_hashes: &[[u8; 32]],
        proof_sink: &dyn StateProofCache,
        code_sink: &dyn BytecodeCache,
    ) {
        use futures::stream::{self, StreamExt};
        const BATCH_PATHSET_CHUNK: usize = 64; // Java SnapBackedStateOracle parity
        const MAX_IN_FLIGHT: usize = 48; // Java PREFETCH_MAX_IN_FLIGHT (per request)
        const MAX_ATTEMPTS: usize = 3; // Java DEFAULT_MAX_ATTEMPTS
        const WAVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        if self.peers.is_empty() || (accounts.is_empty() && code_hashes.is_empty()) {
            return;
        }
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
        let quality = self.quality.clone();

        /// One item's outcome for retry + reputation bookkeeping.
        enum ItemOutcome {
            Skipped, // already cached — no request sent, no reputation signal
            Served,
            Failed,
        }

        // One (account, slots) item against one peer: account leaf first (its
        // proof also decides absent/empty-trie zero-slots), then the slots
        // concurrently — every wire request behind its own semaphore permit.
        let fetch_item = |peer: Arc<ManagedPeer>, addr: [u8; 20], slots: Vec<U256>| {
            let sem = Arc::clone(&sem);
            async move {
                // Only the slots this root doesn't already have — a RETRY after
                // a partial failure re-fetches just the gaps, and a fully-cached
                // item skips without touching the peer (no reputation signal).
                let missing: Vec<U256> = slots
                    .iter()
                    .filter(|s| proof_sink.get_storage(state_root, &addr, s).is_none())
                    .copied()
                    .collect();
                let account_cached = proof_sink.get_account(state_root, &addr).is_some();
                if account_cached && missing.is_empty() {
                    return ItemOutcome::Skipped;
                }
                // The account leaf: reuse this call's memo (primed target /
                // earlier iterations) before spending a round-trip.
                let memoed = self.leaf_memo.lock().unwrap().get(&addr).cloned();
                let leaf = match memoed {
                    Some(None) => {
                        // Proven absent already — every slot is zero, no request.
                        proof_sink.put_account(state_root, &addr, None);
                        for slot in &missing {
                            proof_sink.put_storage(state_root, &addr, slot, U256::ZERO);
                        }
                        return ItemOutcome::Skipped;
                    }
                    Some(Some(leaf)) => leaf,
                    None => {
                        // A closed semaphore (impossible in practice — nothing
                        // closes it) must FAIL the item, never bypass the bound.
                        let Ok(_permit) = sem.acquire().await else {
                            return ItemOutcome::Failed;
                        };
                        let started = std::time::Instant::now();
                        let outcome = peer.snap_get_account(state_root, &addr).await;
                        if let Ok(o) = &outcome {
                            let leaf = match o {
                                AccountOutcome::Present(l) => Some(l),
                                AccountOutcome::Absent => None,
                            };
                            self.note_account(addr, state_root, leaf, started);
                        }
                        match outcome {
                            Ok(AccountOutcome::Present(leaf)) => leaf,
                            Ok(AccountOutcome::Absent) => {
                                proof_sink.put_account(state_root, &addr, None);
                                for slot in &missing {
                                    proof_sink.put_storage(state_root, &addr, slot, U256::ZERO);
                                }
                                self.leaf_memo.lock().unwrap().insert(addr, None);
                                return ItemOutcome::Served;
                            }
                            Err(_) => return ItemOutcome::Failed,
                        }
                    }
                };
                let Some(account) = leaf_account(&leaf) else {
                    return ItemOutcome::Failed; // oversized balance scalar
                };
                proof_sink.put_account(state_root, &addr, Some(account));
                self.leaf_memo.lock().unwrap().insert(addr, Some(leaf.clone()));
                if leaf.storage_root == EMPTY_TRIE_ROOT {
                    for slot in &missing {
                        proof_sink.put_storage(state_root, &addr, slot, U256::ZERO);
                    }
                    return ItemOutcome::Served;
                }
                let values = futures::future::join_all(missing.iter().map(|slot| {
                    let position = slot.to_be_bytes::<32>();
                    let peer = Arc::clone(&peer);
                    let leaf = leaf.clone();
                    let sem = Arc::clone(&sem);
                    async move {
                        let Ok(_permit) = sem.acquire().await else {
                            return None; // closed semaphore = local failure
                        };
                        let started = std::time::Instant::now();
                        let value = peer
                            .snap_get_storage(state_root, &addr, &leaf, &position)
                            .await
                            .ok()
                            .and_then(|bytes| u256_be(&bytes));
                        if let Some(v) = value {
                            self.note_storage(addr, position, state_root, leaf.storage_root, v, started);
                        }
                        value
                    }
                }))
                .await;
                let mut any_slot_failed = false;
                for (slot, value) in missing.iter().zip(values) {
                    match value {
                        Some(v) => proof_sink.put_storage(state_root, &addr, slot, v),
                        None => any_slot_failed = true,
                    }
                }
                // A partial slot failure fails the ITEM so the rotation retries
                // it on the next peer — the retry only re-fetches the gaps
                // (cached slots are filtered out above). Successful puts keep.
                if any_slot_failed {
                    ItemOutcome::Failed
                } else {
                    ItemOutcome::Served
                }
            }
        };

        let wave = async {
            // ALL chunks concurrently (each pinned to its own rotating peer).
            let chunk_runs = accounts.chunks(BATCH_PATHSET_CHUNK).enumerate().map(
                |(chunk_idx, chunk)| {
                    let quality = quality.clone();
                    let fetch_item = &fetch_item;
                    async move {
                        // Items still needing a fetch; failed ones retry on the
                        // next peer (Java tryWithRetries chunk rotation).
                        let mut pending: Vec<&([u8; 20], Vec<U256>)> = chunk.iter().collect();
                        let attempts = MAX_ATTEMPTS.min(self.peers.len()).max(1);
                        // Peers that failed every item they were asked, held
                        // until a later peer serves what they could not (then
                        // witnessed) or the rotation runs out (then not — a
                        // root every peer pruned is about our ask; #465).
                        let mut unwitnessed: Vec<std::net::SocketAddr> = Vec::new();
                        for attempt in 0..attempts {
                            if pending.is_empty() {
                                break;
                            }
                            let peer =
                                &self.peers[(chunk_idx + attempt) % self.peers.len()];
                            let outcomes = futures::future::join_all(pending.iter().map(
                                |(addr, slots)| {
                                    fetch_item(Arc::clone(peer), *addr, slots.clone())
                                },
                            ))
                            .await;
                            let mut still_failed = Vec::new();
                            let mut served_any = false;
                            let mut asked_any = false;
                            for (item, outcome) in pending.into_iter().zip(outcomes) {
                                match outcome {
                                    ItemOutcome::Served => served_any = true,
                                    ItemOutcome::Failed => {
                                        asked_any = true;
                                        still_failed.push(item);
                                    }
                                    // Cache-skips carry NO reputation signal —
                                    // the peer was never asked.
                                    ItemOutcome::Skipped => {}
                                }
                            }
                            if let Some(q) = &quality {
                                if served_any {
                                    // This peer served items the held peers
                                    // could not: their failures are witnessed
                                    // — unless the call runs at the finalized
                                    // root, where an item failure is almost
                                    // always "does not hold that root" and
                                    // the wave keeps no reason to tell it
                                    // from transport (the serial reads that
                                    // follow still strike a silent peer).
                                    for addr in unwitnessed.drain(..) {
                                        if !self.finalized {
                                            q.failed(addr, true).await;
                                        }
                                    }
                                    q.served(peer.addr()).await;
                                } else if asked_any {
                                    unwitnessed.push(peer.addr());
                                }
                            }
                            pending = still_failed;
                        }
                        if let Some(q) = &quality {
                            for addr in unwitnessed {
                                if !self.finalized {
                                    q.failed(addr, false).await;
                                }
                            }
                        }
                    }
                },
            );
            futures::future::join_all(chunk_runs).await;

            // Bytecode: content-addressed, verified by hash inside the peer call.
            let code_fetches = code_hashes.iter().enumerate().map(|(i, hash)| {
                let peer = Arc::clone(&self.peers[i % self.peers.len()]);
                let sem = Arc::clone(&sem);
                async move {
                    if code_sink.get(hash).is_some() {
                        return;
                    }
                    let Ok(_permit) = sem.acquire().await else {
                        return; // closed semaphore — never bypass the bound
                    };
                    let started = std::time::Instant::now();
                    if let Ok(code) = peer.snap_get_bytecode(hash).await {
                        self.stats.observe_code(*hash, started.elapsed());
                        code_sink.put(hash, code.into());
                    }
                }
            });
            stream::iter(code_fetches)
                .buffer_unordered(MAX_IN_FLIGHT)
                .collect::<Vec<()>>()
                .await;
        };
        // The whole wave is bounded (Java PREFETCH_WAVE_TIMEOUT_SEC): on timeout
        // whatever landed is kept and the loop's next iteration proceeds — an
        // eth_call must never hang on a slow warm-up.
        let _ = self.wait(async {
            let _ = tokio::time::timeout(WAVE_TIMEOUT, wave).await;
        });
    }

    fn fetch_storage(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
        slot: U256,
    ) -> Result<U256, OracleError> {
        // An absent account (or one with an empty storage trie) has every slot
        // provably zero — no round trip.
        let Some(leaf) = self.leaf(state_root, address)? else {
            return Ok(U256::ZERO);
        };
        if leaf.storage_root == EMPTY_TRIE_ROOT {
            return Ok(U256::ZERO);
        }
        let position = slot.to_be_bytes::<32>();
        let quality = self.quality.clone();
        let started = std::time::Instant::now();
        let (asked, peers) = self.ladder();
        let peers = &peers;
        let leaf = &leaf;
        let fetched = self.wait(async {
            // Hedged like the account leaf above.
            let out = hedged_race(
                peers,
                HEDGE_DELAY,
                |peer: Arc<ManagedPeer>| async move {
                    peer.snap_get_storage(state_root, &address, leaf, &position).await
                },
                |_: &Vec<u8>| true,
            )
            .await;
            Self::record_race(&quality, peers, &out, self.finalized).await;
            self.learn_order(&asked, &out);
            out.accepted.map(|(_, value)| value)
        })?;
        match fetched {
            // Empty bytes = a proven-zero / absent slot.
            Some(value) => {
                let v = u256_be(&value).ok_or_else(|| OracleError::InvalidProof {
                    state_root: *state_root,
                    address,
                    detail: format!("storage value scalar too long ({} bytes)", value.len()),
                })?;
                self.note_storage(address, position, state_root, leaf.storage_root, v, started);
                Ok(v)
            }
            None => Err(OracleError::StateUnavailable {
                state_root: *state_root,
                address,
                slot: Some(position),
            }),
        }
    }

    fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
        // Content-addressed: snap_get_bytecode checks keccak(code) == code_hash,
        // so any peer's bytes are trusted iff they hash correctly.
        let quality = self.quality.clone();
        let started = std::time::Instant::now();
        let (asked, peers) = self.ladder();
        let peers = &peers;
        let fetched = self.wait(async {
            // Hedged like the account leaf above. Code is content-addressed and
            // keyed by hash, so racing discloses nothing new about the caller.
            let out = hedged_race(
                peers,
                HEDGE_DELAY,
                |peer: Arc<ManagedPeer>| async move { peer.snap_get_bytecode(code_hash).await },
                |_: &Vec<u8>| true,
            )
            .await;
            Self::record_race(&quality, peers, &out, self.finalized).await;
            self.learn_order(&asked, &out);
            out.accepted.map(|(_, code)| code)
        })?;
        let code = fetched.ok_or(OracleError::BytecodeUnavailable {
            code_hash: *code_hash,
        })?;
        self.stats.observe_code(*code_hash, started.elapsed());
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_to_u64_parses_minimal_scalar() {
        assert_eq!(be_to_u64(&[]), 0);
        assert_eq!(be_to_u64(&[0x07]), 7);
        assert_eq!(be_to_u64(&[0x01, 0x00]), 256);
        assert_eq!(be_to_u64(&[0xff; 8]), u64::MAX);
        assert_eq!(be_to_u64(&[0xff; 9]), u64::MAX); // oversized saturates, no panic
    }

    #[test]
    fn u256_be_guards_oversized() {
        assert_eq!(u256_be(&[0x2a]).unwrap(), U256::from(42));
        assert_eq!(u256_be(&[]).unwrap(), U256::ZERO);
        assert!(u256_be(&[0u8; 33]).is_none()); // > 32 bytes → None, no panic
    }

    #[test]
    fn block_context_maps_header_fields() {
        let mut h = BlockHeader::default();
        h.state_root = [0xAB; 32];
        h.number = 21_000_000;
        h.timestamp = 1_710_338_200;
        h.beneficiary = vec![0x11; 20];
        h.mix_hash_or_prev_randao = [0x33; 32];
        h.gas_limit = 30_000_000;
        h.base_fee_per_gas = Some(vec![0x01, 0x00]); // 256 wei
        let ctx = block_context(&h, 1).unwrap();
        assert_eq!(ctx.state_root, [0xAB; 32]);
        assert_eq!(ctx.block_number, 21_000_000);
        assert_eq!(ctx.timestamp, 1_710_338_200);
        assert_eq!(ctx.base_fee_per_gas, 256);
        assert_eq!(ctx.coinbase, [0x11; 20]);
        assert_eq!(ctx.prev_randao, [0x33; 32]);
        assert_eq!(ctx.chain_id, 1);
        assert_eq!(ctx.gas_limit, 30_000_000);
    }

    #[test]
    fn block_context_rejects_bad_coinbase() {
        let mut h = BlockHeader::default();
        h.beneficiary = vec![0x11; 19]; // not 20 bytes
        assert!(block_context(&h, 1).is_err());
    }

    #[test]
    fn block_context_carries_the_slot_number() {
        let pre = BlockHeader {
            beneficiary: vec![0x11; 20],
            ..BlockHeader::default()
        };
        assert_eq!(block_context(&pre, 11_155_111).unwrap().slot_number, None);
        let amsterdam = BlockHeader {
            slot_number: Some(11_296_768),
            ..pre
        };
        assert_eq!(
            block_context(&amsterdam, 11_155_111).unwrap().slot_number,
            Some(11_296_768)
        );
    }

    #[test]
    fn a_refusal_stays_permanent_and_everything_else_keeps_its_mapping() {
        fn missing<T>() -> Result<T, EvmError> {
            Err(EvmError::MissingSlotNumber { block_number: 7 })
        }
        assert!(matches!(
            CallOutcome::from_executor(missing()),
            CallOutcome::Refused(_)
        ));
        assert!(matches!(
            GasOutcome::from_executor(missing()),
            GasOutcome::Refused(_)
        ));
        // Unchanged for everything that isn't a refusal.
        assert!(
            matches!(CallOutcome::from_executor(Ok(vec![1])), CallOutcome::Success(d) if d == [1])
        );
        assert!(matches!(
            CallOutcome::from_executor(Err(EvmError::Reverted { data: vec![2] })),
            CallOutcome::Revert(d) if d == [2]
        ));
        assert!(matches!(
            CallOutcome::from_executor(Err(EvmError::OutOfGas)),
            CallOutcome::Unavailable(_)
        ));
        assert!(matches!(
            GasOutcome::from_executor(Ok(24_150)),
            GasOutcome::Estimate(24_150)
        ));
        assert!(matches!(
            GasOutcome::from_executor(Err(EvmError::Reverted { data: vec![3] })),
            GasOutcome::Revert(d) if d == [3]
        ));
        assert!(matches!(
            GasOutcome::from_executor(Err(EvmError::UnsupportedChain { chain_id: 137 })),
            GasOutcome::Unavailable(_)
        ));
    }

    /// End to end: an Amsterdam header's slot travels from the wire bytes
    /// through `block_context` to what SLOTNUM returns — and a header without
    /// it is refused, never answered with slot 0.
    mod slotnum {
        use super::*;
        use myotis_core::rlp::{self, Item};
        use myotis_evm::{EvmExecutor, NoopBytecodeCache, NoopStateProofCache};
        use std::sync::Arc;

        const TARGET: [u8; 20] = [0x11; 20];
        /// SLOTNUM PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN.
        const CODE: [u8; 9] = [0x4b, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];

        /// Serves exactly one contract (CODE at TARGET); everything else is absent.
        struct OneContract;
        impl SnapStateOracle for OneContract {
            fn fetch_account(
                &self,
                _: &[u8; 32],
                address: [u8; 20],
            ) -> Result<Option<OracleAccount>, OracleError> {
                Ok((address == TARGET).then(|| OracleAccount {
                    nonce: 1,
                    balance: U256::ZERO,
                    code_hash: myotis_core::keccak::keccak256(&CODE),
                    storage_root: EMPTY_TRIE_ROOT,
                }))
            }
            fn fetch_storage(
                &self,
                _: &[u8; 32],
                _: [u8; 20],
                _: U256,
            ) -> Result<U256, OracleError> {
                Ok(U256::ZERO)
            }
            fn fetch_bytecode(&self, _: &[u8; 32]) -> Result<Vec<u8>, OracleError> {
                Ok(CODE.to_vec())
            }
        }

        /// A sepolia header at Amsterdam's activation, with `tail` appended
        /// after requestsHash (the Amsterdam pair, or nothing).
        fn sepolia_header(tail: Vec<Item>) -> BlockHeader {
            let base = BlockHeader {
                beneficiary: vec![0x22; 20],
                number: 10_000_000,
                gas_limit: 60_000_000,
                timestamp: myotis_evm::fork::SEPOLIA_AMSTERDAM_TIME,
                logs_bloom: vec![0; 256],
                nonce: vec![0; 8],
                base_fee_per_gas: Some(vec![0x07]),
                withdrawals_root: Some([0x08; 32]),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some([0x09; 32]),
                ..BlockHeader::default()
            };
            let mut items = rlp::decode(&base.encode())
                .unwrap()
                .as_list()
                .unwrap()
                .to_vec();
            items.push(Item::Bytes(vec![0x0a; 32])); // requestsHash
            items.extend(tail);
            BlockHeader::decode(&rlp::encode(&Item::List(items))).unwrap()
        }

        fn run(header: &BlockHeader) -> Result<Vec<u8>, EvmError> {
            let exec = EvmExecutor::new(
                Arc::new(OneContract),
                Arc::new(NoopStateProofCache),
                Arc::new(NoopBytecodeCache),
            );
            exec.call_view(TARGET, &[], &block_context(header, 11_155_111).unwrap())
        }

        #[test]
        fn slotnum_reads_the_slot_from_the_header_bytes() {
            let slot = 11_296_768u64; // Sepolia's first Amsterdam slot
            let h = sepolia_header(vec![
                Item::Bytes(vec![0x0b; 32]),
                Item::Bytes(rlp::u64_to_minimal_be(slot)),
            ]);
            let out = run(&h).expect("an Amsterdam call with a slot runs");
            assert_eq!(U256::from_be_slice(&out), U256::from(slot));
        }

        #[test]
        fn a_header_without_the_slot_is_refused_not_answered_with_zero() {
            let outcome = CallOutcome::from_executor(run(&sepolia_header(Vec::new())));
            assert!(matches!(outcome, CallOutcome::Refused(_)), "{outcome:?}");
        }
    }

    /// The oracle's within-call ask order: a dead first peer in the call's
    /// snapshot must cost one hedge delay per CALL, not one per state read.
    mod ask_order {
        use super::*;
        use std::time::Duration;

        fn outcome(accepted: Option<usize>, missed: Vec<usize>, outpaced: Vec<usize>) -> RaceOutcome<()> {
            RaceOutcome {
                accepted: accepted.map(|pos| (pos, ())),
                fallback: None,
                missed,
                outpaced,
                errors: Vec::new(),
            }
        }

        #[test]
        fn the_winner_leads_and_the_losers_trail() {
            let order = [0, 1, 2, 3];
            // Peer 0 was outpaced by peer 1.
            assert_eq!(next_order(&order, &order, &outcome(Some(1), vec![], vec![0])), vec![1, 2, 3, 0]);
            // Peer 0 missed and peer 1 was outpaced; peer 2 won and peer 3 was never asked.
            assert_eq!(next_order(&order, &order, &outcome(Some(2), vec![0], vec![1])), vec![2, 3, 0, 1]);
            // The first peer answered at once: nothing moves.
            assert_eq!(next_order(&order, &order, &outcome(Some(0), vec![], vec![])), vec![0, 1, 2, 3]);
            // Nobody won and everybody missed: the order stands.
            assert_eq!(next_order(&order, &order, &outcome(None, vec![0, 1, 2, 3], vec![])), vec![0, 1, 2, 3]);
        }

        #[test]
        fn race_positions_map_through_the_order_the_race_used() {
            // The race asked in order [2, 0, 1], so its position 0 is peer 2.
            let order = [2, 0, 1];
            assert_eq!(next_order(&order, &order, &outcome(Some(1), vec![], vec![0])), vec![0, 1, 2]);
            // A race that ran on an older order still applies by peer id, and a
            // position outside that order is ignored rather than trusted.
            let asked = [0, 1, 2];
            assert_eq!(next_order(&[1, 2, 0], &asked, &outcome(Some(2), vec![7], vec![0])), vec![2, 1, 0]);
        }

        #[test]
        fn the_order_stays_a_permutation() {
            let order = [3, 1, 4, 0, 2];
            for winner in [None, Some(0), Some(4)] {
                let next = next_order(&order, &order, &outcome(winner, vec![1, 2], vec![3]));
                let mut sorted = next.clone();
                sorted.sort_unstable();
                assert_eq!(sorted, vec![0, 1, 2, 3, 4], "{next:?}");
            }
        }

        #[tokio::test(start_paused = true)]
        async fn a_dead_first_peer_costs_one_hedge_delay_per_call() {
            // Peer 0 never answers and peer 1 answers in 50 ms. Three state
            // reads in one call, each asking in the order the previous one left.
            let ask = |id: usize| async move {
                crate::el::peer::mark_request_sent();
                let wait = if id == 0 { Duration::from_secs(600) } else { Duration::from_millis(50) };
                tokio::time::sleep(wait).await;
                Ok::<usize, String>(id)
            };
            let mut order = vec![0usize, 1];
            let mut costs = Vec::new();
            for _ in 0..3 {
                let started = tokio::time::Instant::now();
                let out = hedged_race(&order, HEDGE_DELAY, ask, |_: &usize| true).await;
                costs.push(started.elapsed());
                assert_eq!(out.accepted.as_ref().map(|(_, id)| *id), Some(1));
                order = next_order(&order, &order, &out);
            }
            let fast = Duration::from_millis(50);
            assert_eq!(costs, vec![HEDGE_DELAY + fast, fast, fast]);
        }
    }
}
