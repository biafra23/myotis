//! The EVM bridge: `eth_call` over verified state.
//!
//! [`myotis_evm`] is sans-I/O and its [`SnapStateOracle`] is synchronous. This
//! module is the I/O half: [`PoolOracle`] implements that trait over the snap
//! peer pool, bridging each verified fetch to the async network via
//! [`Handle::block_on`], and [`ElReader::eth_call`](crate::el::reader::ElReader)
//! drives the `revm` executor on a blocking thread so that bridge never nests a
//! `block_on` inside a runtime worker.
//!
//! Every fetch pins to the executor-supplied `state_root` (the verified head's),
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

use myotis_core::header::BlockHeader;
use myotis_core::trie::{AccountLeaf, EMPTY_TRIE_ROOT};
use myotis_evm::{
    BlockContext, BytecodeCache, OracleAccount, OracleError, SnapStateOracle, StateProofCache,
    U256,
};

use crate::el::peer::ManagedPeer;
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
}

/// The outcome of an `estimateGas`. `estimateGas` has no number for a revert or a
/// failed/unverifiable run — the host maps `Unavailable` to a JSON-RPC null, like
/// the Java engine.
#[derive(Debug, Clone)]
pub enum GasOutcome {
    /// The gas-limit estimate (already buffered by the executor).
    Estimate(u64),
    /// No estimate (revert / halt / state unavailable). The string is diagnostic.
    Unavailable(String),
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
/// chain config (the header carries no chain id).
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
fn u256_be(bytes: &[u8]) -> Option<U256> {
    if bytes.len() > 32 {
        None
    } else {
        Some(U256::from_be_slice(bytes))
    }
}

/// A [`SnapStateOracle`] over a fixed snapshot of snap peers, bridging the sync
/// trait to the async snap fetch path. Created per `eth_call`.
pub struct PoolOracle {
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
}

impl PoolOracle {
    pub fn new(
        peers: Vec<Arc<ManagedPeer>>,
        handle: Handle,
        quality: Option<crate::el::pool::SnapQualitySink>,
    ) -> PoolOracle {
        PoolOracle {
            peers,
            handle,
            quality,
            leaf_memo: Mutex::new(HashMap::new()),
        }
    }

    /// Record one per-peer fetch outcome (no-op without a sink).
    async fn record(quality: &Option<crate::el::pool::SnapQualitySink>, peer: &ManagedPeer, served: bool) {
        if let Some(q) = quality {
            if served {
                q.served(peer.addr()).await;
            } else {
                q.failed(peer.addr()).await;
            }
        }
    }

    /// The proof-verified account leaf at `address`, or `None` when proven absent.
    /// Memoised per call. `Err` only when no peer could prove it.
    fn leaf(
        &self,
        state_root: &[u8; 32],
        address: [u8; 20],
    ) -> Result<Option<AccountLeaf>, OracleError> {
        if let Some(cached) = self.leaf_memo.lock().unwrap().get(&address) {
            return Ok(cached.clone());
        }
        // No lock held across the network fetch.
        let quality = self.quality.clone();
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer.snap_get_account(state_root, &address).await {
                    Ok(AccountOutcome::Present(leaf)) => {
                        Self::record(&quality, peer, true).await;
                        return Some(Some(leaf));
                    }
                    Ok(AccountOutcome::Absent) => {
                        Self::record(&quality, peer, true).await;
                        return Some(None);
                    }
                    // Bad proof / transport for this peer — try the next.
                    Err(_) => Self::record(&quality, peer, false).await,
                }
            }
            None
        });
        match fetched {
            Some(leaf) => {
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
                        match peer.snap_get_account(state_root, &addr).await {
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
                        peer.snap_get_storage(state_root, &addr, &leaf, &position)
                            .await
                            .ok()
                            .and_then(|bytes| u256_be(&bytes))
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
                                    q.served(peer.addr()).await;
                                } else if asked_any {
                                    q.failed(peer.addr()).await;
                                }
                            }
                            pending = still_failed;
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
                    if let Ok(code) = peer.snap_get_bytecode(hash).await {
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
        self.handle.block_on(async {
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
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer
                    .snap_get_storage(state_root, &address, &leaf, &position)
                    .await
                {
                    Ok(value) => {
                        Self::record(&quality, peer, true).await;
                        return Some(value);
                    }
                    Err(_) => Self::record(&quality, peer, false).await,
                }
            }
            None
        });
        match fetched {
            // Empty bytes = a proven-zero / absent slot.
            Some(value) => u256_be(&value).ok_or_else(|| OracleError::InvalidProof {
                state_root: *state_root,
                address,
                detail: format!("storage value scalar too long ({} bytes)", value.len()),
            }),
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
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer.snap_get_bytecode(code_hash).await {
                    Ok(code) => {
                        Self::record(&quality, peer, true).await;
                        return Some(code);
                    }
                    Err(_) => Self::record(&quality, peer, false).await,
                }
            }
            None
        });
        fetched.ok_or(OracleError::BytecodeUnavailable {
            code_hash: *code_hash,
        })
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
}
