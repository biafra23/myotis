//! The EL verified-read reader (EL-A7b): composes discv4 discovery + the peer
//! pool + the CL-fed [`ExecAnchor`] into verified account/storage queries — the
//! Rust twin of the Java `VerifiedAccountQuery` / `VerifiedStorageQuery` ladders.
//!
//! One [`ElReader`] per hosted chain owns its own discv4 UDP service and
//! [`PeerPool`], and borrows the beacon sync loop's [`ExecAnchor`] (the CL→EL
//! trust bridge). A query:
//!
//! 1. picks a live snap peer from the pool,
//! 2. fetches the peer's FRESH head header → its state root + block number (peers
//!    prune state beyond ~128 blocks, so a beacon-finalized root is usually too
//!    stale to serve),
//! 3. snap-fetches the account/slot and MPT-verifies it against that state root
//!    (the proof is the trust anchor, never the peer's slim body),
//! 4. anchors the state root to the beacon chain via the verified ladder
//!    (`stateRootMatch` fast path, else the `headerChain` walk),
//! 5. returns the data + the verdict tokens; verification failures are recorded
//!    in `fail_reason`, never raised.

use std::sync::Arc;

use tokio::sync::mpsc;

use myotis_core::header::BlockHeader;
use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
use myotis_core::triehash;

use myotis_evm::{
    EnsError, EvmError, EvmExecutor, ExecutorCaller, InMemoryBytecodeCache,
    InMemoryStateProofCache, U256,
};

use crate::el::anchor::ExecAnchor;
use crate::el::discv4::{Discv4Config, Discv4Service};
use crate::el::eth::session::EthConfig;
use crate::el::evm::{
    block_context, CallOutcome, EnsOutcome, EnsQuery, EnsQueryOutcome, EnsRecordValue,
    EnsRootMode, GasOutcome, PoolOracle,
};
use crate::el::peer::ManagedPeer;
use crate::el::pool::{PeerPool, PoolConfig};
use crate::el::receipt::DecodedReceipt;
use crate::el::snap::fetch::AccountOutcome;
use crate::el::tx;
use crate::el::tx::TxSummary;

/// EL network parameters for the reader's discv4 + eth handshake.
#[derive(Debug, Clone)]
pub struct ElConfig {
    pub network_id: u64,
    /// Execution-layer genesis block hash (the eth Status gate).
    pub genesis_hash: [u8; 32],
    pub fork_id_hash: [u8; 4],
    pub fork_next: u64,
    /// discv4 bootnodes (`ip:port`, no keys).
    pub bootnodes: Vec<std::net::SocketAddr>,
    /// discv4 UDP bind port (0 = ephemeral).
    pub discv4_port: u16,
    /// The TCP port we advertise in Hello (informational for a dialer).
    pub listen_port: u16,
    pub pool_config: PoolConfig,
    /// Path to the EL peer cache (`dataDir/peers.cache`) for warm-start; `None`
    /// runs without persistence.
    pub cache_path: Option<std::path::PathBuf>,
    /// Network floor for the suggested priority fee (wei) — the Java
    /// `NetworkConfig.minSuggestedTipWei` (mainnet/sepolia 0.1 gwei; gnosis 0.001).
    pub min_suggested_tip_wei: u128,
}

impl ElConfig {
    /// Mainnet EL parameters (the values the live tests pin). The fork-id is the
    /// pinned hash the Java engine also carries; a hard fork would need a bump
    /// here (tracked as the EL-A7 fork-id item).
    pub fn mainnet() -> ElConfig {
        const MAINNET_BOOTNODES: &[&str] = &[
            "18.138.108.67:30303",
            "3.209.45.79:30303",
            "18.188.214.86:30303",
            "3.219.208.172:30303",
        ];
        ElConfig {
            network_id: 1,
            genesis_hash: hex32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"),
            fork_id_hash: [0x07, 0xc9, 0x46, 0x2e],
            fork_next: 0,
            bootnodes: MAINNET_BOOTNODES.iter().filter_map(|s| s.parse().ok()).collect(),
            discv4_port: 0,
            listen_port: 30303,
            pool_config: PoolConfig::default(),
            cache_path: None,
            min_suggested_tip_wei: 100_000_000, // 0.1 gwei
        }
    }

    /// Sepolia EL parameters — duplicated verbatim from the Java
    /// `NetworkConfig.SEPOLIA` (fork-id is the post-BPO2/Fusaka pinned hash the
    /// Java engine also carries; a hard fork needs a bump here, same as mainnet).
    pub fn sepolia() -> ElConfig {
        const SEPOLIA_BOOTNODES: &[&str] = &[
            "138.197.51.181:30303",
            "146.190.1.103:30303",
            "170.64.250.88:30303",
            "139.59.49.206:30303",
            "138.68.123.152:30303",
        ];
        ElConfig {
            network_id: 11_155_111,
            genesis_hash: hex32("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9"),
            fork_id_hash: [0x26, 0x89, 0x56, 0xb6],
            fork_next: 0,
            bootnodes: SEPOLIA_BOOTNODES.iter().filter_map(|s| s.parse().ok()).collect(),
            discv4_port: 0,
            // Sepolia's conventional EL port (Java `defaultElPort` 30305);
            // informational for a dialer, like mainnet's 30303.
            listen_port: 30305,
            pool_config: PoolConfig::default(),
            cache_path: None,
            min_suggested_tip_wei: 100_000_000, // 0.1 gwei
        }
    }
    /// Gnosis EL parameters — verbatim from the Java `NetworkConfig.GNOSIS`. The
    /// fork-id is the pinned Fulu/Osaka-head hash from live gnosis peers' eth Status.
    pub fn gnosis() -> ElConfig {
        const GNOSIS_BOOTNODES: &[&str] = &[
            "65.109.103.148:30303",
            "65.109.103.149:30303",
            "141.94.97.22:30303",
            "141.94.97.74:30303",
            "141.94.97.84:30303",
            "51.68.39.206:30303",
        ];
        ElConfig {
            network_id: 100,
            genesis_hash: hex32("4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756"),
            fork_id_hash: [0xcf, 0xca, 0x38, 0x7c],
            fork_next: 0,
            bootnodes: GNOSIS_BOOTNODES.iter().filter_map(|s| s.parse().ok()).collect(),
            discv4_port: 0,
            listen_port: 30304, // gnosis conventional EL port (Java defaultElPort)
            pool_config: PoolConfig::default(),
            cache_path: None,
            min_suggested_tip_wei: 1_000_000, // 0.001 gwei — cheap-chain floor
        }
    }
}

/// A verified account query result — the account data, the proof verdict, and
/// the beacon diagnostics (twin of the Java `AccountProofResult`, minus the
/// CL-status period fields and proof-node echo, which the JNI layer fills).
#[derive(Debug, Clone)]
pub struct VerifiedAccount {
    pub address: [u8; 20],
    /// keccak256(address) — the snap trie key.
    pub account_hash: [u8; 32],
    pub exists: bool,
    pub nonce: u64,
    /// Big-endian wei bytes (empty when `!exists`).
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
    /// Peer-reported block the proof anchors to.
    pub block_number: u64,
    pub peer_state_root: [u8; 32],
    pub peer_proof_valid: bool,
    pub beacon_chain_verified: bool,
    pub bls_verified: bool,
    pub matched_beacon_slot: i64,
    pub verify_method: Option<&'static str>,
    pub fail_reason: Option<&'static str>,
    pub beacon_synced: bool,
    pub finalized_block_number: u64,
    pub optimistic_block_number: u64,
}

/// A verified storage-slot query result (twin of the Java `StorageProofResult`).
#[derive(Debug, Clone)]
pub struct VerifiedStorage {
    pub address: [u8; 20],
    pub slot: u64,
    /// The holder address for an ERC-20 mapping lookup, if any.
    pub holder: Option<[u8; 20]>,
    /// The 32-byte storage key: the plain padded slot, or the ERC-20 mapping
    /// slot `keccak256(pad32(holder) ‖ uint256(slot))`.
    pub storage_key: [u8; 32],
    /// keccak256(storage key) — the slot's trie key.
    pub slot_key_hash: [u8; 32],
    pub found: bool,
    /// Big-endian value bytes (empty = zero / not found).
    pub value: Vec<u8>,
    /// The proof-verified account storage root the slot was checked against.
    pub storage_root: [u8; 32],
    pub storage_proof_valid: bool,
    pub block_number: u64,
    pub peer_state_root: [u8; 32],
    pub beacon_chain_verified: bool,
    pub bls_verified: bool,
    pub matched_beacon_slot: i64,
    pub verify_method: Option<&'static str>,
    pub fail_reason: Option<&'static str>,
    pub beacon_synced: bool,
    pub finalized_block_number: u64,
    pub optimistic_block_number: u64,
}

/// A verified contract-code query result (for `eth_getCode`). The bytecode is
/// content-addressed: `snap_get_bytecode` checks `keccak256(code) == code_hash`,
/// and `code_hash` itself comes from the beacon-anchored, proof-verified account,
/// so `verify_method`/`fail_reason` are inherited from that account query.
#[derive(Debug, Clone)]
pub struct VerifiedCode {
    pub address: [u8; 20],
    pub exists: bool,
    /// The contract bytecode (empty for an EOA / empty-code account / unverified).
    pub code: Vec<u8>,
    pub code_hash: [u8; 32],
    pub block_number: u64,
    pub beacon_chain_verified: bool,
    pub bls_verified: bool,
    pub matched_beacon_slot: i64,
    pub verify_method: Option<&'static str>,
    pub fail_reason: Option<&'static str>,
    pub beacon_synced: bool,
    pub finalized_block_number: u64,
    pub optimistic_block_number: u64,
}

/// A verified block result (`eth_getBlockByNumber`, transactions as hashes). The
/// header is anchored to the beacon optimistic head via a hash-linked header
/// window, and the body's transactions verify against the header's
/// `transactions_root` — so returning it at all IS the verification (the eth block
/// object carries no verdict field).
#[derive(Debug, Clone)]
pub struct VerifiedBlock {
    pub hash: [u8; 32],
    pub header: BlockHeader,
    /// keccak256 of each transaction's raw bytes, in block order.
    pub tx_hashes: Vec<[u8; 32]>,
}

/// How far below the beacon head a block pin may be and still verify cheaply
/// (mirrors the Java `VerifiedRpcBackend.BLOCK_LOOKBACK_MAX`): the header window
/// [target..head] is fetched in one request, so this bounds its size.
const BLOCK_LOOKBACK_MAX: u64 = 256;

/// First-ever receipt scan for a tx hash looks back this many blocks below the
/// head (the Java `RECEIPT_INITIAL_LOOKBACK_BLOCKS`); the per-tx cursor then
/// grows coverage forward as the wallet polls.
const RECEIPT_INITIAL_LOOKBACK_BLOCKS: u64 = 8;

/// Catch-up cap per receipt poll (the Java `RECEIPT_MAX_SCAN_BLOCKS_PER_POLL`):
/// after a long polling gap only the newest this-many blocks are scanned, so one
/// poll can't trigger a huge fetch.
const RECEIPT_MAX_SCAN_BLOCKS_PER_POLL: u64 = 128;

/// Idle TTL for a per-tx receipt scan cursor (the Java `RECEIPT_SCAN_TTL_MS`):
/// an entry untouched this long is dropped by the next sweep.
const RECEIPT_SCAN_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// How often the cursor map's TTL sweep may run (piggybacked on lookups; the
/// Java twin uses a background warmer tick). Well under the TTL, so eviction
/// lags it by at most a small fraction.
const RECEIPT_SCAN_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-peer deadline for one receipt scan attempt (window fetch + per-block
/// bodies) — the Java stage timeout (`HEADER_CHAIN_TIMEOUT_SEC`); on expiry the
/// next peer is tried.
const RECEIPT_SCAN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// A verified `eth_getTransactionReceipt` result. The containing block header is
/// anchored to the beacon optimistic head via a hash-linked header window, the
/// body verified against `transactionsRoot` (locating the tx + its index), and
/// the receipt list against `receiptsRoot` — so, as with [`VerifiedBlock`],
/// returning it at all IS the verification.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    pub tx_hash: [u8; 32],
    pub tx_index: u64,
    pub block_hash: [u8; 32],
    pub block_number: u64,
    /// This tx's own gas: `cumulative - previous receipt's cumulative`.
    pub gas_used: u64,
    /// Logs emitted by receipts BEFORE this one in the block — the base the
    /// block-global `logIndex` of each log adds its position to.
    pub log_index_base: u64,
    pub receipt: DecodedReceipt,
    /// The verified tx's summary (`None` when the tx couldn't be decoded — the
    /// receipt is then served without the tx-derived fields, like Java).
    pub tx: Option<TxSummary>,
    /// The effective gas price paid (receipt convention); `None` iff `tx` is.
    pub effective_gas_price: Option<u128>,
    /// The deployed address for a creation tx with a recovered sender.
    pub contract_address: Option<[u8; 20]>,
}

/// Where a mined tx was found, cached per tx hash so wallet polls don't rescan
/// (the Java `TxLocation`). The header/body were verified when this was built;
/// canonicality is re-confirmed on later polls until the block finalizes.
#[derive(Debug, Clone)]
struct TxLocation {
    header: BlockHeader,
    block_hash: [u8; 32],
    index: usize,
    raw_tx: Vec<u8>,
}

/// Per-tx incremental scan cursor (the Java `TxScanState`): coverage grows
/// forward from the first poll's small lookback, so per-poll cost is roughly the
/// number of NEW blocks.
struct TxScanState {
    /// Highest block already scanned (`None` = never scanned).
    high_scanned: Option<u64>,
    found: Option<TxLocation>,
    last_touched: std::time::Instant,
}

/// Recent blocks sampled for the `eth_maxPriorityFeePerGas` tip suggestion
/// (mirrors the Java `TIP_SUGGEST_BLOCKS`).
const TIP_SUGGEST_BLOCKS: u64 = 3;

/// A verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`), both
/// in wei. The tip is the median effective priority fee over the last
/// `TIP_SUGGEST_BLOCKS` verified blocks (floored); the gas price is the next
/// block's base fee plus that tip.
#[derive(Debug, Clone, Copy)]
pub struct FeeEstimate {
    pub max_priority_fee_wei: u128,
    pub gas_price_wei: u128,
}

/// A running EL reader: owns discv4 + the peer pool, borrows the beacon anchor.
pub struct ElReader {
    discovery: Discv4Service,
    pool: PeerPool,
    anchor: Arc<ExecAnchor>,
    /// Network floor for the suggested tip (from `ElConfig::min_suggested_tip_wei`).
    min_suggested_tip_wei: u128,
    /// Cross-call EVM caches, shared across every `eth_call` on this reader. Both
    /// hold `stateRoot`-keyed / content-addressed cryptographic facts, so reuse is
    /// sound. Because a call pins to the CURRENT head (whose root advances ~every
    /// 12 s), the win is on a burst of identical calls that land on the same head,
    /// plus bytecode (content-addressed → never re-fetched once seen) — NOT across
    /// a head advance. Freezing a per-block-number context so a slow retry reuses
    /// the cache is a later dispatch-fairness refinement (EL-C-3).
    evm_proof_cache: Arc<InMemoryStateProofCache>,
    evm_bytecode_cache: Arc<InMemoryBytecodeCache>,
    /// Per-tx receipt scan cursors (`eth_getTransactionReceipt` /
    /// `locateMinedTx`). Outer std Mutex guards only the map (held briefly);
    /// each entry's tokio Mutex serializes the (network-slow) scan per tx hash,
    /// so concurrent polls for the SAME tx don't duplicate fetches while
    /// different txs proceed in parallel.
    tx_scans: std::sync::Mutex<TxScanMap>,
}

/// The scan-cursor map plus its last TTL sweep — one lock covers both, so the
/// sweep can be time-gated without a second synchronization point.
struct TxScanMap {
    map: std::collections::HashMap<[u8; 32], Arc<tokio::sync::Mutex<TxScanState>>>,
    last_sweep: std::time::Instant,
}

/// Per-kind bound for the cross-call state-proof cache (accounts and storage
/// slots each) — Java `STATE_PROOF_CACHE_MAX` parity: sized so a ~1000-token
/// balance sweep's slots survive across the prefetch convergence loop and
/// repeat calls. Honest ceiling: BOTH kinds fully populated cost ~40 MB
/// (hashbrown buckets: accounts ~176 B, storage ~128 B × 128k buckets each),
/// and full population is reachable on a long-running daemon because keys
/// include the state_root (every new head re-proves). Same order as the Java
/// cache at the same count; eviction is LRU.
const EVM_PROOF_CACHE_ENTRIES: usize = 65_536;

/// Overall deadline for one ENS resolution walk (mirrors the Java
/// `JavaEnsApi.RESOLVE_TIMEOUT_SEC` order of magnitude — the EnsApi contract
/// promises a bounded worst case of ~2 min).
const RESOLVE_ENS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Per-ATTEMPT deadline inside the ENS root ladder (the Java
/// `VerifiedRpcBackend.ENS_TIMEOUT_SEC` twin): AUTO runs up to two attempts
/// (finalized, then optimistic), each bounded here, with
/// [`RESOLVE_ENS_DEADLINE`] as the outer cap on the whole query — so a stalled
/// finalized attempt can't consume the optimistic attempt's budget, and the
/// JNI caller's total block time stays within the API's ~2 min contract.
const RESOLVE_ENS_ATTEMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

impl ElReader {
    /// Start a mainnet reader with a freshly-generated ephemeral node key (the
    /// CL side generates its libp2p identity per run too; a persistent EL
    /// identity is an EL-A8 concern). `cache_path` is the EL peer cache for
    /// warm-start (`dataDir/peers.cache`), or `None` to run without persistence.
    pub async fn start_mainnet(
        anchor: Arc<ExecAnchor>,
        cache_path: Option<std::path::PathBuf>,
    ) -> Result<ElReader, String> {
        ElReader::start_for(anchor, cache_path, ElConfig::mainnet()).await
    }

    /// Start a reader for any network's [`ElConfig`] with a freshly-generated
    /// ephemeral node key (see [`Self::start_mainnet`] for the key rationale).
    /// `base` is the network's config; `cache_path` overrides its peer cache.
    pub async fn start_for(
        anchor: Arc<ExecAnchor>,
        cache_path: Option<std::path::PathBuf>,
        base: ElConfig,
    ) -> Result<ElReader, String> {
        let key = generate_node_key()?;
        let cfg = ElConfig { cache_path, ..base };
        ElReader::start(key, anchor, cfg).await
    }

    /// Start discovery + the peer pool for `cfg`, reading verified state against
    /// `anchor` (the beacon sync loop's execution anchor).
    pub async fn start(
        key: Arc<NodeKey>,
        anchor: Arc<ExecAnchor>,
        cfg: ElConfig,
    ) -> Result<ElReader, String> {
        let (tx, rx) = mpsc::channel(256);
        let discovery = Discv4Service::start(
            Arc::clone(&key),
            Discv4Config { bind_port: cfg.discv4_port, bootnodes: cfg.bootnodes.clone() },
            tx,
        )
        .await?;
        let eth_cfg = Arc::new(EthConfig {
            network_id: cfg.network_id,
            genesis_hash: cfg.genesis_hash,
            fork_id_hash: cfg.fork_id_hash,
            fork_next: cfg.fork_next,
            // A light client advertises genesis as its head; peers gate on fork-id.
            head_hash: cfg.genesis_hash,
            head_number: 0,
            listen_port: cfg.listen_port,
        });
        // Load the EL peer cache for warm-start (disabled if no path).
        let cache = match &cfg.cache_path {
            Some(path) => crate::el::peercache::ElPeerCache::load(path.clone()),
            None => crate::el::peercache::ElPeerCache::disabled(),
        };
        let local_pubkey = key.public_key_bytes();
        let pool = PeerPool::start(key, local_pubkey, eth_cfg, cfg.pool_config, cache, rx);
        Ok(ElReader {
            discovery,
            pool,
            anchor,
            min_suggested_tip_wei: cfg.min_suggested_tip_wei,
            evm_proof_cache: Arc::new(InMemoryStateProofCache::new(EVM_PROOF_CACHE_ENTRIES)),
            evm_bytecode_cache: Arc::new(InMemoryBytecodeCache::new()),
            tx_scans: std::sync::Mutex::new(TxScanMap {
                map: std::collections::HashMap::new(),
                last_sweep: std::time::Instant::now(),
            }),
        })
    }

    /// Count of live snap peers (for host status).
    pub async fn snap_peer_count(&self) -> usize {
        self.pool.snap_peer_count().await
    }

    /// EL pool/discovery counts for the host status snapshot.
    pub async fn attempted_count(&self) -> usize {
        self.pool.attempted_count().await
    }

    /// Inbound-serve counters `(header_asked, header_served, body_asked,
    /// body_served)` — what OTHER peers ask us for. Lock-free.
    pub fn serve_stats(&self) -> (u64, u64, u64, u64) {
        self.pool.serve_stats()
    }

    /// EL hunt engaged on the pool (serving pool empty past the stall window).
    pub fn el_hunting(&self) -> bool {
        self.pool.el_hunting()
    }

    pub async fn blacklist_count(&self) -> usize {
        self.pool.blacklist_count().await
    }

    pub async fn backoff_count(&self) -> usize {
        self.pool.backoff_count().await
    }

    /// discv4 routing-table size (peers discovered/known).
    pub fn discovered_count(&self) -> usize {
        self.discovery.table_size()
    }

    /// The beacon optimistic-head execution block number (`eth_blockNumber`), or 0
    /// before the anchor has a head. This is the verified canonical head the
    /// account/storage reads' peer tips are checked to chain to.
    pub fn optimistic_block_number(&self) -> u64 {
        self.anchor.optimistic_block_number()
    }

    /// The finalized execution block number, or 0 before the anchor has one.
    pub fn finalized_block_number(&self) -> u64 {
        self.anchor.finalized_execution().map(|f| f.block_number).unwrap_or(0)
    }

    /// Fetch + verify one account, running the full beacon-anchor ladder.
    ///
    /// Tries each live snap peer in turn (newest first) and returns the first
    /// that serves — twin of the Java `RLPxConnector.trySnapPeer` retry loop, so
    /// a single hung/dead peer doesn't fail the query. A serving peer is marked
    /// CONFIRMED in the cache, a failing one records a strike (→ deprioritized).
    pub async fn get_account(&self, address: [u8; 20]) -> Result<VerifiedAccount, String> {
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut fallback: Option<VerifiedAccount> = None;
        let mut last_err = String::new();
        for peer in &peers {
            match self.get_account_from(peer, address).await {
                Ok(result) => {
                    // Verified, or a GLOBAL verdict failure (beacon not ready —
                    // identical for every peer): this is the answer.
                    if result.verify_method.is_some() || is_global_fail(result.fail_reason) {
                        self.pool.record_snap_served(peer.addr()).await;
                        return Ok(result);
                    }
                    // A PER-PEER verdict failure (a stale/behind head or a bad
                    // proof — a different peer can still verify): keep it as a
                    // fallback and try the next peer.
                    self.pool.record_snap_failure(peer.addr()).await;
                    fallback.get_or_insert(result);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        // No peer verified; return the best per-peer result if we got one.
        fallback.map(Ok).unwrap_or_else(|| {
            Err(format!("all {total} snap peer(s) failed to serve a verifiable account: {last_err}"))
        })
    }

    /// One account fetch + verdict against a single peer (no retry, no cache
    /// bookkeeping — the caller loop owns those). Any transport/proof error
    /// propagates so the loop can move to the next peer.
    async fn get_account_from(
        &self,
        peer: &ManagedPeer,
        address: [u8; 20],
    ) -> Result<VerifiedAccount, String> {
        let (state_root, block_number) = fresh_head(peer).await?;
        // Verify-on-fetch: snap_get_account MPT-verifies against state_root and
        // returns Present/Absent only when the proof holds.
        let outcome = peer.snap_get_account(&state_root, &address).await?;
        // Anchor the (proof-valid) peer state root to the beacon chain.
        let verdict = peer
            .verified_state_root(&self.anchor, &state_root, to_ladder_block(block_number), true)
            .await;
        let (fin_num, opt_num, synced) = self.anchor_diagnostics();

        let account_hash = keccak256(&address);
        let mut result = VerifiedAccount {
            address,
            account_hash,
            exists: false,
            nonce: 0,
            balance: Vec::new(),
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_CODE_HASH,
            block_number,
            peer_state_root: state_root,
            peer_proof_valid: true,
            beacon_chain_verified: verdict.beacon_chain_verified,
            bls_verified: verdict.bls_verified,
            matched_beacon_slot: matched_slot(&verdict),
            verify_method: verdict.verify_method,
            fail_reason: verdict.fail_reason,
            beacon_synced: synced,
            finalized_block_number: fin_num,
            optimistic_block_number: opt_num,
        };
        if let AccountOutcome::Present(leaf) = outcome {
            result.exists = true;
            result.nonce = leaf.nonce;
            result.balance = leaf.balance;
            result.storage_root = leaf.storage_root;
            result.code_hash = leaf.code_hash;
        }
        Ok(result)
    }

    /// Fetch + verify one storage slot. `holder` switches the key to the
    /// Solidity mapping slot `keccak256(pad32(holder) ‖ uint256(slot))` (ERC-20
    /// balances); otherwise the plain `uint256(slot)` key is used.
    pub async fn get_storage(
        &self,
        address: [u8; 20],
        slot: u64,
        holder: Option<[u8; 20]>,
    ) -> Result<VerifiedStorage, String> {
        self.get_storage_keyed(address, slot, holder, storage_key(slot, holder)).await
    }

    /// Fetch + verify a RAW 32-byte storage position (`eth_getStorageAt`): the
    /// storage key IS the position — no `uint256(slot)` padding, no ERC-20 mapping.
    /// `slot`/`holder` are labels only (0 / none): a full 32-byte position has no
    /// meaningful u64 index.
    pub async fn get_storage_at(
        &self,
        address: [u8; 20],
        position: [u8; 32],
    ) -> Result<VerifiedStorage, String> {
        self.get_storage_keyed(address, 0, None, position).await
    }

    /// The cross-peer retry loop shared by `get_storage` / `get_storage_at`, keyed
    /// on the precomputed 32-byte storage key. Verification-aware: returns on the
    /// first peer that produces a verdict (or a global failure); a per-peer failure
    /// (stale head / bad proof) moves to the next peer, keeping the best as fallback.
    async fn get_storage_keyed(
        &self,
        address: [u8; 20],
        slot: u64,
        holder: Option<[u8; 20]>,
        storage_key: [u8; 32],
    ) -> Result<VerifiedStorage, String> {
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut fallback: Option<VerifiedStorage> = None;
        let mut last_err = String::new();
        for peer in &peers {
            match self.get_storage_from(peer, address, slot, holder, storage_key).await {
                Ok(result) => {
                    if result.verify_method.is_some() || is_global_fail(result.fail_reason) {
                        self.pool.record_snap_served(peer.addr()).await;
                        return Ok(result);
                    }
                    self.pool.record_snap_failure(peer.addr()).await;
                    fallback.get_or_insert(result);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        fallback.map(Ok).unwrap_or_else(|| {
            Err(format!("all {total} snap peer(s) failed to serve verifiable storage: {last_err}"))
        })
    }

    /// One storage-slot fetch + verdict against a single peer (no retry / cache
    /// bookkeeping — the caller loop owns those). Errors propagate for retry.
    async fn get_storage_from(
        &self,
        peer: &ManagedPeer,
        address: [u8; 20],
        slot: u64,
        holder: Option<[u8; 20]>,
        storage_key: [u8; 32],
    ) -> Result<VerifiedStorage, String> {
        let (state_root, block_number) = fresh_head(peer).await?;

        let slot_key_hash = keccak256(&storage_key);

        // Step 1: the proof-verified account gives the trusted storage root.
        let outcome = peer.snap_get_account(&state_root, &address).await?;

        let (fin_num, opt_num, synced) = self.anchor_diagnostics();
        let mut result = VerifiedStorage {
            address,
            slot,
            holder,
            storage_key,
            slot_key_hash,
            found: false,
            value: Vec::new(),
            storage_root: EMPTY_TRIE_ROOT,
            storage_proof_valid: false,
            block_number,
            peer_state_root: state_root,
            beacon_chain_verified: false,
            bls_verified: false,
            matched_beacon_slot: -1,
            verify_method: None,
            fail_reason: None,
            beacon_synced: synced,
            finalized_block_number: fin_num,
            optimistic_block_number: opt_num,
        };

        // An absent account has no storage: every slot is provably zero, and the
        // account exclusion proof verified. Anchor the state root so the result
        // carries the beacon verdict, then return it; this per-peer helper does no
        // cache bookkeeping — the outer retry loop records served/failure from the
        // verdict.
        let AccountOutcome::Present(leaf) = outcome else {
            // Still anchor the state root so the verdict reflects the beacon tie.
            let verdict = peer
                .verified_state_root(&self.anchor, &state_root, to_ladder_block(block_number), true)
                .await;
            result.storage_proof_valid = true; // exclusion proof held
            apply_verdict(&mut result, &verdict);
            return Ok(result);
        };
        result.storage_root = leaf.storage_root;

        // Step 2: verify the slot against the proof-verified storage root.
        let value = peer
            .snap_get_storage(&state_root, &address, &leaf, &storage_key)
            .await?;
        result.storage_proof_valid = true;
        // `found` means the slot holds a non-zero value (Java's convention): a
        // zero slot is pruned from the trie and indistinguishable from unset,
        // whether the account's storage trie is empty or the slot has a verified
        // exclusion proof. Both report found=false, value=zero (empty bytes).
        if !value.is_empty() {
            result.found = true;
            result.value = value;
        }

        // Step 3: anchor the account's state root to the beacon chain.
        let verdict = peer
            .verified_state_root(&self.anchor, &state_root, to_ladder_block(block_number), true)
            .await;
        apply_verdict(&mut result, &verdict);
        Ok(result)
    }

    /// Fetch + verify a contract's bytecode (`eth_getCode`). The account query is
    /// the trust anchor: it yields a beacon-anchored, proof-verified `code_hash`
    /// and verdict. The bytecode itself is then content-addressed — any snap peer's
    /// bytes are trusted iff `keccak256(code) == code_hash` — so the verdict is
    /// inherited from the account. A verified EOA / empty-code / absent account has
    /// provably empty code (no round trip). An unverified account returns empty code
    /// with `verify_method: None` (the caller surfaces that as "can't answer").
    pub async fn get_code(&self, address: [u8; 20]) -> Result<VerifiedCode, String> {
        let account = self.get_account(address).await?;
        let mut result = VerifiedCode {
            address,
            exists: account.exists,
            code: Vec::new(),
            code_hash: account.code_hash,
            block_number: account.block_number,
            beacon_chain_verified: account.beacon_chain_verified,
            bls_verified: account.bls_verified,
            matched_beacon_slot: account.matched_beacon_slot,
            verify_method: account.verify_method,
            fail_reason: account.fail_reason,
            beacon_synced: account.beacon_synced,
            finalized_block_number: account.finalized_block_number,
            optimistic_block_number: account.optimistic_block_number,
        };
        // No bytecode to fetch when the answer isn't verified, the account is
        // absent, or the code hash is empty (an EOA / empty-code contract): a
        // verified account with EMPTY_CODE_HASH has provably empty code.
        if account.verify_method.is_none()
            || !account.exists
            || account.code_hash == EMPTY_CODE_HASH
        {
            return Ok(result);
        }
        result.code = self.fetch_bytecode(&account.code_hash).await?;
        Ok(result)
    }

    /// Fetch bytecode for a verified `code_hash`, trying snap peers until one
    /// serves bytes that hash to it (`snap_get_bytecode` verifies the hash, so no
    /// per-peer verdict is needed — the code is content-addressed).
    async fn fetch_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, String> {
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            match peer.snap_get_bytecode(code_hash).await {
                Ok(code) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(code);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve verifiable bytecode: {last_err}"))
    }

    /// Verified `eth_call`: run a read-only call against the verified head's state.
    ///
    /// The block is pinned to the current verified head (the host gates the RPC
    /// block param to the servable window before calling this, as it does for the
    /// other reads). Builds a [`BlockContext`](myotis_evm::BlockContext) from the
    /// head header, then runs the `revm` executor on a blocking thread — its
    /// [`PoolOracle`] bridges each verified snap fetch to the network via
    /// `block_on`, which is sound there (a blocking thread, not a runtime worker).
    /// Returns [`CallOutcome`]: success data, revert data, or an unavailable/
    /// unverifiable reason (the host maps the latter two to a JSON-RPC null).
    pub async fn eth_call(
        &self,
        from: Option<[u8; 20]>,
        to: [u8; 20],
        data: Vec<u8>,
        value: U256,
        chain_id: u64,
    ) -> Result<CallOutcome, String> {
        let (ctx, executor) = self.evm_setup(chain_id, "eth_call").await?;
        // Run the SYNCHRONOUS executor off the runtime worker so the oracle's
        // per-fetch `block_on` is a fresh (non-nested) runtime entry.
        let joined = tokio::task::spawn_blocking(move || {
            // A from-less call still honours `value` — the default sender is the zero
            // ADDRESS, not zero value — so always thread `value` through
            // call_view_from (call_view would force value = 0 and drop it).
            let sender = from.unwrap_or([0u8; 20]);
            executor.call_view_from(sender, to, &data, value, &ctx)
        })
        .await
        .map_err(|e| format!("eth_call task join error: {e}"))?;
        Ok(match joined {
            Ok(bytes) => CallOutcome::Success(bytes),
            Err(EvmError::Reverted { data }) => CallOutcome::Revert(data),
            Err(other) => CallOutcome::Unavailable(other.to_string()),
        })
    }

    /// Verified `eth_estimateGas` for a call (`to` set): run the call against the
    /// verified head and return the gas-limit estimate. A revert / halt / unverifiable
    /// run yields [`GasOutcome::Unavailable`] (no number → the host returns null, as
    /// the reference engine does). Same head-pinning + executor bridge as [`Self::eth_call`].
    pub async fn estimate_gas(
        &self,
        from: Option<[u8; 20]>,
        to: [u8; 20],
        data: Vec<u8>,
        value: U256,
        chain_id: u64,
    ) -> Result<GasOutcome, String> {
        let (ctx, executor) = self.evm_setup(chain_id, "estimateGas").await?;
        let joined = tokio::task::spawn_blocking(move || {
            let sender = from.unwrap_or([0u8; 20]);
            executor.estimate_gas(sender, to, &data, value, &ctx)
        })
        .await
        .map_err(|e| format!("estimateGas task join error: {e}"))?;
        Ok(match joined {
            Ok(gas) => GasOutcome::Estimate(gas),
            Err(e) => GasOutcome::Unavailable(e.to_string()),
        })
    }

    /// Verified ENS forward resolution: `name` → its address record, resolved
    /// entirely over verified `eth_call`s against the current head (the registry
    /// resolver-walk + `addr`/ENSIP-10 `resolve` in `myotis_evm::ens`). Runs the
    /// whole walk on one blocking thread (each step's oracle fetch bridges via
    /// `block_on`, same as [`Self::eth_call`]). An invalid name or a state failure
    /// is `Err`; an offchain (CCIP) name is the distinguishable
    /// [`EnsOutcome::Offchain`].
    pub async fn resolve_ens(&self, name: String, chain_id: u64) -> Result<EnsOutcome, String> {
        let (ctx, executor) = self.evm_setup(chain_id, "resolve-ens").await?;
        let block_number = ctx.block_number;
        let walk = tokio::task::spawn_blocking(move || {
            let caller = ExecutorCaller { executor: &executor, ctx: &ctx };
            myotis_evm::resolve_address(&caller, &name)
        });
        // Overall deadline (the EnsApi contract promises a bounded worst case): the
        // walk is a chain of per-request-bounded peer calls, but a many-label name
        // against stalling peers could multiply far past that. On timeout the
        // abandoned closure still runs out its in-flight peer call on the blocking
        // thread (spawn_blocking can't be cancelled) — only the caller is released.
        let joined = tokio::time::timeout(RESOLVE_ENS_DEADLINE, walk)
            .await
            .map_err(|_| "resolve-ens timed out".to_string())?
            .map_err(|e| format!("resolve-ens task join error: {e}"))?;
        match joined {
            Ok(Some(address)) => Ok(EnsOutcome::Resolved { address, block_number }),
            Ok(None) => Ok(EnsOutcome::NoRecord { block_number }),
            Err(EnsError::OffchainLookup { .. }) => Ok(EnsOutcome::Offchain { block_number }),
            Err(e) => Err(e.to_string()),
        }
    }

    /// One [`EnsQuery`] against the root the caller demands (EL-C-5-2). `Auto`
    /// mirrors the Java ladder: attempt the beacon-FINALIZED root first and
    /// return its answer when it produced a value or an offchain marker;
    /// otherwise (no record, or the finalized attempt failed — e.g. no peer
    /// still serves that root) retry against the optimistic head. `Finalized`
    /// fails closed instead of downgrading. `verified` in the outcome = "ran
    /// against the finalized root".
    pub async fn resolve_ens_query(
        &self,
        query: EnsQuery,
        chain_id: u64,
        root: EnsRootMode,
    ) -> Result<EnsQueryOutcome, String> {
        // ONE outer deadline over the whole query — including context setups and
        // both AUTO attempts — so the (synchronously blocking) JNI caller's worst
        // case stays within the API's ~2 min contract regardless of root mode.
        let ladder = async {
            match root {
                EnsRootMode::Finalized => self.ens_attempt(query, chain_id, true).await,
                EnsRootMode::Optimistic => self.ens_attempt(query, chain_id, false).await,
                EnsRootMode::Auto => {
                    match self.ens_attempt(query.clone(), chain_id, true).await {
                        // A finalized value / offchain marker is the answer (an
                        // offchain gateway response won't change with the root).
                        Ok(out @ EnsQueryOutcome::Value { .. })
                        | Ok(out @ EnsQueryOutcome::Offchain { .. }) => Ok(out),
                        // No record at the finalized root, or the finalized attempt
                        // itself failed → the optimistic head decides.
                        Ok(EnsQueryOutcome::NoRecord { .. }) | Err(_) => {
                            self.ens_attempt(query, chain_id, false).await
                        }
                    }
                }
            }
        };
        tokio::time::timeout(RESOLVE_ENS_DEADLINE, ladder)
            .await
            .map_err(|_| "resolve-ens timed out".to_string())?
    }

    /// One ERC-3668 CALLBACK re-entry (EL-C-5-3): the host drove the gateway;
    /// this executes `sender.callbackFunction(response, extraData)` against the
    /// SAME root kind as the original attempt and decodes the answer with the
    /// original query's record semantics. A second `OffchainLookup` from the
    /// callback surfaces as `Offchain` again — the HOST enforces the recursion
    /// cap (Java `MAX_RECURSION_DEPTH = 1`). For a `Reverse` query the decoded
    /// claimed name is forward-verified here, exactly like the direct path.
    #[allow(clippy::too_many_arguments)]
    pub async fn ens_ccip_callback(
        &self,
        query: EnsQuery,
        chain_id: u64,
        finalized: bool,
        sender: [u8; 20],
        callback_function: [u8; 4],
        response: Vec<u8>,
        extra_data: Vec<u8>,
        wrapped: bool,
    ) -> Result<EnsQueryOutcome, String> {
        let attempt = async {
            let (ctx, executor) = if finalized {
                self.evm_setup_finalized(chain_id, "resolve-ens").await?
            } else {
                self.evm_setup(chain_id, "resolve-ens").await?
            };
            let block_number = ctx.block_number;
            let walk = tokio::task::spawn_blocking(move || {
                let caller = ExecutorCaller { executor: &executor, ctx: &ctx };
                let raw = myotis_evm::ccip_callback(
                    &caller,
                    sender,
                    callback_function,
                    &response,
                    &extra_data,
                    wrapped,
                )?;
                let Some(raw) = raw else { return Ok(None) };
                decode_ccip_answer(&caller, &query, &raw)
            });
            let joined = tokio::time::timeout(RESOLVE_ENS_ATTEMPT_DEADLINE, walk)
                .await
                .map_err(|_| "resolve-ens attempt timed out".to_string())?
                .map_err(|e| format!("resolve-ens task join error: {e}"))?;
            match joined {
                Ok(Some(value)) => {
                    Ok(EnsQueryOutcome::Value { value, block_number, verified: finalized })
                }
                Ok(None) => Ok(EnsQueryOutcome::NoRecord { block_number, verified: finalized }),
                Err(EnsError::OffchainLookup { lookup, wrapped }) => {
                    Ok(EnsQueryOutcome::Offchain {
                        block_number,
                        verified: finalized,
                        lookup,
                        wrapped,
                    })
                }
                Err(e) => Err(e.to_string()),
            }
        };
        tokio::time::timeout(RESOLVE_ENS_DEADLINE, attempt)
            .await
            .map_err(|_| "resolve-ens timed out".to_string())?
    }

    /// One resolution attempt against one root (finalized or optimistic).
    async fn ens_attempt(
        &self,
        query: EnsQuery,
        chain_id: u64,
        finalized: bool,
    ) -> Result<EnsQueryOutcome, String> {
        let (ctx, executor) = if finalized {
            self.evm_setup_finalized(chain_id, "resolve-ens").await?
        } else {
            self.evm_setup(chain_id, "resolve-ens").await?
        };
        let block_number = ctx.block_number;
        let walk = tokio::task::spawn_blocking(move || {
            let caller = ExecutorCaller { executor: &executor, ctx: &ctx };
            run_ens_query(&caller, &query)
        });
        // Per-attempt deadline (Java ENS_TIMEOUT_SEC twin): a stalled finalized
        // walk must leave budget for AUTO's optimistic attempt under the outer
        // cap. The timed-out spawn_blocking closure still runs out its in-flight
        // peer call (can't be cancelled) — only the caller is released.
        let joined = tokio::time::timeout(RESOLVE_ENS_ATTEMPT_DEADLINE, walk)
            .await
            .map_err(|_| "resolve-ens attempt timed out".to_string())?
            .map_err(|e| format!("resolve-ens task join error: {e}"))?;
        match joined {
            Ok(Some(value)) => Ok(EnsQueryOutcome::Value { value, block_number, verified: finalized }),
            Ok(None) => Ok(EnsQueryOutcome::NoRecord { block_number, verified: finalized }),
            Err(EnsError::OffchainLookup { lookup, wrapped }) => Ok(EnsQueryOutcome::Offchain {
                block_number,
                verified: finalized,
                lookup,
                wrapped,
            }),
            Err(e) => Err(e.to_string()),
        }
    }

    /// [`Self::evm_setup`], anchored at the beacon-FINALIZED execution block
    /// instead of the optimistic head. The header is fetched over the verified
    /// hash-chain window and then CROSS-CHECKED against the finalized anchor's
    /// own hash + state root, so the context provably IS the finalized state.
    /// Note the servable-edge caveat: execution peers prune state, so a
    /// finalized root (~2 epochs back) can be unservable — that fails closed
    /// here or in the oracle, and AUTO falls back to the optimistic head.
    async fn evm_setup_finalized(
        &self,
        chain_id: u64,
        what: &str,
    ) -> Result<(myotis_evm::BlockContext, EvmExecutor), String> {
        let Some(fin) = self.anchor.finalized_execution() else {
            return Err(format!("no beacon-finalized execution block for {what}"));
        };
        let Some(block) = self.get_block_by_number(Some(fin.block_number)).await? else {
            return Err(format!(
                "finalized block {} not fetchable for {what}",
                fin.block_number
            ));
        };
        // The window walk verified hash-linkage to the optimistic head; also pin
        // the header to the finalized anchor itself (belt and braces — the
        // finalized payload is the trust anchor this mode advertises).
        if block.hash != fin.block_hash {
            return Err(format!(
                "finalized-block hash mismatch at {} for {what}",
                fin.block_number
            ));
        }
        if block.header.state_root != fin.state_root {
            return Err(format!(
                "finalized-block state-root mismatch at {} for {what}",
                fin.block_number
            ));
        }
        let ctx = block_context(&block.header, chain_id)?;
        self.evm_executor_for(ctx, what).await
    }

    /// Shared setup for the EVM reads: a [`BlockContext`](myotis_evm::BlockContext)
    /// from the verified head + an [`EvmExecutor`] over a fresh snap-peer snapshot and
    /// the reader's cross-call caches. `what` names the caller in the error messages.
    async fn evm_setup(
        &self,
        chain_id: u64,
        what: &str,
    ) -> Result<(myotis_evm::BlockContext, EvmExecutor), String> {
        let Some(block) = self.get_block_by_number(None).await? else {
            return Err(format!("no verified head to run {what} against"));
        };
        let ctx = block_context(&block.header, chain_id)?;
        self.evm_executor_for(ctx, what).await
    }

    /// The executor half of the EVM setup: a fresh snap-peer snapshot + the
    /// reader's cross-call caches bound over the given context.
    async fn evm_executor_for(
        &self,
        ctx: myotis_evm::BlockContext,
        what: &str,
    ) -> Result<(myotis_evm::BlockContext, EvmExecutor), String> {
        // Snapshot the snap peers once: one consistent set for the whole call.
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err(format!("no snap peer available for {what}"));
        }
        let oracle = Arc::new(PoolOracle::new(
            peers,
            tokio::runtime::Handle::current(),
            Some(self.pool.quality_sink()),
        ));
        // Bind the concrete Arc types first, then let the unsizing coercion to the
        // trait objects happen at the constructor call (a coercion directly on
        // `Arc::clone` would instead infer `Arc<dyn Trait>` and fail to type-check).
        let proof_cache = Arc::clone(&self.evm_proof_cache);
        let bytecode_cache = Arc::clone(&self.evm_bytecode_cache);
        let executor = EvmExecutor::new(oracle, proof_cache, bytecode_cache);
        Ok((ctx, executor))
    }

    /// Verified `eth_getBlockByNumber` (transactions as hashes). `target` is the
    /// block number, or `None` for the latest (the beacon optimistic head).
    ///
    /// Returns `Ok(Some(block))` when a block is fetched and verified; `Ok(None)`
    /// for a number ABOVE the verified head (a future/unknown block → eth `null`);
    /// and `Err` when it can't verify right now (no anchor, too far back, or every
    /// peer failed → the host maps this to an error the router surfaces as -32000).
    pub async fn get_block_by_number(
        &self,
        target: Option<u64>,
    ) -> Result<Option<VerifiedBlock>, String> {
        let head_num = self.anchor.optimistic_block_number();
        let Some(head_hash) = self.anchor.optimistic_block_hash() else {
            return Err("no beacon-anchored head yet".to_string());
        };
        if head_num == 0 {
            return Err("beacon not synced".to_string());
        }
        let target_num = target.unwrap_or(head_num);
        // A pin above the verified head is future/unknown, not an error.
        if target_num > head_num {
            return Ok(None);
        }
        let back = head_num - target_num;
        if back >= BLOCK_LOOKBACK_MAX {
            return Err(format!(
                "block {target_num} is {back} behind the head — beyond the {BLOCK_LOOKBACK_MAX}-block verify window"
            ));
        }
        // Serve over the snap pool (the peer set the reader maintains); a block
        // serve is eth-only (headers + bodies), so this is a superset of what's
        // needed. If eth peers exist but none negotiated snap, this fails closed
        // (Err → -32000), never a false "null". Reputation reuses the snap sinks.
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            match self.get_block_from(peer, target_num, back, &head_hash).await {
                Ok(block) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(Some(block));
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve a verifiable block: {last_err}"))
    }

    /// Fetch + verify one block against a single peer. Fetches the header window
    /// [target..head], checks it hash-links up to the beacon-anchored head hash,
    /// then fetches the target's body and verifies its transactions against the
    /// header's `transactions_root`. Any mismatch/transport error propagates for
    /// the caller loop to try the next peer.
    async fn get_block_from(
        &self,
        peer: &ManagedPeer,
        target_num: u64,
        back: u64,
        head_hash: &[u8; 32],
    ) -> Result<VerifiedBlock, String> {
        // The contiguous forward window [target .. head] (back + 1 headers), in one
        // request. back < BLOCK_LOOKBACK_MAX (256) bounds this to ~150 KB, within the
        // eth response soft limit; a peer that caps its response below back+1 fails
        // the anchored-window length check and is skipped (fails closed — the caller
        // tries the next peer), so deep pins carry a slightly higher liveness risk
        // than a batched fetch would. The common case (latest / a few blocks back) is
        // one small response.
        let window = fetch_anchored_window(peer, target_num, back + 1, head_hash).await?;
        let vh = &window[0];
        // Body: verify its transactions against the (now trusted) transactions_root.
        let bodies = peer.get_block_bodies(&[vh.hash]).await?;
        let body = bodies.into_iter().next().ok_or("peer returned no block body")?;
        if !triehash::verify(&body.transactions, &vh.header.transactions_root) {
            return Err("block body transactions do not match the header transactionsRoot".to_string());
        }
        let tx_hashes = body.transactions.iter().map(|t| keccak256(t)).collect();
        Ok(VerifiedBlock { hash: vh.hash, header: vh.header.clone(), tx_hashes })
    }

    /// Verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`). Samples
    /// the last `TIP_SUGGEST_BLOCKS` beacon-anchored blocks: median per-tx effective
    /// tip (floored at the network's `min_suggested_tip_wei`) as the priority fee, and next-block
    /// base fee + that tip as the legacy gas price. `Err` when it can't verify.
    pub async fn fee_estimate(&self) -> Result<FeeEstimate, String> {
        let head_num = self.anchor.optimistic_block_number();
        let Some(head_hash) = self.anchor.optimistic_block_hash() else {
            return Err("no beacon-anchored head yet".to_string());
        };
        if head_num == 0 {
            return Err("beacon not synced".to_string());
        }
        // Sample [start..head]; never below genesis.
        let count = TIP_SUGGEST_BLOCKS.min(head_num + 1);
        let start = head_num + 1 - count;
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            match self.fee_estimate_from(peer, start, count, &head_hash).await {
                Ok(est) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(est);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve a verifiable fee estimate: {last_err}"))
    }

    /// Compute the fee estimate against a single peer: fetch the header window
    /// [start..head] (anchored + hash-linked to the beacon head), fetch all bodies
    /// in one request, verify each against its header's `transactions_root`, then
    /// take the median per-tx effective tip and the next-block base fee.
    async fn fee_estimate_from(
        &self,
        peer: &ManagedPeer,
        start: u64,
        count: u64,
        head_hash: &[u8; 32],
    ) -> Result<FeeEstimate, String> {
        let window = fetch_anchored_window(peer, start, count, head_hash).await?;
        let hashes: Vec<[u8; 32]> = window.iter().map(|vh| vh.hash).collect();
        let bodies = peer.get_block_bodies(&hashes).await?;
        if bodies.len() != window.len() {
            return Err(format!("peer returned {} bodies, expected {}", bodies.len(), window.len()));
        }
        let mut tips: Vec<u128> = Vec::new();
        for (vh, body) in window.iter().zip(bodies.iter()) {
            // Verify each body against its (chain-verified) header, then decode tips
            // at THAT block's base fee. A body that fails its transactionsRoot fails
            // the WHOLE estimate (→ next peer): stricter than the Java cold path,
            // which would median over the remaining good blocks — safer here, at a
            // small availability cost. (A wrong header/body pairing from an out-of-
            // order peer response is caught the same way.)
            if !triehash::verify(&body.transactions, &vh.header.transactions_root) {
                return Err("block body transactions do not match the header transactionsRoot".to_string());
            }
            let base = header_base_fee(&vh.header);
            for raw in &body.transactions {
                // A tx the minimal fee decoder can't read is skipped (not dropped
                // with its whole block, as Java does) — no real-world divergence
                // since every current mainnet tx type decodes.
                if let Some(t) = tx::effective_tip(raw, base) {
                    tips.push(t);
                }
            }
        }
        let tip = if tips.is_empty() {
            self.min_suggested_tip_wei
        } else {
            tips.sort_unstable();
            tips[tips.len() / 2].max(self.min_suggested_tip_wei)
        };
        // Gas price = the NEXT block's base fee (from the head header) + the tip.
        let head_header = &window[window.len() - 1].header;
        let gas_price = next_base_fee(head_header).saturating_add(tip);
        Ok(FeeEstimate { max_priority_fee_wei: tip, gas_price_wei: gas_price })
    }

    /// Gossip a signed raw transaction to peers (the engine never signs) and return
    /// `keccak256(rawTx)` — the tx hash — once at least one peer received the
    /// broadcast. `Err` when the input isn't a plausible tx or no peer could be
    /// reached. This is a WRITE: nothing is beacon-verified; the peers' mempools and
    /// a later verified receipt lookup are what confirm inclusion.
    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<[u8; 32], String> {
        // Minimal sanity only (we never sign or fully validate — peers reject a bad
        // tx): non-empty with a plausible prefix — a legacy RLP list (>= 0xc0) or an
        // EIP-2718 type byte (0x01..=0x7f). Avoids gossiping obvious garbage.
        match raw_tx.first() {
            Some(&b) if b >= 0xc0 || (0x01..=0x7f).contains(&b) => {}
            _ => return Err("not a valid raw transaction".to_string()),
        }
        let hash = keccak256(raw_tx);
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no peer available to broadcast the transaction".to_string());
        }
        // Broadcast to all peers concurrently — the success criterion is just
        // "≥1 peer received it", so there's no reason to serialize per-peer writes.
        let sent = futures::future::join_all(peers.iter().map(|peer| peer.send_transaction(raw_tx)))
            .await
            .iter()
            .filter(|r| r.is_ok())
            .count();
        if sent == 0 {
            return Err("no peer accepted the transaction broadcast".to_string());
        }
        Ok(hash)
    }

    /// Verified `eth_getTransactionReceipt`. Scans a bounded, incrementally
    /// growing window of recent blocks below the beacon-anchored head: bodies
    /// verify against `transactionsRoot` (locating the tx + its index), then the
    /// block's receipts against `receiptsRoot`, before anything is served. Twin
    /// of the Java `VerifiedRpcBackend.rpcGetTransactionReceipt`/`locateMinedTx`.
    ///
    /// Returns `Ok(Some)` for a verified receipt; `Ok(None)` for a VERIFIED
    /// "not seen" (scanned coverage doesn't contain the tx — eth's null, the
    /// wallet keeps polling); `Err` when it can't verify right now (no anchor /
    /// every peer failed → the host maps it to -32000). One deliberate
    /// divergence from Java: a scan the peers couldn't serve is `Err` here
    /// (Java's anchor-failure path answers "null"), and a block whose body
    /// fetch fails aborts that peer's scan instead of being silently skipped —
    /// stricter, so a skipped block can never masquerade as "not seen".
    ///
    /// COVERAGE CAVEAT (Java parity): "not seen" means not seen in the SCANNED
    /// coverage. A tx mined more than [`RECEIPT_INITIAL_LOOKBACK_BLOCKS`] below
    /// the head before its FIRST poll, or inside a catch-up gap the
    /// [`RECEIPT_MAX_SCAN_BLOCKS_PER_POLL`] cap skipped, keeps reading as null.
    /// The Java engine narrows this for the wallet's own txs via the sent-tx
    /// watch's broadcast-head reachback — that lands with the sent-tx slice
    /// (milestone B chunk 3).
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<VerifiedReceipt>, String> {
        let head_num = self.anchor.optimistic_block_number();
        let Some(head_hash) = self.anchor.optimistic_block_hash() else {
            return Err("no beacon-anchored head yet".to_string());
        };
        if head_num == 0 {
            return Err("beacon not synced".to_string());
        }
        let state = self.tx_scan_state(tx_hash)?;
        // Serialize concurrent polls for the same tx (the Java per-state
        // synchronized block); held across the network stages below on purpose.
        let mut st = state.lock().await;
        st.last_touched = std::time::Instant::now();

        // A cached location below the finalized height is immutable; one still
        // near the head must be re-confirmed canonical (it can be reorged out).
        if let Some(loc) = &st.found {
            let finalized = self.finalized_block_number();
            let immutable = finalized > 0 && loc.header.number <= finalized;
            if !immutable && !self.still_canonical(loc, head_num, &head_hash).await {
                // Proven reorged out: rescan the recent region from scratch.
                st.found = None;
                st.high_scanned = None;
            }
        }

        if st.found.is_none() {
            // A short reorg can pull the optimistic head BELOW an
            // already-scanned height. Clamp the cursor so the replacement
            // blocks are rescanned as the head re-advances — otherwise
            // `from = high + 1 > head` skips scanning until the head passes the
            // stale cursor, and a tx mined in a replacement block would keep
            // reading as a verified "not seen" in the meantime.
            if let Some(high) = st.high_scanned {
                if high > head_num {
                    st.high_scanned = Some(head_num);
                }
            }
            let mut from = match st.high_scanned {
                None => head_num.saturating_sub(RECEIPT_INITIAL_LOOKBACK_BLOCKS - 1),
                Some(high) => high + 1,
            };
            let cap_floor = head_num.saturating_sub(RECEIPT_MAX_SCAN_BLOCKS_PER_POLL - 1);
            if from < cap_floor {
                tracing::info!(
                    from,
                    cap_floor,
                    "tx scan: catch-up gap, skipping blocks below the per-poll cap"
                );
                from = cap_floor;
            }
            // from > head_num means the head hasn't advanced since the last
            // scan — nothing new to look at (the cached "not seen" stands).
            if from <= head_num {
                let peers = self.pool.snap_peers().await;
                if peers.is_empty() {
                    return Err("no snap peer available".to_string());
                }
                let total = peers.len();
                let mut scanned = false;
                let mut last_err = String::new();
                for peer in &peers {
                    let attempt = tokio::time::timeout(
                        RECEIPT_SCAN_DEADLINE,
                        self.scan_blocks_from(peer, from, head_num, &head_hash, &tx_hash),
                    )
                    .await
                    .unwrap_or_else(|_| Err("tx scan timed out".to_string()));
                    match attempt {
                        Ok(found) => {
                            self.pool.record_snap_served(peer.addr()).await;
                            // Advance the cursor only after a fully verified
                            // scan of [from..head] (found or not).
                            st.high_scanned = Some(head_num);
                            st.found = found;
                            scanned = true;
                            break;
                        }
                        Err(e) => {
                            self.pool.record_snap_failure(peer.addr()).await;
                            last_err = e;
                        }
                    }
                }
                if !scanned {
                    return Err(format!(
                        "all {total} snap peer(s) failed to serve a verifiable tx scan: {last_err}"
                    ));
                }
            }
        }

        let Some(loc) = st.found.clone() else {
            return Ok(None); // verified "not seen" in the scanned coverage → eth null
        };
        // The cursor is settled; release it before the receipt round-trip so
        // concurrent polls for the SAME tx aren't serialized behind network I/O
        // (the Java twin's synchronized block also ends at locateMinedTx).
        drop(st);

        // Fetch + verify the block's receipts against the (anchored) header's
        // receiptsRoot, then build the result. Receipts are re-fetched per poll
        // (only the LOCATION is cached), matching Java.
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            match self.receipt_from(peer, &loc, &tx_hash).await {
                Ok(vr) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(Some(vr));
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve verifiable receipts: {last_err}"))
    }

    /// Get-or-create the per-tx scan cursor. The idle-TTL sweep is time-gated
    /// (at most once per [`RECEIPT_SCAN_SWEEP_INTERVAL`]) so a burst of
    /// distinct hashes — the map key is attacker-suppliable via the public RPC
    /// — costs O(1) per lookup, not an O(n) walk each time (the Java twin
    /// evicts on a background warmer tick). `Err` only on a poisoned lock
    /// (can't happen under panic="abort", but never panic here).
    fn tx_scan_state(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Arc<tokio::sync::Mutex<TxScanState>>, String> {
        let mut scans = self.tx_scans.lock().map_err(|_| "engine lock poisoned".to_string())?;
        let now = std::time::Instant::now();
        if now.duration_since(scans.last_sweep) >= RECEIPT_SCAN_SWEEP_INTERVAL {
            scans.last_sweep = now;
            // An entry whose tokio lock is HELD is in use — keep it regardless.
            // saturating: a concurrent poll can stamp last_touched AFTER `now`
            // was captured; that reads as zero idle (kept), never a panic. (On
            // Rust >= 1.60 plain duration_since saturates too — this just says
            // so explicitly, matching the workspace's panic-free-by-construction
            // policy under panic="abort".)
            scans.map.retain(|_, st| match st.try_lock() {
                Ok(guard) => now.saturating_duration_since(guard.last_touched) < RECEIPT_SCAN_TTL,
                Err(_) => true,
            });
        }
        Ok(Arc::clone(scans.map.entry(tx_hash).or_insert_with(|| {
            Arc::new(tokio::sync::Mutex::new(TxScanState {
                high_scanned: None,
                found: None,
                last_touched: now,
            }))
        })))
    }

    /// Whether a cached tx location is still on the canonical chain: re-fetch
    /// headers `[loc.block .. head]`, anchor them to the beacon head hash, and
    /// compare the hash at loc's height. Conservatively `true` when it can't
    /// DISPROVE canonicality (peer hiccup, implausibly large range) so a glitch
    /// never flips a real receipt to "unknown"; `false` only on a proven hash
    /// mismatch / the head dropping below the block (the Java `stillCanonical`).
    async fn still_canonical(
        &self,
        loc: &TxLocation,
        head_num: u64,
        head_hash: &[u8; 32],
    ) -> bool {
        if loc.header.number > head_num {
            return false; // head sits below it — deep reorg
        }
        let count = head_num - loc.header.number + 1;
        if count > RECEIPT_MAX_SCAN_BLOCKS_PER_POLL {
            return true; // too far to recheck cheaply
        }
        let peers = self.pool.snap_peers().await;
        for peer in &peers {
            match self.confirm_canonical_from(peer, loc, count, head_hash).await {
                Ok(canonical) => return canonical,
                Err(_) => continue, // transport/anchor failure — can't disprove
            }
        }
        true
    }

    /// One peer's canonicality check: fetch `[loc.block .. head]`, require the
    /// anchored + hash-linked window, and compare `window[0]` to the cached
    /// block hash. `Err` = couldn't verify either way (caller tries next peer).
    async fn confirm_canonical_from(
        &self,
        peer: &ManagedPeer,
        loc: &TxLocation,
        count: u64,
        head_hash: &[u8; 32],
    ) -> Result<bool, String> {
        let window = fetch_anchored_window(peer, loc.header.number, count, head_hash).await?;
        Ok(window[0].hash == loc.block_hash)
    }

    /// Scan `[from..head]` against one peer for the tx hash: fetch the header
    /// window, anchor it to the beacon head + hash-link it, then check the
    /// blocks NEWEST-first (a just-mined tx is found on the first body
    /// checked), each body verified against its header's `transactionsRoot`
    /// before its tx hashes are trusted. Bodies are requested concurrently (the
    /// Java twin's bodyFutures — one pipelined round instead of up-to-128
    /// serial RTTs). Any fetch/verify failure fails the WHOLE scan for this
    /// peer (→ next peer) — a skipped block could otherwise read as a verified
    /// "not seen".
    async fn scan_blocks_from(
        &self,
        peer: &ManagedPeer,
        from: u64,
        head_num: u64,
        head_hash: &[u8; 32],
        want: &[u8; 32],
    ) -> Result<Option<TxLocation>, String> {
        let count = head_num - from + 1;
        let window = fetch_anchored_window(peer, from, count, head_hash).await?;
        // One single-hash request per block (bounded per-response size), all in
        // flight at once on this peer's multiplexed connection.
        let all_bodies = futures::future::join_all(window.iter().map(|vh| {
            let hash = [vh.hash]; // owned by the future (the request outlives this closure)
            async move { peer.get_block_bodies(&hash).await }
        }))
        .await;
        for (vh, bodies) in window.iter().zip(all_bodies).rev() {
            let body = bodies?.into_iter().next().ok_or("peer returned no block body")?;
            if !triehash::verify(&body.transactions, &vh.header.transactions_root) {
                return Err(format!(
                    "block {} body does not match the header transactionsRoot",
                    vh.header.number
                ));
            }
            for (i, raw) in body.transactions.iter().enumerate() {
                if &keccak256(raw) == want {
                    return Ok(Some(TxLocation {
                        header: vh.header.clone(),
                        block_hash: vh.hash,
                        index: i,
                        raw_tx: raw.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Fetch one block's receipts from one peer, verify them against the
    /// (anchored) header's `receiptsRoot`, and build the [`VerifiedReceipt`]
    /// for the located tx.
    async fn receipt_from(
        &self,
        peer: &ManagedPeer,
        loc: &TxLocation,
        tx_hash: &[u8; 32],
    ) -> Result<VerifiedReceipt, String> {
        let blocks = peer.get_receipts(&[loc.block_hash]).await?;
        let receipts = blocks.into_iter().next().ok_or("peer returned no receipts")?;
        if receipts.is_empty() {
            return Err("peer returned no receipts".to_string());
        }
        if !triehash::verify(&receipts, &loc.header.receipts_root) {
            return Err(format!(
                "block {} receipts do not match the header receiptsRoot",
                loc.header.number
            ));
        }
        if loc.index >= receipts.len() {
            return Err("tx index out of receipt range".to_string());
        }
        build_verified_receipt(loc, &receipts, tx_hash)
    }

    /// `(finalized_block_number, optimistic_block_number, is_synced)` snapshot.
    fn anchor_diagnostics(&self) -> (u64, u64, bool) {
        let fin = self.anchor.finalized_execution().map(|f| f.block_number).unwrap_or(0);
        (fin, self.anchor.optimistic_block_number(), self.anchor.is_synced())
    }

    /// Stop discovery + the pool.
    pub async fn stop(self) {
        self.pool.stop().await;
        self.discovery.stop().await;
    }
}

/// Build the [`VerifiedReceipt`] from a block's ROOT-VERIFIED receipt list and
/// the located tx. Pure: decodes the target receipt, one pass over the
/// preceding receipts for `gas_used` (previous cumulative) and the block-global
/// log-index base (the Java `buildReceiptJson` preamble), then derives the
/// tx-side fields (sender, effective gas price, created contract address) from
/// the transactionsRoot-verified raw tx — decoded defensively: an unknown
/// future tx type yields a receipt without those fields, never an error.
fn build_verified_receipt(
    loc: &TxLocation,
    receipts: &[Vec<u8>],
    tx_hash: &[u8; 32],
) -> Result<VerifiedReceipt, String> {
    let decoded = crate::el::receipt::decode(&receipts[loc.index])?;
    let mut prev_cum = 0u64;
    let mut log_index_base = 0u64;
    for prior in &receipts[..loc.index] {
        let prev = crate::el::receipt::decode(prior)?;
        log_index_base += prev.logs.len() as u64;
        // The last iteration leaves receipt[index-1]'s cumulative gas here.
        prev_cum = prev.cumulative_gas_used;
    }
    let gas_used = decoded.cumulative_gas_used.saturating_sub(prev_cum);
    let tx_summary = tx::decode_summary(&loc.raw_tx);
    let effective_gas_price = tx_summary
        .as_ref()
        .and_then(|t| tx::effective_gas_price(t, header_base_fee(&loc.header)));
    let contract_address = tx_summary.as_ref().and_then(|t| {
        // Only a creation tx (empty `to`) with a recovered sender deploys.
        match (&t.to, &t.from) {
            (None, Some(from)) => Some(tx::contract_address(from, t.nonce)),
            _ => None,
        }
    });
    Ok(VerifiedReceipt {
        tx_hash: *tx_hash,
        tx_index: loc.index as u64,
        block_hash: loc.block_hash,
        block_number: loc.header.number,
        gas_used,
        log_index_base,
        receipt: decoded,
        tx: tx_summary,
        effective_gas_price,
        contract_address,
    })
}

/// Fetch the contiguous header window `[from ..= from+count-1]` from one peer
/// and run the trust gate every anchored read shares: exact length, the right
/// starting number, the window head IS the beacon-anchored head hash, and every
/// header hash-links to the next. This is the sole gate that turns
/// peer-supplied headers into trusted ones — one implementation, four callers
/// (block serve, fee estimate, receipt scan, canonicality re-check), so a
/// hardening never has to be applied in four places.
async fn fetch_anchored_window(
    peer: &ManagedPeer,
    from: u64,
    count: u64,
    head_hash: &[u8; 32],
) -> Result<Vec<crate::el::eth::messages::VerifiedHeader>, String> {
    let window = peer.get_block_headers_by_number(from, count, 0, false).await?;
    if window.len() as u64 != count {
        return Err(format!("peer returned {} headers, expected {count}", window.len()));
    }
    if window[0].header.number != from {
        return Err("peer returned the wrong starting block number".to_string());
    }
    // The window's head must BE the beacon-anchored head, and each header must
    // hash-link to the next — proving every header in it chains to the verified
    // head (the trust gate: head_hash is the light-client-attested exec hash).
    if &window[window.len() - 1].hash != head_hash {
        return Err("window head does not match the beacon-anchored head hash".to_string());
    }
    for i in 0..window.len() - 1 {
        if window[i + 1].header.parent_hash != window[i].hash {
            return Err("header window is not hash-linked".to_string());
        }
    }
    Ok(window)
}

/// Fetch a peer's fresh head header and return `(state_root, block_number)`.
async fn fresh_head(peer: &ManagedPeer) -> Result<([u8; 32], u64), String> {
    let head_hash = peer.peer_status.best_hash;
    let headers = peer.get_block_headers_by_hash(&head_hash, 1).await?;
    let head = headers.into_iter().next().ok_or("peer returned no head header")?;
    // `head.hash` is OUR keccak of the returned header RLP, so this confirms the
    // peer actually returned the block we asked for (by hash) — a buggy/hostile
    // peer returning a different header is caught here with a clear error rather
    // than surfacing as a confusing header-chain failure downstream. (The state
    // root is anchored to the beacon chain regardless, so this is robustness,
    // not the trust gate.)
    if head.hash != head_hash {
        return Err("peer returned a header not matching the requested hash".to_string());
    }
    // A peer advertising a genesis head (block 0) can't serve current state —
    // vitalik.eth would verify as ABSENT at the genesis root, and the ladder
    // rejects it as noPeerBlockNumber. Treat it as a failure so the retry loop
    // moves to a peer with a real head (junk/light-client nodes can negotiate
    // snap/1 yet still advertise genesis).
    if head.header.number == 0 {
        return Err("peer advertises a genesis head (block 0 — no current state)".to_string());
    }
    let state_root = head.header.state_root;
    if state_root == [0u8; 32] {
        return Err("peer head has no state root".to_string());
    }
    Ok((state_root, head.header.number))
}

/// Copy a verdict's tokens onto a storage result.
fn apply_verdict(result: &mut VerifiedStorage, verdict: &crate::el::verify::Verdict) {
    result.beacon_chain_verified = verdict.beacon_chain_verified;
    result.bls_verified = verdict.bls_verified;
    result.matched_beacon_slot = matched_slot(verdict);
    result.verify_method = verdict.verify_method;
    result.fail_reason = verdict.fail_reason;
}

/// The matched beacon slot for a result, using the Java `-1`-when-none
/// convention (the `Verdict` default is a bare `0`, which would read as slot 0).
fn matched_slot(verdict: &crate::el::verify::Verdict) -> i64 {
    if verdict.beacon_chain_verified {
        verdict.matched_slot
    } else {
        -1
    }
}

/// The 32-byte storage key: plain `uint256(slot)`, or the ERC-20 mapping key
/// `keccak256(abi.encode(holder, uint256(slot)))` when `holder` is set.
fn storage_key(slot: u64, holder: Option<[u8; 20]>) -> [u8; 32] {
    match holder {
        None => {
            let mut key = [0u8; 32];
            key[24..32].copy_from_slice(&slot.to_be_bytes());
            key
        }
        Some(holder) => {
            let mut encoded = [0u8; 64];
            encoded[12..32].copy_from_slice(&holder); // left-pad holder to 32 bytes
            encoded[56..64].copy_from_slice(&slot.to_be_bytes());
            keccak256(&encoded)
        }
    }
}

/// Generate a valid secp256k1 node key from OS entropy. Returns `Err` rather
/// than panicking (the engine host is panic-free by construction); retries the
/// negligibly-rare out-of-range secret.
pub fn generate_node_key() -> Result<Arc<NodeKey>, String> {
    for _ in 0..8 {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|e| format!("OS entropy: {e}"))?;
        if let Ok(key) = NodeKey::from_secret_bytes(&secret) {
            return Ok(Arc::new(key));
        }
    }
    Err("could not generate a valid node key from OS entropy".to_string())
}

/// Decode a fixed 64-char hex CONSTANT. Panics on a malformed literal (a
/// programming error caught immediately in dev/tests — never runs on peer data),
/// matching the `sync.rs` convention; it does NOT silently zero-pad bad input.
fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid 64-char hex constant");
    }
    out
}

/// Whether a ladder `fail_reason` is GLOBAL — determined by the beacon anchor's
/// state, identical for every peer — vs PER-PEER (a stale/behind head, an
/// invalid proof: another peer can still verify). A global failure short-circuits
/// the cross-peer retry (no point re-asking); a per-peer failure moves on.
fn is_global_fail(reason: Option<&'static str>) -> bool {
    matches!(reason, Some("beaconNotSynced") | Some("beaconBlockUnavailable"))
}

/// Convert a peer-reported block number to the `i64` the verify ladder takes.
/// A realistic block number always fits; an out-of-range value (a hostile peer
/// claiming >= 2^63) maps to a negative sentinel, which the ladder rejects as
/// `noPeerBlockNumber` — fail-closed and explicit, no wrapping cast.
fn to_ladder_block(block_number: u64) -> i64 {
    i64::try_from(block_number).unwrap_or(-1)
}

/// A header's `base_fee_per_gas` (minimal big-endian scalar) as `u128`; 0 when
/// absent (pre-London — not mainnet today) or implausibly wide (> 16 bytes).
fn header_base_fee(h: &BlockHeader) -> u128 {
    match &h.base_fee_per_gas {
        Some(b) if b.len() <= 16 => b.iter().fold(0u128, |acc, &x| (acc << 8) | x as u128),
        _ => 0,
    }
}

/// The EIP-1559 next-block base fee from `h` (mirrors the Java
/// `VerifiedRpcBackend.nextBaseFee`): ±1/8 of the parent base fee scaled by how far
/// gasUsed is from the gasTarget (gasLimit/2), with the +1 minimum-bump rule.
fn next_base_fee(h: &BlockHeader) -> u128 {
    next_base_fee_calc(header_base_fee(h), h.gas_limit, h.gas_used)
}

/// Pure EIP-1559 next-base-fee arithmetic (extracted from `next_base_fee` for unit
/// testing). `base == 0` (pre-London) → 0.
fn next_base_fee_calc(base: u128, gas_limit: u64, gas_used: u64) -> u128 {
    if base == 0 {
        return 0;
    }
    let gas_target = gas_limit / 2;
    if gas_target == 0 || gas_used == gas_target {
        return base;
    }
    let target = gas_target as u128;
    if gas_used > gas_target {
        let delta = (base.saturating_mul((gas_used - gas_target) as u128) / target / 8).max(1);
        base.saturating_add(delta)
    } else {
        let delta = base.saturating_mul((gas_target - gas_used) as u128) / target / 8;
        base.saturating_sub(delta)
    }
}

/// Dispatch one [`EnsQuery`] to its `myotis_evm::ens` resolver function,
/// folding each typed answer into [`EnsRecordValue`]. Runs on a blocking
/// thread (every step's oracle fetch bridges via `block_on`).
fn run_ens_query(
    caller: &dyn myotis_evm::EthCaller,
    query: &EnsQuery,
) -> Result<Option<EnsRecordValue>, EnsError> {
    Ok(match query {
        EnsQuery::Addr { name } => {
            myotis_evm::resolve_address(caller, name)?.map(EnsRecordValue::Address)
        }
        EnsQuery::Text { name, key } => {
            myotis_evm::resolve_text(caller, name, key)?.map(EnsRecordValue::Text)
        }
        EnsQuery::Contenthash { name } => {
            myotis_evm::resolve_contenthash(caller, name)?.map(EnsRecordValue::Bytes)
        }
        EnsQuery::Multicoin { name, coin_type } => {
            myotis_evm::resolve_multicoin(caller, name, *coin_type)?.map(EnsRecordValue::Bytes)
        }
        EnsQuery::Pubkey { name } => myotis_evm::resolve_pubkey(caller, name)?
            .map(|(x, y)| EnsRecordValue::Pubkey { x, y }),
        EnsQuery::Abi { name, content_types } => {
            myotis_evm::resolve_abi(caller, name, *content_types)?
                .map(|(content_type, data)| EnsRecordValue::Abi { content_type, data })
        }
        EnsQuery::DnsRecord { name, dns_name, resource } => {
            myotis_evm::resolve_dns_record(caller, name, dns_name, *resource)?
                .map(EnsRecordValue::Bytes)
        }
        EnsQuery::Interface { name, interface_id } => {
            myotis_evm::resolve_interface_implementer(caller, name, *interface_id)?
                .map(EnsRecordValue::Address)
        }
        EnsQuery::Reverse { address } => {
            myotis_evm::reverse_resolve(caller, *address)?.map(EnsRecordValue::Name)
        }
    })
}

/// Decode a CCIP callback's raw answer with the ORIGINAL query's record
/// semantics (single source: the myotis-evm `decode_*_answer` helpers). A
/// `Reverse` claimed name is forward-verified here, exactly like the direct
/// path (the forward walk may itself surface `OffchainLookup` — propagated).
fn decode_ccip_answer(
    caller: &dyn myotis_evm::EthCaller,
    query: &EnsQuery,
    raw: &[u8],
) -> Result<Option<EnsRecordValue>, EnsError> {
    Ok(match query {
        EnsQuery::Addr { .. } | EnsQuery::Interface { .. } => {
            myotis_evm::decode_address_answer(raw).map(EnsRecordValue::Address)
        }
        EnsQuery::Text { .. } => myotis_evm::decode_text_answer(raw).map(EnsRecordValue::Text),
        EnsQuery::Contenthash { .. } | EnsQuery::Multicoin { .. } | EnsQuery::DnsRecord { .. } => {
            myotis_evm::decode_bytes_answer(raw).map(EnsRecordValue::Bytes)
        }
        EnsQuery::Pubkey { .. } => {
            myotis_evm::decode_pubkey_answer(raw).map(|(x, y)| EnsRecordValue::Pubkey { x, y })
        }
        EnsQuery::Abi { .. } => myotis_evm::decode_abi_answer(raw)
            .map(|(content_type, data)| EnsRecordValue::Abi { content_type, data }),
        EnsQuery::Reverse { address } => match myotis_evm::decode_name_answer(raw) {
            None => None,
            // Same hardening as the direct reverse path: a MALFORMED claimed
            // name (adversarial gateway data) is a failed verify, never an
            // error a malicious resolver can force.
            Some(claimed) => match myotis_evm::resolve_address(caller, &claimed) {
                Ok(Some(fwd)) if fwd == *address => Some(EnsRecordValue::Name(claimed)),
                Ok(_) | Err(EnsError::InvalidName(_)) => None,
                Err(e) => return Err(e),
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedCaller(Vec<([u8; 20], Vec<u8>)>);
    impl myotis_evm::EthCaller for ScriptedCaller {
        fn eth_call(
            &self,
            target: [u8; 20],
            calldata: &[u8],
        ) -> Result<Vec<u8>, myotis_evm::EvmError> {
            for (t, out) in &self.0 {
                if *t == target {
                    let _ = calldata;
                    return Ok(out.clone());
                }
            }
            Ok(vec![0u8; 32])
        }
    }

    fn addr_word(a: [u8; 20]) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    }

    #[test]
    fn ccip_answer_decodes_per_query_kind() {
        // Addr answers decode as addresses — NOT pubkey/bytes (the queryMethod
        // mis-map regression class).
        let caller = ScriptedCaller(Vec::new());
        let addr = decode_ccip_answer(
            &caller,
            &EnsQuery::Addr { name: "a.eth".into() },
            &addr_word([0xd8; 20]),
        )
        .unwrap();
        assert_eq!(addr, Some(EnsRecordValue::Address([0xd8; 20])));
        // The same 32-byte answer under a pubkey query is None (needs 64) —
        // proving the kinds are NOT interchangeable.
        let pk = decode_ccip_answer(
            &caller,
            &EnsQuery::Pubkey { name: "a.eth".into() },
            &addr_word([0xd8; 20]),
        )
        .unwrap();
        assert_eq!(pk, None);
    }

    #[test]
    fn ccip_reverse_malformed_claimed_name_is_none_not_error() {
        // A gateway-supplied claimed name with an interior empty label must be
        // a failed forward-verify (None), never an InvalidName error.
        let mut claimed = vec![0u8; 32];
        claimed[31] = 0x20;
        let name = b"a..eth";
        let mut len = vec![0u8; 32];
        len[31] = name.len() as u8;
        claimed.extend_from_slice(&len);
        claimed.extend_from_slice(name);
        claimed.extend_from_slice(&[0u8; 26]);
        let caller = ScriptedCaller(Vec::new());
        let out = decode_ccip_answer(
            &caller,
            &EnsQuery::Reverse { address: [0xd8; 20] },
            &claimed,
        )
        .unwrap();
        assert_eq!(out, None);
    }

    #[test]
    fn next_base_fee_at_target_is_unchanged() {
        // gasUsed == gasTarget (gasLimit/2) → base fee holds.
        assert_eq!(next_base_fee_calc(1_000_000_000, 30_000_000, 15_000_000), 1_000_000_000);
    }

    #[test]
    fn next_base_fee_full_block_rises_one_eighth() {
        // gasUsed == gasLimit (2× target) → +1/8: delta = base*target/target/8 = base/8.
        assert_eq!(
            next_base_fee_calc(1_000_000_000, 30_000_000, 30_000_000),
            1_000_000_000 + 125_000_000
        );
    }

    #[test]
    fn next_base_fee_empty_block_falls_one_eighth() {
        // gasUsed == 0 → -1/8: delta = base*target/target/8 = base/8.
        assert_eq!(
            next_base_fee_calc(1_000_000_000, 30_000_000, 0),
            1_000_000_000 - 125_000_000
        );
    }

    #[test]
    fn next_base_fee_min_bump_is_one_wei() {
        // Barely over target with a tiny base: the up-delta rounds to 0 but is
        // floored to +1 wei (the EIP-1559 minimum bump); the down side has no floor.
        assert_eq!(next_base_fee_calc(1, 30_000_000, 15_000_001), 2);
        assert_eq!(next_base_fee_calc(1, 30_000_000, 14_999_999), 1);
    }

    #[test]
    fn next_base_fee_pre_london_is_zero() {
        assert_eq!(next_base_fee_calc(0, 30_000_000, 15_000_000), 0);
    }

    #[test]
    fn plain_storage_key_is_padded_slot() {
        assert_eq!(storage_key(1, None)[31], 1);
        assert_eq!(storage_key(1, None)[..31], [0u8; 31]);
        // 0x0102 at the low end, big-endian.
        assert_eq!(storage_key(0x0102, None)[30..32], [0x01, 0x02]);
    }

    #[test]
    fn erc20_mapping_key_matches_solidity_layout() {
        // keccak256(pad32(holder) ‖ uint256(slot)) — check the pre-image layout.
        let holder = [0xABu8; 20];
        let key = storage_key(5, Some(holder));
        // Recompute the expected pre-image independently.
        let mut pre = [0u8; 64];
        pre[12..32].copy_from_slice(&holder);
        pre[63] = 5;
        assert_eq!(key, keccak256(&pre));
        // Differs from the plain-slot key.
        assert_ne!(key, storage_key(5, None));
    }

    #[test]
    fn mainnet_config_pins_known_values() {
        let c = ElConfig::mainnet();
        assert_eq!(c.network_id, 1);
        assert_eq!(c.fork_id_hash, [0x07, 0xc9, 0x46, 0x2e]);
        assert_eq!(
            c.genesis_hash,
            hex32("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
        );
        assert_eq!(c.bootnodes.len(), 4, "all four mainnet bootnodes must parse");
    }

    #[test]
    fn sepolia_config_pins_known_values() {
        let cfg = ElConfig::sepolia();
        assert_eq!(cfg.network_id, 11_155_111);
        assert_eq!(
            cfg.genesis_hash,
            super::hex32("25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9")
        );
        assert_eq!(cfg.fork_id_hash, [0x26, 0x89, 0x56, 0xb6]);
        assert_eq!(cfg.fork_next, 0);
        assert_eq!(cfg.bootnodes.len(), 5, "all five sepolia bootnodes must parse");
        assert_eq!(cfg.listen_port, 30305);
        assert_eq!(cfg.min_suggested_tip_wei, 100_000_000);
    }

    #[test]
    fn gnosis_config_pins_known_values() {
        let cfg = ElConfig::gnosis();
        assert_eq!(cfg.network_id, 100);
        assert_eq!(
            cfg.genesis_hash,
            super::hex32("4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756")
        );
        assert_eq!(cfg.fork_id_hash, [0xcf, 0xca, 0x38, 0x7c]);
        assert_eq!(cfg.fork_next, 0);
        assert_eq!(cfg.bootnodes.len(), 6, "all six gnosis bootnodes must parse");
        assert_eq!(cfg.listen_port, 30304);
        assert_eq!(cfg.min_suggested_tip_wei, 1_000_000, "gnosis cheap-chain tip floor");
    }
}
