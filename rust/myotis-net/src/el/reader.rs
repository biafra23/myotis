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
    /// Path to the eth_getLogs watch-list index (`dataDir/logindex[-net].db`);
    /// `None` keeps the index memory-only (docs/eth-getlogs-design.md).
    pub log_index_path: Option<std::path::PathBuf>,
    /// Network floor for the suggested priority fee (wei) — the Java
    /// `NetworkConfig.minSuggestedTipWei` (mainnet/sepolia 0.1 gwei; gnosis 0.001).
    pub min_suggested_tip_wei: u128,
    /// Pinned EL peers to direct-dial, as `(address, 64-byte secp256k1 pubkey)`.
    /// Twin of the Java `NetworkConfig.elBootEnodes()`. Unlike `bootnodes`
    /// (discv4 UDP endpoints, no key) these carry the pubkey the ECIES
    /// handshake needs, so they are dialed over RLPx directly instead of
    /// waiting for discovery to surface them.
    pub boot_enodes: Vec<(std::net::SocketAddr, [u8; 64])>,
}

/// The dedicated myotis-serving sepolia node (docs/dedicated-sepolia-node.md).
/// Key stable (persisted nodekey); the IP is residential, so a rotation makes
/// this entry stale and discovery carries the load until it is refreshed.
const SEPOLIA_MYOTIS_ENODE: &str =
    "enode://cfd3572bd7691fe03baf52106b873e01d9b5dca1714a74b316cb94151127dfd20adae3be559e3e6b44b78a5af1ed6f92ecc8676a2555fc7cdb2d29a0c37e1b2c@87.154.209.161:30405";

/// Parse `enode://<128 hex pubkey>@host:port` entries into dialable
/// `(addr, pubkey)` pairs, skipping anything malformed — a bad pin must not
/// panic a wallet at startup, it just leaves discovery to do the work. Twin of
/// the Java `ChainStack.parseBootEnodes`.
fn parse_boot_enodes(enodes: &[&str]) -> Vec<(std::net::SocketAddr, [u8; 64])> {
    let mut out = Vec::new();
    for e in enodes {
        let Some(body) = e.strip_prefix("enode://") else { continue };
        let Some((pubkey_hex, host_port)) = body.split_once('@') else { continue };
        // is_ascii() is load-bearing, not belt-and-braces: len() counts BYTES,
        // so 64 multi-byte chars (e.g. "é" × 64 = 128 bytes) pass the length
        // check and then panic in the slicing below at a non-char boundary —
        // an abort, since the workspace builds panic = "abort". This parser
        // exists to be lenient with untrusted-ish input, so it must not.
        if pubkey_hex.len() != 128 || !pubkey_hex.is_ascii() {
            continue;
        }
        let Ok(bytes) = (0..64)
            .map(|i| u8::from_str_radix(&pubkey_hex[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
        else {
            continue;
        };
        let Ok(addr) = host_port.parse::<std::net::SocketAddr>() else { continue };
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&bytes);
        out.push((addr, pubkey));
    }
    out
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
            log_index_path: None,
            min_suggested_tip_wei: 100_000_000, // 0.1 gwei
            boot_enodes: Vec::new(),
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
            log_index_path: None,
            min_suggested_tip_wei: 100_000_000, // 0.1 gwei
            // The dedicated myotis-serving node (docs/dedicated-sepolia-node.md):
            // it admits wallets past its peer cap by RLPx Hello client-id, so
            // direct-dialing it beats waiting for discovery on a saturated
            // testnet. Mirrors the Java `NetworkConfig.SEPOLIA_EL_ENODES`.
            boot_enodes: parse_boot_enodes(&[SEPOLIA_MYOTIS_ENODE]),
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
            log_index_path: None,
            min_suggested_tip_wei: 1_000_000, // 0.001 gwei — cheap-chain floor
            boot_enodes: Vec::new(),
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
    /// The fully decoded transactions (the `fullTransactions=true` form), in
    /// block order; `None` when the caller asked for hashes only. Populated
    /// only from the `transactionsRoot`-verified body — an undecodable tx
    /// fails the serve rather than degrade to a hash.
    pub full_transactions: Option<Vec<VerifiedTransaction>>,
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

/// A verified `eth_getTransactionByHash` result: the located tx's block
/// coordinates plus the fully decoded tx fields. As with [`VerifiedReceipt`],
/// the location was proven by the `transactionsRoot`-verified body inside a
/// beacon-anchored header window — returning it IS the verification.
#[derive(Debug, Clone)]
pub struct VerifiedTransaction {
    pub tx_hash: [u8; 32],
    pub tx_index: u64,
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub tx: TxSummary,
}

/// Entry cap for the verified block-hash → number map (the Java
/// `blockHashToNumber` cache's 512).
const BLOCK_HASH_LRU_MAX: usize = 512;

/// Raw-bytes cache cap for the wallet's own broadcast txs (the Java
/// `sentTxCache` LRU's 256). Bytes aging out silently end that tx's
/// rebroadcast (still watched, nothing left to push).
const SENT_TX_CACHE_MAX: usize = 256;

/// Minimum spacing between rebroadcast sweeps (the Java
/// `TX_REBROADCAST_INTERVAL_MS`). Java runs it on a warmer thread; here it
/// piggybacks time-gated on the wallet's poll paths (receipt/tx/nonce reads),
/// the same pattern as the scan-map TTL sweep — a wallet mid-confirm-loop
/// polls every few seconds, far below this gate. DIVERGENCE (documented): with
/// zero RPC traffic nothing rebroadcasts; Java's timer does. Acceptable — a
/// wallet that stopped polling has abandoned the confirm flow, and peers
/// dedupe repeats anyway.
const TX_REBROADCAST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// How far behind the finalized head the log-index append edge may fall before
/// the head BRIDGE takes over from the per-block appender. The per-block path
/// anchors a window from each target block to the optimistic head, so it stays
/// well inside that lookback cap; anything deeper is a bridge walk.
const APPEND_WINDOW: u64 = 128;

/// The sent-tx state behind one lock (see the `sent_txs` field doc). The
/// WATCH itself lives separately in the shared Arc every peer read loop also
/// holds (gossip sightings) — see `ElReader::sent_tx_watch`.
struct SentTxState {
    pending_nonces: crate::el::sent_tx::PendingNonceTracker,
    /// Raw broadcast bytes by tx hash — what a rebroadcast re-pushes.
    bytes: myotis_evm::Lru<[u8; 32], Vec<u8>>,
    last_rebroadcast: std::time::Instant,
}

/// An in-progress head-gap bridge: the plan that carries log-index coverage
/// from its stale append edge up to a finalized anchor after downtime (see
/// [`ElReader::log_index_bridge_step`]).
///
/// Two phases, both resumable across ticks:
/// 1. DESCEND from the finalized anchor collecting `(number, hash, candidate)`
///    for every block down to the edge. Trust flows downward only — a header
///    is trusted because the block above it names its hash as parent — so the
///    gap can only be learned top-down. Blooms are evaluated during the
///    descent and discarded (one bool per block, not 256 bytes).
/// 2. ASCEND from the edge applying blocks in order: coverage extends upward
///    contiguously, so the bottom block must land first. Non-candidates apply
///    with no network at all; candidates re-fetch their header by (trusted)
///    hash plus body and receipts, verified against both roots exactly like
///    the backfill walk.
///
/// The anchor is the FINALIZED block, so nothing collected here can reorg.
struct BridgePlan {
    /// The finalized block this plan descends from, and the coverage edge it
    /// must reach. Both fixed for the plan's lifetime — a moved finalized head
    /// or edge (an append landing, a config change) discards and rebuilds it.
    anchor_n: u64,
    anchor_hash: [u8; 32],
    target: u64,
    /// Lowest block the descent has reached so far (`anchor_n` + 1 hash when
    /// the descent hasn't started), the resume point for the next slice.
    low_n: u64,
    low_hash: [u8; 32],
    /// Collected blocks in DESCENDING order (`blocks[0]` is the anchor).
    /// `candidate` is the header-bloom verdict: false is a definitive skip.
    blocks: Vec<(u64, [u8; 32], bool)>,
    /// The watch-list this plan's bloom verdicts were computed against. A
    /// `candidate=false` is a DEFINITIVE skip for that list only, so applying
    /// the plan to a replaced index would claim coverage for blocks whose
    /// new-address logs were never fetched. Re-checked under the index lock
    /// before every apply — `clear_log_index_bridge` cannot help here, since
    /// the tick holds the plan outside the slot across its network I/O.
    fingerprint: u64,
    /// Set once the descent has reached `target`; the ascent runs after.
    descended: bool,
    /// Next index to apply during the ascent, counted from the END of
    /// `blocks` (the bottom block) upward.
    applied: usize,
}

/// `eth_getTransactionByHash`'s three verified answers (the Java engine's
/// mined / own-pending / null trichotomy).
pub enum TxLookup {
    /// Located in a verified block.
    Mined(VerifiedTransaction),
    /// Not in the scanned chain, but it is OUR broadcast (the sent-tx cache
    /// holds the bytes): the pending shape — block fields explicitly null.
    Pending { tx_hash: [u8; 32], tx: TxSummary },
    /// Verified "not seen" (eth's null; the wallet keeps polling).
    NotSeen,
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
    /// `Arc` so a poll hands the cached location out by pointer bump — the
    /// header + raw-tx bytes aren't re-copied on every wallet confirm poll.
    found: Option<Arc<TxLocation>>,
    last_touched: std::time::Instant,
}

/// Recent blocks sampled for the `eth_maxPriorityFeePerGas` tip suggestion
/// (mirrors the Java `TIP_SUGGEST_BLOCKS`).
const TIP_SUGGEST_BLOCKS: u64 = 3;

/// Tor read fan-out bounds (docs/privacy-and-tor.md): how many clearnet-validated
/// snap peers a single Tor-routed read may try, and the wall-clock ceiling on the
/// whole read. Kept small because each Tor dial is slow and many peers reject
/// Tor-exit inbound — without these a bad-exit walk could hang the FFI call for
/// minutes. Fail-closed when the deadline is hit.
#[cfg(feature = "tor")]
const TOR_MAX_CANDIDATES: usize = 5;
#[cfg(feature = "tor")]
const TOR_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// `eth_feeHistory` block-count clamp (the Java `FEE_HISTORY_MAX_BLOCKS`) —
/// each block with reward percentiles costs a verified body + receipts fetch.
const FEE_HISTORY_MAX_BLOCKS: u64 = 10;

/// Per-peer deadline for one `eth_feeHistory` build (header window + the
/// pipelined per-block body/receipt fetches) — the Java stage timeout.
const FEE_HISTORY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// Why [`ElReader::fee_history`] failed — the split the Java `rpcFeeHistory`
/// expresses with `return null` vs `serveStaleFeeHistory(...)`: a `Reject` is a
/// bad request against the current head (answered -32000, NEVER from a stale
/// snapshot), a `Build` is a transport/verify failure the host may answer from
/// its last-good same-signature result.
#[derive(Debug, Clone)]
pub enum FeeHistoryError {
    Reject(String),
    Build(String),
}

impl FeeHistoryError {
    /// The user-facing message, whichever side it is.
    pub fn message(&self) -> &str {
        match self {
            FeeHistoryError::Reject(m) | FeeHistoryError::Build(m) => m,
        }
    }
}

/// Why a single-peer block serve ([`ElReader::get_block_from`]) failed: a
/// `Peer` failure (transport / root mismatch / short window) is that peer's
/// fault — the caller loop counts it against the peer and tries the next one;
/// `Undecodable` means the body VERIFIED against the header's
/// `transactionsRoot` but a tx inside it can't be decoded (an unknown future
/// tx type) — deterministic for every peer, so the loop must stop without
/// blaming peers that served correct bytes.
enum BlockFromError {
    Peer(String),
    Undecodable(String),
}

/// A verified `eth_feeHistory` result (the Java `rpcFeeHistory` twin). Every
/// value comes from the beacon-anchored header window; rewards additionally
/// from bodies verified against `transactionsRoot` and receipts against
/// `receiptsRoot` (gas-used-weighted percentile walk, geth's algorithm).
#[derive(Debug, Clone)]
pub struct FeeHistory {
    pub oldest_block: u64,
    /// `count + 1` entries: the requested blocks' base fees plus the NEXT
    /// block's — its actual base fee when the anchored window extends past
    /// `newest`, else the EIP-1559 prediction from `newest`.
    pub base_fee_per_gas: Vec<u128>,
    /// `count` entries: `gasUsed / gasLimit` (0.0 for a zero gasLimit).
    pub gas_used_ratio: Vec<f64>,
    /// `count` rows of one effective tip per requested percentile; `None` when
    /// no percentiles were requested (the `reward` key is then omitted).
    pub reward: Option<Vec<Vec<u128>>>,
}

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
    /// Our eth handshake parameters — reused by the Tor read path
    /// (`docs/privacy-and-tor.md`) to dial a per-address isolated circuit with a
    /// fresh ephemeral identity, independent of the pool's clearnet connections.
    /// Only read on the `tor` feature; kept unconditionally so the struct shape
    /// doesn't depend on the feature.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    eth_cfg: Arc<EthConfig>,
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
    /// Recently-VERIFIED block hash → number, so `eth_getBlockByHash` (which
    /// wallets call right after a receipt to finalize a tx) resolves to the
    /// verified by-number path (the Java `blockHashToNumber` twin). Populated
    /// ONLY by blocks this reader itself verified (the receipt/tx scan and the
    /// by-number serve); the shared LRU is the myotis-evm cache one.
    block_hash_numbers: std::sync::Mutex<myotis_evm::Lru<[u8; 32], u64>>,
    /// The sent-tx watch + pending-nonce overlay + raw-bytes cache (the Java
    /// `sentTxWatch`/`pendingNonces`/`sentTxCache` trio). One brief-hold lock:
    /// every access is a map poke; the rebroadcast collects its work under the
    /// lock and BROADCASTS outside it.
    sent_txs: std::sync::Mutex<SentTxState>,
    /// The sent-tx WATCH, shared with every peer's read loop (which marks
    /// gossip sightings) — the Java TxGossipObserver seam's equivalent.
    sent_tx_watch: crate::el::sent_tx::SharedSentTxWatch,
    /// The opt-in eth_getLogs watch-list index (docs/eth-getlogs-design.md).
    /// `None` until the host supplies a config. Brief-hold lock: appends and
    /// queries are in-memory work; persistence happens on checkpoints and
    /// stop, never under a network await.
    log_index: std::sync::Mutex<Option<crate::el::logindex::LogIndex>>,
    /// Last backfill checkpoint write — throttles the full-index persist
    /// (see the step's PERSIST_MIN_INTERVAL).
    log_index_last_persist: std::sync::Mutex<Option<std::time::Instant>>,
    /// Adaptive chunk-pipeline depth signal: true after an untruncated batch
    /// (pipelining pays), false after a budget-truncated one (prefetch would
    /// waste the serving link). See log_index_backfill_batch.
    log_index_pipeline_full: std::sync::atomic::AtomicBool,
    /// Rolling backfill throughput — see [`Self::log_index_rate_bps`]. The
    /// sample anchor is (instant, cursor) at the last PROGRESS observation, so
    /// the rate is measured against WALL CLOCK between progress points (idle
    /// tick tails count; a busy-time denominator overstated nice-mode rates
    /// ~6x). Reset on any config (re)apply and on cursor regression.
    log_index_rate: std::sync::Mutex<Option<(std::time::Instant, u64, f64)>>,
    /// In-progress head-gap bridge (see [`Self::log_index_bridge_step`]).
    /// `None` whenever the coverage edge is within the appender's reach.
    log_index_bridge: std::sync::Mutex<Option<BridgePlan>>,
    /// `(number, hash)` for every block THIS RUN appended above finality,
    /// ascending — the tail's own record of what it claimed, which is what
    /// makes a reorg detectable (compare against the canonical chain) and a
    /// tail inherited from a previous run identifiable (this list is empty,
    /// so those blocks' hashes are unknown and coverage above finality must
    /// be rewound rather than trusted). See [`Self::log_index_tail_tick`].
    log_index_tail: std::sync::Mutex<Vec<(u64, [u8; 32])>>,
    log_index_path: Option<std::path::PathBuf>,
    /// The head-follow appender task (spawned on enable, aborted on stop).
    log_index_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Serializes coverage-advancing ticks. The background appender and an
    /// on-demand fill ([`Self::advance_log_index_tail_now`]) both mutate
    /// coverage and the tail's `(number, hash)` reorg record; running them
    /// concurrently would race that bookkeeping. Async mutex: held across the
    /// tick's network awaits.
    log_index_drive: tokio::sync::Mutex<()>,
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
            // Seed the serve window's genesis where the embedded RLP matches this
            // network's genesis hash (mainnet today; the helper self-verifies via
            // keccak, so a non-mainnet config simply gets None).
            genesis_header_rlp: crate::el::served::mainnet_genesis()
                .filter(|(h, _)| *h == cfg.genesis_hash)
                .map(|(_, rlp)| rlp),
        });
        // Load the EL peer cache for warm-start (disabled if no path). The
        // network's pinned boot enodes are NOT seeded here — they go to the pool
        // directly, so they survive a disabled cache and never overwrite a snap
        // flag the peer earned in an earlier run (see PeerPool's warm start).
        let cache = match &cfg.cache_path {
            Some(path) => crate::el::peercache::ElPeerCache::load(path.clone()),
            None => crate::el::peercache::ElPeerCache::disabled(),
        };
        let local_pubkey = key.public_key_bytes();
        let sent_tx_watch: crate::el::sent_tx::SharedSentTxWatch = Arc::new(
            std::sync::Mutex::new(crate::el::sent_tx::SentTxTracker::new()),
        );
        let pool = PeerPool::start(
            key,
            local_pubkey,
            Arc::clone(&eth_cfg),
            cfg.pool_config,
            cache,
            cfg.boot_enodes.clone(),
            rx,
            Some(Arc::clone(&sent_tx_watch)),
            Some(discovery.probe_sender()),
            // Header-backfill head source: the beacon-anchored optimistic head —
            // number AND hash, because every backfill batch must hash-chain to it.
            Some(Box::new({
                let anchor = Arc::clone(&anchor);
                move || {
                    let n = anchor.optimistic_block_number();
                    anchor.optimistic_block_hash().filter(|_| n > 0).map(|h| (n, h))
                }
            })),
        );
        Ok(ElReader {
            discovery,
            pool,
            anchor,
            eth_cfg,
            min_suggested_tip_wei: cfg.min_suggested_tip_wei,
            evm_proof_cache: Arc::new(InMemoryStateProofCache::new(EVM_PROOF_CACHE_ENTRIES)),
            evm_bytecode_cache: Arc::new(InMemoryBytecodeCache::new()),
            tx_scans: std::sync::Mutex::new(TxScanMap {
                map: std::collections::HashMap::new(),
                last_sweep: std::time::Instant::now(),
            }),
            block_hash_numbers: std::sync::Mutex::new(myotis_evm::Lru::new(BLOCK_HASH_LRU_MAX)),
            sent_txs: std::sync::Mutex::new(SentTxState {
                pending_nonces: crate::el::sent_tx::PendingNonceTracker::new(),
                bytes: myotis_evm::Lru::new(SENT_TX_CACHE_MAX),
                last_rebroadcast: std::time::Instant::now(),
            }),
            sent_tx_watch,
            log_index: std::sync::Mutex::new(None),
            log_index_rate: std::sync::Mutex::new(None),
            log_index_bridge: std::sync::Mutex::new(None),
            log_index_tail: std::sync::Mutex::new(Vec::new()),
            log_index_last_persist: std::sync::Mutex::new(None),
            log_index_pipeline_full: std::sync::atomic::AtomicBool::new(true),
            log_index_path: cfg.log_index_path,
            log_index_task: std::sync::Mutex::new(None),
            log_index_drive: tokio::sync::Mutex::new(()),
        })
    }

    /// Install (or replace) the eth_getLogs watch-list config: reload the
    /// persisted index when it matches the config's fingerprint, else start
    /// empty (re-index). See docs/eth-getlogs-design.md.
    /// Returns false (and installs nothing) for an invalid config
    /// (duplicate watch addresses). Re-applying a config whose watch-list
    /// fingerprint matches the installed one only updates the enabled bit —
    /// in-memory progress survives settings pokes; a genuinely changed
    /// watch-list checkpoints the old index before replacing it.
    pub fn set_log_index_config(&self, config: crate::el::logindex::LogIndexConfig) -> bool {
        let finalized_now = self.finalized_block_number();
        // A SUCCESSFUL config apply invalidates the rate anchor: a pacing
        // flip changes the true rate (stale EMA → bogus ETA for minutes) and
        // a watch-list change starts a new walk. Reset on the success paths
        // only — a rejected poke shouldn't blank a valid ETA.
        let reset_rate = || {
            if let Ok(mut rate) = self.log_index_rate.lock() {
                *rate = None;
            }
        };
        let Ok(mut slot) = self.log_index.lock() else {
            return false;
        };
        if let Some(ix) = slot.as_mut() {
            if ix.config().fingerprint() == config.fingerprint() {
                // Same watch-list: the index (and so the mapped gap and the
                // tail record) still describes this coverage. Toggling enable
                // or max-speed must not cost a full re-descent and a tail
                // rewind back to finality.
                ix.set_enabled(config.enabled);
                ix.set_max_speed(config.max_speed);
                reset_rate();
                return true;
            }
            // A different watch-list REPLACES the index below, which
            // invalidates both: neither describes the new coverage.
            self.clear_log_index_bridge();
            if let Ok(mut t) = self.log_index_tail.lock() {
                t.clear();
            }
            if let Some(p) = self.log_index_path.as_deref() {
                // Clamped like every other checkpoint: optimistic coverage is
                // only verifiable against this run's tail record. A zero
                // finality means no anchor (so nothing optimistic exists) —
                // clamping there would erase the file.
                let _ = if finalized_now == 0 {
                    ix.persist(p)
                } else {
                    ix.persist_clamped(p, finalized_now)
                };
            }
        }
        let loaded = self
            .log_index_path
            .as_deref()
            .and_then(|p| crate::el::logindex::LogIndex::load(&config, p));
        let ix = match loaded {
            Some(ix) => ix,
            None => match crate::el::logindex::LogIndex::new(config) {
                Ok(ix) => ix,
                Err(_) => return false,
            },
        };
        *slot = Some(ix);
        reset_rate();
        true
    }

    /// The beacon-anchored head block number, if the anchor is ready — the
    /// resolution target for `latest`-style tags in eth_getLogs filters.
    pub fn head_block_number(&self) -> Option<u64> {
        self.anchored_head().ok().map(|(n, _)| n)
    }

    /// Deterministically stop the appender: abort AND await the task, which
    /// guarantees its per-tick strong Arc has been dropped — hosts call this
    /// BEFORE Arc::try_unwrap so teardown never races a long catch-up tick.
    pub async fn stop_log_index_appender(&self) {
        let handle = match self.log_index_task.lock() {
            Ok(mut t) => t.take(),
            Err(_) => None,
        };
        if let Some(h) = handle {
            h.abort();
            let _ = h.await; // JoinError::Cancelled — the task's Arc is gone
        }
    }

    /// Spawn (or keep) the head-follow appender for this reader. Idempotent:
    /// a live task is left alone. `rt` makes the runtime-context invariant
    /// unforgeable (a bare tokio::spawn outside a runtime would abort the
    /// whole host process under panic="abort").
    pub fn ensure_log_index_appender(self: &Arc<Self>, rt: &tokio::runtime::Handle) {
        let Ok(mut slot) = self.log_index_task.lock() else {
            return;
        };
        if slot.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }
        // The task holds only a WEAK reference: a strong Arc here would keep
        // the reader's strong count above 1 forever, making the host's
        // Arc::try_unwrap → ElReader::stop teardown unreachable (leaked
        // networking on stop/pause). Each tick upgrades for its duration and
        // the task exits on its own once the reader is gone; the abort in
        // stop() is the fast path.
        let weak = Arc::downgrade(self);
        *slot = Some(rt.spawn(async move {
            // Coverage grows on three paths, in this order of preference:
            // the per-block appender (finalized, contiguous, cheap), the head
            // BRIDGE when a gap outgrows the appender's window, and the
            // optimistic TAIL above finality — which is where `latest` points
            // and so what head-reaching queries actually need. Only the tail
            // can reorg, and it carries the rewind machinery for that.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(6));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut since_persist = 0u32;
            let mut ticks = 0u64;
            let mut backfill_ok = 0u64;
            loop {
                tick.tick().await;
                let Some(reader) = weak.upgrade() else {
                    return; // reader torn down; the appender dies with it
                };
                {
                    // Serialize only the coverage-advancing tick against
                    // on-demand fills (advance_log_index_tail_now): both mutate
                    // coverage + the tail reorg record. The backfill step works
                    // the low-side cursor only (never the tail record), so it
                    // runs OUTSIDE the lock — holding it there would make an
                    // on-demand caller (a synchronous FFI thread) wait behind the
                    // backfill budget for nothing.
                    let _drive = reader.log_index_drive.lock().await;
                    reader.log_index_append_tick(&mut since_persist, ticks).await;
                }
                reader.log_index_backfill_step(ticks, &mut backfill_ok).await;
                ticks = ticks.wrapping_add(1);
            }
        }));
    }

    /// One appender tick: record finalized blocks from the append edge up to
    /// the finalized head (bounded batch per tick).
    async fn log_index_append_tick(&self, since_persist: &mut u32, ticks: u64) {
        // Checkpoint due from a PREVIOUS tick first: batches that end early
        // (peer failure mid-catch-up) must not defer persistence forever.
        if *since_persist >= 64 {
            self.persist_log_index(self.finalized_block_number());
            *since_persist = 0;
        }
        let enabled = self.with_log_index(|ix| ix.config().enabled).unwrap_or(false);
        if !enabled {
            self.clear_log_index_bridge(); // don't park a mapped gap while off
            self.retire_tail_record();
            return;
        }
        let finalized = self.finalized_block_number();
        if finalized == 0 {
            self.clear_log_index_bridge();
            self.retire_tail_record();
            return;
        }
        let edge = self.with_log_index(|ix| ix.append_edge()).flatten();
        let start = match edge {
            None => finalized, // fresh index: start at the finalized head
            Some(e) if e <= finalized => e,
            // Caught up to finality — now follow the OPTIMISTIC tail, which is
            // where `toBlock: "latest"` actually points.
            Some(_) => return self.log_index_tail_tick(finalized, ticks).await,
        };
        // The verified whole-block path anchors a window from the target to
        // the optimistic head; stay well inside its lookback cap. A deeper lag
        // (downtime, a suspended laptop, an imported index whose top predates
        // this run) is the BRIDGE's job — it closes the gap with the same
        // verified machinery the backfill walk uses, after which this per-block
        // path resumes. Without it the edge froze permanently: every later
        // append needs contiguity, so a single gap wider than the window meant
        // coverage never advanced again and every `toBlock: "latest"` query
        // stayed outside coverage forever.
        if finalized.saturating_sub(start) > APPEND_WINDOW {
            self.log_index_bridge_step(start, finalized, ticks).await;
            return;
        }
        self.clear_log_index_bridge();
        // Coverage is at/below finality here, so the tail tick (and its
        // vouched check) will not run: any entry left in the record describes
        // a block this run never proved canonical.
        self.retire_tail_record();
        let last = finalized.min(start.saturating_add(15));
        for n in start..=last {
            let (block_hash, receipts) = match self.block_receipts_at(Some(n)).await {
                Ok(Some(r)) => r,
                Ok(None) => return, // future/unknown under this anchor — retry next tick
                Err(e) => {
                    tracing::debug!(block = n, error = %e, "log index append: receipts unavailable");
                    return;
                }
            };
            // Strict conversion: any malformed field (wrong-length address or
            // topic, index overflow) aborts THIS block's append rather than
            // silently storing an altered shape under advancing coverage — a
            // dropped topic0 would shift the rest and change what
            // filter/watch matching sees for verified data.
            let Some(logs) = stored_logs_for_block(&receipts) else {
                tracing::warn!(block = n, "log index append: malformed log field in verified receipts; will retry");
                return;
            };
            let appended = match self.log_index.lock() {
                Ok(mut slot) => match slot.as_mut() {
                    Some(ix) => match ix.append_block(n, block_hash, logs) {
                        Ok(()) => true,
                        Err(gap) => {
                            // Transient (config replaced / rewind raced this
                            // tick) → retrying next tick is right; if it ever
                            // became persistent this warn is the telemetry.
                            tracing::warn!(block = n, edge = gap.edge, "log index append rejected (coverage gap); retrying");
                            false
                        }
                    },
                    None => false,
                },
                Err(_) => false,
            };
            if !appended {
                return;
            }
            *since_persist += 1;
        }
        // Checkpoint roughly every 64 appended blocks (best-effort).
        if *since_persist >= 64 {
            self.persist_log_index(self.finalized_block_number());
            *since_persist = 0;
        }
    }

    /// Drive ONE coverage-advancing tick on demand, serialized against the
    /// background appender.
    ///
    /// Purpose: close the 0-1 block gap between the anchored head — what
    /// `eth_blockNumber` reports, and what a wallet then passes as an explicit
    /// `toBlock` — and the log index's covered top, which the 6s appender tick
    /// leaves trailing for up to a tick. A head-reaching `eth_getLogs` would
    /// otherwise be refused for those few seconds even though the block is
    /// verified and about to be indexed. This runs the SAME verified machinery
    /// as the background tick (no new trust path); it just runs it now.
    /// `target`: the block the caller needs covered. Bounded by a hard deadline —
    /// this sits on a wallet-facing request path, and in degraded peer conditions
    /// an unbounded lock-wait + tick could turn a microsecond refusal into a
    /// minutes-long stall. On timeout the caller just re-queries and serves the
    /// original refusal; the wallet already handles retry.
    pub async fn advance_log_index_tail_now(&self, target: u64) {
        const FILL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
        let fill = async {
            let _drive = self.log_index_drive.lock().await;
            // Re-check under the lock: the background tick — or another caller's
            // fill that just finished — may already cover the target. Skipping
            // saves a full header-window fetch per queued caller.
            if self.log_index_covered_high().is_some_and(|top| top >= target) {
                return;
            }
            let mut since_persist = 0u32;
            self.log_index_append_tick(&mut since_persist, 0).await;
        };
        // Cancellation at an await point is safe: coverage and the tail record
        // mutate only synchronously under the index lock (append_block).
        let _ = tokio::time::timeout(FILL_DEADLINE, fill).await;
    }

    /// Follow the OPTIMISTIC tail: keep coverage running from finality up to
    /// the beacon-anchored head, which is where `latest` points and therefore
    /// what every head-reaching `eth_getLogs` needs. Runs once coverage has
    /// reached finality (the appender/bridge get there first).
    ///
    /// Finalized blocks can never reorg, but these can, so the tail keeps its
    /// own `(number, hash)` record of what it appended and re-checks it
    /// against the canonical chain every tick. The window therefore reaches
    /// DOWN THROUGH the recorded blocks (not just up from the coverage edge —
    /// comparing a window that starts at the edge against records that all sit
    /// below it compares disjoint ranges and can never detect anything), and a
    /// mismatch rewinds coverage and stored logs to the fork point before
    /// re-appending. A chain that has shortened below the edge is itself proof
    /// of a reorg and rewinds the same way.
    ///
    /// Coverage above finality that this run did NOT append — a persisted tail
    /// from an older build, or an imported index — has unknown hashes and
    /// cannot be re-checked, so it is rewound to finality rather than trusted.
    /// (Checkpoints clamp at finality, so a normal restart never inherits
    /// optimistic coverage in the first place.)
    ///
    /// Serving at the optimistic head matches the rest of the engine, where
    /// every verified read (`eth_call`, `getCode`, `getBalance`) answers under
    /// the same anchor.
    async fn log_index_tail_tick(&self, finalized: u64, ticks: u64) {
        /// Never chase more than this above finality: a stalled beacon anchor
        /// must not turn into an unbounded walk.
        const TAIL_MAX: u64 = 1024;
        /// Candidate blocks per body/receipts request, as the bridge uses —
        /// an unchunked burst of a full tail would blow every peer's response
        /// budget and make no progress at all.
        const CANDIDATE_CHUNK: usize = 64;
        /// Wall-clock budget, for the same reason the bridge has one: after a
        /// rewind the tail's catch-up spans the whole head-to-finality range,
        /// and the backfill step runs after it in the same task.
        const TICK_BUDGET: std::time::Duration = std::time::Duration::from_millis(2000);

        let started = std::time::Instant::now();
        let Ok((head_n, head_hash)) = self.anchored_head() else {
            return;
        };
        // Re-read the edge under this tick (the caller's value predates the
        // finalized catch-up that may have just advanced it).
        let Some(mut edge) = self.with_log_index(|ix| ix.append_edge()).flatten() else {
            return;
        };
        let recorded: Vec<(u64, [u8; 32])> =
            self.log_index_tail.lock().map(|t| t.clone()).unwrap_or_default();
        // The bloom decisions below are made against THIS watch-list; a
        // concurrent replacement would make them lies about the new one (its
        // addresses were "definitively" skipped). Every append re-checks it
        // under the index lock, exactly as the backfill commit does.
        let Some(fingerprint) = self.with_log_index(|ix| ix.config().fingerprint()) else {
            return;
        };
        // Coverage above finality this run cannot vouch for: rewind.
        if !tail_vouches_for(&recorded, edge, finalized) {
            tracing::info!(
                covered_high = edge.saturating_sub(1),
                finalized,
                "log index tail: rewinding unvouched coverage above finality"
            );
            self.log_index_rewind_to(finalized);
            edge = finalized.saturating_add(1);
        }
        // The rewind above drops record entries; re-read rather than compare
        // against a stale snapshot (which would fork-rewind coverage that no
        // longer exists and waste a tick on a misleading warning).
        let recorded: Vec<(u64, [u8; 32])> =
            self.log_index_tail.lock().map(|t| t.clone()).unwrap_or_default();
        if head_n.saturating_sub(finalized) >= TAIL_MAX {
            // Finality has stalled far below the head. The tail cannot
            // re-check what it appended from here (the window would exceed
            // the 1024-header serve ceiling, so no peer can cover the floor),
            // and coverage nobody re-checks must not keep serving: drop back
            // to finality rather than answer explicit-number queries from
            // blocks that can still reorg. `>=` because the window is
            // inclusive at both ends — at exactly TAIL_MAX it needs 1025.
            if edge > finalized.saturating_add(1) {
                // Guarded: rewind_above scans the whole log store under the
                // index lock, and this branch repeats every 6s for as long as
                // finality stalls.
                self.log_index_rewind_to(finalized);
            }
            if ticks % 100 == 0 {
                tracing::warn!(finalized, head_n, "log index tail: finality too far below the head; coverage held at finality");
            }
            return;
        }
        // COVERAGE DECISIONS FIRST, PEERS SECOND. Both checks below give
        // coverage back, and neither needs the network — running them after an
        // empty-pool return would let coverage the tail can no longer re-check
        // keep answering local queries for as long as the pool stays empty.
        let lowest_recorded = recorded.iter().map(|(n, _)| *n).min();
        // The window must reach down through every RECORDED block (so a reorg
        // is detectable) and the covered top (so the first appended block links
        // to it by parent hash) — with no clamp, since a clamp would silently
        // drop records out of the comparison. Whether the resulting window is
        // obtainable at all is `tail_window_is_servable`'s question.
        let floor = tail_window_floor(edge, lowest_recorded);
        if !tail_window_is_servable(head_n, floor, TAIL_MAX) {
            // No single window can cover what must be compared, so those
            // records can never be confirmed — and retiring them as if they
            // had been would be exactly the lie this module exists to prevent.
            // Give their coverage back; the appender or bridge re-adds it
            // verified.
            self.retire_tail_record();
            return;
        }
        if !tail_chain_reaches_coverage(head_n, edge) {
            // The chain no longer reaches our covered top: a reorg shortened
            // it, and every block above the new head is orphaned.
            tracing::info!(head_n, covered_high = edge.saturating_sub(1), "log index tail: chain shortened; rewinding");
            self.log_index_rewind_to(head_n);
            if let Ok(mut t) = self.log_index_tail.lock() {
                t.retain(|(n, _)| *n <= head_n);
            }
            return;
        }
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return;
        }
        // Panic-free by construction, and it takes BOTH guards above to make
        // it so: `tail_chain_reaches_coverage` puts `head_n` at or above the
        // covered top (and the floor never exceeds that), so the subtraction
        // cannot wrap; servability bounds the span at TAIL_MAX. A clamp here
        // is what let the window stop above the floor and reject every peer.
        let want = head_n.saturating_sub(floor) + 1;
        let mut window = Vec::new();
        for peer in peers.iter() {
            match peer.get_block_headers_by_number(head_n, want, 0, true).await {
                Ok(w) => {
                    let w = &w[..w.len().min(want as usize)];
                    let Some((top, _)) = w.split_first() else { continue };
                    if top.header.number != head_n || top.hash != head_hash {
                        continue; // not our anchored head; try another peer
                    }
                    let mut verified = 1usize;
                    for pair in w.windows(2) {
                        let [upper, lower] = pair else { break };
                        if upper.header.parent_hash != lower.hash
                            || lower.header.number != upper.header.number.wrapping_sub(1)
                        {
                            break;
                        }
                        verified += 1;
                    }
                    let reaches_floor = w
                        .get(verified - 1)
                        .is_some_and(|lowest| lowest.header.number <= floor);
                    if !reaches_floor {
                        // A window that stops above the floor cannot re-check
                        // the recorded blocks — comparing against it is the
                        // disjoint-range mistake all over again, and a peer
                        // could induce it deliberately. Try another peer.
                        tracing::debug!(floor, "log index tail: window does not reach the check floor");
                        continue;
                    }
                    window = w[..verified].to_vec();
                    break;
                }
                Err(e) => tracing::debug!(error = %e, "log index tail: header window failed"),
            }
        }
        if window.is_empty() {
            return;
        }
        // Ascending, so coverage extends contiguously.
        let canonical: Vec<crate::el::eth::messages::VerifiedHeader> =
            window.into_iter().rev().collect();
        let canon_pairs: Vec<(u64, [u8; 32])> =
            canonical.iter().map(|c| (c.header.number, c.hash)).collect();

        if let Some(fork) = tail_fork_point(&recorded, &canon_pairs) {
            tracing::info!(fork_at = fork, "log index tail: reorg detected; rewinding");
            self.log_index_rewind_to(fork.saturating_sub(1));
            if let Ok(mut t) = self.log_index_tail.lock() {
                t.retain(|(n, _)| *n < fork);
            }
            edge = fork;
        }

        let pending: Vec<&crate::el::eth::messages::VerifiedHeader> =
            canonical.iter().filter(|c| c.header.number >= edge).collect();
        if pending.is_empty() {
            return;
        }
        let candidate_hashes: Vec<[u8; 32]> = pending
            .iter()
            .filter(|c| match <&[u8; 256]>::try_from(c.header.logs_bloom.as_slice()) {
                Ok(bloom) => {
                    self.with_log_index(|ix| ix.bloom_may_match(c.header.number, bloom)).unwrap_or(false)
                }
                Err(_) => true,
            })
            .map(|c| c.hash)
            .collect();
        let mut logs: std::collections::HashMap<u64, Vec<crate::el::logindex::StoredLog>> =
            std::collections::HashMap::new();
        let mut peer_idx = 0usize;
        'chunks: for chunk in candidate_hashes.chunks(CANDIDATE_CHUNK) {
            if started.elapsed() >= TICK_BUDGET {
                break; // apply the contiguous prefix; the rest is next tick's
            }
            // The headers are already in hand, parent-chain-verified in the
            // window fetched above — no per-candidate header round trip.
            let chunk_headers: Vec<Option<crate::el::eth::messages::VerifiedHeader>> = chunk
                .iter()
                .map(|h| canonical.iter().find(|c| c.hash == *h).cloned())
                .collect();
            loop {
                let Some(peer) = peers.get(peer_idx) else {
                    break 'chunks; // pool exhausted; apply the prefix we have
                };
                match self.fetch_logs_for_known_headers(peer, chunk, &chunk_headers).await {
                    Ok(map) => {
                        logs.extend(map);
                        break;
                    }
                    Err(e) => {
                        // Rotate rather than stall: a persistently failing
                        // first peer would otherwise freeze the tail while
                        // healthy peers sit idle.
                        tracing::debug!(error = %e, "log index tail: candidate fetch failed");
                        peer_idx += 1;
                    }
                }
            }
        }
        let mut appended = 0usize;
        for c in &pending {
            let n = c.header.number;
            // A candidate whose logs this round didn't get (byte-budget
            // truncation) stops the tail here: coverage must stay contiguous.
            if candidate_hashes.contains(&c.hash) && !logs.contains_key(&n) {
                break;
            }
            let block_logs = logs.get(&n).cloned().unwrap_or_default();
            let ok = match self.log_index.lock() {
                Ok(mut slot) => match slot.as_mut() {
                    Some(ix) if ix.config().fingerprint() == fingerprint => {
                        let stored = ix.append_block(n, c.hash, block_logs).is_ok();
                        if stored {
                            // Under the SAME hold: a config replace between
                            // the append and the push would otherwise seed a
                            // record describing the old index into the new
                            // one, whose next fork scan would rewind coverage
                            // that record has nothing to do with.
                            if let Ok(mut t) = self.log_index_tail.lock() {
                                t.push((n, c.hash));
                            }
                        }
                        stored
                    }
                    // Uninstalled, or the watch-list changed under us: this
                    // block's candidacy was decided against the old list.
                    _ => false,
                },
                Err(_) => false,
            };
            if !ok {
                // Visible: a silently broken tail is the same failure shape as
                // the frozen append edge this whole change exists to fix.
                tracing::warn!(block = n, edge, "log index tail: append rejected; coverage holds here");
                break;
            }
            appended += 1;
        }
        // Retire records only now, through the shared rule. The evidence this
        // site can supply is `compared = true`: the canonical window above
        // covered every record (a window that fails to reach the floor is
        // rejected before this point), so a survivor at or below finality has
        // been confirmed canonical and can never change again.
        if let Ok(mut t) = self.log_index_tail.lock() {
            t.retain(|(bn, _)| !record_may_retire(*bn, finalized, true));
        }
        if appended > 0 {
            tracing::debug!(appended, head_n, "log index tail advanced");
            if self.log_index_persist_due() {
                self.persist_log_index(finalized);
            }
        }
    }

    /// Rewind the index (coverage and stored logs) above `fork_point`, and
    /// forget the tail record above it.
    fn log_index_rewind_to(&self, fork_point: u64) {
        if let Ok(mut slot) = self.log_index.lock() {
            if let Some(ix) = slot.as_mut() {
                ix.rewind_above(fork_point);
            }
        }
        if let Ok(mut t) = self.log_index_tail.lock() {
            t.retain(|(n, _)| *n <= fork_point);
        }
    }

    /// Checkpoint the index, CLAMPED AT FINALITY: optimistic coverage is only
    /// as trustworthy as this run's in-memory tail record, which does not
    /// survive a restart. Persisting it would leave a later run holding
    /// coverage it can never re-check — and once finality moves past those
    /// blocks, nothing would ever rewind them (they would look immutable
    /// while possibly being orphaned).
    fn persist_log_index(&self, finalized: u64) {
        if let (Some(path), Ok(slot)) = (self.log_index_path.as_deref(), self.log_index.lock()) {
            if let Some(ix) = slot.as_ref() {
                if finalized == 0 {
                    // No beacon anchor yet. There is no optimistic coverage to
                    // clamp either (the tail only runs below a real finality),
                    // and clamping AT ZERO would rewind the whole index and
                    // rename an empty file over a good checkpoint — losing, on
                    // a phone, months of backfill. Write it as it stands.
                    let _ = ix.persist(path);
                } else {
                    let _ = ix.persist_clamped(path, finalized);
                }
            }
        }
    }

    /// The highest block the log index currently covers, or None when nothing
    /// is indexed. Hosts resolve `latest` against this so a head that moved
    /// since the last tail tick doesn't flap head-reaching queries into
    /// refusals (see `LOG_INDEX_LATEST_SLACK` on the host side).
    pub fn log_index_covered_high(&self) -> Option<u64> {
        self.with_log_index(|ix| ix.append_edge())
            .flatten()
            .map(|edge| edge.saturating_sub(1))
    }

    /// True when a full-index checkpoint is due (and claims the slot). The
    /// persist is a whole-file rewrite under the index lock, so both the
    /// backfill and the bridge share this throttle.
    fn log_index_persist_due(&self) -> bool {
        const PERSIST_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
        self.log_index_last_persist.lock().is_ok_and(|mut t| {
            if t.is_none_or(|prev| prev.elapsed() >= PERSIST_MIN_INTERVAL) {
                *t = Some(std::time::Instant::now());
                true
            } else {
                false
            }
        })
    }

    /// Drop any in-progress bridge plan (the gap closed, or the premises it
    /// were built on changed). Deliberately does NOT touch the tail record —
    /// see [`Self::retire_tail_record`] for the one invariant that governs it.
    fn clear_log_index_bridge(&self) {
        if let Ok(mut slot) = self.log_index_bridge.lock() {
            if slot.is_some() {
                *slot = None;
            }
        }
    }

    /// THE invariant for the tail record, and the only way an entry leaves it
    /// besides the post-comparison prune at the end of a tail tick:
    ///
    /// > A record entry may be dropped only after the canonical chain
    /// > confirmed it at a height at or below finality, or together with the
    /// > coverage it describes.
    ///
    /// An entry is evidence that THIS run appended a block optimistically and
    /// has not yet proven it canonical. Finality moving past it proves nothing
    /// — finality fixes the canonical block at that height, not the possibly
    /// orphaned one we stored. So when the walker leaves the tail (index
    /// disabled, anchor lost, finality overtook the whole tail), unconfirmed
    /// entries cannot simply be forgotten: their coverage goes with them.
    ///
    /// Cheap by construction — the record spans at most one tail window, so
    /// the rewind gives back at most that many blocks, which the appender or
    /// bridge re-adds verified.
    fn retire_tail_record(&self) {
        let lowest = match self.log_index_tail.lock() {
            Ok(t) => t.iter().map(|(n, _)| *n).min(),
            Err(_) => None,
        };
        let Some(lowest) = lowest else {
            return; // nothing unconfirmed
        };
        tracing::info!(
            from = lowest,
            "log index tail: dropping coverage this run could not confirm canonical"
        );
        self.log_index_rewind_to(lowest.saturating_sub(1));
    }

    /// One head-gap bridge step: carry coverage from a stale append edge up to
    /// the finalized head, one bounded slice per tick, using the same verified
    /// machinery as the backfill walk (parent-hash chain from a beacon anchor,
    /// header bloom pre-filter, receipts checked against both roots).
    ///
    /// Runs only while the gap exceeds the appender's per-block window; the
    /// last slice hands back to the appender, which keeps up from there. See
    /// [`BridgePlan`] for the two phases and why they run in that order.
    async fn log_index_bridge_step(&self, edge: u64, finalized: u64, ticks: u64) {
        /// Headers per descent request — the eth/66+ serve ceiling.
        const DESCENT_BATCH: u64 = 1024;
        /// Descent requests per tick: bounds a long gap's catch-up work per
        /// 6s tick instead of monopolizing the walker for minutes.
        const DESCENT_BATCHES_PER_TICK: usize = 8;
        /// Blocks applied per tick during the ascent.
        const ASCENT_PER_TICK: usize = 2048;
        /// Candidate blocks per body/receipts request (backfill's chunk size).
        const CANDIDATE_CHUNK: usize = 64;
        /// Wall-clock budget per tick — the bridge shares the pool with RPC
        /// traffic and runs BEFORE the backfill in the same task, so it must
        /// leave the tail of the 6s tick to both (the backfill's own budget
        /// makes the same trade).
        const TICK_BUDGET: std::time::Duration = std::time::Duration::from_millis(3000);
        /// Widest gap a single plan will map. Each entry is a padded
        /// `(u64, [u8;32], bool)` = 48 bytes, so 500k blocks is ~24 MB —
        /// deliberately sized for a phone (CLAUDE.md keeps Android
        /// first-class), not for a workstation. Beyond it coverage simply
        /// holds: a staged bridge (descend headers-only to an intermediate
        /// anchor, then map MAX_GAP at a time) is the follow-up that would
        /// close arbitrarily deep gaps without an unbounded plan.
        const MAX_GAP: u64 = 500_000;

        let Some((fin_n, fin_hash)) = self.anchor.finalized_execution().map(|f| (f.block_number, f.block_hash))
        else {
            return; // no finalized anchor yet — nothing to anchor trust on
        };
        if fin_n != finalized {
            return; // moved under us; next tick re-reads it
        }
        if finalized.saturating_sub(edge) > MAX_GAP {
            if ticks % 100 == 0 {
                tracing::warn!(
                    edge,
                    finalized,
                    "log index head gap exceeds the bridge's span; coverage holds here until the watch-list changes (which replaces the index) or the index file is removed"
                );
            }
            return;
        }
        let started = std::time::Instant::now();
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            if ticks % 100 == 0 {
                tracing::info!(edge, finalized, "log index head bridge idle: no peers this tick");
            }
            return;
        }

        // Take the plan out for the duration and put it back at the end. A
        // PARTIAL descent is worth keeping: its blocks are parent-hash-chained
        // to an immutable finalized anchor, so a transient peer failure must
        // not throw away work — re-descending 8 windows (~4.5 MB) every tick
        // would burn bandwidth forever on exactly the deep-gap case this
        // exists for. Only a premise change (see the reuse check) discards it.
        let mut plan = match self.log_index_bridge.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => None,
        };
        // A plan survives across ticks as long as it still lines up with where
        // coverage now is. Two things move under it, and NEITHER invalidates
        // the mapped blocks:
        //  - the edge, which the ascent itself advances (so the plan's own
        //    progress must be added back before comparing), and
        //  - the finalized head, which only moves forward; everything the plan
        //    mapped sits below its own anchor and below finality, so it stays
        //    immutable. Blocks finalized since are simply not in this plan —
        //    the appender (or the next plan) picks them up afterwards.
        // Getting this wrong is expensive rather than unsafe: a discarded plan
        // re-descends the whole gap, which for a large gap is every tick's
        // work thrown away.
        if let Some(p) = &plan {
            if !plan_still_matches(p.anchor_n, p.target, p.applied, fin_n, edge) {
                plan = None;
            }
        }
        let Some(fingerprint) = self.with_log_index(|ix| ix.config().fingerprint()) else {
            return;
        };
        if plan.as_ref().is_some_and(|p| p.fingerprint != fingerprint) {
            plan = None; // watch-list replaced: the mapped blooms don't apply
        }
        let mut plan = plan.unwrap_or_else(|| BridgePlan {
            anchor_n: fin_n,
            anchor_hash: fin_hash,
            fingerprint,
            target: edge,
            low_n: fin_n.saturating_add(1),
            low_hash: fin_hash,
            // Sized up front: growing by doubling would hold BOTH buffers
            // live at the realloc — a ~1.5x transient spike on the deep-gap
            // path, on a platform where that is an OOM kill, not a slowdown.
            blocks: Vec::with_capacity((fin_n.saturating_sub(edge) + 1) as usize),
            descended: false,
            applied: 0,
        });

        // The descent verifies against the plan's OWN anchor: finality may have
        // advanced since the plan was built, and re-anchoring mid-descent would
        // break the parent-hash chain the collected blocks were verified under.
        let (anchor_n, anchor_hash) = (plan.anchor_n, plan.anchor_hash);
        let mut peer_idx = 0usize;
        if !plan.descended {
            for _ in 0..DESCENT_BATCHES_PER_TICK {
                if started.elapsed() >= TICK_BUDGET {
                    break;
                }
                // First request starts AT the anchor; later ones continue from
                // the lowest verified block (which is re-served as the head of
                // the window, so its hash re-anchors the chain check).
                let from = plan.low_n.min(anchor_n);
                let want = (from.saturating_sub(plan.target) + 1).min(DESCENT_BATCH);
                // Rotate peers on failure like every other walker here: one
                // slow or pruned peer at the head of the pool must not stall
                // the bridge (and, with the plan retained, each retry keeps
                // whatever the previous peers already chained).
                let Some(peer) = peers.get(peer_idx) else {
                    break; // pool exhausted this tick; plan survives
                };
                let window = match peer.get_block_headers_by_number(from, want, 0, true).await {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::debug!(error = %e, from, "log index head bridge: header window failed");
                        peer_idx += 1;
                        continue;
                    }
                };
                // A peer may over-serve; anything past `want` is outside the
                // gap this plan describes and would push `low_n` below the
                // target, permanently desynchronizing plan and coverage.
                let window = &window[..window.len().min(want as usize)];
                let Some((top, _)) = window.split_first() else {
                    peer_idx += 1;
                    continue;
                };
                let before_low = plan.low_n;
                let expect_hash = if plan.blocks.is_empty() { anchor_hash } else { plan.low_hash };
                if top.header.number != from || top.hash != expect_hash {
                    tracing::debug!(from, "log index head bridge: window does not start at the anchor");
                    peer_idx += 1;
                    continue;
                }
                // Descending parent-hash chain, exactly as the backfill batch
                // verifies it: only the chained prefix is trusted.
                let mut verified = 1usize; // the anchor block itself
                for pair in window.windows(2) {
                    let [upper, lower] = pair else { break };
                    if upper.header.parent_hash != lower.hash
                        || lower.header.number != upper.header.number.wrapping_sub(1)
                    {
                        break;
                    }
                    verified += 1;
                }
                for vh in &window[..verified] {
                    // The anchor block is collected once; continuation windows
                    // re-serve their head, which is already collected.
                    if !plan.blocks.is_empty() && vh.header.number >= plan.low_n {
                        continue;
                    }
                    let candidate = match <&[u8; 256]>::try_from(vh.header.logs_bloom.as_slice()) {
                        Ok(bloom) => self
                            .with_log_index(|ix| ix.bloom_may_match(vh.header.number, bloom))
                            .unwrap_or(false),
                        Err(_) => true, // odd bloom width: verify via receipts
                    };
                    plan.blocks.push((vh.header.number, vh.hash, candidate));
                    plan.low_n = vh.header.number;
                    plan.low_hash = vh.hash;
                }
                if plan.low_n >= before_low {
                    // A window that chains nothing new (peer served only the
                    // re-anchor block, or an unchained response): try the next
                    // peer rather than spinning on this one.
                    tracing::debug!(from, "log index head bridge: window added no chained blocks");
                    peer_idx += 1;
                    continue;
                }
                if plan.low_n <= plan.target {
                    plan.descended = true;
                    tracing::info!(
                        from = plan.target,
                        to = anchor_n,
                        blocks = plan.blocks.len(),
                        candidates = plan.blocks.iter().filter(|b| b.2).count(),
                        "log index head bridge: gap mapped; applying"
                    );
                    break;
                }
            }
        }

        if plan.descended {
            let total = plan.blocks.len();
            let mut applied_this_tick = 0usize;
            while plan.applied < total
                && applied_this_tick < ASCENT_PER_TICK
                && started.elapsed() < TICK_BUDGET
            {
                // One request per RUN of candidates ahead of the cursor —
                // candidates are sparse, so a chunk typically covers a long
                // stretch of plain blocks that need no network at all. The
                // chunk is bounded by what this tick can still APPLY, so a
                // sparse watch-list doesn't fetch 64 candidates' bodies and
                // receipts only to discard most of them at the budget line.
                let budget_left = ASCENT_PER_TICK - applied_this_tick;
                let hashes = bridge_candidate_chunk(
                    &plan.blocks,
                    plan.applied,
                    CANDIDATE_CHUNK,
                    budget_left,
                );
                let logs = if hashes.is_empty() {
                    std::collections::HashMap::new()
                } else {
                    // Rotate on failure like the descent: retry this slice
                    // against the next peer rather than idling a whole tick
                    // (and, once the pool is exhausted, keep the plan and let
                    // the next tick start over from the top of the pool).
                    let mut fetched = None;
                    // `hashes[0]` is the block the ascent is standing on; a
                    // response without it makes no progress possible, so it
                    // counts as a failure and rotates. Returning it as success
                    // wedged the bridge on one peer indefinitely (the apply
                    // loop breaks, the plan survives, the same peer is first
                    // again next tick).
                    let need = plan.blocks[total - 1 - plan.applied].0;
                    while peer_idx < peers.len() {
                        match self.bridge_fetch_logs(&peers[peer_idx], &hashes).await {
                            Ok(map) if map.contains_key(&need) => {
                                fetched = Some(map);
                                break;
                            }
                            Ok(_) => {
                                tracing::debug!("log index head bridge: peer served no usable prefix");
                                peer_idx += 1;
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "log index head bridge: candidate fetch failed");
                                peer_idx += 1;
                            }
                        }
                    }
                    let Some(map) = fetched else {
                        break; // pool exhausted this tick; the plan survives
                    };
                    map
                };
                // Apply this block plus every non-candidate up to the next
                // candidate whose logs we just fetched.
                let mut progressed = false;
                while plan.applied < total && applied_this_tick < ASCENT_PER_TICK {
                    let j = total - 1 - plan.applied;
                    let (n, h, cand) = plan.blocks[j];
                    if cand && !logs.contains_key(&n) {
                        break; // needs a fetch this round didn't cover
                    }
                    let block_logs = logs.get(&n).cloned().unwrap_or_default();
                    let ok = match self.log_index.lock() {
                        Ok(mut slot) => match slot.as_mut() {
                            Some(ix) if ix.config().fingerprint() == plan.fingerprint => {
                                ix.append_block(n, h, block_logs).is_ok()
                            }
                            // Uninstalled, or the watch-list changed under us.
                            _ => false,
                        },
                        Err(_) => false,
                    };
                    if !ok {
                        // Uninstalled, replaced, or non-adjacent: a genuine
                        // premise change, so this IS one of the few paths that
                        // deliberately drops the plan.
                        tracing::debug!(block = n, "log index head bridge: append rejected; replanning");
                        return;
                    }
                    plan.applied += 1;
                    applied_this_tick += 1;
                    progressed = true;
                }
                if !progressed {
                    break; // nothing became applicable this round — retry next tick
                }
            }
            let done = plan.applied >= total;
            // Checkpoint on the same throttle the backfill uses — the persist
            // is a full-index rewrite, and bridging can apply thousands of
            // blocks per tick. Always checkpoint the final slice.
            if applied_this_tick > 0 && (done || self.log_index_persist_due()) {
                self.persist_log_index(self.finalized_block_number());
            }
            if done {
                tracing::info!(to = anchor_n, "log index head bridge complete; head-follow resumes");
                return; // plan finished — dropped, appender takes over
            }
        }
        if let Ok(mut slot) = self.log_index_bridge.lock() {
            *slot = Some(plan);
        }
    }

    /// Fetch bodies+receipts for candidate blocks named by their TRUSTED
    /// hashes (the plan's descent chained them to a beacon anchor) and return
    /// their watch-list logs by block number.
    ///
    /// Headers are re-fetched here by hash rather than cached in the plan: a
    /// header is self-verifying under a hash we already trust (`hash !=
    /// requested` is rejected), and caching them would make plan memory scale
    /// with candidate DENSITY — a watched high-traffic contract hits the bloom
    /// in nearly every block, which on a long gap is hundreds of megabytes on
    /// a phone. The fetches ride the multiplexed connection concurrently, so
    /// the extra round trip costs latency once per chunk, not per block.
    ///
    /// Verification is the backfill's, block for block: transactions against
    /// the header's `transactionsRoot`, receipts against its `receiptsRoot`,
    /// so a peer cannot substitute a different block's data.
    async fn bridge_fetch_logs(
        &self,
        peer: &ManagedPeer,
        hashes: &[[u8; 32]],
    ) -> Result<std::collections::HashMap<u64, Vec<crate::el::logindex::StoredLog>>, String> {
        if hashes.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        // join_all, not try_join_all: short-circuiting would drop the sibling
        // requests still in flight (and the bodies/receipts already served)
        // the moment one header failed. Failures become per-block holes that
        // simply shorten the usable prefix.
        let headers = futures::future::join_all(hashes.iter().map(|h| async move {
            let got = peer.get_block_headers_by_hash(h, 1).await.ok()?;
            let vh = got.into_iter().next()?;
            (vh.hash == *h).then_some(vh)
        }))
        .await;
        self.fetch_logs_for_known_headers(peer, hashes, &headers).await
    }

    /// The verify core shared by the bridge and the tail: given TRUSTED
    /// headers (chained to a beacon anchor by the caller), fetch each block's
    /// body and receipts and return the watch-list logs by block number. The
    /// tail passes the headers from the window it just verified rather than
    /// re-fetching one per candidate every tick.
    async fn fetch_logs_for_known_headers(
        &self,
        peer: &ManagedPeer,
        hashes: &[[u8; 32]],
        headers: &[Option<crate::el::eth::messages::VerifiedHeader>],
    ) -> Result<std::collections::HashMap<u64, Vec<crate::el::logindex::StoredLog>>, String> {
        let mut out = std::collections::HashMap::new();
        if hashes.is_empty() {
            return Ok(out);
        }
        let (bodies, receipt_blocks) =
            futures::future::join(peer.get_block_bodies(hashes), peer.get_receipts(hashes)).await;
        let (bodies, receipt_blocks) = (bodies?, receipt_blocks?);
        // Honest byte-budget truncation: use the served prefix, leave the rest
        // for the next round (the caller re-requests what it didn't get).
        let usable = bodies.len().min(receipt_blocks.len()).min(hashes.len());
        if usable == 0 {
            return Err("peer served no bodies/receipts for bridge candidates".to_string());
        }
        for i in 0..usable {
            // A missing/mismatched header ends the usable prefix rather than
            // failing the chunk: the caller applies what is contiguous.
            let Some(vh) = headers.get(i).and_then(|h| h.as_ref()) else {
                break;
            };
            verify_body_transactions(&vh.header, &bodies[i])?;
            if receipt_blocks[i].len() != bodies[i].transactions.len() {
                return Err(format!(
                    "block {}: {} receipts for {} transactions",
                    vh.header.number,
                    receipt_blocks[i].len(),
                    bodies[i].transactions.len()
                ));
            }
            verify_block_receipts(&vh.header, &receipt_blocks[i])?;
            let built = build_block_receipts(&vh.header, vh.hash, &bodies[i], &receipt_blocks[i])?;
            let stored =
                stored_logs_for_block(&built).ok_or("malformed log field in verified receipts")?;
            let watched: Vec<crate::el::logindex::StoredLog> = self
                .with_log_index(|ix| {
                    stored.iter().filter(|l| ix.config().watches(l)).cloned().collect::<Vec<_>>()
                })
                .unwrap_or_default();
            out.insert(vh.header.number, watched);
        }
        Ok(out)
    }

    /// One backfill step: walk the verified header chain DOWNWARD from the
    /// index's trust cursor toward the lowest watched from_block, one batch
    /// per tick (docs/eth-getlogs-design.md §backfill). Every header is
    /// trusted only through parent-hash linkage into the cursor (whose own
    /// trust chains back to a beacon-anchored append); candidate blocks
    /// (bloom hit) get body+receipts fetched and verified against both roots
    /// before any log is stored. Peer refusal is a stall, never corruption:
    /// coverage simply doesn't extend until some peer serves the range.
    async fn log_index_backfill_step(&self, ticks: u64, backfill_ok: &mut u64) {
        // Pacing: "nice" works ONE batch per 6s tick (background politeness);
        // "max speed" keeps working batches until a per-tick time budget is
        // spent — the difference between ~55 blocks/6s and peer-limited
        // throughput on dense ranges. The budget leaves the tail of each tick
        // for the appender and for RPC traffic on the shared pool.
        const MAX_SPEED_TICK_BUDGET: std::time::Duration = std::time::Duration::from_millis(4500);
        let started = std::time::Instant::now();
        let mut any_progress = false;
        loop {
            let (progressed, max_speed) = self.log_index_backfill_round(ticks, backfill_ok).await;
            any_progress |= progressed;
            if !progressed || !max_speed || started.elapsed() >= MAX_SPEED_TICK_BUDGET {
                break;
            }
            // Yield between rounds so this task never monopolizes the runtime.
            tokio::task::yield_now().await;
        }
        // Checkpoint at most once per throttle window of progressing steps
        // (not per batch, not even per step) — see log_index_persist_due; a
        // crash now costs at most ~10s of batches.
        let persist_due = any_progress && self.log_index_persist_due();
        if persist_due {
            self.persist_log_index(self.finalized_block_number());
        }
        // Rolling throughput for the status ETA, measured against WALL CLOCK
        // between progress observations (the anchor persists across idle
        // ticks, so nice mode's 6s cadence divides honestly). Cursor
        // regression (fresh walk) resets the anchor without emitting a sample.
        if let Some((cursor_now, _)) = self.with_log_index(|ix| ix.cursor).flatten() {
            let now = std::time::Instant::now();
            if let Ok(mut rate) = self.log_index_rate.lock() {
                *rate = match *rate {
                    Some((anchor_t, anchor_cursor, ema)) if cursor_now < anchor_cursor => {
                        let blocks = (anchor_cursor - cursor_now) as f64;
                        let secs = now.duration_since(anchor_t).as_secs_f64().max(0.001);
                        let inst = blocks / secs;
                        // 0.0 is the fresh-anchor SENTINEL, not a measurement —
                        // blending it would bias the first displayed rate to
                        // 20% of truth (ETA ~5x overstated) right after the
                        // config poke that reset the anchor. Seed with the
                        // first real sample instead.
                        let blended = if ema > 0.0 { ema * 0.8 + inst * 0.2 } else { inst };
                        Some((now, cursor_now, blended))
                    }
                    Some((anchor_t, anchor_cursor, ema)) if cursor_now == anchor_cursor => {
                        // No progress this step: keep the anchor so the next
                        // sample's denominator includes this idle time.
                        Some((anchor_t, anchor_cursor, ema))
                    }
                    // First observation, or cursor regressed (new walk).
                    _ => Some((now, cursor_now, 0.0)),
                };
            }
        }
    }

    /// One backfill round: try every pooled peer for one batch at the current
    /// cursor. Returns (progressed, max_speed_configured).
    async fn log_index_backfill_round(&self, ticks: u64, backfill_ok: &mut u64) -> (bool, bool) {
        let Some((config, cursor)) = self.with_log_index(|ix| (ix.config().clone(), ix.cursor)) else {
            return (false, false);
        };
        let max_speed = config.max_speed;
        let (Some(target_low), Some((cur_n, cur_hash))) =
            (config.watch.iter().map(|w| w.from_block).min(), cursor)
        else {
            return (false, max_speed); // no watch entries, or the edge isn't seeded yet
        };
        if !config.enabled || cur_n <= target_low {
            return (false, max_speed);
        }
        let fingerprint = config.fingerprint();
        // count+1 headers are requested (the top one is the cursor block), and
        // honest peers cap header serves at 1024 (our own served.rs agrees) —
        // so the batch is 1023 new blocks, keeping the request exactly at cap.
        const BATCH: u64 = 1023;
        let count = (cur_n - target_low).min(BATCH);
        let from = cur_n - count;
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            // Visible (rate-limited): a silently empty pool looked identical
            // to a hung walker during the 2026-08-06 stall investigation.
            if ticks % 100 == 0 {
                tracing::info!(cursor = cur_n, "log index backfill idle: no snap peers this tick");
            }
            return (false, max_speed);
        }
        for peer in &peers {
            match self
                .log_index_backfill_batch(peer, count, cur_n, cur_hash, &config, fingerprint)
                .await
            {
                Ok(()) => {
                    // Count SUCCESSES, not ticks: with intermittent failures a
                    // ticks-modulo log can systematically miss the successful
                    // ticks and stay silent while progressing. First success
                    // logs immediately, then every 50th (~5 min when healthy).
                    *backfill_ok += 1;
                    if *backfill_ok % 50 == 1 {
                        let new_cursor = self.with_log_index(|ix| ix.cursor).flatten();
                        tracing::info!(
                            cursor = new_cursor.map(|(n, _)| n).unwrap_or(cur_n),
                            target = target_low,
                            batches_applied = *backfill_ok,
                            "log index backfill progress"
                        );
                    }
                    // Persistence happens once per step (see the caller) —
                    // per-batch fsyncs would eat the max-speed budget.
                    return (true, max_speed);
                }
                Err(e) => {
                    tracing::debug!(from, count, error = %e, "log index backfill batch failed; trying next peer");
                }
            }
        }
        if ticks % 100 == 0 {
            tracing::warn!(
                cursor = cur_n,
                target = target_low,
                "log index backfill: no peer served the range this round (history depth?); will keep retrying"
            );
        }
        (false, max_speed)
    }

    /// Fetch and apply one descending backfill batch from one peer:
    /// headers [from, cur_n] ascending (count+1, so the top one IS the cursor
    /// block), full parent-hash chain check, bloom-filtered candidate
    /// body+receipts fetch verified against both roots, then apply top-down.
    /// Fetch and apply one descending backfill batch from one peer. The
    /// request is `reverse=true` starting AT the trusted cursor block, so the
    /// trust root is the FIRST header of the response — a short serve (peers
    /// may cap below the 1024 ceiling, or truncate on byte budget) still
    /// yields a verifiable parent-hash-chained prefix and partial progress,
    /// instead of failing an exact-length check forever. (`remember_served`
    /// only tracks ascending shapes, so reverse fetches skip that side
    /// channel — harmless.) Candidates are bloom-filtered and their logs
    /// pre-filtered against the captured config, so transient memory is
    /// proportional to logs that will actually be stored.
    async fn log_index_backfill_batch(
        &self,
        peer: &ManagedPeer,
        count: u64,
        cur_n: u64,
        cur_hash: [u8; 32],
        config: &crate::el::logindex::LogIndexConfig,
        fingerprint: u64,
    ) -> Result<(), String> {
        let window = peer.get_block_headers_by_number(cur_n, count + 1, 0, true).await?;
        let Some((top, rest)) = window.split_first() else {
            return Err("peer returned no headers".to_string());
        };
        if top.header.number != cur_n || top.hash != cur_hash {
            return Err("peer window does not start at the trusted cursor block".to_string());
        }
        if rest.is_empty() {
            return Err("peer served only the cursor block".to_string());
        }
        // Descending parent-hash chain: each header's parent is the next one.
        // Only the verified prefix is used, so a mid-response break just
        // shortens the batch instead of failing it.
        let mut verified = 0usize;
        for pair in window.windows(2) {
            let [upper, lower] = pair else {
                return Err("header window pairing failed".to_string());
            };
            if upper.header.parent_hash != lower.hash
                || lower.header.number != upper.header.number.wrapping_sub(1)
            {
                break;
            }
            verified += 1;
        }
        if verified == 0 {
            return Err("peer response does not chain to the cursor block".to_string());
        }
        let new_blocks = rest.get(..verified).ok_or("verified prefix out of range")?;
        // Bloom-filter candidates among the NEW blocks. A miss is a
        // definitive skip; a hit needs verified receipts.
        let candidates: Vec<&crate::el::eth::messages::VerifiedHeader> = new_blocks
            .iter()
            .filter(|h| {
                let Ok(bloom): Result<&[u8; 256], _> = h.header.logs_bloom.as_slice().try_into() else {
                    return true; // odd bloom width: treat as maybe, verify via receipts
                };
                self.with_log_index(|ix| ix.bloom_may_match(h.header.number, bloom)).unwrap_or(false)
            })
            .collect();
        let mut logs_by_block: std::collections::HashMap<u64, Vec<crate::el::logindex::StoredLog>> =
            std::collections::HashMap::new();
        // Chunked: one request for ~1023 candidate blocks would blow through
        // peer soft response limits (~2 MiB) and permanently stall a
        // candidate-dense range on the exact-length check below.
        // (Truncation arithmetic lives in `truncation_plan`/`should_apply` —
        // pure and unit-tested; see backfill_truncation_tests.)
        // First candidate the peer did NOT serve this round (honest byte-budget
        // truncation): the batch is applied only ABOVE it, so coverage never
        // claims a block whose receipts we didn't verify, and the next tick's
        // batch resumes right at it. Never a hard error — geth-class peers cap
        // bodies/receipts responses by a soft byte budget, so on candidate-dense
        // ranges a short response is the EXPECTED shape, and treating it as
        // peer failure permanently stalled the walk (observed on sepolia at
        // ~#11.43M: 64 requested → 41 bodies / 23 receipt sets served).
        // PIPELINED chunk fetches (#297 option 1): keep several chunk
        // requests in flight on the multiplexed connection while results are
        // consumed strictly IN ORDER — verification is per-block, but the
        // truncation cut and coverage adjacency depend on request order, so
        // ordering lives in the consumer (`buffered`, not `buffer_unordered`).
        // On truncation/failure the stream is dropped, cancelling in-flight
        // fetches (their late responses are discarded by the peer read loop;
        // worst case a few response budgets of wasted bandwidth past the cut —
        // or, if a cancellation lands mid-frame-write, the connection itself:
        // the writer's torn marker then fails the peer at its next send
        // rather than let it write MAC-garbage; see peer.rs `GuardedWriter`).
        const CHUNK_PIPELINE: usize = 4;
        const CHUNK_LEN: usize = 64;
        // ADAPTIVE depth: pipelining only pays where chunks come back FULL
        // (sequential RTTs dominate); in budget-truncated ranges the batch
        // ends at the first chunk and any prefetched chunks are pure wasted
        // bandwidth on the already-saturated serving link — so after a
        // truncated batch the next one degrades to depth 1 (identical to the
        // pre-pipeline behavior), and a clean batch restores full depth.
        let depth = if self
            .log_index_pipeline_full
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            CHUNK_PIPELINE
        } else {
            1
        };
        let mut stop_below: Option<u64> = None;
        // Owned per-chunk hash lists move into the fetch futures (borrowing
        // the header slices across the stream trips Send inference in the
        // spawned appender task); the consumer re-derives each chunk slice by
        // index for verification.
        let chunk_hashes: Vec<Vec<[u8; 32]>> = candidates
            .chunks(CHUNK_LEN)
            .map(|c| c.iter().map(|h| h.hash).collect())
            .collect();
        let mut fetches = futures::StreamExt::buffered(
            futures::stream::iter(chunk_hashes.into_iter().enumerate().map(|(i, hashes)| {
                async move {
                    let (bodies, receipts) = futures::future::join(
                        peer.get_block_bodies(&hashes),
                        peer.get_receipts(&hashes),
                    )
                    .await;
                    (i, bodies, receipts)
                }
            })),
            depth,
        );
        'chunks: while let Some((chunk_idx, bodies, receipt_blocks)) =
            futures::StreamExt::next(&mut fetches).await
        {
            let chunk = candidates
                .chunks(CHUNK_LEN)
                .nth(chunk_idx)
                .ok_or("chunk index out of range")?;
            let (bodies, receipt_blocks) = match (bodies, receipt_blocks) {
                (Ok(b), Ok(r)) => (b, r),
                (b, r) => {
                    // A failed chunk fetch may be a pipelining artifact: at
                    // depth 4 a tail request's 15s timer runs while the peer
                    // serves the full-budget responses queued ahead of it, so
                    // a slow link can time out where the sequential shape
                    // worked — and unlike truncation, an error would otherwise
                    // leave the depth at 4 and repeat the failure on the next
                    // peer. Degrade like a truncated batch; a clean batch
                    // restores full depth.
                    self.log_index_pipeline_full
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    return Err(b.err().or(r.err()).unwrap_or_else(|| "chunk fetch failed".into()));
                }
            };
            // Served items are an in-order prefix of the request (the per-block
            // root verification below catches any peer that violates that).
            let chunk_numbers: Vec<u64> = chunk.iter().map(|h| h.header.number).collect();
            let Some((usable, chunk_stop)) =
                truncation_plan(&chunk_numbers, bodies.len(), receipt_blocks.len())
            else {
                // Nothing served at all — a single block's receipts always fit
                // a response budget, so this peer genuinely can't (or won't)
                // serve the range (pruned history, not a byte budget); let the
                // caller rotate to the next peer. DELIBERATE on later chunks
                // too: this discards the batch's earlier verified chunks, but
                // an empty serve is a data-availability signal, and retrying
                // the whole batch against a peer that HAS the range beats
                // committing a shortened batch sourced from one that doesn't.
                return Err(format!(
                    "peer served no bodies/receipts for candidate chunk starting at block {}",
                    chunk_numbers.first().copied().unwrap_or_default()
                ));
            };
            for ((vh, body), receipts) in
                chunk[..usable].iter().zip(&bodies[..usable]).zip(&receipt_blocks[..usable]) {
                verify_body_transactions(&vh.header, body)?;
                if receipts.len() != body.transactions.len() {
                    return Err(format!(
                        "block {}: {} receipts for {} transactions",
                        vh.header.number,
                        receipts.len(),
                        body.transactions.len()
                    ));
                }
                verify_block_receipts(&vh.header, receipts)?;
                let built = build_block_receipts(&vh.header, vh.hash, body, receipts)?;
                let stored = stored_logs_for_block(&built)
                    .ok_or("malformed log field in verified receipts")?;
                // Pre-filter: buffer only logs the captured watch-list will
                // store (the fingerprint recheck below discards the batch if
                // the config changed, so filtering against the snapshot is
                // safe) — transient memory stays proportional to stored logs.
                let watched: Vec<crate::el::logindex::StoredLog> =
                    stored.into_iter().filter(|l| config.watches(l)).collect();
                if !watched.is_empty() {
                    logs_by_block.insert(vh.header.number, watched);
                }
            }
            if let Some(stop) = chunk_stop {
                self.log_index_pipeline_full
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                stop_below = Some(stop);
                tracing::debug!(
                    served = usable,
                    requested = chunk.len(),
                    resume_at = stop,
                    "backfill chunk truncated by peer response budget; applying partial batch"
                );
                break 'chunks;
            }
        }
        if stop_below.is_none() && !candidates.is_empty() {
            // Whole candidate set served untruncated — this range rewards
            // pipelining; restore full depth for the next batch. (A bloom-empty
            // batch is no evidence either way and leaves the depth alone.)
            self.log_index_pipeline_full
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Apply top-down (the response is already descending) so every block
        // adjoins the low edge; the trust edge advances with each block. A
        // truncated chunk caps the applied span ABOVE the first unprocessed
        // candidate — partial progress, never a lying coverage claim.
        match self.log_index.lock() {
            Ok(mut slot) => {
                let Some(ix) = slot.as_mut() else {
                    return Err("log index uninstalled mid-batch".to_string());
                };
                // The batch ran across several awaits; a concurrent
                // set_log_index_config may have replaced the index (fresh
                // cursor None, empty spans that would accept ANY block). Our
                // candidates were bloom-selected against the OLD watch-list —
                // applying them to a new one would claim coverage for blocks
                // whose new-address logs were "definitively" skipped. Bail
                // unless both the trust edge and the config are the ones this
                // batch was computed against.
                if ix.cursor != Some((cur_n, cur_hash)) || ix.config().fingerprint() != fingerprint {
                    return Err("index changed mid-batch; recomputing next tick".to_string());
                }
                for vh in new_blocks {
                    let n = vh.header.number;
                    if !should_apply(n, stop_below) {
                        break; // unprocessed candidate — resume here next tick
                    }
                    let logs = logs_by_block.remove(&n).unwrap_or_default();
                    ix.backfill_block(n, vh.hash, logs)
                        .map_err(|g| format!("backfill gap at {} (edge {})", g.block, g.edge))?;
                }
                Ok(())
            }
            Err(_) => Err("log index lock poisoned".to_string()),
        }
    }

    /// Rolling backfill throughput in blocks/second (EMA over recent steps),
    /// `None` until the walker has made measurable progress this run. Feeds
    /// the status JSON's ETA; diagnostic only — never used for control flow.
    pub fn log_index_rate_bps(&self) -> Option<f64> {
        // The anchor instant is the LAST PROGRESS time: a stalled walk would
        // otherwise keep reporting its old rate (and a confident ETA) for
        // hours. After 60s without progress the rate is withheld and the
        // hosts fall back to the x/y display.
        const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
        self.log_index_rate
            .lock()
            .ok()
            .and_then(|r| *r)
            .filter(|(t, _, ema)| *ema > 0.0 && t.elapsed() < STALE_AFTER)
            .map(|(_, _, ema)| ema)
    }

    /// Run `f` against the index if one is configured. The single accessor
    /// for queries and status — callers never touch the lock directly.
    pub fn with_log_index<T>(&self, f: impl FnOnce(&crate::el::logindex::LogIndex) -> T) -> Option<T> {
        match self.log_index.lock() {
            Ok(slot) => slot.as_ref().map(f),
            Err(_) => None,
        }
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

    /// Live-adjust the eth/69 served-block window (Settings knob).
    pub fn set_served_block_window(&self, blocks: u64) {
        self.pool.set_served_block_window(blocks);
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
        // Tor mode (docs/privacy-and-tor.md): route this read — the §1 "core
        // leak" flow — over a per-address isolated Tor circuit instead of the
        // pool's clearnet connections. Fail-closed if no aged peer is available.
        #[cfg(feature = "tor")]
        if crate::el::tor::is_enabled() {
            return self.get_account_over_tor(address).await;
        }
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
        Ok(self.build_verified_account(address, state_root, block_number, outcome, verdict))
    }

    /// Assemble a `VerifiedAccount` from the proof-verified outcome + the beacon
    /// anchor verdict + the reader's live anchor diagnostics. Shared by the
    /// clearnet ([`get_account_from`]) and Tor read paths so the verdict/trust
    /// fields are identical regardless of transport.
    fn build_verified_account(
        &self,
        address: [u8; 20],
        state_root: [u8; 32],
        block_number: u64,
        outcome: AccountOutcome,
        verdict: crate::el::verify::Verdict,
    ) -> VerifiedAccount {
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
        result
    }

    /// Tor read path for [`get_account`]: dial a per-address ISOLATED Tor circuit
    /// with a FRESH ephemeral RLPx identity (docs §3/§6.1) to a peer the pool
    /// already validated on clearnet, and run the identical fetch + beacon-anchor
    /// verdict as the clearnet path. Fails CLOSED when no such peer is available
    /// — never silently falls back to a clearnet dial (docs §5).
    #[cfg(feature = "tor")]
    async fn get_account_over_tor(&self, address: [u8; 20]) -> Result<VerifiedAccount, String> {
        // Candidate identities: peers this reader's pool discovered & validated
        // over clearnet (addr + enode pubkey), snap-serving-quality first (the
        // pool orders them). We reuse only their IDENTITY; the dial itself is a
        // fresh Tor circuit with an ephemeral node key, so the peer never sees our
        // real IP or our persistent node key.
        //
        // KNOWN LIMITATION (docs §5): `snap_peers()` returns peers we hold a LIVE
        // clearnet connection to right now, so the Tor circuit reaches a node that
        // simultaneously sees our real IP — a peer could pair the two by timing +
        // the (rare) client fingerprint (§6.3). The design's fix is the quarantined,
        // AGED, multi-source-promoted Tor pool (§5) that dials only peers we are NOT
        // currently clearnet-connected to; that sidecar is out of scope for this
        // experimental v1 and tracked as the follow-up.
        //
        // Bound the fan-out: each Tor dial is
        // slow and many peers reject Tor-exit inbound, so cap the candidates AND
        // the whole read, or one balance query could hang the FFI call for minutes
        // (a bad-exit walk); fail-closed on the deadline.
        let candidates: Vec<(std::net::SocketAddr, [u8; 64])> = self
            .pool
            .snap_peers()
            .await
            .iter()
            .take(TOR_MAX_CANDIDATES)
            .map(|p| (p.addr(), p.peer_pubkey()))
            .collect();
        if candidates.is_empty() {
            return Err("tor: no clearnet-validated snap peer to dial over Tor (fail-closed)".into());
        }
        let deadline = tokio::time::Instant::now() + TOR_READ_DEADLINE;
        let mut fallback: Option<VerifiedAccount> = None;
        let mut last_err = String::new();
        for (addr, pubkey) in candidates {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                last_err = "tor read deadline exceeded".to_string();
                break;
            }
            // Bound each candidate's whole dial+read by the remaining budget.
            let attempt = async {
                let mut session =
                    crate::el::tor::open_snap_session(&address, addr, pubkey, &self.eth_cfg).await?;
                self.account_from_tor_session(&mut session, address).await
            };
            // NB deliberately NO record_snap_served/record_snap_failure here: those
            // feed the SHARED, persisted clearnet peer-quality cache, and a peer
            // that rejects Tor-exit inbound (a Tor property) is not a bad CLEARNET
            // snap peer — striking it would poison clearnet dialing on the next run.
            // Tor-side peer quality belongs in the Tor sidecar (docs §5), a follow-up.
            match tokio::time::timeout(remaining, attempt).await {
                Ok(Ok(result)) => {
                    if result.verify_method.is_some() || is_global_fail(result.fail_reason) {
                        return Ok(result);
                    }
                    fallback.get_or_insert(result);
                }
                Ok(Err(e)) => last_err = e,
                Err(_) => last_err = format!("tor dial to {addr} exceeded the read budget"),
            }
        }
        fallback.map(Ok).unwrap_or_else(|| {
            Err(format!("tor: all snap-peer dials failed to serve a verifiable account: {last_err}"))
        })
    }

    /// One account fetch + beacon verdict over an already-connected Tor
    /// [`EthSession`] (the [`get_account_from`] twin for the one-shot Tor path).
    #[cfg(feature = "tor")]
    async fn account_from_tor_session(
        &self,
        session: &mut crate::el::eth::session::EthSession<arti_client::DataStream>,
        address: [u8; 20],
    ) -> Result<VerifiedAccount, String> {
        let (state_root, block_number) = fresh_head_session(session).await?;
        let outcome = session.snap_get_account(&state_root, &address).await?;
        let verdict = session
            .verified_state_root(&self.anchor, &state_root, to_ladder_block(block_number), true)
            .await;
        Ok(self.build_verified_account(address, state_root, block_number, outcome, verdict))
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
        self.eth_call_overridden(from, to, data, value, chain_id, Default::default()).await
    }

    /// `eth_call` with NO `to` — contract creation. The init code runs and its
    /// return data is the answer (the deployless `Deploy` form wallets use).
    pub async fn eth_call_create(
        &self,
        from: Option<[u8; 20]>,
        init_code: Vec<u8>,
        value: U256,
        chain_id: u64,
        overrides: myotis_evm::overrides::StateOverrides,
    ) -> Result<CallOutcome, String> {
        let (ctx, executor) = self.evm_setup(chain_id, "eth_call (create)").await?;
        let joined = tokio::task::spawn_blocking(move || {
            let sender = from.unwrap_or([0u8; 20]);
            executor.create_view(sender, &init_code, value, &ctx, overrides)
        })
        .await
        .map_err(|e| format!("eth_call task join error: {e}"))?;
        Ok(match joined {
            Ok(bytes) => CallOutcome::Success(bytes),
            Err(EvmError::Reverted { data }) => CallOutcome::Revert(data),
            Err(other) => CallOutcome::Unavailable(other.to_string()),
        })
    }

    /// [`Self::eth_call`] with caller-supplied state overrides applied for this
    /// call only (see `myotis_evm::overrides`). The answer is what the call
    /// WOULD return under the caller's hypothesis — verified state underneath,
    /// but not itself a chain fact, so hosts label it distinctly.
    pub async fn eth_call_overridden(
        &self,
        from: Option<[u8; 20]>,
        to: [u8; 20],
        data: Vec<u8>,
        value: U256,
        chain_id: u64,
        overrides: myotis_evm::overrides::StateOverrides,
    ) -> Result<CallOutcome, String> {
        let (ctx, executor) = self.evm_setup(chain_id, "eth_call").await?;
        // Run the SYNCHRONOUS executor off the runtime worker so the oracle's
        // per-fetch `block_on` is a fresh (non-nested) runtime entry.
        let joined = tokio::task::spawn_blocking(move || {
            // A from-less call still honours `value` — the default sender is the zero
            // ADDRESS, not zero value — so always thread `value` through
            // call_view_from (call_view would force value = 0 and drop it).
            let sender = from.unwrap_or([0u8; 20]);
            executor.call_view_overridden(sender, to, &data, value, &ctx, overrides)
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
        let Some(block) = self.get_block_by_number(Some(fin.block_number), false).await? else {
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
        let Some(block) = self.get_block_by_number(None, false).await? else {
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

    /// Verified `eth_getBlockByNumber`. `target` is the block number, or `None`
    /// for the latest (the beacon optimistic head); `full_transactions` selects
    /// fully decoded tx objects (incl. the recovered sender) instead of hashes —
    /// an undecodable tx inside the verified body fails the serve (`Err`), never
    /// a silent hash fallback.
    ///
    /// Returns `Ok(Some(block))` when a block is fetched and verified; `Ok(None)`
    /// for a number ABOVE the verified head (a future/unknown block → eth `null`);
    /// and `Err` when it can't verify right now (no anchor, too far back, or every
    /// peer failed → the host maps this to an error the router surfaces as -32000).
    pub async fn get_block_by_number(
        &self,
        target: Option<u64>,
        full_transactions: bool,
    ) -> Result<Option<VerifiedBlock>, String> {
        let (head_num, head_hash) = self.anchored_head()?;
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
            match self.get_block_from(peer, target_num, back, &head_hash, full_transactions).await
            {
                Ok(block) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(Some(block));
                }
                // The body root-verified but a tx inside it doesn't decode: the
                // peer served CORRECT data and every peer would serve the same
                // bytes — rendering it is our failure. Credit the peer and stop
                // (retrying the pool would just re-download the block N times
                // and burn the shared snap reputation on verified-good peers).
                Err(BlockFromError::Undecodable(e)) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Err(e);
                }
                Err(BlockFromError::Peer(e)) => {
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
    /// header's `transactions_root`. A [`BlockFromError::Peer`] (mismatch /
    /// transport) is this peer's failure — the caller loop tries the next one;
    /// a [`BlockFromError::Undecodable`] is deterministic across peers and must
    /// short-circuit the loop.
    async fn get_block_from(
        &self,
        peer: &ManagedPeer,
        target_num: u64,
        back: u64,
        head_hash: &[u8; 32],
        full_transactions: bool,
    ) -> Result<VerifiedBlock, BlockFromError> {
        // The contiguous forward window [target .. head] (back + 1 headers), in one
        // request. back < BLOCK_LOOKBACK_MAX (256) bounds this to ~150 KB, within the
        // eth response soft limit; a peer that caps its response below back+1 fails
        // the anchored-window length check and is skipped (fails closed — the caller
        // tries the next peer), so deep pins carry a slightly higher liveness risk
        // than a batched fetch would. The common case (latest / a few blocks back) is
        // one small response.
        let window = fetch_anchored_window(peer, target_num, back + 1, head_hash)
            .await
            .map_err(BlockFromError::Peer)?;
        let vh = &window[0];
        // Body: verify its transactions against the (now trusted) transactions_root.
        let bodies = peer.get_block_bodies(&[vh.hash]).await.map_err(BlockFromError::Peer)?;
        let body = bodies
            .into_iter()
            .next()
            .ok_or_else(|| BlockFromError::Peer("peer returned no block body".to_string()))?;
        verify_body_transactions(&vh.header, &body).map_err(BlockFromError::Peer)?;
        let tx_hashes: Vec<[u8; 32]> = body.transactions.iter().map(|t| keccak256(t)).collect();
        // Full mode: decode every tx of the (root-verified) body. Strict, like
        // the Java buildBlockJson: found-but-unrenderable fails the serve.
        let full = if full_transactions {
            let mut out = Vec::with_capacity(body.transactions.len());
            for (i, raw_tx) in body.transactions.iter().enumerate() {
                let tx = tx::decode_summary(raw_tx).ok_or_else(|| {
                    BlockFromError::Undecodable(format!(
                        "block {} has an undecodable tx at index {i}",
                        vh.header.number
                    ))
                })?;
                out.push(VerifiedTransaction {
                    tx_hash: tx_hashes[i],
                    tx_index: i as u64,
                    block_hash: vh.hash,
                    block_number: vh.header.number,
                    tx,
                });
            }
            Some(out)
        } else {
            None
        };
        // Remember the fully verified hash↔number so eth_getBlockByHash resolves
        // it (the Java rpcGetBlockByNumber does the same).
        self.remember_block_number(vh.hash, vh.header.number);
        Ok(VerifiedBlock {
            hash: vh.hash,
            header: vh.header.clone(),
            tx_hashes,
            full_transactions: full,
        })
    }

    /// Verified fee suggestion (`eth_gasPrice` + `eth_maxPriorityFeePerGas`). Samples
    /// the last `TIP_SUGGEST_BLOCKS` beacon-anchored blocks: median per-tx effective
    /// tip (floored at the network's `min_suggested_tip_wei`) as the priority fee, and next-block
    /// base fee + that tip as the legacy gas price. `Err` when it can't verify.
    pub async fn fee_estimate(&self) -> Result<FeeEstimate, String> {
        let (head_num, head_hash) = self.anchored_head()?;
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
            verify_body_transactions(&vh.header, body)?;
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

    /// Verified `eth_feeHistory` (the Java `rpcFeeHistory` twin). `newest_block`
    /// `None` = the latest tag (the beacon-anchored head); `reward_percentiles`
    /// `None` omits the reward matrix (its per-block cost is a verified body +
    /// receipts fetch). `block_count` is clamped to [`FEE_HISTORY_MAX_BLOCKS`];
    /// the result reflects what was served.
    ///
    /// The error carries the Java tri-state split: a [`FeeHistoryError::Reject`]
    /// is a bad request AGAINST THE CURRENT HEAD (Java answers these -32000,
    /// never stale); a [`FeeHistoryError::Build`] is a transport/verify failure
    /// the host may answer from its last-good same-signature snapshot.
    pub async fn fee_history(
        &self,
        block_count: u64,
        newest_block: Option<u64>,
        reward_percentiles: Option<&[f64]>,
    ) -> Result<FeeHistory, FeeHistoryError> {
        if block_count == 0 {
            return Err(FeeHistoryError::Reject("blockCount must be at least 1".to_string()));
        }
        // No anchor yet is a BUILD failure (Java's `anchor == null` path also
        // falls to the stale-serve), unlike the request rejects below.
        let (head_num, head_hash) = self.anchored_head().map_err(FeeHistoryError::Build)?;
        let newest = newest_block.unwrap_or(head_num);
        if newest > head_num {
            return Err(FeeHistoryError::Reject(
                "newest block is beyond the verified head".to_string(),
            ));
        }
        let count = block_count.min(FEE_HISTORY_MAX_BLOCKS).min(newest + 1);
        let oldest = newest + 1 - count;
        if head_num - oldest >= BLOCK_LOOKBACK_MAX {
            return Err(FeeHistoryError::Reject(format!(
                "oldest block {oldest} is beyond the {BLOCK_LOOKBACK_MAX}-block verify window"
            )));
        }
        self.fee_history_build(oldest, count, head_num, &head_hash, reward_percentiles)
            .await
            .map_err(FeeHistoryError::Build)
    }

    /// The peer-failover build stage of [`Self::fee_history`] (every error here
    /// is a BUILD failure — the bounds were already accepted).
    async fn fee_history_build(
        &self,
        oldest: u64,
        count: u64,
        head_num: u64,
        head_hash: &[u8; 32],
        reward_percentiles: Option<&[f64]>,
    ) -> Result<FeeHistory, String> {
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            let attempt = tokio::time::timeout(
                FEE_HISTORY_DEADLINE,
                self.fee_history_from(peer, oldest, count, head_num, head_hash, reward_percentiles),
            )
            .await
            .unwrap_or_else(|_| Err("feeHistory build timed out".to_string()));
            match attempt {
                Ok(history) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(history);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve a verifiable feeHistory: {last_err}"))
    }

    /// Build the fee history against one peer: one anchored window
    /// `[oldest..head]` (the span past `newest` is what anchors it — and gives
    /// the ACTUAL next-block base fee), then, when percentiles were requested,
    /// every block's body + receipts fetched CONCURRENTLY (the Java pipelined
    /// `verifiedBlockTipsAsync` — sequential per-block round-trips blew the
    /// wallet's fee-poll timeout) and verified against `transactionsRoot` /
    /// `receiptsRoot` before any tip is trusted.
    async fn fee_history_from(
        &self,
        peer: &ManagedPeer,
        oldest: u64,
        count: u64,
        head_num: u64,
        head_hash: &[u8; 32],
        reward_percentiles: Option<&[f64]>,
    ) -> Result<FeeHistory, String> {
        let window_len = head_num - oldest + 1;
        let window = fetch_anchored_window(peer, oldest, window_len, head_hash).await?;
        let count = count as usize;

        let mut base_fee_per_gas: Vec<u128> =
            window[..count].iter().map(|vh| header_base_fee(&vh.header)).collect();
        // Entry count+1: the next block after `newest` — its actual base fee
        // when the window extends past newest, else the EIP-1559 prediction.
        base_fee_per_gas.push(if count < window.len() {
            header_base_fee(&window[count].header)
        } else {
            next_base_fee(&window[count - 1].header)
        });

        let gas_used_ratio: Vec<f64> = window[..count]
            .iter()
            .map(|vh| {
                let h = &vh.header;
                if h.gas_limit > 0 { h.gas_used as f64 / h.gas_limit as f64 } else { 0.0 }
            })
            .collect();

        let reward = match reward_percentiles {
            None => None,
            Some(percentiles) => {
                // All bodies + receipts in flight at once on this peer's
                // multiplexed connection; one slowest-block round-trip of
                // wall-clock instead of 2×count sequential ones.
                let per_block = futures::future::join_all(window[..count].iter().map(|vh| {
                    let hash = [vh.hash];
                    async move {
                        let (bodies, receipts) = futures::future::join(
                            peer.get_block_bodies(&hash),
                            peer.get_receipts(&hash),
                        )
                        .await;
                        (bodies, receipts)
                    }
                }))
                .await;
                let mut rows = Vec::with_capacity(count);
                for (vh, (bodies, receipts)) in window[..count].iter().zip(per_block) {
                    let tips = block_tx_tips(&vh.header, bodies?, receipts?)?;
                    rows.push(percentile_rewards(tips, percentiles));
                }
                Some(rows)
            }
        };

        Ok(FeeHistory { oldest_block: oldest, base_fee_per_gas, gas_used_ratio, reward })
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
        // The sent-tx watch (the Java rpcSendRawTransaction tail, mirrored):
        // cache the bytes for rebroadcast, record the sender's pending nonce
        // (best-effort — an undecodable/senderless tx is silently skipped),
        // and start watching with the head recorded AT BROADCAST — the beacon
        // OPTIMISTIC number (the Java broadcastHead source), which the receipt
        // scan's reachback uses as its floor for our own txs.
        let now = std::time::Instant::now();
        let broadcast_head = match self.anchor.optimistic_block_number() {
            0 => None,
            n => Some(n),
        };
        {
            let mut st = self.sent_txs.lock().unwrap();
            st.bytes.put(hash, raw_tx.to_vec());
            if let Some(t) = tx::decode_summary(raw_tx) {
                if let Some(from) = t.from {
                    st.pending_nonces.record(from, t.nonce, now);
                }
            }
        }
        self.sent_tx_watch.lock().unwrap().watch(hash, now, broadcast_head);
        Ok(hash)
    }

    /// The "pending" nonce overlay (the Java `pendingNonceOverlay` twin): raise
    /// the verified mined count to `our nonce + 1` while our own broadcast is
    /// unmined and unexpired. Identity for every other caller. Only the
    /// `pending` tag may consult this — never settled tags.
    pub fn pending_nonce_overlay(&self, sender: &[u8; 20], mined_count: u64) -> u64 {
        let mut st = self.sent_txs.lock().unwrap();
        st.pending_nonces.overlay(sender, mined_count, std::time::Instant::now())
    }

    /// Time-gated rebroadcast of our own not-yet-seen txs (the Java
    /// `rebroadcastPendingTxs` behind its 20 s gate). Piggybacks on the
    /// wallet's poll paths (see [`TX_REBROADCAST_INTERVAL`]); evicts expired
    /// watches first. The peer writes happen OUTSIDE the state lock.
    async fn maybe_rebroadcast_sent_txs(&self) {
        let now = std::time::Instant::now();
        let unseen = {
            let mut watch = self.sent_tx_watch.lock().unwrap();
            if !watch.watching_any() {
                return;
            }
            watch.evict_expired(now);
            watch.unseen()
        };
        let work: Vec<Vec<u8>> = {
            let mut st = self.sent_txs.lock().unwrap();
            if now.saturating_duration_since(st.last_rebroadcast) < TX_REBROADCAST_INTERVAL {
                return;
            }
            st.last_rebroadcast = now;
            unseen
                .iter()
                // Bytes aged out of the LRU → nothing to push (Java parity).
                .filter_map(|h| st.bytes.get(h).cloned())
                .collect()
        };
        if work.is_empty() {
            return;
        }
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return;
        }
        // DETACHED, like the Java warmer thread: the wallet's receipt poll
        // carries the trigger but must never wait on the pushes — a wedged
        // peer (writer lock held, full send buffer) would otherwise freeze
        // the confirm loop. Bounded per write; peers are owned Arcs.
        tokio::spawn(async move {
            let count = work.len();
            for raw in work {
                let sends = peers.iter().map(|peer| {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        peer.send_transaction(&raw),
                    )
                });
                futures::future::join_all(sends).await;
            }
            tracing::debug!("rebroadcast {} sent tx(s) to {} peer(s)", count, peers.len());
        });
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
        // The wallet's post-send confirm loop polls exactly this — the natural
        // carrier for the time-gated sent-tx rebroadcast (see the interval doc).
        self.maybe_rebroadcast_sent_txs().await;
        let (head_num, head_hash) = self.anchored_head()?;
        let Some(loc) = self.locate_mined_tx(tx_hash, head_num, &head_hash).await? else {
            return Ok(None); // verified "not seen" in the scanned coverage → eth null
        };

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
            match self.receipt_from(peer, &loc).await {
                Ok(vr) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    // A verified receipt IS inclusion — the watch is done
                    // (the Java rpcGetTransactionReceipt's confirmMined).
                    self.sent_tx_watch.lock().unwrap().confirm_mined(&tx_hash);
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

    /// Verified `eth_getTransactionByHash` — the same beacon-anchored,
    /// `transactionsRoot`-verified locate as the receipt path, followed by the
    /// full tx decode (Java `rpcGetTransactionByHash`/`buildTxJson`).
    ///
    /// Returns `Ok(Some)` when found+verified; `Ok(None)` for a verified "not
    /// seen" (an unknown/pending tx — eth's null; the Java engine additionally
    /// answers "pending" for its OWN just-sent txs from the sent-tx cache,
    /// which lands with the sent-tx slice); `Err` when it can't verify right
    /// now, INCLUDING a located tx whose type the decoder doesn't know — the tx
    /// exists, so "can't render it" must never read as "unknown tx" (the Java
    /// buildTxJson-null convention).
    pub async fn get_transaction_by_hash(&self, tx_hash: [u8; 32]) -> Result<TxLookup, String> {
        self.maybe_rebroadcast_sent_txs().await;
        // Anchor loss must not hide the wallet's OWN broadcast (Java parity:
        // locateMinedTx answers null on a missing anchor and the sentTxCache
        // check still runs): a send needs only peers, not an anchor, and the
        // confirm loop starts polling immediately — serve pending, not -32000.
        let (head_num, head_hash) = match self.anchored_head() {
            Ok(v) => v,
            Err(e) => {
                let mut st = self.sent_txs.lock().unwrap();
                if let Some(raw) = st.bytes.get(&tx_hash) {
                    let tx = tx::decode_summary(raw)
                        .ok_or("own sent tx cached but cannot be decoded")?;
                    return Ok(TxLookup::Pending { tx_hash, tx });
                }
                return Err(e);
            }
        };
        let Some(loc) = self.locate_mined_tx(tx_hash, head_num, &head_hash).await? else {
            // Not in the scanned chain — but if it is OUR broadcast, answer the
            // pending shape from the cached bytes (the Java sentTxCache path):
            // the wallet sees its tx exists while it awaits inclusion.
            let mut st = self.sent_txs.lock().unwrap();
            if let Some(raw) = st.bytes.get(&tx_hash) {
                let tx = tx::decode_summary(raw)
                    .ok_or("own sent tx cached but cannot be decoded")?;
                return Ok(TxLookup::Pending { tx_hash, tx });
            }
            return Ok(TxLookup::NotSeen);
        };
        // Located in a verified block: the watch is done with this tx.
        self.sent_tx_watch.lock().unwrap().confirm_mined(&tx_hash);
        let tx = tx::decode_summary(&loc.raw_tx)
            .ok_or("transaction located but its type cannot be decoded")?;
        Ok(TxLookup::Mined(VerifiedTransaction {
            tx_hash,
            tx_index: loc.index as u64,
            block_hash: loc.block_hash,
            block_number: loc.header.number,
            tx,
        }))
    }

    /// Verified `eth_getBlockByHash` (transactions as hashes). Wallets call it
    /// right after a receipt to finalize a tx as confirmed, so the hash is
    /// resolved from blocks this reader has ALREADY verified (the receipt scan
    /// and the by-number serve populate the map), then served via the verified
    /// by-number path, re-confirming the served block still carries the
    /// requested hash (a reorg can remap the height). A hash never verified →
    /// `Ok(None)` (eth's unknown-block null) — the confirm flow always
    /// pre-populates it via the preceding receipt. Twin of the Java
    /// `rpcGetBlockByHash`.
    pub async fn get_block_by_hash(
        &self,
        block_hash: [u8; 32],
        full_transactions: bool,
    ) -> Result<Option<VerifiedBlock>, String> {
        let Some(number) = self.lookup_block_number(&block_hash) else {
            return Ok(None); // not a block we've verified — unknown to us
        };
        match self.get_block_by_number(Some(number), full_transactions).await? {
            Some(block) if block.hash == block_hash => Ok(Some(block)),
            // The height serves a DIFFERENT canonical block now (reorg) — or the
            // number sits above the current head: the requested hash is unknown.
            _ => Ok(None),
        }
    }

    /// Verified `eth_getBlockReceipts` by number/tag (`None` = latest): every
    /// receipt of the block, each carrying the same verified fields as
    /// [`Self::get_transaction_receipt`] (the Java `rpcGetBlockReceipts` twin).
    /// `Ok(None)` = a verified future/unknown block (eth's null).
    pub async fn get_block_receipts(
        &self,
        target: Option<u64>,
    ) -> Result<Option<Vec<VerifiedReceipt>>, String> {
        Ok(self.block_receipts_at(target).await?.map(|(_, receipts)| receipts))
    }

    /// Verified `eth_getBlockReceipts` by block hash: resolves through the
    /// verified hash→number map (a never-verified hash → `Ok(None)`) and
    /// re-confirms the block served at that height still carries the requested
    /// hash (a reorg can remap the number under a stale map entry).
    pub async fn get_block_receipts_by_hash(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<Vec<VerifiedReceipt>>, String> {
        let Some(number) = self.lookup_block_number(&block_hash) else {
            return Ok(None); // not a block we've verified — unknown to us
        };
        match self.block_receipts_at(Some(number)).await? {
            Some((served, receipts)) if served == block_hash => Ok(Some(receipts)),
            _ => Ok(None),
        }
    }

    /// The shared block-receipts serve: anchored window → target header, body +
    /// receipts fetched together (one round of wall-clock) and root-verified,
    /// then one pass building every receipt. Returns the SERVED block hash so
    /// the by-hash entry can re-confirm it.
    async fn block_receipts_at(
        &self,
        target: Option<u64>,
    ) -> Result<Option<([u8; 32], Vec<VerifiedReceipt>)>, String> {
        let (head_num, head_hash) = self.anchored_head()?;
        let target_num = target.unwrap_or(head_num);
        if target_num > head_num {
            return Ok(None); // future/unknown block → eth null
        }
        let back = head_num - target_num;
        if back >= BLOCK_LOOKBACK_MAX {
            return Err(format!(
                "block {target_num} is {back} behind the head — beyond the {BLOCK_LOOKBACK_MAX}-block verify window"
            ));
        }
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            match self.block_receipts_from(peer, target_num, back, &head_hash).await {
                Ok(served) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(Some(served));
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!(
            "all {total} snap peer(s) failed to serve verifiable block receipts: {last_err}"
        ))
    }

    /// One peer's block-receipts serve: anchored window, body + receipts in
    /// flight together, both roots verified before anything is trusted.
    async fn block_receipts_from(
        &self,
        peer: &ManagedPeer,
        target_num: u64,
        back: u64,
        head_hash: &[u8; 32],
    ) -> Result<([u8; 32], Vec<VerifiedReceipt>), String> {
        let window = fetch_anchored_window(peer, target_num, back + 1, head_hash).await?;
        let vh = &window[0];
        let (bodies, receipt_blocks) = futures::future::join(
            peer.get_block_bodies(&[vh.hash]),
            peer.get_receipts(&[vh.hash]),
        )
        .await;
        let body = bodies?.into_iter().next().ok_or("peer returned no block body")?;
        verify_body_transactions(&vh.header, &body)?;
        let receipts = receipt_blocks?.into_iter().next().ok_or("peer returned no receipts")?;
        if receipts.len() != body.transactions.len() {
            return Err(format!(
                "block {} receipt count mismatch ({} receipts for {} txs)",
                vh.header.number,
                receipts.len(),
                body.transactions.len()
            ));
        }
        verify_block_receipts(&vh.header, &receipts)?;
        // Remember the fully verified hash↔number (feeds getBlockByHash and the
        // by-hash entry of this method).
        self.remember_block_number(vh.hash, vh.header.number);
        let built = build_block_receipts(&vh.header, vh.hash, &body, &receipts)?;
        Ok((vh.hash, built))
    }

    /// Look a block hash up in the verified hash→number map (LRU-refreshing).
    /// `None` = we never verified that hash. Poisoning is unreachable
    /// (panic="abort"); read as a miss rather than propagate.
    fn lookup_block_number(&self, block_hash: &[u8; 32]) -> Option<u64> {
        self.block_hash_numbers.lock().ok()?.get(block_hash).copied()
    }

    /// Remember a VERIFIED block hash↔number for `eth_getBlockByHash`.
    fn remember_block_number(&self, block_hash: [u8; 32], number: u64) {
        if let Ok(mut lru) = self.block_hash_numbers.lock() {
            lru.put(block_hash, number);
        }
    }

    /// The beacon-anchored optimistic head `(number, hash)`, or the standard
    /// not-ready errors every verified read shares.
    fn anchored_head(&self) -> Result<(u64, [u8; 32]), String> {
        let head_num = self.anchor.optimistic_block_number();
        let Some(head_hash) = self.anchor.optimistic_block_hash() else {
            return Err("no beacon-anchored head yet".to_string());
        };
        if head_num == 0 {
            return Err("beacon not synced".to_string());
        }
        Ok((head_num, head_hash))
    }

    /// The shared locate stage (the Java `locateMinedTx` twin): resolve the tx
    /// hash to its verified block location via the per-tx incremental scan
    /// cursor. Holds the tx's cursor lock for the duration (concurrent polls
    /// for the SAME tx serialize here and only here); returns a clone of the
    /// cached/found location.
    async fn locate_mined_tx(
        &self,
        tx_hash: [u8; 32],
        head_num: u64,
        head_hash: &[u8; 32],
    ) -> Result<Option<Arc<TxLocation>>, String> {
        let state = self.tx_scan_state(tx_hash)?;
        let mut st = state.lock().await;
        st.last_touched = std::time::Instant::now();

        // A cached location below the finalized height is immutable; one still
        // near the head must be re-confirmed canonical (it can be reorged out).
        if let Some(loc) = &st.found {
            let finalized = self.finalized_block_number();
            let immutable = finalized > 0 && loc.header.number <= finalized;
            if !immutable && !self.still_canonical(loc, head_num, head_hash).await {
                // Proven reorged out: rescan the recent region from scratch.
                st.found = None;
                st.high_scanned = None;
            }
        }

        if st.found.is_none() {
            // A short reorg can pull the optimistic head BELOW an
            // already-scanned height — everything scanned above the new head
            // was replaced, and the fork may reach a few blocks deeper. Reset
            // the cursor for a fresh initial-lookback scan (covers forks up to
            // that depth past the new head); merely clamping to the new head
            // would leave `from = head + 1` and never rescan the replacement
            // head block itself, so a tx mined there would keep reading as a
            // verified "not seen".
            if st.high_scanned.is_some_and(|high| high > head_num) {
                st.high_scanned = None;
            }
            let mut from = match st.high_scanned {
                None => {
                    let mut first = head_num.saturating_sub(RECEIPT_INITIAL_LOOKBACK_BLOCKS - 1);
                    // Own-tx reachback (the Java locateMinedTx twin): the FIRST
                    // scan for a tx WE broadcast reaches back to the head
                    // recorded at broadcast time — a tx mined right after a
                    // slow broadcast can sit below the default lookback. Still
                    // subject to the per-poll cap below.
                    if let Some(bc_head) = self.sent_tx_watch.lock().unwrap().broadcast_head(&tx_hash)
                    {
                        if bc_head < first {
                            first = bc_head;
                        }
                    }
                    first
                }
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
                let found = self.scan_window(from, head_num, head_hash, &tx_hash).await?;
                // Advance the cursor only after a fully verified scan of
                // [from..head] (found or not) — an Err above leaves it put.
                st.high_scanned = Some(head_num);
                st.found = found.map(Arc::new);
            }
        }

        // The cursor is settled; the lock releases at return, BEFORE any
        // follow-up round-trips (the Java twin's synchronized block also ends
        // at locateMinedTx).
        Ok(st.found.clone())
    }

    /// Run one `[from..head]` scan across the snap pool: try each peer (each
    /// attempt bounded by [`RECEIPT_SCAN_DEADLINE`]) until one serves a fully
    /// verified window, recording served/failure reputation per peer.
    async fn scan_window(
        &self,
        from: u64,
        head_num: u64,
        head_hash: &[u8; 32],
        tx_hash: &[u8; 32],
    ) -> Result<Option<TxLocation>, String> {
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err("no snap peer available".to_string());
        }
        let total = peers.len();
        let mut last_err = String::new();
        for peer in &peers {
            let attempt = tokio::time::timeout(
                RECEIPT_SCAN_DEADLINE,
                self.scan_blocks_from(peer, from, head_num, head_hash, tx_hash),
            )
            .await
            .unwrap_or_else(|_| Err("tx scan timed out".to_string()));
            match attempt {
                Ok(found) => {
                    self.pool.record_snap_served(peer.addr()).await;
                    return Ok(found);
                }
                Err(e) => {
                    self.pool.record_snap_failure(peer.addr()).await;
                    last_err = e;
                }
            }
        }
        Err(format!("all {total} snap peer(s) failed to serve a verifiable tx scan: {last_err}"))
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
            verify_body_transactions(&vh.header, &body)?;
            for (i, raw) in body.transactions.iter().enumerate() {
                if &keccak256(raw) == want {
                    // Pre-populate for the eth_getBlockByHash the wallet issues
                    // right after the receipt (the Java locateMinedTx twin).
                    self.remember_block_number(vh.hash, vh.header.number);
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
    ) -> Result<VerifiedReceipt, String> {
        let blocks = peer.get_receipts(&[loc.block_hash]).await?;
        let receipts = blocks.into_iter().next().ok_or("peer returned no receipts")?;
        if receipts.is_empty() {
            return Err("peer returned no receipts".to_string());
        }
        verify_block_receipts(&loc.header, &receipts)?;
        if loc.index >= receipts.len() {
            return Err("tx index out of receipt range".to_string());
        }
        build_verified_receipt(loc, &receipts)
    }

    /// `(finalized_block_number, optimistic_block_number, is_synced)` snapshot.
    fn anchor_diagnostics(&self) -> (u64, u64, bool) {
        let fin = self.anchor.finalized_execution().map(|f| f.block_number).unwrap_or(0);
        (fin, self.anchor.optimistic_block_number(), self.anchor.is_synced())
    }

    /// Stop discovery + the pool.
    pub async fn stop(self) {
        if let Ok(mut t) = self.log_index_task.lock() {
            if let Some(h) = t.take() {
                h.abort();
            }
        }
        // Best-effort index checkpoint before teardown: a failed write only
        // costs a re-index of the uncheckpointed tail, never correctness.
        self.persist_log_index(self.finalized_block_number());
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
    Ok(build_one_receipt(
        &loc.header,
        loc.block_hash,
        loc.index as u64,
        &loc.raw_tx,
        decoded,
        prev_cum,
        log_index_base,
    ))
}

/// The per-element construction both receipt paths share: the caller supplies
/// the ALREADY-DECODED receipt and the running accumulators (previous
/// cumulative gas, block-global log-index base). The subtle rules live once:
/// the tx decodes DEFENSIVELY (an unknown future type yields a partial receipt,
/// never an error), and only a creation tx with a recovered sender carries a
/// contract address.
fn build_one_receipt(
    header: &BlockHeader,
    block_hash: [u8; 32],
    tx_index: u64,
    raw_tx: &[u8],
    decoded: DecodedReceipt,
    prev_cum: u64,
    log_index_base: u64,
) -> VerifiedReceipt {
    let tx_summary = tx::decode_summary(raw_tx);
    let effective_gas_price =
        tx_summary.as_ref().and_then(|t| tx::effective_gas_price(t, header_base_fee(header)));
    let contract_address = tx_summary.as_ref().and_then(|t| match (&t.to, &t.from) {
        (None, Some(from)) => Some(tx::contract_address(from, t.nonce)),
        _ => None,
    });
    VerifiedReceipt {
        tx_hash: keccak256(raw_tx),
        tx_index,
        block_hash,
        block_number: header.number,
        gas_used: decoded.cumulative_gas_used.saturating_sub(prev_cum),
        log_index_base,
        receipt: decoded,
        tx: tx_summary,
        effective_gas_price,
        contract_address,
    }
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

/// Build EVERY receipt of a ROOT-VERIFIED block in one pass — the batch form of
/// [`build_verified_receipt`]: the running cumulative-gas and the block-global
/// log-index base accumulate instead of being re-derived per index (the
/// single-receipt path's preamble would make a full block O(n²)). The caller
/// has already verified the body against `transactionsRoot`, the receipts
/// against `receiptsRoot`, and their counts equal.
fn build_block_receipts(
    header: &BlockHeader,
    block_hash: [u8; 32],
    body: &crate::el::eth::messages::BlockBody,
    receipts: &[Vec<u8>],
) -> Result<Vec<VerifiedReceipt>, String> {
    let mut out = Vec::with_capacity(receipts.len());
    let mut prev_cum = 0u64;
    let mut log_index_base = 0u64;
    for (i, (raw_tx, receipt)) in body.transactions.iter().zip(receipts).enumerate() {
        let decoded = crate::el::receipt::decode(receipt)?;
        let log_count = decoded.logs.len() as u64;
        let cum = decoded.cumulative_gas_used;
        out.push(build_one_receipt(
            header,
            block_hash,
            i as u64,
            raw_tx,
            decoded,
            prev_cum,
            log_index_base,
        ));
        prev_cum = cum;
        log_index_base += log_count;
    }
    Ok(out)
}

/// The body half of the per-block trust gate: the fetched transactions must
/// rebuild the (already anchored) header's `transactionsRoot`. One
/// implementation for every consumer (block serve, fee estimate, tx scan,
/// fee history), so a hardening never has to be applied in four places.
fn verify_body_transactions(
    header: &BlockHeader,
    body: &crate::el::eth::messages::BlockBody,
) -> Result<(), String> {
    if !triehash::verify(&body.transactions, &header.transactions_root) {
        return Err(format!(
            "block {} body does not match the header transactionsRoot",
            header.number
        ));
    }
    Ok(())
}

/// The receipts half of the per-block trust gate: the fetched receipt list
/// must rebuild the (already anchored) header's `receiptsRoot`.
fn verify_block_receipts(header: &BlockHeader, receipts: &[Vec<u8>]) -> Result<(), String> {
    if !triehash::verify(receipts, &header.receipts_root) {
        return Err(format!(
            "block {} receipts do not match the header receiptsRoot",
            header.number
        ));
    }
    Ok(())
}

/// One block's per-tx `(effective_tip, gas_used)` list from its FETCHED body +
/// receipts, verified against the (already anchored) header's
/// `transactionsRoot` / `receiptsRoot` before anything is trusted (the Java
/// `decodeBlockTips` twin). Strict like Java: an undecodable tx inside a
/// verified body, a receipt-count mismatch, or a failed root fails the block.
fn block_tx_tips(
    header: &BlockHeader,
    bodies: Vec<crate::el::eth::messages::BlockBody>,
    receipt_blocks: Vec<Vec<Vec<u8>>>,
) -> Result<Vec<(u128, u64)>, String> {
    let body = bodies.into_iter().next().ok_or("peer returned no block body")?;
    verify_body_transactions(header, &body)?;
    if body.transactions.is_empty() {
        // A root-verified EMPTY tx list ⇒ the anchored header must carry
        // gasUsed 0 (same strictness as the non-empty path's final-sum check).
        // Receipts are deliberately NOT consulted here — no weights to derive —
        // matching the Java decodeBlockTips early return, and not making a
        // quiet chain's feeHistory depend on how peers answer GetReceipts for
        // zero-tx blocks.
        if header.gas_used != 0 {
            return Err(format!(
                "block {} has no transactions but a non-zero header gasUsed {}",
                header.number, header.gas_used
            ));
        }
        return Ok(Vec::new());
    }
    let receipts = receipt_blocks.into_iter().next().ok_or("peer returned no receipts")?;
    if receipts.len() != body.transactions.len() {
        return Err(format!(
            "block {} receipt count mismatch ({} receipts for {} txs)",
            header.number,
            receipts.len(),
            body.transactions.len()
        ));
    }
    verify_block_receipts(header, &receipts)?;
    let base_fee = header_base_fee(header);
    let mut out = Vec::with_capacity(body.transactions.len());
    let mut prev_cum = 0u64;
    for (raw, receipt) in body.transactions.iter().zip(&receipts) {
        let tip = tx::effective_tip(raw, base_fee)
            .ok_or_else(|| format!("block {} has an undecodable tx", header.number))?;
        let cum = crate::el::receipt::decode(receipt)?.cumulative_gas_used;
        // Strict, like the rest of this path: cumulative gas must be
        // monotonic (a regression is impossible in a consensus-valid block —
        // fail the block rather than silently zero a weight), …
        if cum < prev_cum {
            return Err(format!(
                "block {} receipts have non-monotonic cumulative gas",
                header.number
            ));
        }
        out.push((tip, cum - prev_cum));
        prev_cum = cum;
    }
    // …and the last receipt's cumulative must equal the ANCHORED header's
    // gasUsed (the header field is beacon-anchored; the receipts are
    // root-verified — consensus ties the two together).
    if prev_cum != header.gas_used {
        return Err(format!(
            "block {} receipts' final cumulative gas {} does not match the header gasUsed {}",
            header.number, prev_cum, header.gas_used
        ));
    }
    Ok(out)
}

/// Gas-used-weighted percentile rewards for one block — the Java `rewardJson`
/// twin (geth-derived: sort txs by tip, walk each percentile's threshold over
/// cumulative gasUsed, take that tx's tip; like Java the threshold stays a
/// float where geth truncates it to an integer — an at-most-one-tx boundary
/// nuance). Percentile ordering/range is the router's validation (ascending,
/// 0..=100), same as for the Java backend; the walk's index never rewinds.
/// Empty block → zeros.
fn percentile_rewards(mut tips: Vec<(u128, u64)>, percentiles: &[f64]) -> Vec<u128> {
    if tips.is_empty() {
        return vec![0; percentiles.len()];
    }
    tips.sort_unstable_by_key(|&(tip, _)| tip);
    let total_gas: u64 = tips.iter().map(|&(_, gas)| gas).sum();
    let mut out = Vec::with_capacity(percentiles.len());
    let mut idx = 0usize;
    let mut cum_gas = tips[0].1;
    for &p in percentiles {
        let threshold = total_gas as f64 * p / 100.0;
        while (cum_gas as f64) < threshold && idx < tips.len() - 1 {
            idx += 1;
            cum_gas += tips[idx].1;
        }
        out.push(tips[idx].0);
    }
    out
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

/// Tor twin of [`fresh_head`] over an [`EthSession`] (same head-hash echo check
/// and genesis-head rejection; the state root is beacon-anchored afterwards).
#[cfg(feature = "tor")]
async fn fresh_head_session(
    session: &mut crate::el::eth::session::EthSession<arti_client::DataStream>,
) -> Result<([u8; 32], u64), String> {
    let head_hash = session.peer_status.best_hash;
    let headers = session.get_block_headers_by_hash(&head_hash, 1).await?;
    let head = headers.into_iter().next().ok_or("peer returned no head header")?;
    if head.hash != head_hash {
        return Err("peer returned a header not matching the requested hash".to_string());
    }
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
    fn sepolia_pins_the_dedicated_serving_node_enode() {
        // Twin of the Java NetworkConfigGnosisTest#sepoliaPinsTheDedicatedServingNodeOnBothLayers.
        let cfg = ElConfig::sepolia();
        assert_eq!(cfg.boot_enodes.len(), 1, "sepolia pins the dedicated serving node");
        let (addr, pubkey) = cfg.boot_enodes[0];
        assert_eq!(addr.to_string(), "87.154.209.161:30405");
        assert_eq!(pubkey[0], 0xcf);
        assert_eq!(pubkey[63], 0x2c);
        // The other networks ship none (mainnet/gnosis reach peers via discovery).
        assert!(ElConfig::mainnet().boot_enodes.is_empty());
        assert!(ElConfig::gnosis().boot_enodes.is_empty());
    }

    #[test]
    fn malformed_boot_enodes_are_skipped_not_fatal() {
        assert!(parse_boot_enodes(&["not-an-enode"]).is_empty());
        assert!(parse_boot_enodes(&["enode://short@1.2.3.4:30303"]).is_empty());
        assert!(parse_boot_enodes(&[&format!("enode://{}@nonsense", "ab".repeat(64))]).is_empty());
        // Non-hex in an otherwise well-shaped key.
        assert!(parse_boot_enodes(&[&format!("enode://{}@1.2.3.4:30303", "zz".repeat(64))]).is_empty());
        // Non-ASCII: 64 x "é" is EXACTLY 128 bytes, so it passes a naive length
        // check and would panic (→ abort) when sliced at a non-char boundary.
        assert!(parse_boot_enodes(&[&format!("enode://{}@1.2.3.4:30303", "\u{00e9}".repeat(64))]).is_empty());
        assert_eq!(parse_boot_enodes(&[SEPOLIA_MYOTIS_ENODE]).len(), 1);
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

    #[test]
    fn percentile_rewards_walks_gas_weighted_thresholds() {
        // Three txs, tips 1/5/10 gwei with gas weights 10k/70k/20k (total 100k).
        // Sorted by tip the cumulative gas is 10k, 80k, 100k:
        //   p10 → threshold 10k → cum 10k not < 10k → tip 1
        //   p25 → threshold 25k → advance to cum 80k → tip 5
        //   p90 → threshold 90k → advance to cum 100k → tip 10
        let tips = vec![
            (5_000_000_000u128, 70_000u64),
            (1_000_000_000, 10_000),
            (10_000_000_000, 20_000),
        ];
        assert_eq!(
            percentile_rewards(tips.clone(), &[10.0, 25.0, 90.0]),
            vec![1_000_000_000, 5_000_000_000, 10_000_000_000]
        );
        // 100th percentile lands on the last (highest-tip) tx.
        assert_eq!(percentile_rewards(tips.clone(), &[100.0]), vec![10_000_000_000]);
        // 0th percentile takes the cheapest tx (threshold 0 never advances).
        assert_eq!(percentile_rewards(tips, &[0.0]), vec![1_000_000_000]);
    }

    #[test]
    fn percentile_rewards_empty_block_is_zeros() {
        assert_eq!(percentile_rewards(Vec::new(), &[25.0, 75.0]), vec![0, 0]);
        assert!(percentile_rewards(Vec::new(), &[]).is_empty());
    }

    #[test]
    fn percentile_rewards_zero_gas_weights_serve_the_cheapest_tip() {
        // All-zero gas weights: every threshold is 0, the walk never advances →
        // the cheapest tip for every percentile (mirrors the Java loop's
        // `cumGas < threshold` never firing).
        let tips = vec![(7u128, 0u64), (3, 0)];
        assert_eq!(percentile_rewards(tips, &[50.0, 99.0]), vec![3, 3]);
    }
}

/// Convert one block's [`VerifiedReceipt`]s into stored logs — strictly:
/// `None` on any field that does not have its canonical width, so a caller
/// never records a block whose stored shape differs from what was verified.
fn stored_logs_for_block(receipts: &[VerifiedReceipt]) -> Option<Vec<crate::el::logindex::StoredLog>> {
    let mut out = Vec::new();
    for r in receipts {
        for (k, l) in r.receipt.logs.iter().enumerate() {
            let mut topics = Vec::with_capacity(l.topics.len());
            for t in &l.topics {
                topics.push(t.as_slice().try_into().ok()?);
            }
            out.push(crate::el::logindex::StoredLog {
                block_number: r.block_number,
                block_hash: r.block_hash,
                tx_hash: r.tx_hash,
                tx_index: u32::try_from(r.tx_index).ok()?,
                log_index: u32::try_from(r.log_index_base).ok()?.checked_add(u32::try_from(k).ok()?)?,
                address: l.address.as_slice().try_into().ok()?,
                topics,
                data: l.data.clone(),
            });
        }
    }
    Some(out)
}

/// Whether this run's tail record accounts for ALL coverage above finality.
/// Optimistic coverage is only trustworthy while the tail can re-check it
/// against the canonical chain, which needs the hash of every block it
/// claims; coverage reaching above finality whose top block this run did not
/// record (an index from an older build that persisted its tail, an imported
/// file) must be rewound instead of trusted. Pure — unit-tested.
fn tail_vouches_for(recorded: &[(u64, [u8; 32])], edge: u64, finalized: u64) -> bool {
    if edge <= finalized.saturating_add(1) {
        return true; // coverage stops at (or below) finality: nothing optimistic
    }
    // The record must reach the covered top and run down to finality without
    // holes — a hole is a block we cannot re-check.
    let top = edge - 1;
    let mut expect = top;
    for (n, _) in recorded.iter().rev() {
        if *n != expect {
            return false;
        }
        if expect == finalized.saturating_add(1) {
            return true;
        }
        expect -= 1;
    }
    expect <= finalized
}

/// The lowest block a tail window must reach. It has to cover every RECORDED
/// block (so a reorg is detectable — a window starting at the coverage edge
/// compares against records that all sit BELOW it, i.e. two disjoint ranges,
/// and can never detect anything) and the covered top itself (so the first
/// appended block links to it by parent hash).
///
/// UNBOUNDED BELOW, deliberately. Not clamped at finality: finality advances
/// BETWEEN ticks, and a record it overtook would then sit below the window,
/// never be compared, and be pruned as "immutable" — which is only true of the
/// CANONICAL block at that height, not of the possibly-orphaned one we
/// appended. Not clamped at a walk limit either: whether the window can be
/// obtained is [`tail_window_is_servable`]'s question, and a clamp here would
/// answer it by silently dropping records out of the comparison. Pure —
/// unit-tested.
fn tail_window_floor(edge: u64, lowest_recorded: Option<u64>) -> u64 {
    let covered_top = edge.saturating_sub(1);
    lowest_recorded.unwrap_or(covered_top).min(covered_top)
}

/// THE record-retirement rule, as a predicate: may an entry recorded at
/// `block` be dropped WITHOUT giving back the coverage it describes?
///
/// Only if the canonical chain confirmed it at a height at or below finality
/// — `compared_at_or_below_finality`. Finality moving past an entry on its own
/// proves nothing: it fixes the CANONICAL block at that height, not the
/// possibly-orphaned one this run appended there. Every retirement site must
/// route through this rule (three separate rounds of review found a site that
/// had drifted from it, each time by dropping records on a path where the
/// tail's own check could no longer run).
fn record_may_retire(block: u64, finalized: u64, compared_at_or_below_finality: bool) -> bool {
    compared_at_or_below_finality && block <= finalized
}

/// Whether a `TAIL_MAX`-header window anchored at `head_n` can actually serve
/// down to `floor`. The window is inclusive at both ends, so a floor exactly
/// `TAIL_MAX` below the head needs one header more than the serve ceiling —
/// which rejected every peer and stalled the tail until finality overtook
/// coverage. Pure — unit-tested.
fn tail_window_is_servable(head_n: u64, floor: u64, tail_max: u64) -> bool {
    head_n.saturating_sub(floor) + 1 <= tail_max
}

/// Whether a chain whose head is `head_n` still reaches the top of what the
/// index covers. `false` means a reorg SHORTENED the chain past our coverage,
/// which is itself proof that the blocks above `head_n` are orphaned. Pure —
/// unit-tested, because the obvious-looking comparison (against the tail
/// window's floor) can never fire: the floor sits at finality whenever the
/// tail record vouches for the coverage.
fn tail_chain_reaches_coverage(head_n: u64, edge: u64) -> bool {
    head_n >= edge.saturating_sub(1)
}

/// The lowest recorded block whose hash the canonical chain contradicts — the
/// fork point of a reorg. `None` when every recorded block the window covers
/// still matches (records outside the window are not evidence either way, and
/// the window is built to cover them). Pure — unit-tested.
fn tail_fork_point(
    recorded: &[(u64, [u8; 32])],
    canonical: &[(u64, [u8; 32])],
) -> Option<u64> {
    let mut fork: Option<u64> = None;
    for (n, h) in recorded {
        if let Some((_, canon_hash)) = canonical.iter().find(|(cn, _)| cn == n) {
            if canon_hash != h {
                fork = Some(fork.map_or(*n, |f: u64| f.min(*n)));
            }
        }
    }
    fork
}

/// Whether an in-progress bridge plan still describes the CURRENT gap, and so
/// may be resumed instead of re-descended. Pure (unit-tested): the two moving
/// premises are the coverage edge — which the plan's own ascent advances, so
/// its progress is added back before comparing — and the finalized head, which
/// only moves forward and leaves everything the plan mapped (below its own
/// anchor) immutable. Anything else means the index changed underneath, and
/// the plan must be rebuilt.
fn plan_still_matches(
    anchor_n: u64,
    target: u64,
    applied: usize,
    finalized_now: u64,
    edge_now: u64,
) -> bool {
    finalized_now >= anchor_n && target.saturating_add(applied as u64) == edge_now
}

/// The next run of head-bridge candidate hashes to request, in ASCENDING
/// block order. `blocks` is the plan's descending `(number, hash, candidate)`
/// list, `applied` is how many blocks the ascent has already applied (counted
/// from the end), `max` caps the request size, and `within` caps how far ahead
/// to look — the blocks this tick can still apply, so bodies and receipts are
/// never fetched for candidates the tick will not reach. Empty when the next
/// block to apply is a plain (bloom-miss) block, which needs no request at
/// all. Pure — the arithmetic that turns a descending plan into ascending
/// work, unit-tested in `bridge_plan_tests`.
fn bridge_candidate_chunk(
    blocks: &[(u64, [u8; 32], bool)],
    applied: usize,
    max: usize,
    within: usize,
) -> Vec<[u8; 32]> {
    let total = blocks.len();
    let mut out = Vec::new();
    if applied >= total || max == 0 || within == 0 || !blocks[total - 1 - applied].2 {
        return out; // done, out of budget, or the cursor sits on a plain block
    }
    let limit = total.min(applied.saturating_add(within));
    let mut i = applied;
    while i < limit && out.len() < max {
        let (_, hash, candidate) = blocks[total - 1 - i];
        if candidate {
            out.push(hash);
        }
        i += 1;
    }
    out
}

/// Pure truncation arithmetic for one backfill candidate chunk: given the
/// chunk's block numbers (descending) and how many bodies/receipts the peer
/// actually served, return `(usable, stop_below)` — the verified-prefix
/// length and, when the peer's byte budget truncated the response, the block
/// number of the FIRST unserved candidate (the batch must apply only above
/// it). `None` = the peer served nothing usable (caller rotates peers).
fn truncation_plan(
    chunk_numbers_desc: &[u64],
    bodies_served: usize,
    receipts_served: usize,
) -> Option<(usize, Option<u64>)> {
    let usable = bodies_served.min(receipts_served).min(chunk_numbers_desc.len());
    if usable == 0 {
        return None;
    }
    let stop = chunk_numbers_desc.get(usable).copied();
    Some((usable, stop))
}

/// Whether block `n` may be applied given the truncation cut: everything at
/// or below the first unprocessed candidate is excluded — coverage must never
/// claim a block whose candidate receipts were not verified.
fn should_apply(n: u64, stop_below: Option<u64>) -> bool {
    !stop_below.is_some_and(|stop| n <= stop)
}

#[cfg(test)]
mod tail_reorg_tests {
    use super::{tail_fork_point, tail_vouches_for, tail_window_floor};

    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn window_floor_reaches_the_records_not_just_the_edge() {
        // THE bug this pins: a window starting at the coverage edge (1_001)
        // compares against records that all sit BELOW it — disjoint ranges, so
        // a reorg could never be detected. The floor must reach the records.
        assert_eq!(tail_window_floor(1_001, Some(996)), 996);
        // No records: still include the covered top so the next block links
        // to it by parent hash.
        assert_eq!(tail_window_floor(1_001, None), 1_000);
        // A record above the covered top can't widen the window past it.
        assert_eq!(tail_window_floor(1_001, Some(1_100)), 1_000);
        // Unbounded below: a record finality overtook between ticks must still
        // be inside the window, because it is only the CANONICAL block at that
        // height that became immutable — not the possibly-orphaned one we
        // appended. (How far down the window may reach is a separate
        // question, answered by tail_window_is_servable.)
        let finality_now = 998;
        assert!(tail_window_floor(1_001, Some(996)) < finality_now);
        assert_eq!(tail_window_floor(1_001, Some(500)), 500);
    }

    #[test]
    fn a_shortened_chain_is_detected_against_the_covered_top() {
        use super::{tail_chain_reaches_coverage, tail_window_floor};
        // Coverage 991..1000 (edge 1001), finality 990, record intact.
        let (edge, finalized) = (1_001u64, 990u64);
        // A head that fell back to 995 no longer reaches the covered top.
        assert!(!tail_chain_reaches_coverage(995, edge));
        // The window FLOOR would not have caught this: with the record
        // reaching finality+1 the floor sits there, so `head < floor` is
        // unreachable and only the covered-top comparison detects it.
        assert!(995 >= tail_window_floor(edge, Some(finalized + 1)));
        // A head at or above the covered top is fine.
        assert!(tail_chain_reaches_coverage(1_000, edge));
        assert!(tail_chain_reaches_coverage(1_200, edge));
    }

    #[test]
    fn a_record_retires_only_once_confirmed_at_or_below_finality() {
        use super::record_may_retire;
        // Compared while already final: safe to forget.
        assert!(record_may_retire(1_000, 1_000, true));
        assert!(record_may_retire(999, 1_000, true));
        // Finality passed it, but nothing ever compared it — the whole point:
        // finality fixes the CANONICAL block at that height, not ours.
        assert!(!record_may_retire(1_000, 1_000, false));
        // Compared, but still above finality: it can still reorg.
        assert!(!record_may_retire(1_001, 1_000, true));
    }

    #[test]
    fn the_tail_window_floor_must_be_servable() {
        use super::{tail_window_floor, tail_window_is_servable};
        const TAIL_MAX: u64 = 1_024;
        let head = 10_000u64;
        // The hard floor the tail uses must be reachable within one window —
        // head - (TAIL_MAX - 1) needs exactly TAIL_MAX headers.
        let hard_floor = head - (TAIL_MAX - 1);
        assert!(tail_window_is_servable(head, hard_floor, TAIL_MAX));
        // One block lower needs 1025 — no peer can serve it, which stalled
        // the tail permanently.
        assert!(!tail_window_is_servable(head, hard_floor - 1, TAIL_MAX));
        // The tail computes its floor UNCLAMPED and then asks whether the
        // window is obtainable — so a record within reach is servable...
        for lowest in [hard_floor, hard_floor + 5, head - 1] {
            let floor = tail_window_floor(head, Some(lowest));
            assert!(tail_window_is_servable(head, floor, TAIL_MAX), "floor {floor}");
        }
        // ...and one out of reach is REJECTED rather than silently clamped
        // out of the comparison (the clamp is what stalled the tail: the
        // window stopped above the floor and every peer was refused).
        let floor = tail_window_floor(head, Some(hard_floor - 1));
        assert!(!tail_window_is_servable(head, floor, TAIL_MAX));
    }

    #[test]
    fn fork_point_is_the_lowest_contradicted_record() {
        let canonical =
            vec![(100, h(1)), (101, h(2)), (102, h(0xAA)), (103, h(0xBB))];
        // All matching → no fork.
        assert_eq!(tail_fork_point(&[(100, h(1)), (101, h(2))], &canonical), None);
        // 102 and 103 both diverge → the LOWEST is the fork point.
        let recorded = vec![(100, h(1)), (101, h(2)), (102, h(3)), (103, h(4))];
        assert_eq!(tail_fork_point(&recorded, &canonical), Some(102));
        // Records the window doesn't cover are not evidence either way.
        assert_eq!(tail_fork_point(&[(99, h(9))], &canonical), None);
        assert_eq!(tail_fork_point(&[], &canonical), None);
    }

    #[test]
    fn vouching_requires_an_unbroken_record_down_to_finality() {
        // Coverage at or below finality: nothing optimistic to vouch for.
        assert!(tail_vouches_for(&[], 991, 990));
        assert!(tail_vouches_for(&[], 500, 990));
        // Full record from the covered top down to finality+1.
        assert!(tail_vouches_for(&[(991, h(1)), (992, h(2))], 993, 990));
        // Empty record but optimistic coverage: an inherited/imported tail.
        assert!(!tail_vouches_for(&[], 993, 990));
        // Record that doesn't reach the covered top (992 missing).
        assert!(!tail_vouches_for(&[(991, h(1))], 993, 990));
        // A HOLE in the record: 992 was never recorded, so it can't be
        // re-checked and the whole optimistic span must be rewound.
        assert!(!tail_vouches_for(&[(991, h(1)), (993, h(3))], 994, 990));
    }
}

#[cfg(test)]
mod bridge_plan_tests {
    use super::bridge_candidate_chunk;

    /// Descending `(number, hash, candidate)` — the plan's own layout.
    fn plan(spec: &[(u64, bool)]) -> Vec<(u64, [u8; 32], bool)> {
        spec.iter()
            .map(|(n, c)| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&n.to_be_bytes());
                (*n, h, *c)
            })
            .collect()
    }

    fn numbers(hashes: &[[u8; 32]]) -> Vec<u64> {
        hashes
            .iter()
            .map(|h| u64::from_be_bytes(h[..8].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn plain_cursor_needs_no_request() {
        // Ascent starts at the bottom (100, plain) → nothing to fetch.
        let p = plan(&[(102, true), (101, false), (100, false)]);
        assert!(bridge_candidate_chunk(&p, 0, 64, 64).is_empty());
        // ...and still nothing one block up.
        assert!(bridge_candidate_chunk(&p, 1, 64, 64).is_empty());
        // At 102 the cursor sits on a candidate.
        assert_eq!(numbers(&bridge_candidate_chunk(&p, 2, 64, 64)), vec![102]);
    }

    #[test]
    fn chunk_collects_candidates_ascending_across_plain_blocks() {
        let p = plan(&[(105, true), (104, false), (103, true), (102, false), (101, true)]);
        // From the bottom candidate: ascending order, plain blocks skipped.
        assert_eq!(numbers(&bridge_candidate_chunk(&p, 0, 64, 64)), vec![101, 103, 105]);
        // The look-ahead bound stops at blocks this tick can still apply:
        // with room for 3 blocks only 101 and 103 are in reach.
        assert_eq!(numbers(&bridge_candidate_chunk(&p, 0, 64, 3)), vec![101, 103]);
        assert!(bridge_candidate_chunk(&p, 0, 64, 0).is_empty());
    }

    #[test]
    fn chunk_respects_the_request_cap() {
        let p = plan(&[(105, true), (104, true), (103, true), (102, true), (101, true)]);
        assert_eq!(numbers(&bridge_candidate_chunk(&p, 0, 2, 64)), vec![101, 102]);
        // A zero cap asks for nothing rather than panicking.
        assert!(bridge_candidate_chunk(&p, 0, 0, 64).is_empty());
    }

    #[test]
    fn a_plan_survives_its_own_progress_and_advancing_finality() {
        use super::plan_still_matches;
        // Fresh plan: target == edge, nothing applied.
        assert!(plan_still_matches(2_000, 1_000, 0, 2_000, 1_000));
        // Mid-ascent: the edge has moved by exactly what the plan applied.
        assert!(plan_still_matches(2_000, 1_000, 250, 2_000, 1_250));
        // Finality advanced past the plan's anchor: the mapped blocks are
        // still below it and still immutable, so the plan is fine.
        assert!(plan_still_matches(2_000, 1_000, 250, 2_064, 1_250));
        // Coverage moved WITHOUT the plan (an appender landing, an import, a
        // reset): the plan no longer lines up and must be rebuilt.
        assert!(!plan_still_matches(2_000, 1_000, 250, 2_000, 1_400));
        assert!(!plan_still_matches(2_000, 1_000, 0, 2_000, 900));
        // Finality REGRESSED (a rewound anchor): rebuild rather than trust it.
        assert!(!plan_still_matches(2_000, 1_000, 0, 1_900, 1_000));
    }

    #[test]
    fn exhausted_plan_yields_nothing() {
        let p = plan(&[(101, true), (100, true)]);
        assert!(bridge_candidate_chunk(&p, 2, 64, 64).is_empty());
        assert!(bridge_candidate_chunk(&p, 9, 64, 64).is_empty());
        assert!(bridge_candidate_chunk(&[], 0, 64, 64).is_empty());
    }
}

#[cfg(test)]
mod backfill_truncation_tests {
    use super::{should_apply, truncation_plan};

    #[test]
    fn full_serve_has_no_cut() {
        assert_eq!(truncation_plan(&[90, 80, 70], 3, 3), Some((3, None)));
        // Over-serve (peer sent more than asked) still caps at the chunk.
        assert_eq!(truncation_plan(&[90, 80], 5, 9), Some((2, None)));
    }

    #[test]
    fn short_serve_cuts_at_first_unserved_candidate() {
        // 3 candidates, only 2 receipt sets served → cut at the 3rd (70).
        assert_eq!(truncation_plan(&[90, 80, 70], 3, 2), Some((2, Some(70))));
        // The boundary block itself must NOT be applied; blocks above must.
        assert!(should_apply(71, Some(70)));
        assert!(!should_apply(70, Some(70)));
        assert!(!should_apply(69, Some(70)));
        assert!(should_apply(70, None));
    }

    #[test]
    fn empty_serve_is_peer_failure() {
        assert_eq!(truncation_plan(&[90, 80], 0, 5), None);
        assert_eq!(truncation_plan(&[90, 80], 5, 0), None);
        assert_eq!(truncation_plan(&[], 5, 5), None);
    }

    #[test]
    fn first_candidate_only_still_makes_progress() {
        // Only the first candidate served: the cut is the SECOND candidate,
        // so the batch still applies at least every block above it — the
        // cursor strictly descends (no same-cursor livelock).
        let plan = truncation_plan(&[100, 99, 98], 1, 1);
        assert_eq!(plan, Some((1, Some(99))));
        assert!(should_apply(100, Some(99)));
        assert!(!should_apply(99, Some(99)));
    }
}

