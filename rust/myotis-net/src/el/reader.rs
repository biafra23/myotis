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

use myotis_evm::{EvmError, EvmExecutor, InMemoryBytecodeCache, InMemoryStateProofCache, U256};

use crate::el::anchor::ExecAnchor;
use crate::el::discv4::{Discv4Config, Discv4Service};
use crate::el::eth::session::EthConfig;
use crate::el::evm::{block_context, CallOutcome, GasOutcome, PoolOracle};
use crate::el::peer::ManagedPeer;
use crate::el::pool::{PeerPool, PoolConfig};
use crate::el::snap::fetch::AccountOutcome;
use crate::el::tx;

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

/// Recent blocks sampled for the `eth_maxPriorityFeePerGas` tip suggestion
/// (mirrors the Java `TIP_SUGGEST_BLOCKS`).
const TIP_SUGGEST_BLOCKS: u64 = 3;

/// Mainnet floor for the suggested tip: 0.1 gwei (mirrors the Java `MIN_SUGGESTED_TIP`).
/// The Rust engine is mainnet-only, so this is a constant here rather than the
/// network-aware `minSuggestedTipWei`.
const MIN_SUGGESTED_TIP_WEI: u128 = 100_000_000;

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
    /// Cross-call EVM caches, shared across every `eth_call` on this reader. Both
    /// hold `stateRoot`-keyed / content-addressed cryptographic facts, so reuse is
    /// sound. Because a call pins to the CURRENT head (whose root advances ~every
    /// 12 s), the win is on a burst of identical calls that land on the same head,
    /// plus bytecode (content-addressed → never re-fetched once seen) — NOT across
    /// a head advance. Freezing a per-block-number context so a slow retry reuses
    /// the cache is a later dispatch-fairness refinement (EL-C-3).
    evm_proof_cache: Arc<InMemoryStateProofCache>,
    evm_bytecode_cache: Arc<InMemoryBytecodeCache>,
}

/// Per-kind bound for the cross-call state-proof cache (accounts and storage
/// slots each). Generous — entries are small and eviction only trims the oldest.
const EVM_PROOF_CACHE_ENTRIES: usize = 8192;

impl ElReader {
    /// Start a mainnet reader with a freshly-generated ephemeral node key (the
    /// CL side generates its libp2p identity per run too; a persistent EL
    /// identity is an EL-A8 concern). `cache_path` is the EL peer cache for
    /// warm-start (`dataDir/peers.cache`), or `None` to run without persistence.
    pub async fn start_mainnet(
        anchor: Arc<ExecAnchor>,
        cache_path: Option<std::path::PathBuf>,
    ) -> Result<ElReader, String> {
        let key = generate_node_key()?;
        let cfg = ElConfig { cache_path, ..ElConfig::mainnet() };
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
            evm_proof_cache: Arc::new(InMemoryStateProofCache::new(EVM_PROOF_CACHE_ENTRIES)),
            evm_bytecode_cache: Arc::new(InMemoryBytecodeCache::new()),
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
        // Snapshot the snap peers once: one consistent set for the whole call.
        let peers = self.pool.snap_peers().await;
        if peers.is_empty() {
            return Err(format!("no snap peer available for {what}"));
        }
        let oracle = Arc::new(PoolOracle::new(peers, tokio::runtime::Handle::current()));
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
        // the length check below and is skipped (fails closed — the caller tries the
        // next peer), so deep pins carry a slightly higher liveness risk than a
        // batched fetch would. The common case (latest / a few blocks back) is one
        // small response.
        let window = peer.get_block_headers_by_number(target_num, back + 1, 0, false).await?;
        if window.len() as u64 != back + 1 {
            return Err(format!("peer returned {} headers, expected {}", window.len(), back + 1));
        }
        // The window's head must BE the beacon-anchored head, and each header must
        // hash-link to the next — proving the target header chains to the verified
        // head (the trust gate: head_hash is the light-client-attested exec hash).
        if &window[window.len() - 1].hash != head_hash {
            return Err("window head does not match the beacon-anchored head hash".to_string());
        }
        for i in 0..window.len() - 1 {
            if window[i + 1].header.parent_hash != window[i].hash {
                return Err("header window is not hash-linked".to_string());
            }
        }
        let vh = &window[0];
        if vh.header.number != target_num {
            return Err("peer returned the wrong target block number".to_string());
        }
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
    /// tip (floored at `MIN_SUGGESTED_TIP_WEI`) as the priority fee, and next-block
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
        let window = peer.get_block_headers_by_number(start, count, 0, false).await?;
        if window.len() as u64 != count {
            return Err(format!("peer returned {} headers, expected {}", window.len(), count));
        }
        if &window[window.len() - 1].hash != head_hash {
            return Err("window head does not match the beacon-anchored head hash".to_string());
        }
        for i in 0..window.len() - 1 {
            if window[i + 1].header.parent_hash != window[i].hash {
                return Err("header window is not hash-linked".to_string());
            }
        }
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
            MIN_SUGGESTED_TIP_WEI
        } else {
            tips.sort_unstable();
            tips[tips.len() / 2].max(MIN_SUGGESTED_TIP_WEI)
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!c.bootnodes.is_empty());
    }
}
