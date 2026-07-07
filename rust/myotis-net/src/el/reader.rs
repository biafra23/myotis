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

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_core::trie::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

use crate::el::anchor::ExecAnchor;
use crate::el::discv4::{Discv4Config, Discv4Service};
use crate::el::eth::session::EthConfig;
use crate::el::peer::ManagedPeer;
use crate::el::pool::{PeerPool, PoolConfig};
use crate::el::snap::fetch::AccountOutcome;

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

/// A running EL reader: owns discv4 + the peer pool, borrows the beacon anchor.
pub struct ElReader {
    discovery: Discv4Service,
    pool: PeerPool,
    anchor: Arc<ExecAnchor>,
}

impl ElReader {
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
        let local_pubkey = key.public_key_bytes();
        let pool = PeerPool::start(key, local_pubkey, eth_cfg, cfg.pool_config, rx);
        Ok(ElReader { discovery, pool, anchor })
    }

    /// Count of live snap peers (for host status).
    pub async fn snap_peer_count(&self) -> usize {
        self.pool.snap_peer_count().await
    }

    /// Fetch + verify one account, running the full beacon-anchor ladder.
    pub async fn get_account(&self, address: [u8; 20]) -> Result<VerifiedAccount, String> {
        let peer = self.pool.snap_peer().await.ok_or("no snap peer available")?;
        let (state_root, block_number) = fresh_head(&peer).await?;

        // Verify-on-fetch: snap_get_account MPT-verifies against state_root and
        // returns Present/Absent only when the proof holds.
        let outcome = peer.snap_get_account(&state_root, &address).await?;
        // Anchor the (proof-valid) peer state root to the beacon chain.
        let verdict = peer
            .verified_state_root(&self.anchor, &state_root, block_number as i64, true)
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
        let peer = self.pool.snap_peer().await.ok_or("no snap peer available")?;
        let (state_root, block_number) = fresh_head(&peer).await?;

        let storage_key = storage_key(slot, holder);
        let slot_key_hash = keccak256(&storage_key);

        // Step 1: the proof-verified account gives the trusted storage root.
        let outcome = peer.snap_get_account(&state_root, &address).await?;

        let (fin_num, opt_num, synced) = self.anchor_diagnostics();
        let mut result = VerifiedStorage {
            address,
            slot,
            holder,
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

        // An absent account has no storage: every slot is provably zero.
        let AccountOutcome::Present(leaf) = outcome else {
            // Still anchor the state root so the verdict reflects the beacon tie.
            let verdict = peer
                .verified_state_root(&self.anchor, &state_root, block_number as i64, true)
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
            .verified_state_root(&self.anchor, &state_root, block_number as i64, true)
            .await;
        apply_verdict(&mut result, &verdict);
        Ok(result)
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

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < 32 && (i * 2 + 1) < bytes.len() {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
