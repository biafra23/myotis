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
use myotis_evm::{BlockContext, OracleAccount, OracleError, SnapStateOracle, U256};

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
    /// Per-call memo of fetched account leaves (keyed by address; the state root
    /// is fixed for the call). Dedups the account fetch that both `fetch_account`
    /// and every `fetch_storage` on the same contract need. `Some(None)` caches a
    /// proven absence.
    leaf_memo: Mutex<HashMap<[u8; 20], Option<AccountLeaf>>>,
}

impl PoolOracle {
    pub fn new(peers: Vec<Arc<ManagedPeer>>, handle: Handle) -> PoolOracle {
        PoolOracle {
            peers,
            handle,
            leaf_memo: Mutex::new(HashMap::new()),
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
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer.snap_get_account(state_root, &address).await {
                    Ok(AccountOutcome::Present(leaf)) => return Some(Some(leaf)),
                    Ok(AccountOutcome::Absent) => return Some(None),
                    // Bad proof / transport for this peer — try the next.
                    Err(_) => continue,
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
            Some(leaf) => {
                let balance = u256_be(&leaf.balance).ok_or_else(|| OracleError::InvalidProof {
                    state_root: *state_root,
                    address,
                    detail: format!(
                        "account balance scalar too long ({} bytes)",
                        leaf.balance.len()
                    ),
                })?;
                Ok(Some(OracleAccount {
                    nonce: leaf.nonce,
                    balance,
                    code_hash: leaf.code_hash,
                    storage_root: leaf.storage_root,
                }))
            }
            None => Ok(None),
        }
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
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer
                    .snap_get_storage(state_root, &address, &leaf, &position)
                    .await
                {
                    Ok(value) => return Some(value),
                    Err(_) => continue,
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
        let fetched = self.handle.block_on(async {
            for peer in &self.peers {
                match peer.snap_get_bytecode(code_hash).await {
                    Ok(code) => return Some(code),
                    Err(_) => continue,
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
