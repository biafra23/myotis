//! Execution-layer block header — twin of `core.types.BlockHeader` (Java).
//!
//! RLP field order (docs/reimplementation/02 §1.2): parentHash, ommersHash,
//! beneficiary(20), stateRoot, transactionsRoot, receiptsRoot, logsBloom(256),
//! difficulty, number, gasLimit, gasUsed, timestamp, extraData,
//! mixHash/prevRandao, nonce(8), then OPTIONAL trailing fields parsed only
//! while the list has more items (not by fork detection): baseFeePerGas
//! (EIP-1559), withdrawalsRoot (EIP-4895), blobGasUsed/excessBlobGas
//! (EIP-4844), parentBeaconBlockRoot (EIP-4788). EIP-7685 `requestsHash` is
//! read-and-discarded, and further unknown trailing fields are tolerated —
//! the header HASH still covers them because it is `keccak256` of the raw
//! encoding, never of a re-encode of what we understood.

use crate::keccak::keccak256;
use crate::rlp::{self, Item};
use crate::{err, CoreError};

/// Decoded EL block header. Big scalars (`difficulty`, `base_fee_per_gas`)
/// are kept as minimal big-endian bytes (Java uses `BigInteger`; a fixed-width
/// integer would silently cap what the wire allows).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    /// 20 bytes on every real header (length not enforced, matching Java).
    pub beneficiary: Vec<u8>,
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    /// 256 bytes on every real header (length not enforced, matching Java).
    pub logs_bloom: Vec<u8>,
    /// Minimal big-endian scalar (empty = zero, the post-Merge value).
    pub difficulty: Vec<u8>,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash_or_prev_randao: [u8; 32],
    /// 8 bytes on every real header (length not enforced, matching Java).
    pub nonce: Vec<u8>,
    /// EIP-1559; `None` pre-London. Minimal big-endian scalar.
    pub base_fee_per_gas: Option<Vec<u8>>,
    /// EIP-4895; `None` pre-Shanghai.
    pub withdrawals_root: Option<[u8; 32]>,
    /// EIP-4844; `None` pre-Cancun (Java uses a -1 sentinel).
    pub blob_gas_used: Option<u64>,
    /// EIP-4844; `None` pre-Cancun.
    pub excess_blob_gas: Option<u64>,
    /// EIP-4788; `None` pre-Cancun.
    pub parent_beacon_block_root: Option<[u8; 32]>,
}

/// keccak256 of the RLP-encoded header — the verifiable anchor. Always hash
/// the RAW bytes as received, never a re-encode.
pub fn hash(rlp_bytes: &[u8]) -> [u8; 32] {
    keccak256(rlp_bytes)
}

impl BlockHeader {
    /// Decode a header from its RLP encoding.
    pub fn decode(rlp_bytes: &[u8]) -> Result<BlockHeader, CoreError> {
        let top = rlp::decode(rlp_bytes)?;
        let items = top.as_list()?;
        if items.len() < 15 {
            return err(format!(
                "header: expected >= 15 RLP fields, got {}",
                items.len()
            ));
        }
        let mut f = items.iter();
        // The 15 always-present fields.
        let parent_hash = fixed32(f.next(), "parentHash")?;
        let ommers_hash = fixed32(f.next(), "ommersHash")?;
        let beneficiary = any_bytes(f.next(), "beneficiary")?;
        let state_root = fixed32(f.next(), "stateRoot")?;
        let transactions_root = fixed32(f.next(), "transactionsRoot")?;
        let receipts_root = fixed32(f.next(), "receiptsRoot")?;
        let logs_bloom = any_bytes(f.next(), "logsBloom")?;
        let difficulty = scalar_bytes(f.next(), "difficulty")?;
        let number = u64_field(f.next(), "number")?;
        let gas_limit = u64_field(f.next(), "gasLimit")?;
        let gas_used = u64_field(f.next(), "gasUsed")?;
        let timestamp = u64_field(f.next(), "timestamp")?;
        let extra_data = any_bytes(f.next(), "extraData")?;
        let mix_hash_or_prev_randao = fixed32(f.next(), "mixHash")?;
        let nonce = any_bytes(f.next(), "nonce")?;
        // Optional trailing fields, by list remainder.
        let base_fee_per_gas = match f.next() {
            Some(it) => Some(scalar_bytes(Some(it), "baseFeePerGas")?),
            None => None,
        };
        let withdrawals_root = match f.next() {
            Some(it) => Some(fixed32(Some(it), "withdrawalsRoot")?),
            None => None,
        };
        let blob_gas_used = match f.next() {
            Some(it) => Some(u64_field(Some(it), "blobGasUsed")?),
            None => None,
        };
        let excess_blob_gas = match f.next() {
            Some(it) => Some(u64_field(Some(it), "excessBlobGas")?),
            None => None,
        };
        let parent_beacon_block_root = match f.next() {
            Some(it) => Some(fixed32(Some(it), "parentBeaconBlockRoot")?),
            None => None,
        };
        // EIP-7685 requestsHash: read-and-discarded, but it must BE a byte
        // string (Java's readValue throws on a list — pinned by the corpus).
        if let Some(it) = f.next() {
            it.as_bytes()
                .map_err(|e| CoreError(format!("header: requestsHash: {}", e.0)))?;
        }
        // Anything a future fork appends beyond that: tolerated and ignored
        // (the raw-bytes hash still covers it; Java never reads this far).
        Ok(BlockHeader {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_hash_or_prev_randao,
            nonce,
            base_fee_per_gas,
            withdrawals_root,
            blob_gas_used,
            excess_blob_gas,
            parent_beacon_block_root,
        })
    }

    /// Canonical re-encode of the KNOWN fields. Matches the input bytes for
    /// headers without discarded trailing fields (requestsHash etc.); callers
    /// that need the hash of a received header must hash the raw bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut items: Vec<Item> = vec![
            Item::Bytes(self.parent_hash.to_vec()),
            Item::Bytes(self.ommers_hash.to_vec()),
            Item::Bytes(self.beneficiary.clone()),
            Item::Bytes(self.state_root.to_vec()),
            Item::Bytes(self.transactions_root.to_vec()),
            Item::Bytes(self.receipts_root.to_vec()),
            Item::Bytes(self.logs_bloom.clone()),
            Item::Bytes(self.difficulty.clone()),
            Item::Bytes(rlp::u64_to_minimal_be(self.number)),
            Item::Bytes(rlp::u64_to_minimal_be(self.gas_limit)),
            Item::Bytes(rlp::u64_to_minimal_be(self.gas_used)),
            Item::Bytes(rlp::u64_to_minimal_be(self.timestamp)),
            Item::Bytes(self.extra_data.clone()),
            Item::Bytes(self.mix_hash_or_prev_randao.to_vec()),
            Item::Bytes(self.nonce.clone()),
        ];
        if let Some(v) = &self.base_fee_per_gas {
            items.push(Item::Bytes(v.clone()));
        }
        if let Some(v) = &self.withdrawals_root {
            items.push(Item::Bytes(v.to_vec()));
        }
        if let Some(v) = self.blob_gas_used {
            items.push(Item::Bytes(rlp::u64_to_minimal_be(v)));
        }
        if let Some(v) = self.excess_blob_gas {
            items.push(Item::Bytes(rlp::u64_to_minimal_be(v)));
        }
        if let Some(v) = &self.parent_beacon_block_root {
            items.push(Item::Bytes(v.to_vec()));
        }
        rlp::encode(&Item::List(items))
    }
}

fn fixed32(item: Option<&Item>, name: &str) -> Result<[u8; 32], CoreError> {
    let it = item.ok_or_else(|| CoreError(format!("header: missing field {name}")))?;
    let b = it
        .as_fixed_bytes(32)
        .map_err(|e| CoreError(format!("header: {name}: {}", e.0)))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

fn any_bytes(item: Option<&Item>, name: &str) -> Result<Vec<u8>, CoreError> {
    let it = item.ok_or_else(|| CoreError(format!("header: missing field {name}")))?;
    Ok(it
        .as_bytes()
        .map_err(|e| CoreError(format!("header: {name}: {}", e.0)))?
        .to_vec())
}

/// Unbounded unsigned scalar (difficulty, baseFee): minimal big-endian bytes,
/// leading zeros rejected (canonical RLP integers).
fn scalar_bytes(item: Option<&Item>, name: &str) -> Result<Vec<u8>, CoreError> {
    let b = any_bytes(item, name)?;
    if !b.is_empty() && b[0] == 0 {
        return err(format!("header: {name}: integer has leading zero byte"));
    }
    Ok(b)
}

fn u64_field(item: Option<&Item>, name: &str) -> Result<u64, CoreError> {
    let it = item.ok_or_else(|| CoreError(format!("header: missing field {name}")))?;
    it.as_u64_fitting_long()
        .map_err(|e| CoreError(format!("header: {name}: {}", e.0)))
}
