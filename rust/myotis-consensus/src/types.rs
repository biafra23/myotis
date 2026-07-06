//! Light-client wire types with SSZ decoding + hash_tree_root — Rust twins of the
//! Java `com.jaeckel.ethp2p.consensus.types` decoders, INCLUDING their runtime
//! fork sniffing (branch lengths / fixed sizes derived from the leading offsets,
//! pre-Electra vs Electra+). Decoding never panics: every malformed input returns
//! `Err(SszError)` with a message shaped like the Java exceptions.

use crate::ssz::{self, Root};

#[derive(Debug, PartialEq, Eq)]
pub struct SszError(pub String);

impl std::fmt::Display for SszError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SszError {}

fn err<T>(msg: impl Into<String>) -> Result<T, SszError> {
    Err(SszError(msg.into()))
}

// -------------------------------------------------------------------------
// BeaconBlockHeader — 112 bytes fixed
// -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

impl BeaconBlockHeader {
    pub const ENCODED_SIZE: usize = 112;

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::ENCODED_SIZE {
            return err(format!(
                "BeaconBlockHeader requires 112 bytes, got {}",
                ssz_bytes.len()
            ));
        }
        Ok(Self {
            slot: ssz::read_u64(ssz_bytes, 0).unwrap(),
            proposer_index: ssz::read_u64(ssz_bytes, 8).unwrap(),
            parent_root: ssz::read_root(ssz_bytes, 16).unwrap(),
            state_root: ssz::read_root(ssz_bytes, 48).unwrap(),
            body_root: ssz::read_root(ssz_bytes, 80).unwrap(),
        })
    }

    pub fn hash_tree_root(&self) -> Root {
        ssz::container_root(&[
            ssz::uint64_root(self.slot),
            ssz::uint64_root(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ])
    }

    /// SSZ encoding — the exact inverse of [`Self::decode`], and byte-identical
    /// to the Java `BeaconBlockHeader.encode()` (the snapshot codec embeds it).
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let mut out = [0u8; Self::ENCODED_SIZE];
        out[0..8].copy_from_slice(&self.slot.to_le_bytes());
        out[8..16].copy_from_slice(&self.proposer_index.to_le_bytes());
        out[16..48].copy_from_slice(&self.parent_root);
        out[48..80].copy_from_slice(&self.state_root);
        out[80..112].copy_from_slice(&self.body_root);
        out
    }
}

// -------------------------------------------------------------------------
// SyncCommittee — 512 * 48 + 48 = 24624 bytes fixed
// -------------------------------------------------------------------------

pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const PUBKEY_SIZE: usize = 48;

#[derive(Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// The 512 pubkeys flattened (512 * 48 bytes) — the layout myotis-bls consumes.
    pub pubkeys: Vec<u8>,
    pub aggregate_pubkey: [u8; PUBKEY_SIZE],
}

impl SyncCommittee {
    pub const ENCODED_SIZE: usize = SYNC_COMMITTEE_SIZE * PUBKEY_SIZE + PUBKEY_SIZE; // 24624

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::ENCODED_SIZE {
            return err(format!(
                "SyncCommittee requires {} bytes, got {}",
                Self::ENCODED_SIZE,
                ssz_bytes.len()
            ));
        }
        let pubkeys = ssz_bytes[..SYNC_COMMITTEE_SIZE * PUBKEY_SIZE].to_vec();
        let aggregate_pubkey = ssz_bytes
            [SYNC_COMMITTEE_SIZE * PUBKEY_SIZE..Self::ENCODED_SIZE]
            .try_into()
            .unwrap();
        Ok(Self { pubkeys, aggregate_pubkey })
    }

    pub fn pubkey(&self, i: usize) -> &[u8] {
        &self.pubkeys[i * PUBKEY_SIZE..(i + 1) * PUBKEY_SIZE]
    }

    /// 48-byte pubkey → root: zero-pad to 64, merkleize the two chunks.
    fn pubkey_root(pk: &[u8]) -> Root {
        let mut c0 = [0u8; 32];
        c0.copy_from_slice(&pk[..32]);
        let mut c1 = [0u8; 32];
        c1[..16].copy_from_slice(&pk[32..48]);
        ssz::merkleize(&[c0, c1])
    }

    pub fn hash_tree_root(&self) -> Root {
        let pubkey_roots: Vec<Root> = (0..SYNC_COMMITTEE_SIZE)
            .map(|i| Self::pubkey_root(self.pubkey(i)))
            .collect();
        let pubkeys_vector_root = ssz::merkleize(&pubkey_roots);
        let aggregate_root = Self::pubkey_root(&self.aggregate_pubkey);
        ssz::container_root(&[pubkeys_vector_root, aggregate_root])
    }
}

impl std::fmt::Debug for SyncCommittee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyncCommittee(512 pubkeys)")
    }
}

// -------------------------------------------------------------------------
// SyncAggregate — 64 + 96 = 160 bytes fixed
// -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    pub sync_committee_bits: [u8; 64],
    pub sync_committee_signature: [u8; 96],
}

impl SyncAggregate {
    pub const ENCODED_SIZE: usize = 160;

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::ENCODED_SIZE {
            return err(format!(
                "SyncAggregate requires 160 bytes, got {}",
                ssz_bytes.len()
            ));
        }
        Ok(Self {
            sync_committee_bits: ssz_bytes[..64].try_into().unwrap(),
            sync_committee_signature: ssz_bytes[64..160].try_into().unwrap(),
        })
    }

    pub fn count_participants(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    pub fn get_bit(&self, i: usize) -> bool {
        (self.sync_committee_bits[i / 8] >> (i % 8)) & 1 == 1
    }
}

// -------------------------------------------------------------------------
// ExecutionPayloadHeader — Deneb (584B fixed) / Electra+ (680B fixed), sniffed
// from the extraData offset, exactly like the Java decoder.
// -------------------------------------------------------------------------

pub const DENEB_FIXED_SIZE: usize = 584;
pub const ELECTRA_FIXED_SIZE: usize = 680;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: Vec<u8>, // 256
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: Root, // uint256 LE
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    // Electra+ request roots are parsed but — mirroring the Java hashTreeRoot,
    // which merkleizes only the 17 Deneb fields — excluded from the root.
    pub deposit_requests_root: Option<Root>,
    pub withdrawal_requests_root: Option<Root>,
    pub consolidation_requests_root: Option<Root>,
}

impl ExecutionPayloadHeader {
    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < DENEB_FIXED_SIZE {
            return err(format!(
                "ExecutionPayloadHeader requires at least {} bytes, got {}",
                DENEB_FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let g = |o: usize| ssz::read_root(ssz_bytes, o).unwrap();
        let extra_data_offset = ssz::read_u32(ssz_bytes, 436).unwrap() as usize;
        let is_electra = extra_data_offset >= ELECTRA_FIXED_SIZE;
        if is_electra && ssz_bytes.len() < ELECTRA_FIXED_SIZE {
            // Same observable outcome as the Java decoder, which reads the three
            // request roots via buf.get and throws BufferUnderflowException here —
            // a decode REJECTION either way, just a clean Err instead of an
            // exception. (Pinned by eph_electra_offset_short_buffer_rejected.)
            return err("ExecutionPayloadHeader: Electra offset but short buffer");
        }
        let fixed = if is_electra { ELECTRA_FIXED_SIZE } else { DENEB_FIXED_SIZE };
        // Out-of-range extraData offsets fall back to EMPTY, deliberately NOT Err:
        // this mirrors the Java reference decoder byte-for-byte (same `>= fixed &&
        // <= len` guard, same empty fallback), and behavioral parity is the contract
        // the conformance corpus pins. A forged offset can't smuggle anything —
        // extraData feeds the EPH hash_tree_root, and a wrong root fails the signed
        // execution-branch check downstream on BOTH engines identically.
        let extra_data = if extra_data_offset >= fixed && extra_data_offset <= ssz_bytes.len() {
            ssz_bytes[extra_data_offset..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            parent_hash: g(0),
            fee_recipient: ssz_bytes[32..52].try_into().unwrap(),
            state_root: g(52),
            receipts_root: g(84),
            logs_bloom: ssz_bytes[116..372].to_vec(),
            prev_randao: g(372),
            block_number: ssz::read_u64(ssz_bytes, 404).unwrap(),
            gas_limit: ssz::read_u64(ssz_bytes, 412).unwrap(),
            gas_used: ssz::read_u64(ssz_bytes, 420).unwrap(),
            timestamp: ssz::read_u64(ssz_bytes, 428).unwrap(),
            extra_data,
            base_fee_per_gas: g(440),
            block_hash: g(472),
            transactions_root: g(504),
            withdrawals_root: g(536),
            blob_gas_used: ssz::read_u64(ssz_bytes, 568).unwrap(),
            excess_blob_gas: ssz::read_u64(ssz_bytes, 576).unwrap(),
            deposit_requests_root: is_electra.then(|| g(584)),
            withdrawal_requests_root: is_electra.then(|| g(616)),
            consolidation_requests_root: is_electra.then(|| g(648)),
        })
    }

    /// 17 Deneb fields, padded to 32 leaves — matches the Java hashTreeRoot (and
    /// beacon nodes' ExecutionPayloadHeader root for Deneb/Electra/Fulu).
    pub fn hash_tree_root(&self) -> Root {
        const MAX_EXTRA_DATA_CHUNKS: usize = 1;
        ssz::container_root(&[
            self.parent_hash,
            ssz::padded_root(&self.fee_recipient),
            self.state_root,
            self.receipts_root,
            ssz::byte_vector_root(&self.logs_bloom),
            self.prev_randao,
            ssz::uint64_root(self.block_number),
            ssz::uint64_root(self.gas_limit),
            ssz::uint64_root(self.gas_used),
            ssz::uint64_root(self.timestamp),
            ssz::byte_list_root(&self.extra_data, MAX_EXTRA_DATA_CHUNKS),
            self.base_fee_per_gas,
            self.block_hash,
            self.transactions_root,
            self.withdrawals_root,
            ssz::uint64_root(self.blob_gas_used),
            ssz::uint64_root(self.excess_blob_gas),
        ])
    }
}

// -------------------------------------------------------------------------
// LightClientHeader — beacon(112) + execution offset(4) + executionBranch(128)
// -------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader,
    pub execution_branch: Vec<Root>, // 4 nodes
}

impl LightClientHeader {
    pub const FIXED_SIZE: usize = 244;

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::FIXED_SIZE {
            return err(format!(
                "LightClientHeader requires at least {} bytes, got {}",
                Self::FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let beacon = BeaconBlockHeader::decode(&ssz_bytes[..112])?;
        let execution_offset = ssz::read_u32(ssz_bytes, 112).unwrap() as usize;
        let execution_branch: Vec<Root> = (0..4)
            .map(|i| ssz::read_root(ssz_bytes, 116 + i * 32).unwrap())
            .collect();
        if execution_offset < Self::FIXED_SIZE || execution_offset > ssz_bytes.len() {
            return err(format!(
                "Invalid execution offset {execution_offset} in LightClientHeader"
            ));
        }
        let execution = ExecutionPayloadHeader::decode(&ssz_bytes[execution_offset..])?;
        Ok(Self { beacon, execution, execution_branch })
    }
}

// -------------------------------------------------------------------------
// LightClientBootstrap
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LightClientBootstrap {
    pub header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub current_sync_committee_branch: Vec<Root>, // 5 or 6, fork-sniffed
}

impl LightClientBootstrap {
    pub const MIN_FIXED_SIZE: usize = 4 + SyncCommittee::ENCODED_SIZE + 5 * 32; // 24788

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::MIN_FIXED_SIZE {
            return err(format!(
                "LightClientBootstrap requires at least {} bytes, got {}",
                Self::MIN_FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let header_offset = ssz::read_u32(ssz_bytes, 0).unwrap() as usize;
        // The header offset IS the fixed size; derive the fork-dependent branch len.
        let branch_bytes = header_offset
            .checked_sub(4 + SyncCommittee::ENCODED_SIZE)
            .unwrap_or(0);
        let branch_nodes = branch_bytes / 32;
        if !(5..=6).contains(&branch_nodes) || branch_bytes % 32 != 0 {
            return err(format!(
                "Invalid branch size: {branch_bytes} bytes (expected 160 or 192) in LightClientBootstrap"
            ));
        }
        let current_sync_committee =
            SyncCommittee::decode(&ssz_bytes[4..4 + SyncCommittee::ENCODED_SIZE])?;
        let branch_start = 4 + SyncCommittee::ENCODED_SIZE;
        // branch_nodes was sniffed from the ATTACKER-CONTROLLED offset: a 6-node
        // claim on a 5-node-sized buffer must reject, not panic (checked reads).
        let current_sync_committee_branch: Vec<Root> = (0..branch_nodes)
            .map(|i| ssz::read_root(ssz_bytes, branch_start + i * 32))
            .collect::<Option<_>>()
            .ok_or_else(|| SszError("LightClientBootstrap: truncated branch".into()))?;
        if header_offset > ssz_bytes.len() {
            return err(format!(
                "Invalid header offset {header_offset} in LightClientBootstrap"
            ));
        }
        let header = LightClientHeader::decode(&ssz_bytes[header_offset..])?;
        Ok(Self { header, current_sync_committee, current_sync_committee_branch })
    }
}

// -------------------------------------------------------------------------
// LightClientUpdate
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: Vec<Root>, // 5 or 6
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vec<Root>, // 6 or 7
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

impl LightClientUpdate {
    pub const MIN_FIXED_SIZE: usize =
        4 + SyncCommittee::ENCODED_SIZE + 5 * 32 + 4 + 6 * 32 + 160 + 8;

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::MIN_FIXED_SIZE {
            return err(format!(
                "LightClientUpdate requires at least {} bytes, got {}",
                Self::MIN_FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let attested_offset = ssz::read_u32(ssz_bytes, 0).unwrap() as usize;
        // Fork sniff (same tolerance as Java: unknown sizes fall back to pre-Electra).
        let total_branch_bytes = attested_offset
            .checked_sub(4 + SyncCommittee::ENCODED_SIZE + 4 + 160 + 8)
            .unwrap_or(0);
        let (sc_nodes, fin_nodes) = if total_branch_bytes == 6 * 32 + 7 * 32 {
            (6usize, 7usize) // Electra+
        } else {
            (5usize, 6usize) // pre-Electra (and the Java fallback)
        };

        let mut pos = 4usize;
        let next_sync_committee =
            SyncCommittee::decode(&ssz_bytes[pos..pos + SyncCommittee::ENCODED_SIZE])?;
        pos += SyncCommittee::ENCODED_SIZE;
        let next_sync_committee_branch: Vec<Root> = (0..sc_nodes)
            .map(|i| ssz::read_root(ssz_bytes, pos + i * 32).unwrap())
            .collect();
        pos += sc_nodes * 32;
        let finalized_offset = ssz::read_u32(ssz_bytes, pos)
            .ok_or_else(|| SszError("LightClientUpdate: truncated".into()))? as usize;
        pos += 4;
        let finality_branch: Vec<Root> = (0..fin_nodes)
            .map(|i| ssz::read_root(ssz_bytes, pos + i * 32))
            .collect::<Option<_>>()
            .ok_or_else(|| SszError("LightClientUpdate: truncated finality branch".into()))?;
        pos += fin_nodes * 32;
        let sync_aggregate = SyncAggregate::decode(
            ssz_bytes
                .get(pos..pos + SyncAggregate::ENCODED_SIZE)
                .ok_or_else(|| SszError("LightClientUpdate: truncated syncAggregate".into()))?,
        )?;
        pos += SyncAggregate::ENCODED_SIZE;
        let signature_slot = ssz::read_u64(ssz_bytes, pos)
            .ok_or_else(|| SszError("LightClientUpdate: truncated signatureSlot".into()))?;

        if attested_offset > ssz_bytes.len() {
            return err(format!("Invalid attestedHeader offset: {attested_offset}"));
        }
        let attested_end = if finalized_offset > attested_offset && finalized_offset <= ssz_bytes.len() {
            finalized_offset
        } else {
            ssz_bytes.len()
        };
        let attested_header = LightClientHeader::decode(&ssz_bytes[attested_offset..attested_end])?;
        if finalized_offset > ssz_bytes.len() {
            return err(format!("Invalid finalizedHeader offset: {finalized_offset}"));
        }
        let finalized_header = LightClientHeader::decode(&ssz_bytes[finalized_offset..])?;

        Ok(Self {
            attested_header,
            next_sync_committee,
            next_sync_committee_branch,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

// -------------------------------------------------------------------------
// LightClientFinalityUpdate
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LightClientFinalityUpdate {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    pub finality_branch: Vec<Root>, // 6 or 7
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

impl LightClientFinalityUpdate {
    pub const MIN_FIXED_SIZE: usize = 4 + 4 + 6 * 32 + 160 + 8; // 368

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::MIN_FIXED_SIZE {
            return err(format!(
                "LightClientFinalityUpdate requires at least {} bytes, got {}",
                Self::MIN_FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let attested_offset = ssz::read_u32(ssz_bytes, 0).unwrap() as usize;
        let finalized_offset = ssz::read_u32(ssz_bytes, 4).unwrap() as usize;

        let branch_bytes = attested_offset.checked_sub(4 + 4 + 160 + 8).unwrap_or(0);
        if branch_bytes % 32 != 0 {
            return err(format!(
                "Finality branch region is not a multiple of 32 bytes: {branch_bytes}"
            ));
        }
        let branch_nodes = branch_bytes / 32;
        if branch_nodes != 6 && branch_nodes != 7 {
            return err(format!(
                "Unexpected finality branch node count: {branch_nodes} (expected 6 or 7)"
            ));
        }
        // branch_nodes came from the ATTACKER-CONTROLLED attested offset: a 7-node
        // claim on a 6-node-sized buffer must reject, not panic (checked reads for
        // everything positioned after the sniffed branch).
        let finality_branch: Vec<Root> = (0..branch_nodes)
            .map(|i| ssz::read_root(ssz_bytes, 8 + i * 32))
            .collect::<Option<_>>()
            .ok_or_else(|| SszError("LightClientFinalityUpdate: truncated branch".into()))?;
        let mut pos = 8 + branch_nodes * 32;
        let sync_aggregate = SyncAggregate::decode(
            ssz_bytes
                .get(pos..pos + 160)
                .ok_or_else(|| SszError("LightClientFinalityUpdate: truncated syncAggregate".into()))?,
        )?;
        pos += 160;
        let signature_slot = ssz::read_u64(ssz_bytes, pos)
            .ok_or_else(|| SszError("LightClientFinalityUpdate: truncated signatureSlot".into()))?;

        let actual_fixed = 4 + 4 + branch_nodes * 32 + 160 + 8;
        if attested_offset < actual_fixed || attested_offset > ssz_bytes.len() {
            return err(format!("Invalid attestedHeader offset: {attested_offset}"));
        }
        if finalized_offset < actual_fixed || finalized_offset > ssz_bytes.len() {
            return err(format!("Invalid finalizedHeader offset: {finalized_offset}"));
        }
        let (attested_end, finalized_end) = if attested_offset < finalized_offset {
            (finalized_offset, ssz_bytes.len())
        } else {
            (ssz_bytes.len(), attested_offset)
        };
        let attested_header = LightClientHeader::decode(&ssz_bytes[attested_offset..attested_end])?;
        let finalized_header =
            LightClientHeader::decode(&ssz_bytes[finalized_offset..finalized_end])?;

        Ok(Self {
            attested_header,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Malformed/truncated inputs must come back as Err, never panic — these
    /// decoders face untrusted peer bytes.
    #[test]
    fn truncated_inputs_error_cleanly() {
        assert!(BeaconBlockHeader::decode(&[0u8; 111]).is_err());
        assert!(SyncCommittee::decode(&[0u8; 100]).is_err());
        assert!(SyncAggregate::decode(&[0u8; 159]).is_err());
        assert!(ExecutionPayloadHeader::decode(&[0u8; 583]).is_err());
        assert!(LightClientHeader::decode(&[0u8; 243]).is_err());
        assert!(LightClientBootstrap::decode(&[0u8; 100]).is_err());
        assert!(LightClientUpdate::decode(&[0u8; 100]).is_err());
        assert!(LightClientFinalityUpdate::decode(&[0u8; 100]).is_err());
    }

    /// All-zero buffers of plausible sizes carry nonsense offsets — still Err/Ok
    /// without panicking (offset arithmetic is checked, not trusted).
    #[test]
    fn zeroed_buffers_never_panic() {
        let _ = LightClientBootstrap::decode(&[0u8; LightClientBootstrap::MIN_FIXED_SIZE]);
        let _ = LightClientUpdate::decode(&[0u8; LightClientUpdate::MIN_FIXED_SIZE]);
        let _ = LightClientFinalityUpdate::decode(&[0u8; LightClientFinalityUpdate::MIN_FIXED_SIZE]);
        let _ = LightClientHeader::decode(&[0u8; LightClientHeader::FIXED_SIZE]);
        let _ = ExecutionPayloadHeader::decode(&[0u8; DENEB_FIXED_SIZE]);
    }

    /// The review's exact reproducers: fork-sniff offsets claiming the LARGER
    /// (Electra) shape over a minimum-size buffer must reject, never panic.
    #[test]
    fn forged_fork_sniff_offsets_reject_cleanly() {
        // Bootstrap: 6-node claim (offset 24820) over a 5-node-sized buffer.
        let mut b = vec![0u8; LightClientBootstrap::MIN_FIXED_SIZE];
        b[..4].copy_from_slice(&24820u32.to_le_bytes());
        assert!(LightClientBootstrap::decode(&b).is_err());

        // FinalityUpdate: 7-node claim (offset 400) over a 368-byte buffer —
        // panicked at the syncAggregate slice before the fix.
        let mut f = vec![0u8; LightClientFinalityUpdate::MIN_FIXED_SIZE];
        f[..4].copy_from_slice(&400u32.to_le_bytes());
        assert!(LightClientFinalityUpdate::decode(&f).is_err());

        // FinalityUpdate: 399-byte buffer — the aggregate slice fits but the
        // signatureSlot read runs off the end.
        let mut f = vec![0u8; 399];
        f[..4].copy_from_slice(&400u32.to_le_bytes());
        assert!(LightClientFinalityUpdate::decode(&f).is_err());
    }

    /// Electra extraData offset over a Deneb-sized buffer: clean Err (the Java
    /// twin throws BufferUnderflowException — a rejection on both engines).
    #[test]
    fn eph_electra_offset_short_buffer_rejected() {
        let mut e = vec![0u8; DENEB_FIXED_SIZE];
        e[436..440].copy_from_slice(&(ELECTRA_FIXED_SIZE as u32).to_le_bytes());
        assert!(ExecutionPayloadHeader::decode(&e).is_err());
    }

    /// Bootstrap with a header offset pointing past the buffer must be rejected.
    #[test]
    fn bootstrap_bad_offset_rejected() {
        let mut b = vec![0u8; LightClientBootstrap::MIN_FIXED_SIZE];
        // offset = fixed size (valid branch len) but buffer ends exactly there → the
        // embedded LightClientHeader decode fails on the empty tail.
        b[..4].copy_from_slice(&(LightClientBootstrap::MIN_FIXED_SIZE as u32).to_le_bytes());
        assert!(LightClientBootstrap::decode(&b).is_err());
    }
}
