//! `Status` / `MetaData` SSZ containers and the fork-digest math — Rust twins of
//! the Java `StatusMessage` / `MetadataMessage` / `BeaconLightClient.computeForkDigest`.

use myotis_consensus::ssz;

/// `Status` v2 (post-Electra, `/req/status/2`): 92 bytes fixed.
/// v1 (`/req/status/1`) is the same layout without `earliest_available_slot` (84 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMessage {
    pub fork_digest: [u8; 4],
    pub finalized_root: [u8; 32],
    pub finalized_epoch: u64,
    pub head_root: [u8; 32],
    pub head_slot: u64,
    pub earliest_available_slot: u64,
}

impl StatusMessage {
    pub const SSZ_SIZE_V2: usize = 92;
    pub const SSZ_SIZE_V1: usize = 84;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SSZ_SIZE_V2);
        out.extend_from_slice(&self.fork_digest);
        out.extend_from_slice(&self.finalized_root);
        out.extend_from_slice(&self.finalized_epoch.to_le_bytes());
        out.extend_from_slice(&self.head_root);
        out.extend_from_slice(&self.head_slot.to_le_bytes());
        out.extend_from_slice(&self.earliest_available_slot.to_le_bytes());
        out
    }

    /// v1: 84 bytes, no `earliest_available_slot`.
    pub fn encode_v1(&self) -> Vec<u8> {
        let mut out = self.encode();
        out.truncate(Self::SSZ_SIZE_V1);
        out
    }

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, String> {
        if ssz_bytes.len() < Self::SSZ_SIZE_V2 {
            return Err(format!(
                "Status requires {} bytes, got {}",
                Self::SSZ_SIZE_V2,
                ssz_bytes.len()
            ));
        }
        let mut s = Self::decode_v1(ssz_bytes)?;
        s.earliest_available_slot =
            u64::from_le_bytes(ssz_bytes[84..92].try_into().expect("length checked"));
        Ok(s)
    }

    /// v1 decode: 84 bytes, `earliest_available_slot` defaulted to 0.
    pub fn decode_v1(ssz_bytes: &[u8]) -> Result<Self, String> {
        if ssz_bytes.len() < Self::SSZ_SIZE_V1 {
            return Err(format!(
                "Status v1 requires {} bytes, got {}",
                Self::SSZ_SIZE_V1,
                ssz_bytes.len()
            ));
        }
        Ok(Self {
            fork_digest: ssz_bytes[0..4].try_into().expect("length checked"),
            finalized_root: ssz_bytes[4..36].try_into().expect("length checked"),
            finalized_epoch: u64::from_le_bytes(ssz_bytes[36..44].try_into().expect("len")),
            head_root: ssz_bytes[44..76].try_into().expect("length checked"),
            head_slot: u64::from_le_bytes(ssz_bytes[76..84].try_into().expect("len")),
            earliest_available_slot: 0,
        })
    }
}

/// `MetaData` v2 (`/req/metadata/2`): seq_number(8) || attnets Bitvector[64](8)
/// || syncnets Bitvector[4](1) = 17 bytes. A pure light client subscribes to
/// nothing, so the canonical answer is all zeros.
pub fn metadata_v2_light_client() -> Vec<u8> {
    vec![0u8; 17]
}

// -------------------------------------------------------------------------
// Fork digest
// -------------------------------------------------------------------------

/// `compute_fork_data_root(fork_version, genesis_validators_root)` — the full
/// 32-byte hash_tree_root of ForkData, over the same ssz primitives
/// `myotis_consensus::verify::compute_domain` uses internally.
pub fn fork_data_root(fork_version: [u8; 4], genesis_validators_root: [u8; 32]) -> [u8; 32] {
    ssz::container_root(&[ssz::padded_root(&fork_version), genesis_validators_root])
}

/// Pre-Fulu `compute_fork_digest`: first 4 bytes of the ForkData root.
pub fn fork_digest(fork_version: [u8; 4], genesis_validators_root: [u8; 32]) -> [u8; 4] {
    let root = fork_data_root(fork_version, genesis_validators_root);
    root[..4].try_into().expect("4 <= 32")
}

/// Fulu / EIP-7892 `compute_fork_digest`, folding the active BPO blob params in:
/// `(fork_data_root XOR sha256(u64_le(epoch) || u64_le(max_blobs)))[0..4]`.
/// `blob_params_epoch == 0` means no BPO is active → the pre-Fulu formula.
/// Mirrors `BeaconLightClient.computeForkDigest` / `NetworkConfig.currentForkDigest`.
pub fn fork_digest_bpo(
    fork_version: [u8; 4],
    genesis_validators_root: [u8; 32],
    blob_params_epoch: u64,
    blob_params_max_blobs: u64,
) -> [u8; 4] {
    let base = fork_data_root(fork_version, genesis_validators_root);
    if blob_params_epoch == 0 {
        return base[..4].try_into().expect("4 <= 32");
    }
    // sha256(epoch_le || max_blobs_le) via the consensus crate's pair hash.
    let bp_hash = ssz::sha256_pair(&blob_params_epoch.to_le_bytes(), &blob_params_max_blobs.to_le_bytes());
    let mut out = [0u8; 4];
    for i in 0..4 {
        out[i] = base[i] ^ bp_hash[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet_gvr() -> [u8; 32] {
        let hex = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// The live values the Java side computes for mainnet (Fulu 0x06000000,
    /// BPO2 epoch=419072 max_blobs=21 — NetworkConfig.MAINNET).
    #[test]
    fn mainnet_fork_digest_matches_java() {
        let base = fork_digest([0x06, 0, 0, 0], mainnet_gvr());
        assert_eq!(base, [0x82, 0xFA, 0xE5, 0x41]);
        let bpo = fork_digest_bpo([0x06, 0, 0, 0], mainnet_gvr(), 419_072, 21);
        assert_eq!(bpo, [0x8C, 0x9F, 0x62, 0xFE]);
        // epoch == 0 falls back to the base formula.
        assert_eq!(fork_digest_bpo([0x06, 0, 0, 0], mainnet_gvr(), 0, 0), base);
    }

    #[test]
    fn status_round_trips_both_versions() {
        let s = StatusMessage {
            fork_digest: [0x8C, 0x9F, 0x62, 0xFE],
            finalized_root: [7u8; 32],
            finalized_epoch: 455_000,
            head_root: [9u8; 32],
            head_slot: 14_560_000,
            earliest_available_slot: 42,
        };
        let v2 = s.encode();
        assert_eq!(v2.len(), StatusMessage::SSZ_SIZE_V2);
        assert_eq!(StatusMessage::decode(&v2).unwrap(), s);

        let v1 = s.encode_v1();
        assert_eq!(v1.len(), StatusMessage::SSZ_SIZE_V1);
        let d1 = StatusMessage::decode_v1(&v1).unwrap();
        assert_eq!(d1.earliest_available_slot, 0);
        assert_eq!(d1.head_slot, s.head_slot);
        assert!(StatusMessage::decode(&v1).is_err()); // 84 bytes is not a v2
    }

    #[test]
    fn metadata_is_17_zero_bytes() {
        assert_eq!(metadata_v2_light_client(), vec![0u8; 17]);
    }
}
