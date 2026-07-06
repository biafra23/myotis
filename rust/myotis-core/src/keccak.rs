//! keccak-256 — the EXECUTION-layer hash (block hashes, node IDs, MPT paths,
//! discv4 packet hashes). Never confuse with the consensus layer's SHA-256
//! (docs/reimplementation README §11.6: SSZ = SHA-256 + little-endian, MPT =
//! keccak-256 + RLP + big-endian).

use sha3::{Digest, Keccak256};

/// `keccak256(data)` — 32 bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// `keccak256(a ‖ b)` without an intermediate concatenation buffer — the
/// discv4 packet layout hashes two-part messages everywhere.
pub fn keccak256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(a);
    hasher.update(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_matches_known_vector() {
        // keccak256("") — the canonical empty hash every Ethereum tool pins.
        let h = keccak256(b"");
        assert_eq!(
            hex(&h),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn concat_equals_joined() {
        assert_eq!(keccak256_concat(b"ab", b"cd"), keccak256(b"abcd"));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
