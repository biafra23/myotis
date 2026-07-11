//! The node's secp256k1 identity — twin of `core.crypto.NodeKey` (Java).
//!
//! Used for: ENR identity, RLPx ECIES handshake, discv4 packet signing.
//! Wire conventions (docs/reimplementation/02 §1.1, §9):
//! - public key crosses as 64 bytes uncompressed WITHOUT the `0x04` prefix;
//! - `nodeId = keccak256(pubkey64)` (the Kademlia node ID / enode id);
//! - signatures are 65 bytes `r(32) ‖ s(32) ‖ v(1)` with `v` = recovery id
//!   0/1 (matching Tuweni/go-ethereum), low-s canonical, RFC 6979 nonces;
//! - `sign_hash` signs a pre-computed 32-byte hash directly, NO re-hashing;
//! - ECDH shared secret = the 32-byte big-endian X coordinate (raw, unhashed).
//!
//! No key GENERATION here: this crate is sans-I/O (no entropy source). The
//! I/O crates generate 32 secret bytes from OS randomness and construct via
//! [`NodeKey::from_secret_bytes`].

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::keccak::keccak256;
use crate::{err, CoreError};

/// secp256k1 identity key pair.
pub struct NodeKey {
    signing: SigningKey,
    /// Cached uncompressed public key, without the 0x04 prefix.
    pubkey64: [u8; 64],
}

impl NodeKey {
    /// Build from a 32-byte secret. Rejects zero / out-of-range scalars.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<NodeKey, CoreError> {
        let signing = SigningKey::from_bytes(secret.into())
            .map_err(|_| CoreError("secp256k1: invalid secret scalar".into()))?;
        let pubkey64 = encode_uncompressed(signing.verifying_key());
        Ok(NodeKey { signing, pubkey64 })
    }

    /// Uncompressed 64-byte public key (without 0x04 prefix).
    pub fn public_key_bytes(&self) -> [u8; 64] {
        self.pubkey64
    }

    /// Node ID = keccak256(publicKeyBytes) — used as the Kademlia node ID.
    pub fn node_id(&self) -> [u8; 32] {
        keccak256(&self.pubkey64)
    }

    /// The 32-byte secret scalar (for persistence by the I/O layer).
    pub fn secret_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.signing.to_bytes());
        out
    }

    /// Sign a pre-computed 32-byte hash directly (no re-hashing).
    /// Returns `r(32) ‖ s(32) ‖ v(1)`, low-s, deterministic (RFC 6979).
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 65], CoreError> {
        let (sig, recid): (Signature, RecoveryId) = self
            .signing
            .sign_prehash_recoverable(hash)
            .map_err(|e| CoreError(format!("secp256k1: signing failed: {e}")))?;
        // k256 yields low-s already; normalize defensively so the recovery id
        // stays consistent if that ever changes.
        let (sig, recid) = match sig.normalize_s() {
            Some(normalized) => {
                let flipped = RecoveryId::from_byte(recid.to_byte() ^ 1)
                    .ok_or_else(|| CoreError("secp256k1: bad recovery id".into()))?;
                (normalized, flipped)
            }
            None => (sig, recid),
        };
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = recid.to_byte();
        Ok(out)
    }

    /// ECDH: shared secret = X coordinate of `secret * peer_pubkey`, raw
    /// 32 bytes big-endian (the RLPx/ECIES convention — no KDF here).
    pub fn ecdh_x(&self, peer_pubkey64: &[u8; 64]) -> Result<[u8; 32], CoreError> {
        let peer = decode_uncompressed(peer_pubkey64)?;
        let shared = k256::ecdh::diffie_hellman(
            self.signing.as_nonzero_scalar(),
            peer.as_affine(),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }
}

/// Recover the 64-byte public key from a 32-byte hash and a 65-byte
/// `r ‖ s ‖ v` signature (v = recovery id 0/1).
pub fn recover_public_key(hash: &[u8; 32], sig65: &[u8; 65]) -> Result<[u8; 64], CoreError> {
    let recid = match sig65[64] {
        v @ 0..=1 => RecoveryId::from_byte(v)
            .ok_or_else(|| CoreError("secp256k1: bad recovery id".into()))?,
        v => return err(format!("secp256k1: recovery id {v} out of range")),
    };
    let sig = Signature::from_slice(&sig65[..64])
        .map_err(|_| CoreError("secp256k1: malformed signature".into()))?;
    let key = VerifyingKey::recover_from_prehash(hash, &sig, recid)
        .map_err(|_| CoreError("secp256k1: public key recovery failed".into()))?;
    Ok(encode_uncompressed(&key))
}

/// Decompress a 33-byte SEC1 compressed public key to the 64-byte form
/// (ENRs store keys compressed — docs/reimplementation/02 §1.3).
pub fn decompress_public_key(compressed33: &[u8]) -> Result<[u8; 64], CoreError> {
    if compressed33.len() != 33 {
        return err(format!(
            "secp256k1: compressed key must be 33 bytes, got {}",
            compressed33.len()
        ));
    }
    let key = k256::PublicKey::from_sec1_bytes(compressed33)
        .map_err(|_| CoreError("secp256k1: invalid compressed public key".into()))?;
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 64];
    out.copy_from_slice(&point.as_bytes()[1..]);
    Ok(out)
}

/// Compress a 64-byte public key to the 33-byte SEC1 form.
pub fn compress_public_key(pubkey64: &[u8; 64]) -> Result<[u8; 33], CoreError> {
    let key = decode_uncompressed(pubkey64)?;
    let point = key.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    Ok(out)
}

fn encode_uncompressed(key: &VerifyingKey) -> [u8; 64] {
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 64];
    // SEC1 uncompressed is 0x04 ‖ x ‖ y — strip the prefix.
    out.copy_from_slice(&point.as_bytes()[1..]);
    out
}

fn decode_uncompressed(pubkey64: &[u8; 64]) -> Result<k256::PublicKey, CoreError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(pubkey64);
    k256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| CoreError("secp256k1: invalid public key (not on curve)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> NodeKey {
        let mut secret = [0u8; 32];
        secret[31] = n;
        NodeKey::from_secret_bytes(&secret).unwrap()
    }

    #[test]
    fn rejects_invalid_secrets() {
        assert!(NodeKey::from_secret_bytes(&[0u8; 32]).is_err());
        assert!(NodeKey::from_secret_bytes(&[0xff; 32]).is_err()); // > curve order
    }

    #[test]
    fn sign_and_recover_round_trip() {
        let k = key(7);
        let hash = keccak256(b"myotis");
        let sig = k.sign_hash(&hash).unwrap();
        assert!(sig[64] <= 1);
        let recovered = recover_public_key(&hash, &sig).unwrap();
        assert_eq!(recovered, k.public_key_bytes());
        // Deterministic (RFC 6979): same input, same signature.
        assert_eq!(sig, k.sign_hash(&hash).unwrap());
    }

    #[test]
    fn recover_rejects_garbage() {
        let hash = [0x11u8; 32];
        let mut sig = [0u8; 65];
        sig[64] = 4; // legacy-EIP-155-style v values are NOT accepted here
        assert!(recover_public_key(&hash, &sig).is_err());
    }

    #[test]
    fn ecdh_is_symmetric() {
        let (a, b) = (key(2), key(3));
        let ab = a.ecdh_x(&b.public_key_bytes()).unwrap();
        let ba = b.ecdh_x(&a.public_key_bytes()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn compress_round_trip() {
        let k = key(9);
        let compressed = compress_public_key(&k.public_key_bytes()).unwrap();
        assert_eq!(
            decompress_public_key(&compressed).unwrap(),
            k.public_key_bytes()
        );
    }
}
