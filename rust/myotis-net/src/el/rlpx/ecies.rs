//! ECIES for RLPx auth/ack (EL-A4), twin of the Java `rlpx.EciesCodec`
//! (docs/reimplementation/02 §5.1, §9.2).
//!
//! Encrypted message: `0x04 ‖ ephemeral-pubkey(65) ‖ IV(16) ‖ ciphertext ‖ MAC(32)`.
//!
//! Load-bearing constants (getting any wrong silently breaks the handshake):
//! - KDF = **NIST concat-KDF with SHA-256**: `SHA256(counter_be32 ‖ Z)`,
//!   counter from 1 — NOT `SHA256(Z ‖ counter)`.
//! - symmetric cipher = **AES-128-CTR** with a random 16-byte IV;
//! - MAC = `HMAC-SHA256(SHA256(macKey), IV ‖ ciphertext ‖ aad)`, AAD ALWAYS
//!   included (even when empty).
//!
//! `encrypt` takes the ephemeral secret and IV as PARAMETERS (the service
//! supplies OS entropy) so the pure path is deterministic and testable; the
//! shared secret comes from the k256 ECDH in `myotis_core`.

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use myotis_core::nodekey::NodeKey;
use myotis_core::CoreError;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;

const KEY_SIZE: usize = 16; // AES-128 enc key
const MAC_KEY_SIZE: usize = 16; // raw KDF mac-key material, then SHA256'd to the HMAC key
const IV_SIZE: usize = 16;
const MAC_SIZE: usize = 32;

/// Encrypt `plaintext` to `recipient_pub64` with a caller-supplied ephemeral
/// secret and IV. `aad` is folded into the MAC (EIP-8 size prefix; empty for
/// legacy). Output: `0x04 ‖ ephPub(64) ‖ IV(16) ‖ ct ‖ MAC(32)`.
pub fn encrypt(
    plaintext: &[u8],
    recipient_pub64: &[u8; 64],
    ephemeral_secret: &[u8; 32],
    iv: &[u8; IV_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let ephemeral = NodeKey::from_secret_bytes(ephemeral_secret)?;
    let shared = ephemeral.ecdh_x(recipient_pub64)?;
    let (enc_key, mac_key) = derive_keys(&shared);

    let mut ciphertext = plaintext.to_vec();
    Aes128Ctr::new((&enc_key).into(), iv.into()).apply_keystream(&mut ciphertext);

    let mac = compute_mac(&mac_key, iv, &ciphertext, aad);

    let eph_pub = ephemeral.public_key_bytes();
    let mut out = Vec::with_capacity(65 + IV_SIZE + ciphertext.len() + MAC_SIZE);
    out.push(0x04);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Decrypt an ECIES message with the recipient's static key. `aad` must match
/// what the sender used (EIP-8 size prefix; empty for legacy).
pub fn decrypt(
    encrypted: &[u8],
    recipient: &NodeKey,
    aad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    // 0x04 ‖ ephPub(64) ‖ IV(16) ‖ ct ‖ MAC(32) — minimum is the empty-ct case.
    if encrypted.len() < 1 + 64 + IV_SIZE + MAC_SIZE {
        return Err(CoreError("ECIES: message too short".into()));
    }
    if encrypted[0] != 0x04 {
        return Err(CoreError("ECIES: expected uncompressed point marker 0x04".into()));
    }
    let mut eph_pub = [0u8; 64];
    eph_pub.copy_from_slice(&encrypted[1..65]);
    let iv = &encrypted[65..65 + IV_SIZE];
    let ct_and_mac = &encrypted[65 + IV_SIZE..];
    let (ciphertext, mac) = ct_and_mac.split_at(ct_and_mac.len() - MAC_SIZE);

    // ecdh_x validates the ephemeral point is on the curve.
    let shared = recipient.ecdh_x(&eph_pub)?;
    let (enc_key, mac_key) = derive_keys(&shared);

    let expected = compute_mac(&mac_key, iv, ciphertext, aad);
    if !constant_time_eq(mac, &expected) {
        return Err(CoreError("ECIES: MAC verification failed".into()));
    }

    let mut plain = ciphertext.to_vec();
    let mut iv_arr = [0u8; IV_SIZE];
    iv_arr.copy_from_slice(iv);
    Aes128Ctr::new((&enc_key).into(), (&iv_arr).into()).apply_keystream(&mut plain);
    Ok(plain)
}

/// Concat-KDF over the shared X: 32 bytes → `(enc_key[16], mac_key[16])`.
fn derive_keys(shared: &[u8; 32]) -> ([u8; KEY_SIZE], [u8; MAC_KEY_SIZE]) {
    let material = concat_kdf(shared, KEY_SIZE + MAC_KEY_SIZE);
    let mut enc_key = [0u8; KEY_SIZE];
    let mut mac_key = [0u8; MAC_KEY_SIZE];
    enc_key.copy_from_slice(&material[..KEY_SIZE]);
    mac_key.copy_from_slice(&material[KEY_SIZE..KEY_SIZE + MAC_KEY_SIZE]);
    (enc_key, mac_key)
}

/// NIST SP 800-56 concat-KDF with SHA-256: `SHA256(counter_be32 ‖ Z)`,
/// counter from 1. (NOT `SHA256(Z ‖ counter)` — that's the classic bug.)
fn concat_kdf(shared: &[u8], output_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(output_len);
    let mut counter: u32 = 1;
    while out.len() < output_len {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(shared);
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(output_len);
    out
}

/// `HMAC-SHA256(SHA256(mac_key), IV ‖ ciphertext ‖ aad)`.
fn compute_mac(mac_key: &[u8; MAC_KEY_SIZE], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> [u8; 32] {
    let hashed_key = Sha256::digest(mac_key);
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(&hashed_key)
        .expect("HMAC accepts any key length");
    hmac.update(iv);
    hmac.update(ciphertext);
    hmac.update(aad);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hmac.finalize().into_bytes());
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::keccak::keccak256;

    #[test]
    fn round_trip_with_and_without_aad() {
        let recipient = NodeKey::from_secret_bytes(&keccak256(b"ecies:recipient")).unwrap();
        let eph = keccak256(b"ecies:ephemeral");
        let iv = {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&keccak256(b"ecies:iv")[..16]);
            iv
        };
        let msg = b"Hello, World! This is a test message.";

        let enc = encrypt(msg, &recipient.public_key_bytes(), &eph, &iv, &[]).unwrap();
        assert_eq!(enc[0], 0x04);
        assert_eq!(decrypt(&enc, &recipient, &[]).unwrap(), msg);

        let aad = [0x01u8, 0xb3];
        let enc = encrypt(msg, &recipient.public_key_bytes(), &eph, &iv, &aad).unwrap();
        assert_eq!(decrypt(&enc, &recipient, &aad).unwrap(), msg);
        // Wrong AAD → MAC failure.
        assert!(decrypt(&enc, &recipient, &[0x02, 0x00]).is_err());
    }

    #[test]
    fn kdf_matches_known_vector() {
        // Concat-KDF(SHA256) of a 32-byte all-0x01 Z, 32 bytes out. Pinned
        // here so a future refactor can't silently flip to SHA256(Z‖counter).
        let z = [0x01u8; 32];
        let out = concat_kdf(&z, 32);
        // SHA256( 00000001 ‖ 01*32 ).
        let mut h = Sha256::new();
        h.update(1u32.to_be_bytes());
        h.update(z);
        assert_eq!(&out[..], &h.finalize()[..]);
    }

    #[test]
    fn decrypt_rejects_truncated() {
        let recipient = NodeKey::from_secret_bytes(&keccak256(b"r")).unwrap();
        assert!(decrypt(&[0x04; 50], &recipient, &[]).is_err());
    }
}
