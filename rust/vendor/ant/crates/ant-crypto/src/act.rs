//! Swarm ACT (access control) key derivation and reference encryption.
//!
//! Mirrors bee's `pkg/accesscontrol` cryptography exactly:
//!
//! - **Session KDF** (`session.go::SessionStruct.Key`): an ECDH between
//!   the node's secp256k1 key and a counterparty public key. The shared
//!   secret is the **x coordinate** of `pub · priv`, encoded the way
//!   Go's `big.Int.Bytes()` does — big-endian *with leading zero bytes
//!   stripped* (so roughly one derivation in 256 hashes fewer than 32
//!   bytes; ant must reproduce that to interoperate). For each nonce
//!   `n`, the derived key is `keccak256(x_bytes ‖ n)`.
//! - **Lookup key / access-key-decryption key**
//!   (`access.go::getKeys`): nonces `[0x00]` and `[0x01]` respectively.
//!   The lookup key indexes the grantee's row in the ACT key-value
//!   store; the AK-decryption key unwraps the stored access key.
//! - **Access-key wrap** (`access.go::AddGrantee`): the 32-byte access
//!   key XOR-encrypted under the grantee's AK-decryption key with bee's
//!   Keccak counter-mode stream cipher (`encryption.New(key, 0, 0,
//!   keccak256)` — [`crate::encryption::stream_xor_in_place`]).
//! - **Reference encryption** (`access.go::EncryptRef` /
//!   `DecryptRef`): the Swarm reference (32 bytes plain, 64 when the
//!   content itself is encrypted) `XOR`ed with the same stream cipher
//!   keyed by the access key.
//! - **Publisher-only wrap** (`controller.go::encryptRefForPublisher`):
//!   the grantee-list reference is encrypted under the publisher's own
//!   nonce-`[0x01]` session key (an ECDH of the node key with itself).
//!
//! Everything here is deterministic given the inputs and pinned by the
//! `act.json` conformance vectors generated from bee's own package.

use k256::elliptic_curve::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};

use crate::encryption::{stream_xor_in_place, KEY_LENGTH};
use crate::{keccak256, CryptoError};

/// Nonce deriving the ACT **lookup key** (bee's `zeroByteArray`).
pub const NONCE_LOOKUP: &[u8] = &[0];
/// Nonce deriving the ACT **access-key-decryption key** (bee's
/// `oneByteArray`).
pub const NONCE_AK_DECRYPT: &[u8] = &[1];

/// Parse a secp256k1 public key from SEC1 bytes (33-byte compressed or
/// 65-byte uncompressed), as bee's `btcec.ParsePubKey` accepts.
pub fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)
}

/// Compressed SEC1 encoding (33 bytes) — bee's
/// `crypto.EncodeSecp256k1PublicKey`, the wire form of `/grantee`
/// responses and the `swarm-act-publisher` header.
#[must_use]
pub fn compress_public_key(pk: &PublicKey) -> [u8; 33] {
    let ep = pk.to_encoded_point(true);
    ep.as_bytes().try_into().expect("compressed SEC1 point")
}

/// Uncompressed SEC1 encoding (65 bytes, `0x04`-prefixed) — bee's
/// `crypto.S256().Marshal`, the on-disk grantee-list entry form.
#[must_use]
pub fn uncompress_public_key(pk: &PublicKey) -> [u8; 65] {
    let ep = pk.to_encoded_point(false);
    ep.as_bytes().try_into().expect("uncompressed SEC1 point")
}

/// Public key of a 32-byte secp256k1 secret.
pub fn public_key_of(secret: &[u8; 32]) -> Result<PublicKey, CryptoError> {
    let sk = SecretKey::from_slice(secret).map_err(CryptoError::InvalidSecretKey)?;
    Ok(sk.public_key())
}

/// ECDH shared-secret x coordinate between `secret` and `public`,
/// encoded like Go's `big.Int.Bytes()`: big-endian, leading zero bytes
/// stripped. This is the exact byte string bee feeds into the session
/// KDF (`session.go` uses `x.Bytes()`).
pub fn shared_secret_x(secret: &[u8; 32], public: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    let sk = SecretKey::from_slice(secret).map_err(CryptoError::InvalidSecretKey)?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), public.as_affine());
    let x = shared.raw_secret_bytes();
    let start = x.iter().position(|&b| b != 0).unwrap_or(x.len());
    Ok(x[start..].to_vec())
}

/// Bee's `Session.Key`: one derived 32-byte key per nonce,
/// `keccak256(shared_x ‖ nonce)`.
pub fn session_keys(
    secret: &[u8; 32],
    public: &PublicKey,
    nonces: &[&[u8]],
) -> Result<Vec<[u8; 32]>, CryptoError> {
    let x = shared_secret_x(secret, public)?;
    Ok(nonces
        .iter()
        .map(|nonce| {
            let mut input = Vec::with_capacity(x.len() + nonce.len());
            input.extend_from_slice(&x);
            input.extend_from_slice(nonce);
            keccak256(&input)
        })
        .collect())
}

/// Bee's `getKeys`: `(lookup_key, access_key_decryption_key)` for a
/// counterparty public key — nonces `[0x00]` and `[0x01]`.
pub fn lookup_and_ak_decryption_keys(
    secret: &[u8; 32],
    public: &PublicKey,
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let keys = session_keys(secret, public, &[NONCE_LOOKUP, NONCE_AK_DECRYPT])?;
    Ok((keys[0], keys[1]))
}

/// Wrap (encrypt) a 32-byte access key under an AK-decryption key —
/// bee's `AddGrantee` cipher step. The same function unwraps (the
/// cipher is an XOR stream).
#[must_use]
pub fn seal_access_key(access_key: &[u8; 32], ak_decryption_key: &[u8; 32]) -> [u8; 32] {
    let mut out = *access_key;
    stream_xor_in_place(&mut out, ak_decryption_key);
    out
}

/// Encrypt or decrypt a Swarm reference (32 or 64 bytes — the cipher is
/// length-preserving) under the ACT access key — bee's
/// `EncryptRef`/`DecryptRef`.
#[must_use]
pub fn transform_reference(reference: &[u8], key: &[u8; KEY_LENGTH]) -> Vec<u8> {
    let mut out = reference.to_vec();
    stream_xor_in_place(&mut out, key);
    out
}

/// A fresh random 32-byte ACT access key (bee's
/// `encryption.GenerateRandomKey(KeyLength)` in `AddGrantee`).
#[must_use]
pub fn random_access_key() -> [u8; 32] {
    crate::random_encryption_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_is_symmetric() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let pa = public_key_of(&a).unwrap();
        let pb = public_key_of(&b).unwrap();
        assert_eq!(
            shared_secret_x(&a, &pb).unwrap(),
            shared_secret_x(&b, &pa).unwrap()
        );
    }

    #[test]
    fn lookup_and_decrypt_keys_differ() {
        let secret = [0x33u8; 32];
        let public = public_key_of(&[0x44u8; 32]).unwrap();
        let (lookup, akdk) = lookup_and_ak_decryption_keys(&secret, &public).unwrap();
        assert_ne!(lookup, akdk);
    }

    #[test]
    fn access_key_wrap_round_trips() {
        let ak = [0xabu8; 32];
        let kdk = [0xcdu8; 32];
        let sealed = seal_access_key(&ak, &kdk);
        assert_ne!(sealed, ak);
        assert_eq!(seal_access_key(&sealed, &kdk), ak);
    }

    #[test]
    fn reference_transform_round_trips_both_widths() {
        let key = [0x55u8; 32];
        for len in [32usize, 64] {
            let reference: Vec<u8> = (0..len as u8).collect();
            let enc = transform_reference(&reference, &key);
            assert_eq!(enc.len(), len);
            assert_ne!(enc, reference);
            assert_eq!(transform_reference(&enc, &key), reference);
        }
    }

    #[test]
    fn pubkey_encodings_round_trip() {
        let pk = public_key_of(&[0x66u8; 32]).unwrap();
        let comp = compress_public_key(&pk);
        let uncomp = uncompress_public_key(&pk);
        assert_eq!(parse_public_key(&comp).unwrap(), pk);
        assert_eq!(parse_public_key(&uncomp).unwrap(), pk);
    }
}
