//! Single-owner-chunk validation.
//!
//! Mirrors `bee/pkg/soc/soc.go::FromChunk` + `soc.Valid`. A SOC chunk is
//! addressed by `keccak256(id ‖ owner)` rather than by BMT hashing —
//! this lets the owner publish updates at a stable known address while
//! still binding the *content* to a signed envelope.
//!
//! Wire layout (without the outer 8-byte LE span that `RetrievedChunk`
//! carries):
//!
//! ```text
//! id(32) ‖ signature(65) ‖ cac_data(span(8) ‖ payload(N))
//! ```
//!
//! The signature is over `keccak256(id ‖ inner_cac_address)` (no
//! EIP-191 prefix). The recovered Ethereum address is the SOC's owner,
//! and `keccak256(id ‖ owner) == soc_address` must hold.

use crate::bmt::bmt_hash_with_span;
use crate::{ethereum_address_from_public_key, keccak256, recover_public_key, SPAN_SIZE};

/// Length of the SOC id field (bytes).
pub const SOC_ID_SIZE: usize = 32;
/// Length of the SOC signature field (bytes).
pub const SOC_SIG_SIZE: usize = 65;
/// `id ‖ sig` block that precedes the wrapped CAC.
pub const SOC_HEADER_SIZE: usize = SOC_ID_SIZE + SOC_SIG_SIZE;
/// Minimum SOC chunk size *including* the wrapped CAC's span: header +
/// span. Anything below this can't possibly be a valid SOC chunk.
pub const SOC_MIN_CHUNK_SIZE: usize = SOC_HEADER_SIZE + SPAN_SIZE;

/// Owner address of every dispersed replica SOC: the Ethereum address of
/// the well-known private key [`REPLICAS_OWNER_SECRET`] (bee
/// `swarm.ReplicasOwner`).
pub const REPLICAS_OWNER: [u8; 20] = [
    0xdc, 0x5b, 0x20, 0x84, 0x7f, 0x43, 0xd6, 0x79, 0x28, 0xf4, 0x9c, 0xd4, 0xf8, 0x5d, 0x69, 0x6b,
    0x5a, 0x76, 0x17, 0xb5,
];

/// The well-known private key behind [`REPLICAS_OWNER`] (bee
/// `pkg/replicas/replicas.go`: `crypto.DecodeSecp256k1PrivateKey(
/// append([]byte{1}, make([]byte, 31)...))`). Deliberately public —
/// anyone must be able to mint (and verify) dispersed replicas of any
/// chunk; the upload side signs replica SOCs with it. Because anyone can
/// sign with it, [`soc_valid`] additionally pins a replica SOC's id to
/// the chunk it wraps (check 4).
pub const REPLICAS_OWNER_SECRET: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

/// Validate a single-owner-chunk whose wire bytes are
/// `id ‖ sig ‖ inner_cac` (where `inner_cac = span(8 LE) ‖ payload`).
/// **No outer span** — that's what `swarm.Chunk.Data()` returns for a
/// SOC: see `bee/pkg/soc/soc.go::toBytes` which writes
/// `id ‖ sig ‖ chunk.Data()` and the inner chunk's `Data()` already
/// includes its own span. CAC chunks, by contrast, have just one span
/// at the front of their `Data()`.
///
/// Returns `true` iff:
///
/// 1. The wire bytes have the right shape (large enough, inner CAC
///    parses, signature is the right length).
/// 2. The inner CAC's BMT hash matches the address that the SOC
///    signature signs.
/// 3. The signature recovers an Ethereum address `owner_eth` such that
///    `keccak256(id ‖ owner_eth) == expected_addr` (the SOC's
///    self-binding property).
/// 4. If `owner_eth` is [`REPLICAS_OWNER`] (a dispersed replica), bytes
///    `1..32` of the id equal bytes `1..32` of the inner CAC's address.
///    The replicas key is public, so without this anyone could sign a
///    SOC at a genuine replica id wrapping arbitrary content (bee
///    `soc.Valid`, ethersphere/bee#5640). Byte 0 is free: it's the
///    replica's dispersal nibble.
///
/// Like Bee's `soc.Valid`, this is a self-validating check: it doesn't
/// take an external owner — recovering the owner *is* the validation.
/// The outer chunk fetcher passes the SOC's claimed address; if a
/// different owner had produced this id+sig combination, the address
/// would not match.
#[must_use]
pub fn soc_valid(expected_addr: &[u8; 32], wire: &[u8]) -> bool {
    if wire.len() < SOC_MIN_CHUNK_SIZE {
        return false;
    }
    let id = &wire[..SOC_ID_SIZE];
    let signature: [u8; SOC_SIG_SIZE] = match wire[SOC_ID_SIZE..SOC_HEADER_SIZE].try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let inner_cac = &wire[SOC_HEADER_SIZE..];
    if inner_cac.len() < SPAN_SIZE {
        return false;
    }
    let inner_span: &[u8; SPAN_SIZE] = match inner_cac[..SPAN_SIZE].try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let Some(inner_cac_addr) = bmt_hash_with_span(inner_span, &inner_cac[SPAN_SIZE..]) else {
        return false;
    };

    // Build the byte string the SOC signer originally signed:
    // `id ‖ inner_cac_addr`. Bee's `soc.SOC.Sign` calls
    // `signer.Sign(hash(id, addr))`, and `defaultSigner.Sign` wraps
    // its input with the EIP-191 `\x19Ethereum Signed Message:` prefix
    // before hashing. So SOC signatures are EIP-191-wrapped over
    // `keccak256(id ‖ addr)`, which means we recover with the same
    // `recover_public_key` we use for the BZZ handshake — *not* the
    // raw-prehash variant.
    let mut sig_data = [0u8; SOC_ID_SIZE + 32];
    sig_data[..SOC_ID_SIZE].copy_from_slice(id);
    sig_data[SOC_ID_SIZE..].copy_from_slice(&inner_cac_addr);
    let prehash = keccak256(&sig_data);

    let Ok(pubkey) = recover_public_key(&signature, &prehash) else {
        return false;
    };
    let owner = ethereum_address_from_public_key(&pubkey);
    if owner == REPLICAS_OWNER && inner_cac_addr[1..] != id[1..] {
        return false;
    }

    let mut soc_addr_input = [0u8; SOC_ID_SIZE + 20];
    soc_addr_input[..SOC_ID_SIZE].copy_from_slice(id);
    soc_addr_input[SOC_ID_SIZE..].copy_from_slice(&owner);
    let computed = keccak256(&soc_addr_input);

    &computed == expected_addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cac_new, sign_handshake_data};
    use k256::ecdsa::{SigningKey, VerifyingKey};

    /// A correctly-signed SOC chunk validates against its computed
    /// `keccak256(id ‖ owner)` address.
    #[test]
    fn valid_soc_passes() {
        let secret: [u8; 32] = [3u8; 32];
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let owner = ethereum_address_from_public_key(&vk);

        let id = [0xa1u8; 32];
        let payload = b"hello swarm";
        let (inner_cac_addr, inner_cac_wire) = cac_new(payload).unwrap();

        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(&id);
        digest_input[32..].copy_from_slice(&inner_cac_addr);
        let digest = keccak256(&digest_input);
        let sig = sign_handshake_data(&secret, &digest).unwrap();

        let mut soc_addr_input = [0u8; 52];
        soc_addr_input[..32].copy_from_slice(&id);
        soc_addr_input[32..].copy_from_slice(&owner);
        let soc_addr = keccak256(&soc_addr_input);

        let mut wire = Vec::new();
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_cac_wire);

        assert!(soc_valid(&soc_addr, &wire));
    }

    /// A SOC chunk delivered at the wrong address is rejected: bee's
    /// validator catches a mismatch between the SOC's claimed address
    /// and `keccak256(id ‖ recovered_owner)`.
    #[test]
    fn wrong_address_rejected() {
        let secret: [u8; 32] = [4u8; 32];
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let owner = ethereum_address_from_public_key(&vk);

        let id = [0xb2u8; 32];
        let (inner_cac_addr, inner_cac_wire) = cac_new(b"x").unwrap();
        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(&id);
        digest_input[32..].copy_from_slice(&inner_cac_addr);
        let sig = sign_handshake_data(&secret, &keccak256(&digest_input)).unwrap();

        let mut soc_addr_input = [0u8; 52];
        soc_addr_input[..32].copy_from_slice(&id);
        soc_addr_input[32..].copy_from_slice(&owner);
        let real_addr = keccak256(&soc_addr_input);

        let mut wire = Vec::new();
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_cac_wire);

        // Pretend we asked for a different address. soc_valid must
        // recompute the owner-bound address and refuse the substitution.
        let wrong_addr = {
            let mut a = real_addr;
            a[0] ^= 0xff;
            a
        };
        assert!(!soc_valid(&wrong_addr, &wire));
    }

    /// A tampered signature recovers a different (random) eth address
    /// than the one that signed; the SOC self-bind check fails.
    #[test]
    fn tampered_signature_rejected() {
        let secret: [u8; 32] = [5u8; 32];
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let vk = VerifyingKey::from(&sk);
        let owner = ethereum_address_from_public_key(&vk);
        let id = [0xc3u8; 32];
        let (inner_cac_addr, inner_cac_wire) = cac_new(b"x").unwrap();
        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(&id);
        digest_input[32..].copy_from_slice(&inner_cac_addr);
        let mut sig = sign_handshake_data(&secret, &keccak256(&digest_input)).unwrap();
        sig[0] ^= 0x01; // flip a bit in r

        let mut soc_addr_input = [0u8; 52];
        soc_addr_input[..32].copy_from_slice(&id);
        soc_addr_input[32..].copy_from_slice(&owner);
        let real_addr = keccak256(&soc_addr_input);

        let mut wire = Vec::new();
        wire.extend_from_slice(&id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_cac_wire);

        // The recovered owner from the tampered sig won't equal the
        // real owner, so the recomputed address can't match real_addr.
        assert!(!soc_valid(&real_addr, &wire));
    }

    /// Build `id ‖ sig ‖ inner_cac` signed by `secret`, returning the
    /// SOC address and wire bytes.
    fn signed_soc(secret: &[u8; 32], id: &[u8; 32], payload: &[u8]) -> ([u8; 32], Vec<u8>) {
        let sk = SigningKey::from_bytes(&(*secret).into()).unwrap();
        let owner = ethereum_address_from_public_key(&VerifyingKey::from(&sk));
        let (inner_cac_addr, inner_cac_wire) = cac_new(payload).unwrap();
        let mut digest_input = [0u8; 64];
        digest_input[..32].copy_from_slice(id);
        digest_input[32..].copy_from_slice(&inner_cac_addr);
        let sig = sign_handshake_data(secret, &keccak256(&digest_input)).unwrap();
        let mut soc_addr_input = [0u8; 52];
        soc_addr_input[..32].copy_from_slice(id);
        soc_addr_input[32..].copy_from_slice(&owner);
        let mut wire = Vec::new();
        wire.extend_from_slice(id);
        wire.extend_from_slice(&sig);
        wire.extend_from_slice(&inner_cac_wire);
        (keccak256(&soc_addr_input), wire)
    }

    /// The public replicas key derives the well-known replicas owner.
    #[test]
    fn replicas_secret_derives_owner() {
        let sk = SigningKey::from_bytes(&REPLICAS_OWNER_SECRET.into()).unwrap();
        let owner = ethereum_address_from_public_key(&VerifyingKey::from(&sk));
        assert_eq!(owner, REPLICAS_OWNER);
    }

    /// A genuine dispersed replica (`id` = wrapped chunk's address with
    /// byte 0 replaced) validates; a SOC signed with the same public key
    /// at the same id but wrapping different content lands at the very
    /// same address and must be rejected (bee#5640).
    #[test]
    fn forged_replica_soc_rejected() {
        let payload = b"genuine replicated root";
        let (root, _) = cac_new(payload).unwrap();
        let mut id = root;
        id[0] = 0x80;

        let (addr, wire) = signed_soc(&REPLICAS_OWNER_SECRET, &id, payload);
        assert!(soc_valid(&addr, &wire), "genuine replica must validate");

        let (forged_addr, forged_wire) =
            signed_soc(&REPLICAS_OWNER_SECRET, &id, b"attacker content");
        assert_eq!(forged_addr, addr, "forgery sits at the replica address");
        assert!(
            !soc_valid(&forged_addr, &forged_wire),
            "replica SOC wrapping other content must be rejected"
        );
    }

    /// The replica id rule only binds the replicas owner: any other
    /// owner may use an arbitrary id.
    #[test]
    fn non_replica_owner_id_unconstrained() {
        let (addr, wire) = signed_soc(&[7u8; 32], &[0x80u8; 32], b"anything");
        assert!(soc_valid(&addr, &wire));
    }

    /// Wire bytes shorter than the minimum SOC layout are rejected
    /// without panicking.
    #[test]
    fn too_short_rejected() {
        assert!(!soc_valid(&[0u8; 32], b""));
        assert!(!soc_valid(&[0u8; 32], &[0u8; SOC_HEADER_SIZE]));
        assert!(!soc_valid(&[0u8; 32], &[0u8; SOC_HEADER_SIZE + 4]));
    }

    /// Real-world fixture: a `blog.swarm.eth` feed update at index 0
    /// fetched verbatim from the public Bee gateway. This pins the SOC
    /// wire layout exactly as the network delivers it (no outer span)
    /// and our exact recovery + self-binding maths against bee's.
    /// 145 bytes total = 32 id + 65 sig + 8 `inner_span` + 40 v1 payload.
    #[test]
    fn real_blog_swarm_eth_feed_update() {
        // SOC chunk for owner=f77a13dc..., topic=861f23d3..., index=0.
        // soc_addr = keccak256(keccak256(topic ‖ 0u64_be) ‖ owner)
        //          = 006b7c2446c7a2791ed79bfddb86579d252b3d16fb1243da567af33151f065b1.
        // Layout (id 32 ‖ sig 65 ‖ span 8 LE ‖ ts 8 BE ‖ ref 32 = 145).
        const WIRE_HEX: &str = "4b7d6b417f027edbbb05165129f2e911133181786c744f86dcb39cb50a01bbe8d9ed42c38be040e74857108af3618a042f55a0270210bc5227d65715ad4a96435c29b8543bbbc450fdcf10d4ae8b34fd212b882543e66bf6c7c7652dc1b566a01c2800000000000000000000006864f0df7d09e9734d89fbb6a124bd1fd2f9e1f95b874a325a85841a55930881b5c68960";
        let wire = hex::decode(WIRE_HEX).expect("hex decode");
        assert_eq!(wire.len(), 145);

        let mut soc_addr = [0u8; 32];
        hex::decode_to_slice(
            "006b7c2446c7a2791ed79bfddb86579d252b3d16fb1243da567af33151f065b1",
            &mut soc_addr,
        )
        .unwrap();

        assert!(
            soc_valid(&soc_addr, &wire),
            "real blog.swarm.eth SOC update must validate"
        );
    }
}
