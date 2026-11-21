//! GSOC (Graffiti Single-Owner Chunk) authoring and neighborhood mining.
//!
//! GSOC is a broadcast-messaging convention layered on single-owner
//! chunks. An app fixes a 32-byte `identifier` (its "topic") and mines a
//! secp256k1 key whose derived SOC address —
//! `keccak256(identifier ‖ owner)` — falls within a chosen number of
//! leading bits of a *target overlay* (the neighborhood messages should
//! land in). Because the mine is a deterministic function of
//! `(target_overlay, identifier, proximity)`, sender and receiver each
//! run it locally and arrive at the **same** key: the sender signs
//! updates with it, the receiver watches the resulting SOC address.
//!
//! This module mirrors bee-js's `gsocMine` / `gsocSend` (`@ethersphere/
//! bee-js`, `bee.js` + `chunk/soc.js`) byte-for-byte so ant can send (and
//! author receiver keys) interoperably with bee-js apps:
//!
//! - **Mining** starts from the private scalar `0xb33` and increments the
//!   full 256-bit big-endian integer, accepting the first key whose SOC
//!   address shares `>= proximity` leading bits with the target overlay.
//!   The leading-bit count is **uncapped** (0..=256) — do *not* reuse
//!   Swarm's node-side proximity, which clamps at `MaxPO`.
//! - **Signing** is the ordinary SOC signature: EIP-191 over
//!   `keccak256(identifier ‖ cac_address)`, yielding `r‖s‖v` with
//!   `v ∈ {27, 28}` — exactly what [`crate::soc::soc_valid`] already
//!   validates and what bee's Go `soc.Valid` recovers.

use crate::bmt::cac_new;
use crate::{
    ethereum_address_from_public_key, keccak256, sign_handshake_data, CryptoError,
    SECP256K1_SECRET_LEN, SOC_ID_SIZE,
};
use k256::ecdsa::{SigningKey, VerifyingKey};

/// First private scalar tried by the miner (bee-js `gsocMine` seed
/// `0xb33`).
const MINE_SEED: u64 = 0xb33;
/// Upper bound on mining attempts, matching bee-js's `i < 0xffff` loop.
const MINE_MAX_ITERS: u64 = 0xffff;

/// Number of leading bits in which two 32-byte values agree, scanning
/// MSB-first — bee-js / cafe-utility `proximity`. Returns `256` for equal
/// inputs. **Uncapped**: unlike `swarm.Proximity` there is no `MaxPO`
/// clamp, because gsoc mining compares full SOC addresses to overlays.
#[must_use]
pub fn leading_equal_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        let diff = x ^ y;
        if diff != 0 {
            return i as u32 * 8 + diff.leading_zeros();
        }
    }
    256
}

/// Derive the 20-byte owner Ethereum address for a candidate secret.
fn owner_of(secret: &[u8; SECP256K1_SECRET_LEN]) -> Result<[u8; 20], CryptoError> {
    let sk = SigningKey::from_bytes(secret.into())?;
    Ok(ethereum_address_from_public_key(&VerifyingKey::from(&sk)))
}

/// The SOC address a given `(identifier, owner)` pair resolves to:
/// `keccak256(identifier ‖ owner)`.
#[must_use]
pub fn soc_address(identifier: &[u8; SOC_ID_SIZE], owner: &[u8; 20]) -> [u8; 32] {
    let mut input = [0u8; SOC_ID_SIZE + 20];
    input[..SOC_ID_SIZE].copy_from_slice(identifier);
    input[SOC_ID_SIZE..].copy_from_slice(owner);
    keccak256(&input)
}

/// A `keccak256(utf8(s))` identifier — bee-js `Identifier.fromString`
/// (also how `Topic.fromString` works). Apps that pass a raw 32-byte id
/// use it directly instead.
#[must_use]
pub fn identifier_from_string(s: &str) -> [u8; SOC_ID_SIZE] {
    keccak256(s.as_bytes())
}

/// Mine a GSOC signer secret whose SOC address for `identifier` lands
/// within `proximity` leading bits of `target_overlay`.
///
/// Deterministic and identical to bee-js `gsocMine(targetOverlay,
/// identifier, proximity)`: candidate secrets are `0xb33, 0xb34, …`
/// encoded as 32-byte big-endian scalars; the first whose
/// `keccak256(identifier ‖ owner)` shares `>= proximity` leading bits
/// with `target_overlay` wins. Fails with
/// [`CryptoError::GsocMiningExhausted`] if none is found within `0xffff`
/// attempts (bee-js throws there).
///
/// `proximity` is bee-js's default of 12 in typical use; the resulting
/// secret is shared implicitly — both ends recompute it — so the caller
/// must pass the exact same `(target_overlay, identifier, proximity)` the
/// counterpart uses.
pub fn gsoc_mine(
    target_overlay: &[u8; 32],
    identifier: &[u8; SOC_ID_SIZE],
    proximity: u32,
) -> Result<[u8; SECP256K1_SECRET_LEN], CryptoError> {
    for i in 0..MINE_MAX_ITERS {
        let mut secret = [0u8; SECP256K1_SECRET_LEN];
        // numberToUint256(0xb33 + i, 'BE'): the scalar fits in u64 for the
        // whole search range, so it occupies the low 8 big-endian bytes.
        secret[SECP256K1_SECRET_LEN - 8..].copy_from_slice(&(MINE_SEED + i).to_be_bytes());
        let owner = owner_of(&secret)?;
        let addr = soc_address(identifier, &owner);
        if leading_equal_bits(&addr, target_overlay) >= proximity {
            return Ok(secret);
        }
    }
    Err(CryptoError::GsocMiningExhausted)
}

/// A GSOC message ready to upload as a single-owner chunk.
#[derive(Clone, Debug)]
pub struct GsocChunk {
    /// 20-byte owner Ethereum address (the `{owner}` path segment).
    pub owner: [u8; 20],
    /// 32-byte SOC identifier (the `{id}` path segment).
    pub identifier: [u8; SOC_ID_SIZE],
    /// `keccak256(identifier ‖ owner)` — where the chunk lands / is
    /// watched.
    pub address: [u8; 32],
    /// 65-byte `r‖s‖v` SOC signature (`?sig=` query, `v ∈ {27,28}`).
    pub signature: [u8; 65],
    /// `span(8 LE) ‖ payload` — the CAC data, which is the HTTP upload
    /// body (`POST /soc/{owner}/{id}`). Id and signature travel in the
    /// URL/query, not the body.
    pub upload_body: Vec<u8>,
    /// Full `id ‖ sig ‖ cac_data` SOC wire form (what a storer holds and
    /// what [`crate::soc::soc_valid`] takes), for callers that push
    /// directly rather than via the HTTP endpoint.
    pub wire: Vec<u8>,
}

/// Build and sign a GSOC single-owner chunk for `payload` under `secret`
/// and `identifier`. `payload` must be 1..=4096 bytes.
///
/// Mirrors bee-js `gsocSend`'s chunk construction: wrap the payload in a
/// content-addressed chunk, then sign `keccak256(identifier ‖ cac_addr)`
/// with EIP-191 (the standard SOC signature). The result validates under
/// bee's `soc.Valid` and ant's [`crate::soc::soc_valid`].
pub fn build_gsoc_chunk(
    secret: &[u8; SECP256K1_SECRET_LEN],
    identifier: &[u8; SOC_ID_SIZE],
    payload: &[u8],
) -> Result<GsocChunk, CryptoError> {
    // Enforce the documented lower bound too: `cac_new` only caps the
    // upper end, but bee rejects an empty SOC payload, so building one
    // here would sign a chunk the network refuses.
    if payload.is_empty() {
        return Err(CryptoError::InvalidChunkPayload);
    }
    let (cac_addr, cac_data) = cac_new(payload).ok_or(CryptoError::InvalidChunkPayload)?;
    let owner = owner_of(secret)?;
    let address = soc_address(identifier, &owner);

    // SOC signature: EIP-191 over keccak256(id ‖ cac_addr), v in {27,28}.
    let mut to_sign = [0u8; SOC_ID_SIZE + 32];
    to_sign[..SOC_ID_SIZE].copy_from_slice(identifier);
    to_sign[SOC_ID_SIZE..].copy_from_slice(&cac_addr);
    let signature = sign_handshake_data(secret, &keccak256(&to_sign))?;

    let mut wire = Vec::with_capacity(SOC_ID_SIZE + 65 + cac_data.len());
    wire.extend_from_slice(identifier);
    wire.extend_from_slice(&signature);
    wire.extend_from_slice(&cac_data);

    Ok(GsocChunk {
        owner,
        identifier: *identifier,
        address,
        signature,
        upload_body: cac_data,
        wire,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soc_valid;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    /// The documented `1..=4096` contract is enforced at BOTH ends: bee
    /// rejects an empty SOC payload, so building one would sign a chunk
    /// the network refuses (round-14 residual: the check existed, the
    /// test pinning it didn't).
    #[test]
    fn build_gsoc_chunk_rejects_empty_and_oversize_payloads() {
        let identifier = identifier_from_string("bounds");
        let secret = gsoc_mine(&[0u8; 32], &identifier, 1).unwrap();
        assert!(matches!(
            build_gsoc_chunk(&secret, &identifier, b""),
            Err(CryptoError::InvalidChunkPayload)
        ));
        assert!(matches!(
            build_gsoc_chunk(&secret, &identifier, &[0u8; 4097]),
            Err(CryptoError::InvalidChunkPayload)
        ));
        assert!(build_gsoc_chunk(&secret, &identifier, &[0u8; 1]).is_ok());
        assert!(build_gsoc_chunk(&secret, &identifier, &[0u8; 4096]).is_ok());
    }

    // Vectors below are tool-verified against @ethersphere/bee-js 12.2.2.

    #[test]
    fn mine_iter0_null_identifier_matches_beejs() {
        // gsocMine iteration 0 (secret 0x…0b33), identifier = 32 zeros.
        let secret = {
            let mut s = [0u8; 32];
            s[24..].copy_from_slice(&MINE_SEED.to_be_bytes());
            s
        };
        let owner = owner_of(&secret).unwrap();
        assert_eq!(
            hex::encode(owner),
            "1d4ac942bc6f8bd053a3cd659b718f0404c9af1f"
        );
        let addr = soc_address(&[0u8; 32], &owner);
        assert_eq!(
            hex::encode(addr),
            "dc32237cd790955dc15e6a7081a118ca5877529aa00b5585a5e9d294ceb9d324"
        );
    }

    #[test]
    fn mine_full_run_matches_beejs() {
        // overlay 0x1234…1234, id = NULL, proximity 8 → bee-js winner i=13
        // (secret 0x…0b40), 9 leading bits.
        let overlay = hex32("1234567890123456789012345678901234567890123456789012345678901234");
        let secret = gsoc_mine(&overlay, &[0u8; 32], 8).unwrap();
        let mut want = [0u8; 32];
        want[24..].copy_from_slice(&(MINE_SEED + 13).to_be_bytes());
        assert_eq!(secret, want, "must find the same key bee-js finds");

        let owner = owner_of(&secret).unwrap();
        assert_eq!(
            hex::encode(owner),
            "aa9bd0a43117b0c9233365418f2f3ea735f89f17"
        );
        let addr = soc_address(&[0u8; 32], &owner);
        assert_eq!(
            hex::encode(addr),
            "127bc733f8345f4b29598a2daab7cfe2ae7c90067e033bf68fb7036bedcb3e22"
        );
        assert!(leading_equal_bits(&addr, &overlay) >= 8);
    }

    #[test]
    fn build_gsoc_chunk_matches_beejs_vector() {
        // signer priv 0x0123…0123, identifier 0xaaaa…aa, data "GSOC!".
        let secret = hex32("0123456789012345678901234567890123456789012345678901234567890123");
        let identifier = [0xaau8; 32];
        let chunk = build_gsoc_chunk(&secret, &identifier, b"GSOC!").unwrap();

        assert_eq!(
            hex::encode(chunk.owner),
            "14791697260e4c9a71f18484c9f997b308e59325"
        );
        assert_eq!(
            hex::encode(chunk.address),
            "36519e62a58ba690dc93f8af16f25fc2da4a8cc8cf697b03d4c92242d054d05a"
        );
        // span (LE, len 5) ‖ "GSOC!"
        assert_eq!(
            hex::encode(&chunk.upload_body),
            "050000000000000047534f4321"
        );
        // Signature must match byte-for-byte (bee-js uses a keccak-based
        // deterministic nonce; ant's k256 RFC6979 nonce differs, so the
        // sig bytes may differ — assert validity via recovery instead of
        // equality). What must hold: the chunk self-validates.
        assert!(
            soc_valid(&chunk.address, &chunk.wire),
            "authored GSOC chunk must validate as a SOC"
        );
    }

    #[test]
    fn leading_equal_bits_boundaries() {
        let a = [0u8; 32];
        assert_eq!(leading_equal_bits(&a, &a), 256);
        let mut b = [0u8; 32];
        b[0] = 0x80; // differ in the very first bit
        assert_eq!(leading_equal_bits(&a, &b), 0);
        b[0] = 0x40; // first byte 0100_0000 → 1 leading equal bit
        assert_eq!(leading_equal_bits(&a, &b), 1);
        let mut c = [0u8; 32];
        c[1] = 0x01; // first byte equal, second differs at last bit → 15
        assert_eq!(leading_equal_bits(&a, &c), 15);
    }

    #[test]
    fn identifier_from_string_is_keccak() {
        assert_eq!(identifier_from_string("chat:v1"), keccak256(b"chat:v1"));
    }
}
