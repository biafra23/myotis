//! Swarm chunk encryption and decryption.
//!
//! Swarm encrypts each content chunk under a fresh 32-byte random key
//! using Keccak-256 in counter mode. An *encrypted reference* is
//! `address(32) ‖ key(32)` (64 bytes): the address locates the stored,
//! encrypted chunk and the key decrypts it. Because a chunk is stored and
//! addressed by the BMT hash of its **encrypted** bytes, retrieval and
//! CAC validation are unchanged — only the bytes need decrypting once they
//! arrive.
//!
//! Mirrors `bee/pkg/encryption` and `bee/pkg/encryption/store`:
//!
//! - **Keystream.** For 32-byte segment `i` (counting from 0 within a
//!   decrypt call) the keystream block is
//!   `keccak256( keccak256(key ‖ le32(i + initCtr)) )`. The plaintext is
//!   the ciphertext XOR this block (`encryption.go::Transcrypt`).
//! - **Span vs data.** A stored chunk is `encSpan(8) ‖ encData(≤4096)`.
//!   The span is decrypted with `initCtr = ChunkSize/KeyLength = 128`
//!   (one segment); the data with `initCtr = 0` (up to 128 segments).
//!   Separate counter ranges avoid keystream reuse
//!   (`chunk_encryption.go::NewSpanEncryption` / `NewDataEncryption`).
//! - **Length.** The decrypted span (little-endian, with the redundancy
//!   level masked off) gives the subtree byte count. For a leaf
//!   (`length ≤ ChunkSize`) that's the content length; for an intermediate
//!   the decrypted payload is a list of 64-byte child references and its
//!   real length is `64 × dataShards`, with `dataShards` derived from the
//!   span exactly as `bee/pkg/file/utils.go::ReferenceCount`
//!   (`store/decrypt_store.go::DecryptChunkData`).
//!
//! [`decrypt_chunk`] handles the redundancy-free (`level == NONE`) case
//! end-to-end. Encrypted trees that carry a Reed–Solomon level need the
//! erasure tables to compute the reference-list truncation, which live in
//! `ant-retrieval` — those callers use [`decrypt_chunk_parts`] and
//! truncate themselves (mirroring `bee`'s `DecryptChunkData`, which calls
//! into `file.ReferenceCount`).
//!
//! The write path ([`encrypt_chunk_unpadded`]) is the exact inverse:
//! `bee`'s `chunkEncrypter.EncryptChunk` encrypts the span with
//! `initCtr = 128` and the payload with `initCtr = 0`, then right-pads
//! the ciphertext with **random** bytes to `ChunkSize` (the padding is
//! appended raw, *outside* the keystream — `encryption.go::pad`). Padding
//! is left to the caller here so deterministic tests/vectors can pad with
//! zeros while production pads randomly, matching bee's observable
//! behaviour (decrypt truncates the padding away either way).

use crate::{keccak256, CHUNK_SIZE, SPAN_SIZE};
use thiserror::Error;

/// Length of a chunk encryption key.
pub const KEY_LENGTH: usize = 32;
/// Length of an encrypted reference: `address(32) ‖ key(32)`.
pub const REFERENCE_SIZE: usize = 64;

/// Initial counter for span encryption: `ChunkSize / KeyLength` (= 128).
/// Keeps the span's single keystream block out of the data's `0..=127`
/// counter range. See `bee` `NewSpanEncryption`.
const SPAN_INIT_CTR: u32 = (CHUNK_SIZE / KEY_LENGTH) as u32;

/// Encrypted branching factor: references per intermediate chunk
/// (`ChunkSize / REFERENCE_SIZE` = 64). See `swarm.EncryptedBranches`.
const ENC_BRANCHES: u64 = (CHUNK_SIZE / REFERENCE_SIZE) as u64;

#[derive(Debug, Error)]
pub enum DecryptError {
    /// The stored chunk is shorter than its 8-byte span header.
    #[error("encrypted chunk too short: {0} bytes")]
    TooShort(usize),
    /// The decrypted span declares a Reed–Solomon redundancy level we
    /// don't decode (only `NONE` is supported on the read path).
    #[error("encrypted chunk uses unsupported redundancy level {0}")]
    UnsupportedRedundancy(u8),
    /// The decrypted content length exceeds the chunk's payload — the key
    /// is wrong or the chunk is corrupt.
    #[error("decrypted length {length} exceeds chunk payload {payload}")]
    LengthOverflow { length: usize, payload: usize },
}

/// Keystream block for 32-byte segment counter `ctr`:
/// `keccak256( keccak256(key ‖ le32(ctr)) )`.
fn segment_key(key: &[u8; KEY_LENGTH], ctr: u32) -> [u8; 32] {
    let mut input = [0u8; KEY_LENGTH + 4];
    input[..KEY_LENGTH].copy_from_slice(key);
    input[KEY_LENGTH..].copy_from_slice(&ctr.to_le_bytes());
    keccak256(&keccak256(&input))
}

/// XOR `data` in place with the counter-mode keystream, 32-byte segments,
/// counters running `init_ctr, init_ctr+1, …`.
fn transcrypt(data: &mut [u8], key: &[u8; KEY_LENGTH], init_ctr: u32) {
    for (i, segment) in data.chunks_mut(KEY_LENGTH).enumerate() {
        let ks = segment_key(key, init_ctr.wrapping_add(i as u32));
        for (b, k) in segment.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
    }
}

/// XOR `data` in place with the Keccak counter-mode keystream starting
/// at counter 0 — bee's `encryption.New(key, 0, 0, keccak256).Encrypt`
/// (and, being an XOR stream, also its `Decrypt`). This is the "bare"
/// cipher bee's access control (`pkg/accesscontrol`) applies to Swarm
/// references and access keys: no padding, no span/data counter split,
/// output exactly as long as the input. A fresh cipher instance per
/// call, so the counter always restarts at 0 (matching every ACT call
/// site in bee, which constructs a new `encryption.New(...)` each time).
pub fn stream_xor_in_place(data: &mut [u8], key: &[u8; KEY_LENGTH]) {
    transcrypt(data, key, 0);
}

/// Split a decrypted little-endian span into `(redundancy_level, length)`.
/// Mirrors `bee/pkg/file/redundancy/span.go::DecodeSpan`: a level is
/// encoded only when the most-significant span byte exceeds 128.
fn decode_span(span: [u8; SPAN_SIZE]) -> (u8, u64) {
    let msb = span[SPAN_SIZE - 1];
    if msb > 128 {
        let mut bytes = span;
        bytes[SPAN_SIZE - 1] = 0;
        (msb & 0x7f, u64::from_le_bytes(bytes))
    } else {
        (0, u64::from_le_bytes(span))
    }
}

/// Number of child data references in an encrypted intermediate chunk
/// whose subtree spans `span` bytes (`span > ChunkSize`), at redundancy
/// level `NONE`. Brute-forces the branch level the way
/// `bee/pkg/file/utils.go::ReferenceCount` does, with the encrypted
/// branching factor (64).
fn enc_reference_count(span: u64) -> usize {
    let mut branch_size = CHUNK_SIZE as u64;
    let mut branch_level: u32 = 1;
    while branch_size < span {
        branch_size = branch_size.saturating_mul(ENC_BRANCHES);
        branch_level += 1;
    }
    // referenceSize = ChunkSize * branching^(branchLevel-2): the span one
    // child reference covers on this level.
    let mut reference_size = CHUNK_SIZE as u64;
    for _ in 1..branch_level.saturating_sub(1) {
        reference_size = reference_size.saturating_mul(ENC_BRANCHES);
    }
    let mut shards = 1usize;
    let mut offset = reference_size;
    while offset < span {
        offset = offset.saturating_add(reference_size);
        shards += 1;
    }
    shards
}

/// Encrypt a plaintext chunk (`span(8) ‖ payload(≤4096)`) under `key`,
/// returning `encSpan(8) ‖ encPayload` with `encPayload` the same length
/// as the payload — **unpadded**. Bee stores encrypted chunks with the
/// ciphertext right-padded to [`CHUNK_SIZE`] with random bytes
/// (`chunk_encryption.go::EncryptChunk` via `Encrypt`'s `padding`
/// parameter); the caller must resize the result to
/// `SPAN_SIZE + CHUNK_SIZE`, choosing the pad bytes (random in
/// production, zeros for deterministic vectors — decryption truncates
/// them either way, so interoperability is unaffected).
///
/// The chunk's stored address is the BMT hash of the **padded** result
/// (header = the encrypted span), and its encrypted reference is
/// `address(32) ‖ key(32)`.
#[must_use]
pub fn encrypt_chunk_unpadded(plain_wire: &[u8], key: &[u8; KEY_LENGTH]) -> Vec<u8> {
    debug_assert!(plain_wire.len() >= SPAN_SIZE);
    debug_assert!(plain_wire.len() <= SPAN_SIZE + CHUNK_SIZE);
    let mut out = plain_wire.to_vec();
    transcrypt(&mut out[..SPAN_SIZE], key, SPAN_INIT_CTR);
    transcrypt(&mut out[SPAN_SIZE..], key, 0);
    out
}

/// A fresh random 32-byte chunk encryption key from the OS RNG
/// (`bee` `encryption.GenerateRandomKey`).
#[must_use]
pub fn random_encryption_key() -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    getrandom::fill(&mut key).expect("OS RNG");
    key
}

/// Decrypt a stored, encrypted chunk into its raw parts: the decrypted
/// 8-byte span (level byte intact) and the **full** decrypted data
/// (padding included, no truncation). Callers that must handle
/// Reed–Solomon-level spans use this and compute the truncation with
/// their own erasure tables (`bee`'s `DecryptChunkData`); everyone else
/// wants [`decrypt_chunk`].
pub fn decrypt_chunk_parts(
    stored_wire: &[u8],
    key: &[u8; KEY_LENGTH],
) -> Result<([u8; SPAN_SIZE], Vec<u8>), DecryptError> {
    if stored_wire.len() < SPAN_SIZE {
        return Err(DecryptError::TooShort(stored_wire.len()));
    }
    let mut span = [0u8; SPAN_SIZE];
    span.copy_from_slice(&stored_wire[..SPAN_SIZE]);
    transcrypt(&mut span, key, SPAN_INIT_CTR);
    let mut data = stored_wire[SPAN_SIZE..].to_vec();
    transcrypt(&mut data, key, 0);
    Ok((span, data))
}

/// Decrypt a stored, encrypted content chunk.
///
/// `stored_wire` is the chunk exactly as fetched / BMT-addressed:
/// `encSpan(8) ‖ encData`. `key` is the 32-byte trailing half of the
/// encrypted reference that pointed here. Returns the decrypted chunk in
/// the same shape an *unencrypted* chunk would have — `span(8) ‖ payload`
/// — where `payload` is the file bytes (leaf) or a list of 64-byte child
/// encrypted references (intermediate), trailing encryption padding
/// stripped. The returned span retains its raw decrypted bytes (including
/// any redundancy-level byte), matching `bee`'s `DecryptChunkData`.
pub fn decrypt_chunk(stored_wire: &[u8], key: &[u8; KEY_LENGTH]) -> Result<Vec<u8>, DecryptError> {
    let (span, data) = decrypt_chunk_parts(stored_wire, key)?;

    let (level, length) = decode_span(span);
    if level != 0 {
        return Err(DecryptError::UnsupportedRedundancy(level));
    }

    let content_len = if length <= CHUNK_SIZE as u64 {
        length as usize
    } else {
        enc_reference_count(length) * REFERENCE_SIZE
    };
    if content_len > data.len() {
        return Err(DecryptError::LengthOverflow {
            length: content_len,
            payload: data.len(),
        });
    }

    let mut out = Vec::with_capacity(SPAN_SIZE + content_len);
    out.extend_from_slice(&span);
    out.extend_from_slice(&data[..content_len]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cac_new;

    /// Stored-form encryptor: [`encrypt_chunk_unpadded`] plus the pad to
    /// `ChunkSize` bee applies (deterministic zeros here rather than
    /// random; decrypt truncates to the real length so the value is moot).
    fn encrypt_chunk(plain_wire: &[u8], key: &[u8; KEY_LENGTH]) -> Vec<u8> {
        let mut out = encrypt_chunk_unpadded(plain_wire, key);
        out.resize(SPAN_SIZE + CHUNK_SIZE, 0);
        out
    }

    #[test]
    fn round_trips_a_leaf_chunk() {
        let key = [0x5au8; KEY_LENGTH];
        let content = b"the quick brown fox jumps over the lazy swarm";
        let (_addr, plain_wire) = cac_new(content).unwrap();

        let enc = encrypt_chunk(&plain_wire, &key);
        // The encrypted chunk is span(8) + padded data(4096).
        assert_eq!(enc.len(), SPAN_SIZE + CHUNK_SIZE);

        let dec = decrypt_chunk(&enc, &key).unwrap();
        assert_eq!(dec, plain_wire, "decrypt must invert encrypt exactly");
        // Span decodes to the content length.
        assert_eq!(
            u64::from_le_bytes(dec[..8].try_into().unwrap()),
            content.len() as u64
        );
        assert_eq!(&dec[8..], content);
    }

    #[test]
    fn round_trips_a_full_leaf_chunk() {
        let key = [0x11u8; KEY_LENGTH];
        let content = vec![0xABu8; CHUNK_SIZE]; // exactly one full chunk
        let (_addr, plain_wire) = cac_new(&content).unwrap();
        let enc = encrypt_chunk(&plain_wire, &key);
        let dec = decrypt_chunk(&enc, &key).unwrap();
        assert_eq!(dec, plain_wire);
    }

    #[test]
    fn intermediate_chunk_strips_padding_to_ref_list() {
        // An intermediate chunk whose subtree spans 3 leaves (≈3 × 4096).
        // Its payload is 3 × 64-byte child references; the rest is padding.
        let key = [0x77u8; KEY_LENGTH];
        let span_bytes = (3u64 * CHUNK_SIZE as u64).to_le_bytes();
        let mut plain = Vec::new();
        plain.extend_from_slice(&span_bytes);
        // three encrypted refs (addr ‖ key), arbitrary bytes
        for i in 0..3u8 {
            plain.extend_from_slice(&[i; REFERENCE_SIZE]);
        }
        // pad plaintext to a full chunk for the encryptor
        let mut plain_full = plain.clone();
        plain_full.resize(SPAN_SIZE + CHUNK_SIZE, 0);

        let enc = encrypt_chunk(&plain_full, &key);
        let dec = decrypt_chunk(&enc, &key).unwrap();

        // Decrypted payload must be exactly the 3 references, no padding.
        assert_eq!(dec.len(), SPAN_SIZE + 3 * REFERENCE_SIZE);
        assert_eq!(&dec[..SPAN_SIZE], &span_bytes);
        assert_eq!(&dec[SPAN_SIZE..], &plain[SPAN_SIZE..]);
    }

    #[test]
    fn wrong_key_does_not_round_trip() {
        let key = [1u8; KEY_LENGTH];
        let wrong = [2u8; KEY_LENGTH];
        let (_addr, plain_wire) = cac_new(b"secret").unwrap();
        let enc = encrypt_chunk(&plain_wire, &key);
        // A wrong key yields a different (here likely nonsensical) span, so
        // the result must not equal the plaintext. (It may error or return
        // garbage; either way it must not silently match.)
        if let Ok(dec) = decrypt_chunk(&enc, &wrong) {
            assert_ne!(dec, plain_wire);
        }
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(
            decrypt_chunk(&[0u8; 4], &[0u8; KEY_LENGTH]),
            Err(DecryptError::TooShort(4))
        ));
    }

    #[test]
    fn enc_reference_count_matches_bee_branching() {
        // 2-level tree: each child covers one 4096-byte leaf.
        assert_eq!(enc_reference_count(2 * CHUNK_SIZE as u64), 2);
        assert_eq!(enc_reference_count(3 * CHUNK_SIZE as u64), 3);
        // Exactly a full level-1 chunk (64 leaves) is still 64 children.
        assert_eq!(enc_reference_count(ENC_BRANCHES * CHUNK_SIZE as u64), 64);
        // One byte into a third level: 65 leaves need a level-2 root whose
        // children each cover 64 leaves → 2 references.
        assert_eq!(enc_reference_count(ENC_BRANCHES * CHUNK_SIZE as u64 + 1), 2);
    }
}
