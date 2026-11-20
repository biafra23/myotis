//! PSS (Postal Service over Swarm) trojan-chunk wrap/unwrap and mining.
//!
//! A PSS message is disguised as an ordinary 4096-byte chunk whose BMT
//! address is *mined* to fall under a short prefix of the recipient's
//! overlay, so the network's pushsync routes it into that neighborhood
//! like any stored data. The payload is ECIES-encrypted to the
//! recipient's public key (ephemeral ECDH + Swarm's keccak stream
//! cipher), and an 8-byte "hint" — doubling as the BMT span header — lets
//! a recipient cheaply test, per registered topic, whether a passing
//! chunk is addressed to them before attempting a full decrypt.
//!
//! This mirrors bee's `pkg/pss/trojan.go` byte-for-byte so ant
//! interoperates with bee senders and receivers. The load-bearing quirks
//! (all reproduced here, validated against Go golden vectors):
//!
//! - The ECDH shared key is `keccak256(minimal_be(x) ‖ topic)` where
//!   `minimal_be(x)` strips leading zero bytes of the x-coordinate
//!   (Go `big.Int.Bytes()`); [`crate::act::shared_secret_x`] already does
//!   this, so both ends agree.
//! - The stream cipher is Swarm's `keccak256(keccak256(key ‖ le32(ctr)))`
//!   double hash over 32-byte segments ([`crate::encryption`]); the
//!   ciphertext is padded to 4032 bytes with **raw random** tail bytes
//!   (not keystream) beyond the plaintext — decryption ignores them.
//! - The hint is `keccak256(shared_key ‖ topic)[:8]` and is hashed
//!   verbatim as the BMT header, so the address is
//!   `keccak256(hint ‖ bmt_root(nonce ‖ ephX ‖ ciphertext))`.
//! - When no `recipient` is supplied the sender encrypts to the
//!   *topic-derived* key `pub(topic mod n)`, so any node registered on
//!   the topic can decrypt (broadcast mode).
//!
//! Layout of the 4104-byte chunk data:
//! `hint(8) ‖ nonce(32) ‖ ephX(32) ‖ ciphertext(4032)`.

use crate::act::{compress_public_key, parse_public_key, public_key_of, shared_secret_x};
use crate::bmt::bmt_hash_with_span;
use crate::{keccak256, random_secp256k1_secret, CryptoError, SPAN_SIZE};
use k256::PublicKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// Topic-hint length; also the BMT header length.
pub const HINT_SIZE: usize = 8;
const NONCE_SIZE: usize = 32;
const EPH_X_SIZE: usize = 32;
/// Encrypted payload length: `ChunkSize − nonce − ephX = 4096 − 64`.
const CIPHERTEXT_SIZE: usize = 4032;
/// The BMT body: `nonce ‖ ephX ‖ ciphertext = 4096`.
const BODY_SIZE: usize = NONCE_SIZE + EPH_X_SIZE + CIPHERTEXT_SIZE;
/// Full trojan chunk data length: `hint ‖ body = 4104`.
pub const TROJAN_DATA_SIZE: usize = HINT_SIZE + BODY_SIZE;
/// Integrity header prepended to the message before encryption.
const INTEGRITY_SIZE: usize = 32;
/// Largest message a trojan chunk can carry: `ChunkSize − 3·HashSize`.
pub const MAX_PAYLOAD_SIZE: usize = 4096 - 3 * 32;
/// Maximum target-prefix length the bee HTTP API accepts (bytes).
pub const MAX_TARGET_LEN: usize = 3;

/// A `keccak256(utf8(s))` topic — bee's `pss.NewTopic`.
#[must_use]
pub fn topic_from_string(s: &str) -> [u8; 32] {
    keccak256(s.as_bytes())
}

/// The ECDH shared key bee's `ElGamal` glue derives:
/// `keccak256(minimal_be(x(secret·public)) ‖ topic)`.
fn shared_key(
    secret: &[u8; 32],
    public: &PublicKey,
    topic: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let x = shared_secret_x(secret, public)?;
    let mut input = Vec::with_capacity(x.len() + 32);
    input.extend_from_slice(&x);
    input.extend_from_slice(topic);
    Ok(keccak256(&input))
}

/// Build the integrity-framed plaintext: `BE16(len) ‖ keccak256(msg)[2..] ‖ msg`.
fn frame_plaintext(msg: &[u8]) -> Vec<u8> {
    let mut integrity = keccak256(msg);
    integrity[0..2].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    let mut out = Vec::with_capacity(INTEGRITY_SIZE + msg.len());
    out.extend_from_slice(&integrity);
    out.extend_from_slice(msg);
    out
}

/// XOR `buf` in place with the keccak counter-mode keystream (counter
/// from 0). Same cipher as [`crate::encryption::stream_xor_in_place`],
/// re-exposed here for clarity of intent.
fn cipher_xor(buf: &mut [u8], key: &[u8; 32]) {
    crate::encryption::stream_xor_in_place(buf, key);
}

/// A recipient public key for [`wrap`]. Either an explicit key or the
/// topic-derived broadcast key.
pub enum Recipient {
    /// Encrypt to this secp256k1 public key (SEC1, 33 or 65 bytes).
    Key(PublicKey),
    /// No recipient given — bee's default: encrypt to `pub(topic mod n)`,
    /// decryptable by anyone registered on the topic.
    TopicDerived,
}

impl Recipient {
    /// Parse an explicit recipient from SEC1 public-key bytes.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Recipient::Key(parse_public_key(bytes)?))
    }

    fn public_key(&self, topic: &[u8; 32]) -> Result<PublicKey, CryptoError> {
        match self {
            Recipient::Key(pk) => Ok(*pk),
            Recipient::TopicDerived => public_key_of(&topic_derived_secret(topic)),
        }
    }
}

/// secp256k1 curve order n (big-endian), for the topic-derived key.
const CURVE_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `topic mod n` as a 32-byte secret — bee's
/// `Secp256k1PrivateKeyFromBytes(topic)` (btcec reduces mod n). Since a
/// topic is a keccak digest, the reduction only ever triggers with
/// negligible probability, and `topic < 2n` always, so a single
/// conditional subtraction suffices.
fn topic_derived_secret(topic: &[u8; 32]) -> [u8; 32] {
    let mut s = *topic;
    if be_ge(&s, &CURVE_ORDER_BE) {
        be_sub_assign(&mut s, &CURVE_ORDER_BE);
    }
    s
}

fn be_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn be_sub_assign(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = i16::from(a[i]) - i16::from(b[i]) - borrow;
        if v < 0 {
            a[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            a[i] = v as u8;
            borrow = 0;
        }
    }
}

/// Wrap `msg` into a trojan chunk mined to one of `targets` (each an
/// overlay-address prefix, all the same length, 1..=3 bytes).
///
/// Returns `(address, chunk_data)` where `chunk_data` is the 4104-byte
/// `hint ‖ nonce ‖ ephX ‖ ciphertext` ready to stamp and pushsync, and
/// `address` is its BMT hash. Mining is CPU-bound (≈`256^target_len`
/// hashes); callers should run this off the async runtime. Uses all
/// available cores.
pub fn wrap(
    topic: &[u8; 32],
    msg: &[u8],
    recipient: &Recipient,
    targets: &[Vec<u8>],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    wrap_cancellable(topic, msg, recipient, targets, &AtomicBool::new(false))
}

/// [`wrap`] with a cooperative cancellation flag: the miner threads poll
/// `cancel` and exit early when it flips, returning
/// [`CryptoError::PssMiningCancelled`]. Lets a server stop paying for a
/// mining job whose requester has disconnected or timed out.
pub fn wrap_cancellable(
    topic: &[u8; 32],
    msg: &[u8],
    recipient: &Recipient,
    targets: &[Vec<u8>],
    cancel: &AtomicBool,
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    if msg.len() > MAX_PAYLOAD_SIZE {
        return Err(CryptoError::PssMessageTooLong);
    }
    validate_targets(targets)?;
    let recipient_pub = recipient.public_key(topic)?;

    // Ephemeral ECDH: fresh keypair, shared key salted with the topic.
    let eph_secret = random_secp256k1_secret();
    let eph_pub = public_key_of(&eph_secret)?;
    let sk = shared_key(&eph_secret, &recipient_pub, topic)?;

    // Encrypt: keystream over the framed plaintext, raw-random tail to 4032.
    let plaintext = frame_plaintext(msg);
    let mut ciphertext = vec![0u8; CIPHERTEXT_SIZE];
    let pt_len = plaintext.len();
    ciphertext[..pt_len].copy_from_slice(&plaintext);
    cipher_xor(&mut ciphertext[..pt_len], &sk);
    getrandom::fill(&mut ciphertext[pt_len..]).expect("OS RNG");

    // Ephemeral X and its parity (for the byte-28 mining bit).
    let eph_compressed = compress_public_key(&eph_pub);
    let odd = eph_compressed[0] & 0x01 != 0;

    // Hint = keccak256(sk ‖ topic)[:8], doubling as the BMT header.
    let mut hint_input = [0u8; 32 + 32];
    hint_input[..32].copy_from_slice(&sk);
    hint_input[32..].copy_from_slice(topic);
    let hint_full = keccak256(&hint_input);
    let mut hint = [0u8; HINT_SIZE];
    hint.copy_from_slice(&hint_full[..HINT_SIZE]);

    // The fixed body tail (ephX ‖ ciphertext) that mining hashes behind
    // the varied nonce.
    let mut body_tail = [0u8; EPH_X_SIZE + CIPHERTEXT_SIZE];
    body_tail[..EPH_X_SIZE].copy_from_slice(&eph_compressed[1..33]);
    body_tail[EPH_X_SIZE..].copy_from_slice(&ciphertext);

    let nonce = mine(hint, &body_tail, targets, odd, cancel)?;

    let mut body = [0u8; BODY_SIZE];
    body[..NONCE_SIZE].copy_from_slice(&nonce);
    body[NONCE_SIZE..].copy_from_slice(&body_tail);
    let address = bmt_hash_with_span(&hint, &body).ok_or(CryptoError::InvalidChunkPayload)?;

    let mut data = Vec::with_capacity(TROJAN_DATA_SIZE);
    data.extend_from_slice(&hint);
    data.extend_from_slice(&body);
    Ok((address, data))
}

fn validate_targets(targets: &[Vec<u8>]) -> Result<(), CryptoError> {
    let Some(first) = targets.first() else {
        return Err(CryptoError::PssInvalidTargets);
    };
    let len = first.len();
    if len == 0 || len > MAX_TARGET_LEN || targets.iter().any(|t| t.len() != len) {
        return Err(CryptoError::PssInvalidTargets);
    }
    Ok(())
}

/// Process-wide pool of mining worker threads. Aggregate mining across
/// every concurrent [`wrap`] call is capped at the machine's parallelism
/// (`available_parallelism`, fallback 1 if it can't be detected) so an
/// attacker who pins several `/pss/send` jobs can't oversubscribe the
/// cores — total mining threads stay bounded no matter how many jobs
/// run. A job that can't get a slot **waits** (rather than spawning an
/// unaccounted worker, which would let N callers run `C + (N-1)` threads
/// and break the invariant); the wait is cancellation-aware so a
/// disconnected/timed-out request doesn't block.
static MINING_POOL: OnceLock<MiningPool> = OnceLock::new();

fn mining_pool() -> &'static MiningPool {
    MINING_POOL.get_or_init(|| {
        // The cap is exactly the machine's parallelism (fallback 1 if it
        // can't be detected) — no floor, so a single-core host runs one
        // mining thread total rather than oversubscribing. `acquire`
        // always grants ≥1 slot, so a job still makes progress.
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        MiningPool::new(cores)
    })
}

/// A counting semaphore of worker slots with a cancellation-aware wait.
struct MiningPool {
    avail: Mutex<usize>,
    cv: Condvar,
    cap: usize,
}

impl MiningPool {
    fn new(cap: usize) -> Self {
        Self {
            avail: Mutex::new(cap),
            cv: Condvar::new(),
            cap,
        }
    }

    /// Block until at least one slot is free, then take up to `desired`
    /// (clamped to the pool cap). Returns `None` if `cancel` flips while
    /// waiting — polled on a short timeout so a cancelled job never
    /// blocks indefinitely. Never returns `Some(0)`: a live job always
    /// gets ≥1 real, accounted slot, so the process-wide cap is exact.
    fn acquire(&self, desired: usize, cancel: &AtomicBool) -> Option<usize> {
        let want = desired.clamp(1, self.cap);
        let mut avail = self.avail.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            if *avail >= 1 {
                let take = want.min(*avail);
                *avail -= take;
                return Some(take);
            }
            let (guard, _timeout) = self
                .cv
                .wait_timeout(avail, Duration::from_millis(50))
                .unwrap_or_else(PoisonError::into_inner);
            avail = guard;
        }
    }

    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        {
            let mut avail = self.avail.lock().unwrap_or_else(PoisonError::into_inner);
            *avail += n;
            // Slots outstanding are only ever created by `acquire` and
            // returned by exactly one matching `release` (the RAII drop),
            // so availability can never exceed the cap. Guard it anyway
            // so a future accounting bug fails loud in debug builds.
            debug_assert!(*avail <= self.cap, "mining pool over-released past cap");
        }
        self.cv.notify_all();
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        *self.avail.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// An RAII claim on `claimed` pool slots; returns them to `pool` on drop
/// (covers early return, `?`, and panics). Lifetime-parameterized so
/// production claims from the `'static` process pool while tests claim
/// from a local pool with no global-state race.
struct MiningThreads<'a> {
    pool: &'a MiningPool,
    claimed: usize,
}

impl<'a> MiningThreads<'a> {
    /// Claim up to `desired` worker slots from `pool`, waiting
    /// (cancellation-aware) if none are free. `None` iff `cancel`
    /// flipped before a slot became available.
    fn claim_from(pool: &'a MiningPool, desired: usize, cancel: &AtomicBool) -> Option<Self> {
        let claimed = pool.acquire(desired, cancel)?;
        Some(MiningThreads { pool, claimed })
    }

    fn count(&self) -> usize {
        self.claimed
    }
}

impl MiningThreads<'static> {
    /// Claim from the process-wide pool.
    fn claim(desired: usize, cancel: &AtomicBool) -> Option<Self> {
        Self::claim_from(mining_pool(), desired, cancel)
    }
}

impl Drop for MiningThreads<'_> {
    fn drop(&mut self) {
        self.pool.release(self.claimed);
    }
}

/// Mine `nonce[0..4]` (with byte 28 parity fixed to `odd`) until the
/// chunk address matches one of `targets`, or `cancel` flips. Multi-
/// threaded, first hit wins. Returns the winning 32-byte nonce.
fn mine(
    hint: [u8; HINT_SIZE],
    body_tail: &[u8; EPH_X_SIZE + CIPHERTEXT_SIZE],
    targets: &[Vec<u8>],
    odd: bool,
    cancel: &AtomicBool,
) -> Result<[u8; NONCE_SIZE], CryptoError> {
    // Fixed nonce template: bytes 4..32 random, byte 28 parity-forced.
    let mut template = [0u8; NONCE_SIZE];
    getrandom::fill(&mut template).expect("OS RNG");
    if odd {
        template[28] |= 0x01;
    } else {
        template[28] &= 0xfe;
    }

    let found = AtomicBool::new(false);
    let winner: Mutex<Option<[u8; NONCE_SIZE]>> = Mutex::new(None);
    // Claim worker threads from the process-wide pool so *aggregate*
    // mining across all concurrent jobs never exceeds the machine's
    // parallelism — two jobs of 16 workers each would otherwise
    // oversubscribe every core. If none are free the claim waits
    // (cancellation-aware): a cancelled/timed-out request returns here
    // rather than spawning an unaccounted worker. The guard returns the
    // slots on completion (including panic/early return).
    let Some(workers) = MiningThreads::claim(16, cancel) else {
        return Err(CryptoError::PssMiningCancelled);
    };

    // Only the nonce (leaf 0 of the BMT) varies per attempt; every other
    // leaf is fixed for the job. Precompute leaf 0's sibling path once
    // and fold each candidate nonce up it: 7 pair hashes + the span mix
    // per attempt instead of a full 127-hash tree — ~16× less keccak
    // work, which also proportionally shrinks how long one deep-target
    // job can hold the mining pool's slots (head-of-line blocking).
    let mut body = [0u8; BODY_SIZE];
    body[NONCE_SIZE..].copy_from_slice(body_tail);
    let siblings =
        crate::bmt::first_segment_siblings(&body).ok_or(CryptoError::InvalidChunkPayload)?;
    let siblings = &siblings;

    std::thread::scope(|scope| {
        for w in 0..workers.count() {
            let found = &found;
            let winner = &winner;
            let template = template;
            scope.spawn(move || {
                let mut nonce = template;
                // Distinct starting counter per worker over nonce[0..4].
                let mut counter = (w as u32).wrapping_mul(0x9E37_79B9);
                loop {
                    if found.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    nonce[0..4].copy_from_slice(&counter.to_le_bytes());
                    let addr = crate::bmt::first_segment_address(&hint, siblings, &nonce);
                    if targets.iter().any(|t| addr[..t.len()] == t[..]) {
                        if !found.swap(true, Ordering::AcqRel) {
                            *winner.lock().unwrap() = Some(nonce);
                        }
                        return;
                    }
                    counter = counter.wrapping_add(1);
                }
            });
        }
    });

    // Workers only exit winnerless when the cancel flag flipped: the
    // search space is re-randomized per call and effectively unbounded.
    let result = *winner.lock().unwrap();
    result.ok_or(CryptoError::PssMiningCancelled)
}

/// The public key of this node's PSS key, SEC1-compressed (33 bytes) —
/// what `GET /addresses` reports as `pssPublicKey`.
pub fn pss_public_key_compressed(pss_secret: &[u8; 32]) -> Result<[u8; 33], CryptoError> {
    Ok(compress_public_key(&public_key_of(pss_secret)?))
}

/// Attempt to decrypt a trojan chunk `data` for this node's `pss_secret`,
/// trying each registered `topic` in order. Returns the `(topic, msg)` of
/// the first match, or `None` if the chunk isn't addressed to us under
/// any topic.
///
/// Also tries the topic-derived key (broadcast mode) per topic, matching
/// bee's `Unwrap` fallback.
#[must_use]
pub fn unwrap(
    pss_secret: &[u8; 32],
    data: &[u8],
    topics: &[[u8; 32]],
) -> Option<([u8; 32], Vec<u8>)> {
    if data.len() != TROJAN_DATA_SIZE {
        return None;
    }
    let hint = &data[..HINT_SIZE];
    let eph_x = &data[HINT_SIZE + NONCE_SIZE..HINT_SIZE + NONCE_SIZE + EPH_X_SIZE];
    let ciphertext = &data[HINT_SIZE + NONCE_SIZE + EPH_X_SIZE..];

    // Lift the ephemeral pubkey from its x-coordinate. ECDH uses x only,
    // so either parity works as long as x is a valid curve point.
    let eph_pub = lift_x(eph_x)?;

    for topic in topics {
        for secret in [*pss_secret, topic_derived_secret(topic)] {
            let Ok(sk) = shared_key(&secret, &eph_pub, topic) else {
                continue;
            };
            let mut hint_input = [0u8; 64];
            hint_input[..32].copy_from_slice(&sk);
            hint_input[32..].copy_from_slice(topic);
            if &keccak256(&hint_input)[..HINT_SIZE] != hint {
                continue;
            }
            if let Some(msg) = decrypt_and_check(ciphertext, &sk) {
                return Some((*topic, msg));
            }
        }
    }
    None
}

/// Reconstruct a secp256k1 public key from a 32-byte x-coordinate,
/// choosing even-y parity (`0x02`). Returns `None` if `x` is not a valid
/// curve x-coordinate.
fn lift_x(x: &[u8]) -> Option<PublicKey> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&sec1).ok()
}

/// Decrypt the 4032-byte ciphertext under `sk` and verify the integrity
/// frame; return the message on success.
fn decrypt_and_check(ciphertext: &[u8], sk: &[u8; 32]) -> Option<Vec<u8>> {
    let mut plain = ciphertext.to_vec();
    cipher_xor(&mut plain, sk);
    if plain.len() < INTEGRITY_SIZE {
        return None;
    }
    let length = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    if length > MAX_PAYLOAD_SIZE || INTEGRITY_SIZE + length > plain.len() {
        return None;
    }
    let msg = plain[INTEGRITY_SIZE..INTEGRITY_SIZE + length].to_vec();
    // Integrity: keccak256(msg)[2..] must equal plain[2..32].
    if keccak256(&msg)[2..] != plain[2..INTEGRITY_SIZE] {
        return None;
    }
    Some(msg)
}

// `SPAN_SIZE` is the BMT header length; assert our hint occupies it.
const _: () = assert!(HINT_SIZE == SPAN_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        hex::decode_to_slice(s, &mut o).unwrap();
        o
    }

    #[test]
    fn dh_shared_key_matches_go_vector() {
        // trojan-prims.jsonl dh_a_pubB_topic-test.
        let priv_a = hex32("1111111111111111111111111111111111111111111111111111111111111111");
        let pub_b = parse_public_key(
            &hex::decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27")
                .unwrap(),
        )
        .unwrap();
        let salt = hex32("9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658");
        let sk = shared_key(&priv_a, &pub_b, &salt).unwrap();
        assert_eq!(
            hex::encode(sk),
            "b2f72bd9208d2a0e3f4ac928f477a6082aee405a1278ca2d9cf8e7da4830ca83"
        );
    }

    #[test]
    fn cipher_matches_go_vector() {
        // trojan-prims.jsonl cipher_pt032.
        let key = hex32("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0");
        let mut buf: Vec<u8> = (0u8..32).collect();
        cipher_xor(&mut buf, &key);
        assert_eq!(
            hex::encode(&buf),
            "2bd4be0260783e61c740cf883a0c0c21c11bb7284bec2708ff6e9a0f186e6aad"
        );
    }

    #[test]
    fn frame_plaintext_layout() {
        let f = frame_plaintext(b"hi");
        assert_eq!(&f[0..2], &[0x00, 0x02]); // BE16 length
        assert_eq!(&f[2..32], &keccak256(b"hi")[2..]);
        assert_eq!(&f[32..], b"hi");
    }

    #[test]
    fn wrap_unwrap_round_trip_explicit_recipient() {
        let topic = topic_from_string("pss-demo");
        let recipient_secret =
            hex32("0202020202020202020202020202020202020202020202020202020202020202");
        let recipient_pub = public_key_of(&recipient_secret).unwrap();
        let msg = b"hello over pss";
        let (addr, data) =
            wrap(&topic, msg, &Recipient::Key(recipient_pub), &[vec![0xabu8]]).unwrap();
        assert_eq!(data.len(), TROJAN_DATA_SIZE);
        assert_eq!(addr[0], 0xab, "address must match the 1-byte target");

        let got = unwrap(&recipient_secret, &data, &[topic]).expect("must decrypt");
        assert_eq!(got.0, topic);
        assert_eq!(got.1, msg);

        // A different topic must not match.
        assert!(unwrap(&recipient_secret, &data, &[topic_from_string("other")]).is_none());
    }

    #[test]
    fn wrap_cancellable_stops_without_a_result() {
        // A pre-flipped cancel flag makes every miner thread exit on its
        // first loop check — even against a 3-byte target that would
        // otherwise take ~2^24 hashes.
        let topic = topic_from_string("cancelled");
        let err = wrap_cancellable(
            &topic,
            b"never mined",
            &Recipient::TopicDerived,
            &[vec![0xde, 0xad, 0xbe]],
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::PssMiningCancelled));
    }

    #[test]
    fn mining_pool_bounds_total_via_raii_claims() {
        // A LOCAL pool so this can't race the global one that live
        // `wrap` calls in other parallel tests share. Exercised through
        // the RAII MiningThreads guard (claim + drop) so release is
        // always balanced against claim — the earlier version leaked
        // fabricated slots by calling release() with counts it never
        // acquired, pushing availability past the cap.
        let pool = MiningPool::new(8);
        let no_cancel = AtomicBool::new(false);
        assert_eq!(pool.available(), 8);

        {
            // One claim takes the whole pool (clamped to cap).
            let a = MiningThreads::claim_from(&pool, 1024, &no_cancel).unwrap();
            assert_eq!(a.count(), 8, "claim is clamped to the pool cap");
            assert_eq!(pool.available(), 0);
            assert!(pool.available() <= pool.cap);

            // Drained + pre-flipped cancel → None, never a fabricated
            // slot (the no-C+1 invariant from round 3).
            let cancelled = AtomicBool::new(true);
            assert!(
                MiningThreads::claim_from(&pool, 4, &cancelled).is_none(),
                "a cancelled claim must not fabricate a slot"
            );
            // `a` still holds all 8 — availability never exceeds cap.
            assert!(pool.available() <= pool.cap);
        }
        // `a` dropped → exactly its 8 slots returned, never more.
        assert_eq!(
            pool.available(),
            8,
            "RAII drop returns exactly what was claimed"
        );
        assert!(pool.available() <= pool.cap);

        // Two partial claims coexist and never over-subscribe.
        {
            let x = MiningThreads::claim_from(&pool, 5, &no_cancel).unwrap();
            let y = MiningThreads::claim_from(&pool, 5, &no_cancel).unwrap();
            assert_eq!(x.count() + y.count(), 8, "two claims split exactly the cap");
            assert_eq!(pool.available(), 0);
        }
        assert_eq!(pool.available(), 8, "both drops restore the cap exactly");
    }

    #[test]
    fn mining_pool_wait_wakes_on_release() {
        use std::sync::Arc;
        // One-slot pool: a second claimant blocks until the first frees
        // its slot, proving acquire waits rather than over-committing.
        let pool = Arc::new(MiningPool::new(1));
        let held = pool.acquire(1, &AtomicBool::new(false)).unwrap();
        assert_eq!(held, 1);

        let p2 = Arc::clone(&pool);
        let waiter = std::thread::spawn(move || {
            // Blocks until the main thread releases below.
            p2.acquire(1, &AtomicBool::new(false)).unwrap()
        });

        // Give the waiter time to park, then release.
        std::thread::sleep(Duration::from_millis(120));
        pool.release(held);
        assert_eq!(waiter.join().unwrap(), 1, "waiter woke and took the slot");
    }

    #[test]
    fn wrap_unwrap_topic_derived_broadcast() {
        let topic = topic_from_string("broadcast-topic");
        let msg = b"anyone on the topic can read this";
        let (_addr, data) = wrap(&topic, msg, &Recipient::TopicDerived, &[vec![0x00u8]]).unwrap();
        // A receiver who only knows the topic (any pss key) decrypts via
        // the topic-derived fallback.
        let unrelated = hex32("0909090909090909090909090909090909090909090909090909090909090909");
        let got = unwrap(&unrelated, &data, &[topic]).expect("broadcast decrypt");
        assert_eq!(got.1, msg);
    }

    #[test]
    fn empty_and_max_messages() {
        let topic = topic_from_string("edge");
        let secret = hex32("0303030303030303030303030303030303030303030303030303030303030303");
        let pk = public_key_of(&secret).unwrap();
        for msg in [vec![], vec![0x42u8; MAX_PAYLOAD_SIZE]] {
            let (_a, data) = wrap(&topic, &msg, &Recipient::Key(pk), &[vec![0x01u8]]).unwrap();
            let got = unwrap(&secret, &data, &[topic]).unwrap();
            assert_eq!(got.1, msg);
        }
        // Over-long is rejected.
        assert!(matches!(
            wrap(
                &topic,
                &vec![0u8; MAX_PAYLOAD_SIZE + 1],
                &Recipient::Key(pk),
                &[vec![1]]
            ),
            Err(CryptoError::PssMessageTooLong)
        ));
    }

    #[test]
    fn rejects_bad_targets() {
        let topic = topic_from_string("t");
        let pk = public_key_of(&hex32(
            "0404040404040404040404040404040404040404040404040404040404040404",
        ))
        .unwrap();
        assert!(wrap(&topic, b"x", &Recipient::Key(pk), &[]).is_err());
        assert!(wrap(&topic, b"x", &Recipient::Key(pk), &[vec![0u8; 4]]).is_err());
        assert!(wrap(&topic, b"x", &Recipient::Key(pk), &[vec![1], vec![2, 3]]).is_err());
    }
}
