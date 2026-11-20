//! Upload-side Swarm content encryption (`swarm-encrypt`).
//!
//! The write-path mirror of [`crate::joiner`]'s `join_encrypted`: splits
//! a payload into the encrypted chunk tree bee's encryption pipeline
//! produces (`pkg/file/pipeline/builder.newEncryptionPipeline`), with or
//! without Reed-Solomon redundancy. The rules, as bee implements them:
//!
//! - **Every content chunk is encrypted under its own fresh 32-byte
//!   key** (`encryption.GenerateRandomKey`). The plaintext wire
//!   (`span(8 LE) ‖ payload`) is transformed with the Keccak-256 counter
//!   keystream — span at `initCtr = 128`, payload at `initCtr = 0` — and
//!   the ciphertext is right-padded to 4096 payload bytes (bee pads with
//!   `crypto/rand` bytes; the pad sits *outside* the keystream and is
//!   truncated away on decrypt). The chunk's stored address is the BMT
//!   hash of the **encrypted** bytes, so storage, pushsync and CAC
//!   validation are unchanged.
//! - **References are 64 bytes** (`address(32) ‖ key(32)`), so an
//!   intermediate chunk holds at most `4096 / 64 = 64` children —
//!   encryption halves the branching factor (`swarm.EncryptedBranches`).
//!   Intermediate chunks are themselves encrypted (fresh key each); the
//!   span they encrypt is the **plaintext** subtree byte count (sum of
//!   the data children's plain spans), exactly like bee's hashtrie,
//!   which threads the unencrypted span alongside the encrypted data.
//! - **Redundancy composes outside encryption.** Parity shards are
//!   Reed-Solomon encodings of the children's *encrypted* wire bytes
//!   (each already exactly 4104 bytes), and the parity chunks themselves
//!   are stored **unencrypted** — their references are plain 32-byte
//!   addresses appended after the 64-byte data references. Geometry
//!   comes from the encrypted erasure tables:
//!   [`crate::rs::max_enc_shards`] data children +
//!   [`crate::rs::get_enc_parities`] parities per node, and the level is
//!   encoded into the span top byte (`level | 0x80`) whenever a node
//!   carries parities. Dispersed replicas of the root are keyed on the
//!   root's 32-byte *address* (the key travels only in the returned
//!   reference); mint them with [`crate::rs_encode::replica_chunks`].
//! - **The root reference is `address ‖ key`** of the topmost chunk —
//!   the 64-byte value bee returns as a 128-hex `reference`.
//!
//! Chunk-level byte-exactness against bee's `pkg/encryption` primitives
//! (with injected keys and zero padding) is pinned by
//! `crates/ant-conformance/tests/encryption.rs` against
//! `conformance/vectors/encryption.json`; whole-tree compatibility is
//! proven the other way round — the same vectors carry trees produced by
//! bee's *real* random-keyed pipeline, which `join_encrypted` must
//! decode — and end-to-end by the mainnet smoke (ant-encrypted upload
//! fetched and decrypted by a canonical bee node).

use crate::rs::{get_enc_parities, max_enc_shards, MAX_LEVEL};
use crate::splitter::SplitChunk;
use crate::ChunkAddr;
use ant_crypto::{
    bmt_hash_with_span, cac_new, encrypt_chunk_unpadded, random_encryption_key, CHUNK_SIZE,
    KEY_LENGTH, SPAN_SIZE,
};

/// Length of an encrypted reference: `address(32) ‖ key(32)`.
pub const ENC_REF_SIZE: usize = ant_crypto::REFERENCE_SIZE;

/// Full encrypted chunk wire size: every stored encrypted chunk is
/// `encSpan(8) ‖ encData(4096)` (bee pads the ciphertext to `ChunkSize`).
const ENC_WIRE_SIZE: usize = SPAN_SIZE + CHUNK_SIZE;

/// Number of reference levels in the trie (bee hashtrie `maxLevel` is 8;
/// index 8 holds the root reference).
const TRIE_LEVELS: usize = 9;

/// One child reference held by a level accumulator: the child's raw
/// 8-byte plaintext span (level bit included when the child carries
/// parities), its stored address, and — for data children — its
/// decryption key. Parity children have no key (stored unencrypted).
#[derive(Clone)]
struct RefEntry {
    span: [u8; SPAN_SIZE],
    addr: ChunkAddr,
    key: Option<[u8; KEY_LENGTH]>,
}

/// Result of an encrypted split.
#[derive(Debug, Clone)]
pub struct EncryptedSplitResult {
    /// The 64-byte encrypted root reference (`address ‖ key`) — hex it
    /// to the 128-char `reference` bee returns.
    pub root_ref: [u8; ENC_REF_SIZE],
    /// The root chunk's stored (encrypted) wire bytes, for
    /// [`crate::rs_encode::replica_chunks`].
    pub root_wire: Vec<u8>,
    /// Total plaintext bytes.
    pub total_bytes: u64,
    /// Every chunk to store/push: encrypted leaves and intermediates
    /// plus (at `level > 0`) unencrypted parity chunks, in bee's
    /// emission order. Dispersed replicas of the root are not included.
    pub chunks: Vec<SplitChunk>,
}

impl EncryptedSplitResult {
    /// The root chunk's 32-byte stored address (`root_ref[..32]`) —
    /// what replicas and pushsync are keyed on.
    #[must_use]
    pub fn root_address(&self) -> ChunkAddr {
        self.root_ref[..32].try_into().expect("64-byte root ref")
    }
}

/// Split `payload` into an encrypted chunk tree at redundancy `level`
/// (0–4) with fresh random keys and random ciphertext padding — the
/// production path, matching bee's `swarm-encrypt: true` pipeline.
///
/// # Panics
///
/// If `level > 4` or the payload exceeds the trie capacity.
#[must_use]
pub fn split_bytes_encrypted(payload: &[u8], level: u8) -> EncryptedSplitResult {
    split_encrypted_inner(payload, level, KeySource::Random)
}

/// Deterministic variant of [`split_bytes_encrypted`] for tests and
/// conformance vectors: chunk keys come from `keys` (called once per
/// encrypted chunk, in bee's chunk-write order) and ciphertext padding
/// is zeros. Interoperable with bee — decryption never sees the pad —
/// but reproducible.
#[must_use]
pub fn split_bytes_encrypted_with_keys(
    payload: &[u8],
    level: u8,
    keys: impl FnMut() -> [u8; KEY_LENGTH],
) -> EncryptedSplitResult {
    split_encrypted_inner(payload, level, KeySource::Injected(Box::new(keys)))
}

enum KeySource<'a> {
    /// OS-random keys, OS-random ciphertext padding (production).
    Random,
    /// Injected key stream, zero ciphertext padding (deterministic).
    Injected(Box<dyn FnMut() -> [u8; KEY_LENGTH] + 'a>),
}

fn split_encrypted_inner(payload: &[u8], level: u8, keys: KeySource) -> EncryptedSplitResult {
    let mut splitter = EncryptedSplitter::new(level, keys);
    let mut chunks = Vec::new();
    for leaf in payload.chunks(CHUNK_SIZE) {
        chunks.extend(splitter.push_leaf(leaf));
    }
    let (root_ref, root_wire, total_bytes, tail) = splitter.finish();
    chunks.extend(tail);
    EncryptedSplitResult {
        root_ref,
        root_wire,
        total_bytes,
        chunks,
    }
}

/// Streaming encrypted splitter mirroring [`crate::RedundantSplitter`]'s
/// push-leaves-then-finish contract, with 64-byte references and the
/// encrypted erasure geometry.
struct EncryptedSplitter<'a> {
    level: u8,
    keys: KeySource<'a>,
    /// Data references per intermediate node (`GetMaxEncShards`; 64 at
    /// level 0).
    max_shards: usize,
    /// Accumulator size at which a level wraps (bee `maxChildrenChunks`
    /// = `max_shards + get_enc_parities(level, max_shards)`).
    max_children: usize,
    /// `acc[l]` holds the child references of the pending intermediate
    /// node at trie level `l`; data entries always precede parity
    /// entries. `acc[8]` ends up holding exactly the root reference.
    acc: Vec<Vec<RefEntry>>,
    /// Count of *data* entries per accumulator level.
    eff: [usize; TRIE_LEVELS],
    /// `buf[l]` buffers the **encrypted** wire bytes of not-yet-encoded
    /// chunks of tree level `l` (bee `redundancy.Params.buffer` holds
    /// `p.Data`, i.e. ciphertext — parities are computed over
    /// ciphertext). At level 0 (no erasure coding) only the most recent
    /// wire is kept, purely so the root's wire survives carry-over
    /// elevation to the top.
    buf: Vec<Vec<Vec<u8>>>,
    bytes_consumed: u64,
    leaves: u64,
    full: bool,
}

impl<'a> EncryptedSplitter<'a> {
    fn new(level: u8, keys: KeySource<'a>) -> Self {
        assert!(level <= MAX_LEVEL, "redundancy level must be 0..=4");
        let shards = max_enc_shards(level);
        Self {
            level,
            keys,
            max_shards: shards,
            max_children: shards + get_enc_parities(level, shards),
            acc: vec![Vec::new(); TRIE_LEVELS],
            eff: [0; TRIE_LEVELS],
            buf: vec![Vec::new(); TRIE_LEVELS],
            bytes_consumed: 0,
            leaves: 0,
            full: false,
        }
    }

    /// Encrypt-and-address one plaintext chunk wire: fresh key,
    /// ciphertext padded to the fixed 4104-byte stored form, address =
    /// BMT over the encrypted bytes (header = encrypted span).
    fn encrypt_store(&mut self, plain_wire: &[u8]) -> (ChunkAddr, [u8; KEY_LENGTH], Vec<u8>) {
        let key = match &mut self.keys {
            KeySource::Random => random_encryption_key(),
            KeySource::Injected(f) => f(),
        };
        let mut wire = encrypt_chunk_unpadded(plain_wire, &key);
        let cipher_len = wire.len();
        wire.resize(ENC_WIRE_SIZE, 0);
        if matches!(self.keys, KeySource::Random) {
            getrandom::fill(&mut wire[cipher_len..]).expect("OS RNG");
        }
        let span: [u8; SPAN_SIZE] = wire[..SPAN_SIZE].try_into().expect("span present");
        let addr = bmt_hash_with_span(&span, &wire[SPAN_SIZE..])
            .expect("encrypted payload is exactly CHUNK_SIZE");
        (addr, key, wire)
    }

    /// Feed one leaf payload (≤ 4096 bytes; only the last may be short).
    /// Returns the chunks produced by this call.
    fn push_leaf(&mut self, payload: &[u8]) -> Vec<SplitChunk> {
        assert!(!self.full, "encrypted trie full");
        assert!(payload.len() <= CHUNK_SIZE, "leaf payload > CHUNK_SIZE");
        let (_, plain_wire) = cac_new(payload).expect("leaf ≤ CHUNK_SIZE by construction");
        let (addr, key, wire) = self.encrypt_store(&plain_wire);
        self.bytes_consumed += payload.len() as u64;
        self.leaves += 1;
        let mut out = vec![SplitChunk {
            address: addr,
            wire: wire.clone(),
        }];
        let span: [u8; SPAN_SIZE] = plain_wire[..SPAN_SIZE].try_into().expect("leaf span");
        // Bee `writeToDataLevel`: reference first, chunk data second.
        self.write_ref(
            1,
            RefEntry {
                span,
                addr,
                key: Some(key),
            },
            &mut out,
        );
        self.chunk_write(0, wire, &mut out);
        out
    }

    /// Bee `writeToIntermediateLevel`: append a child reference at
    /// `level`, wrapping the level when it reaches `max_children`.
    fn write_ref(&mut self, level: usize, entry: RefEntry, out: &mut Vec<SplitChunk>) {
        if entry.key.is_some() {
            self.eff[level] += 1;
        }
        self.acc[level].push(entry);
        if self.acc[level].len() == self.max_children {
            self.wrap_full_level(level, out);
        }
    }

    /// Bee `redundancy.Params.chunkWrite` over ciphertext: buffer one
    /// stored chunk's wire bytes at tree level `chunk_level`, RS-encoding
    /// the group when `max_shards` are buffered. At level 0 there is no
    /// erasure coding; keep only the latest wire (root-wire tracking).
    fn chunk_write(&mut self, chunk_level: usize, wire: Vec<u8>, out: &mut Vec<SplitChunk>) {
        if self.level == 0 {
            self.buf[chunk_level].clear();
            self.buf[chunk_level].push(wire);
            return;
        }
        self.buf[chunk_level].push(wire);
        if self.buf[chunk_level].len() == self.max_shards {
            self.encode(chunk_level, out);
        }
    }

    /// Bee `redundancy.Params.encode` with the encrypted tables:
    /// Reed-Solomon over the buffered *encrypted* wires; each parity
    /// shard becomes an **unencrypted** chunk referenced one level up by
    /// its bare 32-byte address.
    fn encode(&mut self, chunk_level: usize, out: &mut Vec<SplitChunk>) {
        let shards = self.buf[chunk_level].len();
        if shards == 0 {
            return;
        }
        let parities = get_enc_parities(self.level, shards);
        debug_assert!(parities > 0, "enc erasure tables cover every count ≥ 1");

        let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(shards + parities);
        for wire in self.buf[chunk_level].drain(..) {
            debug_assert_eq!(wire.len(), ENC_WIRE_SIZE, "encrypted wires are full-size");
            matrix.push(wire);
        }
        matrix.extend(std::iter::repeat_with(|| vec![0u8; ENC_WIRE_SIZE]).take(parities));

        let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(shards, parities)
            .expect("shards ≥ 1 and shards + parities ≤ 128 by table construction");
        rs.encode(&mut matrix)
            .expect("shard geometry fixed at construction");

        for shard in matrix.drain(..).skip(shards) {
            let span: [u8; SPAN_SIZE] = shard[..SPAN_SIZE].try_into().expect("full shard");
            let addr = bmt_hash_with_span(&span, &shard[SPAN_SIZE..])
                .expect("shard payload is exactly CHUNK_SIZE");
            out.push(SplitChunk {
                address: addr,
                wire: shard,
            });
            self.write_ref(
                chunk_level + 1,
                RefEntry {
                    span,
                    addr,
                    key: None,
                },
                out,
            );
        }
    }

    /// Bee `wrapFullLevel`: wrap the accumulator at `level` into an
    /// *encrypted* intermediate chunk (plaintext span = Σ data-child
    /// spans, level bit when parities present; plaintext payload =
    /// 64-byte data refs then 32-byte parity refs), reference it one
    /// level up, and buffer its encrypted wire for that level's erasure
    /// group.
    fn wrap_full_level(&mut self, level: usize, out: &mut Vec<SplitChunk>) {
        let entries = std::mem::take(&mut self.acc[level]);
        let eff = std::mem::take(&mut self.eff[level]);
        let parities = entries.len() - eff;

        let mut sp: u64 = 0;
        for entry in &entries[..eff] {
            sp = sp.wrapping_add(u64::from_le_bytes(entry.span));
        }
        let mut span = sp.to_le_bytes();
        if parities > 0 {
            span[SPAN_SIZE - 1] = self.level | 0x80;
        }

        let mut payload = Vec::with_capacity(eff * ENC_REF_SIZE + parities * 32);
        for entry in &entries {
            payload.extend_from_slice(&entry.addr);
            if let Some(key) = &entry.key {
                payload.extend_from_slice(key);
            }
        }
        let mut plain_wire = Vec::with_capacity(SPAN_SIZE + payload.len());
        plain_wire.extend_from_slice(&span);
        plain_wire.extend_from_slice(&payload);

        let (addr, key, wire) = self.encrypt_store(&plain_wire);
        out.push(SplitChunk {
            address: addr,
            wire: wire.clone(),
        });

        self.write_ref(
            level + 1,
            RefEntry {
                span,
                addr,
                key: Some(key),
            },
            out,
        );
        self.chunk_write(level, wire, out);
        if level + 1 == TRIE_LEVELS - 1 {
            self.full = true;
        }
    }

    /// Drain partial levels into the root (bee hashtrie `Sum`). Returns
    /// `(root_ref, root_wire, total_bytes, tail_chunks)`. An empty input
    /// produces the encrypted empty leaf as root.
    #[must_use]
    fn finish(mut self) -> ([u8; ENC_REF_SIZE], Vec<u8>, u64, Vec<SplitChunk>) {
        let mut out = Vec::new();
        if self.leaves == 0 {
            out.extend(self.push_leaf(b""));
        }

        for level in 1..TRIE_LEVELS - 1 {
            match self.acc[level].len() {
                0 => {}
                1 => {
                    // Carry the lone subtree root one level up, moving
                    // its buffered wire along (`ElevateCarrierChunk`).
                    let entry = self.acc[level].pop().expect("len checked");
                    if entry.key.is_some() {
                        self.eff[level + 1] += 1;
                    }
                    self.acc[level + 1].push(entry);
                    self.eff[level] = 0;
                    debug_assert_eq!(
                        self.buf[level - 1].len(),
                        1,
                        "carrier chunk must be the level's only buffered chunk",
                    );
                    let data = self.buf[level - 1].pop().expect("carrier chunk buffered");
                    self.chunk_write(level, data, &mut out);
                }
                n if n == self.max_children => self.wrap_full_level(level, &mut out),
                _ => {
                    // Rightmost partial group: parities for the actual
                    // shard count (no-op at level 0), then wrap.
                    if self.level > 0 {
                        self.encode(level - 1, &mut out);
                    }
                    self.wrap_full_level(level, &mut out);
                }
            }
        }

        let top = &self.acc[TRIE_LEVELS - 1];
        assert_eq!(top.len(), 1, "trie must collapse to a single root");
        let entry = &top[0];
        let key = entry.key.expect("root is always an encrypted data chunk");
        let mut root_ref = [0u8; ENC_REF_SIZE];
        root_ref[..32].copy_from_slice(&entry.addr);
        root_ref[32..].copy_from_slice(&key);
        let root_wire = self.buf[TRIE_LEVELS - 2]
            .pop()
            .expect("root wire elevated to the top buffer level");
        debug_assert_eq!(
            bmt_hash_with_span(
                root_wire[..SPAN_SIZE].try_into().expect("root span"),
                &root_wire[SPAN_SIZE..],
            ),
            Some(entry.addr),
            "elevated root wire must hash to the root address",
        );
        (root_ref, root_wire, self.bytes_consumed, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::joiner::join_encrypted;
    use crate::rs_encode::replica_chunks;
    use crate::ChunkFetcher;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::error::Error;

    struct MapFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
    }

    #[async_trait]
    impl ChunkFetcher for MapFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            self.chunks
                .get(&addr)
                .cloned()
                .ok_or_else(|| -> Box<dyn Error + Send + Sync> {
                    format!("missing chunk {}", hex::encode(addr)).into()
                })
        }
    }

    fn det(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 41) % 251) as u8).collect()
    }

    fn det_keys() -> impl FnMut() -> [u8; KEY_LENGTH] {
        let mut i = 0u64;
        move || {
            i += 1;
            let mut k = [0u8; KEY_LENGTH];
            k[..8].copy_from_slice(&i.to_le_bytes());
            k
        }
    }

    /// Every stored chunk is the fixed 4104-byte encrypted form and the
    /// root reference is 64 bytes with the root's address up front.
    #[test]
    fn stored_shapes() {
        let result = split_bytes_encrypted(&det(CHUNK_SIZE * 3 + 5), 0);
        assert_eq!(result.total_bytes, (CHUNK_SIZE * 3 + 5) as u64);
        assert_eq!(result.chunks.len(), 5, "4 leaves + 1 intermediate");
        for c in &result.chunks {
            assert_eq!(c.wire.len(), ENC_WIRE_SIZE);
        }
        assert_eq!(result.root_address().as_slice(), &result.root_ref[..32]);
        assert!(result
            .chunks
            .iter()
            .any(|c| c.address == result.root_address() && c.wire == result.root_wire));
    }

    /// Joiner round-trip at every level for a spread of shapes,
    /// including single leaf, exactly-full groups and carries.
    #[tokio::test]
    async fn encrypted_split_round_trips_through_join_encrypted() {
        for level in 0..=MAX_LEVEL {
            let shards = max_enc_shards(level);
            for len in [
                0usize,
                10,
                CHUNK_SIZE,
                CHUNK_SIZE + 1,
                CHUNK_SIZE * 3 + 7,
                CHUNK_SIZE * shards,
                CHUNK_SIZE * shards + 1,
                CHUNK_SIZE * (shards + 2) + 100,
            ] {
                let payload = det(len);
                let result = split_bytes_encrypted(&payload, level);
                let fetcher = MapFetcher {
                    chunks: result
                        .chunks
                        .iter()
                        .map(|c| (c.address, c.wire.clone()))
                        .collect(),
                };
                let back = join_encrypted(&fetcher, result.root_ref, 1 << 30)
                    .await
                    .unwrap_or_else(|e| panic!("level {level} len {len}: join failed: {e}"));
                assert_eq!(back, payload, "level {level} len {len}");
            }
        }
    }

    /// The injected-key variant is deterministic and differs between key
    /// streams; the random variant differs run to run.
    #[test]
    fn key_injection_is_deterministic() {
        let payload = det(CHUNK_SIZE + 100);
        let a = split_bytes_encrypted_with_keys(&payload, 0, det_keys());
        let b = split_bytes_encrypted_with_keys(&payload, 0, det_keys());
        assert_eq!(a.root_ref, b.root_ref);
        assert_eq!(a.chunks.len(), b.chunks.len());
        for (x, y) in a.chunks.iter().zip(&b.chunks) {
            assert_eq!(x.address, y.address);
            assert_eq!(x.wire, y.wire);
        }
        let c = split_bytes_encrypted(&payload, 0);
        assert_ne!(a.root_ref, c.root_ref, "random keys change the tree");
    }

    /// Redundant encrypted trees carry the level bit on the root span
    /// (once decrypted) and mixed 64/32-byte reference lists whose
    /// geometry matches `reference_count_enc`.
    #[test]
    fn redundant_geometry_matches_decoder_expectations() {
        let level = 1;
        let len = CHUNK_SIZE * 10 + 5;
        let result = split_bytes_encrypted_with_keys(&det(len), level, det_keys());
        let key: [u8; 32] = result.root_ref[32..].try_into().unwrap();
        let (span_raw, _) = ant_crypto::decrypt_chunk_parts(&result.root_wire, &key).unwrap();
        let (l, plain) = crate::rs::decode_span(span_raw);
        assert_eq!(l, level);
        assert_eq!(u64::from_le_bytes(plain), len as u64);
        let (shards, parities) = crate::rs::reference_count_enc(len as u64, level);
        assert_eq!(shards, 11);
        assert!(parities > 0);
    }

    /// Replica SOCs derive from the encrypted root's address + wire the
    /// same way plain redundant roots do.
    #[test]
    fn replicas_derive_from_encrypted_root() {
        let level = 1;
        let result = split_bytes_encrypted(&det(100), level);
        let replicas = replica_chunks(&result.root_address(), &result.root_wire, level);
        assert_eq!(replicas.len(), crate::rs::REPLICA_COUNTS[level as usize]);
        for r in &replicas {
            assert!(ant_crypto::soc_valid(&r.address, &r.wire));
        }
    }

    /// Decrypt-walk an encrypted tree and collect, per intermediate
    /// node, its data children's 32-byte address halves and its parity
    /// count — the geometry the joiner's recovery path relies on.
    fn collect_enc_nodes(
        chunks: &HashMap<[u8; 32], Vec<u8>>,
        node_ref: [u8; ENC_REF_SIZE],
        out: &mut Vec<(Vec<[u8; 32]>, usize)>,
    ) {
        let addr: [u8; 32] = node_ref[..32].try_into().unwrap();
        let key: [u8; 32] = node_ref[32..].try_into().unwrap();
        let (span_raw, payload) = ant_crypto::decrypt_chunk_parts(&chunks[&addr], &key).unwrap();
        let (level, plain) = crate::rs::decode_span(span_raw);
        let span = u64::from_le_bytes(plain);
        if span <= CHUNK_SIZE as u64 {
            return;
        }
        let (shards, parities) = crate::rs::reference_count_enc(span, level);
        let mut data = Vec::with_capacity(shards);
        for i in 0..shards {
            let child: [u8; ENC_REF_SIZE] = payload[i * ENC_REF_SIZE..(i + 1) * ENC_REF_SIZE]
                .try_into()
                .unwrap();
            data.push(child[..32].try_into().unwrap());
            collect_enc_nodes(chunks, child, out);
        }
        out.push((data, parities));
    }

    /// Read-path recovery over our own writer's output: at every level,
    /// delete up to `parityCnt` data children per intermediate node
    /// (first and last shard included) and the joiner must still decode
    /// the exact payload by reconstructing the missing ciphertext wires
    /// from the parities.
    #[tokio::test]
    async fn join_encrypted_recovers_missing_data_chunks() {
        for level in 1..=MAX_LEVEL {
            let shards = max_enc_shards(level);
            let payload = det(CHUNK_SIZE * (shards + 2) + 100);
            let result = split_bytes_encrypted(&payload, level);
            let chunks: HashMap<[u8; 32], Vec<u8>> = result
                .chunks
                .iter()
                .map(|c| (c.address, c.wire.clone()))
                .collect();
            let mut nodes = Vec::new();
            collect_enc_nodes(&chunks, result.root_ref, &mut nodes);
            assert!(nodes.len() >= 2, "level {level}: want a multi-node tree");

            let mut store = chunks.clone();
            for (data, parities) in &nodes {
                assert!(*parities > 0, "level {level}: node without parities");
                let k = (*parities).min(data.len());
                // k indices spread over the node, first and last included.
                for j in 0..k {
                    let i = if k == 1 {
                        0
                    } else {
                        j * (data.len() - 1) / (k - 1)
                    };
                    store.remove(&data[i]);
                }
            }
            assert!(store.len() < chunks.len());

            let fetcher = MapFetcher { chunks: store };
            let back = join_encrypted(&fetcher, result.root_ref, 1 << 30)
                .await
                .unwrap_or_else(|e| panic!("level {level}: recovery join failed: {e}"));
            assert_eq!(back, payload, "level {level}");
        }
    }

    /// Losing more than `parityCnt` data children of one node is a
    /// terminal `Recovery` error, not a hang or garbage output.
    #[tokio::test]
    async fn join_encrypted_over_loss_is_terminal() {
        let level = 1;
        let payload = det(CHUNK_SIZE * 10 + 5);
        let result = split_bytes_encrypted(&payload, level);
        let chunks: HashMap<[u8; 32], Vec<u8>> = result
            .chunks
            .iter()
            .map(|c| (c.address, c.wire.clone()))
            .collect();
        let mut nodes = Vec::new();
        collect_enc_nodes(&chunks, result.root_ref, &mut nodes);
        let (data, parities) = &nodes[0];
        assert!(data.len() > *parities);
        let mut store = chunks;
        for addr in data.iter().take(parities + 1) {
            store.remove(addr);
        }
        let fetcher = MapFetcher { chunks: store };
        let err = join_encrypted(&fetcher, result.root_ref, 1 << 30)
            .await
            .expect_err("over-loss must fail");
        assert!(
            matches!(err, crate::JoinError::Recovery { .. }),
            "expected Recovery, got {err:?}"
        );
    }

    /// A lost encrypted root is recovered from its dispersed replicas:
    /// the replica SOC wraps the *encrypted* root chunk, keyed on the
    /// root's 32-byte address half.
    #[tokio::test]
    async fn join_encrypted_recovers_root_from_replicas() {
        let level = 2;
        let payload = det(CHUNK_SIZE * 3 + 11);
        let result = split_bytes_encrypted(&payload, level);
        let mut store: HashMap<[u8; 32], Vec<u8>> = result
            .chunks
            .iter()
            .map(|c| (c.address, c.wire.clone()))
            .collect();
        store.remove(&result.root_address());
        for r in replica_chunks(&result.root_address(), &result.root_wire, level) {
            store.insert(r.address, r.wire);
        }
        let fetcher = MapFetcher { chunks: store };
        let back = join_encrypted(&fetcher, result.root_ref, 1 << 30)
            .await
            .expect("replica fallback join");
        assert_eq!(back, payload);
    }
}
