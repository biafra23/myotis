//! Upload-side Reed-Solomon erasure encoding.
//!
//! The write-path mirror of [`crate::rs`]: splits a payload into the
//! exact chunk set bee's redundant upload pipeline produces for a
//! `swarm-redundancy-level` of 1–4. Faithfully reimplements the
//! interplay of bee's `pkg/file/pipeline/hashtrie` (the per-level
//! reference accumulators and their wrap rules) and
//! `pkg/file/redundancy.Params` (the per-level chunk-data buffers the
//! parities are computed over). The rules, as bee implements them:
//!
//! - Every chunk of tree level `L` (leaves are level 0) has its full
//!   wire bytes (`span ‖ payload`, zero-padded to 4104) buffered. When
//!   `max_shards(level)` of them accumulate, a Reed-Solomon encoder
//!   (GF(2^8), Backblaze/klauspost construction — the same
//!   `reed-solomon-erasure` crate the decoder uses) produces
//!   `get_parities(level, max_shards)` parity shards. Each parity
//!   shard *is* a chunk: its first 8 bytes act as its span and its BMT
//!   address is `bmt(shard[..8], shard[8..])`.
//! - The intermediate node above carries the data children's addresses
//!   followed by the parity addresses. Its span is the sum of the data
//!   children's raw 8-byte spans (parity spans are never summed), with
//!   the redundancy level encoded into the top byte (`level | 0x80`)
//!   whenever the node carries parities.
//! - **Partial groups** (the rightmost node of each level): at finish
//!   time the still-buffered `n < max_shards` chunk datas are encoded
//!   with `get_parities(level, n)` parities — the erasure table row for
//!   the actual shard count — before the node is wrapped.
//! - **Single carry-over** (a level whose only entry is the subtree
//!   root so far): no parities are produced; the entry *and its
//!   buffered chunk data* are elevated one level up, exactly like
//!   bee's `ElevateCarrierChunk`. A file that fits one leaf therefore
//!   produces no parities at all — only dispersed replicas of its root.
//! - **The root** is an ordinary wrapped node: it carries parities for
//!   its own children like any other intermediate node. Additionally
//!   [`replica_chunks`] derives the 2^level dispersed-replica SOCs of
//!   the root that bee's `pkg/replicas` putter uploads alongside.
//!
//! Byte-for-byte equality with bee's pipeline — root address, every
//! data/parity chunk, and the replica SOCs — is pinned by
//! `crates/ant-conformance/tests/rs_encode.rs` against
//! `conformance/vectors/rs_files.json` (fixtures produced by bee's real
//! `builder.NewPipelineBuilder`).

use crate::rs::{get_parities, max_shards, MAX_LEVEL, REPLICA_COUNTS};
use crate::splitter::{split_bytes, SplitChunk, SplitResult};
use crate::ChunkAddr;
use ant_crypto::{bmt_hash_with_span, cac_new, CHUNK_SIZE, SPAN_SIZE};

/// Full RS shard size (`swarm.ChunkWithSpanSize`).
const SHARD_SIZE: usize = CHUNK_SIZE + SPAN_SIZE;

/// Number of reference levels in the trie (bee hashtrie `maxLevel` is 8;
/// index 8 holds the root reference).
const TRIE_LEVELS: usize = 9;

/// One child reference held by a level accumulator: the child's raw
/// 8-byte span (level bit included for redundant subtrees, RS-shard
/// prefix for parities) and its address.
#[derive(Clone)]
struct RefEntry {
    span: [u8; SPAN_SIZE],
    addr: ChunkAddr,
}

/// Result of a redundant split: like [`SplitResult`] plus the root's
/// wire bytes, which [`replica_chunks`] needs to build the dispersed
/// replica SOCs.
#[derive(Debug, Clone)]
pub struct RedundantSplitResult {
    /// Address of the file's root chunk.
    pub root: ChunkAddr,
    /// The root chunk's exact wire bytes (`span ‖ payload`).
    pub root_wire: Vec<u8>,
    /// Total file bytes.
    pub total_bytes: u64,
    /// Every chunk needed to serve the file: leaves, intermediates
    /// *and parity chunks*, in bee's emission order. Dispersed replicas
    /// of the root are **not** included — they are SOCs, not CACs; get
    /// them from [`replica_chunks`].
    pub chunks: Vec<SplitChunk>,
}

/// Split `payload` into a redundant chunk tree at `level` (1–4). For
/// `level == 0` this delegates to [`split_bytes`] (no parities, no
/// level bits) and reports the leaf/root wire accordingly.
///
/// # Panics
///
/// If `level > 4`, or if the payload exceeds the trie capacity
/// (`max_shards(level)^7 × 4096` bytes — beyond any gateway cap).
#[must_use]
pub fn split_bytes_with_redundancy(payload: &[u8], level: u8) -> RedundantSplitResult {
    if level == 0 {
        let SplitResult {
            root,
            total_bytes,
            chunks,
        } = split_bytes(payload);
        let root_wire = chunks
            .iter()
            .find(|c| c.address == root)
            .expect("split_bytes always emits the root")
            .wire
            .clone();
        return RedundantSplitResult {
            root,
            root_wire,
            total_bytes,
            chunks,
        };
    }

    let mut splitter = RedundantSplitter::new(level);
    let mut chunks = Vec::new();
    for leaf in payload.chunks(CHUNK_SIZE) {
        chunks.extend(splitter.push_leaf(leaf));
    }
    let (root, root_wire, total_bytes, tail) = splitter.finish();
    chunks.extend(tail);
    RedundantSplitResult {
        root,
        root_wire,
        total_bytes,
        chunks,
    }
}

/// Streaming redundant splitter: the level-aware counterpart of
/// [`crate::splitter::StreamingSplitter`], with the same
/// push-leaves-then-finish contract. Memory is bounded by the per-level
/// RS buffers (`≤ 8 × max_shards(level) × 4104 B` ≈ 4 MiB at level 1),
/// independent of file size — bee's own pipeline holds the same state.
pub struct RedundantSplitter {
    level: u8,
    max_shards: usize,
    /// `max_shards + get_parities(level, max_shards)`: the accumulator
    /// size at which a level wraps (bee `maxChildrenChunks`).
    max_children: usize,
    /// `acc[l]` holds the child references of the pending intermediate
    /// node at trie level `l` (children are chunks of tree level
    /// `l - 1`); data entries always precede parity entries. `acc[8]`
    /// ends up holding exactly the root reference.
    acc: Vec<Vec<RefEntry>>,
    /// Count of *data* (non-parity) entries per accumulator level
    /// (bee `effectiveChunkCounters`).
    eff: [usize; TRIE_LEVELS],
    /// `buf[l]` buffers the raw wire bytes of not-yet-encoded chunks of
    /// tree level `l` (bee `redundancy.Params.buffer`; bee pads on
    /// insert, we pad at encode time so the root's exact wire survives
    /// elevation).
    buf: Vec<Vec<Vec<u8>>>,
    bytes_consumed: u64,
    leaves: u64,
    /// Set once the root lands on the top level; further writes panic
    /// (bee `errTrieFull`).
    full: bool,
}

impl RedundantSplitter {
    /// # Panics
    ///
    /// If `level` is 0 (use [`crate::splitter::StreamingSplitter`]) or
    /// greater than [`MAX_LEVEL`].
    #[must_use]
    pub fn new(level: u8) -> Self {
        assert!(
            (1..=MAX_LEVEL).contains(&level),
            "redundancy level must be 1..=4, got {level}",
        );
        let shards = max_shards(level);
        Self {
            level,
            max_shards: shards,
            max_children: shards + get_parities(level, shards),
            acc: vec![Vec::new(); TRIE_LEVELS],
            eff: [0; TRIE_LEVELS],
            buf: vec![Vec::new(); TRIE_LEVELS],
            bytes_consumed: 0,
            leaves: 0,
            full: false,
        }
    }

    /// Bytes fed in so far.
    #[must_use]
    pub const fn bytes_consumed(&self) -> u64 {
        self.bytes_consumed
    }

    /// Feed one leaf payload (≤ 4096 bytes; only the last may be
    /// short). Returns the chunks produced by this call: the leaf,
    /// plus any parity chunks and intermediates that completed.
    pub fn push_leaf(&mut self, payload: &[u8]) -> Vec<SplitChunk> {
        assert!(!self.full, "redundant trie full");
        assert!(
            payload.len() <= CHUNK_SIZE,
            "leaf payload {} > CHUNK_SIZE {CHUNK_SIZE}",
            payload.len(),
        );
        let (addr, wire) = cac_new(payload).expect("leaf ≤ CHUNK_SIZE by construction");
        self.bytes_consumed += payload.len() as u64;
        self.leaves += 1;
        let mut out = vec![SplitChunk {
            address: addr,
            wire: wire.clone(),
        }];
        let span: [u8; SPAN_SIZE] = wire[..SPAN_SIZE].try_into().expect("leaf wire has a span");
        // Bee `writeToDataLevel`: reference first, chunk data second
        // (the data write may trigger the parity encode that completes
        // the level).
        self.write_ref(1, false, RefEntry { span, addr }, &mut out);
        self.chunk_write(0, wire, &mut out);
        out
    }

    /// Bee `writeToIntermediateLevel`: append a child reference at
    /// `level`, wrapping the level when it reaches `max_children`.
    fn write_ref(
        &mut self,
        level: usize,
        parity: bool,
        entry: RefEntry,
        out: &mut Vec<SplitChunk>,
    ) {
        self.acc[level].push(entry);
        if !parity {
            self.eff[level] += 1;
        }
        if self.acc[level].len() == self.max_children {
            self.wrap_full_level(level, out);
        }
    }

    /// Bee `redundancy.Params.chunkWrite`: buffer one chunk's wire
    /// bytes at tree level `chunk_level`, RS-encoding the group when
    /// `max_shards` are buffered.
    fn chunk_write(&mut self, chunk_level: usize, wire: Vec<u8>, out: &mut Vec<SplitChunk>) {
        self.buf[chunk_level].push(wire);
        if self.buf[chunk_level].len() == self.max_shards {
            self.encode(chunk_level, out);
        }
    }

    /// Bee `redundancy.Params.encode`: Reed-Solomon encode the chunks
    /// buffered at `chunk_level`, emit each parity shard as a chunk and
    /// append its reference (as a parity) one level up.
    fn encode(&mut self, chunk_level: usize, out: &mut Vec<SplitChunk>) {
        let shards = self.buf[chunk_level].len();
        if shards == 0 {
            return;
        }
        let parities = get_parities(self.level, shards);
        debug_assert!(parities > 0, "erasure tables cover every shard count ≥ 1");

        let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(shards + parities);
        for wire in self.buf[chunk_level].drain(..) {
            let mut padded = wire;
            padded.resize(SHARD_SIZE, 0);
            matrix.push(padded);
        }
        matrix.extend(std::iter::repeat_with(|| vec![0u8; SHARD_SIZE]).take(parities));

        let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(shards, parities)
            .expect("shards ≥ 1 and shards + parities ≤ 128 by table construction");
        rs.encode(&mut matrix)
            .expect("shard geometry fixed at construction");

        for shard in matrix.drain(..).skip(shards) {
            let span: [u8; SPAN_SIZE] = shard[..SPAN_SIZE]
                .try_into()
                .expect("shard is SHARD_SIZE bytes");
            let addr = bmt_hash_with_span(&span, &shard[SPAN_SIZE..])
                .expect("shard payload is exactly CHUNK_SIZE");
            out.push(SplitChunk {
                address: addr,
                wire: shard,
            });
            self.write_ref(chunk_level + 1, true, RefEntry { span, addr }, out);
        }
    }

    /// Bee `wrapFullLevel`: turn the accumulator at `level` into an
    /// intermediate chunk (span = Σ data-child spans, level bit set
    /// when the node carries parities), reference it one level up, and
    /// buffer its wire for that level's erasure group.
    fn wrap_full_level(&mut self, level: usize, out: &mut Vec<SplitChunk>) {
        let entries = std::mem::take(&mut self.acc[level]);
        let eff = std::mem::take(&mut self.eff[level]);
        let parities = entries.len() - eff;

        // Bee sums the children's *raw* span words — the level bit in a
        // redundant child's top byte overflows harmlessly into bits the
        // parent's own level bit overwrites next.
        let mut sp: u64 = 0;
        for entry in &entries[..eff] {
            sp = sp.wrapping_add(u64::from_le_bytes(entry.span));
        }
        let mut span = sp.to_le_bytes();
        if parities > 0 {
            span[SPAN_SIZE - 1] = self.level | 0x80;
        }

        let mut payload = Vec::with_capacity(entries.len() * 32);
        for entry in &entries {
            payload.extend_from_slice(&entry.addr);
        }
        let addr = bmt_hash_with_span(&span, &payload)
            .expect("≤ 128 references fit an intermediate chunk");
        let mut wire = Vec::with_capacity(SPAN_SIZE + payload.len());
        wire.extend_from_slice(&span);
        wire.extend_from_slice(&payload);
        out.push(SplitChunk {
            address: addr,
            wire: wire.clone(),
        });

        self.write_ref(level + 1, false, RefEntry { span, addr }, out);
        self.chunk_write(level, wire, out);
        if level + 1 == TRIE_LEVELS - 1 {
            self.full = true;
        }
    }

    /// Drain partial levels into the root (bee hashtrie `Sum`).
    /// Returns `(root_address, root_wire, total_bytes, tail_chunks)`.
    /// An empty input produces the well-known empty leaf as root, like
    /// [`split_bytes`].
    #[must_use]
    pub fn finish(mut self) -> (ChunkAddr, Vec<u8>, u64, Vec<SplitChunk>) {
        let mut out = Vec::new();
        if self.leaves == 0 {
            out.extend(self.push_leaf(b""));
        }

        for level in 1..TRIE_LEVELS - 1 {
            match self.acc[level].len() {
                0 => {}
                1 => {
                    // Carry the lone subtree root one level up, moving
                    // its buffered chunk data along
                    // (`ElevateCarrierChunk`) so it joins the upper
                    // level's erasure group.
                    let entry = self.acc[level].pop().expect("len checked");
                    self.acc[level + 1].push(entry);
                    self.eff[level + 1] += 1;
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
                    // shard count, then wrap.
                    self.encode(level - 1, &mut out);
                    self.wrap_full_level(level, &mut out);
                }
            }
        }

        let top = &self.acc[TRIE_LEVELS - 1];
        assert_eq!(top.len(), 1, "trie must collapse to a single root");
        let root = top[0].addr;
        // The root's wire bytes were elevated all the way to the top
        // buffer level (bee `GetRootData`, minus bee's zero-padding).
        let root_wire = self.buf[TRIE_LEVELS - 2]
            .pop()
            .expect("root chunk data elevated to the top buffer level");
        debug_assert_eq!(
            bmt_hash_with_span(
                root_wire[..SPAN_SIZE].try_into().expect("root span"),
                &root_wire[SPAN_SIZE..],
            ),
            Some(root),
            "elevated root data must hash to the root reference",
        );
        (root, root_wire, self.bytes_consumed, out)
    }
}

/// The dispersed-replica SOC chunks of `root` at `level`, in bee's
/// dispersal order — what `pkg/replicas.NewPutter` uploads after a
/// redundant pipeline sums (each [`SplitChunk`]'s `address` is the SOC
/// address, its `wire` the SOC's `id ‖ sig ‖ root_wire` bytes; push
/// them as SOCs, not CACs).
///
/// The SOCs are signed with the well-known replicas key (`0x01` ‖ 31
/// zero bytes, bee `pkg/replicas/replicas.go`), so ant's replicas are
/// address- and signature-identical to bee's. One deliberate
/// difference: bee wraps the root data zero-padded to 4104 bytes (an
/// artifact of its erasure buffer); we wrap the exact wire bytes. The
/// BMT ignores payload padding, so addresses and signatures are
/// unaffected — only the replicas' trailing padding differs.
///
/// `root_wire` must be the exact chunk data of `root` (validated by
/// the SOC consumers, not here). Level 0 yields no replicas.
#[must_use]
pub fn replica_chunks(root: &ChunkAddr, root_wire: &[u8], level: u8) -> Vec<SplitChunk> {
    crate::rs::replica_identities(root, level)
        .into_iter()
        .map(|(id, soc_addr)| {
            let mut digest_input = [0u8; 64];
            digest_input[..32].copy_from_slice(&id);
            digest_input[32..].copy_from_slice(root);
            let digest = ant_crypto::keccak256(&digest_input);
            let sig = ant_crypto::sign_handshake_data(&crate::rs::REPLICAS_OWNER_SECRET, &digest)
                .expect("well-known replicas key is a valid secp256k1 scalar");
            let mut wire = Vec::with_capacity(32 + 65 + root_wire.len());
            wire.extend_from_slice(&id);
            wire.extend_from_slice(&sig);
            wire.extend_from_slice(root_wire);
            SplitChunk {
                address: soc_addr,
                wire,
            }
        })
        .collect()
}

/// Number of dispersed replicas uploaded for a root at `level`.
#[must_use]
pub fn replica_count(level: u8) -> usize {
    REPLICA_COUNTS[level.min(MAX_LEVEL) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::joiner::join;
    use crate::rs;
    use crate::ChunkFetcher;
    use ant_crypto::soc_valid;
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

    /// Joiner round-trip at every level for a spread of shapes: single
    /// leaf, partial group, exactly-full group, full group + carry,
    /// and a two-level tree.
    #[tokio::test]
    async fn redundant_split_round_trips_through_joiner() {
        for level in 1..=MAX_LEVEL {
            let shards = rs::max_shards(level);
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
                let result = split_bytes_with_redundancy(&payload, level);
                assert_eq!(result.total_bytes, len as u64, "level {level} len {len}");
                let fetcher = MapFetcher {
                    chunks: result
                        .chunks
                        .iter()
                        .map(|c| (c.address, c.wire.clone()))
                        .collect(),
                };
                assert_eq!(
                    fetcher.chunks.get(&result.root),
                    Some(&result.root_wire),
                    "root wire must be among the emitted chunks",
                );
                let back = join(&fetcher, &result.root_wire, 1 << 30)
                    .await
                    .unwrap_or_else(|e| panic!("level {level} len {len}: join failed: {e}"));
                assert_eq!(back, payload, "level {level} len {len}: payload mismatch");
            }
        }
    }

    /// Redundant trees survive losing `parityCnt` data children per
    /// node: split, delete data leaves, and let the joiner's RS decoder
    /// recover them — the encoder/decoder pair is self-consistent.
    #[tokio::test]
    async fn own_parities_recover_deleted_leaves() {
        let level = 2;
        let payload = det(CHUNK_SIZE * 10 + 5);
        let result = split_bytes_with_redundancy(&payload, level);
        // Root node: 11 data children, parities per the STRONG table.
        let parities = rs::get_parities(level, 11);
        assert!(parities > 0);
        let mut chunks: HashMap<[u8; 32], Vec<u8>> = result
            .chunks
            .iter()
            .map(|c| (c.address, c.wire.clone()))
            .collect();
        // Delete the first `parities` leaves (children of the root).
        for child in result.root_wire[SPAN_SIZE..].chunks(32).take(parities) {
            let addr: [u8; 32] = child.try_into().unwrap();
            assert!(chunks.remove(&addr).is_some());
        }
        let fetcher = MapFetcher { chunks };
        let back = join(&fetcher, &result.root_wire, 1 << 30).await.unwrap();
        assert_eq!(back, payload);
    }

    /// A single-leaf redundant file: no parities (nothing to protect),
    /// root == leaf, and replicas derive from the root.
    #[test]
    fn single_leaf_has_no_parities_only_replicas() {
        let payload = b"tiny redundant file";
        for level in 1..=MAX_LEVEL {
            let result = split_bytes_with_redundancy(payload, level);
            let baseline = split_bytes(payload);
            assert_eq!(result.root, baseline.root);
            assert_eq!(result.chunks.len(), 1, "a single leaf gains no parities");
            assert_eq!(result.root_wire, baseline.chunks[0].wire);

            let replicas = replica_chunks(&result.root, &result.root_wire, level);
            assert_eq!(replicas.len(), REPLICA_COUNTS[level as usize]);
            let derived = rs::replica_addresses(&result.root, level);
            for (chunk, addr) in replicas.iter().zip(derived) {
                assert_eq!(chunk.address, addr);
                assert!(
                    soc_valid(&chunk.address, &chunk.wire),
                    "replica SOC must self-validate",
                );
                assert_eq!(&chunk.wire[32 + 65..], result.root_wire.as_slice());
            }
        }
    }

    /// Level 0 delegates to `split_bytes` byte-for-byte.
    #[test]
    fn level_zero_matches_split_bytes() {
        let payload = det(CHUNK_SIZE * 5 + 3);
        let redundant = split_bytes_with_redundancy(&payload, 0);
        let baseline = split_bytes(&payload);
        assert_eq!(redundant.root, baseline.root);
        assert_eq!(redundant.chunks.len(), baseline.chunks.len());
        for (a, b) in redundant.chunks.iter().zip(&baseline.chunks) {
            assert_eq!(a.address, b.address);
            assert_eq!(a.wire, b.wire);
        }
        assert!(replica_chunks(&redundant.root, &redundant.root_wire, 0).is_empty());
    }

    /// Intermediate nodes carry the level bit exactly when they hold
    /// parities, and their geometry matches `reference_count` (what the
    /// joiner will derive on the way back).
    #[test]
    fn root_span_and_geometry_match_decoder_expectations() {
        let level = 1;
        let len = 150 * 1024;
        let result = split_bytes_with_redundancy(&det(len), level);
        let span: [u8; SPAN_SIZE] = result.root_wire[..SPAN_SIZE].try_into().unwrap();
        assert!(rs::is_level_encoded(&span));
        let (l, plain) = rs::decode_span(span);
        assert_eq!(l, level);
        assert_eq!(u64::from_le_bytes(plain), len as u64);
        let (shards, parities) = rs::reference_count(len as u64, level);
        assert_eq!(result.root_wire.len(), SPAN_SIZE + (shards + parities) * 32,);
    }
}
