//! File splitter: bytes → balanced k-ary chunk tree.
//!
//! The inverse of [`crate::joiner`]. Given a byte slice, produces every
//! content-addressed chunk needed to represent the file on Swarm: leaf
//! chunks (4 KiB of payload each) and intermediate "join" chunks (lists
//! of up to 128 child references) all the way up to a single root.
//!
//! Wire shape matches `bee/pkg/file/splitter`:
//!
//! - **Leaf chunk** = `span (8 LE) || payload (≤ 4096)`. Span equals the
//!   payload length, so a leaf is identical to whatever
//!   [`ant_crypto::cac_new`] would produce.
//! - **Intermediate chunk** = `span (8 LE) || refs`, where `refs` is the
//!   concatenation of N ∈ [2, 128] child addresses (32 bytes each) and
//!   `span` is the *total file-data bytes covered by the entire subtree*
//!   rooted at this chunk — not the chunk's own payload length.
//!
//! The tree is left-leaning: leaves are filled to 4 KiB before starting a
//! new one; intermediates at level k are filled to 128 children before a
//! new sibling is opened. This matches what bee's splitter emits and is
//! also exactly what [`crate::joiner::join`] expects on the way back.
//!
//! Returned vectors are in *push order*: data leaves first, then each
//! level of intermediates bottom-up, with the root last. Callers that
//! upload via pushsync can simply iterate; callers that need the root
//! address explicitly read [`SplitResult::root`].

use ant_crypto::{bmt_hash_with_span, cac_new, CHUNK_SIZE, SPAN_SIZE};

use crate::ChunkAddr;

/// Maximum number of child references packed into one intermediate chunk.
/// Equal to bee's `swarm.Branches` (4096 / 32).
pub const BRANCHES: usize = CHUNK_SIZE / 32;

/// One chunk produced by the splitter, ready to push: address + wire bytes
/// (`span (8 LE) || payload`).
#[derive(Debug, Clone)]
pub struct SplitChunk {
    pub address: ChunkAddr,
    pub wire: Vec<u8>,
}

/// Result of splitting a byte buffer.
#[derive(Debug, Clone)]
pub struct SplitResult {
    /// Address of the file's root chunk. Hand this to a joiner / mantaray
    /// "entry" field to fetch the file back.
    pub root: ChunkAddr,
    /// Total file bytes (matches the root chunk's span).
    pub total_bytes: u64,
    /// Every chunk needed to reconstruct the file. The last entry is the
    /// root; data leaves come first, intermediate levels next.
    pub chunks: Vec<SplitChunk>,
}

/// Split `payload` into a balanced chunk tree.
///
/// Empty input is treated as a single 0-byte leaf — the same chunk a
/// `cac_new(b"")` produces. The resulting `root` is the well-known
/// empty-content reference and the file has zero bytes.
///
/// This is the plain (`swarm-redundancy-level: 0`) splitter. For
/// erasure-coded trees use
/// [`crate::rs_encode::split_bytes_with_redundancy`], which produces
/// bee's exact redundant pipeline output (parity chunks, level-encoded
/// spans, `max_shards(level)` branching).
///
/// # Panics
///
/// Never; all chunk constructions stay within [`CHUNK_SIZE`] by
/// construction. The internal `cac_new` / `bmt_hash_with_span` callers
/// `unwrap()` only after enforcing payload length ≤ `CHUNK_SIZE`.
#[must_use]
pub fn split_bytes(payload: &[u8]) -> SplitResult {
    if payload.len() <= CHUNK_SIZE {
        let (root, wire) = cac_new(payload).expect("payload length already ≤ CHUNK_SIZE");
        return SplitResult {
            root,
            total_bytes: payload.len() as u64,
            chunks: vec![SplitChunk {
                address: root,
                wire,
            }],
        };
    }

    let mut chunks: Vec<SplitChunk> = Vec::new();

    // Level 0: data leaves. Each carries up to CHUNK_SIZE bytes and its
    // span equals its own payload length.
    let mut level: Vec<(ChunkAddr, u64)> = payload
        .chunks(CHUNK_SIZE)
        .map(|leaf| {
            let (addr, wire) = cac_new(leaf).expect("leaf ≤ CHUNK_SIZE by construction");
            chunks.push(SplitChunk {
                address: addr,
                wire,
            });
            (addr, leaf.len() as u64)
        })
        .collect();

    // Levels 1..R: pack the previous level into intermediate chunks of up
    // to BRANCHES children each. Repeat until the level collapses to one
    // chunk — that's the root.
    while level.len() > 1 {
        let mut next: Vec<(ChunkAddr, u64)> = Vec::with_capacity(level.len().div_ceil(BRANCHES));
        for group in level.chunks(BRANCHES) {
            // A lone trailing reference is carried up unchanged, never
            // wrapped in a 1-child intermediate: bee's hashtrie `Sum`
            // does the same, and a wrapper whose span fits one leaf
            // would read back as that leaf (issue #234).
            if let [only] = group {
                next.push(*only);
                continue;
            }
            let mut intermediate_payload = Vec::with_capacity(group.len() * 32);
            let mut subtree_span: u64 = 0;
            for (child_addr, child_span) in group {
                intermediate_payload.extend_from_slice(child_addr);
                subtree_span += child_span;
            }
            let span_le = subtree_span.to_le_bytes();
            let addr = bmt_hash_with_span(&span_le, &intermediate_payload)
                .expect("intermediate payload ≤ CHUNK_SIZE (BRANCHES * 32)");
            let mut wire = Vec::with_capacity(SPAN_SIZE + intermediate_payload.len());
            wire.extend_from_slice(&span_le);
            wire.extend_from_slice(&intermediate_payload);
            chunks.push(SplitChunk {
                address: addr,
                wire,
            });
            next.push((addr, subtree_span));
        }
        level = next;
    }

    let (root, total_bytes) = level[0];
    SplitResult {
        root,
        total_bytes,
        chunks,
    }
}

/// Streaming counterpart of [`split_bytes`]: feed leaves one at a time
/// and pull the resulting [`SplitChunk`]s as they're produced, never
/// materialising the whole file (or the whole chunk list) in RAM.
///
/// Level-0 only; the redundancy-aware streaming counterpart with the
/// same push-leaves-then-finish contract is
/// [`crate::rs_encode::RedundantSplitter`].
///
/// The output is byte-identical to what [`split_bytes`] would have
/// produced for the same total payload, including the well-known
/// edge cases (empty input → single zero-byte leaf; ≤ `CHUNK_SIZE`
/// input → root == leaf, no intermediate). This is the property the
/// upload manager relies on when it re-streams a file from byte 0
/// during resume: every chunk address is a deterministic function of
/// position, so we can skip pushsync for chunks already accepted by
/// the network without storing per-chunk receipts.
///
/// # Memory profile
///
/// Bounded above by `tree_depth × BRANCHES × 32 B`. For a 7 GiB file
/// (~1.7 M leaves, depth 4) that's `4 × 128 × 32 = 16 KiB` of rolling
/// child references plus the in-flight leaf payload — independent of
/// file size.
///
/// # API contract
///
/// 1. Call [`StreamingSplitter::push_leaf`] with leaves in order. Every
///    leaf except possibly the last must be exactly `CHUNK_SIZE` bytes;
///    the final leaf may be shorter (including zero, which is what
///    [`split_bytes`] produces for `payload.len() == 0`).
/// 2. Each call returns the freshly-produced chunks: always the leaf
///    itself, plus any intermediates that bubbled to fullness during
///    that call.
/// 3. Call [`StreamingSplitter::finish`] exactly once at the end. It
///    drains partial intermediate levels into the final root chunk
///    and returns `(root_addr, total_bytes, tail_chunks)`.
///
/// Calls after [`finish`](StreamingSplitter::finish) panic.
#[derive(Debug)]
pub struct StreamingSplitter {
    /// `levels[L]` accumulates child `(addr, span)` pairs for the
    /// not-yet-flushed intermediate at depth `L`. `levels[0]` only
    /// holds the *most recent* leaf so [`finish`](Self::finish) can
    /// recognise the "single leaf, no intermediate" root case.
    levels: Vec<Vec<(ChunkAddr, u64)>>,
    /// Cumulative bytes fed via [`push_leaf`]; equals the file body
    /// size once [`finish`](Self::finish) is called.
    bytes_consumed: u64,
    /// Cumulative leaves fed via [`push_leaf`]. Used by `finish` to
    /// distinguish "empty file" (must emit the empty leaf to match
    /// [`split_bytes`]) from "non-empty file with at least one leaf".
    leaves_emitted: u64,
}

impl Default for StreamingSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingSplitter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            levels: Vec::new(),
            bytes_consumed: 0,
            leaves_emitted: 0,
        }
    }

    /// Bytes fed in so far. Useful for progress accounting.
    #[must_use]
    pub const fn bytes_consumed(&self) -> u64 {
        self.bytes_consumed
    }

    /// Number of leaves fed in so far (== chunk index of the next
    /// leaf to be pushed).
    #[must_use]
    pub const fn leaves_emitted(&self) -> u64 {
        self.leaves_emitted
    }

    /// Feed one leaf payload. Length must be ≤ `CHUNK_SIZE`; only the
    /// last leaf may be shorter than `CHUNK_SIZE`. Returns the chunks
    /// produced by this call: the leaf itself, plus any intermediates
    /// that filled and were flushed in the bubble-up.
    pub fn push_leaf(&mut self, payload: &[u8]) -> Vec<SplitChunk> {
        assert!(
            payload.len() <= CHUNK_SIZE,
            "leaf payload {} > CHUNK_SIZE {CHUNK_SIZE}",
            payload.len(),
        );
        let (addr, wire) = cac_new(payload).expect("leaf ≤ CHUNK_SIZE by construction");
        self.bytes_consumed += payload.len() as u64;
        self.leaves_emitted += 1;
        let mut emitted = vec![SplitChunk {
            address: addr,
            wire,
        }];
        self.bubble_up(0, addr, payload.len() as u64, &mut emitted);
        emitted
    }

    /// Bubble a fresh `(addr, span)` into level `level`. If that level
    /// fills, flush it into a fresh intermediate chunk, append it to
    /// `emitted`, and recurse into `level + 1`.
    fn bubble_up(
        &mut self,
        level: usize,
        child_addr: ChunkAddr,
        child_span: u64,
        emitted: &mut Vec<SplitChunk>,
    ) {
        if self.levels.len() <= level {
            self.levels.push(Vec::with_capacity(BRANCHES));
        }
        // Level 0 is special: it holds *only* the last leaf, so
        // `finish` can detect "the single leaf is the root". Higher
        // levels accumulate up to BRANCHES children before flushing.
        if level == 0 {
            let buf = &mut self.levels[0];
            buf.clear();
            buf.push((child_addr, child_span));
            // We don't bubble up from level 0 on every leaf — that's
            // what level 1's accumulator does. Bubble the leaf into
            // level 1 directly.
            self.bubble_up(1, child_addr, child_span, emitted);
            return;
        }
        self.levels[level].push((child_addr, child_span));
        if self.levels[level].len() == BRANCHES {
            let (addr, span, chunk) = flush_level(&mut self.levels[level]);
            emitted.push(chunk);
            self.bubble_up(level + 1, addr, span, emitted);
        }
    }

    /// Drain partial intermediate levels into the file root. A partial
    /// level holding a single reference is carried up as it is, not
    /// wrapped (bee hashtrie `Sum`). Returns
    /// `(root_addr, total_bytes, tail_chunks)` where `tail_chunks` is
    /// any intermediates produced by the drain (the root is the last
    /// entry, except in the single-leaf case where the leaf was
    /// already returned by [`push_leaf`] and `tail_chunks` is empty).
    ///
    /// For an empty input (no [`push_leaf`] calls), emits the
    /// well-known zero-byte leaf and returns it as the root, matching
    /// [`split_bytes(b"")`].
    #[must_use]
    pub fn finish(mut self) -> (ChunkAddr, u64, Vec<SplitChunk>) {
        // Empty input: emit the zero-byte leaf as both leaf and root,
        // matching `split_bytes(b"")`.
        if self.leaves_emitted == 0 {
            let (addr, wire) = cac_new(b"").expect("empty leaf");
            return (
                addr,
                0,
                vec![SplitChunk {
                    address: addr,
                    wire,
                }],
            );
        }

        // Single-leaf file (≤ CHUNK_SIZE): the leaf is the root and
        // was already returned by `push_leaf`. No intermediate exists
        // — `levels[1]` was created with one entry but never reached
        // BRANCHES, and we must NOT wrap a 1-child intermediate
        // around it. This matches the `split_bytes` fast path.
        if self.leaves_emitted == 1 {
            let (root_addr, root_span) = self.levels[0][0];
            return (root_addr, root_span, Vec::new());
        }

        // General case: flush partial levels bottom-up. Skip level 0
        // (it only ever held the last leaf, which is already in level
        // 1).
        let mut emitted = Vec::new();
        let mut level = 1;
        loop {
            // Grow `levels` lazily so the `level + 1 == levels.len()`
            // invariant below is meaningful.
            if self.levels.len() <= level {
                self.levels.push(Vec::new());
            }
            let n = self.levels[level].len();
            // Reached a level that has exactly the root — done.
            if level + 1 >= self.levels.len() && n == 1 {
                let (root_addr, root_span) = self.levels[level][0];
                return (root_addr, root_span, emitted);
            }
            // Empty level (everything already bubbled up at fullness):
            // climb one rung.
            if n == 0 {
                level += 1;
                continue;
            }
            // A lone reference is carried up unchanged rather than
            // wrapped in a 1-child intermediate, like bee's hashtrie
            // `Sum` (and `RedundantSplitter::finish`). A wrapper would
            // give a non-bee reference, and one whose span fits a
            // single leaf reads back as that leaf, so the file's tail
            // comes back wrong (issue #234).
            let entry = if n == 1 {
                self.levels[level].pop().expect("len checked")
            } else {
                let (addr, span, chunk) = flush_level(&mut self.levels[level]);
                emitted.push(chunk);
                (addr, span)
            };
            // Bubble into the next level up; create one if necessary.
            if self.levels.len() <= level + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[level + 1].push(entry);
            level += 1;
        }
    }
}

/// Flush a level's accumulator into one intermediate chunk. Drains
/// `buf` in place. Caller is responsible for not calling this on an
/// empty buffer.
fn flush_level(buf: &mut Vec<(ChunkAddr, u64)>) -> (ChunkAddr, u64, SplitChunk) {
    debug_assert!(!buf.is_empty(), "flush_level on empty accumulator");
    let mut payload = Vec::with_capacity(buf.len() * 32);
    let mut span: u64 = 0;
    for (addr, child_span) in buf.iter() {
        payload.extend_from_slice(addr);
        span += *child_span;
    }
    let span_le = span.to_le_bytes();
    let addr =
        bmt_hash_with_span(&span_le, &payload).expect("intermediate payload ≤ BRANCHES * 32");
    let mut wire = Vec::with_capacity(SPAN_SIZE + payload.len());
    wire.extend_from_slice(&span_le);
    wire.extend_from_slice(&payload);
    buf.clear();
    (
        addr,
        span,
        SplitChunk {
            address: addr,
            wire,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::joiner::{join, JoinError};
    use crate::ChunkFetcher;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::error::Error;

    /// HashMap-backed fetcher so we can round-trip splitter output through
    /// the existing joiner in unit tests, byte-for-byte.
    struct MapFetcher {
        chunks: HashMap<[u8; 32], Vec<u8>>,
    }

    impl MapFetcher {
        fn from_split(result: &SplitResult) -> Self {
            let mut m = HashMap::new();
            for c in &result.chunks {
                m.insert(c.address, c.wire.clone());
            }
            Self { chunks: m }
        }
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

    async fn round_trip(payload: &[u8]) -> Result<Vec<u8>, JoinError> {
        let result = split_bytes(payload);
        let fetcher = MapFetcher::from_split(&result);
        let root_chunk = fetcher.chunks.get(&result.root).expect("root in fetcher");
        join(&fetcher, root_chunk, 64 * 1024 * 1024).await
    }

    /// Tiny payload (< `CHUNK_SIZE)`: one leaf, root == leaf.
    #[tokio::test]
    async fn single_leaf_round_trip() {
        let payload = b"hello swarm".to_vec();
        let result = split_bytes(&payload);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.total_bytes, payload.len() as u64);
        assert_eq!(result.root, result.chunks[0].address);
        let back = round_trip(&payload).await.unwrap();
        assert_eq!(back, payload);
    }

    /// Empty input: still produces one valid leaf — bee accepts zero-byte
    /// files and `cac_new(b"")` is a defined chunk.
    #[tokio::test]
    async fn empty_round_trip() {
        let result = split_bytes(b"");
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.total_bytes, 0);
        let back = round_trip(b"").await.unwrap();
        assert_eq!(back, [] as [u8; 0]);
    }

    /// 5 KiB → root has 2 leaf children, first 4 KiB and second 1 KiB.
    /// This is the simplest case where intermediate-vs-leaf logic kicks in.
    #[tokio::test]
    async fn two_leaf_root_round_trip() {
        let payload: Vec<u8> = (0..5120).map(|i| (i % 251) as u8).collect();
        let result = split_bytes(&payload);
        assert_eq!(result.total_bytes, 5120);
        // 2 leaves + 1 intermediate root
        assert_eq!(result.chunks.len(), 3);
        let back = round_trip(&payload).await.unwrap();
        assert_eq!(back, payload);
    }

    /// 4 KiB exactly: still one leaf (boundary).
    #[tokio::test]
    async fn exact_chunk_boundary() {
        let payload: Vec<u8> = (0..CHUNK_SIZE as u32).map(|i| (i % 251) as u8).collect();
        let result = split_bytes(&payload);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.total_bytes, CHUNK_SIZE as u64);
        let back = round_trip(&payload).await.unwrap();
        assert_eq!(back, payload);
    }

    /// Multi-MiB payload triggers two-level fan-out (256 leaves → 2
    /// intermediates → 1 root). Verifies the iterative level builder
    /// closes out properly when the deepest level isn't full.
    #[tokio::test]
    async fn multi_level_fanout_round_trip() {
        let len = 1_000_000usize;
        let payload: Vec<u8> = (0..len).map(|i| ((i * 31) % 251) as u8).collect();
        let result = split_bytes(&payload);
        assert_eq!(result.total_bytes, len as u64);
        // 245 leaves (ceil(1_000_000 / 4096)) + 2 intermediates (groups of
        // 128 + 117 leaves) + 1 root = 248 chunks.
        let leaves = len.div_ceil(CHUNK_SIZE);
        let level1 = leaves.div_ceil(BRANCHES);
        let expected = leaves + level1 + 1;
        assert_eq!(result.chunks.len(), expected);
        let back = round_trip(&payload).await.unwrap();
        assert_eq!(back, payload);
    }

    /// Run the same payload through both [`split_bytes`] and the
    /// streaming splitter and assert the two outputs are equivalent:
    /// same root, same total bytes, same set of `(address, wire)`
    /// pairs (the *order* differs — streaming emits intermediates
    /// as soon as they fill, while `split_bytes` writes all leaves
    /// first then all intermediates).
    ///
    /// Also runs the streaming output through the joiner to confirm
    /// it reconstructs the original payload byte-for-byte; this is
    /// the same correctness check the rest of the test module uses
    /// for `split_bytes`.
    fn assert_streaming_matches(payload: &[u8]) {
        let baseline = split_bytes(payload);

        let mut s = StreamingSplitter::new();
        let mut produced: Vec<SplitChunk> = Vec::new();
        if payload.is_empty() {
            // Match the `split_bytes(b"")` shape: no `push_leaf`
            // calls, `finish` emits the empty leaf.
        } else {
            for leaf in payload.chunks(CHUNK_SIZE) {
                produced.extend(s.push_leaf(leaf));
            }
        }
        let (root, total_bytes, tail) = s.finish();
        produced.extend(tail);

        assert_eq!(root, baseline.root, "root mismatch");
        assert_eq!(total_bytes, baseline.total_bytes, "total_bytes mismatch");
        assert_eq!(
            produced.len(),
            baseline.chunks.len(),
            "chunk count mismatch",
        );

        // Compare as sorted-by-address lists so emit-order
        // differences don't trigger false positives.
        let mut a: Vec<&SplitChunk> = produced.iter().collect();
        let mut b: Vec<&SplitChunk> = baseline.chunks.iter().collect();
        a.sort_by_key(|c| c.address);
        b.sort_by_key(|c| c.address);
        for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(x.address, y.address, "sorted entry {i} address mismatch");
            assert_eq!(x.wire, y.wire, "sorted entry {i} wire mismatch");
        }

        // Round-trip through the joiner using a HashMap fetcher
        // built from the streaming output.
        let mut map = HashMap::new();
        for c in &produced {
            map.insert(c.address, c.wire.clone());
        }
        let fetcher = MapFetcher { chunks: map };
        let root_chunk = fetcher.chunks.get(&root).expect("root chunk in fetcher");
        let rt = futures::executor::block_on(join(&fetcher, root_chunk, 256 * 1024 * 1024))
            .expect("streaming output joined back without error");
        assert_eq!(rt, payload, "streaming output round-tripped to wrong bytes");
    }

    #[test]
    fn streaming_matches_split_bytes_empty() {
        assert_streaming_matches(b"");
    }

    #[test]
    fn streaming_matches_split_bytes_short() {
        assert_streaming_matches(b"hello swarm");
    }

    #[test]
    fn streaming_matches_split_bytes_exact_chunk() {
        let p: Vec<u8> = (0..CHUNK_SIZE as u32).map(|i| (i % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    #[test]
    fn streaming_matches_split_bytes_two_leaves() {
        let p: Vec<u8> = (0..5120).map(|i| (i % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    #[test]
    fn streaming_matches_split_bytes_full_first_intermediate() {
        let len = CHUNK_SIZE * BRANCHES;
        let p: Vec<u8> = (0..len).map(|i| ((i * 7) % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    #[test]
    fn streaming_matches_split_bytes_partial_intermediate() {
        let len = 1_000_000usize;
        let p: Vec<u8> = (0..len).map(|i| ((i * 31) % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    /// Two-level fan-out with the top level partially full: the
    /// second L1 intermediate carries fewer than `BRANCHES`
    /// children, and the L2 root has exactly two children. Catches
    /// off-by-one drain errors in `finish`. Kept small (BRANCHES + 5
    /// leaves ≈ 532 KiB) so the unit test runs in well under a second
    /// even in debug mode.
    #[test]
    fn streaming_matches_split_bytes_two_levels_partial() {
        let len = CHUNK_SIZE * (BRANCHES + 5);
        let p: Vec<u8> = (0..len).map(|i| ((i * 17) % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    /// Three-level fan-out: BRANCHES * BRANCHES + 5 leaves so the L3
    /// root has exactly 2 children: the first, full L2 chunk, and the
    /// lone L1 chunk over the last 5 leaves, carried up unwrapped
    /// (bee's hashtrie `Sum`, #234). Exercises the recursive bubble-up
    /// across three intermediate levels and matches the shape of a
    /// multi-GiB upload at small scale.
    ///
    /// `#[ignore]` only because this synthesises ~64 MiB of payload
    /// and BMT-hashes it through both the reference and the
    /// streaming splitter — ~110 s in debug, well under a second in
    /// release. Run on demand with `cargo test --release -p
    /// ant-retrieval -- --include-ignored streaming_matches_split_bytes_three_levels`.
    #[test]
    #[ignore = "slow in debug; run with --release --include-ignored"]
    fn streaming_matches_split_bytes_three_levels() {
        let len = CHUNK_SIZE * (BRANCHES * BRANCHES + 5);
        let p: Vec<u8> = (0..len).map(|i| ((i * 23) % 251) as u8).collect();
        assert_streaming_matches(&p);
    }

    /// Content of the cross-implementation file vectors (swarmfs, issue
    /// #62): with `k = i / 4096`, byte `i` is
    /// `((i * 7 + k) % 251) ^ ((k / 251) & 0xff)`.
    fn pattern(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| {
                let k = i / 4096;
                (((i * 7 + k) % 251) ^ ((k / 251) & 0xff)) as u8
            })
            .collect()
    }

    /// Both splitters give `want_root` for `pattern(size)`, and the
    /// tree joins back to the exact bytes (via
    /// [`assert_streaming_matches`]).
    fn assert_pattern_root(size: usize, want_root: &str) {
        let payload = pattern(size);
        assert_eq!(
            hex::encode(split_bytes(&payload).root),
            want_root,
            "split_bytes root for {size} bytes",
        );
        assert_streaming_matches(&payload);
    }

    /// Issue #234: 129 leaves, the last one 1 byte. Level 1 ends with a
    /// lone leaf, which bee's hashtrie `Sum` carries up unwrapped: the
    /// root holds two references, the level-1 chunk over the first 128
    /// leaves and the 1-byte leaf itself. Ant used to wrap that leaf in
    /// a 1-ref intermediate of span 1, which a joiner reads as the leaf,
    /// so the file's last byte came back as the first byte of the leaf's
    /// address. Root is bee's (and swarmfs's) for this content.
    #[test]
    fn lone_trailing_leaf_is_carried_up_like_bee() {
        let size = CHUNK_SIZE * BRANCHES + 1;
        assert_pattern_root(
            size,
            "95cefbc8d063b2ba7ffaa05cf0fb07fdb2df148acb12fc0ea50e3a825035eb03",
        );

        let payload = pattern(size);
        let result = split_bytes(&payload);
        let root = result
            .chunks
            .iter()
            .find(|c| c.address == result.root)
            .expect("root chunk emitted");
        let last_leaf = cac_new(&payload[CHUNK_SIZE * BRANCHES..]).unwrap().0;
        assert_eq!(root.wire.len(), SPAN_SIZE + 2 * 32, "root has two refs");
        assert_eq!(
            &root.wire[SPAN_SIZE + 32..],
            &last_leaf,
            "second ref is the leaf"
        );
        // 129 leaves + the level-1 chunk + the root; no wrapper.
        assert_eq!(result.chunks.len(), BRANCHES + 1 + 2);
    }

    /// Every last-leaf size up to the reference size (32 bytes), where a
    /// wrapper read as a leaf corrupted the tail, round-trips exactly.
    #[test]
    fn short_lone_trailing_leaf_round_trips() {
        for tail in [1usize, 2, 31, 32, 33] {
            assert_streaming_matches(&pattern(CHUNK_SIZE * BRANCHES + tail));
        }
    }

    /// Issue #234, one level up: 16,386 leaves leave a lone level-1
    /// chunk at the end of level 2, carried up to the root unwrapped.
    /// Root is bee's (and swarmfs's). `#[ignore]` for the same reason
    /// as `streaming_matches_split_bytes_three_levels` (64 MiB); run
    /// with `cargo test --release -p ant-retrieval -- --include-ignored
    /// lone_trailing_intermediate`.
    #[test]
    #[ignore = "slow in debug; run with --release --include-ignored"]
    fn lone_trailing_intermediate_is_carried_up_like_bee() {
        assert_pattern_root(
            67_112_961,
            "3b62c8ee52bd5eebf3136917e0ef5be7b7c3d33522720235b74214b8c92da6fc",
        );
    }

    /// Sizes with no lone reference at any level are unchanged by the
    /// #234 fix (roots as before it; 4,097 and 8,193 are also
    /// swarmfs's).
    #[test]
    fn trees_without_a_lone_reference_are_unchanged() {
        for (size, root) in [
            (
                4_097,
                "137cdd31a6f36bc5d2d1cd404cae073ffb02ba2b807f7e5bd76870abc77ced93",
            ),
            (
                8_193,
                "c35513aae4ed2df7794e79367f70a6530a3c9dcb9dcbf053d9e5c0e30de34a5a",
            ),
            (
                528_385,
                "04518821b08b169754b62bd34d438e63b06e7a25fa365209e8c48c1c157b4e20",
            ),
        ] {
            assert_pattern_root(size, root);
        }
    }

    /// Boundary that bee's splitter explicitly tests: 524288 bytes (128
    /// full leaves). Should produce 128 leaves + 1 root, no second level.
    #[tokio::test]
    async fn full_first_intermediate() {
        let len = CHUNK_SIZE * BRANCHES; // 4096 * 128 = 524288
        let payload: Vec<u8> = (0..len).map(|i| ((i * 7) % 251) as u8).collect();
        let result = split_bytes(&payload);
        assert_eq!(result.chunks.len(), BRANCHES + 1);
        assert_eq!(result.total_bytes, len as u64);
        let back = round_trip(&payload).await.unwrap();
        assert_eq!(back, payload);
    }
}
