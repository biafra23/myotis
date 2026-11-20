//! Content-tree traversal — parity with bee `pkg/traversal`.
//!
//! Given a root reference, [`traverse_chunk_addresses`] yields the
//! address of **every** chunk making up the content rooted there:
//!
//! * a valid SOC root is just the single chunk (bee: `soc.Valid` ⇒
//!   `iterFn(addr)` and stop);
//! * a single-chunk root that parses as a mantaray manifest is walked
//!   fork by fork: each manifest node's own chunk tree is enumerated
//!   and every value entry's file tree is enumerated in turn (bee:
//!   `manifest.IterateAddresses` with `processBytes` on node references
//!   *and* entries). Feed manifests are **not** dereferenced — like
//!   bee, the traversal covers the manifest's own metadata nodes, not
//!   whatever content the feed currently points at;
//! * anything else is a plain data span tree: the root, every interior
//!   node, and every leaf (bee: `joiner.IterateChunkAddresses`).
//!
//! Interior/manifest nodes are fetched through the supplied
//! [`ChunkFetcher`] (they must be readable to learn their children);
//! data leaves are *listed but not fetched* — callers that need to
//! prove leaf retrievability (stewardship `isRetrievable`) or re-push
//! leaves (stewardship re-upload) fetch each returned address
//! themselves. Addresses are deduplicated, in discovery order.

use std::collections::HashSet;

use thiserror::Error;

use crate::joiner::{enumerate_chunk_tree, subtrie_section, JoinError, JoinOptions};
use crate::mantaray::{ManifestError, Node};
use crate::{join_with_options, ChunkFetcher, ENC_REF_SIZE};
use ant_crypto::{soc_valid, CHUNK_SIZE, SPAN_SIZE};

#[derive(Debug, Error)]
pub enum TraversalError {
    #[error("traversal: {0}")]
    Join(#[from] JoinError),
    #[error("traversal: manifest walk: {0}")]
    Manifest(#[from] ManifestError),
    #[error("traversal: fetch {addr}: {source}")]
    Fetch {
        addr: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Enumerate every chunk address of the content tree rooted at `root`.
/// `max_bytes` bounds each joined file span the same way the joiner's
/// byte cap does (pass a generous ceiling; bee's traversal is uncapped).
pub async fn traverse_chunk_addresses(
    fetcher: &dyn ChunkFetcher,
    root: [u8; 32],
    max_bytes: usize,
) -> Result<Vec<[u8; 32]>, TraversalError> {
    // Traversal (pin, stewardship) never waits for peer credit (#117).
    let fetcher = &crate::NoCreditWait(fetcher);
    let root_wire = fetcher
        .fetch(root)
        .await
        .map_err(|source| TraversalError::Fetch {
            addr: hex::encode(root),
            source,
        })?;

    // A single-owner chunk has no tree below it (its wrapped CAC is
    // carried inline); bee stops at the SOC address itself.
    if soc_valid(&root, &root_wire) {
        return Ok(vec![root]);
    }

    let mut out = Vec::new();
    let mut emitted = HashSet::new();

    // Manifest heuristic, mirroring bee: only a root whose span fits a
    // single chunk can be a mantaray root node worth probing. Mask the
    // redundancy level off the span's high byte like the joiner does.
    let span = masked_span(&root_wire)?;
    if span <= CHUNK_SIZE as u64 && root_wire.len() >= SPAN_SIZE {
        match Node::unmarshal(&root_wire[SPAN_SIZE..]) {
            Ok(_) => {
                traverse_manifest(fetcher, root, max_bytes, &mut out, &mut emitted).await?;
                return Ok(out);
            }
            // Same fallbacks bee's traversal takes: a version-hash
            // mismatch or too-short blob concludes "not a manifest" and
            // retries plain span-tree processing. Anything else (e.g.
            // an encrypted manifest we can't walk) is a real failure.
            Err(ManifestError::NotAManifest | ManifestError::TooShort(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }

    push_tree(fetcher, root, &root_wire, max_bytes, &mut out, &mut emitted).await?;
    Ok(out)
}

/// Little-endian span with the top (redundancy-level) byte always
/// zeroed. Looser than the joiner's `rs::decode_span`, which clears that
/// byte only when it carries a level (> 128): a top byte of 1..=128 is
/// rejected by the joiner as too large but read here as a smaller span.
fn masked_span(wire: &[u8]) -> Result<u64, TraversalError> {
    let mut span: [u8; SPAN_SIZE] = wire
        .get(..SPAN_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or(JoinError::MalformedChunk {
            offset: 0,
            detail: format!("root shorter than span: {} bytes", wire.len()),
        })?;
    span[7] = 0;
    Ok(u64::from_le_bytes(span))
}

/// Enumerate the span tree rooted at `(addr, wire)` into `out`,
/// deduplicating against `emitted`. Interior nodes are fetched; leaves
/// are listed only.
async fn push_tree(
    fetcher: &dyn ChunkFetcher,
    addr: [u8; 32],
    wire: &[u8],
    max_bytes: usize,
    out: &mut Vec<[u8; 32]>,
    emitted: &mut HashSet<[u8; 32]>,
) -> Result<(), TraversalError> {
    let opts = JoinOptions {
        allow_degraded_redundancy: true,
    };
    let inv = enumerate_chunk_tree(fetcher, addr, wire, max_bytes, opts).await?;
    for a in inv.intermediates.into_iter().chain(inv.leaves) {
        if emitted.insert(a) {
            out.push(a);
        }
    }
    Ok(())
}

/// Walk a mantaray trie rooted at the manifest node `root`, emitting
/// every manifest node's own chunk tree and every value entry's file
/// tree, without dereferencing feed metadata. Iterative with a visited
/// set so a (malformed) cyclic manifest can't loop forever.
async fn traverse_manifest(
    fetcher: &dyn ChunkFetcher,
    root: [u8; 32],
    max_bytes: usize,
    out: &mut Vec<[u8; 32]>,
    emitted: &mut HashSet<[u8; 32]>,
) -> Result<(), TraversalError> {
    let opts = JoinOptions {
        allow_degraded_redundancy: true,
    };
    let mut visited = HashSet::new();
    let mut stack = vec![root];
    while let Some(node_ref) = stack.pop() {
        if !visited.insert(node_ref) {
            continue;
        }
        let node_wire = fetcher
            .fetch(node_ref)
            .await
            .map_err(|source| TraversalError::Fetch {
                addr: hex::encode(node_ref),
                source,
            })?;
        // The manifest node is itself a swarm file (usually one chunk);
        // its own chunk tree is part of the content.
        push_tree(fetcher, node_ref, &node_wire, max_bytes, out, emitted).await?;
        let node_bytes = join_with_options(fetcher, &node_wire, max_bytes, opts).await?;
        let node = Node::unmarshal(&node_bytes)?;

        // Value entry: the file data reference (bee skips the all-zero
        // sentinel used by metadata-only nodes, e.g. feed manifests).
        if node.entry.len() == 32 && node.entry.iter().any(|&b| b != 0) {
            let mut entry = [0u8; 32];
            entry.copy_from_slice(&node.entry);
            if !emitted.contains(&entry) {
                let entry_wire =
                    fetcher
                        .fetch(entry)
                        .await
                        .map_err(|source| TraversalError::Fetch {
                            addr: hex::encode(entry),
                            source,
                        })?;
                push_tree(fetcher, entry, &entry_wire, max_bytes, out, emitted).await?;
            }
        }

        for fork in node.forks.values() {
            // Encrypted manifests (64-byte fork refs) can't reach this
            // walker: their node chunks are ciphertext, so `unmarshal`
            // above already fails for them. Only plain 32-byte children
            // are traversable.
            if let Ok(child) = <[u8; 32]>::try_from(fork.child_ref.as_slice()) {
                if child != [0u8; 32] {
                    stack.push(child);
                }
            }
        }
    }
    Ok(())
}

/// Enumerate every **stored chunk address** of the encrypted content
/// tree rooted at the 64-byte reference `root_ref` (`address ‖
/// decryption key`). Chunks of an encrypted upload are stored under
/// the BMT address of their *ciphertext* — the "addr half" of each
/// 64-byte child reference — so that is what this yields (the key half
/// never leaves the reference). Parity chunks of a redundancy-encoded
/// tree ride along as bare 32-byte references and are emitted too.
///
/// Encrypted mantaray manifests are walked like
/// [`traverse_chunk_addresses`] walks plain ones: a single-chunk root
/// whose *decrypted* bytes parse as a manifest is descended fork by
/// fork (fork/entry references are 64 bytes there), covering each
/// node's own chunk tree and every value entry's file tree.
///
/// Interior nodes are fetched (and decrypted) to learn their children;
/// leaves are listed but not fetched, mirroring the plain traversal.
pub async fn traverse_encrypted_chunk_addresses(
    fetcher: &dyn ChunkFetcher,
    root_ref: [u8; ENC_REF_SIZE],
    max_bytes: usize,
) -> Result<Vec<[u8; 32]>, TraversalError> {
    // Traversal (pin, stewardship) never waits for peer credit (#117).
    let fetcher = &crate::NoCreditWait(fetcher);
    let mut out = Vec::new();
    let mut emitted = HashSet::new();

    // Manifest probe, mirroring the plain traversal: only a
    // single-chunk root can be a mantaray root node. The node bytes
    // are ciphertext, so the probe needs the decrypted payload.
    let (span, payload) = fetch_and_decrypt(fetcher, &root_ref).await?;
    if span <= CHUNK_SIZE as u64 && (span as usize) <= payload.len() {
        match Node::unmarshal(&payload[..span as usize]) {
            Ok(_) => {
                traverse_encrypted_manifest(fetcher, root_ref, max_bytes, &mut out, &mut emitted)
                    .await?;
                return Ok(out);
            }
            Err(ManifestError::NotAManifest | ManifestError::TooShort(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }

    push_encrypted_tree(fetcher, root_ref, max_bytes, &mut out, &mut emitted).await?;
    Ok(out)
}

/// Fetch the stored (ciphertext) chunk behind a 64-byte reference and
/// decrypt it, returning the plaintext span and payload.
async fn fetch_and_decrypt(
    fetcher: &dyn ChunkFetcher,
    node_ref: &[u8; ENC_REF_SIZE],
) -> Result<(u64, Vec<u8>), TraversalError> {
    let addr: [u8; 32] = node_ref[..32].try_into().expect("64-byte reference");
    let key: [u8; 32] = node_ref[32..].try_into().expect("64-byte reference");
    let wire = fetcher
        .fetch(addr)
        .await
        .map_err(|source| TraversalError::Fetch {
            addr: hex::encode(addr),
            source,
        })?;
    let (span_raw, payload) =
        ant_crypto::decrypt_chunk_parts(&wire, &key).map_err(|e| TraversalError::Fetch {
            addr: hex::encode(addr),
            source: format!("decrypt: {e}").into(),
        })?;
    let (_, plain_span) = crate::rs::decode_span(span_raw);
    Ok((u64::from_le_bytes(plain_span), payload))
}

/// Enumerate the encrypted span tree rooted at `node_ref` into `out`
/// (stored addresses: addr halves of data refs + bare parity refs).
/// Interior nodes are fetched + decrypted; leaves are listed only.
async fn push_encrypted_tree(
    fetcher: &dyn ChunkFetcher,
    root_ref: [u8; ENC_REF_SIZE],
    max_bytes: usize,
    out: &mut Vec<[u8; 32]>,
    emitted: &mut HashSet<[u8; 32]>,
) -> Result<(), TraversalError> {
    // Stack of refs still to expand as *interior or unknown* nodes.
    let mut stack: Vec<[u8; ENC_REF_SIZE]> = vec![root_ref];
    while let Some(node_ref) = stack.pop() {
        let addr: [u8; 32] = node_ref[..32].try_into().expect("64-byte reference");
        if !emitted.insert(addr) {
            continue;
        }
        out.push(addr);

        let key: [u8; 32] = node_ref[32..].try_into().expect("64-byte reference");
        let wire = fetcher
            .fetch(addr)
            .await
            .map_err(|source| TraversalError::Fetch {
                addr: hex::encode(addr),
                source,
            })?;
        let (span_raw, payload) =
            ant_crypto::decrypt_chunk_parts(&wire, &key).map_err(|e| TraversalError::Fetch {
                addr: hex::encode(addr),
                source: format!("decrypt: {e}").into(),
            })?;
        let (level, plain_span) = crate::rs::decode_span(span_raw);
        let span = u64::from_le_bytes(plain_span);
        if span > max_bytes as u64 {
            return Err(JoinError::TooLarge {
                span,
                cap: max_bytes,
            }
            .into());
        }
        // Leaf: nothing below it.
        if span <= CHUNK_SIZE as u64 {
            continue;
        }
        // Intermediate: `shards` 64-byte data refs then `parities`
        // bare 32-byte parity refs (see `join_encrypted_into`).
        let (shards, parities) = crate::rs::reference_count_enc(span, level);
        let needed = shards * ENC_REF_SIZE + parities * 32;
        if needed > payload.len() {
            return Err(JoinError::MalformedChunk {
                offset: 0,
                detail: format!(
                    "encrypted intermediate needs {needed} reference bytes, payload has {}",
                    payload.len()
                ),
            }
            .into());
        }
        let branching = crate::rs::max_enc_shards(level) as u64;
        let branch_size = subtrie_section(shards, span, branching);
        let mut remaining = span;
        for i in 0..shards {
            if remaining == 0 {
                break;
            }
            let child: [u8; ENC_REF_SIZE] = payload[i * ENC_REF_SIZE..(i + 1) * ENC_REF_SIZE]
                .try_into()
                .expect("slice length");
            let child_span = branch_size.min(remaining);
            if child_span <= CHUNK_SIZE as u64 {
                // Data leaf: list its stored address without fetching.
                let child_addr: [u8; 32] = child[..32].try_into().expect("slice length");
                if emitted.insert(child_addr) {
                    out.push(child_addr);
                }
            } else {
                stack.push(child);
            }
            remaining -= child_span;
        }
        let parity_base = shards * ENC_REF_SIZE;
        for i in 0..parities {
            let parity_addr: [u8; 32] = payload[parity_base + i * 32..parity_base + (i + 1) * 32]
                .try_into()
                .expect("slice length");
            if emitted.insert(parity_addr) {
                out.push(parity_addr);
            }
        }
    }
    Ok(())
}

/// Walk an encrypted mantaray trie: every node's own (encrypted) chunk
/// tree, every 64-byte value entry's file tree, forks descended
/// iteratively with a visited set. The rare legacy 32-byte entry in an
/// otherwise-encrypted manifest falls back to the plain traversal.
async fn traverse_encrypted_manifest(
    fetcher: &dyn ChunkFetcher,
    root_ref: [u8; ENC_REF_SIZE],
    max_bytes: usize,
    out: &mut Vec<[u8; 32]>,
    emitted: &mut HashSet<[u8; 32]>,
) -> Result<(), TraversalError> {
    let mut visited = HashSet::new();
    let mut stack: Vec<[u8; ENC_REF_SIZE]> = vec![root_ref];
    while let Some(node_ref) = stack.pop() {
        if !visited.insert(node_ref) {
            continue;
        }
        // The manifest node is itself a (usually single-chunk) swarm
        // file; its chunk tree is part of the content.
        push_encrypted_tree(fetcher, node_ref, max_bytes, out, emitted).await?;
        let (span, payload) = fetch_and_decrypt(fetcher, &node_ref).await?;
        if span > payload.len() as u64 {
            return Err(JoinError::MalformedChunk {
                offset: 0,
                detail: format!(
                    "manifest node span {span} exceeds payload {}",
                    payload.len()
                ),
            }
            .into());
        }
        let node = Node::unmarshal(&payload[..span as usize])?;

        // Value entry (64-byte in an encrypted manifest; bee skips the
        // all-zero sentinel of metadata-only nodes).
        if node.entry.iter().any(|&b| b != 0) {
            if node.entry.len() == ENC_REF_SIZE {
                let entry: [u8; ENC_REF_SIZE] =
                    node.entry.as_slice().try_into().expect("length checked");
                push_encrypted_tree(fetcher, entry, max_bytes, out, emitted).await?;
            } else if node.entry.len() == 32 {
                let entry: [u8; 32] = node.entry.as_slice().try_into().expect("length checked");
                if !emitted.contains(&entry) {
                    let entry_wire =
                        fetcher
                            .fetch(entry)
                            .await
                            .map_err(|source| TraversalError::Fetch {
                                addr: hex::encode(entry),
                                source,
                            })?;
                    push_tree(fetcher, entry, &entry_wire, max_bytes, out, emitted).await?;
                }
            }
        }

        for fork in node.forks.values() {
            if let Ok(child) = <[u8; ENC_REF_SIZE]>::try_from(fork.child_ref.as_slice()) {
                if child.iter().any(|&b| b != 0) {
                    stack.push(child);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest_writer::build_single_file_manifest;
    use crate::splitter::split_bytes;
    use std::collections::HashMap;
    use std::error::Error as StdError;
    use std::sync::Mutex;

    struct MapFetcher {
        chunks: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    }

    impl MapFetcher {
        fn new() -> Self {
            Self {
                chunks: Mutex::new(HashMap::new()),
            }
        }
        fn insert(&self, addr: [u8; 32], wire: Vec<u8>) {
            self.chunks.lock().unwrap().insert(addr, wire);
        }
        fn remove(&self, addr: &[u8; 32]) {
            self.chunks.lock().unwrap().remove(addr);
        }
    }

    #[async_trait::async_trait]
    impl ChunkFetcher for MapFetcher {
        async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
            self.chunks
                .lock()
                .unwrap()
                .get(&addr)
                .cloned()
                .ok_or_else(|| format!("chunk {} not found", hex::encode(addr)).into())
        }
    }

    const CAP: usize = 64 * 1024 * 1024;

    /// A single-chunk `/bytes` upload traverses to exactly its root.
    #[tokio::test]
    async fn single_chunk_bytes() {
        let store = MapFetcher::new();
        let split = split_bytes(b"tiny payload");
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let addrs = traverse_chunk_addresses(&store, split.root, CAP)
            .await
            .unwrap();
        assert_eq!(addrs, vec![split.root]);
    }

    /// A multi-chunk `/bytes` tree yields the root, every interior
    /// node, and every leaf — exactly the set the splitter produced.
    #[tokio::test]
    async fn multi_chunk_bytes_lists_whole_tree() {
        let store = MapFetcher::new();
        let body = vec![0xabu8; 4096 * 3 + 100];
        let split = split_bytes(&body);
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let addrs = traverse_chunk_addresses(&store, split.root, CAP)
            .await
            .unwrap();
        let got: HashSet<_> = addrs.iter().copied().collect();
        let want: HashSet<_> = split.chunks.iter().map(|c| c.address).collect();
        assert_eq!(got, want);
        // The repeated-content leaves share an address; the traversal
        // output is deduplicated.
        assert_eq!(addrs.len(), got.len(), "no duplicates");
    }

    /// A single-file mantaray manifest traverses to every manifest node
    /// *and* the file's data tree.
    #[tokio::test]
    async fn manifest_traversal_covers_nodes_and_data() {
        let store = MapFetcher::new();
        let body = vec![0x5au8; 4096 * 2 + 17];
        let split = split_bytes(&body);
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let manifest = build_single_file_manifest("hello.txt", Some("text/plain"), split.root)
            .expect("manifest");
        for c in &manifest.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let addrs = traverse_chunk_addresses(&store, manifest.root, CAP)
            .await
            .unwrap();
        let got: HashSet<_> = addrs.iter().copied().collect();
        for c in &manifest.chunks {
            assert!(got.contains(&c.address), "manifest node missing");
        }
        for c in &split.chunks {
            assert!(got.contains(&c.address), "data chunk missing");
        }
    }

    /// A missing *interior* node fails the traversal (its children are
    /// unknowable); a missing *leaf* does not — leaves are listed from
    /// their parents without being fetched, and it's the caller's probe
    /// that discovers they're gone.
    #[tokio::test]
    async fn missing_interior_fails_missing_leaf_lists() {
        let store = MapFetcher::new();
        let body = vec![0x11u8; 4096 * 200];
        let split = split_bytes(&body);
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        // Drop one leaf: traversal still lists it.
        let leaf = split.chunks[0].address;
        assert_ne!(leaf, split.root);
        store.remove(&leaf);
        let addrs = traverse_chunk_addresses(&store, split.root, CAP)
            .await
            .unwrap();
        assert!(addrs.contains(&leaf));

        // Drop an interior node: with 200 leaves the tree has a second
        // level, so some non-root chunk declares a span > one chunk.
        // Removing it makes its subtree unenumerable.
        let interior = split
            .chunks
            .iter()
            .find(|c| {
                if c.address == split.root || c.wire.len() < 8 {
                    return false;
                }
                let mut span = [0u8; 8];
                span.copy_from_slice(&c.wire[..8]);
                u64::from_le_bytes(span) > 4096
            })
            .map(|c| c.address)
            .expect("a non-root interior node");
        store.remove(&interior);
        assert!(traverse_chunk_addresses(&store, split.root, CAP)
            .await
            .is_err());
    }

    /// Encrypted `/bytes` tree (with redundancy): the traversal lists
    /// exactly the stored ciphertext addresses the encrypted splitter
    /// produced — addr halves of the 64-byte refs plus parities.
    #[tokio::test]
    async fn encrypted_traversal_lists_stored_addresses() {
        let store = MapFetcher::new();
        let body: Vec<u8> = (0..40_000usize).map(|i| ((i * 13) % 251) as u8).collect();
        let split = crate::split_bytes_encrypted(&body, 2);
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let addrs = traverse_encrypted_chunk_addresses(&store, split.root_ref, CAP)
            .await
            .unwrap();
        let got: HashSet<_> = addrs.iter().copied().collect();
        let want: HashSet<_> = split.chunks.iter().map(|c| c.address).collect();
        assert_eq!(got, want, "stored ciphertext + parity addresses");
        assert_eq!(addrs.len(), got.len(), "no duplicates");
        assert!(got.contains(&split.root_address()), "root addr half listed");
    }

    /// A single-chunk encrypted upload traverses to just its stored
    /// address (the addr half of the reference).
    #[tokio::test]
    async fn encrypted_single_chunk() {
        let store = MapFetcher::new();
        let split = crate::split_bytes_encrypted(b"tiny encrypted payload", 0);
        for c in &split.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let addrs = traverse_encrypted_chunk_addresses(&store, split.root_ref, CAP)
            .await
            .unwrap();
        assert_eq!(addrs, vec![split.root_address()]);
    }

    /// Encrypted single-file manifest: traversal covers the manifest
    /// node's stored chunks *and* the (encrypted) file data tree.
    #[tokio::test]
    async fn encrypted_manifest_traversal_covers_nodes_and_data() {
        let store = MapFetcher::new();
        let body = vec![0x5au8; 4096 * 2 + 17];
        let data = crate::split_bytes_encrypted(&body, 0);
        for c in &data.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let manifest = crate::manifest_writer::build_single_file_manifest_encrypted(
            "secret.txt",
            Some("text/plain"),
            &data.root_ref,
            0,
        )
        .expect("manifest");
        for c in &manifest.chunks {
            store.insert(c.address, c.wire.clone());
        }
        let root_ref: [u8; ENC_REF_SIZE] = manifest.root_ref;
        let addrs = traverse_encrypted_chunk_addresses(&store, root_ref, CAP)
            .await
            .unwrap();
        let got: HashSet<_> = addrs.iter().copied().collect();
        for c in &manifest.chunks {
            assert!(got.contains(&c.address), "manifest node chunk missing");
        }
        for c in &data.chunks {
            assert!(got.contains(&c.address), "data chunk missing");
        }
    }

    /// Missing root is an error the callers map to `isRetrievable:
    /// false`.
    #[tokio::test]
    async fn missing_root_errors() {
        let store = MapFetcher::new();
        let err = traverse_chunk_addresses(&store, [0xee; 32], CAP)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}
