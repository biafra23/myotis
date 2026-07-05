//! SSZ hashing/merkleization primitives — the Rust twin of the Java `SszUtil`.
//!
//! Hand-rolled (sha2 only) rather than the `ethereum_ssz`/`tree_hash` derive stack:
//! the wire types this crate decodes are fork-POLYMORPHIC (branch lengths and fixed
//! sizes are sniffed from offsets at runtime, exactly like the Java decoders), which
//! static ssz_derive containers cannot express. Conformance to the spec is pinned by
//! the shared corpus (`rust/testdata/lc/mainnet`) instead of by a library.

use sha2::{Digest, Sha256};

pub const ROOT_LEN: usize = 32;
pub type Root = [u8; ROOT_LEN];

/// SHA-256 of `a || b` (the only hash SSZ merkleization needs).
pub fn sha256_pair(a: &[u8], b: &[u8]) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// zero_hashes[0] = 32 zero bytes; zero_hashes[n] = H(zh[n-1] || zh[n-1]).
fn zero_hash(depth: usize) -> Root {
    // Depth is tiny (<32) on every path here; recompute instead of a lazy static.
    let mut z = [0u8; 32];
    for _ in 0..depth {
        z = sha256_pair(&z, &z);
    }
    z
}

fn next_power_of_two(n: usize) -> usize {
    n.max(1).next_power_of_two()
}

/// Merkleize chunks, padding with zero hashes to `max(next_pow2(len), limit)` leaves.
///
/// Pads the BOTTOM layer with zero leaves and hashes upward — equivalent to the
/// Java `merkleizeWithSize(chunks, size, depthOffset=0)`; Java's sparse variant
/// (which pads with `ZERO_HASHES[depth]`) serves huge-limit lists these light
/// client containers never contain, so it's deliberately absent here.
pub fn merkleize_with_limit(chunks: &[Root], limit: usize) -> Root {
    let size = next_power_of_two(chunks.len()).max(next_power_of_two(limit));
    let mut layer: Vec<Root> = Vec::with_capacity(size);
    layer.extend_from_slice(chunks);
    layer.resize(size, zero_hash(0));
    // In-place pairwise reduction: no per-level reallocation.
    let mut len = size;
    while len > 1 {
        for i in 0..len / 2 {
            layer[i] = sha256_pair(&layer[2 * i], &layer[2 * i + 1]);
        }
        len /= 2;
    }
    layer[0]
}

pub fn merkleize(chunks: &[Root]) -> Root {
    merkleize_with_limit(chunks, 0)
}

/// hash_tree_root of a container = merkleize of its field roots.
pub fn container_root(field_roots: &[Root]) -> Root {
    merkleize(field_roots)
}

/// mix_in_length: H(root || LE64(length) zero-padded to 32).
pub fn mix_in_length(root: &Root, length: u64) -> Root {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&length.to_le_bytes());
    sha256_pair(root, &chunk)
}

pub fn uint64_root(v: u64) -> Root {
    let mut chunk = [0u8; 32];
    chunk[..8].copy_from_slice(&v.to_le_bytes());
    chunk
}

pub fn bytes32_root(b: &[u8; 32]) -> Root {
    *b
}

/// Zero-pad a short fixed byte value (bytes4 / bytes20) into one chunk.
pub fn padded_root(b: &[u8]) -> Root {
    debug_assert!(b.len() <= 32);
    let mut chunk = [0u8; 32];
    chunk[..b.len()].copy_from_slice(b);
    chunk
}

/// hash_tree_root of a fixed-length byte vector of any size (chunked, zero-padded).
pub fn byte_vector_root(data: &[u8]) -> Root {
    let chunks: Vec<Root> = data
        .chunks(32)
        .map(|c| {
            let mut chunk = [0u8; 32];
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect();
    merkleize(&chunks)
}

/// hash_tree_root of a variable byte list with a chunk limit (extraData).
pub fn byte_list_root(data: &[u8], chunk_limit: usize) -> Root {
    // No empty-data special case needed: merkleize_with_limit pads an empty chunk
    // list with zero leaves up to the limit, which equals the Java one-zero-chunk
    // path's root exactly.
    let chunks: Vec<Root> = data
        .chunks(32)
        .map(|c| {
            let mut chunk = [0u8; 32];
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect();
    let root = merkleize_with_limit(&chunks, chunk_limit);
    mix_in_length(&root, data.len() as u64)
}

/// Verify an SSZ Merkle inclusion proof (mirrors `SszUtil.verifyMerkleBranch`).
pub fn verify_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    depth: usize,
    index: u64,
    root: &Root,
) -> bool {
    if branch.len() != depth {
        return false;
    }
    let mut value = *leaf;
    for (i, node) in branch.iter().enumerate() {
        value = if (index >> i) & 1 == 1 {
            sha256_pair(node, &value)
        } else {
            sha256_pair(&value, node)
        };
    }
    value == *root
}

// ---- little-endian readers over untrusted input (checked) ----

pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

pub fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

pub fn read_root(data: &[u8], offset: usize) -> Option<Root> {
    data.get(offset..offset + 32).map(|b| b.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hash_chain_matches_definition() {
        assert_eq!(zero_hash(0), [0u8; 32]);
        assert_eq!(zero_hash(1), sha256_pair(&[0u8; 32], &[0u8; 32]));
        let z1 = zero_hash(1);
        assert_eq!(zero_hash(2), sha256_pair(&z1, &z1));
    }

    #[test]
    fn merkle_branch_roundtrip() {
        // Build a 4-leaf tree by hand and prove leaf 2 (gindex 4+2=6).
        let leaves: Vec<Root> = (0u8..4).map(|i| [i; 32]).collect();
        let root = merkleize(&leaves);
        let branch = [leaves[3], sha256_pair(&leaves[0], &leaves[1])];
        assert!(verify_merkle_branch(&leaves[2], &branch, 2, 6, &root));
        assert!(!verify_merkle_branch(&leaves[2], &branch, 2, 7, &root));
    }
}
