//! Ordered Merkle-Patricia trie root — twin of `consensus.proof.OrderedTrieRoot`
//! (Java). The construction behind a block's `transactionsRoot` /
//! `receiptsRoot`: a trie mapping `key = RLP(index)` (UN-hashed) to the
//! item's consensus encoding, built bottom-up so a full body/receipt list can
//! be verified against a trusted header without trusting the peer
//! (docs/reimplementation/03 §2, README §11.11).

use crate::keccak::keccak256;
use crate::rlp;
use crate::trie::{hex_prefix_encode, to_nibbles, EMPTY_TRIE_ROOT};

/// True iff the ordered trie over `items` roots to `expected_root`.
pub fn verify(items: &[Vec<u8>], expected_root: &[u8; 32]) -> bool {
    ordered_trie_root(items) == *expected_root
}

/// Root of the ordered trie mapping `RLP(i) -> items[i]`.
pub fn ordered_trie_root(items: &[Vec<u8>]) -> [u8; 32] {
    if items.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    let mut entries: Vec<(Vec<u8>, &[u8])> = items
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let key = rlp::encode_bytes(&rlp::u64_to_minimal_be(i as u64));
            (to_nibbles(&key), v.as_slice())
        })
        .collect();
    // Trie shape follows key-nibble order, not insertion order.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    keccak256(&build_node(&entries, 0))
}

/// RLP bytes of the trie node covering `entries`, which all share nibbles
/// `[0, depth)`. Recursion is bounded by the key length (RLP(u64) index keys
/// are ≤ 9 bytes = 18 nibbles) — never by untrusted input.
fn build_node(entries: &[(Vec<u8>, &[u8])], depth: usize) -> Vec<u8> {
    if entries.len() == 1 {
        let (path, value) = &entries[0];
        let mut payload = rlp::encode_bytes(&hex_prefix_encode(&path[depth..], true));
        payload.extend_from_slice(&rlp::encode_bytes(value));
        return rlp::encode_list_payload(&payload);
    }
    let common = common_prefix_end(entries, depth);
    if common > depth {
        let shared = &entries[0].0[depth..common];
        let child = build_node(entries, common);
        let mut payload = rlp::encode_bytes(&hex_prefix_encode(shared, false));
        write_ref(&mut payload, &child);
        return rlp::encode_list_payload(&payload);
    }
    // Branch node: 16 child slots + a value slot (key ending exactly here).
    let mut branch_value: &[u8] = &[];
    let mut groups: [Vec<(Vec<u8>, &[u8])>; 16] = Default::default();
    for (path, value) in entries {
        if path.len() == depth {
            branch_value = value;
        } else {
            groups[path[depth] as usize].push((path.clone(), value));
        }
    }
    let mut payload = Vec::new();
    for group in &groups {
        if group.is_empty() {
            payload.extend_from_slice(&rlp::encode_bytes(&[]));
        } else {
            let child = build_node(group, depth + 1);
            write_ref(&mut payload, &child);
        }
    }
    payload.extend_from_slice(&rlp::encode_bytes(branch_value));
    rlp::encode_list_payload(&payload)
}

/// Child reference: inline the node RLP when < 32 bytes, else its keccak hash.
fn write_ref(payload: &mut Vec<u8>, child_rlp: &[u8]) {
    if child_rlp.len() < 32 {
        payload.extend_from_slice(child_rlp);
    } else {
        payload.extend_from_slice(&rlp::encode_bytes(&keccak256(child_rlp)));
    }
}

/// Largest nibble index `c >= depth` such that every entry shares `[depth, c)`.
/// Entries are sorted, so the first and last bound the whole set.
fn common_prefix_end(entries: &[(Vec<u8>, &[u8])], depth: usize) -> usize {
    let first = &entries[0].0;
    let last = &entries[entries.len() - 1].0;
    let mut c = depth;
    while c < first.len() && c < last.len() && first[c] == last[c] {
        c += 1;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_is_empty_root() {
        assert_eq!(ordered_trie_root(&[]), EMPTY_TRIE_ROOT);
        assert!(verify(&[], &EMPTY_TRIE_ROOT));
    }

    #[test]
    fn single_item_root_is_hash_of_leaf() {
        // One item: trie is a single leaf [HP(nibbles(0x80), leaf), value].
        let value = b"first".to_vec();
        let root = ordered_trie_root(std::slice::from_ref(&value));
        let key = rlp::encode_bytes(&[]); // RLP(0) = 0x80
        let leaf = {
            let mut payload = rlp::encode_bytes(&hex_prefix_encode(&to_nibbles(&key), true));
            payload.extend_from_slice(&rlp::encode_bytes(&value));
            rlp::encode_list_payload(&payload)
        };
        assert_eq!(root, keccak256(&leaf));
    }

    #[test]
    fn order_matters() {
        let a = vec![b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(), b"b".to_vec()];
        let b = vec![b"b".to_vec(), b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec()];
        assert_ne!(ordered_trie_root(&a), ordered_trie_root(&b));
    }

    #[test]
    fn large_list_spans_multibyte_index_keys() {
        // 200 items crosses the RLP(127)→RLP(128) key-width boundary and
        // exercises branch/extension building + inline-vs-hash child refs.
        let items: Vec<Vec<u8>> = (0..200u32)
            .map(|i| keccak256(format!("item-{i}").as_bytes()).to_vec())
            .collect();
        let root = ordered_trie_root(&items);
        assert_ne!(root, EMPTY_TRIE_ROOT);
        // Deterministic: same input, same root.
        assert_eq!(root, ordered_trie_root(&items));
    }
}
