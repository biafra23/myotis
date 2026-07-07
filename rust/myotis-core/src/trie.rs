//! Merkle-Patricia proof verification — twin of `core.trie` (Java:
//! `MerklePatriciaProofVerifier` + `HexPrefix`). The state trust anchor for
//! SNAP-served data (docs/reimplementation/03 §2): given a trusted `root`, an
//! un-hashed `key`, and the peer's RLP node list, decide
//! Found / Absent / Invalid. Semantics are pinned cross-language by the
//! `rust/testdata/el/mpt/` corpus — replicate-verbatim territory
//! (README §11.8-9: `storageRoot`/`codeHash` only ever come from the
//! proof-verified account leaf).
//!
//! Unlike the Java original this walk is ITERATIVE — a hostile proof chaining
//! zero-nibble extension nodes must not grow the stack (the workspace builds
//! with `panic = "abort"`).

use std::collections::HashMap;

use crate::keccak::keccak256;
use crate::rlp::{self, Item};
use crate::{err, CoreError};

/// `keccak256(rlp(""))` — the conventional root of an empty trie.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
    0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
    0xb4, 0x21,
];

/// `keccak256("")` — the code hash of an empty account.
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
    0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
    0xa4, 0x70,
];

/// Outcome of a verification attempt. `Invalid` is the ONLY error channel —
/// verification never panics and never returns `Result::Err`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofResult {
    /// Proof verifies and the key is present with this value.
    Found(Vec<u8>),
    /// Proof verifies and the key is provably absent (exclusion proof).
    Absent,
    /// Proof did not verify; the reason explains why.
    Invalid(String),
}

/// Verify a proof. `key` is the un-hashed key — for the state trie callers
/// pass `keccak256(address)`, for a storage trie `keccak256(slot32)`; the
/// verifier converts to nibbles internally.
pub fn verify_proof(root: &[u8; 32], key: &[u8], proof_nodes: &[Vec<u8>]) -> ProofResult {
    if key.is_empty() {
        return ProofResult::Invalid("empty key".into());
    }
    if proof_nodes.is_empty() {
        // The empty trie has a well-known root. With no proof nodes we can
        // only assert absence if the root says the trie is empty.
        if *root == EMPTY_TRIE_ROOT {
            return ProofResult::Absent;
        }
        return ProofResult::Invalid("empty proof for non-empty root".into());
    }

    // Index nodes by keccak256 so descent picks the next node by hash match
    // (tolerates out-of-order node lists; lets one node set serve many keys).
    let mut by_hash: HashMap<[u8; 32], &[u8]> = HashMap::with_capacity(proof_nodes.len());
    for node in proof_nodes {
        by_hash.insert(keccak256(node), node.as_slice());
    }

    let path = to_nibbles(key);

    // Iterative descent. `pending` is the next node to interpret — either a
    // hash the proof must contain, or an embedded (< 32-byte) child Item.
    //
    // Termination bound: one walk can visit each supplied node AT MOST once —
    // revisiting would require the trie to contain a keccak cycle (a node
    // whose descendants hash-reference it), which no proof, honest or
    // hostile, can construct. The explicit counter makes termination
    // structural instead of resting on that cryptographic argument alone
    // (embedded in-node descent is separately bounded by the RLP depth cap).
    let mut expected_hash = *root;
    let mut idx = 0usize;
    let mut lookups = 0usize;
    loop {
        lookups += 1;
        if lookups > by_hash.len() {
            return ProofResult::Invalid(
                "proof walk exceeded the supplied node count (cycle)".into(),
            );
        }
        let node_rlp = match by_hash.get(&expected_hash) {
            Some(n) => *n,
            None => {
                return ProofResult::Invalid(format!(
                    "missing node {} (path idx={idx})",
                    hex32(&expected_hash)
                ))
            }
        };
        let item = match rlp::decode(node_rlp) {
            Ok(it) => it,
            Err(e) => return ProofResult::Invalid(format!("malformed node RLP: {}", e.0)),
        };
        // Interpret this node, following embedded children in-line until we
        // either terminate or reach the next hash reference.
        let mut current = item;
        loop {
            match interpret(&current, &path, idx) {
                Step::Done(result) => return result,
                Step::Hash(h, new_idx) => {
                    expected_hash = h;
                    idx = new_idx;
                    break; // back to the by-hash lookup
                }
                Step::Embedded(child, new_idx) => {
                    current = child;
                    idx = new_idx;
                }
            }
        }
    }
}

/// Ethereum state-trie account leaf: `RLP([nonce, balance, storageRoot, codeHash])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLeaf {
    pub nonce: u64,
    /// Minimal big-endian wei balance (empty = zero).
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// Decode a proof-verified account leaf value. THE ONLY legitimate source of
/// `storage_root`/`code_hash` (README §11.8) — never a peer's slim body.
///
/// Stricter than the current Java production decode (`SnapBackedStateOracle`
/// uses lenient Tuweni readers): leading-zero scalars and out-of-range values
/// are rejected here. Honest tries never contain them; pin the Java side to
/// the same rules when the EL wiring lands (EL-A6/A7).
pub fn decode_account_leaf(value: &[u8]) -> Result<AccountLeaf, CoreError> {
    let top = rlp::decode(value).map_err(|e| CoreError(format!("account leaf: {}", e.0)))?;
    let items = top.as_list()?;
    if items.len() != 4 {
        return err(format!("account leaf: expected 4 fields, got {}", items.len()));
    }
    let nonce = items[0]
        .as_u64_fitting_long()
        .map_err(|e| CoreError(format!("account leaf: nonce: {}", e.0)))?;
    let balance = items[1].as_bytes()?.to_vec();
    if !balance.is_empty() && balance[0] == 0 {
        return err("account leaf: balance has leading zero byte");
    }
    let mut storage_root = [0u8; 32];
    storage_root.copy_from_slice(items[2].as_fixed_bytes(32)?);
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(items[3].as_fixed_bytes(32)?);
    Ok(AccountLeaf {
        nonce,
        balance,
        storage_root,
        code_hash,
    })
}

/// Decode a proof-verified storage leaf value: `rlp(trimmed_uint256)` —
/// returns the minimal big-endian slot value (empty = zero).
pub fn decode_storage_leaf(value: &[u8]) -> Result<Vec<u8>, CoreError> {
    let top = rlp::decode(value).map_err(|e| CoreError(format!("storage leaf: {}", e.0)))?;
    let bytes = top.as_bytes()?;
    if bytes.len() > 32 {
        return err(format!("storage leaf: value is {} bytes (> 32)", bytes.len()));
    }
    if !bytes.is_empty() && bytes[0] == 0 {
        return err("storage leaf: value has leading zero byte");
    }
    Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Node interpretation.
// ---------------------------------------------------------------------------

enum Step {
    Done(ProofResult),
    /// Descend to the node with this hash, path consumed up to `usize`.
    Hash([u8; 32], usize),
    /// Descend into an embedded (< 32-byte) child, path consumed up to `usize`.
    Embedded(Item, usize),
}

fn interpret(node: &Item, path: &[u8], idx: usize) -> Step {
    let items = match node.as_list() {
        Ok(l) => l,
        Err(_) => {
            return Step::Done(ProofResult::Invalid(
                "malformed node RLP: expected list".into(),
            ))
        }
    };
    match items.len() {
        17 => interpret_branch(items, path, idx),
        2 => interpret_short(items, path, idx),
        n => Step::Done(ProofResult::Invalid(format!("unexpected node arity: {n}"))),
    }
}

/// Branch: 17 items — 16 child slots + 1 value at slot 16.
fn interpret_branch(items: &[Item], path: &[u8], idx: usize) -> Step {
    if idx == path.len() {
        // Path exhausted; the value lives at slot 16. (Java parity: a list in
        // the value slot passes through as its raw encoding.)
        return Step::Done(match &items[16] {
            Item::Bytes(v) if v.is_empty() => ProofResult::Absent,
            Item::Bytes(v) => ProofResult::Found(v.clone()),
            it @ Item::List(_) => ProofResult::Found(rlp::encode(it)),
        });
    }
    let nibble = (path[idx] & 0x0f) as usize;
    match &items[nibble] {
        it @ Item::List(_) => Step::Embedded(it.clone(), idx + 1),
        Item::Bytes(child) if child.is_empty() => Step::Done(ProofResult::Absent),
        Item::Bytes(child) if child.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(child);
            Step::Hash(h, idx + 1)
        }
        Item::Bytes(child) => Step::Done(ProofResult::Invalid(format!(
            "branch child {nibble} is {} bytes; expected 32-byte hash or embedded list",
            child.len()
        ))),
    }
}

/// Leaf or extension: 2 items — encoded-path + (value | next-hash | embedded).
fn interpret_short(items: &[Item], path: &[u8], idx: usize) -> Step {
    let encoded_path = match items[0].as_bytes() {
        Ok(b) => b,
        Err(_) => {
            return Step::Done(ProofResult::Invalid(
                "bad hex-prefix path: not a byte string".into(),
            ))
        }
    };
    let (leaf, node_nibbles) = match hex_prefix_decode(encoded_path) {
        Ok(d) => d,
        Err(e) => return Step::Done(ProofResult::Invalid(format!("bad hex-prefix path: {}", e.0))),
    };

    // Remaining path must start with the node's nibbles; otherwise the
    // queried key cannot live below this node — a valid exclusion.
    let remaining = path.len() - idx;
    if node_nibbles.len() > remaining || node_nibbles != path[idx..idx + node_nibbles.len()] {
        return Step::Done(ProofResult::Absent);
    }
    let new_idx = idx + node_nibbles.len();

    if leaf {
        if new_idx != path.len() {
            // Leaf ends the key here but our path has more nibbles — a
            // different key would live below.
            return Step::Done(ProofResult::Absent);
        }
        return Step::Done(match &items[1] {
            Item::Bytes(v) => ProofResult::Found(v.clone()),
            it @ Item::List(_) => ProofResult::Found(rlp::encode(it)), // Java passthrough parity
        });
    }
    // Extension: descend into the child.
    match &items[1] {
        it @ Item::List(_) => Step::Embedded(it.clone(), new_idx),
        Item::Bytes(child) if child.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(child);
            Step::Hash(h, new_idx)
        }
        Item::Bytes(child) => Step::Done(ProofResult::Invalid(format!(
            "extension child is {} bytes; expected 32-byte hash or embedded list",
            child.len()
        ))),
    }
}

// ---------------------------------------------------------------------------
// Hex-prefix (compact) encoding — Yellow Paper Appendix C.
// ---------------------------------------------------------------------------

/// Decode a compact-encoded path into `(is_leaf, nibbles)`.
pub(crate) fn hex_prefix_decode(encoded: &[u8]) -> Result<(bool, Vec<u8>), CoreError> {
    let first = match encoded.first() {
        Some(&b) => b,
        None => return err("empty hex-prefix path"),
    };
    let flag = first >> 4;
    if flag > 3 {
        return err(format!("invalid hex-prefix flag nibble: {flag}"));
    }
    let leaf = (flag & 0x02) != 0;
    let odd = (flag & 0x01) != 0;
    let mut nibbles = Vec::with_capacity(encoded.len() * 2);
    if odd {
        nibbles.push(first & 0x0f);
    }
    for &b in &encoded[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((leaf, nibbles))
}

/// Encode nibbles + leaf flag into the compact hex-prefix form.
pub(crate) fn hex_prefix_encode(nibbles: &[u8], leaf: bool) -> Vec<u8> {
    let odd = nibbles.len() % 2 == 1;
    let flag = (if leaf { 2u8 } else { 0 }) | (if odd { 1 } else { 0 });
    let mut out = Vec::with_capacity(1 + nibbles.len() / 2);
    let rest = if odd {
        out.push((flag << 4) | (nibbles[0] & 0x0f));
        &nibbles[1..]
    } else {
        out.push(flag << 4);
        nibbles
    };
    for pair in rest.chunks_exact(2) {
        out.push((pair[0] << 4) | (pair[1] & 0x0f));
    }
    out
}

/// Bytes → nibbles (high nibble first).
pub(crate) fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rlp::Item;

    fn leaf_node(key_nibbles: &[u8], value: &[u8]) -> Vec<u8> {
        rlp::encode(&Item::List(vec![
            Item::Bytes(hex_prefix_encode(key_nibbles, true)),
            Item::Bytes(value.to_vec()),
        ]))
    }

    #[test]
    fn single_leaf_found_and_excluded() {
        let key = [0xab, 0xcd];
        let value = b"myotis-value".to_vec();
        let node = leaf_node(&to_nibbles(&key), &value);
        let root = keccak256(&node);
        assert_eq!(
            verify_proof(&root, &key, &[node.clone()]),
            ProofResult::Found(value)
        );
        // Different key under the same root: leaf path diverges → Absent.
        assert_eq!(
            verify_proof(&root, &[0xab, 0xce], &[node]),
            ProofResult::Absent
        );
    }

    #[test]
    fn empty_trie_and_empty_proof() {
        assert_eq!(
            verify_proof(&EMPTY_TRIE_ROOT, &[0x01], &[]),
            ProofResult::Absent
        );
        assert!(matches!(
            verify_proof(&[0x11; 32], &[0x01], &[]),
            ProofResult::Invalid(_)
        ));
        assert!(matches!(
            verify_proof(&EMPTY_TRIE_ROOT, &[], &[]),
            ProofResult::Invalid(_)
        ));
    }

    #[test]
    fn missing_node_is_invalid() {
        let node = leaf_node(&to_nibbles(&[0x01]), b"v");
        let root = keccak256(&node);
        // Proof list holds a DIFFERENT node than the root references.
        let other = leaf_node(&to_nibbles(&[0x02]), b"w");
        assert!(matches!(
            verify_proof(&root, &[0x01], &[other]),
            ProofResult::Invalid(_)
        ));
    }

    #[test]
    fn hex_prefix_round_trip() {
        for (nibbles, leaf) in [
            (vec![], false),
            (vec![1u8], true),
            (vec![1, 2, 3], false),
            (vec![0xf, 0xe, 0xd, 0xc], true),
        ] {
            let enc = hex_prefix_encode(&nibbles, leaf);
            assert_eq!(hex_prefix_decode(&enc).unwrap(), (leaf, nibbles));
        }
        assert!(hex_prefix_decode(&[]).is_err());
        assert!(hex_prefix_decode(&[0x40]).is_err()); // flag nibble 4
    }

    #[test]
    fn account_and_storage_leaf_decode() {
        // [nonce=7, balance=0x0de0b6b3a7640000 (1 ETH), storageRoot, codeHash]
        let balance = vec![0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00];
        let leaf = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![7]),
            Item::Bytes(balance.clone()),
            Item::Bytes(EMPTY_TRIE_ROOT.to_vec()),
            Item::Bytes(EMPTY_CODE_HASH.to_vec()),
        ]));
        let acct = decode_account_leaf(&leaf).unwrap();
        assert_eq!(acct.nonce, 7);
        assert_eq!(acct.balance, balance);
        assert_eq!(acct.storage_root, EMPTY_TRIE_ROOT);
        assert_eq!(acct.code_hash, EMPTY_CODE_HASH);
        assert!(decode_account_leaf(b"junk").is_err());

        let slot = rlp::encode_bytes(&[0x2a]);
        assert_eq!(decode_storage_leaf(&slot).unwrap(), vec![0x2a]);
        assert_eq!(decode_storage_leaf(&rlp::encode_bytes(&[])).unwrap(), Vec::<u8>::new());
        assert!(decode_storage_leaf(&rlp::encode_bytes(&[0u8, 1])).is_err());
    }
}
