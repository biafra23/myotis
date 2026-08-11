//! Verify-on-fetch for snap/1 state (EL-A6), the security-critical half of the
//! snap oracle (docs/reimplementation/03 §3.2, README §11.8-12).
//!
//! Every value is verified against a TRUSTED state root via the MPT proof
//! verifier before it is returned; the peer's "slim" account body is NEVER
//! trusted (a peer can keep nonce/balance honest while forging
//! storageRoot/codeHash), so the account fields come only from the
//! proof-verified leaf. Storage anchors at the account's proven storageRoot,
//! not the world state root. Bytecode is accepted iff `keccak256(code) ==
//! codeHash`.
//!
//! These are pure functions over decoded [`super::messages`] responses; the
//! async single-shot request methods live on
//! [`crate::el::eth::session::EthSession`]. **Deferred to EL-A7** (the
//! managed-peer connection layer): peer rotation on `Invalid`/timeout +
//! root-unavailable marking, the stale-head floor (`minSensibleHeadBlock`),
//! and answering inbound snap `Get*` with empty responses (needs a background
//! read loop the single-request model here doesn't have).

use myotis_core::keccak::keccak256;
use myotis_core::trie::{
    decode_account_leaf, decode_storage_leaf, verify_proof, AccountLeaf, ProofResult,
    EMPTY_CODE_HASH, EMPTY_TRIE_ROOT,
};
use myotis_core::CoreError;

use super::messages::{AccountRange, StorageRanges};

/// The verified outcome of an account lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOutcome {
    /// The account exists with these proof-verified fields.
    Present(AccountLeaf),
    /// The account is provably absent (verified exclusion proof) → empty account.
    Absent,
}

/// Marker shared by every proof-verification failure message. LOAD-BEARING:
/// `reader::snap_account_at_best_root` classifies anchor-root failures by this
/// substring — "the peer answered but could not prove at that root" (pruned /
/// trailing / malformed proof) takes the handshake-head fallback, while
/// transport-shaped errors propagate immediately. Keep the format strings
/// below built from this constant, and keep
/// [`is_unservable_root_error`] + its tests in sync.
pub const PROOF_INVALID_MARKER: &str = "proof invalid";

/// Does this fetch error mean "the peer responded, but the proof did not
/// verify against the requested root"? True for a pruned/unknown root (empty
/// proof), a trailing peer, or a malformed/hostile proof — all cases where a
/// retry against a DIFFERENT root can still succeed. False for
/// transport-shaped failures (timeout/disconnect), where a second query
/// against the same peer would just pay the same timeout again.
pub fn is_unservable_root_error(error: &str) -> bool {
    error.contains(PROOF_INVALID_MARKER)
}

/// Verify an AccountRange response for `address` against the trusted
/// `state_root`. A single-account query (`starting = keccak(address)`) yields a
/// left-boundary proof that is exactly the Merkle proof for `keccak(address)`.
pub fn verify_account(
    state_root: &[u8; 32],
    address: &[u8; 20],
    response: &AccountRange,
) -> Result<AccountOutcome, CoreError> {
    let key = keccak256(address);
    match verify_proof(state_root, &key, &response.proof) {
        ProofResult::Found(leaf) => Ok(AccountOutcome::Present(decode_account_leaf(&leaf)?)),
        ProofResult::Absent => Ok(AccountOutcome::Absent),
        ProofResult::Invalid(reason) => {
            Err(CoreError(format!("account {PROOF_INVALID_MARKER}: {reason}")))
        }
    }
}

/// The verified outcome of a storage lookup: the minimal big-endian slot value
/// (empty = zero).
pub fn verify_storage(
    account: &AccountLeaf,
    slot: &[u8; 32],
    response: &StorageRanges,
) -> Result<Vec<u8>, CoreError> {
    // An empty storage trie: the value is zero with no proof needed.
    if account.storage_root == EMPTY_TRIE_ROOT {
        return Ok(Vec::new());
    }
    // Storage anchors at the account's PROVEN storageRoot, not the state root.
    let key = keccak256(slot);
    match verify_proof(&account.storage_root, &key, &response.proof) {
        ProofResult::Found(value) => decode_storage_leaf(&value),
        ProofResult::Absent => Ok(Vec::new()),
        ProofResult::Invalid(reason) => {
            Err(CoreError(format!("storage {PROOF_INVALID_MARKER}: {reason}")))
        }
    }
}

/// Match a returned bytecode against its requested `code_hash`
/// (`keccak256(code) == code_hash`). Returns the code if any returned entry
/// matches. An empty-code-hash request short-circuits to empty bytes (a
/// code-less account) with no round trip.
pub fn verify_bytecode(code_hash: &[u8; 32], returned: &[Vec<u8>]) -> Option<Vec<u8>> {
    if code_hash == &EMPTY_CODE_HASH {
        return Some(Vec::new());
    }
    for code in returned {
        if &keccak256(code) == code_hash {
            return Some(code.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::rlp::{self, Item};
    use myotis_core::trie::EMPTY_CODE_HASH;
    use super::super::messages::{AccountRange, SlimAccount, StorageRanges, StorageSlot};

    /// Build a single-leaf trie proving `key -> value`; returns (root, [node]).
    /// A full 32-byte key is 64 nibbles (even), so its hex-prefix compact form
    /// is the leaf flag `0x20` followed by the 32 key bytes.
    fn single_leaf(key: &[u8; 32], value: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
        let mut compact = vec![0x20u8];
        compact.extend_from_slice(key);
        let node = rlp::encode(&Item::List(vec![
            Item::Bytes(compact),
            Item::Bytes(value.to_vec()),
        ]));
        (keccak256(&node), vec![node])
    }

    #[test]
    fn account_present_from_proof_not_slim_body() {
        let address = [0x11u8; 20];
        let key = keccak256(&address);
        // The trusted leaf: nonce=5, balance=1 ETH, real storageRoot/codeHash.
        let sroot = keccak256(b"real-storage-root");
        let chash = keccak256(b"real-code");
        let leaf_value = rlp::encode(&Item::List(vec![
            Item::Bytes(rlp::u64_to_minimal_be(5)),
            Item::Bytes(vec![0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]),
            Item::Bytes(sroot.to_vec()),
            Item::Bytes(chash.to_vec()),
        ]));
        let (state_root, proof) = single_leaf(&key, &leaf_value);
        // The peer's slim body LIES about storageRoot/codeHash — must be ignored.
        let response = AccountRange {
            request_id: 1,
            accounts: vec![SlimAccount {
                account_hash: key,
                nonce: 5,
                balance: vec![0x01],
                storage_root: [0xaa; 32], // forged
                code_hash: [0xbb; 32],    // forged
            }],
            proof,
        };
        let outcome = verify_account(&state_root, &address, &response).unwrap();
        match outcome {
            AccountOutcome::Present(acct) => {
                // Verified from the PROOF, not the forged slim body.
                assert_eq!(acct.storage_root, sroot);
                assert_eq!(acct.code_hash, chash);
                assert_eq!(acct.nonce, 5);
            }
            AccountOutcome::Absent => panic!("expected Present"),
        }
    }

    #[test]
    fn unservable_root_classification_pins_the_real_error_shapes() {
        // The exact #355 failure: a peer that pruned (or never had) the root
        // answers with an EMPTY proof against a non-empty root. The resulting
        // error MUST classify as unservable-root (→ handshake-head fallback in
        // reader::snap_account_at_best_root), or the fallback silently dies.
        let address = [0x33u8; 20];
        let response = AccountRange { request_id: 1, accounts: vec![], proof: vec![] };
        let err = verify_account(&[0x42u8; 32], &address, &response).unwrap_err();
        assert!(
            is_unservable_root_error(&err.0),
            "empty-proof error must take the fallback: {}",
            err.0
        );
        // A garbage proof (ProofResult::Invalid of another shape) also counts:
        // the peer answered; a different root may still be servable.
        let response = AccountRange {
            request_id: 1,
            accounts: vec![],
            proof: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        };
        let err = verify_account(&[0x42u8; 32], &address, &response).unwrap_err();
        assert!(is_unservable_root_error(&err.0), "garbage proof: {}", err.0);
        // Transport-shaped failures must NOT take the fallback — a second
        // query against the same dead peer just pays the same timeout again.
        assert!(!is_unservable_root_error("request timed out"));
        assert!(!is_unservable_root_error("peer disconnected"));
        assert!(!is_unservable_root_error("connection reset by peer"));
    }

    #[test]
    fn account_absent_on_exclusion_proof() {
        let present_key = keccak256(b"some-other-account");
        let (state_root, proof) = single_leaf(&present_key, b"whatever");
        let address = [0x22u8; 20]; // keccak differs from present_key
        let response = AccountRange { request_id: 1, accounts: vec![], proof };
        assert_eq!(
            verify_account(&state_root, &address, &response).unwrap(),
            AccountOutcome::Absent
        );
    }

    #[test]
    fn account_invalid_proof_errors() {
        let address = [0x33u8; 20];
        let response = AccountRange {
            request_id: 1,
            accounts: vec![],
            proof: vec![vec![0xc0]], // a node that doesn't hash to the root
        };
        assert!(verify_account(&[0x99; 32], &address, &response).is_err());
    }

    #[test]
    fn storage_empty_root_is_zero_without_proof() {
        let account = AccountLeaf {
            nonce: 0,
            balance: Vec::new(),
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_CODE_HASH,
        };
        let response = StorageRanges { request_id: 1, slots: vec![], proof: vec![] };
        assert_eq!(verify_storage(&account, &[0x01; 32], &response).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn storage_value_from_proof() {
        let slot = [0x07u8; 32];
        let key = keccak256(&slot);
        let slot_value = rlp::encode_bytes(&[0x2a]); // rlp(42)
        let (storage_root, proof) = single_leaf(&key, &slot_value);
        let account = AccountLeaf {
            nonce: 0,
            balance: Vec::new(),
            storage_root,
            code_hash: EMPTY_CODE_HASH,
        };
        let response = StorageRanges {
            request_id: 1,
            slots: vec![StorageSlot { slot_hash: key, raw_trie_value: slot_value }],
            proof,
        };
        assert_eq!(verify_storage(&account, &slot, &response).unwrap(), vec![0x2a]);
    }

    #[test]
    fn bytecode_matches_hash() {
        let code = vec![0x60, 0x00, 0x60, 0x00];
        let h = keccak256(&code);
        assert_eq!(verify_bytecode(&h, &[code.clone()]), Some(code));
        assert_eq!(verify_bytecode(&[0x00; 32], &[vec![0x60]]), None);
    }
}
