//! The verified-read trust anchor (EL-A7), twin of the Java
//! `node-core.VerifiedAccountQuery`/`VerifiedStorageQuery` ladder
//! (docs/reimplementation/04 §2.1, README §3). Ties a peer-served state root
//! to the beacon chain via `stateRootMatch` (fast path) or the `headerChain`
//! walk, producing the exact `verifyMethod`/`failReason` tokens the operator
//! tooling and integration tests grep for.
//!
//! The async header fetch is threaded in by the caller (EL-A7b) — this module
//! is the PURE decision logic: given the MPT-proof result, the anchor, and (for
//! the header-chain branch) the fetched header range, it yields the verdict.

use myotis_core::header::BlockHeader;

use super::anchor::ExecAnchor;

/// Same bound as the Java `MAX_HEADER_CHAIN_GAP` — the header-chain walk covers
/// at most 8192 blocks from the finalized block.
pub const MAX_HEADER_CHAIN_GAP: u64 = 8192;

/// The verification verdict for a state read. `verify_method` is set (and
/// `fail_reason` null) exactly when the state root is beacon-anchored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    pub beacon_chain_verified: bool,
    pub bls_verified: bool,
    /// The beacon slot the anchoring matched (finalized slot for headerChain).
    pub matched_slot: i64,
    /// `"stateRootMatch"` | `"headerChain"` | `None`.
    pub verify_method: Option<&'static str>,
    /// `None` when verified; else a stable token (`beaconNotSynced`,
    /// `headerChainGapTooLarge`, …).
    pub fail_reason: Option<&'static str>,
}

impl Verdict {
    fn verified(method: &'static str, slot: i64, bls: bool) -> Verdict {
        Verdict {
            beacon_chain_verified: true,
            bls_verified: bls,
            matched_slot: slot,
            verify_method: Some(method),
            fail_reason: None,
        }
    }

    fn failed(reason: &'static str) -> Verdict {
        Verdict {
            fail_reason: Some(reason),
            ..Verdict::default()
        }
    }
}

/// The next step after the pre-check: either a final verdict, or the
/// caller must fetch `[finalized_block ..= peer_block]` and call
/// [`header_chain_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderStep {
    /// A final verdict (stateRootMatch success, or an early failReason).
    Done(Verdict),
    /// Fetch the header range, then call [`header_chain_verdict`].
    NeedHeaderChain {
        finalized_block: u64,
        peer_block: u64,
        /// The beacon-finalized BLOCK HASH — the trust anchor the first fetched
        /// header must hash to.
        beacon_block_hash: [u8; 32],
        finalized_slot: i64,
    },
}

/// Run the verification ladder up to (but not including) the header fetch.
/// Mirrors `VerifiedAccountQuery.verify`'s decision tree exactly, token for
/// token. `peer_proof_valid` = "the MPT account/storage proof verified against
/// `peer_state_root`" (the caller runs the EL-A2 verifier first).
pub fn ladder_precheck(
    peer_state_root: Option<&[u8; 32]>,
    peer_proof_valid: bool,
    peer_block_number: i64,
    anchor: &ExecAnchor,
) -> LadderStep {
    // Fast path: the BLC has already attested the peer's exact state root.
    if let Some(root) = peer_state_root {
        if let Some(m) = anchor.find_state_root(root) {
            return LadderStep::Done(Verdict::verified(
                "stateRootMatch",
                m.slot as i64,
                m.bls_verified,
            ));
        }
    }

    // headerChain failure ladder — token order matches VerifiedAccountQuery.verify
    // EXACTLY (a reordering would change which failReason a caller/grep sees).
    if peer_state_root.is_none() {
        return LadderStep::Done(Verdict::failed("noPeerStateRoot"));
    }
    if !peer_proof_valid {
        return LadderStep::Done(Verdict::failed("peerProofInvalid"));
    }
    // is_synced() is derived from "have a finalized exec root", so past this
    // point finalized_execution() is Some (updates only add, never remove it).
    if !anchor.is_synced() {
        return LadderStep::Done(Verdict::failed("beaconNotSynced"));
    }
    if peer_block_number <= 0 {
        return LadderStep::Done(Verdict::failed("noPeerBlockNumber"));
    }
    let peer_block = peer_block_number as u64;
    let Some(fin) = anchor.finalized_execution() else {
        return LadderStep::Done(Verdict::failed("beaconBlockUnavailable"));
    };
    if fin.block_number == 0 {
        return LadderStep::Done(Verdict::failed("beaconBlockUnavailable"));
    }
    if peer_block <= fin.block_number {
        return LadderStep::Done(Verdict::failed("peerBlockBehindFinalized"));
    }
    if peer_block - fin.block_number > MAX_HEADER_CHAIN_GAP {
        return LadderStep::Done(Verdict::failed("headerChainGapTooLarge"));
    }
    LadderStep::NeedHeaderChain {
        finalized_block: fin.block_number,
        peer_block,
        beacon_block_hash: fin.block_hash,
        finalized_slot: anchor.finalized_slot() as i64,
    }
}

/// The verified header range `[finalized_block ..= peer_block]`, with each
/// header's `(hash, header)` (hash = keccak256 of the canonical RLP, computed
/// at decode by EL-A5).
pub struct ChainHeader {
    pub hash: [u8; 32],
    pub header: BlockHeader,
}

/// Verdict for the header-chain branch: verify the fetched range end-to-end and
/// return `headerChain` / `headerChainInvalid`. `beacon_block_hash` is the
/// finalized block HASH (must equal the FIRST header's keccak — the trust
/// anchor); `peer_state_root` is what the snap query used (must equal the LAST
/// header's state root).
pub fn header_chain_verdict(
    headers: &[ChainHeader],
    beacon_block_hash: &[u8; 32],
    peer_state_root: &[u8; 32],
    finalized_slot: i64,
) -> Verdict {
    if verify_header_chain(headers, beacon_block_hash, peer_state_root) {
        Verdict::verified("headerChain", finalized_slot, true)
    } else {
        Verdict::failed("headerChainInvalid")
    }
}

/// Pure verification of a contiguous header range (twin of
/// `VerifiedAccountQuery.verifyHeaderChain`):
/// 1. the FIRST header's HASH == the beacon-finalized block hash — THE trust
///    anchor. Must be the block HASH, not just the state root: the block hash
///    is `keccak256` of the whole header, so it pins the header completely,
///    whereas a state-root-only check lets a peer copy the PUBLIC finalized
///    state root into a fabricated `H_0'` and forge a chain to a fake root.
/// 2. the LAST header's state root == the peer-reported root (the query target);
/// 3. every consecutive pair links: `header[i].hash == header[i+1].parentHash`
///    (each hash being `keccak256(RLP)`, so the chain is peer-unforgeable).
pub fn verify_header_chain(
    headers: &[ChainHeader],
    expected_first_block_hash: &[u8; 32],
    expected_last_state_root: &[u8; 32],
) -> bool {
    if headers.is_empty() {
        return false;
    }
    if &headers[0].hash != expected_first_block_hash {
        return false;
    }
    if &headers[headers.len() - 1].header.state_root != expected_last_state_root {
        return false;
    }
    for pair in headers.windows(2) {
        if pair[0].hash != pair[1].header.parent_hash {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::header::{self, BlockHeader};
    use myotis_core::rlp::{self, Item};

    fn root(n: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = n;
        r
    }

    /// Build a header with a given number, state root and parent hash; returns
    /// its (hash, decoded header) as a ChainHeader.
    fn header(number: u64, state_root: [u8; 32], parent_hash: [u8; 32]) -> ChainHeader {
        let z32 = vec![0u8; 32];
        let rlp = rlp::encode(&Item::List(vec![
            Item::Bytes(parent_hash.to_vec()),
            Item::Bytes(z32.clone()), // ommers
            Item::Bytes(vec![0u8; 20]),
            Item::Bytes(state_root.to_vec()),
            Item::Bytes(z32.clone()), // txRoot
            Item::Bytes(z32.clone()), // receiptsRoot
            Item::Bytes(vec![0u8; 256]),
            Item::Bytes(Vec::new()), // difficulty
            Item::Bytes(rlp::u64_to_minimal_be(number)),
            Item::Bytes(rlp::u64_to_minimal_be(30_000_000)),
            Item::Bytes(Vec::new()),
            Item::Bytes(rlp::u64_to_minimal_be(1_700_000_000)),
            Item::Bytes(Vec::new()),
            Item::Bytes(z32),          // mixHash
            Item::Bytes(vec![0u8; 8]), // nonce
        ]));
        ChainHeader {
            hash: header::hash(&rlp),
            header: BlockHeader::decode(&rlp).unwrap(),
        }
    }

    #[test]
    fn valid_chain_verifies() {
        let h0 = header(100, root(0xa0), root(0xff)); // finalized
        let h1 = header(101, root(0xa1), h0.hash);
        let h2 = header(102, root(0xa2), h1.hash); // peer head
        let h0_hash = h0.hash;
        let chain = [h0, h1, h2];
        // Anchored by the FIRST header's block HASH, ending at the peer state root.
        assert!(verify_header_chain(&chain, &h0_hash, &root(0xa2)));
        // Wrong first (beacon) block hash, wrong last (peer) root, both rejected.
        assert!(!verify_header_chain(&chain, &root(0xbb), &root(0xa2)));
        assert!(!verify_header_chain(&chain, &h0_hash, &root(0xbb)));
    }

    #[test]
    fn forged_first_header_with_correct_state_root_is_rejected() {
        // THE attack: a fabricated H_0' that copies the public finalized state
        // root into its stateRoot field but is otherwise fake — its block HASH
        // differs from the trusted finalized block hash, so anchoring on the
        // hash rejects it (a state-root-only anchor would have accepted it).
        let real_h0 = header(100, root(0xa0), root(0xff));
        let forged_h0 = header(100, root(0xa0), root(0xde)); // same stateRoot, different parent → different hash
        assert_ne!(real_h0.hash, forged_h0.hash);
        let h1 = header(101, root(0xa1), forged_h0.hash);
        let chain = [forged_h0, h1];
        // Anchored on the REAL finalized block hash → the forged chain is rejected.
        assert!(!verify_header_chain(&chain, &real_h0.hash, &root(0xa1)));
    }

    #[test]
    fn broken_parent_link_rejected() {
        let h0 = header(100, root(0xa0), root(0xff));
        let h1 = header(101, root(0xa1), root(0xde)); // parent != h0.hash
        let h0_hash = h0.hash;
        let chain = [h0, h1];
        assert!(!verify_header_chain(&chain, &h0_hash, &root(0xa1)));
    }

    #[test]
    fn state_root_match_fast_path() {
        let anchor = ExecAnchor::new();
        anchor.record_state_root(50, root(7), true);
        match ladder_precheck(Some(&root(7)), true, 123, &anchor) {
            LadderStep::Done(v) => {
                assert_eq!(v.verify_method, Some("stateRootMatch"));
                assert_eq!(v.matched_slot, 50);
                assert!(v.beacon_chain_verified);
            }
            _ => panic!("expected stateRootMatch"),
        }
    }

    #[test]
    fn ladder_fail_tokens() {
        let anchor = ExecAnchor::new();
        // No peer state root at all.
        assert_eq!(
            fail(ladder_precheck(None, false, 0, &anchor)),
            Some("noPeerStateRoot")
        );
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), false, 100, &anchor)),
            Some("peerProofInvalid")
        );
        // Not synced = no finalized exec root yet.
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 100, &anchor)),
            Some("beaconNotSynced")
        );
        // Synced (a finalized exec root landed) but the peer reports no block.
        anchor.update_finalized(200, root(0xf0), 21_000_000, root(0xf1));
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 0, &anchor)),
            Some("noPeerBlockNumber")
        );
        // peer behind finalized.
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 20_999_999, &anchor)),
            Some("peerBlockBehindFinalized")
        );
        // gap too large.
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 21_000_000 + 8193, &anchor)),
            Some("headerChainGapTooLarge")
        );
        // in range → NeedHeaderChain, carrying the finalized BLOCK HASH.
        match ladder_precheck(Some(&root(1)), true, 21_000_100, &anchor) {
            LadderStep::NeedHeaderChain { finalized_block, peer_block, beacon_block_hash, .. } => {
                assert_eq!(finalized_block, 21_000_000);
                assert_eq!(peer_block, 21_000_100);
                assert_eq!(beacon_block_hash, root(0xf1)); // the finalized block hash
            }
            _ => panic!("expected NeedHeaderChain"),
        }
    }

    #[test]
    fn beacon_block_unavailable_when_finalized_number_zero() {
        // Synced (root present) but finalized block number 0 → beaconBlockUnavailable,
        // and crucially it's reported only AFTER the peer-block check (Java order).
        let anchor = ExecAnchor::new();
        anchor.update_finalized(1, root(0xf0), 0, root(0xf1));
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 100, &anchor)),
            Some("beaconBlockUnavailable")
        );
        // peer-block <= 0 still wins first.
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 0, &anchor)),
            Some("noPeerBlockNumber")
        );
    }

    fn fail(step: LadderStep) -> Option<&'static str> {
        match step {
            LadderStep::Done(v) => v.fail_reason,
            LadderStep::NeedHeaderChain { .. } => None,
        }
    }
}
