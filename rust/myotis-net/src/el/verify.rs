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
/// at most 8192 headers, the read block and its attested anchor included.
pub const MAX_HEADER_CHAIN_GAP: u64 = 8192;

/// The verification verdict for a state read. `verify_method` is set (and
/// `fail_reason` null) exactly when the state root is beacon-anchored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    pub beacon_chain_verified: bool,
    pub bls_verified: bool,
    /// The beacon slot the anchoring matched (for headerChain, the slot that
    /// attested the walk's anchor block).
    pub matched_slot: i64,
    /// `"stateRootMatch"` | `"headerChain"` | `None`.
    pub verify_method: Option<&'static str>,
    /// `None` when verified; else a stable token (`beaconNotSynced`,
    /// `headerChainGapTooLarge`, …).
    pub fail_reason: Option<&'static str>,
    /// The read block's own timestamp (unix seconds) when the verdict proved
    /// its whole header: a headerChain walk STARTS at the read block, which
    /// its child's parent hash pins all the way down from the attested anchor.
    /// `None` for every other verdict — a stateRootMatch proves the root, not
    /// a header.
    pub block_timestamp: Option<u64>,
}

impl Verdict {
    fn verified(method: &'static str, slot: i64, bls: bool) -> Verdict {
        Verdict {
            beacon_chain_verified: true,
            bls_verified: bls,
            matched_slot: slot,
            verify_method: Some(method),
            fail_reason: None,
            block_timestamp: None,
        }
    }

    fn failed(reason: &'static str) -> Verdict {
        Verdict {
            fail_reason: Some(reason),
            ..Verdict::default()
        }
    }
}

/// The verdict for a proof verified DIRECTLY against the beacon-finalized
/// state root (a finalized state read, ABI ≥ 32): `stateRootMatch` at the
/// finalized slot, BLS-verified — that root arrived in a sync-committee-signed
/// finality update (`ExecAnchor::update_finalized` records it as such), so no
/// ladder runs: there is nothing left for a header walk to prove.
pub fn finalized_root_verdict(finalized_slot: u64) -> Verdict {
    Verdict::verified("stateRootMatch", finalized_slot as i64, true)
}

/// The next step after the pre-check: either a final verdict, or the
/// caller must fetch `[peer_block ..= anchor_block]` and call
/// [`header_chain_verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderStep {
    /// A final verdict (stateRootMatch success, or an early failReason).
    Done(Verdict),
    /// Fetch the header range, then call [`header_chain_verdict`].
    NeedHeaderChain {
        /// The block the peer's state root belongs to: the FIRST header.
        peer_block: u64,
        /// The beacon-attested optimistic head at or above it: the LAST header.
        anchor_block: u64,
        /// `anchor_block`'s BLS-attested BLOCK HASH — the trust anchor the
        /// last fetched header must hash to.
        anchor_hash: [u8; 32],
        /// The beacon slot that attested `anchor_block`.
        anchor_slot: i64,
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
    // The freshness floor: state at or below finality is too old to answer
    // with (and its root, were it current, would have matched above).
    if peer_block <= fin.block_number {
        return LadderStep::Done(Verdict::failed("peerBlockBehindFinalized"));
    }
    // The walk ends at an attested block AT OR ABOVE the peer's, never below
    // it: a header's parent hash pins its parent, so an attested block pins
    // every header beneath it, while nothing pins a child — a walk upward
    // from an attested block accepts any header that names it as parent. So
    // the anchor is the optimistic head, and a peer block past it has nothing
    // attested above it yet.
    let Some((anchor_block, anchor_hash, anchor_slot)) =
        anchor.optimistic_anchor().filter(|&(number, _, _)| peer_block <= number)
    else {
        return LadderStep::Done(Verdict::failed("peerBlockAheadOfAnchor"));
    };
    if anchor_block - peer_block >= MAX_HEADER_CHAIN_GAP {
        return LadderStep::Done(Verdict::failed("headerChainGapTooLarge"));
    }
    LadderStep::NeedHeaderChain {
        peer_block,
        anchor_block,
        anchor_hash,
        anchor_slot: anchor_slot as i64,
    }
}

/// The verified header range `[peer_block ..= anchor_block]`, with each
/// header's `(hash, header)` (hash = keccak256 of the canonical RLP, computed
/// at decode by EL-A5).
pub struct ChainHeader {
    pub hash: [u8; 32],
    pub header: BlockHeader,
}

/// Verdict for the header-chain branch: verify the fetched range end-to-end and
/// return `headerChain` / `headerChainInvalid`. `anchor_hash` is the attested
/// anchor block's HASH (must equal the LAST header's keccak — the trust
/// anchor); `peer_state_root` is what the snap query used (must equal the
/// FIRST header's state root). A verified walk proves the first header whole,
/// so its timestamp rides along as the read block's.
pub fn header_chain_verdict(
    headers: &[ChainHeader],
    anchor_hash: &[u8; 32],
    peer_state_root: &[u8; 32],
    anchor_slot: i64,
) -> Verdict {
    if verify_header_chain(headers, anchor_hash, peer_state_root) {
        Verdict {
            block_timestamp: Some(headers[0].header.timestamp),
            ..Verdict::verified("headerChain", anchor_slot, true)
        }
    } else {
        Verdict::failed("headerChainInvalid")
    }
}

/// Pure verification of a contiguous header range (twin of
/// `VerifiedAccountQuery.verifyHeaderChain`):
/// 1. the LAST header's HASH == the attested anchor block hash — THE trust
///    anchor. It must be the block HASH, not just the state root: the hash is
///    `keccak256` of the whole header, so it pins that header completely,
///    whereas a state-root-only check lets a peer copy a PUBLIC attested
///    state root into a fabricated header.
/// 2. the FIRST header's state root == the peer-reported root (the query target);
/// 3. every consecutive pair links: `header[i].hash == header[i+1].parentHash`.
///
/// The anchor must be the NEWEST header. A parent hash commits a header to its
/// parent, never to its children, so trust flows only DOWN from the anchor:
/// the anchor pins its parent, which pins its own, and so on to the first
/// header. Anchored at the OLDEST header instead (as this walk once was),
/// nothing pins the headers above it — a peer could name the anchor as the
/// parent of a header it made up, with any state root, and pass.
pub fn verify_header_chain(
    headers: &[ChainHeader],
    expected_last_block_hash: &[u8; 32],
    expected_first_state_root: &[u8; 32],
) -> bool {
    if headers.is_empty() {
        return false;
    }
    if &headers[headers.len() - 1].hash != expected_last_block_hash {
        return false;
    }
    if &headers[0].header.state_root != expected_first_state_root {
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
        let h0 = header(100, root(0xa0), root(0xff)); // the peer's block
        let h1 = header(101, root(0xa1), h0.hash);
        let h2 = header(102, root(0xa2), h1.hash); // the attested anchor
        let h2_hash = h2.hash;
        let chain = [h0, h1, h2];
        // Anchored by the LAST header's block HASH, starting at the peer state root.
        assert!(verify_header_chain(&chain, &h2_hash, &root(0xa0)));
        // Wrong last (anchor) block hash, wrong first (peer) root: both rejected.
        assert!(!verify_header_chain(&chain, &root(0xbb), &root(0xa0)));
        assert!(!verify_header_chain(&chain, &h2_hash, &root(0xbb)));
        // A one-header walk is the anchor itself, at the peer's root.
        let alone = [header(102, root(0xa2), root(0xa1))];
        let alone_hash = alone[0].hash;
        assert!(verify_header_chain(&alone, &alone_hash, &root(0xa2)));
    }

    #[test]
    fn a_made_up_child_of_the_attested_block_is_rejected() {
        // THE attack the old upward walk let through: the walk anchored on the
        // OLDEST header, and a parent hash pins only a parent — so a peer named
        // the real attested block as the parent of a header it made up, with
        // any state root, and the chain verified. Anchored on the NEWEST
        // header, the made-up child would have to hash to the attested block.
        let attested = header(100, root(0xa0), root(0xff));
        let made_up = header(101, root(0x66), attested.hash);
        let attested_hash = attested.hash;
        let chain = [attested, made_up];
        assert!(!verify_header_chain(&chain, &attested_hash, &root(0x66)));
    }

    #[test]
    fn a_forged_anchor_header_with_the_attested_state_root_is_rejected() {
        // A fabricated stand-in for the anchor that copies its PUBLIC state
        // root but is otherwise fake: its block HASH differs from the attested
        // one, so anchoring on the hash rejects it.
        let real_anchor = header(101, root(0xa1), root(0xff));
        let peer_block = header(100, root(0xa0), root(0xee));
        let forged_anchor = header(101, root(0xa1), peer_block.hash);
        assert_ne!(real_anchor.hash, forged_anchor.hash);
        let chain = [peer_block, forged_anchor];
        assert!(!verify_header_chain(&chain, &real_anchor.hash, &root(0xa0)));
    }

    #[test]
    fn broken_parent_link_rejected() {
        let h0 = header(100, root(0xa0), root(0xff));
        let h1 = header(101, root(0xa1), root(0xde)); // parent != h0.hash
        let h1_hash = h1.hash;
        let chain = [h0, h1];
        assert!(!verify_header_chain(&chain, &h1_hash, &root(0xa0)));
    }

    #[test]
    fn a_verified_walk_dates_the_read_block_and_a_failed_one_nothing() {
        let h0 = header(100, root(0xa0), root(0xff));
        let h1 = header(101, root(0xa1), h0.hash);
        let h1_hash = h1.hash;
        let chain = [h0, h1];
        let v = header_chain_verdict(&chain, &h1_hash, &root(0xa0), 77);
        assert_eq!(v.verify_method, Some("headerChain"));
        assert_eq!(v.matched_slot, 77, "the slot that attested the anchor");
        assert_eq!(v.block_timestamp, Some(1_700_000_000), "the FIRST header's own timestamp");
        let bad = header_chain_verdict(&chain, &root(0xbb), &root(0xa0), 77);
        assert_eq!(bad.fail_reason, Some("headerChainInvalid"));
        assert_eq!(bad.block_timestamp, None);
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
                assert_eq!(v.block_timestamp, None, "a root match proves no header");
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
        anchor.update_finalized(200, root(0xf0), 21_000_000, root(0xf1), 0);
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 0, &anchor)),
            Some("noPeerBlockNumber")
        );
        // At or behind finality: below the freshness floor.
        for behind in [21_000_000, 20_999_999] {
            assert_eq!(
                fail(ladder_precheck(Some(&root(1)), true, behind, &anchor)),
                Some("peerBlockBehindFinalized")
            );
        }
        // Above finality with no optimistic head to anchor on.
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 21_000_001, &anchor)),
            Some("peerBlockAheadOfAnchor")
        );
        // Above the optimistic head: nothing attested above it yet.
        anchor.update_optimistic(264, 21_000_064, root(0xe1), root(0xe0), 0);
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 21_000_065, &anchor)),
            Some("peerBlockAheadOfAnchor")
        );
        // A walk longer than its bound (a stalled finality far below the head):
        // MAX headers, the anchor included, is the longest one allowed.
        anchor.update_optimistic(300, 21_009_000, root(0xd1), root(0xd0), 0);
        assert_eq!(
            fail(ladder_precheck(Some(&root(1)), true, 21_009_000 - 8192, &anchor)),
            Some("headerChainGapTooLarge")
        );
        assert!(matches!(
            ladder_precheck(Some(&root(1)), true, 21_009_000 - 8191, &anchor),
            LadderStep::NeedHeaderChain { .. }
        ));
    }

    #[test]
    fn the_walk_ends_at_the_optimistic_head_above_the_peer() {
        let anchor = ExecAnchor::new();
        anchor.update_finalized(200, root(0xf0), 21_000_000, root(0xf1), 0);
        anchor.update_optimistic(264, 21_000_064, root(0xe1), root(0xe0), 0);
        assert_eq!(
            ladder_precheck(Some(&root(1)), true, 21_000_010, &anchor),
            LadderStep::NeedHeaderChain {
                peer_block: 21_000_010,
                anchor_block: 21_000_064,
                anchor_hash: root(0xe1),
                anchor_slot: 264,
            }
        );
        // AT the optimistic head: a one-header walk against its own hash.
        assert!(matches!(
            ladder_precheck(Some(&root(1)), true, 21_000_064, &anchor),
            LadderStep::NeedHeaderChain { anchor_block: 21_000_064, peer_block: 21_000_064, .. }
        ));
    }

    #[test]
    fn beacon_block_unavailable_when_finalized_number_zero() {
        // Synced (root present) but finalized block number 0 → beaconBlockUnavailable,
        // and crucially it's reported only AFTER the peer-block check (Java order).
        let anchor = ExecAnchor::new();
        anchor.update_finalized(1, root(0xf0), 0, root(0xf1), 0);
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
