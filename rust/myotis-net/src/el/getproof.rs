//! `eth_getProof` (EIP-1186): the Merkle proofs the verified reads already
//! check, handed to the caller — at EXACTLY the block it names, or refused.
//!
//! The proofs are the ones every account and storage read fetches over snap
//! and verifies against a beacon-attested state root
//! (docs/snap-server-design.md, *Measured*): a single-key snap response
//! carries `trie.Prove(key)` plus a page of neighbours and the page's other
//! boundary path, and [`myotis_core::trie::verify_proof_path`] keeps only the
//! walk to the key — the list `eth_getProof` returns.
//!
//! **The pin rules.** An `eth_getProof` answer carries no block number and no
//! root, so a client checks it against the `stateRoot` of the block it asked
//! for. The other state reads answer a near-head number from HEAD state (the
//! documented trade-off, `RpcBlockWindow`); for a proof that would be a
//! well-formed answer that fails the client's check, indistinguishable from a
//! forged one. So a proof is served only at a root this node holds attested
//! for exactly the block named: the optimistic head (`latest`, `pending`, or
//! its number), one of the last [`RECENT_HEADS`] heads this node held that the
//! current head builds on (a number a client got from `eth_blockNumber` a few
//! blocks ago, or from a light client of its own a block behind — checked
//! through each head's proven parent hash, and where a skipped head breaks
//! that chain against one header window anchored at the current head, so a
//! head a sibling chain replaced never answers for its number:
//! `ExecAnchor::recent_head_at`, `ElReader::get_proof`), or the
//! beacon-finalized
//! block (`finalized`, or its number). Any other number is refused —
//! permanently below the head, which never comes back to it; retryably above
//! it, which the head may yet reach. No fallback to a peer's own head either,
//! the other reads' last resort: it is a different block.
//!
//! A block HASH (EIP-1898, #641) is served at the root of exactly the block it
//! names, placed among those same attested blocks by its hash in one read of
//! the anchor ([`crate::el::anchor::ExecAnchor::attested_block_of`]) — never
//! resolved to a number first and proven at whatever block holds that number
//! a moment later. A hash it does not place is declined retryably: a hash of a
//! block this node has not attested YET is one the head may still reach.

use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

use crate::el::anchor::{FinalizedExecution, RECENT_HEADS};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The most storage keys one `eth_getProof` may ask for. Each is a snap round
/// trip at one root, so the bound caps one request's fan-out; geth sets none,
/// and a call's storage reads (`eth_createAccessList`, then a proof per
/// account) stay far below it.
pub const MAX_PROOF_STORAGE_KEYS: usize = 1024;

/// Storage proofs one attempt keeps in flight on its peer — the slots of one
/// account at one root, as the EVM prefetch fans them out.
pub const PROOF_SLOTS_IN_FLIGHT: usize = 16;

/// The hedge delay for a proof of `distinct_keys` storage keys: the reads'
/// `base` per round of [`PROOF_SLOTS_IN_FLIGHT`] keys, but never more than a
/// third of the whole read's `budget`. An attempt is the WHOLE proof from one
/// peer, so a fixed delay would start a full duplicate on another peer every
/// `base` while a large proof is still arriving — and mark the earlier peers
/// outpaced when one finishes. A failed attempt (a silent peer's request
/// times out) still starts the next at once; the cap is for a peer that keeps
/// answering, slowly: past ~465 keys the uncapped delay would outlast the
/// budget, and such a peer would hold the read until it ran out with no
/// second peer ever asked.
pub fn proof_hedge_delay(
    base: std::time::Duration,
    distinct_keys: usize,
    budget: std::time::Duration,
) -> std::time::Duration {
    let rounds = distinct_keys.div_ceil(PROOF_SLOTS_IN_FLIGHT).max(1);
    base.saturating_mul(u32::try_from(rounds).unwrap_or(u32::MAX)).min(budget / 3)
}

/// The block an `eth_getProof` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBlock {
    /// `latest` / `pending` / absent: the optimistic head.
    Head,
    /// `finalized`: the beacon-finalized block.
    Finalized,
    /// A number: served only when it is the head's or the finalized block's.
    Number(u64),
    /// A block hash: served only when it is the hash of the head, of a recent
    /// head or of the finalized block, at that block's own attested root.
    Hash([u8; 32]),
}

/// Why no proof was served. Hosts answer [`ProofError::Refused`] with the
/// permanent -32602 and [`ProofError::Unavailable`] with the retryable -32000.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// No retry makes this request servable here.
    Refused(String),
    /// Not now: not synced, no peer holds the root, the block not reached yet.
    Unavailable(String),
}

/// The attested root a proof read runs at, and the block it is the root of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofTarget {
    pub block_number: u64,
    pub state_root: [u8; 32],
}

/// Resolve the block a request names to the root it is proven at, by the pin
/// rules above. `head` is the optimistic head's `(number, state_root)`, read
/// together; `finalized` the beacon-finalized block; `recent` the root of a
/// number among the recent heads (`ExecAnchor::optimistic_root_at`); `by_hash`
/// the `(number, state_root)` of a hash among the attested blocks
/// (`ExecAnchor::attested_block_of`) — all as the anchor holds them now.
pub fn resolve_target(
    block: ProofBlock,
    head: Option<(u64, [u8; 32])>,
    finalized: Option<FinalizedExecution>,
    recent: impl Fn(u64) -> Option<[u8; 32]>,
    by_hash: impl Fn(&[u8; 32]) -> Option<(u64, [u8; 32])>,
) -> Result<ProofTarget, ProofError> {
    let at_head = |(block_number, state_root): (u64, [u8; 32])| ProofTarget { block_number, state_root };
    let at_finalized = |fin: FinalizedExecution| ProofTarget {
        block_number: fin.block_number,
        state_root: fin.state_root,
    };
    match block {
        ProofBlock::Head => head
            .map(at_head)
            .ok_or_else(|| ProofError::Unavailable("beacon not synced: no verified head yet".into())),
        ProofBlock::Finalized => finalized.map(at_finalized).ok_or_else(|| {
            ProofError::Unavailable("no beacon-finalized execution block yet".into())
        }),
        // One lookup gives the number AND the root of the block the hash
        // names: there is no second read in which a reorg could put another
        // block at that number.
        ProofBlock::Hash(hash) => by_hash(&hash).map(at_head).ok_or_else(|| {
            ProofError::Unavailable(format!(
                "eth_getProof at block hash 0x{} is not served now: a proof is pinned to a state \
                 root this node holds attested for exactly that block — the last \
                 {RECENT_HEADS} heads it held, or the finalized block — and this hash is none \
                 of them (not yet, or no longer)",
                hex(&hash)
            ))
        }),
        ProofBlock::Number(n) => {
            if let Some(h) = head.filter(|&(number, _)| number == n) {
                return Ok(at_head(h));
            }
            if let Some(fin) = finalized.filter(|fin| fin.block_number == n) {
                return Ok(at_finalized(fin));
            }
            if let Some(root) = recent(n) {
                return Ok(at_head((n, root)));
            }
            let Some((head_number, _)) = head else {
                return Err(ProofError::Unavailable(format!(
                    "beacon not synced: no verified head to check block {n:#x} against"
                )));
            };
            if n > head_number {
                return Err(ProofError::Unavailable(format!(
                    "block {n:#x} ({n}) is ahead of the verified head ({head_number})"
                )));
            }
            let fin = finalized
                .map(|f| format!(", or the finalized block ({})", f.block_number))
                .unwrap_or_default();
            Err(ProofError::Refused(format!(
                "eth_getProof at block {n:#x} ({n}) is not served: a proof is pinned to a state \
                 root this node holds attested for exactly that block — the last {RECENT_HEADS} \
                 heads it held that the verified head ({head_number}) builds on{fin} — and a \
                 proof at another root would not verify against block {n}'s stateRoot"
            )))
        }
    }
}

/// Why a proof at `hash` — a block hash no attested block carries, which the
/// node placed at `number` all the same — is not served: refused for good when
/// that block is at or below the head (`head`), which never becomes attested
/// once passed, as a number there is refused; retryable above it, or with no
/// head to judge by.
pub fn unattested_hash(hash: &[u8; 32], number: u64, head: Option<u64>) -> ProofError {
    match head {
        Some(head) if number <= head => ProofError::Refused(format!(
            "eth_getProof at block hash 0x{} (block {number}) is not served: a proof is pinned to \
             a state root this node holds attested for exactly that block — the last \
             {RECENT_HEADS} heads it held, up to the verified head ({head}), or the finalized \
             block — and that block is none of them",
            hex(hash)
        )),
        _ => ProofError::Unavailable(format!(
            "eth_getProof at block hash 0x{} (block {number}) is not served now: the block is not \
             attested here yet",
            hex(hash)
        )),
    }
}

/// Whether a recent head at `number` that the anchor's ring does not link to
/// the current head (`ExecAnchor::recent_head_at`) can be confirmed by a header
/// window `[number ..= head]` anchored at the head: at or below the head, and
/// less than `lookback` blocks below it (the one-request window bound).
pub fn confirmable(number: u64, head: u64, lookback: u64) -> bool {
    number <= head && head - number < lookback
}

/// The root an unlinked recent head is served at, once a header window
/// anchored at the current head starts with `canonical` (the hash of the
/// canonical block at its number; `None` for an empty window): its own
/// attested root when it IS that block, else nothing — a sibling chain
/// replaced it, and its root would not verify against the canonical block.
pub fn confirmed_root(
    head: &crate::el::anchor::RecentHeadAt,
    canonical: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    (canonical == Some(head.hash)).then_some(head.state_root)
}

/// One storage key's proof: the key as asked (a 32-byte word), its minimal
/// big-endian value (empty = zero) and the root-first path under the account's
/// proven `storageRoot` (empty when the account has no storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProof {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub proof: Vec<Vec<u8>>,
}

/// A verified `eth_getProof` answer: every proof checked against `state_root`,
/// the attested root of block `block_number`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    pub address: [u8; 20],
    pub block_number: u64,
    pub state_root: [u8; 32],
    /// The proven leaf; an absent account reads as the empty account (zero
    /// nonce and balance, the empty trie's root, the empty code's hash), which
    /// is what its exclusion proof proves.
    pub account: AccountLeaf,
    pub account_proof: Vec<Vec<u8>>,
    /// One entry per requested key, in request order (repeats included).
    pub storage: Vec<StorageProof>,
}

/// The leaf an exclusion proof stands for.
pub fn empty_account() -> AccountLeaf {
    AccountLeaf {
        nonce: 0,
        balance: Vec::new(),
        storage_root: EMPTY_TRIE_ROOT,
        code_hash: EMPTY_CODE_HASH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: (u64, [u8; 32]) = (1_000, [0xaa; 32]);

    fn fin(block_number: u64) -> FinalizedExecution {
        FinalizedExecution {
            slot: 7,
            block_number,
            state_root: [0xff; 32],
            block_hash: [0xee; 32],
            timestamp: 0,
        }
    }

    /// No recent head remembered.
    fn none(_: u64) -> Option<[u8; 32]> {
        None
    }

    /// No block placed by hash.
    fn unplaced(_: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        None
    }

    #[test]
    fn tags_resolve_to_their_own_roots() {
        let t = resolve_target(ProofBlock::Head, Some(HEAD), Some(fin(936)), none, unplaced).unwrap();
        assert_eq!((t.block_number, t.state_root), (1_000, [0xaa; 32]));
        let t = resolve_target(ProofBlock::Finalized, Some(HEAD), Some(fin(936)), none, unplaced).unwrap();
        assert_eq!((t.block_number, t.state_root), (936, [0xff; 32]));
        // Not synced: retryable, for either tag.
        assert!(matches!(
            resolve_target(ProofBlock::Head, None, None, none, unplaced),
            Err(ProofError::Unavailable(_))
        ));
        assert!(matches!(
            resolve_target(ProofBlock::Finalized, Some(HEAD), None, none, unplaced),
            Err(ProofError::Unavailable(_))
        ));
    }

    #[test]
    fn a_number_is_served_only_at_a_root_attested_for_exactly_that_block() {
        let t = resolve_target(ProofBlock::Number(1_000), Some(HEAD), Some(fin(936)), none, unplaced).unwrap();
        assert_eq!((t.block_number, t.state_root), (1_000, [0xaa; 32]));
        let t = resolve_target(ProofBlock::Number(936), Some(HEAD), Some(fin(936)), none, unplaced).unwrap();
        assert_eq!((t.block_number, t.state_root), (936, [0xff; 32]));
        // Just behind the head: inside the other reads' window, but a proof
        // at head state would not verify against this block — refused for good.
        let Err(ProofError::Refused(why)) =
            resolve_target(ProofBlock::Number(999), Some(HEAD), Some(fin(936)), none, unplaced)
        else {
            panic!("a number below the head that is not finalized must be refused");
        };
        assert!(why.contains("(1000)") && why.contains("(936)"), "{why}");
        // Below finality too.
        assert!(matches!(
            resolve_target(ProofBlock::Number(10), Some(HEAD), None, none, unplaced),
            Err(ProofError::Refused(_))
        ));
        // Ahead of the head: the head may yet reach it.
        assert!(matches!(
            resolve_target(ProofBlock::Number(1_001), Some(HEAD), Some(fin(936)), none, unplaced),
            Err(ProofError::Unavailable(_))
        ));
        // No head to judge a number against: retryable, even when the number
        // is no finalized block either.
        assert!(matches!(
            resolve_target(ProofBlock::Number(5), None, Some(fin(936)), none, unplaced),
            Err(ProofError::Unavailable(_))
        ));
        // ...but the finalized block's own number is servable without a head.
        assert!(resolve_target(ProofBlock::Number(936), None, Some(fin(936)), none, unplaced).is_ok());
        // A recent head this node held (a client pinned the number it got a
        // block ago) is served at the root attested for it.
        let recent = |n: u64| (n == 999).then_some([0x99; 32]);
        let t = resolve_target(ProofBlock::Number(999), Some(HEAD), Some(fin(936)), recent, unplaced).unwrap();
        assert_eq!((t.block_number, t.state_root), (999, [0x99; 32]));
        // The head and the finalized block still take precedence.
        let any = |_: u64| Some([0x11; 32]);
        let t = resolve_target(ProofBlock::Number(1_000), Some(HEAD), Some(fin(936)), any, unplaced).unwrap();
        assert_eq!(t.state_root, [0xaa; 32]);
        let t = resolve_target(ProofBlock::Number(936), Some(HEAD), Some(fin(936)), any, unplaced).unwrap();
        assert_eq!(t.state_root, [0xff; 32]);
    }

    #[test]
    fn a_hash_is_served_only_at_the_root_attested_for_the_block_it_names() {
        // A hash the anchor places: that block's number and its own root, in
        // one lookup — even where the head or a recent head holds another root.
        let placed = |h: &[u8; 32]| (h == &[0x77; 32]).then_some((999, [0x99; 32]));
        let any = |_: u64| Some([0x11; 32]);
        let t = resolve_target(ProofBlock::Hash([0x77; 32]), Some(HEAD), Some(fin(936)), any, placed)
            .unwrap();
        assert_eq!((t.block_number, t.state_root), (999, [0x99; 32]));
        // Placed even with no head to judge numbers against.
        assert!(resolve_target(ProofBlock::Hash([0x77; 32]), None, None, none, placed).is_ok());
        // A hash it does not place: retryable (the head may yet reach it), and
        // never answered at the head's or a recent head's root.
        let Err(ProofError::Unavailable(why)) =
            resolve_target(ProofBlock::Hash([0x55; 32]), Some(HEAD), Some(fin(936)), any, placed)
        else {
            panic!("an unplaced hash must be declined retryably");
        };
        assert!(why.contains(&"55".repeat(32)), "{why}");
    }

    #[test]
    fn an_unattested_hash_is_refused_like_its_number() {
        // At or below the head: never attested once passed — permanent, by name.
        let Some(ProofError::Refused(why)) = Some(unattested_hash(&[0x44; 32], 990, Some(1_000))) else {
            panic!("a placed hash below the head must be refused for good");
        };
        assert!(why.contains(&"44".repeat(32)) && why.contains("(block 990)") && why.contains("(1000)"), "{why}");
        // A fork block at the head's own height is no attested block either.
        assert!(matches!(unattested_hash(&[0x44; 32], 1_000, Some(1_000)), ProofError::Refused(_)));
        // Above the head, or with no head: the head may yet reach it.
        assert!(matches!(unattested_hash(&[0x44; 32], 1_001, Some(1_000)), ProofError::Unavailable(_)));
        assert!(matches!(unattested_hash(&[0x44; 32], 5, None), ProofError::Unavailable(_)));
    }

    #[test]
    fn an_unlinked_recent_head_is_served_only_while_it_is_the_canonical_block() {
        use crate::el::anchor::RecentHeadAt;
        let head = RecentHeadAt { hash: [0x11; 32], state_root: [0x22; 32], linked: false };
        // The window anchored at the current head starts with this very block.
        assert_eq!(confirmed_root(&head, Some([0x11; 32])), Some([0x22; 32]));
        // Another block holds the number now (a sibling chain replaced it), or
        // the window came back empty: never served at this head's root.
        assert_eq!(confirmed_root(&head, Some([0x33; 32])), None);
        assert_eq!(confirmed_root(&head, None), None);
    }

    #[test]
    fn only_a_number_one_window_below_the_head_can_be_confirmed() {
        assert!(confirmable(990, 1_000, 512));
        assert!(confirmable(1_000, 1_000, 512));
        assert!(confirmable(489, 1_000, 512));
        // Past the window bound, or above the head: nothing to confirm against.
        assert!(!confirmable(488, 1_000, 512));
        assert!(!confirmable(1_001, 1_000, 512));
    }

    #[test]
    fn the_hedge_waits_one_base_delay_per_round_of_keys_within_a_third_of_the_budget() {
        let base = std::time::Duration::from_secs(3);
        let budget = std::time::Duration::from_secs(90);
        assert_eq!(proof_hedge_delay(base, 0, budget), base);
        assert_eq!(proof_hedge_delay(base, PROOF_SLOTS_IN_FLIGHT, budget), base);
        assert_eq!(proof_hedge_delay(base, PROOF_SLOTS_IN_FLIGHT + 1, budget), base * 2);
        // Ten rounds fit under the cap; the 1024-key cap (64 rounds) does not,
        // and still leaves room for two more attempts within the budget.
        assert_eq!(proof_hedge_delay(base, 10 * PROOF_SLOTS_IN_FLIGHT, budget), base * 10);
        assert_eq!(proof_hedge_delay(base, MAX_PROOF_STORAGE_KEYS, budget), budget / 3);
    }
}
