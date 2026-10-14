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
//! its number), one of the [`RECENT_HEADS`] heads before it as this node held
//! them (a number a client got from `eth_blockNumber` a few blocks ago, or
//! from a light client of its own a block behind), or the beacon-finalized
//! block (`finalized`, or its number). Any other number is refused —
//! permanently below the head, which never comes back to it; retryably above
//! it, which the head may yet reach. No fallback to a peer's own head either,
//! the other reads' last resort: it is a different block.

use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

use crate::el::anchor::{FinalizedExecution, RECENT_HEADS};

/// The most storage keys one `eth_getProof` may ask for. Each is a snap round
/// trip at one root, so the bound caps one request's fan-out; geth sets none,
/// and a call's storage reads (`eth_createAccessList`, then a proof per
/// account) stay far below it.
pub const MAX_PROOF_STORAGE_KEYS: usize = 1024;

/// Storage proofs one attempt keeps in flight on its peer — the slots of one
/// account at one root, as the EVM prefetch fans them out.
pub const PROOF_SLOTS_IN_FLIGHT: usize = 16;

/// The hedge delay for a proof of `distinct_keys` storage keys: the reads'
/// `base` per round of [`PROOF_SLOTS_IN_FLIGHT`] keys. An attempt is the WHOLE
/// proof from one peer, so a fixed delay would start a full duplicate on
/// another peer every `base` while a large proof is still arriving — and mark
/// the earlier peers outpaced when one finishes. A failed attempt still starts
/// the next at once; only a slow one waits this long for its hedge.
pub fn proof_hedge_delay(base: std::time::Duration, distinct_keys: usize) -> std::time::Duration {
    let rounds = distinct_keys.div_ceil(PROOF_SLOTS_IN_FLIGHT).max(1);
    base.saturating_mul(u32::try_from(rounds).unwrap_or(u32::MAX))
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
    /// Set when the root is the beacon-finalized block's: a peer that pruned
    /// it answers with an empty proof, a miss the race excuses.
    pub finalized: Option<FinalizedExecution>,
}

/// Resolve the block a request names to the root it is proven at, by the pin
/// rules above. `head` is the optimistic head's `(number, state_root)`, read
/// together; `finalized` the beacon-finalized block; `recent` the root of a
/// number among the recent heads (`ExecAnchor::optimistic_root_at`) — all as
/// the anchor holds them now.
pub fn resolve_target(
    block: ProofBlock,
    head: Option<(u64, [u8; 32])>,
    finalized: Option<FinalizedExecution>,
    recent: impl Fn(u64) -> Option<[u8; 32]>,
) -> Result<ProofTarget, ProofError> {
    let at_head = |(block_number, state_root): (u64, [u8; 32])| ProofTarget {
        block_number,
        state_root,
        finalized: None,
    };
    let at_finalized = |fin: FinalizedExecution| ProofTarget {
        block_number: fin.block_number,
        state_root: fin.state_root,
        finalized: Some(fin),
    };
    match block {
        ProofBlock::Head => head
            .map(at_head)
            .ok_or_else(|| ProofError::Unavailable("beacon not synced: no verified head yet".into())),
        ProofBlock::Finalized => finalized.map(at_finalized).ok_or_else(|| {
            ProofError::Unavailable("no beacon-finalized execution block yet".into())
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
                 root this node holds attested for exactly that block — the verified head \
                 ({head_number}), the {RECENT_HEADS} heads before it as this node held them{fin} — \
                 and a proof at another root would not verify against block {n}'s stateRoot"
            )))
        }
    }
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

    #[test]
    fn tags_resolve_to_their_own_roots() {
        let t = resolve_target(ProofBlock::Head, Some(HEAD), Some(fin(936)), none).unwrap();
        assert_eq!((t.block_number, t.state_root, t.finalized), (1_000, [0xaa; 32], None));
        let t = resolve_target(ProofBlock::Finalized, Some(HEAD), Some(fin(936)), none).unwrap();
        assert_eq!((t.block_number, t.state_root), (936, [0xff; 32]));
        assert_eq!(t.finalized, Some(fin(936)));
        // Not synced: retryable, for either tag.
        assert!(matches!(
            resolve_target(ProofBlock::Head, None, None, none),
            Err(ProofError::Unavailable(_))
        ));
        assert!(matches!(
            resolve_target(ProofBlock::Finalized, Some(HEAD), None, none),
            Err(ProofError::Unavailable(_))
        ));
    }

    #[test]
    fn a_number_is_served_only_at_a_root_attested_for_exactly_that_block() {
        let t = resolve_target(ProofBlock::Number(1_000), Some(HEAD), Some(fin(936)), none).unwrap();
        assert_eq!((t.state_root, t.finalized), ([0xaa; 32], None));
        let t = resolve_target(ProofBlock::Number(936), Some(HEAD), Some(fin(936)), none).unwrap();
        assert_eq!((t.state_root, t.finalized), ([0xff; 32], Some(fin(936))));
        // Just behind the head: inside the other reads' window, but a proof
        // at head state would not verify against this block — refused for good.
        let Err(ProofError::Refused(why)) =
            resolve_target(ProofBlock::Number(999), Some(HEAD), Some(fin(936)), none)
        else {
            panic!("a number below the head that is not finalized must be refused");
        };
        assert!(why.contains("(1000)") && why.contains("(936)"), "{why}");
        // Below finality too.
        assert!(matches!(
            resolve_target(ProofBlock::Number(10), Some(HEAD), None, none),
            Err(ProofError::Refused(_))
        ));
        // Ahead of the head: the head may yet reach it.
        assert!(matches!(
            resolve_target(ProofBlock::Number(1_001), Some(HEAD), Some(fin(936)), none),
            Err(ProofError::Unavailable(_))
        ));
        // No head to judge a number against: retryable, even when the number
        // is no finalized block either.
        assert!(matches!(
            resolve_target(ProofBlock::Number(5), None, Some(fin(936)), none),
            Err(ProofError::Unavailable(_))
        ));
        // ...but the finalized block's own number is servable without a head.
        assert!(resolve_target(ProofBlock::Number(936), None, Some(fin(936)), none).is_ok());
        // A recent head this node held (a client pinned the number it got a
        // block ago) is served at the root attested for it.
        let recent = |n: u64| (n == 999).then_some([0x99; 32]);
        let t = resolve_target(ProofBlock::Number(999), Some(HEAD), Some(fin(936)), recent).unwrap();
        assert_eq!((t.block_number, t.state_root, t.finalized), (999, [0x99; 32], None));
        // The head and the finalized block still take precedence.
        let any = |_: u64| Some([0x11; 32]);
        let t = resolve_target(ProofBlock::Number(1_000), Some(HEAD), Some(fin(936)), any).unwrap();
        assert_eq!(t.state_root, [0xaa; 32]);
        let t = resolve_target(ProofBlock::Number(936), Some(HEAD), Some(fin(936)), any).unwrap();
        assert_eq!(t.finalized, Some(fin(936)));
    }

    #[test]
    fn the_hedge_waits_one_base_delay_per_round_of_keys() {
        let base = std::time::Duration::from_secs(3);
        assert_eq!(proof_hedge_delay(base, 0), base);
        assert_eq!(proof_hedge_delay(base, PROOF_SLOTS_IN_FLIGHT), base);
        assert_eq!(proof_hedge_delay(base, PROOF_SLOTS_IN_FLIGHT + 1), base * 2);
        assert_eq!(
            proof_hedge_delay(base, MAX_PROOF_STORAGE_KEYS),
            base * (MAX_PROOF_STORAGE_KEYS / PROOF_SLOTS_IN_FLIGHT) as u32
        );
    }
}
