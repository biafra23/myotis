//! The pre-broadcast check of `eth_sendRawTransaction` (#531): a transaction
//! its sender cannot pay for, or whose nonce is already used, is never mined,
//! and the eth protocol sends no word back when a peer drops it. geth, Nethermind,
//! Besu and Reth refuse such a transaction before they answer, and wallets read
//! geth's words (ethers v6 and viem classify by message text). This module is
//! the pure half: geth's two txpool verdicts and the freshness rule that decides
//! whether state is new enough to judge by. The reader supplies the verified
//! account and the clock.
//!
//! The check fails OPEN. Anything that stops it from judging (an undecodable
//! transaction — a blob transaction's network form among them — an
//! unrecovered sender, another chain's transaction, a stale head, an
//! unreadable wall clock, Tor-routed reads, too many reads already in flight,
//! a slow account read or one not proven at the head's own root) broadcasts
//! the transaction as before: a node that lags the chain must never block a
//! send.

use std::time::Duration;

use myotis_evm::U256;

use crate::el::tx::TxSummary;

/// Slack on top of two block times before the head is too old to judge a send
/// by. A light client learns block N from block N+1's sync aggregate, so its
/// head is normally one to two blocks old, and the update reaches it a few
/// seconds into the slot after.
pub const FRESH_HEAD_GRACE: Duration = Duration::from_secs(6);

/// How long the check may wait for the sender's verified account. A verified
/// account read takes 0.1–0.8 s on a healthy pool (#531's log).
pub const ACCOUNT_READ_BUDGET: Duration = Duration::from_secs(2);

/// How long the read may run on, detached, after the check stopped waiting
/// for it: up to this rather than cut at [`ACCOUNT_READ_BUDGET`], since a read
/// cut mid-request can tear its peer's connection.
pub const DETACHED_READ_BUDGET: Duration = Duration::from_secs(20);

/// The most such reads in flight at once; past that a send goes unchecked
/// rather than pile reads onto slow peers (the fee computes' cap, #532).
pub const DETACHED_READS_MAX: usize = 4;

/// How old a head may be to judge a send by: two block times plus
/// [`FRESH_HEAD_GRACE`].
pub fn fresh_bound(block_time: Duration) -> Duration {
    2 * block_time + FRESH_HEAD_GRACE
}

/// Whether a head is fresh enough to judge a send by ([`fresh_bound`]): by
/// its proven timestamp (unix seconds) against the wall clock `now_unix` — a
/// head in the future, clock skew, counts as fresh — AND by how long ago this
/// node adopted it, on its own monotonic clock, which a wall clock set wrong
/// cannot fake: a stalled light client's head ages there whatever the wall
/// clock says.
pub fn head_is_fresh(now_unix: u64, head_timestamp: u64, adopted_ago: Duration, block_time: Duration) -> bool {
    let bound = fresh_bound(block_time);
    now_unix <= head_timestamp.saturating_add(bound.as_secs()) && adopted_ago <= bound
}

/// What the transaction may cost its sender at most: `value + gas × fee`, the
/// fee being the gas price (types 0 and 1) or the max fee per gas (types 2 and
/// 4), as geth's `tx.Cost()` reckons it. `None` for a blob transaction (type 3
/// also pays the blob fee, which the summary does not carry) and for fields
/// the summary lacks; the check then does not judge.
pub fn max_cost(tx: &TxSummary) -> Option<U256> {
    let fee = match tx.ty {
        0 | 1 => tx.gas_price?,
        2 | 4 => tx.max_fee_per_gas?,
        _ => return None,
    };
    let value = U256::try_from_be_slice(&tx.value)?;
    Some((U256::from(tx.gas) * U256::from(fee)).saturating_add(value))
}

/// geth's txpool verdict for `tx` against its sender's account, in geth's
/// order and words: `Some(message)` when the transaction can never be mined as
/// sent, `None` when it may be. A nonce above the account's is a gap a later
/// transaction fills (geth queues it). Each transaction is judged alone
/// against the balance: geth's pool also counts the sender's transactions it
/// already queued, which this node does not see, and a replacement at the
/// same nonce must still pass. A transaction whose cost is unknown (a decoded
/// blob transaction) is judged by its nonce only.
pub fn verdict(tx: &TxSummary, balance: U256, account_nonce: u64) -> Option<String> {
    if tx.nonce < account_nonce {
        return Some(format!("nonce too low: next nonce {account_nonce}, tx nonce {}", tx.nonce));
    }
    let cost = max_cost(tx)?;
    (balance < cost).then(|| {
        format!(
            "insufficient funds for gas * price + value: balance {balance}, tx cost {cost}, overshot {}",
            cost - balance
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A summary of a type-`ty` transaction: nonce 5, 21 000 gas at 10 wei,
    /// value 1 000 — a maximum cost of 211 000.
    fn tx(ty: u8) -> TxSummary {
        let (gas_price, max_fee) = if ty < 2 { (Some(10), None) } else { (None, Some(10)) };
        TxSummary {
            ty,
            chain_id: Some(1),
            nonce: 5,
            to: Some([0x22; 20]),
            gas_price,
            max_priority_fee_per_gas: max_fee.map(|_| 1),
            max_fee_per_gas: max_fee,
            gas: 21_000,
            value: vec![0x03, 0xe8],
            input: Vec::new(),
            v: 0,
            r: [1; 32],
            s: [2; 32],
            from: Some([0x11; 20]),
        }
    }

    #[test]
    fn the_cost_is_value_plus_gas_at_the_highest_fee() {
        for ty in [0, 1, 2, 4] {
            assert_eq!(max_cost(&tx(ty)), Some(U256::from(211_000u64)), "type {ty}");
        }
        // A blob transaction also pays a blob fee the summary does not carry.
        assert_eq!(max_cost(&tx(3)), None);
    }

    #[test]
    fn a_balance_one_wei_short_of_the_cost_is_insufficient_funds() {
        // #531's acceptance: 1 wei above and below the maximum cost, for
        // types 0, 2 and 4, in geth's words (wallets classify by them).
        for ty in [0, 2, 4] {
            assert_eq!(
                verdict(&tx(ty), U256::from(210_999u64), 5).as_deref(),
                Some("insufficient funds for gas * price + value: balance 210999, tx cost 211000, overshot 1"),
                "type {ty}"
            );
            assert_eq!(verdict(&tx(ty), U256::from(211_000u64), 5), None, "type {ty}: exactly the cost");
            assert_eq!(verdict(&tx(ty), U256::from(211_001u64), 5), None, "type {ty}");
        }
    }

    #[test]
    fn a_used_nonce_is_too_low_and_a_gap_is_not_an_error() {
        let tx = tx(2);
        assert_eq!(verdict(&tx, U256::MAX, 6).as_deref(), Some("nonce too low: next nonce 6, tx nonce 5"));
        // The account's next nonce: a new transaction, or a replacement.
        assert_eq!(verdict(&tx, U256::MAX, 5), None);
        // A gap: geth queues it, and wallets send several in a row.
        assert_eq!(verdict(&tx, U256::MAX, 2), None);
    }

    #[test]
    fn a_used_nonce_is_reported_before_the_funds() {
        // geth's order: the nonce, then the balance.
        assert!(verdict(&tx(2), U256::ZERO, 9).is_some_and(|m| m.starts_with("nonce too low")));
    }

    #[test]
    fn a_blob_transaction_is_judged_by_its_nonce_only() {
        assert!(verdict(&tx(3), U256::ZERO, 9).is_some());
        assert_eq!(verdict(&tx(3), U256::ZERO, 5), None, "its cost is unknown, so its funds are not judged");
    }

    #[test]
    fn a_head_is_fresh_for_two_block_times_and_the_grace() {
        let slot = Duration::from_secs(12);
        let head = 1_700_000_000;
        let just = Duration::from_secs(1);
        // A light client's head is normally one to two blocks old.
        assert!(head_is_fresh(head + 12, head, just, slot));
        assert!(head_is_fresh(head + 30, head, just, slot), "2 × 12 s + 6 s");
        assert!(!head_is_fresh(head + 31, head, just, slot));
        // Gnosis: 5 s blocks.
        assert!(head_is_fresh(head + 16, head, just, Duration::from_secs(5)));
        assert!(!head_is_fresh(head + 17, head, just, Duration::from_secs(5)));
        // A clock behind the chain's.
        assert!(head_is_fresh(head - 3, head, just, slot));
    }

    #[test]
    fn a_wrong_wall_clock_cannot_pass_a_stalled_head_as_fresh() {
        // The wall clock says the head is 10 s old, but this node adopted it a
        // minute ago and has heard of no newer one: its light client stalled.
        let slot = Duration::from_secs(12);
        assert!(!head_is_fresh(1_700_000_010, 1_700_000_000, Duration::from_secs(60), slot));
        assert!(head_is_fresh(1_700_000_010, 1_700_000_000, Duration::from_secs(30), slot));
    }
}
