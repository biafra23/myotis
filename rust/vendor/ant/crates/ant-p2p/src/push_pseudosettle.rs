//! Cheque-less pushsync settlement: mirror push debt into the shared
//! [`Accounting`] so the pseudosettle driver refreshes upload peers.
//!
//! Perf-lab **Experiment 1** (the 512 MiB stall). Without a chequebook
//! the daemon has NO settlement on the push path at all: the only
//! [`PushsyncSettlement`] implementation was the SWAP service, and the
//! pseudosettle driver's scan covers retrieval debt (the `Accounting`
//! mirror) only. Bee meanwhile debits us for every pushed chunk in the
//! same per-peer ledger it uses for retrieval; once our unsettled debt
//! crosses its payment threshold + tolerance, it answers with
//! overdrafts and RSTs. Measured baseline signature (2026-07-05):
//! within one 256 MiB upload, throughput decayed 370 → ~145 KiB/s as
//! debt accumulated — extrapolating to the documented "uploads run for
//! ~20 K chunks then stall" failure at 512 MiB. Connection churn
//! partially masks it (bee resets per-peer accounting on reconnect),
//! which is why smaller uploads look healthy.
//!
//! Bee's own light nodes settle upload debt **time-based** via
//! `/swarm/pseudosettle` — no cheques, no chain, no BZZ. Ant already
//! runs the full pseudosettle driver for retrieval; this adapter just
//! records push debits in the same `Accounting` mirror, from which the
//! driver reads, every tick, which peers a refresh is due to
//! (`Accounting::refresh_due`).
//!
//! DEFAULT ON since the perf-lab verdict (collapse-to-zero became a
//! stable plateau; see PERF-LAB.md exp 1). `ANT_PUSH_PSEUDOSETTLE=0`
//! disables it on a node without a chequebook (the A/B control arm).
//!
//! With a chequebook it is how uploads pay, too (issue #127): the
//! mirror is bee's one balance per peer, so the payer installed in it
//! (`PushsyncSwap`, while `swap-enable` is on and the chequebook has
//! funds) settles push debt exactly as it settles retrieval debt — the
//! refresh first, then a cheque priced `units × exchange + deduction`
//! once the debt reaches the early-payment threshold. See
//! `behaviour::push_settlement`.
//!
//! Like bee's pushsync client, every push first reserves its price in
//! the mirror (`PrepareCredit`, [`Accounting::try_reserve`]); a peer the
//! push would take past its disconnect limit is refused, and the fetcher
//! pushes to the next-closest peer instead (issue #128). Reserving runs
//! the mirror's settle step, so a cheque that is due starts before the
//! push, not after. A receipt applies the reservation, past the limit
//! too if the debt grew meanwhile, since the push has happened (PR #126
//! R1-M2); a push that ends without one releases it.

use ant_retrieval::accounting::Accounting;
use ant_retrieval::{PushCredit, PushsyncSettlement};
use libp2p::PeerId;
use std::sync::Arc;

/// Adapter: push debits → the shared retrieval `Accounting` mirror.
pub struct PushPseudosettle(Arc<Accounting>);

impl PushPseudosettle {
    #[must_use]
    pub fn new(accounting: Arc<Accounting>) -> Self {
        Self(accounting)
    }

    /// Default ON; `ANT_PUSH_PSEUDOSETTLE=0`/`false` opts out (the
    /// A/B control arm).
    #[must_use]
    pub fn enabled_by_env() -> bool {
        match std::env::var("ANT_PUSH_PSEUDOSETTLE") {
            Err(_) => true,
            Ok(v) => {
                let v = v.trim();
                !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
            }
        }
    }
}

impl PushsyncSettlement for PushPseudosettle {
    fn prepare_credit(&self, peer: PeerId, price: u64) -> Option<PushCredit> {
        self.0.try_reserve(peer, price).map(PushCredit::new)
    }

    fn forget(&self, peer: &PeerId) {
        self.0.forget(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_retrieval::accounting::OVERDRAFT_LIMIT;

    /// Bee's `PrepareCredit` for pushes: a push is admitted only while
    /// the mirror's expected debt (applied and reserved) stays inside the
    /// peer's disconnect limit; an applied receipt is debited, a dropped
    /// credit releases its reservation (issue #128).
    #[test]
    fn pushes_reserve_credit_and_are_refused_past_the_limit() {
        let acc = Arc::new(Accounting::new());
        let settle = PushPseudosettle::new(acc.clone());
        let peer = PeerId::random();
        let price = 100_000;
        let fit = OVERDRAFT_LIMIT / price;
        let mut held: Vec<PushCredit> = (0..fit)
            .map(|_| {
                settle
                    .prepare_credit(peer, price)
                    .expect("inside the limit")
            })
            .collect();
        assert_eq!(acc.debug_snapshot(&peer), Some((0, fit * price)));
        assert!(
            settle.prepare_credit(peer, price).is_none(),
            "one more in-flight push would cross the disconnect limit",
        );
        // A receipt moves its reservation into the balance; a failed push
        // releases its reservation.
        held.pop().expect("held").apply();
        drop(held.pop());
        assert_eq!(acc.debug_snapshot(&peer), Some((price, (fit - 2) * price)));
        assert!(settle.prepare_credit(peer, price).is_some(), "credit freed");
        // A different peer is unaffected.
        assert!(settle.prepare_credit(PeerId::random(), price).is_some());
        // Every receipt is recorded (PR #126 R1-M2): the push happened.
        for credit in held {
            credit.apply();
        }
        assert_eq!(acc.debug_snapshot(&peer), Some(((fit - 1) * price, 0)));
    }
}
