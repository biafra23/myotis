//! `eth_call` state overrides: caller-supplied account state layered over the
//! verified state for the duration of ONE call.
//!
//! Why this is not a hole in the trust model. Everything else in this crate
//! answers "what IS true on chain", proven against a beacon-anchored state
//! root. An override answers a different question — "what WOULD this call
//! return if these accounts looked like this" — and the caller is the one
//! supplying the hypothesis. Nothing here is presented as chain data, and the
//! layer lives for one call: it is never cached, never persisted, and cannot
//! reach the proof or bytecode caches (see `OracleDatabase`, which consults
//! overrides ahead of them and never writes an overridden value back).
//!
//! Wallets depend on this. Ambire (and so Kohaku) reads account state through
//! a helper contract it never deploys: it calls a magic address and supplies
//! the helper's bytecode as an override. A node that ignores the parameter
//! answers a well-formed result computed against different state, which the
//! caller cannot distinguish from a real one — see issue #314.
//!
//! Semantics follow geth's `StateOverride`:
//! - `code`, `balance`, `nonce` replace those fields.
//! - `state` replaces the account's storage ENTIRELY — any slot not listed
//!   reads as zero, without touching the chain.
//! - `state_diff` overlays individual slots, leaving the rest to fall through
//!   to verified state.
//! - `state` and `state_diff` are mutually exclusive per account; when both are
//!   present `state` wins (the stricter reading — never fall through).

use std::collections::HashMap;

use revm::primitives::U256;

/// One account's override. Every field is optional; an all-`None` entry still
/// forces the account to EXIST (geth does the same), which matters for a call
/// to an address that has no on-chain account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountOverride {
    pub code: Option<Vec<u8>>,
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    /// Full storage replacement — unlisted slots read as zero.
    pub state: Option<HashMap<U256, U256>>,
    /// Per-slot overlay; unlisted slots fall through to verified state.
    pub state_diff: HashMap<U256, U256>,
}

impl AccountOverride {
    /// The value this override dictates for `slot`, and whether it is
    /// authoritative. `Some(v)` = use `v` and do NOT consult the chain;
    /// `None` = fall through.
    pub fn storage(&self, slot: U256) -> Option<U256> {
        if let Some(full) = &self.state {
            // Full replacement: an absent slot is zero, not a fall-through.
            return Some(full.get(&slot).copied().unwrap_or(U256::ZERO));
        }
        self.state_diff.get(&slot).copied()
    }
}

/// The override set for one call. Empty is the overwhelmingly common case and
/// costs a single `is_empty` check on the hot path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateOverrides {
    accounts: HashMap<[u8; 20], AccountOverride>,
}

impl StateOverrides {
    pub fn new() -> StateOverrides {
        StateOverrides::default()
    }

    pub fn insert(&mut self, address: [u8; 20], over: AccountOverride) {
        self.accounts.insert(address, over);
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn get(&self, address: &[u8; 20]) -> Option<&AccountOverride> {
        self.accounts.get(address)
    }

    /// Overridden code whose keccak matches `hash`, if any. revm resolves code
    /// by hash when an `AccountInfo` carries one, so an overridden account's
    /// bytecode has to be reachable that way too.
    pub fn code_by_hash(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.accounts.values().find_map(|a| {
            let code = a.code.as_deref()?;
            (myotis_core::keccak::keccak256(code) == *hash).then_some(code)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u64) -> U256 {
        U256::from(n)
    }

    #[test]
    fn state_diff_overlays_and_falls_through() {
        let mut o = AccountOverride::default();
        o.state_diff.insert(slot(1), U256::from(42));
        assert_eq!(o.storage(slot(1)), Some(U256::from(42)));
        // Unlisted slot: the caller said nothing about it, so the chain answers.
        assert_eq!(o.storage(slot(2)), None);
    }

    #[test]
    fn full_state_replacement_zeroes_unlisted_slots() {
        let mut map = HashMap::new();
        map.insert(slot(1), U256::from(7));
        let o = AccountOverride { state: Some(map), ..Default::default() };
        assert_eq!(o.storage(slot(1)), Some(U256::from(7)));
        // NOT a fall-through: `state` replaces the whole storage, so an unlisted
        // slot is provably zero for this call.
        assert_eq!(o.storage(slot(2)), Some(U256::ZERO));
    }

    #[test]
    fn full_state_wins_over_state_diff() {
        let mut full = HashMap::new();
        full.insert(slot(1), U256::from(1));
        let mut o = AccountOverride { state: Some(full), ..Default::default() };
        o.state_diff.insert(slot(1), U256::from(2));
        o.state_diff.insert(slot(9), U256::from(3));
        assert_eq!(o.storage(slot(1)), Some(U256::from(1)));
        // The diff cannot re-open a slot the full replacement closed.
        assert_eq!(o.storage(slot(9)), Some(U256::ZERO));
    }

    #[test]
    fn code_is_addressable_by_its_keccak() {
        let code = vec![0x60u8, 0x00, 0x60, 0x00, 0xf3];
        let hash = myotis_core::keccak::keccak256(&code);
        let mut s = StateOverrides::new();
        s.insert([0x69; 20], AccountOverride { code: Some(code.clone()), ..Default::default() });
        assert_eq!(s.code_by_hash(&hash), Some(code.as_slice()));
        assert_eq!(s.code_by_hash(&[0xff; 32]), None);
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn empty_is_the_cheap_default() {
        let s = StateOverrides::new();
        assert!(s.is_empty());
        assert!(s.get(&[0x69; 20]).is_none());
        assert!(s.code_by_hash(&[0u8; 32]).is_none());
    }
}
