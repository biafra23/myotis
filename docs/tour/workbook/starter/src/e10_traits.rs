//! Exercise 10: traits, generics vs `dyn`, and a decorator.
//! Modelled on `SnapStateOracle` (myotis-evm/src/oracle.rs) and the
//! `Counting { inner, fetches }` test helper in myotis-evm/src/executor.rs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Option<u64>;

    /// A default method: implementors may override it.
    fn label(&self) -> String {
        "source".to_string()
    }
}

pub struct Fixture {
    pub balances: HashMap<[u8; 20], u64>,
}

impl StateSource for Fixture {
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        todo!("your code here")
    }
}

/// Wraps any source, counts calls, and forwards to `inner`.
pub struct Counting<S> {
    pub inner: S,
    pub calls: AtomicUsize,
}

impl<S: StateSource> StateSource for Counting<S> {
    /// Count the call (through `&self`!), then forward to `self.inner`.
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        todo!("your code here")
    }

    /// "counting(<inner label>)".
    fn label(&self) -> String {
        todo!("your code here")
    }
}

/// Static dispatch: compiled once per concrete `S`. `?Sized` also allows
/// `S = dyn StateSource`.
pub fn total<S: StateSource + ?Sized>(src: &S, addrs: &[[u8; 20]]) -> u64 {
    todo!("your code here")
}

/// Dynamic dispatch: the sources have different types, so they are trait
/// objects. Return the label and balance of the source that reports the most
/// for `address`, or `None` if none knows it.
pub fn richest(sources: &[&dyn StateSource], address: [u8; 20]) -> Option<(String, u64)> {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(v: u64) -> Fixture {
        Fixture { balances: HashMap::from([([1; 20], v)]) }
    }

    #[test]
    fn decorator_counts_and_forwards() {
        let c = Counting { inner: fixture(5), calls: AtomicUsize::new(0) };
        assert_eq!(total(&c, &[[1; 20], [2; 20]]), 5);
        assert_eq!(c.calls.load(Ordering::Relaxed), 2);
        assert_eq!(c.label(), "counting(source)");
    }

    #[test]
    fn dyn_mixes_types() {
        let a = fixture(5);
        let b = Counting { inner: fixture(9), calls: AtomicUsize::new(0) };
        let srcs: [&dyn StateSource; 2] = [&a, &b];
        assert_eq!(richest(&srcs, [1; 20]), Some(("counting(source)".to_string(), 9)));
        assert_eq!(richest(&srcs, [7; 20]), None);
        let as_dyn: &dyn StateSource = &a;
        assert_eq!(total(as_dyn, &[[1; 20]]), 5);
    }
}
