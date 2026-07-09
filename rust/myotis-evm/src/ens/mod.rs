//! ENS resolution (EL-C-5): forward `name → address` over verified `eth_call`s.
//!
//! Mirrors the Java `EnsResolver` direct registry-walk (NOT the Universal
//! Resolver): find the resolver for the name (or an ancestor, for ENSIP-10
//! wildcard), detect a wildcard/extended resolver via `supportsInterface`, then
//! call `addr(bytes32)` directly (legacy) or wrap it in `resolve(bytes,bytes)`
//! (ENSIP-10). Every step is an `eth_call` against verified state, abstracted
//! behind [`EthCaller`] so the walk is unit-testable without a node.
//!
//! Scope of this slice: forward address resolution only. Reverse + forward-verify
//! and CCIP-Read (`OffchainLookup`) offchain resolution are later slices — an
//! `OffchainLookup` revert surfaces as the distinguishable
//! [`EnsError::OffchainLookup`] (never folded into "no record"); driving the
//! gateway arrives with CCIP (EL-C-5-3).
//!
//! One deliberate divergence from the Java `EnsResolver`: a NON-revert failure
//! (state unavailable, halt) during the walk or `supportsInterface` probe
//! propagates as [`EnsError::Call`] here, where Java folds it into "keep
//! walking" / `false`. Failing closed is the safer contract — missing state must
//! never read as "name unregistered".

mod abi;
mod name;

pub use name::{dns_encode, namehash};

use crate::block::BlockContext;
use crate::error::EvmError;
use crate::executor::EvmExecutor;

/// The ENS registry, identical on every EIP-137 network.
const REGISTRY: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x2E, 0x07, 0x4e, 0xC6, 0x9A, 0x0d, 0xFb, 0x29, 0x97, 0xBA,
    0x6C, 0x7d, 0x2e, 0x1e,
];

/// `IExtendedResolver` (ENSIP-10 wildcard) ERC-165 interface id.
const EXTENDED_RESOLVER_INTERFACE_ID: [u8; 4] = [0x90, 0x61, 0xb9, 0x23];

/// The ERC-3668 `OffchainLookup(address,string[],bytes,bytes4,bytes)` revert
/// selector — an offchain (CCIP-Read) name announcing itself.
const OFFCHAIN_LOOKUP_SELECTOR: [u8; 4] = [0x55, 0x6f, 0x18, 0x30];

/// An ENS resolution failure. `Ok(None)` from the resolver means "no record"
/// (absent name, zero address, non-wildcard ancestor); `EnsError` is a hard
/// failure — including an offchain name, which is DISTINGUISHABLE from "no
/// record" (mirrors the Java `decodeOutcome`, which rethrows an `OffchainLookup`
/// revert rather than folding it into empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsError {
    /// The name is malformed (empty/oversized label).
    InvalidName(&'static str),
    /// The resolver reverted with ERC-3668 `OffchainLookup`: the name resolves
    /// OFFCHAIN via a CCIP-Read gateway, which this engine doesn't drive yet
    /// (EL-C-5-3). Explicitly not "no record" — the record exists, offchain.
    OffchainLookup,
    /// A resolution `eth_call` failed for a non-revert reason (state unavailable,
    /// halt, unsupported chain). A plain revert is treated as "no record", not an
    /// error.
    Call(EvmError),
}

impl std::fmt::Display for EnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnsError::InvalidName(why) => write!(f, "invalid ENS name: {why}"),
            EnsError::OffchainLookup => write!(
                f,
                "name resolves offchain (ERC-3668 OffchainLookup); CCIP-Read not yet supported"
            ),
            EnsError::Call(e) => write!(f, "ENS resolution call failed: {e}"),
        }
    }
}

impl std::error::Error for EnsError {}

/// The verified-`eth_call` capability the resolver reads through. Implemented for
/// the real [`EvmExecutor`] via [`ExecutorCaller`]; mocked in tests.
pub trait EthCaller {
    /// A from-less view call to `target` with `calldata`. A revert surfaces as
    /// `Err(EvmError::Reverted { .. })` (the resolver treats that as "no record").
    fn eth_call(&self, target: [u8; 20], calldata: &[u8]) -> Result<Vec<u8>, EvmError>;
}

/// Binds an [`EvmExecutor`] + [`BlockContext`] as an [`EthCaller`] (anonymous
/// zero-sender view calls, which is what ENS registry/resolver reads are).
pub struct ExecutorCaller<'a> {
    pub executor: &'a EvmExecutor,
    pub ctx: &'a BlockContext,
}

impl EthCaller for ExecutorCaller<'_> {
    fn eth_call(&self, target: [u8; 20], calldata: &[u8]) -> Result<Vec<u8>, EvmError> {
        self.executor.call_view(target, calldata, self.ctx)
    }
}

struct ResolverInfo {
    resolver: [u8; 20],
    /// The resolver was found for the exact name (not an ancestor).
    exact: bool,
    /// The resolver implements `IExtendedResolver` (ENSIP-10 wildcard).
    extended: bool,
}

/// Resolve `name` to its ENS address record, or `Ok(None)` when there is no
/// (onchain) address record.
pub fn resolve_address(
    caller: &dyn EthCaller,
    name: &str,
) -> Result<Option<[u8; 20]>, EnsError> {
    let Some(info) = find_resolver(caller, name)? else {
        return Ok(None);
    };
    // A resolver found only for an ancestor can answer a subname ONLY if it is a
    // wildcard (ENSIP-10) resolver; a legacy ancestor resolver cannot.
    if !info.exact && !info.extended {
        return Ok(None);
    }

    let node = namehash(name);
    let inner = abi::encode_call_bytes32("addr(bytes32)", &node);
    // DNS-encode eagerly on BOTH paths (Java `dispatchResolve` parity): a
    // malformed name (empty / oversized label) is rejected even when the legacy
    // path wouldn't need the wire form.
    let dns = dns_encode(name)?;

    let raw = if info.extended {
        // ENSIP-10: resolver.resolve(dnsEncode(name), addr(node)) → bytes wrapping
        // the inner return.
        let call = abi::encode_resolve(&dns, &inner);
        match caller.eth_call(info.resolver, &call) {
            Ok(out) => match abi::decode_dynamic_bytes(&out, 0) {
                Some(unwrapped) => unwrapped,
                None => return Ok(None),
            },
            Err(EvmError::Reverted { data }) => return revert_outcome(&data),
            Err(e) => return Err(EnsError::Call(e)),
        }
    } else {
        // Legacy exact resolver: resolver.addr(node) directly.
        match caller.eth_call(info.resolver, &inner) {
            Ok(out) => out,
            Err(EvmError::Reverted { data }) => return revert_outcome(&data),
            Err(e) => return Err(EnsError::Call(e)),
        }
    };

    // A zero address is "no record", not an answer. decode_address is stricter
    // than the Java decoder (a dirty upper-12-byte word → None rather than
    // slicing the trailing 20) — deliberately fail-safe for a fund-destination.
    Ok(abi::decode_address(&raw).filter(|a| a != &[0u8; 20]))
}

/// Classify a resolver-call revert: an ERC-3668 `OffchainLookup` is a
/// distinguishable "resolves offchain" failure (never folded into "no record");
/// any other revert is "no record".
fn revert_outcome(data: &[u8]) -> Result<Option<[u8; 20]>, EnsError> {
    if data.len() >= 4 && data[..4] == OFFCHAIN_LOOKUP_SELECTOR {
        Err(EnsError::OffchainLookup)
    } else {
        Ok(None)
    }
}

/// Walk the registry from the full name up through its ancestors (the root node
/// itself is NOT queried — Java's `walkResolver` stops at the last label, and the
/// root has no resolver), returning the first non-zero resolver and whether it was
/// found for the exact name + is a wildcard resolver.
///
/// The walk splits like Java's `split("\\.")`: trailing empty labels are dropped
/// (interior ones kept), while [`namehash`] itself keeps them — the same
/// asymmetry as the Java engine, so both engines treat a trailing-dot name
/// identically (walk the trimmed suffixes, hash the raw name → "no record").
fn find_resolver(caller: &dyn EthCaller, name: &str) -> Result<Option<ResolverInfo>, EnsError> {
    let lower = name.to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    let labels: Vec<&str> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('.').collect()
    };

    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        let suffix_node = namehash(&suffix);
        let call = abi::encode_call_bytes32("resolver(bytes32)", &suffix_node);
        let out = match caller.eth_call(REGISTRY, &call) {
            Ok(out) => out,
            Err(EvmError::Reverted { .. }) => continue,
            Err(e) => return Err(EnsError::Call(e)),
        };
        if let Some(resolver) = abi::decode_address(&out).filter(|a| a != &[0u8; 20]) {
            let extended = supports_interface(caller, resolver, EXTENDED_RESOLVER_INTERFACE_ID)?;
            return Ok(Some(ResolverInfo { resolver, exact: i == 0, extended }));
        }
    }
    Ok(None)
}

/// ERC-165 `supportsInterface` — `false` on a revert (a non-165 resolver).
fn supports_interface(
    caller: &dyn EthCaller,
    resolver: [u8; 20],
    interface_id: [u8; 4],
) -> Result<bool, EnsError> {
    let call = abi::encode_supports_interface(interface_id);
    match caller.eth_call(resolver, &call) {
        Ok(out) => Ok(abi::decode_bool(&out)),
        Err(EvmError::Reverted { .. }) => Ok(false),
        Err(e) => Err(EnsError::Call(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A scripted [`EthCaller`]: each closure inspects (target, calldata) and
    /// returns a response, an error, or falls through to the next.
    struct MockCaller {
        #[allow(clippy::type_complexity)]
        handlers: Vec<Box<dyn Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>>>>,
        calls: RefCell<usize>,
    }

    impl MockCaller {
        fn new() -> MockCaller {
            MockCaller { handlers: Vec::new(), calls: RefCell::new(0) }
        }
        fn on(
            mut self,
            f: impl Fn([u8; 20], &[u8]) -> Option<Result<Vec<u8>, EvmError>> + 'static,
        ) -> Self {
            self.handlers.push(Box::new(f));
            self
        }
    }

    impl EthCaller for MockCaller {
        fn eth_call(&self, target: [u8; 20], calldata: &[u8]) -> Result<Vec<u8>, EvmError> {
            *self.calls.borrow_mut() += 1;
            for h in &self.handlers {
                if let Some(r) = h(target, calldata) {
                    return r;
                }
            }
            // Unmatched call → empty (decodes to zero address / false).
            Ok(vec![0u8; 32])
        }
    }

    fn sel(calldata: &[u8]) -> [u8; 4] {
        [calldata[0], calldata[1], calldata[2], calldata[3]]
    }
    fn addr_word(a: [u8; 20]) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    }
    fn bool_word(b: bool) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        if b {
            w[31] = 1;
        }
        w
    }
    fn revert() -> Result<Vec<u8>, EvmError> {
        Err(EvmError::Reverted { data: Vec::new() })
    }

    const RESOLVER: [u8; 20] = [0x44; 20];
    const VITALIK: [u8; 20] = [0xd8; 20];

    #[test]
    fn extended_resolver_id_is_the_resolve_selector() {
        // The IExtendedResolver ERC-165 id is defined as the `resolve(bytes,bytes)`
        // selector; lock the constant to it so an edit to either can't drift.
        assert_eq!(EXTENDED_RESOLVER_INTERFACE_ID, abi::selector("resolve(bytes,bytes)"));
    }

    #[test]
    fn offchain_lookup_selector_is_locked() {
        assert_eq!(
            OFFCHAIN_LOOKUP_SELECTOR,
            abi::selector("OffchainLookup(address,string[],bytes,bytes4,bytes)")
        );
    }

    #[test]
    fn offchain_lookup_revert_is_distinguishable_from_no_record() {
        let resolver_sel = abi::selector("resolver(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        let resolve_sel = abi::selector("resolve(bytes,bytes)");
        // A wildcard resolver that reverts with OffchainLookup(...) → the caller
        // must see EnsError::OffchainLookup, NOT Ok(None).
        let caller = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(|| Ok(bool_word(true))))
            .on(move |t, cd| {
                (t == RESOLVER && sel(cd) == resolve_sel).then(|| {
                    let mut data = OFFCHAIN_LOOKUP_SELECTOR.to_vec();
                    data.extend_from_slice(&[0u8; 32]); // truncated body — selector is enough
                    Err(EvmError::Reverted { data })
                })
            });
        assert_eq!(resolve_address(&caller, "offchain.eth"), Err(EnsError::OffchainLookup));
        // A plain revert stays "no record".
        let plain = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(revert))
            .on(move |t, _cd| (t == RESOLVER).then(revert));
        assert_eq!(resolve_address(&plain, "plain.eth"), Ok(None));
    }

    #[test]
    fn dirty_supports_interface_word_is_not_extended() {
        // A dirty word with a ZERO last byte must classify as legacy (Solidity
        // bool = last byte), so the resolver is still queried via addr().
        let resolver_sel = abi::selector("resolver(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        let addr_sel = abi::selector("addr(bytes32)");
        let caller = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| {
                (t == RESOLVER && sel(cd) == supports_sel).then(|| {
                    let mut dirty = vec![0u8; 32];
                    dirty[0] = 0xff; // non-zero high byte, zero last byte
                    Ok(dirty)
                })
            })
            .on(move |t, cd| (t == RESOLVER && sel(cd) == addr_sel).then(|| Ok(addr_word(VITALIK))));
        assert_eq!(resolve_address(&caller, "vitalik.eth").unwrap(), Some(VITALIK));
    }

    #[test]
    fn legacy_exact_resolver_resolves_addr() {
        let addr_sel = abi::selector("addr(bytes32)");
        let resolver_sel = abi::selector("resolver(bytes32)");
        let caller = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            // legacy resolver: supportsInterface reverts → not extended
            .on(move |t, cd| {
                (t == RESOLVER && sel(cd) == abi::selector("supportsInterface(bytes4)")).then(revert)
            })
            .on(move |t, cd| (t == RESOLVER && sel(cd) == addr_sel).then(|| Ok(addr_word(VITALIK))));
        let got = resolve_address(&caller, "vitalik.eth").unwrap();
        assert_eq!(got, Some(VITALIK));
    }

    #[test]
    fn wildcard_resolver_uses_ensip10_resolve() {
        let resolver_sel = abi::selector("resolver(bytes32)");
        let resolve_sel = abi::selector("resolve(bytes,bytes)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        // Registry: only the PARENT (eth) has a resolver → wildcard path.
        let caller = MockCaller::new()
            .on(move |t, cd| {
                if t != REGISTRY || sel(cd) != resolver_sel {
                    return None;
                }
                // resolver(namehash("vitalik.eth")) → 0 (no exact); resolver(namehash("eth")) → RESOLVER
                let node = &cd[4..36];
                if node == super::namehash("eth") {
                    Some(Ok(addr_word(RESOLVER)))
                } else {
                    Some(Ok(vec![0u8; 32])) // zero → keep walking
                }
            })
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(|| Ok(bool_word(true))))
            .on(move |t, cd| {
                // resolve(bytes,bytes) → bytes-wrapping the addr word
                (t == RESOLVER && sel(cd) == resolve_sel).then(|| {
                    // `resolve` returns `bytes` wrapping the inner addr return:
                    // offset(0x20) + length(0x20) + the addr word.
                    let mut o = vec![0u8; 32];
                    o[31] = 0x20;
                    let mut len = vec![0u8; 32];
                    len[31] = 0x20;
                    o.extend_from_slice(&len);
                    o.extend_from_slice(&addr_word(VITALIK));
                    Ok(o)
                })
            });
        let got = resolve_address(&caller, "vitalik.eth").unwrap();
        assert_eq!(got, Some(VITALIK));
    }

    #[test]
    fn no_resolver_is_none() {
        // Registry returns zero for every suffix → no resolver anywhere.
        let caller = MockCaller::new().on(|_t, _cd| Some(Ok(vec![0u8; 32])));
        assert_eq!(resolve_address(&caller, "nonexistent.eth").unwrap(), None);
    }

    #[test]
    fn non_wildcard_ancestor_cannot_resolve_subname() {
        let resolver_sel = abi::selector("resolver(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        // Resolver only at the parent, and it is NOT a wildcard resolver.
        let caller = MockCaller::new()
            .on(move |t, cd| {
                if t != REGISTRY || sel(cd) != resolver_sel {
                    return None;
                }
                let node = &cd[4..36];
                Some(Ok(if node == super::namehash("eth") {
                    addr_word(RESOLVER)
                } else {
                    vec![0u8; 32]
                }))
            })
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(revert)); // not extended
        assert_eq!(resolve_address(&caller, "sub.eth").unwrap(), None);
    }

    #[test]
    fn zero_address_record_is_none() {
        let resolver_sel = abi::selector("resolver(bytes32)");
        let addr_sel = abi::selector("addr(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        let caller = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(revert))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == addr_sel).then(|| Ok(vec![0u8; 32]))); // zero addr
        assert_eq!(resolve_address(&caller, "vitalik.eth").unwrap(), None);
    }
}
