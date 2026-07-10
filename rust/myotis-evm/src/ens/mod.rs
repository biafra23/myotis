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
    let node = namehash(name);
    let inner = abi::encode_call_bytes32("addr(bytes32)", &node);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    // A zero address is "no record", not an answer. decode_address is stricter
    // than the Java decoder (a dirty upper-12-byte word → None rather than
    // slicing the trailing 20) — deliberately fail-safe for a fund-destination.
    Ok(abi::decode_address(&raw).filter(|a| a != &[0u8; 20]))
}

/// Resolve a `text(bytes32,string)` record. `Ok(None)` = no record (absent
/// name/resolver, empty string — Java `decodeStringResult` parity).
pub fn resolve_text(
    caller: &dyn EthCaller,
    name: &str,
    key: &str,
) -> Result<Option<String>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32_string("text(bytes32,string)", &node, key);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_string(&raw).filter(|s| !s.is_empty()))
}

/// Resolve a `contenthash(bytes32)` record (raw multicodec bytes). `Ok(None)` =
/// no record (empty bytes).
pub fn resolve_contenthash(
    caller: &dyn EthCaller,
    name: &str,
) -> Result<Option<Vec<u8>>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32("contenthash(bytes32)", &node);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_dynamic_bytes(&raw, 0).filter(|b| !b.is_empty()))
}

/// Resolve an ENSIP-9 multi-coin `addr(bytes32,uint256)` record (raw
/// coin-specific address bytes). `Ok(None)` = no record (empty bytes).
pub fn resolve_multicoin(
    caller: &dyn EthCaller,
    name: &str,
    coin_type: u64,
) -> Result<Option<Vec<u8>>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32_u64("addr(bytes32,uint256)", &node, coin_type);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_dynamic_bytes(&raw, 0).filter(|b| !b.is_empty()))
}

/// Resolve a `pubkey(bytes32)` record — a fixed `(bytes32 x, bytes32 y)` tuple,
/// NO dynamic offsets. `Ok(None)` = no record (short return or both words zero).
pub fn resolve_pubkey(
    caller: &dyn EthCaller,
    name: &str,
) -> Result<Option<([u8; 32], [u8; 32])>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32("pubkey(bytes32)", &node);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_two_words(&raw).filter(|(x, y)| x != &[0u8; 32] || y != &[0u8; 32]))
}

/// Resolve an `ABI(bytes32,uint256)` record → `(contentType, data)`. `Ok(None)`
/// = no record (empty data — the contentType word alone is NOT checked, Java
/// `decodeAbiResult` parity).
pub fn resolve_abi(
    caller: &dyn EthCaller,
    name: &str,
    content_types: u64,
) -> Result<Option<(u64, Vec<u8>)>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32_u64("ABI(bytes32,uint256)", &node, content_types);
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_uint_bytes(&raw).filter(|(_, data)| !data.is_empty()))
}

/// Resolve a `dnsRecord(bytes32,bytes,uint16)` record: `dns_name` is the DNS
/// name queried (its RAW wire encoding is the second arg — the Java engine's
/// signature, selector 0xee8de1f7; see [`abi::encode_call_bytes32_bytes_u64`]),
/// `resource` the DNS record type (1 = A, 16 = TXT, …). `Ok(None)` = no record.
pub fn resolve_dns_record(
    caller: &dyn EthCaller,
    name: &str,
    dns_name: &str,
    resource: u16,
) -> Result<Option<Vec<u8>>, EnsError> {
    let node = namehash(name);
    let wire = dns_encode(dns_name)?;
    let inner = abi::encode_call_bytes32_bytes_u64(
        "dnsRecord(bytes32,bytes,uint16)",
        &node,
        &wire,
        u64::from(resource),
    );
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_dynamic_bytes(&raw, 0).filter(|b| !b.is_empty()))
}

/// Resolve an `interfaceImplementer(bytes32,bytes4)` record (EIP-1820 over
/// ENS). `Ok(None)` = no record (zero address).
pub fn resolve_interface_implementer(
    caller: &dyn EthCaller,
    name: &str,
    interface_id: [u8; 4],
) -> Result<Option<[u8; 20]>, EnsError> {
    let node = namehash(name);
    let inner = abi::encode_call_bytes32_bytes4(
        "interfaceImplementer(bytes32,bytes4)",
        &node,
        interface_id,
    );
    let Some(raw) = resolve_record(caller, name, &inner)? else {
        return Ok(None);
    };
    Ok(abi::decode_address(&raw).filter(|a| a != &[0u8; 20]))
}

/// Reverse-resolve `address` → its primary ENS name, **forward-verified**: the
/// claimed name is forward-resolved and must map back to `address`, or the
/// answer is discarded. Empty reverse record, no reverse resolver, and a failed
/// forward-verify are all indistinguishable `Ok(None)` (Java parity — no
/// special error token).
///
/// The reverse side is deliberately simpler than forward resolution (Java
/// `resolveName` parity): the resolver is looked up at the EXACT
/// `<hex>.addr.reverse` node — no ancestor walk, no `supportsInterface` probe,
/// no ENSIP-10 wrap — and `name(bytes32)` is called directly on it.
///
/// One deliberate divergence from the Java reverse path: a plain REVERT during
/// the reverse lookup (registry or `name()`) folds to `Ok(None)` here, where
/// Java surfaces it as an error record — this matches the FORWARD path's
/// revert-is-no-record classification on both engines, and a reverse resolver
/// without a `name(bytes32)` function simply has no reverse record to give.
/// Non-revert failures (state unavailable) still propagate as errors.
pub fn reverse_resolve(
    caller: &dyn EthCaller,
    address: [u8; 20],
) -> Result<Option<String>, EnsError> {
    let rev_name = reverse_name(address);
    let rev_node = namehash(&rev_name);

    // Exact resolver lookup; a zero resolver (or a revert) is "no reverse record".
    let call = abi::encode_call_bytes32("resolver(bytes32)", &rev_node);
    let out = match caller.eth_call(REGISTRY, &call) {
        Ok(out) => out,
        Err(EvmError::Reverted { .. }) => return Ok(None),
        Err(e) => return Err(EnsError::Call(e)),
    };
    let Some(resolver) = abi::decode_address(&out).filter(|a| a != &[0u8; 20]) else {
        return Ok(None);
    };

    // name(node) → the claimed primary name (empty/malformed → no record). An
    // OffchainLookup revert stays distinguishable, like every resolver call.
    let name_call = abi::encode_call_bytes32("name(bytes32)", &rev_node);
    let raw = match caller.eth_call(resolver, &name_call) {
        Ok(out) => out,
        Err(EvmError::Reverted { data }) => {
            return match revert_outcome(&data) {
                Ok(_) => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(e) => return Err(EnsError::Call(e)),
    };
    let Some(claimed) = abi::decode_string(&raw).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };

    // Forward-verify through the FULL forward path (registry walk + ENSIP-10):
    // the claimed name must resolve back to the queried address, byte-equal.
    // A MALFORMED claimed name is a failed verify (no record), not an error —
    // a malicious reverse record must not be able to force an error result
    // where "no verified reverse record" is the truthful answer.
    match resolve_address(caller, &claimed) {
        Ok(Some(fwd)) if fwd == address => Ok(Some(claimed)),
        Ok(_) | Err(EnsError::InvalidName(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `<lowercase-hex-no-0x>.addr.reverse` (EIP-181; Java `ReverseLookup.nameFor`).
fn reverse_name(address: [u8; 20]) -> String {
    let mut s = String::with_capacity(40 + 13);
    for b in address {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str(".addr.reverse");
    s
}

/// The shared resolution path every record type rides: find the (possibly
/// wildcard) resolver for `name`, dispatch `inner_call` to it — wrapped in
/// ENSIP-10 `resolve(bytes,bytes)` for an extended resolver, direct for a legacy
/// one — and return the raw inner return bytes. `Ok(None)` = no resolver / a
/// non-wildcard ancestor / a plain revert / an unwrappable extended return;
/// per-record "empty answer" semantics (zero address, empty string, …) belong to
/// the typed wrappers on top.
fn resolve_record(
    caller: &dyn EthCaller,
    name: &str,
    inner_call: &[u8],
) -> Result<Option<Vec<u8>>, EnsError> {
    // DNS-encode BEFORE the walk (Java `dispatchResolve` ordering): a malformed
    // name (empty / oversized label) is always an InvalidName error — never a
    // "no record" — even when the walk would find no resolver or the legacy
    // path wouldn't need the wire form.
    let dns = dns_encode(name)?;

    let Some(info) = find_resolver(caller, name)? else {
        return Ok(None);
    };
    // A resolver found only for an ancestor can answer a subname ONLY if it is a
    // wildcard (ENSIP-10) resolver; a legacy ancestor resolver cannot.
    if !info.exact && !info.extended {
        return Ok(None);
    }

    if info.extended {
        // ENSIP-10: resolver.resolve(dnsEncode(name), inner) → bytes wrapping
        // the inner return.
        let call = abi::encode_resolve(&dns, inner_call);
        match caller.eth_call(info.resolver, &call) {
            Ok(out) => Ok(abi::decode_dynamic_bytes(&out, 0)),
            Err(EvmError::Reverted { data }) => revert_outcome(&data),
            Err(e) => Err(EnsError::Call(e)),
        }
    } else {
        // Legacy exact resolver: dispatch the inner call directly.
        match caller.eth_call(info.resolver, inner_call) {
            Ok(out) => Ok(Some(out)),
            Err(EvmError::Reverted { data }) => revert_outcome(&data),
            Err(e) => Err(EnsError::Call(e)),
        }
    }
}

/// Classify a resolver-call revert: an ERC-3668 `OffchainLookup` is a
/// distinguishable "resolves offchain" failure (never folded into "no record");
/// any other revert is "no record".
fn revert_outcome(data: &[u8]) -> Result<Option<Vec<u8>>, EnsError> {
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
    fn malformed_name_errors_even_without_a_resolver() {
        // DNS-encoding runs BEFORE the walk (Java dispatchResolve ordering): an
        // interior empty label is InvalidName, never a clean "no record" — even
        // when the registry has no resolver for any suffix.
        let caller = MockCaller::new().on(|_t, _cd| Some(Ok(vec![0u8; 32])));
        assert!(matches!(
            resolve_address(&caller, "a..eth"),
            Err(EnsError::InvalidName(_))
        ));
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

    // ---- record types (EL-C-5-2) ----

    /// A legacy exact resolver answering `record_sel` with `response`.
    fn legacy_resolver_caller(
        record_sel: [u8; 4],
        response: Vec<u8>,
    ) -> MockCaller {
        let resolver_sel = abi::selector("resolver(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(revert))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == record_sel).then(|| Ok(response.clone())))
    }

    /// `bytes`/`string` head-tail wrapping of `payload` (offset ‖ len ‖ data ‖ pad).
    fn dyn_bytes_return(payload: &[u8]) -> Vec<u8> {
        let mut o = vec![0u8; 32];
        o[31] = 0x20;
        let mut len = vec![0u8; 32];
        len[24..].copy_from_slice(&(payload.len() as u64).to_be_bytes());
        o.extend_from_slice(&len);
        o.extend_from_slice(payload);
        o.extend(std::iter::repeat_n(0u8, (32 - (payload.len() % 32)) % 32));
        o
    }

    #[test]
    fn text_record_resolves_and_empty_is_none() {
        let text_sel = abi::selector("text(bytes32,string)");
        let caller = legacy_resolver_caller(text_sel, dyn_bytes_return(b"https://vitalik.ca"));
        assert_eq!(
            resolve_text(&caller, "vitalik.eth", "url").unwrap(),
            Some("https://vitalik.ca".to_string())
        );
        // The queried key must be inside the calldata (dynamic string arg).
        let empty = legacy_resolver_caller(text_sel, dyn_bytes_return(b""));
        assert_eq!(resolve_text(&empty, "vitalik.eth", "url").unwrap(), None);
        // Short return (< offset+len words) → None, not an error.
        let short = legacy_resolver_caller(text_sel, vec![0u8; 32]);
        assert_eq!(resolve_text(&short, "vitalik.eth", "url").unwrap(), None);
    }

    #[test]
    fn contenthash_and_multicoin_and_dnsrecord_empty_bytes_are_none() {
        for (sel4, run) in [
            (abi::selector("contenthash(bytes32)"),
             Box::new(|c: &dyn EthCaller| resolve_contenthash(c, "a.eth").unwrap())
                 as Box<dyn Fn(&dyn EthCaller) -> Option<Vec<u8>>>),
            (abi::selector("addr(bytes32,uint256)"),
             Box::new(|c: &dyn EthCaller| resolve_multicoin(c, "a.eth", 0).unwrap())),
            (abi::selector("dnsRecord(bytes32,bytes,uint16)"),
             Box::new(|c: &dyn EthCaller| resolve_dns_record(c, "a.eth", "a.eth", 1).unwrap())),
        ] {
            let payload = vec![0xC0u8, 0xFF, 0xEE];
            let full = legacy_resolver_caller(sel4, dyn_bytes_return(&payload));
            assert_eq!(run(&full), Some(payload), "selector {sel4:02x?}");
            let empty = legacy_resolver_caller(sel4, dyn_bytes_return(b""));
            assert_eq!(run(&empty), None, "selector {sel4:02x?}");
        }
    }

    #[test]
    fn pubkey_fixed_tuple_and_zero_is_none() {
        let pk_sel = abi::selector("pubkey(bytes32)");
        let mut xy = vec![0x0A; 32];
        xy.extend_from_slice(&[0x0B; 32]);
        let caller = legacy_resolver_caller(pk_sel, xy);
        assert_eq!(
            resolve_pubkey(&caller, "a.eth").unwrap(),
            Some(([0x0A; 32], [0x0B; 32]))
        );
        let zero = legacy_resolver_caller(pk_sel, vec![0u8; 64]);
        assert_eq!(resolve_pubkey(&zero, "a.eth").unwrap(), None);
        let short = legacy_resolver_caller(pk_sel, vec![0u8; 32]);
        assert_eq!(resolve_pubkey(&short, "a.eth").unwrap(), None);
    }

    #[test]
    fn abi_record_returns_content_type_and_data() {
        let abi_sel = abi::selector("ABI(bytes32,uint256)");
        // (uint256 contentType=1, bytes data="{}") — offset 0x40 (after 2 head words).
        let mut ret = vec![0u8; 32];
        ret[31] = 1;
        let mut off = vec![0u8; 32];
        off[31] = 0x40;
        ret.extend_from_slice(&off);
        let mut len = vec![0u8; 32];
        len[31] = 2;
        ret.extend_from_slice(&len);
        ret.extend_from_slice(b"{}");
        ret.extend_from_slice(&[0u8; 30]);
        let caller = legacy_resolver_caller(abi_sel, ret);
        assert_eq!(resolve_abi(&caller, "a.eth", 0xF).unwrap(), Some((1, b"{}".to_vec())));
        // Empty data → None even with a non-zero contentType word shape.
        let mut empty = vec![0u8; 32];
        empty[31] = 1;
        let mut off2 = vec![0u8; 32];
        off2[31] = 0x40;
        empty.extend_from_slice(&off2);
        empty.extend_from_slice(&[0u8; 32]); // len 0
        let caller2 = legacy_resolver_caller(abi_sel, empty);
        assert_eq!(resolve_abi(&caller2, "a.eth", 0xF).unwrap(), None);
    }

    #[test]
    fn interface_implementer_zero_is_none() {
        let ii_sel = abi::selector("interfaceImplementer(bytes32,bytes4)");
        let caller = legacy_resolver_caller(ii_sel, addr_word([0x77; 20]));
        assert_eq!(
            resolve_interface_implementer(&caller, "a.eth", [0x5b, 0x5e, 0x13, 0x9f]).unwrap(),
            Some([0x77; 20])
        );
        let zero = legacy_resolver_caller(ii_sel, vec![0u8; 32]);
        assert_eq!(
            resolve_interface_implementer(&zero, "a.eth", [0x5b, 0x5e, 0x13, 0x9f]).unwrap(),
            None
        );
    }

    #[test]
    fn records_ride_the_ensip10_wrap() {
        // A WILDCARD resolver: the text() inner call must arrive wrapped in
        // resolve(bytes,bytes) and the answer is bytes-unwrapped.
        let resolver_sel = abi::selector("resolver(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        let resolve_sel = abi::selector("resolve(bytes,bytes)");
        let text_sel = abi::selector("text(bytes32,string)");
        let caller = MockCaller::new()
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(|| Ok(bool_word(true))))
            .on(move |t, cd| {
                if t != RESOLVER || sel(cd) != resolve_sel {
                    return None;
                }
                // The inner call (2nd dynamic arg) must be the text() call.
                let inner = abi::decode_dynamic_bytes(&cd[4..], 1).unwrap();
                assert_eq!(&inner[..4], &text_sel);
                // Return bytes-wrapping of the inner string return.
                Some(Ok(dyn_bytes_return(&dyn_bytes_return(b"wrapped!"))))
            });
        assert_eq!(
            resolve_text(&caller, "sub.gateway.eth", "url").unwrap(),
            Some("wrapped!".to_string())
        );
    }

    // ---- reverse resolution (EL-C-5-2) ----

    /// registry.resolver(REVERSE node) → REV_RESOLVER; name(node) → `claimed`;
    /// then the forward path for `claimed` → `forward_addr`.
    fn reverse_caller(claimed: &str, forward_addr: [u8; 20]) -> MockCaller {
        const REV_RESOLVER: [u8; 20] = [0x55; 20];
        let resolver_sel = abi::selector("resolver(bytes32)");
        let name_sel = abi::selector("name(bytes32)");
        let supports_sel = abi::selector("supportsInterface(bytes4)");
        let addr_sel = abi::selector("addr(bytes32)");
        let rev_node = namehash(&reverse_name(VITALIK));
        let claimed_ret = dyn_bytes_return(claimed.as_bytes());
        MockCaller::new()
            .on(move |t, cd| {
                (t == REGISTRY && sel(cd) == resolver_sel && cd[4..36] == rev_node)
                    .then(|| Ok(addr_word(REV_RESOLVER)))
            })
            .on(move |t, cd| {
                (t == REV_RESOLVER && sel(cd) == name_sel).then(|| Ok(claimed_ret.clone()))
            })
            // forward path: exact resolver for the claimed name, legacy.
            .on(move |t, cd| (t == REGISTRY && sel(cd) == resolver_sel).then(|| Ok(addr_word(RESOLVER))))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == supports_sel).then(revert))
            .on(move |t, cd| (t == RESOLVER && sel(cd) == addr_sel).then(|| Ok(addr_word(forward_addr))))
    }

    #[test]
    fn reverse_resolves_with_forward_verify() {
        let caller = reverse_caller("vitalik.eth", VITALIK);
        assert_eq!(reverse_resolve(&caller, VITALIK).unwrap(), Some("vitalik.eth".to_string()));
    }

    #[test]
    fn reverse_impersonation_is_rejected() {
        // The reverse record claims "vitalik.eth" but the forward resolution of
        // that name points at a DIFFERENT address → the claim is discarded.
        let caller = reverse_caller("vitalik.eth", [0xBA; 20]);
        assert_eq!(reverse_resolve(&caller, VITALIK).unwrap(), None);
    }

    #[test]
    fn reverse_malformed_claimed_name_is_none_not_error() {
        // A malicious reverse record claiming a malformed name ("a..eth") must
        // read as a failed forward-verify (None) — not surface InvalidName.
        let caller = reverse_caller("a..eth", VITALIK);
        assert_eq!(reverse_resolve(&caller, VITALIK).unwrap(), None);
    }

    #[test]
    fn reverse_empty_record_and_no_resolver_are_none() {
        // No resolver at the reverse node.
        let no_resolver = MockCaller::new().on(|_t, _cd| Some(Ok(vec![0u8; 32])));
        assert_eq!(reverse_resolve(&no_resolver, VITALIK).unwrap(), None);
        // Resolver set but name() returns an empty string.
        let caller = reverse_caller("", VITALIK);
        assert_eq!(reverse_resolve(&caller, VITALIK).unwrap(), None);
    }

    #[test]
    fn reverse_name_is_lowercase_hex() {
        assert_eq!(
            reverse_name([0xd8; 20]),
            format!("{}.addr.reverse", "d8".repeat(20))
        );
    }
}
