//! Pluggable JSON-RPC transport for the chain module (issue #77).
//!
//! Every chain request this crate issues goes through
//! [`ChainClient::rpc`](crate::ChainClient::rpc). By default that is the
//! configured Gnosis RPC URL — exactly what ant has always done. A host
//! that has its own *verified* chain source (Freedom's embedded Myotis
//! light client, a Colibri stateless verifier, an RPC quorum, …) can
//! install a [`ChainTransport`] and get first refusal on each request.
//!
//! The seam is deliberately **transport, not policy**: ant keeps issuing
//! precisely the requests it issued before (`eth_call`, `eth_getBalance`,
//! `eth_getLogs`, `eth_getTransactionReceipt`, `eth_sendRawTransaction`,
//! `eth_getTransactionCount`, `eth_blockNumber`, `eth_getCode`), and the
//! transport only decides *where* they are answered.
//!
//! # Can't-serve
//!
//! A host is allowed to answer "not me" for any request, and ant then
//! falls through to the configured URL exactly as if no transport were
//! installed. Two answers mean can't-serve:
//!
//! 1. **`None`** (a `NULL` return across the FFI) — the host does not
//!    serve this request at all.
//! 2. **A retryable `-32000`** ([`RETRYABLE_ERROR_CODE`]) — the host
//!    *would* serve it but its backing index does not cover the
//!    requested range yet, and the error carries the window it does
//!    cover (Myotis' log-index coverage semantics). This must fall
//!    through: surfacing it as an error (or worse, as an empty result)
//!    would silently truncate batch discovery.
//!
//! Any other JSON-RPC `error` member is a genuine answer (an `eth_call`
//! revert, say) and is surfaced to the caller unchanged.
//!
//! # `-32000` is for coverage gaps only
//!
//! **A host must emit `-32000` only when its index cannot cover the
//! request** — never as a generic failure code. geth and Nethermind use
//! `-32000` as a catch-all for genuine, non-retryable failures as well:
//! `nonce too low`, `already known`,
//! `insufficient funds for gas * price + value`,
//! `replacement transaction underpriced`, and on some backends
//! `execution reverted`. A host whose verified ladder bottoms out at an
//! RPC-quorum stage and forwards backend replies verbatim therefore
//! turns every one of those into can't-serve, and ant replays the
//! request against the configured URL: for `eth_sendRawTransaction` that
//! is a *second broadcast* of an already-signed transaction, and the
//! caller then sees the fallback URL's error instead of the real one.
//! Map any failure that is not a coverage gap to a different error code,
//! or answer authoritatively.

use std::sync::Arc;

/// JSON-RPC error code that means "retryable — I can't cover this
/// range yet". A backend answering with it is expected to carry its
/// covered block window in the error's `data`; ant does not parse that
/// window (it has no use for it — it simply falls back), it only needs
/// to know the answer is *not* an authoritative empty result.
///
/// Reserved for that one meaning: a host that also emits `-32000` for
/// genuine failures (as geth and Nethermind do for `nonce too low`,
/// `already known`, `insufficient funds …`, `replacement transaction
/// underpriced`, `execution reverted`) makes ant replay those requests
/// against the configured URL — see the [module docs](self).
pub const RETRYABLE_ERROR_CODE: i64 = -32000;

/// A host-provided JSON-RPC transport.
///
/// `serve` is **blocking** and is always called from a blocking-OK
/// thread (ant runs it on the runtime's blocking pool), so an
/// implementation may do synchronous I/O, take locks, or block on its
/// own executor without starving the node's async tasks.
///
/// Return the JSON-RPC response body for `request_json`, or `None` to
/// signal can't-serve — see the [module docs](self). Implementations
/// must not panic; a panic is caught and treated as can't-serve, but it
/// costs a fallback round trip.
///
/// An implementation that wraps other backends must not pass their
/// `-32000` errors through: here that code means "coverage gap, try
/// elsewhere" and nothing else, while geth/Nethermind also use it for
/// genuine failures (`nonce too low`, `already known`, `insufficient
/// funds …`, `execution reverted`). Forwarding those verbatim gets the
/// request replayed against the configured URL — a second broadcast for
/// `eth_sendRawTransaction`. Re-code them, or answer authoritatively.
pub trait ChainTransport: Send + Sync + 'static {
    /// Answer a single JSON-RPC request. `request_json` is a complete
    /// request object (`{"jsonrpc":"2.0","id":…,"method":…,"params":…}`).
    fn serve(&self, request_json: &str) -> Option<String>;
}

/// Shared handle to a host transport, as stored on a
/// [`ChainClient`](crate::ChainClient).
pub type SharedChainTransport = Arc<dyn ChainTransport>;

/// What a host transport's raw answer turned out to be.
#[cfg(feature = "chain-rpc")]
pub(crate) enum HostAnswer {
    /// A usable JSON-RPC response body — hand it to the caller.
    Served(serde_json::Value),
    /// Can't serve, with the reason for the (debug-level) log line.
    /// The request falls through to the configured RPC URL.
    CantServe(&'static str),
}

/// Classify a host transport's raw response body.
///
/// Anything ant cannot use as a JSON-RPC response — unparseable, not an
/// object, carrying neither `result` nor `error` — is can't-serve
/// rather than an error, so a buggy host degrades to today's behaviour
/// instead of breaking chequebook / postage flows.
#[cfg(feature = "chain-rpc")]
pub(crate) fn classify(raw: &str) -> HostAnswer {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return HostAnswer::CantServe("response is not valid JSON");
    };
    if !v.is_object() {
        return HostAnswer::CantServe("response is not a JSON-RPC object");
    }
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        if err.get("code").and_then(serde_json::Value::as_i64) == Some(RETRYABLE_ERROR_CODE) {
            return HostAnswer::CantServe("retryable -32000 (range not covered yet)");
        }
        // Any other error is a real answer from the host's backend.
        return HostAnswer::Served(v);
    }
    if v.get("result").is_none() {
        return HostAnswer::CantServe("response has neither result nor error");
    }
    HostAnswer::Served(v)
}

#[cfg(all(test, feature = "chain-rpc"))]
mod tests {
    use super::*;

    fn reason(raw: &str) -> Option<&'static str> {
        match classify(raw) {
            HostAnswer::Served(_) => None,
            HostAnswer::CantServe(r) => Some(r),
        }
    }

    #[test]
    fn plain_result_is_served() {
        match classify(r#"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#) {
            HostAnswer::Served(v) => assert_eq!(v["result"], "0x2a"),
            HostAnswer::CantServe(r) => panic!("unexpected can't-serve: {r}"),
        }
    }

    /// An empty `eth_getLogs` array from the host is an authoritative
    /// answer — only a `-32000` means "I don't cover that range".
    #[test]
    fn empty_result_array_is_served() {
        assert!(reason(r#"{"jsonrpc":"2.0","id":1,"result":[]}"#).is_none());
    }

    #[test]
    fn null_result_is_served() {
        // `eth_getTransactionReceipt` for an unmined tx.
        assert!(reason(r#"{"jsonrpc":"2.0","id":1,"result":null}"#).is_none());
    }

    #[test]
    fn retryable_minus_32000_is_cant_serve() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,
            "message":"log index does not cover this range",
            "data":{"coveredFrom":"0x1dd8ac8","coveredTo":"0x1f4a3b0"}}}"#;
        assert_eq!(
            reason(raw),
            Some("retryable -32000 (range not covered yet)")
        );
    }

    /// A revert / bad-params error is a genuine answer, not a
    /// can't-serve — the caller decides what it means.
    #[test]
    fn other_errors_are_served() {
        assert!(reason(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#
        )
        .is_none());
    }

    #[test]
    fn junk_is_cant_serve() {
        assert_eq!(
            reason("not json at all"),
            Some("response is not valid JSON")
        );
        assert_eq!(reason("[1,2,3]"), Some("response is not a JSON-RPC object"));
        assert_eq!(
            reason(r#"{"jsonrpc":"2.0","id":1}"#),
            Some("response has neither result nor error")
        );
        // An explicit `"error": null` alongside a result is not an error.
        assert!(reason(r#"{"jsonrpc":"2.0","id":1,"error":null,"result":"0x1"}"#).is_none());
    }
}
