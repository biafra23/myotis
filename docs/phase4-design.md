# Phase 4 — CCIP-Read (ERC-3668)

Phase 3 ships forward + reverse ENS resolution for classic on-chain
names. Phase 4 makes modern ENS work — Coinbase IDs (`*.cb.id`),
Uniswap names (`*.uni.eth`), Base subnames (`*.base.eth`), and
generally any name whose resolver delegates lookups off-chain via
ERC-3668.

> **Scope:** make `EnsResolver.resolveAddress("someone.cb.id")` work.
> Generic `eth_call` exposing CCIP-Read at the public API surface is
> deliberately out of scope (the plan calls for a narrow surface — only
> `callView` and `estimateGas`).

## Acceptance criteria (from the original plan)

- CCIP-Read handler with URL template substitution and GET/POST routing.
- Universal Resolver path enabled in `EnsResolver`.
- Modern ENS test corpus passes:
  - A `.cb.id` name resolves
  - A `.uni.eth` name resolves
  - A Base subdomain resolves

## What's already in place from earlier phases

`OffchainLookupRevert` (parser for the ERC-3668 revert payload) and a
`CcipReadHandler` skeleton already shipped in Phase 0. The handler
currently uses `java.net.http.HttpClient`, which is documented in
`CLAUDE.md` as not Android-safe. Phase 4 refactors it.

## Design

### HTTP client decoupling

`CcipReadHandler` currently embeds `java.net.http.HttpClient`. Two
problems:

- That package is API 33+ on Android and not in the desugar set, so the
  handler crashes at runtime on `minSdk = 29` devices.
- `CLAUDE.md` mandates Ktor for HTTP, since Ktor is Multiplatform-ready.

Pulling Ktor into `:myotis-evm` is a substantial dep-graph addition
(Kotlin runtime + coroutines). **Phase 4 sidesteps the question**: the
handler is refactored to take a `CcipGateway` interface — a small SAM-
shape `(method, url, body) → CompletableFuture<String>`. The handler
does URL template substitution, body construction, and JSON parsing;
the actual HTTP transport is supplied by the caller. Tests use an
in-memory implementation that returns hardcoded responses; the
production implementation lives in `:app` (or wherever the Android
wiring sits) and uses Ktor.

This mirrors the `SnapPeer` decoupling pattern in `:myotis-evm`:
`:myotis-evm` doesn't depend on `:networking`; the wallet integration
provides the bridge.

### Wiring into `DefaultEvmExecutor.callView`

```
DefaultEvmExecutor.callView(target, calldata, ctx)
  result = runOnTracedView(...)         // existing path
  catch EvmExecutionException(Reverted(data)):
    parsed = OffchainLookupRevert.tryParse(data)
    if parsed.isEmpty(): rethrow         // not CCIP-Read; bubble up
    if depth >= MAX_RECURSION_DEPTH: rethrow CcipGatewayFailed
    response = ccipGateway.request(...)  // (parsed.urls, parsed.callData, parsed.sender)
    callback = parsed.callbackSelector || abi.encode(response, parsed.extraData)
    // Re-enter against the original sender, depth+1
    return callView(parsed.sender, callback, ctx, depth+1)
```

The depth cap is plan-mandated at 1 — the spec allows nested
OffchainLookup reverts, but no real resolver does it, and capping is a
defensive property against gateway loops.

### Universal Resolver path

The plan says "switch `EnsResolver` to use the Universal Resolver path
now that CCIP-Read is supported." The UR's `resolve(name, data)` method
takes a DNS-encoded name and ABI-encoded inner-call data, and handles
wildcard resolution + CCIP-Read in one place. `EnsResolver` becomes:

```
ur.resolve(dnsEncode("vitalik.eth"),
           abi.encode(addr.selector, namehash("vitalik.eth")))
```

One callView instead of two. CCIP-Read happens transparently inside the
UR's bytecode, surfacing as the normal `OffchainLookup` revert that the
Phase 4 executor handles.

A new `DnsEncoder` helper produces the DNS wire format
(length-prefixed labels + null terminator). Reusable; small (~30 lines).

### What this branch will ship

This is a multi-commit phase:

- **Commit 1** (this commit): refactor `CcipReadHandler` around a
  `CcipGateway` interface, wire CCIP-Read into `DefaultEvmExecutor`
  with the 1-hop cap, end-to-end tests using bytecode that reverts
  with the `OffchainLookup` selector.
- **Commit 2**: `DnsEncoder`, `EnsResolver` UR path, mainnet IT corpus
  expansion to include `.cb.id`/`.uni.eth`/`.base.eth`.
- **Commit 3 (optional)**: Ktor `CcipGateway` implementation in a
  separate module (probably `:myotis-ens-impl` or in `:app`'s wiring).

## Out of scope

- Generic `eth_call` exposed via the public API. The narrow surface is
  intentional.
- Tor routing for CCIP-Read gateways (privacy concern documented in
  `CcipReadHandler`'s Javadoc; future phase).
- Caching gateway responses across calls. Each `callView` re-fetches
  unless the wallet integration adds a layer.

## Privacy note

CCIP-Read gateways necessarily learn:
- The user's IP address.
- The queried name (because the request includes its callData).
- Approximate request timing.

Documenting this on `EvmExecutor.callView` and on `CcipReadHandler` so
consumers understand the trade-off before turning on resolution for
gateway-based names. Tor routing is a separate piece of work tracked
in the wallet's privacy roadmap.
