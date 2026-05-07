# Phase 3 — ENS resolution

Phases 0–2 made the EVM run correctly and quickly against SNAP-verified
state. Phase 3 puts that machinery to use for the wallet's first concrete
feature: forward and reverse ENS resolution for classic, on-chain names.

> **Scope:** classic on-chain names only — `vitalik.eth`, `nick.eth`,
> `*.base.eth` records that don't use CCIP-Read, etc. Names that resolve
> via ERC-3668 / CCIP-Read (Coinbase IDs, Uniswap names, etc.) are Phase 4.
> The split matters: the step-by-step resolution path Phase 3 ships
> handles classic names directly; the Universal Resolver path Phase 4
> introduces is what unifies CCIP-Read.

## Acceptance criteria (from the original plan)

- `myotis-ens` module compiles and tests pass.
- `EnsResolverTest.resolveAddress("vitalik.eth")` returns `0xd8dA…6045`.
- Forward + reverse resolution works for a curated set of ~10 names.
- The wallet's existing storage-proof-based ENS lookup is replaced by
  `EnsResolver` (consumer-side change; out of scope for this branch).

## Design

### Mainnet anchor

The ENS Registry lives at `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`
on mainnet. It maps `(node) → (owner, resolver, ttl)`. Forward
resolution uses the registry only to find the resolver; the actual
`addr` lookup goes to whatever resolver the registry points at (almost
always the ENS Public Resolver).

### Forward resolution

```
node = namehash("vitalik.eth")
resolverAddr = registry.resolver(node)            // first callView
addr = resolver.addr(node)                         // second callView
```

Both calls go through `EvmExecutor.callView`. The resolver address comes
back as a 20-byte address; if it's `0x0`, the name has no resolver and
the lookup returns absent.

### Reverse resolution (ENSIP-3)

```
reverseNode = namehash(addressHex.toLowerCase().replace("0x", "") + ".addr.reverse")
reverseResolver = registry.resolver(reverseNode)
name = reverseResolver.name(reverseNode)
// Verification step (mandatory per ENSIP-3):
forward = resolveAddress(name)
if forward != address: return absent
```

The verification round-trip defeats impersonation: anyone can claim any
name in their reverse record without proof, so the resolver's word alone
isn't trustworthy. Only when a forward resolution of the claimed name
points back at the original address do we accept it.

### Why step-by-step instead of Universal Resolver

The plan mandates step-by-step for Phase 3 because the Universal
Resolver's value lies primarily in unifying CCIP-Read flows, and
CCIP-Read is a Phase 4 concern. Step-by-step is also simpler to reason
about: two separate `callView` invocations whose interfaces are
documented in plain Solidity, no need to decode UR's opaque
multi-record return shape.

Switching to UR happens in Phase 4 once `DefaultEvmExecutor` learns to
catch and handle ERC-3668 reverts.

## Module layout

```
myotis-ens/
├── build.gradle.kts
├── src/main/java/io/myotis/ens/
│   ├── EnsResolver.java          // public API
│   ├── EnsAddresses.java         // canonical mainnet addresses (registry)
│   └── ReverseLookup.java        // reverse-name encoding helper
└── src/test/java/io/myotis/ens/
    ├── EnsResolverTest.java      // unit tests with mock EvmExecutor
    └── ReverseLookupTest.java    // encoding tests
```

`EnsResolver` takes an `EvmExecutor` at construction; the wallet supplies
a `PrefetchingEvmExecutor` (Phase 2) wired to a `SnapBackedStateOracle`
(Phase 1). Tests can substitute a fake `EvmExecutor` that returns
hardcoded responses for specific calls — that lets us verify the
two-step orchestration, ABI codec usage, and reverse-lookup verification
without standing up a fixture for the whole ENS bytecode chain.

`Namehash` stays in `:myotis-evm/ens` (where Phase 0 parked it). The
plan said it could relocate "without API impact"; keeping it where the
ABI / EVM types live avoids a `:myotis-evm` → `:myotis-ens` reverse
dependency that'd be created if `:myotis-evm`'s integration tests still
need namehash.

## What this branch will ship

- Commit 1 (this design + module + EnsResolver core): the module skeleton,
  forward/reverse resolution against a mock EvmExecutor, unit tests
  covering the orchestration and verification logic.
- Commit 2 (mainnet IT): an env-gated benchmark / acceptance IT for the
  ~10-name curated test set. Same gating story as Phase 1/2 — depends
  on the `:app:Main` bootstrap helper extraction to actually run.
- (Optional commit 3): the wallet-integration switch — replacing the
  existing storage-proof-based ENS lookup with `EnsResolver`. Out of
  scope unless the integration site is small.

## Out of scope

- CCIP-Read (Phase 4).
- Universal Resolver path (Phase 4 once CCIP-Read lands).
- ENS subdomains that delegate to off-chain resolvers (a special case of
  CCIP-Read).
- Full ENSIP-1 normalisation (UTS-46 + IDNA). The Phase 0 `Namehash`
  helper lower-cases ASCII; non-ASCII names will likely produce wrong
  hashes. Documenting the gap; production-grade normalisation is a
  larger undertaking that affects every ENS-touching surface.
