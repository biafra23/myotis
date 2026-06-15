# Multi-chain in one process — evaluation & design

Status: **design only.** Gnosis Chain is implemented as a first-class network
today, but it runs as one daemon per network (separate ports, separate IPC
socket) exactly like mainnet. This document records *why* we would eventually
want several chains in one process, what blocks it today, and the recommended
architecture — so the refactor can be picked up deliberately rather than
bolted on.

## Scope decision

- **Shared ports are out.** Multiplexing two networks onto one UDP/TCP port
  (routing by fork-id) is not something real clients do; rejected. Each chain
  keeps its own discovery/RLPx ports. "One process, multiple chains" means
  *separate ports inside one JVM*, which is completely standard.
- The motivation is the **Android wallet**, where the project already treats
  Android as a first-class target. On a server you'd just run two daemons.

## Why one process (the synergies)

1. **It's the only sane multi-chain wallet architecture on Android.** An Android
   app is one process per package id. A wallet must show ETH (mainnet) and
   GNO/xDai (Gnosis) together and switch instantly. The alternatives are bad:
   two package-id apps (absurd UX, can't share a keystore), or one app that
   cold-starts a chain on every switch (a light-client cold start =
   re-bootstrap + sync-committee catch-up + BLS verification — seconds to
   minutes, and battery). One process keeps **both light clients warm and
   verified at once**.

2. **Amortized fixed costs.** Each chain stack pulls in the same heavy
   machinery: the BLS native lib (Milagro — expensive static init, and there's
   already a `NoClassDefFoundError`-on-init footgun guarded in `Main`), the Besu
   EVM classpath, Netty event-loop groups, SSZ/Merkle code. Two processes pay
   all of it twice — double resident memory, and on Android double the DEX/APK
   footprint and double ART warm-up. One process loads each once. On a
   memory-constrained phone this is the difference between staying resident and
   being killed.

3. **Battery / radio coordination.** Two independent processes wake the cellular
   radio on uncoordinated schedules — among the worst mobile battery patterns
   because of the radio's high-power tail. One process can bundle both chains'
   sync into shared wake windows under a single wakelock and a single
   foreground service. (Two apps also means two permanent foreground-service
   notifications.)

4. **One service/IPC surface.** The UI binds to one Android Service / one IPC
   socket and asks `get-account --network gnosis` vs `--network mainnet`. Two
   processes mean two sockets/Binders and two lifecycles to coordinate.

5. **Trustless cross-chain verification (the long-term payoff).** Gnosis is
   bridged to Ethereum (the AMB / xDai bridge). With both light clients' verified
   heads in the same memory, a bridge message (mainnet deposit → Gnosis mint) can
   be verified against *both* independently-verified chains with no trusted RPC
   or relayer — squarely in this project's "everything cryptographically
   verified" mandate, and impossible across separate apps.

### Not a synergy / the cost

- **Shared discovery** would save sockets and UDP chatter, but only if a single
  discovery port served all networks (route peers by ENR fork-id) — that's the
  shared-port idea we rejected. With separate ports, discovery stays separate.
- **Fault isolation is the real cost.** One process means a crash or OOM in one
  chain's stack can take the other down. Today only mainnet is battle-tested, so
  the per-network stacks must be made robust and resource-bounded *within* the
  process before this is safe.

## What blocks it today

The codebase is "one daemon = one network" by construction: a single
`NetworkConfig` is threaded through every service.

- **`nodekey.hex` is one global identity** (`Main.loadOrGenerate`). Per-network
  ENRs would want distinct (or per-network-derived) keys so each network
  advertises its own fork-id.
- **discv5 port is hardcoded to 9000** (`Main` → `DiscV5Service.start(9000)`),
  with only an ephemeral fallback. A second network in-process needs its own
  configurable CL port.
- **The core services each bind to one `NetworkConfig`**: `RLPxConnector`,
  `DiscV4Service`, `DiscV5Service`, `BeaconLightClient`. They would become maps
  keyed by network plus a routing layer.
- **IPC is one socket per network** (`/tmp/ethp2p[-<net>].sock`). A single-process
  build would want one socket whose commands carry a `--network` selector (the
  CLI already parses `--network`).
- Caches/locks/snapshots are already network-suffixed (`peers-<net>.cache`,
  `cl-peers-<net>.cache`, `sync-state-<net>.snapshot`, `ethp2p-<net>.lock`), so
  those need no change.

## Recommended architecture

A `NodeRegistry` owning a `Map<String, ChainStack>`, where each `ChainStack`
bundles the per-network `NetworkConfig`, `DiscV4Service`, `DiscV5Service`,
`RLPxConnector`, `BeaconLightClient`, `BeaconSyncState`, and caches — each on its
own ports. Shared, process-level singletons: the Netty event-loop groups, the
BLS verifier, the Besu EVM classpath, the virtual-thread schedulers, and one IPC
server that routes each command to the right `ChainStack` by its `--network`
field. On Android, a single foreground Service hosts the registry and schedules
all chains' sync into shared radio wake windows.

This is a real refactor (hoisting the single-`NetworkConfig` assumption into a
registry) and is intentionally **out of scope** for the Gnosis change, to keep
the proven mainnet path stable. Sizing: mostly mechanical in `Main`/`CommandHandler`
plus the discv5-port and node-key parameterization; the risk is fault isolation,
which argues for doing it only after Gnosis (and any second chain) is proven
solid on its own.

## Today's supported model

Run a second chain as its own daemon in its own process:

```
./gradlew :app:run                       # mainnet  (UDP/TCP 30303, /tmp/ethp2p.sock)
./gradlew :app:run -Pnetwork=gnosis -Pport=30304   # gnosis (/tmp/ethp2p-gnosis.sock)
```

Each is independent: separate node identity file would still be shared via
`nodekey.hex` in the same working dir, so run them from different working
directories (or different `ETHP2P_SOCKET`/cwd) if both must be active at once.
