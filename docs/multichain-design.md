# Multi-chain in one process — evaluation & design

Status: **implemented — the architecture recommended below is what was built.**
`node-core`'s `NodeRegistry` owns a `Map<network, ChainStack>` behind the engine
API (`MyotisEngine.create(...)` per network, `hostedNetworks()`); the daemon hosts
every network named in `-Pnetwork=mainnet,gnosis` in one process
(`app/.../Main.java`), and the Android, desktop and iOS apps host mainnet, Gnosis
and Sepolia together — on either engine — each network on its own ports, lock
file and IPC socket. The Rust engine hosts several networks in one process the
same way (one handle per network). This document is kept as the record of *why*
several chains share one process and of the trade-offs; the "What blocked it"
section describes the code before the refactor. The long-term payoff in item 5
(trustless cross-chain verification between two in-process light clients) is
still not built.

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

## What blocked it (before the refactor — historical)

The codebase was "one daemon = one network" by construction: a single
`NetworkConfig` was threaded through every service. Every item below has since
been resolved by the `NodeRegistry`/`ChainStack` refactor.

- **Node identity is per-network (resolved).** `Main.nodeKeyFile` gives mainnet
  `nodekey.hex` and every other network `nodekey-<net>.hex`, so each advertises
  its own fork-id. (Originally a single global `nodekey.hex`.)
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

Host several chains in one daemon process, or run them as separate daemons —
both work, and the per-network files (`nodekey-<net>.hex`, `peers-<net>.cache`,
`cl-peers-<net>.cache`, `sync-state-<net>.snapshot`, `ethp2p-<net>.lock`,
`/tmp/ethp2p-<net>.sock`) never collide:

```
./gradlew :app:run -Pnetwork=mainnet,gnosis          # one process, both chains
./gradlew :app:run                                    # mainnet only  (UDP/TCP 30303, /tmp/ethp2p.sock)
./gradlew :app:run -Pnetwork=gnosis -Pport=30304      # gnosis as its own daemon (/tmp/ethp2p-gnosis.sock)
```

The apps do the same in-process: every network enabled in Settings runs in the
one foreground service / desktop process, and the Status screen's chips switch
between them.
