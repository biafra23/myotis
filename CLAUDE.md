# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build all modules
./gradlew build

# Compile only (no tests)
./gradlew compileJava

# Run tests (all modules)
./gradlew test

# Run a single test class
./gradlew :networking:test --tests "devp2p.networking.rlpx.HandshakeRoundTripTest"

# Start daemon (mainnet, blocks until stopped)
./gradlew :app:run

# Start daemon on a testnet
./gradlew :app:run -Pnetwork=sepolia
./gradlew :app:run -Pnetwork=holesky

# Send IPC commands to running daemon
./gradlew :app:run -Pargs=status
./gradlew :app:run -Pargs=peers
./gradlew :app:run -Pargs="get-headers 21000000 3"
./gradlew :app:run -Pargs=stop
./gradlew :app:run -Pargs=purge-cache
```

## Architecture

Three Gradle modules (Java 21):

- **core** — Cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** — Three protocol layers, all Netty-based:
  - `discv4` — UDP peer discovery using Kademlia DHT (ping/pong/findnode/neighbors)
  - `rlpx` — TCP transport: EIP-8 ECIES handshake → AES-256-CTR framed channel
  - `eth` — eth/67-68 sub-protocol on top of RLPx (hello → status → ready)
- **app** — Daemon/CLI entry point, Unix domain socket IPC server, peer caching

**Protocol flow**: `DiscV4Service` discovers peers → `Main` dials them via `RLPxConnector.connect()` → `RLPxHandler` performs ECIES handshake (state machine: HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED) → fires `RLPX_READY` event → `EthHandler` runs eth handshake (AWAITING_HELLO → AWAITING_STATUS → READY) → block header requests available.

**Daemon vs Client mode**: `Main` checks if the Unix socket (`/tmp/devp2p.sock`) is already listening. No args = daemon mode (discovery + RLPx + IPC server). With args = client mode (send JSON command and exit).

## Key Dependencies

- **Tuweni 2.7.2** (ConsenSys) — RLP encoding, SECP256K1, byte utilities. Fetched from ConsenSys Maven repo.
- **Netty 4.2.x** — NIO-only (no epoll/kqueue). 4-thread `NioEventLoopGroup` for RLPx.
- **BouncyCastle** — SECP256K1 crypto provider

## Conventions

- All protocol messages use Tuweni `RLP.encode()`/`RLP.decode()` for serialization
- State machines are explicit enums in handler classes (not generic FSM framework)
- Concurrent collections (`ConcurrentHashMap.newKeySet()`) for shared mutable state
- IPC uses JSON-Lines over Unix domain sockets with Java 21 virtual threads
- Network configs (genesis hash, fork ID, bootnodes) live in `NetworkConfig`

## Trust

- Peer trusted is never an option everything has to be cryptographically verified
- The only trust anchors are sync committee signatures and  the embedded pre-Merge historical hashes accumulator and the Bellatrix-era historical roots accumulator

## Data sources
- the only sources for data are devp2p and libp2p calling a local client via http may only be used for debugging purposes it is not an option for production
