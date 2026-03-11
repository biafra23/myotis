# devp2p Playground

A from-scratch Ethereum devp2p implementation in Java 21. Connects to the Ethereum mainnet (or testnets) using the devp2p protocol stack: discv4 peer discovery, RLPx encrypted transport, and eth/67-69 sub-protocol. Includes a beacon chain light client for consensus-layer state root verification and snap/1 support for account lookups with Merkle proofs.

## Requirements

- Java 21+
- Gradle (wrapper included)

## Build

```bash
# Build all modules (includes tests)
./gradlew build

# Compile only (skip tests)
./gradlew compileJava

# Run tests
./gradlew test
```

## Run

The application operates in two modes: **daemon** and **client**. The daemon discovers peers, maintains connections, and listens for commands on a Unix domain socket (`/tmp/devp2p.sock`). The client sends a single command to the running daemon and exits.

### Start the daemon

```bash
# Mainnet (default)
./gradlew :app:run

# Testnet
./gradlew :app:run -Pnetwork=sepolia
./gradlew :app:run -Pnetwork=holesky

# Custom port (default: 30303)
./gradlew :app:run -Pport=30304
```

The daemon runs in the foreground. It discovers peers via discv4 (Kademlia DHT), establishes RLPx encrypted connections, and performs eth protocol handshakes. A beacon chain light client syncs finalized state roots from the consensus layer.

### Stop the daemon

```bash
./gradlew :app:run -Pargs=stop
```

## Query commands

All commands are sent to the running daemon via IPC. Responses are JSON.

### Status

```bash
./gradlew :app:run -Pargs=status
```

Returns uptime, discovered/connected/ready peer counts, snap peer count, and backoff/blacklist stats.

### Peers

```bash
./gradlew :app:run -Pargs=peers
```

Returns discovered peers (from the Kademlia table) and connected peers with their state, snap support, and client ID.

### Beacon status

```bash
./gradlew :app:run -Pargs=beacon-status
```

Returns beacon light client sync state: finalized slot, execution state root, and sync status.

### Get block headers

```bash
# Get 3 headers starting at block 21000000
./gradlew :app:run -Pargs="get-headers 21000000 3"
```

### Get block (header + body)

```bash
./gradlew :app:run -Pargs="get-block 21000000"
```

### Get account

```bash
./gradlew :app:run -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
```

Returns account data (nonce, balance, storage root, code hash) with a Merkle-Patricia proof. The proof is verified against both the peer's current state root (`peerProofValid`) and the beacon-finalized state root (`beaconProofValid`).

### Dial a specific peer

```bash
./gradlew :app:run -Pargs="dial enode://..."
```

## Helper scripts

Convenience scripts that wrap the Gradle commands and format the output with `jq`:

### `peers.sh`

Lists connected peers in READY state, sorted by snap support and client ID:

```bash
./peers.sh
# Output:
# 1.2.3.4:30303 snap=true Geth/v1.15.0/linux-amd64/go1.23.4
# 5.6.7.8:30303 snap=true Nethermind/v1.30.0/...
```

### `status.sh`

Prints daemon status as JSON:

```bash
./status.sh
# {"ok":true,"state":"RUNNING","uptimeSeconds":120,"discoveredPeers":214,...}
```

### `beacon-status.sh`

Prints beacon light client sync status:

```bash
./beacon-status.sh
```

## Beacon chain light client

The daemon includes a consensus-layer light client that tracks finalized state roots from the beacon chain. This enables trustless verification of account proofs against the canonical chain state.

The light client can sync from:
- A local beacon node HTTP API (e.g. Lighthouse on `http://localhost:5052`)
- Beacon chain P2P network (libp2p)

Helper scripts for running a local beacon node are in `scripts/`:
- `scripts/lighthouse.sh` -- starts Lighthouse via Docker with checkpoint sync
- `scripts/lodestar.sh` -- starts Lodestar via Docker with checkpoint sync

## Architecture

Three Gradle modules:

- **core** -- cryptographic identity (`NodeKey`), data types (`BlockHeader`), ENR decoding
- **networking** -- protocol layers, all Netty-based:
  - `discv4` -- UDP peer discovery (ping/pong/findnode/neighbors)
  - `rlpx` -- TCP transport with EIP-8 ECIES handshake and AES-256-CTR framed channel
  - `eth` -- eth/67-69 sub-protocol (hello, status, block headers/bodies)
  - `snap` -- snap/1 sub-protocol (account range queries with Merkle proofs)
- **consensus** -- beacon chain light client, Merkle-Patricia proof verification
- **app** -- daemon/CLI entry point, Unix domain socket IPC server, peer caching

### Protocol flow

```
DiscV4Service (UDP)
  discovers peers
    --> RLPxConnector.connect() (TCP)
      --> ECIES handshake (HANDSHAKE_WRITE -> HANDSHAKE_READ -> FRAMED)
        --> EthHandler (AWAITING_HELLO -> AWAITING_STATUS -> READY)
          --> block headers, account queries available
```

### Key dependencies

- **Tuweni 2.7.2** -- RLP encoding, SECP256K1, byte utilities
- **Netty 4.2.x** -- NIO transport
- **BouncyCastle** -- SECP256K1 crypto provider
- **jvm-libp2p** -- beacon chain P2P networking (consensus module)
