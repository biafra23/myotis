# tor-poc — Tor integration proof of concept

A runnable proof of concept for the network-privacy design in
[`docs/privacy-and-tor.md`](../../docs/privacy-and-tor.md). It exercises the
load-bearing technical claims of that design against the **live Ethereum
mainnet**, so we know they hold before committing to a production build.

This crate is **standalone and excluded from the Rust workspace** (`exclude`
in `rust/Cargo.toml`) so the Arti dependency tree never lands in the
pure-engine build or CI. It reuses the real `myotis-net` RLPx + eth/snap stack
by path.

## What it proves

| Design claim | How the PoC demonstrates it |
|---|---|
| §3 Arti embeds in-process | Bootstraps an in-process `arti_client::TorClient` (no external `tor`/Orbot). |
| §3 Opens streams to Ethereum `:30303` over Tor | `connect_with_prefs` opens Tor `DataStream`s to real mainnet peers. |
| §4 The existing RLPx/eth/snap stack runs **unmodified** over Tor | `RlpxConnection`/`EthSession` were made generic over the byte stream (default `TcpStream`); the PoC feeds them an Arti `DataStream`. A clearnet baseline runs the *same code* over `TcpStream` for comparison. |
| §3 Per-address stream isolation | One `IsolationToken` per wallet address → a distinct circuit per address, so no exit correlates two of the user's addresses. |
| §6.1 Ephemeral Tor-side RLPx keys | Each Tor connection presents a fresh random secp256k1 node key, never the persistent `nodekey.hex`. |
| §1 The "core leak" flow, hidden | Issues a real `GetAccountRange` for the user's address and MPT-verifies the proof — over Tor, with the user's IP behind three hops. |

### Example run (real output)

```
[3/3] Verified snap account reads over Tor — one isolated circuit + ephemeral key PER address:

  address[0] 0xd8da6bf26964af9d7eed9e03e53415d37aa96045  (isolation token #0, fresh ephemeral key)
      timing: dial=135ms  +rlpx=273ms  +eth/69=420ms  +snap=985ms
      peer=... client="Geth/v1.17.3-stable/linux-amd64" head=#25545115 stateRoot=0x2b619530c404…
      VERIFIED present: nonce=5932 balance=0x5c54eb1980c072b3 wei  codeHash=0xd8ef78646344
```

## The one production change this required

Making the RLPx transport stream-generic (`rust/myotis-net`):

- `RlpxConnection<S = TcpStream>` and `EthSession<S = TcpStream>` — the default
  type parameter keeps every clearnet caller untouched; the Tor path supplies
  `S = arti_client::DataStream`.
- `RlpxConnection::handshake_over(stream, key, pubkey)` runs the initiator
  handshake over an already-connected stream (TCP or Tor).
- **Flush after every write.** A `TcpStream` sends eagerly; Arti's `DataStream`
  buffers until flushed. Without the added `flush()` calls the peer never sees
  our auth and FINs — the whole Tor path failed with "early eof" reading the
  ack until this was fixed. (Harmless no-op on TCP.)

## Empirical findings (feed back into the design)

- **Arti bootstrap:** ~11 s cold. RLPx-over-Tor handshake to an accepting peer:
  ~0.7–2 s; a full verified snap read: ~1–5 s. In line with the latency budget
  discussion (§8.5).
- **Exit-pool health for `:30303` is a real constraint (§2, §8.1).** Some
  circuits fail with "no exit circuit for ports" (reduced exit policy excludes
  30303); others reach the peer but time out.
- **Peer-side acceptance of Tor exits is the dominant blocker, not the
  transport.** Many synced full nodes are inbound-saturated and drop Tor-exit
  connections (immediate FIN after auth) or send `reason=4` (Too Many Peers).
  Tor-accepting peers skew toward *less-busy* nodes — occasionally unsynced ones
  advertising head #0. The PoC therefore retries fresh circuits and explicitly
  selects a **synced** Tor-reachable peer. Production peer selection (the §5
  quarantined pool) must likewise prefer peers that accept Tor inbound.

## Running it

```bash
# Uses the daemon's peers.cache to find live snap peers (the design's
# clearnet-discovery → Tor-use split). Point it at a populated cache:
MYOTIS_PEER_CACHE=/path/to/app/peers.cache \
  cargo run --manifest-path rust/tor-poc/Cargo.toml

# Query specific addresses:
MYOTIS_PEER_CACHE=... cargo run --manifest-path rust/tor-poc/Cargo.toml -- \
  0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
```

With no populated cache it falls back to the go-ethereum bootnodes, which are
usually discovery-only and won't serve snap — a fresh `peers.cache` from a
short `./gradlew :app:run` is the reliable source of live snap peers.

## Scope / what this is NOT

- No quarantined peer pool (§5), no multi-source popularity promotion (§6.2),
  no generic request-shape hardening (§6.3).
- The snap proof anchors to the peer's **claimed fresh head**, not the
  beacon-verified anchor that is the wallet's real trust root. This is a
  networking-plumbing proof, not a trust-model change.
