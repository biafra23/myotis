# 02 — Execution-Layer Networking (devp2p)

> Companion to the [re-implementation spec](README.md). Covers the **devp2p** stack that finds
> execution-layer peers and fetches block/state data: `core` crypto/types, discv4, discv5, EIP-1459
> DNS discovery, RLPx (ECIES handshake + AES-CTR framed channel), and the `eth` / `snap`
> sub-protocols.

Reference modules: `core/` and `networking/` (`com.jaeckel.ethp2p.core`, `…networking`).

> **Scope note.** The reference is a **client/dialer only**: it dials peers but never listens; it
> sends discv4 Ping/FindNode but does **not** respond to FindNode and does **not** implement
> ENRRequest/ENRResponse; it answers inbound `eth`/`snap` requests with **empty** responses (so
> peers don't time out and disconnect). A re-implementation that also *serves* would need the
> responder halves. For a wallet engine, client-only is correct and far simpler.

---

## 1. `core` — primitives shared by every layer

### 1.1 `NodeKey` — secp256k1 identity

Wraps a secp256k1 keypair (load-or-generate, persisted as a 32-byte hex secret).
- `publicKeyBytes()` → **64-byte uncompressed pubkey without the `0x04` prefix**.
- **`nodeId() = keccak256(publicKeyBytes)`** (32 bytes) — the Kademlia node ID / enode id.
- `sign(hash)` signs a **pre-computed 32-byte hash with no re-hashing** (must match go-ethereum).

### 1.2 `BlockHeader`

Immutable EL header decoded via RLP, fields in order: `parentHash, ommersHash, beneficiary(20),
stateRoot, transactionsRoot, receiptsRoot, logsBloom(256), difficulty(bigint), number, gasLimit,
gasUsed, timestamp, extraData, mixHash/prevRandao, nonce(8)`, then **optional trailing fields
parsed only while the RLP list has more items** (not by fork detection): `baseFeePerGas`
(EIP-1559), `withdrawalsRoot` (EIP-4895), `blobGasUsed`/`excessBlobGas` (EIP-4844, sentinel -1),
`parentBeaconBlockRoot` (EIP-4788); EIP-7685 `requestsHash` is read-and-discarded.
`hash(rlpBytes) = keccak256(rlp)` — the verifiable anchor.

### 1.3 `Enr` (EIP-778 Ethereum Node Record)

Wire form `RLP([signature, seq, k, v, …])`; `enr:`-prefixed strings are **base64url**-decoded.
Decode skips the signature, reads `seq`, then key/value pairs (list-valued pairs like `eth2`,
`attnets` are skipped in the generic map, re-parsed on demand). **The ENR signature is not
verified in the discv4/discv5 decode path** (it is verified in the DNS path — see §4). Keys used:
`id, ip, tcp, udp, secp256k1` (stored **33-byte compressed**, decompressed to 64-byte on demand).
Helpers: `eth2()` (CL `fork_digest(4) ‖ next_fork_version(4) ‖ next_fork_epoch(u64 LE)`),
`ethForkIdHash()` (EL EIP-868 `eth` field, re-parsed from raw RLP), `toLibp2pMultiaddr()` /
`derivePeerId()` (protobuf-wrap the compressed key → identity multihash → base58).

### 1.4 MPT proof verifier (`core/trie`) — covered in companion 03

`MerklePatriciaProofVerifier` + `HexPrefix` + `RlpItems`. The state trust anchor; see companion 03.

---

## 2. discv4 — UDP Kademlia discovery

### 2.1 Packet wire format

```
packet = hash(32) ‖ signature(65) ‖ packet-type(1) ‖ packet-data(RLP)
  sigHash   = keccak256(packet-type ‖ packet-data)
  signature = secp256k1_sign(sigHash)        → 65 bytes  [ r(32) ‖ s(32) ‖ v(1) ]   v = recid 0/1
  hash      = keccak256(signature ‖ packet-type ‖ packet-data)
```

`parse()`: min 98 bytes; verify `hash == keccak256(packet[32:])`; recover sender pubkey via
`recoverFromHashAndSignature(keccak256(packet[97:]), sig)`. r/s zero-padded to 32 bytes.

Types & bodies (`VERSION = 4`, `expiry = now + 20 s`; endpoint = `[ip(4|16), udpPort, tcpPort]`):

| Type | Code | Body |
|---|---|---|
| Ping | `0x01` | `[version, from, to, expiry]` (`from` carries our tcpPort; `to.tcpPort` = 0) |
| Pong | `0x02` | `[to, ping-hash, expiry]` (`ping-hash` = 32-byte hash of the Ping answered) |
| FindNode | `0x03` | `[target(64-byte pubkey), expiry]` |
| Neighbors | `0x04` | `[[ip, udp, tcp, nodeId], …], expiry]` (decode only) |

(ENRRequest/ENRResponse `0x05/0x06` are not implemented.)

### 2.2 Kademlia table

256 buckets (one per distance bit), `K = 16` per bucket. Distance = XOR of node IDs
(`keccak256(pubkey)`); bucket index = leading-zero count of the XOR distance, clamped to 255.
`add` dedups by nodeId; if a bucket is full it drops the oldest (the reference notes real
ping-before-evict is not implemented). `closest(target, k)` sorts all entries by XOR distance.
The table is behind a single lock.

### 2.3 Handler & service behavior (client-only)

- On **Ping**: rate-limit, send Pong, record the sender's advertised tcpPort, add to table, fire
  `onPeerDiscovered`. (Does **not** send FindNode on Ping.)
- On **Pong**: verify against a `pendingPings` map (`addr → expected ping hash`), add to table.
- On **Neighbors**: decode, add each, fire the callback.
- **Bonding/endpoint proof** is initiator-only: we ping, store the hash, verify the matching pong.
- **Rate limiting**: per-IP sliding window, 5 pings / 10 s.
- The service binds a UDP socket with a **fixed 4096-byte receive buffer + 1 MB SO_RCVBUF**
  (NEIGHBORS packets are ~1.2 KB and default allocators truncate them on some stacks — notably
  Android/ART). Refresh every 15 s: if the table is empty re-ping bootnodes; else FindNode to
  bootnodes (target = our own pubkey) and ping-then-FindNode to ≤10 random peers with a random
  64-byte target to spread across the keyspace.

---

## 3. discv5 (consensus-layer discovery)

discv5 is **not hand-rolled** — the reference wraps the ConsenSys `io.consensys.protocols:discovery`
library (the same one Teku uses). A port should use the `discv5` crate (Rust) or go-ethereum's v5
discovery (Go) rather than re-implementing the wire.

Behavior the wrapper adds: build a `NodeRecord` signed with the node key, seed from
`clDiscv5Bootnodes`, poll `streamLiveNodes()` on a 15 s timer, diff against a seen-set, convert
each new record to an `Enr`, and hand it up. Port-bind is resilient (probe the requested UDP port,
fall back to an OS-chosen free port — a light client never accepts inbound, so a fallback port is
fine). discv5 is **non-essential**: if it fails to start, EL keeps working and the CL falls back to
cache + seed multiaddrs.

---

## 4. EIP-1459 DNS discovery (`dns/`)

A DNS-TXT merkle tree of ENRs — the EF publishes one for the EL (`all.mainnet.ethdisco.net`).
Doubles as a **discv4-independent dial path** on NAT/CGNAT/mobile networks where unsolicited
inbound UDP is dropped.

- `enrtree://<base32-compressed-pubkey>@<domain>` — the base32 key is the 33-byte compressed
  tree-operator key. The tree is authoritative **iff its root TXT signature recovers to this key**.
- Records: `enrtree-root:v1 …`, `enrtree-branch:<hash>,<hash>,…`, `enr:<base64url>`.
- **Root verification (the trust step):** signed message = the root string **minus the trailing
  ` sig=<base64url>`**; signature = 65 bytes `r‖s‖v` base64url-no-padding over `keccak256(message)`;
  the recovered pubkey **must equal** the URL's key, else reject. Parse `e=`(eRoot), `l=`(lRoot),
  `seq=`.
- Walk from `eRoot`: fetch each node as TXT at `<hash>.<domain>`; `enrtree-branch:` → push
  children; `enr:` → parse. Only the `e=` ENR subtree is walked (the `l=` link subtree is ignored).
  Caps: 512 nodes, depth 16, per-lookup 2 s, overall deadline + grace.
- DNS transport tries last-good server → host-supplied DNS IPs (mobile) → system resolver →
  public fallbacks `1.1.1.1`/`8.8.8.8` **over TCP** (SLIRP NAT on emulators forwards TCP DNS when
  UDP is broken). Parallelized over a small fixed pool.

The engine refreshes the resolved ENR pool periodically (rate-capped) and fork-filters it; it's the
candidate pool the snap-peer maintainer dials from. Chains with no DNS tree (Gnosis) instead carry
a list of full `enode://pubkey@host:port` constants for direct RLPx dialing.

---

## 5. RLPx — TCP transport (ECIES/EIP-8 handshake → AES-CTR framed channel)

Initiator-only. This is the trickiest wire code to port; the constants below are load-bearing.

### 5.1 ECIES (`EciesCodec`)

Encrypted message: `0x04 ‖ ephemeral-pubkey(65) ‖ IV(16) ‖ ciphertext ‖ MAC(32)`.

- ECDH over secp256k1; shared secret = the 32-byte big-endian X coordinate.
- **KDF = NIST SP 800-56 concatenation KDF with SHA-256**: `SHA256(counter_be32 ‖ Z)` with the
  counter starting at 1, until ≥32 bytes; `encKey = out[0:16]` (AES-128), `macKey = out[16:32]`.
  **⚠ Do not use a library `KDF2`** — BouncyCastle's `KDF2BytesGenerator` computes
  `SHA256(Z ‖ counter)` (wrong order) and silently breaks the handshake.
- Symmetric cipher: **AES-128-CTR** with a random 16-byte IV.
- MAC = `HMAC-SHA256( SHA256(macKey), IV ‖ ciphertext ‖ aad )`. **AAD is always included** (even
  when empty).

### 5.2 Handshake (`AuthHandshake`, EIP-8)

Bodies (RLP):
- Auth: `[sig(65), pubkey(64), nonce(32), version(4), …padding]` — EIP-8 random padding (100–300
  bytes) is a **trailing list element** (go-eth `rlp:"tail"`).
- Ack: `[ephemeral-pubkey(64), nonce(32), version(4)]`.

Build auth:
```
staticShared = ECDH(localStaticPriv, remoteStaticPub)         // 32 bytes
token        = staticShared XOR localNonce
sig          = signHashed(token, ephemeralKey)                // sign the token DIRECTLY, no re-hash
authBody     = RLP([sig, localStaticPub64, localNonce, version, padding])
encSize      = bodyLen + 65 + 16 + 32
sizePrefix   = uint16_be(encSize)                             // 2 bytes
ciphertext   = ECIES_encrypt(authBody, aad = sizePrefix)      // size prefix is the ECIES AAD
wire         = sizePrefix ‖ ciphertext                        // save the full wire bytes for MAC seeding
```
Process ack symmetrically (the ack size prefix is its ECIES AAD).

**Key derivation:**
```
ephShared    = ECDH(localEphemeralPriv, remoteEphemeralPub)
sharedSecret = keccak256( ephShared ‖ keccak256(remoteNonce ‖ localNonce) )
aesSecret    = keccak256( ephShared ‖ sharedSecret )
macSecret    = keccak256( ephShared ‖ aesSecret )
```

### 5.3 Framed channel (`FrameCodec`) — AES-256-CTR + keccak MAC chains

Frame: `header(16) ‖ header-mac(16) ‖ body(padded to 16) ‖ body-mac(16)`.
Header (16, encrypted): `body-size(3 be) ‖ rlp([0, 0]) = 0xc2 0x80 0x80 ‖ zero padding`.
The header-data MUST be the canonical geth `zeroHeader` `rlp([0, 0])`, **not** a bare
empty list `0xc0`: Nethermind's `FrameHeaderReader` unconditionally decodes an integer
from the first sequence item and throws on `0xc0` + zero padding, killing the session
with Disconnect `0x10` on the first frame (fatal on the Nethermind-dominant gnosis
network — myotis #291).

- **Two AES-256-CTR ciphers** (egress encrypt / ingress decrypt), both keyed with `aesSecret`,
  **zero IV, one continuous keystream per direction**.
- **MAC keccak chains** (go-eth compatible), initiator side:
  ```
  egress-mac:  keccak.update(macSecret XOR respNonce); keccak.update(authWireBytes)
  ingress-mac: keccak.update(macSecret XOR initNonce); keccak.update(ackWireBytes)
  updateMac(seed16): aesbuf = AES256-ECB(currentDigest[:16]) XOR seed[:16];
                     keccak.update(aesbuf); return keccak.digest[:16]
  ```
  The MAC AES is a **separate ECB cipher keyed with `macSecret`**; `currentDigest()` clones the
  keccak state to read non-destructively.
- **Encode**: Snappy-compress the payload **except Hello (code 0x00)**; prepend the RLP-encoded
  msg-id; pad to 16; encrypt header → `headerMac = egressMac.updateMac(encHeader)`; encrypt body →
  feed `encBody` into the egress mac, then `bodyMac = egressMac.updateMac(egressDigest[:16])`.
- **Decode**: verify `ingressMac.updateMac(encHeader) == headerMac`, decrypt header, read the
  3-byte body size (cap 10 MB), feed `encBody` into the ingress mac, verify body mac, decrypt,
  strip the RLP msg-id, Snappy-**uncompress except Hello** (with a fallback to raw — some peers
  send Disconnect/Ping/Pong uncompressed).

### 5.4 State machine & p2p control

`HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED`. On reaching FRAMED, fire a `RLPX_READY` event up to
the `eth` layer. p2p control messages: Hello `0x00`, Disconnect `0x01`, Ping `0x02`, Pong `0x03`.
The frame codec is stateful and not thread-safe — all sends must be marshaled onto the connection's
single event loop.

### 5.5 Connection management

A shared event-loop group (4 threads) handles all peer connections; per-connection pipeline is
`rlpx → eth`. Request methods return futures: headers (batched 1024/req with per-peer failover),
bodies, receipts, snap account/storage (peer failover), and `broadcastTransaction` to all ready
peers. A "snap-heavy" gate pauses *new* dials while a long snap round-trip chain (e.g. ENS) runs,
to avoid event-loop contention.

---

## 6. The `eth` sub-protocol (eth/66–69)

### 6.1 Handler state machine

`AWAITING_HELLO → AWAITING_STATUS → READY`, triggered by `RLPX_READY` → send Hello, with a 30 s
handshake timeout that closes the connection if READY isn't reached.

### 6.2 Capability negotiation (Hello)

Hello RLP: `[protocolVersion(5), clientId, [[capName, capVersion], …], listenPort, nodeId(64)]`.
Advertise `eth/66, eth/67, eth/68, eth/69, snap/1` (capabilities ascending). Negotiate the highest
mutually supported eth version (`{66,67,68}` floor 66 — it introduced request-ids and shares the
Status/snap layout with 67/68; ≤65 rejected; 69 supported). `snap/1` negotiated if the peer
advertises it.

### 6.3 Message codes (absolute, p2p base 0x10)

p2p: `0x00 Hello, 0x01 Disconnect, 0x02 Ping, 0x03 Pong`.
eth: `0x10 Status, 0x11 NewBlockHashes, 0x12 Transactions, 0x13 GetBlockHeaders,
0x14 BlockHeaders, 0x15 GetBlockBodies, 0x16 BlockBodies, 0x17 NewBlock,
0x18 NewPooledTransactionHashes, 0x19 GetPooledTransactions, 0x1a PooledTransactions,
0x1f GetReceipts (eth msg 0x0f), 0x20 Receipts (eth msg 0x10)`.
A wallet ignores gossip/mempool messages (`0x11/0x12/0x17/0x18/0x19/0x1a/0x1d/0x1e`) on receipt.

### 6.4 Status handshake

- eth/67–68: `[protocolVersion, networkId, td, bestHash, genesisHash, forkId([forkHash, forkNext])]`
  (post-Merge `td` = empty bytes).
- eth/69: `[protocolVersion, networkId, genesis, forkId, earliestBlock, latestBlock, latestBlockHash]`
  (no TD; carries block numbers).
- Compatibility gate: `networkId == expected && genesisHash == expected`. Incompatible → close
  (and don't let a foreign chain's head poison local state). Remote peers validate **our** fork id
  and disconnect on mismatch, so it must be correct (the reference pins it; see README §6).

### 6.5 Request/response correlation

A single `AtomicLong` request-id (from 1); per-message-type maps of `requestId → future`. Each
request allocates an id, registers the future, sends, and arms a timeout that removes the map
entry. Responses decode the id and complete the matching future. On disconnect, all pending
futures complete exceptionally.

### 6.6 Message wire formats

- **GetBlockHeaders** `[reqId, [startBlockOrHash, maxHeaders, skip, reverse]]` (eth/69 drops
  reqId). Start ≤8 bytes ⇒ block number, else a 32-byte hash.
- **BlockHeaders** `[reqId, [header, …]]`. Each header is **re-encoded canonically** to compute
  `keccak256` → `(hash, header, rawRlp)`. Tolerate unknown trailing header fields.
- **GetBlockBodies / BlockBodies** `[reqId, [hash, …]]` / `[reqId, [[txs, uncles, withdrawals?], …]]`.
  Legacy txs (RLP list) re-encoded; typed txs (EIP-2718) kept as a byte string.
- **GetReceipts / Receipts** `[reqId, [hash, …]]` / `[reqId, [[receipt, …], …]]`. Capture the **raw
  consensus receipt bytes** (the trie value). **eth/69 (EIP-7642** — the `eth` *wire-protocol* change
"history expiry and simpler receipts"; distinct from the consensus-level **EIP-7668** "Remove bloom
filters"**)** receipts are *bloomless* and
  envelope-flattened `[txType, statusOrState, cumGas, logs]` — **recompute the 2048-bit logs bloom**
  (M3:2048 — three bits from the low 11 bits of keccak byte-pairs) and re-canonicalize so
  `receiptsRoot` verification is version-agnostic.
- **Transactions** `[tx, …]` (legacy embedded as RLP list, typed as byte string) — used for
  outbound broadcast and matching the node's own gossip.

---

## 7. The `snap` sub-protocol (snap/1)

No separate handler — dispatched inside the `eth` handler. **Use `GetAccountRange` /
`GetStorageRanges` (they return full root-to-leaf Merkle proofs), not `GetTrieNodes`** (geth's
`GetTrieNodes` returns only the node at the path — no descend-able proof, useless for verifying
from a state root).

### 7.1 Dynamic message codes

snap base = `0x10 + eth-protocol-length`. eth/67–68 length 17 → base `0x21`; eth/69 length 18
(adds BlockRangeUpdate `0x11`) → base `0x22`. Offsets from base:
`0x00 GetAccountRange / 0x01 AccountRange, 0x02 GetStorageRanges / 0x03 StorageRanges,
0x04 GetByteCodes / 0x05 ByteCodes, 0x06 GetTrieNodes / 0x07 TrieNodes`.

### 7.2 Wire formats

- **GetAccountRange** `[reqId, stateRoot, startingHash, limitHash, responseBytes]`. Single-account
  lookup: `startingHash = keccak256(address)`, `limitHash = 0xff…ff`.
- **AccountRange** `[reqId, [[accountHash, slimAccountBody], …], [proofNode, …]]`. `slimAccountBody`
  is `[nonce, balance, storageRoot, codeHash]` (slim form: empty storageRoot/codeHash default to
  EMPTY_ROOT / EMPTY_CODE_HASH).
- **GetStorageRanges** `[reqId, stateRoot, [accountHash, …], startingHash, limitHash, responseBytes]`.
- **StorageRanges** `[reqId, [[slots-for-account-0], …], [proofNode, …]]`; read the first account's
  slots `[[slotHash, slotValue], …]`. The slot value is double-RLP-wrapped (`rlp(rlp(uint256))`).
- **GetByteCodes** `[reqId, [codeHash, …], responseBytes]` / **ByteCodes** `[reqId, [bytecode, …]]`
  (same order; hash each and match `codeHash`).
- **GetTrieNodes / TrieNodes** wired at the wire layer but deliberately not used by the state
  oracle (see above).

### 7.3 How state is fetched & verified (critical)

1. **Fresh, per-peer state root.** Before any snap query, fetch the peer's *current* head header
   (by its `peerBestBlockHash`) and use *that* header's `stateRoot`. Peers prune state beyond ~128
   blocks, so a root from peer A is unsafe against peer B. Reject stale heads
   (`minSensibleHeadBlock` floor).
2. Send `GetAccountRange(reqId, freshStateRoot, accountHash, 0xff…ff, ~4 KB)`. The **full
   `[origin, 0xff…ff]` range with a small `responseBytes` cap** is deliberate: the peer returns at
   least one account **plus the complete boundary proof** regardless of the cap, so the proof is
   never truncated while the discarded data page stays tiny.
3. Verify with the MPT verifier (companion 03) against the fresh state root; storage verifies
   against the account's proven `storageRoot`; bytecode by `keccak256(code) == codeHash`. On
   failure, rotate to the next peer (and mark this peer as not serving this root).
4. As a wallet, answer all inbound snap `Get*` with empty responses so peers don't disconnect.

---

## 8. NetworkConfig & the per-network constants

See [README §6](README.md#6-network-configuration) for the full table. Key reminders for this
layer: each network pins `genesisHash`, a 4-byte EIP-2124 `forkIdHash` (the reference pins it;
implement real CRC32 fork-id for forward-compat), `bootnodes` (bare ip:port for discv4 pings),
`elEnrTreeUrls` (EIP-1459 trees), and `elBootEnodes` (full enode:// for direct dial on chains
without a DNS tree). Per-network ports keep stacks from colliding (mainnet 30303, Gnosis 30304,
Sepolia 30305 for both RLPx-TCP and discv4-UDP).

---

## 9. Re-implementation gotchas (load-bearing)

1. discv4 signs `keccak256(type ‖ data)` directly (no double hash); outer `hash = keccak256(sig ‖
   type ‖ data)`.
2. ECIES KDF is **`SHA256(counter ‖ Z)`** (NIST concat-KDF), **not** `SHA256(Z ‖ counter)`.
3. RLPx auth `sig` signs the **token (`staticShared XOR localNonce`) directly**; recovery uses
   `Ecrecover(token, sig)`.
4. The EIP-8 2-byte size prefix is the **ECIES AAD**, and the full wire bytes (including the prefix)
   seed the MAC keccak chains.
5. AES-256-CTR uses a **zero IV and one continuous keystream per direction**; the MAC AES is a
   separate ECB cipher keyed with `macSecret`.
6. Snappy applies to **all messages except Hello**, with a raw fallback for uncompressed control
   messages.
7. snap requests use the full `[origin, 0xff…ff]` range + small `responseBytes` to get a complete
   boundary proof; the data page is discarded.
8. snap state roots must be **per-peer and fresh** (peers prune beyond ~128 blocks).
9. eth/69 receipts are bloomless — recompute the logs bloom before any `receiptsRoot` check.
10. discv4 needs a large fixed UDP receive buffer (NEIGHBORS packets are truncated by default
    allocators on some stacks).
11. The whole stack is client/dialer-only; add responder halves only if you intend to serve.
