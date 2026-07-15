# Chunk 3 design — sent-tx watch + pending overlay (Rust engine)

Working notes for the `claude/rust-sent-tx-watch` branch. Java twins:
`SentTxTracker` / `PendingNonceTracker` / their `VerifiedRpcBackend` wiring
(constants and semantics below are the Java engine's, byte-for-byte where they
reach the wire). Delete this file when the slice lands in docs/07.

## Components

### `el/sent_tx.rs` (new, sans-I/O, unit-tested)

- `SentTxTracker` — `HashMap<[u8;32], Watch>` behind the reader's usual
  `std::sync::Mutex`. `Watch { broadcast_at: Instant, seen_at: Option<Instant>,
  broadcast_head: Option<u64> }`. TTL 180s (`SENT_TX_WATCH_TTL`). Methods:
  `watch`, `broadcast_head`, `watching_any`, `mark_seen` (first sighting only →
  returns latency), `confirm_mined` (remove), `unseen`, `evict_expired`.
  Strict `>` on the TTL boundary (Java parity).
- `PendingNonceTracker` — `HashMap<[u8;20], (u64 nonce, Instant at)>`.
  TTL 90s. `record` keeps the HIGHEST nonce (`>=` refreshes timestamp);
  `overlay(sender, mined)`: entry mined-past (`mined > nonce`) or expired →
  remove + return `mined`; else `max(mined, nonce + 1)`. Never lowers below
  the verified mined floor. NOT reusable for settled tags (Java doc).
- Sent-tx raw-bytes cache: `myotis_evm::Lru<[u8;32], Vec<u8>>`, cap 256
  (`SENT_TX_CACHE_MAX`, the Java `sentTxCache` LRU twin).

### Reader integration (`el/reader.rs`)

- `send_raw_transaction`: after ≥1 peer accepted — cache raw bytes, decode
  via `tx::decode_summary` → `pending_nonces.record(from, nonce)` (skip
  silently if undecodable/senderless), `sent_tx_watch.watch(hash, now,
  anchor.optimistic_block_number())` (the Java broadcast head is the beacon
  OPTIMISTIC number, not the scan anchor's head — keep that asymmetry).
- `locate_mined_tx`: on the FIRST scan for a hash, reach `from` back to
  `sent_tx_watch.broadcast_head(hash)` when it is below the initial 8-block
  lookback, still capped by `RECEIPT_MAX_SCAN_BLOCKS_PER_POLL` (128) and
  clamped ≥ 0 (Java 2334-2345).
- Receipt path: `confirm_mined(hash)` once a verified receipt is built
  (Java 2552); same from the tx-by-hash mined path.
- `get_transaction_by_hash`: when the scan says "not seen" AND the sent-tx
  cache holds the raw bytes → serve the PENDING shape: decoded tx with
  `blockHash`/`blockNumber`/`transactionIndex` as explicit JSON null
  (present-but-null, NOT omitted — load-bearing wire parity). Plumb as
  `VerifiedTransaction` with the block fields made `Option` (None = pending)
  OR a dedicated pending variant in eljson — decide at implementation;
  eljson must emit exactly the Java `buildTxJson` pending branch.
- `pending_nonce_overlay(addr20, mined) -> u64` — public, for the account
  read path when the tag is `pending` only.
- Rebroadcast: tokio interval task (20s, `TX_REBROADCAST_INTERVAL`), spawned
  where the reader/pool tasks are spawned; each tick: `evict_expired`, then
  for each `unseen()` hash with cached bytes, `peer.send_transaction(raw)` to
  the current snap peers (peers dedupe; re-send is harmless). Java gates a
  20s rebroadcast inside a 5s warmer — the interval task is equivalent.

### Gossip "seen" hook — documented divergence

Java observes `NewPooledTransactionHashes` via a Netty pipeline observer.
The Rust session has NO standing per-peer read loop: frames are only read
inside `await_response`, which currently SKIPS non-matching codes. Hook
there (and in `recv_answering_ping` if that's the shared reader): when
`frame.message_code == NEW_POOLED_TRANSACTION_HASHES (0x18)` and
`sent_tx_watch.watching_any()`, decode the hash list (eth/68 shape:
[types, sizes, hashes] — tolerate the eth/66 flat list) and `mark_seen`
each. DIVERGENCE (document in the PR + code): with no request in flight the
Rust engine reads no frames, so a sighting can be delayed until the next
poll — acceptable because "seen" only gates the 20s rebroadcast (peers
dedupe repeats); it is not a trust surface. A standing read loop is a
deliberate non-goal (architecture change).

### FFI / hosts (ABI 19)

- `get_transaction_by_hash` already crosses as JSON — the pending shape needs
  NO new native (the tri-state "null" case simply becomes rarer for own txs).
- Pending nonce: `nativeGetTransactionCountJson`? — today RustVerifiedReads
  derives the nonce from `requestAccount`. Add a small native
  `nativePendingNonceOverlay(handle, address20Hex, minedNonce) -> long`
  (returns the overlaid nonce; identity when no entry) OR fold into the
  account JSON. PREFER the dedicated native: requestAccount is a hot shared
  path and its JSON is golden-pinned; a bolted-on field would churn goldens
  for an overlay only `pending` reads use. RustVerifiedReads.getTransactionCount
  calls it only when `block == "pending"` (Java 801-802 twin). Mirror into
  capi.rs + header + RustEngine.kt + IosRpcBackend (iOS twin rule from #235).
- ABI 18 → 19 (lib.rs doc line, RustEngineNative, RustEngine.kt, header
  comment), jniLibs regen.

## Constants (Java parity)

| const | value |
|---|---|
| SENT_TX_WATCH_TTL | 180s |
| PENDING_NONCE_TTL | 90s |
| TX_REBROADCAST_INTERVAL | 20s |
| SENT_TX_CACHE_MAX | 256 |
| reachback cap | RECEIPT_MAX_SCAN_BLOCKS_PER_POLL = 128 |

## Test plan

- `sent_tx.rs` unit tests mirroring SentTxTrackerTest/PendingNonceTrackerTest
  (TTL boundary strict `>`, highest-nonce record, overlay max rule,
  mined-past removal, first-sighting-only latency).
- eljson golden: pending tx JSON (block trio as JSON null, omit rules for
  chainId/from/gasPrice/1559 fields/yParity) vs the Java buildTxJson pending
  branch output.
- Reachback: locate cursor unit-style test if the scan seam allows; else
  covered by review + the integration gate.
