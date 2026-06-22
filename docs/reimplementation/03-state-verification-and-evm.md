# 03 — State Verification, Local EVM, and ENS

> Companion to the [re-implementation spec](README.md). Covers how peer-served state is verified
> (Merkle-Patricia proofs), the SNAP-backed state oracle, the local EVM stack (view calls + gas
> estimation), the ABI codec, CCIP-Read (ERC-3668), and ENS resolution.

Reference modules: `myotis-evm/` (`io.myotis.evm`) and `myotis-ens/` (`io.myotis.ens`); the MPT
verifier lives in `core/` (`com.jaeckel.ethp2p.core.trie`).

> **Biggest single port:** the EVM. The reference embeds **Hyperledger Besu's standalone `evm`
> module**. Replace it with **revm** (Rust) or **go-ethereum `core/vm`** (Go). Everything in the
> `world` package is an adapter to Besu's `WorldUpdater` SPI — re-target it to revm's
> `Database`/`DatabaseRef` trait or geth's `vm.StateDB`.

---

## 1. The trust chain this layer implements

```
beacon-anchored EL stateRoot  (from companion 01 — execution branch + header-chain/stateRootMatch)
   ├─ account:  MPT proof over keccak256(address)        → [nonce, balance, storageRoot, codeHash]
   ├─ storage:  MPT proof over keccak256(slot) at the account's storageRoot → uint256 value
   ├─ code:     keccak256(code) == codeHash (from the proven account leaf)
   └─ EVM:      execute resolver/contract bytecode, every SLOAD/account read served+verified above
```

**Two security invariants restated** (companion 01 §11 / README §11): `storageRoot` and `codeHash`
must come **only** from the proof-verified account leaf (never a peer's "slim" body); storage
proofs anchor at the **account's `storageRoot`**, not the world `stateRoot`.

---

## 2. Merkle-Patricia proof verification (`core/trie`) — the state trust anchor

Three files: `MerklePatriciaProofVerifier`, `HexPrefix`, `RlpItems`. keccak-256 + RLP, big-endian.
**Port this by hand and test it against known proofs even if a library exists** — the Found / Absent
/ Invalid semantics are load-bearing.

- `EMPTY_TRIE_ROOT = keccak256(rlp("")) = 0x56e81f17…363b421`.
- `verify(root, key, proofNodes) -> Found(value) | Absent() | Invalid(reason)`:
  1. Index proof nodes by `keccak256(node)` into a map (tolerates out-of-order nodes).
  2. Convert `key` to nibbles; descend from `root` by hash:
     - **17 items** = branch: consume one nibble, descend that slot; if the path is exhausted read
       slot 16 (the value slot).
     - **2 items** = leaf or extension, distinguished by the **hex-prefix** first-nibble flag
       (`HexPrefix`: `0`=ext-even, `1`=ext-odd, `2`=leaf-even, `3`=leaf-odd).
     - child reference: 32 bytes ⇒ look up the next node by hash; sub-32-byte list ⇒ an **embedded**
       node, interpreted inline (no hash step).
  3. Missing node / wrong arity / size mismatch ⇒ `Invalid`. Path divergence ⇒ `Absent`
     (a valid exclusion proof). Full key consumed at a leaf ⇒ `Found(value)`.
- Account leaf value is RLP `[nonce, balance, storageRoot, codeHash]`. Storage leaf value is
  `rlp(trimmed_uint256)` (strip the inner RLP header, then `uint256` big-endian).
- `OrderedTrieRoot` (in `consensus/proof`) rebuilds the tx/receipt/withdrawals trie root from an
  **ordered list** using `key = RLP(index)` **un-hashed** as the path — so a full body/receipt list
  is checked against the header's `transactionsRoot`/`receiptsRoot` without trusting the peer.

---

## 3. The SNAP-backed state oracle (`world` package)

### 3.1 Interfaces

- `SnapStateOracle` — async state source: `fetchAccount(stateRoot, addr)`,
  `fetchStorage(stateRoot, addr, slot)`, `fetchBytecode(codeHash)`, `fetchBatch(...)`.
- `SnapPeer` — wire abstraction decoupling the EVM from the networking module: `getTrieNodes(...)`,
  `getByteCodes(...)`, `reportRootUnavailable()`. **Note the misleading name:** the real adapter
  routes account-only requests to `GetAccountRange` and storage requests to `GetStorageRanges`
  (both return proofs), **not** to snap `GetTrieNodes`.
- `BytecodeCache` (codeHash → code; immutable forever, cross-session-safe).
- `StateProofCache` (cross-call, keyed by `stateRoot`).

### 3.2 `SnapBackedStateOracle` — verify-on-fetch

- **Account** (`keccak256(address)` → `GetAccountRange` → `MerklePatriciaProofVerifier.verify`):
  `Invalid` → throw `InvalidProof`; `Absent` → empty account `(0, 0, EMPTY_CODE_HASH,
  EMPTY_TRIE_ROOT)`; `Found` → decode the leaf.
- **Storage**: fetch the account first (re-using the cache) for its proven `storageRoot`; if it's
  `EMPTY_TRIE_ROOT`, the value is zero with no round-trip; else `keccak256(padded slot)` →
  `GetStorageRanges` → verify against `storageRoot`.
- **Bytecode**: `keccak256(returned) == codeHash` or `InvalidProof`; empty-code-hash short-circuits;
  cache forever.
- **Peer rotation**: run an op against successive peers up to `maxAttempts` (3 by default; the RPC
  backend uses 8). `InvalidProof` / `StateUnavailable` / timeout / IO all rotate; on a "can't serve
  this root" cause, call `reportRootUnavailable()` so the routing supplier deprioritizes that peer
  for this head.
- **Batching**: coalesce an account→slots map into chunked requests (~64 path-sets each); each item
  still verifies independently (the verifier builds a per-node hash map), collapsing a 1000-account
  sweep from ~1000 round-trips to ~16.
- **Three cache tiers**: per-call (`SyncStateView`), per-resolution in-flight dedup
  (`accountCache`), and cross-call `StateProofCache` (safe because state at a fixed `stateRoot` is
  immutable — a cached `(stateRoot, addr, slot) → value` is a cryptographic fact, not peer-trusted).

### 3.3 Sync↔async bridge (`SyncStateView`)

The EVM is synchronous; the oracle is async. The bridge has three modes:
- **cache-only** — read from in-view caches;
- **block-on-miss** (default) — `fetch…().join()` (blocks the calling thread → must run on a
  worker, never an I/O thread);
- **sentinel-on-miss** (prefetch iteration 0) — return zero/empty placeholders without blocking or
  caching, recording the access; a `sentinelMissCount()` lets the loop tell an all-cache-hit run
  (real result) from one computed on placeholders.

---

## 4. The local EVM stack (`besu` + executor decorators)

### 4.1 Public API

- `EvmExecutor.callView(target, calldata, BlockContext) -> future<bytes>` (view call → raw ABI
  return bytes).
- `EvmExecutor.estimateGas(UnsignedTransaction, BlockContext) -> future<long>`.
- `Address` is a dedicated 20-byte type (deliberately **not** Besu's, to keep the EVM engine out of
  the public API — do the same in a port so the engine is swappable).
- `EvmExecutionError` is a closed/sealed error set: `Reverted(data)`, `OutOfGas`, `InvalidProof`,
  `StateUnavailable`, `CcipGatewayFailed(urls, reasons)`, …

### 4.2 Executor decorator stack (compose outermost-first)

```
CcipReadEvmExecutor( PrefetchingEvmExecutor( DefaultEvmExecutor( SnapBackedStateOracle ) ) )
```

1. **`DefaultEvmExecutor`** — runs one call/tx against the SNAP-backed state and returns the result.
2. **`PrefetchingEvmExecutor`** — a multi-hop speculative loop: run with sentinel-on-miss to record
   every account/storage access, batch-fetch the misses in parallel (semaphore-bounded so a
   1000-token sweep doesn't flood one peer), warm the cache, repeat until a run hits the cache for
   every read, then return *that* run's result. Eliminates the round-trip-per-SLOAD latency. See
   [companion 04 §3](04-engine-and-hosts.md#3-resource-dispatch-for-large-queries-the-metamask-all-balances-at-once-case)
   for the full large-query (MetaMask "all balances at once") dispatch story — intra-call waves,
   batch coalescing, peer fan-out bounding, and inter-call lane/gate/cache fairness.
3. **`CcipReadEvmExecutor`** — catches `OffchainLookup` reverts at the call boundary, fetches the
   gateway response, and re-enters the EVM with the resolver's callback (§6). CCIP is outermost
   because the revert is only observable there; it does **not** apply to `estimateGas`.

### 4.3 View-call frame setup (replicate exactly)

- Build a fork-correct EVM for the block (see §4.5), with the precompile set + gas calculator that
  match the fork.
- Child `WorldUpdater` so commits/reverts don't pollute the read-through cache.
- **Sender = zero address** for view calls (matches geth default); `gasPrice = 0`; `value = 0`;
  `isStatic = true`.
- `initialGas = 30,000,000` (`DEFAULT_GAS_LIMIT`).
- **EIP-7702 delegation**: if the target's code is exactly 23 bytes and starts with `0xef0100`,
  follow the designator **one hop** (chains are not followed — that correctly yields invalid-opcode).
- **BLOCKHASH is deliberately unsupported** (no verified block-hash provider) — fail fast rather
  than return a wrong hash.
- Drive the frame stack until empty; derive the outcome from the original outer frame
  (`COMPLETED_SUCCESS` → output bytes; revert reason present → `Reverted`; insufficient-gas halt →
  `OutOfGas`; else `Reverted` with a human detail).

### 4.4 Gas estimation (replicate exactly)

- Intrinsic gas (Yellow Paper App. G): `21000 + 4·zeroBytes + 16·nonzeroBytes` (EIP-2028).
  **EIP-2930 access lists and EIP-3860 init-code are not modeled; contract creation is unsupported.**
- `evmBudget = ceiling - intrinsic`; run with `isStatic = false` (so SSTORE meters/refunds), real
  `value`, real `from`.
- On success: `total = intrinsic + (evmBudget - remainingGas)`; return **`ceil(total · 1.15)`** (a
  15% safety buffer, rounded **up** so a too-low estimate can't OOG the broadcast tx).
- A reverting/OOG tx **does not get a number** — it throws, so callers never broadcast a doomed tx.
- The JSON-RPC `eth_estimateGas` short-circuits a plain value transfer to a code-less account to
  exactly `21000` (no EVM run, no buffer).

### 4.5 Fork schedule (mainnet, hardcoded — parameterize per chain if needed)

The reference hardcodes mainnet boundaries: pre-Merge **by block number** (London 12,965,000,
Paris 15,537,394), post-Merge **by timestamp** (Shanghai 1,681,338,455, Cancun 1,710,338,135,
Prague 1,746,612,311); **throws below London**. Notable: Shanghai uses Istanbul precompiles (KZG
point-eval is post-Shanghai). A port replicates this table and maps it to the engine's spec id
(revm `SpecId`, geth chain config); parameterize per chain if Gnosis EVM execution is required.

### 4.6 WorldUpdater journal notes

The updater keeps a `touched` map + `deleted` set; child updaters propagate dirty accounts on
commit; the top-level commit is a **no-op** (view-only — the journal is discarded). `SnapAccount`
lazy-loads code/storage and preserves original storage values for refund logic; `isStorageEmpty()`
always returns **false** (you can't prove emptiness under SNAP without enumerating the whole storage
trie — `false` is the safe direction).

---

## 5. ABI codec (`abi` package)

Hand-rolled, dependency-light (deliberately not a full ABI library). Supported: `uint256`,
`address`, `bool`, `bytes32`, dynamic `bytes`, `string`, and dynamic arrays `uint256[]`, `bytes[]`,
`string[]`. **Tuples/structs not supported.** `encodeCall(sig, args…) = keccak256(sig)[:4] ‖
head/tail-encoded args`. The decoder is positional (caller knows the shape) and hardened against
untrusted input (max index 64 MiB; oversized/negative offsets throw a clean error that maps to
`Reverted`, not a DoS). For a port, `alloy`/`ethabi` (Rust) or `go-ethereum/accounts/abi` (Go) work,
but the hand-rolled subset is trivial and keeps mobile binary size down.

---

## 6. CCIP-Read (ERC-3668, `ccipread` package)

### 6.1 The revert

`OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes
extraData)`. Parse by checking the 4-byte selector then the body (min 160 bytes; cap `urls` at 32;
`callbackFunction` is **left-aligned** in its slot).

### 6.2 Gateway iteration

Try URLs **serially** (ERC-3668 §6.4 — first listed should win). Per URL: **GET if the template
contains `{data}`** (request fits in the URL), else **POST** with body `{"sender":"0x..","data":
"0x.."}`. Substitute `{sender}` and `{data}`. Parse `"data":"0x…"` from the response. Detect the
ERC-7884 `HttpError(uint16,string)` selector (`0xca7a4e75`) even in a 200 body and treat it as a
gateway failure (gateways wrap upstream 429/5xx this way). All URLs failing → `CcipGatewayFailed`.

The transport is the injected **`CcipGateway`** interface (`request(method, url, body) -> bytes`) —
so the EVM module has **no HTTP dependency**. Hosts supply it (desktop: native HTTP client; mobile:
platform HTTP client). Needs GET+POST, ~10–15 s timeouts, and a bounded response size (the Android
impl caps at 1 MiB).

### 6.3 Callback re-execution & the verification model (critical)

On `OffchainLookup`: fetch the gateway response, then re-enter the EVM via
`callbackFunction(response, extraData)` against the same SNAP-verified state (recursion capped at 1).
**CCIP-Read data is untrusted** — trust comes from the resolver's own callback validating it
on-chain (typically checking a signer's signature against trusted-signers stored in proof-verified
storage). If the gateway lies, the callback reverts and resolution fails cleanly. The gateway is
never a trust anchor; it's a data carrier whose output passes back through the verified EVM.

---

## 7. ENS resolution (`myotis-ens` + `evm/ens`)

### 7.1 Encodings

- **Namehash** (ENSIP-1): `node = keccak256(node ‖ keccak256(label))` right-to-left; empty name = 32
  zero bytes. **Only lowercase is applied — full UTS-46/IDNA normalization is a documented gap**;
  add it if you need non-ASCII names.
- **DNS-encode** (ENSIP-10): each label length-prefixed (1 byte), zero-terminated; reject empty
  labels and labels >63 bytes.
- **Reverse** (ENSIP-3): `"<lowercase-hex-addr-no-0x>.addr.reverse"`.

### 7.2 Resolution (architectural choice worth keeping)

Despite pinning a UniversalResolver address, forward resolution does resolver **discovery itself**
over SNAP and calls the resolver **directly** (no third-party CCIP relay in the trust path):

1. **Discover resolver** (ENSIP-10 walk): try `registry.resolver(namehash(suffix))` for the exact
   name, then each parent suffix, until non-zero. Cache per `(registry, name)` for 5 min.
2. **Detect extended** resolver via `supportsInterface(0x9061b923)` (IExtendedResolver).
3. **Dispatch**: extended → `resolve(dnsEncode(name), innerCalldata)` then unwrap the ABI bytes;
   exact legacy → call the record method directly; resolver only on an ancestor and not
   wildcard-aware → "no record".
4. **Revert taxonomy**: `OffchainLookup` → rethrow (handled by `CcipReadEvmExecutor`); any other
   revert → "no record" (`empty`); non-revert failure → propagate.

### 7.3 Record types (each → one `callView` + a typed decode)

| Method | Selector | Spec |
|---|---|---|
| `addr(bytes32)` | forward address | ENSIP-1 |
| `addr(bytes32, uint256)` | multi-coin / SLIP-44 | ENSIP-9 |
| `text(bytes32, string)` | text records | ENSIP-5 |
| `contenthash(bytes32)` | content hash | ENSIP-7 |
| `pubkey(bytes32)` | public key (x, y) | EIP-619 |
| `ABI(bytes32, uint256)` | ABI metadata | EIP-205 |
| `dnsRecord(bytes32, bytes, uint16)` | DNS records | ENSIP-8 |
| `interfaceImplementer(bytes32, bytes4)` | interface implementer | EIP-1820 |

**Reverse** (`address → name`): `registry.resolver(namehash("<hex>.addr.reverse"))` →
`resolver.name(node)` → **mandatory forward-verification** (resolve the claimed name forward; accept
only if it returns the original address).

### 7.4 Trust vs freshness (`EnsResolutionRoot`)

- `FINALIZED` — run against the beacon-finalized execution state root (fully verified; ~12 min
  stale; needs a snap peer retaining that block's state). Response carries `beaconVerified = true`.
- `PEER_HEAD` — the peer's latest head (freshest, but peer-claimed, not beacon-verified for the
  resolution itself; the *account* lookup afterward is still beacon-verified).
- `AUTO` (default) — try `FINALIZED`, fall back to `PEER_HEAD` on no-record/error.

### 7.5 Network coverage

ENS is pinned for **mainnet (1)** and **sepolia (11155111)** only (Holesky retired). The factory
keys on chain id and throws for chains without canonical ENS (e.g. Gnosis) — `NetworkConfig.hasEns()`
gates the UI. Keep ENS off `NetworkConfig` so the ENS module doesn't depend on the networking stack.

---

## 8. Dependency mapping for this layer

| Concern | Reference | Rust | Go |
|---|---|---|---|
| EVM | Besu `evm` | `revm` | go-ethereum `core/vm` |
| MPT proof verify | hand-rolled (`core/trie`) | port by hand / `alloy-trie` (re-validate) | port by hand / geth `trie` |
| ABI | hand-rolled | `alloy`/`ethabi` or hand-rolled | geth `accounts/abi` or hand-rolled |
| keccak / RLP / uint256 | Tuweni + BouncyCastle | `tiny-keccak`,`alloy-rlp`,`ruint` | geth `crypto`/`rlp`, `holiman/uint256` |
| HTTP (CCIP) | injected `CcipGateway` (java.net.http / platform) | `reqwest` (behind the port) | `net/http` (behind the port) |

**Port priority**: (1) MPT verifier — security-critical, small; (2) the `world`/oracle adapter to
your EVM's state trait; (3) the EVM fork table + view-call/estimate frame setup; (4) CCIP-Read + ENS
(pure logic). The verification semantics (Found/Absent/Invalid, leaf-only storageRoot/codeHash,
bytecode-by-codeHash, the 15% gas buffer, EIP-7702 one-hop, BLOCKHASH-unsupported) are the parts to
replicate verbatim and test.
