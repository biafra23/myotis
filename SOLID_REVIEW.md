# SOLID Review

Read-only review of the four Gradle modules. No code was changed.

Principle key: **S** Single Responsibility · **O** Open/Closed · **L** Liskov Substitution · **I** Interface Segregation · **D** Dependency Inversion.

---

## Phase 1 — Module map (one line per file)

### core — cryptographic identity & EL data types
| File | Responsibility |
|---|---|
| `crypto/NodeKey.java` | secp256k1 identity keypair: generate/load/persist, derive node ID, sign hashes. |
| `enr/Enr.java` | Decode EIP-778 ENR + derive libp2p multiaddr/PeerId + base58. |
| `types/BlockHeader.java` | Immutable EL block header value object + RLP decode + keccak hash. |

### consensus — beacon light client & verification
| File | Responsibility |
|---|---|
| `BeaconLightClient.java` | Top-level CL orchestrator: discovery, bootstrap, catch-up, polling, chain-fill, HTTP+P2P transport, JSON/hex parsing, sync-state publishing. |
| `BeaconSyncState.java` | Thread-safe holder for verified execution state root + rolling window of state roots. |
| `lightclient/LightClientProcessor.java` | Verify & apply LightClientUpdate / FinalityUpdate against the store (BLS + Merkle). |
| `lightclient/LightClientStore.java` | Thread-safe store of finalized/optimistic headers and current/next sync committees. |
| `lightclient/SyncCommitteeVerifier.java` | Stateless sync-aggregate BLS signature verification over a beacon header. |
| `lightclient/BeaconChainSpec.java` | Constants + pure functions for periods and generalized indices. |
| `bls/BlsVerifier.java` | BLS12-381 fast-aggregate-verify + Zcash-format G1/G2 point (de)serialization. |
| `bls/HashToCurve.java` | RFC 9380 hash-to-curve for BLS12-381 G2. |
| `ssz/SszUtil.java` | SSZ merkleization primitives, per-type hash_tree_root helpers, LE readers. |
| `proof/MerklePatriciaVerifier.java` | Verify account/storage MPT proofs against a state root (hand-rolled RLP + nibble codec). |
| `libp2p/BeaconP2PService.java` | libp2p host lifecycle, peer/connection mgmt, eth2 req/resp orchestration, chunk/snappy framing, Netty I/O. |
| `libp2p/ReqRespCodec.java` | eth2 req/resp wire framing: snappy + protobuf varint encode/decode. |
| `types/BeaconBlockParser.java` | Parse SignedBeaconBlock SSZ + compute header root. |
| `types/*` (block body, payload header, light-client updates, etc.) | SSZ container decode + hash_tree_root per beacon type. |

### networking — devp2p (discovery, RLPx, eth/snap)
| File | Responsibility |
|---|---|
| `eth/EthHandler.java` | eth/68 + snap state machine, message dispatch, header serving, header cache, request bookkeeping. |
| `rlpx/RLPxConnector.java` | Build outbound Netty connections + peer-selection/retry routing for header/body/snap requests. |
| `rlpx/RLPxHandler.java` | RLPx Netty handler: handshake state machine + frame decode/encode dispatch. |
| `rlpx/AuthHandshake.java` | EIP-8 auth/ack handshake + ECDH + session-secret derivation. |
| `rlpx/EciesCodec.java` | Static ECIES encrypt/decrypt for auth/ack. |
| `rlpx/FrameCodec.java` | AES-256-CTR + Keccak-MAC frame encode/decode (incl. Snappy + inner MAC state). |
| `rlpx/SessionSecrets.java` | Immutable record of derived session secrets. |
| `discv4/DiscV4Service.java` | UDP discovery lifecycle: bind, bootstrap, periodic refresh. |
| `discv4/DiscV4Handler.java` | UDP packet handler: ping/pong/neighbors + rate limiting + table population. |
| `discv4/KademliaTable.java` | Kademlia routing table (buckets, closest-peers, distance). |
| `discv4/Packet.java` | discv4 wire packet encode/parse/sign/verify. |
| `dns/DnsEnrResolver.java` | EIP-1459 enrtree walk + root signature verify + TXT lookup (injects `TxtResolver`). |
| `dns/EnrTreeUrl.java` | Parse enrtree:// URL + base32 decode + key decompress. |
| `NetworkConfig.java` | Per-chain config record + static network constants + genesis RLP. |
| `ChainHead.java` | Thread-safe best-head holder. |
| `eth/messages/*`, `snap/messages/*` | RLP (de)serialization of individual wire messages. |

### app — daemon/CLI entry point & IPC
| File | Responsibility |
|---|---|
| `Main.java` | Process entry: arg parsing, daemon/client mode select, full daemon bootstrap/wiring. |
| `CommandHandler.java` | Parse IPC JSON commands → JSON responses for every command, plus beacon verification, tx parsing, JSON codec. |
| `DaemonServer.java` | Unix-socket acceptor: virtual-thread-per-client, reads JSON-Lines, delegates to `CommandHandler`. |
| `DaemonClient.java` | CLI client: argv → JSON request → socket → print response. |
| `PeerCache.java` | Persist/load EL (RLPx) peers to flat file. |
| `CLPeerCache.java` | Persist/load CL (libp2p) peer multiaddrs with failure-based eviction. |

---

## Phase 2 — Findings (grouped by severity)

### High severity

| # | Principle | Location | Description | Refactor |
|---|---|---|---|---|
| 1 | S | `app/.../CommandHandler.java:45` (whole class, 1341 lines) | God class: command dispatch + beacon verification + MPT proof handling + RLP tx parsing + hand-rolled JSON codec in one class. | Split into `BlockVerifier`, `TxParser`, `JsonWriter`/`JsonReader`, and one handler per command group. |
| 2 | S | `consensus/.../BeaconLightClient.java:50` (whole class, 1176 lines) | God class mixing HTTP transport, P2P transport, regex JSON parsing, hex utils, bootstrap/catch-up/poll orchestration, chain verification, and sync-state publishing. | Split into `BeaconApiClient`, `Bootstrapper`, `SyncCommitteeCatchUp`, `ChainFiller`, and a thin orchestrator. |
| 3 | S | `networking/.../eth/EthHandler.java:40-897` | God class: eth+snap FSM, dispatch, header serving, dual LRU header cache, async request bookkeeping, stale-header policy, disconnect decoding (~900 lines). | Split into `EthHandler` (FSM/dispatch), `HeaderCache`, `SnapRequestService`, `PeerStatus`. |
| 4 | S | `consensus/.../libp2p/BeaconP2PService.java:44` | God class: host lifecycle, peer/connection caching, Identify querying, per-protocol request orchestration, multi-chunk decode, snappy-frame scanning, Netty I/O. | Split into host/connection manager, response-framing parser, and per-protocol request methods. |
| 5 | D | `app/.../Main.java:190,223,273,333,348,349` | Daemon hard-`new`s every collaborator (`DnsEnrResolver`, `RLPxConnector`, `DiscV4Service`, `BeaconLightClient`, `CommandHandler`, `DaemonServer`); nothing substitutable. | Inject collaborators via interfaces/factories into the bootstrap. |
| 6 | D | `consensus/.../BeaconLightClient.java:172-174` | Orchestrator `new`s `LightClientStore`, `LightClientProcessor`, `BeaconP2PService`; no test double or alternate transport possible. | Inject these collaborators (P2P behind an interface) via constructor. |
| 7 | D | `consensus/.../BeaconLightClient.java:254-262,348-357,724-731` | Concrete dependence on `java.net.http.HttpClient` + live beacon-node URL inside the verification orchestrator; untestable without real HTTP, and blurs the "HTTP only for debugging" trust boundary. | Depend on an injected `BeaconApiClient` abstraction. |
| 8 | D | `networking/.../eth/EthHandler.java:157` | Reaches into the Netty pipeline by literal name (`pipeline().get("rlpx")`) and casts to concrete `RLPxHandler`. | Inject a `MessageSender` abstraction into the constructor. |
| 9 | D | `consensus/.../libp2p/BeaconP2PService.java:77-85` | `start()` hard-codes concrete libp2p stack (TcpTransport, NoiseXX, Yamux/Mplex, ephemeral addr, SECP256K1); no injection point. | Accept a host factory/config object so transport & security inject. |
| 10 | D | `app/.../CommandHandler.java:167-178,134-143` | Hard-codes concrete `IpfsHttpClient`, embedded manifest CID, and reflective binding to TrueBlocks/kethereum — command handling coupled to an external IPFS source. | Depend on an injected `TransactionSource`; move CID/reflection config out of the handler. |
| 11 | D | `consensus/.../lightclient/LightClientProcessor.java:61,124` | Verification calls `static SyncCommitteeVerifier.verify(...)`; BLS step cannot be stubbed to test the processor's branch logic. | Depend on an injected `SignatureVerifier` interface. |
| 12 | S | `consensus/.../BeaconLightClient.java:268-298,738-800` | Beacon-API JSON parsed via hand-rolled regex inside the orchestrator (second embedded responsibility). | Move response parsing into a `BeaconApiClient`/decoder returning typed objects. |
| 13 | S | `app/.../Main.java:158` (`runDaemon`, ~235 lines) | One method does lock, key load, DNS, bootnode dedup, cached-peer dial, discv4 wiring, beacon setup, IPC start, shutdown. | Extract a `Daemon` bootstrap class with discrete, testable steps. |
| 14 | S | `consensus/.../libp2p/BeaconP2PService.java:470,515` | `decodeMultiChunkResponse` / `skipSnappyFrames` embed eth2 chunk + snappy-frame parsing inside the transport service, duplicating `ReqRespCodec`'s concern. | Move chunk/snappy-frame scanning into `ReqRespCodec`. |
| 15 | O | `app/.../CommandHandler.java:93-104` | Adding a command means editing the central `switch` plus `handleStreaming` and `DaemonClient.buildJson` — not open for extension. | Replace switch with a `Map<String,Command>` self-registering handler registry. |
| 16 | O | `networking/.../eth/EthHandler.java:442-454` | snap dispatch is an if/else chain on computed codes in the READY switch `default`; new message types require editing it. | Use a code→handler map populated at negotiation time. |
| 17 | O | `consensus/.../types/ExecutionPayloadHeader.java:132-219` | Deneb-vs-Electra forks hard-branched in one `decode`/`hashTreeRoot`; each fork edits field lists + offset math. | Extract a fork-version strategy (field set + offsets). |
| 18 | D | `networking/.../eth/EthHandler.java:128-140` | Constructor hard-codes mainnet genesis pre-cache (`"mainnet".equals(...)`, `MAINNET_GENESIS_HEADER_RLP`), coupling generic handler to one network. | Move genesis header into `NetworkConfig` (`Optional<byte[]> genesisHeaderRlp()`). |
| 19 | S | `networking/.../rlpx/RLPxConnector.java:41-368` | Mixes connection factory (Netty bootstrap) with a request-routing/retry engine (batched headers, snap peer retry, empty-response fallback). | Extract a `PeerRequestRouter` consuming the connector's active peers. |

### Medium severity

| # | Principle | Location | Description | Refactor |
|---|---|---|---|---|
| 20 | S | `app/.../CommandHandler.java:1313-1340 & 953-1127` | JSON extraction/escaping and beacon proof-verification logic embedded in the handler. | Move `extractString`/`extractLong`/`escapeJson` to a `Json` util; verification to `BeaconBlockVerifier`. |
| 21 | S | `app/.../CommandHandler.java:674-864` (`handleGetStorage`, ~190 lines) | One method: hex parse, ERC-20 slot-key calc, account fetch, storage fetch, MPT verify, beacon verify, JSON assembly. | Extract slot-key derivation + verification block; build response via JSON builder. |
| 21 | O | `app/.../DaemonClient.java:83-117` | Second `switch` duplicates the server's command set; client and server edited in lockstep per command. | Share a command-descriptor abstraction (arg spec + JSON shape) defined once. |
| 22 | D | `app/.../CommandHandler.java:458,877,1107` | Mainnet magic constants (`MERGE_BLOCK`, `32*256`, `8192`) baked in instead of from `NetworkConfig`/`clGenesisTime` — wrong on testnets. | Source these from the injected network config. |
| 23 | I | `app/.../CommandHandler.java:59-87` | Three telescoping constructors force callers/tests to supply the full dependency set even when unused. | Use a builder or a small context object. |
| 24 | S | `app/.../PeerCache.java:78-88` / `CLPeerCache.java:100-110` | `purge` writes user-facing messages to `System.out`/`err`, mixing persistence with presentation. | Return a result / throw; let `Main` report. |
| 25 | S | `consensus/.../bls/BlsVerifier.java:20` | Conflates the verification protocol (`fastAggregateVerify`) with Zcash/Ethereum compressed-point (de)serialization. | Extract a `BlsPointCodec`; keep `BlsVerifier` to the pairing check. |
| 26 | S | `consensus/.../proof/MerklePatriciaVerifier.java:35` | Mixes proof traversal, hand-rolled RLP parser, nibble/compact codec, and account-field business validation. | Split RLP parser + nibble codec into helpers; move account assertions out. |
| 27 | O | `consensus/.../proof/MerklePatriciaVerifier.java:236-290` | `verifyAccountValue` hard-codes nonce/balance-only checks (String balance, `-1` sentinel); other fields require editing it. | Return decoded account fields; let callers assert. |
| 28 | S | `consensus/.../ssz/SszUtil.java:9` | Grab-bag util: generic merkleization + per-type HTR helpers + LE readers + composite list hashers; grows per new SSZ type. | Separate core merkleization from type-specific HTR helpers and byte readers. |
| 29 | O | `consensus/.../types/BeaconBlockBody.java:108-158` | `hashTreeRoot` hard-branches Deneb (12) vs Electra (13) fields with literal offsets. | Drive field layout from a per-fork schema/descriptor. |
| 30 | L | `consensus/.../libp2p/BeaconP2PService.java:262-273` | Single-response and multi-chunk request methods return differently-shaped futures off one `doReqResp` channel; single-response callers can mishandle multi-chunk replies. | Distinguish single vs streaming responses in the return type. |
| 31 | S | `networking/.../eth/EthHandler.java:622-802` | Snap methods bury the "fetch fresh non-pruned header first" policy + hard-coded staleness thresholds (`<20_000_000`, `<1_000_000`) inline. | Extract a `StateRootProvider` encapsulating fresh-header fetch + staleness policy. |
| 32 | S | `networking/.../discv4/DiscV4Handler.java:79-99` | Ping rate-limiting (sliding-window ring buffer) embedded in the packet handler. | Extract an injected `PingRateLimiter`. |
| 33 | D | `networking/.../discv4/DiscV4Service.java:42-49` | Service constructs its own `KademliaTable` and `NioEventLoopGroup`; not substitutable in tests. | Accept routing table + event-loop group via constructor. |
| 34 | D | `networking/.../rlpx/RLPxConnector.java:70` | Connector `new`s `ChainHead`; callers can't share/observe chain head. | Inject `ChainHead`. |
| 35 | O | `networking/.../eth/messages/StatusMessage.java:50-134` | `if (ethVersion >= 69)` branching duplicated across encode + two decode paths. | Per-version Status codecs behind a small interface. |
| 36 | L | `networking/.../rlpx/RLPxHandler.java:190-191` | `sendMessage` throws if handshake incomplete; callers must know internal state — precondition not in any contract. | Queue-until-ready, or expose `MessageSender` only after READY. |
| 37 | I | `networking/.../rlpx/RLPxConnector.java:139-347` | Fat surface mixing header/batched-header/body/account/storage requests; eth-only consumers depend on snap methods. | Segregate into `HeaderSource`, `BodySource`, `SnapSource`. |
| 38 | S | `core/.../enr/Enr.java:23` | `Enr` is both an EIP-778 decoder/accessor and a libp2p PeerId/multiaddr/base58 deriver (lines 133-200). | Extract `Libp2pPeerId`/`Base58` into the libp2p layer. |
| 39 | D | `core/.../enr/Enr.java:80-91` | `publicKey()` reaches directly into BouncyCastle `ECDomainParameters`/`SECNamedCurves` for decompression. | Route decompression through a crypto helper. |
| 40 | O | `core/.../types/BlockHeader.java:98-111` | Fork evolution (London/Shanghai/Cancun/Prague) handled by a positional `if (!reader.isComplete())` ladder; each EIP edits `decode`. | Introduce a fork-keyed decode strategy/schema. |
| 41 | I | `consensus/.../BeaconSyncState.java:43,50,58` | Three overloaded `update(...)`; 3-arg and 4-arg forms silently null block hash/number — misusable partial interface. | Collapse to one `update(State)`/builder. |
| 42 | O | `consensus/.../lightclient/BeaconChainSpec.java:30-58` | Hard-coded pre-Electra gindex constants alongside depth-parameterized computation; constants misleading once `syncCommitteeGindex(depth)` exists. | Compute all gindices from field index + depth; drop literal constants. |
| 43 | S | `core/.../crypto/NodeKey.java:44-55` | `loadOrGenerate(Path)` couples key identity with filesystem persistence (read/parse/write hex). | Move persistence to a `NodeKeyStore`; keep `NodeKey` to the keypair. |

### Low severity

| # | Principle | Location | Description | Refactor |
|---|---|---|---|---|
| 44 | L | `app/.../CommandHandler.java:56,889` | `beaconLightClient` is nullable; one constructor sets it `null`, silently degrading `beacon-status` vs another construction. | Use a no-op `BeaconLightClient` instead of `null`. |
| 45 | S | `app/.../PeerCache.java:35-47` vs `CLPeerCache.java:45-76` | Two near-identical cache classes, no shared abstraction; eviction only in one. | Extract a common `FilePeerCache<T>`. |
| 46 | O | `app/.../CommandHandler.java:1143-1282` | Tx-type parsing is a closed `switch` with one near-duplicate method per EIP type. | Table-drive per-type field layout or a parser-per-type registry. |
| 47 | D | `app/.../DaemonServer.java:36-39` | Bound to concrete `CommandHandler` rather than a dispatcher interface. | Depend on a `CommandDispatcher` interface. |
| 48 | D | `consensus/.../BeaconLightClient.java:65-66,83-151` | Peer success/failure wired as nullable `Consumer<String>` through five telescoping constructors. | Replace with a `PeerLifecycleListener` + one constructor/builder. |
| 49 | S | `consensus/.../BeaconLightClient.java:810,1102` & `LightClientProcessor.java:180` | `bytesToHex`/`hexToBytes` duplicated as private statics across classes. | Extract a shared `Hex` utility. |
| 50 | S | `core/.../enr/Enr.java:48` | `decode` advertises ENR semantics but skips signature verification — the type doesn't validate the record. | Add a `verify()` path or a separate verified-ENR type. |
| 51 | O | `consensus/.../lightclient/LightClientProcessor.java:45-101` vs `117-174` | `processFinalityUpdate` and `processUpdate` duplicate the BLS+finality-branch verification block. | Extract the shared verify-and-advance steps. |
| 52 | D | `consensus/.../types/ExecutionPayloadHeader.java:273-294` & `BeaconBlockBody.java:113-157` | HTR methods call many `SszUtil.*` concretions, coupling every container to the concrete util. | Depend on a small HTR helper interface. |
| 53 | O | `consensus/.../types/LightClientUpdate.java:88-97` | Branch-size detection enumerates only two known fork shapes, silently falling back to pre-Electra. | Derive branch sizes from a fork descriptor. |
| 54 | S | `consensus/.../bls/BlsVerifier.java:25-26` | Sync-committee domain-separation tag hard-coded inside the verifier. | Pass the DST in (or via config). |
| 55 | I | `consensus/.../ssz/SszUtil.java:370-378` | `merkleize` exposed in three overloads + `merkleizeSparse`/`emptyListRoot`, leaking internal sizing to callers. | Consolidate behind one entry that picks sparse vs dense internally. |
| 56 | S | `networking/.../NetworkConfig.java:204-225` | A `record` carries a static `MAINNET_GENESIS_HEADER_RLP` initializer that does RLP encode + hash verify (data mixed with computation). | Move genesis-header construction to a factory/constants holder. |
| 57 | S | `networking/.../dns/EnrTreeUrl.java:68-109` | URL value object also implements RFC4648 base32 decode + secp256k1 decompression. | Move base32/decompress to a shared crypto/encoding util. |
| 58 | D | `networking/.../discv4/DiscV4Handler.java:36`, `eth/EthHandler.java:97-109` | Handlers depend on concrete `KademliaTable`/cache types rather than narrow interfaces. | Introduce minimal interfaces (`RoutingTable`). |
| 59 | S | `networking/.../discv4/DiscV4Handler.java:165-171` | Dead unused private `addToTable` — responsibility drift. | Remove dead code. |
| 60 | O | `networking/.../eth/EthHandler.java:879-889` | Disconnect-reason names are a fixed array plus ad-hoc `if (reason == 16)`. | Replace with an enum keyed by code. |

---

## Cross-cutting observations

- **Four god classes dominate** and are the highest-leverage targets: `CommandHandler` (1341), `BeaconLightClient` (1176), `EthHandler` (897), `BeaconP2PService` (770). Each concentrates 4–6 responsibilities and `new`s its own collaborators, making the corresponding layer effectively untestable in isolation.
- **DIP is the pervasive root cause.** `Main` and the orchestrators wire everything with `new`; almost nothing sits behind an interface. The one positive model in the codebase is `DnsEnrResolver`, which already injects a `TxtResolver` for testability — the pattern the god classes lack.
- **OCP fork/version branching** recurs across the consensus SSZ types and eth message codecs (Deneb/Electra, eth≥69); each new fork forces edits to `decode`/`hashTreeRoot`/`encode` rather than registering a strategy.
- **Trust-boundary note (per CLAUDE.md):** the embedded HTTP beacon-API paths in `BeaconLightClient` and the IPFS/`IpfsHttpClient` dependency in `CommandHandler` sit on the "HTTP only for debugging / no client trust" boundary — the DIP fixes (#7, #10) would make those paths explicit and removable for production.
- **Genuine Liskov violations are rare** (most types are `final`/static); the L findings are contract-shape inconsistencies (#30, #36, #44), not subtype substitution failures.
