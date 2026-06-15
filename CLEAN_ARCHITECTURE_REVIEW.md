# Clean Architecture Review

Read-only review of the four Gradle modules against Robert C. Martin's Clean Architecture. No code was changed.

The lens here is **layering and the Dependency Rule**, not generic SOLID (see [SOLID_REVIEW.md](SOLID_REVIEW.md) for that). Layers, innermost → outermost:

1. **Entities** — enterprise/domain data + rules (value objects, consensus invariants)
2. **Use Cases** — application-specific business rules (verification, sync orchestration)
3. **Interface Adapters** — controllers, presenters, gateways, codecs
4. **Frameworks & Drivers** — Netty, libp2p, HTTP, BouncyCastle/Milagro, IPFS, sockets, filesystem

**The Dependency Rule:** source dependencies point only inward. Inner layers must not name outer-layer concretions or framework types.

---

## Phase 1 — Layer map (intended layer → how it actually behaves)

### core (should be innermost: Entities)
| File | Should be | Actually behaves as |
|---|---|---|
| `crypto/NodeKey.java` | Entity (identity value object) | Entity **+ Framework/Driver** — registers BouncyCastle JCA provider in a static block, does filesystem I/O |
| `enr/Enr.java` | Entity (value object) | Entity **+ Interface Adapter** — embeds RLP / Base58 / BouncyCastle / libp2p multiaddr codecs |
| `types/BlockHeader.java` | Entity (value object) | Entity **+ Interface Adapter** — owns its own RLP decode + keccak |

### consensus (Entities + Use Cases)
| File | Should be | Actually behaves as |
|---|---|---|
| `BeaconLightClient.java` | Use Case (sync orchestration) | Use Case **+ Framework/Driver + Adapter** — HTTP client, regex JSON parsing, concrete libp2p service all inlined |
| `BeaconSyncState.java` | Entity / app state | Entity (clean) |
| `lightclient/LightClientProcessor.java` | Use Case (consensus rules) | Use Case — clean logic, but statically bound to crypto/SSZ concretions |
| `lightclient/SyncCommitteeVerifier.java` | Use Case (central trust rule) | Use Case — statically bound to `BlsVerifier`/`SszUtil` |
| `lightclient/LightClientStore.java` | Entity / app state | Entity (clean) |
| `lightclient/BeaconChainSpec.java` | Entity (constants/pure fns) | Entity (clean) |
| `bls/BlsVerifier.java` | Use Case (verification rule) | Use Case **+ Adapter** (owns Zcash point (de)serialization), bound to Milagro |
| `bls/HashToCurve.java` | Use Case (domain crypto) | Clean logic, hard-bound to Milagro `BLS381.*` |
| `ssz/SszUtil.java` | Use Case (merkleization rule) | Use Case — appropriate, JDK-only |
| `proof/MerklePatriciaVerifier.java` | Use Case (proof rule) | Use Case **+ Framework coupling** (Tuweni RLP/Hash + SLF4J) |
| `libp2p/BeaconP2PService.java` | Framework & Driver | Driver — but exposes **no port** and drags wire decoding into itself |
| `libp2p/ReqRespCodec.java` | Interface Adapter (framing) | Adapter (appropriate) |
| `types/BeaconBlockParser.java` | Interface Adapter (SSZ decode) | Adapter **+ Use Case** (HTR/merkleization) in one static method |
| `types/BeaconBlockBody.java` | Entity | Entity **+ Adapter** (SSZ decode w/ retained `raw`) **+ Use Case** (HTR) |
| `types/ExecutionPayloadHeader.java` | Entity | Entity **+ Adapter** (SSZ decode) **+ Use Case** (HTR) |
| `types/LightClientUpdate.java` | Entity | Entity **+ Adapter** (SSZ decode) — cleanest of the three |

### networking (mostly Frameworks & Drivers / Adapters)
| File | Should be | Actually behaves as |
|---|---|---|
| `eth/EthHandler.java` | Use Case (eth/snap protocol) behind a thin Netty adapter | 900-line **Netty handler fusing the entire eth/snap use case** to `ChannelHandlerContext` |
| `rlpx/RLPxConnector.java` | Interface Adapter (the upward port) | De-facto port with **no interface**; also embeds peer-selection/retry use case |
| `rlpx/RLPxHandler.java` | Framework & Driver | Reasonable thin glue; owns framing-loop + state |
| `rlpx/AuthHandshake.java` | Use Case / pure protocol | **Clean** — Bytes in/out, testable |
| `rlpx/EciesCodec.java` | Framework & Driver (crypto adapter) | **Clean** — pure functions, framework-free |
| `rlpx/FrameCodec.java` | Framework & Driver (codec) | **Clean** — pure byte[]→byte[], no Netty |
| `discv4/DiscV4Handler.java` | Framework & Driver | **Mixes** Netty I/O with use-case logic (bonding, rate-limit, table updates) |
| `discv4/DiscV4Service.java` | Framework & Driver | Driver, but owns refresh/lookup **policy** (use case) |
| `discv4/KademliaTable.java` | Entity / domain logic | **Clean** — pure XOR/routing |
| `discv4/Packet.java` | Interface Adapter (wire codec) | **Clean** — Bytes in/out |
| `dns/DnsEnrResolver.java` | Use Case + Driver | **Good** — injects a `TxtResolver` port (the model to follow) |
| `NetworkConfig.java` | Entity / config | Entity, but **mixes EL + CL/beacon** config concerns |
| `ChainHead.java` | Entity | Clean entity |
| `eth/messages/*` | Interface Adapter (DTO + codec) | Clean DTOs+codecs; `BlockHeadersMessage` also does verification |

### app (outermost: composition root + delivery)
| File | Should be | Actually behaves as |
|---|---|---|
| `Main.java` | Composition root + wiring | Mostly correct wiring **+ leaked orchestration** (peer-connect/backoff/blacklist policy, DNS merge/dedup) |
| `CommandHandler.java` | Interface Adapter (IPC controller/presenter) | **The whole missing Use-Case + Entity layer** — beacon verification, MPT proofs, tx decode, storage-key derivation, behind a JSON-string boundary |
| `DaemonServer.java` | Framework & Driver (transport) | **Clean** transport adapter |
| `DaemonClient.java` | Framework & Driver (CLI driver) | Correct, but owns request wire-format duplicating the server contract |
| `PeerCache.java` | Interface Adapter (gateway) | Gateway with **no port**, leaks presentation (`System.out`) |
| `CLPeerCache.java` | Interface Adapter (gateway) | Same — concrete gateway, no port, leaks `System.out` |

---

## Phase 2 — Findings (grouped by severity)

### High severity

| # | Concern | Location | Description | Refactor |
|---|---|---|---|---|
| 1 | Business rule in delivery layer | `app/.../CommandHandler.java:461-616` | Beacon-chain block verification (state-root match, header-chain anchoring, parent-hash walking) — a core consensus use case — is implemented inside the IPC handler. | Extract a `VerifyBlockUseCase` interactor; handler only formats its result. |
| 2 | Business rule in delivery layer | `app/.../CommandHandler.java:953-1127` | Account/storage proof verification orchestration (MPT verify + beacon anchoring + period-lag policy) lives in the handler. | Move into `VerifyAccount`/`VerifyStorage` interactors; `MerklePatriciaVerifier`/`BeaconSyncState` become injected gateways. |
| 3 | Business rule in delivery layer | `app/.../CommandHandler.java:695-732` | EVM storage-key derivation (keccak of slot, ERC-20 `keccak(abi.encode(holder,slot))`) is an entity-level rule hand-coded in the handler. | Move to a `StorageSlot.keyFor(...)` domain helper in core. |
| 4 | Business rule in delivery layer | `app/.../CommandHandler.java:1143-1295` | Full RLP transaction decoding for 4 tx types — entity-level parsing — sits in the delivery adapter, emitting JSON directly. | Introduce a `Transaction` entity + `TxDecoder` in core; handler renders the entity. |
| 5 | No use-case boundary / port missing | `app/.../CommandHandler.java:49-87` | Handler depends directly on networking/consensus concretions (`RLPxConnector`, `BeaconSyncState`, `DiscV4Service`) with no interactor/port between delivery and inner layers. | Define use-case input/output ports; inject concretions at the composition root. |
| 6 | External gateway missing | `app/.../CommandHandler.java:166-179` | `IpfsHttpClient` + hardcoded manifest CID + kethereum reflection instantiated directly inside the delivery handler. | Hide behind an `AppearanceIndexGateway` port; move CID to config. |
| 7 | Delivery coupling (no req/resp models) | `app/.../CommandHandler.java:90-131, 1305-1340` | Raw JSON strings cross the boundary both ways (hand-rolled StringBuilder build + `extractString/extractLong` parse), so use cases can't be driven by HTTP/library/tests. | Introduce request/response DTOs; make JSON a thin presenter detail. |
| 8 | Dependency Rule | `consensus/.../BeaconLightClient.java:17-19,254-262,348-357,724-732` | Use-case orchestrator constructs `java.net.http.HttpClient` and talks to a beacon REST API — business flow welded to an HTTP framework (also blurs the "HTTP only for debugging" trust boundary). | Define a `BeaconDataSource`/`CheckpointProvider` port; inject an HTTP adapter from `app`. |
| 9 | Boundary/port missing | `consensus/.../BeaconLightClient.java:174` | Use case `new`s the concrete libp2p `BeaconP2PService` and calls it directly; no gateway between use case and network. | Introduce a `BeaconPeerGateway`/`LightClientGateway` port returning domain DTOs. |
| 10 | Layer mixing | `consensus/.../BeaconLightClient.java:273-290,741-799` | Wire-format JSON parsed via regex inside the use case — transport/serialization sharing a class with sync rules. | Move decoding into an adapter returning domain DTOs across the boundary. |
| 11 | Framework coupling (entity) | `core/.../NodeKey.java:20-25` | An entity statically registers the BouncyCastle JCA provider, so loading the identity type drags in a crypto framework as a side effect. | Move provider bootstrap to the composition root / crypto adapter. |
| 12 | Dependency Rule (entity does I/O) | `core/.../NodeKey.java:9-11,44-55` | The identity entity performs filesystem I/O (`Files.read/writeString`) — an outer concern in an inner entity. | Extract a `NodeKeyRepository` port; keep `NodeKey` a pure value object. |
| 13 | Layer mixing (use case fused to framework) | `networking/.../eth/EthHandler.java:40,200,315` | The entire eth/snap state machine (negotiation, READY dispatch, request/response correlation) lives in a `ChannelInboundHandlerAdapter`, unreachable without a live Netty pipeline. | Extract a framework-free `EthProtocol` use case (decoded `(code,payload)` + a `MessageSender` port); make `EthHandler` a thin adapter. |
| 14 | Framework coupling | `networking/.../eth/EthHandler.java:315-388` | GetBlockHeaders **serving** (RLP parse, cache lookup, response encode) is pure logic but inlined in the Netty handler, depending on `ChannelHandlerContext`. | Move to a `HeaderServer` use case over a cache port returning a response DTO. |
| 15 | Boundary/port missing (upward) | `networking/.../rlpx/RLPxConnector.java:41` consumed by `app/.../CommandHandler.java:50` & `Main.java` | `app` depends on the concrete Netty-owning `RLPxConnector` for get-headers/bodies/account/storage — no port, so the application layer is coupled to the framework layer. | Define a framework-free `EthClient`/`PeerDataSource` interface; `app` depends on it, `RLPxConnector` implements it. |
| 16 | Dependency Rule (framework-mediated collaboration) | `networking/.../eth/EthHandler.java:157` + `rlpx/RLPxConnector.java:104-121` | `EthHandler` reaches back into the pipeline by name (`pipeline().get("rlpx")`); collaboration between eth and rlpx is mediated by Netty's pipeline, not an explicit port. | Inject an `RLPxMessageSender` port into the eth use case; remove the named-handler lookup. |
| 17 | Layer mixing | `networking/.../rlpx/RLPxConnector.java:166-347` | Peer-selection/batching/failover-retry policy (a use case) lives inside the Netty connector alongside `NioEventLoopGroup`/`Bootstrap`. | Split a `PeerRouter` use case from the socket-owning driver. |
| 18 | Framework coupling (wire leaks across boundary) | `consensus/.../libp2p/BeaconP2PService.java:248-317` | Public req-resp API returns raw `byte[]`/`CompletableFuture<byte[]>` SSZ blobs, so inner-layer callers must know snappy/SSZ wire shape. | The gateway port should expose typed domain results; decode in the adapter. |
| 19 | Layer mixing | `consensus/.../libp2p/BeaconP2PService.java:470-561` | Multi-chunk/snappy frame-scanning (transport decoding logic) lives inside the libp2p driver among Netty handlers. | Move framing into `ReqRespCodec`; keep `BeaconP2PService` a pure stream driver. |
| 20 | Entity polluted | `consensus/.../types/BeaconBlockBody.java:71-104,108-158` | An entity owns SSZ byte-offset decoding and retains `raw`/`varOffsets` purely to serve serialization — domain type fused to the wire format. | Split a pure entity from a `BeaconBlockBodySszCodec`; HTR may stay as a rule over entity fields. |

### Medium severity

| # | Concern | Location | Description | Refactor |
|---|---|---|---|---|
| 21 | Composition root leak | `app/.../Main.java:240-294,442-477` | Peer-connection policy (attempted-set, backoff, blacklist, 2000-cap) is application orchestration embedded in `main()`. | Extract a `PeerConnectionManager` interactor; `main` only constructs/starts it. |
| 22 | Composition root leak | `app/.../Main.java:199-217,322-332` | DNS-ENR merge/dedup of bootnodes and CL peers is application logic in `main()`. | Move into a `BootstrapPeers` use case. |
| 23 | Persistence detail leak | `app/.../PeerCache.java:81-86`, `CLPeerCache.java:104-109` | `purge()` writes directly to `System.out`/`err`, mixing presentation into a persistence gateway. | Return a result/throw; let the CLI driver print. |
| 24 | Boundary/port missing (repository) | `app/.../PeerCache.java:21`, `CLPeerCache.java:26` | Caches are concrete gateways with no repository interface; callers bind to concretions and the file format. | Define `PeerRepository`/`ClPeerRepository` ports; file impl is a detail. |
| 25 | Delivery coupling (duplicated wire contract) | `app/.../DaemonClient.java:80-118` | Client re-encodes every command's JSON shape, duplicating the server's contract with no shared model. | Share request DTOs/serializer between client and server. |
| 26 | Delivery coupling (streaming tied to writer) | `app/.../CommandHandler.java:155-288` | `handleGetTransactions` writes JSON lines straight to the socket `BufferedWriter`, fusing the use case to IPC transport. | Interactor emits to an output-boundary callback; an IPC presenter adapts it. |
| 27 | Framework coupling (entity crypto) | `consensus/.../bls/BlsVerifier.java:3`, `HashToCurve.java:3` | Inner verification logic imports `org.apache.milagro.amcl.BLS381.*` concretely — welded to one crypto library. | Hide the curve library behind a `PairingEngine`/SPI. |
| 28 | Layer mixing | `consensus/.../bls/BlsVerifier.java:104-234` | Verification rule (`fastAggregateVerify`) and Zcash compressed-point (de)serialization share one class. | Extract a `Bls12381Codec`; keep `BlsVerifier` the pure pairing check. |
| 29 | Framework coupling | `consensus/.../lightclient/SyncCommitteeVerifier.java:3,63` & `LightClientProcessor.java:3,61,78` | The central trust rule is statically bound to concrete `BlsVerifier`/`SszUtil`, so consensus rules can't run with substituted crypto. | Hide behind injected `SignatureVerifier`/`MerkleProofVerifier` ports. |
| 30 | Entity polluted | `consensus/.../types/ExecutionPayloadHeader.java:132-219,269-294` | Entity carries SSZ `decode()` with hard-coded byte offsets, mixing wire parsing into the data type. | Move `decode` to an SSZ codec adapter; HTR may remain a rule. |
| 31 | Module direction | `consensus/.../types/BeaconBlockParser.java:42-72` | One static method both decodes SSZ (adapter) and computes merkle roots (use case). | Separate a `SignedBeaconBlockCodec` from a `BlockRootCalculator`. |
| 32 | Framework coupling | `consensus/.../proof/MerklePatriciaVerifier.java:3-5,471` | Proof-verification use case binds directly to Tuweni `RLP`/`Hash`/`Bytes` for keccak + account decode. | Inject a `KeccakFunction` + `RlpDecoder` port; keep MPT traversal framework-free. |
| 33 | Entity polluted | `core/.../Enr.java:78-94,157-200` | The ENR entity embeds BouncyCastle EC decompression, a Base58 codec, and libp2p multiaddr/PeerId derivation. | Move decompression + multiaddr derivation into an adapter consuming raw ENR fields. |
| 34 | Entity polluted | `core/.../Enr.java:48-71` & `core/.../types/BlockHeader.java:80-119` | Entities own their RLP wire-decoding (Tuweni `RLP`), binding the innermost types to a serialization framework. | Relocate decoding to `EnrCodec`/`BlockHeaderCodec` adapters returning pure entities. |
| 35 | Layer mixing (trust policy inline) | `consensus/.../BeaconLightClient.java:684-703,872-899` | The "seed without BLS / record unverified roots" trust policy is interleaved with the transport/orchestration loop. | Express verified-vs-unverified seeding as an explicit use-case policy object. |
| 36 | Layer mixing | `networking/.../discv4/DiscV4Handler.java:101-163` | Bonding rules, ping rate-limiting, and routing-table updates are interleaved with Netty `DatagramPacket` I/O. | Extract a `Discv4Engine` use case over parsed packets + a `PacketSender` port. |
| 37 | Layer mixing (policy in driver) | `networking/.../discv4/DiscV4Service.java:111-138` | Discovery policy (refresh cadence, random-target fan-out, re-bootstrap when empty) embedded in the Netty driver. | Move the strategy into a scheduler-agnostic use case. |
| 38 | Domain type leak | `networking/.../eth/messages/BlockHeadersMessage.java:29` via `RLPxConnector.requestBlockHeaders` | The upward API returns `VerifiedHeader` carrying `rawRlp` (wire `Bytes`) alongside the domain header, leaking wire encoding to `app`. | Return a pure domain header DTO; keep `rawRlp` internal. |
| 39 | Layer mixing | `networking/.../eth/messages/BlockHeadersMessage.java:73-145` | The decoder also performs canonical re-encode + keccak hashing (verification rule) inside the message codec. | Split `HeaderCodec` (decode) from `HeaderVerifier`. |
| 40 | Framework coupling (cache in handler) | `networking/.../eth/EthHandler.java:96-141` | The per-connection Netty handler owns header/hash LRU caches and pre-caches genesis — persistence policy in a transient handler. | Inject a shared `HeaderCache` port. |
| 41 | Module direction | `networking/.../NetworkConfig.java:25-33,84-106` | A networking-layer record bundles EL fields with consensus-layer/beacon config (validators root, CL multiaddrs, beacon API URL). | Split EL-discovery config from a CL/consensus config owned by the consensus layer. |
| 42 | Entity polluted (entity knows serializer) | `consensus/.../types/BeaconBlockBody.java:3`, `ExecutionPayloadHeader.java:3` | Entities depend on the `SszUtil` concretion for decode + HTR. | Depend on an `SszHasher` abstraction, or isolate decode out. |

### Low severity

| # | Concern | Location | Description | Refactor |
|---|---|---|---|---|
| 43 | Hand-rolled framework detail | `app/.../CommandHandler.java:1305-1340` | Custom JSON parse/escape reimplements a framework concern via fragile substring scanning at the boundary. | Once DTOs exist, delegate to a JSON lib in the presenter. |
| 44 | Domain constant in delivery layer | `app/.../CommandHandler.java:457-459` | `MERGE_BLOCK`/`MAX_HEADER_CHAIN_GAP` domain constants defined in the IPC handler. | Relocate to a consensus/domain constants class. |
| 45 | Reflection coupling at boundary | `app/.../CommandHandler.java:133-153,173-178` | Reflective access to kethereum/trueblocks Kotlin types couples the adapter to an external lib's binary shape. | Encapsulate inside the external gateway adapter. |
| 46 | Entity polluted (format helpers) | `core/.../NodeKey.java:80-82`, `Enr.java:38-42` | Hex/Base64 string (de)serialization helpers live on the entities. | Push string-format concerns into codecs/adapters. |
| 47 | Layer mixing (scattered utils) | `consensus/.../BeaconLightClient.java:810-817,1102-1106` & `LightClientProcessor.java:180-184` | Duplicated hand-rolled `hexToBytes`/`bytesToHex` across use-case classes. | Move to a shared util in the appropriate layer. |
| 48 | Testability (no clock abstraction) | `consensus/.../BeaconLightClient.java:189-191,230` | Sync loop spawns a virtual thread and `Thread.sleep(12_000)` directly, coupling the use case to a concrete scheduler/clock. | Inject a `Clock`/scheduler abstraction. |
| 49 | Dependency Rule (logger in rule) | `consensus/.../proof/MerklePatriciaVerifier.java:37,107,196` | Pure verification logic hard-wires SLF4J `LoggerFactory`. | For strictness, route diagnostics through an injected logging port. |
| 50 | Boundary erosion (raw arrays in DTO) | `consensus/.../libp2p/ReqRespCodec.java:61-122` | `DecodeResult` holds raw `forkDigest`/`sszPayload` byte arrays that then flow unchanged into the use case. | Have the gateway convert to typed domain objects before crossing inward. |
| 51 | Framework coupling | `networking/.../rlpx/RLPxHandler.java:88-138` | EIP-8 ack size-detection/buffering is interleaved with `ByteBuf` reader-index manipulation, so ack-parsing can't be tested without a `ByteBuf`. | Extract a pure `AckFramer` (byte[]→complete-ack). |
| 52 | Business constants in handler | `networking/.../eth/EthHandler.java:298,675,757` | Hardcoded protocol thresholds (`21_000_000` probe, `20_000_000`/`1_000_000` staleness floors) buried in the Netty handler. | Hoist into the eth use case / config. |
| 53 | Layer mixing | `networking/.../discv4/DiscV4Handler.java:114` | TCP-port-from-Ping fallback and endpoint trust policy live in the I/O handler. | Fold endpoint-resolution policy into the discovery use case. |

---

## Cross-cutting observations

- **The single largest structural gap is a missing use-case layer in `app`.** `CommandHandler` (1341 lines) is nominally an IPC adapter but actually holds the application's load-bearing business rules — beacon verification, MPT proof checking, header-chain walking, tx decoding, storage-key derivation — interleaved with hand-rolled JSON. In Clean Architecture terms this is inner-layer logic that has leaked all the way to the outermost ring. Introducing interactors with typed request/response DTOs and gateway ports is the highest-leverage change in the whole codebase.

- **No port exists at the networking↔app seam.** `app` depends on the concrete, Netty-owning `RLPxConnector`, and `EthHandler` even reaches collaborators by pipeline name. One `EthClient`/`PeerDataSource` interface (getHeaders/getBodies/getAccount/getStorage returning domain DTOs) would invert the app→framework dependency and make the eth protocol testable with a fake sender.

- **Module dependency *direction* between Gradle modules is correct.** `core`/`consensus` never import `networking`/`app`; no inward-pointing-outward module dependency was found. Every violation is a *within-module layer collapse*, not a cross-module direction error — the build graph is right, the internal layering is not.

- **Business rules are clean but framework-locked.** The actual trust logic (`LightClientProcessor`, `SyncCommitteeVerifier`, `LightClientStore`, `BeaconChainSpec`, `SszUtil`, `MerklePatriciaVerifier`, `BlsVerifier`) is well-isolated from transport and largely unit-testable — but it imports concrete crypto/SSZ libraries (Milagro, Tuweni) and `BeaconLightClient` `new`s its data sources, so the *sync flow* can't be exercised without HTTP + libp2p infra.

- **Entities are not pure.** `NodeKey`, `Enr`, `BlockHeader`, and the SSZ containers each fuse domain data with serialization (RLP/Base58/Base64/SSZ-offset) and, for `NodeKey`/`Enr`, crypto-provider and libp2p logic. The decode halves belong in codec adapters. (Nuance: SSZ `hashTreeRoot` is arguably a domain verification rule and may stay on the type; it is the *byte-offset decode* and retained `raw` bytes that should move out.)

- **The codebase already contains the pattern to copy.** `DnsEnrResolver` injects a `TxtResolver` port, and `EciesCodec`/`FrameCodec`/`AuthHandshake`/`Packet`/`KademliaTable` are framework-free and unit-testable. These prove the team can keep logic off the framework — the eth/snap layer, `BeaconLightClient`, and `CommandHandler` simply weren't held to the same standard.

- **Trust-boundary tie-in (per CLAUDE.md):** the inlined HTTP beacon-API in `BeaconLightClient` and the `IpfsHttpClient` source in `CommandHandler` are exactly the "HTTP only for debugging / nothing trusted without crypto verification" boundary. Putting both behind gateway ports (#6, #8) makes those paths explicit, swappable, and removable for production.
