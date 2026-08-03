# Inbound devp2p connections — design & feasibility

Status: **design only, not scheduled**. This document records why accepting
inbound RLPx connections matters for Myotis, whether it can work at all on the
networks our users actually sit behind (home router, mobile, Starlink), and
what the implementation would look like in both engines. Nothing here is
implemented; the gap analysis cites the code as of 2026-08-03 (post #276/#277/#278).

---

## 1. Why: outbound-only nodes starve on saturated networks

Myotis is dial-only today. Field evidence from the sepolia desktop stack
(2026-08-03 logs) shows what that costs:

- The busy-peer counter introduced in #278 pegged at its tracking cap:
  **at least 256 distinct peers rejected us with `Disconnect(0x04
  TooManyPeers)` within 10 minutes** (256 is the counter's bound, so the true
  figure may be higher)
  while the serving pool sat at zero and the EL hunt was engaged.
- With no serving snap peer, the verified head went stale (>120 s) and every
  Kohaku state request failed: in one ~90-minute window, `eth_call` 89
  failures vs 56 successes, `eth_getTransactionCount` 31/19,
  `eth_getCode` 26/23, `eth_estimateGas` 16/1.
- Of ~250 crawler-visible sepolia EL nodes, only ~116 have *ever* completed a
  handshake with us. The missing bucket is largely structural: nodes that are
  NAT'd (unreachable to our dials) or perpetually full. An outbound-only node
  can reach neither — it must win slot lotteries against every other dialer
  the moment a slot frees.

**The payoff asymmetry is what makes inbound worth the effort**: an inbound
connection arrives from a node that is filling its *outbound* slots — i.e. a
full node, snap-capable by construction, exactly the peer class we starve
for. Reciprocally, NAT'd peers (invisible to our dialer forever) can reach us
if we are reachable. Even modest reachability disproportionately fixes the
"everyone is full" failure mode.

**The trust model is unaffected.** Peers are never trusted (CLAUDE.md: the
only trust anchors are sync-committee signatures and the embedded
accumulators). Inbound changes *peer acquisition*, not verification — every
header, account, and storage proof from an inbound peer is verified exactly
like one from a dialed peer. An attacker connecting to us can waste our
sockets, not poison our state; the exposure is availability/DoS and
enumerability (see §5).

---

## 2. Can it work behind NAT? Per-network feasibility

The desktop will almost always be NAT'd. The honest summary: **IPv6 is the
common denominator, UPnP covers the IPv4 home case, and CGNAT-without-IPv6
has no in-protocol rescue.**

### Home router
Two viable paths, covering most desktop users:

- **IPv4 + port mapping**: UPnP-IGD is enabled by default on most consumer
  routers; NAT-PMP/PCP are its Apple/IETF successors. A startup "map TCP+UDP
  30303" attempt is standard practice — geth has shipped exactly this for
  years. Caveat: **DS-Lite** connections (common on German cable, e.g.
  Vodafone) put the IPv4 side behind CGNAT — UPnP then maps a port on the
  router that still isn't reachable from the internet. Detect this (mapped
  external address in 100.64.0.0/10 or RFC1918) and report it honestly.
- **IPv6**: those same DS-Lite connections have public IPv6. FritzBox-class
  routers support per-device IPv6 port sharing (pinholes); some support PCP
  to automate it. A v6 listener plus a router pinhole is fully reachable.

### Mobile (LTE/5G)
- **IPv4: hard no.** CGNAT is universal, no subscriber-controllable mapping
  exists, no exceptions.
- **IPv6: sometimes, unreliably.** Many carriers assign public v6 and some do
  not filter unsolicited inbound (measurement studies repeatedly find
  reachable handsets), but it is carrier-dependent, unverifiable in advance,
  and changes without notice.
- **Recommendation: mobile stays outbound-only by design.** Independent of
  NAT, a phone that accepts inbound pays in battery and fights Doze; the
  Android host should never bind a listener. Out of scope.

### Starlink
- **IPv4: no** on standard/residential plans — CGNAT (100.64.0.0/10), no port
  forwarding, no usable UPnP. (Priority/business plans sell public IPv4.)
- **IPv6: yes.** Starlink delegates a native /56. With the Starlink router in
  bypass mode behind the user's own router (or suitable firewall settings),
  inbound IPv6 works. Starlink is the clearest case where **only** IPv6
  delivers reachability.

### The escape hatches for CGNAT-without-IPv6
devp2p has no rendezvous or hole-punching (unlike libp2p's AutoNAT/DCUtR on
the CL side, which does not help EL snap traffic). For users who want
reachability anyway:

- A cheap VPS with a public IP forwarding TCP/UDP 30303 over a WireGuard
  tunnel to the desktop.
- Running one's own full node on any reachable box. This is doubly effective:
  it is a permanent, never-busy snap server for the wallet, and the trust
  model doesn't care that it's ours — responses are verified like anyone
  else's.

### Reachability math caveat
A v6-only listener is reachable only by the v6-capable slice of the Ethereum
node population — a growing minority, not a majority. IPv6 listening is
therefore most valuable *in combination* with v4+UPnP (home) and is the sole
option on Starlink/DS-Lite, but it must not be oversold: "reachable via v6"
≠ "reachable by most peers".

---

## 3. How: gap analysis and design

Survey of the code as of 2026-08-03. The recurring theme: the *serving* side
is already done and connection-direction-agnostic; what's missing is the
responder half of the transport handshake, a listener, and honest
self-advertisement.

### Gap A — recipient-side RLPx handshake (the core new code, both engines)

Both engines implement only the initiator role:

- Java `networking/.../rlpx/AuthHandshake.java` — the class doc says
  "Implements the initiator side"; the mutating API is `buildAuthMessage()` +
  `processAck()` (plus a `secrets()` accessor). The constructor takes the remote pubkey up front,
  which a recipient doesn't have until it parses the auth body (and must
  ecrecover the initiator's *ephemeral* key from the auth signature — no such
  recovery exists under `rlpx/` today). `deriveSecrets()` hashes
  `remoteNonce ‖ localNonce`, which is only correct for the initiator (the
  spec fixes `recipient-nonce ‖ initiator-nonce`).
- Rust `rust/myotis-net/src/el/rlpx/handshake.rs` — `pub struct Initiator`
  only; its own test comments note the same initiator-centric nonce order.

What already exists and is reusable:

- The ECIES primitives are role-agnostic: Java `EciesCodec.decrypt(...)`
  already handles the size-prefix AAD an inbound auth needs; Rust
  `ecies.rs::decrypt` likewise.
- `HandshakeRoundTripTest.java` hand-rolls the entire responder inline
  (decrypt auth, build ack, swap nonces/wires into `SessionSecrets`) — it is
  the executable spec for a production `RecipientHandshake` and becomes a
  real round-trip test once the production class exists.
- Rust `transport.rs::handshake_over` is generic over any
  `AsyncReadExt + AsyncWriteExt + Unpin` stream (built for Tor), so an accepted `TcpStream` feeds
  straight in; only a `Responder` counterpart to `Initiator` is needed.
- `FrameCodec` (both engines) is role-agnostic given correctly-swapped
  secrets; comments are labelled `[initiator]` and need updating, not logic.

New work: parse auth (EIP-8, with the pre-EIP-8 fallback dialers still send),
ecrecover the ephemeral key, build auth-ack, derive recipient-side secrets,
and a `Responder`/`RecipientHandshake` type per engine.

### Gap B — a TCP listener

There is no EL server socket in either engine (no Netty `ServerBootstrap`
anywhere; the only Rust `TcpListener::bind` is inside a test). Precedents:

- `app/.../DaemonServer.java` — accept-loop structure (Unix domain socket).
- The CL side already listens: `consensus/.../BeaconP2PService.java` binds
  a libp2p listener with the telling comment "some peers reject dial-only
  hosts".

A useful irony to exploit: **we already advertise a TCP listen port we never
bind.** `ChainPorts.elPort` is bound for UDP discv4 but merely *claimed* as
our TCP port in the eth Hello (`EthHandler` → `HelloMessage.encode`) and in
the discv4 Ping `from` endpoint (which carries `tcp = udp = elPort`). Peers
parse that field today. Binding the port we already advertise makes an
existing advertisement true — no new negotiation needed.

### Gap C — learning our external address

Both engines parse-then-discard the one signal the protocol gives us: the
pong-reflected `to` endpoint ("this is the address I saw your ping come
from"). Java `Packet.decodePongPingHash` literally `skipNext()`s it; Rust
`decode_pong_ping_hash` reads only the ping hash. Java even has an unused
`decodePingDestination` decoder (inbound pings carry the same hint).

Design: a small **reflected-address voter** — collect the reflected
IP:port from recent pongs (and inbound pings), take the majority over a
sliding window, expose it as "our external address, confidence N/M". This
feeds the discv4 `from` endpoint (Gap D) and, later, our ENR. It also detects
CGNAT for free: a reflected address in 100.64.0.0/10 means unreachable-v4
regardless of any UPnP mapping.

### Gap D — advertising ourselves honestly

Today we advertise almost nothing, and what we advertise is wrong:

- The discv4 Ping `from` endpoint carries IP `0.0.0.0` (our wildcard bind)
  with `tcp = udp = elPort`.
- We never build or sign our own ENR (`core/.../Enr.java` is decode-only; the
  Rust CL discv5 record is built with a throwaway key and no address fields).
- We answer neither FindNode nor ENRRequest — a deliberate "client-only"
  stance, documented in `rust/.../el/discv4.rs`.

Minimum viable advertisement, in order:

1. **Truthful Ping `from`**: real reflected IP (Gap C) + genuinely-bound TCP
   port. This alone makes us dialable by every peer that processes ping
   endpoints — no ENR required for discv4-level reachability.
2. **Own signed ENR + ENRRequest answers** (later): needed for discv5/ENR-first
   clients and DNS trees. Requires an ENR encoder/signer (new in both
   engines) and sequence-number persistence.
3. **Answering FindNode** (later, explicit policy decision): ends the
   client-only posture — we would join the DHT as a first-class citizen,
   which improves our discoverability but makes the wallet node enumerable
   and adds an amplification-abuse surface (see §5 and
   `docs/privacy-and-tor.md`).

### Gap E — inbound peer plumbing above the transport

- **Identity inversion**: `RLPxConnector.connect(peerAddr, peerPublicKey)`
  takes the peer key as a parameter; for inbound it is a *result* of the auth
  message. The bookkeeping keyed by `ip:port` (`ChainStack`'s
  `attempted`/`backoff`/`blacklistedNodeIds`, the Rust pool's twins) must
  tolerate peers whose source port is ephemeral (track inbound peers by node
  id + claimed listen port, not by the accept-socket port —
  `blacklistedNodeIds` is already node-id-keyed; only the address-keyed maps
  need the inversion).
- **Hello ordering**: both engines send Hello immediately on transport-ready
  and then require the peer's first frame to be Hello. RLPx Hello is
  symmetric (both sides send unprompted), so inbound works with the same
  logic — but the 30 s handshake timer is anchored to our send and should be
  anchored to accept for inbound.
- **Serving needs nothing**: `ServedHeaderWindow`/`ServedHeaders`,
  `ServeStats`, and the eth/69 range advertisement are per-stack and
  connection-direction-agnostic. An accepted peer gets served headers/bodies
  and lands in the existing status counters with zero changes.
- **Slot policy (new)**: an inbound cap separate from `targetSnapPeers`,
  a per-IP limit, the same fork-id/genesis gating via Status that dialed
  peers get, and — pleasingly symmetric — *sending* `Disconnect(0x04
  TooManyPeers)` when full, the very signal #278 taught us to classify.

### Gap F — dual-stack binds

- Rust discv4 is already dual-stack (`bind_udp`: v6 socket with
  `set_only_v6(false)`, v4-mapped addressing, v4 fallback). The new Rust TCP
  listener should reuse that pattern.
- Java has never made a family decision: discv4 binds the JVM-default family
  and hardcodes `0.0.0.0` as its advertised address; `RLPxConnector` uses
  `NioSocketChannel` unpinned. The Java listener (and the discv4 bind) need a
  deliberate `::`-with-v6only-off bind plus v4-literal handling, or two
  sockets.

### Gap G — port mapping (greenfield)

No UPnP/NAT-PMP/PCP code or dependency exists in the repo. Design:

- **Java**: a small IGD/NAT-PMP client (candidates: weupnp, jupnp; must be
  Android-safe per CLAUDE.md even though the feature is desktop-first —
  or kept in a desktop-only module).
- **Rust**: `igd` / `natpmp` crates, optional like other native extras.
- **Startup flow**: attempt mapping → confirm via the reflected-address voter
  (Gap C) or a self-dial → surface one of four states in the status line:
  `mapped` / `CGNAT detected` / `refused` / `v6-only`. Renew mappings on
  their lease interval; unmap on clean shutdown.
- UPnP speaks to the local gateway only (no external service), so this does
  not conflict with the data-sources policy.

---

## 4. Phasing

1. **Listener + recipient handshake + truthful discv4 `from`** — desktop,
   Java engine first. Reflected-address voter, inbound slot policy, status
   reachability indicator ("N inbound peers / reachable: yes-v4 / yes-v6 /
   no").
2. **Rust engine twin** — `Responder` type, listener in the pool/reader
   composition, same voter; reuses `handshake_over`.
3. **Port mapping** — UPnP/NAT-PMP/PCP attempt + verification + status
   surface.
4. **First-class DHT presence** — own signed ENR, ENRRequest/FindNode
   answers, after the §5 policy discussion. DNS-tree submission out of scope.

Testing per phase: loopback inbound round-trips (promoting
`HandshakeRoundTripTest`'s hand-rolled responder into production-backed
tests), cross-engine interop (Java dials the Rust listener and vice versa —
both ends in-repo, no network needed), and opportunistic live tests gated
like `rust/myotis-net/tests/live_pool.rs`.

---

## 5. Open questions (recorded, not resolved)

- **Inbound slot budget** and its interaction with `targetSnapPeers` and the
  EL hunt: do inbound snap-capable peers count toward the serving pool
  (they should — they're the best kind), and does their presence disengage
  the hunt?
- **Android**: recommended never to listen (battery, Doze, CGNAT). Confirm
  and encode as policy rather than leaving it configurable.
- **Privacy**: a reachable, eventually ENR-published node is enumerable — an
  observer can associate an IP with "runs a Myotis wallet". This directly
  tensions with the Tor work (`docs/privacy-and-tor.md`), where inbound is
  impossible by construction. Likely resolution: reachability and Tor
  routing are mutually exclusive modes, chosen in Settings; default TBD.
- **DoS surface**: accept-rate limiting, handshake timeouts on accepted
  sockets, and memory bounds for half-open inbound handshakes need explicit
  budgets before phase 1 ships.
