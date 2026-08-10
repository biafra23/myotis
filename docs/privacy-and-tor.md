# Privacy & Tor — design sketch

> **Status: the core transport path is in production, feature-gated.**
> `-PtorEngine` links Arti into the Rust engine
> (`rust/myotis-net/src/el/tor.rs`), and a Settings toggle routes **account
> (balance/nonce) reads only** — the single routing switch sits in
> `get_account` (`reader.rs`) — over per-address isolated circuits with
> ephemeral RLPx keys. Wired up on the desktop host only today; storage/token
> reads, contract code, `eth_call`/gas estimation, tx broadcast, the CL fetch,
> and discovery still use the real IP. The runnable proof of concept
> (`rust/tor-poc`, see [§9](#9-proof-of-concept--what-was-validated)) validated
> the transport against live mainnet and its measurements are folded back in
> below (marked **PoC:**). The quarantined peer pool, multi-source promotion,
> and request-shape hardening remain unimplemented proposals — everything about
> them is design, not shipped behavior.

Companion docs: [Disk & Network Usage](disk-and-network-usage.md) (traffic volumes
this design would route), [Optimisations & Limitations](../OPTIMISATIONS_AND_LIMITATIONS.md)
(why round-trip latency is the binding performance constraint).

---

## 1. What leaks today (threat model)

Myotis verifies everything cryptographically — a peer can never *lie* to us. But
peers, and anyone observing traffic, can *learn* from what we ask. Ranked by
sensitivity:

| Flow | What an observer/peer learns | Severity |
|---|---|---|
| **snap queries** (`GetAccountRange`/`GetStorageRanges`) | The request carries `keccak(address)` and storage-key hashes. Hashing hides nothing: keccak of every known-active address is trivially precomputed, so every snap peer we query learns **address ↔ IP**, plus which tokens/contracts the user cares about. | **High — the core leak** |
| **Transaction broadcast** | The signed tx is pushed directly to ~32 peers from the user's IP (`RLPxConnector.broadcastTransaction`) — the classic "first spy" deanonymization setup: **tx ↔ IP**. Note broadcast is the one flow where relaying through anything costs *zero* trust — Myotis' trust model protects reads; a broadcast can't be forged, only censored. | **High** |
| Receipt tracking | Which blocks' bodies we fetch while watching a send. Weak signal — whole bodies are decent cover. | Low |
| **CL light client** (finality/committee updates) | Content is public chain data, identical for every client — nothing user-specific. It does *fingerprint* the IP as running an Ethereum CL light client, with wake/sleep timing that mirrors app usage. | Low (content-benign) |
| **Discovery** (discv4/discv5) | The IP participates in the Ethereum DHTs — i.e. runs a client. No addresses involved. | Low |

The design goal is therefore precise: **unlink the snap-query and tx-broadcast
flows from the user's IP**, without breaking the trust model, and without paying
Tor's latency on flows that don't need it.

## 2. Transport inventory — what can and cannot cross Tor

Tor carries **TCP streams only**. Myotis' transports:

| Layer | Transport | Tor-able? |
|---|---|---|
| RLPx / eth / snap (port 30303) | TCP | Yes (Arti data stream) |
| CL libp2p req/resp (port 9000) | TCP | Yes — but content-benign, may not need it |
| discv4 (EL discovery) | UDP | **No** |
| discv5 (CL discovery) | UDP | **No** |
| EIP-1459 ENR trees | DNS TXT (dnsjava) | Not directly; needs DoH over a Tor stream |
| CCIP-Read gateways | HTTPS | Yes (standard) |

Myotis is effectively **outbound-only** (a light client that dials), which is
Tor-friendly: no inbound reachability, no onion service needed.

**Exit policies.** Tor's default exit policy does **not** block 30303 or 9000
(its reject list is SMTP/NetBIOS/BitTorrent-ranges/etc.), so default-policy exits
carry them. However, a large fraction of exits run the "reduced exit policy"
(~65 web/mail/IRC/Bitcoin ports), which excludes both. Tor selects exits whose
policy permits the destination port automatically — connections succeed, but from
a smaller, often more loaded exit pool. This should be measured (see Open
questions) before committing.

> **PoC:** confirmed real, not just theoretical. A fraction of circuit builds to
> `:30303` fail with Arti's `Failed to obtain exit circuit for ports` (the reduced
> policy at work), and others reach the peer but time out at the exit. The port is
> reachable — most attempts do get a stream — but the exit pool for it is visibly
> smaller and lossier than for web ports. Quantifying the exact fraction is still
> open (§8.1); the qualitative answer is "usable with retries, not free."

**Latency.** Per the Optimisations doc, round-trip time — not bandwidth — is what
makes or breaks the wallet experience, and Tor adds ~0.5–1.5 s per round trip
plus ~1 s+ per circuit build. This is the strongest argument for routing **only
the sensitive flows** through Tor and keeping bulk/benign flows direct.

> **PoC:** measured, and the variance is the story. Arti cold bootstrap is a
> one-time ~11–12 s. Once bootstrapped, a full verified snap account read (Tor
> connect + RLPx handshake + eth Status + head-header fetch + GetAccountRange)
> was **~0.75 s on a good circuit but up to ~18 s on a slow/lossy one** — the
> single account fetch alone hit 14 s through a bad exit. The mean is tolerable;
> the tail is not, and it lands exactly on the confirm-screen path. This
> sharpens §8.5: the Tor mode needs its own serve-stale / timeout-and-retry
> policy, not just the clearnet budget.

## 3. Tor client library: Arti, in the Rust engine

Per-identity circuit isolation ("stream isolation") is a first-class Tor concept.
The proposal targets **Arti** (the Tor Project's official Rust implementation,
embeddable as a plain library) inside the **Rust engine** — and only there:

- Isolation is an explicit API: an `IsolationToken` attached to `StreamPrefs`
  per stream — streams with different tokens never share a circuit — plus
  `TorClient::isolated_client()` for a fully isolated handle. **One token per
  wallet address** gives exactly the property we want: any single exit node
  ever sees queries for one address, not the user's whole portfolio.
- **Android is covered by the same code.** The Rust engine already crosses to
  Android as jniLibs (`cargoNdkAndroid`); Arti compiles for the same NDK
  targets and embeds in the engine, so the Android host needs no separate Tor
  integration (no bundled daemon, no Orbot dependency). Likewise iOS, where the
  Rust engine is the only engine.
- **The Java engine gets no Tor mode for now.** A Java path would mean bundling
  a Tor daemon and driving it over SOCKS — deliberately out of scope; hosts
  that want private mode select the Rust engine (`myotis.engine=rust`). This
  also keeps the privacy machinery in one implementation instead of two
  parity-tracked ones.

Two properties to keep in mind:

- **Isolation cost**: each isolated circuit is a fresh 3-hop build (~1 s+).
  Per-address isolation (circuits reused across that address's fetches) is
  affordable; per-*connection* isolation on a 32-peer dial wave is not.
- **The guard doesn't change.** Isolation varies middle + exit; the entry guard
  stays pinned (Tor's Sybil defense). Isolated circuits unlink addresses from
  each other at the exit — they are not "completely new paths."

> **PoC:** validated. `arti_client::TorClient` bootstraps and runs entirely
> in-process (no bundled `tor`, no Orbot), and `StreamPrefs::set_isolation(token)`
> with one `IsolationToken` per address drives distinct circuits. The PoC dials
> real mainnet peers on `:30303` and completes RLPx + eth/66-69 + snap/1 through
> them. **The one production change needed was making the RLPx transport generic
> over the byte stream** (`RlpxConnection<S = TcpStream>` / `EthSession<S>` +
> `handshake_over()`); the default type parameter keeps every clearnet caller
> untouched, so the *same* handshake/frame/eth/snap code drives both a `TcpStream`
> and an Arti `DataStream`. No protocol logic changed.
>
> **Implementation gotcha (cost us the whole path until found):** Arti's
> `DataStream` **buffers writes and requires an explicit `flush()`** to emit
> cells onto the circuit, whereas `TcpStream` sends eagerly. Without a flush after
> writing the auth/frames the peer never sees them and FINs, surfacing as a
> misleading "early eof" reading the RLPx ack. The production Tor path must flush
> after every write (a harmless no-op on TCP).
>
> **Bound the handshake explicitly.** The clearnet `dial()` wrapped the whole
> handshake in a timeout; the extracted `handshake_over()` is deliberately
> unbounded so the caller can pick a Tor-appropriate budget. A Tor peer that
> accepts the stream but never sends the ack will otherwise hang the task and
> leak a circuit slot — so every Tor-side caller MUST wrap it in a timeout
> (retrying on a fresh circuit is the natural response, given exit variance).

## 4. The proposed split: clearnet background, Tor foreground

Route by sensitivity, not wholesale:

**Stays clearnet (real IP):**

1. **Discovery** — discv4/discv5 are UDP and can't cross Tor anyway; they reveal
   only "this IP runs a client."
2. **Snap capability/quality validation** — probing a discovered peer with
   `GetAccountRange` at **random** account hashes / random ranges reveals nothing
   about the wallet and looks like ordinary state-sync traffic. This feeds the
   existing quality cache (`snapok`/`snapbad` in `peers.cache` —
   `app/.../PeerCache.java`).
3. **CL light client** — content-benign (§1); paying Tor latency on the per-slot
   finality fan-out buys little. (Optionally proxied later; see Open questions.)

**Goes over Tor:**

4. **Real snap queries** for the user's addresses — per-address circuit
   isolation (§3) and **ephemeral RLPx node keys** (§6.1).
5. **Transaction broadcast** — over Tor to the proven peer pool; zero trust cost
   by construction.

## 5. The quarantined peer pool (delayed use)

The link an adversarial peer could still make is: "IP X discovered/probed me,
and *some Tor client* later queried address A through me." The proposal breaks
the pairing with a **randomized aging window between the last clearnet contact
with a peer and the first real (Tor-side) use of that peer** — on the order of
**days**.

Timeline per peer:

```
discover (clearnet, UDP)
   └─> validate immediately (clearnet, random-range snap probe)
          └─> cache entry stamped lastClearnetContact = now
                 └─> QUARANTINE: not Tor-usable until
                     now + randomized threshold (days)
                        └─> Tor-side dial ranking may select it
                            (fresh RLPx identity, per-address circuit)
```

Design rules:

- **The clock runs from the *last* clearnet contact, not the first.** Peer
  quality decays over days, and re-validating in the clear is always allowed
  (random ranges stay non-sensitive) — but every clearnet contact restarts that
  peer's quarantine, otherwise "days of silence before Tor use" quietly erodes
  to hours. This naturally pushes toward **rotating batches**: validate batch A,
  let it quarantine untouched while batch B is being probed; use aged batch A
  over Tor; retire and re-probe it later.
- **Every background clearnet loop must respect the quarantine.** This is not
  automatic: today's peer maintenance re-dials cached peers in the clear all the
  time (`ChainStack.maintainSnapPeers` tops up the active pool from the cache
  every 10 s; discovery re-pings table peers every 15 s). Left unmodified, those
  loops would keep touching quarantining peers and perpetually reset their
  clocks — no peer would ever mature. So quarantine membership must be a hard
  filter on *all* clearnet contact, not just on probing: the maintainer and
  dial ranking draw only from the active (clearnet) batch, quarantining peers
  are excluded from clearnet dialing entirely, and the Tor-side pool is the only
  consumer that ever contacts them again. (Unsolicited *inbound* contact — a
  quarantined peer pinging us via discv4 — doesn't reset the clock: the property
  is about what our IP initiates toward that peer.)
- **Fail closed.** When the aged, multi-source-confirmed pool runs dry, the
  Tor-side path must error or wait for the pool to refill — never fall back to
  freshly discovered peers, or the property silently evaporates exactly when
  it's under stress. (Same philosophy as the existing verified-reads posture:
  honest error over degraded answer.)

- **Tor-reachability is a first-class selection criterion — this is the PoC's
  biggest surprise.** The design assumed "reach a good snap peer" was the same
  problem over Tor as over clearnet. It is not. **Most synced full nodes drop
  inbound connections from Tor exit IPs** — either an immediate FIN right after
  our auth, or a `reason=4` "Too Many Peers" disconnect — because they are
  inbound-saturated and the whole Tor network arrives from a small, busy set of
  exit IPs. Empirically the peers that *do* accept Tor inbound skew toward
  *less-busy* nodes, which are disproportionately **poorly-synced or stuck at
  genesis** (they have free slots precisely because nobody else wants them). A
  peer that completes the handshake over Tor but advertises head #0 cannot serve
  a snap query at a fresh retained state root — so "accepts Tor inbound AND is
  synced" must be an explicit promotion gate for the Tor pool, validated (like
  snap quality) during the clearnet probe and re-checked over Tor. Selecting on
  clearnet snap-quality alone is not enough.
- **Bootstrap via popular peers.** A strict quarantine would mean no private
  queries for days after first install. The escape is the *popularity* property:
  peers on the public EIP-1459 DNS ENR tree (mainnet pins
  `all.mainnet.ethdisco.net`) and the hardcoded bootnode-adjacent set are known
  to every client in existence — dialing them over Tor reveals nothing about how
  *you* found them, so they are Tor-usable on day one with **zero aging**. The
  personally-discovered, quality-validated pool matures in quarantine and
  gradually takes over.
- **Implementation is small — but in a separate file, not a new `peers.cache`
  column.** `peers.cache` is shared byte-identically between the Java and Rust
  engines, and each engine's rewrite path serializes only the columns it knows
  (`PeerCache.java`, `peercache.rs`) — since the Java engine gets no Tor mode
  (§3), a Java-side rewrite would silently strip a Tor-only column. Quarantine
  metadata (`lastClearnetContact`, discovery-source confirmations) therefore
  lives in a **Tor-only sidecar** (e.g. `peers-tor<suffix>.cache`) keyed by the
  peer's public key, owned exclusively by the Rust engine's Tor mode. The
  Tor-side dial ranking joins it against the shared cache and filters on
  `now − lastClearnetContact > randomizedThreshold` before the existing
  `snapok` preference. (Entries whose peer disappears from `peers.cache` are
  pruned; a missing sidecar just means an empty Tor pool — fail closed, §5.)

## 6. Attacks the delay does NOT stop (each needs its own fix)

The aging window defeats **timing correlation** — with days in between and
thousands of other clients contacting the same peer, proximity-pairing is noise.
Three linkage channels survive arbitrary delay:

### 6.1 Node identity reuse — fatal if unfixed

Myotis has one persistent secp256k1 node key (`nodekey.hex`,
`app/.../FileNodeKeyStore.java`) used for discovery ENRs **and** RLPx handshakes.
If a Tor-side handshake presents the public key a peer already saw from the
user's real IP during probing, the peer links them instantly — delay irrelevant.
**Tor-side connections must generate ephemeral RLPx keys** (per address, matching
the circuit isolation). Cheap: Myotis is outbound-only, so nothing depends on our
identity persisting.

### 6.2 Poisoned discovery results as tracking tags

A malicious discovery node can hand **each querier a unique enode** in its
NEIGHBORS/discv5 responses. Whoever later dials that unique peer — via Tor, days
later — is identified as the querier from IP X. This is *set-membership*
correlation; delay never helps. Mitigation: a peer is promoted into the
Tor-usable pool only when confirmed from **multiple independent sources**
(several disjoint FINDNODE paths, and ideally the DNS ENR tree). Popularity
breaks linkage more fundamentally than delay: delay handles timing, popularity
handles membership.

### 6.3 Client fingerprinting — anonymity bounded by the user base

The Hello advertises `myotis/0.1.2` (`HelloMessage.java`), and even with a
spoofed clientId the request shape is distinctive (single-account ranges with
full-range limit and the 4 KiB response cap, the characteristic header probe).
A peer can plausibly tag both the clearnet prober and the Tor-side client as "a
Myotis instance." With many Myotis users, fine — the delay plus a large
anonymity set prevents pairing *which* instance. With very few users, the
correlation is strong regardless of delay. Structural today; dissolves with
adoption. It argues for making Tor-side request shapes as generic as practical,
and for not shipping a unique clientId on the Tor path.

## 7. What each mechanism buys — summary

| Mechanism | Defeats |
|---|---|
| Tor + per-address isolation (§3, §4) | address ↔ IP linkage at snap peers; tx ↔ IP at broadcast; cross-address linkage at exits |
| Ephemeral Tor-side RLPx keys (§6.1) | identity-based pairing of clearnet probe ↔ Tor use |
| Quarantine delay (§5) | timing correlation between clearnet contact and Tor use |
| Multi-source / popularity promotion (§6.2) | per-querier poisoned-peer tracking tags |
| Generic Tor-side request shapes (§6.3) | (partially) client-fingerprint pairing; fully only with adoption |
| Fail-closed pool (§5) | silent property loss under peer starvation |
| Tor-reachability + synced gate (§5, PoC) | selecting peers that clearnet-validate but drop Tor inbound / are unsynced → a dry Tor pool at query time |

## 8. Open questions for review

1. **Exit-pool health for port 30303/9000** — what fraction of exit bandwidth
   permits them in practice, and what does that do to circuit build success and
   latency? Needs measurement before committing.
   > **PoC:** partially answered — `:30303` is reachable over Tor but from a
   > visibly smaller/lossier exit pool; some builds fail outright on the reduced
   > exit policy. The exact usable-bandwidth fraction is still unquantified.
2. **Delay distribution** — uniform over what range? Per-peer independent draws?
   Is there an analysis that pins how much delay is enough given peer contact
   rates observed from crawlers?
3. **Pool sizing** — how large must the quarantined pool be to absorb days of
   churn and still hold N healthy snap peers at query time?
   > **PoC:** the constraint is tighter than churn alone — the pool must hold N
   > peers that are *both* synced *and* Tor-inbound-accepting (see §5), a
   > materially smaller fraction of discovered snap peers than expected.
4. **Should the CL side eventually be proxied too?** Content-benign, but it
   fingerprints wake/sleep timing at the real IP. A later phase could route it
   through the same machinery at low priority.
5. **Latency budget** — with per-address circuit reuse and the batched snap
   fetches (`BATCH_PATHSET_CHUNK`), is a Tor-routed balance read acceptable on
   the confirm-screen path, or does the Tor mode need its own serve-stale
   policy?
   > **PoC:** measured ~0.75 s (good circuit) to ~18 s (slow/lossy) for a full
   > verified read — the tail is too slow for a synchronous confirm screen, so
   > the Tor mode almost certainly needs its own serve-stale + retry policy.
6. **Tx broadcast fan-out over Tor** — one circuit to a few aged peers, or
   several isolated circuits to disjoint peer subsets (stronger against a
   listening peer, more circuit builds)?
7. **Mobile cost** — the embedded Arti client keeps a
   guard connection alive; interaction with idle-pause and battery needs design
   (probably: Tor client lifecycle == stack awake lifecycle).
8. **DoH-over-Tor for the ENR tree walk** — which resolver, and does that
   introduce its own linkage?
9. **Peer-side Tor-exit rejection (new, from the PoC)** — synced full nodes
   widely drop inbound from Tor exit IPs (immediate FIN or `reason=4`), and the
   nodes that *do* accept skew toward unsynced ones (§5). How large is the
   population of synced, snap-serving, Tor-accepting mainnet peers really, and is
   it stable enough to sustain a fail-closed pool? This gates everything and is
   the first thing to measure at scale. If it proves fatal, the first
   alternative to measure is a VPN-style overlay whose exit IPs are not the
   Tor exit set — see §10.

## 9. Proof of concept — what was validated

A runnable PoC lives at `rust/tor-poc` (standalone crate, excluded from the Rust
workspace so Arti's dependency tree never touches the pure-engine build). It
reuses the real `myotis-net` RLPx + eth/snap stack by path and runs it over Tor
against live mainnet. See `rust/tor-poc/README.md` for how to run it.

**Validated end-to-end:**

- Arti embeds and bootstraps in-process (§3) — no bundled `tor`, no Orbot.
- Per-address stream isolation (§3): one `IsolationToken` per address → distinct
  circuits; the PoC reads two addresses each over its own isolated circuit.
- Ephemeral Tor-side RLPx keys (§6.1): a fresh random node key per connection.
- The existing RLPx + eth/66-69 + snap/1 stack runs **unmodified** over an Arti
  `DataStream` (§4) — the only production change was making the transport
  generic over the stream type (default `TcpStream`). A clearnet baseline runs
  the identical code over `TcpStream` for comparison.
- The §1 "core leak" flow itself: a real `GetAccountRange` for a user address,
  MPT-verified, returned over Tor with the IP behind three hops (e.g. a verified
  balance for `d8dA…6045` against a synced peer's head state root).

**Deliberately out of scope (still proposals):** the quarantined peer pool and
its aging window (§5), the `peers-tor` sidecar, multi-source popularity
promotion (§6.2), generic request-shape hardening (§6.3), tx-broadcast fan-out
(§8.6), and — importantly — **the beacon-anchored trust root**: the PoC anchors
the snap proof to the peer's *own claimed* fresh head, not the sync-committee
anchor. It proves the transport, not a trust-model change; its `VERIFIED` output
means "MPT-consistent with a peer-claimed head," which is strictly weaker than
the wallet's real verified-read guarantee (see the "Trust" section of
`CLAUDE.md`). Any productionization must anchor to the beacon chain.

**Key learnings folded into the sections above:** the `DataStream` flush
requirement and mandatory handshake timeout (§3), the measured latency tail
(§2/§8.5), the reduced-exit-policy reality for `:30303` (§2/§8.1), and the
dominant blocker — peer-side rejection of Tor exit IPs, which promotes
"Tor-reachable + synced" to a first-class peer-selection gate (§5/§8.9).

## 10. Alternatives considered: HOPR / Gnosis VPN (assessment, 2026-08-10)

Would the [HOPR mixnet](https://hoprnet.org) or
[Gnosis VPN](https://vpn.gnosis.eth.limo) (a VPN built on it, funded by
GnosisDAO) serve the §1 goal better than Tor? Short answer: **not instead —
possibly alongside.** Arti stays the embedded transport; Gnosis VPN is worth
recommending to desktop users as a system-level complement once it is
generally available; direct HOPR integration is a dead end today.

### The facts (as of 2026-08)

**HOPR** — incentivized Sphinx mixnet; relays are paid in tickets settled on
Gnosis Chain:

- No embeddable client library exists. Using the mixnet means running a
  `hoprd` node: operator onboarding is permissioned (waitlist), with a 30k
  wxHOPR minimum stake (10k with an early-supporter NFT) behind a Safe, per
  HOPR's node docs.
- The Sessions API — TCP **and UDP** tunneling over 0–3 hops — is the right
  shape for a wallet, but it is an API *of a running hoprd*, not a library.
- HOPR's own productization of exactly this use case — **RPCh**, "private RPC
  for wallets" — is officially paused (the `hoprnet/RPCh` repo is flagged
  "-development paused-").
- The relay network is on the order of hundreds of nodes with modest traffic;
  whatever the mixing theory says, the practical anonymity set is orders of
  magnitude below Tor's (~7–8k relays, millions of daily users).

**Gnosis VPN** — a system-level VPN over the HOPR mixnet:

- Not a library: a Rust system service (root routing daemon + worker + control
  CLI) that owns system routing and DNS. No SDK, no SOCKS interface — nothing
  an engine could link, and nothing it could drive per-connection.
- Status per its published roadmap (fetched 2026-08-10): the current beta
  ("El Dorado") is **Mac/Linux only**; **multi-hop routing only arrives with
  "Shangri-La" (Sep 2026)** — until then a relay/exit can see both the user's
  IP and the destination, i.e. trust-the-operator VPN privacy, not mixnet
  privacy; six exit locations; **on-chain metered payments**; broader
  platform/OS support is a 2027 milestone ("Xanadu").

### Why neither replaces the embedded Arti path

| Axis | Arti/Tor (shipped) | HOPR direct | Gnosis VPN |
|---|---|---|---|
| Embeddable in the engine | Yes — in-process library (§3) | No — needs a staked, waitlisted hoprd | No — root-owned system service |
| Mobile | Compiles for the same NDK/iOS targets (§3) | No | No (2027 roadmap) |
| Per-address unlinkability | Yes — one `IsolationToken` per address (§3) | Conceivable via per-address Sessions | **No — one tunnel, one exit identity** |
| Anonymity set | ~7–8k relays, millions of users | Hundreds of nodes | Its (beta) user base |
| Cost to use | Free | On-chain ticket payments | On-chain metered payments; planned Circles-identity onboarding |
| Maturity | ~20 years in production | Mixnet live; the wallet product (RPCh) paused | Closed beta |

Two of these rows are decisive:

- **Per-address unlinkability.** The §1 core leak is not only address ↔ IP but
  the clustering of one user's addresses. Per-address isolation makes queries
  for different addresses arrive at snap peers from different exit IPs; a
  single system tunnel hides the home IP but presents one exit identity, so a
  peer can still cluster every queried address as "same user." A VPN-shaped
  transport cannot express the §3 isolation model at all.
- **Payment bootstrap circularity.** Both HOPR and Gnosis VPN charge on-chain.
  A wallet would need chain access — and would leave a linkable on-chain
  payment trail — to buy the privacy layer that is supposed to protect its
  chain access. Tor is free and leaves no such footprint.

### What Gnosis VPN is genuinely good for (complementary, user-operated)

Run *underneath* Myotis by the user, a system VPN covers, with zero Myotis
code, everything the embedded Tor path does not:

- **The UDP surfaces** — discv4/discv5 discovery can never cross Tor (§2).
- **Every not-yet-routed flow** — storage/token reads, `eth_call`, tx
  broadcast, the CL fetch, and the Java-engine host surfaces (DNS ENR walk,
  CCIP-Read, the tx-history debug fetch) — on both engines.
- **A path around §8.9.** Synced peers drop Tor exits because the whole Tor
  network arrives from one small, saturated, widely blocklisted set of exit
  IPs. Gnosis VPN's exits are today ordinary, low-traffic addresses that
  devp2p peers treat like any VPN customer — though a six-location fleet would
  recreate the same funnel if its adoption grew.

The properties are weaker (table above: one exit identity, operator-visible
until multi-hop ships, beta-sized anonymity set) but the *coverage* is total,
and the two compose: the engine's Tor mode keeps per-address isolation for
account reads while the VPN blankets everything else. (Running Arti through a
VPN is unremarkable — the guard then sees the VPN exit instead of the home IP;
the exit-side story of §3–§5 is unchanged.)

### Revisit triggers

Re-evaluate when any of these becomes true:

1. **Gnosis VPN ships something embeddable** — an SDK, a SOCKS/local-proxy
   interface, or mobile support ("Xanadu", 2027, is the earliest plausible
   date). A local-proxy interface would slot in as a second `S` behind the
   generic `RlpxConnection<S>`/`EthSession<S>` seam (§3), same as Arti did.
2. **HOPR Sessions become permissionless** — usable without a staked,
   waitlisted hoprd, with a payment story that doesn't leave an on-chain
   trail.
3. **§8.9 proves fatal at scale** — if the synced-and-Tor-accepting peer
   population cannot sustain a fail-closed pool, Gnosis VPN's exit fleet is
   the first alternative to measure.

## Code pointers (current behavior this design touches)

- Node key: `app/.../FileNodeKeyStore.java`, `core/.../crypto/NodeKey.java`
- Peer cache + quality tokens: `app/.../PeerCache.java`,
  `rust/myotis-net/src/el/peercache.rs`
- Dial ranking / peer maintenance: `node-core/.../ChainStack.java`
  (`dialCachedPeers`, `snapDialRank`, `maintainSnapPeers`)
- snap request shapes: `networking/.../eth/EthHandler.java`
  (`SNAP_RESPONSE_BYTES`, GetAccountRange/GetStorageRanges senders)
- Tx broadcast: `networking/.../rlpx/RLPxConnector.java`
  (`broadcastTransaction`)
- DNS ENR trees: `networking/dns/DnsEnrResolver`, `NetworkConfig.elEnrTreeUrls`
- Hello clientId: `networking/.../HelloMessage.java`
