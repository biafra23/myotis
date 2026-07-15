# Privacy & Tor — design sketch

> **Status: design discussion only. Nothing in this document is implemented.**
> It captures a proposed architecture for network-level privacy (unlinking wallet
> addresses from the user's IP) for review. Facts about current Myotis behavior
> are code-grounded and marked with file pointers; everything about Tor routing,
> quarantined peer pools, and identity separation is a proposal.

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
| RLPx / eth / snap (port 30303) | TCP | Yes (SOCKS5) |
| CL libp2p req/resp (port 9000) | TCP | Yes — but content-benign, may not need it |
| discv4 (EL discovery) | UDP | **No** |
| discv5 (CL discovery) | UDP | **No** |
| EIP-1459 ENR trees | DNS TXT (dnsjava) | Not via SOCKS; needs DoH-over-Tor |
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

**Latency.** Per the Optimisations doc, round-trip time — not bandwidth — is what
makes or breaks the wallet experience, and Tor adds ~0.5–1.5 s per round trip
plus ~1 s+ per circuit build. This is the strongest argument for routing **only
the sensitive flows** through Tor and keeping bulk/benign flows direct.

## 3. Tor client libraries and circuit isolation

Per-identity circuit isolation ("stream isolation") is a first-class Tor concept;
how it's expressed depends on the library:

- **Rust engine → Arti** (the Tor Project's official Rust implementation,
  embeddable as a plain library). Isolation is an explicit API: an
  `IsolationToken` attached to `StreamPrefs` per stream — streams with different
  tokens never share a circuit — plus `TorClient::isolated_client()` for a fully
  isolated handle. **One token per wallet address** gives exactly the property we
  want: any single exit node ever sees queries for one address, not the user's
  whole portfolio.
- **Java engine → bundled Tor daemon** (tor-android/Orbot, kmp-tor; jtorctl for
  the control port — there is no maintained pure-Java Tor). Isolation rides on
  SOCKS5 credentials: `IsolateSOCKSAuth` is on by default, so streams presenting
  different SOCKS username/password pairs get different circuits. The "parameter"
  is simply the SOCKS username sent per CONNECT — use the address (or a hash of
  it) as the username. (`SIGNAL NEWNYM` is the wrong tool: rate-limited ~10 s and
  global, not per-connection.)

Two properties to keep in mind:

- **Isolation cost**: each isolated circuit is a fresh 3-hop build (~1 s+).
  Per-address isolation (circuits reused across that address's fetches) is
  affordable; per-*connection* isolation on a 32-peer dial wave is not.
- **The guard doesn't change.** Isolation varies middle + exit; the entry guard
  stays pinned (Tor's Sybil defense). Isolated circuits unlink addresses from
  each other at the exit — they are not "completely new paths."

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
- **Fail closed.** When the aged, multi-source-confirmed pool runs dry, the
  Tor-side path must error or wait for the pool to refill — never fall back to
  freshly discovered peers, or the property silently evaporates exactly when
  it's under stress. (Same philosophy as the existing verified-reads posture:
  honest error over degraded answer.)
- **Bootstrap via popular peers.** A strict quarantine would mean no private
  queries for days after first install. The escape is the *popularity* property:
  peers on the public EIP-1459 DNS ENR tree (mainnet pins
  `all.mainnet.ethdisco.net`) and the hardcoded bootnode-adjacent set are known
  to every client in existence — dialing them over Tor reveals nothing about how
  *you* found them, so they are Tor-usable on day one with **zero aging**. The
  personally-discovered, quality-validated pool matures in quarantine and
  gradually takes over.
- **Implementation is small.** The peer-cache line format already carries
  learned quality tokens; adding a last-clearnet-contact timestamp is one more
  column, and the Tor-side dial ranking filters on
  `now − lastClearnetContact > randomizedThreshold` before the existing
  `snapok` preference.

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

The Hello advertises `ethp2p/0.1.2` (`HelloMessage.java`), and even with a
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

## 8. Open questions for review

1. **Exit-pool health for port 30303/9000** — what fraction of exit bandwidth
   permits them in practice, and what does that do to circuit build success and
   latency? Needs measurement before committing.
2. **Delay distribution** — uniform over what range? Per-peer independent draws?
   Is there an analysis that pins how much delay is enough given peer contact
   rates observed from crawlers?
3. **Pool sizing** — how large must the quarantined pool be to absorb days of
   churn and still hold N healthy snap peers at query time?
4. **Should the CL side eventually be proxied too?** Content-benign, but it
   fingerprints wake/sleep timing at the real IP. A later phase could route it
   through the same machinery at low priority.
5. **Latency budget** — with per-address circuit reuse and the batched snap
   fetches (`BATCH_PATHSET_CHUNK`), is a Tor-routed balance read acceptable on
   the confirm-screen path, or does the Tor mode need its own serve-stale
   policy?
6. **Tx broadcast fan-out over Tor** — one circuit to a few aged peers, or
   several isolated circuits to disjoint peer subsets (stronger against a
   listening peer, more circuit builds)?
7. **Mobile cost** — a bundled Tor client (kmp-tor / Arti on Android) keeps a
   guard connection alive; interaction with idle-pause and battery needs design
   (probably: Tor client lifecycle == stack awake lifecycle).
8. **DoH-over-Tor for the ENR tree walk** — which resolver, and does that
   introduce its own linkage?

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
