# Onion services on wallets: wallets serving each other without an IP

Status: **analysis — nothing here is built.** It asks whether myotis wallets
(phones in particular) could serve each other data by each running a Tor onion
service, what that would and would not solve, and what identity it needs. It
answers one question for good on the way: **myotis's Ethereum-facing peer ids
cannot be ed25519, but the identity of a myotis-to-myotis overlay can — and
then a peer id *is* an onion address.** Related:
[`inbound-connections.md`](inbound-connections.md) (accepting connections from
full nodes; mobile kept outbound-only), [`privacy-and-tor.md`](privacy-and-tor.md)
(the Tor client in the Rust engine), [`lc-server-design.md`](lc-server-design.md)
(roost) and [`snap-server-design.md`](snap-server-design.md) (why snap is
different). The open decisions at the end are the owner's.

## TL;DR

- **Reachability for other myotis wallets: solved.** An onion service makes
  only outbound connections, so a phone behind CGNAT is reachable by any Tor
  client holding its address, and it reveals no IP. That holds for
  myotis-to-myotis traffic only: full nodes find peers by IP endpoint and
  never dial an onion, so `inbound-connections.md`'s own goal (inbound RLPx
  from snap-capable full nodes) and its §5 conflict are unaffected.
- **Availability: not solved.** A phone is reachable only while Tor runs and
  the stack is awake. On Android that is in practice the existing
  charging-on-unmetered window; on iOS, the foreground.
- **What wallets can share is light-client and recent-block data, not
  snap.** Light-client bootstraps and updates and recent headers are
  self-verifying and valid for every wallet; recent bodies and receipts would
  be too, but wallets don't keep them today. Snap proofs are not available: a
  wallet holds no state. So this would make light-client data more available;
  it does not touch the scarce resource, a full node with a free snap slot.
- **Identity: the overlay can be ed25519, and should be separate.** devp2p and
  the consensus p2p spec both require secp256k1, and the code enforces it. A
  myotis-only overlay is bound by neither. With an ed25519 identity, a libp2p
  peer id converts to an onion address and back offline — verified below.
- **Finding peers stays open.** v3 onion addresses cannot be enumerated, and
  discv5 is UDP, which Tor does not carry. Something has to tell wallets which
  onions exist.

## What an onion service solves

| Problem | Today | With an onion service per wallet |
|---|---|---|
| Phone behind CGNAT | unreachable: `inbound-connections.md` §2 has mobile "IPv4: hard no" and IPv6 only "sometimes, unreliably" | reachable **by other myotis wallets over Tor**: the phone keeps outbound circuits to its introduction points; clients meet it at a rendezvous point. Full nodes still cannot reach it |
| Being reachable reveals the IP | yes — a listener plus an advertised address (`inbound-connections.md` §5, "reachability and Tor routing are mutually exclusive modes") | not for overlay traffic: nobody learns the phone's IP. §5's conflict stands for inbound from full nodes |
| Authenticating the peer | a separate handshake (RLPx, Noise) over an address that proves nothing | the onion address *is* the service's public key: reaching it proves the other side holds the key |
| Tor exits refusing or dropping traffic (`privacy-and-tor.md` §2, §8.9) | the dominant Tor-mode failure | no exit is involved |

`inbound-connections.md` recommends that Android never bind a listener, for
three reasons: CGNAT, battery and Doze. An onion service binds no public
socket, so for the overlay the first reason goes away — not for that
document's goal, which is inbound from full nodes. The other two reasons hold
either way — see the next section.

## What it does not solve

### Phones are asleep

The Android host idle-pauses each stack five minutes after the last wallet
request once synced, and stays awake only while charging on an unmetered
network ("stay awake while charging", on by default;
`disk-and-network-usage.md` §3.3). iOS suspends backgrounded apps. An onion
service exists only while Tor runs, so a phone's service is up roughly when
the phone is on the charger at home — which is also the only window in which
serving costs the user neither battery nor mobile data. That window is the
natural, and probably the only acceptable, serving policy.

Keeping a service published is not free even when idle. Per the v3 spec
(`rend-spec`, *deriving keys*), a service uploads its descriptor to
`hsdir_n_replicas × hsdir_spread_store` = 2 × 4 = 8 HSDirs for each of the
current and the upcoming time period — 16 uploads — re-uploads at a random
60–120 minutes, and keeps
circuits open to its introduction points (C tor's default is three). Every
switch between Wi-Fi and mobile data rebuilds them. The cost per hour on a
phone has to be measured before anything here is relied on.

### What a wallet can serve is not what is scarce

| Data | Self-verifying | Same for every wallet | Held by a wallet today | What serving it reveals |
|---|---|---|---|---|
| LC bootstrap at the release's embedded checkpoint | yes — checkpoint pin + Merkle branches | yes, per release | **fresh installs only**, verified once and not kept as bytes; a wallet resuming a newer snapshot skips it | the release it runs |
| LC updates by period | yes — sync-committee signatures, chained | valid for all, not byte-identical: each node keeps its own best update per period | **not kept**: the snapshot holds the derived store (`StoreSnapshot`, `myotis-consensus/src/snapshot.rs`), not the signed updates | nothing |
| Finality / optimistic update | yes | valid for all, per slot; signature participation may differ | verified in passing, not kept | that it is online now |
| Recent headers | yes — hash chain to the beacon-anchored block | yes | yes, the served window (`el/served.rs`, 32 blocks) | nothing |
| Recent bodies and receipts | yes — against the header's roots | yes | **not kept**: the fee cache holds derived tips and gas (`el/feecache.rs`), not the blocks | nothing |
| Bytecode | yes — `keccak(code) == codeHash` | yes | in the EVM's bytecode cache | **which contracts the owner uses** |
| Log-index chunks | yes — against headers (`logindex-verified-bundle-design.md`) | per watched contract | the index | **which contracts the owner watches** |
| Snap proofs | yes — against the state root | per key | only the ones it fetched, valid for one block | **the owner's addresses** |

Three conclusions:

- **The shareable set is the light-client and recent-block data.** The
  light-client half is what roost serves (through `LcResponder`); the
  recent-block half is what every EL full node serves over `eth` — roost
  speaks no devp2p. Wallets serving either to each other is a resilience gain
  (a swarm of small roosts when roost and the public CL servers are scarce),
  not new capability.
- **Snap stays a full-node problem.** A wallet relaying proofs it fetched
  serves a perishable object (one block — measured in
  [`snap-server-design.md`](snap-server-design.md#measured-what-a-proof-weighs-and-how-long-it-lives))
  and publishes its owner's portfolio while doing it. Out.
- **Bytecode and log-index data are verifiable but personal.** Serving them
  leaks what the owner uses; leave them out unless a wallet serves only
  what it has been *asked* for by others, which is a cache policy, not a
  default.

The serving half exists: `LcResponder` (`rust/myotis-net/src/reqresp.rs`) is
the hook roost feeds, and a wallet passes `None`. What a wallet would have to
keep depends on whom it serves:

- **Already-synced wallets** need only the latest finality and optimistic
  updates and the current period's update — a few tens of KB.
- **Cold starts and catch-up** — where LC servers have actually been scarce
  (#422 was a catch-up failure) — need much more. A fresh install verifies
  every period from its pin's period up to now, in order, each against the
  committee the previous one handed over; a peer holding only the current
  period has nothing it can apply. And "the bootstrap at its pin" is held only
  by fresh installs: a wallet resuming from a persisted snapshot newer than
  its release's checkpoint skips the bootstrap entirely (`sync.rs`, "resumed
  from persisted snapshot — skipping bootstrap"), so a wallet upgraded in
  place never downloads its current release's pinned bootstrap.

  So for the overlay to help where it matters, each serving wallet would also
  fetch and verify its release's pinned bootstrap after an upgrade (~26 KB,
  checkable against the pinned root) and keep every period's update from the
  pin's period on (~27 KB per period — about 0.7 MB for a month of mainnet
  periods). Still cheap, but it is a retention policy, not a few tens of KB;
  without it the swarm only helps wallets that are already synced.

Serving recent blocks needs the same kind of new retention for bodies and
receipts.

### Finding each other

v3 onion addresses cannot be enumerated: the HSDir ring stores descriptors
under per-period blinded keys, so nobody can list the onions that exist. That
is good for privacy and means discovery must be built:

- **discv5 cannot carry it.** An ENR could hold an onion address in a custom
  key, but discv5 runs over UDP, which Tor does not carry; publishing a record
  means joining the DHT from the clearnet, which ties the onion to the IP that
  published it.
- **Seeds plus peer exchange.** A few myotis-operated onions as seeds, and
  wallets exchanging the onions they know over the overlay itself. Cheap, and
  no IP is ever involved. But a seed is useful only if it hands out other
  wallets' onions, so it answers peer exchange — and at bootstrap it is the
  one peer a new wallet knows, so it receives wallets' onions as they come
  online (a presence timeline) and serves a list no wallet can verify (a
  sybil-filled one steers discovery). Those are the directory's two
  objections below, softened only in degree because wallets also gossip among
  themselves. With roost as the seed it is likewise outside roost's carve-out
  and needs the same owner decision; a separate myotis-operated seed avoids
  the carve-out question but sees the same things.
- **A directory at roost.** Wallets register their onion with roost, over
  Tor. Roost then knows which overlay identities are online and when — no
  IPs, but one operator holding the presence timeline of every participating
  wallet. Same concentration trade as the snap server's
  ([`snap-server-design.md`](snap-server-design.md#the-proofs-privacy)), on milder data —
  and a new job for roost outside its carve-out: CLAUDE.md lets roost
  relay *self-verifying* consensus objects, and a directory of onion addresses
  is not self-verifying (a sybil-filled one steers discovery). It would need
  its own owner decision.
- **A DHT over Tor.** Possible; every lookup step costs a rendezvous of
  seconds. Not worth it at the scale a wallet overlay would have.

## Identity: can myotis peer ids be ed25519?

### The ones Ethereum sees: no

- **devp2p (EL).** The identity is secp256k1 by protocol: the RLPx handshake
  is ECIES over secp256k1 with signature recovery, the enode id is the
  64-byte secp256k1 public key, and discv4 packets are secp256k1-signed. The
  only ENR identity scheme defined (EIP-778's `v4`) is secp256k1.
- **libp2p (CL).** The consensus p2p spec (`p2p-interface.md`) specifies
  Noise "with `secp256k1` identities" and an ENR whose `secp256k1` field is
  the node's compressed key; a wallet derives a server's peer id from that
  ENR key (`enr_to_peer_id`, `rust/myotis-net/src/discovery.rs`). The code enforces it: the
  host key is secp256k1 because "the default ed25519 would make some peers
  reject the noise handshake payload" (`start_host_with`, `reqresp.rs`), and a
  non-secp256k1 host key is refused rather than published under a peer id no
  record matches (`discv5_key_from_libp2p`, `discovery.rs`, test
  `a_non_secp256k1_host_key_is_refused_rather_than_silently_wrong`).

An ed25519 key cannot be derived from those publicly either: a wallet could
derive an ed25519 *private* key from its secp256k1 one, but nobody else could
compute the matching onion address from its peer id, which is the property
worth having.

### A myotis-to-myotis overlay: yes

An overlay spoken only between myotis nodes is bound by neither spec, and
libp2p supports ed25519 natively. With an ed25519 overlay key `K`:

```
onion_address = base32(K | CHECKSUM | 0x03) + ".onion"
CHECKSUM      = SHA3-256(".onion checksum" | K | 0x03)[:2]

libp2p peer id = base58btc(0x00 0x24 | 0x08 0x01 0x12 0x20 | K)
                 # identity multihash of the protobuf PublicKey{Ed25519, K}
```

Both are pure functions of the same 32 bytes, so a peer id converts to an
onion address and back with no lookup — Tor's HSDir ring becomes the "where is
this peer" lookup. Verified on 2026-10-11 against a real service:
DuckDuckGo's `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`
checks out under the checksum formula, and its key as a libp2p ed25519 peer id
is `12D3KooWBme66b4BEomkxJ3jWM4v2vgwp3xVCYGBSusixfqAswtg`, which converts back
to the same address. (A secp256k1 peer id, `16Uiu2…`, also embeds its key, but
a secp256k1 key is not an onion key.)

### And it must be a separate identity

- **The Rust engine has no stable identity, on purpose.** Its libp2p key is
  generated at every start (`start_host_with`), so is its devp2p key
  (`ElReader::start_for` → `generate_node_key`), and Tor-mode reads use a
  fresh RLPx key per connection (`el/tor.rs`). (The Java engine does persist
  a devp2p node key per network — `nodekey.hex` /
  `nodekey-<net>.hex`, `JavaMyotisEngine.loadOrCreateKey`.) An overlay
  identity must not undo that: it must never appear on the clearnet, never be
  the key of the Ethereum-facing hosts, and never be linked to the user's
  addresses.
- **A stable onion is a stable pseudonym.** Anyone holding the address can
  check whether its descriptor is published, and so learn when the phone is
  online. Rotating the key (per release, per week) bounds that and costs
  every peer that knew the old address a rediscovery. *Restricted discovery*
  (Tor's client authorization) only narrows it: it encrypts the descriptor's
  second layer, but the descriptor is still uploaded under the same blinded
  key and its first layer is derived from the onion address alone
  (rend-spec-v3, descriptor encryption). An unlisted holder of the address
  still sees whether a descriptor is published and refreshed (every 60–120
  min while the service is up); what it loses is the introduction points, so
  it can no longer connect or probe liveness at fine grain. And it closes the
  overlay to strangers — the opposite of open sharing. Key rotation remains
  the only real bound on the presence timeline.
- **The overlay may not need libp2p's handshake at all.** Reaching an onion
  address already authenticates the service end and encrypts the stream;
  for public, self-verifying data the client needs no identity. Plain
  request/response over the Tor stream, with the onion address as the only
  identity, avoids using `K` for both Tor (which derives per-period blinded
  keys from it) and libp2p Noise signatures — a cross-protocol key reuse
  that is probably harmless and better not decided by default. But a plain
  stream protocol is neither devp2p nor libp2p, the only production data
  sources CLAUDE.md (*Data sources*) names; the trust argument holds either
  way, the rule question is the owner's (see *Open decisions*). libp2p over
  the onion stays inside the rule.
- **Supplying the key.** C tor accepts a caller-chosen key (`ADD_ONION
  ED25519-V3:…`). Whether Arti lets the host supply the service's identity key
  instead of generating it in its keystore is to be checked.

## The Tor side

The Rust engine embeds Arti as a client (`rust/myotis-net/Cargo.toml`:
`arti-client` 0.44 with `default-features = false`, `tokio` + TLS, behind
`-PtorEngine`). Even *reading* from the overlay needs a feature today's build
lacks: `onion-service-client` is not enabled (`rust/Cargo.lock` has no
`tor-hsclient`), so every reading wallet needs it, and its size belongs next
to the ~9.3 MB per ABI Arti already adds to the APK (`privacy-and-tor.md`
§3). Hosting needs `onion-service-service` as well, which is opt-in, and very
likely an
Arti upgrade first — with the Android and iOS build work that brings — since
what follows describes the current release, not the pinned one. Current Arti
docs (arti 2.7.0, tor-hsservice 0.47.0, October 2026) list onion-service hosting,
vanguards on by default, and restricted discovery as experimental;
`tor-hsservice` still calls itself "a low-level implementation … that may not
be suitable for typical users". Whether Arti services enforce the
proof-of-work introduction defence (C tor has had it since 0.4.8) is not
stated and must be checked: a phone-hosted service is a DoS target whose
bandwidth the user pays for.

Every serving node needs its own limits regardless. Some exist in the
`myotis-net` host roost reuses — connection caps, a per-connection
concurrent-stream cap for `updates_by_range`, a global in-flight byte ceiling,
response-size and update-range caps (`MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128`).
Two would be new code, unlike roost: a per-connection request-rate cap, and
an hourly upload budget — the one a phone user actually pays for.

## Trust

Unchanged, and the reason this is worth considering at all. Everything in the
shareable set verifies against the wallet's own anchor, so a malicious or
sybil overlay peer can withhold or send garbage and costs a retry, never a
wrong answer (CLAUDE.md, *Trust*). The overlay only adds sources; wallets keep
roost and the public CL and EL peers.

## Suggested path

1. **Desktop and daemon first.** Always on, no battery: upgrade Arti to a
   release whose hosting support is known, then host an onion service
   that serves the light-client set and recent headers, and measure the
   idle cost of staying published and the connect latency from a client.
2. **Keep the verbatim bytes.** Retain the signed LC objects a wallet already
   verifies — and, to serve cold starts, the pinned bootstrap and every period
   since the pin (see *What a wallet can serve*) — and feed them to
   `LcResponder`; useful even without Tor.
3. **Android, opt-in, in the charging-on-unmetered window**, with the idle
   cost from step 1 in hand.
4. **Discovery by seeds plus peer exchange**, once the owner has decided who
   runs the seed and what it may see (*Open decisions*).

## Open decisions

- **Build at all?** The gain is resilience for light-client data that roost
  already serves; the cost is a long-lived identity on every participating
  wallet.
- **Identity policy:** how often the overlay key rotates, and whether it is
  shared across networks.
- **Discovery:** seeds plus peer exchange, or a registration directory at
  roost. Both put an unverifiable list and wallets' online timelines with an
  operator; at roost either is outside its carve-out (relaying only
  self-verifying consensus objects), so who runs the seed and what it may see
  is the owner's call.
- **Wire protocol:** libp2p over the onion (inside CLAUDE.md's *Data sources*
  rule), or plain request/response over the Tor stream (simpler, avoids key
  reuse, but a third data protocol the rule does not name).
- **Serving policy:** off by default, or on in the charging-on-unmetered
  window; and whether Tor-mode wallets may read from the overlay.
- **Out of scope here, worth its own note:** relaying other wallets'
  transactions over the overlay, which would hide a sender's IP from the
  network the way Tor broadcast does, at the cost of trusting the relaying
  wallet with liveness.
