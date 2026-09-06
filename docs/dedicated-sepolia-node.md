# Dedicated Sepolia EL+CL node for myotis clients

A runbook for standing up a Sepolia execution-layer + consensus-layer pair on a
Linux box whose serving capacity is **never exhausted for myotis wallets**.
Myotis clients are admitted by the client-ID string in their RLPx Hello and
bypass the EL's peer cap; everyone else is subject to normal limits, so the
node remains an ordinary public Sepolia citizen.

Everything here was researched in Aug 2026; re-verify client versions/flags
before a fresh deployment much later.

## 1. Why these clients

### EL: patched Geth (Erigon is not an option)

Myotis syncs state over **snap/1** (`GetAccountRange` / `GetStorageRanges` /
`GetTrieNodes`, all proof-carrying) as a regular devp2p peer — not JSON-RPC.
That dictates the EL choice:

| Client | Serves snap/1? | Notes |
|---|---|---|
| **Geth** | **Yes, always on** | Reference server; cannot be disabled |
| Nethermind | Yes (halfpath/FlatDb layouts) | `Sync.SnapServingEnabled`, auto-on with the modern layout — credible fallback |
| Besu | Opt-in | `--snapsync-server-enabled` (GA since 25.7.0, off by default) |
| **Erigon 2/3** | **No** | Does not implement the snap capability at all; p2p speaks only eth/6x (state ships via BitTorrent snapshots) |
| Reth | No snap/1 | Only an experimental default-off **snap/2** server (EIP-8189 — drops GetTrieNodes, so useless for myotis healing) |

So despite Erigon's small footprint reputation, an Erigon node could serve
myotis headers but never state. **Geth is the only zero-config, battle-tested
snap/1 server.** (Footprint barely differs on Sepolia anyway — the testnet was
spam-heavy; Erigon measures its Sepolia archive at ~1.1 TB, and a Geth
full/snap node is estimated 500–900 GB. Provision 2 TB either way.)

Serving characteristics that matter (from `eth/protocols/snap/handler.go`):
2 MiB soft response cap, 1024-lookup / 5 s budget on `GetTrieNodes`, and
requests on one connection are handled **sequentially per peer**. Myotis
pipelines many single-account/single-slot requests with request IDs on one
socket and caps range responses at 4 KiB, so per-connection serialization is
harmless — **one EL node is sufficient**; more connections, not more nodes, is
the scaling axis.

### CL: Nimbus

Myotis's light client needs libp2p **req/resp** serving (not the REST API) of
`light_client_bootstrap`, `light_client_updates_by_range`, and
finality/optimistic updates (see `BeaconP2PService`). Status:

- **Nimbus** — serves all of it **default-on** (`--light-client-data-serve`),
  lightest footprint of the major CLs. **Chosen.**
- Lighthouse ≥ v7.0.0 — also default-on; solid backup.
- Lodestar — default-on; heavier (Node.js).
- Prysm — behind `--enable-light-client`, off by default.
- Teku — cannot serve light-client data over p2p at all.

## 2. Host requirements

- 4+ cores, 32 GB RAM (16 GB floor), **2 TB NVMe** (random-read performance
  matters for `GetTrieNodes`; page cache does the rest).
- A public IP. It does **not** have to be static: both clients below are
  configured to detect it themselves (§4, §5), so a residential/dynamic
  address self-corrects. What a rotation does break is any **pinned** entry in
  `NetworkConfig` (§7) — those carry a literal IP, so wallets fall back to
  discovery until refreshed. Degraded, not broken.
- Open ports: **30303 tcp+udp** (Geth devp2p/discv4), **9000 tcp+udp**
  (Nimbus libp2p/discv5). The Engine API (8551) and any RPC stay on loopback.
  The port numbers are free choices — they just become part of the enode /
  multiaddr pinned in §7. The zbox deployment uses **30405** and **9104**
  because 30303/9000 were already forwarded to other nodes on that LAN; adjust
  the ufw rules, the `--port`/`--tcp-port` flags, and the router forwards
  together. Behind NAT the router forwards matter as much as ufw, and both
  protocols are load-bearing: TCP for RLPx/libp2p, UDP for discv4/discv5.

```bash
sudo ufw allow 30303/tcp && sudo ufw allow 30303/udp
sudo ufw allow 9000/tcp  && sudo ufw allow 9000/udp
```

Layout used below: `/data/geth`, `/data/nimbus`, shared `/data/jwt.hex`,
service users `geth` and `nimbus`.

```bash
sudo useradd --system --home /data/geth   --shell /usr/sbin/nologin geth
sudo useradd --system --home /data/nimbus --shell /usr/sbin/nologin nimbus
sudo mkdir -p /data/geth /data/nimbus
openssl rand -hex 32 | sudo tee /data/jwt.hex >/dev/null
sudo chown geth:nimbus /data/jwt.hex && sudo chmod 640 /data/jwt.hex
sudo chown -R geth:geth /data/geth && sudo chown -R nimbus:nimbus /data/nimbus
```

## 3. Build the patched Geth ("myotis never busy")

The idea: once the remote's Hello client-ID is known, connections whose name
contains `myotis` (or `ethp2p`, the pre-rename Java id) are marked trusted.
Trusted connections are exempt from `MaxPeers` and the inbound cap, so a
myotis wallet is never turned away with `DiscTooManyPeers` (0x04).

The catch (and why this is a 3-part patch, not one line): stock Geth enforces
the capacity checks at the **post-encryption-handshake checkpoint**, *before*
the protocol handshake — i.e. before the Hello client name exists. So the
capacity checks must be **deferred** to the add-peer checkpoint (which re-runs
them anyway, via `addPeerChecks`), where the name is known. Identity checks
(already-connected / self) stay at the early checkpoint. The transient
overshoot between the two checkpoints is bounded by `MaxPendingPeers`
(default 50).

```bash
git clone --depth 1 --branch $(curl -s https://api.github.com/repos/ethereum/go-ethereum/releases/latest | grep -oP '"tag_name": "\K[^"]+') \
    https://github.com/ethereum/go-ethereum.git
cd go-ethereum
```

All three edits are in `p2p/server.go` (line numbers as of mid-2026; the
anchors are stable function/case names):

**(a)** Add `"strings"` to the import block (it is *not* already imported).

**(b)** In `run()`, the `case c := <-srv.checkpointPostHandshake:` handler
calls `srv.postHandshakeChecks(peers, inboundCount, c)`. Replace that call so
only identity is checked at this stage:

```go
	case c := <-srv.checkpointPostHandshake:
		// A connection has passed the encryption handshake so
		// the remote identity is known (but hasn't been verified yet).
		if trusted[c.node.ID()] {
			// Ensure that the trusted flag is set before checking against MaxPeers.
			c.flags |= trustedConn
		}
		// myotis patch: capacity (MaxPeers / inbound) is NOT checked here —
		// the Hello client name isn't known yet. addPeerChecks re-runs the
		// full postHandshakeChecks at checkpointAddPeer, after the myotis
		// name-bypass below has had a chance to set trustedConn. Transient
		// overshoot between the checkpoints is bounded by MaxPendingPeers.
		c.cont <- srv.postIdentityChecks(peers, c)
```

and add the helper next to `postHandshakeChecks`:

```go
// postIdentityChecks is the identity-only subset of postHandshakeChecks,
// used at the post-encryption checkpoint where the Hello name is unknown.
func (srv *Server) postIdentityChecks(peers map[enode.ID]*Peer, c *conn) error {
	switch {
	case peers[c.node.ID()] != nil:
		return DiscAlreadyConnected
	case c.node.ID() == srv.localnode.ID():
		return DiscSelf
	default:
		return nil
	}
}
```

**(c)** In `setupConn()`, immediately after the protocol-handshake results are
stored (`c.caps, c.name = phs.Caps, phs.Name`) and **before**
`checkpointAddPeer`:

```go
	c.caps, c.name = phs.Caps, phs.Name

	// myotis patch: wallets bypass the peer cap like trusted peers.
	// "ethp2p" is the pre-rename Java-engine client id; drop it once all
	// deployed wallets send "myotis".
	if !c.is(trustedConn) {
		lname := strings.ToLower(c.name)
		if strings.Contains(lname, "myotis") || strings.Contains(lname, "ethp2p") {
			c.flags |= trustedConn
		}
	}
```

Net effect: stock peers now get their `DiscTooManyPeers` after the Hello
exchange instead of before it (same disconnect code — myotis's busy
classifier reads it at that phase anyway), myotis peers pass the cap, and
nothing else moves.

Notes and accepted trade-offs:

- The name is self-declared: anyone can send "myotis" and bypass the cap.
  Acceptable on a testnet server. If abused, add a counter capping the number
  of name-bypassed connections in edit (c).
- Because the flag mutates on the conn (not the static trusted set), it
  applies to inbound and outbound alike — exactly what we want.
- Keep a normal `--maxpeers` so the node still serves the wider network and
  keeps itself well-synced; myotis peers ride on top of the cap.
- Residual limit: Geth's pre-handshake per-IP inbound throttle
  (`checkInboundConn`, one attempt per ~30 s per IP, trust-exempt only for
  the static trusted set) still applies. A wallet reconnect-looping from one
  IP can hit it; a normally behaving wallet won't.

Build and install:

```bash
make geth
sudo install -o root -g root -m 0755 build/bin/geth /usr/local/bin/geth-myotis
```

Rebasing later: the patch is 8 lines against a stable tag; re-apply per
release (keep it as a commit on a `myotis-serving` branch and
`git rebase <new-tag>`).

## 4. Run Geth

The node key is auto-generated at `/data/geth/geth/nodekey` on first start
and reused for as long as the datadir persists, so the **enode URL is stable**
(it will later be pinned in myotis's `NetworkConfig`). After the first start
(below), back it up:

```bash
sudo cp -a /data/geth/geth/nodekey /data/geth/nodekey.backup
```

`/etc/systemd/system/geth-sepolia.service`:

```ini
[Unit]
Description=Geth Sepolia (myotis serving node)
After=network-online.target
Wants=network-online.target

[Service]
User=geth
ExecStart=/usr/local/bin/geth-myotis \
  --sepolia \
  --datadir /data/geth \
  --syncmode snap \
  --maxpeers 200 \
  --nat stun \
  --port 30303 \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port 8551 \
  --authrpc.jwtsecret /data/jwt.hex \
  --http --http.addr 127.0.0.1 --http.port 8560 --http.api eth,net,admin \
  --history.chain all
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=0
LimitNOFILE=65536
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now geth-sepolia
```

The loopback HTTP endpoint is for operations only (`admin.peers`,
`admin.nodeInfo`); myotis never uses RPC. It is on **8560**, not Geth's default
8545, deliberately: 8545 is what every EVM dev tool assumes (anvil, hardhat,
metamask-localhost), and a real synced client answering there masks a missing
local dev node. Any free port works — keep it consistent with the §6 checks.

`--history.chain all` pins the default (keep every pre-merge body and receipt).
It is explicit because Geth 1.16+ can expire history (`--history.chain
postmerge`), and myotis's trust anchors include the embedded pre-Merge
accumulator — a future default flip must not silently drop what it needs.
`StartLimitIntervalSec=0` removes systemd's give-up-after-5-restarts rule, so a
crash-looping node keeps retrying instead of staying down. Record the stable enode:

```bash
geth-myotis attach --datadir /data/geth --exec admin.nodeInfo.enode
```

**On `--nat stun` rather than `extip:<PUBLIC_IP>`.** Geth learns its external
address from a STUN server and re-checks it, so a dynamic/residential IP
self-corrects and the enode + ENR follow. `extip:` hardcodes an assertion:
after a rotation the node keeps confidently advertising an address that is no
longer its own, which is worse than being undiscoverable. STUN is the right
mechanism here specifically because the port forwards are manual — `any` (the
UPnP/NAT-PMP autodetect) can come up empty on a router with UPnP disabled.
Verify what it settled on (the enode must carry the PUBLIC IP, and it is the
line myotis pins in §7):

**Relay exception (2026-09-06).** Behind the netcup relay (§7, "Remaining")
zbox runs `--nat extip:188.68.32.16`: the address to advertise is the relay's,
which STUN would never observe (zbox's own uplink is mobile CGNAT), and the
relay is a static VPS, so the assertion cannot go stale the way a residential
IP does.

```bash
geth-myotis attach --datadir /data/geth --exec admin.nodeInfo.enode
```

## 5. Run Nimbus

Install a recent `nimbus_beacon_node` (distro package, released binary, or
`make nimbus_beacon_node`). One-time checkpoint sync (pick any maintained
Sepolia checkpoint provider — the same set `./gradlew refreshCheckpoint -Pnetwork=sepolia`
cross-validates, e.g. `https://sepolia.beaconstate.info`):

```bash
sudo -u nimbus nimbus_beacon_node trustedNodeSync \
  --network=sepolia \
  --data-dir=/data/nimbus \
  --trusted-node-url=https://sepolia.beaconstate.info \
  --backfill=false
```

`/etc/systemd/system/nimbus-sepolia.service`:

```ini
[Unit]
Description=Nimbus Sepolia (myotis light-client serving)
After=network-online.target geth-sepolia.service
Wants=network-online.target

[Service]
User=nimbus
ExecStart=/usr/bin/nimbus_beacon_node \
  --network=sepolia \
  --data-dir=/data/nimbus \
  --el=http://127.0.0.1:8551 \
  --jwt-secret=/data/jwt.hex \
  --tcp-port=9000 --udp-port=9000 \
  --nat=any \
  --enr-auto-update=true \
  --netkey-file=/data/nimbus/netkey \
  --insecure-netkey-password=true \
  --max-peers=500 \
  --hard-max-peers=800 \
  --rest \
  --light-client-data-serve=true \
  --light-client-data-import-mode=full
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nimbus-sepolia
```

Notes:

- Light-client serving is **default-on** in Nimbus; the flags are explicit for
  the record. `--light-client-data-import-mode=full` (rather than the default
  `only-new`) also imports light-client data for slots the node already has,
  and the default retention covers all available periods. This matters
  because a wallet's first request is `light_client_bootstrap` for its
  **pinned checkpoint** (`NetworkConfig.SEPOLIA`, refreshed via
  `./gradlew refreshCheckpoint -Pnetwork=sepolia`), which is typically days-to-weeks old
  (a sync-committee period is ~27 h) — with `only-new` the node could not
  serve bootstraps older than its own start.
- Hard limit either way: Nimbus can only produce light-client data for slots
  it processed with state — i.e. from its trustedNodeSync point forward
  (block backfill doesn't help; bootstraps need the sync committee from
  state). So after the node is up, run `./gradlew refreshCheckpoint -Pnetwork=sepolia`
  in the myotis repo so the shipped pin is **newer than the node's sync
  point** — that is the mitigation that actually works.
- **`--netkey-file` is REQUIRED for a stable peer-id.** It defaults to
  `random`, i.e. Nimbus mints a **new** network key — and therefore a new
  peer-id and multiaddr — on *every start*, silently invalidating any pinned
  multiaddr (verified the hard way: a restart changed the peer-id and myotis
  then failed every dial with `InvalidRemotePubKey`). The flags above pin it to
  `/data/nimbus/netkey` (`--insecure-netkey-password=true` keeps startup
  unattended). Back up `/data/nimbus/` early. Record the multiaddr from the
  startup log line ("Starting discovery" / "Local node identity"):
  `/ip4/<PUBLIC_IP>/tcp/<port>/p2p/<peerId>`.
- **`--nat=any --enr-auto-update=true` rather than `extip:<PUBLIC_IP>`.**
  Nimbus has no STUN option (only `any`, `none`, `upnp`, `pmp`, `extip:`), so
  the self-correction comes from `--enr-auto-update`, which rewrites the ENR
  with the address peers actually observe. Same reasoning as Geth's `stun`:
  `extip:` is an assertion that goes stale on an IP rotation, and a node
  advertising an address that is not its own is worse than one that is simply
  hard to find. Watch out for one failure mode `any` can hit on a router with
  UPnP disabled: Nimbus may initially publish its **LAN** address and only
  correct itself once peers report otherwise. Check the startup line and
  confirm the public IP:

  **Relay exception (2026-09-06):** behind the netcup relay the unit runs
  `--nat=extip:188.68.32.16` (with `--enr-auto-update=true` kept), for the
  same reason as Geth's `extip` above — the relay's address is static and is
  not what any peer-observation of zbox's own uplink would report.

  ```bash
  journalctl -u nimbus-sepolia --since '2 min ago' | grep 'Discovery ENR initialized'
  # ... enrAutoUpdate=true seqNum=1 ip=ok(<PUBLIC_IP>) tcpPort=ok(<port>) ...
  ```

  If it stays stuck on a `192.168.*` address, fall back to `extip:` for Nimbus
  only and treat its IP as manual maintenance.
- **Raise the peer limits on a serving node.** Nimbus's default
  `--max-peers=160` fills up with ordinary network peers and then stops
  accepting: new inbound connections pile up unaccepted in the kernel backlog
  (observed: 800 queued, 600 CLOSE-WAIT), so a wallet's TCP connect succeeds
  but the libp2p handshake never happens and it times out. There is no
  CL-side equivalent of the EL's name-based cap bypass, so headroom
  (`--max-peers=500 --hard-max-peers=800`) is the only lever.

## 6. Verify end-to-end with myotis

Wait until Geth is snap-synced (`eth.syncing == false`) and Nimbus is at the
head.

1. **EL admission.** From a myotis checkout:

   ```bash
   ./gradlew :app:run -Pnetwork=sepolia
   ```

   then in a second shell:

   ```bash
   ./gradlew :app:run -Pnetwork=sepolia -Pargs="dial enode://<pubkey>@<PUBLIC_IP>:30303"
   ```

   (Java engine only — `RustChainHandle.dialPeer` is not implemented.)
   `-Pargs=peers` must show the node READY with snap. On the server the wallet
   appears with `"trusted": true` — the cap bypass working. Without a TTY for
   `attach`, the loopback RPC answers the same question:

   ```bash
   curl -s -X POST -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}' \
     http://127.0.0.1:8560 | \
     python3 -c 'import json,sys; [print(p["name"], p["network"]["trusted"]) \
       for p in json.load(sys.stdin)["result"] if "myotis" in p["name"].lower()]'
   ```

   Geth's debug log names the reason for any rejection, which is worth having
   ready — it is how the eth/69 wire-code bug was found. A throwaway instance
   costs nothing and needs no sudo:

   ```bash
   geth-myotis --sepolia --datadir /tmp/gethdbg --port 30999 --nodiscover \
     --verbosity 5 --authrpc.port 8552 2>&1 | grep -iE 'myotis|message handling'
   # DEBUG Adding p2p peer  conn=trusted-inbound name=myotis/0.1.2
   ```

2. **Cap-bypass proof.** Temporarily restart Geth with `--maxpeers 1`, wait
   for the slot to fill, then dial from myotis: the wallet must still be
   admitted, while a stock Geth dialing in is refused normally. Restore
   `--maxpeers 200` afterwards.

3. **Snap serving.** With the wallet's beacon state SYNCED
   (`-Pargs=beacon-status`), the standard integration checks must return
   `"verifyMethod":"headerChain"`:

   ```bash
   ./gradlew :app:run -Pnetwork=sepolia -Pargs="get-account 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
   ```

4. **CL serving.** The multiaddr now ships pinned (§7), so a stock build
   already dials it — confirm the peer serves `light_client_bootstrap` /
   `light_client_updates_by_range`. Measured on this pair: connection
   established in ~235 ms, bootstrap (25,673 bytes) delivered ~272 ms later,
   Nimbus identified as `agent=nimbus` with 4 light-client protocols. For a
   node whose multiaddr is NOT yet pinned there is no runtime mechanism to
   seed one — edit `clPeerMultiaddrs` via the `prependLocal(...)` helper and
   rebuild.

   If every dial fails with `InvalidRemotePubKey`, the peer-id in the pin no
   longer matches the node: Nimbus was restarted without `--netkey-file` at
   some point and minted a fresh key (§5). Re-read the peer-id from its
   startup log and update the constant.

## 7. Pinned identities (DONE) and remaining follow-ups

The pair is pinned in `NetworkConfig.SEPOLIA` on both layers and in both
engines: `elBootEnodes()` returns the enode (Java) / `ElConfig::sepolia()`
seeds `boot_enodes` into the peer cache for the pool's warm-start dial (Rust),
and the CL multiaddr is `prependLocal`-ed onto `clPeerMultiaddrs` so the light
client tries it first.

| layer | identity |
|---|---|
| EL | `enode://cfd3572b…c37e1b2c@188.68.32.16:30405` |
| CL (roost, first) | `/ip4/188.68.32.16/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5` |
| CL (Nimbus, fallback) | `/ip4/188.68.32.16/tcp/9104/p2p/16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6` |

Both are only stable because of the key-persistence flags above (Geth's
datadir `nodekey`, Nimbus's `--netkey-file`). The **address** in every entry is
the netcup relay (188.68.32.16, a static VPS), not zbox: since 2026-09-06 zbox
sits behind mobile CGNAT and is reachable only through a WireGuard tunnel to the
relay, which DNATs the nine serving ports (30405-30407, 9104-9109, tcp+udp) to
zbox without rewriting peer source addresses. On zbox, uid-based ip rules route
the geth/nimbus/roost processes through the tunnel and the clients announce the
relay as their own address (`--nat extip:188.68.32.16`, `--nat=extip:…`, roost
via the upstream's ENR), so every discovery layer agrees on one public address
and zbox's own uplink rotating no longer touches the pins.

Remaining:

- ~~Use a DNS name in the pins~~ — superseded by the relay (above): the VPS
  address is static, so the pins carry that literal and the DynDNS name is gone.
- **Drop the `ethp2p` match** from the Geth patch once all deployed wallets
  send the renamed `myotis/…` Hello client id.
- **No CL equivalent of the EL cap bypass exists.** The Geth patch admits
  wallets by RLPx Hello client-id; Nimbus has no such hook, and myotis does
  not even set a libp2p agent string today (`BeaconP2PService.start()` builds
  the host without one), so there is nothing to match on. `--max-peers=500` is
  headroom, not a reservation: once those fill, wallets are shut out exactly
  as at the default 160. A real bypass would need an agent string on both
  myotis CL paths plus a Nimbus patch deferring its accept decision past
  Identify. Cheaper alternative worth testing first: `--discv5=false` on the
  serving node — wallets reach it by the pinned multiaddr anyway, and without
  a discv5 record the random-peer inflow that consumes the slots largely dries
  up (cost: the node then needs `--direct-peer` entries to follow the chain).
- Optional: a second EL (Nethermind, halfpath/FlatDb layout) for
  serving-diversity; not needed for capacity.
