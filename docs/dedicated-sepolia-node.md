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
- Static public IP (or stable DNS + `--nat extip`).
- Open ports: **30303 tcp+udp** (Geth devp2p/discv4), **9000 tcp+udp**
  (Nimbus libp2p/discv5). The Engine API (8551) and any RPC stay on loopback.

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

The patch: after the devp2p protocol handshake, if the remote Hello client-ID
contains `myotis` (or `ethp2p`, the pre-rename Java id), mark the connection
trusted. Trusted connections are exempt from `MaxPeers` and the inbound cap in
Geth's `postHandshakeChecks`, so a myotis wallet can **never** be turned away
with `DiscTooManyPeers` (0x04) by this node.

```bash
git clone --depth 1 --branch $(curl -s https://api.github.com/repos/ethereum/go-ethereum/releases/latest | grep -oP '"tag_name": "\K[^"]+') \
    https://github.com/ethereum/go-ethereum.git
cd go-ethereum
```

Apply this change in `p2p/server.go`, inside `setupConn()`, immediately after
the line that stores the protocol-handshake results
(`c.caps, c.name = phs.Caps, phs.Name` — around line 946 as of mid-2026):

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

(`strings` is already imported in `p2p/server.go`; if the surrounding code has
moved, the anchor is wherever `phs.Name` lands on the conn — the flag must be
set **before** `checkpointAddPeer`.)

Notes and accepted trade-offs:

- The name is self-declared: anyone can send "myotis" and bypass the cap.
  Acceptable on a testnet server. If abused, add a counter capping the number
  of name-bypassed connections at the same spot.
- Because the flag mutates on the conn (not the static trusted set), it
  applies to inbound and outbound alike — exactly what we want.
- Keep a normal `--maxpeers` so the node still serves the wider network and
  keeps itself well-synced; myotis peers ride on top of the cap.

Build and install:

```bash
make geth
sudo install -o root -g root -m 0755 build/bin/geth /usr/local/bin/geth-myotis
```

Rebasing later: the patch is 8 lines against a stable tag; re-apply per
release (keep it as a commit on a `myotis-serving` branch and
`git rebase <new-tag>`).

## 4. Run Geth

Persist the node key first so the **enode URL never changes** (it will later
be pinned in myotis's `NetworkConfig`):

```bash
sudo -u geth bash -c 'geth-myotis --sepolia --datadir /data/geth account list >/dev/null 2>&1; true'
# The nodekey is auto-generated at /data/geth/geth/nodekey on first start and
# reused as long as the datadir persists. Back it up:
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
  --nat extip:<PUBLIC_IP> \
  --port 30303 \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port 8551 \
  --authrpc.jwtsecret /data/jwt.hex \
  --http --http.addr 127.0.0.1 --http.api eth,net,admin
Restart=on-failure
RestartSec=5
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
`admin.nodeInfo`); myotis never uses RPC. Record the stable enode:

```bash
geth-myotis attach --datadir /data/geth --exec admin.nodeInfo.enode
```

If the reported IP is wrong, fix `--nat extip:` — the enode must carry the
public IP.

## 5. Run Nimbus

Install a recent `nimbus_beacon_node` (distro package, released binary, or
`make nimbus_beacon_node`). One-time checkpoint sync (pick any maintained
Sepolia checkpoint provider — the same set `./gradlew refreshSepoliaCheckpoint`
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
  --nat=extip:<PUBLIC_IP> \
  --light-client-data-serve=true \
  --light-client-data-import-mode=full
Restart=on-failure
RestartSec=5

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
  `./gradlew refreshSepoliaCheckpoint`), which is typically days-to-weeks old
  (a sync-committee period is ~27 h) — with `only-new` the node could not
  serve bootstraps older than its own start.
- Belt-and-braces: after the node is up, run `./gradlew
  refreshSepoliaCheckpoint` in the myotis repo so the shipped pin is newer
  than the node's earliest light-client data. If wallets must bootstrap from
  pins older than the trustedNodeSync point, re-run trustedNodeSync without
  `--backfill=false`.
- The libp2p **network key persists** in the data dir, so the peer-id — and
  therefore the multiaddr — is stable across restarts. Back up
  `/data/nimbus/` early. Record the multiaddr from the startup log line
  ("Starting discovery" / "Local node identity"):
  `/ip4/<PUBLIC_IP>/tcp/9000/p2p/<peerId>`.

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
   `-Pargs=peers` must show the node READY with snap. On the server,
   `geth-myotis attach --exec admin.peers` shows the wallet with
   `"trusted": true`.

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

4. **CL serving.** Seed the wallet with the node's multiaddr (dev-only local
   peer seeding — see README §"Local beacon node"), and confirm the peer ends
   up serving `light_client_bootstrap` / `light_client_updates_by_range`
   (it should join `provenBootstrapPeers` and rank Tier 1 in the
   `BeaconLightClient` peer-tier logs).

## 7. Follow-ups (deliberately not done yet)

- **Pin the node in myotis** once it is stable: add the enode to
  `NetworkConfig.SEPOLIA.elBootEnodes()` (Java) and `ElConfig::sepolia()`
  (`rust/myotis-net/src/el/reader.rs`), and prepend the CL multiaddr via
  `prependLocal(...)` in `clPeerMultiaddrs` — every wallet then direct-dials
  the dedicated pair at startup, no discovery needed.
- **Drop the `ethp2p` match** from the Geth patch once all deployed wallets
  send the renamed `myotis/…` Hello client id.
- Optional: a second EL (Nethermind, halfpath/FlatDb layout) for
  serving-diversity; not needed for capacity.
