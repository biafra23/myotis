# Multichain Phase B — Android (`NodeService` registry + per-network UI)

Status: **plan.** The shared core (Phase A) is merged (PR #83), and the Phase B
*foundation* is on this branch (`feat/multichain-android`) and compiles:

- `android-app` depends on `:node-core`.
- `AndroidPeerCacheAdapter` / `AndroidClPeerCacheAdapter` wrap the existing Android
  caches as the node-core `PeerCachePort` / `ClPeerCachePort`.
- `ChainStack.rpcBackend()` getter added for the host.
- **The snap-peer maintainer is now in `ChainStack`** (opt-in via
  `configureSnapMaintainer(target, DnsServerProvider)`), de-Android-ified, and
  **verified running on the daemon**. Android will reuse this instead of its own copy.

What remains is the device-tested part: make `NodeService` host a
`Map<String,ChainStack>` and add the per-network UI. **This needs a connected device
to verify** (NAT handling, the Stop→Start race from PR #82, the foreground service),
which is why it's handed off to the Mac.

Decisions already taken (from the approved plan): default **mainnet ON / Gnosis
opt-in**; **full per-network UI**; maintainer **moved into `ChainStack`** (shared).
The daemon currently **enables** the maintainer (`Main.SNAP_PEER_TARGET = 32`); leave
on (helps Gnosis snap retention) or flip off — cosmetic.

---

## Step 8b — `NodeService` hosts `Map<String,ChainStack>`

Goal: replace the single inline stack with one `ChainStack` per *enabled* network,
built through the Android adapters. Keep mainnet-only as the default so the proven
path is what runs unless the user toggles a second chain.

### Per-network holder
`NodeService` currently keeps the stack as singleton fields
(`discV4/discV5/connector/rpcServer/rpcBackend/beaconLightClient/beaconSyncState/
clGenesisTime/peerCache/clPeerCache/peerMaintainer` ~lines 310–330) plus the dial
state (`attempted/backoff/blacklistedNodeIds`, `dnsElEnrs` ~288–305). All of that now
lives inside `ChainStack`. Replace it with:

```java
private final java.util.Map<String, ChainStack> stacks = new java.util.concurrent.ConcurrentHashMap<>();
// keep per-network the Android cache refs the maintainer/snapshot don't need, only if
// a screen still needs them; otherwise drop — ChainStack owns the caches via adapters.
```

Keep the process-global `ccipPool` (line 333) and `queryHistory` (342) as-is.

### Building a stack (port from `startNode()`/`startAndPublish()`, ~1070–1460)
For a network name `n`:

```java
NetworkConfig net = NetworkConfig.byName(n);
ChainPorts ports = ChainPorts.defaultsFor(net)                 // 30303/9000/8545, gnosis 30304/9001/8546
        .withRpcPort(rpcPortFor(this, n));                     // honor the per-network pref
Path keyFile = new File(getFilesDir(),
        n.equals("mainnet") ? "nodekey.hex" : "nodekey-" + n + ".hex").toPath();
NodeKey key = NodeKey.loadOrGenerate(keyFile);
AndroidPeerCache pc = new AndroidPeerCache(netCacheFor(n, "peers", ".cache").toPath());
AndroidCLPeerCache cl = new AndroidCLPeerCache(netCacheFor(n, "cl-peers", ".cache").toPath());
ChainStack stack = new ChainStack(net, ports, key,
        new AndroidPeerCacheAdapter(pc), new AndroidClPeerCacheAdapter(cl),
        new com.jaeckel.ethp2p.android.ens.AndroidCcipGateway(ccipPool),
        netCacheFor(n, "sync-state", ".snapshot").toPath(),
        /*gossipsub*/ false);
stack.configureSnapMaintainer(snapTarget(this), this::activeNetworkDnsServers); // DnsServerProvider
stacks.put(n, stack);
new Thread(() -> { if (!stack.start()) stacks.remove(n); }, "ethp2p-boot-" + n).start();
```

- `netCache(base, ext)` (~278) is keyed on the single `activeNetwork` today — generalize
  to `netCacheFor(String network, base, ext)` (suffix `-<net>` for non-mainnet). The
  existing one-arg `netCache` can delegate for any remaining single-network callers.
- `activeNetworkDnsServers()` (~928, `ConnectivityManager`) becomes the
  `DnsServerProvider` passed to the stack — it stays in `NodeService` (Android API),
  matching `DnsServerProvider.get()`.
- `snapTarget`/`rpcPortFor` prefs already exist and are per-network for RPC port.

### Lifecycle methods (new)
- `enableNetwork(String n)`: if absent, build+start as above; persist `enabled_<n>=true`;
  `startForegroundService` if the service isn't up.
- `disableNetwork(String n)`: `stacks.remove(n)` then `stack.shutdown()` on a worker; if
  `stacks.isEmpty()` → `stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()`.
- `onStartCommand` (~the RUNNING guard): iterate the **enabled-set** pref (default
  `{mainnet}`) and `enableNetwork(n)` each. The global `RUNNING` stays the "service up"
  flag; per-stack liveness is `ChainStack.isRunning()`.
- `doShutdown`/`onDestroy`: iterate `stacks.values()`, `shutdown()` each, clear the map.
  **Move the all-stacks-down `stopForeground/stopSelf` here** — today the single-stack
  boot-failure path calls it (~1332); per-stack failures must NOT stop the service.
- Delete `switchNetwork`/`restartWithCurrentSettings`/`restartAfterShutdown` (~254–276,
  174). An RPC-port change for `n` = `disableNetwork(n); enableNetwork(n)` (only that
  stack reboots). Keep the **Stop→Start race** safety: `ChainStack.start()`/`shutdown()`
  are already `synchronized` together, so a fast disable→enable on one stack serializes
  on that stack's monitor (this replaces the old service-wide `restartAfterShutdown`
  dance — verify on device that a port-change reboot of one chain doesn't flap the
  notification).

### Snapshot + query, per-stack
- `snapshot()` → `snapshots()` returning `Map<String, Snapshot>` (one per live stack).
  Keep the `Snapshot` record shape; build each from a `ChainStack`'s getters
  (`connector()`, `discV4()`, `discV5()`, `beaconLightClient()`, `beaconSyncState()`,
  `network()`), exactly as the current single-network `snapshot()`/`beaconStatsSnapshot()`
  read the singletons. The `network` field is the map key.
- `requestAccount(addr)` / `resolveEns(name)` take (or default) a network and route to
  `stacks.get(n).connector()` / `.rpcBackend()`. Default to the primary enabled network
  for back-compat.
- **Remove** `startPeerMaintainer/maintainSnapPeers/refreshDnsPool/dnsDialBudget/dialEnr/
  dialCachedSnapPeer/snapDialRank` and the `attempted/backoff/blacklistedNodeIds/dns*`
  fields from `NodeService` — they now live in `ChainStack`. `setTargetSnapPeers` becomes
  "set on every live stack" (`stacks.values().forEach(s -> s.setTargetSnapPeers(v))`).

### Prefs migration
- Add `enabled_<net>` booleans (default: mainnet true, others false). Seed from the
  legacy `K_NETWORK` if the `enabled_*` keys are absent (so existing installs keep their
  chain). Retire `K_NETWORK`/`selectedNetwork`/`setSelectedNetwork` once the UI uses the
  enabled-set. `rpcPortFor`/`setRpcPort` stay (already per-network); generalize
  `setRpcPort(ctx, port)` → `setRpcPort(ctx, network, port)`.

---

## Step 9 — `MainActivity` per-network UI

- **Settings** (`SettingsScreen`, ~503–605): replace the mainnet/gnosis **radio**
  (~541–558) with a `Switch` per network → `onEnableNetwork(id, on)`; give each row its
  own RPC-port `OutlinedTextField` bound to `rpcPortFor(ctx, id)`. Drive the list from
  `NetworkConfig.allNetworks()` so adding a config entry auto-adds a row. Keep the snap
  target + deep-pool fields (apply to all stacks).
- **Status** (`NodeScreen`/`StatusTab`): hold `snapshots: Map<String,Snapshot>` from
  `svc.snapshots()`; add a small network selector (chips/segmented) above the existing
  `StatusTab` and render it per selected chain. `SyncProgressBar`/`ReadinessStrip` already
  take one `Snapshot` — call per chain.
- **Query/ENS**: add a chain selector; route via the selected stack. Default to the
  primary enabled network.
- Activity callbacks (~227–251): `switchNetwork` → `enableNetwork(name, on)`;
  `applyTunables` takes a network for the RPC port.

---

## Device verification (on the Mac, phone connected)

```bash
adb forward tcp:8545 tcp:8545
adb forward tcp:8546 tcp:8546
```

1. Default launch → only mainnet runs; `eth_chainId` on :8545 → `0x1`; Status shows
   mainnet reaching SYNCED; behavior matches today (regression check).
2. Toggle **Gnosis on** in Settings → a second stack boots; `eth_chainId` on :8546 →
   `0x64`; both chains show in Status; no port collision in logs (discv4 30303/30304,
   discv5 9000/9001); `nodekey-gnosis.hex` appears in `getFilesDir()`.
3. Both reach SYNCED concurrently; the per-network snap-peer maintainer logs show it
   topping up each chain.
4. Toggle Gnosis **off** → only its stack stops; mainnet keeps serving; service stays
   foreground.
5. Change a network's RPC port → only that stack reboots (notification doesn't flap).
6. Add both `http://<host>:8545` and `:8546` as MetaMask custom RPCs → both resolve.
7. Memory/battery sanity with two stacks; confirm one foreground notification.

## Risks / watch-items
- Stop→Start race (PR #82): now per-stack via `ChainStack`'s synchronized start/shutdown
  — verify a port-change reboot doesn't flap the foreground notification.
- Snapshot polling must tolerate a stack mid-boot (null getters) — guard like today.
- `AndroidCcipGateway`/`ccipPool` shared across stacks is fine (stateless per call).
- Keep the proven single-network path the default; only the toggle enables concurrency.
