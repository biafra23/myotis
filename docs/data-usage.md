# Data usage

Every network the engine hosts counts the bytes it sends and receives, and keeps
a per-day total that survives a restart. A host reads it from the status call;
an app that embeds Myotis can show "data used today" without an OS API of its
own. The engine also echoes back what the host told it about the device's
network — metered (mobile data) or not — and splits today's figure along it.

For what the numbers *should* be — a cold sync, a day of staying synced, a
transaction — see [disk-and-network-usage.md](disk-and-network-usage.md). This
page is about the meter.

## What a host reads

`ChainHandle.status()` → `StatusSnapshot.dataUsage()` (`io.myotis.api.DataUsage`)
and `StatusSnapshot.networkMetering()`:

| Field | Meaning |
|---|---|
| `bytesIn` / `bytesOut` | received / sent since the handle was created (this process), across pauses |
| `elBytesIn` … `clBytesOut` | the same, split: execution layer (RLPx, discv4) and consensus layer (libp2p, discv5) |
| `day` | the local date (`YYYY-MM-DD`) the `today*` figures cover |
| `todayBytesIn` / `todayBytesOut` | received / sent today |
| `todayMeteredBytesIn` / `…Out` | of today's, moved while the host reported a **metered** network |
| `networkMetering` | `METERED`, `UNMETERED` or `UNKNOWN` — the host's last report (below) |

The figures are **per network**. A host running mainnet and Gnosis side by side
adds the two up for the app's total.

The same object is in every status surface, with the same keys in the same
order:

- the daemon's `status` IPC command (`dataUsage`, `networkMetering`),
- JSON-RPC `myotis_status` on the loopback listener,
- the engine's own status JSON (`status_json` / `myotis_status_json`, ABI 50),
  which the JVM wrapper and the iOS module decode into the types above,
- the apps' Status screen: **Data today** (↓ in, ↑ out, and the metered part),
  **Data total** (since start) and **Connection** (metered / unmetered /
  unknown), in Expert mode.

## Metered or not: the host says

The engine cannot see what kind of network the device is on, so the host tells
it — `MyotisEngine.setNetworkMetering(NetworkMetering)`, engine-wide because it
is the device's network, not a chain's. Bytes moved while it is `METERED` count
toward the `todayMetered*` figures; `UNKNOWN` (the default, and what the daemon
and the desktop app report) is not counted as metered. Before the switch every
network's ledger is brought up to date, so the bytes moved before a change keep
the label they were moved under.

- **Android** (`NodeService`): `ConnectivityManager`'s active network —
  `NET_CAPABILITY_NOT_METERED` is unmetered, any other connected network is
  metered, none is unknown. Pushed at service start and on every default-network
  capability change (Wi-Fi → mobile data does not flip connectivity up or down,
  so it is pushed before that gate).
- **iOS** (`IosNetworkMetering`): Network.framework's path monitor — an
  *expensive* path (cellular, a personal hotspot) or a *constrained* one (Low
  Data Mode) is metered, any other satisfied path unmetered, no path unknown.
- **An app embedding the engine library** does the same with its own
  connectivity callback:

  ```kotlin
  engine.setNetworkMetering(
      if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) NetworkMetering.UNMETERED
      else NetworkMetering.METERED,
  )
  val today = engine.hostedNetworks().sumOf { engine.get(it)!!.status().dataUsage().todayBytes() }
  ```

## How it is counted

Each network's stack owns one meter, created with the handle and shared by every
socket it opens, so a pause and resume keeps counting into the same one.

| Traffic | Rust engine | Java engine |
|---|---|---|
| RLPx (EL, TCP) | every handshake and frame byte at the stream (`el/rlpx/transport.rs`) | a Netty handler first in the pipeline (`CountingHandler`) |
| discv4 (EL, UDP) | every datagram's payload (`el/discv4.rs`) | the same handler on the datagram channel |
| libp2p over TCP (CL) | the raw socket, below noise and the muxer (`traffic::CountingStream`) | the same handler, installed before the secure channel (jvm-libp2p's `beforeSecureHandler`) |
| libp2p over QUIC (CL) | the stream payload above QUIC (`traffic::CountingMuxer`) | — (no QUIC) |
| discv5 (CL, UDP) | the `discv5` crate's process-wide counters, handed to the networks whose discovery runs, evenly (`traffic::Discv5Share`) | **not counted** (the ConsenSys discv5 library exposes no hook) |

Not counted, by either engine: IP/TCP/UDP headers, QUIC's own packet overhead
and TLS handshake, EIP-1459 DNS lookups, the CCIP-Read gateway's HTTP, and
**Tor** — Arti's circuits and directory downloads are invisible to the engine
(the sessions routed over Tor are not counted either). So the figure is a
floor, close to the truth for the default (clearnet) configuration. The OS's
own per-app accounting (Android's Settings → Data usage) remains the
authority; this meter exists so that a host *without* one (iOS has none per
app), or an app that embeds Myotis among other traffic, can still show what
Myotis itself moved.

discv5's split is exact with one network running. With several, its traffic
is divided evenly among them — the crate counts per process, not per instance —
so per-network CL figures are approximate there while their sum stays exact.

## The day ledger

Each tick adds the meter's growth since the previous tick to the current
**local** day (the C library's time zone in the Rust engine — `TZ`,
`/etc/localtime`, Android's and iOS's system zone — and `LocalDate.now()` in
the Java engine) and, while metered, to its metered part. A tick runs on every
status read, once a minute in the background, before a metering change, and at
pause and stop. Bytes moved in the minute around midnight can land on the next
day.

Today's figures are written to `data-usage.json` (mainnet) /
`data-usage-<network>.json` beside the sync snapshot in the handle's data
directory — at most every five minutes while traffic flows, and at once on a
new day, at pause and at stop. A crash loses at most those five minutes. On
creation the ledger picks the file up again if it is today's; a previous day's
is ignored. Both engines read and write the same file
(`{"version":1,"day":…,"bytesIn":…,"bytesOut":…,"meteredBytesIn":…,"meteredBytesOut":…}`),
so an engine switch keeps the day's count. Without a data directory the ledger
is memory-only.

## Code pointers

- Rust: `rust/myotis-net/src/traffic.rs` (the meter, the libp2p wrappers, the
  discv5 share), `rust/myotis-engine/src/usage.rs` (the ledger, the metering
  state), `host.rs` (`status_object`'s `dataUsage`, `set_network_metering`,
  the minute ticker), FFI `set_network_metering` / `network_metering`
  (C: `myotis_set_network_metering` / `myotis_network_metering`).
- Java: `core/…/traffic/TrafficMeter.java`,
  `networking/…/traffic/CountingHandler.java`,
  `myotis-engine-common/…/DataUsageLedger.java`, `ChainStack` (wiring).
- API: `myotis-api/…/DataUsage.java`, `NetworkMetering.java`,
  `MyotisEngine.setNetworkMetering`.
