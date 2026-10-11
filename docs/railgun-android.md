# Importing the RAILGUN seed on Android

How to load the RAILGUN PoC seed ([railgun-poc.md](railgun-poc.md)) into the
Android app's log index. Afterwards a wallet on the same phone can scan
RAILGUN's history through Myotis's JSON-RPC on `127.0.0.1`. Android has no
RAILGUN flavour like the desktop dmg. This guide uses the generic
**Import log-index snapshot…** button on the Index tab (Settings → Expert mode), which takes any portable
MLIX snapshot. A seed framed by `scripts/synth_logindex.py` is one, and the Rust
test `synth_logindex_script_frame_is_importable` (`el/logindex.rs`) checks that
the portable loader accepts it.

**DEBUG / DEMO, not a production path.** This is the same seed as the desktop
PoC build, with the same standing. It is a full node's `eth_getLogs` output
with no receipt-root proof, and the engine serves it exactly like logs it
walked and verified itself. The seeded-history exception (CLAUDE.md, owner's
decision 2026-09-25; [seeded-log-histories.md](seeded-log-histories.md)) does
not cover it. On Android it is also **unlabelled**: the desktop flavour shows a
"seeded, unverified" notice on the Index tab from its bundled manifest
(`seededIndexNotice`), but an Android import has no manifest, so nothing on the
phone says where the coverage came from.

## What you need

- **The Rust engine.** The log index exists only there. It is the default:
  leave Settings → **Prefer Java engine** off. The network chips in the header
  show each network's engine as a one-letter suffix (`NetworkChips`):
  "Sepolia (r)" is the Rust engine, "(j)" would be the Java one. An APK built
  with `-PskipRustEngine` cannot do this. With a forced Java engine the Index
  tab is not shown at all.
- **The framed seed.** Not the release asset itself, which is a raw fetch;
  step 1 frames it. Start with Sepolia: it is 9 MB instead of 261 MB, imports
  in moments, and needs no real funds.
- **Free storage of about twice the file's size** while importing. The app
  first copies the picked file into its cache, then merges it into the index,
  then deletes the copy.

As of the seed assets uploaded on 2026-10-01 (the figures change when the
`railgun-seed` release is refreshed):

| | mainnet | Sepolia |
|---|---|---|
| release asset | `railgun-seed.tar.gz` (~120 MB) | `railgun-seed-sepolia.tar.gz` (~4 MB) |
| contract | `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9` | `0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea` |
| `--watch` | `0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9:14737691` | `0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea:5784774` |
| `--network-id` | `1` | `11155111` |
| framed file | `logindex.db`, 261 MB, 437,765 logs | `logindex-sepolia.db`, 9 MB, 14,761 logs |
| coverage | 14,737,691 – 26,097,965 | 5,784,774 – 11,824,017 |
| usable until block | 26,597,965 | 12,324,017 |
| Android RPC port | `8545` | `8547` |

The two "usable until" blocks fall in early December 2026 at 12 s per block.
The table's numbers were reproduced on 2026-10-03 by running step 1 on both
assets. Framing mainnet took 51 s.

## 1. Frame the seed

On any machine with Python 3 and a checkout of this repo. Use a **fresh
directory**, because the glob below must match exactly one `*.meta.json`.
Sepolia is shown; for mainnet, swap in the table's values.

```bash
SEED=$HOME/myotis-node/railgun-sepolia-android && mkdir -p "$SEED" && cd "$SEED"
base=https://github.com/biafra23/myotis/releases/download/railgun-seed
curl -L -O "$base/railgun-seed-sepolia.tar.gz" -O "$base/railgun-seed-sepolia.tar.gz.sha256"
sha256sum -c railgun-seed-sepolia.tar.gz.sha256      # macOS: shasum -a 256 -c …
tar -xzf railgun-seed-sepolia.tar.gz
grep toBlockTag railgun-logs-*.meta.json              # must say "finalized" for --finality-margin 0

cd /path/to/myotis
python3 scripts/synth_logindex.py \
    --meta "$SEED"/railgun-logs-*.meta.json \
    --logs "$SEED"/railgun-logs.jsonl \
    --watch 0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea:5784774 \
    --network-id 11155111 \
    --finality-margin 0 \
    --out "$SEED"/logindex-sepolia.db \
    --manifest "$SEED"/railgun-poc-seed-sepolia.properties
cat "$SEED"/railgun-poc-seed-sepolia.properties       # coverage, usableUntilBlock, sha256
```

These are the arguments `prepareRailgunPocSeed` (`app-desktop/build.gradle.kts`)
passes, and they are not negotiable:

- **The `--watch` block is the contract's real deployment block.** It tells the
  engine there are no logs below that block, so a higher number turns real
  history into plausible empty answers. On Sepolia that means 5,784,774, not
  the SDK's 5,784,866. See *The deployment block is load-bearing* in
  railgun-poc.md.
- **Pass `--finality-margin 0` only when the meta says `"toBlockTag":
  "finalized"`.** Otherwise leave it out. The default margin trims a top that
  could still reorg, instead of freezing an orphaned block into the seed.

`python3 scripts/synth_logindex.py --check <file>` prints what a framed file
claims: chain tag, watch entry and coverage.

**Alternative on a Mac:** every `v*` release's
`Myotis-v<version>-railgun-poc-arm64.dmg` bundles both framed files beside
their manifests (`railgun-poc-seed.properties`,
`railgun-poc-seed-sepolia.properties`). Mount it and copy them out:

```bash
hdiutil attach Myotis-v<version>-railgun-poc-arm64.dmg
find /Volumes -name 'logindex*.db' -o -name 'railgun-poc-seed*.properties'
```

Check the copy with `shasum -a 256` against the manifest's `sha256=`. Also
check its `usableUntilBlock`: a dmg carries the seed from when it was built.

## 2. Copy it to the phone

The import uses the system file picker, so put the file anywhere the picker
can open, for example `adb push logindex-sepolia.db /sdcard/Download/`. The
file name does not matter. The file carries its own chain tag and watch
entry.

## 3. Prepare the app

1. **Run the seed's network.** Under Settings → Networks, switch on Sepolia for
   the Sepolia seed; mainnet is the usual default. The import needs the
   network running, otherwise it answers "Node is not running — start it
   first." or "Import failed: sepolia is not running".
2. **Do not add the RAILGUN proxy on the Index tab yourself.** The seed brings
   its own watch entry. The engine unions watch entries and keeps the **lower**
   from-block (`LogIndexConfig::union_with`). So a hand-typed earlier block
   reaches below the seed's coverage, and queries into that band are refused
   until the backfill walks it. Subscriptions are add-only
   ([eth-getlogs-design.md](eth-getlogs-design.md) §Import), so this cannot be
   undone short of deleting the index.

   The commonly quoted mainnet block 14,693,013 is exactly that mistake, and the
   retired built-in Kohaku preset used it. An install that once had the preset on
   gets it seeded into its watch list (`LogIndexWatch.legacyKohakuWatchJson`).
   If the Index tab already lists `0xFA70…4b9` from block 14693013, expect
   queries below 14,737,691 to be refused for a while. RAILGUN wallets start
   scanning at 14,737,691, so they do not hit this.
3. **Prefer a network whose index was never switched on.** An import merges
   all-or-nothing with any index already there, and the merged index's top is
   the **lower** of the two tops (eth-getlogs-design.md §Import, *Merge
   rules*). Importing into an index that follows the head drops its coverage
   above the seed's top, and the bridge then fetches that band again. Importing
   into one that stopped long ago (the network was off for weeks) drops the
   merged top to the old index's top. If that is more than 500,000 blocks
   behind the head, nothing catches it up again (*Shelf life* below).
4. **Keep the node awake for the catch-up in step 5.** Idle sleep stops all P2P
   networking after 5 minutes without RPC or UI activity. That does not happen
   while the phone is charging and online (**Stay awake while charging**, on by
   default). Otherwise set **Idle sleep after (minutes, 0 = never)** to 0 until
   the catch-up is done.

## 4. Import

Open the Index tab. If several networks are running, pick the seed's network
in the chips at the top. Tap **Import log-index snapshot…** and pick the file.

- Success reads "Imported 1 snapshot — catch-up started." Importing switches
  **Collect logs on <network>** on, and the app persists that across restarts.
- A failure reads "Import failed: <reason>" with the engine's reason. The usual
  mistake is importing on the wrong network. The engine checks the seed's
  chain tag and refuses with "…: belongs to another chain (network id 11155111,
  this node is 1)" (`ElReader::import_log_index`).

## 5. Let it catch up to the head

The Index tab now shows the proxy as "complete — blocks <deployment>–<top>",
where the top starts at the seed's coverage high. The seed covers everything
down to the deployment block, so the downward walk has nothing to do. The
**Pause backfill** switch makes no difference here, unless step 3.2's lower
from-block applies.

What is left is the gap from the seed's top to the chain head. The **head
bridge** closes it over devp2p, verified, once the beacon sync is `SYNCED`.
Then the per-block appender follows the head. Until then:

- A range inside coverage is served at once.
- A range reaching above the covered top is refused with `-32000` "requested
  range is not indexed yet (covered: L-H); retry as the index catches up".
  It is never answered with `[]`.

So a wallet that scans to the chain head waits for the bridge.

**On mainnet, bridge on Wi-Fi and from a fresh seed.** The bridge bloom-filters
the gap and fetches the full receipts of every candidate block. Mainnet's
`logsBloom` is saturated, so most blocks are candidates. The bundle design
estimates, unmeasured, that ~85–95 % of blocks are candidates, at 100–200 KB
of receipts each ([logindex-verified-bundle-design.md](logindex-verified-bundle-design.md),
*Where this pays*). At 7,200 blocks a day that is on the order of **a gigabyte
of download per day of seed age**. The bridge has not been timed on a phone.
On Sepolia it is not measured either.

## 6. Check it from the phone

Apps on the same device share `127.0.0.1`, so a terminal app such as Termux
(`pkg install curl`) reaches the RPC. These two queries cover the first
100,000 blocks after each deployment:

```bash
# Sepolia (port 8547)
curl -s http://127.0.0.1:8547 -H 'content-type: application/json' --data \
  '{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"address":"0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea","fromBlock":"0x5844c6","toBlock":"0x59cb66"}]}'

# mainnet (port 8545)
curl -s http://127.0.0.1:8545 -H 'content-type: application/json' --data \
  '{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"address":"0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9","fromBlock":"0xe0e11b","toBlock":"0xe267bb"}]}'
```

What each answer means:

- **A non-empty `result`:** the seed is serving.
- **"log index is not configured on this network":** this network has no
  index. The import did not reach it, or went to another network.
- **"address is not on this node's log watch-list":** this network has an
  index, but not for this contract.
- **An empty `result` for a range entirely below the deployment block:** this
  is correct. The watch entry asserts there is nothing there.

The ports are the Android defaults (`NodeService.defaultRpcPort`); Settings
can change them. The desktop flavour's 8555/8557 do not apply. Those exist
only so the PoC dmg does not fight a regular desktop install for the port.

## Pointing a wallet at it

Myotis replaces only the wallet's JSON-RPC provider. Anything else the wallet
talks to, such as broadcasters and POI nodes, is unaffected. As of 2026-10
there is no RAILGUN wallet for Android that accepts a plain `http://`
endpoint:

- **Railway** was withdrawn from Google Play on 2025-12-01.
- **Railway's custom-RPC field** accepts only `https://` and `wss://`
  (`SettingsAddCustomRPCScreen.tsx` in its source).

The [Terminal Wallet CLI](https://github.com/Terminal-Wallet/terminal-wallet-cli),
which the desktop PoC targets, accepts `http://` endpoints. Running it on the
phone is **untested**. It needs Node ≥ 20 and the native `leveldown` module.
`leveldown` 6.1.1 ships an `android-arm64` prebuild, which may let plain Termux
work; a `proot-distro` Debian inside Termux is the fallback.

Its RPC list is not the only RPC it uses. At start it also reads a remote config
with one `eth_call` (`getConfig()` on `0x5e982525d50046A813DBf55Ae72a3E00e99fbC94`,
an Ethereum mainnet contract). That call goes to `REMOTE_CONFIG_RPC`, or to
`https://ethereum-rpc.publicnode.com` when the variable is unset
(`loadConfigForNetwork`, `src/railgun/network/network-util.ts` in its source as
of 2026-08-20). Set `REMOTE_CONFIG_RPC=http://127.0.0.1:8545` to keep that call
on the phone. The call needs mainnet running in Myotis even when you test on
Sepolia. If it fails, the wallet logs it and falls back to its built-in
defaults.

## Shelf life, storage, and removal

- **Shelf life: 500,000 blocks above the seed's top (~69 days on both
  networks).** The head bridge maps at most that much (`BRIDGE_MAX_GAP`,
  `el/reader.rs`). A seed older than its `usableUntilBlock` imports fine and
  then never reaches the head. Once caught up, the index stays current by
  itself while the network runs. The bound matters again only if the network
  is off long enough to fall that far behind. In that case, frame a fresh seed
  and import it. A source whose coverage is a subset of another's is pruned
  before the merge, so a newer single-contract seed supersedes the stale index.
- **The index lives in the app's cache directory.** Android passes
  `getCacheDir()` as the engine's data directory (`NodeService`, "reconstructible
  engine-owned state"), and the index is `logindex.db` / `logindex-sepolia.db`
  there. Android may delete cache files when the device runs low on storage.
  An imported seed is not cheaply reconstructible: losing it means a fresh
  import, or the multi-day walk the seed exists to avoid. Keep some storage
  free, and re-check the Index tab if a wallet suddenly gets "not configured".
- **Removing it:** switch **Collect logs on <network>** off, then use Android
  Settings → Apps → Myotis → Storage → **Clear cache**. That wipes the index
  together with the peer caches and the sync snapshot, which rebuild
  themselves. Identity and query history are in the app's files directory and
  survive. Removing the entry from the Index tab's watch list does not
  unsubscribe an index that already holds it.
