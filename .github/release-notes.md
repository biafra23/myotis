Pre-release build of the Myotis wallet apps.

**Android (`*-android.apk`)** — the Myotis app, signed with Myotis's own release key
(its certificate's SHA-256 is in `android-app/release-signing-cert.sha256` in the
repository). Install via "Install unknown apps" and switch that off again afterwards;
only ever install Myotis, and its updates, from this releases page.

**Android debug (`*-android-debug.apk`)** — a separate test app ("Myotis Debug", amber
icon, package `com.jaeckel.ethp2p.android.debug`), signed with the publicly known debug
key: anyone can build an APK that installs over it as an update, so do not rely on it for
a wallet you use. It installs next to the release app, but run only one of them at a time:
both use the same network and JSON-RPC ports.

**Coming from an older Android release?** Releases that shipped only an
`*-android-debug.apk` installed Myotis itself (package `com.jaeckel.ethp2p.android`)
signed with that public debug key. Android will not update it to the release-signed app
("App not installed … conflicts with an existing package"), and while it stays installed
anyone's lookalike can replace it. Uninstall it first: that deletes its settings, allowed
websites and sync progress (Myotis holds no wallet keys or funds), and the new app
re-syncs on its first start.

**Desktop macOS (`Myotis-v<version>-<arch>.dmg`)** — unsigned; download the dmg matching
your Mac (arm64 for Apple Silicon, x64 for Intel). First launch:
right-click → Open to get past Gatekeeper (not notarized yet).

**Bee PoC (`Myotis-v<version>-bee-poc-arm64.dmg`, when present)** — a separate app
("Myotis Bee PoC", own data dir) that a Swarm Bee full node can use as its
Gnosis RPC from the first minute: it ships a pre-built PostageStamp log-index
seed and warm peer caches. Demo/debug artefact — the seed is RPC-sourced and
served unverified (only the backfill walk would re-check it, and the app ships
with that walk switched off), and it stops catching up about 29
days after its fetch (the Index tab shows the block it is usable until). See
docs/bee-rpc-service.md.

**RAILGUN PoC (`Myotis-v<version>-railgun-poc-arm64.dmg`, when present)** — a separate
app ("Myotis RAILGUN PoC", own data dir) that the RAILGUN Terminal Wallet CLI can use as
its mainnet RPC from the first minute, and as its Sepolia RPC once Sepolia is switched on
in the app: it ships pre-built log-index seeds covering the RailgunSmartWallet contract
on both networks from its deployment block. It
serves mainnet on port 8555 and Sepolia on 8557, not the regular app's 8545 and 8547:
point the wallet at `http://127.0.0.1:8555` or `http://127.0.0.1:8557`. Debug/demo
artefact, not a production path — the seeds are RPC-sourced and unverified (no
receipt-root proof), and each stops catching up about 69 days after its fetch (the
Index tab shows the block it is usable until). See docs/railgun-poc.md.

**Desktop Linux (`Myotis-v<version>-<arch>.deb`)** — install with
`sudo apt install ./Myotis-v<version>-<arch>.deb` (x64 for Intel/AMD, arm64 for
Raspberry Pi 5 / ARM machines).
