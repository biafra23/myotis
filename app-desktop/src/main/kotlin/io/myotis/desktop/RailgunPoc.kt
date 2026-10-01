package io.myotis.desktop

/**
 * The **RAILGUN PoC** flavour of the desktop app
 * (`./gradlew :app-desktop:packageDmg -PrailgunPoc -PrailgunSeedDir=<dir> -PrailgunSepoliaSeedDir=<dir>`,
 * see app-desktop/build.gradle.kts): a Myotis the RAILGUN Terminal Wallet
 * (https://github.com/Terminal-Wallet/terminal-wallet-cli) can point at INSTEAD OF a public
 * RPC provider, from the first minute. The wallet scans one contract's whole history to
 * rebuild its private balances, which over devp2p is a multi-day walk; the log-index seeds
 * for mainnet and Sepolia are bundled in the app bundle instead, installed into the
 * flavour's own data dir on first start, and the first start enables both networks with
 * the log index on, so `http://127.0.0.1:8555` (mainnet) and `http://127.0.0.1:8557`
 * (Sepolia) serve the wallet's `eth_getLogs` pages as soon as each beacon sync is `SYNCED`.
 *
 * The contract is the **RailgunSmartWallet proxy**, which the CLI reaches through
 * `@railgun-community/wallet` → `@railgun-community/shared-models`; it hardcodes no address
 * of its own. The wallet hands its engine the proxy, the relay-adapt contract and the V3
 * contracts; the relay adapt is used to build transactions rather than scanned for
 * history, and the V3 contracts are deployed on neither network (empty in that config,
 * `supportsV3: false`), so one watch entry per network covers what the wallet reads.
 *
 * Unlike the Bee seed, these reach the contract's real deployment block, so their coverage
 * is COMPLETE: there is no band below for the walker to fill, and every query the wallet
 * makes is either served from the index or refused as above the covered head. That is also
 * why the backfill default here is a formality — there is nothing below to walk — rather
 * than the contention fix it is for Bee.
 *
 * This is a DEBUG / DEMO artefact, not a production path: each seed is a full node's
 * `eth_getLogs` output framed by `scripts/synth_logindex.py`, unverified until the walker
 * re-fetches it (docs/railgun-poc.md), and it expires ~500,000 blocks (~69 days on either
 * network) after its fetch — the manifest carries the block it is usable until.
 *
 * Everything here is a no-op unless the packaged app carries `-Dmyotis.railgunPoc=true`
 * (the Gradle property adds it to the bundle's JVM args and to the dev `run` task).
 */
object RailgunPoc : PocFlavour(
    prop = "myotis.railgunPoc",
    label = "RAILGUN PoC",
    dataDirName = ".myotis-railgun-poc",
    seeds = listOf(
        PocSeed(
            network = "mainnet",
            // Mainnet's index has NO network suffix — the engine derives `logindex.db` for
            // it and `logindex-<network>.db` for the rest (rust/myotis-engine/src/host.rs,
            // log_index_path). Getting this wrong means the seed is staged, installed, and
            // then silently never opened, which looks exactly like a slow first start.
            seedFile = "logindex.db",
            manifestFile = "railgun-poc-seed.properties",
            installedManifestFile = "logindex.seed.properties",
            // None yet: the warm caches the Bee flavour ships were captured from a
            // long-running Gnosis node, and no equivalent mainnet pair has been captured.
            // Discovery seeds from the embedded bootnodes instead, which costs a slower
            // first minute, not correctness.
            peerCacheFiles = emptyList(),
            watchAddress = RAILGUN_PROXY,
            watchDeployBlock = RAILGUN_PROXY_DEPLOYED,
            seedSubject = "RailgunSmartWallet logs",
            seedSource = "a mainnet full node",
            // NOT mainnet's default 8545: a regular Myotis install serves mainnet on that
            // port, so two installed apps would fight for it and a wallet aimed at 8545
            // could silently reach the regular one — which has no seeded index, and answers
            // this demo's own queries with -32000. The Bee flavour never hit this because
            // gnosis/8546 is a port no regular install uses by default.
            rpcPort = RAILGUN_RPC_PORT,
        ),
        PocSeed(
            network = "sepolia",
            seedFile = "logindex-sepolia.db",
            manifestFile = "railgun-poc-seed-sepolia.properties",
            installedManifestFile = "logindex-sepolia.seed.properties",
            // None, as for mainnet; Sepolia discovery seeds from its embedded bootnodes.
            peerCacheFiles = emptyList(),
            watchAddress = RAILGUN_SEPOLIA_PROXY,
            watchDeployBlock = RAILGUN_SEPOLIA_PROXY_DEPLOYED,
            seedSubject = "RailgunSmartWallet logs",
            seedSource = "a Sepolia full node",
            // NOT Sepolia's default 8547, for the same reason as mainnet: a regular install
            // with Sepolia switched on serves it there.
            rpcPort = RAILGUN_SEPOLIA_RPC_PORT,
        ),
    ),
    // Nothing to pause in practice — coverage already starts at the deployment block, so
    // the downward walk has no hole to descend into. Set anyway so the Index tab's switch
    // shows a decided state rather than an unset default, and so a later re-seed that
    // starts higher cannot quietly start a walk on a demo machine.
    pauseBackfillByDefault = true,
) {
    /**
     * The system property the packaged app sets. Duplicated from the constructor argument
     * ONLY because tests and callers name it as a constant — see [BeePoc.PROP].
     */
    const val PROP = "myotis.railgunPoc"
}

/** The port this flavour serves mainnet on — see the mainnet seed's `rpcPort` for why it is not 8545. */
const val RAILGUN_RPC_PORT = 8555

/** The port this flavour serves Sepolia on: Sepolia's default 8547 plus ten, as mainnet's is 8545 plus ten. */
const val RAILGUN_SEPOLIA_RPC_PORT = 8557

/**
 * The RailgunSmartWallet proxy on Ethereum mainnet, from
 * `@railgun-community/shared-models`' network config (chain id 1) — the address the
 * Terminal Wallet CLI ends up querying.
 */
const val RAILGUN_PROXY = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"

/**
 * Its REAL deployment block: `from_block` is the engine's "no logs below here" assertion,
 * and below it the engine answers `[]` WITHOUT consulting coverage — so a value ABOVE the
 * real deployment turns the history below it into plausible empty answers instead of the
 * honest `-32000` refusal. A value below it is safe but not free: the seed's coverage
 * starts at the fetch, so the span in between is refused as out of coverage, and under
 * this flavour's paused backfill it stays refused.
 *
 * 14,737,691 is what the SDK config states AND what the chain shows: the contract's first
 * log falls on exactly that block, and a sweep from genesis to it found no logs at all
 * (zbox, 2026-09-22). Note that 14,693,013 circulates as "the RAILGUN deployment block" and
 * is wrong for this purpose — it would leave 44,678 blocks, which hold no logs, refused as
 * out of coverage for as long as the backfill stays paused.
 */
const val RAILGUN_PROXY_DEPLOYED = 14_737_691L

/**
 * The RailgunSmartWallet proxy on Ethereum Sepolia, from the same shared-models config
 * (chain id 11155111).
 */
const val RAILGUN_SEPOLIA_PROXY = "0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea"

/**
 * Its REAL deployment block, by the same rule as [RAILGUN_PROXY_DEPLOYED] — and here the
 * SDK and the chain DISAGREE, so the chain decides. The proxy was created in block
 * 5,784,774 (a top-level creation transaction; its receipt names the proxy as
 * `contractAddress`), its first log is at 5,784,776, and a sweep from genesis found no logs
 * below it (zbox, 2026-10-01). The shared-models config gives 5,784,866 instead, which is
 * where the wallet STARTS SCANNING, after the 62 setup events of the deployment (verifying
 * keys, ownership, initialisation). Used as the watch floor it would assert that those 62
 * logs do not exist: the direction that turns real history into plausible empty answers.
 */
const val RAILGUN_SEPOLIA_PROXY_DEPLOYED = 5_784_774L
