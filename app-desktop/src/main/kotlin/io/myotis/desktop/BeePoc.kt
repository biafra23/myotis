package io.myotis.desktop

/**
 * The **Bee PoC** flavour of the desktop app (`./gradlew :app-desktop:packageDmg -PbeePoc`,
 * see app-desktop/build.gradle.kts): a Myotis a Swarm Bee full node can point at
 * IMMEDIATELY — no multi-day backfill. The Gnosis PostageStamp log-index seed is bundled
 * in the app bundle (Compose appResources), installed into the flavour's own data dir on
 * first start, and the first start enables Gnosis with the log index on, so
 * `http://127.0.0.1:8546` serves Bee's `eth_getLogs` pages as soon as the beacon sync is
 * `SYNCED` (seconds with a fresh anchor). The warm Gnosis peer caches from `data/bee/gnosis`
 * (`peers-gnosis.cache`, `cl-peers-gnosis.cache`; public peers only) ride along the same
 * way — installed once, never over what the engine has learned since — so the pool does
 * not start cold either.
 *
 * This is a DEBUG / DEMO artefact, not a production path: the seed is a full node's
 * `eth_getLogs` output framed by `scripts/synth_logindex.py`, unverified until the walker
 * re-fetches it (docs/bee-rpc-service.md, *Demo only*), and it expires ~500,000 Gnosis
 * blocks (~29 days) after its fetch — the manifest carries the block it is usable until.
 *
 * Everything here is a no-op unless the packaged app carries `-Dmyotis.beePoc=true`
 * (the Gradle property adds it to the bundle's JVM args and to the dev `run` task).
 *
 * The machinery itself lives in [PocFlavour], shared with [RailgunPoc]; this object is the
 * Bee-shaped configuration of it plus the constants the build and the tests name directly.
 */
object BeePoc : PocFlavour(
    prop = "myotis.beePoc",
    label = "Bee PoC",
    network = "gnosis",
    dataDirName = ".myotis-bee-poc",
    seedFile = "logindex-gnosis.db",
    manifestFile = "bee-poc-seed.properties",
    installedManifestFile = "logindex-gnosis.seed.properties",
    // A cold Gnosis pool is the PoC's other failure mode: with no cache the app once sank
    // to a single unresponsive snap peer, the index stopped following the head, and Bee's
    // ten-minute stall rule shut it down.
    peerCacheFiles = listOf("peers-gnosis.cache", "cl-peers-gnosis.cache"),
    watchAddress = "0x45a1502382541Cd610CC9068e88727426b696293",
    watchDeployBlock = 31_305_656L,
    seedSubject = "PostageStamp logs",
    seedSource = "a Gnosis full node",
    // Bee embeds the postage history below the seed (`go:embed` in Bee's
    // pkg/postage/snapshot, events to block 47,061,407) and has never once asked below it,
    // so the downward walk only steals peers from the head-follow that Bee does depend on.
    // See PocFlavour.backfillPausedDefault for the measurements.
    pauseBackfillByDefault = true,
) {
    /** The system property the packaged app sets. Named here because the build names it. */
    const val PROP = "myotis.beePoc"
    const val NETWORK = "gnosis"

    /**
     * The seed as staged into appResources (`common/`), and the manifest beside it. The
     * seed's name is the engine's own drop-in name for this network —
     * `dataDir/logindex-<network>.db`, derived in `rust/myotis-engine/src/host.rs`
     * (`log_index_path`) from the sync-snapshot path the desktop host passes, and
     * activated at engine start by `activate_log_index_from_disk`. A rename on the
     * engine side must be mirrored here or the seed is silently never opened.
     */
    const val SEED_FILE = "logindex-gnosis.db"
    const val MANIFEST_FILE = "bee-poc-seed.properties"

    /** The manifest's copy in the data dir — how the UI knows the index was seeded. */
    const val INSTALLED_MANIFEST_FILE = "logindex-gnosis.seed.properties"

    /**
     * The seed's watch entry: the PostageStamp contract at its REAL deployment block —
     * `from_block` is the engine's "no logs below here" assertion, so it must never be the
     * seed's fetched low edge (docs/bee-rpc-service.md explains the difference).
     */
    const val POSTAGE_STAMP = "0x45a1502382541Cd610CC9068e88727426b696293"
    const val POSTAGE_STAMP_DEPLOYED = 31_305_656L
}
