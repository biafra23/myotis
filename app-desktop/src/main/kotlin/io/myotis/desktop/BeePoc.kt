package io.myotis.desktop

import io.myotis.ui.Settings
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Properties

/**
 * The **Bee PoC** flavour of the desktop app (`./gradlew :app-desktop:packageDmg -PbeePoc`,
 * see app-desktop/build.gradle.kts): a Myotis a Swarm Bee full node can point at
 * IMMEDIATELY — no multi-day backfill. The Gnosis PostageStamp log-index seed is bundled
 * in the app bundle (Compose appResources), installed into the flavour's own data dir on
 * first start, and the first start enables Gnosis with the log index on, so
 * `http://127.0.0.1:8546` serves Bee's `eth_getLogs` pages from the first minute.
 *
 * This is a DEBUG / DEMO artefact, not a production path: the seed is a full node's
 * `eth_getLogs` output framed by `scripts/synth_logindex.py`, unverified until the walker
 * re-fetches it (docs/bee-rpc-service.md, *Demo only*), and it expires ~500,000 Gnosis
 * blocks (~29 days) after its fetch — the manifest carries the block it is usable until.
 *
 * Everything here is a no-op unless the packaged app carries `-Dmyotis.beePoc=true`
 * (the Gradle property adds it to the bundle's JVM args and to the dev `run` task).
 */
object BeePoc {
    const val PROP = "myotis.beePoc"
    const val NETWORK = "gnosis"

    /** The seed as staged into appResources (`common/`), and the manifest beside it. */
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
    const val WATCH_JSON = """[{"address":"$POSTAGE_STAMP","fromBlock":$POSTAGE_STAMP_DEPLOYED}]"""

    fun enabled(): Boolean = System.getProperty(PROP).toBoolean()

    /** The flavour's own data dir — it never touches a regular Myotis install's `~/.myotis`. */
    fun dataDir(): Path = Path.of(System.getProperty("user.home"), ".myotis-bee-poc")

    /**
     * Copy the bundled seed (and its manifest) into [dataDir] when no index file exists there
     * yet, after checking the seed's sha256 against the manifest. NEVER overwrites: once the
     * engine has started it owns `logindex-gnosis.db` (it rewrites it as its own checkpoint),
     * and a seed older than what the node accumulated would only lose coverage. Returns true
     * when a seed was installed on this call.
     */
    fun installSeedIfAbsent(resourcesDir: Path?, dataDir: Path): Boolean {
        val dir = resourcesDir ?: return false
        val seed = dir.resolve(SEED_FILE)
        val manifest = dir.resolve(MANIFEST_FILE)
        if (!Files.isRegularFile(seed) || !Files.isRegularFile(manifest)) return false
        val target = dataDir.resolve(SEED_FILE)
        if (Files.exists(target)) return false
        val props = loadProps(manifest) ?: return false
        val expected = props.getProperty("sha256")?.lowercase()
        if (expected == null || sha256Hex(seed) != expected) {
            log.warn("bee-poc: bundled seed {} does not match its manifest sha256 — not installing", seed)
            return false
        }
        return runCatching {
            Files.createDirectories(dataDir)
            atomicCopy(seed, target)
            atomicCopy(manifest, dataDir.resolve(INSTALLED_MANIFEST_FILE))
            log.info(
                "bee-poc: installed the bundled Gnosis log-index seed into {} (coverage {}–{}, usable until block {})",
                target, props.getProperty("coveredLow"), props.getProperty("coveredHigh"), props.getProperty("usableUntilBlock"),
            )
            true
        }.onFailure {
            log.warn("bee-poc: seed install into {} failed: {}", dataDir, it.toString())
            runCatching { Files.deleteIfExists(target) }
        }.getOrDefault(false)
    }

    /**
     * On a genuinely first start ([firstStart] = no settings file existed yet) make the PoC
     * boot straight into its purpose: Gnosis only, log index on, the seed's watch entry
     * visible in the Index tab. Later starts leave the user's settings alone — in
     * particular, this must never persist `logIndex.gnosis=false`, which would push a
     * disable to the engine and turn the seeded index off (queries → -32000).
     */
    fun applyFirstStartSettings(settings: Settings, firstStart: Boolean) {
        if (!firstStart) return
        settings.setNetworkEnabled("mainnet", false)
        settings.setNetworkEnabled(NETWORK, true)
        settings.setLogIndexEnabled(NETWORK, true)
        settings.setLogIndexWatchJson(NETWORK, WATCH_JSON)
    }

    /**
     * One line for the Index tab when [network]'s index was seeded by this flavour, from the
     * installed manifest; null otherwise (regular installs, other networks).
     */
    fun seededIndexNotice(dataDir: Path, network: String): String? {
        if (network != NETWORK) return null
        val props = loadProps(dataDir.resolve(INSTALLED_MANIFEST_FILE)) ?: return null
        val low = props.getProperty("coveredLow") ?: return null
        val high = props.getProperty("coveredHigh") ?: return null
        val until = props.getProperty("usableUntilBlock") ?: return null
        val logs = props.getProperty("logs") ?: "?"
        return "Bee PoC seed: $logs PostageStamp logs, blocks $low–$high, from a Gnosis full node — " +
            "unverified until the walker re-fetches them; usable until about block $until " +
            "(the head bridge spans at most 500,000 blocks above the seed)."
    }

    private fun loadProps(file: Path): Properties? =
        runCatching { Files.newInputStream(file).use { Properties().apply { load(it) } } }.getOrNull()

    private fun sha256Hex(file: Path): String {
        val md = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(file).use { input ->
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /** tmp + atomic move, the same pattern DesktopSettings uses for its file. */
    private fun atomicCopy(from: Path, to: Path) {
        val tmp = to.resolveSibling("${to.fileName}.tmp")
        Files.copy(from, tmp, StandardCopyOption.REPLACE_EXISTING)
        try {
            Files.move(tmp, to, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmp, to, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    // Lazy on purpose: Main.kt redirects the PoC's logs (myotis.logdir) before the
    // first log call, and logback fixes its file location at first use — an eager
    // logger here would initialise it when `enabled()` is first touched.
    private val log: org.slf4j.Logger by lazy { org.slf4j.LoggerFactory.getLogger(BeePoc::class.java) }
}
