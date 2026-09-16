package io.myotis.desktop

import io.myotis.ui.LogIndexWatch
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
 * `http://127.0.0.1:8546` serves Bee's `eth_getLogs` pages as soon as the beacon sync is
 * `SYNCED` (seconds with a fresh anchor). The warm Gnosis peer caches from `data/bee/gnosis`
 * (`peers-gnosis.cache`, `cl-peers-gnosis.cache`; public peers only) ride along the same way — installed once, never over what the engine
 * has learned since — so the pool does not start cold either.
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
     * Warm peer caches bundled beside the seed, in the engine's own formats and under the
     * engine's own data-dir names (`peers{-network}.cache` for EL snap peers,
     * `cl-peers{-network}.cache` for beacon light-client peers — see `host.rs`). Public
     * peer addresses only; the engine re-verifies every peer it dials, so these are hints
     * that shortcut discovery, not trust. A cold Gnosis pool is the PoC's other failure
     * mode: with no cache the app once sank to a single unresponsive snap peer, the index
     * stopped following the head, and Bee's ten-minute stall rule shut it down.
     */
    val PEER_CACHE_FILES: List<String> = listOf("peers-gnosis.cache", "cl-peers-gnosis.cache")

    /**
     * The seed's watch entry: the PostageStamp contract at its REAL deployment block —
     * `from_block` is the engine's "no logs below here" assertion, so it must never be the
     * seed's fetched low edge (docs/bee-rpc-service.md explains the difference).
     */
    const val POSTAGE_STAMP = "0x45a1502382541Cd610CC9068e88727426b696293"
    const val POSTAGE_STAMP_DEPLOYED = 31_305_656L
    val WATCH_JSON: String =
        LogIndexWatch.serialize(listOf(LogIndexWatch.Entry(POSTAGE_STAMP, POSTAGE_STAMP_DEPLOYED)))

    /** What [installSeedIfAbsent] did on this launch — the Index tab says so when it went wrong. */
    enum class Outcome { INSTALLED, KEPT_EXISTING, NOT_BUNDLED, BAD_CHECKSUM, FAILED }

    @Volatile
    var lastOutcome: Outcome? = null
        private set

    fun enabled(): Boolean = System.getProperty(PROP).toBoolean()

    /** The flavour's own data dir — it never touches a regular Myotis install's `~/.myotis`. */
    fun dataDir(): Path = Path.of(System.getProperty("user.home"), ".myotis-bee-poc")

    /**
     * Install the bundled seed (and its manifest) into [dataDir]. The seed lands when no
     * index file exists there yet, or when the bundled seed is NEWER than the one this
     * flavour installed before (a rebuilt app after the previous seed's shelf life —
     * the manifest's `coveredHigh` is the version); the sha256 is checked against the
     * manifest first. It never touches an index this flavour did not install (no
     * installed manifest), and it must run BEFORE the engine starts: the engine rewrites
     * `logindex-gnosis.db` as its own checkpoint and activates whatever is there.
     * Returns the outcome (also kept in [lastOutcome]).
     */
    fun installSeedIfAbsent(resourcesDir: Path?, dataDir: Path): Outcome {
        val outcome = install(resourcesDir, dataDir)
        lastOutcome = outcome
        installPeerCachesIfAbsent(resourcesDir, dataDir)
        return outcome
    }

    /**
     * Copy each bundled peer cache into [dataDir] when the engine has none there yet.
     * Independent of the seed's outcome, and never over an existing file: the engine
     * rewrites these as it learns, and what it learned beats what we shipped. Returns the
     * names installed on this call.
     */
    fun installPeerCachesIfAbsent(resourcesDir: Path?, dataDir: Path): List<String> {
        val dir = resourcesDir ?: return emptyList()
        return PEER_CACHE_FILES.filter { name ->
            val src = dir.resolve(name)
            val target = dataDir.resolve(name)
            if (!Files.isRegularFile(src)) {
                // The dmg leg asserts the caches are bundled; a dev `run` may lack them.
                log.debug("bee-poc: no bundled {} in {}", name, dir)
                return@filter false
            }
            if (Files.exists(target)) return@filter false
            runCatching {
                Files.createDirectories(dataDir)
                atomicCopy(src, target)
                log.info("bee-poc: installed the bundled warm peer cache {}", target)
                true
            }.onFailure {
                log.warn("bee-poc: could not install peer cache {}: {}", name, it.toString())
                runCatching { Files.deleteIfExists(target.resolveSibling("${target.fileName}.tmp")) }
            }.getOrDefault(false)
        }
    }

    private fun install(resourcesDir: Path?, dataDir: Path): Outcome {
        val dir = resourcesDir ?: return Outcome.NOT_BUNDLED
        val seed = dir.resolve(SEED_FILE)
        val manifest = dir.resolve(MANIFEST_FILE)
        if (!Files.isRegularFile(seed) || !Files.isRegularFile(manifest)) return Outcome.NOT_BUNDLED
        val bundled = loadProps(manifest) ?: return Outcome.NOT_BUNDLED
        val target = dataDir.resolve(SEED_FILE)
        val installedManifest = dataDir.resolve(INSTALLED_MANIFEST_FILE)
        if (Files.exists(target)) {
            val installed = loadProps(installedManifest)
                ?: return Outcome.KEPT_EXISTING // an index this flavour did not install: leave it alone
            val installedHigh = installed.getProperty("coveredHigh")?.toLongOrNull() ?: 0L
            val bundledHigh = bundled.getProperty("coveredHigh")?.toLongOrNull() ?: 0L
            if (bundledHigh <= installedHigh) return Outcome.KEPT_EXISTING
            log.info(
                "bee-poc: the bundled seed (to block {}) is newer than the installed one (to block {}) — re-seeding",
                bundledHigh, installedHigh,
            )
        }
        val expected = bundled.getProperty("sha256")?.lowercase()
        val actual = runCatching { sha256Hex(seed) }.getOrElse {
            log.warn("bee-poc: bundled seed {} is unreadable, previous state kept: {}", seed, it.toString())
            return Outcome.FAILED
        }
        if (expected == null || actual != expected) {
            log.warn("bee-poc: bundled seed {} does not match its manifest sha256 — not installing", seed)
            return Outcome.BAD_CHECKSUM
        }
        return runCatching {
            Files.createDirectories(dataDir)
            atomicCopy(seed, target)
            atomicCopy(manifest, installedManifest)
            log.info(
                "bee-poc: installed the bundled Gnosis log-index seed into {} (coverage {}–{}, usable until block {})",
                target, bundled.getProperty("coveredLow"), bundled.getProperty("coveredHigh"), bundled.getProperty("usableUntilBlock"),
            )
            Outcome.INSTALLED
        }.onFailure {
            // atomicCopy only ever replaces a file with a COMPLETE one (tmp + rename), so
            // whatever `target` holds now is intact — the previous index in the re-seed
            // path, nothing in the fresh path. Never delete it; only sweep the tmp
            // siblings a failed copy or move can leave behind.
            log.warn("bee-poc: seed install into {} failed, previous state kept: {}", dataDir, it.toString())
            for (f in listOf(target, installedManifest)) {
                runCatching { Files.deleteIfExists(f.resolveSibling("${f.fileName}.tmp")) }
            }
        }.getOrDefault(Outcome.FAILED)
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
     * One line for the Index tab about [network]'s seed: what the installed manifest says
     * it covered (the live coverage shown next to it grows from there), or why the bundled
     * seed did not get installed on this launch. Null for other networks and for a regular
     * install. Cheap to call once; callers cache it — nothing here changes after start.
     */
    fun seededIndexNotice(dataDir: Path, network: String): String? {
        if (network != NETWORK) return null
        val props = loadProps(dataDir.resolve(INSTALLED_MANIFEST_FILE))
        if (props == null) {
            return when (lastOutcome) {
                Outcome.BAD_CHECKSUM, Outcome.FAILED, Outcome.NOT_BUNDLED ->
                    "Bee PoC: the bundled seed was NOT installed (${lastOutcome!!.name.lowercase().replace('_', ' ')}; see the log) — " +
                        "this index will backfill from peers instead, which takes days."
                else -> null
            }
        }
        val low = props.getProperty("coveredLow") ?: return null
        val high = props.getProperty("coveredHigh") ?: return null
        val until = props.getProperty("usableUntilBlock") ?: return null
        val logs = props.getProperty("logs") ?: "?"
        return "Bee PoC seed: $logs PostageStamp logs, blocks $low–$high, from a Gnosis full node — " +
            "unverified until the walker re-fetches them (the live coverage below grows from there); " +
            "usable until about block $until, after which a rebuilt app re-seeds."
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
