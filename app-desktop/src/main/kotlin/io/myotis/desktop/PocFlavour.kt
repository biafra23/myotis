package io.myotis.desktop

import io.myotis.ui.LogIndexWatch
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Properties
import java.util.concurrent.ConcurrentHashMap

/** What a flavour's seed install did on this launch — the Index tab says so when it went wrong. */
enum class SeedOutcome { INSTALLED, KEPT_EXISTING, NOT_BUNDLED, BAD_CHECKSUM, FAILED }

/**
 * One network a [PocFlavour] seeds: the log index it bundles for that network, the names
 * it lands under, and what the flavour configures for the network.
 *
 * @param network the network this seed is for, which the flavour enables
 * @param seedFile the engine's OWN drop-in name for [network]'s index
 *   (`dataDir/logindex-<network>.db`, mainnet without the suffix), derived in
 *   `rust/myotis-engine/src/host.rs` (`log_index_path`) and activated at engine start by
 *   `activate_log_index_from_disk`. A rename on the engine side must be mirrored here or
 *   the seed is silently never opened.
 * @param manifestFile the bundled manifest beside the seed
 * @param installedManifestFile the manifest's copy in the data dir — how the UI knows the
 *   index was seeded, and how a re-seed compares versions
 * @param peerCacheFiles warm peer caches bundled beside the seed, in the engine's own
 *   formats and under the engine's own data-dir names. Public addresses only; the engine
 *   re-verifies every peer it dials, so these shortcut discovery rather than grant trust.
 *   May be empty for a network that ships none.
 * @param watchAddress the contract the seed indexes
 * @param watchDeployBlock its REAL deployment block. `from_block` is the engine's "no logs
 *   below here" assertion, so this must never be the seed's fetched low edge: below it the
 *   engine answers `[]` WITHOUT consulting coverage, and a plausible empty answer is worse
 *   than the `-32000` refusal an out-of-coverage range gets.
 * @param seedSubject what the seed's logs are, for the Index tab line
 * @param seedSource where they came from, for the Index tab line
 * @param rpcPort the port the flavour pins for [network], or null to keep that network's
 *   default. A network a REGULAR install also serves needs one: otherwise both apps want
 *   the same port, the second to start cannot bind it, and a client aimed at that port
 *   silently reaches whichever won — for a PoC, an install with no seeded index, which
 *   answers the demo's own queries with -32000.
 */
class PocSeed(
    val network: String,
    val seedFile: String,
    val manifestFile: String,
    val installedManifestFile: String,
    val peerCacheFiles: List<String>,
    val watchAddress: String,
    val watchDeployBlock: Long,
    val seedSubject: String,
    val seedSource: String,
    val rpcPort: Int? = null,
) {
    /** The seed's watch entry, as the Index tab and the engine both read it. */
    val watchJson: String =
        LogIndexWatch.serialize(listOf(LogIndexWatch.Entry(watchAddress, watchDeployBlock)))
}

/**
 * A **seeded proof-of-concept flavour** of the desktop app: a Myotis one specific consumer
 * can point at IMMEDIATELY, because the log index it needs is bundled in the app bundle
 * instead of being walked over devp2p for days.
 *
 * Two of them exist ([BeePoc] for a Swarm Bee full node on Gnosis, [RailgunPoc] for the
 * RAILGUN Terminal Wallet on mainnet and Sepolia). Everything that differs between them is
 * a constructor parameter, per network a [PocSeed]; everything below is shared, because
 * the install, re-seed, checksum and first-start rules were all learned the hard way on
 * the Bee build and a second copy of them would drift.
 *
 * Each flavour lives in its own data dir and under its own bundle id, so it never touches
 * a regular install's `~/.myotis` or the other flavour's dir, and all of it is a no-op
 * unless the packaged app carries that flavour's `-D` property.
 *
 * DEBUG / DEMO artefact, not a production path: a seed is a full node's `eth_getLogs`
 * output framed by `scripts/synth_logindex.py`, unverified until the walker re-fetches it,
 * and it expires ~500,000 blocks after its fetch — the manifest carries the block it is
 * usable until.
 *
 * @param prop the system property the packaged app sets to select this flavour
 * @param label how the flavour names itself in logs and in the Index tab
 * @param dataDirName the flavour's own directory under the user's home
 * @param seeds one per network the flavour seeds and enables; the first is its primary
 *   network, the one a first start lists first
 * @param pauseBackfillByDefault whether a network with no stored preference starts with the
 *   downward walk stopped
 */
open class PocFlavour(
    val prop: String,
    val label: String,
    val dataDirName: String,
    val seeds: List<PocSeed>,
    val pauseBackfillByDefault: Boolean,
) {
    init {
        require(seeds.isNotEmpty()) { "$prop: a flavour seeds at least one network" }
        // Each network's seed lands under that network's names, so two seeds for one
        // network would overwrite each other in the data dir.
        require(seeds.map { it.network }.distinct().size == seeds.size) { "$prop: one seed per network" }
    }

    /** The network a first start lists first — the flavour's original one. */
    val primaryNetwork: String get() = seeds.first().network

    fun seedFor(network: String): PocSeed? = seeds.firstOrNull { it.network == network }

    /** What each network's seed install did on this launch, for [seededIndexNotice]. */
    private val lastOutcomes = ConcurrentHashMap<String, SeedOutcome>()

    fun enabled(): Boolean = System.getProperty(prop).toBoolean()

    /**
     * Whether a network with no stored preference should have its log-index backfill
     * PAUSED — true in this flavour when [pauseBackfillByDefault], false in a regular
     * install.
     *
     * A PoC serves exactly one consumer whose history need the seed already covers, so the
     * downward walk fetches data that consumer cannot use while competing for the snap pool
     * head-follow needs. Measured on the Bee build (zbox, 2026-09-19): the walk ran at
     * ~1000 blocks/min while head-follow managed 3-4.5 against a chain doing 12, coverage
     * fell behind, and Bee shut itself down with "postage syncing stalled".
     *
     * Pausing is the honest lever. Raising the watch entry's fromBlock to the coverage
     * floor would stop the walk too, but `fromBlock` asserts the contract has NO logs below
     * it, so queries down there would answer an empty list. Paused, they keep getting
     * `OutOfCoverage` — an error the caller can act on.
     */
    fun backfillPausedDefault(): Boolean = enabled() && pauseBackfillByDefault

    /** The flavour's own data dir — it never touches a regular install's `~/.myotis`. */
    fun dataDir(): Path = Path.of(System.getProperty("user.home"), dataDirName)

    /**
     * Install each network's bundled seed (and its manifest) into [dataDir]. A seed lands
     * when no index file exists there yet for its network, or when the bundled seed is
     * NEWER than the one this flavour installed before (a rebuilt app after the previous
     * seed's shelf life — the manifest's `coveredHigh` is the version); the sha256 is
     * checked against the manifest first. It never touches an index this flavour did not
     * install (no installed manifest), and it must run BEFORE the engine starts: the engine
     * rewrites the seed file as its own checkpoint and activates whatever is there. Returns
     * each network's outcome (also kept for [seededIndexNotice]).
     */
    fun installSeedsIfAbsent(resourcesDir: Path?, dataDir: Path): Map<String, SeedOutcome> {
        val outcomes = seeds.associate { seed ->
            seed.network to install(seed, resourcesDir, dataDir).also { lastOutcomes[seed.network] = it }
        }
        installPeerCachesIfAbsent(resourcesDir, dataDir)
        return outcomes
    }

    /**
     * Copy each bundled peer cache into [dataDir] when the engine has none there yet.
     * Independent of the seeds' outcomes, and never over an existing file: the engine
     * rewrites these as it learns, and what it learned beats what we shipped. Returns the
     * names installed on this call.
     */
    fun installPeerCachesIfAbsent(resourcesDir: Path?, dataDir: Path): List<String> {
        val dir = resourcesDir ?: return emptyList()
        return seeds.flatMap { it.peerCacheFiles }.filter { name ->
            val src = dir.resolve(name)
            val target = dataDir.resolve(name)
            if (!Files.isRegularFile(src)) {
                // The dmg leg asserts the caches are bundled; a dev `run` may lack them.
                log.debug("{}: no bundled {} in {}", logTag, name, dir)
                return@filter false
            }
            if (Files.exists(target)) return@filter false
            runCatching {
                Files.createDirectories(dataDir)
                atomicCopy(src, target)
                log.info("{}: installed the bundled warm peer cache {}", logTag, target)
                true
            }.onFailure {
                log.warn("{}: could not install peer cache {}: {}", logTag, name, it.toString())
                runCatching { Files.deleteIfExists(target.resolveSibling("${target.fileName}.tmp")) }
            }.getOrDefault(false)
        }
    }

    private fun install(spec: PocSeed, resourcesDir: Path?, dataDir: Path): SeedOutcome {
        val dir = resourcesDir ?: return SeedOutcome.NOT_BUNDLED
        val seed = dir.resolve(spec.seedFile)
        val manifest = dir.resolve(spec.manifestFile)
        if (!Files.isRegularFile(seed) || !Files.isRegularFile(manifest)) return SeedOutcome.NOT_BUNDLED
        val bundled = loadProps(manifest) ?: return SeedOutcome.NOT_BUNDLED
        val target = dataDir.resolve(spec.seedFile)
        val installedManifest = dataDir.resolve(spec.installedManifestFile)
        if (Files.exists(target)) {
            val installed = loadProps(installedManifest)
                ?: return SeedOutcome.KEPT_EXISTING // an index this flavour did not install: leave it alone
            val installedHigh = installed.getProperty("coveredHigh")?.toLongOrNull() ?: 0L
            val bundledHigh = bundled.getProperty("coveredHigh")?.toLongOrNull() ?: 0L
            if (bundledHigh <= installedHigh) return SeedOutcome.KEPT_EXISTING
            // NOTE (raised in review of #477, deferred to the owner): a newer bundled
            // seed can still be BEHIND the live index. The engine rewrites this same
            // file as its own checkpoint, so after a long run head-follow has taken it
            // past the manifest written at install time — and on RAILGUN's 69-day
            // mainnet shelf life that window is wide. Overwriting then replaces a
            // further-along index with a shorter frame, and queries in the difference
            // turn from served into -32000 until the bridge re-walks it.
            //
            // Deciding that needs the live index's own coverage, which only the engine
            // can read; a file-timestamp proxy was tried and rejected (it is
            // platform-dependent — it never fired on ext4 and always fired on APFS).
            // The shipped Bee behaviour, which these tests pin, is to re-seed, and
            // changing it is the owner's call rather than this PR's.
            log.info(
                "{}: the bundled {} seed (to block {}) is newer than the installed one (to block {}) — re-seeding",
                logTag, spec.network, bundledHigh, installedHigh,
            )
        }
        val expected = bundled.getProperty("sha256")?.lowercase()
        val actual = runCatching { sha256Hex(seed) }.getOrElse {
            log.warn("{}: bundled seed {} is unreadable, previous state kept: {}", logTag, seed, it.toString())
            return SeedOutcome.FAILED
        }
        if (expected == null || actual != expected) {
            log.warn("{}: bundled seed {} does not match its manifest sha256 — not installing", logTag, seed)
            return SeedOutcome.BAD_CHECKSUM
        }
        return runCatching {
            Files.createDirectories(dataDir)
            atomicCopy(seed, target)
            atomicCopy(manifest, installedManifest)
            log.info(
                "{}: installed the bundled {} log-index seed into {} (coverage {}–{}, usable until block {})",
                logTag, spec.network, target,
                bundled.getProperty("coveredLow"), bundled.getProperty("coveredHigh"),
                bundled.getProperty("usableUntilBlock"),
            )
            SeedOutcome.INSTALLED
        }.onFailure {
            // atomicCopy only ever replaces a file with a COMPLETE one (tmp + rename), so
            // whatever `target` holds now is intact — the previous index in the re-seed
            // path, nothing in the fresh path. Never delete it; only sweep the tmp
            // siblings a failed copy or move can leave behind.
            log.warn("{}: {} seed install into {} failed, previous state kept: {}", logTag, spec.network, dataDir, it.toString())
            for (f in listOf(target, installedManifest)) {
                runCatching { Files.deleteIfExists(f.resolveSibling("${f.fileName}.tmp")) }
            }
        }.getOrDefault(SeedOutcome.FAILED)
    }

    /**
     * Make the PoC boot straight into its purpose: each seeded network enabled with its log
     * index on, the seed's watch entry visible in the Index tab, and its port pinned.
     *
     * Each seeded network is configured ONCE, by the first start that finds it unconfigured.
     * On the flavour's genuinely first start ([firstStart] = no settings file existed yet)
     * that is every seeded network, and the networks a regular install may start by default
     * are switched off. On a later start it is only a network whose seed this build bundles
     * and the install has never configured — an install that predates that network's seed —
     * so updating the app brings the new network up exactly as a fresh install would.
     * Nothing else a later start touches: in particular, it must never persist
     * `logIndex.<network>=false`, which would push a disable to the engine and turn the
     * seeded index off (queries → -32000), and a network the user turned off after it was
     * configured stays off.
     *
     * What has been configured is recorded in the settings file
     * ([DesktopSettings.pocConfiguredNetworks]), so deleting that file starts over. An install
     * from before the record existed had configured exactly its [primaryNetwork], at its
     * first start.
     */
    fun applyFirstStartSettings(settings: DesktopSettings, firstStart: Boolean) {
        val done = if (firstStart) emptySet() else settings.pocConfiguredNetworks() ?: setOf(primaryNetwork)
        val todo = seeds.filter { it.network !in done }
        if (todo.isEmpty()) return
        if (firstStart) {
            for (other in OTHER_NETWORKS) if (seedFor(other) == null) settings.setNetworkEnabled(other, false)
        }
        for (seed in todo) {
            settings.setNetworkEnabled(seed.network, true)
            seed.rpcPort?.let { settings.setRpcPort(seed.network, it) }
            settings.setLogIndexEnabled(seed.network, true)
            settings.setLogIndexWatchJson(seed.network, seed.watchJson)
            // Explicit, so the Index tab's switch shows the state the flavour runs in
            // rather than an unset default (see backfillPausedDefault for why).
            settings.setLogIndexBackfillPaused(seed.network, pauseBackfillByDefault)
        }
        settings.setPocConfiguredNetworks(done + todo.map { it.network })
    }

    /**
     * One line for the Index tab about [net]'s seed: what the installed manifest says it
     * covered (the live coverage shown next to it grows from there), or why the bundled
     * seed did not get installed on this launch. Null for networks this flavour does not
     * seed and for a regular install. Cheap to call once; callers cache it — nothing here
     * changes after start.
     */
    fun seededIndexNotice(dataDir: Path, net: String): String? {
        val seed = seedFor(net) ?: return null
        val props = loadProps(dataDir.resolve(seed.installedManifestFile))
        if (props == null) {
            return when (val outcome = lastOutcomes[net]) {
                SeedOutcome.BAD_CHECKSUM, SeedOutcome.FAILED, SeedOutcome.NOT_BUNDLED ->
                    "$label: the bundled seed was NOT installed " +
                        "(${outcome.name.lowercase().replace('_', ' ')}; see the log) — " +
                        "this index will backfill from peers instead, which takes days."
                else -> null
            }
        }
        val low = props.getProperty("coveredLow") ?: return null
        val high = props.getProperty("coveredHigh") ?: return null
        val until = props.getProperty("usableUntilBlock") ?: return null
        val logs = props.getProperty("logs") ?: "?"
        return "$label seed: $logs ${seed.seedSubject}, blocks $low–$high, from ${seed.seedSource} — " +
            "unverified until the walker re-fetches them (the live coverage below grows from there); " +
            "usable until about block $until, after which a rebuilt app re-seeds."
    }

    private val logTag: String get() = prop.substringAfterLast('.')

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

    private companion object {
        /**
         * The networks a first start explicitly switches OFF unless the flavour seeds them,
         * so a flavour boots into its own networks rather than whatever the defaults enable.
         * Only networks a regular install may start by default need to be here.
         */
        val OTHER_NETWORKS = listOf("mainnet", "gnosis")

        // Lazy on purpose: Main.kt redirects a flavour's logs (myotis.logdir) before the
        // first log call, and logback fixes its file location at first use — an eager
        // logger here would initialise it when `enabled()` is first touched.
        val log: org.slf4j.Logger by lazy { org.slf4j.LoggerFactory.getLogger(PocFlavour::class.java) }
    }
}

/**
 * The flavour this process was built as, if any.
 *
 * Exactly one may be active: the flavours disagree about which network to enable and which
 * data dir to own, so a build that somehow set both properties would half-apply each. That
 * is a packaging mistake rather than a user error, so it fails loudly at start instead of
 * picking one.
 */
object Poc {
    val ALL: List<PocFlavour> = listOf(BeePoc, RailgunPoc)

    fun active(): PocFlavour? {
        val on = ALL.filter { it.enabled() }
        require(on.size <= 1) {
            "more than one PoC flavour is enabled (${on.joinToString { it.prop }}) — a build sets exactly one"
        }
        return on.firstOrNull()
    }
}
