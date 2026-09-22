// :app-desktop — the Compose-Multiplatform DESKTOP app. Hosts the shared `:ui` NodeScreen
// and drives the Java backend (`node-core`) in-process via DesktopNodeController — the same
// backend the daemon and Android use, so there's no duplication. (JVM target; not iOS.)

import org.gradle.api.tasks.PathSensitivity
import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin { jvmToolchain(21) }

// Installer versions, DERIVED from the project version so a release sweep can't
// leave an installer stamped with the previous release (v0.1.0–v0.1.3 all shipped
// a dmg hardcoded to "1.0.0", so every macOS bundle reported the same frozen
// version in About / Get Info regardless of the release it came from).
val releaseVersion = project.version.toString().substringBefore('-')  // 0.1.4-SNAPSHOT -> 0.1.4

// jpackage REJECTS a major of 0 on macOS (--app-version must start above 0), so
// the .dmg cannot carry the honest 0.x version. The rule is therefore: macOS
// MAJOR is always the project MAJOR plus one (0.1.4 -> 1.1.4, 1.0.0 -> 2.0.0).
//
// Adding a constant to the major is order-preserving, so the emitted version is
// strictly increasing for every version bump, forever — which is what macOS
// needs to treat a new bundle as an upgrade rather than a downgrade. Two wrong
// rules it deliberately avoids:
//   - "1.0.<patch>" reads closest to the real version but breaks on a minor
//     bump: 0.2.0 would emit 1.0.0, LOWER than 0.1.4's 1.0.4.
//   - "1.<minor>.<patch>" for 0.x only (what this started as) is fine within
//     0.x but falls off a cliff at the real 1.0.0, which emits 1.0.0 — lower
//     than every 1.x already shipped for late 0.x (0.9.0 -> 1.9.0). Silent
//     downgrade, and it only surfaces years later.
// The +1 rule has no cliff and needs no revisiting at 1.0, so nothing here
// depends on someone re-reading this comment before the transition.
val macOsPackageVersion: String = releaseVersion.split('.').let { parts ->
    require(parts.size == 3 && parts.all { it.toIntOrNull() != null }) {
        "Unexpected project version '${project.version}': expected numeric MAJOR.MINOR.PATCH"
    }
    "${parts[0].toInt() + 1}.${parts[1]}.${parts[2]}"
}

// Historical (Besu ≤24.12; 26.4 targets tuweni 2.7.2 so io.tmio is gone from the
// graph — the exclude stays as a cheap guard):
// Besu (via :myotis-evm) dragged in the pre-rename tuweni coordinates io.tmio:tuweni-* 2.4.2,
// whose org.apache.tuweni.bytes.Bytes collides with the JitPack Kotlin fork we use
// (com.github.biafra23.tuweni-kotlin 2.7.2). A single classloader loads only ONE Bytes for
// that FQN: tuweni-rlp 2.7.2 (BytesRLPWriter.kt) needs the 2.7.2 Bytes' Kotlin `Companion`,
// which the 2.4.2 class lacks → NoSuchFieldError at launch. The `gradle run` daemon happens
// to load the 2.7.2 jar first; jpackage's flattened classpath lets the 2.4.2 one win. Strip
// io.tmio so only one tuweni 2.7.2 remains (same packages; Besu already runs against 2.7.2 on
// the daemon, so 2.4.2 is unneeded) — mirrors the :android-app exclusion.
// (Historical: while the Kotlin tuweni/netty forks were in use, io.consensys.tuweni and
// io.netty were also excluded here to prevent duplicate-class crashes in the flattened
// jpackage bundle. Upstream is canonical again, so those excludes are gone — a single
// source per class.)
configurations.all {
    exclude(group = "io.tmio")
}

dependencies {
    implementation(project(":ui"))

    // The shared backend + the daemon's file-backed cache adapters / CCIP gateway, reused.
    implementation(project(":node-core"))
    // Engine selector: DesktopNodeController defaults to Engines.engine().
    implementation(project(":myotis-engines"))
    implementation(project(":app"))
    // TrueBlocks tx-history scan for the Query tab (documented API-boundary exemption:
    // it reaches the raw connector via SelectorEngine.javaDelegate().debugStack).
    implementation(project(":tx-history"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    // EnsResolutionRoot is referenced directly when calling rpcBackend().resolveEns(...).
    implementation(project(":myotis-ens"))
    implementation(project(":rpc-backend"))
    // VerifiedRpcBackend implements jsonrpc-server's MyotisRpcBackend; calling
    // verifiedHeadAgeMs() forces Kotlin to resolve that supertype, so it must be on the
    // compile classpath (rpc-backend exposes VerifiedRpcBackend only as `implementation`).
    implementation(project(":jsonrpc-server"))
    implementation(project(":core"))

    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.core)
    // AppNap.kt talks to the Objective-C runtime through JNA (already on the classpath
    // transitively for the Rust engine; declared here because the app uses it directly).
    implementation(libs.jna)

    // implementation (not runtimeOnly): DesktopLogAppender compiles against logback's
    // AppenderBase/ILoggingEvent to tee logs into the in-app Logs tab's in-memory ring.
    implementation(libs.logback.classic)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // The Compose plugin drags an older junit-platform-launcher onto the test runtime
    // classpath; pin the bom-aligned one or the jupiter engine fails discovery
    // ("OutputDirectoryProvider not available … unaligned versions").
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// This module skips the root `java`-plugin conventions (Compose brings its own plugins),
// so wire the JUnit platform here like :app does.
tasks.withType<Test> {
    useJUnitPlatform()
}

// Headless check that the Desktop controller drives node-core (no display needed).
tasks.register<JavaExec>("syncSmoke") {
    group = "verification"
    description = "Start the primary network in-process and exit 0 on SYNCED (no GUI)."
    mainClass.set("io.myotis.desktop.SyncSmokeKt")
    classpath = sourceSets["main"].runtimeClasspath
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
    systemProperty("myotis.logfile", rootProject.file("devp2p.log").absolutePath)
}

// ---------------------------------------------------------------------------
// Bundle the Rust engine into PACKAGED desktop apps (dmg/deb/distributable):
// cargoBuildHost's host lib is staged into Compose's appResources under the
// current os-arch subdir; jpackage ships that dir inside the app and exposes
// it at runtime via the `compose.application.resources.dir` system property,
// which Main.kt forwards to the engine loader (-Dmyotis.engine.lib). Dev
// `run`/`syncSmoke` keep their absolute-path wiring below and never bake a
// path into packages. FAIL-LOUD: packaging without cargo must error, never
// silently ship a Java-only app with a dead engine toggle (same philosophy
// as the APK workflow's self-skip guard).
// ---------------------------------------------------------------------------
val rustHostLibName = rootProject.extra["rustEngineLibName"] as String
val rustReleaseDir = rootProject.extra["rustReleaseDir"] as String
val composeOsArchDir = run {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val osPart = when {
        os.contains("mac") -> "macos"
        os.contains("win") -> "windows"
        else -> "linux"
    }
    val archPart = if (arch == "aarch64" || arch == "arm64") "arm64" else "x64"
    "$osPart-$archPart"
}

// The Bee PoC flavour flag: bare `-PbeePoc` or `-PbeePoc=true` builds the PoC
// (see the Bee PoC section below), `-PbeePoc=false` a regular build. Anything
// else is refused rather than quietly building the regular flavour — a flag
// that changes the artifact must be applied or rejected, never ignored.
fun flavourFlag(name: String): Boolean = providers.gradleProperty(name)
    .map { raw ->
        when (raw.trim().lowercase()) {
            "", "true" -> true
            "false" -> false
            else -> throw GradleException("-P$name must be bare, =true or =false (got '$raw')")
        }
    }
    .getOrElse(false)

val beePoc: Boolean = flavourFlag("beePoc")

// The RAILGUN PoC flavour flag (-PrailgunPoc): bundles the mainnet
// RailgunSmartWallet log-index seed so the RAILGUN Terminal Wallet can use the
// app instead of a public RPC provider from the first minute (RailgunPoc.kt,
// docs/railgun-poc.md). Same accept-or-refuse rule as -PbeePoc.
val railgunPoc: Boolean = flavourFlag("railgunPoc")

// Exactly one flavour, or none. The two disagree about which network to enable
// and which data dir to own, so a build with both would produce an app that
// half-applies each — a packaging mistake, caught here rather than at runtime.
if (beePoc && railgunPoc) {
    throw GradleException("-PbeePoc and -PrailgunPoc are mutually exclusive — build one flavour at a time")
}

/** The active flavour's staging root name and the seed files only it may ship. */
val pocFlavourName: String? = when {
    beePoc -> "beePoc"
    railgunPoc -> "railgunPoc"
    else -> null
}

// Single source of truth for the staged-resources root: the staging tasks'
// outputs, Compose's appResourcesRootDir, and the packaging tasks' input all
// derive from it (a drifting duplicate literal would silently untrack). It is
// FLAVOUR-SPECIFIC: the two flavours never share a staging dir, so a regular
// build cannot ship a seed a -PbeePoc build staged earlier.
val rustAppResourcesRoot =
    layout.buildDirectory.dir(pocFlavourName?.let { "${it}AppResources" } ?: "rustAppResources")

val prepareRustAppResources = tasks.register("prepareRustAppResources") {
    group = "build"
    description = "Stage the Rust engine host lib into Compose appResources for packaging"
    dependsOn(rootProject.tasks.named("cargoBuildHost"))
    val src = rootProject.file("$rustReleaseDir/$rustHostLibName")
    val destDir = rustAppResourcesRoot.map { it.dir(composeOsArchDir) }
    inputs.files(src).optional() // optional so the ACTION runs even when absent
    outputs.dir(destDir)
    // A plain task, NOT Copy: a Copy with a missing source is skipped as
    // NO-SOURCE — actions included — so its doLast guard never fires and
    // packaging silently ships a Java-only app (empirically reproduced in
    // review). Plain-task actions always run; the check below is the real
    // fail-loud gate.
    doLast {
        check(src.isFile) {
            "Rust engine lib missing ($src) — packaging requires cargo " +
                "(cargoBuildHost self-skipped?). A packaged app must never " +
                "silently ship without the Rust engine."
        }
        copy {
            from(src)
            into(destDir)
        }
        // The regular app must never carry the Bee PoC seed. The flavours stage
        // into different roots, but a root that predates that split (or a stray
        // copy) would be synced into the bundle unnoticed — scrub it here, on
        // every regular staging run.
        if (pocFlavourName == null) {
            val common = rustAppResourcesRoot.get().dir("common").asFile
            listOf(
                "logindex-gnosis.db", "bee-poc-seed.properties", "peers-gnosis.cache", "cl-peers-gnosis.cache",
                "logindex.db", "railgun-poc-seed.properties",
            ).forEach { common.resolve(it).delete() }
        }
    }
}

// ---------------------------------------------------------------------------
// JNA's own native stub. JNA normally extracts libjnidispatch from its jar into
// ~/Library/Caches/JNA/temp at runtime and dlopens it from there. A jpackage'd
// app is ad-hoc signed with library validation, and macOS refuses that
// unsigned temp file ("Trying to load an unsigned library") — so the Rust
// engine silently never loaded in the packaged desktop app (observed on macOS
// 15.7 with the Bee PoC dmg, 2026-09-15: RustEngineNative logged the dlopen
// failure and SelectorEngine fell back to the Java engine, which has no log
// index). Staging the stub next to the engine dylib — under a `.dylib` name,
// because jpackage's signing pass signs `*.dylib` and executables but leaves a
// 0644 `.jnilib` untouched, and JNA's boot-path lookup tries both names —
// gets it ad-hoc signed with the rest of the bundle, and
// `-Djna.boot.library.path=$APPDIR/resources` (below) makes JNA load it from
// there instead of extracting. Dev runs see a literal, nonexistent `$APPDIR`
// and JNA falls back to extraction, which a plain JDK process may do.
// ---------------------------------------------------------------------------
val prepareJnaBootLib = tasks.register("prepareJnaBootLib") {
    group = "build"
    description = "Stage JNA's native stub into Compose appResources so the packaged app can load the Rust engine"
    val destDir = rustAppResourcesRoot.map { it.dir(composeOsArchDir) }
    // The exact artifact the version catalog pins, resolved on its own rather
    // than found by a name-prefix scan of the runtime classpath.
    val jnaJar = configurations.detachedConfiguration(
        dependencies.create("net.java.dev.jna:jna:${libs.versions.jna.get()}@jar"),
    ).also { it.isTransitive = false }
    val osPart = composeOsArchDir.substringBefore('-')
    val daemonArm = composeOsArchDir.substringAfter('-') == "arm64"
    val (entry, stagedName) = when (osPart) {
        "macos" -> (if (daemonArm) "com/sun/jna/darwin-aarch64/libjnidispatch.jnilib" else "com/sun/jna/darwin-x86-64/libjnidispatch.jnilib") to "libjnidispatch.dylib"
        "linux" -> (if (daemonArm) "com/sun/jna/linux-aarch64/libjnidispatch.so" else "com/sun/jna/linux-x86-64/libjnidispatch.so") to "libjnidispatch.so"
        "windows" -> "com/sun/jna/win32-x86-64/jnidispatch.dll" to "jnidispatch.dll"
        else -> error("no JNA native stub mapping for $composeOsArchDir")
    }
    val staged = destDir.map { it.file(stagedName) }
    // The packaged app's architecture is the jpackage toolchain JDK's, while
    // Compose picks the Skiko natives — and this task picks the stub — by the
    // Gradle daemon's. A mixed pair packages an app that dies at launch
    // ("Can't load library: libskiko-macos-<arch>.dylib"): seen on a Mac that
    // ran Gradle under an x86_64 JDK 17 with an aarch64 JDK 21 toolchain. The
    // CI legs pin both to one arch; locally, fail loudly instead of shipping it.
    val toolchainArch = javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(21))
    }.map { launcher ->
        val release = launcher.metadata.installationPath.asFile.resolve("release")
        runCatching { Regex("OS_ARCH=\"([^\"]+)\"").find(release.readText())?.groupValues?.get(1) }
            .getOrNull()?.lowercase() ?: "unknown"
    }
    inputs.files(jnaJar)
    inputs.property("osArch", composeOsArchDir)
    inputs.property("toolchainArch", toolchainArch)
    outputs.file(staged)
    doLast {
        val tc = toolchainArch.get()
        check(tc == "unknown" || (tc in setOf("aarch64", "arm64")) == daemonArm) {
            "Gradle runs under a ${System.getProperty("os.arch")} JVM but the JDK 21 toolchain jpackage uses " +
                "is $tc: the packaged app would mix native libraries and die at launch. Run Gradle under a JDK " +
                "of the target architecture (JAVA_HOME=<that JDK> plus " +
                "-Porg.gradle.java.installations.paths=\$JAVA_HOME, as the dmg workflow does)."
        }
        val jar = jnaJar.singleFile
        copy {
            from(zipTree(jar)) { include(entry) }
            into(destDir)
            // Flatten com/sun/jna/<platform>/ away and apply the signable name:
            // JNA's boot path is a plain dir.
            eachFile { path = stagedName }
            includeEmptyDirs = false
        }
        check(staged.get().asFile.isFile) { "JNA native stub $entry not found in $jar" }
    }
}

// ---------------------------------------------------------------------------
// Bee PoC flavour (-PbeePoc): bundle the Gnosis PostageStamp log-index seed so
// a Swarm Bee full node can use the app from the first minute (BeePoc.kt;
// docs/bee-rpc-service.md, "Bee PoC desktop build"). The seed is synthesized
// at build time from the committed data set by scripts/synth_logindex.py and
// staged into appResources/common/ (Compose flattens common/ next to the
// os-arch dir) beside a manifest — coverage, expiry, sha256 — that the app
// checks before installing it. DEBUG/DEMO artefact: RPC-sourced data,
// unverified until the walker re-fetches it, expiring ~500,000 Gnosis blocks
// (~29 days) after its fetch. Only runs for -PbeePoc; the flavour-specific
// resources root above keeps a regular build from ever shipping the seed.
// ---------------------------------------------------------------------------
// Compose flattens appResources/common/ next to the os-arch dir; both
// flavours stage their seed there, into their own flavour-specific root.
val pocSeedDir = rustAppResourcesRoot.map { it.dir("common") }

// The PostageStamp contract at its REAL deployment block — never the seed's
// fetched low edge (from_block is the engine's "no logs below here" assertion).
val beePocWatch = "0x45a1502382541Cd610CC9068e88727426b696293:31305656"

val prepareBeePocSeed = tasks.register("prepareBeePocSeed") {
    group = "build"
    description = "Synthesize the Bee PoC Gnosis log-index seed from data/bee/gnosis and stage it, with the warm peer caches, into Compose appResources (-PbeePoc only)"
    onlyIf { beePoc }
    val meta = rootProject.file("data/bee/gnosis/postagestamp-logs-47000000-48262804.meta.json")
    val logs = rootProject.file("data/bee/gnosis/postagestamp-logs-47000000-48262804.jsonl.gz")
    val script = rootProject.file("scripts/synth_logindex.py")
    val seed = pocSeedDir.map { it.file("logindex-gnosis.db") }
    val manifest = pocSeedDir.map { it.file("bee-poc-seed.properties") }
    // Warm peer caches (the engine's own tab/multiaddr text formats, public
    // peers only): a cold Gnosis pool is the PoC's other failure mode — on
    // 2026-09-15 it sank to one unresponsive snap peer for ten minutes, the
    // index stopped following the head and Bee's stall rule shut it down.
    val peerCaches = listOf("peers-gnosis.cache", "cl-peers-gnosis.cache")
    val cacheSources = peerCaches.map { rootProject.file("data/bee/gnosis/$it") }
    inputs.files(meta, logs, script, cacheSources)
    // Same reason as the RAILGUN task: the watch assertion is not a file and the
    // build script is not a task input, so without this a corrected deployment block
    // would leave the task UP-TO-DATE and ship the previous frame.
    inputs.property("watch", beePocWatch)
    outputs.files(seed, manifest, peerCaches.map { n -> pocSeedDir.map { it.file(n) } })
    doLast {
        pocSeedDir.get().asFile.mkdirs()
        cacheSources.forEach { src ->
            check(src.isFile && src.length() > 0) { "bee-poc: warm peer cache missing or empty: $src" }
            src.copyTo(pocSeedDir.get().asFile.resolve(src.name), overwrite = true)
        }
        val cmd = listOf(
            "python3", script.absolutePath,
            "--meta", meta.absolutePath,
            "--logs", logs.absolutePath,
            // The REAL deployment block: from_block is the engine's "no logs
            // below here" assertion, never the seed's fetched low edge.
            "--watch", beePocWatch,
            "--out", seed.get().asFile.absolutePath,
            // The script describes what it wrote (coverage, usable-until block,
            // sha256) — the manifest BeePoc.kt checks before installing.
            "--manifest", manifest.get().asFile.absolutePath,
        )
        val proc = ProcessBuilder(cmd).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
        val stderr = proc.errorStream.bufferedReader().readText()
        check(proc.waitFor() == 0 && seed.get().asFile.isFile && manifest.get().asFile.isFile) {
            "bee-poc: scripts/synth_logindex.py failed (python3 required):\n$stderr"
        }
        val summary = manifest.get().asFile.readLines()
            .filter { it.startsWith("covered") || it.startsWith("usableUntil") || it.startsWith("logs=") }
            .joinToString(", ")
        logger.lifecycle("bee-poc: staged ${seed.get().asFile.name} — $summary")
    }
}

// ---------------------------------------------------------------------------
// RAILGUN PoC flavour (-PrailgunPoc): bundle the mainnet RailgunSmartWallet
// log-index seed so the RAILGUN Terminal Wallet can be pointed at this app
// instead of a public RPC provider (RailgunPoc.kt; docs/railgun-poc.md).
//
// The seed data is NOT committed, unlike the Bee flavour's. The Bee set is a
// 58 MB gzip of ~39k logs; RAILGUN's is 426k logs over 11.3M blocks — 549 MB
// raw, and a git object nobody wants in a clone. So this task reads the fetch
// from a directory given by -PrailgunSeedDir (default ~/myotis-node/railgun),
// produced by the fetch described in docs/railgun-poc.md, and fails with that
// instruction when it is not there. A missing seed must never degrade into a
// silently seedless "RAILGUN PoC" build that then backfills for days.
// ---------------------------------------------------------------------------
val railgunSeedDir: File = providers.gradleProperty("railgunSeedDir")
    .map { file(it) }
    .getOrElse(File(System.getProperty("user.home"), "myotis-node/railgun"))

// The REAL deployment block, and the chain agrees: the proxy's first log is at
// exactly 14737691 and a sweep from genesis found none below it. `from_block` is
// the engine's "no logs below here" assertion, so a lower value here turns real
// history into plausible empty answers (docs/railgun-poc.md spells this out).
val railgunWatch = "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9:14737691"

val prepareRailgunPocSeed = tasks.register("prepareRailgunPocSeed") {
    group = "build"
    description = "Synthesize the RAILGUN PoC mainnet log-index seed from -PrailgunSeedDir and stage it into Compose appResources (-PrailgunPoc only)"
    onlyIf { railgunPoc }
    val script = rootProject.file("scripts/synth_logindex.py")
    val seed = pocSeedDir.map { it.file("logindex.db") }
    val manifest = pocSeedDir.map { it.file("railgun-poc-seed.properties") }
    val seedDir = railgunSeedDir
    inputs.files(script)
    // A fileTree behind a provider, NOT inputs.dir: a missing dir makes Gradle fail
    // validation with "an input file was expected to be present", which buries the
    // instruction the developer actually needs. Absent here means no inputs, and the
    // doLast check below is the fail-loud gate that names the fix.
    //
    // NARROWED to the fetch's own files on purpose: the docs tell developers to run
    // the framing script by hand in this directory to inspect the result, which drops
    // a ~243 MB logindex.db and a manifest beside the ~549 MB jsonl. Fingerprinting
    // the whole tree would re-hash ~800 MB on every up-to-date check and mark the
    // task dirty after each manual inspection.
    inputs.files(
        provider {
            if (seedDir.isDirectory) {
                fileTree(seedDir) { include("*.meta.json", "railgun-logs.jsonl", "railgun-logs.jsonl.gz") }
            } else {
                files()
            }
        },
    )
    // The frame's OWN assertions, declared so a change to either re-runs the task.
    // Neither is a file, and the build script is not a task input, so without these a
    // corrected deployment block would leave the dmg shipping the previous frame —
    // whose from_block makes the engine answer [] below the floor without consulting
    // coverage. That is the one defect class this file keeps warning about.
    inputs.property("watch", railgunWatch)
    outputs.files(seed, manifest)
    doLast {
        check(seedDir.isDirectory) {
            "railgun-poc: no seed data at $seedDir. Fetch it first (docs/railgun-poc.md, " +
                "\"Building the seed\"), or point -PrailgunSeedDir at a directory holding the " +
                "fetch's .jsonl and .meta.json."
        }
        // One pair, found by shape rather than by a pinned filename: the range is
        // in the name and a re-fetch changes it. Two pairs would be ambiguous, so
        // refuse rather than guess which fetch the build meant.
        val metas = seedDir.listFiles { f: File -> f.name.endsWith(".meta.json") }?.sorted().orEmpty()
        check(metas.size == 1) {
            "railgun-poc: expected exactly one *.meta.json in $seedDir, found ${metas.size} " +
                "${metas.map { it.name }} — leave only the fetch this build should bundle."
        }
        val meta = metas.single()
        val logs = seedDir.resolve("railgun-logs.jsonl").takeIf { it.isFile }
            ?: seedDir.resolve("railgun-logs.jsonl.gz").takeIf { it.isFile }
            ?: throw GradleException("railgun-poc: no railgun-logs.jsonl(.gz) beside $meta")
        pocSeedDir.get().asFile.mkdirs()
        // Trimming the top is only safe to skip when the fetch ran to a block that
        // CANNOT reorg. The meta records which tag it used; a fetch to `latest` with
        // margin 0 would freeze a since-reorged block into the seed and the engine
        // would serve it as fully covered — a silent wrong answer, the exact case the
        // coverage rules exist to prevent. So the margin follows the meta rather than
        // a convention the developer was asked to remember.
        val toBlockTag = groovy.json.JsonSlurper().parse(meta) .let { (it as Map<*, *>)["toBlockTag"] }?.toString()
        val margin = if (toBlockTag == "finalized") "0" else null
        if (margin == null) {
            logger.lifecycle(
                "railgun-poc: ${meta.name} does not declare toBlockTag=finalized (got ${toBlockTag ?: "nothing"}) — " +
                    "keeping the default reorg margin, so the seed's top is trimmed",
            )
        }
        val cmd = listOf(
            "python3", script.absolutePath,
            "--meta", meta.absolutePath,
            "--logs", logs.absolutePath,
            "--watch", railgunWatch,
        ) + (margin?.let { listOf("--finality-margin", it) } ?: emptyList()) + listOf(
            "--out", seed.get().asFile.absolutePath,
            "--manifest", manifest.get().asFile.absolutePath,
        )
        val proc = ProcessBuilder(cmd).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
        val stderr = proc.errorStream.bufferedReader().readText()
        check(proc.waitFor() == 0 && seed.get().asFile.isFile && manifest.get().asFile.isFile) {
            "railgun-poc: scripts/synth_logindex.py failed (python3 required):\n$stderr"
        }
        val summary = manifest.get().asFile.readLines()
            .filter { it.startsWith("covered") || it.startsWith("usableUntil") || it.startsWith("logs=") }
            .joinToString(", ")
        logger.lifecycle("railgun-poc: staged ${seed.get().asFile.name} — $summary")
    }
}

// Compose's own internal prepareAppResources task copies appResourcesRootDir
// into the image — our staging must run before IT (depending only on the
// package*/createDistributable* umbrella tasks is too late: the internal copy
// consumes the dir first).
tasks.configureEach {
    // configureEach (not tasks.matching{}, which realizes every task eagerly):
    // the name check runs lazily as each task is configured.
    if (name == "prepareAppResources"
        || name.startsWith("package") || name.startsWith("createDistributable")
        || name.startsWith("createReleaseDistributable")
        || name.startsWith("runDistributable") || name.startsWith("runRelease")
    ) {
        dependsOn(prepareRustAppResources)
        dependsOn(prepareJnaBootLib)
        dependsOn(prepareBeePocSeed, prepareRailgunPocSeed)
        // Compose's jpackage tasks do NOT track the app-resources CONTENT as
        // an input: after a Rust-only change, prepareRustAppResources and
        // Compose's own prepareAppResources both re-run, yet
        // createDistributable/packageDmg still report UP-TO-DATE and ship the
        // previous image — i.e. a stale engine dylib with no error anywhere
        // (reproduced 2026-08-06: staged+prepared dirs carried a new exported
        // symbol, the packaged .app didn't). Declaring the staged dir as an
        // explicit input makes any dylib change dirty the image and every
        // installer built from it. Fingerprinting happens at execution time,
        // after prepareRustAppResources (dependsOn above) has created the dir.
        // The uber-jar packagers match the name predicate but bundle no app
        // resources — skip them so a Rust-only change doesn't re-zip the jar.
        if (!name.contains("UberJar")) {
            inputs.dir(rustAppResourcesRoot)
                .withPropertyName("rustEngineAppResources")
                .withPathSensitivity(PathSensitivity.RELATIVE)
        }
    }
}

compose.desktop {
    application {
        mainClass = "io.myotis.desktop.MainKt"
        // Use our desktop logback config (rolling, size-capped, ~/.myotis/logs, app level
        // adjustable via -Dmyotis.log.level) instead of the DEBUG-to-unbounded-file logback.xml
        // that :app puts on the classpath. Applies to both the packaged app and :app-desktop:run.
        jvmArgs += listOf("-Dlogback.configurationFile=logback-desktop.xml")
        // JNA loads its native stub from here in the packaged app (see
        // prepareJnaBootLib); jpackage's launcher expands $APPDIR at start.
        jvmArgs += "-Djna.boot.library.path=\$APPDIR/resources"
        // The Bee PoC flavour identifies itself to Main.kt/BeePoc.kt through this
        // property — baked into the package AND applied to :app-desktop:run.
        if (beePoc) jvmArgs += "-Dmyotis.beePoc=true"
        if (railgunPoc) jvmArgs += "-Dmyotis.railgunPoc=true"
        // Pin the runtime jpackage bundles (via jlink) to the Java 21 toolchain. Our bytecode
        // is class-file 65 (jvmToolchain(21)) and the backend (:networking discv5, :myotis-evm
        // Besu) ships Java-21 classes that NEED a 21 runtime to load. Without this, jpackage
        // defaults to whatever JDK runs Gradle — a Java 17 default JAVA_HOME bundles a 17 JRE
        // that can't load our classes (UnsupportedClassVersionError: class file 65.0 vs 61.0).
        // CI happened to work only because its JAVA_HOME is already 21.
        javaHome = javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(21))
        }.get().metadata.installationPath.asFile.absolutePath
        nativeDistributions {
            // The staged Rust engine lib (see prepareRustAppResources above).
            appResourcesRootDir.set(rustAppResourcesRoot)
            // jpackage is host-OS-bound: the .dmg can only be produced on macOS, the .deb only
            // on Linux. CI builds each on its matching runner (desktop-dmg.yml /
            // desktop-linux-deb.yml); locally you get the format for your OS. Msi when a
            // Windows host exists.
            targetFormats(TargetFormat.Dmg, TargetFormat.Deb)
            // The Bee PoC flavour is a separate app (own name, own bundle id, own
            // data dir — see BeePoc.kt) so it coexists with a regular install.
            packageName = when {
                beePoc -> "Myotis Bee PoC"
                railgunPoc -> "Myotis RAILGUN PoC"
                else -> "Myotis"
            }
            // Applies to the dmg (and a future msi); the deb overrides it below.
            // See macOsPackageVersion at the top of this file for the +1-major rule.
            packageVersion = macOsPackageVersion
            // jpackage builds the deb's Maintainer field as "<vendor> <debMaintainer>",
            // so the human name lives here and debMaintainer stays a bare email.
            vendor = "Dirk Jäckel"
            // Bundle the FULL JDK module graph. jlink otherwise strips the runtime to the
            // modules it can statically detect, but the backend reaches them reflectively —
            // DNS (java.naming), JDBC-style lookups, EC TLS (jdk.crypto.ec), XML, etc. — so a
            // stripped runtime dies at launch with NoClassDefFoundError (first seen:
            // javax/naming/NamingException). includeAllModules trades a bigger bundle for a
            // runtime that can actually load Netty / Besu / jvm-libp2p / BouncyCastle.
            includeAllModules = true
            macOS {
                bundleID = when {
                    beePoc -> "io.myotis.desktop.beepoc"
                    railgunPoc -> "io.myotis.desktop.railgunpoc"
                    else -> "io.myotis.desktop"
                }
            }
            linux {
                // Unlike the dmg (jpackage requires major > 0 on macOS), deb versions may
                // start at 0 — so Linux carries the app's honest version.
                packageVersion = releaseVersion
                debMaintainer = "dirk@jaeckel.com"
            }
        }
    }
}

// Dev runs load the Rust engine lib via an ABSOLUTE path (-Dmyotis.engine.lib), set
// only on these JavaExec tasks — deliberately NOT via compose.desktop jvmArgs, which
// would bake a dev-machine path into packaged apps. Packaged desktop builds ship
// without the Rust engine until the packaging PR.
tasks.withType<JavaExec>().matching { it.name == "run" || it.name == "syncSmoke" }.configureEach {
    dependsOn(rootProject.tasks.named("cargoBuildHost"))
    // -Pengine=java|rust|auto → -Dmyotis.engine (same knob as :app run).
    (project.findProperty("engine") as String?)?.let { systemProperty("myotis.engine", it) }
    // -Ptor=true → -Dmyotis.tor (dev knob to force Tor routing on at boot; needs the
    // engine dylib built with -PtorEngine to actually route — docs/privacy-and-tor.md).
    (project.findProperty("tor") as String?)?.let { systemProperty("myotis.tor", it) }
    doFirst {
        val os = System.getProperty("os.name").lowercase()
        val lib = when {
            os.contains("mac") -> "libmyotis_engine.dylib"
            os.contains("win") -> "myotis_engine.dll"
            else -> "libmyotis_engine.so"
        }
        rootProject.file("rust/target/release/$lib").takeIf { it.exists() }?.let {
            systemProperty("myotis.engine.lib", it.absolutePath)
        }
    }
}
