import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Properties
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    java
    // Load the Android/Kotlin/Compose plugins once on the root classpath (apply false) so
    // subprojects that apply them via alias don't each load their own copy — required once a
    // Kotlin-Multiplatform module (:ui) is in the build, which fails hard on duplicate loads.
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.compose.compiler) apply false
    alias(libs.plugins.compose.multiplatform) apply false
}

allprojects {
    group = "com.jaeckel.ethp2p"
    version = "0.1.4-SNAPSHOT"
}

// The release version — project.version minus the -SNAPSHOT suffix — exactly as
// :app-desktop and :android-app derive their installer / app versions from it.
// Release CI reads it from HERE (via Gradle, so it can never drift from what the
// build actually uses) and refuses to publish when the pushed `v*` tag disagrees:
// otherwise tagging without running the version sweep goes green and ships assets
// named after the tag while the binaries inside report the older version.
// See .github/workflows/release-version-guard.yml.
//
// Marker-prefixed output: `./gradlew -q` still lets non-task text reach stdout
// (wrapper distribution download progress on a cold runner, JVM/plugin warnings),
// so the consumer greps for the marker instead of trusting the last line.
tasks.register("printReleaseVersion") {
    group = "help"
    description = "Print the release version (project.version without -SNAPSHOT) as releaseVersion=<x.y.z>"
    // Read at configuration time: the task action captures a plain String, so it
    // stays configuration-cache compatible.
    val releaseVersion = project.version.toString().substringBefore('-')
    doLast { println("releaseVersion=$releaseVersion") }
}

subprojects {
    // These bring their own plugins (Android Gradle Plugin / Kotlin Multiplatform /
    // Compose), which are incompatible with the `java` plugin applied below:
    //   android-app  → com.android.application
    //   ui           → kotlin-multiplatform + com.android.library + compose
    //   app-desktop  → kotlin.jvm + compose (desktop)
    //   app-ios      → kotlin-multiplatform + compose (iOS framework)
    //   jsonrpc-server → kotlin-multiplatform (JVM hosts + the iOS RPC listener)
    // Excludes shared by EVERY module (Android plugin modules included):
    // - native Netty transports, for Android compatibility;
    // - Besu 26.4's log4j: it drags log4j-slf4j2-impl — a SECOND slf4j
    //   provider — plus log4j-core. Whichever provider classloads first gets
    //   ALL logging; jpackage's flattened classpath deterministically picked
    //   log4j and the desktop app's Logs tab (a LOGBACK appender) went dark.
    //   Logback is this repo's one true backend: drop the competing provider
    //   + core everywhere; Besu's log4j-api calls route into slf4j via the
    //   log4j-to-slf4j bridge (added in :myotis-evm).
    configurations.all {
        exclude(group = "io.netty", module = "netty-transport-native-epoll")
        exclude(group = "io.netty", module = "netty-transport-native-kqueue")
        exclude(group = "io.netty", module = "netty-transport-native-unix-common")
        // jvm-libp2p constrains in the QUIC codec (+ big per-OS natives); we only use
        // its TCP transport and ran without QUIC classes throughout the fork era.
        exclude(group = "io.netty", module = "netty-codec-native-quic")
        exclude(group = "org.apache.logging.log4j", module = "log4j-slf4j2-impl")
        exclude(group = "org.apache.logging.log4j", module = "log4j-slf4j-impl")
        exclude(group = "org.apache.logging.log4j", module = "log4j-slf4j18-impl")
        exclude(group = "org.apache.logging.log4j", module = "log4j-core")
    }

    if (name in setOf("android-app", "ui", "app-desktop", "app-ios", "jsonrpc-server")) {
        return@subprojects
    }

    apply(plugin = "java")

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    // (Historical: while the tuweni-kotlin fork was in use, io.consensys.tuweni was
    // excluded here project-wide to prevent duplicate org.apache.tuweni classes.
    // Upstream io.consensys.tuweni is canonical again — single source per class.)

    tasks.test {
        useJUnitPlatform()
    }

    // Besu 26.4's imported BOM pins junit-platform 1.13 onto every test
    // classpath that (transitively) sees :myotis-evm; without a matching
    // launcher the engine fails discovery ("unaligned versions of the
    // junit-platform-engine and junit-platform-launcher jars"). One aligned
    // launcher for every JVM module.
    dependencies {
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }
}

// -------------------------------------------------------------------------
// Optional Rust build (rust/ Cargo workspace — the coming Rust engine plus the
// native BLS backend). Rust is strictly OPTIONAL: without cargo on the machine
// every cargo* task self-skips with a single lifecycle note and the pure-Java
// build is untouched. With cargo installed, Gradle builds both engines:
//   cargoBuildHost  → rust/target/release/*.{so,dylib,dll}; wired into
//                     :app run (java.library.path) and :consensus test
//   cargoTest       → cargo test --workspace; wired into root `check`
//   cargoNdkAndroid → Android jniLibs via rust/build-android.sh; wired into
//                     :android-app preBuild. Extra-guarded on cargo-ndk + an
//                     NDK — the committed jniLibs stay the fallback.
// -------------------------------------------------------------------------

// Configuration-cache-safe tool probe: `<cmd...>` stdout, or "" when the tool
// is missing / exits non-zero.
abstract class ToolProbe : ValueSource<String, ToolProbe.Params> {
    interface Params : ValueSourceParameters {
        val command: ListProperty<String>
        val workingDir: Property<File>
    }

    @get:Inject abstract val execOperations: ExecOperations

    override fun obtain(): String = try {
        val out = ByteArrayOutputStream()
        val result = execOperations.exec {
            commandLine(parameters.command.get())
            workingDir = parameters.workingDir.get()
            standardOutput = out
            errorOutput = ByteArrayOutputStream()
            isIgnoreExitValue = true
        }
        if (result.exitValue == 0) out.toString(Charsets.UTF_8).trim() else ""
    } catch (e: Exception) {
        "" // binary not on PATH
    }
}

// Probed from rust/ so rust-toolchain.toml governs which toolchain rustup
// reports — probing the repo root would measure the rustup DEFAULT toolchain,
// not the one the builds actually run. (If rustup has no stable installed,
// the probe exits non-zero → "" → Rust is skipped, not downloaded.)
fun probeTool(vararg cmd: String): String =
    providers.of(ToolProbe::class) {
        parameters.command.set(cmd.toList())
        parameters.workingDir.set(file("rust"))
    }.get()

val cargoVersion = probeTool("cargo", "--version") // "cargo 1.96.0 (…)" or ""
val cargoNdkVersion = if (cargoVersion.isEmpty()) "" else probeTool("cargo", "ndk", "--version")

// Minimum toolchain: headroom for the crates the engine phase pulls in
// (alloy-primitives / ethereum_ssz MSRVs move quickly). Older toolchains skip
// the Rust build exactly like a missing cargo — java stays fully functional.
val minRustMinor = 85
val rustAvailable = Regex("""cargo (\d+)\.(\d+)""").find(cargoVersion)?.let {
    val (major, minor) = it.destructured
    major.toInt() > 1 || (major.toInt() == 1 && minor.toInt() >= minRustMinor)
} ?: false

// NDK for cargoNdkAndroid: $ANDROID_NDK_HOME, else the newest ndk/<version>
// under the SDK from local.properties / $ANDROID_HOME / $ANDROID_SDK_ROOT.
fun findAndroidNdk(): File? {
    System.getenv("ANDROID_NDK_HOME")?.let { p ->
        File(p).takeIf { it.isDirectory }?.let { return it }
    }
    // java.util.Properties for real unescaping — Windows local.properties
    // writes sdk.dir=C\:\\Users\\… which a raw line split would mangle.
    val sdkDir = file("local.properties").takeIf { it.exists() }?.let { f ->
        Properties().apply { f.inputStream().use { load(it) } }.getProperty("sdk.dir")
    }
        ?: System.getenv("ANDROID_HOME")
        ?: System.getenv("ANDROID_SDK_ROOT")
        ?: return null
    val numericVersion = Comparator<File> { a, b ->
        val pa = a.name.split('.')
        val pb = b.name.split('.')
        (0 until maxOf(pa.size, pb.size)).asSequence()
            .map { i ->
                (pa.getOrNull(i)?.toLongOrNull() ?: -1L)
                    .compareTo(pb.getOrNull(i)?.toLongOrNull() ?: -1L)
            }
            .firstOrNull { it != 0 } ?: 0
    }
    return File(sdkDir, "ndk").listFiles()?.filter { it.isDirectory }?.maxWithOrNull(numericVersion)
}
val androidNdkDir = findAndroidNdk()

val rustSources = fileTree("rust") {
    include(
        "**/*.rs", "**/Cargo.toml", "Cargo.lock",
        "rust-toolchain.toml", ".cargo/**", "build-android.sh",
    )
    exclude("target/**")
}

val hostLibNames = run {
    val os = System.getProperty("os.name").lowercase()
    listOf("myotis_bls", "myotis_engine").map {
        when {
            // mac first, matching the copies in app-desktop/Main.kt — the
            // branch ORDER is harmless today but consistent ordering is how
            // copy-paste drift stays visible.
            os.contains("mac") -> "lib$it.dylib"
            os.contains("win") -> "$it.dll"
            else -> "lib$it.so"
        }
    }
}

// Optional cross-target triple (-PrustTarget=… or RUST_TARGET env): needed by
// the x64 dmg CI leg, which runs on arm64 runners under Rosetta — cargo builds
// its HOST triple regardless of the JVM's arch, so without an explicit
// --target the x64 dmg would bundle an arm64 dylib (dead engine toggle on
// Intel Macs, invisible to a launcher-only arch check).
val rustTargetTriple: String? =
    ((findProperty("rustTarget") as? String) ?: System.getenv("RUST_TARGET"))
        ?.takeIf { it.isNotBlank() } // an empty env var must mean "host", never --target ""

// Where cargo puts the host libs: target/release, or target/<triple>/release
// when cross-compiling. Exposed (with the lib names) for :app-desktop's
// packaging staging.
val rustReleaseDir = if (rustTargetTriple != null) {
    "rust/target/$rustTargetTriple/release"
} else {
    "rust/target/release"
}
extra["rustReleaseDir"] = rustReleaseDir
extra["rustEngineLibName"] = hostLibNames.last() // lib?myotis_engine.{dylib,so,dll}

// Opt-in Tor support in the host engine dylib (docs/privacy-and-tor.md): builds
// myotis-engine with `--features tor`, pulling the Arti tree into the host lib so
// the desktop/daemon can offer the runtime Settings toggle. OFF by default so CI
// and the daemon build stay Arti-free. Presence-based, like a typical opt-in flag
// (a bare `-PtorEngine` sets the property to "", so use hasProperty); build a
// Tor-capable desktop app with `./gradlew :app-desktop:run -PtorEngine`.
val torEngine = project.hasProperty("torEngine")
        && (project.property("torEngine") as? String).let { it.isNullOrBlank() || it.toBoolean() }

tasks.register<Exec>("cargoBuildHost") {
    group = "rust"
    description = "cargo build --release for the host OS (self-skips when cargo is missing)"
    onlyIf { rustAvailable }
    workingDir = file("rust")
    commandLine(
        buildList {
            addAll(listOf("cargo", "build", "--release", "--workspace"))
            // Enable Tor only on the engine crate (package/feature form — a bare
            // `--features tor` with `--workspace` would try every member).
            if (torEngine) addAll(listOf("--features", "myotis-engine/tor"))
            rustTargetTriple?.let { addAll(listOf("--target", it)) }
        }
    )
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    // Toolchain identity is an input: a rustc upgrade with unchanged sources
    // must rebuild, or stale artifacts survive UP-TO-DATE checks.
    inputs.property("cargoVersion", cargoVersion)
    inputs.property("rustTarget", rustTargetTriple ?: "host")
    // The Tor feature flips the artifact's contents, so it must key UP-TO-DATE too.
    inputs.property("torEngine", torEngine)
    outputs.files(hostLibNames.map { file("$rustReleaseDir/$it") })
}

// Regenerate the UniFFI Kotlin bindings for the Rust engine into :myotis-engines'
// source tree. The generated file is COMMITTED (like the Android jniLibs) so
// cargo-less machines still compile the pure-Java/Kotlin build; re-run this task
// whenever rust/myotis-engine/src/ffi.rs changes shape. Library mode: bindgen
// reads the metadata baked into the built .so, so scaffolding and bindings can
// never disagree silently (UniFFI additionally checksum-verifies at load time).
tasks.register<Exec>("uniffiGenerateKotlin") {
    group = "rust"
    description = "Regenerate the committed UniFFI Kotlin bindings in :myotis-engines (self-skips without cargo)"
    onlyIf { rustAvailable }
    dependsOn(tasks.named("cargoBuildHost"))
    workingDir = file("rust")
    commandLine(
        "cargo", "run", "--release", "-p", "uniffi-bindgen", "--",
        "generate", "--library", "$rustReleaseDir/${hostLibNames.last()}".removePrefix("rust/"),
        "--language", "kotlin", "--no-format",
        "--out-dir", project(":myotis-engines").projectDir.resolve("src/main/kotlin").absolutePath,
    )
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("cargoVersion", cargoVersion)
    outputs.files(
        project(":myotis-engines").projectDir
            .resolve("src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt")
    )
}

val cargoTest = tasks.register<Exec>("cargoTest") {
    group = "rust"
    description = "cargo test --workspace (self-skips when cargo is missing)"
    onlyIf { rustAvailable }
    workingDir = file("rust")
    commandLine("cargo", "test", "--workspace")
    // No declared outputs: cargo's own incrementalism makes a no-change rerun
    // cheap, and test verdicts aren't files Gradle could fingerprint.
}
tasks.named("check") { dependsOn(cargoTest) }

// wasm32 canary: `cargo check --target wasm32-unknown-unknown` for the sans-I/O
// crates (myotis-consensus, and myotis-core since the EL phase). PROVES they
// stayed sans-I/O — tokio/libp2p/discv5 (and any sockets/fs dependency someone
// accidentally adds) don't build for plain wasm32, so the check failing is the
// tripwire. Needs BOTH the rustup target installed AND clang on PATH (blst
// compiles its C sources with clang for wasm); self-skips otherwise with one
// lifecycle note, like every other cargo* task.
val installedRustupTargets: Set<String> = if (rustAvailable) {
    probeTool("rustup", "target", "list", "--installed")
        .lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toSet()
} else {
    emptySet()
}
val wasmTargetInstalled = "wasm32-unknown-unknown" in installedRustupTargets
val clangAvailable = rustAvailable && probeTool("clang", "--version").isNotEmpty()
val cargoCheckWasm = tasks.register<Exec>("cargoCheckWasm") {
    group = "rust"
    description = "cargo check -p myotis-consensus -p myotis-core for wasm32-unknown-unknown — the sans-I/O canary (self-skips without cargo + the rustup wasm32 target + clang)"
    onlyIf { rustAvailable && wasmTargetInstalled && clangAvailable }
    workingDir = file("rust")
    commandLine(
        "cargo", "check", "--target", "wasm32-unknown-unknown",
        "-p", "myotis-consensus", "-p", "myotis-core",
    )
    // No declared outputs, same rationale as cargoTest: cargo's own
    // incrementalism makes a no-change rerun cheap.
}
tasks.named("check") { dependsOn(cargoCheckWasm) }

tasks.register<Exec>("cargoNdkAndroid") {
    group = "rust"
    description = "Cross-compile the Android jniLibs via rust/build-android.sh (self-skips without cargo + cargo-ndk + NDK; the committed jniLibs are the fallback)"
    onlyIf { rustAvailable && cargoNdkVersion.isNotEmpty() && androidNdkDir != null }
    workingDir = file("rust")
    androidNdkDir?.let { environment("ANDROID_NDK_HOME", it.absolutePath) }
    // Windows can't exec a .sh directly (CreateProcess error=193); route it
    // through bash there (Git for Windows ships one alongside git itself).
    if (System.getProperty("os.name").lowercase().contains("win")) {
        commandLine("bash", "./build-android.sh")
    } else {
        commandLine("./build-android.sh")
    }
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    // Toolchain identity as inputs: switching rustc, cargo-ndk, or the NDK must
    // re-run the build AND its 16 KB alignment check — that check exists to
    // catch exactly these toolchain swaps.
    inputs.property("cargoVersion", cargoVersion)
    inputs.property("cargoNdkVersion", cargoNdkVersion)
    inputs.property("ndkDir", androidNdkDir?.absolutePath ?: "")
    outputs.files(
        file("android-app/src/main/jniLibs/arm64-v8a/libmyotis_bls.so"),
        file("android-app/src/main/jniLibs/x86_64/libmyotis_bls.so"),
        file("android-app/src/main/jniLibs/arm64-v8a/libmyotis_engine.so"),
        file("android-app/src/main/jniLibs/x86_64/libmyotis_engine.so"),
    )
}

// iOS static libs (libmyotis_engine.a) for the :app-ios Kotlin/Native framework —
// cinterop absorbs them into the framework over the plain C ABI (rust/include/
// myotis_engine.h). One task per Apple triple; :app-ios wires each Kotlin/Native
// target's cinterop to the matching task. Self-skips off-macOS or without the
// rustup target (rustup target add aarch64-apple-ios aarch64-apple-ios-sim).
val isMacHost = System.getProperty("os.name").lowercase().contains("mac")
fun registerCargoBuildIos(taskName: String, triple: String) =
    tasks.register<Exec>(taskName) {
        group = "rust"
        description = "cargo build --release -p myotis-engine for $triple (self-skips without cargo + the rustup target on macOS)"
        onlyIf { rustAvailable && isMacHost && triple in installedRustupTargets }
        workingDir = file("rust")
        // `cargo rustc --crate-type staticlib` (not `cargo build`): only the .a is
        // consumed on iOS, and building the crate's cdylib type too would fail the
        // device link — rustc doesn't link compiler-rt builtins for iOS dylibs, so
        // blst's ___chkstk_darwin stays undefined there. In the staticlib the symbol
        // simply stays unresolved until the app link, where Xcode's clang provides it.
        commandLine(
            "cargo", "rustc", "--release", "--target", triple, "-p", "myotis-engine",
            "--crate-type", "staticlib",
        )
        inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
        inputs.property("cargoVersion", cargoVersion)
        outputs.files(file("rust/target/$triple/release/libmyotis_engine.a"))
    }
registerCargoBuildIos("cargoBuildIosDevice", "aarch64-apple-ios")
registerCargoBuildIos("cargoBuildIosSim", "aarch64-apple-ios-sim")

// Whether the :app-ios framework chain can run at all: EVERY triple's
// libmyotis_engine.a can either be built now (the cargo task's own onlyIf) or
// absorbed from an earlier build. When false, :app-ios disables its whole task
// chain (see its build file — it reads this single-sourced verdict) instead of
// failing at the cinterop, keeping "cargo strictly optional" true build-wide.
// All-or-nothing across the triples: the shared-source metadata/commonizer
// tasks span both targets, so a half-enabled module would just move the
// missing-input failure.
val iosTriples = listOf("aarch64-apple-ios", "aarch64-apple-ios-sim")
val iosFrameworkBuildable = iosTriples.all { triple ->
    (rustAvailable && isMacHost && triple in installedRustupTargets) ||
        file("rust/target/$triple/release/libmyotis_engine.a").exists()
}
extra["myotis.iosFrameworkBuildable"] = iosFrameworkBuildable

// Exactly ONE note when Rust work was requested but is being skipped — enough
// to explain the SKIPPED tasks without spamming every unrelated invocation.
// (taskGraph.whenReady isn't configuration-cache-safe; this build doesn't
// enable the config cache — move the note into the tasks if that changes.)
val rustSkipNote = when {
    cargoVersion.isEmpty() ->
        "[rust] cargo/rustc not found — skipping the Rust build; the pure-Java build is unaffected"
    !rustAvailable ->
        "[rust] $cargoVersion is older than 1.$minRustMinor — skipping the Rust build; the pure-Java build is unaffected"
    else -> null
}
gradle.taskGraph.whenReady {
    if (allTasks.none { it.name.startsWith("cargo") }) return@whenReady
    if (rustSkipNote != null) {
        logger.lifecycle(rustSkipNote)
    } else if (allTasks.any { it.name == "cargoNdkAndroid" } &&
        (cargoNdkVersion.isEmpty() || androidNdkDir == null)
    ) {
        logger.lifecycle("[rust] cargo-ndk or Android NDK not found — Android keeps the committed jniLibs")
    } else if (allTasks.any { it.name == "cargoCheckWasm" } &&
        (!wasmTargetInstalled || !clangAvailable)
    ) {
        logger.lifecycle("[rust] wasm32 canary skipped — needs rustup target wasm32-unknown-unknown + clang")
    }
    // The iOS skips get a WARNING, not a note: unlike the other cargo tasks there
    // is no committed fallback. With a previously built libmyotis_engine.a in
    // rust/target the cinterop absorbs it (possibly STALE — only the runtime ABI
    // handshake would catch the drift); with no .a at all, :app-ios disables its
    // whole framework chain (see app-ios/build.gradle.kts) so a cargo-less build
    // still passes.
    listOf("cargoBuildIosDevice" to "aarch64-apple-ios", "cargoBuildIosSim" to "aarch64-apple-ios-sim")
        .forEach { (task, triple) ->
            if (allTasks.any { it.name == task } && (!isMacHost || rustSkipNote != null || triple !in installedRustupTargets)) {
                val prereqs = "needs macOS + cargo + `rustup target add --toolchain stable $triple`"
                logger.warn(
                    if (iosFrameworkBuildable)
                        "[rust] $task skipped ($prereqs) — the iOS framework will embed the EXISTING " +
                            "rust/target/$triple/release/libmyotis_engine.a, which may be stale"
                    else
                        "[rust] $task skipped ($prereqs) — the :app-ios framework tasks are disabled " +
                            "(not every triple has a previously built libmyotis_engine.a to embed); " +
                            "the rest of the build is unaffected"
                )
            }
        }
}

// -------------------------------------------------------------------------
// Trust anchor refresh: fetch the current finalized block root from multiple
// independent public checkpoint endpoints, cross-validate, and rewrite the
// `@checkpoint:<network>` region in NetworkConfig.java. Shared by the mainnet
// and sepolia tasks (identical Beacon API shape and mainnet-preset slot math);
// Gnosis has its own task below (different API surface, scarce endpoints).
// -------------------------------------------------------------------------

fun registerCheckpointRefresh(taskName: String, network: String, endpoints: List<String>, genesisTimeProperty: String) =
    tasks.register(taskName) {
    group = "trust"
    description = "Fetch the finalized $network block root from ${endpoints.size} public checkpoint providers, cross-validate, and update NetworkConfig.java. Use -Pdry to preview the diff without writing."

    doLast {
        val dryRun = project.hasProperty("dry")
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

        fun fetch(url: String): String? = try {
            val req = HttpRequest.newBuilder()
                .uri(URI(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .GET().build()
            val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
            if (resp.statusCode() == 200) resp.body()
            else { logger.warn("[refresh] $url → HTTP ${resp.statusCode()}"); null }
        } catch (e: Exception) {
            logger.warn("[refresh] $url failed: ${e.message}"); null
        }

        // `data.root` is nested directly under `data`; target that specifically to avoid
        // matching `parent_root`/`state_root`/`body_root` inside a header. Some endpoints
        // omit the `0x` prefix, so accept either form.
        val rootRe = Regex(""""data"\s*:\s*\{\s*"root"\s*:\s*"(0x)?([0-9a-fA-F]+)"""")
        // Anchor the slot search inside the "data" object. A full beacon block response
        // contains nested attestations that each carry a "slot" field — without the
        // anchor the regex would otherwise match those.
        val slotRe = Regex(""""data"\s*:\s*\{.*?"slot"\s*:\s*"?(\d+)"?""", RegexOption.DOT_MATCHES_ALL)

        fun normRoot(m: MatchResult): String = m.groupValues[2].lowercase()

        data class Fetched(val base: String, val slot: Long, val root: String? = null)

        // Phase 1: discover each endpoint's currently-finalized slot. Providers can disagree
        // by an epoch because they poll upstream nodes at different rates.
        val probed = endpoints.mapNotNull { base ->
            val body = fetch("$base/eth/v2/beacon/blocks/finalized") ?: return@mapNotNull null
            val slot = slotRe.find(body)?.groupValues?.get(1)?.toLong()
            if (slot == null) {
                logger.warn("[refresh] $base response missing slot"); null
            } else {
                logger.lifecycle("[refresh] $base → finalized slot=$slot")
                Fetched(base, slot)
            }
        }
        if (probed.size < 2) {
            throw GradleException("Need at least 2 successful endpoints; got ${probed.size}")
        }

        // Phase 2: normalize to the oldest observed finalized slot (which all endpoints can
        // serve) and re-query each for the canonical root AT that slot.
        val minSlot = probed.minOf { it.slot }
        val resolved = probed.map { f ->
            val body = fetch("${f.base}/eth/v1/beacon/blocks/$minSlot/root")
                ?: throw GradleException("${f.base} could not resolve slot $minSlot")
            val root = rootRe.find(body)?.let { normRoot(it) }
                ?: throw GradleException("${f.base} response at slot $minSlot missing root field")
            logger.lifecycle("[refresh] ${f.base} @ slot $minSlot → $root")
            Fetched(f.base, minSlot, root)
        }

        val distinct = resolved.mapNotNull { it.root }.toSet()
        if (distinct.size != 1) {
            val detail = resolved.joinToString("\n  ") { "${it.base} → ${it.root}" }
            throw GradleException(
                "Cross-validation FAILED at slot $minSlot. Endpoints disagreed:\n  $detail\n" +
                "Aborting; NetworkConfig.java not modified.")
        }

        val finalRoot = distinct.single().removePrefix("0x")
        val period = minSlot / 8192
        // Shared with the Java-side genesis constants via gradle.properties
        val genesis = (project.findProperty(genesisTimeProperty) as? String)?.takeIf { it.isNotBlank() }?.toLongOrNull()
            ?: throw GradleException("Property '$genesisTimeProperty' is missing, blank, or not a valid Long")
        val ts = Instant.ofEpochSecond(genesis + minSlot * 12)
        val date = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC).format(ts)

        val file = project(":networking").projectDir.resolve(
            "src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java")
        val original = file.readText()
        val beginMarker = "// @checkpoint:$network:begin"
        val endMarker = "// @checkpoint:$network:end"
        val beginIdx = original.indexOf(beginMarker)
        val endIdx = original.indexOf(endMarker)
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw GradleException("Could not find @checkpoint:$network:begin/end markers in NetworkConfig.java")
        }
        // Preserve whatever line ending the source file uses so we don't mix CRLF/LF
        // when running on Windows.
        val eol = if (original.contains("\r\n")) "\r\n" else "\n"
        val beginLineStart = original.lastIndexOf('\n', beginIdx) + 1
        // Stop the replaced region at the end of the end-marker text itself (not at the
        // following newline), so the original line terminator is preserved verbatim.
        val endMarkerEnd = endIdx + endMarker.length
        val indent = original.substring(beginLineStart, beginIdx)

        val replacement = buildString {
            append(indent).append("// @checkpoint:$network:begin — managed by `./gradlew $taskName`").append(eol)
            append(indent).append("// trusted checkpoint: recent finalized $network block root (slot $minSlot, $date, period $period)").append(eol)
            append(indent).append("Bytes.fromHexString(\"$finalRoot\").toArrayUnsafe(),").append(eol)
            append(indent).append("${minSlot}L, // checkpoint slot (epoch = slot/32). Must stay in sync with the root above.").append(eol)
            append(indent).append("// @checkpoint:$network:end")
        }
        val updated = original.substring(0, beginLineStart) + replacement + original.substring(endMarkerEnd)

        if (original == updated) {
            logger.lifecycle("[refresh] NetworkConfig.java already up to date (slot $minSlot, root 0x$finalRoot). No change.")
            return@doLast
        }

        val matchedHosts = probed.map { URI(it.base).host }
        if (dryRun) {
            logger.lifecycle("[refresh] -Pdry set; preview only (no write):")
            original.substring(beginLineStart, endMarkerEnd).lines().forEach { logger.lifecycle("- $it") }
            replacement.lines().forEach { logger.lifecycle("+ $it") }
            logger.lifecycle("[refresh] consensus: slot=$minSlot date=$date period=$period")
            logger.lifecycle("[refresh] matched ${probed.size}/${endpoints.size} endpoints: $matchedHosts")
        } else {
            val tmp = File(file.absolutePath + ".tmp")
            tmp.writeText(updated)
            Files.move(
                tmp.toPath(), file.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
            logger.lifecycle("[refresh] NetworkConfig.java updated.")
            logger.lifecycle("[refresh]   slot=$minSlot period=$period date=$date")
            logger.lifecycle("[refresh]   root=0x$finalRoot")
            logger.lifecycle("[refresh]   matched ${probed.size}/${endpoints.size} endpoints: $matchedHosts")
        }
    }
}

// Independent checkpoint-sync endpoints per network. These serve only a narrow
// slice of the Beacon API (/eth/v1/beacon/blocks/{id}/root + /eth/v2/beacon/blocks/{id}),
// which is enough for what we need here.
registerCheckpointRefresh(
    "refreshMainnetCheckpoint", "mainnet",
    listOf(
        "https://beaconstate.info",
        "https://sync-mainnet.beaconcha.in",
        "https://mainnet-checkpoint-sync.attestant.io",
    ),
    "ethp2p.mainnet.genesisTime",
)
// The full eth-clients/checkpoint-sync-endpoints sepolia list; the task needs
// any 2 of them live for cross-validation.
registerCheckpointRefresh(
    "refreshSepoliaCheckpoint", "sepolia",
    listOf(
        "https://sepolia.beaconstate.info",
        "https://checkpoint-sync.sepolia.ethpandaops.io",
        "https://beaconstate-sepolia.chainsafe.io",
    ),
    "ethp2p.sepolia.genesisTime",
)

// -------------------------------------------------------------------------
// Gnosis checkpoint refresh. Public Gnosis beacon endpoints serving the
// finalized API are scarce (effectively only the official rpc-gbc), so this
// cross-validates when ≥2 respond at the same slot and otherwise proceeds from
// a single trusted source with a loud warning. Uses
// /eth/v1/beacon/headers/finalized (root + slot in one response), which works
// on checkpointz and full nodes alike — unlike the mainnet task's two-call
// blocks API, which Gnosis checkpointz servers don't fully expose.
// Regenerates BOTH the root and the checkpoint-slot line inside the markers.
// -------------------------------------------------------------------------
tasks.register("refreshGnosisCheckpoint") {
    group = "trust"
    description = "Fetch the finalized Gnosis block root, cross-validate when possible, and update the @checkpoint:gnosis region in NetworkConfig.java. Use -Pdry to preview without writing."

    doLast {
        val endpoints = listOf(
            "https://rpc-gbc.gnosischain.com",
            "https://checkpoint.gnosischain.com",
            "https://gnosis-beacon.publicnode.com",
        )
        val dryRun = project.hasProperty("dry")
        val secondsPerSlot = 5L
        val genesis = (project.property("ethp2p.gnosis.genesisTime") as String).toLong()
        val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

        fun fetch(url: String): String? = try {
            val req = HttpRequest.newBuilder()
                .uri(URI(url))
                .timeout(Duration.ofSeconds(15))
                .header("Accept", "application/json")
                .GET().build()
            val resp = client.send(req, HttpResponse.BodyHandlers.ofString())
            if (resp.statusCode() == 200) resp.body()
            else { logger.warn("[refresh] $url → HTTP ${resp.statusCode()}"); null }
        } catch (e: Exception) {
            logger.warn("[refresh] $url failed: ${e.message}"); null
        }

        // headers/finalized JSON: data.root is the first "root":"0x..64hex.." key
        // (parent_root/state_root/body_root keys don't match the bare "root").
        val rootRe = Regex(""""root"\s*:\s*"(0x)?([0-9a-fA-F]{64})"""")
        val slotRe = Regex(""""slot"\s*:\s*"?(\d+)"?""")

        data class Hdr(val base: String, val slot: Long, val root: String)

        val probed = endpoints.mapNotNull { base ->
            val body = fetch("$base/eth/v1/beacon/headers/finalized") ?: return@mapNotNull null
            val slot = slotRe.find(body)?.groupValues?.get(1)?.toLong()
            val root = rootRe.find(body)?.groupValues?.get(2)?.lowercase()
            if (slot == null || root == null) {
                logger.warn("[refresh] $base response missing slot/root"); null
            } else {
                logger.lifecycle("[refresh] $base → finalized slot=$slot root=0x$root")
                Hdr(base, slot, root)
            }
        }
        if (probed.isEmpty()) {
            throw GradleException("No Gnosis endpoint returned a finalized header")
        }

        // Normalize to the oldest observed finalized slot so all responders can agree,
        // then re-query the endpoints that reported a *newer* slot for the header AT minSlot.
        // Beacon nodes are routinely a few slots out of sync, so filtering to those that
        // happened to report exactly minSlot would usually leave a single endpoint and
        // silently skip cross-validation. The standard /eth/v1/beacon/headers/{slot}
        // endpoint lets every responder be checked at the same slot (mirrors the
        // mainnet task's Phase 2).
        val minSlot = probed.minOf { it.slot }
        val resolved = probed.mapNotNull { f ->
            if (f.slot == minSlot) {
                f
            } else {
                val body = fetch("${f.base}/eth/v1/beacon/headers/$minSlot")
                val root = body?.let { rootRe.find(it)?.groupValues?.get(2)?.lowercase() }
                if (root == null) {
                    logger.warn("[refresh] ${f.base} could not resolve slot $minSlot"); null
                } else {
                    Hdr(f.base, minSlot, root)
                }
            }
        }
        if (resolved.isEmpty()) {
            throw GradleException("No Gnosis endpoint could resolve slot $minSlot")
        }
        val distinct = resolved.map { it.root }.toSet()
        if (distinct.size != 1) {
            val detail = resolved.joinToString("\n  ") { "${it.base} → 0x${it.root}" }
            throw GradleException(
                "Cross-validation FAILED at slot $minSlot. Endpoints disagreed:\n  $detail\n" +
                "Aborting; NetworkConfig.java not modified.")
        }
        val finalRoot = distinct.single()
        if (resolved.size < 2) {
            logger.warn("[refresh] WARNING: only ${resolved.size} endpoint served slot $minSlot — " +
                "checkpoint NOT cross-validated. Verify 0x$finalRoot against a Gnosis explorer.")
        }

        val period = minSlot / 8192
        val ts = Instant.ofEpochSecond(genesis + minSlot * secondsPerSlot)
        val date = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC).format(ts)

        val file = project(":networking").projectDir.resolve(
            "src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java")
        val original = file.readText()
        val beginMarker = "// @checkpoint:gnosis:begin"
        val endMarker = "// @checkpoint:gnosis:end"
        val beginIdx = original.indexOf(beginMarker)
        val endIdx = original.indexOf(endMarker)
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw GradleException("Could not find @checkpoint:gnosis:begin/end markers in NetworkConfig.java")
        }
        val eol = if (original.contains("\r\n")) "\r\n" else "\n"
        val beginLineStart = original.lastIndexOf('\n', beginIdx) + 1
        val endMarkerEnd = endIdx + endMarker.length
        val indent = original.substring(beginLineStart, beginIdx)

        val replacement = buildString {
            append(indent).append("// @checkpoint:gnosis:begin — managed by `./gradlew refreshGnosisCheckpoint`").append(eol)
            append(indent).append("// trusted checkpoint: recent finalized Gnosis block root (slot $minSlot, $date, period $period)").append(eol)
            append(indent).append("Bytes.fromHexString(\"$finalRoot\").toArrayUnsafe(),").append(eol)
            append(indent).append("${minSlot}L, // checkpoint slot. Must stay in sync with the root above.").append(eol)
            append(indent).append("// @checkpoint:gnosis:end")
        }
        val updated = original.substring(0, beginLineStart) + replacement + original.substring(endMarkerEnd)

        if (original == updated) {
            logger.lifecycle("[refresh] NetworkConfig.java already up to date (slot $minSlot, root 0x$finalRoot). No change.")
            return@doLast
        }

        if (dryRun) {
            logger.lifecycle("[refresh] -Pdry set; preview only (no write):")
            original.substring(beginLineStart, endMarkerEnd).lines().forEach { logger.lifecycle("- $it") }
            replacement.lines().forEach { logger.lifecycle("+ $it") }
        } else {
            val tmp = File(file.absolutePath + ".tmp")
            tmp.writeText(updated)
            Files.move(
                tmp.toPath(), file.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
            logger.lifecycle("[refresh] NetworkConfig.java updated: gnosis slot=$minSlot date=$date root=0x$finalRoot")
        }
    }
}
