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

// R8/D8 override: AGP 8.7.3 bundles R8 8.7.18, which predates Kotlin 2.2 and
// cannot parse this build's Kotlin 2.2.21 metadata — every Android dex step
// then warns "An error occurred when parsing kotlin metadata" per Kotlin
// class, and an R8-minified build ships stale/dropped @Metadata (visible to
// kotlin-reflect). The remedy while AGP is older than the Kotlin toolchain is
// pinning a newer R8 on the root buildscript classpath (the R8 project's
// documented override; the compatible versions come from
// developer.android.com/studio/build/kotlin-d8-r8-versions): 8.13.19 is that
// table's version for AGP 8.2.2-8.13 and understands Kotlin 2.2/2.3 metadata.
// Drop this whole block when AGP itself moves past 8.10 — the bundled R8 then
// understands Kotlin 2.2 natively.
buildscript {
    repositories {
        google {
            // Filtered per the convention for special-purpose repos in
            // settings.gradle.kts: this entry exists only to serve the R8 pin.
            content { includeGroup("com.android.tools") }
        }
    }
    dependencies {
        classpath("com.android.tools:r8:8.13.19")
    }
}

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
    version = "0.1.7-SNAPSHOT"
}

// The release version — project.version minus the -SNAPSHOT suffix — exactly as
// :app-desktop and :android-app derive their installer / app versions from it.
// Release CI reads it from HERE (via Gradle, so it can never drift from what the
// build actually uses) and refuses to publish when the pushed `v*` tag disagrees:
// otherwise tagging without running the version sweep goes green and ships assets
// named after the tag while the binaries inside report the older version.
// See .github/workflows/release-version-guard.yml. This reads the ROOT project's
// version, which is what the consumers see only because `allprojects` above sets
// ONE version for the whole build — give a module its own version and it silently
// stops being covered by the guard.
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

// The release sweep sets ONE version for the Gradle build (above) and repeats it
// in each myotis-* crate's Cargo.toml. That was convention only, and since the
// Rust engine derives its wire-visible client ids from CARGO_PKG_VERSION
// (rust/myotis-net/src/{el/rlpx/transport,reqresp}.rs) a sweep that bumped Gradle
// but missed the crates would ship an engine advertising the PREVIOUS release's
// id — the release guard would not notice, because it only compares the tag to
// project.version.
//
// So the invariant is checked here, on the PR that breaks it, rather than at tag
// time when the tag already exists and must be moved. Deliberately a plain file
// parse: no cargo needed, so it runs on cargo-less machines and under
// -PskipRustEngine, which is how CI's `./gradlew build` invokes `check`.
//
// Scope is rust/myotis-*/ — exactly the crates the sweep bumps. roost and tor-poc
// are standalone and pinned at 0.0.0 on purpose, uniffi-bindgen is a pinned tool;
// none of them are release artifacts, and none are matched by the glob.
val verifyCrateVersions = tasks.register("verifyCrateVersions") {
    group = "verification"
    description = "Fail when a myotis-* crate version disagrees with the Gradle release version"
    val releaseVersion = project.version.toString().substringBefore('-')
    val manifests = fileTree("rust") {
        include("myotis-*/Cargo.toml")
    }.files.sortedBy { it.path }
    val rootDir = project.rootDir
    doLast {
        if (manifests.isEmpty()) {
            // A rename that empties the glob must fail loudly: a check that
            // silently verifies nothing is worse than no check at all.
            throw GradleException(
                "verifyCrateVersions found no rust/myotis-*/Cargo.toml — the glob is stale, fix it rather than deleting this check"
            )
        }
        // Only the [package] section's version counts: a dependency's
        // `version = "…"` line elsewhere in the file must never be mistaken for
        // the crate's own.
        val mismatches = manifests.mapNotNull { manifest ->
            val packageSection = manifest.readText()
                .substringAfter("[package]", "")
                .substringBefore("\n[")
            val found = Regex("""^version\s*=\s*"([^"]+)"""", RegexOption.MULTILINE)
                .find(packageSection)?.groupValues?.get(1)
            when (found) {
                releaseVersion -> null
                null -> "${manifest.relativeTo(rootDir)}: no [package] version found"
                else -> "${manifest.relativeTo(rootDir)}: $found"
            }
        }
        if (mismatches.isNotEmpty()) {
            throw GradleException(
                "crate versions disagree with the Gradle release version ($releaseVersion):\n" +
                    mismatches.joinToString("\n") { "  $it" } +
                    "\nThe release sweep must bump these together — the Rust engine's devp2p Hello" +
                    "\nand libp2p agent ids come from the crate version, so a stale crate ships a" +
                    "\nstale client id. Fix the Cargo.toml(s) and regenerate the Cargo.lock files."
            )
        }
    }
}
tasks.named("check") { dependsOn(verifyCrateVersions) }

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
// native BLS backend). Rust is OPTIONAL for the JVM hosts: without cargo the
// cargo* tasks self-skip with a single lifecycle note and the pure-Java build is
// untouched. The ANDROID app is the exception — it builds the Rust engine from
// source by default (see requireAndroidRustEngine / -PskipRustEngine below).
// With cargo installed, Gradle builds both engines:
//   cargoBuildHost  → rust/target/release/*.{so,dylib,dll}; wired into
//                     :app run (java.library.path) and :consensus test
//   cargoTest       → cargo test --workspace; wired into root `check`
//   cargoNdkAndroid → Android jniLibs (engine + native BLS) via
//                     rust/build-android.sh; built from source (no committed
//                     .so) and wired into :android-app preBuild. Required by
//                     default; -PskipRustEngine opts out.
// -------------------------------------------------------------------------

// Configuration-cache-safe tool probe: `<cmd...>` stdout, or "" when the tool
// is missing / exits non-zero.
abstract class ToolProbe : ValueSource<String, ToolProbe.Params> {
    interface Params : ValueSourceParameters {
        val command: ListProperty<String>
        val workingDir: Property<File>
        val path: Property<String> // optional PATH override (see rustToolchainPath)
    }

    @get:Inject abstract val execOperations: ExecOperations

    override fun obtain(): String = try {
        val out = ByteArrayOutputStream()
        val result = execOperations.exec {
            commandLine(parameters.command.get())
            workingDir = parameters.workingDir.get()
            parameters.path.orNull?.let { environment("PATH", it) }
            standardOutput = out
            errorOutput = ByteArrayOutputStream()
            isIgnoreExitValue = true
        }
        if (result.exitValue == 0) out.toString(Charsets.UTF_8).trim() else ""
    } catch (e: Exception) {
        "" // binary not on PATH
    }
}

// GUI-launched IDEs inherit launchd's minimal PATH on macOS (no ~/.cargo/bin),
// so a Rust toolchain that works from a terminal "vanishes" when the same build
// runs inside Android Studio — requireAndroidRustEngine then fails claiming
// cargo is missing. rustToolBinDir is the directory holding cargo: from the
// daemon's PATH when present, else the standard rustup install dir
// ($CARGO_HOME/bin, default ~/.cargo/bin); null only when cargo is in neither
// (the toolchain is really missing). It feeds two mechanisms, both needed:
//   • rustTool resolves direct cargo/rustup invocations to absolute paths —
//     exec resolves a bare command name against the PATH the JVM captured at
//     its FIRST process spawn, not the current System.getenv, so even a
//     PATH-listed cargo is resolved absolutely (a Studio-spawned daemon reused
//     by a terminal build syncs the env but keeps the frozen exec search path);
//   • rustToolchainPath prepends the dir to each probe's/task's child PATH,
//     reaching what those processes spawn: cargo's rustc/rustup shims,
//     `cargo ndk` subcommand lookup, the bare `cargo` inside build-android.sh.
// (On Windows a second `PATH` key can duplicate the inherited `Path` with
// unspecified precedence — acceptable: the launchd problem is macOS-specific,
// and rustTool fixes the direct invocations regardless.)
val isWindowsHost = System.getProperty("os.name").lowercase().contains("win")
val rustToolBinDir: File? = run {
    val exe = if (isWindowsHost) "cargo.exe" else "cargo"
    fun executableIn(dir: File) = dir.resolve(exe).let { it.isFile && it.canExecute() }
    val envPath = System.getenv("PATH") ?: ""
    envPath.split(File.pathSeparator)
        .firstOrNull { it.isNotEmpty() && executableIn(File(it)) }
        ?.let { return@run File(it) }
    listOfNotNull(
        // Set-but-empty must mean unset, same as rustTargetTriple below.
        System.getenv("CARGO_HOME")?.takeIf { it.isNotBlank() }?.let { File(it) },
        File(System.getProperty("user.home"), ".cargo"),
    )
        .map { it.resolve("bin") }
        .firstOrNull { executableIn(it) }
        ?.also {
            // Self-announcing, but only at --info: an engaged fallback means the
            // cargo this build runs is not the one `which cargo` shows in a shell.
            logger.info("[rust] cargo is not on the daemon's PATH; using $it")
        }
}
val rustToolchainPath: String? = rustToolBinDir?.let { bin ->
    // No trailing separator when PATH is unset: an empty PATH element means cwd.
    val envPath = System.getenv("PATH")
    if (envPath.isNullOrEmpty()) bin.absolutePath
    else "${bin.absolutePath}${File.pathSeparator}$envPath"
}

// Every direct cargo/rustup invocation goes through this resolver (see the
// rustToolBinDir rationale above); a tool not present in that dir (clang) falls
// through to the bare name and resolves as before.
fun rustTool(name: String): String {
    val exe = if (isWindowsHost) "$name.exe" else name
    return rustToolBinDir?.resolve(exe)?.takeIf { it.isFile && it.canExecute() }?.absolutePath ?: name
}

// Probed from rust/ so rust-toolchain.toml governs which toolchain rustup
// reports — probing the repo root would measure the rustup DEFAULT toolchain,
// not the one the builds actually run. (If rustup has no stable installed,
// the probe exits non-zero → "" → Rust is skipped, not downloaded.)
fun probeTool(vararg cmd: String): String =
    providers.of(ToolProbe::class) {
        // rustTool resolves the executable itself; the PATH override covers
        // what it spawns (the cargo shim re-execs via rustup, for one).
        parameters.command.set(listOf(rustTool(cmd.first())) + cmd.drop(1))
        parameters.workingDir.set(file("rust"))
        rustToolchainPath?.let { parameters.path.set(it) }
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
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(
        buildList {
            addAll(listOf(rustTool("cargo"), "build", "--release", "--workspace"))
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
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(
        rustTool("cargo"), "run", "--release", "-p", "uniffi-bindgen", "--",
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
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(rustTool("cargo"), "test", "--workspace")
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
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(
        rustTool("cargo"), "check", "--target", "wasm32-unknown-unknown",
        "-p", "myotis-consensus", "-p", "myotis-core",
    )
    // No declared outputs, same rationale as cargoTest: cargo's own
    // incrementalism makes a no-change rerun cheap.
}
tasks.named("check") { dependsOn(cargoCheckWasm) }

// The Android app builds the Rust engine (its jniLibs) FROM SOURCE — cargo,
// cargo-ndk, the Android NDK, and the Android rustup targets are REQUIRED to
// build :android-app by default. Making the engine a build output (not a
// committed binary) is what stops a stale artifact from silently shipping a
// dead "Rust engine" toggle: there is no committed .so to drift from the source.
//
// Opt out with `-PskipRustEngine` to build the app WITHOUT the Rust engine when
// you don't have (or don't want) the toolchain — the app then uses the Java
// engine (and JVM BLS) at runtime. requireAndroidRustEngine (below) tells the
// developer about this switch if the toolchain is missing and the flag is unset.
// Presence-based: a bare `-PskipRustEngine` counts as true, as do the usual
// truthy spellings (true/1/yes/on). Only an explicit false-y value
// (false/0/no/off) disables it — this flag is the documented escape hatch out of
// a hard failure, so a stray `-PskipRustEngine=1` must NOT silently parse as
// "don't skip" and send the user straight back into the toolchain error.
val skipRustEngine = project.hasProperty("skipRustEngine") &&
    (project.property("skipRustEngine") as? String).let {
        it.isNullOrBlank() || it.trim().lowercase() !in setOf("false", "0", "no", "off")
    }
val androidRustTargets = listOf("aarch64-linux-android", "x86_64-linux-android")
val androidRustToolchainReady = rustAvailable &&
    cargoNdkVersion.isNotEmpty() &&
    androidNdkDir != null &&
    androidRustTargets.all { it in installedRustupTargets }

tasks.register<Exec>("cargoNdkAndroid") {
    group = "rust"
    description = "Cross-compile the Android jniLibs (the Rust engine + native BLS) from source via rust/build-android.sh; skipped by -PskipRustEngine"
    onlyIf { androidRustToolchainReady && !skipRustEngine }
    workingDir = file("rust")
    rustToolchainPath?.let { environment("PATH", it) }
    androidNdkDir?.let { environment("ANDROID_NDK_HOME", it.absolutePath) }
    // Windows can't exec a .sh directly (CreateProcess error=193); route it
    // through bash there (Git for Windows ships one alongside git itself).
    if (isWindowsHost) {
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

// Build-time contract for :android-app: the Rust engine is built from source by
// default (cargoNdkAndroid), so a MISSING toolchain must fail loudly and name the
// escape hatch — never silently produce a Java-only app. Wired into
// :android-app:preBuild (see its build file). `-PskipRustEngine` is the opt-out.
tasks.register("requireAndroidRustEngine") {
    group = "verification"
    description = "Fail the Android build when the Rust engine toolchain is missing, unless -PskipRustEngine is set"
    // A fast environment gate — no inputs/outputs, always evaluates.
    doLast {
        if (skipRustEngine) {
            logger.lifecycle("[rust] -PskipRustEngine set — building :android-app WITHOUT the " +
                "Rust engine; it will use the Java engine (and JVM BLS) at runtime.")
            return@doLast
        }
        if (!androidRustToolchainReady) {
            val missing = buildList {
                if (cargoVersion.isEmpty()) add("cargo/rustc (need 1.$minRustMinor or newer)")
                else if (!rustAvailable) add("a newer rustc (need 1.$minRustMinor+; found \"$cargoVersion\")")
                if (cargoNdkVersion.isEmpty()) add("cargo-ndk (`cargo install cargo-ndk`)")
                if (androidNdkDir == null) add("the Android NDK r28+ (set ANDROID_NDK_HOME, or install it under <sdk>/ndk/)")
                val tgts = androidRustTargets.filterNot { it in installedRustupTargets }
                if (tgts.isNotEmpty()) add("Android rustup targets (`rustup target add ${tgts.joinToString(" ")}`)")
            }
            throw GradleException(
                "The Android app builds the Rust engine from source, but the toolchain is " +
                    "incomplete — missing: ${missing.joinToString("; ")}.\n" +
                    "  • Install it (one-time setup is documented in rust/build-android.sh), OR\n" +
                    "  • Build WITHOUT the Rust engine: add -PskipRustEngine (the app will use the " +
                    "Java engine at runtime).",
            )
        }
    }
}

// Post-build sanity check on the jniLibs that will actually ship. With the libs
// built from source (not committed) this normally can't drift, but it's a cheap
// backstop against a partial/interrupted cargoNdkAndroid or a bindings/scaffolding
// skew, turning a broken .so into a build failure instead of a silent runtime
// fallback — the failure class this whole contract exists to prevent. Two checks:
//   • libmyotis_engine.so exports every UniFFI symbol the committed bindings
//     require (else the Rust engine fails UniFFI validation on-device → Java);
//   • libmyotis_bls.so is present and a valid ELF for each shipped ABI (else the
//     native BLS backend is unavailable on-device → the slower JVM BLS).
// The BLS lib carries no UniFFI surface to check, so presence + ELF magic is the
// meaningful signal there. Skipped with -PskipRustEngine (nothing is built).
//
// Symbol PRESENCE (one scan of the .so for the required names), not a full ELF
// .dynsym parse: a missing export is simply absent from the .so's string table,
// which a byte scan catches with no external tools. A same-name signature change
// (checksum drift, no new symbol) is still caught at load time by UniFFI's
// checksum gate and, in CI, by the regenerate-and-diff step in android-apk.yml.
val shippedAbis = listOf("arm64-v8a", "x86_64")
val engineJniLibs = shippedAbis.map { file("android-app/src/main/jniLibs/$it/libmyotis_engine.so") }
val blsJniLibs = shippedAbis.map { file("android-app/src/main/jniLibs/$it/libmyotis_bls.so") }
val committedBindings = project(":myotis-engines").projectDir
    .resolve("src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt")
tasks.register("verifyAndroidJniLibs") {
    group = "verification"
    description =
        "Fail if the built Android jniLibs are broken — engine .so missing a required UniFFI " +
            "symbol, or BLS .so missing/not an ELF (post-build backstop; skipped by -PskipRustEngine)"
    onlyIf { !skipRustEngine }
    inputs.file(committedBindings).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(engineJniLibs).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(blsJniLibs).withPathSensitivity(PathSensitivity.RELATIVE)
    val marker = layout.buildDirectory.file("verifyAndroidJniLibs.ok")
    outputs.file(marker)
    doLast {
        fun requireElf(so: File, hint: String) {
            check(so.exists()) {
                "verifyAndroidJniLibs: missing jniLib $so — cargoNdkAndroid did not produce it$hint. " +
                    "Run `./gradlew cargoNdkAndroid` (needs the Android Rust toolchain), or build " +
                    "without the native libs via -PskipRustEngine."
            }
            val magic = so.inputStream().use { ins -> ByteArray(4).also { ins.read(it) } }
            check(magic.contentEquals(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) {
                "verifyAndroidJniLibs: ${so.parentFile.name}/${so.name} is not an ELF binary " +
                    "(truncated/corrupt build?). Rebuild with `./gradlew cargoNdkAndroid`."
            }
        }
        // Every native symbol JNA's Native.register resolves eagerly at load:
        // both the uniffi_* (per-function + per-function-checksum) and the
        // ffi_* (rustbuffer/contract-version/future runtime) external funcs.
        val required = Regex("""external fun (uniffi_myotis_engine_\w+|ffi_myotis_engine_\w+)\s*\(""")
            .findAll(committedBindings.readText())
            .map { it.groupValues[1] }
            .toSortedSet()
        check(required.isNotEmpty()) {
            "verifyAndroidJniLibs: found no UniFFI symbols in $committedBindings — " +
                "the bindings file moved or its shape changed; update this task."
        }
        val symbol = Regex("""uniffi_myotis_engine_\w+|ffi_myotis_engine_\w+""")
        engineJniLibs.forEach { so ->
            requireElf(so, " (the Rust engine)")
            // ISO-8859-1 maps each byte 1:1 to a char; one scan collects every
            // engine symbol present (they live in .dynstr), then set-diff vs required.
            val present = symbol.findAll(String(so.readBytes(), Charsets.ISO_8859_1))
                .map { it.value }.toHashSet()
            val missing = required.filterNot { it in present }
            check(missing.isEmpty()) {
                "verifyAndroidJniLibs: ${so.parentFile.name}/${so.name} is missing " +
                    "${missing.size} UniFFI symbol(s) the bindings require, e.g. " +
                    "${missing.take(3)}. The Rust engine would fail UniFFI validation on-device " +
                    "and silently fall back to Java. Rebuild with `./gradlew cargoNdkAndroid`; if " +
                    "the bindings are the stale side, regenerate them with " +
                    "`./gradlew uniffiGenerateKotlin`."
            }
        }
        // The native BLS lib has no UniFFI surface — presence + ELF is the signal.
        blsJniLibs.forEach { requireElf(it, " (native BLS)") }
        marker.get().asFile.apply { parentFile.mkdirs(); writeText("ok") }
        logger.lifecycle("[rust] verifyAndroidJniLibs: engine jniLibs export all " +
            "${required.size} required UniFFI symbols; native BLS present for ${shippedAbis.joinToString(", ")}")
    }
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
        rustToolchainPath?.let { environment("PATH", it) }
        // `cargo rustc --crate-type staticlib` (not `cargo build`): only the .a is
        // consumed on iOS, and building the crate's cdylib type too would fail the
        // device link — rustc doesn't link compiler-rt builtins for iOS dylibs, so
        // blst's ___chkstk_darwin stays undefined there. In the staticlib the symbol
        // simply stays unresolved until the app link, where Xcode's clang provides it.
        commandLine(
            rustTool("cargo"), "rustc", "--release", "--target", triple, "-p", "myotis-engine",
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
    } else if (allTasks.any { it.name == "cargoNdkAndroid" } && skipRustEngine) {
        // Missing-toolchain (without the flag) is handled loudly at execution by
        // requireAndroidRustEngine; here we only note the deliberate opt-out.
        logger.lifecycle("[rust] -PskipRustEngine set — the Android app will omit the Rust engine (Java engine at runtime)")
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
// Trust anchor refresh — ONE task for every network, writing EVERY engine.
//
// Supersedes the per-network tasks (refreshMainnetCheckpoint / Sepolia /
// Gnosis), which are removed rather than left alongside: they wrote only the
// Java region, so running one after this would silently split the anchor
// between the two engines — the failure this task exists to prevent.
// -------------------------------------------------------------------------

/** One network: fetch, cross-validate, then rewrite the marked region in every engine. */
fun refreshOneCheckpoint(project: Project, logger: org.gradle.api.logging.Logger, net: String) {
    // An extra source the operator NAMES, e.g. -PextraEndpoint=http://127.0.0.1:5054.
    // It is appended, never substituted, so it adds a voice to cross-validation
    // rather than displacing the public ones — and it is checked against the
    // pinned genesis_validators_root below before it counts.
    //
    // Not normally needed: the checkpointz providers answer `finalized` only and
    // 404 on historical slots, but each network's list leads with a full archive
    // endpoint, so even -Pperiod cross-validates without a local node. This is
    // the escape hatch for when that stops being true.
    val extra = (project.findProperty("extraEndpoint") as String?)?.split(",")?.map { it.trim() }
        ?.filter { it.isNotEmpty() } ?: emptyList()
    val endpoints = checkpointEndpoints.getValue(net) + extra
    val secondsPerSlot = checkpointSecondsPerSlot.getValue(net)
    val slotsPerPeriod = checkpointSlotsPerPeriod.getValue(net)
    val slotsPerEpoch = checkpointSlotsPerEpoch.getValue(net)

    val javaFile = project(":networking").projectDir
        .resolve("src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java")
    // The chain identity we check a named endpoint against. It is a COPY of a
    // value that lives in the engines, so verify it still matches before
    // trusting it — a drifted copy would turn the check below into theatre.
    val gvr = checkpointGenesisValidatorsRoot.getValue(net)
    // Scoped to THIS network's block of the file, not the whole file: all three
    // networks' roots appear in NetworkConfig.java, so whole-file containment
    // would pass a cross-network swap in the map above — which would invert the
    // chain gate below (refuse the right chain, accept the wrong one). The gvr
    // literal sits a few lines above its network's checkpoint region, so the
    // slice from the previous network's end marker to this one's begin marker
    // identifies it uniquely.
    run {
        val cfgText = javaFile.readText()
        val beginIdx = cfgText.indexOf("// @checkpoint:$net:begin")
        if (beginIdx < 0) {
            throw GradleException("[refresh:$net] no @checkpoint:$net:begin marker in ${javaFile.name}")
        }
        val sliceStart = checkpointEndpoints.keys.filter { it != net }
            .mapNotNull { other ->
                cfgText.indexOf("// @checkpoint:$other:end").takeIf { it in 0 until beginIdx }
            }
            .maxOrNull() ?: 0
        if (!cfgText.substring(sliceStart, beginIdx).contains(gvr)) {
            throw GradleException(
                "[refresh:$net] genesis_validators_root $gvr is not in the $net block of ${javaFile.name} — " +
                "this build script's copy has drifted (or been swapped across networks); fix it before refreshing an anchor")
        }
    }
    // Guarded, as the helper this replaces was: a missing or malformed property
    // would otherwise surface as a ClassCastException or NumberFormatException
    // deep in the task rather than as the configuration error it is.
    val genesis = (project.findProperty("ethp2p.$net.genesisTime") as? String)
        ?.takeIf { it.isNotBlank() }?.toLongOrNull()
        ?: throw GradleException("missing or malformed property ethp2p.$net.genesisTime")

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

    // A named endpoint is unauthenticated and unidentified — nothing about
    // `http://127.0.0.1:5054` says which chain answers on it. Ask, and refuse if
    // the answer is not this chain: a gnosis node on the port meant for mainnet
    // would otherwise put its root straight into the mainnet trust anchor, and
    // every downstream check would pass on a value from the wrong network.
    val gvrRe = Regex(""""genesis_validators_root"\s*:\s*"(0x)?([0-9a-fA-F]{64})"""")
    extra.forEach { base ->
        val body = fetch("$base/eth/v1/beacon/genesis")
            ?: throw GradleException(
                "[refresh:$net] -PextraEndpoint $base did not answer /eth/v1/beacon/genesis — " +
                "refusing to use an endpoint whose chain cannot be confirmed")
        val seen = gvrRe.find(body)?.groupValues?.get(2)?.lowercase()
            ?: throw GradleException(
                "[refresh:$net] -PextraEndpoint $base answered /eth/v1/beacon/genesis without a " +
                "parseable genesis_validators_root — refusing an endpoint whose chain cannot be confirmed")
        if (seen != gvr) {
            throw GradleException(
                "[refresh:$net] -PextraEndpoint $base is on the WRONG CHAIN: " +
                "genesis_validators_root 0x$seen, expected 0x$gvr")
        }
        logger.lifecycle("[refresh:$net] $base chain-checked: genesis_validators_root matches $net")
    }

    // rootRe is applied ONLY to /eth/v1/beacon/blocks/{slot}/root responses,
    // whose data.root is the first (and only) bare "root" key. It must NEVER be
    // applied to a /eth/v2/beacon/blocks body: a block names itself by
    // parent_root/state_root/body_root only, so the first bare "root" there is
    // an attestation's justified-checkpoint root — an epoch-boundary root 2-3
    // epochs OLDER than the block. Extracting that mispairs (slot, root) in the
    // committed anchor, invisibly: every provider serves the same canonical
    // JSON, so cross-validation agrees on the same wrong value.
    val rootRe = Regex(""""root"\s*:\s*"(0x)?([0-9a-fA-F]{64})"""")
    val slotRe = Regex(""""slot"\s*:\s*"?(\d+)"?""")

    // An explicit target period anchors at that period's FIRST slot instead of at
    // head. Anchoring at head is wrong for this deployment: roost's archive only
    // grows FORWARD, so an anchor at the newest period leaves a wallet nothing to
    // walk and goes stale the moment the period rolls. The useful anchor is
    // roost's FLOOR — the oldest period it can still serve.
    //
    // A period's first slot may be SKIPPED (no block proposed), which the beacon
    // API answers with 404, so walk forward until a block exists. Bounded at 32
    // slots (one mainnet epoch, two gnosis epochs): past that the chain has
    // bigger problems, and failing loudly beats anchoring somewhere unintended.
    // -Pslot pins an EXACT slot instead. It exists because a bootstrap is only
    // servable where the serving node retained a state, and those retention
    // points are specific slots (epoch boundaries near its trustedNodeSync
    // anchor), not period firsts — the oldest testable anchor is one of them.
    // The slot must hold a block: a skipped slot fails loudly rather than being
    // walked past, because an explicit slot is a statement of intent.
    // Guarded like genesisTime above: a malformed value ('10,838,080', a stray
    // space, a bare -Pslot) must surface as the configuration error it is, not
    // as a NumberFormatException deep in the task.
    val targetPeriod = (project.findProperty("period") as String?)?.let {
        it.trim().toLongOrNull() ?: throw GradleException("[refresh:$net] malformed -Pperiod: '$it'")
    }
    val targetSlot = (project.findProperty("slot") as String?)?.let {
        it.trim().toLongOrNull() ?: throw GradleException("[refresh:$net] malformed -Pslot: '$it'")
    }
    if (targetPeriod != null && targetSlot != null) {
        // Applied-or-refused: silently preferring one would compute a well-formed
        // anchor against something other than what the caller asked for.
        throw GradleException("[refresh:$net] -Pperiod and -Pslot are mutually exclusive — pass one")
    }
    val pinnedSlot: Long? = targetSlot ?: targetPeriod?.let { p ->
        val first = p * slotsPerPeriod
        (first until first + 32).firstOrNull { slot ->
            endpoints.any { base -> fetch("$base/eth/v2/beacon/blocks/$slot") != null }
        } ?: throw GradleException(
            "[refresh:$net] no block in slots $first..${first + 31} for period $p")
    }
    if (pinnedSlot != null) {
        logger.lifecycle("[refresh:$net] pinning ${targetSlot?.let { "slot $it" } ?: "period $targetPeriod"} → slot $pinnedSlot (period ${pinnedSlot / slotsPerPeriod})")
    }

    // Phase 1 — slot DISCOVERY only. The v2 block body is fetched to learn each
    // responder's finalized slot (or to confirm the pinned slot exists); its
    // roots are deliberately not read — see the rootRe note above.
    //
    // In pinned mode a responder whose body reports a DIFFERENT slot than the
    // one requested (nonconformant gateway, caching proxy) is dropped, not
    // believed: minSlot is min() over responders, so one bad body could
    // otherwise drag the anchor to a slot nobody pinned — with every honest
    // endpoint then agreeing on the canonical root at that wrong slot, the
    // exact silent re-anchoring -Pslot exists to refuse.
    val probed = endpoints.mapNotNull { base ->
        val path = if (pinnedSlot != null) "$pinnedSlot" else "finalized"
        val body = fetch("$base/eth/v2/beacon/blocks/$path") ?: return@mapNotNull null
        val slot = slotRe.find(body)?.groupValues?.get(1)?.toLong()
        if (slot == null) {
            logger.warn("[refresh] $base response missing slot"); null
        } else if (pinnedSlot != null && slot != pinnedSlot) {
            logger.warn("[refresh] $base answered slot $slot for a request pinned to $pinnedSlot — dropped"); null
        } else {
            logger.lifecycle("[refresh] $base → ${if (pinnedSlot != null) "pinned" else "finalized"} slot=$slot")
            base to slot
        }
    }
    if (probed.isEmpty()) {
        throw GradleException(
            if (pinnedSlot != null) "No $net endpoint served pinned slot $pinnedSlot"
            else "No $net endpoint returned a finalized block")
    }

    // Phase 2 — resolve the BLOCK ROOT at one agreed slot, from every responder.
    // Normalized to the oldest observed finalized slot so all responders can
    // answer: beacon nodes are routinely a few slots out of sync, and filtering
    // to those that happened to report exactly minSlot would usually leave a
    // single endpoint and silently skip cross-validation.
    //
    // The root comes from /eth/v1/beacon/blocks/{slot}/root — the endpoint that
    // returns the block's OWN hash_tree_root — for every responder, including
    // those whose finalized slot already was minSlot. (This mirrors the original
    // per-network mainnet task's Phase 2; the generalised task briefly read the
    // v2 body instead and extracted an attestation checkpoint root, mispairing
    // slot and root in the committed anchor.)
    data class Hdr(val base: String, val slot: Long, val root: String)
    val minSlot = probed.minOf { it.second }
    // Unreachable after the pinned-mode filter above; kept as the written
    // invariant so a refactor of the probe cannot silently reopen the gap.
    if (pinnedSlot != null && minSlot != pinnedSlot) {
        throw GradleException("[refresh:$net] resolved slot $minSlot != pinned slot $pinnedSlot")
    }
    val resolved = probed.mapNotNull { (base, _) ->
        val body = fetch("$base/eth/v1/beacon/blocks/$minSlot/root")
        val root = body?.let { rootRe.find(it)?.groupValues?.get(2)?.lowercase() }
        if (root == null) {
            logger.warn("[refresh] $base could not resolve the block root at slot $minSlot"); null
        } else {
            logger.lifecycle("[refresh] $base → slot=$minSlot root=0x$root")
            Hdr(base, minSlot, root)
        }
    }
    if (resolved.isEmpty()) {
        throw GradleException("No $net endpoint could resolve the block root at slot $minSlot")
    }
    val distinct = resolved.map { it.root }.toSet()
    if (distinct.size != 1) {
        val detail = resolved.joinToString("\n  ") { "${it.base} → 0x${it.root}" }
        throw GradleException(
            "Cross-validation FAILED at slot $minSlot. Endpoints disagreed:\n  $detail\n" +
            "Aborting; NetworkConfig.java not modified.")
    }
    val finalRoot = distinct.single()
    // REFUSE below two agreeing OPERATORS rather than warn. This writes a TRUST
    // ROOT, and the per-network tasks this replaces already refused — warning
    // instead would have quietly weakened mainnet and sepolia while claiming to
    // unify them. Agreement is counted per registrable domain, not per URL:
    // two hostnames of the same operator (gnosis-beacon-api.publicnode.com and
    // gnosis-beacon.publicnode.com, say) are one voice, not two — otherwise a
    // single operator could satisfy the gate alone. -PallowSingleSource is the
    // named escape hatch for a chain whose providers really are unavailable, so
    // the weaker guarantee is always an explicit choice made on the command line.
    val operators = resolved.map { hdr ->
        URI(hdr.base).host.split(".").takeLast(2).joinToString(".")
    }.toSet()
    if (operators.size < 2) {
        val msg = "[refresh:$net] only ${operators.size} operator (${operators.joinToString()}) " +
            "served the block root at slot $minSlot — NOT cross-validated (root 0x$finalRoot)"
        if (project.hasProperty("allowSingleSource")) {
            logger.warn("$msg; -PallowSingleSource set, continuing. " +
                "Verify against a $net explorer before trusting this anchor.")
        } else {
            throw GradleException("$msg. Re-run with -PallowSingleSource to accept it.")
        }
    }

    val period = minSlot / slotsPerPeriod
    val ts = Instant.ofEpochSecond(genesis + minSlot * secondsPerSlot)

    val date = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC).format(ts)

    // An anchor pinned to a chosen old slot is NOT "recent finalized" — wrong
    // provenance wording beside a trust root invites the next reader to trust
    // the wrong story, same argument as keeping provenance inside the markers.
    val provenance = if (pinnedSlot != null) "pinned" else "recent finalized"

    /** 14560000 -> 14_560_000, the form every other numeric literal in sync.rs uses. */
    fun rustLiteral(n: Long): String = n.toString().reversed().chunked(3).joinToString("_").reversed()

    // One marked region to rewrite. The marker suffix is carried EXPLICITLY
    // rather than inferred from position in the list: two of these regions live
    // in the same file, and a position-inferred suffix made that coupling
    // invisible — which is exactly how the last-writer-wins bug below got in.
    data class Region(val file: File, val suffix: String, val render: (String, String) -> String)

    val rustFile = project.rootDir.resolve("rust/myotis-net/src/sync.rs")

    // BOTH engines, from one fetch. Hand-mirroring the Rust copy is what was
    // forgotten before, and a disagreement between them is a split trust anchor.
    val targets = listOf(
        Region(javaFile, "",
            { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    append(ind).append("// trusted checkpoint: $provenance $net block root (slot $minSlot, $date, period $period)").append(eol)
                    append(ind).append("Bytes.fromHexString(\"$finalRoot\").toArrayUnsafe(),").append(eol)
                    append(ind).append("${minSlot}L, // checkpoint slot (epoch = slot/$slotsPerEpoch). Must stay in sync with the root above.").append(eol)
                    append(ind).append("// @checkpoint:$net:end")
                }
            }),
        Region(rustFile, "",
            { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    // Provenance INSIDE the region, so it is rewritten with the
                    // values it describes. Outside, it would keep narrating the
                    // previous anchor next to the new root — and wrong provenance
                    // beside a trust root invites the next reader to skip the
                    // verification that was never done for the value in front of them.
                    append(ind).append("// trusted checkpoint: $provenance $net block root (slot $minSlot, $date, period $period)").append(eol)
                    append(ind).append("checkpoint_root: hex32(").append(eol)
                    append(ind).append("    \"$finalRoot\",").append(eol)
                    append(ind).append("),").append(eol)
                    append(ind).append("checkpoint_slot: ${rustLiteral(minSlot)},").append(eol)
                    append(ind).append("// @checkpoint:$net:end")
                }
            }),
        // THIRD region, SECOND one in sync.rs: the parity test literals. They pin
        // the same two values outside the config markers, so a refresh that
        // skipped them would leave `cargo test -p myotis-net` red on its first
        // real run — the tool would break the repo it is meant to maintain.
        Region(rustFile, ":test",
            { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:test:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    append(ind).append("assert_eq!(c.checkpoint_slot, ${rustLiteral(minSlot)});").append(eol)
                    append(ind).append("assert_eq!(").append(eol)
                    append(ind).append("    hex_str(&c.checkpoint_root),").append(eol)
                    append(ind).append("    \"$finalRoot\"").append(eol)
                    append(ind).append(");").append(eol)
                    append(ind).append("// @checkpoint:$net:test:end")
                }
            }),
    )

    data class Staged(
        val file: File,
        val original: String,
        val updated: String,
        val previews: List<Pair<String, String>>,
    )

    // Render and validate EVERY region before writing ANY file. Writing as we go
    // could commit NetworkConfig.java and then throw on sync.rs, leaving the two
    // engines disagreeing about the trust anchor — the exact split this exists
    // to prevent.
    //
    // Group by FILE and fold every region of a file into ONE text. sync.rs holds
    // two regions, and computing each from the pristine file would make the
    // second write discard the first: the config region would silently revert
    // while the test region moved, leaving Rust anchored to the old root and its
    // own parity test asserting the new one. (That is not hypothetical — it is
    // what this code did until a non-dry run was actually tried.)
    val staged = targets.groupBy { it.file }.map { (file, regions) ->
        val original = file.readText()
        var text = original
        val previews = regions.map { region ->
            val beginMarker = "// @checkpoint:$net${region.suffix}:begin"
            val endMarker = "// @checkpoint:$net${region.suffix}:end"
            val beginIdx = text.indexOf(beginMarker)
            val endIdx = text.indexOf(endMarker)
            if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
                throw GradleException("Could not find $beginMarker / $endMarker in ${file.name}")
            }
            val eol = if (text.contains("\r\n")) "\r\n" else "\n"
            val beginLineStart = text.lastIndexOf('\n', beginIdx) + 1
            val endMarkerEnd = endIdx + endMarker.length
            val indent = text.substring(beginLineStart, beginIdx)
            val replacement = region.render(indent, eol)
            val before = text.substring(beginLineStart, endMarkerEnd)
            text = text.substring(0, beginLineStart) + replacement + text.substring(endMarkerEnd)
            before to replacement
        }
        Staged(file, original, text, previews)
    }

    staged.forEach { (file, original, updated, previews) ->
        if (original == updated) {
            logger.lifecycle("[refresh:$net] ${file.name} already up to date (slot $minSlot). No change.")
        } else if (dryRun) {
            logger.lifecycle("[refresh:$net] -Pdry; preview of ${file.name}:")
            previews.forEach { (before, after) ->
                before.lines().forEach { logger.lifecycle("- $it") }
                after.lines().forEach { logger.lifecycle("+ $it") }
            }
        } else {
            val tmp = File(file.absolutePath + ".tmp")
            tmp.writeText(updated)
            Files.move(tmp.toPath(), file.toPath(),
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            logger.lifecycle("[refresh:$net] ${file.name} updated: slot=$minSlot period=$period root=0x$finalRoot")
        }
    }
}

/** Per-network checkpoint sources — independent, public, and PLURAL by design.
 *
 *  These serve a narrow slice of the Beacon API (`/eth/v2/beacon/blocks/{id}`
 *  + `/eth/v1/beacon/blocks/{id}/root`), which is all this task needs. An
 *  earlier revision of this task queried `/eth/v1/beacon/headers/finalized`
 *  instead — the shape the gnosis-only task used — saw 404s, and concluded the
 *  providers were dead. They are not: on the endpoint they actually document,
 *  mainnet and sepolia both cross-validate across several of these hosts.
 *
 *  No loopback address belongs in this list. A local node is a legitimate
 *  source — it followed the chain over p2p, so it is an opinion rather than a
 *  relay — but listing it here makes it a slot-SETTING peer: a node that is
 *  behind drags `minSlot` down to a slot the checkpointz providers will not
 *  serve historically, they drop out, and the run degrades to the single
 *  source that is by construction least independent of the operator. It is
 *  `-PextraEndpoint=<url>` instead: appended, never substituted, and
 *  chain-checked against the pinned `genesis_validators_root` before it counts.
 *
 *  Unreachable endpoints are skipped and reported; the task refuses to write
 *  when fewer than two agree (`-PallowSingleSource` to override). */
val checkpointEndpoints = mapOf(
    "mainnet" to listOf(
        // publicnode serves HISTORICAL slots, which the checkpointz providers
        // below do not (they answer `finalized` only and 404 on anything else).
        // That is what lets -Pperiod cross-validate instead of falling back to a
        // single source. Verified 2026-08-10 for all three networks.
        "https://ethereum-beacon-api.publicnode.com",
        "https://beaconstate.info",
        "https://sync-mainnet.beaconcha.in",
        "https://mainnet-checkpoint-sync.attestant.io",
    ),
    "sepolia" to listOf(
        "https://ethereum-sepolia-beacon-api.publicnode.com",
        "https://sepolia.beaconstate.info",
        "https://checkpoint-sync.sepolia.ethpandaops.io",
        "https://beaconstate-sepolia.chainsafe.io",
    ),
    // NOTE: rpc-gbc and checkpoint are both the Gnosis team — one operator, two
    // hostnames. The agreement gate counts operators (registrable domains), so
    // they add redundancy but only one voice; publicnode is the second voice.
    // (gnosis-beacon.publicnode.com was dropped: same operator and backend as
    // the api hostname, so it could never add a voice either.)
    "gnosis" to listOf(
        "https://gnosis-beacon-api.publicnode.com",
        "https://rpc-gbc.gnosischain.com",
        "https://checkpoint.gnosischain.com",
    ),
)
val checkpointSecondsPerSlot = mapOf("mainnet" to 12L, "sepolia" to 12L, "gnosis" to 5L)
val checkpointSlotsPerPeriod = mapOf("mainnet" to 8192L, "sepolia" to 8192L, "gnosis" to 8192L)
// Gnosis reaches the same 8192-slot period from 16 x 512 rather than 32 x 256,
// so the epoch divisor is NOT shared even though the period one is. Only used
// for the generated comment — but a comment on a trust anchor that says
// `epoch = slot/32` on a 16-slot-epoch chain is exactly the kind of wrong an
// operator would act on.
val checkpointSlotsPerEpoch = mapOf("mainnet" to 32L, "sepolia" to 32L, "gnosis" to 16L)
/** Pinned `genesis_validators_root` per network — the chain's identity, used to
 *  confirm a `-PextraEndpoint` node is on the chain the operator thinks it is.
 *  Checked against `NetworkConfig.java` on every run so this copy cannot drift. */
val checkpointGenesisValidatorsRoot = mapOf(
    "mainnet" to "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
    "sepolia" to "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
    "gnosis" to "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47",
)

/**
 * Refresh a network's trusted checkpoint in BOTH engines.
 *
 *   ./gradlew refreshCheckpoint                      # all three networks
 *   ./gradlew refreshCheckpoint -Pnetwork=mainnet    # one
 *   ./gradlew refreshCheckpoint -Pdry                # preview, no write
 *
 * Generalised from the gnosis-only task after the same gap appeared twice: an
 * anchor that drifts below roost's archive floor can never be reached, because
 * the archive only grows FORWARD. mainnet sat at period 1777 against a roost
 * floor of 1825 and simply could not sync.
 *
 * It writes the Rust `ChainConfig` as well as `NetworkConfig.java`. The Rust
 * copy used to carry a "mirror this by hand" note, and hand-mirroring is
 * exactly what gets forgotten — the two engines then disagree about the trust
 * anchor, which the cross-engine parity tests catch only if someone runs them.
 */
tasks.register("refreshCheckpoint") {
    group = "trust"
    description = "Refresh trusted checkpoints in NetworkConfig.java AND the Rust ChainConfig. -Pnetwork=<name> for one, -Pdry to preview, -Pperiod=<n>/-Pslot=<n> to pin instead of head."

    doLast {
        val only = project.findProperty("network") as String?
        // A slot or period number is meaningful on ONE chain. Fanning it out to
        // all three would, on any chain whose head is past it, find a real
        // block, cross-validate the root honestly, and re-anchor a chain the
        // caller never meant to touch — well-formed, verified, and wrong.
        // Applied-or-refused: a pin requires naming the chain it pins.
        if ((project.findProperty("slot") != null || project.findProperty("period") != null) && only == null) {
            throw GradleException("-Pslot/-Pperiod need an explicit -Pnetwork=<name> — a slot is only meaningful on one chain")
        }
        val nets = if (only != null) listOf(only) else listOf("mainnet", "sepolia", "gnosis")
        nets.forEach { n ->
            if (!checkpointEndpoints.containsKey(n)) {
                throw GradleException("unknown network '$n' (mainnet|sepolia|gnosis)")
            }
        }
        nets.forEach { net -> refreshOneCheckpoint(project, logger, net) }
    }
}

