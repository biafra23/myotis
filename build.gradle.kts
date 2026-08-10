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
    version = "0.1.5-SNAPSHOT"
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
    // Public checkpointz providers serve `finalized` ONLY — they 404 on any
    // historical slot — so -Pperiod needs a full node, and the operator names it
    // explicitly rather than the task reaching for loopback behind their back:
    //   -PextraEndpoint=http://127.0.0.1:5054
    // It is appended, never substituted, so it adds a voice to cross-validation
    // instead of replacing the public ones.
    val extra = (project.findProperty("extraEndpoint") as String?)?.split(",")?.map { it.trim() }
        ?.filter { it.isNotEmpty() } ?: emptyList()
    val endpoints = checkpointEndpoints.getValue(net) + extra
    val secondsPerSlot = checkpointSecondsPerSlot.getValue(net)
    val slotsPerPeriod = checkpointSlotsPerPeriod.getValue(net)
    val genesis = (project.property("ethp2p.$net.genesisTime") as String).toLong()

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

    // headers/finalized JSON: data.root is the first "root":"0x..64hex.." key
    // (parent_root/state_root/body_root keys don't match the bare "root").
    val rootRe = Regex(""""root"\s*:\s*"(0x)?([0-9a-fA-F]{64})"""")
    val slotRe = Regex(""""slot"\s*:\s*"?(\d+)"?""")

    data class Hdr(val base: String, val slot: Long, val root: String)

    // An explicit target period anchors at that period's FIRST slot instead of at
    // head. Anchoring at head is wrong for this deployment: roost's archive only
    // grows FORWARD, so an anchor at the newest period leaves a wallet nothing to
    // walk and goes stale the moment the period rolls. The useful anchor is
    // roost's FLOOR — the oldest period it can still serve.
    //
    // A period's first slot may be SKIPPED (no block proposed), which the beacon
    // API answers with 404, so walk forward until a block exists. Bounded at one
    // epoch: past that the chain has bigger problems, and failing loudly beats
    // anchoring somewhere unintended.
    val targetPeriod = (project.findProperty("period") as String?)?.toLong()
    val pinnedSlot: Long? = targetPeriod?.let { p ->
        val first = p * slotsPerPeriod
        (first until first + 32).firstOrNull { slot ->
            endpoints.any { base -> fetch("$base/eth/v2/beacon/blocks/$slot") != null }
        } ?: throw GradleException(
            "[refresh:$net] no block in slots $first..${first + 31} for period $p")
    }
    if (pinnedSlot != null) {
        logger.lifecycle("[refresh:$net] pinning period $targetPeriod → slot $pinnedSlot")
    }

    val probed = endpoints.mapNotNull { base ->
        val path = if (pinnedSlot != null) "$pinnedSlot" else "finalized"
        val body = fetch("$base/eth/v2/beacon/blocks/$path") ?: return@mapNotNull null
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
        throw GradleException("No $net endpoint returned a finalized header")
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
            val body = fetch("${f.base}/eth/v2/beacon/blocks/$minSlot")
            val root = body?.let { rootRe.find(it)?.groupValues?.get(2)?.lowercase() }
            if (root == null) {
                logger.warn("[refresh] ${f.base} could not resolve slot $minSlot"); null
            } else {
                Hdr(f.base, minSlot, root)
            }
        }
    }
    if (resolved.isEmpty()) {
        throw GradleException("No $net endpoint could resolve slot $minSlot")
    }
    val distinct = resolved.map { it.root }.toSet()
    if (distinct.size != 1) {
        val detail = resolved.joinToString("\n  ") { "${it.base} → 0x${it.root}" }
        throw GradleException(
            "Cross-validation FAILED at slot $minSlot. Endpoints disagreed:\n  $detail\n" +
            "Aborting; NetworkConfig.java not modified.")
    }
    val finalRoot = distinct.single()
    // REFUSE on a single responder rather than warn. This writes a TRUST ROOT,
    // and the per-network tasks this replaces already refused — warning instead
    // would have quietly weakened mainnet and sepolia while claiming to unify
    // them. -PallowSingleSource is the named escape hatch for a chain whose
    // providers really are unavailable, so the weaker guarantee is always an
    // explicit choice made on the command line.
    if (resolved.size < 2) {
        val msg = "[refresh:$net] only ${resolved.size} endpoint served slot $minSlot — " +
            "NOT cross-validated (root 0x$finalRoot)"
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

    // BOTH engines, from one fetch. Hand-mirroring the Rust copy is what was
    // forgotten before, and a disagreement between them is a split trust anchor.
    val targets = listOf(
        project(":networking").projectDir.resolve("src/main/java/com/jaeckel/ethp2p/networking/NetworkConfig.java")
            to { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    append(ind).append("// trusted checkpoint: recent finalized $net block root (slot $minSlot, $date, period $period)").append(eol)
                    append(ind).append("Bytes.fromHexString(\"$finalRoot\").toArrayUnsafe(),").append(eol)
                    append(ind).append("${minSlot}L, // checkpoint slot. Must stay in sync with the root above.").append(eol)
                    append(ind).append("// @checkpoint:$net:end")
                }
            },
        project.rootDir.resolve("rust/myotis-net/src/sync.rs")
            to { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    append(ind).append("checkpoint_root: hex32(").append(eol)
                    append(ind).append("    \"$finalRoot\",").append(eol)
                    append(ind).append("),").append(eol)
                    append(ind).append("checkpoint_slot: ${minSlot},").append(eol)
                    append(ind).append("// @checkpoint:$net:end")
                }
            },
        // THIRD target: the parity test literals. They pin the same two values
        // outside the config markers, so a refresh that skipped them would leave
        // `cargo test -p myotis-net` red on its first real run — the tool would
        // break the repo it is meant to maintain.
        project.rootDir.resolve("rust/myotis-net/src/sync.rs")
            to { ind: String, eol: String ->
                buildString {
                    append(ind).append("// @checkpoint:$net:test:begin — managed by `./gradlew refreshCheckpoint`").append(eol)
                    append(ind).append("assert_eq!(c.checkpoint_slot, ${minSlot});").append(eol)
                    append(ind).append("assert_eq!(").append(eol)
                    append(ind).append("    hex_str(&c.checkpoint_root),").append(eol)
                    append(ind).append("    \"$finalRoot\"").append(eol)
                    append(ind).append(");").append(eol)
                    append(ind).append("// @checkpoint:$net:test:end")
                }
            },
    )

    // Render and validate EVERY target before writing ANY. Writing as we go
    // could commit NetworkConfig.java and then throw on sync.rs, leaving the two
    // engines disagreeing about the trust anchor — the exact split this exists
    // to prevent.
    val planned = targets.mapIndexed { idx, (file, render) ->
        val original = file.readText()
        val suffix = if (idx == 2) ":test" else ""
        val beginMarker = "// @checkpoint:$net$suffix:begin"
        val endMarker = "// @checkpoint:$net$suffix:end"
        val beginIdx = original.indexOf(beginMarker)
        val endIdx = original.indexOf(endMarker)
        if (beginIdx < 0 || endIdx < 0 || endIdx < beginIdx) {
            throw GradleException("Could not find @checkpoint:$net markers in ${file.name}")
        }
        val eol = if (original.contains("\r\n")) "\r\n" else "\n"
        val beginLineStart = original.lastIndexOf('\n', beginIdx) + 1
        val endMarkerEnd = endIdx + endMarker.length
        val indent = original.substring(beginLineStart, beginIdx)
        val replacement = render(indent, eol)
        val updated = original.substring(0, beginLineStart) + replacement + original.substring(endMarkerEnd)
        Triple(file, updated, original.substring(beginLineStart, endMarkerEnd) to replacement)
    }

    planned.forEach { (file, updated, diff) ->
        val original = file.readText()
        if (original == updated) {
            logger.lifecycle("[refresh:$net] ${file.name} already up to date (slot $minSlot). No change.")
        } else if (dryRun) {
            logger.lifecycle("[refresh:$net] -Pdry; preview of ${file.name}:")
            diff.first.lines().forEach { logger.lifecycle("- $it") }
            diff.second.lines().forEach { logger.lifecycle("+ $it") }
        } else {
            val tmp = File(file.absolutePath + ".tmp")
            tmp.writeText(updated)
            Files.move(tmp.toPath(), file.toPath(),
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            logger.lifecycle("[refresh:$net] ${file.name} updated: slot=$minSlot period=$period root=0x$finalRoot")
        }
    }
}

/** Per-network checkpoint sources.
 *
 *  A LOCAL beacon node comes first when one is running. As of 2026-08-10 the
 *  public checkpoint-sync providers no longer answer
 *  `/eth/v1/beacon/headers/finalized` — beaconstate.info, beaconcha.in and
 *  attestant all fail or 404 — so on a machine without a local node this task
 *  now has no source at all. That is a finding about the providers, not about
 *  this task: the pre-existing per-network tasks depend on the same endpoint
 *  and are equally dead.
 *
 *  A local node is a legitimate source and NOT a shortcut: it followed the chain
 *  over p2p from its own checkpoint, so it is an independent opinion rather than
 *  a relay of one of these providers. It is still ONE opinion — when it is the
 *  only responder the task says so loudly, exactly as it did for gnosis, and
 *  the operator is expected to cross-check against an explorer before trusting
 *  a fresh anchor.
 *
 *  Unreachable endpoints are skipped and reported; the task refuses to write
 *  when nothing responds. */
val checkpointEndpoints = mapOf(
    "mainnet" to listOf(
        "https://beaconstate.info",
        "https://sync-mainnet.beaconcha.in",
        "https://mainnet-checkpoint-sync.attestant.io",
    ),
    "sepolia" to listOf(
        "https://sepolia.beaconstate.info",
        "https://checkpoint-sync.sepolia.ethpandaops.io",
        "https://beaconstate-sepolia.chainsafe.io",
    ),
    "gnosis" to listOf(
        "https://rpc-gbc.gnosischain.com",
        "https://checkpoint.gnosischain.com",
        "https://gnosis-beacon.publicnode.com",
    ),
)
val checkpointSecondsPerSlot = mapOf("mainnet" to 12L, "sepolia" to 12L, "gnosis" to 5L)
val checkpointSlotsPerPeriod = mapOf("mainnet" to 8192L, "sepolia" to 8192L, "gnosis" to 8192L)

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
    description = "Refresh trusted checkpoints in NetworkConfig.java AND the Rust ChainConfig. -Pnetwork=<name> for one, -Pdry to preview."

    doLast {
        val only = project.findProperty("network") as String?
        val nets = if (only != null) listOf(only) else listOf("mainnet", "sepolia", "gnosis")
        nets.forEach { n ->
            if (!checkpointEndpoints.containsKey(n)) {
                throw GradleException("unknown network '$n' (mainnet|sepolia|gnosis)")
            }
        }
        nets.forEach { net -> refreshOneCheckpoint(project, logger, net) }
    }
}

