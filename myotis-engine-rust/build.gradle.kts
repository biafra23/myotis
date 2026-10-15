// :myotis-engine-rust — the RUST engine behind the :myotis-api contract, on its own:
// RustMyotisEngine / RustChainHandle / RustVerifiedReads / RustEnsApi over the
// COMMITTED UniFFI-generated Kotlin bindings (src/main/kotlin/uniffi/myotis_engine/,
// regenerated via the root `uniffiGenerateKotlin` task) and JNA, plus the Tor seam.
// The goal is a module that depends on NOTHING from the Java engine (node-core /
// networking / consensus / Besu), so that a library can ship this engine alone and a
// consumer needs none of the Java engine's Android build hacks (the Besu fork
// substitutions, the Guava variant pin, the log4j shim). NOT THERE YET: the direct
// node-core dependency is gone (WakeGate/SleepMetrics live in :myotis-engine-common
// now), but :jsonrpc-server below still pulls :networking, :consensus and
// :myotis-evm (Besu) in transitively — the next part of feature/android-aar turns it
// into a port. Host composition roots keep using the :myotis-engines selector; this
// module is what the selector routes `rust`/`auto` to, and what the Kotlin
// Multiplatform engine library (the Android AAR + the desktop jar) will wrap.

plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
}

// JVM 21 class files, not the project's preferred 17: :jsonrpc-server (the Ktor
// JSON-RPC server the Rust engine self-starts over RustVerifiedReads) targets JVM 21,
// and Gradle's variant matching refuses a 17-targeted consumer. The Android app
// already compiles against class-file-65 dependencies via its jvmToolchain(21)
// two-layer setup (android-app/build.gradle.kts). Revisit when :jsonrpc-server
// drops to 17.
kotlin { jvmToolchain(21) }

// The committed UniFFI bindings are NOT force-regenerated from compileKotlin:
// a `dependsOn(uniffiGenerateKotlin)` would drag a full `cargo build --release`
// (via cargoBuildHost) in front of every JVM host's Kotlin compile and make a
// broken rust/ break the JVM build — violating "Rust is OPTIONAL for the JVM
// hosts". Auto-regeneration is scoped to the Android build (:android-app
// preBuild, where cargo is already required); CI enforces freshness everywhere
// via the regenerate-and-diff step in android-apk.yml; regenerate manually
// elsewhere with `./gradlew uniffiGenerateKotlin`.
//
// mustRunAfter (NOT dependsOn) is ORDERING ONLY — inert when uniffiGenerateKotlin
// isn't in the graph (every non-Android build: no cargo pulled in), and, when it
// IS (an Android build regenerating the bindings), it makes compileKotlin read
// the fresh .kt and satisfies Gradle's implicit-dependency validation, since
// compileKotlin consumes uniffiGenerateKotlin's declared output.
tasks.named("compileKotlin") {
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}

dependencies {
    // The contract this engine implements.
    api(project(":myotis-api"))
    // WakeGate + SleepMetrics: the lifecycle primitives both engines' handles wire.
    implementation(project(":myotis-engine-common"))
    // The shared JSON-RPC server (MyotisRpcServer/RpcRouter): the Rust engine self-
    // starts it over RustVerifiedReads, mirroring how the Java engine (node-core)
    // self-starts it internally. STILL HERE, and it is the one edge that still drags
    // the Java engine's stack in (its jvmMain depends on :networking, :consensus and
    // :myotis-evm). The library must not carry the loopback server (owner's request,
    // 2026-10-15), so the next part turns this into a port the :myotis-engines
    // selector supplies for the JVM hosts, and moves RpcBlockWindow (the
    // serving-window policy RustVerifiedReads shares with the iOS backend) out of
    // :jsonrpc-server.
    implementation(project(":jsonrpc-server"))
    // Android-safe minSdk-29 shims shared across the engine modules (core.encoding.Hex
    // for the FFI hex boundary — java.util.HexFormat is API 34; see CLAUDE.md).
    implementation(project(":core"))
    implementation(libs.minimal.json)
    implementation(libs.slf4j.api)
    // The FFI layer under the UniFFI-generated Kotlin bindings. Plain JVM artifact
    // here; the Android hosts supply the @aar natives (libjnidispatch.so) themselves.
    implementation(libs.jna)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Build the Rust workspace first (no-op without cargo) and put its release dir on
    // java.library.path so the native-backed tests exercise the real libmyotis_engine.
    // Declared as an INPUT so a rebuilt native lib re-runs these tests (mirrors
    // :consensus). inputs.files tolerates missing outputs on cargo-less machines,
    // where those tests self-skip via assumeTrue.
    inputs.files(rootProject.tasks.named("cargoBuildHost")).withPropertyName("nativeRustLibs")
    doFirst {
        val nativeDir = rootProject.file("rust/target/release")
        if (nativeDir.exists()) {
            val sep = System.getProperty("path.separator")
            systemProperty(
                "java.library.path",
                nativeDir.absolutePath + sep + System.getProperty("java.library.path"),
            )
        }
    }
}
