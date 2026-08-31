// :myotis-engines — the engine SELECTOR: the one module hosts point their composition
// roots at instead of naming a concrete engine. `Engines.engine()` returns a
// SelectorEngine that routes create() to the Java engine (node-core) or the Rust
// engine (rust/myotis-engine via hand-JNI) per `myotis.engine=java|rust|auto`
// (default java), and routes get/stop by recorded ownership.

plugins {
    `java-library`
    // Kotlin hosts the COMMITTED UniFFI-generated bindings for the Rust engine
    // (src/main/kotlin/uniffi/myotis_engine/ — regenerate via the root
    // `uniffiGenerateKotlin` task); RustEngineNative delegates to them.
    alias(libs.plugins.kotlin.jvm)
}

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

// JVM 21 class files, not the project's preferred 17: the :node-core dependency (the
// Java engine) publishes a JVM-21 floor (transitively forced by :networking's discv5),
// and Gradle's variant matching refuses a 17-targeted consumer. Same documented
// exception as :networking/:myotis-evm — revisit if node-core ever drops to 17.

dependencies {
    // The contract this module selects implementations of.
    api(project(":myotis-api"))
    // The Java engine (JavaMyotisEngine) — one of the two selectable engines.
    implementation(project(":node-core"))
    // The shared JSON-RPC server (MyotisRpcServer/RpcRouter): the Rust engine self-
    // starts it over RustVerifiedReads, mirroring how the Java engine (node-core)
    // self-starts it internally. Consumers already ship it transitively via node-core.
    implementation(project(":jsonrpc-server"))
    // Android-safe minSdk-29 shims shared across the engine modules (core.encoding.Hex
    // for the FFI hex boundary — java.util.HexFormat is API 34; see CLAUDE.md).
    implementation(project(":core"))
    implementation(libs.minimal.json)
    implementation(libs.slf4j.api)
    // The FFI layer under the UniFFI-generated Kotlin bindings (replaces hand-JNI).
    // Plain JVM artifact here; :android-app pins the @aar variant for its natives.
    implementation(libs.jna)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // JavaMyotisEngine.availableNetworks() class-loads NetworkConfig, whose genesis
    // verification needs the KECCAK-256 JCE provider.
    testImplementation(libs.bouncycastle)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Build the Rust workspace first (no-op without cargo) and put its release dir on
    // java.library.path so the catalog-parity tests exercise the real libmyotis_engine.
    // Declared as an INPUT so a rebuilt native lib re-runs these tests (mirrors
    // :consensus). inputs.files tolerates missing outputs on cargo-less machines,
    // where the parity tests self-skip via assumeTrue.
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
