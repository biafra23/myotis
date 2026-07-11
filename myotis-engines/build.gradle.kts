// :myotis-engines — the engine SELECTOR: the one module hosts point their composition
// roots at instead of naming a concrete engine. `Engines.engine()` returns a
// SelectorEngine that routes create() to the Java engine (node-core) or the Rust
// engine (rust/myotis-engine via hand-JNI) per `myotis.engine=java|rust|auto`
// (default java), and routes get/stop by recorded ownership.

plugins {
    `java-library`
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
    implementation(libs.minimal.json)
    implementation(libs.slf4j.api)

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
