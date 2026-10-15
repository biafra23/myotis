// :myotis-engines — the engine SELECTOR: the one module hosts point their composition
// roots at instead of naming a concrete engine. `Engines.engine()` returns a
// SelectorEngine that routes create() to the Java engine (node-core) or the Rust
// engine (:myotis-engine-rust, over the UniFFI bindings) per
// `myotis.engine=java|rust|auto` (default auto), and routes get/stop by recorded
// ownership. The Rust engine itself lives in :myotis-engine-rust so that it can be
// packaged without the Java engine (the Android library); this module is the
// composition of the two.

plugins {
    `java-library`
}

// JVM 21 class files, not the project's preferred 17: the :node-core dependency (the
// Java engine) publishes a JVM-21 floor (transitively forced by :networking's discv5),
// and Gradle's variant matching refuses a 17-targeted consumer. Same documented
// exception as :networking/:myotis-evm — revisit if node-core ever drops to 17.
java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // The contract this module selects implementations of.
    api(project(":myotis-api"))
    // The Rust engine — the other selectable engine. `implementation`, like
    // node-core: a host that uses the Rust engine's own host-side seam (the Tor
    // toggle, a documented exemption in CLAUDE.md) declares :myotis-engine-rust
    // itself, so the engine does not land on every host's compile classpath by
    // way of the selector.
    implementation(project(":myotis-engine-rust"))
    // The Java engine (JavaMyotisEngine) — the other selectable engine.
    implementation(project(":node-core"))
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
    // java.library.path so the catalog-parity and selector tests exercise the real
    // libmyotis_engine. Declared as an INPUT so a rebuilt native lib re-runs these
    // tests (mirrors :consensus). inputs.files tolerates missing outputs on cargo-less
    // machines, where the native-backed tests self-skip via assumeTrue.
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
