// myotis-ens — classic on-chain ENS forward + reverse resolution.
//
// Builds on :myotis-evm — the resolver chains two callView invocations
// through the EvmExecutor (registry.resolver(node) → resolver.addr(node))
// and re-uses its ABI codec + Namehash helper.
//
// Source/target Java 21 because :myotis-evm pins Java 21 (transitive
// requirement from Besu); the Java-17 target is the project default but
// modules that depend on :myotis-evm have to match its bytecode floor.

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    implementation(project(":myotis-evm"))
    // Android-safe minSdk-29 shims shared across the engine modules
    // (core.encoding.Hex, core.math.BigIntegers — see CLAUDE.md's API budget).
    implementation(project(":core"))

    // Tuweni Bytes for hex parsing of the canonical mainnet addresses.
    implementation(libs.tuweni.bytes)

    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}

// ----------------------------------------------------------------------------
// Mainnet integration tests
//
// Closes Phase 3's acceptance criterion: forward + reverse resolution against
// a curated test set of ~10 names against a real SNAP peer at a verified
// state root.
//
// Same env-gating as Phase 1/2: MYOTIS_MAINNET=1 enables the tests; they read
// the supporting peer / state-root env vars. Run via
// `./gradlew :myotis-ens:integrationTest`.
// ----------------------------------------------------------------------------
sourceSets {
    create("integrationTest") {
        java.srcDir("src/integrationTest/java")
        resources.srcDir("src/integrationTest/resources")
        compileClasspath += sourceSets["main"].output
        runtimeClasspath += sourceSets["main"].output
    }
}

configurations {
    "integrationTestImplementation" {
        extendsFrom(configurations["testImplementation"])
    }
    "integrationTestRuntimeOnly" {
        extendsFrom(configurations["testRuntimeOnly"])
    }
}

dependencies {
    "integrationTestImplementation"(project(":app"))
    "integrationTestImplementation"(project(":networking"))
    "integrationTestImplementation"(libs.tuweni.bytes)
}

tasks.register<Test>("integrationTest") {
    description = "Phase 3 mainnet ENS resolution tests (env-gated, requires MYOTIS_MAINNET=1)."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter("test")
}
