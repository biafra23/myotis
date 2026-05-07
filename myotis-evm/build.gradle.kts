// myotis-evm — local EVM execution against SNAP-verified state.
//
// Phase 0: the Besu EVM module is wired in and a fixture-backed WorldUpdater
// proves the integration end-to-end. Later phases swap the fixture for a
// SNAP-backed oracle without touching this file.
//
// Source/target is Java 21 because org.hyperledger.besu:evm:24.12.2 publishes
// Gradle module metadata declaring a JVM-21 floor (same situation as the
// ConsenSys discv5 library used by :networking). CLAUDE.md's default is
// Java 17, with explicit licence to diverge when a transitive forces it; this
// is one of those cases. AGP 8.7's D8 accepts Java 21 class files as input
// for the Android module, verified by the existing :networking pipeline.
// No Netty excludes needed: nothing here pulls it.

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    implementation(project(":core"))

    // Besu EVM. Brings in besu-datatypes transitively, but pin both so the
    // version catalog is the single bump-point.
    implementation(libs.besu.evm)
    implementation(libs.besu.datatypes)

    // Tuweni Bytes/UInt256 are part of Besu's public API surface, so we use
    // the same coordinates here for ABI codec inputs/outputs.
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.units)
    implementation(libs.tuweni.crypto)
    implementation(libs.tuweni.rlp)

    // BouncyCastle: Tuweni's Hash.keccak256 dispatches through JCA, which
    // requires BouncyCastle to be registered as a security provider.
    implementation(libs.bouncycastle)

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
// Closes Phase 1's acceptance criterion: USDC / DAI / ENS public-resolver
// balanceOf/addr against a real SNAP peer at a verified state root, results
// compared with eth_call from a public RPC at the same block.
//
// Gated by env var MYOTIS_MAINNET=1 so `./gradlew :myotis-evm:test` (the unit
// suite) stays offline. Run explicitly via `./gradlew :myotis-evm:integrationTest`
// after providing a peer + state root via env vars (see the test class for
// the contract).
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
    description = "Phase 1 mainnet integration tests (env-gated, requires MYOTIS_MAINNET=1)."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform()
    // Don't bind to `./gradlew check` — operators run this on demand.
    shouldRunAfter("test")
}
