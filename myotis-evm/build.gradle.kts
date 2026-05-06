// myotis-evm — local EVM execution against SNAP-verified state.
//
// Phase 0: the Besu EVM module is wired in and a fixture-backed WorldUpdater
// proves the integration end-to-end. Later phases swap the fixture for a
// SNAP-backed oracle without touching this file.
//
// The module currently targets the JVM (Java 21) only. The android-app module
// already strips io.netty natives and is the eventual consumer; nothing in
// myotis-evm pulls Netty, so no extra excludes are needed.

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
