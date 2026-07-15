// :tx-history — TrueBlocks Unchained Index transaction history (a DEBUG/explorer aid).
//
// Scans the index's bloom-filtered chunks (IPFS, disk-cached) for address appearances
// and resolves them to transactions over devp2p. Shared by the daemon's IPC
// `get-transactions` stream and the desktop Query tab. Like that IPC command, this
// module is a documented exemption from the "hosts consume only :myotis-api" rule:
// it wraps the raw RLPxConnector (engine internals), is Java-engine-only, and results
// are UNVERIFIED (never checked against a transactionsRoot).
//
// JVM 21 (not the 17 default): :networking ships Java-21 classes (ConsenSys discv5
// 26.4.0 — see its build file), and this module compiles against RLPxConnector.
// Desktop/daemon-only; the Android host never consumes it.

plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":networking"))   // RLPxConnector, EthTxDecoder, block messages
    implementation(project(":myotis-api"))    // VerifiedReads (manifest eth_call + head block)

    implementation(libs.trueblocks.kotlin)    // manifest/bloom/index parsing
    // Compile-time access to org.kethereum.model.Address for Bloom.isMemberBytes —
    // trueblocks-kotlin's POM exposes kethereum at runtime scope only.
    implementation(libs.kethereum.model)

    implementation(libs.kotlinx.coroutines.core)
    // Ktor for the bloom/index chunk downloads (project HTTP-client convention);
    // the manifest fetch reuses trueblocks-kotlin's own OkHttp-based client, which
    // is already on the classpath transitively.
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.cio)

    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)        // keccak256 for tx hashes
    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.tuweni.rlp)       // fixture txs are hand-RLP'd + signed in tests
    // EthTxDecoder's sender recovery needs the BouncyCastle SECP256K1 provider on
    // the test classpath (hosts register it at startup; tests do it in @BeforeAll).
    testImplementation(libs.bouncycastle)
}
