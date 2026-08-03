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
// Consumed by the daemon, desktop AND Android hosts — Android already dexes
// classfile-65 bytecode (discv5, see libs.versions.toml), and everything here is
// Android-safe: java.nio.file (API 26+; minSdk is 29), Ktor client (the project's
// HTTP convention), no java.net.http, no logback-coupled code (see the trueblocks
// dependency excludes below).

plugins {
    alias(libs.plugins.kotlin.jvm)
    // java-library: TxHistoryService's public constructor leaks :networking and
    // :myotis-api types, so they're `api` deps (see below) — that configuration
    // comes from java-library, not the bare kotlin-jvm plugin.
    `java-library`
}

kotlin { jvmToolchain(21) }

dependencies {
    // api (not implementation): TxHistoryService's PUBLIC constructor exposes
    // RLPxConnector (:networking) and VerifiedReads (:myotis-api), so a consumer must
    // see those types transitively — today's consumers (:app, :app-desktop) only happen
    // to already depend on both.
    api(project(":networking"))               // RLPxConnector, EthTxDecoder, block messages
    api(project(":myotis-api"))               // VerifiedReads (manifest eth_call + head block)

    implementation(libs.trueblocks.kotlin) {  // bloom/index byte parsers only
        // Only the pure parsers (Bloom, IndexParser, AppearanceRecord) are used; the
        // lib's own IpfsHttpClient is never constructed — its constructor force-casts
        // the slf4j factory to logback's LoggerContext, which would crash on Android
        // (no logback binding there). Keep its HTTP/JSON/logging stack out of the
        // classpath and the APK.
        exclude(group = "com.squareup.okhttp3")
        exclude(group = "com.squareup.moshi")
        exclude(group = "ch.qos.logback")
        exclude(group = "com.github.biafra23", module = "ipfs-api-kotlin")
    }
    // Compile-time access to org.kethereum.model.Address for Bloom.isMemberBytes —
    // trueblocks-kotlin's POM exposes kethereum at runtime scope only.
    implementation(libs.kethereum.model)
    // Manifest JSON parsing (tiny, dependency-free, Android-safe — same parser
    // :myotis-engines uses for its JNI marshalling).
    implementation(libs.minimal.json)

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
