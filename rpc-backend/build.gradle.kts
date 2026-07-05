// :rpc-backend — the shared, verified JSON-RPC backend.
//
// Hosts the verified-read machinery (head-context anchoring, the snap-backed
// state oracle wiring, the cross-call StateProofCache, fee derivation, the
// per-pinned-block frozen context) behind the `MyotisRpcBackend` interface from
// :jsonrpc-server, plus the shared `EthHandlerSnapPeer` adapter that bridges
// :networking's EthHandler to :myotis-evm's SnapPeer.
//
// This is the single implementation that BOTH :android-app (NodeService) and the
// :app CLI daemon construct, so the verified-RPC logic — and the confirm-screen
// fixes — live once. Before this module, that logic was Android-only in
// NodeService and the adapter was copy-pasted into :app and :android-app (no
// common module saw both :networking and :myotis-evm). This module does.
//
// Java 21 source/target: it depends on :networking (discv5) and :myotis-evm
// (Besu), both of which publish JVM-21 Gradle metadata, so a 21 consumer is
// required (same rationale as those modules; CLAUDE.md's 17 default yields when
// a transitive forces 21). AGP 8.7's D8 dexes 21 class files for :android-app.

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // The engine API — VerifiedRpcBackend implements io.myotis.api.VerifiedReads.
    // (node-core, the only consumer that reads it as a VerifiedReads, depends on
    // :myotis-api directly too, so implementation scope is sufficient.)
    implementation(project(":myotis-api"))
    // The Ktor JSON-RPC server this backend is served through.
    implementation(project(":jsonrpc-server"))

    // Verified-read primitives, shared with both hosts.
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    implementation(project(":myotis-ens"))

    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.units)
    implementation(libs.tuweni.crypto)
    implementation(libs.tuweni.rlp)

    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
