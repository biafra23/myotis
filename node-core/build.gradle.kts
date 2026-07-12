// :node-core — the shared multi-network host core.
//
// Owns `ChainStack` (one network's full stack: RLPxConnector + DiscV4Service +
// DiscV5Service + BeaconLightClient + BeaconSyncState + VerifiedRpcBackend +
// MyotisRpcServer, on its own ports + identity) and `NodeRegistry`
// (Map<String,ChainStack>). BOTH the :app CLI daemon and :android-app NodeService
// host the SAME registry; platform-specific pieces (peer caches, node-key file
// location, CCIP gateway, RPC upstream) are injected via small interfaces defined
// here, so the per-network lifecycle + dial logic + N-RPC wiring live once instead
// of being duplicated across the two hosts.
//
// Java 21 source/target: it depends on :networking (discv5), :consensus (libp2p),
// :myotis-evm (Besu) and :rpc-backend, all of which publish JVM-21 Gradle metadata,
// so a 21 consumer is required (same rationale as :rpc-backend; CLAUDE.md's 17
// default yields when a transitive forces 21). AGP 8.7's D8 dexes 21 class files
// for :android-app.

plugins {
    // On top of the root `java` plugin: adds the `api` configuration so the
    // :myotis-api contract types flow transitively to hosts.
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // The formal engine boundary this module implements (io.myotis.node.api adapters).
    // `api` (not `implementation`): hosts consume the interface types transitively.
    api(project(":myotis-api"))
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    implementation(project(":myotis-ens"))
    // The verified backend + the Ktor JSON-RPC server each ChainStack hosts.
    implementation(project(":jsonrpc-server"))
    implementation(project(":rpc-backend"))

    // node-core source references io.netty.channel.* via :networking's RLPxConnector
    // API; :networking declares netty as implementation (not exposed transitively),
    // so declare it here for the compile classpath (same as :app).
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)

    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.units)
    implementation(libs.tuweni.crypto)
    implementation(libs.tuweni.rlp)

    implementation(libs.slf4j.api)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // Tuweni's keccak256 needs the BC provider registered in tests.
    testImplementation(libs.bouncycastle)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
    // Regeneration knob for the EL conformance corpora (ElVerifyVectorConformanceTest):
    // forward it into the forked test JVM, as :consensus and :networking do.
    System.getProperty("myotis.el.writeExpected")?.let {
        systemProperty("myotis.el.writeExpected", it)
    }
}
