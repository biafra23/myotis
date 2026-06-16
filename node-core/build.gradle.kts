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

configurations.all {
    // Mirror :app / :android-app: strip upstream io.netty so the JitPack
    // netty-kotlin fork (republished under the same io.netty.* names, supplied by
    // :networking/:consensus) is the single netty on the runtime classpath.
    exclude(group = "io.netty")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    implementation(project(":myotis-ens"))
    // The verified backend + the Ktor JSON-RPC server each ChainStack hosts.
    implementation(project(":jsonrpc-server"))
    implementation(project(":rpc-backend"))

    // node-core source references io.netty.channel.* via :networking's RLPxConnector
    // API; with io.netty excluded group-wide the fork must be on the compile
    // classpath explicitly (same as :app).
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
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    useJUnitPlatform()
}
