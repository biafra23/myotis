// The daemon must run the SAME netty as the Android app: the JitPack
// netty-kotlin fork, not upstream io.netty. jvm-libp2p (via :consensus) and
// Besu's netty-bom (via :myotis-evm) would otherwise drag upstream io.netty
// onto the runtime classpath. Strip it group-wide; the fork (republished under
// the same io.netty.* package names) is supplied by :consensus and :networking
// and satisfies every io.netty.* reference at runtime. Mirrors android-app.
configurations.all {
    exclude(group = "io.netty")
}

dependencies {
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    implementation(project(":myotis-ens"))
    // Verified JSON-RPC endpoint: the shared backend (:rpc-backend) served over
    // the Ktor HTTP server (:jsonrpc-server) on 127.0.0.1:8545 — same pair the
    // Android app hosts in NodeService.
    implementation(project(":jsonrpc-server"))
    implementation(project(":rpc-backend"))
    // :app source references io.netty.channel.* (via :networking's RLPxConnector
    // API). With io.netty excluded group-wide, the fork must be on :app's compile
    // classpath explicitly (:networking declares it as implementation, so it
    // isn't exposed transitively). Same fork artifacts as android-app/:consensus.
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    implementation(libs.trueblocks.kotlin)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("run") {
    group = "application"
    description = "Run the ethp2p daemon (no args) or send a command to a running daemon (-Pargs=<cmd>)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass = "com.jaeckel.ethp2p.app.Main"
    // Use Java 21 toolchain JVM (matches compile target)
    javaLauncher = javaToolchains.launcherFor {
        languageVersion = JavaLanguageVersion.of(21)
    }
    // Pass -Pargs="status" / -Pargs="get-headers 21000000 3" etc. to the JVM main
    // Pass -Pnetwork=sepolia to select a testnet (default: mainnet)
    val appArgs = mutableListOf<String>()
    val networkArg = project.findProperty("network") as String?
    if (networkArg != null) {
        appArgs.add("--network")
        appArgs.add(networkArg)
    }
    val portArg = project.findProperty("port") as String?
    if (portArg != null) {
        appArgs.add("--port")
        appArgs.add(portArg)
    }
    // -Pgossipsub=true enables the (observation-only) light-client gossipsub
    // subscription. Off by default because short-session clients churn the mesh.
    val gossipsubArg = project.findProperty("gossipsub") as String?
    if (gossipsubArg != null && gossipsubArg.equals("true", ignoreCase = true)) {
        appArgs.add("--gossipsub")
    }
    val cmdArgs = (project.findProperty("args") as String?)
        ?.split("\\s+".toRegex())
        ?.filter { it.isNotEmpty() }
        ?: emptyList()
    appArgs.addAll(cmdArgs)
    args(appArgs)
}
