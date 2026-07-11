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
    // Shared per-network host core: ChainStack/NodeRegistry. The daemon supplies
    // file-backed cache adapters + the JVM CCIP gateway and hosts the same stacks
    // the Android app does.
    implementation(project(":node-core"))
    // The engine selector: Main's composition root is Engines.engine(), routing to
    // the Java or Rust engine per -Dmyotis.engine.
    implementation(project(":myotis-engines"))
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
    // CommandHandler's static init computes a keccak256 → tests must register the BC provider.
    testImplementation(libs.bouncycastle)
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
    // Build the Rust workspace first (no-op without cargo; instant when unchanged) and
    // put its release dir on java.library.path so BlsBackends auto-selects the native
    // backend (~15x faster BLS verify). Falls back to Milagro when cargo is absent.
    // Override choice with -Dmyotis.bls.backend=milagro|native|compare.
    dependsOn(rootProject.tasks.named("cargoBuildHost"))
    // Resolved in doFirst — the dir only exists AFTER cargoBuildHost has run once.
    doFirst {
        rootProject.file("rust/target/release").takeIf { it.exists() }?.let {
            systemProperty(
                "java.library.path",
                it.absolutePath + System.getProperty("path.separator") + System.getProperty("java.library.path"),
            )
        }
    }
    // -Pbls=milagro|native|compare|auto → -Dmyotis.bls.backend (e.g. compare logs a
    // per-verify Milagro-vs-native head-to-head during a live sync).
    (project.findProperty("bls") as String?)?.let { systemProperty("myotis.bls.backend", it) }
    // -Pengine=java|rust|auto → -Dmyotis.engine (the :myotis-engines selector).
    // Fail fast on a typo: an unrecognized value would otherwise silently fall
    // back to the Java engine (Engines.normalize warns + yields java), so a
    // `-Pengine=rust.` runs Java without it being obvious. Blank → unset (default
    // java).
    (project.findProperty("engine") as? String)?.takeIf { it.isNotBlank() }?.let { raw ->
        val v = raw.trim().lowercase()
        if (v !in listOf("java", "rust", "auto")) {
            throw GradleException("-Pengine must be one of java|rust|auto (got '$raw')")
        }
        systemProperty("myotis.engine", v)
    }
    // -Prustlog=<filter> → RUST_LOG for the Rust engine's tracing (drained to
    // stdout via the `rust` logger). Gradle's run task doesn't forward the
    // shell's RUST_LOG to the forked JVM, so set it explicitly. Accepts the full
    // env_logger/tracing syntax: `-Prustlog=debug` for everything, or a targeted
    // filter like `-Prustlog=myotis_net=debug,info` (default when unset:
    // info with the noisy deps at warn).
    // Guard against a blank value: `-Prustlog=` would set RUST_LOG="" and
    // OVERRIDE the engine's default filter with an empty one (silencing the Rust
    // logs) — treat blank as unset so the default stands.
    (project.findProperty("rustlog") as? String)?.takeIf { it.isNotBlank() }
        ?.let { environment("RUST_LOG", it) }
    // -Plcdump=<dir> → -Dmyotis.lc.dumpVectors: capture raw light-client SSZ
    // (bootstrap/updates/finality) for the rust/testdata conformance corpus.
    (project.findProperty("lcdump") as String?)?.let { systemProperty("myotis.lc.dumpVectors", it) }
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
    // Force our logback config over the one trueblocks-kotlin bundles on the
    // classpath. Both are console-only (stdout); the daemon vs client split just
    // differs in log levels. Follow the daemon with `./gradlew :app:run` in the
    // terminal (or redirect its stdout).
    systemProperty(
        "logback.configurationFile",
        if (cmdArgs.isEmpty()) "logback-daemon.xml" else "logback-client.xml",
    )
}
