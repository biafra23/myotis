dependencies {
    implementation(project(":core"))
    implementation(project(":networking"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.crypto)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.logback.classic)
}

tasks.register<JavaExec>("run") {
    group = "application"
    description = "Run the devp2p daemon (no args) or send a command to a running daemon (-Pargs=<cmd>)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass = "devp2p.app.Main"
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
    val cmdArgs = (project.findProperty("args") as String?)
        ?.split("\\s+".toRegex())
        ?.filter { it.isNotEmpty() }
        ?: emptyList()
    appArgs.addAll(cmdArgs)
    args(appArgs)
}
