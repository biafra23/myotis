// :app-desktop — the Compose-Multiplatform DESKTOP app. Hosts the shared `:ui` NodeScreen
// and drives the Java backend (`node-core`) in-process via DesktopNodeController — the same
// backend the daemon and Android use, so there's no duplication. (JVM target; not iOS.)

import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin { jvmToolchain(21) }

// Historical (Besu ≤24.12; 26.4 targets tuweni 2.7.2 so io.tmio is gone from the
// graph — the exclude stays as a cheap guard):
// Besu (via :myotis-evm) dragged in the pre-rename tuweni coordinates io.tmio:tuweni-* 2.4.2,
// whose org.apache.tuweni.bytes.Bytes collides with the JitPack Kotlin fork we use
// (com.github.biafra23.tuweni-kotlin 2.7.2). A single classloader loads only ONE Bytes for
// that FQN: tuweni-rlp 2.7.2 (BytesRLPWriter.kt) needs the 2.7.2 Bytes' Kotlin `Companion`,
// which the 2.4.2 class lacks → NoSuchFieldError at launch. The `gradle run` daemon happens
// to load the 2.7.2 jar first; jpackage's flattened classpath lets the 2.4.2 one win. Strip
// io.tmio so only one tuweni 2.7.2 remains (same packages; Besu already runs against 2.7.2 on
// the daemon, so 2.4.2 is unneeded) — mirrors the :android-app exclusion.
// (Historical: while the Kotlin tuweni/netty forks were in use, io.consensys.tuweni and
// io.netty were also excluded here to prevent duplicate-class crashes in the flattened
// jpackage bundle. Upstream is canonical again, so those excludes are gone — a single
// source per class.)
configurations.all {
    exclude(group = "io.tmio")
}

dependencies {
    implementation(project(":ui"))

    // The shared backend + the daemon's file-backed cache adapters / CCIP gateway, reused.
    implementation(project(":node-core"))
    // Engine selector: DesktopNodeController defaults to Engines.engine().
    implementation(project(":myotis-engines"))
    implementation(project(":app"))
    // TrueBlocks tx-history scan for the Query tab (documented API-boundary exemption:
    // it reaches the raw connector via SelectorEngine.javaDelegate().debugStack).
    implementation(project(":tx-history"))
    implementation(project(":networking"))
    implementation(project(":consensus"))
    implementation(project(":myotis-evm"))
    // EnsResolutionRoot is referenced directly when calling rpcBackend().resolveEns(...).
    implementation(project(":myotis-ens"))
    implementation(project(":rpc-backend"))
    // VerifiedRpcBackend implements jsonrpc-server's MyotisRpcBackend; calling
    // verifiedHeadAgeMs() forces Kotlin to resolve that supertype, so it must be on the
    // compile classpath (rpc-backend exposes VerifiedRpcBackend only as `implementation`).
    implementation(project(":jsonrpc-server"))
    implementation(project(":core"))

    implementation(compose.desktop.currentOs)
    implementation(libs.kotlinx.coroutines.core)

    // implementation (not runtimeOnly): DesktopLogAppender compiles against logback's
    // AppenderBase/ILoggingEvent to tee logs into the in-app Logs tab's in-memory ring.
    implementation(libs.logback.classic)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // The Compose plugin drags an older junit-platform-launcher onto the test runtime
    // classpath; pin the bom-aligned one or the jupiter engine fails discovery
    // ("OutputDirectoryProvider not available … unaligned versions").
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// This module skips the root `java`-plugin conventions (Compose brings its own plugins),
// so wire the JUnit platform here like :app does.
tasks.withType<Test> {
    useJUnitPlatform()
}

// Headless check that the Desktop controller drives node-core (no display needed).
tasks.register<JavaExec>("syncSmoke") {
    group = "verification"
    description = "Start the primary network in-process and exit 0 on SYNCED (no GUI)."
    mainClass.set("io.myotis.desktop.SyncSmokeKt")
    classpath = sourceSets["main"].runtimeClasspath
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
    systemProperty("myotis.logfile", rootProject.file("devp2p.log").absolutePath)
}

// ---------------------------------------------------------------------------
// Bundle the Rust engine into PACKAGED desktop apps (dmg/deb/distributable):
// cargoBuildHost's host lib is staged into Compose's appResources under the
// current os-arch subdir; jpackage ships that dir inside the app and exposes
// it at runtime via the `compose.application.resources.dir` system property,
// which Main.kt forwards to the engine loader (-Dmyotis.engine.lib). Dev
// `run`/`syncSmoke` keep their absolute-path wiring below and never bake a
// path into packages. FAIL-LOUD: packaging without cargo must error, never
// silently ship a Java-only app with a dead engine toggle (same philosophy
// as the APK workflow's self-skip guard).
// ---------------------------------------------------------------------------
val rustHostLibName = rootProject.extra["rustEngineLibName"] as String
val rustReleaseDir = rootProject.extra["rustReleaseDir"] as String
val composeOsArchDir = run {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val osPart = when {
        os.contains("mac") -> "macos"
        os.contains("win") -> "windows"
        else -> "linux"
    }
    val archPart = if (arch == "aarch64" || arch == "arm64") "arm64" else "x64"
    "$osPart-$archPart"
}

val prepareRustAppResources = tasks.register("prepareRustAppResources") {
    group = "build"
    description = "Stage the Rust engine host lib into Compose appResources for packaging"
    dependsOn(rootProject.tasks.named("cargoBuildHost"))
    val src = rootProject.file("$rustReleaseDir/$rustHostLibName")
    val destDir = layout.buildDirectory.dir("rustAppResources/$composeOsArchDir")
    inputs.files(src).optional() // optional so the ACTION runs even when absent
    outputs.dir(destDir)
    // A plain task, NOT Copy: a Copy with a missing source is skipped as
    // NO-SOURCE — actions included — so its doLast guard never fires and
    // packaging silently ships a Java-only app (empirically reproduced in
    // review). Plain-task actions always run; the check below is the real
    // fail-loud gate.
    doLast {
        check(src.isFile) {
            "Rust engine lib missing ($src) — packaging requires cargo " +
                "(cargoBuildHost self-skipped?). A packaged app must never " +
                "silently ship without the Rust engine."
        }
        copy {
            from(src)
            into(destDir)
        }
    }
}

// Compose's own internal prepareAppResources task copies appResourcesRootDir
// into the image — our staging must run before IT (depending only on the
// package*/createDistributable* umbrella tasks is too late: the internal copy
// consumes the dir first).
tasks.configureEach {
    // configureEach (not tasks.matching{}, which realizes every task eagerly):
    // the name check runs lazily as each task is configured.
    if (name == "prepareAppResources"
        || name.startsWith("package") || name.startsWith("createDistributable")
        || name.startsWith("createReleaseDistributable")
        || name.startsWith("runDistributable") || name.startsWith("runRelease")
    ) {
        dependsOn(prepareRustAppResources)
    }
}

compose.desktop {
    application {
        mainClass = "io.myotis.desktop.MainKt"
        // Use our desktop logback config (rolling, size-capped, ~/.myotis/logs, app level
        // adjustable via -Dmyotis.log.level) instead of the DEBUG-to-unbounded-file logback.xml
        // that :app puts on the classpath. Applies to both the packaged app and :app-desktop:run.
        jvmArgs += listOf("-Dlogback.configurationFile=logback-desktop.xml")
        // Pin the runtime jpackage bundles (via jlink) to the Java 21 toolchain. Our bytecode
        // is class-file 65 (jvmToolchain(21)) and the backend (:networking discv5, :myotis-evm
        // Besu) ships Java-21 classes that NEED a 21 runtime to load. Without this, jpackage
        // defaults to whatever JDK runs Gradle — a Java 17 default JAVA_HOME bundles a 17 JRE
        // that can't load our classes (UnsupportedClassVersionError: class file 65.0 vs 61.0).
        // CI happened to work only because its JAVA_HOME is already 21.
        javaHome = javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(21))
        }.get().metadata.installationPath.asFile.absolutePath
        nativeDistributions {
            // The staged Rust engine lib (see prepareRustAppResources above).
            appResourcesRootDir.set(layout.buildDirectory.dir("rustAppResources"))
            // jpackage is host-OS-bound: the .dmg can only be produced on macOS, the .deb only
            // on Linux. CI builds each on its matching runner (desktop-dmg.yml /
            // desktop-linux-deb.yml); locally you get the format for your OS. Msi when a
            // Windows host exists.
            targetFormats(TargetFormat.Dmg, TargetFormat.Deb)
            packageName = "Myotis"
            packageVersion = "1.0.0"  // jpackage/dmg requires MAJOR > 0
            // jpackage builds the deb's Maintainer field as "<vendor> <debMaintainer>",
            // so the human name lives here and debMaintainer stays a bare email.
            vendor = "Dirk Jäckel"
            // Bundle the FULL JDK module graph. jlink otherwise strips the runtime to the
            // modules it can statically detect, but the backend reaches them reflectively —
            // DNS (java.naming), JDBC-style lookups, EC TLS (jdk.crypto.ec), XML, etc. — so a
            // stripped runtime dies at launch with NoClassDefFoundError (first seen:
            // javax/naming/NamingException). includeAllModules trades a bigger bundle for a
            // runtime that can actually load Netty / Besu / jvm-libp2p / BouncyCastle.
            includeAllModules = true
            macOS {
                bundleID = "io.myotis.desktop"
            }
            linux {
                // Unlike the dmg (jpackage requires major > 0 on macOS), deb versions may
                // start at 0 — so Linux carries the app's honest version.
                packageVersion = "0.1.2"
                debMaintainer = "dirk@jaeckel.com"
            }
        }
    }
}

// Dev runs load the Rust engine lib via an ABSOLUTE path (-Dmyotis.engine.lib), set
// only on these JavaExec tasks — deliberately NOT via compose.desktop jvmArgs, which
// would bake a dev-machine path into packaged apps. Packaged desktop builds ship
// without the Rust engine until the packaging PR.
tasks.withType<JavaExec>().matching { it.name == "run" || it.name == "syncSmoke" }.configureEach {
    dependsOn(rootProject.tasks.named("cargoBuildHost"))
    // -Pengine=java|rust|auto → -Dmyotis.engine (same knob as :app run).
    (project.findProperty("engine") as String?)?.let { systemProperty("myotis.engine", it) }
    doFirst {
        val os = System.getProperty("os.name").lowercase()
        val lib = when {
            os.contains("mac") -> "libmyotis_engine.dylib"
            os.contains("win") -> "myotis_engine.dll"
            else -> "libmyotis_engine.so"
        }
        rootProject.file("rust/target/release/$lib").takeIf { it.exists() }?.let {
            systemProperty("myotis.engine.lib", it.absolutePath)
        }
    }
}
