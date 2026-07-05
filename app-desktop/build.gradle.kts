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

// Besu (via :myotis-evm) drags in the pre-rename tuweni coordinates io.tmio:tuweni-* 2.4.2,
// whose org.apache.tuweni.bytes.Bytes collides with the JitPack Kotlin fork we use
// (com.github.biafra23.tuweni-kotlin 2.7.2). A single classloader loads only ONE Bytes for
// that FQN: tuweni-rlp 2.7.2 (BytesRLPWriter.kt) needs the 2.7.2 Bytes' Kotlin `Companion`,
// which the 2.4.2 class lacks → NoSuchFieldError at launch. The `gradle run` daemon happens
// to load the 2.7.2 jar first; jpackage's flattened classpath lets the 2.4.2 one win. Strip
// io.tmio so only the 2.7.2 fork remains (same packages; Besu already runs against 2.7.2 on
// the daemon, so 2.4.2 is unneeded) — mirrors the :android-app exclusion.
//
// io.netty: the same class of conflict. The JitPack netty-kotlin fork
// (com.github.biafra23.netty-kotlin, 4.2.x) republishes io.netty.* classes; Besu / vertx /
// jvm-libp2p drag in upstream io.netty 4.1.115. Both ship e.g. io.netty.channel
// .SingleThreadEventLoop, and the fork's NioEventLoopGroup calls a 4.2.x constructor the
// 4.1.115 class lacks → NoSuchMethodError, so the stack fails to start in the flattened
// jpackage bundle. The :app daemon excludes io.netty group-wide and runs end-to-end on only
// the fork (reaches SYNCED), so it's safe to do the same here.
configurations.all {
    exclude(group = "io.tmio")
    exclude(group = "io.netty")
}

dependencies {
    implementation(project(":ui"))

    // The shared backend + the daemon's file-backed cache adapters / CCIP gateway, reused.
    implementation(project(":node-core"))
    implementation(project(":app"))
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
            // jpackage is host-OS-bound: the .dmg can only be produced on macOS, the .deb only
            // on Linux. CI builds each on its matching runner (desktop-dmg.yml /
            // desktop-linux-deb.yml); locally you get the format for your OS. Msi when a
            // Windows host exists.
            targetFormats(TargetFormat.Dmg, TargetFormat.Deb)
            packageName = "Myotis"
            packageVersion = "1.0.0"  // jpackage/dmg requires MAJOR > 0
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
                packageVersion = "0.1.0"
                debMaintainer = "dirk@jaeckel.com"
            }
        }
    }
}
