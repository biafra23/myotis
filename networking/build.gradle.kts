plugins {
    // java-library (on top of the root's java): RLPxConnector's public surface
    // returns io.netty.channel.ChannelFuture, so netty-transport is an API
    // dependency — consumers (:app, :node-core) get it on their compile
    // classpath transitively instead of redeclaring it.
    `java-library`
}

java {
    // Bumped from 17 to 21 because ConsenSys discv5 26.4.0 (consumed as the
    // biafra23/discovery Android fork — the libs.versions.toml entry is the
    // canonical doc) publishes Gradle module metadata declaring a JVM-21
    // floor, and is compiled as class file major=65. AGP 8.7's D8 accepts
    // Java 21 class files as input and rewrites them for the Android runtime,
    // so this keeps working on android-app (minSdk 29) provided the library
    // doesn't use post-minSdk JDK runtime APIs — which is exactly what the
    // fork patches out (re-verifiable anytime: dexdump the assembled APK and
    // grep for the patched members listed in the catalog entry — zero refs).
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
    // discv5 logs through log4j-api; log4j-core is excluded repo-wide (root
    // build — Logback is the single backend), so bridge it for this module's
    // tests/dnsSmoke too.
    testRuntimeOnly(libs.log4j.to.slf4j)
    implementation(project(":core"))
    implementation(libs.tuweni.bytes)
    implementation(libs.tuweni.rlp)
    implementation(libs.tuweni.crypto)
    api(libs.netty.transport) // leaked by RLPxConnector's API (ChannelFuture) — see plugins block
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)
    implementation(libs.bouncycastle)
    implementation(libs.snappy)
    implementation(libs.slf4j.api)
    implementation(libs.dnsjava)
    // ConsenSys discv5 library — republished successor of tech.pegasys.discovery,
    // consumed via the biafra23/discovery Android fork (JitPack) so it runs at
    // minSdk 29. The libs.versions.toml entry is the canonical doc: patch set,
    // why the swap is repo-wide (unlike besu's :android-app-only substitution),
    // and the re-tag playbook. The swap must be the declared coordinate itself:
    // a resolutionStrategy substitution here would not propagate — consumers
    // (:app, :android-app) resolve their own dependency graphs.
    // log4j is NOT excluded: several of the library's internal classes
    // (IdentitySchemaV4Interpreter etc.) reference org.apache.logging.log4j.LogManager
    // in their <clinit>, so stripping it NoClassDefFoundErrors the whole library
    // at first use. Our own code stays on slf4j + logback; log4j-api just
    // satisfies the library's static init.
    implementation(libs.discovery) {
        // Single-netty policy: discovery pulls 4.1.x; we standardize on 4.2.x
        // (supplied above). Its tuweni deps are io.consensys.tuweni like ours
        // (its pom pins 2.7.0; version conflict resolves to our 2.7.2), so no
        // tuweni exclude is needed anymore.
        exclude(group = "io.netty")
    }

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.test {
    // Regeneration knob for the EL-core conformance corpus (ElCoreVectorConformanceTest):
    // forward it into the forked test JVM, where -D on the gradlew line doesn't reach.
    // Same pattern as :consensus and myotis.lc.writeExpected.
    System.getProperty("myotis.el.writeExpected")?.let {
        systemProperty("myotis.el.writeExpected", it)
    }
}

tasks.register<JavaExec>("dnsSmoke") {
    group = "verification"
    description = "Live DNS smoke test against the Ethereum Foundation EL tree"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass = "com.jaeckel.ethp2p.networking.dns.DnsSmokeTest"
}
