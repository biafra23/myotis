java {
    // Bumped from 17 to 21 because io.consensys.protocols:discovery:26.4.0
    // (ConsenSys discv5) publishes Gradle module metadata declaring a JVM-21
    // floor, and is compiled as class file major=65. AGP 8.7's D8 accepts
    // Java 21 class files as input and rewrites them for the Android runtime,
    // so this keeps working on android-app (minSdk 29) provided the library
    // doesn't use Java 21 runtime APIs (SequencedCollection, scoped values,
    // structured concurrency).
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
    implementation(libs.netty.transport)
    implementation(libs.netty.codec)
    implementation(libs.netty.handler)
    implementation(libs.bouncycastle)
    implementation(libs.snappy)
    implementation(libs.slf4j.api)
    implementation(libs.dnsjava)
    // ConsenSys discv5 library — republished successor of tech.pegasys.discovery.
    // Excludes upstream io.netty: the JitPack netty-kotlin fork republishes the
    // same classes under different coordinates; D8 rejects the duplicates on
    // Android. android-app already strips io.netty group-wide; mirror that here
    // so the JVM daemon also resolves to the fork.
    //
    // Same story for io.consensys.tuweni: discovery transitively pulls upstream
    // tuweni 2.7.0, but we resolve tuweni via the JitPack fork
    // (com.github.biafra23.tuweni-kotlin, recompiled to Java 17 bytecode). The
    // fork kept the original org.apache.tuweni.* package names, so both jars
    // ship identical FQCNs under different coordinates — Gradle can't dedupe
    // them and D8's checkDebugDuplicateClasses fails. The fork is a >=2.7.0
    // recompile of the same classes, so it satisfies everything discovery needs.
    //
    // log4j is NOT excluded: several of the library's internal classes
    // (IdentitySchemaV4Interpreter etc.) reference org.apache.logging.log4j.LogManager
    // in their <clinit>, so stripping it NoClassDefFoundErrors the whole library
    // at first use. Our own code stays on slf4j + logback; log4j-api just
    // satisfies the library's static init.
    implementation(libs.discovery) {
        exclude(group = "io.netty")
        exclude(group = "io.consensys.tuweni")
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
