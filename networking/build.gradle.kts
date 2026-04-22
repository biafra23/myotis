java {
    // Bumped from 17 to 21 because io.consensys.protocols:discovery:26.4.0
    // (ConsenSys discv5) publishes Gradle module metadata declaring a JVM-21
    // floor, and is compiled as class file major=65. AGP 8.7's D8 accepts
    // Java 21 class files as input and rewrites them for the Android runtime,
    // so this keeps working on android-app (minSdk 29) provided the library
    // doesn't use Java 21 runtime APIs (SequencedCollection, scoped values,
    // structured concurrency). Verified at integration time; fall back to an
    // in-tree discv5 port if assembleDebug rejects it.
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

dependencies {
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
    // Excludes:
    //  - upstream io.netty: the JitPack netty-kotlin fork republishes the same
    //    classes under different coordinates; D8 rejects the duplicates on Android.
    //    android-app already strips io.netty group-wide; mirror that here so the
    //    JVM daemon also resolves to the fork.
    //  - log4j: the rest of the project uses slf4j-api + logback; we don't want
    //    log4j on the classpath just for this library's internal logs.
    implementation(libs.discovery) {
        exclude(group = "io.netty")
        exclude(group = "org.apache.logging.log4j")
    }

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.logback.classic)
}

tasks.register<JavaExec>("dnsSmoke") {
    group = "verification"
    description = "Live DNS smoke test against the Ethereum Foundation EL tree"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass = "com.jaeckel.ethp2p.networking.dns.DnsSmokeTest"
}
