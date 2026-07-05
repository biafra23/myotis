// :myotis-api — the formal, language-neutral engine boundary.
//
// This module is the CONTRACT between hosts (the :app daemon, :app-desktop,
// :android-app) and the engine (node-core + rpc-backend + consensus + networking +
// myotis-evm/-ens). The Java engine implements it today; a future Rust/Go engine
// replaces everything behind it via a thin FFI binding implementing the same
// interfaces (see docs/reimplementation/). Hosts must consume ONLY these types.
//
// HARD RULES for everything in this module (FFI-portability + Android minSdk 29):
//   - ZERO dependencies. Only java.lang / java.util / plain records, interfaces,
//     enums. The check task below enforces the empty runtime classpath.
//   - Types crossing the boundary: byte[], String, long/int/boolean, enums, flat
//     records, java.util.List. NO Tuweni, NO Netty, NO kotlinx, NO
//     CompletableFuture, NO BigInteger, NO Optional, NO InetSocketAddress,
//     NO java.nio.file.Path, NO checked exceptions.
//   - Java 17 bytecode, desugar-safe API only (consumable by :android-app, minSdk 29).
// Full conventions: io.myotis.api package-info.

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile>().configureEach {
    // `release` (not just source/target) so JDK-21-only library APIs can't slip into
    // the contract while compiling under the newer toolchain.
    options.release = 17
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
}

tasks.test {
    useJUnitPlatform()
}

// The API's whole value is being dependency-free (an FFI binding must not have to
// reproduce third-party types). Fail the build if anything sneaks onto the runtime
// OR compile classpath — a compileOnly dep would leak third-party types into API
// signatures while leaving the runtime classpath empty.
tasks.register("checkZeroDependencies") {
    val classpaths = mapOf(
        "runtimeClasspath" to configurations.runtimeClasspath,
        "compileClasspath" to configurations.compileClasspath,
    )
    doLast {
        for ((label, provider) in classpaths) {
            val deps = provider.get().resolvedConfiguration.resolvedArtifacts
            check(deps.isEmpty()) {
                ":myotis-api must have zero dependencies, but $label has: " +
                    deps.joinToString { it.name }
            }
        }
    }
}
tasks.named("check") { dependsOn("checkZeroDependencies") }
