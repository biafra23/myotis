rootProject.name = "ethp2p"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            name = "ConsenSys"
            url = uri("https://artifacts.consensys.net/public/maven/maven/")
        }
        maven {
            name = "Cloudsmith-libp2p"
            url = uri("https://dl.cloudsmith.io/public/libp2p/jvm-libp2p/maven/")
        }
        // Hyperledger Besu publishes release artifacts (incl. the standalone
        // `evm` module) here. Maven Central mirrors are inconsistent across
        // versions, so we pin the source.
        maven {
            name = "Hyperledger"
            url = uri("https://hyperledger.jfrog.io/artifactory/besu-maven")
        }
        // biafra23/netty-kotlin, republished as a static Maven repo on GitHub
        // Pages (com.jaeckel:netty-*:1.0-SNAPSHOT) — replaces the JitPack-built
        // netty fork. The coords are com.jaeckel:* (not io.netty), so the
        // project-wide exclude(group = "io.netty") still strips upstream Netty
        // while keeping this fork. See docs/jitpack-migration.md.
        maven {
            name = "NettyKotlin"
            url = uri("https://biafra23.github.io/netty-kotlin/")
        }
        // JitPack — ordered last (slowest / least reliable). The library FORKS no
        // longer need it (tuweni-kotlin + besu are composite builds via
        // includeBuild below; netty-kotlin is the NettyKotlin Pages repo above),
        // but it's still REQUIRED for non-fork dependencies that publish only on
        // JitPack: com.github.multiformats:java-multibase (a runtime transitive of
        // io.libp2p:jvm-libp2p, used by :consensus) and trueblocks-kotlin's own
        // transitives (komputing kethereum/khex, biafra23:ipfs-api-kotlin).
        maven {
            name = "JitPack"
            url = uri("https://jitpack.io")
        }
    }
}

include("core", "networking", "consensus", "app", "android-app", "myotis-evm", "myotis-ens", "jsonrpc-server", "rpc-backend")

// ============================================================================
// Composite builds — locally-built library forks (replaces JitPack-built jars)
// ----------------------------------------------------------------------------
// Source is pinned via git submodules under submodules/ (see .gitmodules), so
// the build no longer depends on JitPack *rebuilding* these forks on demand.
//
// Migrated: trueblocks-kotlin — a single-module Gradle build published by
// JitPack as com.github.biafra23:trueblocks-kotlin:main-SNAPSHOT. A SNAPSHOT
// coordinate is the worst case for JitPack reproducibility (rebuilt from HEAD),
// so this is the highest-value, lowest-risk fork to localise: it has a single
// consumer (:app) and no io.netty / io.consensys.tuweni group-exclude overlap.
//
// Not composite builds (see docs/jitpack-migration.md):
//   • netty-kotlin  — a Maven project (pom.xml, group com.jaeckel) that Gradle's
//                     includeBuild can't consume. Now OFF JitPack anyway: pulled
//                     as a normal Maven dependency (com.jaeckel:netty-*:1.0-SNAPSHOT)
//                     from the GitHub Pages repo declared in repositories above.
//   • tuweni-kotlin — KEPT ON JITPACK: every dependency version comes from the
//                     io.spring.dependency-management plugin, which writes
//                     versions only into PUBLISHED POMs; composite-build
//                     consumers see version-less transitives (io.vertx:vertx-core)
//                     and fail to resolve.
//   • besu          — KEPT ON JITPACK: a scoped composite is impossible
//                     (android-app's substitution doesn't chain into includeBuild),
//                     and the build-wide alternative moves the JVM daemon onto the
//                     Android-only patched fork. Tag-pinned, so low JitPack risk.
// ============================================================================
includeBuild("submodules/trueblocks-kotlin") {
    dependencySubstitution {
        // JitPack served the repo root as com.github.biafra23:trueblocks-kotlin;
        // map that coordinate onto the included build's root project.
        substitute(module("com.github.biafra23:trueblocks-kotlin"))
            .using(project(":"))
    }
}

// tuweni-kotlin — multi-module Gradle build (JitPack-published as
// com.github.biafra23.tuweni-kotlin:tuweni-<module>). Built from source here;
// only the consumed modules (bytes/crypto/rlp/units) are mapped — their internal
// siblings (e.g. :io) resolve inside the included build. The fork's
// io.spring.dependency-management plugin writes dependency versions only into
// published POMs, so a composite build sees version-less transitives; the main
// build supplies those versions via dependency constraints (root build.gradle.kts
// for the JVM modules + android-app). See docs/jitpack-migration.md.
includeBuild("submodules/tuweni-kotlin") {
    dependencySubstitution {
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-bytes")).using(project(":bytes"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-crypto")).using(project(":crypto"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-rlp")).using(project(":rlp"))
        substitute(module("com.github.biafra23.tuweni-kotlin:tuweni-units")).using(project(":units"))
    }
}

// besu — the Android-patched fork (biafra23/besu), built from source. Besu's own
// ~50-module Gradle build configures here, but only the modules actually
// requested get built. The swap is build-wide (covers :android-app, which needs
// the ART patches, AND the JVM daemon :myotis-evm/:app) — a scoped swap is
// impossible (a config-level org.hyperledger.besu -> com.github.biafra23.besu
// substitution doesn't chain into includeBuild), and the patches are JVM-safe
// (API-1 Provider ctor; LinkedHashMap CodeCache), so the daemon is unaffected
// functionally. Substitutions are EXPLICIT because Besu's publication coords
// don't match its project names (auto-detection doesn't fire — e.g. project
// :datatypes publishes as besu-datatypes). Mapping all five requested modules to
// the included projects keeps a single, consistent Besu on the graph.
includeBuild("submodules/besu") {
    dependencySubstitution {
        substitute(module("org.hyperledger.besu:evm")).using(project(":evm"))
        substitute(module("org.hyperledger.besu:besu-datatypes")).using(project(":datatypes"))
        substitute(module("org.hyperledger.besu.internal:algorithms")).using(project(":crypto:algorithms"))
        substitute(module("org.hyperledger.besu.internal:rlp")).using(project(":ethereum:rlp"))
        substitute(module("org.hyperledger.besu:bom")).using(project(":platform"))
    }
}
