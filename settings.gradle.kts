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
        // JitPack last — slowest / least reliable, which is the whole reason
        // we're moving forks to composite builds. Still required for forks that
        // can't (yet) be local composite builds: netty-kotlin (a Maven build,
        // which Gradle's includeBuild cannot consume) and trueblocks-kotlin's
        // transitive com.github.* deps (ipfs-api-kotlin, komputing.*).
        // NOTE: this repository was previously declared twice in this file
        // (once unnamed, once as "JitPack"); de-duplicated to a single entry.
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
// NOT migrated to composite builds (kept on JitPack — see docs/jitpack-migration.md):
//   • netty-kotlin  — a Maven project (pom.xml, group com.jaeckel); Gradle
//                     includeBuild only consumes Gradle builds.
//   • tuweni-kotlin — every dependency version comes from the
//                     io.spring.dependency-management plugin, which writes
//                     versions only into PUBLISHED POMs; composite-build
//                     consumers see version-less transitives (io.vertx:vertx-core)
//                     and fail to resolve.
//   • besu          — a scoped composite is impossible (android-app's
//                     substitution doesn't chain into includeBuild), and the
//                     build-wide alternative moves the JVM daemon onto the
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

// (tuweni-kotlin composite build attempted and reverted — see
// docs/jitpack-migration.md: io.spring.dependency-management supplies versions
// only in published POMs, not in the live project metadata composite builds
// consume, so consumers fail to resolve version-less transitives e.g.
// io.vertx:vertx-core. Stays on JitPack.)

// (besu composite build attempted and reverted — see docs/jitpack-migration.md.
// besu :evm builds fine from source here, but a *scoped* composite is impossible:
// android-app's config-level substitution org.hyperledger.besu:evm ->
// com.github.biafra23.besu:evm yields a final module selector that is NOT re-fed
// through this includeBuild's substitution, so android-app keeps resolving the
// JitPack module (verified via dependencyInsight). The only wiring that works is
// build-wide org.hyperledger.besu:* -> project, which also moves the JVM daemon
// onto the Android-patched fork. besu is tag-pinned on JitPack, so it stays.)
