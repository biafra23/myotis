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
        // JitPack last — slowest / least reliable, which is the whole reason
        // we're moving forks off it. Still required for: tuweni-kotlin and besu
        // (com.github.biafra23.{tuweni-kotlin,besu}:*), plus trueblocks-kotlin's
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
