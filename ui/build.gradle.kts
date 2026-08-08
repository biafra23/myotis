// :ui — the shared Compose-Multiplatform UI + the pure-Kotlin NodeController/Settings seam.
// commonMain holds the screens + seam interfaces (no backend dependency); the Android,
// Desktop, and iOS hosts each supply the actuals. Targets: Android + Desktop JVM + iOS
// (arm64 device + arm64 simulator — :app-ios supplies the actuals over the Rust engine).

import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

// The version string the top bar shows, generated into commonMain so ALL THREE hosts
// (Android, Desktop, iOS) read the same constant with no per-host wiring — iOS in
// particular has no BuildConfig to fall back on.
//
// project.version NEVER loses its qualifier in this repo: a release is a pushed `v<x.y.z>`
// TAG on the commit, and the release workflows strip "-SNAPSHOT" only to form the
// packaging version (android-app's versionName, app-desktop's packageVersion — neither
// format accepts a qualifier). So the version string alone can't tell a release build from
// a dev build. Git can:
//
//   clean checkout of a v* tag  ->  "0.1.4"          a real release build
//   any other commit            ->  "0.1.4-fbf551"   last release + 6 sha digits
//   dirty tree on a v* tag      ->  "0.1.4-fbf551"   NOT what shipped — label it a dev build
//   git but no tags reachable   ->  "0.1.4-SNAPSHOT-fbf551"   see below
//   no git at all (src tarball) ->  "0.1.4-SNAPSHOT" project.version verbatim
//
// The tagless row deliberately KEEPS the qualifier. Its base is project.version — the
// version being worked TOWARD — while every other row's base is the last version actually
// RELEASED, and the bump to X.Y.Z-SNAPSHOT lands ~9 commits BEFORE vX.Y.Z is tagged. Strip
// the qualifier there and one commit renders as "0.1.4-fbf551" from a full clone and
// "0.1.4-fbf551" from a shallow one while meaning "after 0.1.4" and "before 0.1.4"
// respectively. "-SNAPSHOT" keeps that lie unsayable.
//
// Every probe degrades to "" instead of failing the build, so a git-less checkout still
// builds — it just shows the least specific label.
//
// Mirrors the root build's ToolProbe: a ValueSource keeps this configuration-cache-safe
// AND lazy, so unrelated invocations (`:app:run -Pargs=status`, say) fork no git at all.
abstract class AppVersionSource : ValueSource<String, AppVersionSource.Params> {
    interface Params : ValueSourceParameters {
        val repoDir: DirectoryProperty
        val projectVersion: Property<String>
    }

    @get:Inject abstract val execOperations: ExecOperations

    /** `git <args>` stdout, or "" when git is missing or the command exits non-zero. */
    private fun git(vararg args: String): String = try {
        val out = ByteArrayOutputStream()
        val result = execOperations.exec {
            commandLine(listOf("git") + args)
            workingDir = parameters.repoDir.get().asFile
            standardOutput = out
            // `describe` fails on every untagged commit — that's an expected answer here,
            // not something to print on each build.
            errorOutput = ByteArrayOutputStream()
            isIgnoreExitValue = true
        }
        if (result.exitValue == 0) out.toString(Charsets.UTF_8).trim() else ""
    } catch (_: Exception) {
        ""  // git not on PATH
    }

    /**
     * True when tracked files differ from HEAD, EXCLUDING the Rust build outputs
     * that the Android build regenerates from source: the jniLibs .so files (now
     * gitignored, so already invisible to --untracked-files=no — kept in the
     * pathspec for intent) and the committed UniFFI bindings under
     * myotis-engines/src/main/kotlin/uniffi. The Android build rebuilds the .so
     * (near-never byte-identical) and regenerates the .kt from source before
     * assembling; counting either would make every release APK label itself a dev
     * build. Untracked files are ignored, matching `describe --dirty`.
     */
    private fun treeIsPatched(): Boolean = git(
        "status", "--porcelain", "--untracked-files=no",
        "--", ".",
        ":(exclude)android-app/src/main/jniLibs",
        ":(exclude)myotis-engines/src/main/kotlin/uniffi",
    ).isNotEmpty()

    /** Newest RELEASED version reachable from HEAD, or null when none is. */
    private fun lastRelease(shape: Regex): String? =
        // Not `describe --abbrev=0`: that returns exactly ONE tag, the nearest, so a single
        // off-shape tag on the release line (v0.2.0-rc1) would fail the shape check and
        // silently demote every descendant commit to the project.version fallback. Listing
        // lets an off-shape tag be SKIPPED rather than poison everything after it.
        git("tag", "--list", "v[0-9]*", "--merged", "HEAD", "--sort=-v:refname")
            .lineSequence().map { it.trim() }
            .firstOrNull { shape.matches(it) }?.removePrefix("v")

    override fun obtain(): String {
        val projectVersion = parameters.projectVersion.get()
        val sha = git("rev-parse", "--short=6", "HEAD")
        if (sha.isEmpty()) return projectVersion  // no git, not a repo, or no commits yet
        val shape = Regex("""^v\d+(\.\d+)*$""")
        // --match confines this to the release line: without it describe picks by tag
        // RECENCY, so a `nightly-*` laid down later would be read as this build's release.
        // (Several v* tags on one commit still resolve by recency — newest wins, which is
        // the answer we want.) The separate patched-tree check is what stops a locally
        // modified tag checkout from claiming to be the release; `describe --dirty` can't
        // serve here because it can't exclude the regenerated jniLibs.
        val exactTag = git("describe", "--tags", "--exact-match", "--match", "v[0-9]*")
        if (shape.matches(exactTag) && !treeIsPatched()) return exactTag.removePrefix("v")
        // Keeping the qualifier on the fallback is load-bearing — see the table above.
        return "${lastRelease(shape) ?: projectVersion}-$sha"
    }
}

val uiAppVersion: Provider<String> = providers.of(AppVersionSource::class) {
    parameters.repoDir.fileValue(rootDir)
    parameters.projectVersion.set(project.version.toString())
}

val generateUiBuildInfo by tasks.registering {
    val outDir = layout.buildDirectory.dir("generated/buildInfo/kotlin")
    // Locals, not script properties: capturing the script object in doLast is what breaks
    // the configuration cache. Both are lazy, so git runs only when this task is in the
    // graph — the input is what makes the file regenerate on a version bump, a new tag or
    // a new commit, and stay up to date otherwise.
    val version = uiAppVersion
    inputs.property("version", version)
    outputs.dir(outDir)
    doLast {
        // Escaped because this lands inside a Kotlin string LITERAL. Unreachable today —
        // every value is a shape-checked tag, a hex sha, or the root build's literal — but
        // a stray " or \ would emit a file that doesn't parse, and a $ would emit a
        // template expression, both surfacing as a compile error in generated code.
        val literal = version.get()
            .replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\${'$'}")
        val f = outDir.get().file("io/myotis/ui/BuildInfo.kt").asFile
        f.parentFile.mkdirs()
        f.writeText(
            """
            // GENERATED by :ui's generateUiBuildInfo task — do not edit.
            package io.myotis.ui

            /** The app version shown under the title in the top bar. */
            internal const val APP_VERSION: String = "$literal"
            """.trimIndent() + "\n",
        )
    }
}

kotlin {
    jvmToolchain(21)

    androidTarget()
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    // The custom jvmSharedMain dependsOn edge below would otherwise make KGP
    // skip the default hierarchy (silently dropping iosMain and its actuals);
    // applying it explicitly keeps both.
    applyDefaultHierarchyTemplate()

    sourceSets {
        val commonMain by getting {
            // The TaskProvider carries the task dependency, so every target's compile
            // (including the Kotlin/Native iOS ones) generates BuildInfo.kt first.
            kotlin.srcDir(generateUiBuildInfo)
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material3)
                implementation(compose.ui)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)  // local-time formatting in the Logs tab
            }
        }
        // CacheFileStats' stat/read actuals are plain java.nio, identical on the
        // Android and Desktop JVM targets: one shared intermediate source set
        // instead of two copied actual files.
        val jvmSharedMain by creating {
            dependsOn(commonMain)
        }
        val desktopMain by getting {
            dependsOn(jvmSharedMain)
        }
        val androidMain by getting {
            dependsOn(jvmSharedMain)
        }
        // Desktop-JVM UI tests: drive the real composables headless (skiko software
        // rendering — no display needed, CI-safe). Regression tests for screen-level
        // state lifetimes (e.g. the Logs-tab filter surviving tab switches) live here.
        val desktopTest by getting {
            dependencies {
                implementation(compose.desktop.uiTestJUnit4)
                implementation(compose.desktop.currentOs)
            }
        }
    }
}

android {
    namespace = "io.myotis.ui"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}
