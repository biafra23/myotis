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
//   git but no tags fetched     ->  "0.1.4-fbf551"   base falls back to project.version
//   no git at all (src tarball) ->  "0.1.4-SNAPSHOT" project.version verbatim
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

    override fun obtain(): String {
        val projectVersion = parameters.projectVersion.get()
        val sha = git("rev-parse", "--short=6", "HEAD")
        if (sha.isEmpty()) return projectVersion  // no git, not a repo, or no commits yet
        // --match confines both probes to the release line: without it describe picks by
        // tag RECENCY, so a `nightly-*` laid down later would be read as this build's
        // release. (Several v* tags on one commit still resolve by recency — newest wins,
        // which is the answer we want.) --dirty is why a locally-patched tag checkout
        // can't claim to be the release: it appends "-dirty", failing the shape check.
        // (--dirty rejects an explicit commit-ish, hence no HEAD argument.)
        val shape = Regex("""^v\d+(\.\d+)*$""")
        val exactTag = git("describe", "--tags", "--exact-match", "--dirty", "--match", "v[0-9]*")
        if (shape.matches(exactTag)) return exactTag.removePrefix("v")
        val lastTag = git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", "HEAD")
            .takeIf { shape.matches(it) }?.removePrefix("v")
        return "${lastTag ?: projectVersion.substringBefore('-')}-$sha"
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
        val f = outDir.get().file("io/myotis/ui/BuildInfo.kt").asFile
        f.parentFile.mkdirs()
        f.writeText(
            """
            // GENERATED by :ui's generateUiBuildInfo task — do not edit.
            package io.myotis.ui

            /** The app version shown under the title in the top bar. */
            internal const val APP_VERSION: String = "${version.get()}"
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
