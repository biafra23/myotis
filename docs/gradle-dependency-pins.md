# Gradle dependency pins

Every JVM/Android/KMP dependency this build downloads is pinned twice: by
**version**, in lockfiles, and by **content**, in a SHA-256 list. A build that
meets anything else fails closed. This is Part 1 of the reproducible-builds
plan (#734): the binary is the one link in the wallet's trust chain that is
not verified yet, and pinned inputs are its precondition.

## What is pinned where

| File | Pins | Written by |
|---|---|---|
| `gradle/wrapper/gradle-wrapper.properties` | the Gradle distribution (`distributionSha256Sum`) | by hand, from `https://services.gradle.org/distributions/gradle-<v>-bin.zip.sha256` |
| `<project>/gradle.lockfile` (one per project, plus the root's) | the exact module version every configuration resolved to, transitives included | `--write-locks` |
| `buildscript-gradle.lockfile`, `settings-gradle.lockfile` | the root buildscript classpath (the R8 pin and every plugin) and the settings classpath | `--write-locks` |
| `gradle/verification-metadata.xml` | the SHA-256 of every artifact and metadata file (`.jar`, `.aar`, `.klib`, `.module`, `.pom`) of every external module, on every CI host | `--write-verification-metadata sha256` |

The lock catches a **version** moving: a transitive version range, or a
dependency's own dependency bumped by a republished BOM. The hashes catch the
**bytes** moving under a fixed version: a JitPack rebuild of a tag (JitPack
jars are not byte-stable across rebuilds), a moved tag, a compromised
repository or mirror. The repositories themselves stay filtered by group
(`settings.gradle.kts`).

The JitPack forks (besu, discovery, trueblocks-kotlin) are covered like
everything else. trueblocks-kotlin is pinned to a commit-hash version
(`d2223849c1`), not a branch build. Taking JitPack out of the graph altogether
is Part 6 of #734.

## The one command

```bash
scripts/update_gradle_pins.sh
```

It runs `resolveAllDependencies`, a task in every project that resolves every
resolvable configuration, three times:
1. Writing the locks. Verification is `lenient` for this run only, because a
   bumped dependency has no hash yet.
2. Writing this host's hashes with the new locks in force, plus `assemble lint`
   (see below; `--quick` skips that). This is a separate run because without
   lock constraints, conflict resolution also fetches the metadata of every
   candidate version it then discards. Pinning those would add some 75 entries
   nobody uses.
3. Verifying, with both pins in force.

Resolving everything matters because a plain build only resolves what its own
tasks need, so pins written from `./gradlew build` would miss the lint or
instrumented-test classpaths. The next build that needs those would then fail.

Some configurations cannot resolve on a given host by design. The task prints
those as `skipped` and goes on:
- KGP's commonizer inputs (`iosMainCInterop`, `nativeMainCInterop`, …), which
  match no published variant on any host (the per-target ones, such as
  `iosArm64CInterop`, resolve and are locked like the rest);
- KGP's IDE-only `*DependenciesMetadata` configurations;
- the Android configurations, without an SDK.

A **pin** failure always fails the task: a missing or wrong hash, a graph that
differs from its lock, or a configuration that resolves with no lock state at
all. That last rule is Gradle's `STRICT` lock mode, enforced in the walk
rather than in every build. `STRICT` itself would break IDE syncs, which
resolve configurations a build never does.

Any other resolution failure is reported as `skipped`, not failed. That
includes "could not find" for an artifact that vanished. The walk checks pins
and nothing else; a missing artifact fails every real build on that host.
Gradle signals a lock that pins a version the graph rejects only through its
message text. To catch a rewording on a Gradle bump, the Linux x64 job runs a
canary that tampers with one lock and one hash and requires both to fail.

### Warm caches write incomplete pins

Gradle reads a parent POM or an imported BOM only while it first parses a
module's POM, then caches the parsed result. On a warm cache those files are
never touched again, so `--write-verification-metadata` does not record them,
and a check run on that cache can't see the gap. When this was set up, 13 such
files were missing, and every one of them failed the first fresh runner.

So every pin-**writing** run uses `--refresh-dependencies`, which re-fetches
and re-parses the metadata. That covers the update script's hash run and the
chain's write step, both of which follow a run that has just warmed the cache.
The `gradle pins` **check** runs with the Gradle cache disabled: only a cold
resolution proves that a fresh checkout verifies.

### Hosts: why CI has to finish the job

Some artifacts exist once per **build host**:
- Compose desktop's `currentOs` runtime and its skiko natives;
- Kotlin/Native's compiler bundle (its artifact; the module is the same everywhere);
- aapt2's per-OS jar.

A Linux machine never downloads the macOS ones, so it cannot pin them. The
`gradle pins` workflow (`.github/workflows/gradle-pins.yml`) runs on the four
hosts that run Gradle in CI: Linux x64, Linux arm64, macOS arm64 and Windows
x64. They run in that chain order: Linux x64, Windows, Linux arm64, then
macOS, so the merged file is written by a Unix host. Each host checks the
committed pins, then adds its own entries to the previous host's file. A host
whose predecessor uploaded nothing uploads nothing either, so a partial
"merged" file never appears. The last upload, `verification-metadata-merged`,
is the union. So the full loop after a dependency change is:

1. Bump `gradle/libs.versions.toml` and run `scripts/update_gradle_pins.sh`.
2. Commit and push. `gradle pins` runs on the PR. A host whose artifacts are
   missing fails, and its job log names them.
3. Once the chain has finished, run `scripts/update_gradle_pins.sh --from-ci`.
   It downloads the merged file from the finished run for your HEAD commit
   (pass a run id to choose another) and strips any `\r`. Commit and push, and
   `gradle pins` goes green.
4. **Review the hash diff like code.** Every new `<component>` is an artifact
   the build will run or ship. Look for anything unexpected: a group nobody
   added, or a version the catalog doesn't name.

The lockfiles hold no host-specific entries: the host-specific modules are
listed in `dependencyLocking.ignoredDependencies` (root `build.gradle.kts`).
Their versions still follow the pinned Compose/Kotlin plugin versions, and
their bytes are still pinned per host in the verification metadata. A lock
mismatch on one host means a new host-specific module. Add it to that list;
don't write locks on that host.

### What resolveAllDependencies does not see

An artifact that a plugin resolves through a *detached* configuration while a
task runs isn't covered by the walk. AGP does this for aapt2 and for the lint
override (`android.experimental.lint.version` in `gradle.properties`): 43
components in all when this was set up. So the update script also runs
`assemble lint` in write mode (`--quick` skips that). In the chain:
- aapt2 has a jar **per OS**, so the Linux x64, Windows and macOS jobs run
  `:android-app:processDebugResources` alongside the walk. That keeps an
  Android build on a developer's Mac or Windows machine working.
- lint is the same jar everywhere, and CI's Build and Test job runs it with
  the pins in force on every PR.

Anything else of this kind fails the build workflow that needs it, with
Gradle's usual verification report. Pin it from that host the same way: run
the update script there, or run that build once with
`--write-verification-metadata sha256` and commit the additions.

### Pruning

`--write-verification-metadata` only ever **adds** entries. That's what lets
one host's run keep the others' hashes, and it means entries for versions
nothing resolves any more stay behind. To start over, run
`scripts/update_gradle_pins.sh --prune`, which deletes the file before
regenerating. Then do steps 2 and 3 above so the other hosts add their entries
back.

## Day to day

- **A build fails with "Dependency verification failed"** or "is not part of
  the dependency lock state": a dependency changed without its pins. If you
  changed it, run the loop above. If you didn't, stop: an artifact's bytes
  changed under a pinned version. Find out why before re-pinning.
- **IDE sources and javadoc** are trusted without hashes
  (`<trusted-artifacts>` in the metadata), so IDE downloads don't fail the
  sync. They are never on a build classpath. Gradle rewrites the file on every
  write and drops XML comments, so explanations live here, not in the file.
- **The wrapper** is regenerated with the checksum flag, or the `wrapper` task
  drops it:
  `./gradlew wrapper --gradle-version <v> --gradle-distribution-sha256-sum <sha>`.
- **PGP signatures are not checked**, only SHA-256. When generating, Gradle's
  `pgp` mode writes a trusted key *instead of* a checksum for each signed
  artifact, so the pin becomes "signed by this key" rather than "these
  bytes". It also downloads a `.asc` per artifact on every cold build and
  needs a committed keyring. A hash pinned on first resolution already fixes the bytes, which is
  what reproducibility needs. Checking signatures *when a pin is added* would
  harden that first resolution; it's a possible follow-up, not part of this
  setup.
