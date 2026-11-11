# Reproducible builds: checking a release

A wallet verifies everything it reads from the network. The one thing it
cannot verify is itself: the binary you install. This page is how to close
that gap for a Myotis release (#734): check that what you downloaded is what
the release published, that it was built by this repository's workflows from
the tagged commit, and, for the Android artifacts, rebuild it yourself and get
the same bytes.

Three checks, each stronger than the one before:

| Check | What it shows | What you need |
|---|---|---|
| [Checksums](#1-checksums) | Your download is the file the release lists | `sha256sum` |
| [Attestations](#2-build-provenance) | That file was built by a workflow of this repository, from the tag | the `gh` CLI |
| [Rebuild](#3-rebuild-it) | The tagged source, built with pinned tools, gives that file | Docker and about an hour |

The first two say who built it. Only the third says **what** was built.

## What reproduces, and what does not yet

"Reproduces" means: built twice, on two machines, from different directories,
as different users, in different time zones and locales and at different
times, the result is identical, bit for bit. `reproducible-builds.yml` does
exactly that on every `v*` tag, weekly on `main`, and before a pull request
that can change a release build is merged, and fails when the two builds
differ in anything they produce ("gated", below).

| Artifact | Release asset | Status |
|---|---|---|
| Android app, unsigned | `Myotis-<tag>-android-unsigned.apk` | **Gated.** Bit for bit. |
| Android app, signed | `Myotis-<tag>-android.apk` | The unsigned APK plus a signature, and nothing else ([below](#the-signed-apk)). The signature itself needs the release key and is not reproducible by design. |
| Android debug app | `Myotis-<tag>-android-debug.apk` | **Gated**, by payload: every entry of the APK. Its signature files are left out of the comparison. The signer is the one public debug key in the tree (`android-app/debug.keystore`), the same on every machine. |
| Engine library | `myotis-engine-<tag>-android.aar`, `myotis-engine-<tag>-maven-repo.zip` | **Gated**, as staged: the AAR, its jars, poms and metadata. In the zip, the natives jars for macOS and Linux and the iOS module come from other builders (see below). |
| Linux desktop | `Myotis-<tag>-<arch>.deb` | **Gated**, as a file and by its contents, as built in the builder image (the release's own `.deb` comes from another builder, see below). |
| macOS desktop | `Myotis-<tag>-<arch>.dmg` | **Gated**, by content: every file of the `.app` in the image, not the dmg container. Packaged under umask 022 (see below). Unsigned, not notarized. |
| Windows desktop | (no release asset yet) | **Gated**, by content: the files the msi installs. |
| iOS frameworks | `MyotisEngine.xcframework.zip`, `MyotisKit.xcframework.zip` | **Gated.** Bit for bit, the zips and their trees. |
| Node addon | `myotis-node.<platform>.node` | **Gated**, as each platform's two legs build it. |
| Daemon jars | `*-SNAPSHOT.jar` | Not compared. |

Android came first, on purpose: it is the artifact that holds a wallet. The
desktop and Apple artifacts joined the gate on 2026-11-11, once their last
differences were fixed and a comparison had come out clean on all three
platforms. A difference now fails the run on any of them, with a diffoscope
report per differing file.

Three limits to state plainly:

- **One step does not vary its umask: packaging the dmg.** jpackage creates
  the directories inside the dmg with the umask of its own process, and
  nothing can normalize them once the image exists. So the dmg is defined as
  packaged under umask 022: the build refuses to package one under any other,
  and both builds of the comparison run that one step under it. Everything
  the dmg takes in is still built under two different umasks.

- **The gate compares two rebuilds with each other.** That the *published*
  assets equal a rebuild is a separate comparison, made on every tag by the
  `Compare the image build with the published assets` job of the tag's
  `reproducible builds` run. It is reported in that run's summary. Read it for
  the release you are checking, or make the comparison yourself (step 3).
  Between tags, every run also builds once on the hosted runner's toolchain,
  the one the release workflows use, and reports it against the image build:
  when the image first built (2026-11-10), every Android artifact was identical
  between the two.
- **The Linux host libraries a release ships are not built in the builder
  image.** They come from `ubuntu-22.04` runners, for a glibc 2.35 floor, so
  the Linux natives jar inside the engine library zip, the `.deb` and the Node
  addon are outside what the image reproduces today.

## 1. Checksums

Every release has one `SHA256SUMS` file that lists every other file of the
release. Download it next to what you downloaded:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

(`shasum -a 256 -c` on macOS.) The release workflows write it from the SHA-256
GitHub records for each asset. Before that, each workflow checks its own
uploads: the hash GitHub recorded must be the hash of the file the job built,
or the job fails. `SHA256SUMS` lists whatever the release holds, so a file
someone added by hand would be listed too; what such a file would lack is the
attestation of the next section.

A checksum file from the same page as the download protects against a broken
download and a swapped single asset. It does not protect against someone who
controls the release page. That is what the next two checks are for.

## 2. Build provenance

Each asset carries a build-provenance attestation (GitHub's artifact
attestations): a statement, signed through Sigstore with a certificate GitHub issues to the
workflow run, that names the repository, the workflow, the commit and the ref
the file was built from.

```bash
gh attestation verify Myotis-v0.1.21-android.apk \
  --repo biafra23/myotis --source-ref refs/tags/v0.1.21
```

It fails if the file is not one a workflow of this repository attested for
that tag. To check a whole release at once, checksums included:

```bash
scripts/verify_release.sh v0.1.21
```

That is stricter than the single command above: for each asset it also asks
for the commit the tag points at (`--source-digest`) and for the workflow that
is supposed to build that asset (`--signer-workflow`, e.g. `android-apk.yml`
for the APKs).

That is what the `verify release` workflow runs on every tag, once the
publishing workflows are done.

An attestation shows where a file was built, not that the build was honest:
it trusts GitHub's runners and this repository's workflows at that commit.
Rebuilding takes that trust out.

## 3. Rebuild it

### The toolchain

The reference toolchain for the Android artifacts is a container image,
`docker/builder/`. Nothing in it moves:

| Part | Pinned by |
|---|---|
| Base image (`ubuntu:26.04`) | digest |
| apt packages | one `snapshot.ubuntu.com` instant; the resulting package list is committed (`apt-packages.txt`) and checked |
| JDK (Eclipse Temurin) | SHA-256 of the archive; version from `.java-version` |
| rustup, rustc | SHA-256 of `rustup-init`; exact rustc from `rust/rust-toolchain.toml` |
| Android command-line tools, platform | SHA-256 of the archives |
| NDK, build-tools, cargo-ndk | exact versions from `gradle/libs.versions.toml` |

`docker/builder/pins.env` holds the pins that exist only for the image; every
other version is read from the one file that pins it for the build itself. The
build's dependencies are pinned separately, by version and by hash: Gradle's
in `gradle.lockfile`s and `gradle/verification-metadata.xml`
([gradle-dependency-pins.md](gradle-dependency-pins.md)), Cargo's in the three
`Cargo.lock` files, used with `--locked`.

### The commands

```bash
git clone https://github.com/biafra23/myotis.git && cd myotis
git checkout v0.1.21                 # the tag you are checking

docker/builder/build.sh              # builds the image from its pins
docker/builder/check.sh              # every tool in it is the pinned version
docker/builder/run.sh -- scripts/repro/build_linux.sh
```

Instead of building the image you can pull the one the project published for
exactly these pins. `docker/builder/image.lock`, in the tag's tree, names it by
digest:

```bash
docker/builder/pull.sh               # in place of build.sh; then check.sh and run.sh as above
```

The two are a choice of whom to trust. `build.sh` trusts only the sources the
Dockerfile pins by digest and hash, and needs `snapshot.ubuntu.com` to answer,
which it does not always. `pull.sh` trusts whoever published the image: it is
the same image for everyone, and `check.sh` holds it to the pins (every tool's
version, the apt package list), but nothing compares it byte for byte with a
build from the Dockerfile, because an image build is not repeatable bit for
bit. CI pulls. For the strongest check, build.

`run.sh` mounts the checkout at its own path, runs as your user with a
read-only image, and gives the build its own `HOME`, cargo home and Gradle
home and nothing of your environment. `build_linux.sh` takes the version from
the tag and `SOURCE_DATE_EPOCH` from the tagged commit. The image is
linux/amd64; on an Apple Silicon Mac it runs under emulation, slowly.

The results:

| Built | Compare with |
|---|---|
| `android-app/build/outputs/apk/release/android-app-release-unsigned.apk` | `Myotis-<tag>-android-unsigned.apk` |
| `build/maven-repo/eth/myotis/myotis-engine-android/<version>/myotis-engine-android-<version>.aar` | `myotis-engine-<tag>-android.aar` |

```bash
sha256sum android-app/build/outputs/apk/release/android-app-release-unsigned.apk
grep android-unsigned.apk SHA256SUMS
```

The two hashes are the same, or the release is not what this source builds.
If they differ, [diffoscope](https://diffoscope.org) names the difference:

```bash
diffoscope android-app/build/outputs/apk/release/android-app-release-unsigned.apk \
  Myotis-v0.1.21-android-unsigned.apk
```

The debug APK is compared by content: `scripts/repro/collect.sh` extracts
every entry of both sides the same way, leaving out the signature files, and
`scripts/repro/compare.py` compares the two trees. That is the comparison CI
makes. (It is signed with the public debug key in the tree, the same for
everyone, so the whole file may well match too; the comparison does not
depend on it.)

### The signed APK

The app you install is signed; a rebuild cannot be, without the release key.
The link between the two is that signing only **adds** to the file. The signed
APK is the unsigned APK's bytes, in place, followed by the signature files
(`META-INF/*.SF`, `*.RSA`, `MANIFEST.MF`), padding, and the APK Signing Block:

```bash
scripts/repro/compare_signed_apk.py Myotis-v0.1.21-android.apk \
  android-app/build/outputs/apk/release/android-app-release-unsigned.apk
```

With your own rebuild as the second argument this is the whole chain in one
step: the installable app is your build plus a signature. The release job runs
the same check between the two published APKs before it publishes either. An
independent tool for the same question, used by F-Droid's verification, is
[apksigcopier](https://github.com/obfusk/apksigcopier):

```bash
apksigcopier compare Myotis-v0.1.21-android.apk \
  --unsigned android-app/build/outputs/apk/release/android-app-release-unsigned.apk
```

Who signed it is a separate check: the signer certificate's SHA-256 is pinned
in `android-app/release-signing-cert.sha256`
([android-release-signing.md](android-release-signing.md)).

## What is inside: the SBOMs

Each release also lists what its products are made of, as CycloneDX 1.5 JSON,
one file per product:

| File | Product |
|---|---|
| `Myotis-<tag>-android.cdx.json` | the Android app (the signed and the unsigned APK) |
| `Myotis-<tag>-android-debug.cdx.json` | the Android debug app, whose classpath also has the Compose tooling |
| `Myotis-<tag>-desktop.cdx.json` | the desktop app in its installers (dmg, deb, msi) |
| `Myotis-<tag>-daemon.cdx.json` | what the daemon runs with (its jars are thin: none of it is inside them) |
| `Myotis-<tag>-engine-library.cdx.json` | the engine library (AAR, desktop jar, natives jars, the iOS module) |
| `Myotis-<tag>-ios.cdx.json` | `MyotisKit.xcframework.zip` and `MyotisEngine.xcframework.zip` |
| `Myotis-<tag>-node.cdx.json` | the Node.js addon |

They are **generated from the pins of the tagged tree, not from a build**
(`scripts/sbom.py`): the Gradle lockfiles and `gradle/verification-metadata.xml`,
`rust/Cargo.lock`, `.java-version` and `rust/rust-toolchain.toml`. So they say
what the build is held to, and you can regenerate them from a checkout of the
tag without building anything and compare (Python 3.11 or newer, nothing else):

```bash
git checkout v0.1.21
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python3 scripts/sbom.py --tag v0.1.21 --out sbom
sha256sum sbom/*.cdx.json    # the hashes SHA256SUMS lists for them
```

What that makes each part, and what is missing:

- **Maven components are exact.** They are the modules the product's runtime
  configuration is locked to (for example `android-app/gradle.lockfile`,
  `releaseRuntimeClasspath`), and a build fails on any other version. For the
  Android apps that includes `desugar_jdk_libs`, which is compiled into the
  APK without being on the classpath; the rules file it is desugared by is
  read by the build only, and each document names what it leaves out for that
  reason (`myotis:sbom:left-out`). Each has
  the SHA-256 the build verifies the file against, where the module has one
  payload file; where it has several (variants, one per host), each pinned file
  is named in the component's properties. The desktop app also lists the
  Compose and skiko modules of each host its document names
  (`myotis:sbom:hosts`): the hosts those modules are pinned for.
- **Rust components are a superset.** `Cargo.lock` records one graph for all
  targets and all kinds of dependency, so the list is every crate reachable
  from the product's own crates: build dependencies, optional ones (Arti,
  which only a Tor-enabled build links) and crates only another operating
  system compiles are in it. Every crate that is linked is listed; not every
  listed crate is linked.
- **Two toolchain components** stand for code that comes from the toolchain
  and ends up inside: the Rust standard library, and for the desktop app the
  Eclipse Temurin JDK its installer bundles. Both carry a CPE.
- **No licenses and no dependency graph.** A lockfile records neither. These
  are inventories, which is what matching against security advisories needs.
- The files describe the tag's pins. That the published binaries were built
  from those pins is what the attestation and the rebuild above are for.

## For maintainers

- The rule for merging is in `CLAUDE.md` (*No merge into `main` may break
  reproducibility*), and what a release has to show in its *Releases* section,
  step 6.
- A red comparison names every differing file in the run's
  `repro-report-<platform>-<leg>-vs-<leg>` artifact. Fix the leak; do not add
  it to `scripts/repro/known-differences.txt`, which is empty and meant to
  stay so.
- The image is published once per set of pins, and `docker/builder/image.lock`
  names it by digest; the comparison pulls that. Moving a pin moves the lock
  in the same change: the `builder image` workflow builds and publishes the new
  image and fails with the lines to commit. It also builds from the pins
  weekly, to notice when that stops working. Moving `APT_SNAPSHOT` or the
  package list moves `docker/builder/apt-packages.txt` too: `check.sh` prints
  the new list when it differs.
- Every release asset is uploaded through `.github/release-assets.sh` and
  attested in the same job, whose last step
  (`release-assets.sh --checksums`) is what keeps `SHA256SUMS` complete.
- The SBOMs need no upkeep for a dependency bump: they are read from the pins.
  What they are read BY is the product table in `scripts/sbom.py` (which
  project's which configuration, which crates). A configuration or crate that
  was renamed fails the `sbom` workflow and `scripts/test_sbom.py` with the
  name it looked for; a new shipped product gets a line there.
