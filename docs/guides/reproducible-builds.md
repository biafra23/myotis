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
that can change a release build is merged, and fails when a gated artifact
differs.

| Artifact | Release asset | Status |
|---|---|---|
| Android app, unsigned | `Myotis-<tag>-android-unsigned.apk` | **Gated.** Bit for bit. |
| Android app, signed | `Myotis-<tag>-android.apk` | The unsigned APK plus a signature, and nothing else ([below](#the-signed-apk)). The signature itself needs the release key and is not reproducible by design. |
| Android debug app | `Myotis-<tag>-android-debug.apk` | **Gated**, by payload: every entry of the APK. Its signature is left out: every build machine signs with its own generated debug key. |
| Engine library | `myotis-engine-<tag>-android.aar`, `myotis-engine-<tag>-maven-repo.zip` | **Gated**, as staged: the AAR, its jars, poms and metadata. In the zip, the natives jars for macOS and Linux and the iOS module come from other builders (see below). |
| Linux desktop | `Myotis-<tag>-<arch>.deb` | Compared and reported, not gated yet. |
| macOS desktop | `Myotis-<tag>-<arch>.dmg` | Compared and reported, not gated yet. Unsigned, not notarized. |
| Windows desktop | (no release asset yet) | Compared and reported, not gated yet. |
| iOS frameworks | `MyotisEngine.xcframework.zip`, `MyotisKit.xcframework.zip` | Compared and reported, not gated yet. |
| Node addon | `myotis-node.<platform>.node` | Compared and reported, not gated yet. |
| Daemon jars | `*-SNAPSHOT.jar` | Not compared. |

Android came first on purpose: it is the artifact that holds a wallet. The
rest joins the gate as its remaining differences are fixed; the workflow's
`Compare` jobs list them, with a diffoscope report per differing file, on
every run.

Two limits to state plainly:

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

It fails if the file is not the one a workflow of this repository attested
for that tag. To check a whole release at once, checksums included:

```bash
scripts/verify_release.sh v0.1.21
```

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

The debug APK is compared by content, since its signature differs on every
build: `scripts/repro/collect.sh` extracts both sides the same way, and
`scripts/repro/compare.py` compares the two trees. That is the comparison CI
makes.

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

## For maintainers

- The rule for merging is in `CLAUDE.md` (*No merge into `main` may break
  reproducibility*), and what a release has to show in its *Releases* section,
  step 6.
- A red comparison names every differing file in the run's
  `repro-report-<platform>-<leg>-vs-<leg>` artifact. Fix the leak; do not add
  it to `scripts/repro/known-differences.txt`, which is empty and meant to
  stay so.
- The image is rebuilt from its pins on every change to one of them and
  weekly (`builder image`); the comparison reuses an image already built from
  the same pins. Moving `APT_SNAPSHOT` or the package list moves
  `docker/builder/apt-packages.txt` in the same change: `check.sh` prints the
  new list when it differs.
- Every release asset is uploaded through `.github/release-assets.sh` and
  attested in the same job, whose last step
  (`release-assets.sh --checksums`) is what keeps `SHA256SUMS` complete.
