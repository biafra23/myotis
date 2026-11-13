# Dependency pins, the builder image and reproducible builds

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read before adding or bumping a dependency, moving a toolchain pin, or touching build scripts, packaging or release workflows. "Ready to merge" is defined in `workflow.md`; *Deferred* in `pull-requests.md`.

## Key Dependencies

- **Every Gradle dependency is pinned by version AND hash** (#734): per-project
  `gradle.lockfile`s plus `gradle/verification-metadata.xml` (verification is
  strict; the locks run in Gradle's default mode, and STRICT's rule, no
  configuration without lock state, is enforced by `resolveAllDependencies` in
  the `gradle pins` check), so a
  new or bumped dependency fails the build until its pins are regenerated with
  `scripts/update_gradle_pins.sh` (then `--from-ci` for the macOS/Windows/arm64
  hashes the `gradle pins` workflow collects). Review the hash diff like code.
  Never "fix" a verification failure you did not cause by re-pinning — bytes
  changed under a pinned version. docs/guides/gradle-dependency-pins.md.
- **The builder image is the reference toolchain for the Linux and Android
  artifacts** (`docker/builder/`, #734): base image by digest, apt from one
  snapshot, the JDK / rustup / Android command-line tools / Go by SHA-256, and
  rustc, the NDK, build-tools and cargo-ndk at the versions the build pins,
  which `build.sh` reads from their one source each (`.java-version`,
  `rust/rust-toolchain.toml`, `gradle/libs.versions.toml`, `go/go.mod`). Bumping the JDK
  therefore also moves `JDK_VERSION` / `JDK_BUILD` / `JDK_SHA256` in
  `docker/builder/pins.env`, in the same change; `build.sh` refuses a mismatch
  and the `builder image` workflow fails the PR. The same holds for Go:
  moving `go/go.mod`'s `go` line moves `GO_VERSION` / `GO_SHA256` there (the
  image builds the Go engine's binaries, which the gate compares). It is what a third party
  rebuilds a release's ANDROID artifacts in (`docker/builder/build.sh`, then
  `docker/builder/run.sh -- scripts/repro/build_linux.sh`; `run.sh` gives the
  build its own HOME, cargo home and Gradle home and none of the caller's
  environment) and what `reproducible-builds.yml`'s Linux legs a and b build
  in. **The image is published** (owner's decision, 2026-11-10), once per set
  of pins, to `ghcr.io/biafra23/myotis-builder`, and
  `docker/builder/image.lock` names it by digest together with the key of the
  pins it was built from (`build.sh --print-key`: the build args and the
  Dockerfile). The comparison, and anyone who prefers not to build it, gets
  that digest with `docker/builder/pull.sh` and checks it with `check.sh`;
  building needs `snapshot.ubuntu.com`, which refuses requests for minutes at
  a time. **Moving a pin therefore moves `image.lock` in the same change**,
  like `apt-packages.txt`: the `builder image` workflow builds the new image
  from the pins, publishes it and fails with the lines to commit; nothing
  is hand-written, and an image already published for a key is never
  replaced (`publish.sh` pushes only when the registry has said the key's tag
  does not exist). The same workflow builds from the pins weekly, without
  pulling, so "the image can still be built" stays observed. **The release workflows themselves still build on the hosted runner**
  (`android-apk.yml`, `engine-library.yml`: the same pinned versions, installed
  by the setup actions); the comparison's leg r builds on that toolchain, and
  `Compare linux image vs runner toolchain` REPORTS whether it and the image
  give the same bytes. It is not gated (the gate is the owner's), and it is a
  proxy: the proof that a published artifact is the image's is a comparison
  with the published assets themselves. **The image is not the builder of the
  Linux host libraries a release ships**: the engine natives jars come from
  `ubuntu-22.04` runners on purpose (a glibc 2.35 floor), the released `.deb`s
  and the Linux Node addons from `ubuntu-26.04` / `ubuntu-24.04-arm`, so all of
  them are outside what the image reproduces until a builder is pinned for
  them.
  The image's apt packages are listed in `docker/builder/apt-packages.txt`,
  which `check.sh` compares with the built image: moving `APT_SNAPSHOT` or the
  package list moves that file in the same change, and its diff is reviewed
  like a dependency bump. Never install or upgrade a tool inside an image
  build of the artifacts: the image is read-only at run time on purpose.
- **Tuweni 2.7.2** (upstream `io.consensys.tuweni`, Maven Central; original `org.apache.tuweni` packages) — RLP encoding, SECP256K1, byte utilities.
- **Netty 4.2.x** — NIO-only (no epoll/kqueue). 4-thread `NioEventLoopGroup` for RLPx.
- **BouncyCastle** — SECP256K1 crypto provider

## No merge into `main` may break reproducibility

**A PR whose merge would make a release build non-reproducible does not merge
into `main`** (owner ruling, 2026-11-10). "Reproducible" is what
`reproducible-builds.yml` GATES (#734): the artifact built twice — two
runners, different checkout path, `CARGO_HOME`, `GRADLE_USER_HOME`, time zone,
locale, umask and wall clock, and on Linux, where both builds run in the
builder image, another user — comes out bit-for-bit identical, apart from the
entries in `scripts/repro/known-differences.txt` (none today). The workflow's
header has the exact list of what the two builds differ in, and the one step
that does not vary (packaging the dmg).

**The gate is everything the two builds produce, on all three platforms**
(owner's decisions: Android first, 2026-11-10; widened 2026-11-11, once the
desktop and Apple artifacts had reproduced). `Compare linux`, `Compare macos`
and `Compare windows` each fail on any difference between their legs a and b:
the unsigned release APK, the debug APK (by payload: its debug-key signature
differs by design), the engine library as staged (the AAR, its jars, natives
jars, poms and metadata), the `.deb` and the Go engine's two binaries
(`myotis-go`, `myotis-lc`; Linux only, owner's decision 2026-11-12); the dmg
(by its `.app`) and the two xcframeworks; the msi (by the files it installs); and on each platform the
host libraries: the engine library and the Node addon. Two comparisons are
REPORTED and do not fail, because their second side is not a second build of
the same kind: `Compare linux image vs runner toolchain`, and on a tag the
image build against the published assets. Do not widen or narrow the gate
without the owner.

- **Before reporting a PR into `main` "ready to merge", its head has a green
  `reproducible builds` run** whenever the PR can change what a release build
  produces: build scripts and plugins (`*.gradle.kts`, `gradle/`,
  `gradle.properties`), dependencies and their pins, toolchain pins
  (`rust/rust-toolchain.toml`, `.java-version`, `.xcode-version`, the NDK /
  build-tools / cargo-ndk pins), `rust/.cargo/`, `rust/*.sh`, Cargo manifests
  and locks, packaging and signing configuration, the release workflows, or
  code that runs at build time (build scripts, macros, codegen, embedded
  resources). The workflow runs by itself on a PR that changes it or its
  scripts; for any other PR, dispatch it on the PR's branch (Actions tab, or
  `gh api repos/<owner>/<repo>/actions/workflows/reproducible-builds.yml/dispatches
  -f ref=<branch>`) and wait for its `Compare` jobs (`Compare linux`,
  `Compare macos` and `Compare windows` carry the gate). When unsure whether a
  change can reach a release artifact, dispatch it. A PR that touches only
  docs, tests or CI that builds nothing shipped needs no run.
- **A red comparison is a blocker, like red CI** (a gated artifact differs):
  find the leak (the run's
  `repro-report-<platform>-<leg>-vs-<leg>` artifact names every differing file, with a
  diffoscope report) and fix it on the PR's own branch. **Never make it green
  by adding a pattern to `known-differences.txt`, or by loosening
  `scripts/repro/compare.py` / `collect.sh`** — that accepts a
  non-reproducible artifact, which is the owner's call (*Deferred*, with the
  cause and the options). An entry whose cause is fixed is REMOVED (the
  comparison names patterns that no longer match).
- **The weekly run on `main` is the backstop**, and a `v*` tag runs the same
  check as the release's own proof. A red weekly or tag run means `main` is
  not reproducible: report it to the owner, and its fix is the next PR into
  `main`, before anything that could hide or compound it.
- This adds a condition to "ready to merge"; it changes nothing about who
  merges. The merge into `main` stays the owner's.
