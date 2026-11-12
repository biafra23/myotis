#!/usr/bin/env bash
# Build the Linux + Android release artifacts (#734).
#
#   scripts/repro/build_linux.sh [VERSION]      in the checkout root
#
# What reproducible-builds.yml's Linux legs run, inside the builder image
# (docker/builder/run.sh), and what a third party runs to rebuild a release's
# ANDROID artifacts: the unsigned release APK, the debug APK and the engine
# library as staged (the AAR and its jars, poms and metadata).
# scripts/repro/collect.sh gathers them afterwards.
#
# It also builds the Linux host libraries, the Node addon, the .deb, a Linux
# natives jar and the Go engine's two binaries (go/cmd/myotis-go,
# go/cmd/myotis-lc, into build/go/), which the comparison of two such builds
# holds to the same bytes like everything else. Nothing publishes the Go
# binaries yet: they are compared so that the day something does, it ships
# bytes a third party can rebuild. Those are NOT the release's
# bytes when built in the image: a release builds its Linux host libraries on
# ubuntu-22.04 (engine-library.yml, for a glibc 2.35 floor) and stages the
# natives of four platforms, and jpackage derives the .deb's Depends from the
# build host's installed libraries.
#
# The inputs a release build has, with the defaults a rebuild needs, so that
# running this on a checkout of a tag gives the release's Android bytes without
# any further setup:
#   SOURCE_DATE_EPOCH  default: the commit time (dpkg-deb clamps the .deb's
#                      mtimes to it; the wall clock otherwise)
#   VERSION            the version the engine library is staged at, as
#                      engine-library.yml publishes it. Default: the v* tag in
#                      GITHUB_REF, else the v* tag HEAD is exactly at, else the
#                      bare release version of the tree.
#   REPRO_UMASK        default 022
#   APP_VERSION        the version the app shows (-PappVersion). Default: read
#                      from git, which needs a clone with the tag; state it
#                      for a source tarball or a shallow clone.
set -euo pipefail
umask "${REPRO_UMASK:-022}"
# Resolved before the export: `export X=$(cmd)` has export's status, and an
# empty value would let the build stamp the wall clock (or fail late).
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null) || SOURCE_DATE_EPOCH=""
    [[ -n "$SOURCE_DATE_EPOCH" ]] || {
        echo "build_linux.sh: no git history here: set SOURCE_DATE_EPOCH to the tagged commit's time" >&2
        exit 1
    }
fi
export SOURCE_DATE_EPOCH

version=${1:-}
if [[ -z "$version" && "${GITHUB_REF:-}" == refs/tags/v* ]]; then version=${GITHUB_REF_NAME#v}; fi
if [[ -z "$version" ]]; then
    tag=$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || true)
    version=${tag#v}
fi
flag=-PpublishRelease
[[ -z "$version" ]] || flag="-PpublishRelease=$version"
app_version=()
[[ -z "${APP_VERSION:-}" ]] || app_version=("-PappVersion=$APP_VERSION")
# No apostrophe inside ${...:-...}: bash versions disagree on whether one opens
# a quote there, even within double quotes.
echo "build_linux.sh: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, engine library version: ${version:-the release version of the tree}"

for attempt in 1 2 3; do
    rm -rf build/maven-repo
    ./gradlew "$flag" ${app_version[@]+"${app_version[@]}"} cargoBuildHost \
        :android-app:assembleRelease :android-app:assembleDebug \
        :app-desktop:packageDeb publishAllPublicationsToStagingRepository \
        --stacktrace && break
    [[ $attempt -lt 3 ]] || { echo "::error::build failed after 3 attempts"; exit 1; }
    echo "::warning::build attempt $attempt failed; retrying in 25s (transient dependency resolution?)"
    sleep 25
done
python3 -I scripts/normalize_maven_metadata.py build/maven-repo
(cd rust && . ./repro-env.sh && cargo build --locked -p myotis-node --release --target x86_64-unknown-linux-gnu)
python3 -I scripts/check_16k_alignment.py android-app/build/outputs/apk/release/*.apk

# The Go engine. -trimpath keeps the checkout path and the module cache's
# location out of the binary; -buildvcs=false keeps the VCS stamp out (a dirty
# flag or a different HEAD would change the bytes); -mod=readonly refuses a
# go.mod/go.sum the build would have to change; GOTOOLCHAIN=local refuses a
# toolchain other than the installed one instead of downloading it. cgo stays
# on: blst (BLS verification, the same C library the Rust engine links) has Go
# bindings only through cgo, so the C compiler is a build input: the builder
# image's, from the pinned apt snapshot (docker/builder/apt-packages.txt).
# Module sources come through GOPROXY and are checked against go/go.sum.
rm -rf build/go
(cd go && GOTOOLCHAIN=local CGO_ENABLED=1 GOFLAGS="-trimpath -mod=readonly -buildvcs=false" \
    go build -o ../build/go/ ./cmd/myotis-go ./cmd/myotis-lc)
