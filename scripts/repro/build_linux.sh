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
# It also builds the Linux host libraries, the Node addon, the .deb and a
# Linux natives jar, which the comparison of two such builds holds to the same
# bytes like everything else. Those are NOT the release's
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
set -euo pipefail
umask "${REPRO_UMASK:-022}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

version=${1:-}
if [[ -z "$version" && "${GITHUB_REF:-}" == refs/tags/v* ]]; then version=${GITHUB_REF_NAME#v}; fi
if [[ -z "$version" ]]; then
    tag=$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || true)
    version=${tag#v}
fi
flag=-PpublishRelease
[[ -z "$version" ]] || flag="-PpublishRelease=$version"
# No apostrophe inside ${...:-...}: bash versions disagree on whether one opens
# a quote there, even within double quotes.
echo "build_linux.sh: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, engine library version: ${version:-the release version of the tree}"

for attempt in 1 2 3; do
    rm -rf build/maven-repo
    ./gradlew "$flag" cargoBuildHost \
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
