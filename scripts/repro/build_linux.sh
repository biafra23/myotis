#!/usr/bin/env bash
# Build the Linux + Android release artifacts (#734).
#
#   scripts/repro/build_linux.sh          in the checkout root
#
# What reproducible-builds.yml's Linux legs run, inside the builder image
# (docker/builder/run.sh), and what a third party runs to rebuild a release:
# the unsigned release APK and the debug APK, the engine library as staged
# (AAR, jars, natives jars, metadata), the Linux host libraries and Node addon,
# and the .deb. scripts/repro/collect.sh gathers them afterwards.
#
# Honours REPRO_UMASK (default 022) and, through the build, SOURCE_DATE_EPOCH.
# On a v* tag (GITHUB_REF) the engine library is staged at the tag's version,
# as engine-library.yml publishes it; otherwise at the bare release version.
set -euo pipefail
umask "${REPRO_UMASK:-022}"

flag=-PpublishRelease
[[ "${GITHUB_REF:-}" != refs/tags/v* ]] || flag="-PpublishRelease=${GITHUB_REF_NAME#v}"

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
