#!/usr/bin/env bash
# Check a staged publication of the engine library before it is published.
#
# Reads the local Maven repository that `./gradlew publishAllPublicationsToStagingRepository`
# writes (build/maven-repo — the root build.gradle.kts `Publishing` section) and
# fails on anything a consumer would only discover after the version is on
# GitHub Packages, where it cannot be replaced:
#
#   - the closure is complete: every module the engine library's POMs reach is
#     in the repository, at the one version, under its eth.myotis artifact id
#     (a project dependency on a module outside the set keeps the build's own
#     group and would resolve to nothing);
#   - the Android AAR carries the Rust engine for every shipped ABI
#     (libmyotis_engine.so + libmyotis_bls.so) and JNA's dispatcher
#     (libjnidispatch.so) next to it — an AAR missing one of them loads no
#     engine on that ABI, and the AAR's classes.jar has the entry point;
#   - the engine library's POMs (jvm AND android) pin JNA with the strict
#     constraint myotis-engine/build.gradle.kts declares, so a consumer whose
#     graph wants another jna version fails at resolution instead of at
#     Native.<clinit> on every device;
#   - the version carries no -SNAPSHOT: the publication is staged with
#     -PpublishRelease (a SNAPSHOT on GitHub Packages would be a release nobody
#     can pin — and Gradle stages a SNAPSHOT under Maven's timestamped file
#     names, which is not the layout the release publishes).
#
# Usage: scripts/check_engine_library.sh <staging-repo-dir> [--without-rust-engine]
#   <staging-repo-dir>     build/maven-repo after
#                          `./gradlew -PpublishRelease publishAllPublicationsToStagingRepository`
#   --without-rust-engine  the publication was built with -PskipRustEngine
#                          (no Android Rust toolchain): skip the jniLibs checks,
#                          keep every other one. For a local run; CI never passes it.
#
# Run by .github/workflows/engine-library.yml on every build of the publication
# and again on the tag build right before anything is uploaded.

set -euo pipefail

repo=${1:?usage: $0 <staging-repo-dir> [--without-rust-engine]}
shift
with_native=1
for arg in "$@"; do
    case "$arg" in
        --without-rust-engine) with_native=0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

here=$(cd "$(dirname "$0")/.." && pwd)
group_dir="$repo/eth/myotis"
[ -d "$group_dir" ] || { echo "::error::$group_dir is missing — nothing was staged (run ./gradlew publishAllPublicationsToStagingRepository first)"; exit 1; }

# The JNA version the AAR's libjnidispatch.so is taken from — the one catalog
# entry both halves of myotis-engine/build.gradle.kts read.
jna_version=$(sed -n 's/^jna *= *"\([^"]*\)".*/\1/p' "$here/gradle/libs.versions.toml")
[ -n "$jna_version" ] || { echo "::error::could not read the jna version from gradle/libs.versions.toml"; exit 1; }

# The ABIs the AAR ships, from rust/build-android.sh's `cargo ndk -t` list — the
# same source the root build's shippedAbis follows. (Portable shell throughout:
# a maintainer runs this on macOS too — bash 3.2, BSD sed — so no mapfile, no
# GNU-only sed.)
abis=($(awk '/cargo ndk/ { for (i = 1; i <= NF; i++) if ($i == "-t") print $(i + 1) }' "$here/rust/build-android.sh"))
[ "${#abis[@]}" -ge 1 ] || { echo "::error::could not read the shipped ABIs from rust/build-android.sh"; exit 1; }

fail=0
err() { echo "::error::$*"; fail=1; }

# One version for the whole set: the directory under the root publication.
# nullglob, so a repository with no myotis-engine at all is "found 0", not a
# literal `*` that every check below then reports as a missing file.
shopt -s nullglob
versions=("$group_dir"/myotis-engine/*/)
shopt -u nullglob
# (`${versions[*]-}`: an empty array is "unbound" to bash < 4.4 under set -u.)
[ "${#versions[@]}" -eq 1 ] || { err "expected exactly one staged version of eth.myotis:myotis-engine, found: ${versions[*]-}"; exit 1; }
version=$(basename "${versions[0]}")
echo "staged version: $version"
case "$version" in
    *-SNAPSHOT)
        echo "::error::the staged version is $version — stage the publication with -PpublishRelease (a SNAPSHOT is staged under timestamped file names, and it is not what a release publishes)"
        exit 1 ;;
esac

# Every artifact a consumer's graph reaches, with the file that must exist for
# it. KMP modules: the root (module metadata + the pom that redirects to the
# target artifacts) and one artifact per published target.
expect() { # <artifactId> <file suffix>
    local f="$group_dir/$1/$version/$1-$version$2"
    [ -s "$f" ] || err "missing or empty: ${f#$repo/}"
}
for a in myotis-api myotis-engine-common myotis-engine-ports myotis-engine-rust; do
    expect "$a" .jar
    expect "$a" -sources.jar
done
expect myotis-rpc-policy-jvm .jar
# The policy module's iOS variants: cross-compiled on the Linux runner and named
# by the root module metadata, so a KMP consumer with an iOS target resolves them.
expect myotis-rpc-policy-iosarm64 .klib
expect myotis-rpc-policy-iossimulatorarm64 .klib
expect myotis-engine-jvm .jar
expect myotis-engine-android .aar
for a in myotis-api myotis-engine-common myotis-engine-ports myotis-engine-rust \
         myotis-rpc-policy myotis-rpc-policy-jvm myotis-rpc-policy-iosarm64 myotis-rpc-policy-iossimulatorarm64 \
         myotis-engine myotis-engine-jvm myotis-engine-android; do
    expect "$a" .pom
    expect "$a" .module
done

# No stale name: nothing may be staged under the Gradle project name `core`, and
# every eth.myotis dependency a POM names must be staged under that name. And
# no leak: a project dependency on a module OUTSIDE the published set keeps
# the build's own group (com.jaeckel.ethp2p) in the POM — resolvable from no
# repository, and the one shape a consumer would otherwise find only after
# the version is on GitHub Packages.
[ ! -e "$group_dir/core" ] && [ ! -e "$group_dir/myotis-core" ] || err ":core was staged — it is not part of the published set (Tuweni + BouncyCastle would ride into every consumer)"
while IFS= read -r pom; do
    if grep -q '<groupId>com.jaeckel.ethp2p</groupId>' "$pom"; then
        err "${pom#$repo/} names com.jaeckel.ethp2p:* — a dependency on an unpublished project module leaked into the publication"
    fi
    # Dependencies and constraints alike: `<groupId>eth.myotis</groupId>` followed
    # by the artifactId on the next line (Gradle's POM layout).
    while IFS= read -r dep; do
        [ -d "$group_dir/$dep/$version" ] \
            || err "${pom#$repo/} depends on eth.myotis:$dep, which is not staged at $version"
    done < <(grep -A1 '<groupId>eth.myotis</groupId>' "$pom" | sed -n 's/.*<artifactId>\(.*\)<\/artifactId>.*/\1/p' | sort -u)
done < <(find "$group_dir" -name "*-$version.pom")

# The JNA pin, in both halves of the engine library. The module metadata, which
# a Gradle consumer reads, carries the constraint as `"strictly": "v"`; the POM,
# for a Maven consumer, carries it as a managed version under
# <dependencyManagement> (Maven has no strict constraint; the managed version is
# what Gradle maps `strictly` to there).
for target in jvm android; do
    pom="$group_dir/myotis-engine-$target/$version/myotis-engine-$target-$version.pom"
    module="$group_dir/myotis-engine-$target/$version/myotis-engine-$target-$version.module"
    [ -s "$pom" ] || continue  # reported above
    # (No `... | grep -q` pipelines in this script: under pipefail, grep -q
    # closing the pipe early can fail the producer with SIGPIPE and read as a
    # miss. Capture, then test the captured text.)
    managed=$(sed -n '/<dependencyManagement>/,/<\/dependencyManagement>/p' "$pom" | grep -A2 '<artifactId>jna</artifactId>' || true)
    [[ "$managed" == *"<version>$jna_version</version>"* ]] \
        || err "${pom#$repo/} does not manage net.java.dev.jna:jna at $jna_version — a Maven consumer's graph could pick another jna than the AAR's libjnidispatch.so"
    if [ -s "$module" ]; then
        grep -q "\"strictly\": *\"$jna_version\"" "$module" \
            || err "${module#$repo/} carries no strict jna $jna_version constraint"
    else
        err "missing: ${module#$repo/}"
    fi
done

# The AAR's contents.
aar="$group_dir/myotis-engine-android/$version/myotis-engine-android-$version.aar"
if [ -s "$aar" ]; then
    listing=$(unzip -Z1 "$aar")
    # Extract only when the entry exists: `unzip -p` of a missing entry would
    # end the script here under set -e, ahead of the ABI checks and the roll-up.
    if grep -qx 'classes.jar' <<<"$listing"; then
        classes_jar=$(mktemp)
        unzip -p "$aar" classes.jar > "$classes_jar"
        classes=$(unzip -Z1 "$classes_jar")
        rm -f "$classes_jar"
        grep -qx 'io/myotis/engine/Myotis.class' <<<"$classes" \
            || err "$(basename "$aar")'s classes.jar has no io.myotis.engine.Myotis — the entry point"
    else
        err "$(basename "$aar") has no classes.jar"
    fi
    for abi in "${abis[@]}"; do
        grep -qx "jni/$abi/libjnidispatch.so" <<<"$listing" \
            || err "$(basename "$aar") has no jni/$abi/libjnidispatch.so (JNA cannot dispatch on $abi)"
        if [ "$with_native" = 1 ]; then
            for lib in libmyotis_engine.so libmyotis_bls.so; do
                grep -qx "jni/$abi/$lib" <<<"$listing" \
                    || err "$(basename "$aar") has no jni/$abi/$lib (no Rust engine on $abi)"
            done
        fi
    done
    if [ "$with_native" = 0 ]; then
        echo "note: --without-rust-engine — libmyotis_*.so not checked"
    fi
    echo "aar: $(du -h "$aar" | cut -f1) $(basename "$aar")"
    printf '%s\n' "$listing" | { grep '^jni/' || true; } | sed 's/^/  /'
fi

[ "$fail" = 0 ] || exit 1
echo "OK: eth.myotis:* $version staged completely under ${repo}"
