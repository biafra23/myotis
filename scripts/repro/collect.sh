#!/usr/bin/env bash
# Collect one rebuild leg's artifacts for comparison (#734, Part 5a).
#
#   scripts/repro/collect.sh PLATFORM SRC OUT     PLATFORM: linux | macos | windows
#
# Copies what reproducible-builds.yml built in the checkout SRC into OUT, under
# names that do not depend on the leg (no checkout path, no runner name), so two
# legs' OUT trees are compared file by file. Tier 1 (bit-for-bit, issue #734
# D-d) is copied as shipped. Tier 2 artifacts, and the signed debug APK, are
# compared by PAYLOAD: their container (dmg, msi, the debug signature) is not
# expected to match, so the payload is extracted and the container left out.
# Every expected artifact must exist: a missing one fails here, not as a
# vacuous "identical" in the comparison.
set -euo pipefail

[[ $# -eq 3 ]] || { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2; exit 2; }
platform=$1 src=$(cd "$2" && pwd) out=$3
mkdir -p "$out"
out=$(cd "$out" && pwd)

# one GLOB: exactly one match, or fail
one() {
    local matches=()
    shopt -s nullglob
    # shellcheck disable=SC2206  # the glob is meant to expand
    matches=($1)
    shopt -u nullglob
    [[ ${#matches[@]} -eq 1 ]] || { echo "collect.sh: expected one $1, found ${#matches[@]}: ${matches[*]-}" >&2; exit 1; }
    printf '%s\n' "${matches[0]}"
}

# put SRC_FILE DEST: copy one artifact into OUT. A plain cp, so the copy's mode
# is the collect step's (a downloaded file carries no mode; only the bytes ship).
# Where modes DO ship, they are kept: the .app's files (ditto) and every APK
# entry's attributes (the .entries listing). compare.py hashes modes too.
put() { mkdir -p "$(dirname "$out/$2")"; cp "$1" "$out/$2"; echo "  $2"; }

# A zip's entries (name, CRC, sizes, method, order) plus their extracted bytes,
# leaving out the signature files a debug key produces (v1 META-INF/*.SF|RSA|EC|
# DSA; the v2/v3 block sits outside the entries and is never extracted).
zip_payload() {
    python3 -I - "$1" "$out/$2" <<'PY'
import os, re, sys, zipfile
apk, dest = sys.argv[1], sys.argv[2]
sig = re.compile(r"^META-INF/[^/]+\.(SF|RSA|EC|DSA)$")
os.makedirs(dest, exist_ok=True)
with zipfile.ZipFile(apk) as z, open(dest + ".entries", "w") as listing:
    for i in z.infolist():
        if sig.match(i.filename):
            continue
        listing.write(f"{i.filename}\t{i.CRC:08x}\t{i.compress_size}\t{i.file_size}"
                      f"\t{i.compress_type}\t{i.external_attr:08x}\t{i.create_system}\n")
        if not i.is_dir():
            path = os.path.join(dest, i.filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(z.read(i))
PY
    echo "  $2/ (payload) + $2.entries"
}

cd "$src"
echo "collecting $platform artifacts from $src into $out:"
case "$platform" in
linux)
    put "$(one 'android-app/build/outputs/apk/release/*-unsigned.apk')" android/app-release-unsigned.apk
    zip_payload "$(one 'android-app/build/outputs/apk/debug/*.apk')" android/app-debug-payload
    put "$(one 'app-desktop/build/compose/binaries/main/deb/*.deb')" desktop/myotis.deb
    put rust/target/release/libmyotis_engine.so host/libmyotis_engine.so
    put rust/target/x86_64-unknown-linux-gnu/release/libmyotis_node.so host/libmyotis_node.so
    # The engine library exactly as engine-library.yml stages it (normalized
    # metadata included), i.e. what the Maven-repository zip and the
    # maven-repo branch carry.
    mkdir -p "$out/maven-repo" && cp -R build/maven-repo/. "$out/maven-repo/" && echo "  maven-repo/"
    ;;
macos)
    put rust/target/release/libmyotis_engine.dylib host/libmyotis_engine.dylib
    put rust/target/aarch64-apple-darwin/release/libmyotis_node.dylib host/libmyotis_node.dylib
    # The xcframeworks as the release ships them (scripts/repro_zip.sh), and
    # their trees, so a difference is reported per file rather than "zip differs"
    # (the tree is a plain cp: its modes ship normalized, through the zip).
    mkdir -p "$out/ios/tree"
    for xc in rust/target/ios-xcframework/MyotisEngine.xcframework app-ios/build/XCFrameworks/release/MyotisKit.xcframework; do
        [[ -d "$xc" ]] || { echo "collect.sh: missing $xc" >&2; exit 1; }
        name=$(basename "$xc")
        scripts/repro_zip.sh "$(dirname "$xc")" "$name" "$out/ios/$name.zip"
        cp -R "$xc" "$out/ios/tree/" && echo "  ios/$name.zip + ios/tree/$name"
    done
    # Tier 2: the dmg's .app, not the disk image around it.
    dmg=$(one 'app-desktop/build/compose/binaries/main/dmg/*.dmg')
    mnt=$(mktemp -d)
    hdiutil attach -readonly -nobrowse -noverify -mountpoint "$mnt" "$dmg" >/dev/null
    app=$(one "$mnt/*.app")
    mkdir -p "$out/desktop/dmg-app"
    ditto --noextattr --noqtn "$app" "$out/desktop/dmg-app/$(basename "$app")"
    hdiutil detach "$mnt" >/dev/null
    echo "  desktop/dmg-app/$(basename "$app") (payload)"
    ;;
windows)
    put rust/target/release/myotis_engine.dll host/myotis_engine.dll
    put rust/target/x86_64-pc-windows-msvc/release/myotis_node.dll host/myotis_node.dll
    # Tier 2: the msi's files, extracted by an administrative install (no
    # registry, no install), not the msi database around them.
    msi=$(one 'app-desktop/build/compose/binaries/main/msi/*.msi')
    dest="$out/desktop/msi-payload"
    mkdir -p "$dest"
    msiexec //a "$(cygpath -w "$msi")" //qn "TARGETDIR=$(cygpath -w "$dest")"
    # The administrative install also drops a copy of the msi database itself.
    find "$dest" -maxdepth 1 -name '*.msi' -delete
    [[ -n "$(find "$dest" -type f -print -quit)" ]] || { echo "collect.sh: the msi extracted no files" >&2; exit 1; }
    echo "  desktop/msi-payload/ (payload)"
    ;;
*)
    echo "collect.sh: unknown platform '$platform'" >&2; exit 2 ;;
esac
