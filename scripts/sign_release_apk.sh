#!/usr/bin/env bash
# Sign the UNSIGNED release APK with the Myotis release key, then prove what was signed.
#
# Usage: scripts/sign_release_apk.sh <unsigned.apk> <out.apk>
#
# Run by the tag-only `sign-release` job in .github/workflows/android-apk.yml, the
# one place the release key exists: its secrets live in the `android-release`
# environment, which only v* tags may use, and that job checks out nothing but
# this script and the pinned certificate, so no Gradle, plugin or cargo code ever
# runs next to the key. Setup, rotation and what to do on loss:
# docs/android-release-signing.md.
#
# Inputs, all from the environment (the job maps the secrets of the same names):
#   ANDROID_RELEASE_KEYSTORE_BASE64    the keystore file (PKCS12 or JKS), base64
#   ANDROID_RELEASE_KEYSTORE_PASSWORD  its store password
#   ANDROID_RELEASE_KEY_ALIAS          the key's alias in it
#   ANDROID_RELEASE_KEY_PASSWORD       optional: the key's own password. A PKCS12
#                                      keystore has only one, so it defaults to the
#                                      store password.
#   ANDROID_BUILD_TOOLS                optional: the build-tools dir with apksigner +
#                                      zipalign; default the newest STABLE one under
#                                      $ANDROID_HOME (35.0.0+: --alignment-preserved).
#
# Refuses (non-zero, nothing written) when: a secret is missing; the pinned
# certificate (android-app/release-signing-cert.sha256) is missing, malformed or
# the public DEBUG certificate; the input already carries a signature (the Gradle
# release build type must not sign — see android-app/build.gradle.kts) or is
# debuggable (release-signed, that would hand its data to anyone with adb, via
# run-as); or the signed result has any signer other than exactly the pinned
# certificate. That last check is what catches a wrong keystore in the secrets.
set -euo pipefail

die() { echo "::error::$*" >&2; exit 1; }

[ "$#" -eq 2 ] || die "usage: $0 <unsigned.apk> <out.apk>"
in=$1 out=$2
[ -f "$in" ] || die "no such APK: $in"
[ ! -e "$out" ] || die "refusing to overwrite $out"

root=$(cd "$(dirname "$0")/.." && pwd)
pin_file="$root/android-app/release-signing-cert.sha256"

# SHA-256 of android-app/debug.keystore's certificate, which anyone can download:
#   keytool -list -v -keystore android-app/debug.keystore -storepass android -alias androiddebugkey
debug_cert=760390cd58e698e9fdad45a053ec109e117f952ed355f2eab5b1ad0d5900e995

# --- the pinned release certificate --------------------------------------------
[ -f "$pin_file" ] \
  || die "no pinned release certificate: commit its SHA-256 as android-app/release-signing-cert.sha256 (docs/android-release-signing.md)"
# First line that is not a comment; keytool prints AB:CD:…, apksigner abcd…: accept both.
pin=$(grep -v '^[[:space:]]*#' "$pin_file" | grep -m1 '[^[:space:]]' | tr -d ': \t\r' | tr 'A-F' 'a-f' || true)
[[ "$pin" =~ ^[0-9a-f]{64}$ ]] \
  || die "android-app/release-signing-cert.sha256 holds no SHA-256 fingerprint (64 hex digits, colons allowed)"
[ "$pin" != "$debug_cert" ] \
  || die "the pinned release certificate is the PUBLIC debug certificate — that is the key this job exists to replace"

# --- the secrets -----------------------------------------------------------------
for v in ANDROID_RELEASE_KEYSTORE_BASE64 ANDROID_RELEASE_KEYSTORE_PASSWORD ANDROID_RELEASE_KEY_ALIAS; do
  [ -n "${!v:-}" ] \
    || die "$v is not set — add it to the android-release environment's secrets (docs/android-release-signing.md)"
done
# apksigner reads the passwords from the environment (env:NAME), never from argv,
# where any process on the runner could list them.
export ANDROID_RELEASE_KEY_PASSWORD="${ANDROID_RELEASE_KEY_PASSWORD:-$ANDROID_RELEASE_KEYSTORE_PASSWORD}"

# --- the tools -------------------------------------------------------------------
if [ -z "${ANDROID_BUILD_TOOLS:-}" ]; then
  [ -n "${ANDROID_HOME:-}" ] || die "neither ANDROID_BUILD_TOOLS nor ANDROID_HOME is set"
  # Numbered stable releases only: an SDK may also hold rc builds and a `current`
  # symlink (one dev Mac's points at 31.0.0), and `sort -V` ranks those last.
  ANDROID_BUILD_TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/*/ 2>/dev/null \
    | grep -E '/[0-9]+\.[0-9]+\.[0-9]+/$' | sort -V | tail -n1 || true)
fi
bt=${ANDROID_BUILD_TOOLS%/}
apksigner="$bt/apksigner" zipalign="$bt/zipalign" aapt2="$bt/aapt2"
[ -x "$apksigner" ] && [ -x "$zipalign" ] && [ -x "$aapt2" ] \
  || die "no apksigner + zipalign + aapt2 in ${bt:-<none>}"
# apksigner --version prints 0.9 in every release, so name the build-tools dir.
echo "apksigner: $apksigner"

# --- the input must be unsigned --------------------------------------------------
# A signature already on it means the Gradle release build type signed it (with
# what key?), and re-signing would hide that.
if "$apksigner" verify "$in" >/dev/null 2>&1; then
  die "$in is already signed — the release build type must stay unsigned (android-app/build.gradle.kts)"
fi
badging=$("$aapt2" dump badging "$in") || die "aapt2 cannot read $in"
! grep -q '^application-debuggable' <<< "$badging" \
  || die "$in is debuggable — never sign a debuggable build with the release key"

# --- sign --------------------------------------------------------------------------
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/myotis-sign.XXXXXX")
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
ks="$work/release.keystore"
( umask 077; printf '%s' "$ANDROID_RELEASE_KEYSTORE_BASE64" | base64 -d > "$ks" ) \
  || die "ANDROID_RELEASE_KEYSTORE_BASE64 is not valid base64"
[ -s "$ks" ] || die "ANDROID_RELEASE_KEYSTORE_BASE64 decodes to an empty file"

# --alignment-preserved: AGP already aligned the entries (4-byte, and the
# uncompressed .so files to the page size); the APK Signing Block goes in front of
# the central directory without moving them, and apksigner must not re-decide that.
# No v4 (.idsig sidecar): sideloaded installs don't use it. The other schemes
# follow minSdk 29: apksigner signs v3 alone, which every API 28+ device checks.
"$apksigner" sign \
  --ks "$ks" \
  --ks-key-alias "$ANDROID_RELEASE_KEY_ALIAS" \
  --ks-pass env:ANDROID_RELEASE_KEYSTORE_PASSWORD \
  --key-pass env:ANDROID_RELEASE_KEY_PASSWORD \
  --alignment-preserved true \
  --v4-signing-enabled false \
  --out "$out" \
  "$in" \
  || { rm -f "$out"; die "apksigner could not sign — its own error is above (password, alias, or build-tools older than 35.0.0 without --alignment-preserved)"; }

# Signing must not degrade the alignment AGP produced: 16 KB-page-aligned native
# libraries (what 16 KB-page devices need to load them in place) stay that way.
if "$zipalign" -c -P 16 4 "$in" >/dev/null 2>&1; then
  "$zipalign" -c -P 16 4 "$out" >/dev/null 2>&1 \
    || { rm -f "$out"; die "signing broke the 16 KB page alignment of the native libraries"; }
else
  "$zipalign" -c 4 "$out" >/dev/null 2>&1 \
    || { rm -f "$out"; die "the signed APK is not 4-byte aligned"; }
fi

# --- prove it ------------------------------------------------------------------------
report=$("$apksigner" verify --verbose --print-certs "$out") \
  || { rm -f "$out"; die "the signed APK does not verify"; }
# EVERY signer line, not just `Signer #N`: v3.1 and rotation-lineage signers print
# as `Signer (minSdkVersion=…, maxSdkVersion=…) certificate SHA-256 digest: …`.
signers=$(sed -n 's/^Signer.* certificate SHA-256 digest: *\([0-9a-f]*\)$/\1/p' <<< "$report" | sort -u)
if [ "$signers" != "$pin" ]; then
  rm -f "$out"
  die "signed with [$(tr '\n' ' ' <<< "$signers")] but the pinned release certificate is $pin — wrong keystore in the secrets, or a stale pin"
fi
grep -Eq '^Verified using v(2|3) scheme .*: true$' <<< "$report" \
  || { rm -f "$out"; die "no v2 or v3 signature on the result"; }
grep -E '^(Verified using|Signer.* certificate (DN|SHA-256))' <<< "$report" || true  # log only
echo "signed: $out"
