#!/usr/bin/env bash
# Run a command in the builder image, the way a build uses it (#734, Part 5b).
#
#   docker/builder/run.sh [--image TAG] [--user UID:GID] [--mount DIR]... -- COMMAND...
#
# The current directory is mounted at the SAME path inside the container and is
# the working directory there, so a path the build records is the path it has
# on the host. Each --mount DIR is mounted at its own path likewise. The command runs as
# --user (default: the caller), with a read-only root file system: the image's
# tools cannot be changed by the build.
#
# The caller provides writable directories through the environment, all passed
# in: HOME (also given to the JVM as user.home, since a uid without a passwd
# entry has none), CARGO_HOME and GRADLE_USER_HOME. Passed through when set:
# TZ, LANG, LC_ALL, SOURCE_DATE_EPOCH, REPRO_UMASK, GITHUB_REF, GITHUB_REF_NAME,
# GRADLE_OPTS.
set -euo pipefail

image=myotis-builder:local
user="$(id -u):$(id -g)"
mounts=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) image=$2; shift 2 ;;
        --user) user=$2; shift 2 ;;
        --mount) mounts+=("$2"); shift 2 ;;
        --) shift; break ;;
        *) echo "run.sh: unknown option '$1' (see the header)" >&2; exit 2 ;;
    esac
done
[[ $# -gt 0 ]] || { echo "run.sh: no command" >&2; exit 2; }
for v in HOME CARGO_HOME GRADLE_USER_HOME; do
    [[ -d "${!v:-}" ]] || { echo "run.sh: $v must name an existing, writable directory (got '${!v:-}')" >&2; exit 2; }
done

# /tmp on disk, under HOME: jpackage assembles the whole .deb there, which a
# RAM-backed tmpfs is the wrong place for.
mkdir -p "$HOME/tmp"
args=(--rm --read-only -v "$HOME/tmp:/tmp" --user "$user" -w "$PWD" -v "$PWD:$PWD")
for m in "${mounts[@]}" "$HOME" "$CARGO_HOME" "$GRADLE_USER_HOME"; do args+=(-v "$m:$m"); done
for v in HOME CARGO_HOME GRADLE_USER_HOME TZ LANG LC_ALL SOURCE_DATE_EPOCH REPRO_UMASK GITHUB_REF GITHUB_REF_NAME GRADLE_OPTS; do
    [[ -z "${!v+x}" ]] || args+=(-e "$v=${!v}")
done
args+=(
    # A uid with no passwd entry: the JVM would report user.home as "?".
    -e "JAVA_TOOL_OPTIONS=-Duser.home=$HOME"
    -e "ANDROID_USER_HOME=$HOME/.android"
    # The checkout belongs to another uid than the one git runs as here.
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e "GIT_CONFIG_VALUE_0=*"
)
exec docker run "${args[@]}" "$image" "$@"
