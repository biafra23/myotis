#!/usr/bin/env bash
# Run a command in the builder image, the way a build uses it (#734, Part 5b).
#
#   docker/builder/run.sh [OPTIONS] -- COMMAND...
#
#   --image TAG          default: myotis-builder:local
#   --user UID:GID       default: the caller
#   --name NAME          the user name the uid gets inside (default: builder)
#   --state DIR          where the build's own directories live when not given
#                        below (default: ~/.cache/myotis-builder)
#   --home DIR           the build's HOME            (default: STATE/home)
#   --cargo-home DIR     the build's CARGO_HOME      (default: STATE/cargo)
#   --gradle-home DIR    the build's GRADLE_USER_HOME (default: STATE/gradle)
#   --mount DIR          also mount DIR at its own path (repeatable)
#   --env NAME=VALUE     also set NAME in the build (repeatable)
#
# The current directory is mounted at the SAME path inside the container and is
# the working directory there, so a path the build records is the path it has
# on the host. The command runs as --user under --name, with a read-only root
# file system: the build cannot change the image's tools.
#
# NOTHING of the caller's environment reaches the build by default. Not HOME,
# CARGO_HOME or GRADLE_USER_HOME: a ~/.cargo/config.toml, a
# ~/.gradle/gradle.properties or an init script would change what is built, and
# the caller's home would be writable by every dependency's build script. The
# three are the build's own, fresh directories unless given explicitly. Not TZ
# or the locale either: the build runs in UTC and C.UTF-8 unless --env says
# otherwise. Only SOURCE_DATE_EPOCH is passed through when set, as its
# convention has it.
#
# Works with bash 3.2 (macOS's /bin/bash, for a rebuild through Docker Desktop).
set -euo pipefail

image=myotis-builder:local
user="$(id -u):$(id -g)"
name=builder
state="${XDG_CACHE_HOME:-$HOME/.cache}/myotis-builder"
home="" cargo_home="" gradle_home=""
mounts=() envs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) image=$2; shift 2 ;;
        --user) user=$2; shift 2 ;;
        --name) name=$2; shift 2 ;;
        --state) state=$2; shift 2 ;;
        --home) home=$2; shift 2 ;;
        --cargo-home) cargo_home=$2; shift 2 ;;
        --gradle-home) gradle_home=$2; shift 2 ;;
        --mount) mounts+=("$2"); shift 2 ;;
        --env) envs+=("$2"); shift 2 ;;
        --) shift; break ;;
        *) echo "run.sh: unknown option '$1' (see the header)" >&2; exit 2 ;;
    esac
done
[[ $# -gt 0 ]] || { echo "run.sh: no command" >&2; exit 2; }
[[ "$user" =~ ^[0-9]+:[0-9]+$ ]] || { echo "run.sh: --user must be UID:GID, got '$user'" >&2; exit 2; }
[[ "$name" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "run.sh: --name must be a plain user name, got '$name'" >&2; exit 2; }
for e in ${envs[@]+"${envs[@]}"}; do
    [[ "$e" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || { echo "run.sh: --env takes NAME=VALUE, got '$e'" >&2; exit 2; }
done

: "${home:=$state/home}" "${cargo_home:=$state/cargo}" "${gradle_home:=$state/gradle}"
for d in "$home" "$cargo_home" "$gradle_home"; do
    # Created here only when missing: a directory that exists is the caller's
    # to have made writable by --user (CI chowns leg b's to its uid).
    [[ -d "$d" ]] || mkdir -p "$d"
done

# State of this run: the passwd and group entries that give the uid a NAME and
# a home (without them the JVM reports user.name and user.home as "?"), and
# /tmp, on disk, since jpackage assembles the whole .deb there.
run=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/myotis-builder.XXXXXX")
uid=${user%%:*} gid=${user##*:}
printf 'root:x:0:0:root:/root:/bin/bash\n%s:x:%s:%s::%s:/bin/bash\n' "$name" "$uid" "$gid" "$home" > "$run/passwd"
printf 'root:x:0:\n%s:x:%s:\n' "$name" "$gid" > "$run/group"
mkdir "$run/tmp"
chmod 644 "$run/passwd" "$run/group"
chmod 755 "$run"
chmod 1777 "$run/tmp"

args=(--rm --read-only --user "$user" -w "$PWD" -v "$PWD:$PWD"
      -v "$run/passwd:/etc/passwd:ro" -v "$run/group:/etc/group:ro" -v "$run/tmp:/tmp")
# ${mounts[@]+...}: an empty array is "unbound" to bash 3.2 under set -u.
for m in ${mounts[@]+"${mounts[@]}"} "$home" "$cargo_home" "$gradle_home"; do args+=(-v "$m:$m"); done
args+=(
    -e "HOME=$home" -e "CARGO_HOME=$cargo_home" -e "GRADLE_USER_HOME=$gradle_home"
    -e "USER=$name" -e "LOGNAME=$name"
    -e TZ=UTC -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8
    # The checkout may belong to another uid than the one git runs as here.
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e "GIT_CONFIG_VALUE_0=*"
)
[[ -z "${SOURCE_DATE_EPOCH+x}" ]] || args+=(-e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH")
# After the defaults, so --env TZ=... overrides them.
for e in ${envs[@]+"${envs[@]}"}; do args+=(-e "$e"); done

status=0
docker run "${args[@]}" "$image" "$@" || status=$?
# Best effort: what the container wrote under tmp/ belongs to --user.
rm -rf "$run" 2>/dev/null || true
exit "$status"
