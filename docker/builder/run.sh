#!/usr/bin/env bash
# Run a command in the builder image, the way a build uses it (#734, Part 5b).
#
#   docker/builder/run.sh [--image TAG] [--user UID:GID] [--name NAME]
#                         [--mount DIR]... -- COMMAND...
#
# The current directory is mounted at the SAME path inside the container and is
# the working directory there, so a path the build records is the path it has
# on the host. Each --mount DIR is mounted at its own path likewise. The command
# runs as --user (default: the caller) under the user name --name (default:
# builder), with a read-only root file system: the build cannot change the
# image's tools.
#
# The caller provides three writable directories through the environment, all
# mounted and passed in: HOME, CARGO_HOME and GRADLE_USER_HOME. They must be
# writable by --user. Passed through when set: TZ, LANG, LC_ALL,
# SOURCE_DATE_EPOCH, REPRO_UMASK, GITHUB_REF, GITHUB_REF_NAME, GRADLE_OPTS.
#
# Works with bash 3.2 (macOS's /bin/bash, for a rebuild through Docker Desktop).
set -euo pipefail

image=myotis-builder:local
user="$(id -u):$(id -g)"
name=builder
mounts=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) image=$2; shift 2 ;;
        --user) user=$2; shift 2 ;;
        --name) name=$2; shift 2 ;;
        --mount) mounts+=("$2"); shift 2 ;;
        --) shift; break ;;
        *) echo "run.sh: unknown option '$1' (see the header)" >&2; exit 2 ;;
    esac
done
[[ $# -gt 0 ]] || { echo "run.sh: no command" >&2; exit 2; }
[[ "$user" =~ ^[0-9]+:[0-9]+$ ]] || { echo "run.sh: --user must be UID:GID, got '$user'" >&2; exit 2; }
[[ "$name" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "run.sh: --name must be a plain user name, got '$name'" >&2; exit 2; }
for v in HOME CARGO_HOME GRADLE_USER_HOME; do
    [[ -d "${!v:-}" ]] || { echo "run.sh: $v must name an existing directory writable by $user (got '${!v:-}')" >&2; exit 2; }
done

# State of this run, outside HOME (which may belong to --user, not the caller):
# the passwd and group entries that give the uid a NAME and a home (without
# them the JVM reports user.name and user.home as "?"), and /tmp, on disk,
# since jpackage assembles the whole .deb there.
state=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/myotis-builder.XXXXXX")
uid=${user%%:*} gid=${user##*:}
printf 'root:x:0:0:root:/root:/bin/bash\n%s:x:%s:%s::%s:/bin/bash\n' "$name" "$uid" "$gid" "$HOME" > "$state/passwd"
printf 'root:x:0:\n%s:x:%s:\n' "$name" "$gid" > "$state/group"
mkdir "$state/tmp"
chmod 644 "$state/passwd" "$state/group"
chmod 755 "$state"
chmod 1777 "$state/tmp"

args=(--rm --read-only --user "$user" -w "$PWD" -v "$PWD:$PWD"
      -v "$state/passwd:/etc/passwd:ro" -v "$state/group:/etc/group:ro" -v "$state/tmp:/tmp")
# ${mounts[@]+...}: an empty array is "unbound" to bash 3.2 under set -u.
for m in ${mounts[@]+"${mounts[@]}"} "$HOME" "$CARGO_HOME" "$GRADLE_USER_HOME"; do args+=(-v "$m:$m"); done
for v in HOME CARGO_HOME GRADLE_USER_HOME TZ LANG LC_ALL SOURCE_DATE_EPOCH REPRO_UMASK GITHUB_REF GITHUB_REF_NAME GRADLE_OPTS; do
    [[ -z "${!v+x}" ]] || args+=(-e "$v=${!v}")
done
args+=(
    -e "USER=$name" -e "LOGNAME=$name"
    # The checkout may belong to another uid than the one git runs as here.
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e "GIT_CONFIG_VALUE_0=*"
)
status=0
docker run "${args[@]}" "$image" "$@" || status=$?
# Best effort: what the container wrote under tmp/ belongs to --user.
rm -rf "$state" 2>/dev/null || true
exit "$status"
