#!/usr/bin/env bash
# Set up one leg of reproducible-builds.yml (#734, Part 5a).
#
#   scripts/repro/setup_leg.sh a|b
#
# Run in the job's checkout ($GITHUB_WORKSPACE) after the toolchains are
# installed. Leg a builds there as it is. Leg b differs in everything a
# reproducible build must not depend on: it builds in a git worktree of the
# same commit at another, deeper path, with an empty CARGO_HOME and
# GRADLE_USER_HOME of its own, another time zone (+05:45, so a local-time stamp
# cannot hide behind a whole-hour offset), another locale and another umask.
# The worktree keeps the history and tags (:ui derives the version from the
# nearest v* tag) and leaves no copy step that could itself normalize mtimes.
#
# Writes the variables to $GITHUB_ENV and the build directory to the step
# output `src`. On Windows the path stays short (MAX_PATH; Gradle and cargo
# nest deep under it) and the time zone is the system's (tzutil), since the
# JVM there ignores TZ.
set -euo pipefail

leg=${1:?usage: setup_leg.sh a|b}
: "${GITHUB_ENV:?not in a GitHub Actions job}" "${GITHUB_OUTPUT:?}" "${RUNNER_TEMP:?}" "${GITHUB_SHA:?}"
windows=false
command -v cygpath >/dev/null 2>&1 && windows=true
tmp=$RUNNER_TEMP
$windows && tmp=$(cygpath -m "$RUNNER_TEMP")

case "$leg" in
a)
    src=$(pwd)
    $windows && src=$(cygpath -m "$src")
    tz=UTC lang=C.UTF-8 mask=022
    ;;
b)
    if $windows; then
        src="$tmp/rb/x/myotis"
    else
        src="$tmp/leg-b/a/much/deeper/build/path/myotis"
    fi
    git worktree add --quiet --detach "$src" "$GITHUB_SHA"
    mkdir -p "$tmp/cargo-home-b" "$tmp/gradle-home-b"
    {
        echo "CARGO_HOME=$tmp/cargo-home-b"
        echo "GRADLE_USER_HOME=$tmp/gradle-home-b"
    } >> "$GITHUB_ENV"
    tz=Asia/Kathmandu lang=en_US.UTF-8 mask=002
    if $windows; then
        tzutil //s "Nepal Standard Time"
        echo "system time zone: $(tzutil //g)"
    fi
    ;;
*)
    echo "setup_leg.sh: leg must be a or b, got '$leg'" >&2; exit 2 ;;
esac

{
    echo "TZ=$tz"
    echo "LANG=$lang"
    echo "LC_ALL=$lang"
    echo "REPRO_UMASK=$mask"
} >> "$GITHUB_ENV"
echo "src=$src" >> "$GITHUB_OUTPUT"
echo "leg $leg: building in $src (TZ=$tz, LANG=$lang, umask $mask${CARGO_HOME:+, CARGO_HOME from the job})"
