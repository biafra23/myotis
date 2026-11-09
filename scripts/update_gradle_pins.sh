#!/usr/bin/env bash
# Regenerate the Gradle dependency pins (#734): the per-project lockfiles
# (gradle.lockfile, buildscript-gradle.lockfile, settings-gradle.lockfile) and
# gradle/verification-metadata.xml. docs/gradle-dependency-pins.md is the
# narrative; this is the one command it points to.
#
#   scripts/update_gradle_pins.sh            this host: locks + hashes
#     --quick                                only the configuration walk, not
#                                            the `assemble lint` pass after it
#     --prune                                delete the metadata first (full
#                                            regeneration; see the doc)
#   scripts/update_gradle_pins.sh --from-ci [RUN]
#                                            take the merged metadata the
#                                            `gradle pins` workflow built on
#                                            every CI host for this commit
#
# Typical update after bumping gradle/libs.versions.toml:
#   1. scripts/update_gradle_pins.sh        (locks + this host's new hashes)
#   2. commit, push, let the `gradle pins` workflow run on the PR. It fails on
#      each host that resolves an artifact the metadata does not pin yet (the
#      macOS/Windows/arm64 natives a Linux box never sees) and uploads the
#      metadata with them added.
#   3. scripts/update_gradle_pins.sh --from-ci   (needs gh), commit, push.
#   4. REVIEW THE HASH DIFF like code: every new <component> is a new artifact
#      the build will execute or ship.
#
# Additive by design: --write-verification-metadata only ADDS entries, so
# hashes another host contributed survive a local run. Entries for versions
# nothing resolves any more stay until a full regeneration (--prune, then
# steps 2-3 so the other hosts re-add theirs).
set -euo pipefail
cd "$(dirname "$0")/.."

metadata=gradle/verification-metadata.xml
usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2; exit 2; }

quick=0 prune=0 from_ci=0 run=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) quick=1 ;;
        --prune) prune=1 ;;
        --from-ci)
            from_ci=1
            if [[ $# -gt 1 && "$2" != --* ]]; then run="$2"; shift; fi
            ;;
        *) usage ;;
    esac
    shift
done
[[ "$from_ci" == 1 && ( "$quick" == 1 || "$prune" == 1 ) ]] && usage

if [[ "$from_ci" == 1 ]]; then
    if [[ -z "$run" ]]; then
        # The run for THIS commit, and only a finished one: an older run's
        # merged file lacks this commit's hashes, a running one has no upload.
        head=$(git rev-parse HEAD)
        run=$(gh run list --workflow gradle-pins.yml --commit "$head" --limit 20 \
            --json databaseId,status \
            --jq '[.[] | select(.status == "completed")][0].databaseId // empty')
        [[ -n "$run" ]] || {
            echo "no finished gradle-pins.yml run for HEAD $head — push it and wait for the chain" >&2
            exit 1
        }
    fi
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    # The last job of the chain uploads the union of every host's entries.
    gh run download "$run" --name verification-metadata-merged --dir "$tmp"
    # LF only, whatever host wrote it last, so the diff shows hashes, not
    # line endings.
    tr -d '\r' < "$tmp/verification-metadata.xml" > "$metadata"
    echo "updated $metadata from run $run — review the diff:"
    git --no-pager diff --stat -- "$metadata"
    exit 0
fi

[[ "$prune" == 1 ]] && rm -f "$metadata"

# -PskipRustEngine: resolution does not need the Android Rust toolchain, and
# without it :myotis-engine refuses to configure. It changes no dependency.
args=(-PskipRustEngine --console=plain)

# Locks first, from the full walk. `lenient` because a bumped dependency is
# not hash-pinned yet: strict verification would fail this step before the
# hashes are written (lenient only warns, and only for this run).
# --write-locks rewrites the lock state of every configuration it resolves, so
# a removed dependency leaves its lockfile here.
./gradlew resolveAllDependencies --write-locks --dependency-verification lenient "${args[@]}"

# Then the hashes, with the NEW locks in force — a separate run on purpose:
# without lock constraints, conflict resolution also fetches the metadata of
# every candidate version it then discards, and those would all be pinned. The
# walk covers every configuration; `assemble lint` follows (unless --quick)
# because AGP resolves some tools through DETACHED configurations only while a
# task runs, which no walk can see — aapt2 and the lint override
# (gradle.properties' android.experimental.lint.version) are the known ones.
# No test task runs.
tasks=(resolveAllDependencies)
[[ "$quick" == 1 ]] || tasks+=(assemble lint)
./gradlew "${tasks[@]}" --write-verification-metadata sha256 "${args[@]}"

# Then a VERIFYING walk with both pins in force: proves the result is complete
# for this host (every configuration resolves, matches its lock and has a hash).
./gradlew resolveAllDependencies "${args[@]}" -q

echo
echo "pins regenerated for this host. Changed:"
git --no-pager diff --stat -- '*.lockfile' "$metadata"
git status --porcelain -- '*.lockfile' | grep '^??' || true
