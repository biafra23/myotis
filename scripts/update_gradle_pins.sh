#!/usr/bin/env bash
# Regenerate the Gradle dependency pins (#734): the per-project lockfiles
# (gradle.lockfile, buildscript-gradle.lockfile, settings-gradle.lockfile) and
# gradle/verification-metadata.xml. docs/guides/gradle-dependency-pins.md is the
# narrative; this is the one command it points to.
#
#   scripts/update_gradle_pins.sh            this host: locks + hashes
#     --quick                                only the configuration walk, not
#                                            the task pass after it
#     --prune                                delete the metadata first (full
#                                            regeneration; see the doc)
#   scripts/update_gradle_pins.sh --from-ci [RUN]
#                                            take the merged metadata the
#                                            `gradle pins` workflow built on
#                                            every CI host for this commit
#     --allow-repin                          accept a change to a hash that is
#                                            ALREADY pinned (see below)
#
# Existing pins only grow. After either mode, the result is compared with the
# metadata committed at HEAD (scripts/check_pins_additive.py): new entries
# pass, and a changed or widened hash of an artifact that was already pinned
# (Gradle records changed bytes as an <also-trust> alternative), a removed
# entry or a changed <configuration> block stops the script, naming each one.
# Bytes that changed under a pinned version are what pinning exists to catch:
# find out why before passing --allow-repin. --prune skips this comparison
# (it removes entries by design) and loses the hand-written <configuration>
# block too (trusted artifacts): restore it from HEAD before committing.
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

quick=0 prune=0 from_ci=0 run="" allow_repin=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick) quick=1 ;;
        --prune) prune=1 ;;
        --allow-repin) allow_repin=1 ;;
        --from-ci)
            from_ci=1
            if [[ $# -gt 1 && "$2" != --* ]]; then run="$2"; shift; fi
            ;;
        *) usage ;;
    esac
    shift
done
[[ "$from_ci" == 1 && ( "$quick" == 1 || "$prune" == 1 ) ]] && usage

# The pins as committed, for the comparison at the end of either mode.
committed=$(mktemp)
trap 'rm -f "$committed"' EXIT
git show "HEAD:$metadata" > "$committed" 2>/dev/null || : > "$committed"
existing_pins_unchanged() {
    [[ "$prune" == 0 && -s "$committed" ]] || return 0
    if ! python3 -I scripts/check_pins_additive.py "$committed" "$metadata"; then
        if [[ "$allow_repin" == 1 ]]; then
            echo "update_gradle_pins.sh: --allow-repin: keeping the changed pins above. Review them like code." >&2
            return 0
        fi
        echo "update_gradle_pins.sh: the result changes pins that were already committed (above)." >&2
        echo "            New pins only add entries. Bytes that changed under a pinned version are what" >&2
        echo "            pinning catches: find out why, and only then re-run with --allow-repin." >&2
        echo "            The file is left as written, for inspection: git diff -- $metadata" >&2
        exit 1
    fi
}

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
    existing_pins_unchanged
    echo "updated $metadata from run $run — review the diff:"
    git --no-pager diff --stat -- "$metadata"
    exit 0
fi

if [[ "$prune" == 1 ]]; then
    rm -f "$metadata"
    echo "update_gradle_pins.sh: --prune: every entry is regenerated, and the <configuration> block" >&2
    echo "            (trusted artifacts) is Gradle's default afterwards: restore it from HEAD." >&2
fi

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
# walk covers every configuration; `assemble lint :app-desktop:checkRuntime`
# follows (unless --quick) because plugins resolve some tools through DETACHED
# configurations only while a task runs, which no walk can see — AGP's aapt2
# and the lint override (gradle.properties' android.experimental.lint.version),
# and Compose's JDK version probe (checkRuntime, on every desktop package
# build), are the known ones.
# No test task runs.
# --refresh-dependencies: Gradle reads a parent POM or an imported BOM only
# while it first PARSES a module's POM, then caches the parsed result, so on a
# warm cache (this host's, or the one the lock run above just warmed) those
# files are never accessed and never recorded — and a fresh checkout then
# fails on them. Refreshing re-fetches and re-parses the metadata, so every
# file a cold resolution touches is recorded.
tasks=(resolveAllDependencies)
[[ "$quick" == 1 ]] || tasks+=(assemble lint :app-desktop:checkRuntime)
./gradlew "${tasks[@]}" --write-verification-metadata sha256 --refresh-dependencies "${args[@]}"

existing_pins_unchanged

# Then a VERIFYING walk with both pins in force: proves the result is complete
# for this host (every configuration resolves, matches its lock and has a hash).
./gradlew resolveAllDependencies "${args[@]}" -q

echo
echo "pins regenerated for this host. Changed:"
git --no-pager diff --stat -- '*.lockfile' "$metadata"
git status --porcelain -- '*.lockfile' | grep '^??' || true
