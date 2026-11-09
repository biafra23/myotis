#!/usr/bin/env bash
# Regenerate the Gradle dependency pins (#734): the per-project lockfiles
# (gradle.lockfile, buildscript-gradle.lockfile, settings-gradle.lockfile) and
# gradle/verification-metadata.xml. docs/gradle-dependency-pins.md is the
# narrative; this is the one command it points to.
#
#   scripts/update_gradle_pins.sh                  this host: locks + hashes
#   scripts/update_gradle_pins.sh --from-ci [RUN]  take the merged metadata a
#                                                  `gradle pins` workflow run
#                                                  built on every CI host
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
# nothing resolves any more stay until a full regeneration (`--prune`: delete
# the file, regenerate here, then run step 2-3 so the other hosts re-add
# theirs).
set -euo pipefail
cd "$(dirname "$0")/.."

metadata=gradle/verification-metadata.xml

if [[ "${1:-}" == "--from-ci" ]]; then
    run="${2:-}"
    if [[ -z "$run" ]]; then
        branch=$(git rev-parse --abbrev-ref HEAD)
        run=$(gh run list --workflow gradle-pins.yml --branch "$branch" --limit 1 \
            --json databaseId --jq '.[0].databaseId')
        [[ -n "$run" ]] || { echo "no gradle-pins.yml run for branch $branch" >&2; exit 1; }
    fi
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    # The last job of the chain uploads the union of every host's entries.
    gh run download "$run" --name verification-metadata-merged --dir "$tmp"
    cp "$tmp/verification-metadata.xml" "$metadata"
    echo "updated $metadata from run $run — review the diff:"
    git --no-pager diff --stat -- "$metadata"
    exit 0
fi

if [[ "${1:-}" == "--prune" ]]; then
    rm -f "$metadata"
elif [[ -n "${1:-}" ]]; then
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//;/^set -euo/d' >&2
    exit 2
fi

# -PskipRustEngine: resolution does not need the Android Rust toolchain, and
# without it :myotis-engine refuses to configure. It changes no dependency.
args=(-PskipRustEngine --console=plain)

# Locks first, from a full walk of every configuration. --write-locks rewrites
# the lock state of each configuration it resolves, so a removed dependency
# disappears from its lockfile here.
./gradlew resolveAllDependencies --write-locks "${args[@]}"

# Then the hashes, again from the full walk (the verification file must cover
# test, lint and tooling classpaths, not just what one task needs).
# Verification is OFF during a --write-verification-metadata run, so a
# verifying run follows to prove the result is complete for this host.
./gradlew resolveAllDependencies --write-verification-metadata sha256 "${args[@]}"
./gradlew resolveAllDependencies "${args[@]}" -q

echo
echo "pins regenerated for this host. Changed:"
git --no-pager diff --stat -- '*.lockfile' "$metadata"
git status --porcelain -- '*.lockfile' | grep '^??' || true
