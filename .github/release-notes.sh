#!/usr/bin/env bash
# The notes of a `v*` tag's GitHub release, written through this script by
# every workflow that publishes assets to it (the list is in
# release-version-guard.yml's header) except ci.yml, whose jars go up with
# softprops/action-gh-release and its generated "What's Changed". There is no
# cross-workflow ordering, so whichever publisher runs first creates the
# release and the others add to it:
#
#   release-notes.sh create <tag> [<section.md>]
#       Create the release with the master notes (release-notes.md, next to this
#       script) plus this workflow's own section, unless it exists already.
#   release-notes.sh append <tag> <section.md>
#       Make sure the release notes carry <section.md> exactly once.
#
# Call `create` before uploading assets and `append` after: a notes failure
# then leaves the assets published and the job red, and a re-run repairs it
# (both commands are idempotent). A workflow whose assets the master notes
# already document (APK, dmg, deb, the PoC dmgs) passes no section and needs no
# `append`.
#
# A section starts with its bold label, `**Name (`asset`)** — …`; that label is
# how `append` recognises it in the body (at the START of a line, so another
# section quoting it mid-sentence does not count), so keep it stable once
# released, and never let the master notes carry another section's label, nor
# start a line with it. Workflows write their section with a quoted heredoc so
# the markdown stays literal. scripts/test_release_notes.sh tests this script
# against a stubbed `gh`.
#
# Why `append` loops: GitHub cannot append to a release body. Every edit sends
# the whole body (read, modify, write), so two publishers editing within the
# same moment can drop each other's section: the later write carries a body
# read before the earlier one landed. `append` therefore re-reads the body
# SETTLE seconds after its own edit and appends again when its section went
# missing. That repairs a lost write as long as the other writer's
# read-to-write window is shorter than SETTLE (milliseconds for `gh`; the
# window GitHub's web editor holds open is minutes, so edit the notes by hand
# only after every publishing job has finished). The other writer's section is
# its own to re-check, which it does the same way.
#
# Env: GH_TOKEN; GH_REPO outside a full checkout; GITHUB_SHA, the commit a new
# tag's release targets (ignored when the tag exists). RELEASE_NOTES_SETTLE
# overrides the 10 s settle time (for tests).
set -euo pipefail

usage() { echo "usage: $0 create <tag> [<section.md>] | append <tag> <section.md>" >&2; exit 2; }
fail() { echo "::error::release-notes.sh: $*" >&2; exit 1; }

[ $# -ge 2 ] || usage
cmd=$1 tag=$2 section=${3:-}
master="$(cd "$(dirname "$0")" && pwd)/release-notes.md"
[ -s "$master" ] || fail "missing master notes $master"

if [ -n "$section" ]; then
  [ -s "$section" ] || fail "missing or empty section file '$section'"
  # The section's bold label: the leading `**…**` of its first line.
  label=$(sed -n '1s/^\(\*\*[^*][^*]*\*\*\).*$/\1/p' "$section")
  [ -n "$label" ] || fail "section '$section' must start with a bold label, **Name (\`asset\`)**"
  # Present in the master notes, the label would read as "appended" on every
  # release this workflow does not create, and the section would never land.
  ! grep -qF -- "$label" "$master" || fail "the master notes already carry the label $label"
fi

# Whether a line of the notes in $1 starts with the section's label.
# (Through ENVIRON: `awk -v` would expand backslash escapes in the label.)
has_section() {
  LABEL="$label" awk 'index($0, ENVIRON["LABEL"]) == 1 { found = 1 } END { exit !found }' "$1"
}

case "$cmd" in
  create)
    [ $# -le 3 ] || usage
    notes=$(mktemp)
    cat "$master" > "$notes"
    if [ -n "$section" ]; then
      printf '\n' >> "$notes"
      cat "$section" >> "$notes"
    fi
    # Another publisher may win this race for the same tag: if `create` fails,
    # re-check with `view` — success there means the other job already created
    # it (fine), while a genuine failure still surfaces because `view` also
    # fails.
    if ! gh release view "$tag" >/dev/null 2>&1; then
      gh release create "$tag" \
        --prerelease \
        --title "Myotis $tag" \
        --notes-file "$notes" \
        --target "${GITHUB_SHA:?GITHUB_SHA must name the commit to release}" \
      || gh release view "$tag" >/dev/null 2>&1
    fi
    ;;
  append)
    if [ $# -ne 3 ] || [ -z "$section" ]; then usage; fi
    settle=${RELEASE_NOTES_SETTLE:-10}
    body=$(mktemp)
    # Each pass reads the body; the section counts as in only on a read that
    # comes at least `settle` after our own last edit (or with no edit at all).
    for attempt in 1 2 3 4 5 6; do
      gh release view "$tag" --json body --jq .body > "$body"
      if has_section "$body"; then
        [ "$attempt" -eq 1 ] || echo "release-notes.sh: $label is in the notes of $tag after $((attempt - 1)) edit(s)"
        exit 0
      fi
      printf '\n' >> "$body"
      cat "$section" >> "$body"
      gh release edit "$tag" --notes-file "$body"
      sleep "$settle"
    done
    # The last edit may have stuck: one more read before calling it a failure.
    gh release view "$tag" --json body --jq .body > "$body"
    if has_section "$body"; then
      echo "release-notes.sh: $label is in the notes of $tag after 6 edits"
      exit 0
    fi
    fail "$label kept disappearing from the notes of $tag (another writer editing in a loop?); re-run this job once the other publishers are done"
    ;;
  *) usage ;;
esac
