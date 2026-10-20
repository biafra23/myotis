#!/usr/bin/env bash
# Tests .github/release-notes.sh against a stubbed `gh` that keeps one release
# body in a temp dir: the create race, the section append and its repair of a
# section a concurrent writer dropped, and the input checks. Nothing touches
# GitHub. The script's failure modes otherwise surface only on a real tag (the
# throwaway-tag rehearsal in release-version-guard.yml skips every publishing
# job), so run this after any edit to it:
#
#   scripts/test_release_notes.sh
#
# Runs on macOS and Linux (bash, awk, sed, grep).
#
# Each check's condition is a single-quoted string that `check` evals, so the
# variables in it expand at check time, as intended (SC2016), and the
# variables they read look unused to shellcheck (SC2034).
# shellcheck disable=SC2016,SC2034
set -u
cd "$(dirname "$0")/.." || exit 1
R=.github/release-notes.sh
MASTER=.github/release-notes.md
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

# The stub. `view --json body` prints the body plus jq's trailing newline.
# $STUB_DIR/race holds the body of a concurrent writer that read before our
# edit: its write lands just before our next read, dropping our section.
# $STUB_DIR/lose_create makes `create` lose the race to another publisher.
mkdir -p "$T/stub"
cat > "$T/stub/gh" <<'STUB'
#!/usr/bin/env bash
set -eu
d=$STUB_DIR; echo "gh $*" >> "$d/log"
[ "$1" = release ] || exit 99
sub=$2; shift 3
notes=""; json=0
while [ $# -gt 0 ]; do
  case "$1" in --notes-file) notes=$2; shift 2;; --json) json=1; shift 2;; --jq) shift 2;; *) shift;; esac
done
case "$sub" in
  view)
    [ -f "$d/exists" ] || { echo "release not found" >&2; exit 1; }
    if [ $json = 1 ]; then
      if [ -f "$d/race" ] && [ -f "$d/edited" ]; then cp "$d/race" "$d/body"; rm "$d/race"; fi
      cat "$d/body"; echo
    fi ;;
  create)
    if [ -f "$d/lose_create" ]; then touch "$d/exists"; printf 'OTHER' > "$d/body"; echo "already exists" >&2; exit 1; fi
    [ ! -f "$d/exists" ] || exit 1
    cp "$notes" "$d/body"; touch "$d/exists" ;;
  edit) cp "$notes" "$d/body"; touch "$d/edited"; echo x >> "$d/edits" ;;
  *) exit 98 ;;
esac
STUB
chmod +x "$T/stub/gh"
export PATH="$T/stub:$PATH" RELEASE_NOTES_SETTLE=0 GITHUB_SHA=0000000000000000000000000000000000000000

pass=0 failed=0
check() {
  if eval "$2"; then echo "PASS $1"; pass=$((pass + 1)); else echo "FAIL $1"; failed=$((failed + 1)); fi
}
n=0
fresh() { n=$((n + 1)); export STUB_DIR="$T/case$n"; mkdir -p "$STUB_DIR"; }
# Lines of the body that START with $1 (how the script counts a section).
count() { awk -v n=0 -v l="$1" 'index($0, l) == 1 { n++ } END { print n }' "$STUB_DIR/body"; }
edits() { [ -f "$STUB_DIR/edits" ] && echo $(($(wc -l < "$STUB_DIR/edits"))) || echo 0; }
# A gh that wraps the stub: $1 is a shell snippet run first, for an `edit`.
wrap_edit() {
  mkdir -p "$STUB_DIR/bin"
  { echo '#!/usr/bin/env bash'
    echo "if [ \"\$2\" = edit ]; then $1; fi"
    echo "exec \"$T/stub/gh\" \"\$@\""; } > "$STUB_DIR/bin/gh"
  chmod +x "$STUB_DIR/bin/gh"
}

NODE='**Node.js addon (`myotis-node.<platform>-<arch>.node`)**'
IOS='**iOS (`MyotisEngine.xcframework.zip`)**'
sec="$T/node.md"; printf '%s\n' "$NODE — prebuilt binding." 'Second line.' > "$sec"
sec2="$T/ios.md"; printf '%s\n' "$IOS — the engine's C ABI." > "$sec2"

fresh
bash $R create v1 "$sec" && bash $R append v1 "$sec"
check "create writes the master notes verbatim" \
  'diff <(head -n "$(wc -l < $MASTER)" "$STUB_DIR/body") $MASTER > /dev/null'
check "create includes the section once" '[ "$(count "$NODE")" = 1 ]'
check "append makes no edit when the section is in" '[ "$(edits)" = 0 ]'

fresh
bash $R create v1 && bash $R append v1 "$sec" && bash $R append v1 "$sec"
check "append adds the section once; a re-run adds nothing" '[ "$(count "$NODE")" = 1 ] && [ "$(edits)" = 1 ]'
check "a blank line precedes the appended section" \
  'grep -B1 -F "$NODE" "$STUB_DIR/body" | head -n 1 | grep -q "^$"'

fresh; touch "$STUB_DIR/lose_create"
bash $R create v1 "$sec" 2> /dev/null; rc=$?
check "a lost create race passes" '[ $rc = 0 ] && grep -q "release create" "$STUB_DIR/log"'

fresh; mkdir -p "$STUB_DIR/bin"; printf '#!/bin/sh\nexit 1\n' > "$STUB_DIR/bin/gh"; chmod +x "$STUB_DIR/bin/gh"
PATH="$STUB_DIR/bin:$PATH" bash $R create v1 2> /dev/null; rc=$?
check "a genuine create failure fails" '[ $rc != 0 ]'

fresh; bash $R create v1
{ cat $MASTER; echo; cat "$sec2"; } > "$STUB_DIR/race"
bash $R append v1 "$sec" > /dev/null; rc=$?
check "a section a concurrent writer dropped is appended again" \
  '[ $rc = 0 ] && [ "$(count "$NODE")" = 1 ] && [ "$(edits)" = 2 ]'
check "the concurrent writer's section stays" '[ "$(count "$IOS")" = 1 ]'

fresh; bash $R create v1; wrap_edit "echo x >> '$STUB_DIR/edits'; exit 0"
PATH="$STUB_DIR/bin:$PATH" bash $R append v1 "$sec" 2> "$STUB_DIR/err"; rc=$?
check "a section that never sticks fails after six edits" \
  '[ $rc = 1 ] && grep -q "::error::" "$STUB_DIR/err" && [ "$(edits)" = 6 ]'

fresh; bash $R create v1
wrap_edit "k=\$(( \$(cat '$STUB_DIR/k' 2> /dev/null || echo 0) + 1 )); echo \$k > '$STUB_DIR/k'; [ \$k -ge 6 ] || exit 0"
PATH="$STUB_DIR/bin:$PATH" bash $R append v1 "$sec" > /dev/null; rc=$?
check "a sixth edit that sticks passes" '[ $rc = 0 ] && [ "$(count "$NODE")" = 1 ]'

fresh; bash $R create v1
quoting="$T/quoting.md"; printf '%s\n' '**Other (`x`)** — unlike' "the $NODE section, this one…" > "$quoting"
bash $R append v1 "$quoting" && bash $R append v1 "$sec" > /dev/null
check "a label quoted mid-line does not count as the section" '[ "$(count "$NODE")" = 1 ] && [ "$(edits)" = 2 ]'

fresh; touch "$STUB_DIR/exists"; printf '%s\r\n' "$(head -n 1 $MASTER)" '' "$NODE — x" > "$STUB_DIR/body"
bash $R append v1 "$sec"
check "a body with CRLF line ends (a web edit) still has the section" '[ "$(edits)" = 0 ]'

fresh
nolabel="$T/nolabel.md"; echo "plain text" > "$nolabel"
bash $R append v1 "$nolabel" 2> /dev/null; rc=$?
check "a section without a bold label is refused" '[ $rc = 1 ]'
inmaster="$T/inmaster.md"; printf '%s\n' '**Desktop Linux (`Myotis-v<version>-<arch>.deb`)** — x' > "$inmaster"
bash $R create v1 "$inmaster" 2> /dev/null; rc=$?
check "a label the master notes carry is refused" '[ $rc = 1 ] && [ ! -f "$STUB_DIR/exists" ]'
bash $R append v1 2> /dev/null; rc=$?
check "append without a section is a usage error" '[ $rc = 2 ]'
bash $R create v1 "$sec" extra 2> /dev/null; rc=$?
check "an extra argument is a usage error" '[ $rc = 2 ]'

# The sections the workflows write: each yields a label, none in the master.
for wf in ios-framework ios-xcframework node-binding engine-library; do
  awk '/cat > "\$section" <<.SECTION./ { on = 1; next } on && /^ *SECTION$/ { exit } on { sub(/^          /, ""); print }' \
    ".github/workflows/$wf.yml" > "$T/$wf.md"
  label=$(sed -n '1s/^\(\*\*[^*][^*]*\*\*\).*$/\1/p' "$T/$wf.md")
  check "$wf's section has a label the master notes do not carry" \
    '[ -n "$label" ] && ! grep -qF -- "$label" $MASTER'
done

echo "passed=$pass failed=$failed"
[ "$failed" = 0 ]
