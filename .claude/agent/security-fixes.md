# Fixing a privately reported vulnerability

> Read in full before you start work on a security issue that is not public
> yet: a report received through `SECURITY.md` (a private advisory), or one
> the owner hands you in private. The owner's request, 2026-11-15, on #870.

`SECURITY.md` promises a reporter that the discussion stays in the private
advisory and that the advisory is published once a fixed release is out.
The standing Workflow points the other way: every work item gets a public PR,
and PRs are the project's public record. This procedure replaces steps 3 to 5
of the Workflow for an embargoed fix and nothing else. Every other rule in
`CLAUDE.md` still applies, the hard rules first.

## When it applies

- A vulnerability that is not public yet, in this repository's code or in how
  it uses a dependency.
- The owner decides whether a report is embargoed. A report that turns out not
  to be a vulnerability, or one that is already public (a published CVE in a
  dependency, an issue someone opened), takes the normal Workflow. Ask when
  unsure; never assume "not embargoed".

## Two periods: before the merge, and until the advisory is published

**Until the owner has merged the fix, nothing leaves the machine** but the
patch and report sent to the owner (step 5).

- **No push to any branch of this repository.** The session's designated
  branch is public too: a pushed commit is a disclosure, whatever its message
  says. This overrides the harness's "commit and push when done".
- No PR, issue, discussion, comment or review reply about it, on GitHub or
  anywhere else.
- Nothing goes to an external service: no gist, no paste site, no issue
  tracker of a dependency. Reporting a dependency's bug upstream is the
  owner's call, through that project's private channel.

**From the merge until the advisory is published, only the wording is held
back.** The code is public from the merge on, so pushes and PRs are normal
again (steps 7 to 9 need them), but every one of them stays neutral:

- A branch name, commit message, code comment, PR, changelog entry or
  release note says what changed ("validate X before Y"). It never says that it
  was a vulnerability, how it is exploited, what it exposes or who reported
  it.
- The release PR and its changelog follow `.claude/agent/releases.md` as
  usual, in that neutral wording.

## Steps

1. **Check that the build runs here, before you code.** Run `./gradlew help`
   (and `cargo --version` for Rust work). If the session cannot build (no
   toolchain, a proxy that blocks a repository), say so to the owner at once:
   the fix is then built and tested where it can be (a local session, the
   owner's machine) before the patch goes into the private fork.
2. **Code** the fix on a local branch off the current `main`. Do not push it.
3. **Run what CI would run, locally.** GitHub runs no CI and no status
   checks in an advisory's temporary private fork, and no integration (the
   CI reviewer among them) can reach it. A PR into `main` is checked by more
   than `ci.yml`, so run each check that applies to what the fix touches:
   - `./gradlew build` (or with `-PskipRustEngine`, saying so), and
     `./gradlew cargoTest` for Rust changes, with the clippy and no_std
     checks of `rust-clippy.yml` and `no-std-canary.yml`.
   - A test that fails without the fix and passes with it.
   - `android-apk.yml`: the minSdk 29 gate, which runs nowhere else. Build
     the APKs and run `python3 scripts/check_apk_min_api.py --apk <apk>` on
     each.
   - A fix that adds or bumps a dependency: `scripts/update_gradle_pins.sh`
     pins this host only. The other build hosts' pins come from the `gradle
     pins` run on a PR, which an embargoed fix does not get. Name those hosts
     as not pinned. A Cargo change also needs `cargo-locks.yml`'s check.
   - **Reproducibility.** If the fix can change what a release build
     produces (`.claude/agent/reproducibility.md`), the rule "no merge into
     `main` may break reproducibility" still binds the advisory merge. The
     workflow cannot run before it, so build the Linux artifacts twice in the
     builder image (`docker/builder/run.sh -- scripts/repro/build_linux.sh`,
     from two checkouts at different paths) and compare them with
     `scripts/repro/compare.py`. The macOS and Windows legs cannot run in
     private: name them as not run. Merging without them is the owner's
     decision, made before the merge, never assumed.
   - What needs macOS or Windows (the iOS framework, the dmg, the msi): name
     it as not run unless the session is on one.
4. **Review** the diff with `/code-review`, locally (never `--comment`), and
   address its findings.
5. **Hand it to the owner.** Write the patch to an ignored path, never the
   checkout's root, where a later `git add -A` would publish it:
   `git format-patch -o build/security-fix origin/main`. Write a short report
   beside it. It opens with **"not built"** if step 1 found no build. Then:
   the commit of `main` the patch is based on (the one the checks ran on; if
   `main` has moved, they no longer cover what is merged), what the fix does,
   every check of step 3 as passed, failed, or not run with the reason, and
   what step 7 will have to do. In a cloud session the container is not the
   owner's machine: send both with the host's file tool (`SendUserFile`, or
   what the host offers), never through GitHub. The owner applies the patch
   in the advisory's temporary private fork, where the reporter and other
   collaborators the owner adds can review it.
6. **The owner merges** the fork's PR into `main` from the advisory. That
   merge is the owner's action, as every merge is. Never merge, and never
   enable auto-merge.
7. **After the merge, before the release.** The fix is public from the merge
   on. The owner, or a session the owner asks, checks every workflow run on
   the merge commit, not `CI` alone (`android-apk.yml`, `gradle-pins.yml`,
   the desktop and iOS builds among them), and, where the fix can change
   release output, dispatches `reproducible builds` on `main` and sees all
   three platforms green. A red run is fixed at once by a normal PR into
   `main`, in the neutral wording above. No `v*` tag goes on a commit whose
   runs are red.
8. **Release.** The release follows `.claude/agent/releases.md` as usual, in
   the neutral wording above. The tag is the owner's action.
9. **Publish.** Publishing the advisory, and requesting a CVE for it, are the
   owner's actions, after the fixed release is out. The release notes may
   then link the advisory; editing them is the owner's call.

## Why it is shaped this way

- The advisory's temporary private fork is the one private place GitHub
  offers for the fix, and nothing automated runs there. The local checks of
  step 3 and the post-merge checks of step 7 stand in for CI and keep the
  release gate: no fixed release is tagged on an unchecked `main`.
- `main` must be releasable at every commit, the advisory merge included.
  With no CI before that merge, the local checks of step 3 are what keep it
  so: they are not optional, and a check that could not run (the macOS and
  Windows reproducibility legs among them) is named in the report so the
  owner can decide before merging.
