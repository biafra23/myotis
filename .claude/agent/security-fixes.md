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

## Nothing public before the advisory is published

- No public PR, issue, discussion, comment, review reply or release note that
  describes the vulnerability, its fix or its affected code.
- **No push to any branch of this repository.** The session's designated
  branch is public too: a pushed commit is a disclosure, whatever its message
  says. This overrides the harness's "commit and push when done".
- Do not post the fix, the report or a reproduction to any external service:
  no gist, no paste site, no issue tracker of a dependency. Reporting a
  dependency's own bug upstream is the owner's call, through that project's
  private channel.
- A branch name, commit message or code comment written for the fix becomes
  public when it merges. Keep them neutral ("validate X before Y"), with no
  word of exploit, impact or reporter.

## Steps

1. **Code** the fix on a local branch. Do not push it.
2. **Test it locally, in place of CI.** GitHub runs no CI and no status
   checks in an advisory's temporary private fork, and no integration (the
   CI reviewer among them) can reach it. So run the checks CI would run on
   what the fix touches: at least `./gradlew build` (or with
   `-PskipRustEngine`, saying so), `./gradlew cargoTest` for Rust changes, and
   a test that fails without the fix and passes with it. List every check as
   passed, failed, or not run with the reason.
   **Reproducibility.** If the fix can change what a release build produces
   (`.claude/agent/reproducibility.md`), the rule "no merge into `main` may
   break reproducibility" still binds the advisory merge. The workflow cannot
   run before it, so build the Linux artifacts twice in the builder image
   (`docker/builder/run.sh -- scripts/repro/build_linux.sh`, from two
   checkouts at different paths) and compare them with
   `scripts/repro/compare.py`. The macOS and Windows legs cannot run in
   private: name them in the report as not run. Merging without them is the
   owner's decision, made before the merge, never assumed.
3. **Review** the diff with `/code-review`, locally (never `--comment`), and
   address its findings.
4. **Hand it to the owner** as a patch: `git format-patch` into the primary
   working directory, plus a short report (what the fix does, the checks of
   step 2 with their results, what could not be checked). In a cloud session
   the container is not the owner's machine: send the patch and the report
   with the host's file tool (`SendUserFile`, or what the host offers), never
   through GitHub. The owner applies it in the advisory's temporary private
   fork, where the reporter and other collaborators the owner adds can review
   it.
5. **The owner merges** the fork's PR into `main` from the advisory. That
   merge is the owner's action, as every merge is. Never merge, and never
   enable auto-merge.
6. **After the merge, before the release.** The fix is public from the merge
   on. The owner, or a session the owner asks, checks that CI on `main` is
   green at the merge commit and, where the fix can change release output,
   dispatches `reproducible builds` on `main` and sees all three platforms
   green. A red run is fixed by a normal PR into `main` at once, worded
   neutrally until the advisory is published. No `v*` tag goes on a commit
   whose CI or required reproducibility run is red.
7. **Release, then publish.** The release follows `.claude/agent/releases.md`
   as usual; its PR and notes stay neutral until the advisory is out. The tag
   is the owner's action. Publishing the advisory, and requesting a CVE for
   it, are the owner's actions too, after the fixed release is out.

## Why it is shaped this way

- The advisory's temporary private fork is the one private place GitHub
  offers for the fix, and nothing automated runs there. The local checks of
  step 2 and the post-merge checks of step 6 stand in for CI and keep the
  release gate: no fixed release is tagged on an unchecked `main`.
- `main` must be releasable at every commit, the advisory merge included.
  With no CI before that merge, the local checks of step 2 are what keep it
  so: they are not optional, and a check that could not run (the macOS and
  Windows reproducibility legs among them) is named in the report so the
  owner can decide before merging.
