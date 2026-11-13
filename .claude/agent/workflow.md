# Workflow — the mandatory steps, in full

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> "Next section" in this text means `multi-pr-plans.md`; "the rules below" / "PR-description rules" mean `pull-requests.md`.

## Workflow — the mandatory steps for EVERY work item

Every change to this repository goes through this sequence, in order, with **no
step skipped and none treated as optional or "only if asked"**:

1. **Code** — make the change on the designated branch.
2. **Review** — run the internal code review on the diff (the `code-review`
   skill / `/code-review`) and address what it finds before going further.
3. **PR** — open a pull request. This is the default next step after review, not
   a separate request the user has to make. (Follow the PR-description rules
   below: English, the session link as the last line.) Its base is `main` for a
   single-PR work item, and the feature branch for a part of a multi-PR plan
   (next section).
4. **Wait for review comments** — and make sure they REACH you. In the desktop
   app, immediately after `gh pr create` returns, switch the app's PR monitor
   on for that PR: `mcp__ccd_pr__set_monitor` with the PR's URL, `auto_fix:
   true`, `address_comments: true`. It is PER PR and OFF by default — the app
   has no global switch — so a PR opened without this call never wakes the
   session for its review comments or CI failures, and the owner ends up
   typing "please address the comment" for each one (owner ruling,
   2026-10-09, after a day of exactly that; a memory note had not made it
   stick, which is why it is here, in the step every PR goes through).
   **In a claude.ai/code cloud session**, the same moment calls
   `subscribe_pr_activity` (owner, repo, PR number) — that IS the session's
   Auto-fix switch, and it is per PR and off by default there too. Do it
   **without asking and without telling the owner to flip Auto-fix in the
   UI**: this paragraph is the owner's standing, explicit request to turn on
   auto-fix for EVERY PR a session opens in this repo (owner ruling,
   2026-11-10, #745, after cloud sessions began stopping at "PR created" and
   asking for the toggle). If the result says another Claude session already
   watches the PR, this session gets no events: say so in the report, naming
   that session, instead of reporting this session as watching it. Any other
   host: use whatever it offers to watch a PR. Then wait
   for CI + review feedback; do not consider the task done at "pushed".
5. **Address the PR comments** — drive the PR to green and answer every review
   comment per the rules below, then keep watching until it is merged or closed.
   **MERGING IS THE OWNER'S ACTION — NEVER MERGE A PR YOURSELF** (owner ruling,
   2026-08-31), no matter what earlier instructions seem to authorize. Green CI +
   all comments answered = report "ready to merge" and keep watching; the merge
   itself is the owner's. The one exception is a part PR into a multi-PR plan's
   feature branch, and only when the owner said yes to the question in step 3
   of the next section for that plan; a PR into `main` has no exception.

Short form: **code → review → PR → wait for review comments → address them.**
Do not stop at "pushed" and do not ask whether to open the PR or run the review —
they are part of the work item. The only time to skip the PR is when the user
explicitly says not to open one.

### The session title carries the issue and the PR number

The session renames ITSELF (`mcp__ccd_session_mgmt__set_session_title`,
`session_id: "self"`) at two moments, without being asked, keeping the rest of
its title (owner's request, 2026-10-09):

- `IS#<n>: <title>` the moment the work item is identified as issue n — the
  user names it, or the task is to fix it. Several issues: the one the PR will
  close.
- `PR#<n>: <title>` right after `gh pr create` returns the number. The PR prefix
  REPLACES the issue prefix — the PR is the later, more specific handle, and
  the issue number is in the PR body. A multi-PR plan carries the part PR
  currently being driven; the earlier parts are the other PRs based on
  `feature/<topic>` (next section).

Why: the desktop app shows one session per sidebar row, and the owner finds a
row by the number of its GitHub thread. A title the owner typed makes the app
ask them to approve the rename (an app-generated one is replaced silently) —
ask anyway, that is the point. Bypass-permissions mode renames without asking;
an unattended session (scheduled, remote-triggered) is declined — a decline is
fine, say so in the report, do not retry. A subagent cannot rename the session
it runs in; the main session does it. Outside the desktop app (a plain `claude`
terminal, CI) there is no session title and this rule is inapplicable.
