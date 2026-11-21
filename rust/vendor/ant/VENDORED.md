# ant, vendored

Upstream: https://github.com/freedom-hq/ant
Commit: b138f6bc074d8c28149017d4e7b1e80db8c67d4d
License: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`, copied with the crates)

The embedded Swarm node behind `rust/swarm` (crate `myotis-swarm`, the reader of the addr1
address index; `.claude/agent/data-sources.md`, the Swarm carve-out). ant is not published
on crates.io. As a git dependency it put git sources into the lock, so every build on a
fresh machine fetched the repository: a third-party repository's availability became part
of every build, with no registry checksum. Vendored instead (owner's decision, 2026-11-20):
no build fetches anything from GitHub, and moving to another ant commit is a diff in this
repository, reviewed like code.

## What is here

- `crates/`: the seven crates `rust/swarm` builds (`ant-chain`, `ant-control`, `ant-crypto`,
  `ant-node`, `ant-p2p`, `ant-postage`, `ant-retrieval`), byte for byte as upstream has them
  at the commit above.
- `Cargo.toml`: ant's workspace manifest, which the crates inherit their edition, lints and
  dependency versions from. Its one change: `members` lists the seven crates instead of all
  of ant's (the others are not copied, and Cargo refuses a missing member). Its
  `[profile.release]` has no effect here: profiles come from the root of the build
  (`rust/swarm`, later the engine).
- `contracts/`: `BzzSwapHelper.bin`, which `ant-chain` embeds (`include_str!` in
  `src/tx.rs`), and its source `BzzSwapHelper.sol`.
- `LICENSE-MIT`, `LICENSE-APACHE`: upstream's.

Not copied: ant's other crates (`ant-ffi`, `ant-gateway`, `antctl`, `antd`, `antop`),
`xtask`, its `Cargo.lock` (the lock that counts is `rust/swarm/Cargo.lock`), and its docs
and scripts.

## Rules

- **Never edit these files by hand.** Myotis carries no fork of ant: a fix goes upstream
  and comes in with the next vendored commit. `scripts/vendor_ant.sh --check` finds any
  change that is not upstream's.
- **Moving to another commit:** `scripts/vendor_ant.sh <commit>`, then let Cargo update
  `rust/swarm/Cargo.lock` (`cargo update --manifest-path rust/swarm/Cargo.toml -p ant-node`,
  plus what the new crates need), in one PR whose description links upstream's compare view
  of the two commits. The diff under `rust/vendor/ant` is ant's change: review it as code
  that runs inside the engine.
- **The commit's age:** like every hand-moved pin (`.github/dependabot.yml`, the inventory
  at its top and the 7-day cooldown), a commit vendored here is at least 7 days old; a
  security fix is the exception, as it is for Dependabot.
- **The commit's origin:** `scripts/vendor_ant.sh` takes only a commit on upstream's
  default branch. GitHub serves a fork's commits through the parent's URL too, so a SHA
  alone does not say the code is upstream's.
- **Checking the copy:** `scripts/vendor_ant.sh --check` fetches upstream at the commit
  above and compares what git tracks, file modes included, and fails on unstaged edits.
  Builds never fetch it; CI runs it when the copy or the script changes
  (`.github/workflows/vendored-ant.yml`).
- **Agent instruction files** (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.mcp.json`, ...) in a
  vendored crate are refused by the script: Claude Code would load a nested `CLAUDE.md`.
  An update that brings one is decided about in its PR.
- These crates are not Myotis code: `cargo fmt` and clippy of the Myotis workspaces do not
  cover them, and their warnings are upstream's. As path dependencies they are built
  without the `--cap-lints allow` Cargo gives registry and git dependencies, so a toolchain
  bump can surface warnings in them, and a lint that is deny by default would fail the build
  in files that must not be edited: the fix then goes upstream, or the toolchain waits.

## Watching upstream

ant is on no registry, so no advisory database (RustSec, GitHub advisories, Dependabot
alerts) can name it, as a git pin or as a copy. Its registry dependencies stay covered
through `rust/swarm/Cargo.lock`; ant's own code, which parses what Swarm peers send, is
not. Nothing reports a security fix in ant: it reaches Myotis only when someone moves this
copy, and so do fixes for freedom-hq/ant#269, #270 and #271, the three reasons the `swarm`
feature is not in a release build (`rust/swarm/src/lib.rs`). Who watches ant's commits and
how often is the owner's to settle, before the engine links it.

## The SBOM

A path crate has no `source` in a lock, which `scripts/sbom.py` otherwise reads as one of
Myotis's own crates. Since the engine links `myotis-swarm` (its `swarm` feature, part 5 of
`feature/swarm-addr1`'s address-history plan), these crates are in `rust/Cargo.lock`, and
`sbom.py` lists every crate of a tree under `rust/vendor` as its upstream at the commit this
file names (`pkg:cargo` with a `vcs_url`, property `myotis:vendored`). A vendored tree
without its `VENDORED.md` is an error, so none is left out silently.
