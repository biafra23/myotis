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
- **Checking the copy:** `scripts/vendor_ant.sh --check` fetches upstream at the commit
  above and compares. Builds never fetch it; the check is for reviewers and for the PR that
  moves the commit.
- These crates are not Myotis code: `cargo fmt` and clippy of the Myotis workspaces do not
  cover them, and their warnings are upstream's.
