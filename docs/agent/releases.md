# Releases and demo bundles

> Moved verbatim from `CLAUDE.md` (the always-loaded core keeps a summary and points here).
> Read in full before any release work: a `v*` tag, a version bump, checkpoints, bootnodes, PoC seeds, release assets, or a bundle workflow. "The section above" (the reproducibility gate) is `reproducibility.md`.

## Releases — ask before cutting one

When the user asks for a release (a `v*` tag, a version bump, "cut a release"),
**ask these three questions first and act only on what they choose** (owner
rulings, 2026-09-02 and 2026-09-11), then **move the version pins — step 4
below, mandatory, never asked about** (owner ruling, 2026-09-24) — and
**refresh the PoC seeds, step 5, mandatory too** (2026-10-13). Everything a
release needs goes into ONE release PR. **The tag is the owner's action**: after
the merge the owner pushes it, or explicitly asks for it to be pushed — never
push a `v*` tag on your own initiative, it is the publish trigger for every
asset workflow and a stronger action than the merge this file already forbids.
(v0.1.12 is the one exception to the one-PR rule: #484 carried steps 1–3 and
#485 the bump and this rule. From v0.1.13 on, one PR.)

1. **Refresh the trust checkpoints?** The embedded checkpoints (`@checkpoint:*`
   blocks in `NetworkConfig.java`, mirrored in `rust/myotis-net/src/sync.rs`;
   `./gradlew refreshCheckpoint -Pnetwork=<net>` writes both engines from one
   fetch) age toward the weak-subjectivity bound (13 periods on mainnet, 3 on
   gnosis). A fresh install past the bound parks in `STALE_ANCHOR` until the
   host consents. The Go engine (`go/internal/chain/lc.go`, mainnet only)
   carries a third copy that the task does NOT write: move it by hand in the
   same commit — the `go test ./internal/chain` drift test
   (`TestCheckpointMatchesRustEngine`) fails the Go CI if the copy lags.

   **A shipped anchor's remaining freshness is NOT a release deadline, and
   nothing may gate a tag on it** (owner ruling, 2026-09-24). Gnosis periods are
   8192 slots of 5 s — 11.4 h — so its 3-period bound gives a fresh install at
   least a **~34-hour** window from the anchor's slot, and at most ~45.5 h: the
   gate is period-granular (`ws_anchor_stale`: `wall - anchor > bound`), so an
   anchor expires only when the wall clock ENTERS period `anchor + 4`, never
   mid-period, and a refresh at head lands anywhere in its period. No release cadence can stay inside that: holding the
   tag to it would mean daily releases, and daily releases would mean expecting
   users to update daily, which trains them to click through updates without
   reading them. Mainnet's 13 periods of 27.3 h (~15 days) is the same
   phenomenon with a kinder constant. Quote the floor, not a fixed width — the
   v0.1.12 tag message quoted an expiry to the second, which is how a
   period-granular bound turns into a deadline nobody can meet.

   So: refresh the anchors because a fresher one serves more installs, never
   because a clock is running out. Do not compute, quote or act on an
   "anchor goes stale at <time>" deadline when preparing a release, and do NOT
   build the `verifyReleaseAnchorFresh` tag gate a review proposed for exactly
   this (#485) — it would refuse correct releases on a schedule no release
   process can meet. On gnosis in particular, `STALE_ANCHOR` on a fresh install
   is the ORDINARY case within two days of any release, not an incident: the
   consent path is the product surface that has to be good, and that is a
   separate design question from how often we tag.
2. **Re-sync the mainnet discv4 bootnodes from go-ethereum?** Source of
   truth is geth's `params/bootnodes.go` `MainnetBootnodes`. Pin sites:
   `NetworkConfig.MAINNET`, `ElConfig::mainnet()`
   (`rust/myotis-net/src/el/reader.rs`), `rust/tor-poc` (with pubkeys),
   `go/internal/chain/chain.go` (with its `TestMainnetPins`; run
   `go test ./...` under `go/` after the edit — Gradle CI doesn't), and
   any other verbatim copy — do not trust this list, `grep -rn` the tree for
   one of the current addresses before and after the edit until zero copies
   of the old ones remain. Since #414 the `myotis-net` live tests read
   `ElConfig::mainnet()` and `mainnet_config_pins_known_values` pins the
   list as strings, so a partial re-sync fails in the fast lib test.
   Mainnet has no pinned enodes and, in the Rust engine, an EIP-1459 DNS
   fallback only where the host allows DNS (desktop and daemon since #539;
   not mobile, not under Tor — the Java engine has one everywhere), so a
   fresh profile with a stale list never seeds EL discovery and never holds
   a snap peer there (#414, 2026-09-02).
   Warm profiles and the dispatched smoke job hide this because they dial
   their peer cache directly.
3. **Run the cold-start checks?** (owner ruling, 2026-09-11.) Three live
   tests, all `#[ignore]`d so nothing else ever runs them, and together the
   only coverage of what a FRESH INSTALL does. Ordinary CI, the emulator smoke
   and the dispatched node smoke all dial a warm peer cache or a release-fresh
   anchor, which is exactly what hides this class of failure — in #422 a
   shipped build could not catch up at all while every automated check was
   green. Dispatch the `cold-start regression` workflow from the Actions tab
   (preferred — a CI runner is a clean host, see the caveat below), or locally:

   ```bash
   cd rust
   # 3a. are the shipped pins and bootnodes alive? (seconds when healthy)
   NET=gnosis cargo test --release -p myotis-net --test live_pins_alive -- \
       --ignored --nocapture --test-threads=1
   # 3b. dead pins: every pinned CL server configured but unreachable
   NET=gnosis cargo test --release -p myotis-net --test live_cold_start -- \
       --ignored --nocapture cold_start_with_every_pinned_peer_unreachable
   # 3c. deep catch-up: an anchor further behind than the network's ws bound
   NET=gnosis MYOTIS_TEST_ANCHOR_ROOT=<64 hex> MYOTIS_TEST_ANCHOR_SLOT=<slot> \
     cargo test --release -p myotis-net --test live_cold_start -- \
       --ignored --nocapture cold_start_from_an_old_anchor
   ```

   Run each for every network you are shipping (`NET=mainnet|sepolia|gnosis`).
   The workflow takes a `scope`: `full` is the release check and REFUSES to run
   without an anchor rather than skipping the deep walk green; `pins-only` is
   for when you deliberately want just 3a and 3b.

   **3a is the one that would have caught #422 before it shipped**, and it is
   the one whose OUTPUT you read rather than just its exit code. It asks every
   pinned CL peer for a `light_client_bootstrap` at this build's own embedded
   anchor and applies the SAME acceptance the production path does (checkpoint
   pin plus both Merkle branches), then asks for the anchor's period of
   `updates_by_range` and runs it through the production processor, and — once
   the chain has left that period — for the current period's, which must be
   attested in it, in its fork's wire shape and above the 2/3 bar. So a pin
   counts as alive only if a fresh install would accept what it serves AND
   could follow the chain from it: an anchor embedded before a server stopped
   (Sepolia's Lighthouse pins at the Gloas fork) no longer hides that. Then it checks the
   bootnodes can seed discv5 at all. It gates on a FLOOR (at least two pins serving), not a clean
   sweep, because these are third-party hosts and demanding perfection makes a
   check people skip. Individual dead pins are a re-census signal
   (`examples/period_census.rs`; the workflow's `census` scope runs it from a
   clean runner), not automatically a blocker.

   **Caveat that will bite you: the result is only as good as the host.** A
   Lighthouse node that has banned your IP reports as `dial failed` while being
   perfectly healthy for everyone else — and any machine that ran a
   pre-gossipsub build carries those bans for 12 h (that ban IS #422). Measured
   2026-09-11 from a dev box: 18 of 23 gnosis pins looked dead from home and
   answered fine through a VPN minutes earlier. So prefer the dispatched
   workflow, and before believing a bad census, check whether your host is the
   outlier.

   The old-anchor run needs an anchor from a release OLDER than the current
   one — the newest tag is usually the release whose checkpoint is already on
   `main`, so it proves nothing, and the test refuses an anchor within the
   network's weak-subjectivity bound:

   ```bash
   prev=$(git tag --sort=-v:refname | sed -n 2p)
   git show "$prev":rust/myotis-net/src/sync.rs | grep -A6 '@checkpoint:gnosis:begin'
   ```

   Run them AFTER any checkpoint refresh from question 1, so the build under
   test is the one being shipped. A failure here is release-blocking: it means
   a fresh install cannot sync, which is the one thing a wallet must do.

4. **Move the version pins. MANDATORY — not a question, and part of the SAME
   release PR as steps 1–3** (owner ruling, 2026-09-24). Every release from
   v0.1.8 to v0.1.11 did this inside its one release PR, but only by precedent;
   the v0.1.12 checkpoint PR (#484) followed this list to the letter, answered
   the three questions, and shipped no bump — `main` still declared 0.1.11, and
   the tag would have been refused. There is no command for it yet (review
   follow-up: a `setReleaseVersion` task); until there is, it is these six
   files (a previous sweep commit touches these plus step 1's two checkpoint
   files, so do not copy its file list blindly):

   | file | what moves |
   |---|---|
   | `build.gradle.kts` | `version = "X.Y.Z-SNAPSHOT"` (root `allprojects`) |
   | `rust/Cargo.toml` | the workspace `version` |
   | `ios-app/Myotis/Version.xcconfig` | `MARKETING_VERSION = X.Y.Z` and `CURRENT_PROJECT_VERSION` = the root build's `releaseBuildNumber`, i.e. `X*1_000_000 + Y*1_000 + Z` (0.1.12 → 1012, 0.2.0 → 2000, 1.0.0 → 1000000; `verifyIosVersion` prints the expected value on a mismatch) |
   | `rust/Cargo.lock`, `rust/roost/Cargo.lock`, `rust/tor-poc/Cargo.lock` | `cargo update --workspace` in each of the three manifests, so the workspace crates' own entries follow |

   And, ONLY when step 3's deep walk (3c) ran from `oldest-servable.properties`'
   entries — the dispatched workflow's default, not the `pins-only` scope and
   not a local run from the previous tag's anchor — note in that file's comment
   that this release's run walked from these roots. It is a servability record
   the cold-start test trusts instead of re-probing; a note about a walk nobody
   observed makes it lie.

   Then verify. The first command is the SAME query the tag guard makes; the
   rest cover the pins the guard does NOT see:

   ```bash
   ./gradlew -q :printReleaseVersion verifyCrateVersions verifyIosVersion   # must print releaseVersion=X.Y.Z
   for m in rust rust/roost rust/tor-poc; do cargo update --workspace --locked --manifest-path $m/Cargo.toml; done
   ```

   `releaseVersion` must equal the tag's version core — the guard accepts
   `vX.Y.Z` and `vX.Y.Z-<suffix>` (rc/hotfix shapes), nothing else. Know what
   catches what: the guard refuses the tag ONLY for the Gradle pin, because it
   compares the tag to `project.version` and nothing more. The other five are
   PR-time failures — `./gradlew check` for the crate and iOS pins, the
   `cargo-locks` workflow for the locks — so run them before asking for the
   merge, or the release PR goes red after the fact. A stale `rust/Cargo.toml`
   that slipped past both would ship a Rust engine whose devp2p and libp2p agent
   strings advertise the previous release. The macOS dmg version is derived
   (major + 1) and needs no edit.

5. **Refresh the PoC log-index seeds. MANDATORY — not a question, and part of
   the SAME release PR** (owner's request, 2026-10-13). Each seed is usable for
   500,000 blocks above its top (`MAX_GAP`): ~29 days on Gnosis, ~69 on mainnet
   and Sepolia. A release built on an older one ships a PoC that starts far
   behind and, past the limit, never catches up: before this step, a Bee PoC
   build started ~365,000 blocks behind. One command, on zbox, when the release
   PR is otherwise ready (the shelf life runs from the fetch):

   ```bash
   scripts/refresh_poc_seeds.py
   ```

   It tops up all three incrementally — only the blocks above each seed's top,
   fetched from zbox's geths to `finalized` and appended — and checks each
   result frames the way the build frames it. The **Bee** seed is rewritten in
   `data/bee/gnosis/`: commit it in the release PR. The two **RAILGUN** seeds
   are published straight to the `railgun-seed` release (a safe swap; the old
   asset stays until the new one is verified), which the tag's `railgun-dmg`
   build downloads, so they are done before the tag with nothing to commit.
   Why not a workflow: zbox's nodes are the seeds' only source, and no GitHub
   runner can reach them. The reminder is one: on a PR that changes the root
   `version`, the `PoC seeds` check (`poc-seeds.yml`) stays red until every
   seed was fetched within 72 hours — re-run it by hand after the RAILGUN
   publish, which makes no commit. Details: docs/guides/railgun-poc.md (*Refreshing the seed*),
   docs/guides/bee-rpc-service.md (*seeding from a full node*).

6. **After the tag: a release is done when its two evidence runs are green.
   MANDATORY to check and report, not a question** (#734). A tag push starts
   them by itself, next to the ten publishing workflows:
   - **`verify release`** waits for the publishers, then checks the finished
     release from the outside (`scripts/verify_release.sh <tag>`): its
     `SHA256SUMS` lists every asset and every hash matches, every asset has a
     build-provenance attestation from this repository, by the workflow that
     builds that asset, for a run on the tag's ref at the tag's commit, and
     the signed APK is the published unsigned APK plus its signature and
     nothing else.
   - **`reproducible builds`** rebuilds the tag twice (the gate of the section
     above), and its `Compare the image build with the published assets` job
     sets the rebuild in the builder image next to the Android assets the
     release published. That job REPORTS (the gate is the owner's): read its
     summary and pass on to the owner whether the unsigned APK and the AAR
     are identical, and what differs if not.

   Report a red run to the owner at once, with what failed. Neither is fixed
   by moving or re-pushing the tag: a publisher that failed is re-run (every
   upload is idempotent), `verify release` is then dispatched for the tag, and
   a release whose published bytes are wrong is the owner's decision.

**Every release asset goes through `.github/release-assets.sh`, never a bare
`gh release upload`** (#734). A publishing job has three steps for it, in this
order: the script uploads and checks that the release serves the bytes the job
built; `actions/attest-build-provenance` attests those files
(`subject-checksums` from the file the script writes; the job needs
`id-token: write` and `attestations: write`); and
`release-assets.sh --checksums <tag>`, last and with `if: ${{ !cancelled() }}`,
keeps the release's one `SHA256SUMS` complete across the ten publishers. A
new publisher has all three and joins the list in
`release-version-guard.yml`'s header. `scripts/test_release_assets.sh` (run by
CI) fails on a bare upload, or an upload without the checksums step, in any
workflow, and the verifier knows which workflow builds which asset
(`workflow_of` in `scripts/verify_release.sh`): a new publisher adds its
family there too. **None of this path runs before a tag, so rehearse it**:
the `release rehearsal` workflow sends a dummy file through the same steps on
a draft release (upload, attestation at the pinned action, `--checksums`,
`gh attestation verify` with the verifier's flags) and deletes the draft. It
runs by itself on a PR that changes the scripts; dispatch it before a tag
whenever the runner image, `gh` or the attestation action has moved since the
last release. docs/guides/reproducible-builds.md is the page for someone
checking a release.

## Demo bundles build on merge to `main`, never on PRs

The demo / PoC installers — the RAILGUN PoC dmg (`railgun-dmg.yml`), the Bee
PoC dmg (the `bee-poc` leg of `desktop-dmg.yml`) and any bundle added later —
build on every push to `main` and on `v*` tags, and NOT on pull requests
(owner ruling, 2026-10-01). A merge to `main` is what refreshes the artifact a
demo machine pulls, so nothing waits for a release; a PR build would only add a
macOS runner leg per push, because a change that breaks a bundle without
failing a test is next to impossible — what a bundle adds over the standard app
(a seed, its manifest, warm peer caches) are build inputs, not code paths, and
the standard dmg leg already proves jpackage on every PR into `main`. A bundle-only
regression therefore surfaces on the next `main` run, where it is a hard gate.
A bundle whose seed lives OUTSIDE the tree (RAILGUN's, on the `railgun-seed`
release) also takes `workflow_dispatch`, so a refreshed seed can be rebuilt
without a commit; a seed committed in the tree (Bee's, `data/bee/gnosis/`)
needs none, since its refresh is itself a push to `main`. On a tag no bundle
may hold back the standard assets: the Bee leg is `continue-on-error` there,
and the RAILGUN dmg is its own workflow, so its failure leaves only itself
red. Give a new bundle the same trigger set, and say so in its doc.
