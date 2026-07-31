# Review follow-ups (TODO)

Concerns raised while reviewing PR #261 (myotis-node napi-rs binding) and
PR #262 (create data_dir in `host::create`), collected 2026-07-31. None are
merge blockers; each should either be fixed or consciously dropped.

## From PR #261 — Node.js binding

- [ ] **libuv thread-pool starvation.** Every verified read runs on Node's
  shared libuv pool (default `UV_THREADPOOL_SIZE=4`). Four concurrent ~90 s
  worst-case reads block ALL of the host's `fs`/`dns`/`zlib`/`crypto` work —
  a real hazard in an Electron host that also runs IPFS/Swarm nodes.
  - Short term: warn in `rust/myotis-node/README.md` (raise
    `UV_THREADPOOL_SIZE`, or serialize long reads host-side).
  - Longer term: dispatch reads onto the engine's own tokio runtime and
    complete via a napi threadsafe function, taking the libuv pool out of
    the picture entirely.

- [ ] **`node-binding.yml` goes dead on merge.** The workflow triggers on
  `push: branches: [feat/node-binding]` — after the PR merges only
  `workflow_dispatch` remains. If the prebuilds should keep running, retarget
  the trigger to `main` with the same `rust/**` paths filter (or add a
  `pull_request` trigger).

- [ ] **`panic = "abort"` now aborts a browser.** Workspace-wide release
  profile choice (`rust/Cargo.toml`), same exposure as the JNI seam — but the
  blast radius is new: a Rust panic takes down the user's entire Electron
  process, not a daemon. Add an explicit note to the binding README; the
  "panic-free by construction" discipline in `host.rs` is carrying more
  weight now.

- [ ] **`smoke-windows` is network-flaky by construction.** Live devp2p/libp2p
  sync from a GitHub runner; `actions/cache` saves only on job success, so
  until one run reaches SYNCED within the 55-min budget every run repeats the
  ~30–40 min cold catch-up — and the 100-min job timeout also covers the
  first-ever `cargo test --workspace` on Windows plus the build. Keep it a
  non-required canary and expect to tune the budgets.

- [ ] **Pin the flat-vs-nested verification-field divergence.** The Rust
  engine's account JSON carries `beaconChainVerified`/`blsVerified`/
  `failReason` flat, where the Java daemon's IPC nests them under
  `verification` (PR #261 field finding #4). If the surfaces are meant to
  converge, pin the discrepancy in the cross-engine golden tests now — before
  a fourth ABI consumer discovers it the hard way.

## Interplay #261 ↔ #262

- [ ] **Sweep the stale "data_dir must exist" notes** once PR #262 (engine
  creates `data_dir` in `host::create`) lands. Three spots in #261 document
  the old behavior: the README "data_dir must exist" note, the usage
  comment (`// dir must exist`), and the workflow's "Ensure data dir exists"
  step. Whichever PR merges second sweeps them; if #262 goes first, #261 can
  drop the workflow workaround step entirely.

## From PR #262 — data_dir creation

Asked of the author in review; tracked here in case they don't land there.

- [ ] **Stale `create()` doc contract.** The doc comment on
  `rust/myotis-engine/src/host.rs` `create()` lists `CREATE_FAILED` causes as
  "unknown name / unavailable runtime" — an uncreatable dataDir is now a
  third cause and belongs in the list.

- [ ] **Misleading Java-side error message.** `RustMyotisEngine.java` maps
  every `id < 0` to "the Rust engine could not initialize the runtime for
  <network>", which points debugging in the wrong direction when the actual
  cause is an uncreatable dataDir (the Rust warn log is then the only clue).
  Broaden the message ("… or create the dataDir for …") or introduce a
  distinct sentinel.
