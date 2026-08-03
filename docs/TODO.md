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

- [x] **`node-binding.yml` goes dead on merge.** Done: push trigger retargeted
  to `main` + `v*` tags, keeping the `rust/**` paths filter for branch pushes
  (GitHub doesn't evaluate paths filters on tag pushes, so release runs
  always fire), and a release job now publishes the five addons plus
  `myotis-node.SHA256SUMS` to the tag's GitHub Release with the engine ABI
  version pinned in the notes.

- [ ] **`panic = "abort"` now aborts a browser.** Workspace-wide release
  profile choice (`rust/Cargo.toml`), same exposure as the JNI seam — but the
  blast radius is new: a Rust panic takes down the user's entire Electron
  process, not a daemon. Add an explicit note to the binding README; the
  "panic-free by construction" discipline in `host.rs` is carrying more
  weight now.

- [x] **`smoke-windows` is network-flaky by construction.** Resolved as
  predicted: `cargo test --workspace` is green on Windows (after the
  `.gitattributes` LF pin for the golden vectors), but the smoke discovers
  peers over UDP yet holds no TCP/libp2p connections — possibly Windows,
  possibly Ethereum peers deprioritizing Azure datacenter IPs (a Linux
  control job disambiguates; real-Windows-box validation pending downstream).
  Both smoke jobs are now manual-only (`workflow_dispatch`) and releases
  never gate on them.

- [ ] **Pin the flat-vs-nested verification-field divergence.** The Rust
  engine's account JSON carries `beaconChainVerified`/`blsVerified`/
  `failReason` flat, where the Java daemon's IPC nests them under
  `verification` (PR #261 field finding #4). If the surfaces are meant to
  converge, pin the discrepancy in the cross-engine golden tests now — before
  a fourth ABI consumer discovers it the hard way.

## Interplay #261 ↔ #262

- [x] **Sweep the stale "data_dir must exist" notes** once PR #262 (engine
  creates `data_dir` in `host::create`) lands. Done: the README usage comment
  and the workflow's "Ensure data dir exists" steps are gone (the README
  Notes bullet had already been dropped at merge time).

## From PR #262 — data_dir creation

Asked of the author in review; tracked here in case they don't land there.

- [x] **Stale `create()` doc contract.** Landed with #262: the doc comment now
  lists "an unknown name, an unavailable runtime, or an uncreatable dataDir".

- [x] **Misleading Java-side error message.** Landed with #262:
  `RustMyotisEngine.java` now throws "could not initialize the runtime or
  create the dataDir for <network>".
