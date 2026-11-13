# How idiomatic is the Rust in `rust/`? — a review

> **Status (2026-11-01):** review only — this document changes no code. Baseline:
> `main` at `3bc5184` (the v0.1.19 release merge), measured with stable
> `rustc 1.97.0`, `clippy 0.1.97`, `rustfmt 1.9.0`. Every finding names a
> `path:line`; the counts are reproducible with the commands in §2. The
> recommendations in §7 are proposals for the owner to pick from, not a plan
> that has been started.

## 1. Verdict

The workspace is **sound, careful Rust with a strong safety discipline, written
in a dialect that is noticeably less idiomatic than its engineering quality**.
Where it matters most it is good: the sans-I/O crates (`myotis-core`,
`myotis-wire`, `myotis-consensus`) decode attacker-controlled bytes without a
single `unwrap()` in production code, the crate layering is clean and
compiler-enforced (`no_std` canaries, one-way dependencies), `let-else`,
`matches!` and `is_some_and` are used freely, structured `tracing` fields are
the norm, and the test volume (44 k lines) is close to the production volume
(45 k lines of code plus 22 k lines of comments).

What keeps it from reading as idiomatic Rust is a handful of **workspace-wide
habits**, each of them a deliberate or historical choice rather than an
accident:

| # | Habit | Scale | Idiom it departs from |
|---|---|---|---|
| 1 | Not formatted with `rustfmt` | 117 of 160 workspace files, 3 155 lines; roost 8 of 8 | `cargo fmt` is the one style every Rust project shares |
| 2 | Stringly-typed errors | 167 `Result<_, String>` mentions, 98 `Err(format!(…))`, 130 `Err("…")`, 126 `map_err(\|e\| format!…)` in production; the three crate-level error types are `struct XError(pub String)`; in six places control flow branches on the *text* of an error (§4.2) | typed error enums with `Display`/`Error` impls and `?`/`From` conversions |
| 3 | Primitive obsession | 723 mentions of `[u8; 32]`, one alias (`ssz::Root`), no newtype for hash/address/slot/epoch/period/block number; 47 `pub fn … slot\|epoch\|period\|block_number\|chain_id: u64` | newtypes so the compiler tells a slot from an epoch and a state root from a block hash |
| 4 | Very large files and functions | 11 files over 2 000 lines (`el/reader.rs` 12 377 production lines), 20 functions over 150 lines (`sync::catch_up` 544) | modules of one responsibility, functions that fit on a screen or two |
| 5 | Everything `pub` | 1 073 `pub fn` vs 141 `pub(crate)`; every submodule of `myotis-net` is `pub mod` | `pub(crate)` by default, a deliberate public surface |
| 6 | JSON by hand | 388 `serde_json::Value`/`json!` sites vs **one** `#[derive(Serialize)]` in the whole tree | `#[derive(Serialize, Deserialize)]` DTOs |
| 7 | Five lock-poisoning policies side by side | `.lock().unwrap()` 55, `.lock().expect("…")` 35, `unwrap_or_else(\|e\| e.into_inner())` 93, the recovery `match` pasted by hand, `lock().ok()?` / `map_err(…)` silently skipping — up to five in one file (`engine/host.rs`) | one policy, one helper (or `parking_lot`) |
| 8 | `unsafe` without `// SAFETY:` | 77 `unsafe {}` blocks in `myotis-node` and 39 `unsafe fn`s in `capi.rs` against 3 `// SAFETY:` comments in the whole production tree; 7 `unsafe extern "C" fn`s without a `# Safety` doc section | every `unsafe` block states the invariant it relies on |
| 9 | Manifest hygiene | no `[workspace.dependencies]` (tokio pinned in 2 crates, tracing in 4, serde_json in 6), no `[workspace.lints]`, edition 2021 on an MSRV (1.91) that allows 2024 | shared workspace dependency and lint tables |

Nothing found here is a soundness hole, and **no panic reachable from peer
input or a host call was found anywhere** — the one low-likelihood exception
is four `expect("OS entropy")` on the RLPx dial path (§5.6). That matters
because the workspace builds with `panic = "abort"`, so a panic on a native
path kills the host app; the code honours that rule far better than its
`unwrap()` count suggests. The severity-A items in §5 are almost all
comments that contradict the code (collected in §4.14) plus a handful of
small real bugs noticed on the way (§4.15).

## 2. How this was measured

All commands run from `rust/` on the baseline above. Dependency lints were
excluded (only paths under `rust/` were counted).

```bash
cargo fmt --all --check                                   # 117 of 160 files differ, 3 155 lines
cargo fmt --manifest-path roost/Cargo.toml --check        # 8 of 8 files differ
cargo clippy --workspace --all-targets                    # 65 distinct warning sites (110 raw messages)
cargo clippy --workspace --all-targets -- -W clippy::pedantic   # +2 320 sites
cargo clippy --workspace --all-targets -- -W clippy::nursery    # +1 082 sites
RUSTDOCFLAGS="-W rustdoc::all" cargo doc --workspace --no-deps --document-private-items  # 79 warnings
```

Plus grep-based counts over **production code only** — `#[cfg(test)]` modules
and `#[test]` functions stripped, `tests/` and `examples/` skipped, comment
lines excluded — and a complete read-through of every crate by eleven
reviewers against one rubric (error handling, ownership, type design, std-trait
conventions, control flow, module structure, `unsafe`/FFI, async, concurrency,
numeric casts, strings, docs/tests, logging, manifests). Their findings were
spot-checked against the source before inclusion; §5 is the result.

Size of the thing reviewed (`rust/`, including `roost` and `tor-poc`):

| | lines |
|---|---|
| all `.rs` | 115 425 |
| production code (no comments, no tests) | 45 162 |
| production comment lines | 21 773 (33 % of non-blank production lines) |
| test code (`tests/`, `examples/`, in-file `#[cfg(test)]`) | 44 139 |

## 3. The numbers at a glance

Production code only unless stated; "mentions" are source-line matches.

| Indicator | Count | Reading |
|---|---|---|
| `unwrap()` / `expect(…)` / `panic!`-family | 95 / 79 / 3 | low for the size; concentrated in `consensus/types.rs` (25), `el/anchor.rs` (24 `expect("anchor mutex")`), `evm/database.rs` (22), `el/evm.rs` (16), `el/reader.rs` (14) — see §4.3 |
| `Result<_, String>` mentions / `Err(format!(` / `Err("…")` / `map_err(\|e\| format!` | 167 / 98 / 130 / 126 | the dominant error style — §4.2 |
| error types that are enums with `Display` + `Error` | 7 (`EvmError`, `OracleError`, `EnsError`, `RequestError`, `ProofError`, roost's `FetchError`, `FramingError`) + 5 enums with `Display` only | the exception, not the rule |
| `as` numeric casts / `try_from`+`try_into` | 218 / 138 | clippy: 140 `cast_possible_truncation` sites in production, 31 of them in `myotis-wire` — §4.7 |
| `.clone()` | 279 | clippy `redundant_clone`: 35 (11 in production) |
| `[u8; 32]` mentions / hash newtypes | 723 / 0 | §4.4 |
| `pub fn` / `pub(crate)` | 1 073 / 141 | §4.6 |
| `pub` structs+enums / without `Debug` | 270 / 76 | §4.6 |
| `#[must_use]` / `#[non_exhaustive]` / `impl FromStr` / `impl From` / `impl Iterator` | 1 / 0 / 0 / 7 / 2 | std-trait conventions barely used — §4.6 |
| `let … else` / `matches!` / `is_some_and`-style combinators | 323 / 157 / present | modern control flow is in use (positive) |
| legacy `format!("{}", x)` / inline `format!("{x}")` | 333 / 497 | mixed in every crate — §4.9 |
| `serde_json::Value`/`json!` sites / `#[derive(Serialize)]` | 388 / 1 | §4.9 |
| `tracing` calls with structured fields / message-only | 171 / 38 | mostly idiomatic (positive) |
| `std::sync::Mutex` / `tokio::sync::Mutex` mentions | 102 / 29 | right default; clippy `significant_drop_tightening`: 44 — §4.8 |
| `Ordering::SeqCst` / weaker orderings | 69 / 138 | mixed — §4.8 |
| `block_on` / `block_on(async { f().await })` | 35 / 12 | the inner `async` block is redundant — §4.8 |
| `unsafe {}` blocks (`myotis-node`) / `unsafe fn`s (`capi.rs`) / `// SAFETY:` comments / `/// # Safety` sections | 77 / 39 / 3 / 31 | §4.10 |
| files > 2 000 lines / functions > 150 lines | 11 / 20 | §4.5 |
| `#[allow(clippy::too_many_arguments)]` / `#[allow(unused_imports)] use alloc::{…}` | 15 / 17 | §4.5, §4.11 |
| rustdoc: broken intra-doc links / public docs linking private items | 23 / 53 | the extensive docs are not `cargo doc`-clean — §4.6 |

## 4. Cross-cutting findings

Severity: **A** = correctness/soundness or a panic reachable from input the
engine does not control; **B** = clearly un-idiomatic, a Rust reviewer would
ask for a change; **C** = style/consistency.

### 4.1 Formatting — not `rustfmt`-clean (B, mechanical)

`cargo fmt --check` rewrites 117 of the 160 workspace files (3 155 lines) and
all 8 roost files. The diffs are what rustfmt always does — wrapping lines over
100 columns (1 435 such lines), splitting long `assert!` and `use` lists,
one-argument-per-line calls — e.g. `myotis-consensus/src/fork.rs:33` (an
`alloc` import list) and `:81–83` (three `assert!`s). Nothing in CI runs
`cargo fmt --check` and there is no `rustfmt.toml`. This is the single most
visible departure from Rust convention and the cheapest to fix: one
`cargo fmt --all` commit (reviewed as whitespace-only) plus a `--check` step in
`rust-clippy.yml`, in the same spirit as that lane's documented ratchet.

### 4.2 Error handling — strings where types belong (B; the workspace's biggest idiom gap)

The dominant error type in production code is `String`, and in six places
the *text* of an error is what the program branches on:

- **Error classification by substring, load-bearing across crates.**
  `myotis-wire/src/snap/fetch.rs:47–72` defines `PROOF_INVALID_MARKER = "proof
  invalid"` and `is_unservable_root_error(error: &str) -> bool { error.contains(..) }`
  — a comment calls the substring "LOAD-BEARING" and asks to keep format
  strings "in sync" with `trie.rs` — and six sites route peers on it:
  `el/reader.rs:6026` and `:6290` call `is_unservable_root_error`, while
  `:5709`, `:6381`, `:6614` and `el/evm.rs:855` call its sibling
  `is_unknown_root_error` (`fetch.rs:70`, the same marker plus a second
  substring). `el/pool.rs:78–80`
  classifies dial outcomes with `e.starts_with("peer disconnected") &&
  e.ends_with("reason=4")` and `e.starts_with("incompatible peer")`
  (`:1490–1492`), with a 40-line test pinning the string shape.
  `el/reader.rs:640–641` decides tip-lag with `f.contains("headers, expected")`,
  so `fetch_anchored_window` has to word two errors differently on purpose
  (`:9935–9941`). `el/request.rs:93–105` returns `"request deadline exceeded"`
  and `myotis-evm/src/oracle.rs:139` tells a deadline from a cancellation by
  comparing that text (its test says "Reword the message here and this
  fails"). `el/tor.rs:254–259` matches `starts_with("tor connect ")`. Three
  live tests assert `e.contains("incompatible peer")`. Each of these is one
  `enum` away from being a `match`; this is the single most consequential
  idiom gap in the workspace, because a reworded message silently changes
  peer routing.
- `Result<_, String>` appears 167 times, about 90 of them in function
  signatures (`el/reader.rs` 19, `fixture/world.rs` 11, `engine/host.rs` 11,
  `el/rlpx/transport.rs` 6, `el/dnsdisco.rs` 5, …). Errors are built with
  `Err(format!(…))` (98), `Err("literal")` (130) and
  `map_err(|e| format!("…{e}"))` (126); callers match on message text or
  cannot match at all.
- The three sans-I/O crates each define one newtype over a string —
  `myotis-core/src/lib.rs:43` `pub struct CoreError(pub String);`,
  `myotis-consensus/src/types.rs:19` `pub struct SszError(pub String);`,
  `myotis-wire/src/eth2/codec.rs:28` `pub struct CodecError(pub String);` —
  documented as "a message, no hierarchy (FFI-flat by design)". FFI flatness
  does not require that: an enum with a `kind` (mapped to the FFI code) and a
  message is just as flat and lets Rust callers match.
- Where enums exist they are done well (`myotis-evm/src/error.rs:13`
  `EvmError`, `oracle.rs:64` `OracleError`, `ens/mod.rs:215` `EnsError`,
  `reqresp.rs:425` `RequestError`, `getproof.rs:92` `ProofError`): variants,
  `Display`, `std::error::Error`. But they are islands — `myotis-evm`'s own
  fixture code is back to `Result<_, String>` (22 mentions), and `EvmError` is
  converted to a string the moment it reaches `myotis-net`.
- Eager error construction: 31 production sites pass an already-formatted
  string to `ok_or(format!(…))` (`engine/host.rs:2488`, `:2497`, `:2569`,
  `rpcd/src/rpc.rs:1770`, `:1778`, `:1795`, `fixture/world.rs:481`–`516`, …),
  allocating on the success path too; the idiom is `ok_or_else(|| …)`.
- Inconsistent `Error` impls across the no_std crates: `myotis-core` uses
  `impl core::error::Error for CoreError {}` unconditionally
  (`lib.rs:53`, the right spelling since Rust 1.81), while `myotis-consensus`
  (`types.rs:26`) and `myotis-wire` (`eth2/codec.rs:35`) write
  `#[cfg(feature = "std")] impl std::error::Error for …`, so a `no_std`
  consumer of those two gets an error type that is not an `Error`.
- Almost no `From` impls to feed `?`: 7 in the whole tree, so conversions are
  `map_err` chains at every call site.

The idiom: per-crate (or per-module) `enum` error types with `Display`,
`Error` (via `core::error::Error`), `From` impls for the errors they wrap, and
`?` at the call sites; a `String`-carrying variant where free text is
genuinely all there is. `thiserror` would cut the boilerplate but is not
required (and would add a proc-macro dependency to the no_std crates).

### 4.3 Panics on production paths under `panic = "abort"` (A where reachable, B otherwise)

The totals are low (95 `unwrap()`, 79 `expect`, 3 `panic!`/`unreachable!` in
45 k lines) and the sans-I/O decoders are clean: **0** `unwrap()` in
`myotis-core` production code, **0** in `myotis-wire` (12 `expect`s, on
fixed-size conversions). The concentrations are:

- `myotis-consensus/src/types.rs` — 25 `unwrap()` (SSZ fixed-size field reads
  such as `.try_into().unwrap()` on slices whose length the decoder has already
  checked). Correct today, but each one is a bounds proof the reader has to
  re-derive; the idiom is a checked `read_u64(at)` helper returning
  `Result`, so the proof lives in one place.
- `myotis-net/src/el/anchor.rs` — 24 `.lock().expect("anchor mutex")`;
  `myotis-evm/src/database.rs` — 22 `.lock().unwrap()`; `myotis-net/src/el/evm.rs` — 16.
  Under `panic = "abort"` no thread can unwind, so a mutex can never be
  poisoned and these cannot fire in release builds; they are the
  "`unwrap()` on a lock" idiom. The finding is the inconsistency (§4.8): the
  same workspace also uses `unwrap_or_else(|e| e.into_inner())` (93 sites) and
  `match m.lock() { Ok(g) => g, Err(_) => return … }` (`el/served.rs:187`,
  `:244`; `engine/host.rs:918`) for the same situation.
- Panics reachable from untrusted input: the reviewers found exactly one
  candidate, the `expect("OS entropy")` on the RLPx dial path (§4.15, §5.6);
  everything else they traced is guarded. The remaining risk is in arithmetic
  and `as` casts (§4.7) and in `Duration` subtraction: `el/evm.rs:470` `WAVE_SILENCE_DEADLINE - quiet`
  is guarded by the `>=` check two lines above, but
  `clippy::unchecked_time_subtraction` flags it and two siblings because
  `Duration - Duration` panics on underflow — `saturating_sub` states the
  intent).
- Constructor validation by `assert!` in library code:
  `myotis-consensus/src/fork.rs:81–83` (`ForkSchedule::new`) and
  `spec.rs:115` panic on a bad fork table. These are programmer-error checks
  on embedded constants, which is a legitimate use of `assert!`, but
  `clippy::missing_panics_doc` (58 sites) notes none of them documents the
  `# Panics` contract.

### 4.4 Type design — primitive obsession and Java-shaped DTOs (B)

- **Hashes, roots, addresses, keys** are all raw arrays: 723 mentions of
  `[u8; 32]`, `[u8; 20]` for addresses, `[u8; 64]` for node ids, with exactly
  one alias (`myotis-consensus/src/ssz.rs:14` `pub type Root = [u8; ROOT_LEN];`)
  and no newtype anywhere. A state root, a block hash, a transaction hash and
  a storage key have the same type, so the compiler cannot catch an argument
  swap; `myotis-evm` sits on top of `revm`, which already provides `B256`,
  `Address` and `U256`, and converts to and from raw arrays at its boundary.
- **Slots, epochs, periods, block numbers, chain ids** are all `u64`: 47
  public functions take one or more of them by that name
  (`pub fn … slot: u64`, `… epoch: u64`, …). The spec arithmetic in
  `myotis-consensus/src/spec.rs` is exactly where a `Slot`/`Epoch`/`Period`
  newtype trio pays off.
- **Tuples as records**: `pub type Enode = (SocketAddr, [u8; 64]);`
  (`el/pool.rs:146`), `pub(crate) type Head = (u64, [u8; 32]);`
  (`el/feecache.rs:28`), `type WalkKey = ([u8; 32], u64);` (`el/evm.rs:48`),
  13 functions returning three-or-more-element tuples —
  `serve_stats(&self) -> (u64, u64, u64, u64)` exists twice
  (`el/pool.rs:1828`, `el/reader.rs:5586`), `into_parts(self) ->
  (RlpxConnection<S>, u64, Option<u64>, Status, Hello)`
  (`el/eth/session.rs:365`). Named structs are the idiom.
- **Bools where enums belong**: 27 public functions take a `bool` parameter
  (`set_tor_enabled(on: bool)`, `tor_candidates(snap_only: bool)`,
  `record_snap_failure(addr, witnessed: bool)`, `for_finalized(finalized: bool)`
  …), and `clippy::struct_excessive_bools` flags four result structs:
  `el/reader.rs:439` `VerifiedAccount` carries `exists`, `peer_proof_valid`,
  `beacon_chain_verified`, `bls_verified`, `matched_beacon_slot: i64`,
  `verify_method: Option<&'static str>`, `fail_reason: Option<&'static str>`
  (`VerifiedStorage` `:504` and `VerifiedCode` `:539` repeat the set). Its
  doc says why — "twin of the Java `AccountProofResult`" — and the JSON shape
  is golden-pinned, but the Rust-side type can still be a `Verification`
  enum (`Verified { method, slot }` / `Failed { reason }`) that *serializes*
  to that shape.
- **Derive hygiene**: 76 of 270 public structs/enums lack `Debug`
  (`myotis-wire/src/rlpx/frame.rs:59` `FrameEncoder`, `myotis-core/src/nodekey.rs:24`
  `NodeKey` — fine to omit for a secret, but then a manual redacting `Debug`
  is the idiom — `myotis-net/src/sync.rs:1262` `SyncHandle`,
  `el/pool.rs:1515` `PeerPool`, `el/reader.rs:1968` `ElReader`, …); only
  2 derive `Hash`; `clippy::derive_partial_eq_without_eq` flags 5.
- `#[must_use]` appears once in the tree; `clippy::must_use_candidate`
  counts 463 candidates and `return_self_not_must_use` 7 builder-style
  methods (`myotis-evm/src/database.rs:136`, `consensus/fork.rs:103`).
- `Option<Option<T>>` is used knowingly in `myotis-evm/src/cache.rs:44`
  ("so the two absents stay distinct") and allowed in `el/tx.rs:403`; a
  two-variant enum (`Cached::Absent` / `Cached::Present(T)`) says the same
  thing without the lint.

### 4.5 Module size and cohesion (B)

Eleven files are over 2 000 lines; the production/test split shows the
production part is still very large:

| file | total | production | in-file tests |
|---|---|---|---|
| `myotis-net/src/el/reader.rs` | 18 288 | 12 377 | 5 911 (19 separate `#[cfg(test)]` modules) |
| `myotis-engine/src/host.rs` | 6 451 | 5 639 | 812 |
| `myotis-net/src/sync.rs` | 5 888 | 4 262 | 1 626 |
| `myotis-net/src/el/pool.rs` | 4 535 | 3 190 | 1 345 |
| `myotis-evm/src/executor.rs` | 4 023 | 1 437 | 2 586 |
| `myotis-net/src/el/logindex.rs` | 3 719 | 1 923 | 1 796 |
| `myotis-net/src/reqresp.rs` | 3 104 | 2 085 | 1 019 |
| `myotis-net/src/el/discv4.rs` | 2 537 | 1 515 | 1 022 |
| `myotis-engine/src/eljson.rs` | 2 342 | 1 101 | 1 241 |
| `myotis-evm/src/ens/mod.rs` | 2 211 | 982 | 1 229 |
| `myotis-net/src/el/evm.rs` | 2 043 | 1 480 | 563 |

Twenty production functions are longer than 150 lines, eight longer than
300: `myotis-net/src/sync.rs:2992` `catch_up` (544 lines), `roost/src/serve.rs:403`
`serve` (505), `sync.rs:2045` `run_sync` (443), `el/reader.rs:5121`
`log_index_backfill_batch` (379), `el/reader.rs:2429` `set_log_index_config`
(335), `el/reader.rs:3626` `log_index_tail_tick` (326), `el/reader.rs:4343`
`log_index_bridge_step` (323), `el/evm.rs:1037` `prefetch_batch` (301),
`myotis-rpcd/src/rpc.rs:574` `dispatch` (284),
`roost/src/main.rs:329` `ingest` (235), `el/pool.rs:1284` `dial_one` (227),
`cl_fork_watch.rs:340` `evaluate_locked` (188), `el/reader.rs:3365`
`log_index_append_tick` (187), `engine/host.rs:695` `spin_up` (183),
`myotis-node/src/scheduler.rs:394` `state` (176), `myotis-rpcd/src/main.rs:142`
`run` (175), `roost/src/main.rs:152` `probe` (169), `el/peer.rs:1111`
`read_loop` (155), `el/pool.rs:2855` `maintainer_loop` (154),
`engine/host.rs:5611` `get_logs_json_impl` (153). Fifteen `#[allow(clippy::too_many_arguments)]`
(six of them in `el/reader.rs`, four in `myotis-evm/src/executor.rs`) and four
unsuppressed hits (`el/pool.rs:1522` takes 11 arguments) point the same way:
parameter structs and smaller units. The reviewers name the seams per file in
§5.

Two smaller structure points:

- Nine four-line **re-export shim modules** keep pre-#505 paths alive —
  `myotis-net/src/{codec,protocols,status}.rs`, `el/eth/messages.rs`,
  `el/rlpx/{ecies,frame,handshake}.rs`, `el/snap/{fetch,messages}.rs` — each
  `pub use myotis_wire::…::*;`. A glob re-export per file is the least
  idiomatic shape for this: one module re-export per parent — `pub use
  myotis_wire::eth2::{codec, protocols, status};` in `lib.rs`, `pub use
  myotis_wire::rlpx::{ecies, frame, handshake};` in `el/rlpx/mod.rs`, and so
  on — keeps every existing path working with no extra files, lets rustdoc
  show the original item docs instead of "Moved to…", and stops every future
  `pub` item of the wire module from entering this crate's API unreviewed.
- `myotis-net/src/el/mod.rs:10–40` lists its 28 submodules in no order
  (`feecache` and `tasks` private among public ones, `tor` with a doc comment,
  `torreserve` `pub(crate)`); `clippy::redundant_pub_crate` (24 sites, 20 in
  `myotis-net`) flags `pub(crate)` items inside already-private modules.

### 4.6 Public surface, std-trait conventions and docs (B/C)

- **Visibility**: 1 073 `pub fn` against 141 `pub(crate)`. In `myotis-net`
  every submodule is `pub mod`, so the whole internal structure (peer pool,
  fee cache, anchor, read stats, …) is the library's public API — the two
  downstream crates (`roost`, `tor-poc`) use a handful of items. The idiom is
  `pub(crate)` by default and a curated set of `pub use` re-exports at the
  crate root, which `myotis-net/src/lib.rs:32–45` already starts
  (`pub use sync::{ChainConfig, SyncHandle, …}`).
- **std traits**: no `FromStr` impl in the tree although hex quantities,
  block tags, enode URLs and ENS names are parsed everywhere (ad-hoc
  `parse_*`/`*_from_hex` functions instead); 7 `From` impls; one
  `IntoIterator` and two `Iterator` impls (`myotis-wire/src/eth.rs:834`/`:850`
  with `ExactSizeIterator`, `myotis-core/src/rlp.rs:184` with `FusedIterator`)
  are the exception and are done right; 8 manual `Default`s next to 47 derived ones;
  `Display` is implemented 17 times, often for things that are then
  `.to_string()`ed into a `String` error.
- **Docs**: the volume is exceptional (every file but two has a `//!` header,
  22 k comment lines), but `cargo doc -W rustdoc::all` reports 23 broken
  intra-doc links (`myotis-engine/src/host.rs:120` `Engine::pending_served_window`,
  `myotis-evm/src/lib.rs:12` `FixtureSnapStateOracle`, six in `myotis-rpcd`,
  six in `myotis-wire`) and 53 public docs linking private items
  (`myotis-bls/src/lib.rs:5` → `jni_shim`, `myotis-evm/src/executor.rs:427`
  → `Self::lowest_working_limit`). `clippy::doc_markdown` (537) and
  `too_long_first_doc_paragraph` (296) are the same symptom: prose written
  as comments, not as rustdoc (identifiers unquoted, no one-line summary).
  `uniffi-bindgen/src/main.rs:1` has no crate docs.

### 4.7 Numeric casts and arithmetic (A/B)

218 `as` casts in production code; clippy's pedantic cast lints find 140
possible truncations (31 in `myotis-wire`, 88 in `myotis-net`), 11 sign
losses, 8 possible wraps. Many are the deliberate kind (`usize` → `u32` after
a bounds check, `count.max(0) as usize` in `myotis-bls/src/lib.rs:122`), but
the pattern is `as` everywhere and `try_from`/`u64::from` (138 sites) only
sometimes, so a reader cannot tell a checked cast from an unchecked one.
Specific sites the reviewers judged reachable from the wire or a host call are
in §5. The idiom: `u64::from(x)` for widening (clippy `cast_lossless`, 30
sites), `usize::try_from(x)?` or `.try_into().map_err(…)` for narrowing on
untrusted values, `as` only on values the local code just bounded. Four
`clippy::manual_saturating_arithmetic` hits (`consensus/types.rs:498`,
`:606`, `:730`, `clcache.rs:126`) spell out `checked_add(…).unwrap_or(MAX)`
where `saturating_add` exists; 20 `manual_is_multiple_of` sites write
`x % n == 0` where `is_multiple_of` (stable 1.87) is clearer.

### 4.8 Async and concurrency (B)

The big picture is right: `std::sync::Mutex` for state that is never held
across an `.await` (102 mentions) and `tokio::sync::Mutex` only where it must
be (29), no `std::thread::sleep` in async production code (the 14 hits are
the blocking `myotis-rpcd` daemon and tests), `async-trait` used exactly once
and only because libp2p's `request_response::Codec` requires it
(`myotis-net/src/reqresp.rs:220`). The findings are second-order:

- **Guard lifetimes**: `clippy::significant_drop_tightening` flags 44 guards
  held longer than their last use — ten in `el/pool.rs` on *tokio* mutexes
  (`:824`, `:947`, `:1237`, `:1661`, `:1777`, `:2501`, `:3196`), where a long
  hold serialises other tasks; `el/anchor.rs:291`, `:324`, `:500`;
  `el/readstats.rs:351`, `:411`, `:451`; `engine/host.rs:918`, `:1152`,
  `:1173`; `evm/database.rs:267`, `:377`, `:476`. The idiom is a block scope
  or an explicit `drop(guard)` right after the critical section.
- **Poisoning policy** (also §4.3): five spellings coexist, up to five in one
  file (`engine/host.rs:301`, `:536`, `:790`, `:885`, `:3121`). Pick one — under
  `panic = "abort"` poisoning is impossible in release, so either a
  workspace-wide `fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T>` helper or
  `parking_lot` (no poisoning, smaller guards) removes the question.
- **Atomic orderings**: 69 `SeqCst` against 138 weaker orderings, with both
  styles inside the same files (`el/reader.rs` 22 `SeqCst`,
  `myotis-evm/src/executor.rs` 19, `el/dnsdisco.rs` 11). Counters and flags
  that are never used to publish other data are `Relaxed` by idiom; `SeqCst`
  by default reads as "not sure", and mixing the two in one file is the worst
  of both.
- **Large futures**: `clippy::large_futures` flags 26 futures over 16 KiB —
  the `eth_call`/`estimate_gas`/`create_access_list` family in
  `el/reader.rs:6783–7076` and their `block_on` callers in
  `engine/host.rs:1861–2447`. On a host-thread stack (the JVM's, iOS's) that
  is worth a `Box::pin` at the top of the chain.
- **Blocking file I/O on tokio worker threads** — found independently by
  five reviewers: the light-client snapshot is written with `std::fs::write` +
  `rename` from the sync loop (`sync.rs:2517`, called at `:2332`, `:2442`,
  `:2476`, `:3504`) and `clcache.flush()` ×4; the EL peer cache's
  `fs::write(path, body).is_ok()` (`el/peercache.rs:587–589` — non-atomic
  truncate-then-write, error swallowed) runs at 14 `cache.flush()` sites inside
  async pool code under a tokio mutex (`el/pool.rs:1083`, `:1301`, `:1463`, …);
  `TorReserve::flush` is the same shape (`el/torreserve.rs:255`);
  `persist_log_index` serializes the whole index under its lock and writes
  with fsync + rename from the async ticks (`el/reader.rs:4001`, `:4043`,
  `:4122`); the engine's per-minute usage ticker does `File::create` +
  `sync_all()` + `rename` inside `engine.rt.spawn` (`engine/host.rs:1266–1271`,
  `usage.rs:219–226`). On a phone's flash an fsync stalls the worker that also
  drives the swarm. `tokio::task::spawn_blocking` (or `tokio::fs`) is the
  idiom, and `el/logindex.rs:1020–1049` `write_atomic` is the in-tree model of
  the durable write itself.
- **`block_on(async { x.await })`** (12 sites, `engine/host.rs:724`, `:768`,
  `:1049`, `:1859`, …): the wrapping `async` block is redundant;
  `rt.block_on(x)` is the idiom.
- `clippy::future_not_send` (3: `el/reader.rs:1371`, `:1547`, `el/evm.rs:845`)
  marks `async fn`s that hold a non-`Send` value across an await; they work
  because they are driven on the current task, but will not `tokio::spawn`.

### 4.9 Strings, formatting and JSON (B/C)

- **Format-argument style is mixed in every crate**: 333 legacy
  `format!("{}", x)` against 497 inline `format!("{x}")`; `myotis-net`
  143/195, `myotis-engine` 61/95, `myotis-rpcd` 43/79, `roost` 44/36. Inline
  captures (1.58) are the current idiom; `cargo clippy --fix` with
  `uninlined_format_args` converts the rest mechanically.
- **JSON by hand**: compound values cross the FFI as JSON strings by design,
  but the shapes are built and parsed with `serde_json::Value`, `json!` and
  `format!` — 388 `Value`/`json!` sites, 32 `format!`-with-escaped-quotes
  sites, 12 `format_push_string`, against **one** `#[derive(Serialize)]`
  (`myotis-engine/src/catalog.rs:11`). `myotis-engine/src/eljson.rs` (1 101
  production lines) is a hand-written serializer for a dozen DTOs. The
  idiom — `#[derive(Serialize, Deserialize)]` structs with
  `#[serde(rename_all = "camelCase")]` and `skip_serializing_if` — keeps the
  golden-pinned shapes (the tests stay the pin) and deletes most of the file.
- **Hex**: `format!("{:02x}")` loops and `format_collect` (14 production
  sites: `myotis-core/src/keccak.rs:47`, `trie.rs:373`,
  `myotis-evm/src/ens/mod.rs:1060`, …) re-implement hex encoding per file; a
  small shared `hex` helper (or the `hex`/`const-hex` crate the std-featured
  crates could take) is the idiom.

### 4.10 `unsafe` and FFI (B, one A-class habit)

`unsafe` is confined to four places — `myotis-engine/src/capi.rs` (39 `unsafe
fn`s), `myotis-node/src/{lib,scheduler}.rs` (77 `unsafe {}` blocks and 3
`unsafe extern "C"` callbacks), `myotis-engine/src/usage.rs` (2 blocks,
`localtime_r`), `myotis-rpcd` (2 blocks) — which is the right shape, and `catch_unwind` is absent
everywhere, which is correct under `panic = "abort"`. Hygiene around it is
not idiomatic:

- **Three `// SAFETY:` comments in the whole production tree**
  (`myotis-engine/src/usage.rs:245`, `myotis-rpcd/src/checkpoint.rs:80`,
  `seeds.rs:60`; two more in tests) against 77 `unsafe {}` blocks in
  `myotis-node` and 39 `unsafe fn`s in `capi.rs`. `capi.rs` documents 31 of
  those 39 with the *caller*-side `/// # Safety` section (good), but
  the *implementer* side is absent: the bodies have no explicit `unsafe {}`
  block at the deref sites — they rely on edition-2021's implicit unsafe-fn
  body (`capi.rs:27–31` `read_string`, `:174`, `:738`), which
  `unsafe_op_in_unsafe_fn` (warn-by-default in edition 2024) rejects — and a
  nested `unsafe fn path<'a>(p: *const c_char) -> Option<&'a str>` returns an
  unbounded lifetime (`:170–174`). `clippy::missing_safety_doc` finds 7
  functions without the section (`:980`, `:992`, `:1022`, `:1044`, `:1051`,
  `:1058`, `:1071`). In `myotis-node` the ownership transfers whose soundness
  rests on non-local facts (`scheduler.rs:88–89` `Box::from_raw(data.cast::<Completion>())`)
  carry no comment, and raw Node-API pointers are stored as `usize` to be
  `Send` (`:36`, `:52`, `:56`) where a newtype with `unsafe impl Send` and the
  invariant in a comment is the idiom.
- **`myotis-node` wraps every C-ABI call in `unsafe { … }`** — including the
  safe ones (`lib.rs:92` `unsafe { myotis_init() }`, `:99`, `:105`) — and
  silences the resulting lint crate-wide: `lib.rs:22`
  `#![allow(unused_unsafe)] // capi fns are a mix of safe/unsafe; calls are wrapped uniformly`.
  Uniformity is not the idiom here: an `unsafe` block is a claim that the
  programmer checked an invariant, and a blanket one says nothing. Mark only
  the 37 genuinely `unsafe extern "C"` entry points (the other 17 are safe
  `pub extern "C" fn`s, e.g. `capi.rs:49`, `:137`, `:145`).
- **`unsafe` is not where the pointers are**: in `capi.rs` the entry points
  that take a `*const c_char` are rightly `pub unsafe extern "C" fn`, but so
  are three that take only integers — `capi.rs:1022`
  `myotis_log_index_status_json(handle: i64)`, `:1044`
  `myotis_address_activity_json(handle: i64, after_block: i64)`, `:1051`
  `myotis_read_stats_json(handle: i64)` — while their pointer-free siblings
  (`:137` `myotis_start(handle: i64)`, `:49` `myotis_init()`) are safe
  `pub extern "C" fn`s. The `unsafe` keyword on an FFI export is a statement
  about preconditions the caller must uphold; a function with none should not
  carry it (and these are three of the seven without a `# Safety` section).
- `clippy::elidable_lifetime_names` flags 26 `<'env>` lifetimes in
  `myotis-node/src/lib.rs` that elision covers.
- Edition 2024 would make the remaining `#[no_mangle]` (54 in `capi.rs`)
  `#[unsafe(no_mangle)]` and `extern "C"` blocks `unsafe extern`, which is
  the current spelling of the same contract.

### 4.11 Manifests, features and lint configuration (B/C)

- **No `[workspace.dependencies]`**: `tokio = "=1.52.3"` is pinned in
  `myotis-net` and `myotis-engine` separately (and again as a dev-dependency),
  `tracing = "=0.1.44"` in four crates, `serde_json = "1"` in six,
  `uniffi = "0.32"` in two; `edition = "2021"` and `license` are repeated in
  all twelve manifests although `version`/`rust-version` already use
  `.workspace = true`. One table keeps the pins the release sweep already
  worries about in one place.
- **No `[workspace.lints]`**: the lint policy lives on a command line in
  `.github/workflows/rust-clippy.yml` (`-D clippy::incompatible_msrv`) and in
  15 scattered `#[allow(clippy::too_many_arguments)]`. A manifest
  `[workspace.lints.clippy]` table (with `[lints] workspace = true` per
  crate) is where a ratchet is declared so `cargo clippy` locally and in CI
  agree; the 65 default-lint sites in Appendix A are what stands between the
  lane and `-D warnings`.
- **Edition 2021 on MSRV 1.91**: edition 2024 (1.85) is available and is the
  current idiom (`unsafe extern`, `#[unsafe(no_mangle)]`, `let` chains in
  1.88, the new `impl Trait` capture rules, `gen` reserved);
  `cargo fix --edition` does most of it.
- **`#[allow(unused_imports)] use alloc::{…, format, string::{String, ToString}, vec, vec::Vec};`**
  heads 17 files in the no_std crates (`myotis-wire` 11, `myotis-consensus`
  6) because with `std` on the names are in the prelude and the import goes
  unused. It works, but it blinds a useful lint per file; the idiom is a
  crate-private `prelude` module (`pub(crate) use alloc::{…}`) imported with
  one `use crate::prelude::*;`, or per-file imports of what the file uses.
- **Manifest text that is no longer true**: `myotis-net/Cargo.toml:51`
  `snap = "=1.1.1"` has no remaining use after #505 (the Snappy code moved to
  `myotis-wire`, which pins its own — `cargo udeps` or
  `#![warn(unused_crate_dependencies)]` would catch it); `myotis-evm/Cargo.toml:29`
  says every dependency is exact-pinned while `serde_json = "1"`;
  `myotis-consensus/Cargo.toml:14` pins `sha2 = "0.10"` where `myotis-core`
  pins `=0.10.9`; `myotis-net/Cargo.toml:6` still describes the crate as
  "consensus-layer networking" though it holds the whole EL stack, and
  `myotis-engine/Cargo.toml:6` as a "JNI cdylib" though `lib.rs:4` says the
  hand-JNI shims are gone.
- `exclude = ["tor-poc", "roost"]` with their own `Cargo.lock`s and a
  path dependency back into the workspace is unusual but well argued
  (`panic = "unwind"`, build cost) — not a finding, only a note that three
  lock files is the price.

### 4.12 Tests (positive, with two C notes)

Test code is 44 k lines, close to production. The shape is idiomatic:
conformance corpora shared with the Java twin under `rust/testdata/`,
`tests/` integration tests, `#[ignore]`d live-network tests gated by
environment, `#[tokio::test(start_paused = true)]` for timing invariants.
Two C-level notes: `myotis-evm/src/executor.rs` and `myotis-engine/src/eljson.rs`
carry more test than production lines in one file (2 586 vs 1 437 and
1 241 vs 1 101) — a `tests/` directory or `executor/tests/` (which already
exists for two files) would shorten the files that §4.5 is about; and
`clippy::items_after_test_module` (`myotis-engine/src/capi.rs:742`) places
production items after a test module.

### 4.13 Logging (positive)

`tracing` with structured fields is the norm (171 field-style calls vs 38
message-only); `println!`/`eprintln!` in library code are confined to
`#[cfg(test)]` skip notices and the two binaries (`myotis-rpcd`'s access log,
`roost`), plus four `eprintln!` in `myotis-node/src/scheduler.rs:122–233` for
a poisoned scheduler where no logger is reachable — defensible as a last
resort, with one caveat: `eprintln!` panics on a stderr write error such as
`EPIPE` (std ignores only a closed descriptor), which under `panic = "abort"`
kills the host; `let _ = writeln!(std::io::stderr(), …)` is the panic-free
spelling (§5.9).

### 4.14 Comments that are wrong about the code (A-class per the rubric, cheap to fix)

The project's heavy comment style is a strength only while the comments are
true. The reviewers found these contradictions between prose and code; none
has a runtime effect, each costs a maintainer a wrong assumption:

- `myotis-net/src/lib.rs:21–22` "no global mutable state" — `traffic.rs:107`
  `static DISCV5`, `el/request.rs:30–31` two static semaphores, `el/tor.rs:52–73`
  five statics including a bootstrapped `TorClient`, `el/pool.rs:2217` contact
  logs, `engine/host.rs:175` the engine itself.
- `myotis-consensus/src/store.rs:37–38` "REFUSES zero rather than defaulting
  to the mainnet preset" — true of `new()`, which asserts it, false of the type:
  `#[derive(Default)]` lets a zero in by another door and `slots_per_period()`
  silently substitutes 8192 (`:17`, `:53–59`).
- `myotis-net/src/el/reader.rs:1977–1980` "Only read on the `tor` feature" +
  `allow(dead_code)` on `eth_cfg`, read at `:2956`, `:3340`, `:4277`.
- `el/peer.rs:323` "Negotiated eth version (66-69)" — branches on `>= 70`/`>= 71`.
- `el/served.rs:11–13`, `:181–182` "no genesis header RLP is embedded" — it is
  (`:38–79`, `:138`).
- `el/anchor.rs:161–162` "Cloneable handle" — `ExecAnchor` has no `Clone`.
- `el/reader.rs:10050–10053` "in four places" — six callers today.
- Doc comments attached to the wrong item, so rustdoc renders the wrong text:
  `reqresp.rs:619–643` (`external_address`'s doc on `observe_via`),
  `reqresp.rs:1063–1078` (`start_host_with`'s on the private `build_swarm`),
  `discovery.rs:199–211` (`seed_bootnodes`' on `node_id_for_peer`),
  `el/reader.rs:4885–4917`, `engine/host.rs:2665–2678`
  (`get_transaction_receipt_json`'s on `pending_nonce_overlay`).
- `engine/host.rs:3390–3391` and `engine/eljson.rs:3–4` claim a hand-built key
  ordering — the `serde_json::Map` half emits alphabetical order (verified:
  `preserve_order` is enabled nowhere), and the golden test at `eljson.rs:2235`
  pins that incidental order.
- `myotis-evm/src/database.rs:332–335` says a fetch is skipped that is
  unconditional; `executor.rs:1430–1431` names a `run` function that does not
  exist; `Cargo.toml:29` "exact-pinned like every workspace dep".
- Post-#505 leftovers in `myotis-wire`: `eth.rs:4–5` links `[super::session]`
  (not in this crate); `discv4.rs:14–17` describes a table and limiter that
  live in `myotis-net`; `snap/messages.rs:23–25` names `rlpx::transport::encode_hello`
  and a round-trip test that does not exist; `snap/messages.rs:438–441` and
  `snap/fetch.rs:14–18` call finished wiring "deferred to EL-A7".
- `myotis-core/src/enr.rs:42–44` doc promises an `enr:` prefix the parser does
  not require; `rlp.rs:8` "a ~250-line codec" (966 lines).
- `myotis-net/Cargo.toml:6` and `myotis-engine/Cargo.toml:6` descriptions (§4.11).

### 4.15 Correctness notes found on the way (not idiom, reported because they were seen)

- `roost/src/serve.rs:578–581`: `tokio::signal::ctrl_c()` is re-created per
  `select!` iteration, so a SIGINT arriving while the tick body runs (REST
  calls, probe dials) is dropped — a Ctrl-C during a tick does nothing, one
  while the loop is parked on `ctrl_c()` works; SIGTERM is never handled. Pin
  one future before the loop.
- `roost/src/serve.rs:534`, `:1130`, `:1139`: `/ip4/{ip}` formatted around an
  address `upstream_external_ip` deliberately lets be IPv6 (`:1094–1101`) — the
  unparseable multiaddr `dialable()`'s doc exists to prevent. Log line only.
- `myotis-net/src/el/reader.rs:9761–9771`: `stop()` calls `h.abort()` on the
  log-index task and immediately writes the final checkpoint and stops the
  pool; `abort()` takes effect at the next yield, so a tick may still be
  writing. `h.abort(); let _ = h.await;` first.
- `el/reader.rs:14228–14282`: `ChunkSizer` updates five `Relaxed` atomics in
  non-atomic read-modify-write groups behind `&self`; safe only because one
  task drives it. A `Mutex<SizerState>`.
- `myotis-consensus/src/store.rs:17`, `:53–59`: `LightClientStore::default()`
  yields a store whose `slots_per_period()` silently answers 8192 (latent, no
  production caller).
- `myotis-evm/src/ens/mod.rs:409–414`: `resolve_ownership`'s `chain_id` is
  `debug_assert_eq!`'d and then shadowed — accepted and ignored in release.
- `myotis-engine/src/host.rs:1442`: `set_ws_bound_periods` turns a negative
  value into "restore the default" (`periods.max(0) as u64`) instead of
  refusing.
- `myotis-net/src/el/rlpx/transport.rs:364–380`: four `expect("OS entropy")`
  on every dial, in functions whose callers already return `Result`; the only
  input-reachable abort the review found (early-boot/seccomp `getrandom`
  failures), while `discv4.rs:1386` and `dnsdisco.rs:543` ignore the same
  failure silently.
- `myotis-consensus/src/types.rs:640–642` vs `:759–762`: `LightClientUpdate::decode`
  checks only the upper bound of `attested_offset`, its sibling both — a parity
  question for the Java twin.
- `myotis-consensus/src/snapshot.rs:460`, `:496`, `:548`: ungated `std::fs` in
  tests of a `no_std` crate — `cargo test --no-default-features` cannot compile
  (CI only builds that configuration).
- `myotis-engine/src/capi.rs:984–987`: a NULL `filter_json` yields a NULL
  result, which the Node binding renders as a *retryable* error for a permanent
  caller fault; `:268` turns NULL into `""`; `:381–385` refuses it — three
  policies on one ABI.
- Five `el_*_conformance` tests return green when their committed corpus
  directory is missing (`myotis-net/tests/el_discv4_conformance.rs:34–37` and
  four siblings).

## 5. Per-crate assessment

Eleven read-throughs against one rubric, every quoted line verified against
the source before inclusion. Severity as in §4; the C counts are aggregated
patterns, not sites. **No panic reachable from peer input or a host call was
found in any crate**, with one low-likelihood exception
(`rlpx/transport.rs:364–380`, §5.6). The A entries are mostly comments that
contradict the code (listed together in §4.14) plus a handful of small real
bugs (§4.15).

| scope | A | B | C |
|---|---|---|---|
| §5.1 `myotis-bls`, `myotis-core`, `myotis-consensus` | 1 | 19 | 31 |
| §5.2 `myotis-wire` + `myotis-net` root modules | 1 | 28 | 24 |
| §5.3 `myotis-net` `sync.rs`, `reqresp.rs`, `cl_fork_watch.rs` | 0 | 29 | 28 |
| §5.4 `myotis-net/src/el/reader.rs` (two halves) | 1 | 26 | 23 |
| §5.5 `myotis-net/src/el` `pool.rs`, `logindex.rs`, `evm.rs` | 0 | 24 | 24 |
| §5.6 `myotis-net/src/el` discovery, peers, cache, sessions | 3 | 25 | 39 |
| §5.7 `myotis-net/src/el` fifteen smaller modules, `tests/`, `examples/` | 2 | 27 | 19 |
| §5.8 `myotis-evm` | 0 | 24 | 39 |
| §5.9 `myotis-engine`, `myotis-node`, `uniffi-bindgen` | 0 | 35 | 38 |
| §5.10 `myotis-rpcd`, `roost`, `tor-poc` | 2 | 24 | 38 |
| **total** | **10** | **261** | **303** |

### 5.1 `myotis-bls`, `myotis-core`, `myotis-consensus` — the sans-I/O core

**Verdict.** The strongest part of the workspace. `myotis-core` has **zero**
`unwrap`/`expect` in production code, `checked_add`-guarded slicing on every
untrusted length (`rlp.rs:190`, `:335–338`), lengths accumulated in `u64`
for 32-bit targets (`:431–443`), an iterative trie walk with an explicit
visit bound (`trie.rs:104–121`), compile-time CRC tables (`forkid.rs:82–129`)
and a zero-allocation `View`/`ViewIter`/`ListBuf` API with differential tests
(`rlp.rs:111–245`, `:661–732`). `myotis-bls` is a tidy wrapper whose JNI shim
contains no `unsafe` at all. `myotis-consensus` is logically careful and very
well tested (spec vectors, synthetic-BLS boundary tests, resume equivalence)
but the least idiomatic of the three. No panic reachable from wire input was
found in any of them. Counts (production): unwrap/expect 0 / 0 / 28 (all
guarded), `as` 1 / 23 / 13, clone 0 / 13 / 8, `Result<_, String>` 0.
Findings: A 1 (latent), B 19, C 31.

- **[A, latent — a documented invariant the type does not hold]** `new()`'s
  doc (`myotis-consensus/src/store.rs:37–38`) says the store "REFUSES zero
  rather than defaulting to the mainnet preset", and `new()` does assert it
  (`:44`) — but the struct is `#[derive(Default)]` (`:17`), so
  `LightClientStore::default()` holds `slots_per_period == 0`, and
  `slots_per_period()` (`:53–59`) then silently substitutes 8192: zero gets in
  by another door and is defaulted exactly as the doc says it never is. No
  production caller uses `Default` (`sync.rs` goes through `new(..)`), so it is
  latent; drop the derive or make the accessor return the field.
- **[B] 25 guarded `.unwrap()`s in the hand-rolled SSZ decoders**
  (`types.rs:56–58` `slot: ssz::read_u64(ssz_bytes, 0).unwrap()`, `:231–232`,
  `:604`, `:619–621`, `:727–728`), each correct only because of a length check
  several lines earlier — while `snapshot.rs:315–342` in the same crate
  already owns a checked cursor (`struct Reader` with `checked_add` and `?`)
  that would remove all of them. The `pub` readers `ssz.rs:170–182` compute
  `offset + 4` unchecked and `try_into().unwrap()`.
- **[B] `padded_root` (`ssz.rs:87–91`) guards a slice with `debug_assert!`
  only** — a > 32-byte input aborts in release; both callers pass fixed arrays,
  so `padded_root<const N: usize>(b: &[u8; N])` with a const assert says so.
- **[B] `SyncCommittee`/`SyncAggregate` expose `pub` fields whose length
  invariants their methods index on** (`types.rs:98`, `:121–123`, `:183–185`);
  `snapshot.rs:297–303` carries a "defensive" pad/truncate because the type
  lacks the invariant. `Box<[[u8; 48]; 512]>` or a private field with
  `TryFrom<&[u8]>`.
- **[B] `process_update`/`process_finality_update` return a bare `bool`**
  (`store.rs:314`, `:472`) while their siblings return `FinalityOutcome` /
  `Result<(), BootstrapReject>`; the eight `return false` sites each name a
  distinct cause only in a `tracing::debug!`, and `tests/gloas_boundary.rs:311–353`
  has to install a subscriber and string-match log text to learn which gate
  fired. About 45 lines are duplicated between the two (`:372–419` vs
  `:490–532`) and have already drifted (the finality path lost its logs).
- **[B] Stringly newtype errors**: `CoreError(pub String)` with callers
  reaching into `.0` (`header.rs:223`, `trie.rs:135`, `:175`, `enr.rs:59`);
  `SszError`/`CodecError` gate `std::error::Error` on the `std` feature
  (`types.rs:26–27`) where `myotis-core` uses `core::error::Error`.
- **[B] `Root` is an alias, slots/epochs/periods bare `u64`**: `verify_merkle_branch(leaf:
  &Root, …, root: &Root)` (`ssz.rs:125–131`), `compute_domain(domain_type: &[u8; 4],
  fork_version: &[u8; 4])` (`verify.rs:13–16`), `update_finalized(header, slot:
  u64)` called with `signature_slot` for optimistic and `beacon.slot` for
  finalized (`store.rs:80`, `:451–452`).
- **[B] `assert!` constructors** (`fork.rs:81–83`, `store.rs:44`, `spec.rs:115`)
  abort the host at start-up on a mis-built constant; `const fn` + `const _:
  () = assert!(..)` at the pin sites (the pattern `types.rs:800–812` already
  uses) or a `Result`.
- **[B] Decoder asymmetry**: `LightClientUpdate::decode` checks only the upper
  bound of `attested_offset` (`types.rs:640–642`) while `LightClientFinalityUpdate::decode`
  checks both (`:759–762`) — a parity gap to confirm against the Java twin.
- **[B] no_std hygiene in tests**: `snapshot.rs:460`, `:496`, `:548` use
  `std::fs` inside `#[cfg(test)]` without a gate, so `cargo test -p
  myotis-consensus --no-default-features` cannot compile; CI only *builds*
  that configuration (`myotis-core/src/rlp.rs:891–897` gates its equivalent).
- **[B] `myotis-core`**: five identical `match f.next()` blocks and helpers
  taking `Option<View>` (`header.rs:103–122`); trie children cloned out of a
  tree that stays alive (`trie.rs:254`, `:304`); `Enr::from_enr_string`
  instead of `FromStr`, and it accepts a missing `enr:` prefix its doc says is
  required (`enr.rs:42–44`); 19 `let mut out = [0u8; N]; out.copy_from_slice(..)`
  sites where `try_into()`/`.into()` is the idiom (`keccak.rs:10–12`,
  `nodekey.rs:51`, `trie.rs:187`); `BlockHeader::encode` builds an owned
  `Item` tree (7 clones + 9 `to_vec`) where the crate's private
  `rlp::write_*` helpers could stream (`header.rs:183–215`).
- **[B] `myotis-bls`**: `fast_aggregate_verify(pubkeys: &[u8], n: usize, ..)`
  carries a count the slice already encodes (`lib.rs:43`, `:65`); every
  verification verdict in the three crates is a bare `bool` with no
  `#[must_use]` (`lib.rs:43`, `ssz.rs:125`, `verify.rs:36`, `store.rs:611`).
- **[C]** `u8 as usize` beside `usize::from` in one file (`rlp.rs:397` vs
  `:263`); 9 `match … { Some(x) => x, None => return err }` where `let-else`
  fits (`rlp.rs:388–391`); `Vec<u8>` for the 20-byte beneficiary and 256-byte
  bloom (`header.rs:29–35`, documented Java parity); `fn of(..)` as a
  constructor name (`bloom.rs:43`); `forks: Vec<(u64, [u8; 4])>` read as
  `.0`/`.1` with a manual linear search where `partition_point` fits
  (`fork.rs:66`, `:171–182`); 73 undocumented `pub` items in
  `myotis-consensus`; `blst`/`sha2` versions pinned differently across the
  three manifests; test helpers duplicated across six integration-test files
  (`tests/common/mod.rs` is the idiom).
- **Positives**: `snapshot.rs`'s checked `Reader`; `const _: () = assert!(..)`
  size proofs (`types.rs:800–812`); `HeaderExecution { Payload(Box<..>),
  BlockHash(Root) }` and `LcFork` as enums; a hand-written `Debug` for
  `SyncCommittee` that does not dump 24 KiB (`types.rs:144–148`);
  `FusedIterator` on `ViewIter`; the allocation-counting test binary
  (`tests/rlp_alloc_bound.rs`, one of the tree's five `// SAFETY:` comments);
  `tests/conformance.rs` pinning the production DST against the fixture DST in
  both directions.

### 5.2 `myotis-wire` and the `myotis-net` root modules (`lib.rs`, `discovery.rs`, `clcache.rs`, `traffic.rs`, the shims)

**Verdict.** `myotis-wire` is a careful sans-I/O crate: every slice into
attacker-controlled bytes sits behind an explicit length check, the built-in
Snappy decoder is written entirely with `get()`/`checked_add` and property-tested
against the reference decoder (`snappy.rs:246–273`, `:398–436`), DoS caps are
applied before any allocation (`rlpx/frame.rs:227–229`, `eth2/codec.rs:102–118`,
`snappy.rs:234–237`), MACs are compared in constant time (`rlpx/ecies.rs:90`,
`rlpx/frame.rs:181`, `:209`), and the newer code uses let-else, borrowed views
(`eth.rs:783–864` `RawList` with `IntoIterator` + `ExactSizeIterator`) and `Cow`
well. No `unsafe`, no `println!`, no file over 2 k lines, no panic reachable
from production input. The `myotis-net` root modules are sound async (no std
guard across an await, with the reason written down at `discovery.rs:465–469`;
`Relaxed` atomics; structured tracing) with un-idiomatic surfaces. Counts
(production): wire — unwrap/expect 12 (all guarded or infallible), `as` 33,
clone 7, `Result<_, String>` 5; net root — unwrap/expect 11, `as` 5, clone 16,
`Result<_, String>` 5; unsafe 0. Findings: A 1 (doc), B 28, C 24.

- **[A — comment contradicts code]** `myotis-net/src/lib.rs:21–22` promises
  "no global mutable state", but `traffic.rs:107` is `static DISCV5:
  Mutex<Discv5Ledger>` (justified by discv5's process-wide metrics, and the
  reason its tests use a local ledger); `el/request.rs:30–31` and `el/tor.rs`
  add more statics (§5.7). Name the exceptions in the crate doc.
- **[B] Error classification by substring, load-bearing across crates**:
  `snap/fetch.rs:47–72` defines `PROOF_INVALID_MARKER = "proof invalid"` and
  `is_unservable_root_error(error: &str) -> bool { error.contains(..) }`, with a
  comment calling the substring "LOAD-BEARING" and asking to keep format
  strings "in sync" with `trie.rs`; `el/reader.rs:6026` and `:6290` branch
  peer-routing on it directly and `:5709`, `:6381`, `:6614` and `el/evm.rs:855`
  through the sibling `is_unknown_root_error` (`:70`). A typed
  `FetchError { ProofInvalid { kind, reason }, Transport(..) }` is the idiom.
- **[B] Three string-error shapes in one crate**: `CodecError(pub String)`
  (`eth2/codec.rs:28`), bare `String` (`rlpx/hello.rs:79`, `eth2/status.rs:42`,
  `:57`, `snappy.rs:83`, `:141`) and `CoreError`; `hello.rs:88–106` does
  `.map_err(|e| e.0)?` eight times and `map_err(|e| format!("hello: {}", e.0))`
  twice to turn one into the other;
  `#[cfg(feature = "std")] impl std::error::Error for CodecError` (`:35–36`)
  where `core::error::Error` is available.
- **[B] Wire-declared `u64` lengths narrowed with `as usize`, one unchecked
  accumulator**: `eth2/codec.rs:186`, `:256`, `:334`, `:399`, `:440` — `read_varint`
  admits values to 2^35−1, so on a 32-bit target the cast truncates (the comment
  at `:178–181` documents the hazard for one path and leaves four); `:436` and
  `:440` add attacker-chosen sizes with plain `+=` (wraps in release). No shipped
  target is 32-bit, hence B: `usize::try_from` once and `saturating_add`.
- **[B] Raw arrays for distinct concepts**: `encode_get_storage_ranges(request_id,
  state_root: &[u8; 32], account_hash: &[u8; 32], starting_hash: &[u8; 32],
  limit_hash: &[u8; 32], ..)` (`snap/messages.rs:232–239`); `SessionSecrets`'
  four interchangeable `[u8; 32]`s (`rlpx/handshake.rs:30–41`); `fork_version:
  [u8; 4]` in and `fork_digest: [u8; 4]` out of the same type (`eth2/status.rs:127–146`);
  `encode_status69` with eight parameters, five of them `u64`, while the decode
  side already has `pub struct Status` (`eth.rs:143–152` vs `:60–72`); every
  `decode_*` returns `(u64, Vec<_>)` tuples; `fork_digest: Vec<u8>` that is
  either 4 bytes or empty (`eth2/codec.rs:193–199`) where the encoder side
  already uses `Option<[u8; 4]>`.
- **[B] Slice parameters that are always 16 bytes, indexed to 16**:
  `update_mac(&mut self, seed16: &[u8])` with `for i in 0..16 { block[i] ^=
  seed16[i]; }` (`rlpx/frame.rs:304–310`) — `&[u8; 16]` excludes the panic by
  type; `encode_frame` silently truncates the body length to 24 bits
  (`:142–155`) with no check symmetric to the decoder's `MAX_FRAME_BODY_SIZE`.
- **[B] Protocol ids as `&str` dispatched by `match` with a silent `_ => 0`**
  (`eth2/protocols.rs:84–92`; also `:57–77`) — an `enum Eth2Protocol` with
  exhaustive `match self` methods.
- **[B] One-shot handshake behind `&self`, cloning the auth wire twice**
  (`rlpx/handshake.rs:146`, `:151`, `:178`; the only caller never touches
  `initiator` again) — `process_ack(self, ..)`.
- **[B] Comments that no longer describe the code after the #505 move**:
  `eth.rs:4–5` links `[super::session]`, which does not exist in the wire
  crate; `discv4.rs:14–17` describes a Kademlia table and rate limiter that
  live in `myotis-net/src/el/discv4.rs:55`, `:163`; `snap/messages.rs:23–25`
  names `rlpx::transport::encode_hello` (now `rlpx::hello`) and claims a
  round-trip test pins `OUR_SNAP_VERSIONS` to the Hello capabilities — no such
  test exists; `snap/messages.rs:438–441` and `snap/fetch.rs:14–18` call the
  empty-responder wiring "deferred to EL-A7" though `peer.rs:1341–1354` has it.
- **[B] `discovery.rs`**: `Result<(JoinHandle<()>, Arc<AtomicUsize>), String>`
  from `spawn` (`:137–140`) while the server side returns a struct
  (`ServerDiscovery`, `:955`); five `Result<_, String>` entry points; `run_lookups`
  takes ten positional parameters (`:244–256`); `seed_bootnodes`' doc is glued
  onto `node_id_for_peer` (`:199–211`); `.expect("seen lock")` ×7 vs
  `traffic.rs:144`'s poison-tolerant lock; `&Option<Arc<..>>` parameter (`:589`);
  an `[u8; 16]` ENR fork-id passed raw and decoded to a 3-tuple (`:573`, `:778`).
- **[B] `clcache.rs`**: the peer cache is five parallel `String`-keyed
  collections kept consistent by hand (`:29–36`, `:244–249`), with
  `self.peers.contains(&addr.to_string())` allocating for an O(n) membership
  test (`:237`, `:269`).
- **[B] `traffic.rs:84` `pub fn new() -> Arc<TrafficMeter>`** (clippy
  `new_ret_no_self`) beside a derived `Default`.
- **[B] Stale dependency**: `myotis-net/Cargo.toml:51` `snap = "=1.1.1"` has no
  remaining use after #505 (the Snappy code moved to `myotis-wire`, which pins
  its own); `cargo udeps` or `#![warn(unused_crate_dependencies)]` would catch it.
- **[C]** 18 `[0u8; N]` + `copy_from_slice` sites where `<[u8; N]>::try_from`
  is used elsewhere in the same crate (`eth.rs:538`); 13 `u8 as usize` vs
  `usize::from` at `rlpx/frame.rs:187`; eight guarded `try_into().expect("length
  checked")` in `eth2/status.rs` that `split_first_chunk` makes panic-free by
  type; `HeadersOrigin` has no derives (`eth.rs:238`), `SessionSecrets` derives
  `Debug` on key material (`rlpx/handshake.rs:29`); `metadata_seq_number() ->
  u64 { 0 }` where a `const` fits (`eth2/status.rs:116`); `fn err<T>(..)`
  defined and then bypassed with `Err(CodecError(format!(..)))` in the same file
  (`eth2/codec.rs:38–40` vs `:104–113`); `lib.rs:4–8` still describes
  `codec`/`protocols`/`status` as implemented in `myotis-net`; `ServerDiscovery`,
  `Discv5Share`, `CountingStream`, `ClPeerCache` without `Debug`.
- **Positives**: the Snappy decoder (`snappy.rs:246–273`); constant-time
  compares via `subtle` exactly where a secret is involved and deliberately
  *not* for the discv4 packet hash (`discv4.rs:181`); decompression bombs
  refused before allocation three times over; `Cow<'_, RawList>` returning
  borrowed eth/66–68 receipts and owned re-canonicalised eth/69 ones
  (`eth.rs:576–629`); `dep:` feature syntax, `tracing?/std`, test-only API behind
  `#[cfg(any(test, feature = "test-util"))]`; pure, testable cores split from the
  async loops (`discovery.rs:506–520` `classify_heard`, `:77–90`
  `rotate_seen_if_changed`).

### 5.3 `myotis-net` consensus-layer networking — `sync.rs`, `reqresp.rs`, `cl_fork_watch.rs`

**Verdict.** Idiomatic in the small, un-idiomatic in the large. `sync.rs`
(5 888 lines, 4 262 production) has excellent async hygiene — bounded
channels, cancel-safe `select!` arms, an abort-on-drop `DiscoveryGuard`
(`sync.rs:2071–2078`), no `std::sync::Mutex` at all, `saturating_*`/`checked_*`
on every peer- or clock-derived number, one `now_unix_ms()` clock seam
(`:138–141`) — and no reachable panic. `reqresp.rs` (3 104 / 2 085) is a
textbook rust-libp2p event loop: `#[derive(NetworkBehaviour)]` with one
`request_response::Behaviour` per protocol (`:308–344`), a single `run_swarm`
task with `select!` over a bounded command channel and
`swarm.select_next_some()` (`:1348–1409`), an actor-style `enum Command` with
`oneshot` replies (`:451–490`), a typed `RequestError` with `Display + Error +
PartialEq` (`:424–449`), and handlers unit-tested with synthetic
`SwarmEvent`s (`:2803–3103`). `cl_fork_watch.rs` (1 055 / 555) is close to
clean: lock released before logging (`:274–305`), overflow-proof clock math
(`:323–327`), `BTreeMap` tallies for determinism. Counts (production):
unwrap/expect 2 / 9 / 0, `as` 6 / 3 / 0, clone 27 / 18 / 1,
`Result<_, String>` 1 / 3 / 0, unsafe 0. Findings: A 0, B 29, C 28.

- **[B] `sync.rs` bundles eight concerns and already marks the seams**:
  `// Chain configuration` (`:36`, with ~520 lines of pinned-peer tables
  `:658–1168`), `// Status snapshot` (`:1170`), `// SyncHandle` (`:1256`),
  `// Peer pool` (`:1370`), `// The sync loop` (`:2041`), `// LC hunt mode`
  (`:2827`), plus the catch-up pipeline (`:2949–3535`) and the CL→EL anchor
  bridge (`:4065–4213`) — `sync/{config,schedule,peer_pool,catchup,finality,status}.rs`
  fall out of the markers.
- **[B] Loop state threaded through 6–11-parameter free functions**:
  `#[allow(clippy::too_many_arguments)] async fn catch_up(config, client, pool,
  processor, status_tx, peer_rx, staged, clcache, resume, last_persisted_period,
  anchor, hunt)` (`:2991–3014`, 11 parameters), `hunt_due` (`:2882`, 10),
  `publish_status`/`try_bootstrap`/`hunt_round` (7 each); every call site
  re-lists the same `&config, &client, &mut pool, &mut processor, &mut clcache`.
  A `struct SyncLoop { … }` with `async fn catch_up(&mut self)` removes the
  lists and both `#[allow]`s.
- **[B] Adjacent positional `bool`s**: `fn candidates(&mut self, n: usize,
  skip_no_lc: bool, respect_cooldown: bool, prefer, skip)` (`:1874`) called as
  `pool.candidates(fanout, false, false, …)` / `(…, true, true, …)` — a
  `CandidateFilter` struct or two enums.
- **[B] Five bare `u64`s meaning slot, slot, count, count**:
  `pub fn light_client_current(period: u64, finalized_slot: u64, wall_slot: u64,
  slots_per_epoch: u64, slots_per_period: u64) -> bool` (`:4133`); also
  `delay_to_next_poll` (`:111`), `sync_state_at` (`:4148`), `feed_exec_anchor`
  (`:4175`). `Slot`/`Epoch`/`Period` newtypes belong in `myotis_consensus::spec`.
- **[B] `i64 = -1` as "unknown"**: `pub sync_start_period: i64` (`:1225`,
  `:1490`), written `… as i64` (`:2398`) and reset to `-1` (`:2432`) — `Option<u64>`
  in Rust, `-1` only where the JSON crosses to the Java twin.
- **[B] A mutating predicate**: `fn poisoned(&mut self, rejects: u32) -> bool`
  (`:2737`) is called both as a read (`!resume.poisoned(0)`) and as a mutation
  (`let _ = resume.poisoned(n)`); split into `note_rejects` + `is_poisoned`,
  and model `ResumeGuard { unconfirmed: bool, rejects }` as the three-state
  enum it is.
- **[B] Blocking `std::fs` inside the tokio task**: `std::fs::write(&tmp, &bytes)
  .and_then(|_| std::fs::rename(&tmp, path))` (`:2517`, from the async loop),
  `std::fs::read` (`:2161`), `remove_file` (`:2425`), `clcache.flush()` ×4 —
  `spawn_blocking`/`tokio::fs` is the idiom on a phone's flash. The temp name
  is built through lossy `path.display()` (`:2512–2516`); `OsString::push` keeps
  non-UTF-8 paths intact.
- **[B] Allocation in a hot lookup**: `id_for_key` formats `"{}/p2p/{}"` for
  every pool entry (up to 512) per call (`:1826–1831`), called per applied
  period; the same key is hand-built at 11 sites — one `Peer::cache_key()`.
- **[B] Same-typed `[u8; 32]` payloads in two orders**: `anchor.update_finalized(slot,
  state_root, number, block_hash, ts)` (`:4086`) vs `update_optimistic(slot,
  number, block_hash, parent_hash, state_root, ts)` (`:4103`) — a swap compiles.
- **[B] 22-field `pub struct ChainConfig` with `Vec<String>` multiaddrs/ENRs**
  parsed at runtime with a `warn!` on failure (`:158–230`, `:2054–2058`) —
  parse the pinned literals once into `Vec<Multiaddr>` / `Vec<Enr>`.
- **[B] Index loops with modular arithmetic** (`for i in 0..len { &peers[(start
  + i) % len] }`, `:1930`, `:1948`, `:1977`, `:2008`) → `iter().cycle().skip(start)`;
  O(n²) `out.iter().any(..)` de-dup → `HashSet`.
- **[B] Hand-rolled hex, duplicated across the crate**: `hex_str` (`:2537`,
  one `String` per byte) beside `el/getproof.rs:42 hex`, `el/eth/session.rs:612
  hex_all`, `el/sent_tx.rs:133 hash_hex`, `reqresp.rs:1863 hex4`/`1869 hex8`,
  and the same six-line `fn hex32` in `sync.rs:650` and `el/reader.rs:11004`
  (differing only in the `expect` text).
- **[B] `reqresp.rs` doc comments attached to the wrong items** — a genuine
  doc bug: the paragraph for `external_address` (`:619–625`) runs without a
  blank line into `observe_via`'s and lands on `observe_via` (`:643`), leaving
  `pub async fn external_address` (`:650`) undocumented; the same at
  `:1063–1078` puts `start_host_with`'s doc ("A server must watch that
  handle") on the private `build_swarm`, and `pub fn start_host_with`
  (`:1165`) has none.
- **[B] Four lock-poisoning policies across three files**:
  `lock().expect("status lock")` (`reqresp.rs:714`, `:717` — an abort under the
  workspace profile), `unwrap_or_else(|e| e.into_inner())` (`:511`, `:1404`,
  `:1582`, `:1660`), `lock().ok()` (`:949`), and `lock().ok()?` / `let Ok(..) =
  … else { return }` in `cl_fork_watch.rs:270`, `:276`.
- **[B] Stringly protocol identifiers**: `fn behaviour_for(swarm, protocol:
  &str)` matches on `&'static str` protocol ids and returns `None` for a typo
  (`:1461–1481`, surfacing as `RequestError::Io("unknown protocol …")`
  `:1501`); the Status version is the string `"v1"`/`"v2"` (`:1836`,
  `note_peer_status(ctx, "v2", …)`) although `Pending::AutoStatusV2/V1` is
  already an enum. An `enum Eth2Proto` with `fn id(self) -> &'static
  StreamProtocol` makes the dispatch total.
- **[B] `submit_request` takes 8 parameters** (`:1417–1427`) that are exactly
  `Command::Request`'s fields — a `RequestSpec` struct; `OutboundFailure →
  RequestError` is mapped by hand (`:1733–1743`) where `impl From` is the idiom;
  `Behaviour::new` `expect`s a static gossipsub config (`:376–378`) inside a
  function whose caller returns `Result`.
- **[B] `pub type AgentMap = Arc<std::sync::RwLock<HashMap<PeerId, String>>>`**
  (`:503`) leaks the lock shape into the public API.
- **[B] `cl_fork_watch.rs`**: `pub fn new(label, schedule, root, blob_params_epoch:
  u64, blob_params_max_blobs: u64, genesis_time: u64, seconds_per_slot: u64)`
  (`:142–150`) — four adjacent `u64`s; `observe_enr(.., digest: [u8; 4],
  next_version: [u8; 4], ..)` (`:189`) — two adjacent same-typed arrays
  (`ForkDigest`/`ForkVersion` newtypes); two hand-rolled argmax loops
  (`:460–472`, `:493–501`) where `max_by_key` fits; `evaluate_locked` is 188 lines.
- **[C]** 12 fully-qualified `std::sync::atomic::…`/`std::collections::BTreeMap`
  paths while the items are imported (`sync.rs:1484`, `:4254`); `use` inside
  function bodies (8 in `reqresp.rs`); derive gaps on `Peer`, `PeerPool`,
  `SyncHandle`, `Eth2Codec`, `ReqRespClient`, `HostConfig`, the fork-watch
  observation structs; `LocalStatus::new` returns `Arc<Self>` (`reqresp.rs:710`);
  `peer_source_ips: HashMap<PeerId, (IpAddr, bool)>` (`:1305`); the CL module
  reaches into `crate::el::pool::log_client_id` for a generic sanitiser
  (`:1657`); `for_genesis` builds all three `ChainConfig`s to compare one root
  (`sync.rs:510–514`); parked gates poll with `sleep(1 s)` instead of a
  `Notify`/`watch` (`:2204`, `:2320`, `:2385`).
- **Tests.** `sync.rs`'s single `mod tests` is 1 626 lines; `reqresp.rs`'s
  real-socket tests with 15 s deadlines live in `src/` while `tests/` holds the
  `live_*` suites; `dns_change_detection_tests` (`:2773–2801`) tests
  `Vec::sort`, not the module, because the set-compare it should test is
  inlined.
- **Positives**: the `FuturesUnordered<BoxFuture<'static, Answer>>` pipeline
  raced against `sleep_until(refill)` with no lost work (`sync.rs:3322–3328`);
  `read_until_quiet` (`reqresp.rs:164–218`) — a cap, a quiet window after the
  first byte, an absolute budget, salvage on reset; `#[async_trait]` only where
  libp2p's `Codec` trait demands it; `Vote` as an enum with data and
  or-pattern bindings (`cl_fork_watch.rs:110–114`, `:398`); typed outcomes
  (`StepOutcome`, `FinalityPoll`) replacing earlier tuples; structured
  `tracing` fields at all 100 macro sites, no `println!`.

### 5.4 `myotis-net/src/el/reader.rs` — the EL verified-reads façade (18 288 lines)

**Lines 1–9 200.** `pub struct ElReader` (`:1968–2172`) has about 45 fields
— 22 `std::sync::Mutex`, 3 `tokio::sync::Mutex`, 4 `JoinHandle` slots, 2
semaphores, 3 atomics, a `Notify` — and `impl ElReader {` (`:2197–9775`) is
7 579 lines; 159 methods (63 `pub`) fall in this range. The field groups never
touch each other (log index 14 fields, fees 7, activity 5, sent-tx 3,
receipts 3), so twelve cohesive units are visible: config + enode parsing
(`:55–353`), verified result types, the hedged-race policy (`:1083–1216`,
`:1518–1708`, `:5740–5876`), send/broadcast/Tor (`:355–433`, `:1218–1516`,
`:8701–9083`), the **log-index driver** (`:2396–5552`, ~3 150 lines), state
reads (`:5656–6769`), EVM/ENS bridging (`:6771–7326`), block reads
(`:7328–7680`), fees (`:7682–8084`, `:8411–8699`), the activity follower
(`:8086–8409`) and receipt/tx lookup (`:9085–9200`) — each a sub-struct and a
module. Counts (production, this range): unwrap/expect 12 (11
`lock().unwrap()` in the sent-tx section + 1 `expect`), `as` 16 (all bounded),
clone 29 + 31 `Arc::clone`, `Result<_, String>` 67 signature sites (28 of them on
`pub` functions), unsafe 0. Findings: A 1, B 16, C 11.

- **[A — comment contradicts code, no runtime effect]** `:1977–1980`: "Only
  read on the `tor` feature" + `#[cfg_attr(not(feature = "tor"),
  allow(dead_code))]` on `eth_cfg`, which is read on non-Tor paths at `:2956`,
  `:3340`, `:4277–4278`.
- **[B] Five functions of 187–379 lines**: `log_index_backfill_batch`
  (`:5121–5499`, 379), `set_log_index_config` (`:2429–2763`, 335),
  `log_index_tail_tick` (`:3626–3951`, 326), `log_index_bridge_step`
  (`:4343–4665`, 323), `log_index_append_tick` (`:3365–3551`, 187) — each a
  sequence of named phases already (the bridge's "descent" `:4444–4532` vs
  "ascent" `:4534–4661`).
- **[B] The tip-lag verdict is decided by substring on another function's
  error text**: `f.contains("headers, expected") || f.contains("window head
  does not match …")` (`:640–641`; the comment at `:632–634` concedes "there is
  no typed error across its six callers"); `excused: impl Fn(&str) -> bool`
  (`:5767`) fed by `is_unknown_root_error(e)`. The same literals are re-typed:
  `"no snap peer available"` ×10, `"log index unavailable"` ×5. `SendError`
  (`:357`), `UnwatchError` (`:986`, no `Display`), `FeeHistoryError` (`:1819`,
  a `message()` method instead of `Display`), `FeeBuildError` (`:1865`) —
  none implements `std::error::Error`.
- **[B] Three lock-poisoning policies in one file**: 11 `lock().unwrap()`
  (`:8857`, …), 2 `unwrap_or_else(|p| p.into_inner())` (`:1393`, `:1408`), and
  60+ soft arms — `let Ok(_writing) = self.log_index_write.lock() else { return
  false }` (`:2460`), `if let Ok(mut rate) = …` (`:2452`), `match … { Err(_) =>
  false }` (`:3511–3526`) — which are dead code under `panic = "abort"`.
- **[B] `bool` parameters where the enum already exists**: `ens_attempt(..,
  finalized: bool)` whose first line is `ReadAnchor::for_finalized(finalized)`
  (`:7138–7149`); `apply_log_index_runtime_bits(enabled, max_speed,
  backfill_paused)` (`:5534–5539`, "travel together" per its own doc);
  `persist_log_index(.., respect_throttle: bool)` (`:4001`);
  `log_index_append_tick(.., stall: Option<&mut AppendStall>, ..)` using the
  `Option` as a mode flag (`:3365–3370`, `:3435`). `bool` returns conflate
  "invalid config" with "lock poisoned" (`set_log_index_config -> bool`,
  `:2429`) although `unwatch_log_index -> Result<usize, UnwatchError>` (`:2808`)
  shows the right shape.
- **[B] Six `#[allow(clippy::too_many_arguments)]`** (`:5759`, `:5831`,
  `:6079`, `:6826`, `:6843`, `:7090`); `ens_ccip_callback` builds `CcipRound {
  … }` from five of its own nine parameters (`:7112`).
- **[B] 21 tuple-shaped returns**: `-> Result<([u8; 32], u64, Option<u64>,
  AccountOutcome), String>` (`:5955`, `:6012`), `anchor_diagnostics() -> (u64,
  u64, bool)` (`:9744`), `pub fn serve_stats() -> (u64, u64, u64, u64)`
  (`:5586`), `Mutex<Option<(Instant, u64, f64)>>` (`:2106`), `HashMap<[u8; 20],
  (u8, u64)>` mutated as `entry.0 += 1; entry.1 = ticks` (`:3260`, `:3337`).
- **[B] Java-shaped result types**: `matched_beacon_slot: i64` with a `-1`
  sentinel (`:468`, `:6457`), `verify_method`/`fail_reason: Option<&'static str>`
  tokens (`:469–470`), chain ids matched as `1 | 11_155_111 | 100` (`:178–181`),
  nine verdict fields copy-pasted across `VerifiedAccount`/`VerifiedStorage`/`VerifiedCode`
  and re-copied field by field in `get_code` (`:6720–6729`).
- **[B] Duplicated blocks**: the descending parent-hash chain-prefix loop
  three times (`:3789–3797`, `:4487–4495`, `:5175–5187`); the ENS outcome
  `match` twice (`:7116–7132`, `:7158–7170`); five `pub async fn x(..) {
  self.request(self.x_inner(..)).await }` wrappers whose bodies differ in one
  method name and a label (`:6783`–`:6971`); `with_log_index(|ix|
  ix.append_edge()).flatten()` ×8; three `ElConfig` constructors restating 15
  fields with 11 identical values (`:197–352`).
- **[B] Misattached rustdoc**: `:4885–4899` documents `log_index_backfill_peer_order`
  (`:4925`, undocumented) but sits on `log_index_note_peer_tried` (`:4917`);
  `:5106–5120` carries two openings of the same paragraph; `#[cfg(feature =
  "tor")]` splits one doc comment at `:6265`.
- **[B] Serialize + fsync on tokio worker threads**: `persist_log_index`
  (`:4001`) serializes the whole index under the index lock (`:4043`, up to
  238 MB per its doc) and writes with fsync + rename (`:4051`, `:4122`) from
  the async ticks (`:3373`, `:3548`, `:3949`, `:4655`, `:4851`);
  `publish_finality_claim` (`:4145`) does file I/O under a std mutex async
  paths also take.
- **[B] Avoidable abort sites**: `slot.take().expect("checked Some above")`
  (`:2565`, a `let-else` away); `hex32("d4e5…")` decoding constants at runtime
  with `expect("valid 64-char hex constant")` (`:240`, `:293`, `:335`,
  `:11004–11007`) — a `const fn` decode turns a typo into a compile error;
  `tracing::warn!(.., "{}", label)` with a runtime message (`:5859`, `:5868`).
- **[C]** `std::time::Duration` ×32 vs bare `Duration` ×4 and `std::sync::Arc`
  ×18 despite imports (`:626`, `:1249`); 5 legacy `format!("{}")` sites
  (`:1913`, `:7931`) vs 20 inline; `Debug` missing on 10 types including `pub
  enum TxLookup` (`:1043`); a quadratic `canonical.iter().find(..)` per chunk
  (`:3870`); `SeqCst`/`AcqRel`/`Relaxed` mixed in one file; two detached
  rebroadcast spawns outside the shutdown watch (`:9026`, `:9066`).
- **Positives**: `parse_enode` (`:117–160`) is a model strict parser (let-else
  chain, `split_once`/`strip_prefix`, no byte-slicing of a possibly multi-byte
  string); `hedged_race` (`:1542–1630`) is pure policy over `FuturesUnordered`
  with `RaceOutcome::indices` returning `impl Iterator`; background tasks hold
  `Weak` refs and are aborted-and-awaited (`:3223–3224`, `:8081–8082`) behind
  `Handle::try_current()` guards; `FeeBuildError` deliberately has no
  `From<String>` so a stray `?` fails to compile (`:1861–1863`); the
  `Notify` enable-before-check idiom in `wait_for_fee` (`:7780–7781`);
  documented lock order honoured at every site (`:2051–2052`); peer-supplied
  windows are bounded before indexing (`:5157`, `:3840`). Verified
  non-findings: every `window[..]` index in range is guarded by
  `fetch_anchored_window`'s exact-length check.



**Lines 9 200–18 287 (3 267 production + 5 821 test lines, 257 test fns in 16
`#[cfg(test)]` modules).** Expression-level Rust here is modern and careful:
`let-else`, `is_none_or`, `then_some`, `checked_`/`saturating_` arithmetic on
every peer-influenced quantity, a native `async fn`-in-trait
(`trait CandidateSource`, `:10324–10335`, no `async-trait`), ordered
`futures::stream::iter(..).buffered(n)` for bounded in-flight body fetches
(`:9980–10001`), and no panic reachable from peer input was found. The
type- and module-level picture is the un-idiomatic one. Counts (production,
this range): unwrap/expect 2, `as` casts 18 (17 lossless), clone 3,
`Result<_, String>` 11 signatures + 4 string-wrapping "blame" enums, unsafe 0,
functions over 150 lines 0 (longest `reward_inputs` `:10621–10704`, 84 lines).

- **[B] Shape.** `impl ElReader {` runs from `:2197` to `:9775` — 7 579 lines
  in one impl block. Production code resumes at `:13380` after a 2 155-line
  `mod tests` (`:11221`) and 15 more test modules are interleaved after their
  code. The range is already ten self-contained clusters, each followed by its
  own tests — receipts (`:9206–9386`), the anchored-window gate
  (`fetch_anchored_window`, `:9845–10001`), the tx scan (`:9440–9741`),
  log-index candidates (`:10118–10484`), fee (`:10486–10891`), ENS/CCIP
  (`:11064–11219`), and four log-index policy clusters — tail
  (`:13403–13662`), backfill (`:13664–13985`), `ChunkSizer` (`:13987–14493`),
  persist cadence (`:14495–14662`) — which are log-index machinery, not
  verified reads, and belong under `el/logindex/`. Moving those four removes
  about 1 300 production and 3 400 test lines without touching an `ElReader`
  method.
- **[B] Stringly errors with four accessor conventions and a substring
  classifier.** `enum CandidateFetchError { Request(String), Answer(String) }`
  (`:10301`), `PoolReadError { Fatal(String), TipLag { error: String, .. } }`
  (`:646`), `FeeBuildError { Peer(String), Ours(String) }` (`:1865`),
  `BackfillBatchError { message: String, blames_peer: bool }` (`:13672`): the
  text is reached via a free function (`pool_read_error_text`, `:9890`), a
  `.message()` method, `Display`, or `.0`; none implements `std::error::Error`.
  The tip-lag classifier matches error text, so `fetch_anchored_window` has to
  word two errors differently on purpose (`:9935–9941`, "Distinct messages on
  purpose … all_tip_lag matches `"headers, expected"`"), and a test pins the
  wording. Idiom: one `enum ReadError { ShortWindow { got, want }, OverServed,
  HeadMismatch, NotLinked, Transport(..), .. }` with `Display + Error`, so
  `all_tip_lag` becomes a `matches!` and blame is a method on the enum.
- **[B] Verdict failure codes are `&'static str` matched by text**:
  `fn is_global_fail(reason: Option<&'static str>) -> bool { matches!(reason,
  Some("beaconNotSynced") | Some("beaconBlockUnavailable")) }` (`:11016`);
  a `#[derive(Copy, PartialEq)] enum FailReason` with `as_str()` for the JSON
  surface keeps a typo from turning a global failure into a per-peer one.
- **[B] Block identities as tuples in both orders.** `head: (u64, [u8; 32])`
  is `(number, hash)` at `:9421` and `:9906`, while `fresh_head` returns
  `([u8; 32], u64)` = `(state_root, number)` at `:10894`;
  `blocks: &[(u64, [u8; 32], bool)]` (`:13642`); `restart_claim_fate(finalized:
  u64, vouched: u64, first: u64, finality_current: bool)` (`:13486`) and
  `next_chunk_len(current: usize, served: usize, requested: usize,
  clean_streak: usize)` (`:14127`) take same-typed positional numbers. Small
  `Copy` structs (`BlockRef { number, hash }`) make the mix-ups
  unrepresentable.
- **[B] Behaviour-selecting `bool`s (7), one needing a macro**:
  `log_call_cost(what, info: bool, ..)` (`:10495`) defines a local
  `macro_rules! breakdown { ($level:ident) => … tracing::$level!(…) }` to pick
  the level (`:10507–10529`) — `tracing::event!(level, …)` takes a runtime
  `Level`; `eager_bodies: bool` (`:10393`), `witnessed: bool` (`:9412`),
  `persist_log_index(.., false)` (`:9771`, `respect_throttle`).
- **[B] `ChunkSizer` is five `Relaxed` atomics updated in non-atomic
  read-modify-write groups behind a `&self` API** (`:14228–14250`,
  `fold` `:14274–14282`: load `width`, load `clean_streak`, compute, store
  both). Safe today only because one task drives both instances; a
  `Mutex<SizerState>` with plain fields is the idiom and removes the four
  `use std::sync::atomic::Ordering::Relaxed;` inside function bodies.
- **[B] `stop()` aborts the log-index task without awaiting it**
  (`:9761–9765` `h.abort();`), then writes the final checkpoint (`:9771`) and
  stops the pool the task may still be using; `abort()` takes effect at the
  next yield point. Idiom: `h.abort(); let _ = h.await;` first.
- **[B] One function, two poisoning policies**: `self.sent_tx_watch.lock().unwrap()`
  (`:9487`) next to `self.tx_scans.lock().map_err(|_| "engine lock
  poisoned".to_string())?` (`:9579`, documented "never panic here").
- **[B] Copy-pasted head checks** between `fresh_head` (`:10904–10918`) and
  its Tor twin `fresh_head_session` (`:10931–10940`).
- **[B/C] Index loops where slice adaptors fit**: `for i in 0..window.len() - 1
  { if window[i + 1].header.parent_hash != window[i].hash …` (`:9957–9961`)
  → `window.windows(2).all(..)`; `:13653–13660` a manual cursor loop →
  `iter().rev().skip().take().filter()`.
- **[C]** About 25 fully-qualified `crate::el::eth::messages::VerifiedHeader`
  paths beside a `use` block that imports every sibling (`:9980–9990`); `use`
  inside function bodies (5); constant closure arguments to `hedged_read`
  (`|_: &Option<TxLocation>| true, |_: &Option<TxLocation>| true, |_: &str|
  false,` `:9561–9563`) that want a policy struct with defaults; `CcipRound`
  (`:11139`) has no derives; a stale "four places" caller count at
  `:10050–10053` (six today); `pub fn generate_node_key` (`:10990`) is
  crate-internal.
- **Tests.** Well-fixtured — scripted peers as data (`enum Peer { Answers(..),
  FailsNow, .. }` `:11472`), an RAII `TempDir` (`:16962`), paused-clock exact
  timings — but `restart_claim_reader_tests` (812 lines), `pre_broadcast_tests`
  and `fee_bounded_wait` boot a full offline `ElReader` and write under
  `temp_dir()`: integration tests kept in `src/` to reach private fields. The
  `hash(n)` helper is redefined five times, `offline_reader` three times.
- **Positives**: `fetch_anchored_window` (`:9926–9970`) is the one header
  trust gate for seven call sites; `reward_inputs` scopes its std guard in a
  block before `join_all(..).await` and uses a tokio `Mutex<()>` only for the
  section genuinely held across awaits (`:10639–10653`); `FeeFailOnDrop`
  (`:10557–10581`) is a clean RAII guard; the pure helpers are defensive by
  construction (`u32::try_from(..).ok()?.checked_add(..)?` `:13393`,
  `div_ceil` + `Duration::clamp` `:14533`).

### 5.5 `myotis-net/src/el` — `pool.rs`, `logindex.rs`, `evm.rs` (the peer pool, the log index, the sync-oracle bridge)

**Verdict.** `logindex.rs` is the most idiomatic of the three: a sans-I/O state
machine with an allocation-bounded byte `Cursor` that is panic-free by
construction (`:1102–1131`), parsers fuzzed for every single-byte corruption
and truncation (`:2437–2463`), and a textbook `write_atomic` (per-call temp
name → fsync → rename → fsync of the directory, tested for concurrent writers,
`:1020–1049`, `:2234–2328`). `pool.rs`'s policy half is small pure tested
functions (`pins_to_dial`, `scaled_backoff`, `backfill_plan`); its runtime half
is a 35-field `PoolInner` lock cluster (`:646–756`) with 9 tokio + 7 std
mutexes. `evm.rs` bridges the synchronous `SnapStateOracle` to the async pool
the standard way — `Handle::block_on` from a `spawn_blocking` thread behind a
bounded slot semaphore (`:825–832`, `request.rs:231–248`), a pinned
cancel-safe `select!` in `wave_request` (`:452–479`). No panic reachable from
peer or on-disk input in any of the three. Counts (production): unwrap/expect
0 / 2 / 16 (the 16 all `lock().unwrap()`); functions over 150 lines: `dial_one`
(227), `maintainer_loop` (154), `prefetch_batch` (301, the longest in scope).
Findings: A 0, B 24, C 24.

- **[B] Dial outcomes classified by matching error text**: `is_busy_disconnect(e:
  &str) -> bool { e.starts_with("peer disconnected") && e.ends_with("reason=4") }`
  (`pool.rs:78–80`), `e.starts_with("incompatible peer") || e.starts_with("peer
  Status decode")` (`:1490–1492`) over `EthSession::handshake`'s `Result<_,
  String>`; the comment at `:1487–1489` explains why `contains` would be
  peer-steerable and a 40-line test (`:4420–4460`) pins the string shape — a
  `HandshakeError` enum removes the whole concern.
- **[B] `tokio::sync::Mutex` where a guard never crosses an await**: of the
  nine tokio mutexes in `PoolInner`, only `peers` (held across `close().await`,
  `:1974`) and `attempted` (held while `cache.lock().await`, `:839–840`) need to
  be; `backoff`, `blacklist`, `cache`, `host_enodes`, `online_signal`,
  `last_scarcity_log`, `last_broadcast_range` could be std like their siblings
  `lingering`/`tor_reserve`/`bal_unable`. Set-once handles live in
  `std::sync::Mutex<Option<Arc<..>>>` (`:726–734`) next to a field that already
  uses `OnceLock` (`:755`).
- **[B] Three poison-handling idioms in one file** (`pool.rs:765`
  `unwrap_or_else(|p| p.into_inner())` ×17, `:1347` `if let Ok(mut no_bal) =
  …` ×3 silently skipping, `:3095–3101` mutating a guard inside an `is_ok_and`
  predicate) and a fourth across the hall: `evm.rs` uses `lock().unwrap()` at
  all 16 of its sites.
- **[B] 14 blocking `cache.flush()` (`std::fs::write`) sites on tokio worker
  threads** (`pool.rs:1083`, `:1301–1302`, `:1463`, …) under a tokio mutex
  guard; `TorReserve::flush` is the same.
- **[B] `dial_one` (`pool.rs:1284–1510`, 227 lines) repeats its "cache + cool-off
  + release" epilogue four times** (`:1359–1367`, `:1380–1390`, `:1448–1456`,
  `:1470–1478`); `PeerPool::start` takes 11 positional arguments including a
  `Box<dyn Fn>` it immediately re-wraps into `Arc` (`:1522–1534`, `:1576`).
- **[B] Primitive/tuple obsession in the public surface**: `pub type Enode =
  (SocketAddr, [u8; 64])` (`:146`), node ids as bare `[u8; 64]` in 40+
  signatures, `serve_stats() -> (u64, u64, u64, u64)` (`:1828`), `backfill_plan ->
  Option<(u64, u64, BatchAnchor)>` (`:1774`), eight pure policy fns taking 1–3
  positional `bool`s (`bal_shielded(demand: bool, this_recent: bool,
  another_recent: bool)`, `:487`) whose tests annotate the argument order in
  comments (`:4210`, `:4219`, `:4229`).
- **[B] `logindex.rs`**: two `expect`s "unreachable by reasoning, not by type"
  in `merge` (`:1713` `h.expect("a span exists, so H exists")`, `:1763`
  `Self::new(config).expect("union has unique keys")`) — under `panic =
  "abort"` an invariant slip aborts the wallet during an import; `merge` itself
  is 142 lines, five closure levels deep, with an index-driven pruning loop
  (`:1624–1765`); `parse_body` returns a three-tuple behind
  `#[allow(clippy::type_complexity)]` (`:1877–1881`) although `ParsedV2`
  (`:1808–1817`) already names the fields; `QueryError`/`CoverageGap`
  implement neither `Display` nor `Error`, `InvalidWatchList`/`MergeError`
  `Display` only (`:418`, `:434`, `:502`, `:1581`); `pub cursor` on an otherwise
  encapsulated struct (`:533`); `same_restriction` clones and sorts both topic
  lists inside O(n²) loops (`:137–141`).
- **[B] `evm.rs`**: `prefetch_batch` is 301 lines with three nested
  `join_all`s, a function-local `enum ItemOutcome` (`:1062`) and six closure
  levels (`:1037–1337`); `leaf.clone()` per storage slot and `slots.clone()` per
  attempt (`:1151–1152`, `:1232`); `record_race(quality: &Option<SnapQualitySink>,
  ..)` (`:840–845`) forcing `self.quality.clone()` at four call sites; a `bool
  finalized` threaded through a file that defines `enum ReadAnchor { Head,
  Finalized }` for exactly that distinction (`:94–103`, `:642`, `:759`);
  unchecked indexing on internal permutations at nine sites (`lost[peer] =
  true`, `peers[*idx]`, `:730`, `:734`, `:862`, `:876`) where `next_order`
  already uses `get`; `block_context(..) -> Result<BlockContext, String>` with
  exactly one failure (`:329–334`); the `block_on` bridge's safety ("only ever
  called from a blocking thread") is a convention, not a type (`:825–832`, a
  `pub` constructor at `:754`).
- **[C]** lock-then-clone of whole sets (`pool.rs:836`, `:1696`); two spellings
  of "speaks snap/2" (`:598` vs `:1345`); three spellings of the shutdown check
  (`:2444`, `:3135`, `:3182`); `std::collections::HashSet` and
  `std::sync::atomic::Ordering` fully qualified beside their imports
  (`pool.rs:180`, `:2644`; `evm.rs` ×31); `fn`-local `use` and policy `const`s
  (`evm.rs:1045–1049`); FNV-1a implemented twice in one file
  (`logindex.rs:336–345`, `:1080–1087`) and a third time in `rpcd`; `query()`
  clones every matching `StoredLog` (`logindex.rs:883–890`); load paths swallow
  every I/O error into `None` (`:1385`, `:1421`, `:1522`); `rewind_above` walks
  the whole `BTreeMap` with `retain` where `split_off` is logarithmic (`:794`);
  `CoverageGap { edge: high, .. }` names the wrong edge for the `< low` arm
  (`:719–720`); process-wide `static DIRECT_CONTACT: LazyLock<Mutex<..>>`
  contact logs (`pool.rs:2217–2222`, documented).
- **Positives**: `const _: () = assert!(READ_FAILS_EVICT ==
  crate::el::peercache::FAILURE_THRESHOLD)` (`pool.rs:378`); `DirectContactOnDrop`
  RAII (`:2226–2232`); spawned tasks owned, aborted and joined through
  `el/tasks.rs`; `now_unix_ms` and `to_socket_addr` with checked conversions
  (`:2134–2140`, `:3215–3231`); `log_client_id` sanitising peer-controlled text
  before it reaches a log line (`:571–578`); `unwatch` built on `mem::take` +
  one `retain` with the same rule the merge uses (`logindex.rs:615–640`);
  `WireTimer` RAII with `u64::try_from(..as_nanos())` (`evm.rs:691–701`);
  `AttemptTally` as a named-field flag struct (`:483–493`) — the pattern
  `pool.rs` lacks; a paused-clock end-to-end test that a dead first peer costs
  exactly one hedge delay per call (`:2019–2040`).

### 5.6 `myotis-net/src/el` — discovery, peers, cache, sessions, transport

**Verdict.** Competent tokio code — cancel-safe `select!` with bounded,
non-blocking fan-out (`discv4.rs:773–804`), socket2 used correctly for the
dual-stack UDP trap (`:388–415`), typestate handshakes instead of state-flag
enums (`transport.rs:149–184` `Initiator → RlpxConnection`, `session.rs:107–222`
`RlpxConnection → EthSession`, generic over the stream so the Tor path reuses
them), `Drop` guards that release claims on cancellation (`dnsdisco.rs:847–855`,
`tasks.rs:36–40`), pure cores with the clock as a parameter. `dnsdisco.rs` is
the most idiomatic file; `peer.rs` the least. Counts (production):
unwrap/expect 6, `as` 12, clone 16 (+9 `to_vec`), `Result<_, String>` 58 (+21
`Err(format!`), unsafe 0; functions over 150 lines: `peer.rs::read_loop`
(155). Findings: A 3 (two wrong comments/dead code, one production `expect`),
B 25, C 39.

- **[A, low likelihood] Four `expect("OS entropy")` on every dial**
  (`rlpx/transport.rs:364`, `:370`, `:377`, `:380`) inside functions whose
  callers already return `Result<_, String>`; `getrandom` fails with
  `EAGAIN`/`ENOSYS` in early boot or seccomp sandboxes, and under `panic =
  "abort"` that is a process abort inside the host. Meanwhile `discv4.rs:1386`,
  `:1508` and `dnsdisco.rs:543` ignore the same failure with `let _ =`, so
  `sample()` degrades to "first k entries" silently — three entropy policies
  in one scope.
- **[A — comments/dead code]** `peer.rs:323` documents "Negotiated eth version
  (66-69)" while the struct branches on `>= 70`/`>= 71` and
  `OUR_ETH_VERSIONS` ends at 71; `discv4.rs:349` `pub fn closest_peers` is
  called only from its own tests (the pool walks `all_peers()`), and
  `TableEntry.last_seen_ms` (`:48`) is written and never read.
- **[B] Stringly errors and `CoreError`'s `Display` bypassed**: 58
  `Result<_, String>` signatures; ~25 sites write `format!("…: {}", e.0)`
  (`peer.rs:649`, `session.rs:191`, `transport.rs:150`, `dnsdisco.rs:183`),
  which is also what forces the legacy positional `format!` style there. One
  `NetError` enum with `From<CoreError>`/`From<io::Error>` would delete the
  `map_err` chains and the pool's string-prefix disconnect classifier
  (`session.rs:580–583`).
- **[B] `tokio::sync::Mutex` on an await-free map, which forces a
  spawn-in-`Drop`**: `type PendingMap = Arc<Mutex<HashMap<u64, Pending>>>`
  (`peer.rs:58`, tokio's `Mutex`); every critical section is synchronous
  (`:133–143`, `:536–541`, `:1382–1388`), so `PendingGuard::drop` must
  `Handle::try_current()` and spawn a detached task to remove its entry
  (`:164–170`), skipped entirely when no runtime is current. A std mutex makes
  the drop a plain `remove`. Same shape at `discv4.rs:262` (tokio mutex around
  a `JoinHandle`, guard held across `task.await` at `:362–364`).
- **[B] Liveness state as hand-ordered flags**: `closed: Arc<AtomicBool>` +
  `close_reason: Arc<Mutex<Option<String>>>` with "the reason before the flag"
  ordering comments (`peer.rs:350–353`, `:1383–1385`) and a manual
  first-reason-wins (`:1391–1398`) — an `Arc<OnceLock<String>>` *is* that
  state machine; `GuardedWriter { inner: Option<RlpxWriter>, torn: bool }`
  (`:70–73`) encodes three states as `Option × bool`.
- **[B] 9- and 12-parameter functions** (`peer.rs:399–410` `from_connection`,
  `:1110–1124` `read_loop`) with `#[allow]`; `fail_all(&self.pending,
  &self.closed, &self.close_reason, ..)` passes the same three `Arc`s at eight
  sites; four identical write-failure blocks in `read_loop` (`:1203–1206`,
  `:1227–1231`, `:1247–1251`, `:553–557`).
- **[B] `session.rs` and `peer.rs` carry copy-pasted logic**:
  `header_chain_verdict` (`session.rs:454–497` = `peer.rs:1047–1097`),
  `verified_state_root` (`:504–519` = `:1024–1039`), the three snap reads
  (`:385–449` = `:883–989`), and two identical 20-line await loops inside
  `session.rs` itself (`:293–316`, `:523–543`). `transport.rs` implements
  frame reading twice (`:204–225`, `:304–338`) — security-relevant framing code
  in two copies.
- **[B] `eth_version: u64` compared against 69/70/71 at nine sites**
  (`peer.rs:603`, `:743`, `:825`, `session.rs:137`) — an `EthVersion(u8)`
  newtype with `has_block_range_update()`-style predicates; `pub snap: bool`
  duplicates `pub snap_version: Option<u64>` as a second public field that must
  agree (`session.rs:80–84`, `peer.rs:326–328`).
- **[B] `peercache.rs`**: `fs::write(path, body).is_ok()` (`:587–589`) is a
  non-atomic rewrite (truncate then write — a crash leaves a torn file whose
  tail `load` silently drops), its error is swallowed with no log, and the only
  production callers run it under a *tokio* mutex in async code
  (`pool.rs:1972`). Entries are keyed by a `"ip\tport"` `String` the cache
  itself built and re-parses on every read (`:145`, `:301`, `:609–611`), and
  the node id is a hex `String` re-parsed on every compare (`:107`, `:280`,
  `:302`, `:377`, `:422`) — `BTreeMap<SocketAddr, Entry>` with `[u8; 64]`.
- **[B] `dnsdisco.rs`**: `pub fn parse(url: &str) -> Result<EnrTreeUrl, String>`
  where `FromStr` is the idiom (`:160`); eight `Err(format!(..))` that are one
  `TreeError` enum (`:132`, `:168`, `:174`, `:210`, `:219`, `:236`, `:282`), with
  a test asserting `e.contains("no address")` on the string.
- **[B] `discv4.rs`** (2 536 lines) bundles the Kademlia table + limiter
  (`:34–195`), the UDP service (`:197–475`), the EIP-868 ENR exchange
  (`:515–749`) and the loop handlers (`:751–1444`); `pub use
  myotis_wire::discv4::*;` (`:32`) glob-re-exports into a module with its own
  items so `parse`/`encode_ping` are unqualified and rustdoc lists them twice;
  `TableEntry { ip: Vec<u8>, node_id: Vec<u8>, tcp_port: u32 }` (`:41–49`)
  forces `to_socket_addr`/`ip_bytes` helpers and a `to_vec()` per packet.
- **[B] The six 4-line glob shims** (`rlpx/{ecies,frame,handshake}.rs`,
  `snap/{fetch,messages}.rs`, `eth/messages.rs`) should be one-line module
  re-exports in the parent `mod.rs` (`pub use myotis_wire::rlpx::{ecies, frame,
  handshake};`) — every path keeps working, rustdoc stops duplicating every
  item, upstream docs survive. `transport.rs:25–28` already shows the explicit
  style.
- **[C]** 11 `tracing` calls interpolate the error into the message
  (`discv4.rs:423`, `dnsdisco.rs:477`) vs 32 structured; hex rendering
  hand-rolled in four places (`peercache.rs:628–635`, 64 `format!` allocations
  per key); wall-clock seconds derived three times (`fork_watch.rs:80` is the
  helper); `&Option<T>` parameters (`peer.rs:283`, `:1325`); `std::time::Instant`
  beside `tokio::time::Instant` (`peer.rs:787`); `Tasks(Mutex<(bool,
  Vec<JoinHandle<()>>)>)` read as `.0`/`.1` (`tasks.rs:7`); the process-global
  `static ENABLED: AtomicBool` DNS switch with `SeqCst` (`dnsdisco.rs:59`); 10
  of 16 `peercache` tests use fixed temp-file names without a pid; the crate
  description in `myotis-net/Cargo.toml:6` still says "consensus-layer
  networking" for a crate holding the whole EL stack.
- **Positives**: `discv4.rs:773–804` — all four `select!` branches cancel-safe,
  `try_send` never stalls the loop, one reused 4 KiB buffer, v4-mapped senders
  canonicalised; `dnsdisco.rs:215–220` and `:338–343` parse hostile text
  without byte-slicing a UTF-8 string; `peer.rs:216` derives `Ord` on
  `Coverage` and pins the variant order with a test; `#[tokio::test(start_paused
  = true)]` timing tests (`peer.rs:1556`); `tasks.rs` keeps every
  `JoinHandle`, aborts then joins on `stop`, aborts on `Drop`.

### 5.7 `myotis-net/src/el` — the fifteen smaller modules, `tests/`, `examples/`

**Verdict.** Solid, panic-conscious Rust: 0 `unsafe`, no reachable panic on a
production path in 9 076 lines, clocks injected (`now: Instant`/`now: u64`) so
freshness rules are unit-tested instantly, `checked_`/`saturating_` on every
peer-facing arithmetic site, no function over 150 lines (longest
`ForkWatch::evaluate_locked`, 78). The residue is organisational and
type-level. Counts (production): unwrap/expect 27 (all `lock().expect(..)`:
`anchor.rs` ×24, `tor.rs` ×3), `as` 14, clone 18, `Result<_, String>` 17,
unsafe 0. Findings: A 2 (doc/code mismatches), B 27, C 19.

- **[A — docs contradict code]** `served.rs:11–13` and `:181–182` say no
  genesis header is embedded while `:38–79`, `:121` and `:138` embed and serve
  it; `anchor.rs:161–162` calls `ExecAnchor` a "Cloneable handle" but it has no
  `Clone` (every user wraps it in `Arc`).
- **[B] Stringly errors used as a protocol**: `request.rs:93–105` returns
  `Err("request cancelled".into())` / `Err("request deadline exceeded".into())`
  and `myotis_evm::OracleError::kind` tells them apart by comparing the text
  (the test at `request.rs:341–356` says "Reword the message here and this
  fails"); `tor::is_peer_unreachable(error: &str)` matches `starts_with("tor
  connect ")` and friends (`tor.rs:254–259`); three live tests match
  `e.contains("incompatible peer")`. 17 `Result<_, String>` signatures in scope.
- **[B] Five mutex-poisoning policies in one directory**: `lock().expect("anchor
  mutex")` ×24 (`anchor.rs:196`), `unwrap_or_else(|e| e.into_inner())`
  (`readstats.rs:351`), the recovery `match` pasted eight times
  (`served.rs:156–159`, `:187`, `:213`, `:233`, `:244`, `:260`, `:274`, `:287`),
  `lock().ok()?` / `let Ok(..) = … else { return }` silently dropping an
  observation (`fork_watch.rs:300`, `:307`), `.lock().map_err(|_| "request
  registry unavailable".to_string())?` (`request.rs:205–207`); `tor.rs` uses
  three of them in one file.
- **[B] Same-typed adjacent parameters that compile when swapped**:
  `update_finalized(&self, finalized_slot: u64, execution_state_root: [u8; 32],
  execution_block_number: u64, execution_block_hash: [u8; 32],
  execution_timestamp: u64)` while `FinalizedExecution` (`anchor.rs:90–101`)
  has exactly these five fields; `observe_storage(.., storage_key: [u8; 32],
  state_root: [u8; 32], storage_root: [u8; 32], value: [u8; 32], ..)`
  (`readstats.rs:377–385`, four `[u8; 32]` in a row); `ForkWatch::new(label,
  local_fork_hash, local_fork_next: u64, genesis_time: u64, epoch_seconds: u64)`
  (`fork_watch.rs:223–229`); `head_is_fresh(now_unix: u64, head_timestamp: u64,
  ..)` (`send_check.rs:57`).
- **[B] Tuples where a struct exists or should**: `optimistic_anchor() ->
  Option<(u64, [u8; 32], u64)>` is (number, **hash**, slot) and
  `optimistic_execution() -> Option<(u64, [u8; 32], u64)>` is (number, **state
  root**, timestamp) (`anchor.rs:441`, `:516`); `by_number: BTreeMap<u64, ([u8;
  32], [u8; 32], Vec<u8>)>` destructured eight times as `(h, _, _)` /
  `(_, p, _)` / `(_, _, raw)` (`served.rs:106`); `head: Option<(u64, [u8; 32])>`
  although `ProofTarget { block_number, state_root }` is that pair
  (`getproof.rs:114` vs `:101–104`); `static BOOTSTRAP: Mutex<(u64,
  Option<Bootstrap>)>` read as `slot.0`/`slot.1` (`tor.rs:178`).
- **[B] Java-shaped numerics and tokens**: `verify.rs:28` `matched_slot: i64`,
  `:99` `peer_block_number: i64` with `<= 0` as "absent" and `as` casts both
  ways (`:68`, `:115`, `:135–138`, `:168`); `verify_method`/`fail_reason:
  Option<&'static str>` with eleven literal tokens (`:30–33`, `:113–162`) while
  `fork_watch::Phase::as_str` and `activity::Via::as_str` show the house enum
  idiom; `tx.rs:83–84` `ty: u8` with "0 legacy, 1 = 2930, 2 = 1559 …" in a
  comment and three consumers re-matching the raw integers; `receipt.rs:24–26`
  `has_status: bool` + `success: bool` for a tri-state; `#[allow(clippy::option_option)]
  fn to_field(..) -> Option<Option<[u8; 20]>>` (`tx.rs:403–404`).
- **[B] Cancellation by 10 ms polling**: `request.rs:121–129` `select! {
  biased; _ = sleep(10 ms) => self.check()?, value = &mut future => … }` wakes
  every live request 100×/s; `deadline` could be `sleep_until`, `cancelled`/`shutdown`
  are `watch` channels with `.changed()`; only the FFI `AtomicBool` (`:37`)
  lacks a waker, which is what forces the poll.
- **[B] Process-wide globals vs the crate's hygiene note**: `request.rs:30–31`
  `static BLOCKING_SLOTS: Semaphore`, `tor.rs:52–73` `ENABLED`, `CLIENT:
  OnceCell<Arc<TorClient>>` (an I/O object held process-wide), `ISOLATION:
  Mutex<Option<HashMap<..>>>` (the `Option` only because `HashMap::new` is not
  `const` — `LazyLock` is the idiom), `STORAGE`, `BOOTSTRAP`; `lib.rs:21–22`
  says the crate has none.
- **[B] Hand-rolled serialisation**: 65 lines of JSON built with
  `s.push('{'); num(&mut s, "schema", 1); …` in `readstats.rs:475–539` that the
  tests parse back with `serde_json`; three hex codecs in `src/el/`
  (`getproof.rs:42–44` one `String` per byte, `sent_tx.rs:133–141`,
  `served.rs:82–99`) and ten more in `tests/`; a TSV format in `torreserve.rs`
  whose `fs::write(path, body)` (`:255`) is non-atomic and runs inside `async
  fn`s in `pool.rs` with no `spawn_blocking`.
- **[B] `pub` far beyond what any consumer imports**: other crates import about
  13 items from these fifteen modules, yet `ExecAnchor` exposes 25 `pub fn`s
  (`anchor.rs:179–556`), `ServedHeaders`/`ServeStats`/`SentTxTracker`/`Verdict`/`LadderStep`/`ActivityState`
  are `pub`; `feecache` shows the crate's own convention (`mod feecache;` +
  `pub(crate)`).
- **[B] Twin finalized/optimistic state duplicated field by field**
  (`anchor.rs:119–159`; `note_finalized_hash` `:238–260` vs `note_optimistic_hash`
  `:263–285` differ in one statement) — a `Head { slot, number, hash,
  state_root, timestamp }` held twice; `feecache.rs:454–457` `missed(&mut
  self, history: bool, served: bool, ..)` called as `missed(true, false, now)`;
  `served.rs:224`, `:271`, `:279` clone every header out under the lock on the
  serve path (`Arc<[u8]>`/`Bytes` would make a serve a refcount bump).
- **[C]** `#[allow(dead_code)] pub fn body_served` — a `pub` method on a `pub`
  type is never dead code, the attribute is a no-op (`served.rs:331–332`);
  `mainnet_genesis()` re-decodes 535 bytes of hex and re-hashes on every call
  (`:67–79`); `elapsed.as_nanos() as u64` ×3 where `request.rs:290` shows the
  `try_from` idiom; `Arc<Vec<u128>>` where `Arc<[u128]>` is the shared-slice
  idiom (`feecache.rs:32–34`); `#[cfg(..)]` placed above the `///` doc comment
  (`torreserve.rs:199`, `:216`); `TorAddr::from((addr.ip().to_string().as_str(),
  addr.port()))` round-tripping an IP through a `String` (`tor.rs:314`);
  `SeqCst` on plain flags (`tor.rs:77`, `:87`, `:294`); `pub logs_bloom: Vec<u8>`
  for a 256-byte bloom while `myotis_core::bloom::LogsBloom` exists
  (`receipt.rs:30`).
- **`tests/` (20 files, 3 990 lines).** No `tests/common/mod.rs`: `hex` is
  byte-identical in ten files, `hex32` in ten (two variants), `parse_expected`
  and `corpus_dir` in five, `to_v4` in four, the mainnet `EthConfig { .. }`
  block in four, `try_peer` near-identical in three. The five `el_*_conformance`
  tests return green when the committed corpus directory is missing
  (`el_discv4_conformance.rs:34–37` and four siblings) — the strongest
  cross-language pin can pass vacuously. `NET` gating is inconsistent:
  `live_cold_start.rs:99`, `live_discv4.rs:53`, `live_pins_alive.rs:122` refuse an
  unknown value (citing the project's apply-or-refuse rule) while
  `live_dns_tree.rs:27–31` and `live_enr_filter.rs:32–36` silently fall back, with
  three different defaults. `live_pins_alive.rs:264–525` is a 262-line test
  function with about seven levels of nesting. Positives: every live test
  carries `#[ignore = "reason"]` and refuses env overrides that would change
  its meaning; budgets are named constants and failure text is derived from
  them; byte-level corpus pins with a two-way key-set check; a counting
  `#[global_allocator]` with a proper `// SAFETY:` comment
  (`el_hostile_frames.rs:42–45`).
- **`examples/` (6 files).** `period_census.rs` is `lc_crawl.rs` copied and
  extended (`Verdict` enum, probe closure, crawl loop, drain, report);
  `main`s of 341 and 229 lines; `std::process::exit` inside `#[tokio::main]`
  at ten sites (`enr_lookup.rs`, `live_sync.rs`, `record_shield_fixture.rs`),
  skipping destructors — `async fn main() -> ExitCode`. Positives: verdicts
  are enums with one `describe()` mapping; malformed env settings stop the run
  instead of defaulting (`period_census.rs:285–295`).

### 5.8 `myotis-evm` — revm behind `SnapStateOracle`, ENS, fixtures

**Verdict.** Idiomatic, careful Rust with a genuinely typed error surface:
`EvmError` (`error.rs:13`), `OracleError` (`oracle.rs:64`) and `EnsError`
(`ens/mod.rs:215`) are closed enums with `Clone/Debug/PartialEq/Eq`,
geth-compatible `Display`, `std::error::Error`, `From` impls and
`is_refusal()`/`is_infeasible()` classifiers that encode the apply-or-refuse
rule (`error.rs:123–153`). The revm-43 integration is in proper style
(`DatabaseRef` + `DBErrorMarker`, `TxEnv::builder()..build()` strict, generic
`Inspector`, `Bytecode::new_raw_checked` with a legacy fallback), every known
revm panic is pre-empted with a typed refusal and a comment naming the revm
`expect` it avoids (`executor.rs:477–482`, `:736–744`, `:1230–1234`,
`database.rs:300–302`), and ABI decoding is bounds-checked in the `u64` domain
before any `usize` cast (`ens/abi.rs:145–151`, `:201–207`). No panic reachable
from calldata, return data, gateway tuples or proof bytes was found. Counts
(production): unwrap/expect 28 (all `Mutex::lock().unwrap()`), `as` 9, unsafe
0, `Result<_, String>` 22 (1 on a production path, 21 in the feature-gated
fixture tooling), functions over 150 lines 0 (longest `estimate_tx`, 127).
Findings: A 0, B 24, C 39.

- **[B] An accepted-and-ignored parameter**: `resolve_ownership(.., chain_id:
  u64, ..)` only `debug_assert_eq!`s it against `caller.chain_id()` and then
  shadows it (`ens/mod.rs:409–414`) — in release a caller passing the wrong
  chain gets a well-formed answer for another one, the exact shape the
  project's rule forbids. Drop the parameter or refuse on disagreement.
- **[B] Hot-path recomputation in the override path**: an overridden
  account's code is deep-copied and re-keccak'd on every `basic_ref`
  (`database.rs:346–347`) and copied again per `code_by_hash_ref` (`:357`);
  `StateOverrides::code_by_hash` hashes every override on every code load
  (`overrides.rs:90–94`) — a 12-pass convergence loop pays this 12× per
  touched account. Store `Bytes` plus a precomputed hash at insert.
- **[B] `OracleError::kind()` classifies a cancellation by string equality
  against another crate's message** (`oracle.rs:139`, `reason == "request
  deadline exceeded"`); `TxRequest::validate -> Result<(), String>` (`tx.rs:182`)
  is the one stringly error on a production path, tested by `.contains(..)`;
  no `source()` on the wrapping variants (`error.rs:273`, `oracle.rs:150`,
  `ens/mod.rs:298`), so `anyhow`-style chains see one flattened message.
- **[B] Structure**: `executor.rs` is 4 022 lines of which 2 585 are an inline
  test module while `executor/tests/*.rs` already exists for two files; crate
  imports sit at `:216–223`, 170 lines into the file and below code that uses
  them; `database.rs` has no test module — its 430 lines of tests live in
  `lib.rs:77–505`; a five-field `(db, spec, tx, gas_limit, ctx)` bundle is
  threaded through six private fns under four `#[allow(clippy::too_many_arguments)]`
  (`:875`, `:931`, `:944`, `:994`).
- **[B] Duplication in `ens/mod.rs`**: nine copies of the three-arm
  `eth_call` match (`:511`, `:520`, `:687`, `:694`, `:835`, `:853`, `:878`,
  `:955`, `:975`); the zero-address filter repeated beside its own helper
  `decode_address_answer` (`:512`, `:692`, `:960` vs `:773–775`); eight
  `resolve_*` wrappers with an identical six-line body (`:364–642`); three
  hand-rolled hex encoders — one allocating a `String` per byte (`:763–765`,
  the anti-pattern `oracle.rs:159–160` explicitly avoids) — while
  `revm::primitives::hex` is already compiled.
- **[B] Public surface**: `AccessSet`, `set_sentinel`, `sentinel_misses`,
  `take_access_set` are `pub` but a private contract between `OracleDatabase`
  and `converge` (`database.rs:124`, `:228–240`); `OracleAccount::empty()` and
  `has_no_code()` have no caller in the workspace (`oracle.rs:44`, `:55`) while
  `database.rs:360` re-derives the empty-code check by hand.
- **[B] Comments wrong about the code**: `database.rs:332–335` says the base
  fetch is skipped for a code-only override (it is unconditional);
  `executor.rs:1430–1431` names a `run` function that does not exist;
  `Cargo.toml:29` says every dependency is exact-pinned while `serde_json =
  "1"` (`:41`, `:44`).
- **[B] Fixture tooling** (feature `fixture`, never shipped): 21 `Result<_,
  String>` signatures, seven eager `ok_or(format!(..))` (`fixture/world.rs:481`,
  `:485`, `:500`, `:516`, `relay_adapt_7702.rs:303`, `:463`, `:511`), and ~350
  lines of hand-written JSON mapping for five types (`world.rs:68`, `:135`,
  `:318`, `:382`, `relay_adapt_7702.rs:298–482`) where
  `#[derive(Serialize, Deserialize)]` + `deny_unknown_fields` gives the strict
  unknown-key refusal for free.
- **[C]** `std::collections::HashSet` spelled out ×3 next to its import
  (`executor.rs:26` vs `:45`, `:1088`, `:1145`); `use` inside fn bodies
  (`:141`, `:1406`); `bool` flags (`set_sentinel(on)`, `wrapped` ×3,
  `history_contract`); `Option<Option<OracleAccount>>` (`cache.rs:44`,
  documented) → `enum Cached { Miss, Absent, Present(T) }`; `Debug` missing on
  7 public types; 21 undocumented `pub` fns; chain ids as bare literals in two
  files (`fork.rs:70–72`, `ens/mod.rs:69`, `:145`); `B256::from(x.to_be_bytes::<32>())`
  where `B256::from(x)` exists (`database.rs:442`); `minus`/`merge` where std
  says `difference`/`Extend` (`database.rs:136`, `:144`); mixed by-value and
  by-reference `[u8; 20]` across the three traits; transaction type as `u8`
  consts compared ordinally (`tx.rs:45–53`, `:192`).
- **Positives**: `to_bytecode` (`database.rs:300–302`) names the revm
  `expect()` it avoids and is pinned by `malformed_eip7702_prefixed_bytecode_does_not_panic`;
  `keccak256(code) == hash` re-verified at the trust boundary (`:387–402`);
  `Relaxed` for the pure `runs` counter (`executor.rs:318`); the compile-time
  `const _: fn()` DB-error guard (`:1432–1435`); `const fn h20` address
  constants (`relay_adapt_7702.rs:723–741`); `fork.rs` pins every activation
  constant in decimal and hex (`:302–319`); `ReplayOracle` fails closed on any
  unrecorded read (`world.rs:285–302`); `request_from_json` refuses unknown
  fields (`:384–391`); `OnceLock` amortising a multi-second fixture replay
  across tests (`executor/tests/relay_adapt_7702_shield.rs:29`).

### 5.9 `myotis-engine`, `myotis-node`, `uniffi-bindgen` — the FFI layers

**Verdict.** Idiomatic where it matters most for an FFI crate: `host.rs` has
**zero** `unwrap`/`expect`/`[]` indexing on runtime data in about 5 600
production lines (6 451 minus two test modules) ("panic-free by construction", `host.rs:20–26`, is real),
saturating arithmetic at every window check, a documented and consistently
applied "snapshot under the lock, release, then `block_on`" discipline
(`:699–718`, `:985–1019`), every pointer-dereferencing C export is `pub unsafe
extern "C"` and every non-dereferencing one is safe, `CString::into_raw` /
`from_raw` are paired through one free function (`capi.rs:37–42`, `:734–739`),
the 54 C symbols match the header exactly and the header is a compile input of
a test (`capi.rs:772`), and there is no `catch_unwind` anywhere. `myotis-node`'s
threading model is right (bounded engine-owned workers, never the JS thread,
per-handle admission, a 90 s deadline + cancel bit, `#[must_use] Cancellation`).
The un-idiomatic side is structural and in `unsafe` hygiene. Counts
(production): host.rs unwrap/expect 0, `as` 9, `Result<_, String>` 14 fns;
capi.rs/ffi.rs 39 `unsafe fn`s with **0 explicit `unsafe {}` blocks** (the
bodies rely on edition-2021's implicit unsafe-fn body); myotis-node 77 `unsafe {}`
blocks + 3 `unsafe extern "C"` callbacks with 0 `// SAFETY:` comments.
Findings: A 0, B 35, C 38.

- **[B] `host.rs` bundles thirteen concerns in 6 450 lines**: engine singleton +
  runtime (`:175–208`), lifecycle + anchor-marker persistence (`:292–1252`),
  status JSON (`:981–1138`, `:3377–3529`), host knobs (`:1293–1479`), state
  reads (`:1508–1760`), EVM call/estimate/access-list + request parsing
  (`:1762–2629`), ENS (`:2128–2281`, `:3177–3291`), block/receipt/tx/fee reads
  (`:2637–3112`), the send gate, hex parsers, log-index config/status/query
  (`:4835–5763`), activity, read stats — with six test modules interleaved
  along exactly those seams. `spin_up` is 183 lines (`:695–877`),
  `get_logs_json_impl` 153.
- **[B] `Result<_, String>` with two meanings**: `parse_read_block` returns
  `Err(eljson::invalid_params_json(&msg))` — a finished JSON envelope
  (`:1486–1488`) — wrapping `parse_call_block`, whose `Err` is a message
  (`:1942`); `read_anchor` (JSON), `parse_state_overrides` (message),
  `parse_tx_args` ("`Err` is the ready JSON", `:2398–2402`),
  `parse_get_logs_filter` (message). The permanent-vs-retryable rule rides on
  string shape; the module already has the right model in miniature —
  `enum CallBlockRefusal` + `fn to_json(&self)` (`:1984–2016`).
- **[B] Five mutex-poisoning policies in one module** (32 lock sites): refuse
  (`:301`), swallow (`:536` `.lock().ok()?`), skip (`:790`), recover (`:885`),
  error string (`:3121` `map_err(|_| "engine lock poisoned")`), plus `Err(_) =>
  true` (`:5577–5592`); `ringlog.rs:54` drops output on poison while `usage.rs:150`
  recovers and `myotis-node` recovers uniformly at 18 sites.
- **[B] Process-global engine holding I/O**: `static ENGINE: OnceLock<Option<EngineState>>`
  (`:175`) owns the tokio runtime and twelve `Mutex<HashMap<i64, …>>` registries
  keyed by raw `i64`; `static STARTED: Once` (`:1264`); `static RECENT_REFUSALS:
  Mutex<Option<HashMap<..>>>` (`:5573–5575`, a `LazyLock` since 1.80). Forced by
  the JVM/UniFFI contract, but every `#[test]` shares one engine and one runtime
  (`:3879–3880`) and nothing can ever be torn down.
- **[B] Per-handle state as positional tuples**: `log_index_runtime_bits:
  Mutex<HashMap<i64, (bool, bool, bool)>>` whose doc spells the order
  "(enabled, max_speed, backfill_paused)" (`:113`, `:121`, read back at `:813`);
  `fee_history_cache: Mutex<HashMap<i64, (String, String, Instant)>>` (`:134`);
  `snapshot_reader(..) -> Result<(Arc<ElReader>, u64, u64), &'static str>`
  whose eleven callers mostly write `(reader, _, _)` (`:3138`); raw `i64` handle
  ids beside `i64` slots, nonces and periods in 49 `pub fn`s
  (`get_storage_proof_json(handle: i64, .., slot: i64, ..)` `:1538–1543`).
- **[B] Apply-or-refuse bent by a silent coercion**: `set_ws_bound_periods`
  does `let sane = periods.max(0) as u64;` (`:1442`) — a negative value is
  neither applied nor refused, it becomes "restore the default".
- **[B] Blocking fsync inside a tokio task**: the per-minute usage ticker is
  `engine.rt.spawn(async move { … tick_all_ledgers(engine) })` (`:1266–1271`)
  → `write_file` → `File::create` + `sync_all()` + `rename` (`usage.rs:219–226`)
  on a runtime worker that also drives the sync loop.
- **[B] `eljson.rs` builds JSON three ways with no `#[derive(Serialize)]`**:
  `serde_json::Map` insertion (`:67–68`, `account_json` and ten siblings),
  85 hand-concatenated `push_str` calls in `block_json` (`:208`, also receipts,
  txs, fee history, logs, activity), and one `json!` (`:934–949`); the module
  doc's rationale "Hand-built (not serde derive) so the key set + shape is the
  pinned contract" (`:3–4`) does not describe the `Map`-built half, whose
  emitted key order is serde_json's alphabetical `BTreeMap` order (verified:
  `preserve_order` is enabled nowhere in the graph), not the insertion order
  the source shows — and the golden test at `:2235` pins that incidental order.
  `catalog.rs:11–13` already proves a derive pins a cross-language shape
  byte-for-byte. `be_to_decimal` (`:1022–1036`) hand-rolls schoolbook bignum
  division while `U256` is a direct dependency.
- **[B] `capi.rs` hygiene**: pointer derefs rely on the implicit unsafe body
  with no `unsafe {}` block or `// SAFETY:` at the operation (`:27–31`
  `read_string`, `:174`, `:738` — what `unsafe_op_in_unsafe_fn`, warn-by-default
  in edition 2024, requires); a nested `unsafe fn path<'a>(p: *const c_char) ->
  Option<&'a str>` returns an unbounded lifetime (`:170–174`); seven exports
  lack `# Safety` (`:980`–`:1071`); three are `unsafe` without dereferencing
  anything (`:1022`, `:1044`, `:1051`), which is what drove `myotis-node` to
  suppress `unused_unsafe` crate-wide; **three NULL-pointer policies** on one
  ABI — NULL ⇒ `""` (`:268`), NULL ⇒ `invalid_params_json` (`:381–385`, well
  argued), NULL ⇒ NULL result (`:984–987`, which Node renders as a *retryable*
  error for a permanent caller fault); production functions appended after the
  test module (`:977–1079`) with a second spelling `std::os::raw::c_char` at 12
  sites; a Rust-only scheduler bridge re-exported from the "plain C ABI" module
  (`:1083`).
- **[B] Three hand-maintained forwarding layers, about 1 900 lines of
  pass-through**: 52 `#[uniffi::export]` fns whose bodies are
  `crate::host::X(handle, &a, &b)` (`ffi.rs:187–189`), 54 C exports of
  `read_string(..).unwrap_or_default()` + `into_c(crate::host::X(..))`
  (`capi.rs:301–309`), ≈45 napi fns of `c_arg` + `take(unsafe { myotis_X(..) })`
  (`myotis-node/src/lib.rs:811–822`). Structural (three ABIs), not accidental —
  but only the header test guards them staying in step; a declarative macro per
  layer would generate the ≈40 uniform ones and leave the deliberate exceptions
  visible as hand-written code. Sentinel-coded results (`create_handle -> i64`
  with −1/−2/−3, `ffi.rs:54–65`) where UniFFI offers `#[derive(uniffi::Error)]`
  typed errors — deferred by design, still worth raising.
- **[B] `myotis-node`**: crate-wide `#![allow(unused_unsafe)] // capi fns are a
  mix of safe/unsafe; calls are wrapped uniformly` (`lib.rs:22`) while `:202`
  and `:208` call capi fns *without* `unsafe` and eight safe fns are wrapped
  (`:92`, `:194`, `:215`, …); 77 `unsafe {}` blocks and 3 `unsafe extern "C"`
  callbacks with zero `// SAFETY:` comments, including ownership transfers
  whose soundness rests on three non-local facts (`scheduler.rs:88–89`
  `Box::from_raw(data.cast::<Completion>())`); raw Node-API pointers stored as
  `usize` to be `Send` and cast back (`:36`, `:52`, `:56`, `:148`, `:706`) —
  a newtype with `unsafe impl Send` + the invariant in a comment is the idiom;
  hand-counted byte lengths for C literals (`c"Myotis Promise completion
  failed".as_ptr(), 32` `:443–446`, `:463–464`, `:738–741`) where
  `NAPI_AUTO_LENGTH`/`count_bytes()` cannot drift; raw `napi::sys` TSFN/deferred
  machinery (36 unsafe blocks) where napi 3 ships `ThreadsafeFunction` and
  `JsDeferred` — the reasons are written down (`:143–146`, `:253–254`,
  `:549–550`) but a module-level "evaluated and rejected because" note is
  missing; four `eprintln!` (`:122`, `:173`, `:218`, `:233`), which panic on a
  stderr write error such as `EPIPE` (std ignores only a closed descriptor)
  and so abort the Electron process under `panic = "abort"`;
  NUL-byte refusal shaped as retryable in two entry points and permanent in the
  rest (`lib.rs:76–78`, `:472–475`).
- **[B] Doc bugs**: the `///` for `get_transaction_receipt_json` runs into
  `pending_nonce_overlay`'s and both land on the latter (`host.rs:2665–2678`;
  `:2695` has no doc); `host.rs:3390–3391` and `eljson.rs:3–4` claim a
  hand-built key ordering that `serde_json::Map` does not give (§4.14).
- **[B] Three copies of the fixed-width hex parser** (`host.rs:3295–3305`,
  `:3309–3321`, `:3346–3356`, the same loop with N = 20/32) and the `0x`/`0X`
  strip written out 14 times (`:1749`, `:1959`, …, `myotis-node/src/lib.rs:507`,
  `:593`, …); `hex0x_var`/`hex32` duplicated between `eljson.rs:1011` and
  `host.rs:3369` (the latter allocating per byte, the thing `eljson.rs:1016`
  comments against).
- **[C]** `myotis_net::el::logindex::` spelled out ×45 and `myotis_evm::` ×24
  inline (`host.rs:4939–4941`, `:5366–5371`); `std::sync::atomic::Ordering`
  fully qualified beside its import (`:1452`); an `Option` flattened into
  sentinel + bool (`:1815–1816`); nested `Result<Result<_, _>, String>`
  (`:3000–3004`); `Some(0)` as a magic "tearing down" id (`:529–538`); leftover
  brace blocks around whole bodies (`:5292–5408`); `std::collections::hash_map::DefaultHasher`
  (home: `std::hash::DefaultHasher` since 1.76, `:5563`); `ringlog.rs`'s
  `OnceLock` around a const-constructible `Mutex<VecDeque<_>>` and a manual pop
  loop where `drain(..n)` fits; `usage.rs` hand-navigating `serde_json::Value`
  for a five-field file (`:188–190`, `:209–218`) beside the derive in
  `catalog.rs`; `catalog.rs:67` `expect("static catalog always serializes")` on
  a host-reachable path; `lib.rs:376–378` a public re-export kept only "so
  `cargo build -p myotis-engine` type-checks the consensus crate"; the manifest
  description still says "JNI cdylib" (`Cargo.toml:6`); `uniffi = "0.32"`
  pinned by hand in two manifests although `uniffi-bindgen/Cargo.toml:11–13`
  says a skew is a build error by design; `admission.rs:41–49` an O(n²)
  index-walking remove loop; `requests: HashMap<u64, (i64, Arc<AtomicBool>)>`
  (`scheduler.rs:58`); `std::result::Result<CString, String>` spelled out
  because `napi::Result` shadows the prelude (`lib.rs:76`).
- **Positives**: `parse_hex_bytes` caps the input *before* `Vec::with_capacity`
  because an OOM is an abort too (`host.rs:3327–3334`); the lock order
  `handles → tearing_down` stated and kept (`:534–535`, `:1202`);
  `CallBlockRefusal` as a typed permanent/retryable refusal with its JSON in one
  place; pure unit-tested parsers that apply-or-refuse every parameter
  (`parse_tx_request`, `parse_state_overrides`, `parse_get_logs_filter`,
  `parse_boot_enodes_json`); anchor-marker persistence with a *required*
  parent-directory fsync and the failure mode explained (`:599–637`); NULL `to`
  on `eth_call` refused rather than collapsed onto contract creation, with a
  cross-wrapper test (`capi.rs:373–385`, `:940–974`); `usage.rs:245–248` the
  one correct `// SAFETY:` in the engine; `LIVE_WORKERS.fetch_update(AcqRel,
  Acquire, |n| ..)` as a one-expression CAS loop (`scheduler.rs:417–421`); the
  Node admission queue as a pure, tested type; every refusal across the three
  ABIs is the same permanent −32602 envelope.

### 5.10 `myotis-rpcd`, `roost`, `tor-poc` — the binaries

**Verdict.** `myotis-rpcd` is a carefully written blocking daemon: a `match`
on method strings over `serde_json::Value`, every client-controlled
index/length bounds-checked (`get`, `checked_add`, `saturating_sub`;
`decode_revert_reason` `rpc.rs:1328–1361` with a `u64::MAX`-offset regression
test), **one** typed error enum (`Fail`, `rpc.rs:124–144`) mapped to JSON-RPC
codes in one place (`fail_parts`, `:504–538`), readiness as a per-body budget
without a mutex (`Budget`/`Gate`, `:203–216`), and minimal documented `unsafe`
(`checkpoint.rs:73–89`, `seeds.rs:59–62` — two of the three `// SAFETY:`
comments in production code in the tree). Zero `unwrap` on the request path.
`roost` is **the cleanest crate**, as expected from the one lane that runs
`-D warnings`: 0 `unsafe`, 0 `Result<_, String>`, `anyhow` used idiomatically
with `.context()`, typed `FetchError`/`FramingError` with `Display + Error`
driving requeue-vs-give-up, checked arithmetic on every wire/file length, a
documented poison policy (`store.rs:125–141`), `create_new(true)` + `mode(0o600)`
in one open, write → fsync → rename → dir-fsync for the ENR sequence
(`enr.rs:82–106`), `const { assert!(..) }` invariants. `tor-poc` is idiomatic for
a proof of concept (anyhow, explicit `timeout` on every await with the reason
stated). Counts (production): rpcd unwrap/expect 2, `as` 13, `Result<_, String>`
10; roost 6 (all infallible fixed-slice `try_into`), 9, 0; tor-poc 4 (on
constants), 0, 0. Findings: A 2 (both roost, both real bugs of low impact),
B 24, C 38.

- **[A — bug] Ctrl-C swallowed while a tick body runs** (`roost/src/serve.rs:578–581`):
  `tokio::signal::ctrl_c()` is a fresh future every `select!` iteration, so
  while the tick arm's body runs (loopback REST calls, outbound probe dials)
  no listener exists and tokio's registry drops the pending SIGINT: a Ctrl-C
  during a tick is lost (one while the loop is parked on `ctrl_c()` works), and
  SIGTERM is never handled. Fix: pin one `ctrl_c()` future before the loop (plus a
  `SignalKind::terminate()` stream).
- **[A — bug, cosmetic] `/ip4/{ip}` formatted around an address that can be
  IPv6** (`serve.rs:534`, `:1130`, `:1139`): `upstream_external_ip`
  deliberately falls back to a routable v6 (`:1094–1101`), producing the
  unparseable `/ip4/2001:db8::…` multiaddr that `dialable()`'s own doc
  (`:267–269`) says it exists to prevent; publication is unaffected (filtered
  at `:1022`).
- **[B] `myotis-rpcd`**: the served-method table is maintained twice —
  `arity()` (`rpc.rs:91–122`) and the `dispatch` match (`:593–855`), whose `_ =>
  Err(Fail::Unsupported)` arm is unreachable (a method added to one and not the
  other is a silent code mismatch); `dispatch` is 284 lines and `run` 175; 40
  magic JSON-RPC code literals (`-32602` ×…, `-32000`, `-32601`) where consts
  or an `enum ErrorCode` would let `permanent_code` and `fail_parts` share one
  definition; `fail_parts` returns `(i64, String, Option<String>)`, which is
  `Fail::Rpc`'s own shape (`:504`); five eager `ok_or(Fail::Unavailable(Some("…".into())))`
  / `ok_or(format!(..))` allocations on the success path (`:666–668`,
  `:693–695`, `:1770`, `:1778`, `:1795`) beside `ok_or_else` done right at
  `:1370`; `&Vec<Value>` with an `empty` sentinel instead of `&[Value]`
  (`:580–583`); `header()` allocating a `String` per lookup, five per request
  (`http.rs:358–363`); `fn main()` + `process::exit(1)` instead of `ExitCode`
  (`main.rs:129–139`); `bound.expect("guarded")` on a value the enclosing match
  already knows (`:208–211`); `OVERRIDE_UNSUPPORTED.replace("{m}", ..)` string
  templating on a `const` (`rpc.rs:862`, `:905`); `parse_wei_quantity -> Option<String>`
  where a `Quantity` newtype with `FromStr`/`Display` is the idiom
  (`quantity.rs:28`); 10 `Result<_, String>` startup/parse sites.
- **[B] `roost`**: a hand-rolled `while i < args.len()` argv parser with six
  near-identical `.ok_or_else(|| anyhow!(..usage()))?` (`main.rs:80–135`) in a
  crate that already links reqwest and tokio, while `myotis-rpcd` uses clap
  derive; `serve()` is 505 lines (`serve.rs:403–907`) with a ~300-line tick body
  carrying eight pieces of loop state and `match`es five deep; root parsing
  re-implemented three times and `finalized_root` duplicating
  `finalized_checkpoint` (`rest.rs:600–623` vs `:127–132`, `:475–487`); the
  capped body-reading loop written twice (`rest.rs:249–269` vs `:292–312`);
  `bootstrap_order.clone()` where `mem::take` fits (`store.rs:243`); two parallel
  `match`es with `unreachable!()` arms encoding one decision three times
  (`main.rs:452–481`); `Result<(ChainParams, Result<Self>)>` (`forks.rs:88–91`);
  two positional `bool`s and a raw `[u8; 16]` ENR fork id in the publication
  gate (`serve.rs:997–1004`); `Archive::open` returning a positional 3-tuple
  (`archive.rs:106–109`).
- **[B] `tor-poc`**: a generic bound on the extension traits (`S: AsyncReadExt
  + AsyncWriteExt + Unpin`, `main.rs:293`) instead of `AsyncRead + AsyncWrite`;
  every `Peer` deep-copied to turn `Vec<&Peer>` into `&[Peer]` because `Peer`
  derives nothing (`:450–453`, `:67–71`).
- **[C]** `SeqCst` on a stop flag and a counter (`rpcd main.rs:313`,
  `http.rs:212`); `PartialEq` without `Eq` on five rpcd types; a raw `i64`
  engine handle passed around (`engine.rs:66`, `main.rs:351`) where
  `StopOnDrop(i64)` already wraps it; `% 2 == 1` next to `is_multiple_of(2)`
  (`rpc.rs:1428` vs `quantity.rs:134`); a likely-dead `#[allow(clippy::too_many_arguments)]`
  on a 7-input fn (`engine.rs:35`); FFI sentinel integers decoded inline
  (`main.rs:227–229`); `fnv64` as the third copy in the tree (`rpc.rs:1947`,
  `roost/src/archive.rs:60`, `logindex.rs:1080`); the 1 296-line test file
  exported as `pub(crate) mod tests` so `http.rs` can import its `Fake`
  (`rpc.rs:1979–1980`); roost's 21 `println!` beside 44 `tracing::` sites in the
  daemon; `pub` and `pub(crate)` used interchangeably in a `[[bin]]`-only crate;
  only SIGINT handled; no advisory lock on the archive file; tor-poc's
  `map_or(true, ..)` (`:349`), a dead `let _ = advertised;` (`:256`),
  `getrandom = "0.2"` two majors behind (since moved to 0.4, with myotis-net).
- **Positives**: `Fail` → `fail_parts` as the single mapping point; the
  `Budget`/`Gate` one-hold-per-body design pinned by timing tests
  (`rpc/tests.rs:1157–1175`); `floor_char_boundary` for safe truncation
  (`rpc.rs:1938`); roost's `ChainParams` with private fields making a zero
  epoch length unconstructible (`rest.rs:47–58`, `:88–119`); `split_updates`
  (`framing.rs:127–170`) and `read_record` (`archive.rs:300–342`) checking every
  length; pure decision functions (`needs_refetch`, `should_replace`,
  `desired_publication`) pinned by table tests; tor-poc's `{e:#}` anyhow chains
  and typed `AccountOutcome` matching (`main.rs:489–507`).


## 6. What the code already does well

- **No reachable panic found.** Eleven reviewers traced every `unwrap`,
  `expect`, index and arithmetic operation reachable from a peer, a file or a
  host call across the whole tree and found one low-likelihood abort
  (`expect("OS entropy")`). For a 115 k-line codebase that ships under
  `panic = "abort"` into other people's processes, that is the headline.
- **Panic-free decoders in the trust-critical crates**: `myotis-core` and
  `myotis-wire` production code has no `unwrap()`; RLP, SSZ, ENR, trie-proof
  and snap decoding return `Result` and are fuzz-shaped by the conformance
  corpora (`myotis-core/tests/el_conformance.rs`, `rlp_alloc_bound.rs` even
  bounds allocation).
- **Compiler-enforced layering**: `#![cfg_attr(not(feature = "std"), no_std)]`
  + `extern crate alloc` in the sans-I/O crates, the `std` feature forwarded
  to dependencies, the `x86_64-unknown-none` canary, one-way dependencies
  (`myotis-net → myotis-consensus`, never back), `core::error::Error` in
  `myotis-core`.
- **Modern control flow**: 323 `let … else`, 157 `matches!`, `is_some_and`,
  `windows(2)`, iterator chains rather than index loops in the codecs
  (`myotis-wire/src/eth.rs:835` implements `IntoIterator` for a raw RLP list).
- **Dependency intent is written down**: every pin, feature and
  target-specific dependency in the manifests carries the reason, exact pins
  where wire interop depends on them, optional heavy trees (`tor`, `fixture`)
  off by default.
- **Honest FFI**: errors stay in-band as documented JSON envelopes, the C ABI
  is versioned (`ABI_VERSION`, with a change log per version), `# Safety`
  sections exist on 31 of 39 `unsafe fn`s, no `catch_unwind` theatre
  under `panic = "abort"`.
- **Tests as the specification**: `#[ignore]`d live tests with a documented
  purpose, paused-clock tokio tests, golden JSON shapes pinned on both sides
  of the FFI, the Java twin's vectors replayed in Rust.

## 7. Suggested order of work (proposals, not started)

Each line is a separate, reviewable change; the first four are mechanical or
tiny.

1. **Fix the wrong comments (§4.14) and the small bugs (§4.15)** — a
   half-day, no design decisions, immediate value for the next reader.
2. **`cargo fmt --all`** once (whitespace-only commit) and a `cargo fmt --check`
   step in `rust-clippy.yml`; the same for `roost`.
3. **Clear the 65 default-lint sites** (Appendix A) and move the lane to
   `-D warnings`, declared in a `[workspace.lints]` table rather than on the
   command line; then ratchet `pedantic` groups one at a time
   (`cast_possible_truncation` and `or_fun_call` first — they carry
   correctness weight). Add `-D rustdoc::broken_intra_doc_links` as roost's
   lane already does.
4. **One lock policy**: a workspace helper (or `parking_lot`) replacing the
   five spellings; shorten the 44 over-long guard lifetimes while there.
5. **Replace the six text-classified errors (§4.2) with enums** —
   `FetchError` in `myotis-wire`, `HandshakeError` for the pool, a
   `ReadError` for `fetch_anchored_window`, a `RequestError` for
   `request::check`, a `TorError` — this is the change with the most
   correctness weight per line.
6. **Blocking I/O off the runtime** (§4.8): `spawn_blocking` around the
   snapshot, peer-cache, Tor-reserve, log-index and usage-ledger writes; make
   the two non-atomic rewrites (`peercache.rs:587`, `torreserve.rs:255`) temp +
   rename like `logindex::write_atomic`.
7. **Typed errors on the hot paths**: `el/reader.rs`, `el/rlpx/transport.rs`,
   `el/eth/session.rs`, `engine/host.rs`'s two-meaning `Result<_, String>`;
   make `CoreError`/`SszError`/`CodecError` kind-carrying enums and use
   `core::error::Error` in all three.
8. **Newtypes**: `Slot`/`Epoch`/`Period` in `myotis_consensus::spec`;
   `Root`/`BlockHash`/`StateRoot`/`TxHash`/`Address`/`NodeId` as
   `#[repr(transparent)]` wrappers with `From<[u8; N]>` both ways so the FFI
   layer is untouched; `EthVersion(u8)`; `HandleId(i64)` below the engine's ABI.
9. **Split the four largest files** along the seams §5 names (`el/reader.rs`
   → per-read-family modules plus `el/logindex/{tail,backfill,chunk_sizer,persist}.rs`;
   `engine/host.rs` → `host/{lifecycle,status,reads,evm,ens,blocks,logindex,parse}.rs`;
   `sync.rs` along its own section markers; `el/pool.rs`'s `PoolInner` into
   grouped sub-structs), and turn `catch_up`/`run_sync`/`serve` into
   state-machine steps on a struct.
10. **Public surface**: `pub(crate)` sweep in `myotis-net` with a curated
    `pub use` list at the root (other crates import about 13 items from the
    fifteen smaller EL modules); replace the nine glob shims with module
    re-exports in the parent `mod.rs`; `#[derive(Debug)]` on the 76 public
    types that lack it; `#[must_use]` on the verification verdicts, builders
    and handles.
11. **Serde DTOs** for the FFI JSON shapes (`eljson.rs`, `readstats.rs`,
    `usage.rs`, the fixture files), keeping the golden tests as the pin;
    `uninlined_format_args` fix-up and one shared `hex` helper alongside (it
    is hand-rolled in at least nine places in `src/` and ten in `tests/`).
12. **Edition 2024** via `cargo fix --edition`, with `// SAFETY:` comments on
    every remaining `unsafe` block, explicit `unsafe {}` at the deref sites in
    `capi.rs`, the three needlessly-`unsafe` C exports made safe, and the
    `myotis-node` blanket `#![allow(unused_unsafe)]` removed.
13. **`tests/common/mod.rs`** in `myotis-net`, `myotis-core` and
    `myotis-consensus`; make the conformance tests fail, not skip, on a missing
    corpus; one `NET` gate.

## Appendix A — the 65 default clippy sites (`cargo clippy --workspace --all-targets`)

What stands between `rust-clippy.yml` and `-D warnings`, grouped by lint;
`tests/`/`examples/` sites included because the lane runs `--all-targets`.

| lint | sites | locations |
|---|---|---|
| `manual_is_multiple_of` | 20 | `consensus/src/types.rs:502`, `:731`; `engine/src/host.rs:3330`; `net/src/discovery.rs:305`; `net/src/el/reader.rs:3308`, `:3675`, `:3734`, `:4373`, `:4385`, `:4815`, `:5008`, `:5096`, `:13927`; `net/src/el/served.rs:83`; `wire/src/rlpx/frame.rs:205`; `bls/tests/conformance.rs:38`; `consensus/tests/lc_conformance.rs:52`, `resume_equivalence.rs:43`; `net/examples/lc_crawl.rs:207`, `period_census.rs:480` |
| `type_complexity` | 9 | `evm/src/ens/mod.rs:576`; `evm/src/executor.rs:2266`, `:2364`; `evm/src/oracle.rs:281`; `net/src/el/pool.rs:703`, `:1532`, `:2834`; `net/src/el/served.rs:106`; `wire/src/snap/messages.rs:377` |
| `missing_safety_doc` | 7 | `engine/src/capi.rs:980`, `:992`, `:1022`, `:1044`, `:1051`, `:1058`, `:1071` |
| `manual_saturating_arithmetic` | 4 | `consensus/src/types.rs:498`, `:606`, `:730`; `net/src/clcache.rs:126` |
| `too_many_arguments` | 4 | `net/src/discovery.rs:244` (10); `net/src/el/pool.rs:1522` (11); `net/src/reqresp.rs:1417` (8); `wire/src/eth.rs:143` (8) |
| `unnecessary_map_or` | 3 | `net/src/el/peercache.rs:208`; `wire/src/rlpx/frame.rs:229`, `:380` |
| `unnecessary_sort_by` | 3 | `net/src/el/reader.rs:1906`; `net/examples/lc_crawl.rs:256`, `:262` |
| `mixed_case_hex_literals` | 2 | `engine/src/host.rs:6198`; `evm/src/ens/mod.rs:37` |
| `cloned_ref_to_slice_refs` | 2 | `core/src/trie.rs:396`; `wire/src/snap/fetch.rs:357` |
| `field_reassign_with_default` | 2 | `net/src/el/evm.rs:1503`, `:1526` |
| `int_plus_one` | 1 | `net/src/el/reader.rs:13583` |
| `empty_line_after_doc_comments` | 1 | `net/src/sync.rs:664` |
| `redundant_closure` | 1 | `net/src/el/reader.rs:7647` |
| `doc_lazy_continuation` | 1 | `net/tests/live_reader.rs:3` |
| `double_ended_iterator_last` | 1 | `net/tests/live_cold_start.rs:121` |
| `single_match` | 1 | `net/examples/lc_crawl.rs:219` |
| `items_after_test_module` | 1 | `engine/src/capi.rs:742` |
| `manual_range_contains` | 1 | `node/src/lib.rs:174` |
| `useless_format` | 1 | `engine/src/host.rs:6444` |

## Appendix B — the larger lint groups, for the ratchet

Pedantic (2 320 sites beyond the default set): `doc_markdown` 537,
`must_use_candidate` 463, `missing_errors_doc` 278, `cast_possible_truncation`
153, `redundant_closure_for_method_calls` 136, `duration_suboptimal_units` 93,
`needless_pass_by_value` 73 (56 of them are the UniFFI/napi exports in
`engine/src/ffi.rs` and `node/src/lib.rs`, where owned `String` parameters are
required by the binding generators — a false positive to allow there),
`missing_panics_doc` 58, `items_after_statements` 49, `map_unwrap_or` 45,
`cast_lossless` 30, `too_many_lines` 29, `manual_let_else` 28,
`format_collect` 28, `large_futures` 26, `elidable_lifetime_names` 26.

Nursery (1 082): `use_self` 392, `too_long_first_doc_paragraph` 296,
`missing_const_for_fn` 159, `option_if_let_else` 81,
`significant_drop_tightening` 44, `redundant_clone` 35, `or_fun_call` 31,
`redundant_pub_crate` 24, `derive_partial_eq_without_eq` 5,
`future_not_send` 3.

rustdoc (`-W rustdoc::all`, 79): `private_intra_doc_links` 53,
`broken_intra_doc_links` 23, `missing_crate_level_docs` 1,
`redundant_explicit_links` 1, `invalid_html_tags` 1.
