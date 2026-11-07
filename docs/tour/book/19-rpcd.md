# myotis-rpcd: a JSON-RPC daemon in Rust

*Stop 19 · crate `myotis-rpcd`* · 8 files · 5,176 lines · about 155 minutes

A new crate since September, and a *binary* crate: one executable that links the engine as a library and answers standard Ethereum JSON-RPC over HTTP, with no JVM and no upstream RPC to fall back on. It exists for hosts that only need a local endpoint: a server, a Raspberry Pi, a container, or a Swarm Bee node. Every answer is one the engine verified; anything it cannot verify is an error. The design is deliberately synchronous: the engine owns its tokio runtime and every read is a blocking call, so the daemon is a blocking HTTP server with two thread pools in front of a router that ports the strict path of the Kotlin `RpcRouter`.

## Rust you will practise

- **A binary crate** `main.rs` + `mod` files, clap's derive macros, `Result<(), String>` and `?` with `From`, `#[cfg(unix)]`/`#[cfg(windows)]`, and a drop guard that stops the engine on every exit path.
- **Threads and channels** `Arc`, a bounded `mpsc::sync_channel` shared through `Arc<Mutex<Receiver>>`, `try_send` giving the value back, atomics, and `Cell` for per-request state that never leaves its thread.
- **Traits as seams** — A `Send + Sync` `Engine` trait with a real and a fake implementation, a generic `Router<E: Engine>`, a `Read` decorator, a `Fail` enum mapped to error codes in one place, and checked arithmetic over attacker-controlled bytes.

![A request through myotis-rpcd. An HTTP client sends a request. One of four intake threads checks the Host and Content-Type headers and parses the body; a large or chunked body is first received on a body-reader thread with a deadline. A body that names only non-blocking methods is answered by the router on the intake thread. A body that names a gated method is sent through a bounded channel to one of the read workers; if the channel is full the request is refused with 503. A read worker runs the router, which holds the request until the node is ready or the ready-wait budget runs out, then calls the engine's blocking ffi functions.](img/19-rpcd-1.svg)

*Two pools, so a health check never waits behind a read that is held for a verified head. Intake never reads from a client's socket; the read pool's size bounds concurrent engine reads, and the channel bounds how many more may wait.*

## The crate at a glance

There is no `lib.rs`: a package with only `src/main.rs` is a binary crate, and `cargo build -p myotis-rpcd --release` produces `target/release/myotis-rpcd`. The six `mod` lines at the top of `main.rs` pull in the other files; `rpc.rs` in turn declares `mod tests;`, whose source lives at `rpc/tests.rs` (the Rust 2018 layout: a module `rpc` may keep its children in a directory named after it, with no `mod.rs`). Being a workspace member, the binary inherits the workspace release profile, including `panic = "abort"`: a panic ends the process, and the data dir resumes on restart.

| File | Role |
|---|---|
| [main.rs](#f-myotis-rpcd-src-main-rs) | CLI flags, startup order, the engine handle and its stop guard, signals, the log-drain and log-index threads. |
| [engine.rs](#f-myotis-rpcd-src-engine-rs) | The `Engine` trait (the router's view of the engine), the real `FfiEngine`, and `Readiness`. |
| [http.rs](#f-myotis-rpcd-src-http-rs) | tiny\_http, the intake and read pools, Host and Content-Type checks, body limits and deadlines. |
| [rpc.rs](#f-myotis-rpcd-src-rpc-rs) | The JSON-RPC router: envelopes, batches, the method table, parameter parsing, engine-JSON reading, error codes. |
| [quantity.rs](#f-myotis-rpcd-src-quantity-rs) | QUANTITY and DATA hex encoding, 256-bit decimal ↔ hex without a bignum crate. |
| [checkpoint.rs](#f-myotis-rpcd-src-checkpoint-rs) | `--checkpoint-root/--checkpoint-slot` and the data dir's anchor marker. |
| [seeds.rs](#f-myotis-rpcd-src-seeds-rs) | `--boot-enodes`: parse the list, push it to the engine, quote its refusal. |
| [rpc/tests.rs](#f-myotis-rpcd-src-rpc-tests-rs) | 30 router tests against a recorded `Fake` engine. |

## Cargo.toml: five dependencies

Five dependencies, each with a comment that says why. The engine comes in as an ordinary path dependency (an rlib), so the daemon calls its functions directly as Rust: the `ffi` module's (which also carry `#[uniffi::export]` for the JVM hosts) and two `capi` ones. Nothing crosses a language boundary.

`rust/myotis-rpcd/Cargo.toml` · lines 9–29

```toml
[dependencies]
# The engine's public `ffi` surface (plus the two `capi` entries `ffi` has no
# wrapper for, create-with-checkpoint and set-boot-enodes). Default features:
# no Tor.
myotis-engine = { path = "../myotis-engine" }
# No tokio and no tracing here: the engine owns its runtime and its log ring,
# and this crate only ever calls the engine's blocking functions.
serde_json = "1"
# Only for `IgnoredAny` (counting a long result's elements in the call log
# without building them); already in the lock through serde_json.
serde = "1"
# clap is already in the lock (uniffi); its default `color` feature is left off
# because it alone would add six crates to it.
clap = { version = "4", default-features = false, features = ["std", "derive", "help", "usage", "error-context", "suggestions"] }
# A blocking HTTP/1.1 server: every engine read blocks (it may hold for a
# verified head), so a fixed worker pool over a synchronous server is the whole
# design — see main.rs. No async stack is linked for it.
tiny_http = "0.12"
# The `iterator` module exists only off Windows; main.rs waits on it under
# cfg(unix) and polls `signal_hook::flag` on Windows, which needs no feature.
signal-hook = { version = "0.4", default-features = false, features = ["iterator"] }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **No HTTP framework and no async runtime.** `tiny_http` is a small blocking HTTP/1.1 server: you call `server.recv()` and get a `Request`, and you answer it with `request.respond(response)`. The comment states the reasoning: every engine read blocks, so a fixed worker pool over a synchronous server is the whole design. The `http.rs` module doc adds that an async server "would only add a second runtime whose every handler is `spawn_blocking` around the same calls".
- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* **Feature selection to keep the lock file small.** `clap` is already in the lock through uniffi, so it costs nothing new, but its default `color` feature would add six crates, so `default-features = false` and an explicit feature list. `signal-hook` gets only `iterator`, which exists only off Windows. `serde` is listed only for `IgnoredAny` (see the call log in rpc.rs).

<a id="f-myotis-rpcd-src-main-rs"></a>

### myotis-rpcd/src/main.rs

*binary entry point · 455 lines*

Parses the command line, checks every input before the engine starts, creates one engine handle for one network, starts the HTTP pools, and waits for SIGINT or SIGTERM. "One engine handle per process": a second network is a second daemon on another port.

`rust/myotis-rpcd/src/main.rs` · lines 31–48

```rust
#[derive(Parser)]
#[command(
    version,
    about = "JVM-free JSON-RPC daemon over the myotis verified light-client engine"
)]
struct Args {
    /// Network to follow.
    #[arg(long, default_value = "gnosis", value_parser = ["gnosis", "mainnet", "sepolia", "chiado"])]
    network: String,
    /// Engine state directory (sync anchor, peers, log index).
    /// Default: ~/.local/share/myotis-rpcd/<network>.
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Address to serve JSON-RPC on. Default: loopback, on the port the apps
    /// and the daemon use for the network (mainnet 8545, gnosis 8546, sepolia
    /// 8547, chiado 8548). The node signs nothing, but it is not built to face the internet.
    #[arg(long, value_name = "ADDR")]
    listen: Option<SocketAddr>,
```

- *[Macros & attributes](01-primer.md#primer-macros) · [Binaries, CLIs & signals](01-primer.md#primer-cli)* **clap's derive.** `#[derive(Parser)]` generates the argument parser from the struct. Each field becomes a flag (`data_dir` → `--data-dir`), its `///` doc comment becomes the help text, and its type decides the parsing: `Option<PathBuf>` is an optional flag, `bool` a switch, `Vec<PathBuf>` a repeatable one, `Option<SocketAddr>` is parsed with `SocketAddr`'s `FromStr`. `value_parser = [...]` restricts the value to a list. Compare picocli's annotations, except that the code is generated at compile time.
- *[Binaries, CLIs & signals](01-primer.md#primer-cli)* `Args::parse()` in `main` exits the process with a usage message on a bad command line, so `run` only ever sees valid flag syntax. Cross-flag rules are declared too: `--checkpoint-root` and `--checkpoint-slot` each `requires` the other, and `--import-log-index` requires `--log-index-config`.

| Flag | Default | Effect |
|---|---|---|
| `--network` | gnosis | gnosis, mainnet, sepolia or chiado. |
| `--data-dir` | `$HOME/.local/share/myotis-rpcd/<net>` | Engine state (sync anchor, peers, log index). |
| `--listen` | 127.0.0.1 on the catalog's `defaultRpcPort` | 8545 mainnet, 8546 gnosis, 8547 sepolia, 8548 chiado. |
| `--http-vhosts` | localhost, 127.0.0.1, \[::1\], the listen address | Host-header allowlist; a list replaces it, `*` disables it. |
| `--workers` / `--http-queue` | 16 / 2 × workers | Concurrent engine reads / how many more may wait. |
| `--ready-wait` | 90 s | How long a read (or a batch) is held for readiness. |
| `--http-body-timeout` | 10 s | Time to receive a large body, else 408. |
| `--checkpoint-root` + `--checkpoint-slot` | none | Bootstrap from an operator-supplied anchor. |
| `--accept-stale-anchor`, `--ws-bound-periods` | off / network default | Trust decisions past the weak-subjectivity bound, this run only. |
| `--boot-enodes` | none | EL peers to dial at start: a comma list or `@FILE`. |
| `--log-index-config`, `--import-log-index` | none | Enables `eth_getLogs`; imports seed snapshots. |
| `--log-calls FILE`, `--access-log` | off | One JSON line per request / one stderr line per request. |

#### Startup: check everything first

`run` returns `Result<(), String>`. Before any flag is used it calls `ffi::engine_init()` and compares the result with `myotis_engine::ABI_VERSION`; the engine is linked statically, so a mismatch means a broken build. It then turns on EIP-1459 DNS discovery (the daemon, like the JVM daemon, may use the system resolver), resolves the network name, and reads the chain id and the default port from the engine's network catalog JSON.

`rust/myotis-rpcd/src/main.rs` · lines 184–199

```rust
let imports = args
    .import_log_index
    .iter()
    .map(|p| std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display())))
    .collect::<Result<Vec<_>, _>>()?;
let call_log = match &args.log_calls {
    Some(p) => Some(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map_err(|e| format!("{}: {e}", p.display()))?,
    ),
    None => None,
};
let boot_enodes = args.boot_enodes.as_deref().map(seeds::load).transpose()?;
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`collect::<Result<Vec<_>, _>>()?`** turns an iterator of `Result`s into one `Result`: all `Ok` gives the vector, the first `Err` stops the iteration and is returned. Java streams have no direct equivalent; you would collect and then check.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`.as_deref().map(seeds::load).transpose()?`**: `as_deref` turns `&Option<String>` into `Option<&str>` without moving the string out of `args`; `map` gives `Option<Result<Vec<String>, String>>`; `transpose` flips it to `Result<Option<…>, …>`, so `?` can return the error and leave `None` when the flag is absent.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The server is bound right after this (line 203), before the engine starts, "so a taken port fails in milliseconds". The same idea runs through the whole function: a typo must not cost a started engine handle.

`rust/myotis-rpcd/src/main.rs` · lines 206–256

```rust
// A dir already bound to a caller-supplied anchor resumes THAT anchor: the
// engine refuses any other (including a plain create), so a restart without
// the flags must reuse it. An explicit pin is still passed through as given
// and the engine judges it.
let bound = checkpoint::bound_anchor(&data_dir, &network)?;
let checkpoint = match (&args.checkpoint_root, args.checkpoint_slot) {
    (Some(root), Some(slot)) => Some(checkpoint::explicit(root, slot)?),
    (None, None) if bound.is_some() => {
        let cp = bound.expect("guarded");
        eprintln!(
            "myotis-rpcd: {} is bound to checkpoint root {} slot {}; resuming it",
            data_dir.display(),
            cp.root,
            cp.slot
        );
        Some(cp)
    }
    _ => None,
};
let dir_str = data_dir.to_string_lossy().into_owned();
let handle = match &checkpoint {
    Some(cp) => checkpoint::create_handle(&network, &dir_str, cp),
    None => ffi::create_handle(network.clone(), dir_str),
};
match handle {
    -1 => return Err(format!("engine could not create a '{network}' handle")),
    -2 => {
        return Err(format!(
            "network '{network}' is not supported by this engine"
        ))
    }
    -3 if checkpoint.is_some() => {
        return Err(format!(
            "{} is bound to a different trust anchor (the embedded checkpoint, or another \
             root/slot); a new checkpoint needs a fresh --data-dir",
            data_dir.display()
        ))
    }
    -3 => {
        return Err(format!(
            "{} was bootstrapped from a caller-supplied checkpoint; pass the same \
             --checkpoint-root/--checkpoint-slot, or use another --data-dir",
            data_dir.display()
        ))
    }
    h if h < 1 => return Err(format!("engine create failed ({h})")),
    _ => {}
}
// From here every way out of this function stops the handle (it persists
// its sync state); the graceful path drops this guard explicitly.
let guard = StopOnDrop(handle);
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Matching on a tuple and on sentinels.** `match (&args.checkpoint_root, args.checkpoint_slot)` takes the two flags apart together; the arm `(None, None) if bound.is_some()` adds a guard. On the handle, `-3 if checkpoint.is_some()` and a second `-3` arm give the same sentinel two messages, and `h if h < 1` binds any other negative value. The engine's negative handles are the C ABI's in-band errors ([Stop 16](16-engine.md)); here they become readable messages.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `bound.expect("guarded")` cannot fail because the guard just checked `is_some()`; `expect` documents that reasoning in the panic message.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **`StopOnDrop(handle)`** is a drop guard (below): from this line on, every `return Err(…)` and every `?` drops `guard`, which stops the handle and lets it persist its sync state.

The rest of `run` (lines 257–304) applies the trust overrides, pushes the boot enodes *before* `start_handle` (the engine stashes them and dials once its EL pool is up), starts a thread that pumps the engine's log ring to stderr every 500 ms, starts a thread that retries the log-index config every 2 s until the EL reader accepts it, and builds the router with chained builder calls (`Router::new(…).with_ready_wait(…).with_access_log(…)`, each taking `self` by value and returning it).

`rust/myotis-rpcd/src/main.rs` · lines 306–319

```rust
    // Graceful stop: stop accepting, shut the engine handle down (it persists
    // its sync state), flush the log ring. Workers still blocked in an engine
    // read are not waited for; the handle they hold is gone.
    if let Some(sig) = wait_for_stop_signal()? {
        eprintln!("myotis-rpcd: signal {sig}, stopping");
    }
    for _ in 0..receivers {
        server.unblock();
    }
    drop(guard);
    stopping.store(true, Ordering::SeqCst);
    print_engine_logs();
    Ok(())
}
```

`rust/myotis-rpcd/src/main.rs` · lines 353–360

```rust
/// Stops a created engine handle when dropped.
struct StopOnDrop(i64);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        ffi::stop_handle(self.0);
    }
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **Shutdown.** tiny\_http's `unblock()` wakes *one* thread waiting in `recv()`, so it is called once per intake thread (`http::spawn` returns that count). Read workers still inside an engine call are not waited for: when `run` returns, `main` returns and the process exits, ending every thread.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* `drop(guard)` runs `StopOnDrop::drop` now rather than at the closing brace, so the handle is stopped before the final log flush. `struct StopOnDrop(i64)` is a tuple struct; `self.0` is its field.
- *[Binaries, CLIs & signals](01-primer.md#primer-cli) · [Result, ? and panics](01-primer.md#primer-error-handling)* In `main` (lines 129–140), an error prints the engine's remaining log lines and then the message, and calls `std::process::exit(1)`. `exit` does not run destructors of values still alive, but by then `run` has returned and its guard has already stopped the handle.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `wait_for_stop_signal` exists twice, under `#[cfg(unix)]` (signal-hook's blocking iterator) and `#[cfg(windows)]` (a flag polled every 100 ms). Only one is compiled for any target, so both can have the same name.

<a id="f-myotis-rpcd-src-engine-rs"></a>

### myotis-rpcd/src/engine.rs

*library module · 246 lines*

The seam between the router and the engine. The `Engine` trait lists what the router asks: strings in, the engine's JSON strings out. `FfiEngine` implements it over one engine handle; the tests implement it with a recorded fake, so the whole router can be tested without a running light client. `Readiness` reads the status JSON and decides whether a read should wait.

`rust/myotis-rpcd/src/engine.rs` · lines 15–62

```rust
/// Everything the router asks of the engine. Nothing here holds for
/// readiness; the reads themselves may still block in the engine.
pub trait Engine: Send + Sync {
    fn chain_id(&self) -> u64;
    /// The handle's status JSON — non-blocking.
    fn status_json(&self) -> String;
    /// The log index's status JSON (`GET /logindex`) — non-blocking.
    fn log_index_status_json(&self) -> String;
    /// The verified optimistic head block number from the status snapshot —
    /// non-blocking; `None` when the engine has none to give.
    fn head_block_number(&self) -> Option<u64>;
    fn request_account(&self, address: &str, block: &str) -> String;
    fn pending_nonce_overlay(&self, address: &str, mined: i64) -> i64;
    fn get_code(&self, address: &str, block: &str) -> String;
    fn get_storage_at(&self, address: &str, position: &str, block: &str) -> String;
    /// `eth_getProof` (ABI 46): the EIP-1186 result object or an error
    /// envelope; `keys` is the JSON array of storage keys as the request
    /// carried them.
    fn get_proof(&self, address: &str, keys: &str, block: &str) -> String;
    fn eth_call(&self, from: &str, to: &str, data: &str, value: &str, block: &str) -> String;
    #[allow(clippy::too_many_arguments)]
    fn eth_call_overrides(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        block: &str,
        overrides: &str,
    ) -> String;
    fn eth_call_tx(&self, tx: &str, block: &str, overrides: &str) -> String;
    fn estimate_gas_tx(&self, tx: &str, block: &str, overrides: &str) -> String;
    /// `eth_createAccessList` for the transaction object (ABI 40): the engine's
    /// access-list JSON, the list and gas next to the run's own failure.
    fn create_access_list(&self, tx: &str, block: &str, overrides: &str) -> String;
    fn block_by_number(&self, tag: &str, full: bool) -> String;
    fn block_by_hash(&self, hash: &str, full: bool) -> String;
    /// The canonical block a block hash names (ABI 47, #641): `{"hash","number"}`,
    /// the literal `null`, or an error envelope — header only.
    fn resolve_block_hash(&self, hash: &str) -> String;
    fn fee_estimate(&self) -> String;
    fn fee_history(&self, count: i64, newest: &str, percentiles: &str) -> String;
    fn send_raw_transaction(&self, raw: &str) -> String;
    fn transaction_receipt(&self, hash: &str) -> String;
    fn transaction_by_hash(&self, hash: &str) -> String;
    fn block_receipts(&self, selector: &str) -> String;
    fn get_logs(&self, filter: &str) -> String;
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **`trait Engine: Send + Sync`** declares supertraits: any implementation must be safe to move to another thread (`Send`) and to use from several threads at once through a shared reference (`Sync`). The router is shared through an `Arc` by the intake threads, the read workers and the body readers, so it needs both, and it can only have them if its engine does. In Java terms every method of the interface must be thread-safe, but here the compiler checks it.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* Every method takes `&self` and `&str` arguments: the router lends its strings and keeps them. `#[allow(clippy::too_many_arguments)]` silences one lint for one method.

`rust/myotis-rpcd/src/engine.rs` · lines 102–119

```rust
    /// The JVM host's `readyForReads`: SYNCED, an anchored head, and a pooled
    /// peer that can serve at it (`snapServingPeers`, not `snapPeers` — a pool of
    /// still-syncing peers keeps the latter positive for hours, #465). A RUNNING
    /// handle with no EL reader, or parked on STALE_ANCHOR, is "attempt now":
    /// waiting cannot change either, and the engine's own refusal is the answer.
    pub fn ready_for_reads(&self) -> bool {
        if self.running && !self.el_reader_available {
            return true;
        }
        if self.running && self.beacon_state == "STALE_ANCHOR" {
            return true;
        }
        self.running
            && self.beacon_state == "SYNCED"
            && self.optimistic_block > 0
            && self.snap_serving_peers > 0
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain)* **The JVM host's `readyForReads`, ported.** Ready means SYNCED, a verified head, and at least one pooled peer that can actually serve at it (`snapServingPeers`, not `snapPeers`: a pool of still-syncing peers can keep the latter positive for hours, #465). Two states say "ready" for a different reason: a running handle with no EL reader, or one parked in `STALE_ANCHOR`. Waiting cannot change either, so the read goes ahead and the engine's own refusal is the answer. `Readiness::parse` (lines 81–100) uses `unwrap_or_default()` on the JSON parse, so garbage reads as "not running", never as ready.

*[Ownership & moves](01-primer.md#primer-ownership) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The `impl Engine for FfiEngine` (lines 121–217) is one line per method, for example `ffi::request_account_json(self.handle, address.into(), block.into())`. The `ffi` functions take `String` by value (the UniFFI convention), so each `.into()` allocates an owned copy of the borrowed `&str`. That copy is the price of reusing the JVM-facing surface; it is negligible next to a network read.

<a id="f-myotis-rpcd-src-http-rs"></a>

### myotis-rpcd/src/http.rs

*library module · 704 lines*

The HTTP side: a tiny\_http server, four intake threads that accept and classify every request, and `--workers` read threads that serve the bodies naming a gated method. It also enforces geth's browser protections (the Host allowlist and the JSON Content-Type rule), the body limits, and a receive deadline for large bodies, so that no client can hold an intake thread.

`rust/myotis-rpcd/src/http.rs` · lines 73–94

```rust
    /// Whether a request with this `Host` header may be served. No header at
    /// all passes, as in geth: every browser sends one, so its absence is a
    /// non-browser client the check is not about.
    pub fn allows(&self, host: Option<&str>) -> bool {
        match (self, host) {
            (VHosts::Any, _) | (_, None) => true,
            (VHosts::Only(list), Some(h)) => list.contains(&host_name(h)),
        }
    }
}

/// A Host header's name, lowercased and without its port (`[::1]:8545` →
/// `[::1]`, `LocalHost:8545` → `localhost`).
fn host_name(h: &str) -> String {
    let h = h.trim();
    let name = if h.starts_with('[') {
        h.find(']').map_or(h, |i| &h[..=i])
    } else {
        h.rsplit_once(':').map_or(h, |(name, _)| name)
    };
    name.to_ascii_lowercase()
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **DNS rebinding.** A web page can make its own domain resolve to 127.0.0.1 and then send requests to the node from the operator's browser. The browser still sends the page's domain in the `Host` header, so an allowlist of local names refuses it with 403. A missing Host header passes, as in geth, because every browser sends one. The Content-Type rule (`json_content_type`, lines 99–109) closes the other door: the cross-origin POSTs a page may send without a CORS preflight are forms and `text/plain`, and those are refused with 415.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `match (self, host)` matches on a tuple, and `(VHosts::Any, _) | (_, None) => true` joins two patterns with `|`. In `host_name`, `&h[..=i]` slices up to and including the `]` of an IPv6 literal; `rsplit_once(':')` splits at the last colon. Both return borrowed slices, and only `to_ascii_lowercase` allocates.

#### Two pools

`rust/myotis-rpcd/src/http.rs` · lines 153–193

```rust
/// Start both pools on `server`. Returns how many threads wait in
/// `server.recv()`: each needs its own `server.unblock()` at shutdown.
pub fn spawn<E: Engine + 'static>(
    server: Arc<tiny_http::Server>,
    router: Arc<Router<E>>,
    vhosts: VHosts,
    workers: usize,
    limits: Limits,
) -> usize {
    // Bounded: a request that finds every worker busy and the queue full is
    // refused, so a flood of gated reads cannot grow memory without limit.
    let (tx, rx) = mpsc::sync_channel::<(tiny_http::Request, Body)>(limits.queue);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..workers.max(1) {
        let (rx, router) = (rx.clone(), router.clone());
        std::thread::spawn(move || loop {
            let next = match rx.lock() {
                Ok(r) => r.recv(),
                Err(_) => return,
            };
            let Ok((req, body)) = next else { return };
            let _ = req.respond(rpc_response(router.handle_parsed(body)));
        });
    }
    let shared = Arc::new(Shared {
        router,
        vhosts,
        reads: tx,
        body_timeout: limits.body_timeout,
        body_reads: AtomicUsize::new(0),
    });
    for _ in 0..INTAKE_THREADS {
        let (server, shared) = (server.clone(), shared.clone());
        std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                intake(req, &shared);
            }
        });
    }
    INTAKE_THREADS
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **A bounded channel with many consumers.** `mpsc::sync_channel(n)` is a channel with room for `n` messages, like a `ArrayBlockingQueue`. Its `Receiver` can't be cloned or shared (it is not `Sync`), so the workers share it as `Arc<Mutex<Receiver>>`: one worker at a time holds the lock while it waits in `recv()`, and the guard is dropped once a request arrives, before the request is served. It is the same design as the thread pool in the final project of the Rust book.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `let (rx, router) = (rx.clone(), router.clone());` clones the two `Arc`s (a reference-count increment, not a copy of the data) *before* the `move` closure, so each thread owns its own handles and the originals stay usable for the next iteration. The same pattern feeds the intake threads.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let Ok((req, body)) = next else { return };` ends the worker when the channel is closed. `std::thread::spawn(move || loop { … })` is a closure whose whole body is a `loop` expression.

`rust/myotis-rpcd/src/http.rs` · lines 197–222

```rust
/// Answer a request whose body is already in memory; hand any other to a
/// body-reader thread. Intake never reads from a client's socket: a client
/// that stalls mid-body would hold the thread, and four of them would starve
/// `GET /` and the status methods. Not even a refusal is sent from here for
/// such a request, because tiny_http drains an unread body when the request is
/// dropped — the same blocking read.
fn intake<E: Engine + 'static>(req: tiny_http::Request, shared: &Arc<Shared<E>>) {
    if body_in_memory(&req) {
        return answer(req, shared, None);
    }
    let shared = shared.clone();
    // One thread per such request is bounded by the open connections: tiny_http
    // already runs one thread per connection, and parses a connection's next
    // request only once this one is answered.
    std::thread::spawn(move || {
        let reading = shared.body_reads.fetch_add(1, Ordering::SeqCst);
        if reading >= MAX_BODY_READS {
            let _ = req.respond(busy(None));
        } else {
            let deadline = Instant::now() + shared.body_timeout;
            answer(req, &shared, Some(deadline));
        }
        // After the respond, which also dropped (and drained) the request.
        shared.body_reads.fetch_sub(1, Ordering::SeqCst);
    });
}
```

*[Threads, Send & Sync](01-primer.md#primer-concurrency)* **Never read from a client's socket on intake.** tiny\_http has already buffered a small body (up to 1 KiB with a Content-Length and no `Expect`; `body_in_memory`, lines 226–236). Any other body may trickle in for as long as the client likes, so it is received on a thread of its own. `fetch_add` returns the value *before* the increment, so at most `MAX_BODY_READS` (32) bodies are being received at once; past that the request is answered 503. The decrement comes after `respond`, which also drops and drains the request.

`rust/myotis-rpcd/src/http.rs` · lines 238–287

```rust
/// Serve one request. `deadline` bounds receiving its body (`None`: it is
/// already in memory).
fn answer<E: Engine>(mut req: tiny_http::Request, shared: &Shared<E>, deadline: Option<Instant>) {
    let router = &shared.router;
    let response = if !shared.vhosts.allows(header(&req, "Host").as_deref()) {
        text(403, "invalid host specified\n".into())
    } else {
        match req.method() {
            tiny_http::Method::Get if req.url() == "/" => {
                text(200, status_line(&router.engine().status_json()))
            }
            tiny_http::Method::Get if req.url() == "/logindex" => {
                tiny_http::Response::from_string(router.engine().log_index_status_json())
                    .with_header(content_type("application/json"))
            }
            tiny_http::Method::Post
                if !json_content_type(header(&req, "Content-Type").as_deref()) =>
            {
                text(
                    415,
                    "invalid content type, only application/json is supported\n".into(),
                )
            }
            tiny_http::Method::Post => match read_body(&mut req, deadline) {
                Err(r) => r,
                Ok(body) => {
                    let body = Body::parse(&body);
                    if body.blocking() {
                        // A read worker answers it. A full queue is refused now,
                        // and so is a closed one (shutdown) — never dropped.
                        match shared.reads.try_send((req, body)) {
                            Ok(()) => return,
                            Err(mpsc::TrySendError::Full((req, body))) => {
                                let _ = req.respond(busy(Some(&body)));
                                return;
                            }
                            Err(mpsc::TrySendError::Disconnected((req, _))) => {
                                let _ = req.respond(text(503, "shutting down\n".into()));
                                return;
                            }
                        }
                    }
                    rpc_response(router.handle_parsed(body))
                }
            },
            _ => text(405, "POST a JSON-RPC request, or GET / for status\n".into()),
        }
    };
    let _ = req.respond(response);
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match req.method()` with guards: `tiny_http::Method::Get if req.url() == "/"` matches only when both hold, and the arms are tried in order, so the Content-Type refusal arm comes before the general `Post` arm.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **`try_send` gives the value back.** Sending moves `(req, body)` into the channel. When the channel is full, the error `TrySendError::Full((req, body))` returns ownership of both, so the request can still be answered with 503 and an error per request in the body. Nothing is dropped unanswered, and the compiler would not let you use `req` after a successful send.
- *[Protocol & domain](01-primer.md#primer-domain)* `Body::parse` parses the JSON once; `body.blocking()` decides which pool answers it, and the router later serves the same parse (`handle_parsed(body)`), so the body is never parsed twice.

`rust/myotis-rpcd/src/http.rs` · lines 301–319

```rust
/// A body reader that gives up once `until` has passed. The check runs before
/// each read, so it ends a body that trickles in; a client that stops sending
/// altogether leaves the thread in a blocking read until the peer closes or
/// sends again, since tiny_http 0.12 exposes no socket timeout (and a receive
/// timeout set on the listener would also time out its accept loop, which then
/// exits). That case holds a body-reader thread, never an intake thread.
struct Deadline<R> {
    inner: R,
    until: Instant,
}

impl<R: Read> Read for Deadline<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if Instant::now() >= self.until {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.inner.read(buf)
    }
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **A `Read` decorator.** `impl<R: Read> Read for Deadline<R>` wraps any reader, like a Java `FilterInputStream`, and fails with `TimedOut` once the deadline has passed. Implementing the one required method `read` is enough: `read_to_string` is a provided method of the trait, built on top of it. In `read_body` (lines 321–349) it wraps `req.as_reader().take(MAX_BODY_BYTES + 1)`; reading one byte more than the limit is how a body that is too large is detected (413). As the doc comment says, the check runs only before each read, so a client that stops sending entirely still holds its body thread, but never an intake thread.

*[Tests](01-primer.md#primer-testing)* The seven tests (lines 402–704) include four that start a real server on `127.0.0.1:0` (the OS picks a free port) and speak raw HTTP over a `TcpStream`: a health check answers while the only read worker is held; foreign hosts get 403 and non-JSON posts 415; a full queue gets 503 with one error per request that has an id; and six clients stalled mid-body do not block `GET /`, then get 408.

<a id="f-myotis-rpcd-src-rpc-rs"></a>

### myotis-rpcd/src/rpc.rs

*library module · 1,980 lines · Java twin · RpcRouter*

The JSON-RPC router: a port of the strict (no-proxy) path of the Kotlin `RpcRouter` in `jsonrpc-server`, with the engine-JSON reading of the Rust-engine adapters (`IosRpcBackend`, `RustVerifiedReads`) folded in. A request is answered from the engine's verified surface or refused. It handles envelopes and batches, the readiness hold, the method table, every parameter, and the mapping from engine JSON to results and error codes.

| Lines | What happens |
|---|---|
| 1–28 | Module doc: the four error codes a client acts on. Imports. |
| 30–122 | Limits (batch 1000, window 64/16, fee history 1024/100, poll 250 ms), `NON_BLOCKING`, `gated`, the override and transaction field lists, and `arity`: the method table. |
| 124–150 | `enum Fail`, `type Out`, `invalid`. |
| 152–192 | `ReportedHeads`: heads this node answered `eth_blockNumber` with in the last 15 minutes. |
| 194–322 | `Router`, `Budget`, `Gate`, `Body` (parse, `blocking`, `refusal`), `Logged`, `Takes`, `Selector`, `TxArgs`, `OverrideParam`. |
| 324–501 | Builder methods; `handle_parsed` (single object, batches, their limits); `handle_one` (envelope rules, dispatch, access and call logs, notifications). |
| 503–571 | `fail_parts` (Fail → code and message), `ready`, `engine_ready` (the hold). |
| 573–857 | `dispatch`: one arm per method. |
| 859–969 | `eth_call`, `eth_estimate_gas`, `eth_create_access_list`, `check_chain_id`. |
| 971–1099 | Block pins: `resolve_hash` (#641), `pin_servable`, `in_window`, `account`. |
| 1101–1137 | `OVERRIDE_UNSUPPORTED`, `Account`, `parse_account` (fails closed on shape drift). |
| 1139–1361 | Engine JSON reading: error envelopes, `engine_object`, `verified`, `tri_state`, `call_outcome`, `non_answer`, `access_list_outcome`, revert decoding. |
| 1363–1852 | Parameter reading: addresses, hashes, data, flags, storage words and keys, `parse_selector`, fee history, state and block overrides, `parse_tx`. |
| 1854–1977 | Envelopes, the `--log-calls` line, `shorten`, FNV-64, an ISO timestamp without a date library. |
| 1979–1980 | `#[cfg(test)] pub(crate) mod tests;` → `rpc/tests.rs`. |

#### The method table and the error codes

`rust/myotis-rpcd/src/rpc.rs` · lines 88–122

```rust
/// The most positional arguments each served method takes — geth's arity, so a
/// request geth refuses with "too many arguments" is refused here too, never
/// served with the extra argument dropped. Also the served-method list.
fn arity(method: &str) -> Option<usize> {
    Some(match method {
        "eth_chainId"
        | "net_version"
        | "eth_blockNumber"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "web3_clientVersion"
        | "eth_syncing"
        | "eth_accounts"
        | "net_listening"
        | "myotis_status" => 0,
        "eth_sendRawTransaction"
        | "eth_getTransactionReceipt"
        | "eth_getTransactionByHash"
        | "eth_getBlockReceipts"
        | "eth_getLogs" => 1,
        "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_getCode"
        | "eth_getBlockByNumber"
        | "eth_getBlockByHash" => 2,
        // transaction, block, state overrides (reth's signature; geth takes no
        // override — one it would refuse as too many arguments is applied here)
        "eth_getStorageAt" | "eth_feeHistory" | "eth_createAccessList" => 3,
        // address, storage keys, block
        "eth_getProof" => 3,
        // transaction, block, state overrides, block overrides
        "eth_call" | "eth_estimateGas" => 4,
        _ => return None,
    })
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **`match` is an expression.** `Some(match method { … })` wraps whatever the arms produce, and the last arm `_ => return None` leaves the function early instead. Arms join string patterns with `|`. One function answers two questions: "is this method served?" (`Some`) and "how many positional arguments may it take?".
- *[Protocol & domain](01-primer.md#primer-domain)* **Too many arguments is an error, not a detail.** `dispatch` refuses a request with more `params` than this, and a `params` that is neither absent, `null` nor an array. An extra argument the server dropped would answer a question the client did not ask. The doc and the comment on line 113 disagree slightly: `eth_createAccessList` takes a third argument (state overrides) that geth does not take, so there a request geth would refuse is served with the override applied.

`gated(method)` (lines 59–63) is "served and not in `NON_BLOCKING`". The seven non-blocking methods are `eth_chainId`, `net_version`, `web3_clientVersion`, `eth_accounts`, `net_listening`, `eth_syncing` and `myotis_status`: config and the status snapshot. Everything else may be held for readiness.

| Method | Max args | Engine call |
|---|---|---|
| `eth_chainId`, `net_version`, `web3_clientVersion`, `eth_accounts`, `net_listening` | 0 | none (config; `eth_accounts` is always `[]`) |
| `eth_syncing`, `myotis_status` | 0 | `status_json` |
| `eth_blockNumber` | 0 | `head_block_number` (status), recorded in `ReportedHeads` |
| `eth_gasPrice`, `eth_maxPriorityFeePerGas` | 0 | `fee_estimate` |
| `eth_getBalance`, `eth_getTransactionCount` | 2 | `request_account` (+ `pending_nonce_overlay` for `pending`) |
| `eth_getCode` / `eth_getStorageAt` / `eth_getProof` | 2 / 3 / 3 | `get_code` / `get_storage_at` / `get_proof` |
| `eth_call` | 4 | `eth_call`, `eth_call_overrides` or `eth_call_tx` |
| `eth_estimateGas` / `eth_createAccessList` | 4 / 3 | `estimate_gas_tx` / `create_access_list` |
| `eth_feeHistory` | 3 | `fee_history` |
| `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getBlockReceipts` | 2, 2, 1 | `block_by_number`, `block_by_hash`, `block_receipts` |
| `eth_getTransactionReceipt`, `eth_getTransactionByHash` | 1 | `transaction_receipt`, `transaction_by_hash` |
| `eth_sendRawTransaction` | 1 | `ffi::check_raw_transaction_json` (no handle), then `send_raw_transaction` |
| `eth_getLogs` | 1 | `get_logs` (needs `--log-index-config`) |
| a block hash as selector (state reads, calls) |   | `resolve_block_hash` first, then served as that number |
| anything else |   | none: `-32601` |

`rust/myotis-rpcd/src/rpc.rs` · lines 124–150

```rust
/// Why a request got no result. The router turns each into its error envelope
/// in one place ([`Router::handle_one`]), so a handler only says what happened.
#[derive(Debug, PartialEq)]
pub enum Fail {
    /// The request can never be served as asked: `-32602` with this text.
    Invalid(String),
    /// No verified answer right now: `-32000`, with the engine's reason when it
    /// gave one.
    Unavailable(Option<String>),
    /// The ENGINE refused for good (`{"error","code":-32602}`): `-32602`.
    Refused(String),
    /// A complete error served verbatim: geth's reverts (code 3, with data)
    /// and geth-worded `-32000` answers (infeasible, txpool rejection, logs).
    Rpc {
        code: i64,
        message: String,
        data: Option<String>,
    },
    /// Not a method this node serves: `-32601`.
    Unsupported,
}

type Out = Result<String, Fail>;

fn invalid<T>(why: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Invalid(why.into()))
}
```

`rust/myotis-rpcd/src/rpc.rs` · lines 503–538

```rust
/// A [`Fail`] as its JSON-RPC error: code, message and optional `data`.
fn fail_parts(&self, method: &str, fail: Fail) -> (i64, String, Option<String>) {
    match fail {
        Fail::Invalid(why) => (-32602, why, None),
        Fail::Refused(why) => (-32602, format!("method '{method}' refused: {why}"), None),
        Fail::Rpc {
            code,
            message,
            data,
        } => (code, message, data),
        Fail::Unsupported => (
            -32601,
            format!("method '{method}' is not supported by this permissionless node"),
            None,
        ),
        Fail::Unavailable(reason) => {
            // A STALE_ANCHOR park gets its own message: unlike not-synced it
            // will NOT progress on its own — a human must decide.
            if Readiness::parse(&self.engine.status_json()).beacon_state == "STALE_ANCHOR" {
                let msg = format!(
                    "method '{method}' refused: the node's trust anchor is past the \
                     weak-subjectivity bound and syncing is paused awaiting consent — \
                     raise the bound or accept the risk"
                );
                return (-32000, msg, None);
            }
            let msg = match reason {
                Some(r) => format!("method '{method}' cannot be served verified right now: {r}"),
                None => format!(
                    "method '{method}' cannot be served verified right now (no peer / not synced)"
                ),
            };
            (-32000, msg, None)
        }
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* **An error enum, mapped in one place.** Handlers return `Result<String, Fail>` (aliased `Out`), where `Ok` is the raw JSON of the result. They only say what happened; `fail_parts` decides the code and the wording. Variants can carry data, unlike a Java enum: `Invalid(String)` is a tuple variant, `Rpc { code, message, data }` a struct variant, `Unsupported` a unit variant. The `match` must cover all five, so adding a sixth breaks the build until it is mapped.
- *[Ownership & moves](01-primer.md#primer-ownership)* `fail_parts(&self, method: &str, fail: Fail)` takes the `Fail` by value, so `Fail::Invalid(why) => (-32602, why, None)` moves the `String` out of the enum into the tuple without copying it.
- *[Protocol & domain](01-primer.md#primer-domain)* **A STALE\_ANCHOR park gets its own message**, because unlike "not synced" it will not resolve itself: a human must raise the bound or accept the risk.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `invalid<T>(why: impl Into<String>) -> Result<T, Fail>` (line 148) is generic in its `Ok` type, so `return invalid("…")` fits in any function returning `Result<_, Fail>`, and it accepts both `&str` and `String`.

| Code | Meaning | Produced by |
|---|---|---|
| `-32700` | The body is not JSON. | `handle_parsed` |
| `-32600` | Not a valid request: an empty batch, a non-object element, `jsonrpc` not `"2.0"`, a non-string method, a bad id, or more than 1000 requests. | `handle_parsed`, `handle_one` |
| `-32601` | Not a method this node serves. | `Fail::Unsupported` |
| `-32602` | Can never be answered as asked. Do not retry. | `Fail::Invalid`, `Fail::Refused` (the engine's permanent envelope), and `eth_getLogs` when the engine marks it permanent |
| `-32000` | Not answerable verified right now. Retryable. Also geth-worded answers (infeasible call, txpool rejection) and "server busy". | `Fail::Unavailable`, `Fail::Rpc` |
| `3` | The call reverted: a verified answer, with the revert data. | `revert_fail` |

> [!WARNING]
> **The project rule behind -32602**<br>
>
> The repository's `CLAUDE.md` (section "Trust") says a parameter that can change the answer must be "APPLIED or REFUSED — never accepted and silently ignored", and that a refusal uses the permanent `-32602`, because `-32000` is documented as retryable and a client would spin on it. The rule came from `eth_call` once dropping a state override (#314). In this file you can see it everywhere: too many arguments, `params` that are not an array, `blockOverrides` (never applied, so present means refused, with a message that says "rejected, not ignored"), an unknown state-override field, `safe` and `earliest`, bare-digit block numbers, a non-boolean `fullTransactions`, both `data` and `input` set and different, blob fields, a `chainId` that is not this chain's, and a missing `eth_feeHistory` newest block. The opposite class, "not now", stays `-32000`: a block a little ahead of the head, a hash the node cannot place yet, a node that is not ready.

#### The readiness hold

`rust/myotis-rpcd/src/rpc.rs` · lines 203–216

```rust
/// The readiness hold ONE HTTP body may spend: a single request, or a whole
/// batch, waits at most `ready_wait` in total. Once a wait has run out, later
/// gated elements of the batch that still find the node unready fail fast.
struct Budget {
    deadline: Instant,
    spent: Cell<bool>,
}

/// One request's pass through the hold: taken at most once, lazily — at its
/// first engine read, so a request refused on its parameters never waits.
struct Gate<'b> {
    budget: &'b Budget,
    passed: Cell<bool>,
}
```

`rust/myotis-rpcd/src/rpc.rs` · lines 544–571

```rust
/// The engine, once this request has passed the readiness hold. The first
/// call holds until the node is serveable or the body's budget runs out,
/// then lets the read go ahead regardless — the engine then answers with its
/// own, more precise, reason. A later element of a batch whose budget is
/// already spent does not wait again: unready, it fails fast (-32000).
fn engine_ready(&self, g: &Gate) -> Result<&E, Fail> {
    if g.passed.replace(true) || self.ready() {
        return Ok(&self.engine);
    }
    if g.budget.spent.get() {
        return Err(Fail::Unavailable(Some(
            "the node is not ready for verified reads, and this batch has already \
             waited --ready-wait for it"
                .into(),
        )));
    }
    loop {
        let now = Instant::now();
        if now >= g.budget.deadline {
            g.budget.spent.set(true);
            return Ok(&self.engine);
        }
        std::thread::sleep(READY_POLL.min(g.budget.deadline - now));
        if self.ready() {
            return Ok(&self.engine);
        }
    }
}
```

- *[Interior mutability](01-primer.md#primer-interior-mutability)* **`Cell`: mutation through a shared reference, single thread only.** Handlers receive `g: &Gate`, a shared borrow, yet the gate must record that it was passed. `Cell<bool>` allows that without a lock: `passed.replace(true)` stores `true` and returns the old value, `spent.get()` and `spent.set(true)` copy the value in and out. `Cell` is not `Sync`, so the compiler would refuse to share a `Gate` between threads. It never needs to be: a `Budget` and its gates live on the stack of the one worker serving the body.
- *[Lifetimes](01-primer.md#primer-lifetimes)* **`Gate<'b>` holds `&'b Budget`.** A struct that stores a reference must name its lifetime, and the compiler then guarantees that the gate cannot outlive the budget. `handle_parsed` creates one `Budget` per HTTP body; `handle_one` creates one `Gate` per request, borrowing it. So a batch shares one wait of at most `--ready-wait`, and each request waits at most once however many times its handler calls `engine_ready` (the pin check, the window check and the read each do).
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `engine_ready` returns `Result<&E, Fail>`: on success a borrow of `self.engine`, with its lifetime tied to `&self` by elision. The handlers write `self.engine_ready(g)?.get_code(…)`, so the engine can only be reached through the gate. The gate is taken lazily, at the first engine read, so a request refused on its parameters never waits.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* The wait is a plain poll: `thread::sleep(READY_POLL.min(deadline - now))`, re-reading the status every 250 ms. When the budget runs out, the read goes ahead anyway, so the error that comes back carries the engine's own reason. Later gated elements of the same batch then fail fast with `-32000`.

#### Dispatch

`rust/myotis-rpcd/src/rpc.rs` · lines 573–593

```rust
/// Route one request; `Ok` is the raw JSON of its result.
fn dispatch(&self, method: &str, root: &Map<String, Value>, g: &Gate) -> Out {
    let Some(max_args) = arity(method) else {
        return Err(Fail::Unsupported);
    };
    // geth's positional-argument rules: `params` absent, null or an array of
    // at most the method's arguments — anything else is refused, never ignored.
    let empty = Vec::new();
    let params: &Vec<Value> = match root.get("params") {
        None | Some(Value::Null) => &empty,
        Some(Value::Array(a)) => a,
        Some(_) => return invalid("params must be an array of positional arguments"),
    };
    if params.len() > max_args {
        return invalid(format!("too many arguments, want at most {max_args}"));
    }
    // Not held for readiness: config and the status snapshot only (the
    // NON_BLOCKING list). Every gated arm reaches the engine through
    // `self.engine_ready(g)?`, which holds once per request.
    let e = &self.engine;
    match method {
```

`rust/myotis-rpcd/src/rpc.rs` · lines 630–657

```rust
"eth_getBalance" => {
    let addr = address_at(params, 0)?;
    let sel = selector_at(params, 1, Takes::NumberOrHash)?;
    let sel = self.resolve_hash(sel, method, g)?;
    self.pin_servable(&sel, method, g)?;
    // Verified-absent account → balance 0: the proof of exclusion IS
    // the verified answer.
    let acct = self.account(&addr, &sel, g)?;
    Ok(json_str(&acct.balance))
}
"eth_getTransactionCount" => {
    let addr = address_at(params, 0)?;
    let sel = selector_at(params, 1, Takes::NumberOrHash)?;
    let sel = self.resolve_hash(sel, method, g)?;
    self.pin_servable(&sel, method, g)?;
    let mined = self.account(&addr, &sel, g)?.nonce;
    // ONLY the pending tag consults the sent-tx overlay:
    // max(mined, our broadcast nonce + 1) while unmined and unexpired.
    let nonce = if sel.value == "pending" {
        // The overlay answers max(mined, ours + 1), or -1 for none.
        let o =
            e.pending_nonce_overlay(&addr, i64::try_from(mined).unwrap_or(i64::MAX));
        u64::try_from(o).unwrap_or(mined)
    } else {
        mined
    };
    Ok(json_str(&hex_quantity(nonce)))
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Borrowing an empty default.** `params` must be a `&Vec<Value>` borrowed from the request. For an absent `params` there is nothing to borrow, so the function first creates a local `empty` vector and borrows that. The local lives until the function returns, so the reference is valid in every arm.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **A pipeline of `?`.** Each step either returns its value or ends the handler with a `Fail`: parse the address, parse the selector, resolve a block hash to a number, refuse a pin behind the window, then read and check the account. The `sel` variable is *shadowed*: `let sel = self.resolve_hash(sel, …)?` moves the old `Selector` into the call and binds the returned one to the same name.
- *[Protocol & domain](01-primer.md#primer-domain)* **Only `pending` consults the overlay.** The engine remembers this node's own unmined broadcasts. `pending_nonce_overlay` returns `max(mined, ours + 1)` or `-1` for none; `u64::try_from(o).unwrap_or(mined)` turns the `-1` back into the mined nonce. A proof of exclusion (`exists: false`) is a verified balance of 0.

#### eth\_call: two engine paths

`rust/myotis-rpcd/src/rpc.rs` · lines 859–901

```rust
fn eth_call(&self, params: &[Value], g: &Gate) -> Out {
    // blockOverrides are never applied: their presence refuses on its own.
    if block_override_present(params) {
        return invalid(OVERRIDE_UNSUPPORTED.replace("{m}", "eth_call"));
    }
    let overrides = match state_override_param(params) {
        OverrideParam::Malformed(why) => {
            return invalid(format!("invalid state override: {why}"))
        }
        OverrideParam::Valid(j) => Some(j),
        OverrideParam::Absent => None,
    };
    let Some(obj) = params.first().and_then(|v| v.as_object()) else {
        return invalid("eth_call expects a transaction object as its first parameter");
    };
    let tx =
        parse_tx(obj).or_else(|why| invalid(format!("invalid transaction object: {why}")))?;
    let sel = selector_at(params, 1, Takes::NumberOrHash)?;
    self.check_chain_id(&tx)?;
    let sel = self.resolve_hash(sel, "eth_call", g)?;
    self.pin_servable(&sel, "eth_call", g)?;
    let json = if tx.extended {
        let e = self.engine_ready(g)?;
        // Gas, fees or lists: only the transaction-object call applies them.
        e.eth_call_tx(
            &tx.canonical,
            &sel.value,
            overrides.as_deref().unwrap_or(""),
        )
    } else {
        // Nothing beyond from/to/data/value: the plain call, window-checked as
        // the adapters check it (the tx call applies the selector itself).
        self.in_window(&sel, g)?;
        let e = self.engine_ready(g)?;
        let from = tx.from.as_deref().unwrap_or(""); // empty = anonymous sender
        let to = tx.to.as_deref().unwrap_or(""); // empty = contract creation
        match &overrides {
            None => e.eth_call(from, to, &tx.data, &tx.value, &sel.value),
            Some(ov) => e.eth_call_overrides(from, to, &tx.data, &tx.value, &sel.value, ov),
        }
    };
    call_outcome(&json, false)
}
```

*[Protocol & domain](01-primer.md#primer-domain) · [Result, ? and panics](01-primer.md#primer-error-handling)* The engine has a plain call (`from, to, data, value`) and a transaction-object call that applies gas, fees, type, access and authorization lists. `parse_tx` sets `tx.extended` when the object carries anything the plain call would drop (lines 1822–1838: an explicit `type`, `gas`, any fee field, a non-empty access list, an authorization list, or a nonce on a contract creation), and then only the transaction-object call may answer. This is #314 solved structurally. `parse_tx(obj).or_else(|why| invalid(…))?` converts the parser's `String` error into a `Fail`. `overrides.as_deref().unwrap_or("")` turns `Option<String>` into a `&str` without moving the string.

#### Block pins

`rust/myotis-rpcd/src/rpc.rs` · lines 1046–1091

```rust
/// Judge a number pin against the state window before the engine is asked:
/// BEHIND it is refused for good (-32602) — no engine holds older state —
/// unless this node itself recently reported a head at or below the pin;
/// no verified head known is a retryable decline. Tags pass; a hash arrives
/// resolved to its block's number ([`Self::resolve_hash`]) and is judged as
/// that number, the refusal naming the hash.
fn pin_servable(&self, sel: &Selector, method: &str, g: &Gate) -> Result<(), Fail> {
    let Some(n) = sel.number else { return Ok(()) };
    let head = self
        .engine_ready(g)?
        .head_block_number()
        .ok_or(Fail::Unavailable(None))?;
    if n < head.saturating_sub(BLOCK_NUM_LAG_TOLERANCE) {
        if self.reported_heads.lowest().is_some_and(|low| n >= low) {
            return Err(Fail::Unavailable(None));
        }
        let asked = match &sel.via_hash {
            Some(h) => format!("block hash {h} (block {n})"),
            None => format!("block {n}"),
        };
        return invalid(format!(
            "{method} at {asked} is not supported: it is more than \
             {BLOCK_NUM_LAG_TOLERANCE} blocks behind the verified head ({head}), and this node \
             holds no historical state"
        ));
    }
    Ok(())
}

/// The adapters' serving window (`RpcBlockWindow.blockInWindow`): a number
/// pin is served from head state only within [head-64, head+16]; ahead of
/// it is a retryable decline (the head may yet reach it).
fn in_window(&self, sel: &Selector, g: &Gate) -> Result<(), Fail> {
    let Some(n) = sel.number else { return Ok(()) };
    let head = self
        .engine_ready(g)?
        .head_block_number()
        .ok_or(Fail::Unavailable(None))?;
    if n + BLOCK_NUM_LAG_TOLERANCE >= head && n <= head + BLOCK_NUM_TOLERANCE {
        Ok(())
    } else {
        Err(Fail::Unavailable(Some(format!(
            "block {n} is outside the served window around the verified head ({head})"
        ))))
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Behind, inside, ahead.** The node holds state only near its verified head. A pin more than 64 blocks behind is refused for good (`-32602`): no wait will make that state appear. A pin up to 16 ahead is served from head state. Further ahead is `-32000`, because the head may yet reach it.
- *[Protocol & domain](01-primer.md#primer-domain)* **`ReportedHeads`.** A wallet pins its reads to the number it was just handed by `eth_blockNumber`. If this node itself reported a head at or below the pin within the last 15 minutes, the pin came from this node, so it is declined retryably instead of being called invalid, even after the head moved on. The struct (lines 156–192) is a `Mutex<VecDeque<(u64, Instant)>>`, pruned by age and capped at 512 entries.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let Some(n) = sel.number else { return Ok(()) };`: tags have no number and pass. `head.saturating_sub(64)` stops at 0 instead of underflowing, which would panic in a debug build (and abort the daemon if overflow checks were on in release). `n + 64` in `in_window` cannot overflow for a caller's number: `parse_selector` refuses numbers above `i64::MAX` (a resolved hash's number comes from a verified header).

*[Protocol & domain](01-primer.md#primer-domain)* A 32-byte block hash goes through `resolve_hash` (lines 971–1044) first: the engine names the canonical block with that hash, header only, and the router then serves the request exactly as that number, through the same window. An engine `null` (a hash it cannot place: not reached yet, too old, or on a fork) is a retryable `-32000` naming the hash, since the node cannot tell "not yet" from "never". The resolver also checks that the engine returned the hash it was asked for and refuses block 0. `eth_getProof` is the exception: it hands the hash straight to the engine, which pins the proof to that block's root in one read, so no reorg can slip in between resolving and reading.

#### Reading the engine's JSON

`rust/myotis-rpcd/src/rpc.rs` · lines 1143–1184

```rust
/// The engine's error envelope: `{"error": …}` (retryable) or
/// `{"error": …, "code": -32602}` (permanent). Anything else — including an
/// object that merely HAS an error key among others — is a result. Returns the
/// message and whether it is permanent.
fn error_envelope_of(v: &Value) -> Option<(String, bool)> {
    let o = v.as_object()?;
    let err = o.get("error")?;
    if !(o.len() == 1 || (o.len() == 2 && o.contains_key("code"))) {
        return None;
    }
    let msg = err
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| err.to_string());
    Some((msg, permanent_code(v)))
}

fn permanent_code(v: &Value) -> bool {
    v.get("code").and_then(|c| c.as_i64()) == Some(-32602)
}

fn envelope_fail(msg: String, permanent: bool) -> Fail {
    if permanent {
        Fail::Refused(msg)
    } else {
        Fail::Unavailable(Some(msg))
    }
}

/// A result-object read (account, code, storage, fees, call, send): the
/// object, or the engine's error as a [`Fail`]. Any non-null `error` key counts.
fn engine_object(json: &str) -> Result<Map<String, Value>, Fail> {
    let v: Value = serde_json::from_str(json.trim()).map_err(|_| Fail::Unavailable(None))?;
    if let Some((msg, permanent)) = error_envelope_of(&v) {
        return Err(envelope_fail(msg, permanent));
    }
    match v {
        Value::Object(o) if o.get("error").is_none_or(Value::is_null) => Ok(o),
        Value::Object(o) => Err(Fail::Unavailable(o.get("error").map(|e| e.to_string()))),
        _ => Err(Fail::Unavailable(None)),
    }
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Fail closed.** The engine signals errors in-band: `{"error": …}` is retryable, `{"error": …, "code": -32602}` permanent. Only an object with exactly those keys counts as an envelope. Anything that does not parse, or that is not an object, is `Fail::Unavailable(None)`, never a result. `verified` (lines 1188–1197) adds the state-read rule: no `verifyMethod` string, no answer. `parse_account` (lines 1117–1137) refuses any shape drift with `-32000`, so a malformed engine reply can never become a "verified" balance of 0.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `err.as_str().map(str::to_owned).unwrap_or_else(|| err.to_string())`: a string error is copied as is; any other JSON value is serialised. `str::to_owned` is a function path used as a closure.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `o.get("error").is_none_or(Value::is_null)` is `true` when the key is absent or `null`; it reads like the Kotlin `o["error"]?.isNull ?: true`.

`tri_state` serves the reads that have three outcomes: a found object, the literal `null` (a *verified* "not seen", which is a valid result), or an error envelope. `call_outcome` maps the EVM's `status`: `ok` → the return data or the gas, `revert` → geth's code 3 with the payload as `data`, `infeasible` → geth's `-32000` in geth's words. A reasonless `infeasible` or a malformed hex field is shape drift: retryable, never a confident answer.

`rust/myotis-rpcd/src/rpc.rs` · lines 1324–1361

```rust
/// Best-effort human reason from a revert payload; `None` for custom errors or
/// anything malformed (the raw payload is always in `data`). Bounds are
/// attacker-controlled and checked at every step; the text is reduced to
/// printable ASCII so it can neither forge log lines nor spoof a UI.
fn decode_revert_reason(d: &[u8]) -> Option<String> {
    // A 32-byte ABI word as u64 — only when its high 24 bytes are zero.
    let word = |at: usize| -> Option<u64> {
        let w = d.get(at..at.checked_add(32)?)?;
        if w[..24].iter().any(|&b| b != 0) {
            return None;
        }
        Some(
            w[24..]
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        )
    };
    if d.len() >= 36 && d[..4] == [0x4e, 0x48, 0x7b, 0x71] {
        return Some(format!("panic 0x{:x}", word(4)?));
    }
    if d.len() < 68 || d[..4] != [0x08, 0xc3, 0x79, 0xa0] {
        return None;
    }
    let off = usize::try_from(word(4)?).ok()?;
    let len_pos = 4usize.checked_add(off)?;
    let len = usize::try_from(word(len_pos)?).ok()?;
    if len > 1024 {
        return None;
    }
    let start = len_pos.checked_add(32)?;
    let bytes = d.get(start..start.checked_add(len)?)?;
    let s = String::from_utf8_lossy(bytes);
    Some(
        s.chars()
            .map(|c| if (' '..='~').contains(&c) { c } else { ' ' })
            .collect(),
    )
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Decoding attacker-controlled bytes.** A revert payload comes from a contract, so its offsets and lengths are hostile. `d.get(at..at.checked_add(32)?)?` returns `None` instead of panicking when the range is out of bounds, and `checked_add` returns `None` on overflow. That matters because a panic aborts the whole daemon (`panic = "abort"`); the test `revert_reason_decoding_is_bounded` feeds it an offset of `u64::MAX`. `Error(string)` starts with the selector `08c379a0`, `Panic(uint256)` with `4e487b71`. The decoded text is reduced to printable ASCII, so it can neither forge log lines nor spoof a UI. Inside the closure `word`, `?` works because the closure itself returns `Option`.

#### Parameters: applied or refused

`rust/myotis-rpcd/src/rpc.rs` · lines 1694–1736

```rust
/// `params[2]`, the state override: absent (nothing to apply), valid, or
/// malformed — never collapsed, because serving a malformed one as absent
/// answers a question the caller did not ask.
fn state_override_param(p: &[Value]) -> OverrideParam {
    let ov = match p.get(2) {
        None | Some(Value::Null) => return OverrideParam::Absent,
        Some(Value::Object(o)) => o,
        Some(_) => {
            return OverrideParam::Malformed(
                "state override must be an object keyed by address".into(),
            )
        }
    };
    let mut changes = false;
    for (addr, entry) in ov {
        if addr.len() != 42 || !is_hex(addr) {
            return OverrideParam::Malformed(format!(
                "state override key '{addr}' is not a 20-byte address"
            ));
        }
        let fields = match entry {
            Value::Null => continue, // "no override for this account", as geth reads it
            Value::Object(f) => f,
            _ => {
                return OverrideParam::Malformed(format!(
                    "state override for '{addr}' must be an object"
                ))
            }
        };
        if let Some(k) = fields
            .keys()
            .find(|k| !OVERRIDE_FIELDS.contains(&k.as_str()))
        {
            return OverrideParam::Malformed(format!("unsupported state override field '{k}'"));
        }
        changes |= !fields.is_empty();
    }
    if changes {
        OverrideParam::Valid(Value::Object(ov.clone()).to_string())
    } else {
        OverrideParam::Absent
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Three states, never two.** `OverrideParam` is `Absent`, `Valid(String)` or `Malformed(String)`. With an `Option`, "malformed" would have to collapse into "absent", which is exactly the silent drop the project rule forbids. An override with no actual changes (only `null` or empty entries) is `Absent`, so the plain call can serve it.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `for (addr, entry) in ov` iterates a `&Map` and yields pairs of references. `changes |= !fields.is_empty();` is a boolean or-assignment. `ov.clone()` copies the map only once it is known to be valid.

`parse_selector` (lines 1476–1620) is "the ONE reading of a block selector": absent or `null` is `latest`; `latest`, `pending` and `finalized` pass as tags; `safe` and `earliest` are refused with an explanation; numbers must be `0x`-hex, nonzero and at most `i64::MAX`; and methods that take a `BlockNumberOrHash` also accept a 32-byte hash, bare or in EIP-1898's object form (`{"blockHash"}` or `{"blockNumber"}`, not both, with an optional boolean `requireCanonical`). It returns a `Selector` whose `value` is what the engine is handed: the tag, a minimal `0x`-number, or a lowercase hash.

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* The envelopes (lines 1858–1885) are built with `format!`, and the result is embedded *verbatim* as already-serialised JSON, because a block with full transactions can run to megabytes and need not be parsed and re-encoded. `{id}` formats a `serde_json::Value` through its `Display`, which is its JSON text. The error object is built as a `Map`, so the message is escaped. The call log (lines 1887–1951) shortens long strings at a UTF-8 character boundary (`floor_char_boundary`), and counts the elements of a long array result by deserialising it into `Vec<IgnoredAny>`, which skips each element without building it.

<a id="f-myotis-rpcd-src-quantity-rs"></a>

### myotis-rpcd/src/quantity.rs

*library module · 204 lines*

JSON-RPC QUANTITY and DATA encoding without a bignum dependency, ported from the Kotlin router's `RpcQuantities`. The engine hands balances and fees across as decimal strings, the wire wants minimal hex, and wei values are at most 256 bits, so schoolbook base conversion over digit arrays is enough.

`rust/myotis-rpcd/src/quantity.rs` · lines 59–84

```rust
/// Unsigned decimal digits → minimal lowercase hex (no `0x`).
pub fn decimal_to_hex(decimal: &str) -> String {
    let mut digits: Vec<u32> = decimal.bytes().map(|b| u32::from(b - b'0')).collect();
    let mut out = Vec::new();
    while !digits.is_empty() {
        // One schoolbook division of the decimal digit array by 16.
        let mut remainder = 0u32;
        let mut quotient = Vec::with_capacity(digits.len());
        for d in &digits {
            let cur = remainder * 10 + d;
            quotient.push(cur / 16);
            remainder = cur % 16;
        }
        out.push(HEX_DIGITS[remainder as usize]);
        let start = quotient
            .iter()
            .position(|&q| q != 0)
            .unwrap_or(quotient.len());
        digits = quotient.split_off(start);
    }
    if out.is_empty() {
        return "0".into();
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **Long division by 16, repeated.** Each pass divides the decimal digit array by 16, keeps the remainder as the next hex digit (least significant first), and replaces `digits` with the quotient. `quotient.split_off(start)` returns the part from the first nonzero digit as a new `Vec`, dropping the leading zeros; assigning it to `digits` drops the old vector. `out.reverse()` then puts the most significant digit first.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `u32::from(b - b'0')` assumes ASCII digits: on any other byte the `u8` subtraction would underflow. Every caller checks the input first (`hex_quantity_decimal`, `parse_wei_quantity`). `String::from_utf8(out)` cannot fail on hex digits, so `unwrap_or_default()` is only a formality.

`parse_hex` is strict on purpose: an odd number of hex digits is refused rather than padded, because padding calldata or storage would shift it by half a byte. `parse_wei_quantity` caps the input at 80 characters before any conversion, so a huge string cannot make parsing expensive. It accepts `0x` alone as zero (a test pins that) and, for parity with Java's `BigInteger`, a `+` sign; geth refuses both.

<a id="f-myotis-rpcd-src-checkpoint-rs"></a>

### myotis-rpcd/src/checkpoint.rs

*library module · 103 lines*

Bootstrapping from an operator-supplied checkpoint instead of the embedded one. `explicit` validates a root (32 bytes of hex) and a slot (at least 1). `bound_anchor` reads the marker the engine writes into a data dir created with a caller's checkpoint (`sync-anchor.json` on mainnet, `sync-anchor-<net>.json` elsewhere), so a restart without the flags resumes that anchor instead of being refused. The trust argument is in the module doc: the root picks the starting point, and the engine verifies everything after it with sync-committee signatures.

`rust/myotis-rpcd/src/checkpoint.rs` · lines 69–90

```rust
/// `myotis_create_with_checkpoint` (the engine's C ABI; `ffi` has no wrapper).
/// Same sentinels as `create`: -1 invalid input, -2 unsupported network, -3 the
/// data dir is bound to a different anchor.
pub fn create_handle(network: &str, data_dir: &str, cp: &Checkpoint) -> i64 {
    let (Ok(n), Ok(d), Ok(r)) = (
        CString::new(network),
        CString::new(data_dir),
        CString::new(cp.root.as_str()),
    ) else {
        return -1;
    };
    // SAFETY: three valid NUL-terminated C strings that outlive the call; the
    // engine copies them before returning.
    unsafe {
        myotis_engine::capi::myotis_create_with_checkpoint(
            n.as_ptr(),
            d.as_ptr(),
            r.as_ptr(),
            cp.slot,
        )
    }
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Lifetimes](01-primer.md#primer-lifetimes)* `ffi` has no wrapper for create-with-checkpoint, so this calls the C ABI function by Rust path, as the Node addon does ([Stop 18](18-node.md)). The `// SAFETY:` comment is the convention for every `unsafe` block: it states why the call is sound. Here the three `CString`s are bound to `n`, `d` and `r`, so they outlive the call, and the engine copies them before returning. `CString::new` fails on an interior NUL byte, which becomes the engine's own sentinel `-1`. Note that `bound_anchor` mirrors the engine's private file name and its keys `checkpointRoot`/`checkpointSlot` (host.rs lines 562–620); if the engine ever renamed them, a restart would get the engine's `-3` refusal and the daemon's message for it.

<a id="f-myotis-rpcd-src-seeds-rs"></a>

### myotis-rpcd/src/seeds.rs

*library module · 188 lines*

`--boot-enodes`: EL peers the operator knows to be serving snap, handed to the engine through `myotis_set_boot_enodes` (#465) so a cold start does not wait for discovery. `load` reads `@FILE` or takes the argument itself. `parse` is a pure iterator chain: `lines()`, cut each at `#`, `flat_map` over commas, `trim`, drop empties, then `map(str::to_string)` to own the results. It also drops a leading UTF-8 byte-order mark, which `trim` would not remove because it is not whitespace. The only local check is "not empty": the engine judges every URL, applies the list or refuses it as a whole, and names every bad entry at once.

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Result, ? and panics](01-primer.md#primer-error-handling)* `push` serialises the list with serde (which escapes a NUL byte as `\u0000`, so `CString::new` cannot fail) and calls the C ABI function in an `unsafe` block with a `SAFETY` comment. The engine reports a refusal only as `false` plus a WARN line in its log ring, so `push` drains the ring and quotes the lines that contain "boot enodes refused". `main.rs` flushes the ring just before calling it, so the lines drained are the push's own. If a `RUST_LOG` filter hides WARN, the message says so instead of quoting nothing.

*[Tests](01-primer.md#primer-testing)* Eight tests: seven that need no engine (comma lists, files with comments, BOM, empty lists, 65 entries passed through unjudged, the refusal quote, a temp file read through `load`), and one that creates a real engine handle in a temp dir, never starts it, and checks that the engine accepts two good URLs and refuses a duplicate, a garbage entry and a NUL byte by entry number.

<a id="f-myotis-rpcd-src-rpc-tests-rs"></a>

### myotis-rpcd/src/rpc/tests.rs

*unit tests · 1,296 lines*

Thirty router tests. The engine replies are the shapes pinned by the engine's own golden tests in `eljson.rs`, so a reshaped engine fails here too. Because this file is `mod tests` *inside* `rpc`, it sees rpc.rs's private items: `parse_account`, `decode_revert_reason`, `Router`'s fields. Privacy in Rust is per module, and a child module may use its parent's private items.

| Lines | What is tested |
|---|---|
| 1–195 | Engine goldens, the `Fake` engine, helpers `call`, `result`, `error`, `calls`. |
| 197–380 | Config methods, envelope rules, batches, balance and nonce, the pending overlay, retryable vs permanent engine errors, selectors. |
| 381–543 | Block hashes as pins (#641): served as the block's number, the window, nulls, drift, genesis, `eth_getProof`. |
| 544–935 | Code and storage, `eth_call` outcomes and paths, the type-only path, refusals by id, estimates, access lists, fees, tri-state reads, proofs, logs. |
| 936–1095 | Send and syncing, STALE\_ANCHOR, revert decoding, the call log. |
| 1096–1148 | Account shape drift fails closed. |
| 1149–1296 | The readiness hold (once per request, once per batch, never for bad params) and body classification. |

`rust/myotis-rpcd/src/rpc/tests.rs` · lines 32–70

```rust
/// A recorded engine: canned replies per method, and the calls it saw.
pub(crate) struct Fake {
    replies: HashMap<&'static str, String>,
    head: Option<u64>,
    pub(crate) status: String,
    overlay: i64,
    calls: Mutex<Vec<String>>,
    /// How many times the status was read (the readiness hold polls it).
    status_reads: AtomicUsize,
    /// Answer the transaction-object calls with the REAL engine entry points
    /// on a handle that does not exist: their request checks run first, so a
    /// refused request comes back exactly as the engine refuses it.
    tx_through_engine: bool,
}

impl Fake {
    pub(crate) fn new() -> Self {
        Fake {
            replies: HashMap::new(),
            head: Some(1000),
            status: SYNCED.into(),
            overlay: -1,
            calls: Mutex::new(Vec::new()),
            status_reads: AtomicUsize::new(0),
            tx_through_engine: false,
        }
    }
    fn reply(mut self, method: &'static str, json: &str) -> Self {
        self.replies.insert(method, json.into());
        self
    }
    fn get(&self, method: &'static str, args: String) -> String {
        self.calls.lock().unwrap().push(format!("{method}({args})"));
        self.replies
            .get(method)
            .cloned()
            .unwrap_or_else(|| r#"{"error":"not stubbed"}"#.into())
    }
}
```

- *[Tests](01-primer.md#primer-testing) · [Interior mutability](01-primer.md#primer-interior-mutability)* **A fake behind the trait.** `Fake` answers each method with a canned reply and records every call, so a test can assert both the answer and what the engine was asked (`calls(&r)[0] == "account(0x…,latest)"`). The trait's methods take `&self`, so recording needs interior mutability, and the trait demands `Sync`, so it is a `Mutex<Vec<String>>` and an `AtomicUsize`, not a `RefCell`.
- *[Ownership & moves](01-primer.md#primer-ownership)* `fn reply(mut self, …) -> Self` is a by-value builder: `Fake::new().reply("account", …).reply("resolve", "null")` moves the fake through each call.
- *[Tests](01-primer.md#primer-testing)* With `tx_through_engine` set, the transaction-object calls go to the *real* engine functions on the handle `i64::MIN`, which does not exist: the engine checks the request before it looks for the handle, so its real refusals (such as "requires an authorizationList") come back. `eth_sendRawTransaction` also always calls the real, handle-less `ffi::check_raw_transaction_json`, outside the trait. So `cargo test -p myotis-rpcd` links and partly exercises the whole engine.

`rust/myotis-rpcd/src/rpc/tests.rs` · lines 369–378

```rust
// A pin at or above a head this node reported recently is never "invalid".
let r = Router::new(Fake::new().reply("account", &account("1", 1)));
assert_eq!(result(&r, "eth_blockNumber", json!([])), "0x3e8");
let mut moved = Fake::new().reply("account", &account("1", 1));
moved.head = Some(2000);
let r2 = Router { engine: moved, ..r };
assert_eq!(
    error(&r2, "eth_getBalance", json!([ADDR, "0x3e8"])).0,
    -32000
);
```

*[Ownership & moves](01-primer.md#primer-ownership)* **Struct update syntax.** `Router { engine: moved, ..r }` builds a new router with a new engine and every other field taken from `r`. Those fields are *moved* (the `Mutex` inside `ReportedHeads` is not `Copy`), so `r` can't be used afterwards. The point of the test: the reported head 1000 survives while the engine's head moves to 2000, so a pin at 1000 is now 1000 blocks behind but is still declined retryably (`-32000`), not refused.

`rust/myotis-rpcd/src/rpc/tests.rs` · lines 1156–1175

```rust
#[test]
fn a_number_pinned_read_waits_at_most_once() {
    // pin_servable, the window check and the account read each used to wait.
    let r = unready(Duration::from_millis(300));
    let t0 = Instant::now();
    assert_eq!(result(&r, "eth_getBalance", json!([ADDR, "0x3e8"])), "0x5");
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(550),
        "{took:?}"
    );
    // Same for eth_call through the plain path (pin, window, call).
    let t0 = Instant::now();
    error(&r, "eth_call", json!([{"to": TOKEN}, "0x3e8"]));
    assert!(
        t0.elapsed() < Duration::from_millis(550),
        "{:?}",
        t0.elapsed()
    );
}
```

*[Tests](01-primer.md#primer-testing) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* A timing test: with a 300 ms hold on a node that never becomes ready, a number-pinned read that passes through `pin_servable`, `in_window` and the account read takes at least 300 ms and less than 550 ms, so it waited once, not three times. The comment "each used to wait" records the bug this pins.

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> The doc comment on `a_block_hash_is_served_as_the_canonical_block_it_names` (lines 381–384) says the hash is resolved "through the engine's own `eth_getBlockByHash`". The router now resolves it through `resolve_block_hash` (ABI 47, header only), and the test stubs that method (`"resolve"`), not `block_hash`.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-rpcd-q1"></a>

**Q1** · Multiple choice

Why does myotis-rpcd answer `GET /` and `eth_chainId` on separate intake threads instead of sending every request to the read workers?

- **A.** tiny\_http requires two pools
- **B.** A read may be held for up to `--ready-wait` waiting for a verified head; if every worker is held, a health check queued behind them would time out. Non-blocking methods need no engine readiness, so intake answers them at once
- **C.** Intake threads are faster because they are async
- **D.** The read workers cannot parse JSON

[Answer →](answers.md#a-rpcd-q1)

<a id="q-rpcd-q2"></a>

**Q2** · Multiple choice

In `answer`, `shared.reads.try_send((req, body))` fails with `TrySendError::Full((req, body))`. Why can the code still respond to `req`?

- **A.** `req` was cloned before sending
- **B.** The channel keeps a copy
- **C.** A failed `try_send` returns ownership of the value inside the error, so the pattern binds `req` and `body` again
- **D.** `req` is `Copy`

[Answer →](answers.md#a-rpcd-q2)

<a id="q-rpcd-q3"></a>

**Q3** · Multiple choice

Why do the read workers share the channel's receiver as `Arc<Mutex<Receiver>>`?

- **A.** A `Receiver` can't be cloned and is not `Sync`, so several threads can only share it behind a lock; one worker at a time waits in `recv()` while holding it
- **B.** The `Mutex` makes `recv` faster
- **C.** `Arc` alone would copy the channel
- **D.** tiny\_http requires it

[Answer →](answers.md#a-rpcd-q3)

<a id="q-rpcd-q4"></a>

**Q4** · Written answer

Explain `Budget` and `Gate<'b>`: what each represents, why they use `Cell` rather than `Mutex`, and what the lifetime `'b` guarantees.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-rpcd-q4)

<a id="q-rpcd-q5"></a>

**Q5** · Multiple choice

The verified head is block 1000. Which answer does `eth_getBalance` give for the pin `"0x100"` (block 256), if this node never reported a head at or below 256?

- **A.** The balance at the head
- **B.** `-32000`, retry later
- **C.** `-32602`: more than 64 blocks behind the head, and this node holds no historical state, so no retry can help
- **D.** `null`

[Answer →](answers.md#a-rpcd-q5)

<a id="q-rpcd-q6"></a>

**Q6** · Written answer

The project rule says a parameter must be applied or refused, never silently ignored. Name three places in rpc.rs where that rule decides the code, and explain why the refusal uses -32602 rather than -32000.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-rpcd-q6)

<a id="q-rpcd-q7"></a>

**Q7** · Multiple choice

Why is the `Engine` trait declared as `pub trait Engine: Send + Sync`?

- **A.** So the trait can be used with `dyn`
- **B.** The router is shared by many threads through an `Arc`; it can only be `Send + Sync` if its engine is, and the supertraits make every implementation, including the test `Fake`, guarantee that
- **C.** It makes the methods non-blocking
- **D.** UniFFI requires it

[Answer →](answers.md#a-rpcd-q7)

<a id="q-rpcd-q8"></a>

**Q8** · Written answer

In `run`, what does `let guard = StopOnDrop(handle);` guarantee, and why would it be defeated if `run` itself called `std::process::exit(1)` on an error?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-rpcd-q8)

<a id="q-rpcd-q9"></a>

**Q9** · Written answer

`decode_revert_reason` reads offsets and lengths from a revert payload. Why does it use `d.get(range)?` and `checked_add` instead of `&d[a..b]` and `+`, and what would go wrong otherwise?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-rpcd-q9)

<a id="q-rpcd-q10"></a>

**Q10** · Multiple choice

An `eth_call` request carries `{"to": …, "gas": "0x5208"}`. Which engine function answers it, and why?

- **A.** `eth_call_tx`: `gas` makes the transaction `extended`, and the plain call has no gas parameter, so it would silently drop it
- **B.** `eth_call`: gas is ignored for calls
- **C.** `estimate_gas_tx`
- **D.** None: gas limits are refused

[Answer →](answers.md#a-rpcd-q10)

<a id="q-rpcd-q11"></a>

**Q11** · Multiple choice

A test writes `let r2 = Router { engine: moved, ..r };`. What happens to `r`?

- **A.** Nothing; `..r` copies the fields
- **B.** Its remaining fields are moved into `r2` (they are not `Copy`), so `r` can no longer be used as a whole
- **C.** It is dropped before `r2` is built
- **D.** It becomes a reference to `r2`

[Answer →](answers.md#a-rpcd-q11)

<a id="q-rpcd-q12"></a>

**Q12** · Written answer

A client sends a 4 KiB JSON body very slowly. Follow it through http.rs: which thread reads it, what bounds that, and what happens if it doesn't arrive within `--http-body-timeout`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-rpcd-q12)

<a id="q-rpcd-q13"></a>

**Q13** · Multiple choice

What does `args.import_log_index.iter().map(|p| std::fs::canonicalize(p).map_err(…)).collect::<Result<Vec<_>, _>>()?` do when the second of three paths does not exist?

- **A.** Returns a vector with two paths
- **B.** Panics
- **C.** Skips the bad path
- **D.** Stops at the second path and returns its error from `run` through `?`; the third path is never canonicalised

[Answer →](answers.md#a-rpcd-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
