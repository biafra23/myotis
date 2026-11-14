//! myotis-rpcd: standard Ethereum JSON-RPC over HTTP on localhost, answered by
//! the myotis verified light-client engine — no JVM, and no upstream RPC to
//! fall back on. Anything the engine cannot verify is an error, never a guess.
//!
//! One engine handle per process (one network). The engine owns its tokio
//! runtime and every read is a BLOCKING call that may hold for a verified head,
//! so the HTTP side is deliberately synchronous (see http.rs): a small intake
//! pool answers everything that cannot block, and a fixed pool of read workers
//! each takes a gated request, blocks in the engine for as long as it must,
//! and answers.

mod checkpoint;
mod engine;
mod http;
mod quantity;
mod rpc;
mod seeds;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use myotis_engine::ffi;

use engine::FfiEngine;
use rpc::Router;

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
    /// Comma-separated host names a request's Host header may carry (geth's
    /// --http.vhosts), against DNS rebinding from a browser. Default:
    /// localhost, 127.0.0.1, [::1] and the --listen address. A list replaces
    /// the default; '*' turns the check off.
    #[arg(long, value_name = "HOSTS", value_delimiter = ',')]
    http_vhosts: Option<Vec<String>>,
    /// eth_getLogs watch-list config (engine JSON:
    /// {"enabled":true,"watch":[{"address":"0x…","fromBlock":N}]}),
    /// installed once the engine's EL reader is up.
    #[arg(long, value_name = "FILE")]
    log_index_config: Option<PathBuf>,
    /// Seconds a read is held waiting for a verified head and a serving peer
    /// before the engine is asked anyway (the JVM host's wake cap).
    #[arg(long, default_value_t = 90, value_name = "SECS")]
    ready_wait: u64,
    /// HTTP read workers, i.e. concurrent engine reads. Requests that cannot
    /// block (GET /, config methods, eth_syncing) never wait for one.
    #[arg(long, default_value_t = 16)]
    workers: usize,
    /// Requests that may wait for a busy read worker; past it a request is
    /// refused at once with HTTP 503 and a -32000 "server busy" error.
    /// Default: twice --workers.
    #[arg(long, value_name = "N")]
    http_queue: Option<usize>,
    /// Seconds to receive a request body; a client still sending after that
    /// is answered 408.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    http_body_timeout: u64,
    /// Consent to sync forward from an embedded trust anchor older than the
    /// weak-subjectivity bound, for this run only. Without it a stale anchor
    /// parks the node (STALE_ANCHOR) and every read is refused. This is a trust
    /// decision: a chain signed by since-exited sync-committee members would be
    /// indistinguishable from the real one.
    #[arg(long)]
    accept_stale_anchor: bool,
    /// Override the weak-subjectivity bound, in sync-committee periods
    /// (0 = the network default). Same trust trade-off as above.
    #[arg(long, value_name = "PERIODS")]
    ws_bound_periods: Option<i64>,
    /// Log every JSON-RPC request (method, outcome, time) to stderr.
    #[arg(long)]
    access_log: bool,
    /// Portable log-index snapshot(s) to import once the --log-index-config is
    /// installed (e.g. a seed from myotis' scripts/synth_logindex.py). The
    /// import is all-or-nothing; its logs are served as the snapshot claims
    /// them, so a seed is only as good as its source.
    #[arg(long, value_name = "FILE", requires = "log_index_config")]
    import_log_index: Vec<PathBuf>,
    /// Append one JSON line per JSON-RPC request (each batch element on its
    /// own line) to FILE: ts, method, params (long strings shortened), outcome
    /// (ok / null / error with code and message), a shortened result, and ms.
    #[arg(long, value_name = "FILE")]
    log_calls: Option<PathBuf>,
    /// Bootstrap from this beacon block root (0x + 32 bytes), with
    /// --checkpoint-slot, instead of the embedded checkpoint.
    ///
    /// The root is trusted as the ANCHOR only: the engine fetches a
    /// light-client bootstrap for it from peers, checks it against the root,
    /// and verifies every later header forward with sync-committee signatures,
    /// exactly as from the embedded checkpoint. It is the alternative to
    /// --accept-stale-anchor when the build's checkpoint has aged out. Where the
    /// root comes from is the operator's choice; the daemon never fetches one.
    /// The data dir is bound to the anchor it was first created with: a
    /// different anchor needs a fresh --data-dir.
    #[arg(long, value_name = "ROOT", requires = "checkpoint_slot")]
    checkpoint_root: Option<String>,
    /// The slot of the block whose root is --checkpoint-root.
    #[arg(long, value_name = "SLOT", requires = "checkpoint_root")]
    checkpoint_slot: Option<u64>,
    /// EL peers to dial as soon as the engine starts, without waiting for
    /// discovery: a comma-separated list of enode:// URLs, or @FILE with one
    /// per line (# comments allowed). For servers known to answer snap, so a
    /// cold start does not wait for discovery to find one. They are dialed
    /// alongside the peer cache, not strictly before it. The engine applies
    /// the list or refuses it as a whole (at most 64 entries, IP addresses
    /// only).
    #[arg(long, value_name = "ENODES|@FILE")]
    boot_enodes: Option<String>,
    /// discv4 (EL discovery) UDP port. 0 = OS-assigned, the default. The EL
    /// side only dials out, so this is its one listening socket.
    #[arg(long, default_value_t = 0, value_name = "PORT")]
    discv4_port: u16,
    /// discv5 (CL discovery) UDP port. 0 = OS-assigned, the default.
    #[arg(long, default_value_t = 0, value_name = "PORT")]
    discv5_port: u16,
    /// libp2p light-client host TCP port. 0 = OS-assigned, the default.
    #[arg(long, default_value_t = 0, value_name = "PORT")]
    libp2p_port: u16,
    /// libp2p light-client host QUIC (UDP) port. 0 = OS-assigned, the default.
    #[arg(long, default_value_t = 0, value_name = "PORT")]
    libp2p_quic_port: u16,
}

impl Args {
    /// The P2P ports asked for on the command line; `None` when all are 0, which
    /// leaves every socket OS-assigned without asking the engine at all.
    fn listen_ports(&self) -> Option<[u16; 4]> {
        let ports = [self.discv4_port, self.discv5_port, self.libp2p_port, self.libp2p_quic_port];
        ports.iter().any(|&p| p != 0).then_some(ports)
    }
}

fn main() {
    let args = Args::parse();
    if let Err(e) = run(args) {
        // The log drain only runs once the engine has started, so whatever
        // the engine logged on the way to this error (a refused create or
        // start, and the stop() the handle's guard ran as run() returned) is
        // still in its ring: print it, then the error last.
        print_engine_logs();
        eprintln!("myotis-rpcd: {e}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    // ABI handshake (also installs the engine's log ring). The engine is linked
    // statically, so a mismatch means a broken build, not a stale library.
    let abi = ffi::engine_init();
    if abi != myotis_engine::ABI_VERSION {
        return Err(format!(
            "engine ABI {abi}, built against {}",
            myotis_engine::ABI_VERSION
        ));
    }
    // EIP-1459 DNS discovery (#539): this daemon resolves through the system
    // resolver, as the JVM daemon does, so the EL pool may walk the network's
    // node list for peers. Off until a host says so; this one does.
    ffi::set_dns_discovery(true);
    let network = ffi::canonical_network_name(args.network.clone())
        .ok_or_else(|| format!("unknown network '{}'", args.network))?;
    let chain_id = chain_id_of(&network)?;
    let listen_ports = args.listen_ports();
    let listen = match args.listen {
        Some(addr) => addr,
        None => default_listen(&network)?,
    };
    let data_dir = match args.data_dir {
        Some(d) => d,
        None => {
            let home = std::env::var_os("HOME").ok_or("HOME is not set; pass --data-dir")?;
            PathBuf::from(home)
                .join(".local/share/myotis-rpcd")
                .join(&network)
        }
    };
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let log_index = match &args.log_index_config {
        Some(p) => {
            let s = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            serde_json::from_str::<serde_json::Value>(&s)
                .map_err(|e| format!("{}: not JSON: {e}", p.display()))?;
            Some(s)
        }
        None => None,
    };
    // Every other input is checked before the engine starts, too: a typo must
    // not cost a started (and then abandoned) engine handle.
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
    let vhosts = http::VHosts::new(args.http_vhosts.as_deref(), listen);

    // Bind before starting the engine, so a taken port fails in milliseconds.
    let server =
        Arc::new(tiny_http::Server::http(listen).map_err(|e| format!("listen {listen}: {e}"))?);

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
    if let Some(p) = args.ws_bound_periods {
        ffi::set_ws_bound_periods(handle, p);
        eprintln!("myotis-rpcd: weak-subjectivity bound overridden to {p} periods");
    }
    if args.accept_stale_anchor {
        ffi::accept_stale_anchor(handle);
        eprintln!("myotis-rpcd: --accept-stale-anchor: a stale trust anchor will be synced from (this run)");
    }
    if let Some(urls) = &boot_enodes {
        // Flush the ring first, so the lines push() drains are its own.
        print_engine_logs();
        seeds::push(handle, urls)?;
        eprintln!("myotis-rpcd: {} boot enode(s) pinned", urls.len());
    }
    if let Some([discv4, discv5, libp2p_tcp, libp2p_quic]) = listen_ports {
        print_engine_logs();
        if !myotis_engine::capi::myotis_set_listen_ports(handle, discv4, discv5, libp2p_tcp, libp2p_quic) {
            // The engine's WARN names the reason (e.g. a UDP port given twice).
            print_engine_logs();
            return Err("the engine refused the --discv4-port/--discv5-port/--libp2p-port/\
                        --libp2p-quic-port set; nothing was bound"
                .into());
        }
        eprintln!(
            "myotis-rpcd: P2P ports pinned (0 = OS-assigned): discv4 udp/{discv4}, discv5 udp/{discv5}, \
             libp2p tcp/{libp2p_tcp}, libp2p quic udp/{libp2p_quic}"
        );
    }
    if !ffi::start_handle(handle) {
        // The engine's WARN says why (e.g. a --libp2p-port another process holds).
        print_engine_logs();
        return Err("engine failed to start".into());
    }
    // A discv4 bind failure is not fatal to the engine: it runs CL-only, with no
    // EL reader until a pause/resume, which rpcd never does — so every state read
    // would fail for the life of the process. With a pinned --discv4-port that is
    // the expected operator error (a port another node holds), so fail the start
    // the way a taken --listen or --libp2p-port does. The reader is built inside
    // start, so the status already says whether it came up.
    if matches!(listen_ports, Some([discv4, ..]) if discv4 != 0) && !el_reader_available(handle) {
        print_engine_logs();
        return Err("the EL reader did not start (the engine's WARN above says why, e.g. a \
                    --discv4-port another process holds); no state read could be served"
            .into());
    }
    eprintln!(
        "myotis-rpcd {}: {network} (chain {chain_id}), data {}, serving http://{}",
        env!("CARGO_PKG_VERSION"),
        data_dir.display(),
        listen
    );

    let stopping = Arc::new(AtomicBool::new(false));
    spawn_log_drain(stopping.clone());
    if let Some(cfg) = log_index {
        spawn_log_index_install(handle, cfg, imports);
    }

    let mut router = Router::new(FfiEngine { handle, chain_id })
        .with_ready_wait(Duration::from_secs(args.ready_wait))
        .with_access_log(args.access_log);
    if let Some(f) = call_log {
        router = router.with_call_log(Box::new(f));
    }
    let mut limits = http::Limits::new(args.workers);
    if let Some(q) = args.http_queue {
        limits.queue = q;
    }
    limits.body_timeout = Duration::from_secs(args.http_body_timeout);
    // A listener whose accept thread died (#737) stops the process the way a
    // signal does, so the engine still persists its state, and run() then
    // fails: the exit status is non-zero and a supervisor restarts rpcd.
    let mut signals = StopSignals::install()?;
    let listener = http::Listener::new(|| {
        let _ = signal_hook::low_level::raise(signal_hook::consts::SIGTERM);
    });
    let receivers = http::spawn(
        server.clone(),
        Arc::new(router),
        vhosts,
        args.workers,
        limits,
        listener.clone(),
    );

    // Graceful stop: stop accepting, shut the engine handle down (it persists
    // its sync state), flush the log ring. Workers still blocked in an engine
    // read are not waited for; the handle they hold is gone.
    let sig = signals.wait();
    // One step: from here no recv() error counts as a failure, and a failure
    // recorded before it (even after the signal) is returned, never lost.
    let failure = listener.stop();
    match (&failure, sig) {
        // The failure itself is printed last, by main(), from run()'s error.
        (Some(_), _) => eprintln!("myotis-rpcd: HTTP listener failed, stopping"),
        (None, Some(sig)) => eprintln!("myotis-rpcd: signal {sig}, stopping"),
        (None, None) => {}
    }
    for _ in 0..receivers {
        server.unblock();
    }
    drop(guard);
    stopping.store(true, Ordering::SeqCst);
    print_engine_logs();
    match failure {
        Some(f) => Err(f),
        None => Ok(()),
    }
}

/// The stop signals, registered before the listener starts: its failure hook
/// raises SIGTERM (#737), which must find a handler, never the default action
/// that would kill the process before the engine persists its state.
/// [`StopSignals::wait`] blocks until one arrives and returns its number
/// (`None`: the iterator closed without one). Unix: SIGINT or SIGTERM,
/// through signal-hook's self-pipe iterator.
#[cfg(unix)]
struct StopSignals(signal_hook::iterator::Signals);

#[cfg(unix)]
impl StopSignals {
    fn install() -> Result<StopSignals, String> {
        use signal_hook::consts::{SIGINT, SIGTERM};
        signal_hook::iterator::Signals::new([SIGINT, SIGTERM])
            .map(StopSignals)
            .map_err(|e| e.to_string())
    }

    fn wait(&mut self) -> Option<i32> {
        self.0.forever().next()
    }
}

/// Windows has no signal iterator (signal-hook builds it only off Windows):
/// the C runtime raises SIGINT for Ctrl-C and SIGBREAK for Ctrl-Break, and
/// SIGTERM can be raised in-process, so each records its number in a flag the
/// main thread polls. Shutdown is no more prompt than that needs to be.
#[cfg(windows)]
struct StopSignals(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(windows)]
impl StopSignals {
    fn install() -> Result<StopSignals, String> {
        use signal_hook::consts::{SIGBREAK, SIGINT, SIGTERM};
        let caught = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for sig in [SIGINT, SIGTERM, SIGBREAK] {
            signal_hook::flag::register_usize(sig, caught.clone(), sig as usize)
                .map_err(|e| e.to_string())?;
        }
        Ok(StopSignals(caught))
    }

    fn wait(&mut self) -> Option<i32> {
        loop {
            match self.0.load(Ordering::SeqCst) {
                0 => std::thread::sleep(Duration::from_millis(100)),
                sig => return Some(sig as i32),
            }
        }
    }
}

/// Stops a created engine handle when dropped.
struct StopOnDrop(i64);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        ffi::stop_handle(self.0);
    }
}

/// Loopback on the per-network JSON-RPC port the Android/desktop apps and the
/// daemon default to — the catalog's `defaultRpcPort`, the one table every
/// host reads: one endpoint per network whichever host serves it (and so, with
/// defaults, not both of them on one machine).
fn default_listen(network: &str) -> Result<SocketAddr, String> {
    let port = catalog_field(network, "defaultRpcPort")?;
    let port = u16::try_from(port).map_err(|_| format!("catalog port {port} for '{network}' is not a port"))?;
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

/// The catalog's chain id for a canonical network name.
fn chain_id_of(network: &str) -> Result<u64, String> {
    catalog_field(network, "chainId")
}

/// One numeric field of `network`'s entry in the engine catalog.
fn catalog_field(network: &str, field: &str) -> Result<u64, String> {
    let v: serde_json::Value = serde_json::from_str(&ffi::available_networks_json())
        .map_err(|e| format!("engine network catalog: {e}"))?;
    v.as_array()
        .and_then(|a| a.iter().find(|n| n["name"] == network))
        .and_then(|n| n[field].as_u64())
        .ok_or_else(|| format!("no {field} for '{network}' in the engine catalog"))
}

/// Pump the engine's tracing ring to stderr, stamped (the ring lines carry no
/// time of their own).
fn spawn_log_drain(stopping: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stopping.load(Ordering::SeqCst) {
            print_engine_logs();
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

/// Whether the handle's status reports a live EL reader (`elReaderAvailable`).
fn el_reader_available(handle: i64) -> bool {
    serde_json::from_str::<serde_json::Value>(&ffi::status_json(handle))
        .ok()
        .and_then(|v| v["elReaderAvailable"].as_bool())
        .unwrap_or(false)
}

fn print_engine_logs() {
    let lines = ffi::drain_logs(1024);
    if lines.is_empty() {
        return;
    }
    let stamp = utc_hms();
    let mut err = std::io::stderr().lock();
    for line in lines.lines() {
        let _ = std::io::Write::write_fmt(&mut err, format_args!("{stamp} {line}\n"));
    }
}

/// `HH:MM:SSZ`, without a date-time dependency.
fn utc_hms() -> String {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    format!("{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// The log-index config can only be installed on a RUNNING handle whose EL
/// reader is up, which is not yet true right after start: retry until the
/// engine takes it. A config it keeps refusing (malformed watch entry) is
/// reported every minute; the engine logs the reason itself.
fn spawn_log_index_install(handle: i64, cfg: String, imports: Vec<PathBuf>) {
    std::thread::spawn(move || {
        let t0 = Instant::now();
        let mut last_warn = Instant::now();
        loop {
            if ffi::set_log_index_config(handle, cfg.clone()) {
                eprintln!(
                    "myotis-rpcd: log index config installed after {}s: {}",
                    t0.elapsed().as_secs(),
                    ffi::log_index_status_json(handle)
                );
                if !imports.is_empty() {
                    let paths: Vec<String> = imports
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect();
                    let json = serde_json::to_string(&paths).unwrap_or_default();
                    eprintln!(
                        "myotis-rpcd: log index import {json}: {}",
                        ffi::import_log_index_files(handle, json.clone())
                    );
                }
                return;
            }
            if last_warn.elapsed() > Duration::from_secs(60) {
                eprintln!("myotis-rpcd: log index config not accepted yet (EL reader down or config refused)");
                last_warn = Instant::now();
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Args {
        Args::try_parse_from(["myotis-rpcd"].iter().chain(extra)).expect("valid arguments")
    }

    #[test]
    fn port_switches_default_to_os_assigned_and_skip_the_engine_call() {
        let args = parse(&[]);
        assert_eq!(
            [args.discv4_port, args.discv5_port, args.libp2p_port, args.libp2p_quic_port],
            [0, 0, 0, 0]
        );
        assert_eq!(args.listen_ports(), None);
    }

    #[test]
    fn any_port_switch_pins_all_four_in_engine_order() {
        let args = parse(&["--discv4-port", "30305", "--libp2p-quic-port", "9106"]);
        assert_eq!(args.listen_ports(), Some([30305, 0, 0, 9106]));
        let all = parse(&[
            "--discv4-port", "30305", "--discv5-port", "9005", "--libp2p-port", "9105", "--libp2p-quic-port", "9106",
        ]);
        assert_eq!(all.listen_ports(), Some([30305, 9005, 9105, 9106]));
    }

    #[test]
    fn a_port_outside_u16_is_a_usage_error() {
        assert!(Args::try_parse_from(["myotis-rpcd", "--discv4-port", "70000"]).is_err());
    }
}
