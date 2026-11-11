//! Debug probe for one execution-layer peer of a chain Myotis does not ship —
//! by default the EEZ RollupX Nethermind bootnode (L2 chain 696991,
//! `rollupx.eez.dev`). It settles PROTOCOL compatibility, nothing more: can the
//! session Myotis ships (`RlpxConnection::dial` → `EthSession::handshake` →
//! `get_block_headers_*` → `snap_get_account` / `_storage` / `_bytecode`) talk
//! to this peer, and how far behind its head does the peer still serve snap
//! proofs?
//!
//! It drives the PRODUCTION session, not hand-rolled frames, so every verdict
//! is about the code Myotis runs: the header step uses Myotis's own
//! `BlockHeader` decoder (a header-layout incompatibility shows up there), and
//! the snap steps verify the MPT proof / code hash themselves.
//!
//! Diagnostic tool, not part of the sync and not a trust path. Without
//! `EEZ_ANCHOR_HASH` every proof is checked against the state root of the
//! peer's OWN head — it proves the peer serves snap proofs for the head it
//! announces and says nothing about that head being canonical. With
//! `EEZ_ANCHOR_HASH` the header is keccak-checked against a hash the CALLER
//! supplies; whether that hash is a sound anchor (for RollupX: the root its L1
//! registry holds, attested by its proof system) is outside this tool.
//!
//! Connections: the target is dialled once. A second connection is opened
//! only when the first one cannot finish — to retry with the fork id the peer
//! announced, or to read the peer's Status without sending ours — and only
//! after a pause (`EEZ_RETRY_PAUSE_SECS`), because Nethermind's recent-IP
//! filter can hold off a quick reconnect from the same address.
//!
//! ```bash
//! cargo run --release -p myotis-net --example eez_probe
//! ```
//!
//! Environment (defaults are the published RollupX values):
//!
//! | variable | meaning |
//! |---|---|
//! | `EEZ_ENODE` | the peer, `enode://<pubkey>@<ip>:<port>` |
//! | `EEZ_NETWORK_ID`, `EEZ_GENESIS` | the chain our Status claims |
//! | `EEZ_FORK_ID` | `<8 hex>[:next]`; default CRC32(genesis), next 0 — a GUESS (no fork at a non-zero block or time) |
//! | `EEZ_ACCOUNT` | the account to prove (20 bytes hex) |
//! | `EEZ_SLOTS` | comma-separated storage slots (hex, left-padded) |
//! | `EEZ_ANCHOR_HASH` | prove at this block hash instead of the peer's head |
//! | `EEZ_DEPTHS` | comma-separated depths below the head for the serving-window sweep; empty = skip |
//! | `EEZ_RETRY_PAUSE_SECS` | pause before a second connection (default 30) |
//! | `CRAWL_SECS` | > 0: afterwards crawl discv4 from this peer alone and probe what it finds (default 0) |

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use myotis_core::forkid::crc32_update;
use myotis_core::nodekey::NodeKey;
use myotis_core::rlp;
use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
use myotis_net::el::discv4::{Discv4Config, Discv4Service, TableEntry};
use myotis_net::el::eth::messages::{self as eth, VerifiedHeader};
use myotis_net::el::eth::session::{EthConfig, EthSession};
use myotis_net::el::rlpx::transport::RlpxConnection;
use myotis_net::el::snap::fetch::{
    is_unknown_root_error, is_unservable_root_error, AccountOutcome,
};
use myotis_wire::rlpx::hello::{decode_hello, encode_hello, Hello, P2P_DISCONNECT, P2P_HELLO};
use tokio::sync::{Mutex, Semaphore};

#[path = "probe_common/mod.rs"]
mod probe_common;
use probe_common::{caps_line, disconnect_reason, fresh_node_key, negotiate, recv_frame, truncate};

// eez-association/eez-rollupX `docs/runbooks/nethermind-snap.md` (PR #128).
const DEFAULT_ENODE: &str = "enode://94c3e3ae1718f646508770483ce335175f97420fe635be7a545a739ab9981d06de2fb3d1ec37737ddfc55ad619f2b1d12922f48dbd15f44501b8f244c9f99d72@104.196.3.9:30313";
const DEFAULT_NETWORK_ID: u64 = 696_991;
const DEFAULT_GENESIS: &str = "b6bd210b7e824a1aabc4c1ae5b64f5643715441b332c7152e641a36ba01835b2";
/// The EEZL2 proxy: has code and storage (sampled in the runbook's audit).
const DEFAULT_ACCOUNT: &str = "4b2760f84b83d6b3829e30a7573b0172b6d6402c";
/// Slot 0 and the EIP-1967 implementation slot (non-zero on an ERC-1967 proxy).
const DEFAULT_SLOTS: &str = "0,360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/// Ascending, to past the 16,384 blocks the RollupX runbook gives as the snap
/// serving depth. (Measured 2026-11-11 on the default target: a root 5,120
/// blocks behind the head was served, one 6,144 behind was not.)
const DEFAULT_DEPTHS: &str = "128,1024,2048,4096,8192,16384,20000";

/// Where the fork id our Status carries came from — it decides how much a
/// passed EIP-2124 check says.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ForkSource {
    /// CRC32(genesis), next 0: right only for a chain with no later fork.
    Guess,
    /// `EEZ_FORK_ID`.
    Env,
    /// Read from the peer's own Status on the first connection and echoed.
    Learned,
}

#[derive(Clone)]
struct Knobs {
    addr: SocketAddr,
    pubkey: [u8; 64],
    network_id: u64,
    genesis: [u8; 32],
    fork_hash: [u8; 4],
    fork_next: u64,
    fork_source: ForkSource,
    account: [u8; 20],
    slots: Vec<[u8; 32]>,
    anchor: Option<[u8; 32]>,
    depths: Vec<u64>,
    retry_pause: Duration,
    crawl_secs: u64,
}

impl Knobs {
    fn from_env() -> Result<Knobs, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let num = |name: &str, default: u64| match var(name) {
            Some(v) => v.trim().parse::<u64>().map_err(|e| format!("{name}: {e}")),
            None => Ok(default),
        };
        let enode = var("EEZ_ENODE").unwrap_or_else(|| DEFAULT_ENODE.into());
        let (addr, pubkey) = myotis_net::el::reader::parse_enode(enode.trim())
            .map_err(|e| format!("EEZ_ENODE: {e}"))?;
        let genesis: [u8; 32] = hex_fixed(
            &var("EEZ_GENESIS").unwrap_or_else(|| DEFAULT_GENESIS.into()),
            false,
        )
        .map_err(|e| format!("EEZ_GENESIS: {e}"))?;
        let (fork_hash, fork_next, fork_source) = match var("EEZ_FORK_ID") {
            Some(v) => {
                let (hash, next) = match v.trim().split_once(':') {
                    Some((h, n)) => (
                        h,
                        n.parse::<u64>()
                            .map_err(|e| format!("EEZ_FORK_ID next: {e}"))?,
                    ),
                    None => (v.trim(), 0),
                };
                let hash: [u8; 4] =
                    hex_fixed(hash, false).map_err(|e| format!("EEZ_FORK_ID: {e}"))?;
                (hash, next, ForkSource::Env)
            }
            None => (genesis_fork_hash(&genesis), 0, ForkSource::Guess),
        };
        let mut slots = Vec::new();
        for s in var("EEZ_SLOTS")
            .unwrap_or_else(|| DEFAULT_SLOTS.into())
            .split(',')
        {
            slots.push(hex_fixed(s, true).map_err(|e| format!("EEZ_SLOTS: {e}"))?);
        }
        let mut depths = Vec::new();
        // An explicitly EMPTY `EEZ_DEPTHS=` skips the sweep, so read it raw.
        let depths_raw = std::env::var("EEZ_DEPTHS").unwrap_or_else(|_| DEFAULT_DEPTHS.into());
        for d in depths_raw
            .split(',')
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            depths.push(d.parse::<u64>().map_err(|e| format!("EEZ_DEPTHS: {e}"))?);
        }
        Ok(Knobs {
            addr,
            pubkey,
            network_id: num("EEZ_NETWORK_ID", DEFAULT_NETWORK_ID)?,
            genesis,
            fork_hash,
            fork_next,
            fork_source,
            account: hex_fixed(
                &var("EEZ_ACCOUNT").unwrap_or_else(|| DEFAULT_ACCOUNT.into()),
                false,
            )
            .map_err(|e| format!("EEZ_ACCOUNT: {e}"))?,
            slots,
            anchor: match var("EEZ_ANCHOR_HASH") {
                Some(v) => Some(hex_fixed(&v, false).map_err(|e| format!("EEZ_ANCHOR_HASH: {e}"))?),
                None => None,
            },
            depths,
            retry_pause: Duration::from_secs(num("EEZ_RETRY_PAUSE_SECS", 30)?),
            crawl_secs: num("CRAWL_SECS", 0)?,
        })
    }

    /// Our side of the eth handshake. A probe holds no chain: it announces the
    /// genesis as its head and serves nothing (`served_range` None → `[0, 0]`
    /// on eth/69+).
    fn eth_config(&self) -> EthConfig {
        EthConfig {
            network_id: self.network_id,
            genesis_hash: self.genesis,
            fork_id_hash: self.fork_hash,
            fork_next: self.fork_next,
            head_hash: self.genesis,
            head_number: 0,
            listen_port: 0,
            genesis_header_rlp: None,
        }
    }
}

/// EIP-2124 fork hash of a chain with no fork past genesis: CRC32(genesis hash).
fn genesis_fork_hash(genesis: &[u8; 32]) -> [u8; 4] {
    crc32_update(0, genesis).to_be_bytes()
}

/// `N` bytes from hex, with or without `0x`. `pad` left-pads a short value
/// with zeros (storage slots: `0` is slot zero); otherwise the length is exact.
fn hex_fixed<const N: usize>(s: &str, pad: bool) -> Result<[u8; N], String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Digits checked here, not left to `from_str_radix`: it also takes a sign.
    let all_hex = s.bytes().all(|b| b.is_ascii_hexdigit());
    if !all_hex || s.is_empty() || s.len() > N * 2 || (!pad && s.len() != N * 2) {
        return Err(format!(
            "expected {}{} hex digits, got \"{}\"",
            if pad { "up to " } else { "" },
            N * 2,
            truncate(s, 80)
        ));
    }
    let padded = format!("{s:0>width$}", width = N * 2);
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// How one connection to the target ended.
enum Outcome {
    /// The session ran. `ok` = every core step (header, account, storage,
    /// bytecode) verified.
    Ran { ok: bool },
    /// No TCP / RLPx session at all: nothing a second connection would add.
    DialFailed(String),
    /// The eth handshake failed before the peer's Status was read.
    HandshakeFailed(String),
    /// The peer announced a fork id other than the one we sent, and then the
    /// session failed: worth one retry echoing the peer's.
    ForkIdRejected {
        peer_hash: [u8; 4],
        peer_next: u64,
        error: String,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let mut knobs = match Knobs::from_env() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("eez_probe: {e}");
            return ExitCode::from(2);
        }
    };
    let key = fresh_node_key();

    println!("=== eez_probe ===");
    println!(
        "target      {} (pubkey {}…)",
        knobs.addr,
        hex(&knobs.pubkey[..8])
    );
    println!(
        "our Status  networkId={} genesis=0x{}",
        knobs.network_id,
        hex(&knobs.genesis)
    );

    let ok = match probe_once(&key, &knobs).await {
        Outcome::Ran { ok } => ok,
        Outcome::DialFailed(e) => {
            println!("\nFAILED  dial: {e}");
            false
        }
        Outcome::ForkIdRejected {
            peer_hash,
            peer_next,
            error,
        } => {
            println!("\nFAILED  {error}");
            println!(
                "        The peer announced fork id {}:{peer_next}, we sent {}:{} — most likely why.",
                hex(&peer_hash),
                hex(&knobs.fork_hash),
                knobs.fork_next
            );
            pause_before_reconnect(&knobs, "retry with the peer's fork id").await;
            knobs.fork_hash = peer_hash;
            knobs.fork_next = peer_next;
            knobs.fork_source = ForkSource::Learned;
            match probe_once(&key, &knobs).await {
                Outcome::Ran { ok } => ok,
                Outcome::DialFailed(e) | Outcome::HandshakeFailed(e) => {
                    println!("\nFAILED  second connection: {e}");
                    false
                }
                Outcome::ForkIdRejected { error, .. } => {
                    println!("\nFAILED  second connection: {error}");
                    false
                }
            }
        }
        Outcome::HandshakeFailed(e) => {
            println!("\nFAILED  eth handshake: {e}");
            // `EthSession::handshake`'s wording for a Disconnect in answer to
            // our Hello (too many peers, already connected, …): the peer sent
            // no Status and would send none to a second Hello either.
            if e.starts_with("peer disconnected during handshake") {
                println!("        The peer refused the connection at Hello; a second one would be refused the same way. Try again later.");
            } else {
                pause_before_reconnect(&knobs, "read the peer's Status without sending ours").await;
                if let Err(e) = diagnose(&key, &knobs).await {
                    println!("FAILED  diagnostic pass: {e}");
                }
            }
            false
        }
    };

    if knobs.crawl_secs > 0 {
        crawl(&key, &knobs).await;
    }

    if ok && knobs.fork_source == ForkSource::Learned {
        // The reads verified, but the handshake only passed by echoing the
        // peer: this build could not have produced that fork id itself.
        println!(
            "\nNOTE    the fork id was LEARNED from the peer; pass EEZ_FORK_ID={}:{} to skip the first connection",
            hex(&knobs.fork_hash),
            knobs.fork_next
        );
    }
    println!("\n=== {} ===", if ok { "PASS" } else { "FAIL" });
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn pause_before_reconnect(knobs: &Knobs, why: &str) {
    println!(
        "\nPausing {} s before a second connection to {} ({why}): Nethermind's recent-IP filter can hold off a quick reconnect from the same address.",
        knobs.retry_pause.as_secs(),
        knobs.addr
    );
    tokio::time::sleep(knobs.retry_pause).await;
}

/// One connection to the target through the production session.
async fn probe_once(key: &Arc<NodeKey>, knobs: &Knobs) -> Outcome {
    let cfg = knobs.eth_config();
    let now = myotis_net::el::fork_watch::wall_clock_secs();
    let (sent_hash, sent_next) = cfg.fork_id_at(now);
    println!(
        "\n--- connecting; our fork id {}:{sent_next} ({}) ---",
        hex(&sent_hash),
        match knobs.fork_source {
            ForkSource::Guess => "a guess: CRC32(genesis), no later fork",
            ForkSource::Env => "from EEZ_FORK_ID",
            ForkSource::Learned => "learned from the peer",
        }
    );
    let conn = match RlpxConnection::dial(Arc::clone(key), knobs.addr, knobs.pubkey).await {
        Ok(c) => c,
        Err(e) => return Outcome::DialFailed(e),
    };
    println!("rlpx        ECIES handshake ok");
    let started = Instant::now();
    let mut session = match EthSession::handshake(conn, &key.public_key_bytes(), &cfg, None).await {
        Ok(s) => s,
        Err(e) => return Outcome::HandshakeFailed(e),
    };

    report_hello(key, &session.peer_hello);
    println!(
        "negotiated  eth/{} snap/{}",
        session.eth_version,
        session
            .snap_version
            .map_or("- (none shared)".into(), |v| v.to_string())
    );
    let status = session.peer_status.clone();
    println!(
        "peer Status networkId={} genesis=0x{}",
        status.network_id,
        hex(&status.genesis_hash)
    );
    println!(
        "            head=0x{} latest={} earliest={}",
        hex(&status.best_hash),
        status.latest_block.map_or("-".into(), |v| v.to_string()),
        status.earliest_block.map_or("-".into(), |v| v.to_string())
    );
    let fork_matches = status.fork_id_hash == sent_hash && status.fork_next == sent_next;
    println!(
        "            forkId={}:{} — {}; {}",
        hex(&status.fork_id_hash),
        status.fork_next,
        if fork_matches {
            "equals what we sent"
        } else {
            "DIFFERS from what we sent"
        },
        if status.fork_id_hash == genesis_fork_hash(&status.genesis_hash) {
            "hash == CRC32(genesis), i.e. no fork past genesis"
        } else {
            "hash != CRC32(genesis), i.e. the chain has forked past genesis"
        }
    );

    let head = match header_by_hash(&mut session, &status.best_hash, "head").await {
        Ok(head) => head,
        // The handshake gates on network id + genesis only, so a peer that
        // rejects our fork id shows as a session that dies on the first
        // request. Only that: an answer we could not use (a header layout
        // Myotis does not decode, say) is a finding of its own, and a later
        // failure is not about the fork id — neither is worth a reconnect.
        Err(HeaderError::Session(error)) if !fork_matches => {
            return Outcome::ForkIdRejected {
                peer_hash: status.fork_id_hash,
                peer_next: status.fork_next,
                error,
            }
        }
        Err(e) => {
            println!("FAILED  {}", e.into_string());
            return Outcome::Ran { ok: false };
        }
    };
    let core = match core_reads(&mut session, knobs, head).await {
        Ok(core) => core,
        Err(e) => {
            println!("FAILED  {e}");
            return Outcome::Ran { ok: false };
        }
    };
    if !fork_matches {
        println!("NOTE    the peer kept the session although its fork id differs from ours (EIP-2124 allows a compatible mismatch)");
    }
    sweep(&mut session, knobs, core.head_number, started).await;
    Outcome::Ran {
        ok: core.all_verified,
    }
}

fn report_hello(key: &Arc<NodeKey>, hello: &Hello) {
    println!("client      {}", truncate(&hello.client_id, 100));
    println!("caps        [{}]", caps_line(hello));
    // What we offer, read back from the Hello the session sends.
    let our_max = decode_hello(&encode_hello(&key.public_key_bytes(), 0))
        .ok()
        .and_then(|h| {
            h.capabilities
                .iter()
                .filter(|c| c.name == "eth")
                .map(|c| c.version)
                .max()
        })
        .unwrap_or(0);
    let mut above: Vec<u64> = hello
        .capabilities
        .iter()
        .filter(|c| c.name == "eth" && c.version > our_max)
        .map(|c| c.version)
        .collect();
    above.sort_unstable();
    if above.is_empty() {
        println!("            the peer offers no eth version above ours (eth/{our_max})");
    } else {
        println!(
            "            the peer also offers eth {above:?}, above ours (eth/{our_max}) — not spoken here"
        );
    }
}

struct Core {
    /// The peer's head block number, the sweep's reference point.
    head_number: u64,
    all_verified: bool,
}

/// Why a header could not be had — the two cases call for different next steps.
enum HeaderError {
    /// No usable session: a Disconnect, a transport error, no answer in time.
    Session(String),
    /// The peer answered, with something we cannot use.
    Answer(String),
}

impl HeaderError {
    fn into_string(self) -> String {
        match self {
            HeaderError::Session(e) | HeaderError::Answer(e) => e,
        }
    }
}

/// One header by hash, with the checks the session leaves to its caller: the
/// peer answered, and with THE header asked for.
async fn header_by_hash(
    session: &mut EthSession,
    hash: &[u8; 32],
    what: &str,
) -> Result<VerifiedHeader, HeaderError> {
    let headers = session
        .get_block_headers_by_hash(hash, 1)
        .await
        .map_err(|e| {
            // The session's own prefix for a response its decoder refused.
            if e.starts_with("BlockHeaders decode") {
                HeaderError::Answer(format!("{what} header: {e}\n        FINDING: Myotis's BlockHeader decoder does not accept this chain's header layout"))
            } else {
                HeaderError::Session(format!("{what} header: {e}"))
            }
        })?;
    let header = headers.into_iter().next().ok_or_else(|| {
        HeaderError::Answer(format!(
            "{what} header: the peer returned none for 0x{}",
            hex(hash)
        ))
    })?;
    if &header.hash != hash {
        return Err(HeaderError::Answer(format!(
            "{what} header: keccak mismatch — asked 0x{}, got 0x{}",
            hex(hash),
            hex(&header.hash)
        )));
    }
    Ok(header)
}

fn describe_header(what: &str, h: &VerifiedHeader) {
    // The field count places the header's fork without naming it: 15 = pre-
    // London, 16 London, 17 Shanghai, 20 Cancun, 21 Prague; more than 21 is
    // past Prague.
    let fields = rlp::View::new(&h.raw_rlp)
        .and_then(|v| v.as_list())
        .map_or(0, |l| l.count());
    println!(
        "{what:<11} #{} hash=0x{} (keccak-checked)",
        h.header.number,
        hex(&h.hash)
    );
    println!(
        "            stateRoot=0x{} timestamp={} rlpFields={fields}",
        hex(&h.header.state_root),
        h.header.timestamp
    );
}

/// From the head header: the optional anchor header, then account → storage → bytecode
/// at the proving root. `Err` = the header or the account could not be had at
/// all; a storage or bytecode failure is reported and clears `all_verified`.
async fn core_reads(
    session: &mut EthSession,
    knobs: &Knobs,
    head: VerifiedHeader,
) -> Result<Core, String> {
    println!();
    describe_header("head", &head);
    let head_number = head.header.number;

    let (at, label) = match &knobs.anchor {
        Some(hash) => {
            let anchor = header_by_hash(session, hash, "anchor")
                .await
                .map_err(HeaderError::into_string)?;
            describe_header("anchor", &anchor);
            println!(
                "            {} blocks behind the peer's head; proving at the CALLER-SUPPLIED hash",
                head_number.saturating_sub(anchor.header.number)
            );
            (anchor, "caller-supplied anchor")
        }
        None => {
            println!("            UNANCHORED: proving at the peer's own head — says nothing about canonicity");
            (head, "peer's own head, UNANCHORED")
        }
    };
    let root = at.header.state_root;

    if session.snap_version.is_none() {
        return Err("no snap version shared with the peer: no proofs to fetch".into());
    }
    let leaf = match session
        .snap_get_account(&root, &knobs.account)
        .await
        .map_err(|e| format!("account 0x{}: {e}", hex(&knobs.account)))?
    {
        AccountOutcome::Present(leaf) => {
            println!(
                "\naccount     0x{} VERIFIED present at block #{} ({label})",
                hex(&knobs.account),
                at.header.number
            );
            println!(
                "            nonce={} balance=0x{} storageRoot=0x{} codeHash=0x{}",
                leaf.nonce,
                hex(&leaf.balance),
                hex(&leaf.storage_root),
                hex(&leaf.code_hash)
            );
            leaf
        }
        AccountOutcome::Absent => {
            println!(
                "\naccount     0x{} VERIFIED ABSENT at block #{} ({label}) — an exclusion proof; storage and code are not exercised",
                hex(&knobs.account),
                at.header.number
            );
            return Ok(Core {
                head_number,
                all_verified: true,
            });
        }
    };

    let storage_ok = read_storage(session, knobs, &root, &leaf).await;
    let code_ok = read_bytecode(session, &leaf).await;
    Ok(Core {
        head_number,
        all_verified: storage_ok && code_ok,
    })
}

async fn read_storage(
    session: &mut EthSession,
    knobs: &Knobs,
    root: &[u8; 32],
    leaf: &AccountLeaf,
) -> bool {
    if leaf.storage_root == EMPTY_TRIE_ROOT {
        println!("storage     the account has no storage trie: nothing to fetch");
        return true;
    }
    let mut ok = true;
    for slot in &knobs.slots {
        match session
            .snap_get_storage(root, &knobs.account, leaf, slot)
            .await
        {
            Ok(value) if value.is_empty() => {
                println!("storage     slot 0x{} VERIFIED zero / absent", hex(slot))
            }
            Ok(value) => println!(
                "storage     slot 0x{} VERIFIED = 0x{}",
                hex(slot),
                hex(&value)
            ),
            Err(e) => {
                println!("FAILED  storage slot 0x{}: {e}", hex(slot));
                ok = false;
            }
        }
    }
    ok
}

async fn read_bytecode(session: &mut EthSession, leaf: &AccountLeaf) -> bool {
    if leaf.code_hash == EMPTY_CODE_HASH {
        println!("bytecode    the account has no code: nothing to fetch");
        return true;
    }
    match session.snap_get_bytecode(&leaf.code_hash).await {
        Ok(code) => {
            println!(
                "bytecode    VERIFIED against codeHash: {} bytes, starts 0x{}",
                code.len(),
                hex(&code[..code.len().min(16)])
            );
            true
        }
        Err(e) => {
            println!("FAILED  bytecode: {e}");
            false
        }
    }
}

/// How far behind the head does the peer still serve a state root? For each
/// depth: the header by NUMBER (unanchored — whatever the peer calls block n),
/// then the account at its state root. Informational: an L1-committed root
/// lags the L2 head, so the answer bounds how stale an anchor may be.
///
/// Keep the depths ASCENDING: a peer that drops the session at the first root
/// it does not serve ends the sweep there, and a deeper one is moot anyway.
async fn sweep(session: &mut EthSession, knobs: &Knobs, head: u64, started: Instant) {
    if knobs.depths.is_empty() {
        return;
    }
    println!("\n--- snap serving window, depths below head #{head} (the head moves on meanwhile, so each depth is a lower bound) ---");
    for &depth in &knobs.depths {
        let Some(number) = head.checked_sub(depth) else {
            println!(
                "{} depth {depth:>6}  skipped: deeper than the chain",
                age(started)
            );
            continue;
        };
        let header = match session
            .get_block_headers_by_number(number, 1, 0, false)
            .await
        {
            Ok(h) => match h.into_iter().next() {
                Some(h) if h.header.number == number => h,
                Some(h) => {
                    println!(
                        "{} depth {depth:>6}  #{number}: the peer answered with block #{} instead",
                        age(started),
                        h.header.number
                    );
                    continue;
                }
                None => {
                    println!(
                        "{} depth {depth:>6}  #{number}: the peer returned no header",
                        age(started)
                    );
                    continue;
                }
            },
            Err(e) => {
                println!("{} depth {depth:>6}  #{number}: header: {e}", age(started));
                // No answer in time, or one the decoder refused: the session
                // is still there. Anything else took it down.
                if !(e.contains("timed out") || e.contains("decode")) {
                    session_lost(started);
                    return;
                }
                continue;
            }
        };
        match session
            .snap_get_account(&header.header.state_root, &knobs.account)
            .await
        {
            Ok(AccountOutcome::Present(_)) => {
                println!(
                    "{} depth {depth:>6}  #{number}: SERVED (account proof verified)",
                    age(started)
                )
            }
            Ok(AccountOutcome::Absent) => {
                println!(
                    "{} depth {depth:>6}  #{number}: SERVED (absence proof verified)",
                    age(started)
                )
            }
            Err(e) if is_unknown_root_error(&e) => {
                println!("{} depth {depth:>6}  #{number}: NOT served — empty proof, the peer does not hold this root", age(started))
            }
            Err(e) if is_unservable_root_error(&e) => {
                println!(
                    "{} depth {depth:>6}  #{number}: proof did NOT verify: {e}",
                    age(started)
                )
            }
            Err(e) if e.contains("timed out") => {
                println!(
                    "{} depth {depth:>6}  #{number}: no answer ({e})",
                    age(started)
                )
            }
            // `EthSession`'s wording for a Disconnect frame. Observed on the
            // default target (Nethermind): a Disconnect, reason 16, is what a
            // root it does not serve gets — where geth sends an empty proof.
            // Why it does not serve that root is not something this shows.
            Err(e) if e.starts_with("peer disconnected") => {
                println!(
                    "{} depth {depth:>6}  #{number}: NOT served — {e}, in place of an answer",
                    age(started)
                );
                session_lost(started);
                return;
            }
            // The peer answered, undecodably: the session is still there.
            Err(e) if e.contains("decode") => {
                println!(
                    "{} depth {depth:>6}  #{number}: unusable answer: {e}",
                    age(started)
                )
            }
            Err(e) => {
                println!("{} depth {depth:>6}  #{number}: {e}", age(started));
                session_lost(started);
                return;
            }
        }
    }
}

/// A disconnect mid-sweep is ambiguous by itself: the peer may object to the
/// request, or simply be done with a peer that serves nothing — the one-shot
/// `EthSession` never answers the peer's own requests (Nethermind probes a new
/// peer's head). The session's age is what tells the two apart across runs
/// with the depths in a different order.
fn session_lost(started: Instant) {
    println!(
        "{} session lost; the sweep ends here (t = seconds since the RLPx handshake)",
        age(started)
    );
}

fn age(started: Instant) -> String {
    format!("t+{:>4.1}s", started.elapsed().as_secs_f32())
}

/// The fallback when the production handshake fails: a raw Hello, then read
/// the peer's Status WITHOUT sending ours (Nethermind, geth and reth send
/// theirs unprompted), and print what a re-run needs.
async fn diagnose(key: &Arc<NodeKey>, knobs: &Knobs) -> Result<(), String> {
    println!("\n--- diagnostic pass: raw Hello, read the peer's Status, send none ---");
    let mut conn = RlpxConnection::dial(Arc::clone(key), knobs.addr, knobs.pubkey).await?;
    let our_hello = encode_hello(&key.public_key_bytes(), 0);
    conn.send(P2P_HELLO, &our_hello).await?;
    let (code, payload) = recv_frame(&mut conn, 10).await?;
    if code == P2P_DISCONNECT {
        return Err(format!(
            "disconnect at Hello: {} (4 = too many peers, 5 = already connected)",
            disconnect_reason(&payload)
        ));
    }
    if code != P2P_HELLO {
        return Err(format!("expected Hello, got 0x{code:02x}"));
    }
    let hello = decode_hello(&payload)?;
    report_hello(key, &hello);
    let (eth_v, snap_v) = negotiate(&decode_hello(&our_hello)?, &hello);
    println!(
        "negotiated  eth/{} snap/{}",
        eth_v.map_or("- (none shared)".into(), |v| v.to_string()),
        snap_v.map_or("- (none shared)".into(), |v| v.to_string())
    );
    let eth_v = eth_v.ok_or("no common eth version: the peer's Status cannot be read")?;

    let (code, payload) = recv_frame(&mut conn, 10).await?;
    if code == P2P_DISCONNECT {
        return Err(format!(
            "disconnect instead of a Status: {}",
            disconnect_reason(&payload)
        ));
    }
    if code != eth::STATUS {
        return Err(format!("expected Status, got 0x{code:02x}"));
    }
    match eth::decode_status(&payload, eth_v) {
        Ok(s) => {
            println!(
                "peer Status networkId={} genesis=0x{}",
                s.network_id,
                hex(&s.genesis_hash)
            );
            println!(
                "            head=0x{} latest={} earliest={}",
                hex(&s.best_hash),
                s.latest_block.map_or("-".into(), |v| v.to_string()),
                s.earliest_block.map_or("-".into(), |v| v.to_string())
            );
            println!(
                "            forkId={}:{}",
                hex(&s.fork_id_hash),
                s.fork_next
            );
            if s.network_id != knobs.network_id || s.genesis_hash != knobs.genesis {
                println!(
                    "            NOT the chain our Status claims (EEZ_NETWORK_ID / EEZ_GENESIS)"
                );
            }
            println!(
                "re-run with EEZ_FORK_ID={}:{}",
                hex(&s.fork_id_hash),
                s.fork_next
            );
        }
        Err(e) => {
            // Not the eth/66-71 shape Myotis reads: show the fields as sent.
            println!(
                "peer Status does not decode as eth/{eth_v} ({}); raw fields:",
                e.0
            );
            match rlp::View::new(&payload).and_then(|v| v.as_list()) {
                Ok(items) => {
                    for (i, item) in items.enumerate() {
                        let raw = item.raw();
                        println!("            [{i}] 0x{}", hex(&raw[..raw.len().min(80)]));
                    }
                }
                Err(e) => println!("            not an RLP list: {}", e.0),
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct CrawlReport {
    addr: String,
    client: String,
    eth: Option<u64>,
    snap: Option<u64>,
    on_chain: bool,
    serves: bool,
    verdict: String,
}

/// Can more nodes of this chain be found? A discv4 crawl seeded with ONLY the
/// target, handshaking every other node it yields with the same Status and
/// asking each for the account at its own head (unanchored, as above).
async fn crawl(key: &Arc<NodeKey>, knobs: &Knobs) {
    println!(
        "\n--- discv4 crawl from {} alone, {} s ---",
        knobs.addr, knobs.crawl_secs
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TableEntry>(1024);
    let discovery = match Discv4Service::start(
        Arc::clone(key),
        Discv4Config {
            bind_port: 0,
            bootnodes: vec![knobs.addr],
            ..Default::default()
        },
        tx,
    )
    .await
    {
        Ok(d) => d,
        Err(e) => {
            println!("crawl skipped: discv4 start: {e}");
            return;
        }
    };

    let reports: Arc<Mutex<Vec<CrawlReport>>> = Arc::default();
    let sem = Arc::new(Semaphore::new(16));
    let mut tried: HashSet<SocketAddr> = HashSet::from([knobs.addr]);
    let mut handles = Vec::new();
    let mut entries = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(knobs.crawl_secs);
    while tokio::time::Instant::now() < deadline {
        let entry = match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                println!("discv4 channel closed; ending the crawl early");
                break;
            }
            Err(_) => continue,
        };
        entries += 1;
        if entry.node_id.len() != 64
            || entry.ip.len() != 4
            || entry.tcp_port == 0
            || entry.tcp_port > 65535
            || entry.node_id == knobs.pubkey
        {
            continue;
        }
        let ip = std::net::Ipv4Addr::new(entry.ip[0], entry.ip[1], entry.ip[2], entry.ip[3]);
        let addr = SocketAddr::from((ip, entry.tcp_port as u16));
        if !tried.insert(addr) {
            continue;
        }
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&entry.node_id);
        let (key, knobs, reports, sem) = (
            Arc::clone(key),
            knobs.clone(),
            Arc::clone(&reports),
            Arc::clone(&sem),
        );
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let mut r = CrawlReport {
                addr: addr.to_string(),
                ..Default::default()
            };
            let run = crawl_peer(&key, &knobs, addr, pubkey, &mut r);
            match tokio::time::timeout(Duration::from_secs(45), run).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => r.verdict = e,
                Err(_) => r.verdict = "timeout".into(),
            }
            reports.lock().await.push(r);
        }));
    }
    discovery.stop().await;
    for h in handles {
        let _ = h.await;
    }

    let reports = reports.lock().await;
    let on_chain = reports.iter().filter(|r| r.on_chain).count();
    let offer = reports
        .iter()
        .filter(|r| r.on_chain && r.snap.is_some())
        .count();
    let serve = reports.iter().filter(|r| r.serves).count();
    println!(
        "discv4 entries: {entries}; other nodes dialled: {}; on networkId {}: {on_chain}; of those sharing a snap version: {offer}, serving a verified proof: {serve}",
        reports.len(),
        knobs.network_id
    );
    // Peers of this chain in full; the rest (other chains, dead addresses) as
    // a histogram — a public discv4 table is mostly those.
    for r in reports.iter().filter(|r| r.on_chain) {
        println!(
            "  {:<22} eth/{:<3} snap/{:<3} {:<40} -> {}",
            r.addr,
            r.eth.map_or("-".into(), |v| v.to_string()),
            r.snap.map_or("-".into(), |v| v.to_string()),
            truncate(&r.client, 40),
            truncate(&r.verdict, 160)
        );
    }
    let mut others: BTreeMap<String, usize> = BTreeMap::new();
    for r in reports.iter().filter(|r| !r.on_chain) {
        *others.entry(truncate(&r.verdict, 60)).or_default() += 1;
    }
    if !others.is_empty() {
        println!("not on this chain, by verdict (first 60 chars):");
        for (verdict, count) in &others {
            println!("  {count:>4}  {verdict}");
        }
    }
}

async fn crawl_peer(
    key: &Arc<NodeKey>,
    knobs: &Knobs,
    addr: SocketAddr,
    pubkey: [u8; 64],
    r: &mut CrawlReport,
) -> Result<(), String> {
    let conn = RlpxConnection::dial(Arc::clone(key), addr, pubkey)
        .await
        .map_err(|e| format!("dial: {e}"))?;
    // The handshake's own gate: an Ok session IS a peer of this network id and
    // genesis; any other chain fails here as "incompatible peer".
    let mut session =
        EthSession::handshake(conn, &key.public_key_bytes(), &knobs.eth_config(), None).await?;
    r.on_chain = true;
    r.client = session.peer_hello.client_id.clone();
    r.eth = Some(session.eth_version);
    r.snap = session.snap_version;
    if session.snap_version.is_none() {
        r.verdict = "on chain, no snap version shared".into();
        return Ok(());
    }
    let head_hash = session.peer_status.best_hash;
    let head = header_by_hash(&mut session, &head_hash, "head")
        .await
        .map_err(HeaderError::into_string)?;
    r.verdict = match session
        .snap_get_account(&head.header.state_root, &knobs.account)
        .await
    {
        Ok(_) => {
            r.serves = true;
            format!("SERVES snap at its head #{}", head.header.number)
        }
        Err(e) => format!("snap at its head #{}: {e}", head.header.number),
    };
    Ok(())
}
