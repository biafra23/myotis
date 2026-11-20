//! On-chain recovery of node-owned state from the node EOA (PLAN.md
//! "node-owned on-chain state recovery").
//!
//! Two discoveries, both driven purely by the node's public Ethereum
//! address (the `swarm.key` EOA) over JSON-RPC, so a node started on a
//! data dir carried over from bee — same key, no sidecar registry —
//! comes back up with its existing on-chain state intact:
//!
//! 1. [`owned_batches_in`] — the postage batches this EOA owns
//!    and that are still funded, so they can be re-registered as usable
//!    stamp issuers.
//! 2. [`owned_chequebook_in`] — the SWAP chequebook this EOA
//!    deployed, so the node adopts it instead of deploying a fresh one
//!    (stranding the old balance).
//!
//! Both read a single cheap scan, [`refresh_transfer_scan`]: the ERC-20
//! `Transfer` event on the xBZZ token, filtered by the indexed `from`
//! topic = node EOA. That filter returns only the node's own outgoing
//! transfers (a tiny set), and every funded chequebook / bought batch
//! was paid for by an ERC-20 transfer *from* the node EOA, so the target
//! addresses are all in the `to` field of that set. The scan is saved in
//! the data dir and continued on the next start, so only the first start
//! reads the history from the xBZZ deploy block.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::json;

use crate::chequebook::{chequebook_issuer_selector, factory_deployed_contracts_calldata};
use crate::tx::batch_created_event_topic;
use crate::{ChainClient, RpcError};

/// `keccak256("Transfer(address,address,uint256)")` — topic[0] of the
/// ERC-20 `Transfer(address indexed from, address indexed to, uint256
/// value)` event. Pinned as a literal (a keccak round-trip test guards
/// it) so the scan filter can't silently drift.
pub const ERC20_TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// xBZZ token deploy block on Gnosis — the lower bound for the log
/// scan (no node transfer predates the token). Bee's hardcoded mainnet
/// constant.
pub const GNOSIS_XBZZ_DEPLOY_BLOCK: u64 = 16_514_506;

/// Initial scan window. Capable RPCs (e.g. `rpc.gnosischain.com`)
/// answer the full token-to-head range in one call because the indexed
/// `from` filter matches almost nothing; range-capped RPCs cause the
/// scanner to shrink the window adaptively.
const INITIAL_SCAN_CHUNK: u64 = 50_000_000;

/// One decoded `eth_getLogs` entry. Richer than [`crate::tx::EventLog`]
/// (which is receipt-shaped): the scan needs the originating tx hash
/// (to match a `Transfer` against the `BatchCreated` logs mined in the
/// same block) and block number (to aim that per-block query, and to
/// prefer the most-recent chequebook on a tie).
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
    pub tx_hash: [u8; 32],
    pub block_number: u64,
}

/// A postage batch the node EOA owns on-chain and that is still funded.
#[derive(Debug, Clone)]
pub struct DiscoveredBatch {
    pub batch_id: [u8; 32],
    pub depth: u8,
    pub bucket_depth: u8,
    pub immutable: bool,
    /// `PostageStamp.remainingBalance(batchId)` — the per-chunk balance
    /// left (normalised minus outpayment). `> 0` means unexpired.
    pub remaining_balance: u128,
}

/// Blocks below the chain head that a scan doesn't yet count as scanned.
/// Transfers in this tail are used, but the next scan reads the tail
/// again, so neither of these leaves a permanent hole in the saved scan:
///
/// - a reorg (Gnosis finalises within ~64 blocks);
/// - a load-balanced RPC whose `eth_blockNumber` and `eth_getLogs` land
///   on different backends, the second one behind: it answers `[]` for
///   blocks it hasn't seen yet rather than an error, so an empty window
///   near the head can't be told from a real "no transfers".
///
/// 1 024 blocks is about 85 minutes on Gnosis — a backend further behind
/// than that is broken, not lagging — and still one `eth_getLogs` window
/// on the 10k/50k-capped public RPCs. A miss below it is what
/// [`rescan_transfer_history`] is for.
const RESCAN_TAIL: u64 = 1_024;

/// Version of the persisted [`TransferScan`] file. Version 1 wasn't keyed
/// by chain; its files are ignored (a full scan, once).
const TRANSFER_SCAN_VERSION: u32 = 2;

/// With an unverified source to fall back on
/// ([`ChainClient::with_unverified_logs`]), the verified route reads a span
/// in at most about this many windows. A wider one — a first scan behind
/// a 10k-block cap is ~3,200 windows, about an hour of quorum rounds — is
/// read from the unverified source instead and confirmed later in at most
/// this many verified windows per try ([`confirm_transfer_scan`]) — one
/// request once the verified route has a second full-history source. 64
/// windows of 10k blocks cover about five weeks offline. While the
/// unverified source fails, a pass reads this many verified windows (about
/// a minute of quorum rounds) between tries of it.
const MAX_VERIFIED_WINDOWS: u64 = 64;

/// How long blocks read only from the unverified source wait for a
/// one-request confirmation before [`find_owned_chequebook`]'s "none" may
/// be confirmed window by window instead: a deploy decision must not wait
/// forever on a second source that stays down. An embedder that confirms
/// in the background gives its settlement another go once this has passed.
pub const CONFIRM_CRAWL_AFTER_SECS: u64 = 6 * 60 * 60;

/// How often a running scan saves its progress, so a first scan cut
/// short (the app quit, the RPC failed) resumes where it stopped.
const SCAN_SAVE_EVERY: std::time::Duration = std::time::Duration::from_secs(15);

/// One xBZZ `Transfer` out of the node wallet: what batch and chequebook
/// rediscovery read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeTransfer {
    /// The recipient: the `PostageStamp` contract for a batch buy or
    /// top-up, a chequebook for a deposit.
    pub to: [u8; 20],
    pub block: u64,
    pub tx_hash: [u8; 32],
}

/// The node wallet's xBZZ `Transfer(from = node)` history, scanned up to
/// a block. Batch and chequebook rediscovery both read it
/// ([`owned_batches_in`], [`owned_chequebook_in`]) instead of each
/// scanning the chain from the xBZZ deploy block, and
/// [`refresh_transfer_scan`] keeps it on disk so a later start only reads
/// the blocks since. A wallet with history behind a range-capped RPC
/// otherwise paid tens of minutes per start for two identical
/// full-history scans (issue #118).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferScan {
    /// The chain scanned (`eth_chainId`); a scan is only ever continued
    /// against the same chain.
    pub chain_id: u64,
    pub node_eoa: [u8; 20],
    /// Every block from the scan start up to and including this one has
    /// been scanned. Transfers above it are in the reorg tail: used, but
    /// read again next time.
    pub scanned_through: u64,
    pub transfers: Vec<NodeTransfer>,
    /// Every block up to this one was read by a *confirming* pass: one
    /// scan from the xBZZ deploy block (a first scan, or
    /// [`rescan_transfer_history`]), then [`find_owned_chequebook`]'s
    /// re-reads of the blocks since. The mark advances window by window
    /// as such a pass reads, and is saved with the scan's progress —
    /// including when the pass fails or is cut short part-way — so
    /// `Some(x)` means "every block up to `x` was read by some confirming
    /// pass", not that a confirming pass ever ran to the head. `None` only
    /// until a confirming pass has read its first window. The blocks above
    /// it were only read by routine continued scans, whose "none" rests
    /// on every earlier answer, so before a "none" may lead to a deploy,
    /// [`find_owned_chequebook`] reads those blocks again — and only
    /// those, so a wallet whose deploy keeps failing pays the full
    /// history once, not on every check.
    pub confirmed_through: Option<u64>,
    /// When some blocks above [`Self::confirmed_through`] were first read
    /// only from the unverified source (unix seconds), until a verified
    /// read confirms them. The transfers found there are used — each batch
    /// and chequebook is still checked through the verified route — but
    /// a "none" they back never leads to a deploy, and
    /// `/health.walletScan` reads `confirming` meanwhile.
    pub provisional_since: Option<u64>,
    /// While [`Self::provisional_since`] is set: the last block read from
    /// the unverified source. A confirmation re-reads the blocks above
    /// [`Self::confirmed_through`] up to here, and those above
    /// [`Self::confirmed_above`] — not the ones in between.
    pub provisional_through: Option<u64>,
    /// While [`Self::provisional_since`] is set: every block in
    /// `(provisional_through, confirmed_above]` was read through the
    /// verified route by a confirming pass — a first scan whose unverified
    /// source failed part-way and that read on window by window. A
    /// confirmation keeps those blocks rather than reading them again.
    pub confirmed_above: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransferScanFile {
    version: u32,
    chain_id: u64,
    node_eoa: String,
    scanned_through: u64,
    transfers: Vec<TransferRecord>,
    /// [`TransferScan::confirmed_through`]. Absent in files written before
    /// it existed: the next confirming check then reads the full history.
    #[serde(default)]
    confirmed_through: Option<u64>,
    /// [`TransferScan::provisional_since`].
    #[serde(default)]
    provisional_since: Option<u64>,
    /// [`TransferScan::provisional_through`].
    #[serde(default)]
    provisional_through: Option<u64>,
    /// [`TransferScan::confirmed_above`].
    #[serde(default)]
    confirmed_above: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransferRecord {
    to: String,
    block: u64,
    tx_hash: String,
}

fn transfer_scan_path(
    data_dir: &std::path::Path,
    chain_id: u64,
    node_eoa: &[u8; 20],
) -> std::path::PathBuf {
    data_dir.join(format!(
        "transfer-scan-{chain_id}-0x{}.json",
        hex::encode(node_eoa)
    ))
}

/// The scan persisted for `node_eoa` on `chain_id` in `data_dir`, or
/// `None` when there is none, it's unreadable, or it belongs to another
/// wallet or chain: the caller then scans from the start.
fn load_transfer_scan(
    data_dir: &std::path::Path,
    chain_id: u64,
    node_eoa: &[u8; 20],
) -> Option<TransferScan> {
    let path = transfer_scan_path(data_dir, chain_id, node_eoa);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(target: "ant_chain", path = %path.display(), "unreadable transfer scan, rescanning: {e}");
            return None;
        }
    };
    let parsed = serde_json::from_slice::<TransferScanFile>(&bytes)
        .ok()
        .filter(|f| f.version == TRANSFER_SCAN_VERSION)
        .and_then(|f| {
            let eoa = parse_addr(&f.node_eoa)?;
            let transfers = f
                .transfers
                .iter()
                .map(|t| {
                    let mut tx_hash = [0u8; 32];
                    hex::decode_to_slice(t.tx_hash.trim_start_matches("0x"), &mut tx_hash).ok()?;
                    Some(NodeTransfer {
                        to: parse_addr(&t.to)?,
                        block: t.block,
                        tx_hash,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            let provisional_through = f
                .provisional_through
                .filter(|&p| f.provisional_since.is_some() && p <= f.scanned_through);
            Some(TransferScan {
                chain_id: f.chain_id,
                node_eoa: eoa,
                scanned_through: f.scanned_through,
                transfers,
                confirmed_through: f.confirmed_through.filter(|&c| c <= f.scanned_through),
                provisional_since: f.provisional_since,
                provisional_through,
                confirmed_above: f.confirmed_above.filter(|&a| {
                    provisional_through.is_some_and(|p| p < a) && a <= f.scanned_through
                }),
            })
        });
    match parsed {
        Some(scan) if scan.node_eoa == *node_eoa && scan.chain_id == chain_id => Some(scan),
        Some(_) => None,
        None => {
            tracing::warn!(target: "ant_chain", path = %path.display(), "malformed transfer scan, rescanning");
            None
        }
    }
}

/// Write `scan` atomically (temp file, then rename). A failure only means
/// the next start scans again, so it's logged rather than returned.
fn persist_transfer_scan(data_dir: &std::path::Path, scan: &TransferScan) {
    let file = TransferScanFile {
        version: TRANSFER_SCAN_VERSION,
        chain_id: scan.chain_id,
        node_eoa: format!("0x{}", hex::encode(scan.node_eoa)),
        scanned_through: scan.scanned_through,
        confirmed_through: scan.confirmed_through,
        provisional_since: scan.provisional_since,
        provisional_through: scan.provisional_through,
        confirmed_above: scan.confirmed_above,
        transfers: scan
            .transfers
            .iter()
            .map(|t| TransferRecord {
                to: format!("0x{}", hex::encode(t.to)),
                block: t.block,
                tx_hash: format!("0x{}", hex::encode(t.tx_hash)),
            })
            .collect(),
    };
    // A temp file per write: a stamp buy's chequebook check and the
    // startup batch rediscovery can save at the same time, and must not
    // rename each other's half-written file into place.
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = transfer_scan_path(data_dir, scan.chain_id, &scan.node_eoa);
    let tmp = path.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let written = serde_json::to_vec_pretty(&file)
        .map_err(std::io::Error::other)
        .and_then(|json| std::fs::write(&tmp, json))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(target: "ant_chain", path = %path.display(), "could not save the transfer scan; the next start rescans: {e}");
    }
}

/// Where a wallet's rediscovery stands, for `/health.walletScan`: an
/// embedder that rediscovers in the background reports it, so a host
/// can show "looking for your existing storage" instead of offering a
/// plan the wallet may already have.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletScanStatus {
    pub state: WalletScanState,
    /// The block this run of the transfer scan started or resumed from.
    pub from: Option<u64>,
    /// Scanned up to and including this block; `None` until the first
    /// window is read.
    pub scanned_through: Option<u64>,
    /// The chain head this run scans up to.
    pub head: Option<u64>,
    /// Why the last attempt failed. Only in [`WalletScanState::Retrying`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Some blocks were read only from the unverified source and aren't
    /// confirmed yet: the rediscovery ends in
    /// [`WalletScanState::Confirming`] rather than `Done`.
    #[serde(skip)]
    pub provisional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletScanState {
    /// A rediscovery will run but hasn't started reading the chain.
    Pending,
    /// Reading the wallet's history.
    Scanning,
    /// The last attempt failed; the embedder retries in the background.
    Retrying,
    /// The scan is up to date and the batches it found are registered.
    /// Later scans (a stamp buy's chequebook check) don't leave it.
    Done,
    /// As `Done`, but part of the history was read only from an
    /// unverified source: what it found is registered (each batch checked
    /// through the verified route), and the embedder confirms in the
    /// background that nothing is missing ([`confirm_transfer_scan`]),
    /// then moves to `Done`. A host shows the normal state here; it may
    /// note that the check is still running.
    Confirming,
}

impl WalletScanState {
    /// The rediscovery finished (confirmed or not): later scans don't
    /// move it back to scanning or retrying.
    fn finished(self) -> bool {
        matches!(self, Self::Done | Self::Confirming)
    }
}

/// The rediscovery status per wallet, for this process. Keyed by the
/// node's address (what `/health` looks up), which isn't always the
/// wallet the rediscovery scans: antd's legacy `--postage-owner-key`
/// scans that key's address, and reports under the node's.
static WALLET_SCANS: std::sync::Mutex<BTreeMap<[u8; 20], WalletScanStatus>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Change `node_eoa`'s status, if a rediscovery is tracked for it.
fn update_wallet_scan(node_eoa: &[u8; 20], change: impl FnOnce(&mut WalletScanStatus)) {
    let mut scans = WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(status) = scans.get_mut(node_eoa) {
        change(status);
    }
}

/// A rediscovery for `node_eoa` is about to run. Call it before the
/// gateway reports `chainReady`, so a host never sees the chain ready
/// with no scan reported and briefly offers storage plans. A
/// rediscovery already running (or retrying) is left as it is.
pub fn wallet_scan_pending(node_eoa: &[u8; 20]) {
    let mut scans = WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tracked = scans.get(node_eoa).map(|s| s.state);
    if matches!(tracked, None | Some(WalletScanState::Done)) {
        scans.insert(
            *node_eoa,
            WalletScanStatus {
                state: WalletScanState::Pending,
                from: None,
                scanned_through: None,
                head: None,
                error: None,
                provisional: false,
            },
        );
    }
}

/// Start tracking `node_eoa` in `state` if nothing is tracked for it;
/// a tracked status is left alone. For an embedder re-announcing a
/// rediscovery whose earlier status it dropped ([`wallet_scan_abandon`]).
pub fn wallet_scan_track(node_eoa: &[u8; 20], state: WalletScanState) {
    WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(*node_eoa)
        .or_insert(WalletScanStatus {
            state,
            from: None,
            scanned_through: None,
            head: None,
            error: None,
            provisional: state == WalletScanState::Confirming,
        });
}

/// The embedder stopped rediscovering for `node_eoa` in the background
/// (its gateway stopped, ending the retry loop): drop an unfinished
/// status, so a later start without a logs RPC reports none instead of
/// a `retrying` nothing will retry. A finished one (`done`, or
/// `confirming`: the batches are registered, and the history read from
/// the unverified source is still unconfirmed) stays — it's still true.
/// Updates from an attempt still in flight are then ignored until the
/// status is tracked again.
pub fn wallet_scan_abandon(node_eoa: &[u8; 20]) {
    let mut scans = WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if scans.get(node_eoa).is_some_and(|s| !s.state.finished()) {
        scans.remove(node_eoa);
    }
}

/// The rediscovery for `node_eoa` finished: its batches are registered.
/// `Done`, or `Confirming` while part of the history was read only from
/// the unverified source.
pub fn wallet_scan_done(node_eoa: &[u8; 20]) {
    update_wallet_scan(node_eoa, |s| {
        s.state = if s.provisional {
            WalletScanState::Confirming
        } else {
            WalletScanState::Done
        };
        s.error = None;
    });
}

/// The rediscovery for `node_eoa` failed and will be retried after
/// [`rediscovery_retry_delay`].
pub fn wallet_scan_failed(node_eoa: &[u8; 20], error: &str) {
    update_wallet_scan(node_eoa, |s| {
        if !s.state.finished() {
            s.state = WalletScanState::Retrying;
            s.error = Some(without_urls(error));
        }
    });
}

/// `error` with every URL replaced by `<url>`. RPC URLs often carry an
/// API key, and `/health` is readable by any origin the CORS list
/// allows; the logs keep the full text.
fn without_urls(error: &str) -> String {
    error
        .split(' ')
        .map(|word| match word.find("://") {
            Some(scheme_end) => {
                let start = word[..scheme_end]
                    .rfind(|c: char| !c.is_ascii_alphanumeric())
                    .map_or(0, |i| i + 1);
                let end = word
                    .rfind(|c: char| !matches!(c, ')' | ']' | ',' | '.' | ';' | '"' | '\''))
                    .map_or(word.len(), |i| i + 1)
                    .max(scheme_end + 3);
                format!("{}<url>{}", &word[..start], &word[end..])
            }
            None => word.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Stop tracking `node_eoa`'s rediscovery: an embedder whose node for it
/// shut down (ant-ffi's `ant_shutdown`) calls this, so a later node for
/// the same account doesn't serve the old one's `scanning`/`retrying`.
pub fn wallet_scan_forget(node_eoa: &[u8; 20]) {
    WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(node_eoa);
}

/// `node_eoa`'s rediscovery status, or `None` when this process doesn't
/// rediscover for it in the background.
#[must_use]
pub fn wallet_scan_status(node_eoa: &[u8; 20]) -> Option<WalletScanStatus> {
    WALLET_SCANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(node_eoa)
        .cloned()
}

/// How long to wait before retrying a failed rediscovery: 15 s,
/// doubling, at most 5 minutes. A failed scan keeps its progress, so a
/// retry only reads what's left.
#[must_use]
pub fn rediscovery_retry_delay(attempt: u32) -> std::time::Duration {
    const FIRST: u64 = 15;
    const MAX: u64 = 300;
    std::time::Duration::from_secs(FIRST.saturating_mul(1u64 << attempt.min(10)).min(MAX))
}

/// What [`scan_transfers`] does with a span the verified route can't
/// serve in [`MAX_VERIFIED_WINDOWS`] windows.
#[derive(Clone, Copy)]
enum Fallback<'a> {
    /// Read it window by window, however many windows it takes.
    Crawl,
    /// Read it from this unverified source; the blocks stay unconfirmed
    /// ([`TransferScan::provisional_since`], set by the first window it
    /// serves). While it fails, read on window by window through the
    /// verified route, as [`Fallback::Crawl`], trying it again every
    /// [`MAX_VERIFIED_WINDOWS`] windows.
    Unverified(&'a ChainClient),
    /// Stop with [`ScanStop::TooWide`]: the span can't be confirmed yet.
    GiveUp,
}

/// Why [`scan_transfers`] stopped short.
#[derive(Debug)]
enum ScanStop {
    Rpc(RpcError),
    /// The verified route can't serve the span in a few windows, and the
    /// pass may neither crawl nor read it unverified.
    TooWide,
}

impl From<RpcError> for ScanStop {
    fn from(e: RpcError) -> Self {
        Self::Rpc(e)
    }
}

impl ScanStop {
    fn into_rpc(self) -> RpcError {
        match self {
            Self::Rpc(e) => e,
            Self::TooWide => RpcError::Rpc(
                "the verified log source can't confirm the wallet's history yet".into(),
            ),
        }
    }
}

/// A confirming pass's progress `scan` (read verified from the confirmed
/// mark up to its `scanned_through`), saved over the provisional scan it
/// `rewound`: the blocks up to where the pass got are confirmed, with the
/// transfers it found there; above that, the rewound scan's transfers,
/// progress and provisional marks are kept — the unverified stretch and
/// the degraded crawl's verified one ([`TransferScan::confirmed_above`])
/// only while the pass hasn't reached past the unverified blocks.
fn confirm_progress(rewound: &TransferScan, scan: &TransferScan) -> TransferScan {
    let mut partial = scan.clone();
    partial.provisional_since = rewound.provisional_since;
    let got_to = scan.scanned_through;
    if got_to < rewound.scanned_through {
        partial.transfers.extend(
            rewound
                .transfers
                .iter()
                .filter(|t| t.block > got_to)
                .copied(),
        );
        partial.scanned_through = rewound.scanned_through;
        if rewound.provisional_through.is_some_and(|p| p > got_to) {
            partial.provisional_through = rewound.provisional_through;
            partial.confirmed_above = rewound.confirmed_above;
        }
    }
    partial
}

/// Blocks a confirmation doesn't read again: `(after, through]` was read
/// through the verified route by a confirming pass
/// ([`TransferScan::confirmed_above`]), with these transfers in it.
struct Reuse {
    after: u64,
    through: u64,
    transfers: Vec<NodeTransfer>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Scan the node wallet's xBZZ transfers from `from_block` to the head,
/// continuing `previous` (same wallet) from where it stopped instead of
/// starting over. Its transfers in the rescan tail are dropped and read
/// again. With `save_to`, the progress is saved there every
/// [`SCAN_SAVE_EVERY`] while the scan runs, and when it fails. With
/// `confirms` — a pass that reads from the deploy block, or re-reads the
/// blocks above the confirmed mark — every block it reads through the
/// verified route is confirmed: the saved progress carries
/// [`TransferScan::confirmed_through`] up to where it got, so a confirming
/// pass cut short and resumed (a first scan interrupted by the app going
/// to the background) only leaves the blocks the resumed part read
/// unconfirmed, not the whole history. Blocks read from the `fallback`'s
/// unverified source are never confirmed.
///
/// `rewound` is the saved, provisional scan a confirming pass rewound to
/// its confirmed mark: until the pass completes, its progress is saved
/// over that scan rather than in place of it ([`confirm_progress`]) — the
/// confirmed mark moves up to what the pass read, and the blocks above it
/// keep what the rewound scan had read there, with its
/// [`TransferScan::provisional_since`] clock and the
/// [`TransferScan::provisional_through`]/[`TransferScan::confirmed_above`]
/// stretch the pass didn't get to. A confirmation cut short part-way thus
/// keeps the original clock (no new [`CONFIRM_CRAWL_AFTER_SECS`] wait),
/// the next continued scan goes on from where the rewound scan stood
/// instead of reading the rest from the unverified source again, and the
/// next try still skips the degraded crawl's verified stretch.
///
/// `reuse` (a confirming re-read only) is a stretch above the scan's
/// confirmed mark that is already confirmed: it is taken as read, not read
/// again, and doesn't count against the window budget.
///
/// With `report`, the scan's progress and failure are reported as the
/// rediscovery status under that key (see [`rediscovery_scan`]); other
/// scans (a stamp buy's chequebook check) leave the status alone. A
/// failed scan hands back what it read ([`ScanFailed::progress`]).
#[allow(clippy::too_many_arguments)]
async fn scan_transfers(
    client: &ChainClient,
    chain_id: u64,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    from_block: u64,
    previous: Option<TransferScan>,
    save_to: Option<&std::path::Path>,
    confirms: bool,
    fallback: Fallback<'_>,
    rewound: Option<&TransferScan>,
    reuse: Option<Reuse>,
    report: Option<&[u8; 20]>,
) -> Result<TransferScan, ScanFailed> {
    // Progress of an unfinished pass, saved over the provisional scan it
    // rewound (see above).
    let save = |dir: &std::path::Path, scan: &TransferScan| match rewound {
        Some(rewound) if scan.provisional_since.is_none() => {
            persist_transfer_scan(dir, &confirm_progress(rewound, scan));
        }
        _ => persist_transfer_scan(dir, scan),
    };
    let head = match client.eth_block_number().await {
        Ok(head) => head,
        Err(error) => {
            return Err(ScanFailed {
                stop: ScanStop::Rpc(error),
                progress: previous.map(Box::new),
            })
        }
    };
    let report_status = |change: &dyn Fn(&mut WalletScanStatus)| {
        if let Some(key) = report {
            update_wallet_scan(key, change);
        }
    };
    let mut scan = match previous.filter(|p| {
        p.node_eoa == *node_eoa
            && p.chain_id == chain_id
            && p.scanned_through.saturating_add(1) >= from_block
    }) {
        Some(mut p) => {
            let through = p.scanned_through;
            p.transfers.retain(|t| t.block <= through);
            p
        }
        None => TransferScan {
            chain_id,
            node_eoa: *node_eoa,
            scanned_through: from_block.saturating_sub(1),
            transfers: Vec::new(),
            confirmed_through: None,
            provisional_since: None,
            provisional_through: None,
            confirmed_above: None,
        },
    };
    let start = scan.scanned_through.saturating_add(1);
    // Blocks up to here count as scanned once read; the tail above is
    // read again next time.
    let settled = head.saturating_sub(RESCAN_TAIL);
    report_status(&|s| {
        if !s.state.finished() {
            *s = WalletScanStatus {
                state: WalletScanState::Scanning,
                from: Some(start),
                scanned_through: None,
                head: Some(head),
                error: None,
                provisional: s.provisional,
            };
        }
    });
    if start > head {
        return Ok(scan);
    }
    let topics = json!([
        format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC)),
        topic_for_address(node_eoa),
    ]);
    let mut saved_at = std::time::Instant::now();
    let mut take = |scan: &mut TransferScan, end: u64, logs: Vec<LogEntry>, verified: bool| {
        for log in logs {
            if log.topics.len() >= 3 {
                scan.transfers.push(NodeTransfer {
                    to: address_from_topic(&log.topics[2]),
                    block: log.block_number,
                    tx_hash: log.tx_hash,
                });
            }
        }
        // Never backwards: a scan within the tail of the previous one
        // leaves its mark where it was.
        scan.scanned_through = scan.scanned_through.max(end.min(settled));
        if confirms && verified {
            if scan.provisional_since.is_none() {
                scan.confirmed_through = Some(scan.scanned_through);
            } else if scan.provisional_through.is_some() {
                // Above blocks this pass read unverified: confirmed, but
                // not contiguously with the mark. Kept apart so a
                // confirmation doesn't read them again.
                scan.confirmed_above = Some(scan.scanned_through);
            }
        }
        if !verified {
            // Stamped by the first window the unverified source actually
            // served, not when the pass turns to it: a read that fails
            // before serving one leaves the scan as verified as it was.
            if scan.provisional_since.is_none() {
                scan.provisional_since = Some(unix_now());
                report_status(&|s| s.provisional = true);
            }
            scan.provisional_through = Some(scan.scanned_through);
            scan.confirmed_above = None;
        }
        // `pending` here is a status a gateway stop dropped and a restart
        // re-tracked while this attempt kept running (ant-ffi's
        // `note_pending`): it is scanning, so say so.
        report_status(&|s| {
            if matches!(
                s.state,
                WalletScanState::Pending | WalletScanState::Scanning
            ) {
                *s = WalletScanStatus {
                    state: WalletScanState::Scanning,
                    from: Some(start),
                    scanned_through: Some(scan.scanned_through),
                    head: Some(head),
                    error: None,
                    provisional: s.provisional,
                };
            }
        });
        if let Some(dir) = save_to {
            if saved_at.elapsed() >= SCAN_SAVE_EVERY {
                save(dir, scan);
                saved_at = std::time::Instant::now();
            }
        }
    };
    // A pass that may fall back reads at most MAX_VERIFIED_WINDOWS windows
    // through the verified route: windows narrower than the span allows
    // stop it at the first refusal, and the window count bounds a route
    // that serves narrow windows without refusing wider ones.
    // A stretch to reuse must sit inside the span; the budget is for the
    // blocks actually read.
    let reuse = reuse.filter(|r| r.after.saturating_add(1) >= start && r.through < head);
    let span = (head - start + 1) - reuse.as_ref().map_or(0, |r| r.through - r.after);
    let (min_window, max_windows) = match fallback {
        Fallback::Crawl => (1, u64::MAX),
        Fallback::Unverified(_) | Fallback::GiveUp => (
            span.div_ceil(MAX_VERIFIED_WINDOWS).max(1),
            MAX_VERIFIED_WINDOWS,
        ),
    };
    let read_to = reuse.as_ref().map_or(head, |r| r.after);
    let mut windows = 0u64;
    let mut verified = if start <= read_to {
        client
            .scan_logs_with(
                xbzz_token,
                &topics,
                start,
                read_to,
                min_window,
                max_windows,
                |end, logs| {
                    windows += 1;
                    take(&mut scan, end, logs, true);
                },
            )
            .await
    } else {
        Ok(None)
    };
    if let (Ok(None), Some(r)) = (&verified, reuse) {
        // Up to the stretch: take it as read, then read on above it.
        scan.transfers.extend(r.transfers);
        take(&mut scan, r.through, Vec::new(), true);
        verified = client
            .scan_logs_with(
                xbzz_token,
                &topics,
                r.through + 1,
                head,
                min_window,
                max_windows.saturating_sub(windows),
                |end, logs| {
                    take(&mut scan, end, logs, true);
                },
            )
            .await;
    }
    let read = match verified {
        Ok(None) => Ok(()),
        Ok(Some(rest)) => match fallback {
            Fallback::Unverified(unverified) => {
                tracing::info!(
                    target: "ant_chain",
                    from_block = rest,
                    to_block = head,
                    "the verified log source can't serve this span in a few windows; reading it \
                     from the unverified source, to be confirmed later",
                );
                // The unverified source is a shortcut, not a dependency:
                // while it fails, read on through the verified route,
                // window by window as without one, rather than failing
                // every pass and leaving a first or long-offline scan stuck
                // for as long as it stays down — but only a stretch at a
                // time, then try it again, so one transient error (a 429)
                // costs about a minute of verified windows, not the rest
                // of the hour-long crawl.
                let mut next = rest;
                loop {
                    let unverified_read = unverified
                        .scan_logs_with(
                            xbzz_token,
                            &topics,
                            next,
                            head,
                            1,
                            u64::MAX,
                            |end, logs| {
                                next = end.saturating_add(1);
                                take(&mut scan, end, logs, false);
                            },
                        )
                        .await;
                    let Err(e) = unverified_read else {
                        break Ok(());
                    };
                    tracing::warn!(
                        target: "ant_chain",
                        from_block = next,
                        to_block = head,
                        error = %without_urls(&e.to_string()),
                        "the unverified log source failed; reading on window by window through \
                         the verified route, trying it again every {MAX_VERIFIED_WINDOWS} windows",
                    );
                    let crawled = client
                        .scan_logs_with(
                            xbzz_token,
                            &topics,
                            next,
                            head,
                            1,
                            MAX_VERIFIED_WINDOWS,
                            |end, logs| {
                                next = end.saturating_add(1);
                                take(&mut scan, end, logs, true);
                            },
                        )
                        .await;
                    match crawled {
                        Ok(None) => break Ok(()),
                        Ok(Some(stopped)) => next = stopped,
                        Err(e) => break Err(ScanStop::Rpc(e)),
                    }
                }
            }
            Fallback::GiveUp | Fallback::Crawl => Err(ScanStop::TooWide),
        },
        Err(e) => Err(ScanStop::Rpc(e)),
    };
    if let Err(e) = read {
        // What the pass read is kept, also when it gave up part-way: the
        // next pass goes on from there instead of reading it again.
        if let Some(dir) = save_to {
            if scan.scanned_through >= start {
                save(dir, &scan);
            }
        }
        return Err(ScanFailed {
            stop: e,
            progress: Some(Box::new(scan)),
        });
    }
    Ok(scan)
}

/// A [`scan_transfers`] that stopped short, with what it had read by then.
struct ScanFailed {
    stop: ScanStop,
    progress: Option<Box<TransferScan>>,
}

/// The node wallet's transfer scan for a background rediscovery, which
/// reports its progress and failure to `/health.walletScan` under
/// `status_key` (the node's address; see [`wallet_scan_pending`]). Like
/// [`refresh_transfer_scan`], or with `full_rescan` like
/// [`rescan_transfer_history`] — including resuming a full rescan an
/// earlier attempt in this process didn't finish. Only the rediscovery
/// reports: a stamp buy's chequebook check scanning the same wallet
/// meanwhile doesn't hide a `retrying` behind its own `scanning`.
pub async fn rediscovery_scan(
    client: &ChainClient,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
    full_rescan: bool,
    status_key: &[u8; 20],
) -> Result<TransferScan, RpcError> {
    let mode = if full_rescan {
        ScanMode::Full
    } else {
        ScanMode::Continue
    };
    update_transfer_scan(
        client,
        xbzz_token,
        node_eoa,
        data_dir,
        mode,
        Some(status_key),
    )
    .await
    .map_err(ScanStop::into_rpc)
}

/// Bring the node wallet's transfer scan in `data_dir` up to the chain
/// head, save it, and return it. The first call scans from the xBZZ
/// deploy block; later ones only read the blocks since the last call (and
/// the rescan tail), so rediscovery takes seconds after the first start.
/// A failed scan returns the error; the progress it made is saved, so the
/// next call resumes from there. The saved scan is keyed by wallet and by
/// the RPC's `eth_chainId`.
///
/// Shared by `antd` and `ant-ffi`, for both batch and chequebook
/// rediscovery: read the result with [`owned_batches_in`] and
/// [`owned_chequebook_in`].
pub async fn refresh_transfer_scan(
    client: &ChainClient,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
) -> Result<TransferScan, RpcError> {
    update_transfer_scan(
        client,
        xbzz_token,
        node_eoa,
        data_dir,
        ScanMode::Continue,
        None,
    )
    .await
    .map_err(ScanStop::into_rpc)
}

/// [`refresh_transfer_scan`], but reading the whole history from the xBZZ
/// deploy block again instead of continuing the saved scan, and replacing
/// it. Each saved scan only advances past blocks some RPC answered for,
/// and an RPC can answer an incomplete `[]` (a backend far behind the
/// head, a lossy log index); this is the way back from such a miss. As
/// slow as the first start's scan behind a range-capped RPC, so it is for
/// an explicit "search the chain" (`ant_storage_discover_full`, antd's
/// `--rescan-chain-history`), not for every start. It reads through the
/// verified route only, never from the unverified source
/// ([`ChainClient::with_unverified_logs`]): it replaces the saved scan,
/// which may be confirmed, and must not swap it for a provisional one.
///
/// The saved scan is only replaced once the rescan completes: a rescan
/// that fails part-way leaves the previous scan as it was (its progress
/// isn't saved over it), so the next start continues that one rather than
/// resuming a long scan from a partial cursor. Within the process, the
/// failed rescan's progress is kept in memory instead: the next rescan of
/// the same wallet (antd's retry, another `ant_storage_discover_full`)
/// continues it rather than reading the history from the deploy block
/// again — still through the verified route only.
pub async fn rescan_transfer_history(
    client: &ChainClient,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
) -> Result<TransferScan, RpcError> {
    update_transfer_scan(client, xbzz_token, node_eoa, data_dir, ScanMode::Full, None)
        .await
        .map_err(ScanStop::into_rpc)
}

/// Full rescans that failed part-way in this process, by data dir, chain
/// and wallet: what they had read, all of it from the deploy block on and
/// through the verified route. The next full rescan of the same wallet
/// continues from it.
#[allow(clippy::type_complexity)]
static PARTIAL_RESCANS: std::sync::Mutex<
    BTreeMap<(std::path::PathBuf, u64, [u8; 20]), TransferScan>,
> = std::sync::Mutex::new(BTreeMap::new());

/// Confirm the blocks the transfer scan read only from the unverified
/// source ([`ChainClient::with_unverified_logs`]): read the blocks above
/// its confirmed mark again through the verified route, in at most
/// [`MAX_VERIFIED_WINDOWS`] (64) windows per try — one request once the
/// verified route has a second full-history source. Blocks a first scan
/// already read through the verified route above the unverified ones
/// (its unverified source failed part-way,
/// [`TransferScan::confirmed_above`]) aren't read again and don't count
/// against those windows. What a try reads is saved, so one that fails or
/// gives up part-way is resumed by the next. `Ok(Some(scan))` once they're
/// confirmed: read its
/// batches and chequebook again, since the unverified read may have
/// missed some, then call [`wallet_scan_done`]. `Ok(None)` while the
/// verified route still can't serve the span: the saved scan stays
/// unconfirmed, with what the try did confirm saved under its
/// [`TransferScan::provisional_since`] (the blocks above stay as the saved
/// scan had them, so the next continued scan doesn't read them again and
/// the next try still skips [`TransferScan::confirmed_above`]); try again after
/// [`confirm_retry_delay`]. It never reads the span window by window —
/// that is the hour-long crawl the unverified read avoided — except
/// through [`find_owned_chequebook`] for a deploy decision that has waited
/// long enough.
///
/// Only an embedder with an unverified source has anything to confirm:
/// `antd` with `--gnosis-unverified-logs-rpc-url`, or an `ant-ffi` host
/// that called `ant_set_unverified_logs_rpc`. `status_key` is the key the
/// rediscovery reports under ([`rediscovery_scan`]): once the scan is
/// confirmed, the [`wallet_scan_done`] there moves it to `done`.
pub async fn confirm_transfer_scan(
    client: &ChainClient,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
    status_key: &[u8; 20],
) -> Result<Option<TransferScan>, RpcError> {
    match update_transfer_scan(
        client,
        xbzz_token,
        node_eoa,
        data_dir,
        ScanMode::Confirm { crawl: false },
        Some(status_key),
    )
    .await
    {
        Ok(scan) => Ok(Some(scan)),
        Err(ScanStop::TooWide) => Ok(None),
        Err(ScanStop::Rpc(e)) => Err(e),
    }
}

/// How long to wait before trying [`confirm_transfer_scan`] again: 1
/// minute, doubling, at most 30 minutes. Each try reads at most
/// [`MAX_VERIFIED_WINDOWS`] (64) verified windows — one request once the
/// verified route has a second full-history source.
#[must_use]
pub fn confirm_retry_delay(attempt: u32) -> std::time::Duration {
    const FIRST: u64 = 60;
    const MAX: u64 = 30 * 60;
    std::time::Duration::from_secs(FIRST.saturating_mul(1u64 << attempt.min(10)).min(MAX))
}

/// How [`update_transfer_scan`] treats the saved scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    /// Continue it from where it stopped.
    Continue,
    /// Read the blocks above its [`TransferScan::confirmed_through`]
    /// again, or the whole history if it has none, through the verified
    /// route only. With an unverified source configured, a span the
    /// verified route can't serve in a few windows stops the pass
    /// ([`ScanStop::TooWide`]) unless `crawl`.
    Confirm { crawl: bool },
    /// Read the whole history again, through the verified route only.
    Full,
}

async fn update_transfer_scan(
    client: &ChainClient,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
    mode: ScanMode,
    report: Option<&[u8; 20]>,
) -> Result<TransferScan, ScanStop> {
    // One scan at a time in this process: a stamp buy's chequebook check
    // that lands during the startup batch rediscovery waits for it, then
    // reads only the blocks since, instead of scanning the history again
    // alongside it.
    static SCANS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _scanning = SCANS.lock().await;
    let chain_id = client.eth_chain_id().await?;
    let saved = load_transfer_scan(data_dir, chain_id, node_eoa);
    // Only a full rescan replaces the saved scan wholesale; a confirming
    // re-read only rewinds it to its confirmed mark, which its progress
    // then carries forward (see below).
    let replacing = saved.is_some() && mode == ScanMode::Full;
    // A confirming re-read clears the saved provisional mark only once it
    // completes; until then its progress is saved over the scan it
    // rewound, which keeps the mark (see `scan_transfers`).
    let rewound = match mode {
        ScanMode::Confirm { .. } => saved.clone().filter(|p| p.provisional_since.is_some()),
        ScanMode::Continue | ScanMode::Full => None,
    };
    // A confirming re-read keeps the blocks a first scan read through
    // the verified route above the ones it read unverified (its unverified
    // source failed part-way): they are confirmed, just not contiguously
    // with the mark.
    let reuse = match (mode, &saved) {
        (ScanMode::Confirm { .. }, Some(p)) => match (p.provisional_through, p.confirmed_above) {
            (Some(after), Some(through))
                if p.confirmed_through.is_none_or(|c| c < after)
                    && after < through
                    && through <= p.scanned_through =>
            {
                Some(Reuse {
                    after,
                    through,
                    transfers: p
                        .transfers
                        .iter()
                        .filter(|t| t.block > after && t.block <= through)
                        .copied()
                        .collect(),
                })
            }
            _ => None,
        },
        _ => None,
    };
    let partial_key = (data_dir.to_path_buf(), chain_id, *node_eoa);
    let previous = match mode {
        ScanMode::Continue => saved,
        // A full rescan an earlier attempt cut short: every block it read
        // was read from the deploy block on, through the verified route, so
        // it continues from there.
        ScanMode::Full => PARTIAL_RESCANS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&partial_key),
        // Drop what the routine scans read above the confirmed mark; the
        // scan below reads those blocks again — including any read only
        // from the unverified source, which this pass reads verified.
        ScanMode::Confirm { .. } => saved.and_then(|mut p| {
            let c = p.confirmed_through?;
            p.scanned_through = c;
            p.provisional_since = None;
            p.provisional_through = None;
            p.confirmed_above = None;
            Some(p)
        }),
    };
    // A scan read in one pass from the deploy block confirms what it read
    // (so does a full rescan resuming its own partial pass); a continued
    // one keeps the mark it had, and a confirming re-read of the blocks
    // since the mark moves it up to what it read.
    let confirms = previous.is_none() || mode != ScanMode::Continue;
    // A full rescan is the explicit, slow "search the chain" and replaces a
    // saved scan that may be confirmed: it reads the whole history through
    // the verified route, never from the unverified source, so it can't
    // swap a confirmed scan for a provisional one.
    let fallback = match (client.unverified_logs(), mode) {
        (None, _) | (Some(_), ScanMode::Confirm { crawl: true } | ScanMode::Full) => {
            Fallback::Crawl
        }
        (Some(_), ScanMode::Confirm { crawl: false }) => Fallback::GiveUp,
        (Some(unverified), ScanMode::Continue) => Fallback::Unverified(unverified),
    };
    let from = previous
        .as_ref()
        .map_or(GNOSIS_XBZZ_DEPLOY_BLOCK, |p| p.scanned_through + 1);
    let started = std::time::Instant::now();
    // Progress saves are for resuming a scan cut short. A full rescan that
    // replaces a saved scan doesn't save its progress over it: a rescan
    // failing part-way would otherwise swap a complete scan for a partial
    // one. It is saved once it completes. A confirming re-read does save
    // its progress, with the confirmed mark moved up to it: cut short, the
    // next check re-reads only the blocks it didn't get to, rather than
    // starting again from the old mark (or from the deploy block, for a
    // scan that had none) every time — also when it gives up part-way.
    // Until it completes, its saved progress keeps the provisional marks
    // and the blocks above it of the scan it rewound (`rewound`).
    let save_progress = !replacing;
    let scanned = scan_transfers(
        client,
        chain_id,
        xbzz_token,
        node_eoa,
        GNOSIS_XBZZ_DEPLOY_BLOCK,
        previous,
        save_progress.then_some(data_dir),
        confirms,
        fallback,
        rewound.as_ref(),
        reuse,
        report,
    )
    .await;
    let mut scan = match scanned {
        Ok(scan) => scan,
        Err(ScanFailed { stop, progress }) => {
            if let (ScanStop::Rpc(e), Some(key)) = (&stop, report) {
                // A tracked rediscovery retries; until it does, it's
                // retrying, not scanning.
                update_wallet_scan(key, |s| {
                    if s.state == WalletScanState::Scanning {
                        s.state = WalletScanState::Retrying;
                        s.error = Some(without_urls(&e.to_string()));
                    }
                });
            }
            // Keep a full rescan's progress for the next one to continue.
            // It read through the verified route only (`Fallback::Crawl`),
            // so what it carries forward is as verified as a fresh pass.
            if let (ScanMode::Full, Some(progress)) = (mode, progress) {
                PARTIAL_RESCANS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(partial_key, *progress);
            }
            return Err(stop);
        }
    };
    if confirms && scan.provisional_since.is_none() {
        scan.confirmed_through = Some(scan.scanned_through);
    }
    // Whether the rediscovery ends in `confirming` follows the saved scan,
    // not just this pass: after a restart, a scan whose unverified blocks
    // aren't confirmed yet still ends there. Once it's confirmed, the
    // embedder moves `confirming` to `done` when it has registered what
    // the confirmation found ([`wallet_scan_done`]).
    let provisional = scan.provisional_since.is_some();
    if let Some(key) = report {
        update_wallet_scan(key, |s| s.provisional = provisional);
    }
    persist_transfer_scan(data_dir, &scan);
    tracing::info!(
        target: "ant_chain",
        chain_id,
        from_block = from,
        scanned_through = scan.scanned_through,
        transfers = scan.transfers.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "node wallet transfer scan up to date",
    );
    Ok(scan)
}

/// The SWAP chequebook the node wallet deployed, read off the saved
/// transfer scan ([`refresh_transfer_scan`] + [`owned_chequebook_in`]).
///
/// With `confirm_none` — the caller deploys a chequebook on `Ok(None)` —
/// a "none" that rests on routine continued scans is confirmed first: the
/// blocks above the scan's [`TransferScan::confirmed_through`] are read
/// again, or the whole history from the xBZZ deploy block if no pass has
/// confirmed it yet. A continued scan's answer rests on every earlier
/// scan's: one window an RPC answered incompletely would otherwise hide
/// the chequebook for good, and the deploy would strand its deposit. The
/// confirmed mark is saved with the scan, so the full history is read
/// once per wallet (on its first scan, or on the first confirming check
/// of a scan saved before the mark existed); a later check — another
/// buy after a deploy that soft-failed, a restart — re-reads only the
/// blocks since the last confirmation.
pub async fn find_owned_chequebook(
    client: &ChainClient,
    factory: &[u8; 20],
    postage_contract: &str,
    xbzz_token: &str,
    node_eoa: &[u8; 20],
    data_dir: &std::path::Path,
    confirm_none: bool,
) -> Result<Option<[u8; 20]>, RpcError> {
    let scan = refresh_transfer_scan(client, xbzz_token, node_eoa, data_dir).await?;
    let found = owned_chequebook_in(client, factory, postage_contract, xbzz_token, &scan).await?;
    if found.is_some() || !confirm_none || scan.confirmed_through == Some(scan.scanned_through) {
        return Ok(found);
    }
    tracing::info!(
        target: "ant_chain",
        confirmed_through = ?scan.confirmed_through,
        "no chequebook in the saved transfer scan; reading the unconfirmed blocks again before deploying one",
    );
    // Blocks read only from the unverified source are confirmed in a few
    // verified windows when the verified route can; a deploy decision that
    // has waited CONFIRM_CRAWL_AFTER_SECS for that reads them window by
    // window instead, rather than leaving the node without settlement for
    // good. A "none" with no unverified read behind it is confirmed window
    // by window at once, as without an unverified source: there is nothing
    // a second source has to vouch for, so nothing to wait on.
    let crawl = scan
        .provisional_since
        .is_none_or(|since| unix_now().saturating_sub(since) >= CONFIRM_CRAWL_AFTER_SECS);
    let scan = match update_transfer_scan(
        client,
        xbzz_token,
        node_eoa,
        data_dir,
        ScanMode::Confirm { crawl },
        None,
    )
    .await
    {
        Ok(scan) => scan,
        Err(e) => return Err(e.into_rpc()),
    };
    owned_chequebook_in(client, factory, postage_contract, xbzz_token, &scan).await
}

impl ChainClient {
    /// `eth_getLogs` for a single contract address over an inclusive
    /// block range, with the given topic filter (already JSON-encoded
    /// as an array of topic strings / nulls).
    pub async fn eth_get_logs(
        &self,
        address: &str,
        topics: &serde_json::Value,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<LogEntry>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_getLogs",
            "params": [{
                "address": address,
                "fromBlock": format!("0x{from_block:x}"),
                "toBlock": format!("0x{to_block:x}"),
                "topics": topics,
            }],
        });
        let v = self.rpc(&body).await?;
        if let Some(err) = crate::rpc_error_json(&v) {
            return Err(RpcError::Rpc(err));
        }
        let arr = v
            .get("result")
            .and_then(|r| r.as_array())
            .ok_or_else(|| RpcError::Rpc("eth_getLogs: missing result array".into()))?;
        arr.iter().map(parse_log_entry).collect()
    }

    /// Scan a contract's logs across `[from_block, to_block]`, shrinking
    /// the window on a range-limit RPC error and growing it again after
    /// a success. Public Gnosis RPCs cap `eth_getLogs` ranges (Alchemy's
    /// free tier at 10 blocks, others at 50 000, etc.); the indexed
    /// `from` filter keeps each window cheap so this stays bounded.
    pub async fn scan_logs(
        &self,
        address: &str,
        topics: &serde_json::Value,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<LogEntry>, RpcError> {
        let mut out = Vec::new();
        self.scan_logs_with(
            address,
            topics,
            from_block,
            to_block,
            1,
            u64::MAX,
            |_, mut logs| {
                out.append(&mut logs);
            },
        )
        .await?;
        Ok(out)
    }

    /// [`Self::scan_logs`], handing each window's logs to `window` along
    /// with the window's last block, in block order, so a caller can keep
    /// its progress. A range limit that would shrink the window below
    /// `min_window` blocks, or a range left after `max_windows` windows,
    /// stops the scan: `Ok(Some(block))` is the first block not read.
    /// `Ok(None)` read it all.
    #[allow(clippy::too_many_arguments)]
    async fn scan_logs_with(
        &self,
        address: &str,
        topics: &serde_json::Value,
        from_block: u64,
        to_block: u64,
        min_window: u64,
        max_windows: u64,
        mut window: impl FnMut(u64, Vec<LogEntry>),
    ) -> Result<Option<u64>, RpcError> {
        let mut start = from_block;
        let mut windows = 0u64;
        // The whole range fits one window: `to - from + 1` blocks, not
        // `to - from`, or the last block costs a request of its own.
        let mut chunk =
            INITIAL_SCAN_CHUNK.min(to_block.saturating_sub(from_block).saturating_add(1).max(1));
        while start <= to_block {
            if windows >= max_windows {
                return Ok(Some(start));
            }
            let end = start.saturating_add(chunk.saturating_sub(1)).min(to_block);
            match self.eth_get_logs(address, topics, start, end).await {
                Ok(logs) => {
                    window(end, logs);
                    windows += 1;
                    start = end.saturating_add(1);
                    chunk = chunk.saturating_mul(2).min(INITIAL_SCAN_CHUNK);
                }
                Err(RpcError::Rpc(msg)) if chunk > 1 && is_range_limit_error(&msg) => {
                    if chunk / 2 < min_window {
                        return Ok(Some(start));
                    }
                    chunk = (chunk / 2).max(1);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// `PostageStamp.remainingBalance(bytes32)` — per-chunk balance left
    /// on a batch (`> 0` means unexpired). Selector `0xd71ba7c4`.
    pub async fn postage_remaining_balance(
        &self,
        postage_contract: &str,
        batch_id: &[u8; 32],
    ) -> Result<u128, RpcError> {
        let mut data = String::with_capacity(2 + 8 + 64);
        data.push_str("0xd71ba7c4");
        write!(data, "{}", hex::encode(batch_id)).unwrap();
        let out = self.eth_call(postage_contract, &data).await?;
        last_word_u128(&out)
    }
}

/// The postage batches `scan`'s wallet owns that are still funded.
/// Batch buys and top-ups pull BZZ via `transferFrom`, emitting a
/// `Transfer` whose `to` is the `PostageStamp` contract.
///
/// For each block such a transfer is in, a **single-block `eth_getLogs`**
/// for `BatchCreated` on the `PostageStamp` contract recovers the batch
/// ids, matched back to the `Transfer` by `transactionHash` (issue #77).
/// This deliberately does *not* use `eth_getTransactionReceipt`: verified
/// backends (Myotis) serve receipts near head only, so a receipt hop
/// returns `null` for any older batch and silently loses it — while the
/// log index they *do* carry covers exactly this query. It is also
/// cheaper against a plain RPC (one request per hit block instead of one
/// per hit transaction). `BatchCreated.owner` is not an indexed topic,
/// so an owner-filtered query cannot replace the `Transfer` scan itself;
/// the per-batch owner check below still does that job.
pub async fn owned_batches_in(
    client: &ChainClient,
    postage_contract: &str,
    scan: &TransferScan,
) -> Result<Vec<DiscoveredBatch>, RpcError> {
    let postage_addr = parse_addr(postage_contract).ok_or_else(|| {
        RpcError::Decode(format!("bad postage contract address {postage_contract}"))
    })?;
    let node_eoa = &scan.node_eoa;

    // Transactions whose Transfer landed in the PostageStamp contract,
    // grouped by the block they were mined in — one `eth_getLogs` per
    // block covers every hit transaction in it.
    let mut hits: BTreeMap<u64, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for t in &scan.transfers {
        if t.to == postage_addr {
            hits.entry(t.block).or_default().insert(t.tx_hash);
        }
    }

    // Pull the BatchCreated batch ids out of each hit block's logs and
    // keep the ones emitted by our own transactions.
    let bc_topic = batch_created_event_topic();
    let bc_topics = json!([format!("0x{}", hex::encode(bc_topic))]);
    let mut batch_ids: BTreeSet<[u8; 32]> = BTreeSet::new();
    for (block, tx_hashes) in &hits {
        let created = client
            .eth_get_logs(postage_contract, &bc_topics, *block, *block)
            .await?;
        for log in &created {
            if log.address == postage_addr
                && log.topics.first() == Some(&bc_topic)
                && tx_hashes.contains(&log.tx_hash)
            {
                if let Some(id) = log.topics.get(1) {
                    batch_ids.insert(*id);
                }
            }
        }
    }

    // Verify each candidate against current chain state. A read that
    // *failed* is not a confirmed negative: swallowing it (skip on a meta
    // error, `unwrap_or(0)` on the balance) would reclassify an RPC /
    // host-backend hiccup as "not ours" / "drained" and hand back a
    // silently truncated list that a restore flow takes as authoritative.
    // Only a chain answer we could actually read may drop a candidate;
    // anything else fails the whole scan, which every caller already
    // handles (antd logs and starts without rediscovery, the FFI surfaces
    // the error).
    let mut out = Vec::new();
    for id in &batch_ids {
        let meta = crate::fetch_postage_batch_meta(client, postage_contract, id).await?;
        if meta.batch_owner_eth != *node_eoa {
            continue;
        }
        let remaining = client
            .postage_remaining_balance(postage_contract, id)
            .await?;
        if remaining == 0 {
            continue; // confirmed expired / drained
        }
        out.push(DiscoveredBatch {
            batch_id: *id,
            depth: meta.depth,
            bucket_depth: meta.bucket_depth,
            immutable: meta.immutable,
            remaining_balance: remaining,
        });
    }
    Ok(out)
}

/// What the chain says about a postage batch reloaded from a persisted
/// `postage/<id>.bin` store — see [`verify_persisted_batch`].
#[derive(Debug)]
pub enum PersistedBatchVerdict {
    /// On-chain, owned by the key we stamp with, and still funded
    /// (`remainingBalance > 0`): keep it.
    Owned,
    /// `batchOwner` reads as the zero address: the batch was never
    /// created, or it expired and has since been evicted (the contract
    /// only deletes an expired batch once someone calls
    /// `expireLimited`). Every storer would reject its stamps, so it
    /// must not be registered.
    NotFound,
    /// Still ours on-chain but `remainingBalance` reads `0`: the batch
    /// has expired and just hasn't been evicted yet (`batchOwner` stays
    /// set until `expireLimited` runs). Storers already reject its
    /// stamps and an expired batch can't be topped up, so it must not
    /// be registered either.
    Expired,
    /// On-chain, but owned by this other address — stamps we sign
    /// would be rejected, so it must not be registered.
    ForeignOwner([u8; 20]),
    /// The chain read itself failed. Unconfirmed is not dead: callers
    /// keep the batch, since dropping a funded batch on an RPC hiccup
    /// is the worse failure.
    Unverified(RpcError),
}

/// Confirm a postage batch reloaded from disk against the chain before
/// stamping with it (the phantom-batch guard, issue #49).
///
/// A persisted issuer proves only that *we once* held the batch — not
/// that the chain still does (it may have expired, or a failed or
/// foreign-chain buy never registered it). Storer peers validate every
/// stamp against their chain-synced batchstore, so an unconfirmable
/// batch means every push is rejected while `/stamps` reads green.
///
/// Expiry is checked on the balance, not only the owner: an expired
/// batch keeps its `batchOwner` until someone evicts it with
/// `expireLimited`, but `remainingBalance` already reads `0`.
///
/// Shared by `antd`'s startup reload and `ant-ffi`'s (which runs it
/// once the host hands it an RPC), so both entry points draw the same
/// line between "dead" and "unconfirmed".
pub async fn verify_persisted_batch(
    client: &ChainClient,
    postage_contract: &str,
    batch_id: &[u8; 32],
    our_owner: &[u8; 20],
) -> PersistedBatchVerdict {
    match crate::fetch_postage_batch_owner(client, postage_contract, batch_id).await {
        Ok(owner) if owner == [0u8; 20] => PersistedBatchVerdict::NotFound,
        Ok(owner) if owner != *our_owner => PersistedBatchVerdict::ForeignOwner(owner),
        Ok(_) => match client
            .postage_remaining_balance(postage_contract, batch_id)
            .await
        {
            Ok(0) => PersistedBatchVerdict::Expired,
            Ok(_) => PersistedBatchVerdict::Owned,
            Err(e) => PersistedBatchVerdict::Unverified(e),
        },
        Err(e) => PersistedBatchVerdict::Unverified(e),
    }
}

/// The SWAP chequebook `scan`'s wallet deployed. Every funded chequebook
/// was deposited into by the node EOA, so it is among the transfers'
/// recipients. Each candidate is verified with
/// `factory.deployedContracts(to)` and `to.issuer() == node_eoa`. On more
/// than one match the most-recently funded chequebook wins.
///
/// `Ok(None)` is authoritative — "every candidate was read, none is
/// ours". A failed read is an `Err`, never an `Ok(None)`: callers treat
/// the empty answer as licence to deploy a new chequebook.
pub async fn owned_chequebook_in(
    client: &ChainClient,
    factory: &[u8; 20],
    postage_contract: &str,
    xbzz_token: &str,
    scan: &TransferScan,
) -> Result<Option<[u8; 20]>, RpcError> {
    let postage_addr = parse_addr(postage_contract);
    let xbzz_addr = parse_addr(xbzz_token);
    let node_eoa = &scan.node_eoa;

    // Distinct `to` addresses, keyed by the highest block we saw them
    // funded at (so we can prefer the most-recent on a tie).
    let mut candidates: BTreeMap<[u8; 20], u64> = BTreeMap::new();
    for t in &scan.transfers {
        let to = t.to;
        if &to == node_eoa || Some(to) == postage_addr || Some(to) == xbzz_addr || to == [0u8; 20] {
            continue;
        }
        let entry = candidates.entry(to).or_insert(0);
        *entry = (*entry).max(t.block);
    }

    // Most-recent first.
    let mut ordered: Vec<([u8; 20], u64)> = candidates.into_iter().collect();
    ordered.sort_by_key(|c| std::cmp::Reverse(c.1));

    // Same rule as the batch scan above: a read that *failed* is not a
    // confirmed negative. Swallowing it (`Err(_) => continue`) turns an
    // RPC / host-backend hiccup into "this EOA owns no chequebook", and
    // the caller acts on that by deploying *and funding* a second one —
    // burning gas and stranding the first chequebook's deposit on the
    // strength of chain state we could not read. Only an answer we
    // actually read may drop a candidate; anything else fails the whole
    // scan.
    let factory_hex = format!("0x{}", hex::encode(factory));
    for (cb, _block) in ordered {
        let cb_hex = format!("0x{}", hex::encode(cb));
        // factory.deployedContracts(cb) -> bool
        let dc_data = format!(
            "0x{}",
            hex::encode(factory_deployed_contracts_calldata(&cb))
        );
        let deployed = last_word_nonzero(&client.eth_call(&factory_hex, &dc_data).await?);
        if !deployed {
            continue; // the factory says it never deployed this address
        }
        // cb.issuer() -> address
        let iss_data = format!("0x{}", hex::encode(chequebook_issuer_selector()));
        let ret = client.eth_call(&cb_hex, &iss_data).await?;
        // A short return is an answer we read: the address has no
        // `issuer()` to report, so it is not our chequebook.
        let Some(word) = ret.len().checked_sub(32).and_then(|off| ret.get(off..)) else {
            continue;
        };
        let issuer = address_from_topic(word.try_into().unwrap());
        if &issuer == node_eoa {
            return Ok(Some(cb));
        }
    }
    Ok(None)
}

fn parse_log_entry(v: &serde_json::Value) -> Result<LogEntry, RpcError> {
    let address = parse_addr(
        v.get("address")
            .and_then(|a| a.as_str())
            .ok_or_else(|| RpcError::Decode("log missing address".into()))?,
    )
    .ok_or_else(|| RpcError::Decode("log bad address".into()))?;
    let topics = v
        .get("topics")
        .and_then(|t| t.as_array())
        .ok_or_else(|| RpcError::Decode("log missing topics".into()))?
        .iter()
        .map(|t| {
            let s = t
                .as_str()
                .ok_or_else(|| RpcError::Decode("non-string topic".into()))?;
            let mut out = [0u8; 32];
            hex::decode_to_slice(s.trim_start_matches("0x"), &mut out)
                .map_err(|e| RpcError::Decode(format!("topic: {e}")))?;
            Ok(out)
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    let data = hex::decode(
        v.get("data")
            .and_then(|d| d.as_str())
            .unwrap_or("0x")
            .trim_start_matches("0x"),
    )
    .map_err(|e| RpcError::Decode(format!("log data: {e}")))?;
    let mut tx_hash = [0u8; 32];
    hex::decode_to_slice(
        v.get("transactionHash")
            .and_then(|t| t.as_str())
            .unwrap_or("0x")
            .trim_start_matches("0x"),
        &mut tx_hash,
    )
    .map_err(|e| RpcError::Decode(format!("transactionHash: {e}")))?;
    // Hard error rather than a 0 default: both callers key off this —
    // the batch scan issues its single-block `BatchCreated` query at
    // exactly this height, and the chequebook scan orders candidates by
    // it. Defaulting a missing/unparseable height to 0 would quietly
    // drop the batch (query block 0, find nothing) instead of surfacing
    // a malformed log.
    let block_number = v
        .get("blockNumber")
        .and_then(|b| b.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .ok_or_else(|| RpcError::Decode("log missing blockNumber".into()))?;
    Ok(LogEntry {
        address,
        topics,
        data,
        tx_hash,
        block_number,
    })
}

/// Heuristic: does this RPC error mean "your block range / result set
/// was too big"? Such errors are recoverable by shrinking the window;
/// anything else (auth, malformed) should propagate immediately.
fn is_range_limit_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    [
        "block range",
        "range",
        "more than",
        "exceed",
        "too large",
        "10000",
        "limit",
        "logs matched",
        "response size",
        "up to a",
        "query timeout",
        "too many results",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

/// 0x-prefixed 64-hex topic word for a 20-byte address (left-padded).
fn topic_for_address(addr: &[u8; 20]) -> String {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    format!("0x{}", hex::encode(w))
}

/// The 20-byte address packed into the low bytes of a 32-byte topic /
/// ABI word.
fn address_from_topic(word: &[u8; 32]) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    a
}

fn parse_addr(s: &str) -> Option<[u8; 20]> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut a = [0u8; 20];
    hex::decode_to_slice(s, &mut a).ok().map(|()| a)
}

/// True when the last 32-byte word of an ABI return has any non-zero
/// byte — the bool-return convention used by `deployedContracts`.
fn last_word_nonzero(ret: &[u8]) -> bool {
    ret.len() >= 32 && ret[ret.len() - 32..].iter().any(|&b| b != 0)
}

fn last_word_u128(ret: &[u8]) -> Result<u128, RpcError> {
    if ret.len() < 32 {
        return Err(RpcError::Decode("ABI return shorter than word".into()));
    }
    let w = &ret[ret.len() - 32..];
    Ok(u128::from_be_bytes(w[16..32].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ChainTransport;
    use sha3::{Digest, Keccak256};
    use std::sync::Mutex;

    #[test]
    fn transfer_topic_matches_keccak() {
        let want = Keccak256::digest(b"Transfer(address,address,uint256)");
        assert_eq!(ERC20_TRANSFER_TOPIC, want.as_slice());
    }

    #[test]
    fn remaining_balance_selector() {
        let sel = &Keccak256::digest(b"remainingBalance(bytes32)")[0..4];
        assert_eq!(hex::encode(sel), "d71ba7c4");
    }

    #[test]
    fn topic_address_round_trip() {
        let addr = [0xabu8; 20];
        let topic = topic_for_address(&addr);
        let mut word = [0u8; 32];
        hex::decode_to_slice(topic.trim_start_matches("0x"), &mut word).unwrap();
        assert_eq!(address_from_topic(&word), addr);
        assert_eq!(&word[0..12], &[0u8; 12]);
    }

    #[test]
    fn range_limit_classification() {
        assert!(is_range_limit_error(
            "Under the Free tier plan, you can make eth_getLogs requests with up to a 10 block range"
        ));
        assert!(is_range_limit_error("exceed maximum block range: 50000"));
        assert!(is_range_limit_error(
            "query returned more than 10000 results"
        ));
        assert!(!is_range_limit_error("invalid api key"));
    }

    #[test]
    fn last_word_helpers() {
        let mut w = [0u8; 32];
        w[31] = 1;
        assert!(last_word_nonzero(&w));
        assert!(!last_word_nonzero(&[0u8; 32]));
        let mut bal = [0u8; 32];
        bal[28..32].copy_from_slice(&0x3a21_096fu32.to_be_bytes());
        assert_eq!(last_word_u128(&bal).unwrap(), 0x3a21_096f);
    }

    /// A log entry with no `blockNumber` is unusable by both scans (the
    /// batch scan aims a per-block query at it, the chequebook scan
    /// orders by it), so it must be a decode error rather than a
    /// silently-dropped batch at block 0.
    #[test]
    fn log_without_block_number_is_a_decode_error() {
        let v = json!({
            "address": "0x45a1502382541cd610cc9068e88727426b696293",
            "topics": [],
            "data": "0x",
            "transactionHash": format!("0x{}", "11".repeat(32)),
        });
        let err = parse_log_entry(&v).unwrap_err().to_string();
        assert!(err.contains("blockNumber"), "got {err}");
    }

    // --- batch-discovery query plan (issue #77) ---

    const NODE_EOA: [u8; 20] = [0xa1; 20];
    /// Block the node's `Transfer` into `PostageStamp` was mined in.
    const HIT_BLOCK: u64 = 0x1dd_8ac8;
    const OUR_TX: [u8; 32] = [0x77; 32];
    const OTHER_TX: [u8; 32] = [0x99; 32];
    const OUR_BATCH: [u8; 32] = [0xbb; 32];
    const OTHER_BATCH: [u8; 32] = [0xcc; 32];

    /// A one-off full scan, then [`owned_batches_in`].
    async fn discover_owned_batches(
        client: &ChainClient,
        postage_contract: &str,
        xbzz_token: &str,
        node_eoa: &[u8; 20],
        from_block: u64,
    ) -> Result<Vec<DiscoveredBatch>, RpcError> {
        let scan = scan_transfers(
            client,
            100,
            xbzz_token,
            node_eoa,
            from_block,
            None,
            None,
            false,
            Fallback::Crawl,
            None,
            None,
            None,
        )
        .await
        .map_err(|f| f.stop.into_rpc())?;
        owned_batches_in(client, postage_contract, &scan).await
    }

    /// A one-off full scan, then [`owned_chequebook_in`].
    async fn discover_owned_chequebook(
        client: &ChainClient,
        factory: &[u8; 20],
        postage_contract: &str,
        xbzz_token: &str,
        node_eoa: &[u8; 20],
        from_block: u64,
    ) -> Result<Option<[u8; 20]>, RpcError> {
        let scan = scan_transfers(
            client,
            100,
            xbzz_token,
            node_eoa,
            from_block,
            None,
            None,
            false,
            Fallback::Crawl,
            None,
            None,
            None,
        )
        .await
        .map_err(|f| f.stop.into_rpc())?;
        owned_chequebook_in(client, factory, postage_contract, xbzz_token, &scan).await
    }

    /// Scripted chain backend, plugged in through the host-transport
    /// seam so the query plan is observable: every method ant issues is
    /// recorded, and anything unscripted is a hard failure rather than a
    /// fall-through to a real RPC.
    #[derive(Default)]
    struct ScriptedChain {
        seen: Mutex<Vec<String>>,
        get_logs_params: Mutex<Vec<serde_json::Value>>,
        /// When set, the `eth_call` carrying this selector answers with a
        /// JSON-RPC error instead of a value — a transient read failure.
        fail_selector: Option<&'static str>,
        /// What `batchOwner` answers; `None` is [`NODE_EOA`].
        batch_owner: Option<[u8; 20]>,
        /// What `remainingBalance` answers; `None` is `42`.
        remaining: Option<u128>,
    }

    fn word_hex(bytes: &[u8]) -> String {
        let mut w = [0u8; 32];
        w[32 - bytes.len()..].copy_from_slice(bytes);
        format!("0x{}", hex::encode(w))
    }

    fn log_json(
        address: &str,
        topics: &[String],
        tx_hash: &[u8; 32],
        block: u64,
    ) -> serde_json::Value {
        json!({
            "address": address,
            "topics": topics,
            "data": "0x",
            "transactionHash": format!("0x{}", hex::encode(tx_hash)),
            "blockNumber": format!("0x{block:x}"),
        })
    }

    impl ScriptedChain {
        fn result(&self, method: &str, params: &serde_json::Value) -> serde_json::Value {
            match method {
                "eth_blockNumber" => json!(format!("0x{:x}", HIT_BLOCK + 500)),
                "eth_getLogs" => {
                    self.get_logs_params.lock().unwrap().push(params[0].clone());
                    let filter = &params[0];
                    let address = filter["address"].as_str().unwrap().to_ascii_lowercase();
                    if address == crate::GNOSIS_BZZ_TOKEN.to_ascii_lowercase() {
                        // The xBZZ Transfer(from = node EOA) scan: one
                        // hit, paying the PostageStamp contract.
                        return json!([log_json(
                            crate::GNOSIS_BZZ_TOKEN,
                            &[
                                format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC)),
                                word_hex(&NODE_EOA),
                                word_hex(&parse_addr(crate::GNOSIS_POSTAGE_STAMP).unwrap()),
                            ],
                            &OUR_TX,
                            HIT_BLOCK,
                        )]);
                    }
                    assert_eq!(address, crate::GNOSIS_POSTAGE_STAMP.to_ascii_lowercase());
                    // Single-block BatchCreated query: our batch plus a
                    // stranger's, mined in the same block.
                    let bc = format!("0x{}", hex::encode(batch_created_event_topic()));
                    json!([
                        log_json(
                            crate::GNOSIS_POSTAGE_STAMP,
                            &[bc.clone(), word_hex(&OUR_BATCH)],
                            &OUR_TX,
                            HIT_BLOCK,
                        ),
                        log_json(
                            crate::GNOSIS_POSTAGE_STAMP,
                            &[bc, word_hex(&OTHER_BATCH)],
                            &OTHER_TX,
                            HIT_BLOCK,
                        ),
                    ])
                }
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap();
                    let owner = self.batch_owner.unwrap_or(NODE_EOA);
                    let word = match &data[0..10] {
                        "0x2182ddb1" => word_hex(&owner), // batchOwner
                        "0x44beae8e" => word_hex(&[17]),  // batchDepth
                        "0x32ac57dd" => word_hex(&[16]),  // bucketDepth
                        "0xd968f44b" => word_hex(&[1]),   // immutableFlag
                        "0xd71ba7c4" => word_hex(&self.remaining.unwrap_or(42).to_be_bytes()), // remainingBalance
                        other => panic!("unscripted eth_call selector {other}"),
                    };
                    json!(word)
                }
                other => panic!("unscripted method {other} — the query plan changed"),
            }
        }
    }

    impl ChainTransport for ScriptedChain {
        fn serve(&self, request_json: &str) -> Option<String> {
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let method = req["method"].as_str().unwrap().to_string();
            if let Some(sel) = self.fail_selector {
                let data = req["params"][0]["data"].as_str().unwrap_or_default();
                if method == "eth_call" && data.starts_with(sel) {
                    self.seen.lock().unwrap().push(method);
                    return Some(
                        json!({
                            "jsonrpc": "2.0",
                            "id": req["id"],
                            // Not the retryable -32000 (that means "I
                            // don't cover this" and falls back to the
                            // URL) — an authoritative backend failure.
                            "error": {"code": -32603, "message": "backend unavailable"},
                        })
                        .to_string(),
                    );
                }
            }
            let result = self.result(&method, &req["params"]);
            self.seen.lock().unwrap().push(method);
            Some(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string())
        }
    }

    /// Batch discovery recovers the batch id from a **single-block
    /// `eth_getLogs` for `BatchCreated`** matched by `transactionHash`,
    /// and never asks for a transaction receipt — verified backends
    /// serve receipts near head only, so the old receipt hop lost every
    /// older batch (issue #77).
    #[tokio::test]
    async fn batch_discovery_uses_logs_not_receipts() {
        let script = std::sync::Arc::new(ScriptedChain::default());
        // An unroutable URL: any fall-through would fail the discovery
        // instead of silently answering from a real RPC.
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(script.clone()));

        let found = discover_owned_batches(
            &client,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            GNOSIS_XBZZ_DEPLOY_BLOCK,
        )
        .await
        .unwrap();

        assert_eq!(found.len(), 1, "exactly our batch, not the stranger's");
        assert_eq!(found[0].batch_id, OUR_BATCH);
        assert_eq!(found[0].depth, 17);
        assert_eq!(found[0].bucket_depth, 16);
        assert!(found[0].immutable);
        assert_eq!(found[0].remaining_balance, 42);

        let seen = script.seen.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|m| m == "eth_getTransactionReceipt"),
            "the receipt hop must be gone: {seen:?}",
        );

        // The BatchCreated query is scoped to the single block the
        // Transfer landed in, and filtered on the event topic.
        let params = script.get_logs_params.lock().unwrap().clone();
        let bc = params
            .iter()
            .find(|p| {
                p["address"]
                    .as_str()
                    .unwrap()
                    .eq_ignore_ascii_case(crate::GNOSIS_POSTAGE_STAMP)
            })
            .expect("a BatchCreated query on the PostageStamp contract");
        assert_eq!(bc["fromBlock"], format!("0x{HIT_BLOCK:x}"));
        assert_eq!(bc["toBlock"], format!("0x{HIT_BLOCK:x}"));
        assert_eq!(
            bc["topics"],
            json!([format!("0x{}", hex::encode(batch_created_event_topic()))]),
        );
    }

    async fn discover_with_failing_call(
        selector: &'static str,
    ) -> Result<Vec<DiscoveredBatch>, RpcError> {
        let script = std::sync::Arc::new(ScriptedChain {
            fail_selector: Some(selector),
            ..ScriptedChain::default()
        });
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(script));
        discover_owned_batches(
            &client,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            GNOSIS_XBZZ_DEPLOY_BLOCK,
        )
        .await
    }

    /// A failed `remainingBalance` read is not a drained batch: the scan
    /// must fail loudly rather than reclassify an RPC / host-backend
    /// hiccup as "expired" and hand a restore flow a list missing a
    /// funded batch.
    #[tokio::test]
    async fn failed_balance_read_is_not_a_drained_batch() {
        let err = discover_with_failing_call("0xd71ba7c4")
            .await
            .expect_err("a failed balance read must not read as remaining = 0");
        assert!(err.to_string().contains("backend unavailable"), "got {err}");
    }

    /// Same for the per-batch meta read: an unreadable `batchOwner` is
    /// not "someone else's batch".
    #[tokio::test]
    async fn failed_meta_read_is_not_a_foreign_batch() {
        let err = discover_with_failing_call("0x2182ddb1")
            .await
            .expect_err("a failed owner read must not read as not-ours");
        assert!(err.to_string().contains("backend unavailable"), "got {err}");
    }

    // --- persisted-issuer verification (issue #49) ---

    async fn verify_against(script: ScriptedChain) -> PersistedBatchVerdict {
        let client = ChainClient::new("http://127.0.0.1:1")
            .with_transport(Some(std::sync::Arc::new(script)));
        verify_persisted_batch(&client, crate::GNOSIS_POSTAGE_STAMP, &OUR_BATCH, &NODE_EOA).await
    }

    #[tokio::test]
    async fn persisted_batch_we_own_is_kept() {
        let verdict = verify_against(ScriptedChain::default()).await;
        assert!(
            matches!(verdict, PersistedBatchVerdict::Owned),
            "got {verdict:?}"
        );
    }

    /// The phantom-batch case: an evicted or never-created batch reads
    /// as the zero owner.
    #[tokio::test]
    async fn zero_owner_is_not_found() {
        let verdict = verify_against(ScriptedChain {
            batch_owner: Some([0u8; 20]),
            ..ScriptedChain::default()
        })
        .await;
        assert!(
            matches!(verdict, PersistedBatchVerdict::NotFound),
            "got {verdict:?}"
        );
    }

    #[tokio::test]
    async fn other_owner_is_foreign() {
        let stranger = [0x5e; 20];
        let verdict = verify_against(ScriptedChain {
            batch_owner: Some(stranger),
            ..ScriptedChain::default()
        })
        .await;
        assert!(
            matches!(verdict, PersistedBatchVerdict::ForeignOwner(o) if o == stranger),
            "got {verdict:?}"
        );
    }

    /// Expired but not yet evicted: `batchOwner` is still ours, yet
    /// `remainingBalance` reads `0` — dead to every storer.
    #[tokio::test]
    async fn owned_but_drained_is_expired() {
        let verdict = verify_against(ScriptedChain {
            remaining: Some(0),
            ..ScriptedChain::default()
        })
        .await;
        assert!(
            matches!(verdict, PersistedBatchVerdict::Expired),
            "got {verdict:?}"
        );
    }

    /// A failed read is not a dead batch: it must come back as
    /// `Unverified` (kept), never as `NotFound` / `Expired` /
    /// `ForeignOwner` — including a failed balance read, which must not
    /// read as `remaining = 0`.
    #[tokio::test]
    async fn failed_read_is_unverified_not_dead() {
        for selector in ["0x2182ddb1", "0xd71ba7c4"] {
            let verdict = verify_against(ScriptedChain {
                fail_selector: Some(selector),
                ..ScriptedChain::default()
            })
            .await;
            match verdict {
                PersistedBatchVerdict::Unverified(e) => {
                    assert!(e.to_string().contains("backend unavailable"), "got {e}");
                }
                other => panic!("failed {selector} read must be Unverified, got {other:?}"),
            }
        }
    }

    // --- chequebook discovery: a failed read is not "no chequebook" ---

    /// The one chequebook the node EOA funded, and so the only `to`
    /// address the scan below has to verify.
    const OUR_CHEQUEBOOK: [u8; 20] = [0xcb; 20];

    fn selector_hex(sel: &[u8]) -> String {
        format!("0x{}", hex::encode(&sel[0..4]))
    }

    fn deployed_contracts_selector() -> String {
        selector_hex(&factory_deployed_contracts_calldata(&OUR_CHEQUEBOOK))
    }

    fn issuer_selector() -> String {
        selector_hex(&chequebook_issuer_selector())
    }

    /// Scripted backend for the chequebook scan: one xBZZ `Transfer`
    /// from the node EOA into `OUR_CHEQUEBOOK`, which then verifies as
    /// factory-deployed and issued by the node EOA — unless the
    /// `eth_call` carrying `fail_selector` answers with a transient
    /// backend error instead.
    struct ScriptedChequebookChain {
        seen: Mutex<Vec<String>>,
        fail_selector: Option<String>,
    }

    impl ChainTransport for ScriptedChequebookChain {
        fn serve(&self, request_json: &str) -> Option<String> {
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let method = req["method"].as_str().unwrap().to_string();
            self.seen.lock().unwrap().push(method.clone());
            let result = match method.as_str() {
                "eth_blockNumber" => json!(format!("0x{:x}", HIT_BLOCK + 500)),
                "eth_getLogs" => json!([log_json(
                    crate::GNOSIS_BZZ_TOKEN,
                    &[
                        format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC)),
                        word_hex(&NODE_EOA),
                        word_hex(&OUR_CHEQUEBOOK),
                    ],
                    &OUR_TX,
                    HIT_BLOCK,
                )]),
                "eth_call" => {
                    let data = req["params"][0]["data"].as_str().unwrap();
                    if self
                        .fail_selector
                        .as_ref()
                        .is_some_and(|sel| data.starts_with(sel.as_str()))
                    {
                        return Some(
                            json!({
                                "jsonrpc": "2.0",
                                "id": req["id"],
                                // Deliberately not the retryable -32000:
                                // that means "I don't cover this" and
                                // falls back to the URL.
                                "error": {"code": -32603, "message": "backend unavailable"},
                            })
                            .to_string(),
                        );
                    }
                    if data.starts_with(&deployed_contracts_selector()) {
                        json!(word_hex(&[1])) // factory deployed it
                    } else if data.starts_with(&issuer_selector()) {
                        json!(word_hex(&NODE_EOA))
                    } else {
                        panic!("unscripted eth_call data {data}")
                    }
                }
                other => panic!("unscripted method {other} — the query plan changed"),
            };
            Some(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string())
        }
    }

    async fn discover_chequebook_with_failing_call(
        fail_selector: Option<String>,
    ) -> Result<Option<[u8; 20]>, RpcError> {
        let script = std::sync::Arc::new(ScriptedChequebookChain {
            seen: Mutex::new(Vec::new()),
            fail_selector,
        });
        // An unroutable URL: any fall-through would fail the scan rather
        // than quietly answer from a real RPC.
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(script));
        discover_owned_chequebook(
            &client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            GNOSIS_XBZZ_DEPLOY_BLOCK,
        )
        .await
    }

    /// With every read answered, the scan finds the chequebook — the
    /// control for the two failure tests below.
    #[tokio::test]
    async fn chequebook_scan_finds_the_node_owned_chequebook() {
        let found = discover_chequebook_with_failing_call(None).await.unwrap();
        assert_eq!(found, Some(OUR_CHEQUEBOOK));
    }

    /// A failed `deployedContracts` read is not "the factory never
    /// deployed this": `Ok(None)` here reads as "this EOA owns no
    /// chequebook", which the FFI acts on by deploying *and funding* a
    /// second one.
    #[tokio::test]
    async fn failed_deployed_contracts_read_is_not_a_missing_chequebook() {
        let err = discover_chequebook_with_failing_call(Some(deployed_contracts_selector()))
            .await
            .expect_err("a failed deployedContracts read must not read as not-deployed");
        assert!(err.to_string().contains("backend unavailable"), "got {err}");
    }

    /// Same for the `issuer()` read: unreadable is not "someone else's
    /// chequebook".
    #[tokio::test]
    async fn failed_issuer_read_is_not_a_foreign_chequebook() {
        let err = discover_chequebook_with_failing_call(Some(issuer_selector()))
            .await
            .expect_err("a failed issuer read must not read as not-ours");
        assert!(err.to_string().contains("backend unavailable"), "got {err}");
    }
    /// A chain whose head can move, answering the xBZZ `Transfer` scan
    /// with only the transfers inside each requested range, and
    /// recording the ranges asked for.
    #[derive(Default)]
    struct GrowingChain {
        head: std::sync::atomic::AtomicU64,
        transfers: Mutex<Vec<NodeTransfer>>,
        ranges: Mutex<Vec<(u64, u64)>>,
        /// Refuse wider `eth_getLogs` ranges, as a capped public RPC does.
        cap: Option<u64>,
        /// Fail every `eth_getLogs` once this many have succeeded.
        fail_after: Mutex<Option<usize>>,
        /// Fail this many `eth_getLogs` (of a range it would serve), then
        /// serve again: a transient outage.
        fail_next: Mutex<usize>,
        /// What `eth_chainId` answers; `0` is Gnosis.
        chain_id: std::sync::atomic::AtomicU64,
        /// How far behind `head` the backend serving `eth_getLogs` is: it
        /// answers `[]` for the blocks it hasn't seen, no error.
        logs_lag: std::sync::atomic::AtomicU64,
        /// `eth_getLogs` requests refused for their range.
        refused: std::sync::atomic::AtomicUsize,
        /// Run after each `eth_getLogs` is answered.
        on_logs: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    }

    impl ChainTransport for GrowingChain {
        fn serve(&self, request_json: &str) -> Option<String> {
            let req: serde_json::Value = serde_json::from_str(request_json).unwrap();
            let hex_u64 =
                |v: &serde_json::Value| u64::from_str_radix(&v.as_str().unwrap()[2..], 16).unwrap();
            let result = match req["method"].as_str().unwrap() {
                "eth_chainId" => json!(format!(
                    "0x{:x}",
                    match self.chain_id.load(std::sync::atomic::Ordering::SeqCst) {
                        0 => GNOSIS,
                        id => id,
                    }
                )),
                "eth_blockNumber" => json!(format!(
                    "0x{:x}",
                    self.head.load(std::sync::atomic::Ordering::SeqCst)
                )),
                // `CB` is a factory-deployed chequebook issued by the node.
                "eth_call" => {
                    let data = req["params"][0]["data"].as_str().unwrap();
                    if data.starts_with(&deployed_contracts_selector()) {
                        json!(word_hex(&[1]))
                    } else if data.starts_with(&issuer_selector()) {
                        json!(word_hex(&NODE_EOA))
                    } else {
                        panic!("unscripted eth_call data {data}")
                    }
                }
                "eth_getLogs" => {
                    let (from, to) = (
                        hex_u64(&req["params"][0]["fromBlock"]),
                        hex_u64(&req["params"][0]["toBlock"]),
                    );
                    let refuse = |message: &str| {
                        Some(
                            json!({
                                "jsonrpc": "2.0",
                                "id": req["id"],
                                "error": {"code": -32603, "message": message},
                            })
                            .to_string(),
                        )
                    };
                    if self.cap.is_some_and(|cap| to - from + 1 > cap) {
                        self.refused
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        return refuse("block range too large");
                    }
                    if *self.fail_after.lock().unwrap() == Some(0) {
                        return refuse("backend unavailable");
                    }
                    {
                        let mut fail_next = self.fail_next.lock().unwrap();
                        if *fail_next > 0 {
                            *fail_next -= 1;
                            return refuse("too many requests");
                        }
                    }
                    if let Some(n) = self.fail_after.lock().unwrap().as_mut() {
                        *n -= 1;
                    }
                    self.ranges.lock().unwrap().push((from, to));
                    if let Some(hook) = self.on_logs.lock().unwrap().as_ref() {
                        hook();
                    }
                    let seen_up_to = self.head.load(std::sync::atomic::Ordering::SeqCst)
                        - self.logs_lag.load(std::sync::atomic::Ordering::SeqCst);
                    let logs: Vec<_> = self
                        .transfers
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|t| (from..=to).contains(&t.block) && t.block <= seen_up_to)
                        .map(|t| {
                            log_json(
                                crate::GNOSIS_BZZ_TOKEN,
                                &[
                                    format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC)),
                                    word_hex(&NODE_EOA),
                                    word_hex(&t.to),
                                ],
                                &t.tx_hash,
                                t.block,
                            )
                        })
                        .collect();
                    json!(logs)
                }
                other => panic!("unscripted method {other}"),
            };
            Some(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string())
        }
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ant-chain-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const CB: [u8; 20] = [0xcb; 20];
    const HEAD: u64 = 48_000_000;
    const GNOSIS: u64 = 100;

    /// A deposit into chequebook [`CB`].
    fn to_cb(block: u64, tx_hash: [u8; 32]) -> NodeTransfer {
        NodeTransfer {
            to: CB,
            block,
            tx_hash,
        }
    }

    /// The second start doesn't rescan history: it reads only the blocks
    /// since the first scan (plus the reorg tail), and keeps what the
    /// first one found (issue #118).
    #[tokio::test]
    async fn a_later_scan_reads_only_the_new_blocks() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(45_000_000, [1; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-cursor");

        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(first.scanned_through, HEAD - RESCAN_TAIL);
        assert_eq!(first.transfers.len(), 1);
        assert_eq!(chain.ranges.lock().unwrap()[0].0, GNOSIS_XBZZ_DEPLOY_BLOCK);

        // A thousand blocks later, with one new transfer.
        chain.ranges.lock().unwrap().clear();
        chain
            .head
            .store(HEAD + 1_000, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(HEAD + 500, [2; 32]));
        let second = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(
            *chain.ranges.lock().unwrap(),
            vec![(HEAD - RESCAN_TAIL + 1, HEAD + 1_000)],
            "only the new blocks and the reorg tail are read"
        );
        assert_eq!(second.transfers.len(), 2);
        assert_eq!(second.scanned_through, HEAD + 1_000 - RESCAN_TAIL);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A transfer seen in the reorg tail isn't remembered as final: if a
    /// reorg drops it, the next scan doesn't report it.
    #[tokio::test]
    async fn a_transfer_reorged_out_of_the_tail_is_forgotten() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(HEAD - 10, [3; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-reorg");

        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(first.transfers.len(), 1, "used while in the tail");

        chain.transfers.lock().unwrap().clear(); // reorged away
        let second = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert!(second.transfers.is_empty(), "{:?}", second.transfers);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A first scan that fails part-way keeps what it read: the next
    /// start resumes after the last window that succeeded instead of
    /// reading the history from the deploy block again.
    #[tokio::test]
    async fn a_failed_scan_resumes_where_it_stopped() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10_000_000),
            fail_after: Mutex::new(Some(2)),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(17_000_000, [4; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-resume");

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .expect_err("the third window fails");
        let read = chain.ranges.lock().unwrap().clone();
        assert_eq!(read.len(), 2);
        let saved = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).expect("progress saved");
        assert_eq!(saved.scanned_through, read[1].1);
        assert_eq!(saved.transfers.len(), 1);

        chain.ranges.lock().unwrap().clear();
        *chain.fail_after.lock().unwrap() = None;
        let scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(chain.ranges.lock().unwrap()[0].0, read[1].1 + 1, "resumed");
        assert_eq!(scan.scanned_through, HEAD - RESCAN_TAIL);
        assert_eq!(scan.transfers.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A first scan cut short and resumed is still confirmed up to where
    /// its first part got: the chequebook check before a deploy re-reads
    /// only the blocks the resumed part read, not the whole history.
    #[tokio::test]
    async fn a_resumed_first_scan_keeps_its_confirmed_mark() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10_000_000),
            fail_after: Mutex::new(Some(2)),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-resume-mark");

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .expect_err("the third window fails");
        let cut = chain.ranges.lock().unwrap()[1].1;
        let saved = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(saved.confirmed_through, Some(cut), "progress is confirmed");

        *chain.fail_after.lock().unwrap() = None;
        let resumed = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(
            resumed.confirmed_through,
            Some(cut),
            "the resumed part isn't"
        );

        chain.ranges.lock().unwrap().clear();
        assert_eq!(find_cb(&client, &dir, true).await, None);
        let ranges = chain.ranges.lock().unwrap().clone();
        assert!(
            ranges.iter().all(|r| r.0 > cut),
            "only the blocks since the mark: {ranges:?}"
        );
        let scan = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A confirming check that reads the whole history (a scan with no
    /// confirmed mark) and is cut short saves its progress with the mark
    /// moved up to it: the next check continues from there instead of
    /// starting again from the deploy block.
    #[tokio::test]
    async fn a_failed_confirming_check_resumes_where_it_stopped() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10_000_000),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(17_000_000, [9; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-confirm-resume");
        let mut scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        // Saved before the mark existed, and missing the deposit.
        scan.confirmed_through = None;
        scan.transfers.clear();
        persist_transfer_scan(&dir, &scan);

        chain.ranges.lock().unwrap().clear();
        // The routine refresh's tail read, then two windows of the
        // confirming read from the deploy block, then a failure.
        *chain.fail_after.lock().unwrap() = Some(3);
        find_owned_chequebook(
            &client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            &dir,
            true,
        )
        .await
        .expect_err("the confirming read fails part-way");
        let read = chain.ranges.lock().unwrap().clone();
        let cut = read.last().unwrap().1;
        assert_eq!(read.len(), 3, "{read:?}");
        assert_eq!(read[1].0, GNOSIS_XBZZ_DEPLOY_BLOCK);
        let saved = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).expect("progress saved");
        assert_eq!(saved.confirmed_through, Some(cut));
        assert_eq!(saved.scanned_through, cut);
        assert_eq!(saved.transfers.len(), 1, "the deposit it found is kept");

        chain.ranges.lock().unwrap().clear();
        *chain.fail_after.lock().unwrap() = None;
        assert_eq!(find_cb(&client, &dir, true).await, Some(CB));
        let ranges = chain.ranges.lock().unwrap().clone();
        assert!(ranges.iter().all(|r| r.0 > cut), "resumed: {ranges:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The rediscovery status a host reads from `/health.walletScan`:
    /// untracked until an embedder announces a rediscovery, then pending,
    /// scanning with progress, and done once the embedder says so. A
    /// later scan (a stamp buy's chequebook check) doesn't leave done.
    /// Each status test uses its own wallet: the registry is
    /// process-wide.
    #[tokio::test]
    async fn wallet_scan_status_follows_the_rediscovery() {
        const EOA: [u8; 20] = [0x51; 20];
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-status");

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert_eq!(
            wallet_scan_status(&EOA),
            None,
            "untracked without a rediscovery"
        );

        wallet_scan_pending(&EOA);
        let pending = wallet_scan_status(&EOA).unwrap();
        assert_eq!(pending.state, WalletScanState::Pending);
        assert_eq!(pending.head, None);

        // Behind by a thousand blocks: the scan resumes and reports it.
        chain
            .head
            .store(HEAD + 1_000, std::sync::atomic::Ordering::SeqCst);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        assert_eq!(
            wallet_scan_status(&EOA).unwrap(),
            WalletScanStatus {
                state: WalletScanState::Scanning,
                from: Some(HEAD - RESCAN_TAIL + 1),
                scanned_through: Some(HEAD + 1_000 - RESCAN_TAIL),
                head: Some(HEAD + 1_000),
                error: None,
                provisional: false,
            }
        );

        wallet_scan_done(&EOA);
        chain
            .head
            .store(HEAD + 2_000, std::sync::atomic::Ordering::SeqCst);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        wallet_scan_failed(&EOA, "late failure");
        let done = wallet_scan_status(&EOA).unwrap();
        assert_eq!(done.state, WalletScanState::Done, "{done:?}");
        assert_eq!(
            done.head,
            Some(HEAD + 1_000),
            "a later scan leaves done alone"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A failed scan reads as retrying, with the error, until the next
    /// attempt starts scanning again.
    #[tokio::test]
    async fn a_failed_tracked_scan_reads_as_retrying() {
        const EOA: [u8; 20] = [0x52; 20];
        let chain = std::sync::Arc::new(GrowingChain {
            fail_after: Mutex::new(Some(0)),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-status-retry");

        wallet_scan_pending(&EOA);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap_err();
        let status = wallet_scan_status(&EOA).unwrap();
        assert_eq!(status.state, WalletScanState::Retrying);
        assert!(
            status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("backend unavailable")),
            "{status:?}"
        );
        // Another announcement doesn't hide the failure.
        wallet_scan_pending(&EOA);
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Retrying
        );

        *chain.fail_after.lock().unwrap() = None;
        // A scan that isn't the rediscovery's (a stamp buy's chequebook
        // check) succeeding meanwhile doesn't hide the failure.
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        let status = wallet_scan_status(&EOA).unwrap();
        assert_eq!(status.state, WalletScanState::Retrying, "{status:?}");
        assert!(status.error.is_some());

        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        let status = wallet_scan_status(&EOA).unwrap();
        assert_eq!(status.state, WalletScanState::Scanning);
        assert_eq!(status.error, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A gateway stop drops a scanning status and a restart re-tracks it
    /// as bare `pending` while the attempt keeps running (ant-ffi's
    /// `stop_retrying` then `note_pending`): the attempt's next window
    /// reports it as scanning again, with its progress.
    #[tokio::test]
    async fn a_retracked_status_shows_the_running_scans_progress() {
        const EOA: [u8; 20] = [0x63; 20];
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(1_000),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        *chain.on_logs.lock().unwrap() = Some(Box::new(move || {
            // After the first window: the stop, then the restart.
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                wallet_scan_abandon(&EOA);
                assert_eq!(wallet_scan_status(&EOA), None);
                wallet_scan_track(&EOA, WalletScanState::Pending);
            }
        }));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-status-retrack");

        wallet_scan_pending(&EOA);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 2);
        let status = wallet_scan_status(&EOA).unwrap();
        assert_eq!(status.state, WalletScanState::Scanning, "{status:?}");
        assert_eq!(status.from, Some(GNOSIS_XBZZ_DEPLOY_BLOCK));
        assert_eq!(status.head, Some(HEAD));
        assert_eq!(status.scanned_through, Some(HEAD - RESCAN_TAIL));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rediscovery scanning a wallet other than the node's (antd's
    /// legacy `--postage-owner-key`) reports under the node's address,
    /// which is what `/health` looks up; forgetting it untracks it.
    #[tokio::test]
    async fn a_rediscovery_reports_under_its_status_key() {
        const NODE: [u8; 20] = [0x61; 20];
        const OWNER: [u8; 20] = [0x62; 20];
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-status-key");

        wallet_scan_pending(&NODE);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &OWNER, &dir, false, &NODE)
            .await
            .unwrap();
        let status = wallet_scan_status(&NODE).unwrap();
        assert_eq!(status.state, WalletScanState::Scanning, "{status:?}");
        assert_eq!(status.head, Some(HEAD));
        assert_eq!(wallet_scan_status(&OWNER), None);

        wallet_scan_forget(&NODE);
        assert_eq!(wallet_scan_status(&NODE), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A gateway stop drops an unfinished status but keeps a finished
    /// one, `confirming` included: its confirmation runs on regardless.
    #[test]
    fn abandon_keeps_a_confirming_status() {
        const EOA: [u8; 20] = [0x68; 20];
        wallet_scan_track(&EOA, WalletScanState::Confirming);
        wallet_scan_abandon(&EOA);
        let status = wallet_scan_status(&EOA).unwrap();
        assert_eq!(status.state, WalletScanState::Confirming);
        assert!(status.provisional);
        wallet_scan_forget(&EOA);
        wallet_scan_track(&EOA, WalletScanState::Pending);
        wallet_scan_abandon(&EOA);
        assert_eq!(wallet_scan_status(&EOA), None);
    }

    #[test]
    fn wallet_scan_status_wire_shape() {
        let status = WalletScanStatus {
            state: WalletScanState::Retrying,
            from: Some(16_514_506),
            scanned_through: None,
            head: Some(48_560_000),
            error: Some("no RPC quorum".into()),
            provisional: false,
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            json!({
                "state": "retrying",
                "from": 16_514_506,
                "scannedThrough": null,
                "head": 48_560_000,
                "error": "no RPC quorum",
            })
        );
        let done = WalletScanStatus {
            state: WalletScanState::Done,
            error: None,
            ..status
        };
        assert!(serde_json::to_value(&done).unwrap().get("error").is_none());
    }

    /// RPC URLs can carry API keys, so `walletScan.error` never shows
    /// one.
    #[test]
    fn wallet_scan_error_hides_urls() {
        assert_eq!(
            without_urls("http: error sending request for url (https://rpc.example/v2/SECRET-KEY)"),
            "http: error sending request for url (<url>)"
        );
        assert_eq!(
            without_urls("rpc https://a.example/k, then wss://b.example/k."),
            "rpc <url>, then <url>."
        );
        assert_eq!(without_urls("no RPC quorum"), "no RPC quorum");
    }

    #[test]
    fn rediscovery_retry_backs_off_to_five_minutes() {
        let secs: Vec<u64> = (0..7)
            .map(|a| rediscovery_retry_delay(a).as_secs())
            .collect();
        assert_eq!(secs, [15, 30, 60, 120, 240, 300, 300]);
        assert_eq!(rediscovery_retry_delay(u32::MAX).as_secs(), 300);
    }

    /// A verified route that serves `cap` blocks per query, with an
    /// unverified source that serves any range, both at `HEAD`, each with
    /// its own transfer list (the unverified one may leave some out).
    fn verified_with_unverified(
        cap: Option<u64>,
        verified: &[NodeTransfer],
        unverified: &[NodeTransfer],
    ) -> (
        ChainClient,
        std::sync::Arc<GrowingChain>,
        std::sync::Arc<GrowingChain>,
    ) {
        let chain = |cap, transfers: &[NodeTransfer]| {
            let c = std::sync::Arc::new(GrowingChain {
                cap,
                ..GrowingChain::default()
            });
            c.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
            c.transfers.lock().unwrap().extend_from_slice(transfers);
            c
        };
        let (v, u) = (chain(cap, verified), chain(None, unverified));
        let mut client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(v.clone()));
        client.unverified_logs = Some(std::sync::Arc::new(
            ChainClient::new("http://127.0.0.1:2").with_transport(Some(u.clone())),
        ));
        (client, v, u)
    }

    /// A first scan the verified route could only serve in ~3,200 windows
    /// is read in one request from the unverified source instead, after a
    /// few instant refusals, and stays unconfirmed: `walletScan` ends in
    /// `confirming`, not `done`.
    #[tokio::test]
    async fn a_wide_first_scan_reads_unverified_and_stays_unconfirmed() {
        const EOA: [u8; 20] = [0x54; 20];
        let found = [to_cb(45_000_000, [1; 32])];
        let (client, v, u) = verified_with_unverified(Some(10_000), &found, &found);
        let dir = scratch_dir("scan-unverified");

        wallet_scan_pending(&EOA);
        let scan = rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        assert_eq!(scan.transfers.len(), 1);
        assert_eq!(scan.scanned_through, HEAD - RESCAN_TAIL);
        assert!(scan.provisional_since.is_some());
        assert_eq!(scan.confirmed_through, None, "nothing was read verified");
        assert!(v.ranges.lock().unwrap().is_empty(), "no verified crawl");
        assert!(v.refused.load(std::sync::atomic::Ordering::SeqCst) <= 8);
        assert_eq!(
            *u.ranges.lock().unwrap(),
            vec![(GNOSIS_XBZZ_DEPLOY_BLOCK, HEAD)],
            "one unverified request"
        );
        wallet_scan_done(&EOA);
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Confirming
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-F1: the unverified source is a shortcut, not a dependency. While
    /// it's down, a wide first scan reads the span window by window through
    /// the verified route, as without one, instead of failing every pass;
    /// nothing in it is unverified, so it's confirmed and ends `done`.
    #[tokio::test]
    async fn a_failing_unverified_source_degrades_to_the_verified_crawl() {
        const EOA: [u8; 20] = [0x58; 20];
        let found = [to_cb(45_000_000, [1; 32])];
        let (client, v, u) = verified_with_unverified(Some(200_000), &found, &found);
        *u.fail_after.lock().unwrap() = Some(0);
        let dir = scratch_dir("scan-unverified-down");

        wallet_scan_pending(&EOA);
        let scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .expect("the verified crawl finishes the scan");
        assert_eq!(scan.transfers.len(), 1);
        assert_eq!(scan.scanned_through, HEAD - RESCAN_TAIL);
        assert_eq!(scan.provisional_since, None, "no unverified block in it");
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        assert!(
            v.ranges.lock().unwrap().len() > 100,
            "crawled window by window"
        );
        assert!(u.ranges.lock().unwrap().is_empty());
        wallet_scan_done(&EOA);
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Done
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R3-M3: one transient unverified-source error doesn't commit the
    /// pass to the hour-long verified crawl: it reads one stretch of
    /// `MAX_VERIFIED_WINDOWS` verified windows, then tries the unverified
    /// source again, which serves the rest.
    #[tokio::test]
    async fn a_recovered_unverified_source_serves_the_rest() {
        const EOA: [u8; 20] = [0x5a; 20];
        let found = [to_cb(45_000_000, [1; 32])];
        let (client, v, u) = verified_with_unverified(Some(200_000), &found, &found);
        *u.fail_next.lock().unwrap() = 1;
        let dir = scratch_dir("scan-unverified-blip");

        let scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert_eq!(scan.transfers.len(), 1);
        assert_eq!(scan.scanned_through, HEAD - RESCAN_TAIL);
        assert_eq!(
            v.ranges.lock().unwrap().len() as u64,
            MAX_VERIFIED_WINDOWS,
            "one stretch of verified windows, not the whole crawl"
        );
        let crawled_to = v.ranges.lock().unwrap().last().unwrap().1;
        assert_eq!(
            *u.ranges.lock().unwrap(),
            vec![(crawled_to + 1, HEAD)],
            "the unverified source read the rest"
        );
        assert!(scan.provisional_since.is_some());
        assert_eq!(scan.provisional_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R3-M4: when the unverified source fails part-way through a first
    /// scan, the blocks the scan then reads through the verified route are
    /// kept as confirmed: a later confirmation reads only the blocks the
    /// unverified source served — a span the verified route can confirm in
    /// a few windows even when the whole history is too wide for it.
    #[tokio::test]
    async fn a_confirmation_skips_what_the_degraded_crawl_read() {
        const EOA: [u8; 20] = [0x5b; 20];
        // One transfer the unverified source misses, early in the history;
        // one late, found by the verified crawl.
        let missed = to_cb(GNOSIS_XBZZ_DEPLOY_BLOCK + 10, [1; 32]);
        let late = to_cb(45_000_000, [2; 32]);
        let (client, _, _) = verified_with_unverified(Some(200_000), &[missed, late], &[]);
        let dir = scratch_dir("scan-confirm-skip");
        // The unverified source serves two 1M-block-capped windows, then
        // fails for good.
        let u = std::sync::Arc::new(GrowingChain {
            cap: Some(1_000_000),
            fail_after: Mutex::new(Some(2)),
            ..GrowingChain::default()
        });
        u.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        u.transfers.lock().unwrap().push(late);
        let client = client.with_unverified_logs_client(Some(
            ChainClient::new("http://127.0.0.1:2").with_transport(Some(u.clone())),
        ));

        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .expect("the verified crawl finishes the scan");
        let served_to = u.ranges.lock().unwrap().last().unwrap().1;
        assert_eq!(first.transfers, vec![late], "the early one was missed");
        assert!(first.provisional_since.is_some());
        assert_eq!(first.provisional_through, Some(served_to));
        assert_eq!(first.confirmed_above, Some(first.scanned_through));
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();
        assert_eq!(saved.confirmed_above, first.confirmed_above, "saved");

        // The verified route still can't serve the whole history in 64
        // windows, but can serve the unverified part. It no longer has the
        // late transfer: only the crawl's read can supply it.
        let (client, v, _) = verified_with_unverified(Some(100_000), &[missed], &[]);
        let confirmed = confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .unwrap()
            .expect("the unverified part fits the window budget");
        assert!(
            v.ranges
                .lock()
                .unwrap()
                .iter()
                .all(|&(from, to)| to <= served_to || from > first.scanned_through),
            "the crawled blocks aren't read again"
        );
        assert_eq!(confirmed.transfers, vec![missed, late]);
        assert_eq!(confirmed.provisional_since, None);
        assert_eq!(confirmed.provisional_through, None);
        assert_eq!(confirmed.confirmed_above, None);
        assert_eq!(confirmed.confirmed_through, Some(confirmed.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R4-M1: a confirmation try that fails part-way saves its progress
    /// over the scan it rewound, keeping the degraded crawl's verified
    /// stretch (`provisional_through`/`confirmed_above`) and the blocks
    /// above: a continued scan in between doesn't read them from the
    /// unverified source again, and the next try still skips the stretch.
    #[tokio::test]
    async fn a_failed_confirmation_keeps_the_crawled_stretch() {
        const EOA: [u8; 20] = [0x5c; 20];
        let missed = to_cb(GNOSIS_XBZZ_DEPLOY_BLOCK + 10, [1; 32]);
        let late = to_cb(45_000_000, [2; 32]);
        let (client, _, _) = verified_with_unverified(Some(200_000), &[missed, late], &[]);
        let dir = scratch_dir("scan-confirm-skip-retry");
        let u = std::sync::Arc::new(GrowingChain {
            cap: Some(1_000_000),
            fail_after: Mutex::new(Some(2)),
            ..GrowingChain::default()
        });
        u.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        u.transfers.lock().unwrap().push(late);
        let client = client.with_unverified_logs_client(Some(
            ChainClient::new("http://127.0.0.1:2").with_transport(Some(u.clone())),
        ));
        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        let served_to = u.ranges.lock().unwrap().last().unwrap().1;
        assert_eq!(first.provisional_through, Some(served_to));
        assert_eq!(first.confirmed_above, Some(first.scanned_through));

        // The first try reads two windows, then hits an RPC error.
        let (client, v, u2) = verified_with_unverified(Some(100_000), &[missed], &[]);
        *v.fail_after.lock().unwrap() = Some(2);
        confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .expect_err("fails part-way");
        let cut = v.ranges.lock().unwrap()[1].1;
        assert!(cut < served_to);
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();
        assert_eq!(saved.confirmed_through, Some(cut), "progress saved");
        assert_eq!(saved.scanned_through, first.scanned_through);
        assert_eq!(saved.provisional_since, first.provisional_since);
        assert_eq!(saved.provisional_through, first.provisional_through);
        assert_eq!(saved.confirmed_above, first.confirmed_above, "stretch kept");
        assert_eq!(saved.transfers, vec![missed, late]);

        // A continued scan in between reads only the tail.
        *v.fail_after.lock().unwrap() = None;
        v.ranges.lock().unwrap().clear();
        let resumed = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert!(
            u2.ranges.lock().unwrap().is_empty(),
            "no unverified re-read"
        );
        assert_eq!(resumed.confirmed_above, first.confirmed_above);

        // The next try confirms, skipping the crawled stretch.
        v.ranges.lock().unwrap().clear();
        let confirmed = confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .unwrap()
            .expect("the rest of the unverified part fits the window budget");
        assert!(
            v.ranges
                .lock()
                .unwrap()
                .iter()
                .all(|&(from, to)| (from > cut && to <= served_to) || from > first.scanned_through),
            "neither the confirmed nor the crawled blocks are read again"
        );
        assert_eq!(confirmed.transfers, vec![missed, late]);
        assert_eq!(confirmed.provisional_since, None);
        assert_eq!(confirmed.confirmed_through, Some(confirmed.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R2-M1: a scan is marked provisional only once the unverified source
    /// has served a window. One that failed before serving any, with the
    /// verified crawl then cut short too, saves its verified progress
    /// unmarked, so a later deploy decision crawls at once instead of
    /// waiting out `CONFIRM_CRAWL_AFTER_SECS` for a confirmation of nothing.
    #[tokio::test]
    async fn a_failed_unverified_read_doesnt_mark_the_scan_provisional() {
        const EOA: [u8; 20] = [0x59; 20];
        let (client, v, u) = verified_with_unverified(Some(200_000), &[], &[]);
        *u.fail_after.lock().unwrap() = Some(0);
        *v.fail_after.lock().unwrap() = Some(5);
        let dir = scratch_dir("scan-unverified-unmarked");

        wallet_scan_pending(&EOA);
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap_err();
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).expect("progress saved");
        assert!(saved.scanned_through >= GNOSIS_XBZZ_DEPLOY_BLOCK);
        assert_eq!(saved.provisional_since, None);
        assert!(!wallet_scan_status(&EOA).unwrap().provisional);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// After a restart, a saved scan that still holds unconfirmed blocks
    /// ends the rediscovery in `confirming`, even though this start's
    /// pass read only the tail, through the verified route.
    #[tokio::test]
    async fn an_unconfirmed_saved_scan_still_reads_confirming_after_a_restart() {
        const EOA: [u8; 20] = [0x56; 20];
        let (client, _, _) = verified_with_unverified(Some(10_000), &[], &[]);
        let dir = scratch_dir("scan-unverified-restart");
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();

        // A new process: nothing tracked until the embedder announces it.
        wallet_scan_pending(&EOA);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        wallet_scan_done(&EOA);
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Confirming
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Confirmation is a few verified windows, never a crawl: while the
    /// verified route still can't serve the span the saved scan stays as
    /// it was; once it can, the scan is confirmed — including a transfer
    /// the unverified source left out — and `walletScan` reads `done`.
    #[tokio::test]
    async fn confirmation_waits_for_the_verified_route_then_finds_what_was_missing() {
        const EOA: [u8; 20] = [0x55; 20];
        let all = [to_cb(45_000_000, [1; 32]), to_cb(46_000_000, [2; 32])];
        let (client, v, _) = verified_with_unverified(Some(10_000), &all, &all[..1]);
        let dir = scratch_dir("scan-confirm-later");
        wallet_scan_pending(&EOA);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, false, &EOA)
            .await
            .unwrap();
        wallet_scan_done(&EOA);

        let refused = v.refused.load(std::sync::atomic::Ordering::SeqCst);
        let unconfirmed = confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .unwrap();
        assert_eq!(unconfirmed, None);
        assert!(v.ranges.lock().unwrap().is_empty(), "no verified crawl");
        assert!(v.refused.load(std::sync::atomic::Ordering::SeqCst) - refused <= 8);
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();
        assert!(saved.provisional_since.is_some(), "kept as it was");
        assert_eq!(saved.transfers.len(), 1);

        // The verified route now serves the whole span (its second source
        // is back).
        let (client, _, _) = verified_with_unverified(None, &all, &all[..1]);
        let confirmed = confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .unwrap()
            .expect("confirmed");
        assert_eq!(confirmed.transfers.len(), 2, "the missed transfer is found");
        assert_eq!(confirmed.provisional_since, None);
        assert_eq!(confirmed.confirmed_through, Some(confirmed.scanned_through));
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Confirming,
            "done only once the embedder has registered what it found"
        );
        wallet_scan_done(&EOA);
        assert_eq!(
            wallet_scan_status(&EOA).unwrap().state,
            WalletScanState::Done
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A "no chequebook" that rests on an unverified read never leads to
    /// a deploy before it's confirmed. Confirmation stays a few verified
    /// windows per try for six hours; after that, the deploy decision reads the span
    /// window by window through the verified route.
    #[tokio::test]
    async fn an_unconfirmed_none_waits_six_hours_before_the_deploy_crawl() {
        let (client, v, _) = verified_with_unverified(Some(200_000), &[], &[]);
        let dir = scratch_dir("scan-confirm-crawl");
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();

        let err = find_owned_chequebook(
            &client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            &dir,
            true,
        )
        .await
        .expect_err("an unconfirmed none must not read as \"deploy\"");
        assert!(err.to_string().contains("can't confirm"), "{err}");
        let crawled = |v: &GrowingChain| {
            v.ranges
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.1 - r.0 > RESCAN_TAIL * 2)
                .count()
        };
        assert_eq!(crawled(&v), 0, "no crawl within six hours");

        let mut saved = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        saved.provisional_since = Some(unix_now() - CONFIRM_CRAWL_AFTER_SECS - 60);
        persist_transfer_scan(&dir, &saved);
        assert_eq!(find_cb(&client, &dir, true).await, None, "a confirmed none");
        assert!(crawled(&v) > 100, "crawled window by window");
        let scan = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(scan.provisional_since, None);
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R1-F1: an explicit full rescan replaces the saved scan, which may be
    /// confirmed, so it reads through the verified route only — never from
    /// the unverified source, which could leave a transfer out and swap a
    /// confirmed scan for a provisional one.
    #[tokio::test]
    async fn a_full_rescan_never_reads_the_unverified_source() {
        const EOA: [u8; 20] = [0x57; 20];
        let all = [to_cb(45_000_000, [1; 32]), to_cb(46_000_000, [2; 32])];
        let dir = scratch_dir("scan-full-verified");
        let (client, _, _) = verified_with_unverified(None, &all, &all[..1]);
        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert_eq!(first.confirmed_through, Some(first.scanned_through));

        // The verified route's second source is down: it serves only
        // narrow windows again.
        let (client, v, u) = verified_with_unverified(Some(200_000), &all, &all[..1]);
        let rescanned = rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert!(u.ranges.lock().unwrap().is_empty(), "no unverified read");
        assert!(v.ranges.lock().unwrap().len() > 64, "read window by window");
        assert_eq!(rescanned.transfers.len(), 2);
        assert_eq!(rescanned.provisional_since, None);
        assert_eq!(rescanned.confirmed_through, Some(rescanned.scanned_through));
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();
        assert_eq!(saved, rescanned);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A full rescan that fails part-way with an unverified source
    /// configured is continued by the next one (#142's in-process resume)
    /// still through the verified route only: the resumed pass never reads
    /// the unverified source, and the completed rescan replaces the
    /// confirmed saved scan with a confirmed one.
    #[tokio::test]
    async fn a_resumed_full_rescan_stays_verified() {
        const EOA: [u8; 20] = [0x65; 20];
        let all = [to_cb(45_000_000, [1; 32]), to_cb(46_000_000, [2; 32])];
        let dir = scratch_dir("scan-full-resume-verified");
        let (client, _, _) = verified_with_unverified(None, &all, &all[..1]);
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        let confirmed = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();

        let (client, v, u) = verified_with_unverified(Some(200_000), &all, &all[..1]);
        *v.fail_after.lock().unwrap() = Some(70);
        rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .expect_err("the verified route fails part-way");
        let read_through = v.ranges.lock().unwrap().last().unwrap().1;
        assert_eq!(
            load_transfer_scan(&dir, GNOSIS, &EOA),
            Some(confirmed),
            "the failed rescan leaves the saved scan as it was"
        );

        v.ranges.lock().unwrap().clear();
        *v.fail_after.lock().unwrap() = None;
        let rescanned = rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert_eq!(
            v.ranges.lock().unwrap().first().map(|r| r.0),
            Some(read_through + 1),
            "continued where the failed rescan stopped"
        );
        assert!(u.ranges.lock().unwrap().is_empty(), "no unverified read");
        assert_eq!(rescanned.transfers.len(), 2);
        assert_eq!(rescanned.provisional_since, None);
        assert_eq!(rescanned.confirmed_through, Some(rescanned.scanned_through));
        assert_eq!(load_transfer_scan(&dir, GNOSIS, &EOA), Some(rescanned));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The confirming state follows the rediscovery's status key, not the
    /// scanned wallet (antd's legacy `--postage-owner-key`): an unverified
    /// rediscovery of the owner's wallet ends `confirming` under the
    /// node's address, and its confirmation moves that to `done`.
    #[tokio::test]
    async fn confirmation_reports_under_the_status_key() {
        const NODE: [u8; 20] = [0x66; 20];
        const OWNER: [u8; 20] = [0x67; 20];
        let dir = scratch_dir("scan-confirm-status-key");
        let (client, _, _) = verified_with_unverified(Some(10_000), &[], &[]);
        wallet_scan_pending(&NODE);
        rediscovery_scan(&client, crate::GNOSIS_BZZ_TOKEN, &OWNER, &dir, false, &NODE)
            .await
            .unwrap();
        wallet_scan_done(&NODE);
        assert_eq!(
            wallet_scan_status(&NODE).unwrap().state,
            WalletScanState::Confirming
        );
        assert_eq!(wallet_scan_status(&OWNER), None);

        let (client, _, _) = verified_with_unverified(None, &[], &[]);
        confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &OWNER, &dir, &NODE)
            .await
            .unwrap()
            .expect("confirmed");
        wallet_scan_done(&NODE);
        assert_eq!(
            wallet_scan_status(&NODE).unwrap().state,
            WalletScanState::Done
        );
        wallet_scan_forget(&NODE);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R1-M1: a deploy-decision crawl over unverified blocks that is cut
    /// short saves its progress with the original provisional mark, so the
    /// next continued scan doesn't restart the six-hour wait: the next
    /// deploy decision crawls again at once.
    #[tokio::test]
    async fn an_interrupted_deploy_crawl_keeps_the_six_hour_clock() {
        let (client, v, _) = verified_with_unverified(Some(200_000), &[], &[]);
        let dir = scratch_dir("scan-crawl-clock");
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        let since = unix_now() - CONFIRM_CRAWL_AFTER_SECS - 60;
        let mut saved = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        saved.provisional_since = Some(since);
        persist_transfer_scan(&dir, &saved);

        // The refresh's tail window, two crawl windows, then a failure.
        *v.fail_after.lock().unwrap() = Some(3);
        find_owned_chequebook(
            &client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            &dir,
            true,
        )
        .await
        .expect_err("the crawl fails part-way");
        let cut = v.ranges.lock().unwrap().last().unwrap().1;
        let partial = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(partial.confirmed_through, Some(cut), "progress saved");
        assert_eq!(partial.scanned_through, saved.scanned_through, "rest kept");
        assert_eq!(partial.provisional_since, Some(since), "the clock is kept");

        // The next start goes on from there.
        *v.fail_after.lock().unwrap() = None;
        let resumed = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(resumed.provisional_since, Some(since));
        assert_eq!(
            find_cb(&client, &dir, true).await,
            None,
            "crawled at once, no new six-hour wait"
        );
        let scan = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(scan.provisional_since, None);
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R1-M2: a "none" that rests on routine verified scans only (no
    /// unverified read behind it) has nothing for a second source to vouch
    /// for, so the deploy decision confirms it window by window at once —
    /// it doesn't stamp a provisional mark nobody tracks and give up.
    #[tokio::test]
    async fn a_verified_unconfirmed_none_is_crawled_at_once() {
        let (client, v, u) = verified_with_unverified(Some(200_000), &[], &[]);
        let dir = scratch_dir("scan-verified-none");
        // Saved before the confirmed mark existed: read verified, but
        // never confirmed.
        persist_transfer_scan(
            &dir,
            &TransferScan {
                chain_id: GNOSIS,
                node_eoa: NODE_EOA,
                scanned_through: HEAD - RESCAN_TAIL,
                transfers: Vec::new(),
                confirmed_through: None,
                provisional_since: None,
                provisional_through: None,
                confirmed_above: None,
            },
        );
        assert_eq!(find_cb(&client, &dir, true).await, None, "a confirmed none");
        assert!(v.ranges.lock().unwrap().len() > 64, "crawled");
        assert!(u.ranges.lock().unwrap().is_empty());
        let scan = load_transfer_scan(&dir, GNOSIS, &NODE_EOA).unwrap();
        assert_eq!(scan.provisional_since, None);
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R1-M3: a background confirmation that fails part-way keeps what it
    /// read (with the provisional mark), so the next try goes on from
    /// there instead of losing it all.
    #[tokio::test]
    async fn a_failed_confirmation_keeps_its_progress() {
        const EOA: [u8; 20] = [0x58; 20];
        let all = [to_cb(45_000_000, [1; 32])];
        let dir = scratch_dir("scan-confirm-progress");
        let (client, _, _) = verified_with_unverified(Some(10_000), &all, &all);
        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        let since = first.provisional_since.expect("read unverified");

        // A verified route that serves the span in ~32 windows, failing
        // after two.
        let (client, v, _) = verified_with_unverified(Some(1_000_000), &all, &all);
        *v.fail_after.lock().unwrap() = Some(2);
        confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .expect_err("fails part-way");
        let cut = v.ranges.lock().unwrap()[1].1;
        let saved = load_transfer_scan(&dir, GNOSIS, &EOA).unwrap();
        assert_eq!(saved.confirmed_through, Some(cut), "progress saved");
        assert_eq!(saved.scanned_through, first.scanned_through, "rest kept");
        assert_eq!(saved.transfers, first.transfers);
        assert_eq!(saved.provisional_since, Some(since));

        v.ranges.lock().unwrap().clear();
        *v.fail_after.lock().unwrap() = None;
        let confirmed = confirm_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir, &EOA)
            .await
            .unwrap()
            .expect("confirmed");
        assert!(
            v.ranges.lock().unwrap().iter().all(|r| r.0 > cut),
            "resumed"
        );
        assert_eq!(confirmed.transfers.len(), 1);
        assert_eq!(confirmed.provisional_since, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// R1-M3: the window budget bounds a scan even when the route never
    /// refuses a window the budget's minimum width allows.
    #[tokio::test]
    async fn the_window_budget_stops_a_scan() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let topics = json!([format!("0x{}", hex::encode(ERC20_TRANSFER_TOPIC))]);
        let rest = client
            .scan_logs_with(crate::GNOSIS_BZZ_TOKEN, &topics, 1, 1_000, 1, 3, |_, _| {})
            .await
            .unwrap();
        assert_eq!(chain.ranges.lock().unwrap().len(), 3);
        assert_eq!(rest, Some(chain.ranges.lock().unwrap()[2].1 + 1));
    }

    #[test]
    fn confirmation_backs_off_to_thirty_minutes() {
        let secs: Vec<u64> = (0..7).map(|a| confirm_retry_delay(a).as_secs()).collect();
        assert_eq!(secs, [60, 120, 240, 480, 960, 1800, 1800]);
    }

    /// An unreadable saved scan means a full scan, not an error.
    #[tokio::test]
    async fn a_corrupt_saved_scan_starts_over() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-corrupt");
        std::fs::write(transfer_scan_path(&dir, GNOSIS, &NODE_EOA), b"{ truncated").unwrap();

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(chain.ranges.lock().unwrap()[0].0, GNOSIS_XBZZ_DEPLOY_BLOCK);
        assert!(
            load_transfer_scan(&dir, GNOSIS, &NODE_EOA).is_some(),
            "rewritten"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An `eth_getLogs` backend behind the `eth_blockNumber` one answers
    /// `[]` for the blocks it hasn't seen. Those blocks stay in the rescan
    /// tail, so the next scan finds the transfer instead of skipping it
    /// for good.
    #[tokio::test]
    async fn a_lagging_logs_backend_does_not_skip_a_transfer() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .logs_lag
            .store(100, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(HEAD - 90, [5; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-lag");

        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert!(first.transfers.is_empty(), "the lagging backend hid it");
        assert!(first.scanned_through < HEAD - 90, "not counted as scanned");

        chain.logs_lag.store(0, std::sync::atomic::Ordering::SeqCst);
        let second = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(second.transfers, vec![to_cb(HEAD - 90, [5; 32])]);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A scan saved against one chain isn't continued against another:
    /// its cursor says nothing about the other chain's blocks.
    #[tokio::test]
    async fn a_scan_is_not_continued_on_another_chain() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-chain");

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        chain.ranges.lock().unwrap().clear();
        chain
            .chain_id
            .store(10_200, std::sync::atomic::Ordering::SeqCst);
        let other = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(other.chain_id, 10_200);
        assert_eq!(other.confirmed_through, Some(other.scanned_through));
        assert_eq!(chain.ranges.lock().unwrap()[0].0, GNOSIS_XBZZ_DEPLOY_BLOCK);
        assert!(
            load_transfer_scan(&dir, GNOSIS, &NODE_EOA).is_some(),
            "kept"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The chequebook check helper the tests below share.
    async fn find_cb(
        client: &ChainClient,
        dir: &std::path::Path,
        confirm_none: bool,
    ) -> Option<[u8; 20]> {
        find_owned_chequebook(
            client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            dir,
            confirm_none,
        )
        .await
        .unwrap()
    }

    /// A saved scan that missed a deposit (an RPC answered one window
    /// incompletely, below the rescan tail) and that no full pass has
    /// confirmed (saved before the confirmed mark existed): the "none"
    /// check before a chequebook deploy reads the whole history again and
    /// finds it — a continued scan's "none" isn't trusted to deploy on.
    #[tokio::test]
    async fn a_missed_deposit_is_found_before_deploying() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-missed");
        let mut scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        scan.confirmed_through = None;
        persist_transfer_scan(&dir, &scan);
        // The deposit was there all along; the saved scan missed it.
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(40_000_000, [6; 32]));

        // Not about to deploy: the saved scan is read as it is.
        chain.ranges.lock().unwrap().clear();
        assert_eq!(find_cb(&client, &dir, false).await, None);
        assert_eq!(chain.ranges.lock().unwrap()[0].0, HEAD - RESCAN_TAIL + 1);

        // About to deploy: "none" is confirmed from the deploy block.
        chain.ranges.lock().unwrap().clear();
        assert_eq!(find_cb(&client, &dir, true).await, Some(CB));
        assert_eq!(
            chain.ranges.lock().unwrap().last().unwrap().0,
            GNOSIS_XBZZ_DEPLOY_BLOCK
        );
        // The rescan replaced the saved scan, so a plain refresh sees it.
        let scan = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(scan.transfers.len(), 1);
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A deposit a routine continued scan missed, above the confirmed
    /// mark, is found by the confirming check, which reads only the
    /// blocks since that mark — not the whole history again.
    #[tokio::test]
    async fn a_deposit_missed_since_the_confirmed_mark_is_found() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-missed-since");
        let first = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        let mark = first.scanned_through;
        assert_eq!(first.confirmed_through, Some(mark));

        // A later routine scan's backend lags far behind and answers `[]`
        // for a deposit below the next scan's rescan tail.
        chain
            .head
            .store(HEAD + 10_000, std::sync::atomic::Ordering::SeqCst);
        chain
            .logs_lag
            .store(10_000, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(HEAD + 2_000, [7; 32]));
        let missed = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(missed.transfers, vec![]);
        assert!(missed.scanned_through > HEAD + 2_000, "past the deposit");
        assert_eq!(missed.confirmed_through, Some(mark), "mark kept");

        chain.logs_lag.store(0, std::sync::atomic::Ordering::SeqCst);
        chain.ranges.lock().unwrap().clear();
        assert_eq!(find_cb(&client, &dir, true).await, Some(CB));
        let ranges = chain.ranges.lock().unwrap().clone();
        assert!(
            ranges.iter().all(|r| r.0 > GNOSIS_XBZZ_DEPLOY_BLOCK),
            "no full-history read: {ranges:?}"
        );
        assert_eq!(ranges.last().unwrap().0, mark + 1, "re-read from the mark");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A wallet with no chequebook whose deploy keeps failing (the caller
    /// checks again on every buy, connect, discover and restart): only the
    /// first confirming check reads the whole history; later ones read
    /// only the blocks since, even across a restart (the mark is saved).
    #[tokio::test]
    async fn repeated_none_checks_read_the_history_once() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10_000_000),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-none-repeat");
        let full_reads = || {
            chain
                .ranges
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.0 == GNOSIS_XBZZ_DEPLOY_BLOCK)
                .count()
        };

        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();
        assert_eq!(full_reads(), 1, "the startup scan");
        for step in 1..=3u64 {
            chain
                .head
                .store(HEAD + step * 2_000, std::sync::atomic::Ordering::SeqCst);
            chain.ranges.lock().unwrap().clear();
            assert_eq!(find_cb(&client, &dir, true).await, None);
            let ranges = chain.ranges.lock().unwrap().clone();
            assert_eq!(
                full_reads(),
                0,
                "check {step} re-read the history: {ranges:?}"
            );
            assert!(ranges.len() <= 2, "check {step}: {ranges:?}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A full rescan that fails part-way leaves the complete saved scan in
    /// place, so the next start continues it instead of resuming a long
    /// scan from the rescan's partial cursor.
    #[tokio::test]
    async fn a_failed_rescan_keeps_the_saved_scan() {
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(10_000_000),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        chain
            .transfers
            .lock()
            .unwrap()
            .push(to_cb(17_000_000, [8; 32]));
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-rescan-fail");
        let complete = refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .unwrap();

        *chain.fail_after.lock().unwrap() = Some(2);
        rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &NODE_EOA, &dir)
            .await
            .expect_err("the third window fails");
        assert_eq!(
            load_transfer_scan(&dir, GNOSIS, &NODE_EOA),
            Some(complete.clone()),
            "the complete scan is kept"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A full rescan that failed part-way is continued by the next one in
    /// the process (antd's retry of `--rescan-chain-history`), not read
    /// again from the deploy block, and the completed rescan replaces the
    /// saved scan, confirmed to its head.
    #[tokio::test]
    async fn a_failed_rescan_is_continued_by_the_next() {
        const EOA: [u8; 20] = [0x64; 20];
        let chain = std::sync::Arc::new(GrowingChain {
            cap: Some(1_000_000),
            ..GrowingChain::default()
        });
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-rescan-resume");
        refresh_transfer_scan(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();

        chain.ranges.lock().unwrap().clear();
        *chain.fail_after.lock().unwrap() = Some(3);
        rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .expect_err("the fourth window fails");
        let first = chain.ranges.lock().unwrap().clone();
        assert_eq!(first.len(), 3, "{first:?}");
        assert_eq!(first[0].0, GNOSIS_XBZZ_DEPLOY_BLOCK);
        let read_through = first.last().unwrap().1;

        chain.ranges.lock().unwrap().clear();
        *chain.fail_after.lock().unwrap() = None;
        let scan = rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        let second = chain.ranges.lock().unwrap().clone();
        assert_eq!(
            second.first().map(|r| r.0),
            Some(read_through + 1),
            "continued where the failed rescan stopped: {second:?}"
        );
        assert_eq!(scan.confirmed_through, Some(scan.scanned_through));
        assert_eq!(load_transfer_scan(&dir, GNOSIS, &EOA), Some(scan));

        // Done: the next rescan reads the history again.
        chain.ranges.lock().unwrap().clear();
        rescan_transfer_history(&client, crate::GNOSIS_BZZ_TOKEN, &EOA, &dir)
            .await
            .unwrap();
        assert_eq!(
            chain.ranges.lock().unwrap().first().map(|r| r.0),
            Some(GNOSIS_XBZZ_DEPLOY_BLOCK)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A chequebook check on a scan that was itself read from the deploy
    /// block doesn't scan the history a second time.
    #[tokio::test]
    async fn a_first_scan_is_not_rescanned_to_confirm_none() {
        let chain = std::sync::Arc::new(GrowingChain::default());
        chain.head.store(HEAD, std::sync::atomic::Ordering::SeqCst);
        let client = ChainClient::new("http://127.0.0.1:1").with_transport(Some(chain.clone()));
        let dir = scratch_dir("scan-first-none");
        let found = find_owned_chequebook(
            &client,
            &crate::chequebook::GNOSIS_CHEQUEBOOK_FACTORY,
            crate::GNOSIS_POSTAGE_STAMP,
            crate::GNOSIS_BZZ_TOKEN,
            &NODE_EOA,
            &dir,
            true,
        )
        .await
        .unwrap();
        assert_eq!(found, None);
        assert_eq!(chain.ranges.lock().unwrap().len(), 1, "one scan");
        std::fs::remove_dir_all(&dir).ok();
    }
}
