//! Deep block anchors: where a by-number read below the 512-block window verifies.
//!
//! The rule is `.claude/agent/data-sources.md` (Trust, "The bundled checkpoint table"); the
//! design is `docs/ideas/deep-block-verification.md`, "Serving block N". A block `n` deeper
//! than the window verifies with one header window `[n ..= a]` hash-linked up to an anchor
//! `a` at most [`K`] - 1 blocks above it:
//!
//! - **At or below the table's top:** the table's anchor
//!   ([`CheckpointTable::anchor_at_or_above`]).
//! - **Above the top (the gap since the table's build):** a hash this node linked itself from
//!   an attested finalized block. [`DeepAnchors::plan`] names the anchor when one is close
//!   enough, else the next window to walk down from the lowest linked hash above `n`. Each
//!   verified window is recorded with [`DeepAnchors::record_window`], which keeps every
//!   1024th block's hash and the window's bottom. The gap closes lazily, only as far down as
//!   a read needs.
//! - **The alarm:** a recorded window that covers the table's top must carry the top's hash.
//!   A mismatch means the table and the beacon chain disagree. Every read resting on the
//!   table is then refused, permanently ([`ALARM_PREFIX`]), and never outvoted.
//!
//! Finality is never reorganized, so a hash linked from a finalized block stays canonical.
//! The linked hashes, the check of the top and the alarm are kept beside the table, in a
//! small file under the data dir (`deep-anchors[-net].txt`, keyed by the table's pin, so a
//! new table starts afresh), and survive a restart. A reader without a data dir keeps them in
//! memory only, and says so in its log. A running node never writes into the
//! bundled table. The fetching and verifying of a window is the reader's.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use myotis_core::checkpoints::CheckpointTable;

/// The stride: an anchor is at most `K - 1` blocks above the block it serves, so a walk is
/// at most `K` headers (geth's `GetBlockHeaders` limit).
pub(crate) const K: u64 = CheckpointTable::K;

/// The start of every refusal the alarm causes. The engine's hosts answer an error that
/// starts with it with the permanent `-32602`, not the retryable `-32000`.
pub const ALARM_PREFIX: &str = "checkpoint table alarm:";

/// What a deep read at `n` needs next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Verify `[n ..= number]` against this hash: one window of at most `K` headers.
    Anchor { number: u64, hash: [u8; 32] },
    /// First walk the window `[from ..= top.0]` anchored at `top`, record it, and plan again.
    Walk { from: u64, top: (u64, [u8; 32]) },
    /// Refused for good (the alarm).
    Refused,
}

/// The deep anchors of one reader: its network's table, if one is bundled, and the hashes
/// it linked above the table's top.
#[derive(Debug, Default)]
pub(crate) struct DeepAnchors {
    table: Option<CheckpointTable<'static>>,
    /// The file the state is kept in, or `None` to keep it in memory only.
    store: Option<PathBuf>,
    state: Mutex<Linked>,
    /// Held by the reader during a gap walk, so concurrent reads in the same gap do not
    /// fetch the same window twice.
    pub(crate) walk_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default)]
struct Linked {
    /// Block number → hash, each linked from an attested finalized block.
    hashes: BTreeMap<u64, [u8; 32]>,
    /// Set once a recorded window disagreed with the table's top.
    alarm: Option<String>,
    /// Set once a recorded window carried the table's top with its hash.
    top_checked: bool,
    /// Set once the light client was re-anchored on a fresh checkpoint (STALE_ANCHOR):
    /// an alarm then names both anchors as in doubt (the rule's last sub-bullet).
    reanchored: bool,
    /// The anchor's re-anchor count this state was linked under (`ExecAnchor::reanchors`,
    /// per process).
    reanchors_seen: u64,
}

impl DeepAnchors {
    /// The anchors for `chain_id`: its bundled table, if any, and the state kept in `store`
    /// for that table. A table that fails its pin is logged and left out, so the reads it
    /// would serve keep today's refusal.
    pub(crate) fn for_chain(chain_id: u64, store: Option<PathBuf>) -> Self {
        let table = table_for(chain_id);
        let state = match (&table, &store) {
            (Some(t), Some(path)) => load(path, &pin_key(t)),
            _ => Linked::default(),
        };
        if let Some(alarm) = &state.alarm {
            tracing::error!(alarm = %alarm, "deep block reads refused (kept from an earlier run)");
        }
        if table.is_some() && store.is_none() {
            tracing::warn!(chain_id, "no data dir: the deep anchors' state (alarm included) is kept in memory only");
        }
        Self { table, store: store.filter(|_| table.is_some()), state: Mutex::new(state), ..Self::default() }
    }

    #[cfg(test)]
    pub(crate) fn with_table(table: CheckpointTable<'static>) -> Self {
        Self { table: Some(table), ..Self::default() }
    }

    /// The light client's re-anchor count is `reanchors` (`ExecAnchor::reanchors`). When it
    /// moved, what was linked under the old anchor is dropped (the top's check with it), and
    /// the state remembers the re-anchor, so a later alarm names both anchors.
    pub(crate) fn observe_reanchors(&self, reanchors: u64) {
        let text = {
            let Ok(mut state) = self.state.lock() else { return };
            if state.reanchors_seen == reanchors {
                return;
            }
            tracing::warn!(reanchors, "re-anchored: the hashes linked under the old anchor are dropped");
            state.reanchors_seen = reanchors;
            state.hashes.clear();
            state.top_checked = false;
            state.reanchored = true;
            self.table.as_ref().map(|t| render_store(&pin_key(t), &state))
        };
        if let (Some(text), Some(path)) = (text, &self.store) {
            if let Err(e) = save(path, &text) {
                tracing::warn!(path = %path.display(), error = %e, "deep anchors not saved");
            }
        }
    }

    /// The alarm's message, once raised.
    pub(crate) fn alarm(&self) -> Option<String> {
        self.state.lock().ok().and_then(|s| s.alarm.clone())
    }

    /// What a read at `n` needs, given the attested finalized block `fin` (`n <= fin.0`).
    /// `None` without a table: the caller keeps today's refusal.
    pub(crate) fn plan(&self, n: u64, fin: (u64, [u8; 32])) -> Option<Plan> {
        let table = self.table.as_ref()?;
        let state = self.state.lock().ok()?;
        if state.alarm.is_some() {
            return Some(Plan::Refused);
        }
        if let Some((number, hash)) = table.anchor_at_or_above(n) {
            return Some(Plan::Anchor { number, hash });
        }
        // The lowest linked hash at or above `from`, or the finalized block itself.
        let lowest_from = |from: u64| {
            state
                .hashes
                .range(from..)
                .next()
                .map(|(k, v)| (*k, *v))
                .filter(|(k, _)| *k <= fin.0)
                .unwrap_or(fin)
        };
        let top = table.top().0;
        // A read within K of the top closes the gap: walk down to the top first, so
        // record_window checks it against the table. Each step records its bottom, which
        // lowers the lowest linked hash above the top, until a window covers the top.
        if n - top < K && !state.top_checked {
            let low = lowest_from(top);
            return Some(Plan::Walk { from: top.max(low.0.saturating_sub(K - 1)), top: low });
        }
        // The gap: each step records its bottom, which is above n, so it ends.
        let above = lowest_from(n);
        Some(if above.0 - n >= K {
            Plan::Walk { from: above.0 - (K - 1), top: above }
        } else {
            Plan::Anchor { number: above.0, hash: above.1 }
        })
    }

    /// Record a window `headers` (ascending `(number, hash)`, contiguous) that the caller
    /// verified up to an attested finalized block or a hash linked from one. Keeps every
    /// `K`-th block and the bottom, and checks the table's top when the window covers it.
    /// Returns the alarm's message when this window raised it.
    pub(crate) fn record_window(&self, headers: &[(u64, [u8; 32])]) -> Option<String> {
        // Rendered under the lock, written after it: plan and alarm never wait on the disk.
        let (raised, text) = {
            let mut state = self.state.lock().ok()?;
            let raised = self.record_locked(&mut state, headers);
            let text = self.table.as_ref().map(|t| render_store(&pin_key(t), &state));
            (raised, text)
        };
        if let (Some(text), Some(path)) = (text, &self.store) {
            if let Err(e) = save(path, &text) {
                tracing::warn!(path = %path.display(), error = %e, "deep anchors not saved");
            }
        }
        raised
    }

    fn record_locked(&self, state: &mut Linked, headers: &[(u64, [u8; 32])]) -> Option<String> {
        if let (Some(table), Some(first), Some(last)) = (&self.table, headers.first(), headers.last()) {
            let (top_number, top_hash) = table.top();
            if (first.0..=last.0).contains(&top_number) {
                let seen = headers.iter().find(|(n, _)| *n == top_number).map(|(_, h)| *h);
                if seen == Some(top_hash) {
                    state.top_checked = true;
                } else {
                    let doubt = if state.reanchored {
                        "; the light client was re-anchored on a fresh checkpoint at a stale \
                         anchor, so either the table or that checkpoint is wrong"
                    } else {
                        ""
                    };
                    let msg = format!(
                        "{ALARM_PREFIX} block {top_number}, linked from the attested finalized \
                         block, is not the bundled table's top {}{doubt}",
                        hex(&top_hash)
                    );
                    tracing::error!(alarm = %msg, "deep block reads refused");
                    state.alarm = Some(msg.clone());
                    return Some(msg);
                }
            }
        }
        for (i, (number, hash)) in headers.iter().enumerate() {
            if i == 0 || number % K == 0 {
                state.hashes.insert(*number, *hash);
            }
        }
        None
    }
}

/// The bundled table for `chain_id`, parsed (its pin checked: a hash of the whole table)
/// once per process, not on every reader start.
fn table_for(chain_id: u64) -> Option<CheckpointTable<'static>> {
    static MAINNET: std::sync::OnceLock<Option<CheckpointTable<'static>>> = std::sync::OnceLock::new();
    let parse = || match myotis_core::checkpoints::for_chain(chain_id) {
        Some(Ok(t)) => Some(t),
        Some(Err(e)) => {
            tracing::error!(chain_id, error = %e, "bundled checkpoint table refused");
            None
        }
        None => None,
    };
    match chain_id {
        1 => *MAINNET.get_or_init(parse),
        _ => parse(),
    }
}

/// The alarm kept in the state file at `path`, if any, whatever else the file holds: what
/// a status reports while no reader runs (a paused handle).
pub fn stored_alarm(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| l.strip_prefix("alarm ").map(str::to_string))
}

/// The state file of a reader whose EL peer cache is `cache_path`
/// (`peers[-net].cache` → `deep-anchors[-net].txt`, beside it).
pub fn store_path(cache_path: &std::path::Path) -> Option<PathBuf> {
    let suffix = cache_path.file_stem()?.to_str()?.strip_prefix("peers")?.to_string();
    Some(cache_path.with_file_name(format!("deep-anchors{suffix}.txt")))
}

/// The key a kept state belongs to: the table's top, which a new table moves.
fn pin_key(table: &CheckpointTable<'_>) -> String {
    let (number, hash) = table.top();
    format!("{number} {}", hex(&hash))
}

const STORE_MAGIC: &str = "myotis deep anchors v1";

/// The state kept for the table `key` in `path`; empty when the file is missing, belongs to
/// another table, or does not parse (it is rebuilt by the next walks).
fn load(path: &std::path::Path, key: &str) -> Linked {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Linked::default(),
        Err(e) => {
            // Fail closed on the alarm: a file we cannot read may hold one.
            tracing::error!(path = %path.display(), error = %e, "deep anchors file unreadable");
            return Linked { alarm: Some(format!("{ALARM_PREFIX} the kept state is unreadable ({e})")), ..Default::default() };
        }
    };
    parse_store(&text, key).unwrap_or_else(|| {
        tracing::warn!(path = %path.display(), "deep anchors file of another table: starting afresh");
        Linked::default()
    })
}

/// The state kept for the table `key`, or `None` when the file belongs to another table.
/// Fail closed: an `alarm` line counts wherever it stands, even in a file of another table
/// or one torn by a crash; a line that does not parse is skipped, never the whole file.
fn parse_store(text: &str, key: &str) -> Option<Linked> {
    let alarm = text.lines().find_map(|l| l.strip_prefix("alarm ").map(str::to_string));
    let mut lines = text.lines();
    let ours = lines.next() == Some(STORE_MAGIC) && lines.next().and_then(|l| l.strip_prefix("table ")) == Some(key);
    if !ours {
        return alarm.map(|alarm| Linked { alarm: Some(alarm), ..Default::default() });
    }
    let mut out = Linked { alarm, ..Default::default() };
    for line in lines {
        if line == "checked" {
            out.top_checked = true;
        } else if line == "reanchored" {
            out.reanchored = true;
        } else if line.starts_with("alarm ") {
            // taken above
        } else if let Some((number, hash)) = parse_linked(line) {
            out.hashes.insert(number, hash);
        } else {
            tracing::warn!(line, "deep anchors: a line that does not parse is skipped");
        }
    }
    Some(out)
}

fn parse_linked(line: &str) -> Option<(u64, [u8; 32])> {
    let (number, hash) = line.split_once(' ')?;
    let hash = hash.strip_prefix("0x")?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut h = [0u8; 32];
    for (i, byte) in h.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hash.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some((number.parse().ok()?, h))
}

fn render_store(key: &str, state: &Linked) -> String {
    let mut out = format!("{STORE_MAGIC}\ntable {key}\n");
    if state.top_checked {
        out.push_str("checked\n");
    }
    if state.reanchored {
        out.push_str("reanchored\n");
    }
    if let Some(alarm) = &state.alarm {
        out.push_str(&format!("alarm {}\n", alarm.replace('\n', " ")));
    }
    for (number, hash) in &state.hashes {
        out.push_str(&format!("{number} {}\n", hex(hash)));
    }
    out
}

/// Written whole to a sibling and renamed over the file, so a crash leaves the old state.
fn save(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("txt.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(text.as_bytes())?;
    // Durable before it replaces the old state: an alarm must survive a power loss.
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::checkpoints::{CheckpointTable, TablePin};
    use myotis_core::keccak::keccak256;

    /// A table of 3 entries (blocks 0, 1024, 2048) with its top at 2100.
    fn table() -> CheckpointTable<'static> {
        let bytes: &'static [u8] = Box::leak((0..3u8).flat_map(|i| [i; 32]).collect::<Vec<_>>().into());
        let pin = TablePin {
            keccak256: keccak256(bytes),
            entries: 3,
            genesis_hash: [0; 32],
            top_number: 2100,
            top_hash: [0x21; 32],
        };
        CheckpointTable::parse_for_test(bytes, &pin).unwrap()
    }

    fn h(n: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn the_state_survives_a_restart_and_a_new_table_starts_afresh() {
        let mut linked = Linked::default();
        linked.hashes.insert(4096, h(4096));
        linked.hashes.insert(3977, h(3977));
        linked.top_checked = true;
        linked.alarm = Some(format!("{ALARM_PREFIX} test"));
        let text = render_store("2100 0x21", &linked);
        let back = parse_store(&text, "2100 0x21").expect("parses");
        assert_eq!(back.hashes, linked.hashes);
        assert!(back.top_checked);
        assert_eq!(back.alarm, linked.alarm);
        // Another table's state starts afresh, but its alarm stands (fail closed).
        let other = parse_store(&text, "3000 0x30").expect("its alarm");
        assert!(other.hashes.is_empty() && other.alarm.is_some());
        assert!(parse_store("garbage", "2100 0x21").is_none());
        // A torn file keeps what parses, and its alarm.
        let torn = format!("{text}12 0xzz\n7");
        let back = parse_store(&torn, "2100 0x21").unwrap();
        assert_eq!(back.hashes, linked.hashes);
        assert!(back.alarm.is_some());
        assert_eq!(stored_alarm_text(&torn), back.alarm);

        // Through the file: an alarm raised in one run refuses in the next.
        let dir = std::env::temp_dir().join(format!("myotis-deep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("deep-anchors.txt");
        let d = DeepAnchors { store: Some(path.clone()), ..DeepAnchors::with_table(table()) };
        let bad: Vec<_> = (2090..=2110).map(|n| (n, h(n))).collect();
        assert!(d.record_window(&bad).is_some());
        let key = pin_key(&table());
        let again = load(&path, &key);
        assert!(again.alarm.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn stored_alarm_text(text: &str) -> Option<String> {
        text.lines().find_map(|l| l.strip_prefix("alarm ").map(str::to_string))
    }

    #[test]
    fn a_reanchor_drops_what_was_linked_and_names_both_anchors() {
        let d = DeepAnchors::with_table(table());
        let fin = (6000, h(6000));
        let window: Vec<_> = (4977..=6000).map(|n| (n, h(n))).collect();
        d.record_window(&window);
        assert_eq!(d.plan(5500, fin), Some(Plan::Anchor { number: 6000, hash: h(6000) }));
        d.observe_reanchors(0); // unchanged: nothing happens
        assert_eq!(d.state.lock().unwrap().hashes.len(), 2);
        d.observe_reanchors(1);
        assert!(d.state.lock().unwrap().hashes.is_empty());
        let bad: Vec<_> = (2090..=2110).map(|n| (n, h(n))).collect();
        let msg = d.record_window(&bad).unwrap();
        assert!(msg.contains("re-anchored"), "{msg}");
    }

    #[test]
    fn the_store_sits_beside_the_peer_cache() {
        let p = std::path::Path::new("/data/peers-sepolia.cache");
        assert_eq!(store_path(p), Some(PathBuf::from("/data/deep-anchors-sepolia.txt")));
        assert_eq!(store_path(std::path::Path::new("/data/peers.cache")), Some(PathBuf::from("/data/deep-anchors.txt")));
        assert_eq!(store_path(std::path::Path::new("/data/other.cache")), None);
    }

    #[test]
    fn no_table_no_plan() {
        let d = DeepAnchors::default();
        assert_eq!(d.plan(5, (10_000, h(10_000))), None);
    }

    #[test]
    fn below_the_top_the_table_anchors() {
        let d = DeepAnchors::with_table(table());
        assert_eq!(d.plan(1, (9000, h(9000))), Some(Plan::Anchor { number: 1024, hash: [1; 32] }));
        assert_eq!(d.plan(2100, (9000, h(9000))), Some(Plan::Anchor { number: 2100, hash: [0x21; 32] }));
    }

    #[test]
    fn the_gap_walks_down_lazily_and_then_anchors() {
        let d = DeepAnchors::with_table(table());
        let fin = (6000, h(6000));
        // 3500 is 2500 below finality (and K or more above the top 2100): walk
        // [4977 ..= 6000] first.
        assert_eq!(d.plan(3500, fin), Some(Plan::Walk { from: 6000 - 1023, top: fin }));
        let window: Vec<_> = (4977..=6000).map(|n| (n, h(n))).collect();
        assert_eq!(d.record_window(&window), None);
        // Then [3954 ..= 4977] from the window's bottom.
        assert_eq!(d.plan(3500, fin), Some(Plan::Walk { from: 4977 - 1023, top: (4977, h(4977)) }));
        let window: Vec<_> = (3954..=4977).map(|n| (n, h(n))).collect();
        assert_eq!(d.record_window(&window), None);
        // Now the bottom 3954 is within K of 3500.
        assert_eq!(d.plan(3500, fin), Some(Plan::Anchor { number: 3954, hash: h(3954) }));
        // A read near a recorded multiple of K anchors there (4096 is in the second window).
        assert_eq!(d.plan(4000, fin), Some(Plan::Anchor { number: 4096, hash: h(4096) }));
        // A read just below finality anchors at finality directly (6000 was the first
        // window's top, which is not kept: neither a multiple of K nor a bottom).
        assert_eq!(d.plan(5500, fin), Some(Plan::Anchor { number: 6000, hash: h(6000) }));
    }

    #[test]
    fn a_linked_hash_above_finality_is_not_used() {
        // A hash linked from a later finalized block than the one the caller holds now is
        // still canonical, but the caller's window must end at or below its own anchor.
        let d = DeepAnchors::with_table(table());
        d.record_window(&[(8000, h(8000))]);
        assert_eq!(d.plan(4000, (4500, h(4500))), Some(Plan::Anchor { number: 4500, hash: h(4500) }));
    }

    #[test]
    fn a_read_near_the_top_walks_to_the_top_once() {
        let d = DeepAnchors::with_table(table());
        let fin = (2600, h(2600));
        // 2200 is within K of the top 2100: walk [2100 ..= 2600] so the top is checked.
        assert_eq!(d.plan(2200, fin), Some(Plan::Walk { from: 2100, top: fin }));
        let window: Vec<_> =
            (2100..=2600).map(|n| (n, if n == 2100 { [0x21; 32] } else { h(n) })).collect();
        assert_eq!(d.record_window(&window), None);
        // Checked: the read anchors at finality.
        assert_eq!(d.plan(2200, fin), Some(Plan::Anchor { number: 2600, hash: h(2600) }));
        // The walk stops at the top: a far read walks down to it, then checks it.
        let d = DeepAnchors::with_table(table());
        let fin = (4000, h(4000));
        assert_eq!(d.plan(2200, fin), Some(Plan::Walk { from: 4000 - 1023, top: fin }));
        let window: Vec<_> = (2977..=4000).map(|n| (n, h(n))).collect();
        d.record_window(&window);
        assert_eq!(d.plan(2200, fin), Some(Plan::Walk { from: 2100, top: (2977, h(2977)) }));
    }

    /// Drive plan + record_window to the end with a well-behaved chain, as the reader does.
    fn drive(d: &DeepAnchors, n: u64, fin: (u64, [u8; 32])) -> (Plan, usize) {
        for steps in 0..64 {
            match d.plan(n, fin).unwrap() {
                Plan::Walk { from, top } => {
                    assert!(top.0 - from < K, "a walk is at most K headers");
                    let w: Vec<_> = (from..=top.0)
                        .map(|b| (b, if b == 2100 { [0x21; 32] } else if b == top.0 { top.1 } else { h(b) }))
                        .collect();
                    assert_eq!(d.record_window(&w), None);
                }
                done => return (done, steps),
            }
        }
        panic!("the walk for {n} did not end");
    }

    #[test]
    fn every_gap_read_ends_in_an_anchor() {
        // The review's case: n = 3100 is within K of the top 2100, finality at 3500. The
        // first window [2477 ..= 3500] holds nothing at or above 3100 but the top of it.
        let d = DeepAnchors::with_table(table());
        let (plan, steps) = drive(&d, 3100, (3500, h(3500)));
        assert_eq!(plan, Plan::Anchor { number: 3500, hash: h(3500) });
        assert_eq!(steps, 2);
        // Every block of the gap, on fresh state, far and near the top.
        for n in (2101..9000).step_by(37) {
            let d = DeepAnchors::with_table(table());
            let fin = (9000, h(9000));
            let (plan, _) = drive(&d, n, fin);
            let Plan::Anchor { number, .. } = plan else { panic!("{n}: {plan:?}") };
            assert!(number >= n && number - n < K, "{n} → {number}");
        }
    }

    #[test]
    fn a_window_over_the_top_must_carry_its_hash() {
        let d = DeepAnchors::with_table(table());
        let good: Vec<_> = (2090..=2110).map(|n| (n, if n == 2100 { [0x21; 32] } else { h(n) })).collect();
        assert_eq!(d.record_window(&good), None);
        assert_eq!(d.alarm(), None);

        let bad: Vec<_> = (2090..=2110).map(|n| (n, h(n))).collect();
        let msg = d.record_window(&bad).expect("the alarm");
        assert!(msg.starts_with(ALARM_PREFIX), "{msg}");
        assert_eq!(d.alarm(), Some(msg));
        // Every read resting on the table is refused from then on, below the top too.
        assert_eq!(d.plan(1, (9000, h(9000))), Some(Plan::Refused));
        assert_eq!(d.plan(3000, (9000, h(9000))), Some(Plan::Refused));
    }
}
