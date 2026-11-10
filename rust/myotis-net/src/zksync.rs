//! ZK sync — fetch and verify Colibri's proof of the committee of one period
//! (docs/how-it-works/zk-sync.md). The proof itself is checked in
//! `myotis_consensus::zk`; this module is the I/O around it: which servers, which
//! file, how long to wait, and the per-run back-off that keeps a failing source
//! from costing more than one request per cycle.
//!
//! The servers are trusted for availability only. A proof that does not verify
//! under this engine's own pinned program, anchor, fork schedule and genesis
//! validators root is discarded exactly like a bad peer response, and the sync
//! loop carries on with the light-client update walk.

use std::time::{Duration, Instant};

use myotis_consensus::zk::{self, ProvenCommittee, ZkChain, ZkSyncData};

use crate::https;
use crate::sync::ChainConfig;

/// Where a network's proofs come from and which proof chain they belong to.
#[derive(Debug, Clone)]
pub struct ZkSyncConfig {
    /// Colibri provers serving `period_store/<period>/zk_proof.ssz`, tried in
    /// order. Every one serves the same proof chain (one anchor per network).
    pub base_urls: Vec<String>,
    /// The anchor committee root of that chain (`myotis_consensus::zk::anchors`).
    pub anchor_keys_root: [u8; 32],
    /// Use a proof only when the store would otherwise walk at least this many
    /// periods. One update is as cheap as the proof plus a finality update, and
    /// stays on the wallet's own anchor, so a single-period catch-up walks.
    pub min_gap_periods: u64,
}

impl ZkSyncConfig {
    fn colibri(net: &str, anchor_keys_root: [u8; 32]) -> Self {
        Self {
            base_urls: vec![
                format!("https://{net}.colibri-proof.tech"),
                format!("https://{net}1.colibri-proof.tech"),
            ],
            anchor_keys_root,
            min_gap_periods: 2,
        }
    }
    pub fn mainnet() -> Self {
        Self::colibri("mainnet", zk::anchors::MAINNET)
    }
    pub fn sepolia() -> Self {
        Self::colibri("sepolia", zk::anchors::SEPOLIA)
    }
    pub fn gnosis() -> Self {
        Self::colibri("gnosis", zk::anchors::GNOSIS)
    }
}

const FETCH_DEADLINE: Duration = Duration::from_secs(20);

/// Whether a ZK start may run at all right now: never while Tor routing is on.
/// The fetch resolves `<net>.colibri-proof.tech` through the system resolver and
/// names it in clear SNI, the same disclosure of "this node runs network X"
/// that #539 keeps the EIP-1459 DNS walk from making under Tor
/// (`el::dnsdisco::allowed`). The update walk is the fallback either way.
pub fn allowed() -> bool {
    #[cfg(feature = "tor")]
    {
        !crate::el::tor::is_enabled()
    }
    #[cfg(not(feature = "tor"))]
    {
        true
    }
}

/// Fetch the proof of `period`'s committee and verify it. `Err` carries a
/// one-line reason for the log; every failure means "walk instead".
pub async fn fetch_proven_committee(config: &ChainConfig, zk_config: &ZkSyncConfig, period: u64) -> Result<ProvenCommittee, String> {
    let mut reasons = Vec::new();
    for base in &zk_config.base_urls {
        let url = format!("{}/period_store/{period}/zk_proof.ssz", base.trim_end_matches('/'));
        let resp = match https::get(&url, "application/octet-stream", zk::MAX_FILE_LEN, FETCH_DEADLINE).await {
            Ok(r) => r,
            Err(e) => {
                reasons.push(format!("{base}: {e}"));
                continue;
            }
        };
        if resp.status != 200 {
            reasons.push(format!("{base}: HTTP {}", resp.status));
            continue;
        }
        let data = match ZkSyncData::decode(&resp.body) {
            Ok(d) => d,
            Err(e) => {
                reasons.push(format!("{base}: {e}"));
                continue;
            }
        };
        // ~10 ms of pairings and 512 key validations: off the async workers.
        let fork_schedule = config.fork_schedule.clone();
        let gvr = config.genesis_validators_root;
        let slots_per_period = config.slots_per_period();
        let anchor = zk_config.anchor_keys_root;
        let verdict = tokio::task::spawn_blocking(move || {
            zk::verify_zk_sync_data(
                &data,
                period,
                &ZkChain {
                    anchor_keys_root: anchor,
                    fork_schedule: &fork_schedule,
                    genesis_validators_root: gvr,
                    slots_per_period,
                },
            )
        })
        .await
        .map_err(|e| e.to_string())?;
        match verdict {
            Ok(proven) => return Ok(proven),
            Err(e) => reasons.push(format!("{base}: {e}")),
        }
    }
    Err(reasons.join("; "))
}

/// Per-run back-off for ZK attempts: the next attempt is due only after the
/// last failure's wait — short when the cause is transient by nature (the
/// period's proof not published yet, finality not across the boundary), long
/// otherwise. Never persisted: a restart tries again at once.
#[derive(Debug)]
pub struct ZkBackoff {
    next_at: Option<Instant>,
}

impl ZkBackoff {
    pub const SHORT: Duration = Duration::from_secs(60);
    pub const LONG: Duration = Duration::from_secs(15 * 60);

    pub fn new() -> Self {
        Self { next_at: None }
    }
    pub fn due(&self, now: Instant) -> bool {
        self.next_at.is_none_or(|t| now >= t)
    }
    pub fn failed(&mut self, now: Instant, wait: Duration) {
        self.next_at = Some(now + wait);
    }
    pub fn succeeded(&mut self) {
        self.next_at = None;
    }
}

impl Default for ZkBackoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_waits_then_allows() {
        let t0 = Instant::now();
        let mut b = ZkBackoff::new();
        assert!(b.due(t0));
        b.failed(t0, ZkBackoff::SHORT);
        assert!(!b.due(t0 + Duration::from_secs(59)));
        assert!(b.due(t0 + Duration::from_secs(60)));
        b.succeeded();
        assert!(b.due(t0));
    }

    #[test]
    fn urls_follow_colibri_naming() {
        let c = ZkSyncConfig::gnosis();
        assert_eq!(c.base_urls, vec!["https://gnosis.colibri-proof.tech", "https://gnosis1.colibri-proof.tech"]);
        assert_eq!(c.anchor_keys_root, zk::anchors::GNOSIS);
    }
}
