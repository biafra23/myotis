//! The Nimbus beacon REST client — roost's only upstream.
//!
//! roost does **not** peer with Nimbus over libp2p. A libp2p connection over
//! 127.0.0.1 is still a libp2p connection: `getIncomingSlot()` does not care
//! about the source address, so loopback buys nothing against Nimbus's shared
//! connection semaphore. The REST API is a genuinely different door — outside
//! the peer table entirely, with no semaphore, no trimmer and no peer scoring —
//! which is what makes "roost can always reach the newest update" true
//! unconditionally rather than only while Nimbus has slots free.
//!
//! Requires Nimbus's `--rest` (off by default, binds 127.0.0.1) plus
//! `--light-client-data-serve=true`.
//!
//! # SSZ, not JSON
//!
//! Every LC endpoint is fetched with `Accept: application/octet-stream`.
//! Verified against Nimbus v26.7.0 on zbox: all four answer 200 with SSZ, at
//! roughly half the bytes of the JSON encoding. This is what lets roost be a
//! **byte cache** — fetch, wrap, serve — with no light-client type modelling on
//! our side, and it keeps what we serve a verbatim relay of what Nimbus produced
//! rather than a re-encode.
//!
//! `/eth/v1/events` is deliberately absent. It may later be used as a
//! *notification* to trigger a refetch, but never as a data source: it is
//! `text/event-stream` with JSON payloads and no SSZ negotiation, so consuming
//! its bodies would reintroduce exactly the modelling this design avoids.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};

/// Slots per sync-committee period: `SLOTS_PER_EPOCH (32) *
/// EPOCHS_PER_SYNC_COMMITTEE_PERIOD (256)`.
pub const SLOTS_PER_PERIOD: u64 = 32 * 256;

/// The spec's `MAX_REQUEST_LIGHT_CLIENT_UPDATES`. Enforced here as well as on
/// the serving side: a caller-controlled count must never fan out into an
/// unbounded upstream fetch.
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

/// The sync-committee period a slot falls in.
pub fn period_of_slot(slot: u64) -> u64 {
    slot / SLOTS_PER_PERIOD
}

/// An SSZ response body plus the fork name Nimbus tagged it with.
#[derive(Debug, Clone)]
pub struct SszResponse {
    pub bytes: Vec<u8>,
    /// `Eth-Consensus-Version` — a fork *name* (e.g. "fulu").
    ///
    /// Note what this is and is not: since EIP-7892 the fork digest is not a
    /// function of the name (it folds in the active blob parameters), so this
    /// header is **not** sufficient to derive context bytes. It is recorded for
    /// diagnostics and for the single-object endpoints, where the digest has to
    /// be computed from the object's slot rather than read off the wire. The
    /// `updates` endpoint needs none of this: it frames a real digest per chunk,
    /// which roost re-emits verbatim.
    pub consensus_version: Option<String>,
}

/// Blocking-free client over Nimbus's REST API.
#[derive(Debug, Clone)]
pub struct NimbusRest {
    http: reqwest::Client,
    base: String,
}

impl NimbusRest {
    /// `base` is the REST root, e.g. `http://127.0.0.1:5052`.
    pub fn new(base: impl Into<String>, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("building the reqwest client")?;
        Ok(Self {
            http,
            base: base.into().trim_end_matches('/').to_string(),
        })
    }

    async fn get_ssz(&self, path: &str) -> Result<SszResponse> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        let status = resp.status();
        let consensus_version = resp
            .headers()
            .get("eth-consensus-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if !status.is_success() {
            return Err(anyhow!("GET {url} -> HTTP {status}"));
        }
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("reading body of {url}"))?
            .to_vec();

        Ok(SszResponse {
            bytes,
            consensus_version,
        })
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .with_context(|| format!("reading body of {url}"))?;
        if !status.is_success() {
            return Err(anyhow!("GET {url} -> HTTP {status}: {text}"));
        }
        serde_json::from_str(&text).with_context(|| format!("parsing JSON from {url}"))
    }

    // --- the four light-client endpoints ---------------------------------

    /// One-shot trust anchor, keyed by an arbitrary block root.
    ///
    /// Arbitrary keying is what makes bootstraps the awkward case for caching —
    /// unbounded and genuinely miss-prone — which is why the design pre-populates
    /// only checkpoint-aligned roots and refuses the rest.
    pub async fn bootstrap(&self, block_root: &[u8; 32]) -> Result<SszResponse> {
        self.get_ssz(&format!(
            "/eth/v1/beacon/light_client/bootstrap/0x{}",
            hex::encode(block_root)
        ))
        .await
    }

    /// Per-period sync-committee updates.
    ///
    /// The body is a concatenation of length-prefixed chunks — see
    /// [`crate::framing::split_updates`]. An empty body means "below the node's
    /// light-client window", not an error.
    pub async fn updates(&self, start_period: u64, count: u64) -> Result<SszResponse> {
        if count == 0 {
            return Err(anyhow!("updates: count must be >= 1"));
        }
        if count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
            return Err(anyhow!(
                "updates: count {count} exceeds MAX_REQUEST_LIGHT_CLIENT_UPDATES ({MAX_REQUEST_LIGHT_CLIENT_UPDATES})"
            ));
        }
        self.get_ssz(&format!(
            "/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}"
        ))
        .await
    }

    /// Per-slot finality update.
    pub async fn finality_update(&self) -> Result<SszResponse> {
        self.get_ssz("/eth/v1/beacon/light_client/finality_update")
            .await
    }

    /// Per-slot optimistic update.
    pub async fn optimistic_update(&self) -> Result<SszResponse> {
        self.get_ssz("/eth/v1/beacon/light_client/optimistic_update")
            .await
    }

    // --- control endpoints (diagnostics, and the chain view for `status`) --

    pub async fn node_version(&self) -> Result<String> {
        let v = self.get_json("/eth/v1/node/version").await?;
        Ok(v["data"]["version"].as_str().unwrap_or("unknown").to_string())
    }

    /// `(head_slot, is_syncing)`.
    pub async fn syncing(&self) -> Result<(u64, bool)> {
        let v = self.get_json("/eth/v1/node/syncing").await?;
        let head = v["data"]["head_slot"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("syncing: missing head_slot"))?;
        let syncing = v["data"]["is_syncing"].as_bool().unwrap_or(true);
        Ok((head, syncing))
    }

    /// The finalized checkpoint root — the checkpoint-aligned block root a
    /// bootstrap should be pre-populated for.
    pub async fn finalized_root(&self) -> Result<[u8; 32]> {
        let v = self
            .get_json("/eth/v1/beacon/states/head/finality_checkpoints")
            .await?;
        let s = v["data"]["finalized"]["root"]
            .as_str()
            .ok_or_else(|| anyhow!("finality_checkpoints: missing finalized.root"))?;
        let raw = hex::decode(s.trim_start_matches("0x"))
            .context("decoding finalized root hex")?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("finalized root is {} bytes, want 32", raw.len()))?;
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_math_matches_the_live_node() {
        // zbox head 10 873 925 sat in period 1327 while serving 1327 as its
        // newest update.
        assert_eq!(period_of_slot(10_873_925), 1327);
        // Boundaries.
        assert_eq!(period_of_slot(0), 0);
        assert_eq!(period_of_slot(SLOTS_PER_PERIOD - 1), 0);
        assert_eq!(period_of_slot(SLOTS_PER_PERIOD), 1);
    }

    #[tokio::test]
    async fn updates_refuses_an_unbounded_count() {
        let c = NimbusRest::new("http://127.0.0.1:1", Duration::from_millis(50)).unwrap();
        // Refused before any I/O happens — the point is that a caller-controlled
        // count cannot fan out upstream.
        let err = c.updates(0, MAX_REQUEST_LIGHT_CLIENT_UPDATES + 1).await.unwrap_err();
        assert!(err.to_string().contains("MAX_REQUEST_LIGHT_CLIENT_UPDATES"));
        let err = c.updates(0, 0).await.unwrap_err();
        assert!(err.to_string().contains("count must be >= 1"));
    }
}
