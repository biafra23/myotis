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

/// The chain's slot/period geometry, read from the upstream rather than assumed.
///
/// # Why this is not a constant
///
/// It was `32 * 256`, documented as `SLOTS_PER_EPOCH (32) *
/// EPOCHS_PER_SYNC_COMMITTEE_PERIOD (256)`. Both factors are mainnet's.
/// **Gnosis runs 16-slot epochs** — it reaches the same 8192 only because it
/// pairs them with 512 epochs per period, so the old constant was right by
/// coincidence and its stated derivation was false for that chain. A future
/// network that pairs different factors would have broken it silently.
///
/// Silently is the operative word: every period number roost computes rests on
/// this, including the keys its **archive records are written under**. A wrong
/// value does not fail — it mis-keys durable data, and the archive is the one
/// thing here that cannot be regenerated.
/// Fields are PRIVATE so [`ChainParams::from_spec`] is the only way in. They
/// were `pub`, which meant `ChainParams { slots_per_epoch: 0, .. }` compiled and
/// divided by zero in `period_of_slot` — unwinding out of `serve`'s main task,
/// not a per-connection one. "Refuse anything unusable" is only a contract if
/// the unusable value cannot be built at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    /// Validated once, at construction — see `from_spec`.
    slots_per_period: u64,
}

impl ChainParams {
    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    pub fn epochs_per_sync_committee_period(&self) -> u64 {
        self.epochs_per_sync_committee_period
    }

    /// Proven usable at construction, so this cannot saturate.
    pub fn slots_per_period(&self) -> u64 {
        self.slots_per_period
    }

    /// The sync-committee period a slot falls in.
    pub fn period_of_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_period()
    }

    pub fn epoch_of_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Parse from a decoded `config/spec` map, refusing anything unusable.
    ///
    /// Both values are REQUIRED and a zero is refused: defaulting either would
    /// reintroduce exactly the silent-wrong-answer failure this type exists to
    /// remove, and a zero would divide by zero.
    pub fn from_spec(spec: &std::collections::BTreeMap<String, String>) -> Result<Self> {
        let read = |key: &str| -> Result<u64> {
            let raw = spec
                .get(key)
                .ok_or_else(|| anyhow!("config/spec has no {key}"))?;
            let v: u64 = raw.parse().with_context(|| format!("parsing {key} = {raw}"))?;
            if v == 0 {
                return Err(anyhow!("config/spec reports {key} = 0"));
            }
            Ok(v)
        };
        let slots_per_epoch = read("SLOTS_PER_EPOCH")?;
        let epochs_per_sync_committee_period = read("EPOCHS_PER_SYNC_COMMITTEE_PERIOD")?;
        // checked, not saturating: a saturating product answers u64::MAX, which
        // makes period_of_slot answer 0 for every real slot — so every archive
        // record would be written under period 0. Silently mis-keying
        // unregenerable data is the exact failure this type exists to prevent,
        // and saturation would have reintroduced it.
        let slots_per_period = slots_per_epoch
            .checked_mul(epochs_per_sync_committee_period)
            .ok_or_else(|| {
                anyhow!(
                    "config/spec geometry overflows u64: {slots_per_epoch} x \
                     {epochs_per_sync_committee_period}"
                )
            })?;
        Ok(Self {
            slots_per_epoch,
            epochs_per_sync_committee_period,
            slots_per_period,
        })
    }
}

/// The spec's `MAX_REQUEST_LIGHT_CLIENT_UPDATES`. Enforced here as well as on
/// the serving side: a caller-controlled count must never fan out into an
/// unbounded upstream fetch.
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

fn parse_root(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("decoding a 32-byte root")?;
    raw.as_slice()
        .try_into()
        .map_err(|_| anyhow!("root is {} bytes, want 32", raw.len()))
}

/// Ceiling on a buffered SSZ response body.
///
/// A full 128-period `updates` answer is ~3.4 MB, so 32 MiB is ~10x headroom.
/// The cap exists because the body is read into memory before `split_updates`
/// can enforce anything: a compromised or malfunctioning upstream could
/// otherwise stream an arbitrarily large chunked response and exhaust the
/// daemon, which would bypass every ingestion bound downstream of it.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Why a fetch failed, split by whether retrying could ever help.
///
/// The distinction is load-bearing for bootstraps: a root is marked attempted
/// BEFORE the fetch, so treating a timeout like a 404 would permanently poison a
/// wallet's pinned checkpoint on one upstream hiccup.
#[derive(Debug)]
pub enum FetchError {
    /// The upstream answered, and its answer means "I do not have this" — 4xx.
    /// Retrying is pointless.
    Unavailable(u16),
    /// Timeout, connection failure, 5xx, oversized or unreadable body. The same
    /// request may well succeed later.
    Transient(anyhow::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(code) => write!(f, "upstream does not have it (HTTP {code})"),
            Self::Transient(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FetchError {}

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
        self.get_ssz_classified(path).await.map_err(|e| match e {
            FetchError::Unavailable(code) => anyhow!("GET {path} -> HTTP {code}"),
            FetchError::Transient(e) => e,
        })
    }

    /// As [`NimbusRest::get_ssz`], but distinguishing "upstream does not have
    /// it" from "try again later", and streaming the body under a hard cap
    /// rather than buffering whatever arrives.
    async fn get_ssz_classified(&self, path: &str) -> std::result::Result<SszResponse, FetchError> {
        let url = format!("{}{}", self.base, path);
        let mut resp = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .send()
            .await
            .map_err(|e| FetchError::Transient(anyhow!("GET {url}: {e}")))?;

        let status = resp.status();
        let consensus_version = resp
            .headers()
            .get("eth-consensus-version")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        if !status.is_success() {
            return Err(if status.is_client_error() {
                FetchError::Unavailable(status.as_u16())
            } else {
                FetchError::Transient(anyhow!("GET {url} -> HTTP {status}"))
            });
        }

        // A declared Content-Length over the cap is refused before a byte of
        // body is read; a chunked response without one is caught below.
        if let Some(len) = resp.content_length() {
            if len > MAX_BODY_BYTES as u64 {
                return Err(FetchError::Transient(anyhow!(
                    "GET {url}: declared body {len} exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
                )));
            }
        }

        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| FetchError::Transient(anyhow!("reading body of {url}: {e}")))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(FetchError::Transient(anyhow!(
                    "GET {url}: body exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }

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
        // Same ceiling and the same reason as the SSZ path above: the body is
        // buffered before anything can bound it, so a compromised or
        // malfunctioning upstream could stream an arbitrarily large chunked
        // response and exhaust the daemon. `resp.text()` has no ceiling, and the
        // JSON endpoints are not the small ones — /eth/v1/node/peers is polled
        // against a node this design sizes at 500-800 peers.
        if let Some(len) = resp.content_length() {
            if len > MAX_BODY_BYTES as u64 {
                return Err(anyhow!(
                    "GET {url}: declared body {len} exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
                ));
            }
        }
        let mut bytes: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("reading body of {url}"))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err(anyhow!(
                    "GET {url}: body exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})"
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(anyhow!(
                "GET {url} -> HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        serde_json::from_slice(&bytes).with_context(|| format!("parsing JSON from {url}"))
    }

    // --- the four light-client endpoints ---------------------------------

    /// One-shot trust anchor, keyed by an arbitrary block root.
    ///
    /// Arbitrary keying is what makes bootstraps the awkward case for caching —
    /// unbounded and genuinely miss-prone — which is why the design pre-populates
    /// only checkpoint-aligned roots and refuses the rest.
    pub async fn bootstrap(&self, block_root: &[u8; 32]) -> Result<SszResponse> {
        self.bootstrap_classified(block_root).await.map_err(Into::into)
    }

    /// [`NimbusRest::bootstrap`] keeping the transient/definitive distinction,
    /// which the background filler needs in order not to poison a root over a
    /// timeout.
    pub async fn bootstrap_classified(
        &self,
        block_root: &[u8; 32],
    ) -> std::result::Result<SszResponse, FetchError> {
        self.get_ssz_classified(&format!(
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

    /// Connected peers' last-seen multiaddrs, for external-address probing.
    ///
    /// The upstream already maintains a live, chain-appropriate peer set (145
    /// inbound on the mainnet node at the time of writing), so probing borrows
    /// it rather than introducing a second hardcoded bootnode list that would
    /// rot independently of the one in `myotis-net`.
    ///
    /// Only `connected` peers are asked for, and only entries whose multiaddr
    /// carries a peer id are returned — a probe needs both halves to dial.
    /// Filtering to ROUTABLE addresses is left to the caller, which owns the
    /// routability rule (`myotis_net::is_routable`); duplicating it here would
    /// be a second definition of the same thing.
    pub async fn connected_peer_addrs(&self) -> Result<Vec<String>> {
        let v = self.get_json("/eth/v1/node/peers?state=connected").await?;
        let arr = v["data"].as_array().ok_or_else(|| anyhow!("node/peers: data is not an array"))?;
        Ok(arr
            .iter()
            .filter_map(|p| p["last_seen_p2p_address"].as_str())
            .filter(|a| a.contains("/p2p/"))
            .map(str::to_string)
            .collect())
    }

    /// The upstream's own externally-visible IPs, from `/eth/v1/node/identity`.
    ///
    /// This is the PRIMARY external-address source, and it is better than
    /// anything roost can determine for itself. Nimbus runs discv5 with
    /// `--enr-auto-update=true`, so it already does robust external-address
    /// discovery across many peers and keeps the answer current; roost shares
    /// its host, therefore its public IP. Asking is one loopback call.
    ///
    /// It does NOT create a new trust dependency: roost is a byte cache over
    /// this same loopback REST already (CLAUDE.md, Data sources carve-out), and
    /// an upstream that lies here costs a wrong advertised address, not a wrong
    /// answer to a wallet — every update a wallet takes is still checked against
    /// sync-committee signatures.
    ///
    /// Returns every routable candidate, unfiltered and in the upstream's own
    /// order; the caller applies `myotis_net::is_routable` and picks. The PORT
    /// in these multiaddrs is the UPSTREAM's listen port and must be discarded —
    /// roost's own port is the one that belongs in anything it advertises.
    pub async fn external_ips(&self) -> Result<Vec<String>> {
        let v = self.get_json("/eth/v1/node/identity").await?;
        let arr = v["data"]["p2p_addresses"]
            .as_array()
            .ok_or_else(|| anyhow!("node/identity: p2p_addresses is not an array"))?;
        Ok(arr.iter().filter_map(|a| a.as_str()).map(str::to_string).collect())
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

    /// `(head_slot, head_root)` — half of what a `status` answer needs.
    pub async fn head_header(&self) -> Result<(u64, [u8; 32])> {
        let v = self.get_json("/eth/v1/beacon/headers/head").await?;
        let slot = v["data"]["header"]["message"]["slot"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("headers/head: missing slot"))?;
        let root = v["data"]["root"]
            .as_str()
            .ok_or_else(|| anyhow!("headers/head: missing root"))?;
        Ok((slot, parse_root(root)?))
    }

    /// `(finalized_root, finalized_epoch)` — the other half.
    pub async fn finalized_checkpoint(&self) -> Result<([u8; 32], u64)> {
        let v = self
            .get_json("/eth/v1/beacon/states/head/finality_checkpoints")
            .await?;
        let root = v["data"]["finalized"]["root"]
            .as_str()
            .ok_or_else(|| anyhow!("finality_checkpoints: missing finalized.root"))?;
        let epoch = v["data"]["finalized"]["epoch"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("finality_checkpoints: missing finalized.epoch"))?;
        Ok((parse_root(root)?, epoch))
    }

    /// `/eth/v1/config/spec` — the chain's fork versions, activation epochs,
    /// `SLOTS_PER_EPOCH` and blob schedule.
    ///
    /// Returns the scalar entries AND the `BLOB_SCHEDULE` array from ONE
    /// request: they live in the same document, and fetching it twice would be
    /// two round trips for one payload.
    ///
    /// This is chain CONFIGURATION, not consensus data — it decides what fork
    /// digest to stamp on a response, and a wrong one costs reachability rather
    /// than correctness (peers answer a mismatched `status` with
    /// Goodbye(IrrelevantNetwork)). Reading it from the node roost already
    /// follows is what stops roost disagreeing with its own upstream about which
    /// fork it is on.
    pub async fn config_spec(
        &self,
    ) -> Result<(
        std::collections::BTreeMap<String, String>,
        Vec<crate::forks::BlobParams>,
    )> {
        let v = self.get_json("/eth/v1/config/spec").await?;
        let obj = v["data"]
            .as_object()
            .ok_or_else(|| anyhow!("config/spec: data is not an object"))?;
        // Stringify NUMERIC scalars too, not just string ones. The Beacon API
        // spec pins these as strings and Nimbus emits them that way, but a
        // client emitting `"SLOTS_PER_EPOCH": 32` would otherwise arrive
        // downstream as an ABSENT key — refused with "config/spec has no
        // SLOTS_PER_EPOCH", which points at the wrong problem entirely. The
        // same brittleness already bit BLOB_SCHEDULE; there it degraded to a
        // fallback, here it is fatal to both serve and probe.
        let scalars = obj
            .iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) => Some((k.clone(), s.clone())),
                serde_json::Value::Number(n) => Some((k.clone(), n.to_string())),
                serde_json::Value::Bool(b) => Some((k.clone(), b.to_string())),
                _ => None,
            })
            .collect();
        Ok((scalars, parse_blob_schedule(&v)?))
    }
}

/// The EIP-7892 `BLOB_SCHEDULE` entries. Absent on a chain with none (pre-Fulu,
/// or a client that does not expose it), which is not an error.
/// A `u64` written either as a JSON string (what the Beacon API spec pins for
/// scalars, and what Nimbus emits) or as a JSON number.
///
/// Accepting both is deliberate. `BLOB_SCHEDULE` is a nested array-of-objects
/// added by Fusaka and is the least settled shape this feature depends on; a
/// client emitting `{"EPOCH": 411072}` as a number would otherwise take roost's
/// computed digests out entirely — the parse fails, the whole schedule is
/// discarded, and serving silently drops to the observed fallback.
fn json_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

/// Parse `BLOB_SCHEDULE`.
///
/// All-or-nothing on purpose: a PARTIAL blob schedule computes wrong digests
/// silently, which is worse than no schedule at all — the caller falls back to
/// the digest observed on the wire and says so.
fn parse_blob_schedule(v: &serde_json::Value) -> Result<Vec<crate::forks::BlobParams>> {
    {
        let Some(entries) = v["data"]["BLOB_SCHEDULE"].as_array() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let epoch = json_u64(&e["EPOCH"])
                .ok_or_else(|| anyhow!("BLOB_SCHEDULE entry has no usable EPOCH"))?;
            let max_blobs = json_u64(&e["MAX_BLOBS_PER_BLOCK"]).ok_or_else(|| {
                anyhow!("BLOB_SCHEDULE entry has no usable MAX_BLOBS_PER_BLOCK")
            })?;
            out.push(crate::forks::BlobParams { epoch, max_blobs });
        }
        Ok(out)
    }
}

impl NimbusRest {
    /// The slot of a block identified by root — how roost learns the epoch a
    /// BOOTSTRAP belongs to without decoding SSZ (it is a byte cache, and
    /// modelling light-client types is exactly what this design avoids).
    pub async fn header_slot(&self, block_root: &[u8; 32]) -> Result<u64> {
        let v = self
            .get_json(&format!(
                "/eth/v1/beacon/headers/0x{}",
                hex::encode(block_root)
            ))
            .await?;
        v["data"]["header"]["message"]["slot"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("headers/<root>: missing slot"))
    }

    /// The chain's slot/period geometry.
    pub async fn chain_params(&self) -> Result<ChainParams> {
        let (spec, _) = self.config_spec().await?;
        ChainParams::from_spec(&spec)
    }

    /// The chain's `genesis_validators_root` — the identity an archive is bound
    /// to, so a file collected for one network can never load for another.
    pub async fn genesis_validators_root(&self) -> Result<[u8; 32]> {
        let v = self.get_json("/eth/v1/beacon/genesis").await?;
        let s = v["data"]["genesis_validators_root"]
            .as_str()
            .ok_or_else(|| anyhow!("genesis: missing genesis_validators_root"))?;
        let raw = hex::decode(s.trim_start_matches("0x"))
            .context("decoding genesis_validators_root hex")?;
        raw.as_slice()
            .try_into()
            .map_err(|_| anyhow!("genesis_validators_root is {} bytes, want 32", raw.len()))
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
    use serde_json::json;

    /// The exact shape zbox's Nimbus v26.7.0 returns — strings.
    #[test]
    fn parses_the_live_nimbus_blob_schedule() {
        let v = json!({"data": {"BLOB_SCHEDULE": [
            {"EPOCH": "274176", "MAX_BLOBS_PER_BLOCK": "15"},
            {"EPOCH": "275712", "MAX_BLOBS_PER_BLOCK": "21"}
        ]}});
        let got = parse_blob_schedule(&v).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].epoch, 274_176);
        assert_eq!(got[0].max_blobs, 15);
        assert_eq!(got[1].epoch, 275_712);
        assert_eq!(got[1].max_blobs, 21);
    }

    /// A client emitting numbers instead of strings must not silently take the
    /// computed digests out — BLOB_SCHEDULE's per-client encoding is the least
    /// settled shape this feature rests on.
    #[test]
    fn parses_a_numeric_blob_schedule() {
        let v = json!({"data": {"BLOB_SCHEDULE": [
            {"EPOCH": 274176, "MAX_BLOBS_PER_BLOCK": 15}
        ]}});
        let got = parse_blob_schedule(&v).unwrap();
        assert_eq!(got[0].epoch, 274_176);
        assert_eq!(got[0].max_blobs, 15);
    }

    #[test]
    fn a_chain_with_no_blob_schedule_is_not_an_error() {
        // Pre-Fulu, or a client that does not expose the key.
        let v = json!({"data": {"SLOTS_PER_EPOCH": "32"}});
        assert_eq!(parse_blob_schedule(&v).unwrap(), vec![]);
    }

    #[test]
    fn a_malformed_entry_fails_rather_than_yielding_a_partial_schedule() {
        // A partial schedule computes wrong digests silently; failing drops us
        // to the observed fallback, which announces itself.
        let v = json!({"data": {"BLOB_SCHEDULE": [
            {"EPOCH": "274176", "MAX_BLOBS_PER_BLOCK": "15"},
            {"EPOCH": "275712"}
        ]}});
        assert!(parse_blob_schedule(&v).is_err());

        let v = json!({"data": {"BLOB_SCHEDULE": [{"EPOCH": true, "MAX_BLOBS_PER_BLOCK": "15"}]}});
        assert!(parse_blob_schedule(&v).is_err());
    }

    fn params(spe: u64, epp: u64) -> ChainParams {
        let m: std::collections::BTreeMap<String, String> = [
            ("SLOTS_PER_EPOCH", spe.to_string()),
            ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", epp.to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        ChainParams::from_spec(&m).unwrap()
    }

    fn mainnet_shaped() -> ChainParams {
        params(32, 256)
    }

    #[test]
    fn period_math_matches_the_live_node() {
        // zbox head 10 873 925 sat in period 1327 while serving 1327 as its
        // newest update.
        let p = mainnet_shaped();
        assert_eq!(p.slots_per_period(), 8192);
        assert_eq!(p.period_of_slot(10_873_925), 1327);
        assert_eq!(p.period_of_slot(0), 0);
        assert_eq!(p.period_of_slot(8191), 0);
        assert_eq!(p.period_of_slot(8192), 1);
    }

    #[test]
    fn gnosis_geometry_reaches_the_same_period_length_by_different_factors() {
        // 16-slot epochs, 512 epochs per period. The old constant (32 * 256)
        // landed on 8192 too — right answer, false derivation. This is the case
        // that would have made a differently-shaped chain wrong in silence.
        let g = params(16, 512);
        assert_eq!(g.slots_per_period(), 8192);
        assert_eq!(g.epoch_of_slot(16), 1, "gnosis epochs are 16 slots, not 32");
        assert_ne!(g.epoch_of_slot(32), mainnet_shaped().epoch_of_slot(32));
    }

    #[test]
    fn a_hypothetical_chain_with_different_factors_is_honoured() {
        // The point of reading it rather than assuming: nothing here says 8192.
        let odd = params(8, 64);
        assert_eq!(odd.slots_per_period(), 512);
        assert_eq!(odd.period_of_slot(512), 1);
    }

    #[test]
    fn refuses_a_spec_it_cannot_use() {
        use std::collections::BTreeMap;
        let ok: BTreeMap<String, String> = [
            ("SLOTS_PER_EPOCH", "16"),
            ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "512"),
        ]
        .into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(ChainParams::from_spec(&ok).unwrap().slots_per_period(), 8192);

        for bad in [
            vec![("SLOTS_PER_EPOCH", "32")],                                  // missing the other
            vec![("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "256")],                // missing the other
            vec![("SLOTS_PER_EPOCH", "0"), ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "256")],
            vec![("SLOTS_PER_EPOCH", "32"), ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "0")],
            vec![("SLOTS_PER_EPOCH", "x"), ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "256")],
            // Overflowing product: saturation would have made every slot land in
            // period 0 rather than failing.
            vec![
                ("SLOTS_PER_EPOCH", "18446744073709551615"),
                ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", "2"),
            ],
        ] {
            let m: BTreeMap<String, String> =
                bad.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            assert!(
                ChainParams::from_spec(&m).is_err(),
                "an unusable spec must fail rather than default — a wrong period \
                 length mis-keys archive records, which are not regenerable"
            );
        }
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
