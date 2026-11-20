//! Minimal Gnosis JSON-RPC helpers for postage batch reads (`PLAN.md` M3 / Phase 5)
//! and writes (Phase 8: createBatch / topUp / increaseDepth via [`tx`]).
//!
//! [`chequebook`] provides the SWAP / cheque primitives (Phase 7):
//! EIP-712 signing of off-chain cheques plus calldata builders for
//! `deployChequebook` and `cashChequeBeneficiary`.

pub mod chequebook;
/// Chequebook bootstrap shared by `antd` and `ant-ffi`: the persisted
/// association record plus resolve / auto-deploy / factory-verify
/// mechanics for outbound SWAP settlement.
pub mod chequebook_store;
/// On-chain recovery of node-owned state (postage batches, chequebook)
/// from the node EOA. RPC-driven, so it needs the `chain-rpc` feature.
#[cfg(feature = "chain-rpc")]
pub mod discover;
/// Storage funding shared by `antd` and `ant-ffi`: price a postage plan
/// against the node wallet and pay for it (and for extending it or the
/// chequebook deposit) with xDAI only.
#[cfg(feature = "chain-rpc")]
pub mod funding;
/// The pluggable JSON-RPC transport seam (issue #77): a host can serve
/// ant's chain requests from its own verified source, with the
/// configured RPC URL as the built-in default and fallback.
pub mod transport;
pub mod tx;

#[cfg(feature = "chain-rpc")]
use serde_json::json;
#[cfg(feature = "chain-rpc")]
use std::fmt::Write;
use thiserror::Error;

pub use transport::{ChainTransport, SharedChainTransport, RETRYABLE_ERROR_CODE};

#[derive(Debug, Error)]
pub enum RpcError {
    #[cfg(feature = "chain-rpc")]
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("decode: {0}")]
    Decode(String),
}

/// The JSON-RPC `error` member of `v`, if it carries one. A literal
/// `"error": null` (some backends always emit the key) is not an error.
#[cfg(feature = "chain-rpc")]
fn rpc_error(v: &serde_json::Value) -> Option<&serde_json::Value> {
    v.get("error").filter(|e| !e.is_null())
}

/// `error.message` only — the terse shape most read helpers surface.
#[cfg(feature = "chain-rpc")]
fn rpc_error_message(v: &serde_json::Value) -> Option<String> {
    rpc_error(v).map(|e| {
        e.get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown RPC error")
            .to_string()
    })
}

/// The whole `error` object as JSON — used where the caller needs the
/// `data` field too (revert reasons, range-limit hints).
#[cfg(feature = "chain-rpc")]
fn rpc_error_json(v: &serde_json::Value) -> Option<String> {
    rpc_error(v).map(std::string::ToString::to_string)
}

/// The `result` member as a string, or the crate's standard
/// "missing result" error.
#[cfg(feature = "chain-rpc")]
fn rpc_result_str(v: &serde_json::Value) -> Result<&str, RpcError> {
    v.get("result")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RpcError::Rpc("missing result".to_string()))
}

/// Mainnet postage stamp contract on Gnosis (Swarm docs / bee defaults).
pub const GNOSIS_POSTAGE_STAMP: &str = "0x45a1502382541Cd610CC9068e88727426b696293";

/// xBZZ on Gnosis.
pub const GNOSIS_BZZ_TOKEN: &str = "0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da";

/// Wrapped xDAI on Gnosis — the native-token ERC-20 the BZZ DEX pool
/// trades against (`token1` of the pool below, 18 decimals).
pub const GNOSIS_WXDAI: &str = "0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d";

/// `SushiSwap` V3 BZZ/WXDAI 0.3% pool on Gnosis — the deepest BZZ market
/// on the chain. `token0` = xBZZ (16 decimals), `token1` = WXDAI. The
/// `swap` auto-funding flow swaps native xDAI through this pool.
pub const GNOSIS_BZZ_WXDAI_POOL: &str = "0x7583b9C573FA4FB5Ea21C83454939c4Cf6aacBc3";

/// Deterministic CREATE2 deployer (Arachnid's "deterministic deployment
/// proxy"), present at the same address on Gnosis and most EVM chains.
/// Called with `salt(32) ‖ initcode` to deploy a contract at an address
/// derived purely from the bytecode, so `AntDrive`'s swap helper lands at
/// a constant, pre-computable address.
pub const CREATE2_DEPLOYER: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/// Cheap to clone: the HTTP client and the transport are shared handles.
#[cfg(feature = "chain-rpc")]
#[derive(Clone)]
pub struct ChainClient {
    url: String,
    http: reqwest::Client,
    /// Optional host-provided transport (issue #77). `None` — the
    /// default — means every request goes straight to [`Self::url`],
    /// which is what ant has always done.
    transport: Option<SharedChainTransport>,
    /// An unverified source the transfer scan may read a wide span from
    /// when this (verified) one can't serve it in a few windows; see
    /// [`Self::with_unverified_logs`].
    unverified_logs: Option<std::sync::Arc<ChainClient>>,
    /// Host transport calls this client (and its clones) started that
    /// are still inside the host's `serve`, whether or not anyone still
    /// awaits them: a timed-out read stops waiting, but its blocking
    /// thread stays parked until the host returns. See
    /// [`Self::with_own_host_call_count`].
    host_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "chain-rpc")]
impl ChainClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::builder()
                .user_agent("ant-chain/1")
                .build()
                .expect("reqwest client"),
            transport: None,
            unverified_logs: None,
            host_calls: std::sync::Arc::default(),
        }
    }

    /// This client with a count of host transport calls of its own
    /// ([`Self::host_calls_in_flight`]), separate from the clients it
    /// was cloned from, so a periodic reader can tell whether *its* last
    /// call is still parked in the host's `serve` (e.g. after a timeout)
    /// without other readers' calls counting.
    #[must_use]
    pub fn with_own_host_call_count(&self) -> Self {
        Self {
            host_calls: std::sync::Arc::default(),
            ..self.clone()
        }
    }

    /// Host transport calls started through this client's count (see
    /// [`Self::with_own_host_call_count`]) that haven't returned from the
    /// host yet. A call a caller stopped waiting for still counts until
    /// the host answers: its blocking-pool thread can't be taken back.
    #[must_use]
    pub fn host_calls_in_flight(&self) -> usize {
        self.host_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Give the wallet's transfer scan an explicitly unverified source
    /// (`None` clears it): a single provider that serves the whole history
    /// in one `eth_getLogs`, where this client is the verified route (e.g.
    /// Freedom's quorum bridge) that may only serve a few thousand blocks
    /// at a time. A span this client can't serve in a few windows is read
    /// from it once instead of window by window; what it finds is checked
    /// item by item through this client, and the span stays unconfirmed
    /// until this client reads it ([`discover::confirm_transfer_scan`]).
    /// While a read from it fails, the scan reads on window by window
    /// through this client, as without one, trying it again every 64
    /// windows; the span is marked unconfirmed only once it has served a
    /// window. Only the transfer scan uses it.
    #[must_use]
    pub fn with_unverified_logs(mut self, url: Option<String>) -> Self {
        self.unverified_logs = url.map(|u| std::sync::Arc::new(ChainClient::new(u)));
        self
    }

    /// [`Self::with_unverified_logs`] with a client of the caller's own,
    /// e.g. one with a host transport.
    #[must_use]
    pub fn with_unverified_logs_client(mut self, client: Option<ChainClient>) -> Self {
        self.unverified_logs = client.map(std::sync::Arc::new);
        self
    }

    /// Whether `other` reads through the same route as `self`: the same
    /// RPC URL, the same host transport (by identity) and the same
    /// unverified source. Two clients built separately for one RPC (each
    /// `ant_start_gateway` re-call builds its own) compare equal, so a
    /// consumer handed a client again can tell a real replacement from a
    /// re-hand of the one it already reads through.
    #[must_use]
    pub fn same_route(&self, other: &ChainClient) -> bool {
        let transport = match (&self.transport, &other.transport) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                std::ptr::addr_eq(std::sync::Arc::as_ptr(a), std::sync::Arc::as_ptr(b))
            }
            _ => false,
        };
        let unverified = match (&self.unverified_logs, &other.unverified_logs) {
            (None, None) => true,
            (Some(a), Some(b)) => a.same_route(b),
            _ => false,
        };
        self.url == other.url && transport && unverified
    }

    pub(crate) fn unverified_logs(&self) -> Option<&ChainClient> {
        self.unverified_logs.as_deref()
    }

    /// Install (or clear, with `None`) a host-provided JSON-RPC
    /// transport. The host gets first refusal on every request this
    /// client issues; a can't-serve answer falls through to
    /// [`Self::url`] exactly as if no transport were installed. See
    /// [`transport`] for the full contract.
    #[must_use]
    pub fn with_transport(mut self, transport: Option<SharedChainTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// Issue one JSON-RPC request and return the parsed response body.
    ///
    /// **This is the single seam every chain request in this crate goes
    /// through** (issue #77). With no host transport installed it is the
    /// plain `POST <url>` path, byte for byte what ant did before. With
    /// one installed the host answers first, and a can't-serve reply —
    /// `None`, or a retryable [`RETRYABLE_ERROR_CODE`] carrying the
    /// backend's covered window — falls through to the URL here rather
    /// than reaching the caller (an empty result would silently truncate
    /// batch discovery).
    pub(crate) async fn rpc(
        &self,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        if let Some(t) = self.transport.clone() {
            match Self::ask_host(t, body.to_string(), self.host_calls.clone()).await {
                Ok(v) => return Ok(v),
                Err(reason) => tracing::debug!(
                    target: "ant-chain",
                    method = body.get("method").and_then(serde_json::Value::as_str).unwrap_or("?"),
                    reason,
                    "host chain transport can't serve; falling back to the configured RPC URL",
                ),
            }
        }
        Ok(self
            .http
            .post(&self.url)
            .json(body)
            .send()
            .await?
            .json()
            .await?)
    }

    /// Run the host transport on the runtime's blocking pool (the
    /// callback is documented as blocking-OK) and classify its answer.
    /// `Err(reason)` means can't-serve.
    async fn ask_host(
        transport: SharedChainTransport,
        request: String,
        in_flight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Result<serde_json::Value, &'static str> {
        /// Counts the call until the blocking closure ends, not until the
        /// awaiting future does: dropped with the closure.
        struct InFlight(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for InFlight {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = InFlight(in_flight);
        match tokio::task::spawn_blocking(move || {
            let _guard = guard;
            transport.serve(&request)
        })
        .await
        {
            // A panicking host must not take the node down with it —
            // treat it like any other can't-serve and use the URL.
            Err(_) => Err("host transport panicked"),
            Ok(None) => Err("host returned NULL"),
            Ok(Some(raw)) => match transport::classify(&raw) {
                transport::HostAnswer::Served(v) => Ok(v),
                transport::HostAnswer::CantServe(reason) => Err(reason),
            },
        }
    }

    pub async fn eth_call(&self, to: &str, data: &str) -> Result<Vec<u8>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_call",
            "params": [
                { "to": to, "data": data },
                "latest",
            ]
        });

        let v = self.rpc(&body).await?;
        if let Some(msg) = rpc_error_message(&v) {
            return Err(RpcError::Rpc(msg));
        }
        decode_hex_prefixed_bytes(rpc_result_str(&v)?).map_err(|e| RpcError::Decode(e.to_string()))
    }

    /// `eth_call` with an explicit `from` address — required for any
    /// view that reads `msg.sender` (e.g. chequebook
    /// `cashChequeBeneficiary`, where `msg.sender` is baked into the
    /// EIP-712 cheque digest the contract recomputes locally).
    ///
    /// On a revert this returns the **full** RPC error JSON in
    /// [`RpcError::Rpc`] (message + `data` field). Callers care
    /// about distinguishing `invalid signature` from
    /// `liquid balance not sufficient` — both arrive here, the
    /// caller decides which one is the test result.
    pub async fn eth_call_from(
        &self,
        from: &[u8; 20],
        to: &[u8; 20],
        data: &[u8],
    ) -> Result<Vec<u8>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_call",
            "params": [
                {
                    "from": format!("0x{}", hex::encode(from)),
                    "to":   format!("0x{}", hex::encode(to)),
                    "data": format!("0x{}", hex::encode(data)),
                },
                "latest",
            ],
        });

        let v = self.rpc(&body).await?;
        if let Some(err) = rpc_error_json(&v) {
            return Err(RpcError::Rpc(err));
        }
        decode_hex_prefixed_bytes(rpc_result_str(&v)?).map_err(|e| RpcError::Decode(e.to_string()))
    }

    /// Native xDAI balance for `addr` (lower 128 bits — that's
    /// 2^128 ≈ 3.4 × 10^38 wei, well above any reasonable wallet).
    pub async fn eth_get_balance_lower128(&self, addr: &[u8; 20]) -> Result<u128, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_getBalance",
            "params": [format!("0x{}", hex::encode(addr)), "latest"],
        });
        let v = self.rpc(&body).await?;
        if let Some(msg) = rpc_error_message(&v) {
            return Err(RpcError::Rpc(msg));
        }
        let s = rpc_result_str(&v)?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = if s.is_empty() { "0" } else { s };
        let n = u128::from_str_radix(s, 16)
            .map_err(|e| RpcError::Decode(format!("eth_getBalance hex: {e}")))?;
        Ok(n)
    }

    /// ERC-20 balance (lower 128 bits — enough for sane BZZ amounts).
    pub async fn erc20_balance_of_lower128(
        &self,
        token: &str,
        owner_eth: &[u8; 20],
    ) -> Result<u128, RpcError> {
        // balanceOf(address) 0x70a08231
        let mut data = String::with_capacity(2 + 8 + 64);
        data.push_str("0x70a08231");
        write!(data, "{:0>64}", hex::encode(owner_eth)).unwrap();
        let out = self.eth_call(token, &data).await?;
        abi_word_last_u128_be(&out)
    }

    /// Latest block number (`eth_blockNumber`). Drives bee's
    /// `/status.lastSyncedBlock` and `/chainstate.block`/`chainTip` —
    /// `antd` is a light node with no block pipeline of its own, so the
    /// chain tip *is* our synced block.
    pub async fn eth_block_number(&self) -> Result<u64, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_blockNumber",
            "params": [],
        });
        let v = self.rpc(&body).await?;
        if let Some(msg) = rpc_error_message(&v) {
            return Err(RpcError::Rpc(msg));
        }
        let s = rpc_result_str(&v)?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = if s.is_empty() { "0" } else { s };
        u64::from_str_radix(s, 16).map_err(|e| RpcError::Decode(format!("eth_blockNumber: {e}")))
    }

    /// The RPC's chain id (`eth_chainId`). Keys state saved from a
    /// chain scan, so a scan made against one chain is never resumed
    /// against another.
    pub async fn eth_chain_id(&self) -> Result<u64, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_chainId",
            "params": [],
        });
        let v = self.rpc(&body).await?;
        if let Some(msg) = rpc_error_message(&v) {
            return Err(RpcError::Rpc(msg));
        }
        let s = rpc_result_str(&v)?;
        let s = s.strip_prefix("0x").unwrap_or(s);
        u64::from_str_radix(s, 16).map_err(|e| RpcError::Decode(format!("eth_chainId: {e}")))
    }

    /// `PostageStamp.lastPrice()` — current price per chunk per block
    /// (PLUR), the value bee-js's stamp-cost math reads from
    /// `/chainstate.currentPrice`.
    pub async fn postage_last_price(&self, postage_contract: &str) -> Result<u128, RpcError> {
        let data = format!("0x{}", hex::encode(fn_selector(b"lastPrice()")));
        let out = self.eth_call(postage_contract, &data).await?;
        abi_word_last_u128_be(&out)
    }

    /// `PostageStamp.currentTotalOutPayment()` — cumulative per-chunk
    /// outpayment, bee's `/chainstate.totalAmount`. Combined with a
    /// batch's `normalisedBalance` this is what TTL math is derived from.
    pub async fn postage_total_amount(&self, postage_contract: &str) -> Result<u128, RpcError> {
        let data = format!(
            "0x{}",
            hex::encode(fn_selector(b"currentTotalOutPayment()"))
        );
        let out = self.eth_call(postage_contract, &data).await?;
        abi_word_last_u128_be(&out)
    }

    /// Deployed bytecode at `addr` (`eth_getCode`). Empty `Vec` means no
    /// contract is deployed there yet — used to decide whether the swap
    /// helper still needs its one-time CREATE2 deployment.
    pub async fn eth_get_code(&self, addr: &str) -> Result<Vec<u8>, RpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_getCode",
            "params": [addr, "latest"],
        });
        let v = self.rpc(&body).await?;
        if let Some(msg) = rpc_error_message(&v) {
            return Err(RpcError::Rpc(msg));
        }
        decode_hex_prefixed_bytes(rpc_result_str(&v)?).map_err(|e| RpcError::Decode(e.to_string()))
    }

    /// Read a Uniswap-V3-style pool's `slot0()` and return the raw
    /// `sqrtPriceX96` (the lower 160 bits of the first ABI word). The
    /// spot price token1-per-token0 is `(sqrtPriceX96 / 2^96)^2`; for the
    /// BZZ/WXDAI pool that's WXDAI-wei per BZZ-plur, which converts a
    /// postage cost straight into the xDAI needed to buy it.
    pub async fn pool_sqrt_price_x96(&self, pool: &str) -> Result<[u8; 32], RpcError> {
        // slot0() selector 0x3850c7bd
        let data = "0x3850c7bd";
        let out = self.eth_call(pool, data).await?;
        if out.len() < 32 {
            return Err(RpcError::Decode("slot0 returned short word".into()));
        }
        let mut word = [0u8; 32];
        word.copy_from_slice(&out[0..32]);
        Ok(word)
    }
}

/// 4-byte ABI function selector = first 4 bytes of `keccak256(sig)`.
#[cfg(feature = "chain-rpc")]
fn fn_selector(sig: &[u8]) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    let h = Keccak256::digest(sig);
    let mut s = [0u8; 4];
    s.copy_from_slice(&h[..4]);
    s
}

/// Views required for a postage `StampIssuer` (bee `batchDepth` / `batchBucketDepth` / `immutableFlag`).
#[derive(Clone, Debug)]
pub struct PostageBatchMeta {
    pub depth: u8,
    pub bucket_depth: u8,
    pub immutable: bool,
    pub batch_owner_eth: [u8; 20],
}

#[cfg(feature = "chain-rpc")]
pub async fn fetch_postage_batch_meta(
    client: &ChainClient,
    postage_contract: &str,
    batch_id: &[u8; 32],
) -> Result<PostageBatchMeta, RpcError> {
    let sel_depth = encode_word32_call("44beae8e", batch_id);
    let sel_buck = encode_word32_call("32ac57dd", batch_id);
    let sel_imm = encode_word32_call("d968f44b", batch_id);

    let batch_owner_eth = fetch_postage_batch_owner(client, postage_contract, batch_id).await?;

    let d = abi_word_tail_u256_as_u64(&client.eth_call(postage_contract, &sel_depth).await?)?;
    let b = abi_word_tail_u256_as_u64(&client.eth_call(postage_contract, &sel_buck).await?)?;
    let im = abi_word_tail_u256_as_u64(&client.eth_call(postage_contract, &sel_imm).await?)?;

    Ok(PostageBatchMeta {
        depth: u8::try_from(d).map_err(|_| RpcError::Decode("batchDepth".into()))?,
        bucket_depth: u8::try_from(b).map_err(|_| RpcError::Decode("bucketDepth".into()))?,
        immutable: im != 0,
        batch_owner_eth,
    })
}

/// `PostageStamp.batchOwner(bytes32)` alone — one `eth_call`, for
/// callers that only need to tell "not on chain" (zero address) apart
/// without paying for the other three [`fetch_postage_batch_meta`] views.
#[cfg(feature = "chain-rpc")]
pub async fn fetch_postage_batch_owner(
    client: &ChainClient,
    postage_contract: &str,
    batch_id: &[u8; 32],
) -> Result<[u8; 20], RpcError> {
    let sel_owner = encode_word32_call("2182ddb1", batch_id);
    let owner_bytes = client.eth_call(postage_contract, &sel_owner).await?;
    last_word_eth_address(&owner_bytes)?;
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&padded_last_word(&owner_bytes)?[12..32]);
    Ok(owner)
}

#[cfg(feature = "chain-rpc")]
fn encode_word32_call(selector4: &str, word32: &[u8; 32]) -> String {
    format!("0x{selector4}{}", hex::encode(word32))
}

#[cfg(feature = "chain-rpc")]
fn decode_hex_prefixed_bytes(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s)
}

#[cfg(feature = "chain-rpc")]
fn padded_last_word(data: &[u8]) -> Result<[u8; 32], RpcError> {
    if data.len() < 32 {
        return Err(RpcError::Decode("ABI return shorter than word".into()));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&data[data.len() - 32..]);
    Ok(w)
}

#[cfg(feature = "chain-rpc")]
fn last_word_eth_address(ret: &[u8]) -> Result<(), RpcError> {
    let w = padded_last_word(ret)?;
    if !w[..12].iter().all(|&b| b == 0) {
        return Err(RpcError::Decode("bad address ABI padding".into()));
    }
    Ok(())
}

#[cfg(feature = "chain-rpc")]
fn abi_word_tail_u256_as_u64(ret: &[u8]) -> Result<u64, RpcError> {
    let w = padded_last_word(ret)?;
    if w[..24].iter().any(|&b| b != 0) {
        return Err(RpcError::Decode("u256 does not fit u64".into()));
    }
    Ok(u64::from_be_bytes(w[24..].try_into().unwrap()))
}

#[cfg(feature = "chain-rpc")]
fn abi_word_last_u128_be(ret: &[u8]) -> Result<u128, RpcError> {
    let w = padded_last_word(ret)?;
    Ok(u128::from_be_bytes(w[16..32].try_into().unwrap()))
}

/// Transport-seam tests (issue #77). Each case pits a host transport
/// against a stub JSON-RPC server standing in for the configured
/// `gnosis_rpc` URL, so "did this request fall through?" is an
/// observable fact (the stub's hit counter) rather than an inference.
#[cfg(all(test, feature = "chain-rpc"))]
mod transport_seam_tests {
    use super::*;
    use crate::transport::ChainTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A stub for the configured RPC URL: answers every request with
    /// `response` and counts how many it served.
    struct StubRpc {
        url: String,
        hits: Arc<AtomicUsize>,
    }

    impl StubRpc {
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    async fn spawn_stub(response: &'static str) -> StubRpc {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    // Drain headers + body so the client never sees a
                    // reset while it is still writing.
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let body_at = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..body_at]).to_lowercase();
                    let len: usize = head
                        .split("content-length:")
                        .nth(1)
                        .and_then(|s| s.split("\r\n").next())
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() < body_at + len {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let out = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{response}",
                        response.len(),
                    );
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        StubRpc { url, hits }
    }

    /// Host transport with a canned reply, recording the methods asked
    /// of it. `reply` of `None` is the FFI `NULL` (can't-serve).
    struct Host {
        reply: Option<String>,
        seen: Mutex<Vec<String>>,
    }

    impl Host {
        fn new(reply: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                reply: reply.map(ToString::to_string),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
    }

    impl ChainTransport for Host {
        fn serve(&self, request_json: &str) -> Option<String> {
            let v: serde_json::Value = serde_json::from_str(request_json).unwrap();
            self.seen
                .lock()
                .unwrap()
                .push(v["method"].as_str().unwrap().to_string());
            self.reply.clone()
        }
    }

    const STUB_BLOCK: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0x2222"}"#;

    /// One real `eth_getLogs` entry, as the configured URL would answer.
    const STUB_LOGS: &str = r#"{"jsonrpc":"2.0","id":1,"result":[{
        "address":"0xdbf3ea6f5bee45c02255b2c26a16f300502f68da",
        "topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
        "data":"0x",
        "transactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111",
        "blockNumber":"0x1e"}]}"#;

    /// (a) The host serves the request: ant uses its answer and never
    /// touches the configured URL.
    #[tokio::test]
    async fn host_serves_the_request() {
        let stub = spawn_stub(STUB_BLOCK).await;
        let host = Host::new(Some(r#"{"jsonrpc":"2.0","id":1,"result":"0x1111"}"#));
        let client = ChainClient::new(&stub.url).with_transport(Some(host.clone()));

        assert_eq!(client.eth_block_number().await.unwrap(), 0x1111);
        assert_eq!(host.calls(), 1);
        assert_eq!(
            stub.hits(),
            0,
            "URL must not be contacted when the host serves"
        );
    }

    /// (b) The host returns NULL ("can't serve"): the request falls
    /// through to the configured URL exactly as today.
    #[tokio::test]
    async fn null_falls_back_to_the_url() {
        let stub = spawn_stub(STUB_BLOCK).await;
        let host = Host::new(None);
        let client = ChainClient::new(&stub.url).with_transport(Some(host.clone()));

        assert_eq!(client.eth_block_number().await.unwrap(), 0x2222);
        assert_eq!(host.calls(), 1);
        assert_eq!(stub.hits(), 1);
    }

    /// (c) The host returns the retryable `-32000` carrying its covered
    /// window: that is can't-serve-*yet*, so the request falls through —
    /// and must never reach the caller as an empty result, which would
    /// silently truncate batch discovery.
    #[tokio::test]
    async fn retryable_minus_32000_falls_back_not_empty() {
        let stub = spawn_stub(STUB_LOGS).await;
        let host = Host::new(Some(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,
                "message":"log index has not backfilled this range",
                "data":{"coveredFrom":"0x1dd8ac8","coveredTo":"0x1f4a3b0"}}}"#,
        ));
        let client = ChainClient::new(&stub.url).with_transport(Some(host.clone()));

        let logs = client
            .eth_get_logs(GNOSIS_BZZ_TOKEN, &json!([]), 0, 100)
            .await
            .expect("-32000 must not surface as an error either");
        assert_eq!(logs.len(), 1, "-32000 must not surface as an empty result");
        assert_eq!(logs[0].block_number, 30);
        assert_eq!(host.calls(), 1);
        assert_eq!(stub.hits(), 1);
    }

    /// A host error that is *not* `-32000` is a genuine answer and is
    /// surfaced to the caller instead of being retried on the URL.
    #[tokio::test]
    async fn other_host_errors_are_surfaced() {
        let stub = spawn_stub(STUB_BLOCK).await;
        let host = Host::new(Some(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#,
        ));
        let client = ChainClient::new(&stub.url).with_transport(Some(host));

        let err = client.eth_block_number().await.unwrap_err().to_string();
        assert!(err.contains("execution reverted"), "got {err}");
        assert_eq!(stub.hits(), 0);
    }

    /// (d) No transport set: byte-for-byte today's behaviour — one
    /// request, straight to the configured URL.
    #[tokio::test]
    async fn no_transport_is_todays_behaviour() {
        let stub = spawn_stub(STUB_BLOCK).await;
        let client = ChainClient::new(&stub.url);

        assert_eq!(client.eth_block_number().await.unwrap(), 0x2222);
        assert_eq!(stub.hits(), 1);
    }

    /// A host that panics must not take the node down, and must not
    /// lose the request either — it degrades to the URL path.
    #[tokio::test]
    async fn panicking_host_falls_back() {
        struct Panicky;
        impl ChainTransport for Panicky {
            fn serve(&self, _request_json: &str) -> Option<String> {
                panic!("host transport blew up");
            }
        }
        let stub = spawn_stub(STUB_BLOCK).await;
        let client = ChainClient::new(&stub.url).with_transport(Some(Arc::new(Panicky)));

        assert_eq!(client.eth_block_number().await.unwrap(), 0x2222);
        assert_eq!(stub.hits(), 1);
    }

    /// Every request shape ant issues routes through the seam — the
    /// point of "transport, not policy". A host that serves everything
    /// leaves the configured URL untouched.
    #[tokio::test]
    async fn every_request_routes_through_the_seam() {
        let stub = spawn_stub(STUB_BLOCK).await;
        // `0x…20 zero bytes` works as a result for every read below:
        // hex bytes for eth_call / eth_getCode, a hex number elsewhere.
        let host = Host::new(Some(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#,
            "00".repeat(32)
        )));
        let client = ChainClient::new(&stub.url).with_transport(Some(host.clone()));

        client.eth_call(GNOSIS_BZZ_TOKEN, "0x").await.unwrap();
        client
            .eth_call_from(&[1u8; 20], &[2u8; 20], &[])
            .await
            .unwrap();
        client.eth_get_balance_lower128(&[1u8; 20]).await.unwrap();
        client.eth_block_number().await.unwrap();
        client.eth_get_code(GNOSIS_BZZ_TOKEN).await.unwrap();
        client
            .eth_get_transaction_count_pending(&[1u8; 20])
            .await
            .unwrap();
        client.eth_send_raw_transaction(&[0u8; 8]).await.unwrap();
        client
            .eth_get_transaction_receipt(&[3u8; 32])
            .await
            .unwrap();

        assert_eq!(
            *host.seen.lock().unwrap(),
            vec![
                "eth_call",
                "eth_call",
                "eth_getBalance",
                "eth_blockNumber",
                "eth_getCode",
                "eth_getTransactionCount",
                "eth_sendRawTransaction",
                "eth_getTransactionReceipt",
            ],
        );
        assert_eq!(stub.hits(), 0);
    }
}
