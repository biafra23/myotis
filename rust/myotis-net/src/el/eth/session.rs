//! The eth/66-69 session: Hello capability negotiation, the Status handshake
//! with the network compatibility gate, and request/response correlation over
//! a FRAMED [`RlpxConnection`] (EL-A5), twin of the Java `EthHandler` state
//! machine (`AWAITING_HELLO → AWAITING_STATUS → READY`).
//!
//! Single-connection, one-request-at-a-time: requests carry a monotonic id and
//! the receive loop matches responses by id, answering p2p Ping and ignoring
//! gossip/mempool traffic in between (the wallet never serves those). The full
//! concurrent futures map is an EL-A7 orchestration concern; this proves the
//! flow end-to-end.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use myotis_core::rlp::{self, Item};

use crate::el::rlpx::frame::MAX_CONTROL_MSG_SIZE;
use crate::el::rlpx::transport::{
    decode_hello, encode_hello, Hello, RlpxConnection, P2P_DISCONNECT, P2P_HELLO, P2P_PING, P2P_PONG,
};

use super::messages::{self, Status};
use crate::el::snap::fetch::{self, AccountOutcome};
use crate::el::snap::messages as snap;
use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

/// eth versions we advertise (highest-common wins, floor 66).
const OUR_ETH_VERSIONS: &[u64] = &[66, 67, 68, 69];
const MIN_ETH_VERSION: u64 = 66;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Parameters for our side of the eth handshake.
///
/// Adding a field? `rust/tor-poc/src/main.rs` also builds this with a struct
/// literal, and tor-poc sits outside the workspace, so CI never compiles it —
/// update it too, then run `cargo check --manifest-path tor-poc/Cargo.toml`
/// from `rust/`.
pub struct EthConfig {
    pub network_id: u64,
    pub genesis_hash: [u8; 32],
    pub fork_id_hash: [u8; 4],
    pub fork_next: u64,
    /// The block hash/number we advertise as our head (a light client can send
    /// genesis; peers don't gate on it beyond fork-id).
    pub head_hash: [u8; 32],
    pub head_number: u64,
    pub listen_port: u16,
    /// Raw genesis header RLP for serve-window seeding (mainnet only today);
    /// verified against `genesis_hash` before use. None → no genesis serving.
    pub genesis_header_rlp: Option<Vec<u8>>,
}

/// A negotiated, READY eth session over one peer connection.
///
/// Generic over the RLPx stream `S` (default [`TcpStream`]) so the clearnet
/// managed-peer path is unchanged while the Tor PoC can run the identical eth +
/// snap flow over a Tor `DataStream` — see `docs/privacy-and-tor.md` §3/§4.
pub struct EthSession<S = TcpStream> {
    conn: RlpxConnection<S>,
    /// Negotiated eth version (66-69).
    pub eth_version: u64,
    /// Whether the peer also advertised snap/1 (drives EL-A6).
    pub snap: bool,
    /// The peer's Status (its head, fork id).
    pub peer_status: Status,
    /// The peer's Hello (client id, capabilities).
    pub peer_hello: Hello,
    next_request_id: u64,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin> EthSession<S> {
    /// Drive `HANDSHAKE → READY`: exchange Hello, negotiate the eth version,
    /// exchange Status, and gate on network id + genesis. `local_pubkey` is our
    /// node id (64-byte). The whole handshake is bounded by a 30 s timeout.
    pub async fn handshake(
        mut conn: RlpxConnection<S>,
        local_pubkey: &[u8; 64],
        cfg: &EthConfig,
        served_range: Option<(u64, u64, [u8; 32])>,
    ) -> Result<EthSession<S>, String> {
        let fut = async {
            // Send our Hello first (Java sends on RLPX_READY).
            conn.send(P2P_HELLO, &encode_hello(local_pubkey, cfg.listen_port))
                .await?;

            // The peer's first framed message must be Hello (or Disconnect).
            let first = conn.recv().await?;
            if first.message_code == P2P_DISCONNECT {
                return Err(format!(
                    "peer disconnected during handshake: {}",
                    describe_disconnect(&first.payload)
                ));
            }
            if first.message_code != P2P_HELLO {
                return Err(format!("expected Hello, got code 0x{:02x}", first.message_code));
            }
            let peer_hello = decode_hello(&first.payload)?;
            let (eth_version, snap) = negotiate(&peer_hello)
                .ok_or_else(|| format!("no common eth version with {:?}", peer_hello.client_id))?;

            // Send our Status in the negotiated version.
            let status = if eth_version >= 69 {
                // eth/69 (EIP-7642) block range: a promise of what we can SERVE — only
                // blocks the pool's ServedHeaders window actually holds (both ends of
                // `served_range` are held headers). None (empty window / no pool) falls
                // back to the minimal genesis-only [0, 0] — NB a small residual
                // over-claim: unlike Java we embed no genesis header RLP, so a genesis
                // probe still gets an empty answer (pre-existing; Java-parity seeding is
                // a follow-up). Claiming [0, head] (or any window under the head)
                // invites header requests we can never answer, which gets us scored
                // down and dropped.
                let (earliest, latest, latest_hash) = match served_range {
                    Some((e, l, h)) => (e, l, h),
                    None => (0, 0, cfg.genesis_hash),
                };
                messages::encode_status69(
                    eth_version,
                    cfg.network_id,
                    &cfg.genesis_hash,
                    &latest_hash,
                    &cfg.fork_id_hash,
                    cfg.fork_next,
                    earliest,
                    latest,
                )
            } else {
                messages::encode_status(
                    eth_version,
                    cfg.network_id,
                    &cfg.genesis_hash,
                    &cfg.head_hash,
                    &cfg.fork_id_hash,
                    cfg.fork_next,
                )
            };
            tracing::debug!(
                // `{:?}` — client_id is peer-controlled and the host log drains
                // split on '\n'; Debug-escape it so it can't forge log lines.
                client = ?peer_hello.client_id,
                eth = eth_version,
                status_hex = %hex_all(&status),
                "eth handshake: Hello ok, sending Status"
            );
            conn.send(messages::STATUS, &status).await?;

            // Read the peer's Status. `recv_answering_ping` answers any Ping in
            // between; the first other frame must be the Status (or a
            // Disconnect). Anything else fails the handshake instead of being
            // skipped — like the Hello stage above and, for eth messages,
            // geth's `readStatusMsg` (geth's p2p layer also drops a stray Pong;
            // we send no Ping here, so none is due) — and unlike the Java
            // `EthHandler`, which logs it and keeps waiting.
            let frame = recv_answering_ping(&mut conn).await?;
            let peer_status = match frame.message_code {
                messages::STATUS => messages::decode_status(&frame.payload, eth_version)
                    .map_err(|e| format!("peer Status decode: {}", e.0))?,
                P2P_DISCONNECT => {
                    return Err(status_disconnect_error(
                        &peer_hello.client_id,
                        eth_version,
                        &frame.payload,
                    ))
                }
                other => return Err(format!("expected Status, got code 0x{other:02x}")),
            };
            if !peer_status.is_compatible(cfg.network_id, &cfg.genesis_hash) {
                return Err(format!(
                    "incompatible peer: networkId={} genesis={}",
                    peer_status.network_id,
                    hex4(&peer_status.genesis_hash)
                ));
            }

            Ok(EthSession {
                conn,
                eth_version,
                snap,
                peer_status,
                peer_hello,
                next_request_id: 1,
            })
        };
        tokio::time::timeout(Duration::from_secs(30), fut)
            .await
            .map_err(|_| "eth handshake timed out".to_string())?
    }

    /// Every eth/66-69 request/response carries a request id. (The eth/69
    /// changes are the Status shape and bloomless receipts — NOT the request-id
    /// wrapper: the Java `EthHandler` decodes all versions with the reqId path,
    /// so the "eth/69 drops reqId" note in doc 02 §6.6 is inaccurate.)
    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    /// Request a batch of headers by starting block number and await the
    /// matching response. Verifies nothing here — the caller checks hashes
    /// against the beacon anchor (EL-A7).
    pub async fn get_block_headers_by_number(
        &mut self,
        block_number: u64,
        max_headers: u64,
        skip: u64,
        reverse: bool,
    ) -> Result<Vec<messages::VerifiedHeader>, String> {
        let id = self.next_id();
        let req = messages::encode_get_block_headers_by_number(
            id,
            block_number,
            max_headers,
            skip,
            reverse,
        );
        self.conn.send(messages::GET_BLOCK_HEADERS, &req).await?;
        let payload = self.await_response(messages::BLOCK_HEADERS, id).await?;
        let (_rid, headers) = messages::decode_block_headers(&payload)
            .map_err(|e| format!("BlockHeaders decode: {}", e.0))?;
        Ok(headers)
    }

    /// Request headers starting at a block HASH (used to fetch a peer's fresh
    /// head header for its state root).
    pub async fn get_block_headers_by_hash(
        &mut self,
        block_hash: &[u8; 32],
        max_headers: u64,
    ) -> Result<Vec<messages::VerifiedHeader>, String> {
        let id = self.next_id();
        let req = messages::encode_get_block_headers_by_hash(id, block_hash, max_headers, 0, false);
        self.conn.send(messages::GET_BLOCK_HEADERS, &req).await?;
        let payload = self.await_response(messages::BLOCK_HEADERS, id).await?;
        let (_rid, headers) = messages::decode_block_headers(&payload)
            .map_err(|e| format!("BlockHeaders decode: {}", e.0))?;
        Ok(headers)
    }

    /// Request block bodies by hash.
    pub async fn get_block_bodies(
        &mut self,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<messages::BlockBody>, String> {
        let id = self.next_id();
        let req = messages::encode_get_block_bodies(id, hashes);
        self.conn.send(messages::GET_BLOCK_BODIES, &req).await?;
        let payload = self.await_response(messages::BLOCK_BODIES, id).await?;
        let (_rid, bodies) = messages::decode_block_bodies(&payload)
            .map_err(|e| format!("BlockBodies decode: {}", e.0))?;
        Ok(bodies)
    }

    /// Read frames until the expected response code arrives with the matching
    /// request id, answering Ping and ignoring gossip in between.
    async fn await_response(&mut self, want_code: u64, want_id: u64) -> Result<Vec<u8>, String> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("timed out awaiting code 0x{want_code:02x}"));
            }
            let frame = tokio::time::timeout(remaining, recv_answering_ping(&mut self.conn))
                .await
                .map_err(|_| format!("timed out awaiting code 0x{want_code:02x}"))??;

            if frame.message_code == P2P_DISCONNECT {
                return Err(format!("peer disconnected: {}", describe_disconnect(&frame.payload)));
            }
            if frame.message_code != want_code {
                // Gossip / mempool / other responses — ignore (wallet is passive).
                continue;
            }
            if messages::leading_request_id(&frame.payload) == Some(want_id) {
                return Ok(frame.payload);
            }
            // A stale/mismatched id — keep reading.
        }
    }

    pub fn peer_pubkey(&self) -> [u8; 64] {
        self.conn.peer_pubkey()
    }

    /// Consume the negotiated session, handing the framed connection and the
    /// negotiated metadata to the [`ManagedPeer`](crate::el::peer::ManagedPeer)
    /// actor, which drives it from a background read loop.
    pub fn into_parts(self) -> (RlpxConnection<S>, u64, bool, Status, Hello) {
        (self.conn, self.eth_version, self.snap, self.peer_status, self.peer_hello)
    }

    // -----------------------------------------------------------------------
    // snap/1 verified state fetch (EL-A6). These share the eth peer's RLPx
    // connection, multiplexed by the dynamic snap message codes.
    // -----------------------------------------------------------------------

    /// The snap message codes for the negotiated eth version (`None` if the
    /// peer didn't advertise snap/1).
    fn snap_codes(&self) -> Option<snap::SnapCodes> {
        self.snap.then(|| snap::SnapCodes::for_eth_version(self.eth_version))
    }

    /// Fetch and verify one account at `state_root`. `state_root` must be a
    /// FRESH root the peer still retains (peers prune beyond ~128 blocks) —
    /// the caller supplies it (EL-A7 pins it to the beacon anchor / a fresh
    /// peer head). The returned account fields come from the MPT-verified
    /// proof leaf, never the peer's slim body.
    pub async fn snap_get_account(
        &mut self,
        state_root: &[u8; 32],
        address: &[u8; 20],
    ) -> Result<AccountOutcome, String> {
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let id = self.next_id();
        let account_hash = myotis_core::keccak::keccak256(address);
        // Full [origin, 0xff…ff] range + a small responseBytes cap: the peer
        // returns one account PLUS the complete boundary proof (doc 02 §7.3).
        let req = snap::encode_get_account(id, state_root, &account_hash, 4096);
        self.conn.send(codes.get_account_range, &req).await?;
        let payload = self
            .await_snap_response(codes.account_range, id)
            .await?;
        let response = snap::decode_account_range(&payload)
            .map_err(|e| format!("AccountRange decode: {}", e.0))?;
        fetch::verify_account(state_root, address, &response).map_err(|e| e.0)
    }

    /// Fetch and verify one storage slot. Requires the account (for its
    /// proven `storage_root`); storage verifies against THAT root, not the
    /// world state root.
    pub async fn snap_get_storage(
        &mut self,
        state_root: &[u8; 32],
        address: &[u8; 20],
        account: &AccountLeaf,
        slot: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        // An account with no storage trie: every slot is provably zero, so skip
        // the round trip entirely (EOAs and storage-less contracts).
        if account.storage_root == EMPTY_TRIE_ROOT {
            return Ok(Vec::new());
        }
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let id = self.next_id();
        let account_hash = myotis_core::keccak::keccak256(address);
        let slot_hash = myotis_core::keccak::keccak256(slot);
        let req = snap::encode_get_storage_slot(id, state_root, &account_hash, &slot_hash, 4096);
        self.conn.send(codes.get_storage_ranges, &req).await?;
        let payload = self
            .await_snap_response(codes.storage_ranges, id)
            .await?;
        let response = snap::decode_storage_ranges(&payload)
            .map_err(|e| format!("StorageRanges decode: {}", e.0))?;
        fetch::verify_storage(account, slot, &response).map_err(|e| e.0)
    }

    /// Fetch and verify one contract's bytecode by its `code_hash`.
    pub async fn snap_get_bytecode(&mut self, code_hash: &[u8; 32]) -> Result<Vec<u8>, String> {
        // A code-less account: no round trip needed (EOAs — the vast majority).
        if code_hash == &EMPTY_CODE_HASH {
            return Ok(Vec::new());
        }
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let id = self.next_id();
        let req = snap::encode_get_byte_codes(id, &[*code_hash], 256 * 1024);
        self.conn.send(codes.get_byte_codes, &req).await?;
        let payload = self.await_snap_response(codes.byte_codes, id).await?;
        let (_id, codes_returned) =
            snap::decode_byte_codes(&payload).map_err(|e| format!("ByteCodes decode: {}", e.0))?;
        fetch::verify_bytecode(code_hash, &codes_returned)
            .ok_or_else(|| "no returned bytecode matched the requested hash".to_string())
    }

    /// Fetch the contiguous header range `[finalized_block ..= peer_block]` and
    /// run the header-chain verdict against the beacon-anchored root. Returns
    /// `headerChainError` on a transport failure and `headerChainInvalid` on a
    /// short/over-long/out-of-range response (matching the Java ladder).
    ///
    /// **A7b:** this is a SINGLE request, so it only spans a gap the peer serves
    /// in one response (~1024 headers on geth) — fine for a typical finalized
    /// gap (~2 epochs, tens–low-hundreds of blocks). A stale-finalized peer with
    /// a multi-thousand-block gap truncates the response → `chain.len() != total`
    /// → `headerChainInvalid` (fail-closed, never a partial-chain trust). Batched
    /// fetching for large gaps lands in the A7b connection layer.
    async fn header_chain_verdict(
        &mut self,
        finalized_block: u64,
        peer_block: u64,
        beacon_block_hash: &[u8; 32],
        peer_state_root: &[u8; 32],
        finalized_slot: i64,
    ) -> crate::el::verify::Verdict {
        use crate::el::verify::{header_chain_verdict, ChainHeader, Verdict, MAX_HEADER_CHAIN_GAP};
        let total = peer_block - finalized_block + 1;
        // Match Java's verifyHeaderChainBatched re-guard: total in [2, MAX].
        // (The precheck admits gap == MAX, i.e. total == MAX+1; Java rejects it
        // here — keep that exact boundary.)
        if total < 2 || total > MAX_HEADER_CHAIN_GAP {
            return Verdict {
                fail_reason: Some("headerChainInvalid"),
                ..Verdict::default()
            };
        }
        // Fetch ascending from the finalized block (skip=0, reverse=false).
        let headers = match self
            .get_block_headers_by_number(finalized_block, total, 0, false)
            .await
        {
            Ok(h) => h,
            Err(_) => {
                return Verdict {
                    fail_reason: Some("headerChainError"),
                    ..Verdict::default()
                }
            }
        };
        let chain: Vec<ChainHeader> = headers
            .into_iter()
            .map(|vh| ChainHeader { hash: vh.hash, header: vh.header })
            .collect();
        // A short/over-long response can't verify — treat as invalid, not a panic.
        if chain.len() as u64 != total {
            return Verdict {
                fail_reason: Some("headerChainInvalid"),
                ..Verdict::default()
            };
        }
        header_chain_verdict(&chain, beacon_block_hash, peer_state_root, finalized_slot)
    }

    /// Anchor a peer-served `state_root` (for `block_number`) to the beacon
    /// chain, running the full ladder: `stateRootMatch` fast path, else the
    /// `headerChain` walk. `proof_valid` is the caller's MPT-proof result
    /// against `state_root`. This is the verdict half of the verified read —
    /// EL-A7b composes it with the snap account fetch + the JNI surface.
    pub async fn verified_state_root(
        &mut self,
        anchor: &crate::el::anchor::ExecAnchor,
        state_root: &[u8; 32],
        block_number: i64,
        proof_valid: bool,
    ) -> crate::el::verify::Verdict {
        use crate::el::verify::{ladder_precheck, LadderStep};
        match ladder_precheck(Some(state_root), proof_valid, block_number, anchor) {
            LadderStep::Done(verdict) => verdict,
            LadderStep::NeedHeaderChain {
                finalized_block,
                peer_block,
                beacon_block_hash,
                finalized_slot,
            } => {
                self.header_chain_verdict(
                    finalized_block,
                    peer_block,
                    &beacon_block_hash,
                    state_root,
                    finalized_slot,
                )
                .await
            }
        }
    }

    /// Like [`await_response`] but matches a snap response id (snap responses
    /// carry the same leading `[reqId, …]`).
    async fn await_snap_response(&mut self, want_code: u64, want_id: u64) -> Result<Vec<u8>, String> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("timed out awaiting snap code 0x{want_code:02x}"));
            }
            let frame = tokio::time::timeout(remaining, recv_answering_ping(&mut self.conn))
                .await
                .map_err(|_| format!("timed out awaiting snap code 0x{want_code:02x}"))??;
            if frame.message_code == P2P_DISCONNECT {
                return Err(format!("peer disconnected: {}", describe_disconnect(&frame.payload)));
            }
            if frame.message_code != want_code {
                continue;
            }
            if messages::leading_request_id(&frame.payload) == Some(want_id) {
                return Ok(frame.payload);
            }
        }
    }
}

/// Highest common eth version (floor 66) + whether snap/1 is offered.
fn negotiate(hello: &Hello) -> Option<(u64, bool)> {
    let mut best: Option<u64> = None;
    let mut snap = false;
    for cap in &hello.capabilities {
        if cap.name == "eth" && OUR_ETH_VERSIONS.contains(&cap.version) && cap.version >= MIN_ETH_VERSION {
            best = Some(best.map_or(cap.version, |b| b.max(cap.version)));
        }
        if cap.name == "snap" && cap.version == 1 {
            snap = true;
        }
    }
    best.map(|v| (v, snap))
}

/// Receive the next frame, transparently answering a p2p Ping with a Pong.
async fn recv_answering_ping<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    conn: &mut RlpxConnection<S>,
) -> Result<crate::el::rlpx::frame::DecodedFrame, String> {
    loop {
        let frame = conn.recv().await?;
        if frame.message_code == P2P_PING {
            // Pong body is an empty RLP list.
            conn.send(P2P_PONG, &[0xc0]).await?;
            continue;
        }
        return Ok(frame);
    }
}

/// The Status-stage disconnect error. Keeps the "peer disconnected" prefix +
/// `describe_disconnect`'s "reason=N" suffix — the pool's busy classifier pins
/// both ends (its test builds a string through THIS producer). `{:?}` on the
/// peer-controlled client id Debug-escapes newlines so it can't forge log
/// lines in the hosts' split-on-'\n' drains.
pub(crate) fn status_disconnect_error(client_id: &str, eth_version: u64, payload: &[u8]) -> String {
    format!(
        "peer disconnected after our Status (client={:?} eth={}): {}",
        client_id,
        eth_version,
        describe_disconnect(payload)
    )
}

/// A p2p Disconnect body is `[reason]` (or a bare `reason`); decode the reason
/// code for logging. `pub(crate)` so the pool's busy-classification test can
/// pin the classifier against THIS producer — a format change here must break
/// that test instead of silently degrading busy classification to transient.
/// The peer read loop reports disconnects through it too. A body over the
/// control-message cap is not decoded (#454) and reads as an unknown reason.
pub(crate) fn describe_disconnect(payload: &[u8]) -> String {
    let reason = Some(payload)
        .filter(|p| p.len() <= MAX_CONTROL_MSG_SIZE)
        .and_then(|p| rlp::decode(p).ok())
        .and_then(|it| match it {
            Item::List(items) => items.first().and_then(|r| r.as_u64().ok()),
            Item::Bytes(_) => it.as_u64().ok(),
        })
        .unwrap_or(u64::MAX);
    format!("reason={reason}")
}

fn hex_all(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex4(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::el::rlpx::handshake::SessionSecrets;
    use crate::el::rlpx::transport::Capability;
    use tokio::io::DuplexStream;

    fn hello_with(caps: Vec<(&str, u64)>) -> Hello {
        Hello {
            protocol_version: 5,
            client_id: "Geth/test".into(),
            capabilities: caps
                .into_iter()
                .map(|(n, v)| Capability { name: n.into(), version: v })
                .collect(),
            listen_port: 30303,
            node_id: vec![0u8; 64],
        }
    }

    #[test]
    fn negotiate_highest_common_and_snap() {
        assert_eq!(
            negotiate(&hello_with(vec![("eth", 66), ("eth", 68), ("snap", 1)])),
            Some((68, true))
        );
        assert_eq!(negotiate(&hello_with(vec![("eth", 69)])), Some((69, false)));
        // eth/65 is below the floor; no common version.
        assert_eq!(negotiate(&hello_with(vec![("eth", 65), ("les", 4)])), None);
        // Unknown-to-us high version is ignored; falls back to the common one.
        assert_eq!(negotiate(&hello_with(vec![("eth", 67), ("eth", 99)])), Some((67, false)));
    }

    #[test]
    fn describe_disconnect_reads_both_shapes_and_not_an_oversized_body() {
        assert_eq!(describe_disconnect(&[0xc1, 0x04]), "reason=4");
        assert_eq!(describe_disconnect(&[0x04]), "reason=4");
        // Too big to be a real Disconnect: not decoded, the reason is unknown.
        let oversized = rlp::encode_list_payload(&[0x04; MAX_CONTROL_MSG_SIZE]);
        assert_eq!(describe_disconnect(&oversized), format!("reason={}", u64::MAX));
    }

    // --- The Status stage, against a scripted peer over an in-memory stream.

    const NETWORK_ID: u64 = 1;
    const GENESIS: [u8; 32] = [0x11; 32];
    const FORK_HASH: [u8; 4] = [0xaa; 4];

    fn test_config() -> EthConfig {
        EthConfig {
            network_id: NETWORK_ID,
            genesis_hash: GENESIS,
            fork_id_hash: FORK_HASH,
            fork_next: 0,
            head_hash: GENESIS,
            head_number: 0,
            listen_port: 30303,
            genesis_header_rlp: None,
        }
    }

    /// Our side (the initiator) and the peer's side of one FRAMED connection
    /// over an in-memory stream — no ECIES handshake.
    fn framed_pair() -> (RlpxConnection<DuplexStream>, RlpxConnection<DuplexStream>) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (initiator, responder) = SessionSecrets::test_pair();
        (
            RlpxConnection::from_secrets(ours, &initiator, [2; 64]),
            RlpxConnection::from_secrets(theirs, &responder, [1; 64]),
        )
    }

    /// Run our handshake against a peer that answers our Hello with its own
    /// (eth/66-69 + snap/1, so eth/69 is negotiated) and sends `script` once our
    /// Status arrives. Returns our outcome (negotiated version, snap, the peer's
    /// Status) and the codes of every frame we sent after our Status.
    async fn handshake_against(
        script: Vec<(u64, Vec<u8>)>,
    ) -> (Result<(u64, bool, Status), String>, Vec<u64>) {
        let (ours, mut peer) = framed_pair();
        let peer_side = tokio::spawn(async move {
            assert_eq!(peer.recv().await.unwrap().message_code, P2P_HELLO);
            peer.send(P2P_HELLO, &encode_hello(&[2; 64], 30303)).await.unwrap();
            assert_eq!(peer.recv().await.unwrap().message_code, messages::STATUS);
            for (code, body) in script {
                peer.send(code, &body).await.unwrap();
            }
            // Whatever we answer, until our side hangs up.
            let mut answered = Vec::new();
            while let Ok(frame) = peer.recv().await {
                answered.push(frame.message_code);
            }
            answered
        });
        let outcome = EthSession::handshake(ours, &[1; 64], &test_config(), None)
            .await
            // Dropping the session's connection is what ends the peer's loop.
            .map(|session| {
                let (_conn, eth_version, snap, status, _hello) = session.into_parts();
                (eth_version, snap, status)
            });
        (outcome, peer_side.await.unwrap())
    }

    // start_paused: a handshake left waiting (e.g. one that skipped the frame
    // under test) hits its 30 s timeout at once instead of stalling the suite.

    #[tokio::test(start_paused = true)]
    async fn status_stage_answers_a_ping_then_accepts_the_status() {
        let status =
            messages::encode_status69(69, NETWORK_ID, &GENESIS, &[0x22; 32], &FORK_HASH, 0, 0, 100);
        let (outcome, answered) =
            handshake_against(vec![(P2P_PING, vec![0xc0]), (messages::STATUS, status)]).await;
        let (eth_version, snap, peer_status) = outcome.expect("handshake completes");
        assert_eq!((eth_version, snap), (69, true));
        assert_eq!(peer_status.network_id, NETWORK_ID);
        assert_eq!(peer_status.latest_block, Some(100));
        assert_eq!(answered, vec![P2P_PONG]);
    }

    #[tokio::test(start_paused = true)]
    async fn status_stage_rejects_any_other_first_frame() {
        // Gossip, an eth/69 BlockRangeUpdate or a stray Pong where the Status
        // must be fails the handshake, unanswered; it is not skipped to wait
        // for a Status that may follow.
        for code in [
            messages::TRANSACTIONS,
            messages::NEW_POOLED_TRANSACTION_HASHES,
            messages::BLOCK_RANGE_UPDATE,
            P2P_PONG,
        ] {
            let (outcome, answered) = handshake_against(vec![(code, vec![0xc0])]).await;
            assert_eq!(outcome.unwrap_err(), format!("expected Status, got code 0x{code:02x}"));
            assert!(answered.is_empty(), "code 0x{code:02x}: answered {answered:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn status_stage_undecodable_or_foreign_status_is_incompatible() {
        // The pool's dial arm blacklists on exactly these PREFIXES (the
        // `incompatible` check in pool.rs) — a rewording here would demote a
        // foreign-chain peer to a transient redial.
        let (outcome, _) = handshake_against(vec![(messages::STATUS, vec![0xc0])]).await;
        let err = outcome.unwrap_err();
        assert!(err.starts_with("peer Status decode"), "{err}");

        let foreign =
            messages::encode_status69(69, 137, &GENESIS, &[0x22; 32], &FORK_HASH, 0, 0, 100);
        let (outcome, _) = handshake_against(vec![(messages::STATUS, foreign)]).await;
        let err = outcome.unwrap_err();
        assert!(err.starts_with("incompatible peer"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn status_stage_refuses_an_oversized_status_as_undecodable() {
        // Our Status plus trailing one-byte fields, which the decoder
        // tolerates at any real size.
        let padded = |extra: usize| {
            let status =
                messages::encode_status69(69, NETWORK_ID, &GENESIS, &[0x22; 32], &FORK_HASH, 0, 0, 100);
            let mut fields = rlp::raw_list_items(&status).unwrap().concat();
            fields.resize(fields.len() + extra, 0x01);
            rlp::encode_list_payload(&fields)
        };
        let (outcome, _) = handshake_against(vec![(messages::STATUS, padded(1_000))]).await;
        assert_eq!(outcome.expect("a padded Status under the cap is accepted").2.latest_block, Some(100));

        // Over the cap it is refused before its tree is built (#454), with the
        // prefix the pool blacklists on, like any undecodable Status.
        let (outcome, _) =
            handshake_against(vec![(messages::STATUS, padded(MAX_CONTROL_MSG_SIZE))]).await;
        let err = outcome.unwrap_err();
        assert!(err.starts_with("peer Status decode"), "{err}");
        assert!(err.contains("control-message cap"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn status_stage_disconnect_classifies_as_busy() {
        // rlp([4]) = TooManyPeers: the Status-stage error must land in the
        // pool's busy class (`BACKOFF_BUSY`), not degrade to transient.
        let (outcome, _) = handshake_against(vec![(P2P_DISCONNECT, vec![0xc1, 0x04])]).await;
        let err = outcome.unwrap_err();
        assert!(err.starts_with("peer disconnected after our Status"), "{err}");
        assert!(crate::el::pool::is_busy_disconnect(&err), "{err}");
    }
}
