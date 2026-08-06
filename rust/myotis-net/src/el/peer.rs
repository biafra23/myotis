//! The managed-peer connection actor (EL-A7b): a negotiated eth/snap peer whose
//! RLPx connection is driven by a background read loop, so requests correlate
//! by request id concurrently instead of the single-shot, one-request-at-a-time
//! [`EthSession`](crate::el::eth::session::EthSession) model.
//!
//! Since the RLPx frame codec's egress and ingress state are independent, the
//! connection splits into a [`RlpxReader`]/[`RlpxWriter`] pair
//! ([`RlpxConnection::split`]). The read task owns the reader and a clone of the
//! shared writer; it classifies each inbound frame:
//!
//! * p2p **Ping** → **Pong** (keeps the peer from dropping us on idle),
//! * p2p **Disconnect** / a read error → fail every in-flight request and stop,
//! * an inbound eth/snap **Get\*** request → an **empty** response (the wallet
//!   serves no chain data, but a well-behaved empty answer beats a timeout),
//! * a response → delivered to the waiting request by `(reqId, code)`,
//! * anything else (gossip, mempool) → ignored.
//!
//! Request methods take `&self`: the writer is an `Arc<Mutex<…>>` and the
//! request-id counter is atomic, so several requests can be outstanding at once.
//! This is the twin of the Java `EthHandler`'s always-listening channel (its
//! Netty pipeline answers Ping and unsolicited Get\* the same way).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

use myotis_core::rlp;
use myotis_core::trie::{AccountLeaf, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};

use crate::el::anchor::ExecAnchor;
use crate::el::served::ServeContext;
use crate::el::eth::messages::{self, Status, VerifiedHeader};
use crate::el::eth::session::EthSession;
use crate::el::rlpx::transport::{
    Hello, RlpxConnection, RlpxReader, RlpxWriter, P2P_DISCONNECT, P2P_PING, P2P_PONG,
};
use crate::el::snap::fetch::{self, AccountOutcome};
use crate::el::snap::messages as snap;
use crate::el::verify::Verdict;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// One in-flight request: the response code it expects and the delivery channel.
struct Pending {
    want_code: u64,
    tx: oneshot::Sender<Result<Vec<u8>, String>>,
}

type PendingMap = Arc<Mutex<HashMap<u64, Pending>>>;

/// The egress writer plus a torn-write marker. A frame write whose future is
/// DROPPED mid-await (request futures are cancelled routinely — e.g. the
/// backfill pipeline dropping its in-flight stream on truncation) may have put
/// a partial frame on the wire with the egress MAC already advanced; nothing
/// runs afterwards to notice. `torn` is set before every send and cleared only
/// when the send completes, so the next lock holder observes the tear and
/// refuses the corrupt stream instead of writing MAC-garbage after it.
struct GuardedWriter {
    inner: RlpxWriter,
    torn: bool,
}

type SharedWriter = Arc<Mutex<GuardedWriter>>;

/// Send one frame under the writer lock, cancel-safely: a previous send that
/// was cancelled mid-frame leaves `torn` set, which this surfaces as a write
/// error — every call site already treats that as fatal (`fail_all` + close).
async fn send_frame(writer: &SharedWriter, code: u64, body: &[u8]) -> Result<(), String> {
    let mut w = writer.lock().await;
    if w.torn {
        return Err("egress stream torn by a cancelled frame write".to_string());
    }
    w.torn = true;
    let result = w.inner.send(code, body).await;
    w.torn = false;
    result
}

/// A negotiated eth/snap peer, driven by a background read loop.
pub struct ManagedPeer {
    writer: SharedWriter,
    pending: PendingMap,
    next_id: AtomicU64,
    /// Set once the read loop terminates (disconnect / read error); requests
    /// short-circuit instead of hanging until timeout.
    closed: Arc<AtomicBool>,
    reader_task: JoinHandle<()>,

    /// Negotiated eth version (66-69).
    pub eth_version: u64,
    /// Whether the peer also advertised snap/1.
    pub snap: bool,
    /// The peer's Status (head, fork id).
    pub peer_status: Status,
    /// The peer's Hello (client id, capabilities).
    pub peer_hello: Hello,
    peer_pubkey: [u8; 64],
    /// The socket address this peer was dialed at — the key the pool's peer
    /// cache records snap-serve/failure outcomes under.
    addr: SocketAddr,
    snap_codes: Option<snap::SnapCodes>,
    /// Pool-shared serving surface (window + counters); None in fixtures that
    /// spawn a peer without a pool.
    serve: Option<ServeContext>,
}

impl ManagedPeer {
    /// Take over a handshook [`EthSession`], splitting its connection and
    /// spawning the background read loop. From here the peer serves concurrent
    /// requests and answers Ping/Get\* on its own.
    pub fn spawn(session: EthSession, addr: SocketAddr) -> ManagedPeer {
        let (conn, eth_version, snap, peer_status, peer_hello) = session.into_parts();
        Self::from_connection(conn, eth_version, snap, peer_status, peer_hello, addr, None, None)
    }

    /// As [`spawn`](Self::spawn), wiring the pool's shared serving surface so this
    /// peer answers GetBlockHeaders from the window and counts inbound demand,
    /// plus the sent-tx watch so gossip sightings of our own broadcasts register
    /// (the Java TxGossipObserver twin).
    pub fn spawn_serving(
        session: EthSession,
        addr: SocketAddr,
        serve: ServeContext,
        tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
    ) -> ManagedPeer {
        let (conn, eth_version, snap, peer_status, peer_hello) = session.into_parts();
        Self::from_connection(
            conn,
            eth_version,
            snap,
            peer_status,
            peer_hello,
            addr,
            Some(serve),
            tx_watch,
        )
    }

    fn from_connection(
        conn: RlpxConnection,
        eth_version: u64,
        snap: bool,
        peer_status: Status,
        peer_hello: Hello,
        addr: SocketAddr,
        serve: Option<ServeContext>,
        tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
    ) -> ManagedPeer {
        let (reader, writer, peer_pubkey) = conn.split();
        let snap_codes = snap.then(|| snap::SnapCodes::for_eth_version(eth_version));
        let writer = Arc::new(Mutex::new(GuardedWriter { inner: writer, torn: false }));
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let closed = Arc::new(AtomicBool::new(false));

        let reader_task = tokio::spawn(read_loop(
            reader,
            Arc::clone(&writer),
            Arc::clone(&pending),
            Arc::clone(&closed),
            snap_codes,
            serve.clone(),
            tx_watch,
        ));

        ManagedPeer {
            writer,
            pending,
            next_id: AtomicU64::new(1),
            closed,
            reader_task,
            eth_version,
            snap,
            peer_status,
            peer_hello,
            peer_pubkey,
            addr,
            snap_codes,
            serve,
        }
    }

    pub fn peer_pubkey(&self) -> [u8; 64] {
        self.peer_pubkey
    }

    /// The socket address this peer was dialed at (the peer-cache key).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// True once the read loop has stopped (peer disconnect or fatal read
    /// error); the peer serves no further requests.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Send one request and await its response, correlating by request id. The
    /// closure receives the allocated id so the encoded body carries it. Fails
    /// fast if the peer is already closed, on a write error, or on timeout.
    async fn request(
        &self,
        send_code: u64,
        want_code: u64,
        encode: impl FnOnce(u64) -> Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = encode(id);
        let (tx, rx) = oneshot::channel();

        // Insert while holding the pending lock, checking `closed` inside it.
        // `fail_all` sets `closed` under the SAME lock, so we can't lose the
        // race where the read loop drains the map (on disconnect) between an
        // unlocked check and our insert — either we insert before the drain (and
        // it delivers our Err) or we observe `closed` and bail here.
        {
            let mut map = self.pending.lock().await;
            if self.closed.load(Ordering::SeqCst) {
                return Err("peer connection closed".to_string());
            }
            map.insert(id, Pending { want_code, tx });
        }

        // Send under the writer lock; a write failure leaves the egress frame
        // stream in an indeterminate state (a partial frame may be on the wire),
        // so fail EVERY in-flight request — not just this one, which would leave
        // the others hanging until their own timeouts on a dead connection.
        // (If THIS future is cancelled inside the send, the torn marker in
        // `send_frame` makes the next writer fail here instead; the pending
        // entry inserted above is then drained by that `fail_all`, or by the
        // discarded late response — either way it stays bounded.)
        if let Err(e) = send_frame(&self.writer, send_code, &body).await {
            fail_all(&self.pending, &self.closed, format!("peer write failure: {e}")).await;
            return Err(e);
        }

        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            // The read loop dropped the sender (disconnect drained the map).
            Ok(Err(_)) => Err("peer connection closed".to_string()),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(format!("timed out awaiting code 0x{want_code:02x}"))
            }
        }
    }

    /// Push an eth/69 BlockRangeUpdate advertising our current servable range.
    /// No-op on eth/68- peers (absolute 0x21 is their SNAP base, not a free
    /// slot) or a closed peer.
    pub async fn send_block_range_update(&self, earliest: u64, latest: u64, latest_hash: [u8; 32]) {
        if self.eth_version < 69 || self.is_closed() {
            return;
        }
        let body = messages::encode_block_range_update(earliest, latest, &latest_hash);
        // The update itself is fire-and-forget, but a WRITE failure is not: a
        // frame-write timeout leaves the egress stream mid-frame with the MAC
        // advanced (see write_frame), so the writer must not be reused — close
        // the peer like every other send path does.
        if let Err(e) = send_frame(&self.writer, messages::BLOCK_RANGE_UPDATE, &body).await {
            fail_all(&self.pending, &self.closed, format!("peer write failure: {e}")).await;
        }
    }

    /// Broadcast a single raw transaction to this peer via the eth `Transactions`
    /// message (fire-and-forget — no request id, no response). `raw_tx` is the
    /// consensus encoding. On a write failure the connection is dead, so fail every
    /// in-flight request too (a partial frame corrupts the stream), same as
    /// [`Self::request`].
    pub async fn send_transaction(&self, raw_tx: &[u8]) -> Result<(), String> {
        let body = messages::encode_transactions(raw_tx);
        if let Err(e) = send_frame(&self.writer, messages::TRANSACTIONS, &body).await {
            fail_all(&self.pending, &self.closed, format!("peer write failure: {e}")).await;
            return Err(e);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // eth requests.
    // -----------------------------------------------------------------------

    /// Request a batch of headers by starting block number. Verifies nothing
    /// here — the caller checks hashes against the beacon anchor.
    pub async fn get_block_headers_by_number(
        &self,
        block_number: u64,
        max_headers: u64,
        skip: u64,
        reverse: bool,
    ) -> Result<Vec<VerifiedHeader>, String> {
        let payload = self
            .request(messages::GET_BLOCK_HEADERS, messages::BLOCK_HEADERS, |id| {
                messages::encode_get_block_headers_by_number(id, block_number, max_headers, skip, reverse)
            })
            .await?;
        let (_rid, headers) = messages::decode_block_headers(&payload)
            .map_err(|e| format!("BlockHeaders decode: {}", e.0))?;
        // Window-poisoning guard: only remember headers whose number lies in the
        // range WE requested — a hostile peer answering with fabricated far-future
        // numbers could otherwise pin the window's eviction floor at ~u64::MAX
        // (killing serving until restart) and poison the advertised eth/69 range.
        // Only the simple ascending-contiguous shape is remembered: with skip or
        // reverse in play a span filter would admit attacker numbers between the
        // steps, and every production fetch (verdict walks) is skip=0/ascending —
        // exotic shapes just skip the (side-channel) window population. The
        // RETURNED headers are unaffected either way; verification consumes them
        // unfiltered and checks hashes itself.
        if skip == 0 && !reverse {
            let hi = block_number.saturating_add(max_headers);
            self.remember_served(headers.iter().filter(|vh| {
                vh.header.number >= block_number && vh.header.number < hi
            }));
        }
        Ok(headers)
    }

    /// As [`get_block_headers_by_number`](Self::get_block_headers_by_number) but
    /// WITHOUT populating the served window: the backfill uses this and admits
    /// headers itself only after anchoring the whole batch to the beacon head
    /// by parent-hash (see `pool::backfill_served_headers`) — stronger than the
    /// range-only filter that guards the organic fetch paths.
    pub async fn get_block_headers_by_number_raw(
        &self,
        block_number: u64,
        max_headers: u64,
    ) -> Result<Vec<VerifiedHeader>, String> {
        let payload = self
            .request(messages::GET_BLOCK_HEADERS, messages::BLOCK_HEADERS, |id| {
                messages::encode_get_block_headers_by_number(id, block_number, max_headers, 0, false)
            })
            .await?;
        let (_rid, headers) = messages::decode_block_headers(&payload)
            .map_err(|e| format!("BlockHeaders decode: {}", e.0))?;
        Ok(headers)
    }

    /// Request headers starting at a block HASH (fetch a peer's fresh head).
    pub async fn get_block_headers_by_hash(
        &self,
        block_hash: &[u8; 32],
        max_headers: u64,
    ) -> Result<Vec<VerifiedHeader>, String> {
        let payload = self
            .request(messages::GET_BLOCK_HEADERS, messages::BLOCK_HEADERS, |id| {
                messages::encode_get_block_headers_by_hash(id, block_hash, max_headers, 0, false)
            })
            .await?;
        let (_rid, headers) = messages::decode_block_headers(&payload)
            .map_err(|e| format!("BlockHeaders decode: {}", e.0))?;
        // Same poisoning guard as the by-number path: only the header whose hash
        // is the one WE asked for may enter the window.
        self.remember_served(headers.iter().filter(|vh| vh.hash == *block_hash));
        Ok(headers)
    }

    /// Make freshly received, REQUEST-MATCHED headers servable to OTHER peers:
    /// headers this node fetches (verdict walks, head probes) land in the
    /// pool-shared window, raw wire bytes + recomputed hash — the same integrity
    /// level as the Java window. Callers filter to what they actually requested
    /// (see the poisoning guards at both call sites). No-op without a pool.
    fn remember_served<'a>(&self, headers: impl Iterator<Item = &'a messages::VerifiedHeader>) {
        if let Some(ctx) = &self.serve {
            for vh in headers {
                ctx.window.put(vh.header.number, vh.hash, vh.header.parent_hash, vh.raw_rlp.clone());
            }
        }
    }

    /// Request block bodies by hash.
    pub async fn get_block_bodies(
        &self,
        hashes: &[[u8; 32]],
    ) -> Result<Vec<messages::BlockBody>, String> {
        let payload = self
            .request(messages::GET_BLOCK_BODIES, messages::BLOCK_BODIES, |id| {
                messages::encode_get_block_bodies(id, hashes)
            })
            .await?;
        let (_rid, bodies) = messages::decode_block_bodies(&payload)
            .map_err(|e| format!("BlockBodies decode: {}", e.0))?;
        Ok(bodies)
    }

    /// Request transaction receipts by block hash, returning the RAW canonical
    /// consensus receipt bytes per block — the receipts-trie values, ready for
    /// `triehash::verify` against a header's `receiptsRoot`. An eth/69 peer's
    /// bloomless response is re-canonicalized (bloom recomputed) by the decoder,
    /// so callers see one shape across versions.
    pub async fn get_receipts(&self, hashes: &[[u8; 32]]) -> Result<Vec<Vec<Vec<u8>>>, String> {
        let payload = self
            .request(messages::GET_RECEIPTS, messages::RECEIPTS, |id| {
                messages::encode_get_receipts(id, hashes)
            })
            .await?;
        let (_rid, blocks) = if self.eth_version >= 69 {
            messages::decode_receipts69(&payload)
                .map_err(|e| format!("Receipts (eth/69) decode: {}", e.0))?
        } else {
            messages::decode_receipts(&payload).map_err(|e| format!("Receipts decode: {}", e.0))?
        };
        Ok(blocks)
    }

    // -----------------------------------------------------------------------
    // snap/1 verified state fetch (shares the eth peer's RLPx connection).
    // -----------------------------------------------------------------------

    fn snap_codes(&self) -> Option<snap::SnapCodes> {
        self.snap_codes
    }

    /// Fetch and verify one account at `state_root` (a FRESH root the peer still
    /// retains). The returned fields come from the MPT-verified proof leaf,
    /// never the peer's slim body.
    pub async fn snap_get_account(
        &self,
        state_root: &[u8; 32],
        address: &[u8; 20],
    ) -> Result<AccountOutcome, String> {
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let account_hash = myotis_core::keccak::keccak256(address);
        let payload = self
            .request(codes.get_account_range, codes.account_range, |id| {
                snap::encode_get_account(id, state_root, &account_hash, 4096)
            })
            .await?;
        let response = snap::decode_account_range(&payload)
            .map_err(|e| format!("AccountRange decode: {}", e.0))?;
        fetch::verify_account(state_root, address, &response).map_err(|e| e.0)
    }

    /// Fetch and verify one storage slot against the account's proven
    /// `storage_root` (not the world state root).
    pub async fn snap_get_storage(
        &self,
        state_root: &[u8; 32],
        address: &[u8; 20],
        account: &AccountLeaf,
        slot: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        // No storage trie → every slot is provably zero; skip the round trip.
        if account.storage_root == EMPTY_TRIE_ROOT {
            return Ok(Vec::new());
        }
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let account_hash = myotis_core::keccak::keccak256(address);
        let slot_hash = myotis_core::keccak::keccak256(slot);
        let payload = self
            .request(codes.get_storage_ranges, codes.storage_ranges, |id| {
                snap::encode_get_storage_slot(id, state_root, &account_hash, &slot_hash, 4096)
            })
            .await?;
        let response = snap::decode_storage_ranges(&payload)
            .map_err(|e| format!("StorageRanges decode: {}", e.0))?;
        fetch::verify_storage(account, slot, &response).map_err(|e| e.0)
    }

    /// Fetch and verify one contract's bytecode by its `code_hash`.
    pub async fn snap_get_bytecode(&self, code_hash: &[u8; 32]) -> Result<Vec<u8>, String> {
        // A code-less account (EOAs — the vast majority): no round trip.
        if code_hash == &EMPTY_CODE_HASH {
            return Ok(Vec::new());
        }
        let codes = self.snap_codes().ok_or("peer does not support snap/1")?;
        let payload = self
            .request(codes.get_byte_codes, codes.byte_codes, |id| {
                snap::encode_get_byte_codes(id, &[*code_hash], 256 * 1024)
            })
            .await?;
        let (_id, codes_returned) =
            snap::decode_byte_codes(&payload).map_err(|e| format!("ByteCodes decode: {}", e.0))?;
        fetch::verify_bytecode(code_hash, &codes_returned)
            .ok_or_else(|| "no returned bytecode matched the requested hash".to_string())
    }

    // -----------------------------------------------------------------------
    // Verified-read verdicts (the ladder over the anchored beacon state).
    // -----------------------------------------------------------------------

    /// Anchor a peer-served `state_root` (for `block_number`) to the beacon
    /// chain: `stateRootMatch` fast path, else the `headerChain` walk.
    /// `proof_valid` is the caller's MPT-proof result against `state_root`.
    pub async fn verified_state_root(
        &self,
        anchor: &ExecAnchor,
        state_root: &[u8; 32],
        block_number: i64,
        proof_valid: bool,
    ) -> Verdict {
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

    /// Fetch `[finalized_block ..= peer_block]` and run the header-chain verdict
    /// against the beacon-anchored block hash. `headerChainError` on transport
    /// failure, `headerChainInvalid` on a short/over-long/out-of-range response
    /// (matching the Java ladder). A single request, so it only spans a gap the
    /// peer serves in one response — a multi-thousand-block gap truncates and
    /// fails closed (batched fetch lands in a later A7b sub-PR).
    async fn header_chain_verdict(
        &self,
        finalized_block: u64,
        peer_block: u64,
        beacon_block_hash: &[u8; 32],
        peer_state_root: &[u8; 32],
        finalized_slot: i64,
    ) -> Verdict {
        use crate::el::verify::{header_chain_verdict, ChainHeader, MAX_HEADER_CHAIN_GAP};
        // `ladder_precheck` only reaches here with peer_block > finalized_block,
        // but guard the subtraction anyway — under panic="abort" an underflow
        // would kill the process, so fail the verdict closed instead.
        let total = match peer_block.checked_sub(finalized_block) {
            Some(diff) => diff + 1,
            None => {
                return Verdict {
                    fail_reason: Some("headerChainInvalid"),
                    ..Verdict::default()
                }
            }
        };
        // Java's verifyHeaderChainBatched re-guard: total in [2, MAX].
        if total < 2 || total > MAX_HEADER_CHAIN_GAP {
            return Verdict {
                fail_reason: Some("headerChainInvalid"),
                ..Verdict::default()
            };
        }
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
        if chain.len() as u64 != total {
            return Verdict {
                fail_reason: Some("headerChainInvalid"),
                ..Verdict::default()
            };
        }
        header_chain_verdict(&chain, beacon_block_hash, peer_state_root, finalized_slot)
    }
}

impl Drop for ManagedPeer {
    fn drop(&mut self) {
        // Stop the background read loop when the last handle goes away.
        self.reader_task.abort();
    }
}

/// The background read loop: classify each inbound frame and either answer it
/// (Ping/Get\*), deliver it to a waiting request, or ignore it. Exits on a read
/// error or a peer Disconnect, failing every in-flight request on the way out.
async fn read_loop(
    mut reader: RlpxReader,
    writer: SharedWriter,
    pending: PendingMap,
    closed: Arc<AtomicBool>,
    snap_codes: Option<snap::SnapCodes>,
    serve: Option<ServeContext>,
    tx_watch: Option<crate::el::sent_tx::SharedSentTxWatch>,
) {
    loop {
        let frame = match reader.recv().await {
            Ok(f) => f,
            Err(e) => {
                fail_all(&pending, &closed, format!("peer read loop ended: {e}")).await;
                break;
            }
        };
        let code = frame.message_code;

        // Tx gossip — the sent-tx watch's "the network has it" signal (the
        // Java TxGossipObserver twin), on BOTH forms devp2p propagates: hash
        // announcements (0x18) and full-body pushes (0x12). The lock is taken
        // twice, briefly, never across the decode: first the gate (evicting
        // expired watches here also self-heals a watch the wallet stopped
        // polling — the Java warmer's job), then the marks. The decoders cap
        // at MAX_GOSSIP_HASHES_PER_MSG so an oversized frame can't turn this
        // into an asymmetric-cost surface.
        if code == messages::NEW_POOLED_TRANSACTION_HASHES || code == messages::TRANSACTIONS {
            if let Some(watch) = &tx_watch {
                let now = std::time::Instant::now();
                let watching = {
                    let mut w = watch.lock().unwrap();
                    w.evict_expired(now);
                    w.watching_any()
                };
                if watching {
                    let hashes = if code == messages::TRANSACTIONS {
                        messages::transactions_gossip_hashes(&frame.payload)
                    } else {
                        messages::decode_new_pooled_tx_hashes(&frame.payload)
                    };
                    let mut w = watch.lock().unwrap();
                    for hash in hashes {
                        w.mark_seen(&hash, now);
                    }
                }
            }
            continue;
        }

        if code == P2P_PING {
            // Pong body is an empty RLP list. A write failure (e.g. a half-closed
            // connection where reads still succeed) means the peer is dead — fail
            // in-flight requests and stop, rather than spin on a zombie.
            if let Err(e) = send_frame(&writer, P2P_PONG, &[0xc0]).await {
                fail_all(&pending, &closed, format!("peer write failure on Pong: {e}")).await;
                break;
            }
            continue;
        }
        if code == P2P_DISCONNECT {
            fail_all(
                &pending,
                &closed,
                format!("peer disconnected: {}", describe_disconnect(&frame.payload)),
            )
            .await;
            break;
        }

        // Inbound header/body requests: count demand (before parsing, so malformed
        // requests register too), then try to SERVE headers from the shared window.
        // Anything unservable falls through to the well-behaved empty answer below.
        if let Some(ctx) = &serve {
            if code == messages::GET_BLOCK_HEADERS {
                ctx.stats.header_asked();
                if let Some(resp) = serve_headers(ctx, &frame.payload) {
                    if let Err(e) = send_frame(&writer, messages::BLOCK_HEADERS, &resp).await {
                        fail_all(&pending, &closed, format!("peer write failure on served headers: {e}"))
                            .await;
                        break;
                    }
                    ctx.stats.header_served();
                    continue;
                }
            } else if code == messages::GET_BLOCK_BODIES {
                ctx.stats.body_asked();
                // No bodies to serve (light client) — the empty answer below replies.
            }
        }

        // An inbound Get* request we answer with an empty response.
        if let Some((resp_code, empty)) = empty_answer(code, &snap_codes, &frame.payload) {
            if let Err(e) = send_frame(&writer, resp_code, &empty).await {
                fail_all(&pending, &closed, format!("peer write failure on empty response: {e}"))
                    .await;
                break;
            }
            continue;
        }

        // Otherwise try to correlate a response by (reqId, code). Anything that
        // doesn't match a waiting request is gossip/mempool — ignore it.
        if let Some(id) = leading_request_id(&frame.payload) {
            let mut map = pending.lock().await;
            if let Some(entry) = map.get(&id) {
                if entry.want_code == code {
                    let entry = map.remove(&id).expect("just checked present");
                    let _ = entry.tx.send(Ok(frame.payload));
                }
            }
        }
    }
    // Backstop: every break above already set `closed` via `fail_all`, but keep
    // this so any future exit path can't leave the peer looking open.
    closed.store(true, Ordering::SeqCst);
}

/// If `code` is an inbound eth/snap Get\* request, return the `(responseCode,
/// emptyBody)` to answer it with — echoing the request's id. `None` for any
/// other frame.
fn empty_answer(
    code: u64,
    snap_codes: &Option<snap::SnapCodes>,
    payload: &[u8],
) -> Option<(u64, Vec<u8>)> {
    let id = leading_request_id(payload)?;
    match code {
        messages::GET_BLOCK_HEADERS => {
            Some((messages::BLOCK_HEADERS, messages::encode_empty_response(id)))
        }
        messages::GET_BLOCK_BODIES => {
            Some((messages::BLOCK_BODIES, messages::encode_empty_response(id)))
        }
        messages::GET_RECEIPTS => Some((messages::RECEIPTS, messages::encode_empty_response(id))),
        _ => {
            let c = snap_codes.as_ref()?;
            if code == c.get_account_range {
                Some((c.account_range, snap::encode_empty_range(id)))
            } else if code == c.get_storage_ranges {
                Some((c.storage_ranges, snap::encode_empty_range(id)))
            } else if code == c.get_byte_codes {
                Some((c.byte_codes, snap::encode_empty_codes(id)))
            } else if code == c.get_trie_nodes {
                Some((c.trie_nodes, snap::encode_empty_codes(id)))
            } else {
                None
            }
        }
    }
}

/// Fail every in-flight request with `reason`, draining the pending map. Marks
/// the peer closed under the pending lock (before draining) so a concurrent
/// [`ManagedPeer::request`] either inserted before the drain — and gets its Err
/// here — or observes `closed` and bails, never hanging on a dead connection.
async fn fail_all(pending: &PendingMap, closed: &Arc<AtomicBool>, reason: String) {
    let mut map = pending.lock().await;
    closed.store(true, Ordering::SeqCst);
    for (_id, entry) in map.drain() {
        let _ = entry.tx.send(Err(reason.clone()));
    }
}

/// The leading request id of an eth/snap request or response (`[reqId, …]`).
fn leading_request_id(payload: &[u8]) -> Option<u64> {
    let items = rlp::raw_list_items(payload).ok()?;
    rlp::decode(items.first()?).ok()?.as_u64().ok()
}

/// Serve an inbound GetBlockHeaders from the shared window, or `None` when the
/// request is malformed, exotic (skip/reverse), or asks for blocks we don't hold
/// (the caller then answers empty — never a fabricated response). Serves the two
/// shapes real peers use: an ascending run by number, and a single header by
/// hash (fork/head probes).
fn serve_headers(ctx: &ServeContext, payload: &[u8]) -> Option<Vec<u8>> {
    use messages::HeadersOrigin;
    let (id, origin, max, skip, reverse) = messages::decode_get_block_headers(payload).ok()?;
    let raws = match origin {
        HeadersOrigin::Number(n) if skip == 0 && !reverse => ctx.window.run_from(n, max),
        // By-hash also requires the simple shape, keeping "exotic (skip/reverse)
        // falls through to the empty answer" true for both arms — and keeping
        // header_requests_served honest about what we chose to serve.
        HeadersOrigin::Hash(h) if max >= 1 && skip == 0 && !reverse => {
            ctx.window.by_hash(&h).into_iter().collect()
        }
        _ => Vec::new(),
    };
    if raws.is_empty() {
        return None;
    }
    Some(messages::encode_block_headers_response(id, &raws))
}

/// A p2p Disconnect body is `[reason]` (or a bare `reason`); decode it.
fn describe_disconnect(payload: &[u8]) -> String {
    let reason = rlp::decode(payload)
        .ok()
        .and_then(|it| match it {
            rlp::Item::List(items) => items.first().and_then(|r| r.as_u64().ok()),
            rlp::Item::Bytes(_) => it.as_u64().ok(),
        })
        .unwrap_or(u64::MAX);
    format!("reason={reason}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve_ctx(window: crate::el::served::ServedHeaders) -> ServeContext {
        ServeContext {
            window: std::sync::Arc::new(window),
            stats: std::sync::Arc::new(crate::el::served::ServeStats::default()),
        }
    }

    #[test]
    fn serve_headers_answers_a_held_run_and_round_trips() {
        use crate::el::served::ServedHeaders;
        // Real header RLP: use the corpus-independent path — encode a minimal
        // list per "header" (serve is byte-preserving, decode isn't re-run here).
        let w = ServedHeaders::new(32);
        let raw = |n: u64| rlp::encode(&rlp::Item::List(vec![rlp::Item::Bytes(vec![n as u8])]));
        let hash = |n: u64| {
            let mut h = [0u8; 32];
            h[0] = n as u8;
            h
        };
        for n in 100..=105u64 {
            w.put(n, hash(n), hash(n - 1), raw(n));
        }
        let ctx = serve_ctx(w);

        // [reqId, [origin=101, max=3, skip=0, reverse=0]]
        let req = messages::encode_get_block_headers_by_number(7, 101, 3, 0, false);
        let resp = serve_headers(&ctx, &req).expect("held run must serve");
        // Response is [reqId, [h101, h102, h103]] with byte-identical headers.
        let items = rlp::raw_list_items(&resp).unwrap();
        assert_eq!(rlp::decode(items[0]).unwrap().as_u64().unwrap(), 7);
        let served = rlp::raw_list_items(items[1]).unwrap();
        assert_eq!(served.len(), 3);
        assert_eq!(served[0], &raw(101)[..]);
        assert_eq!(served[2], &raw(103)[..]);

        // By hash: single header.
        let req = messages::encode_get_block_headers_by_hash(9, &hash(104), 1, 0, false);
        let resp = serve_headers(&ctx, &req).expect("held hash must serve");
        let items = rlp::raw_list_items(&resp).unwrap();
        assert_eq!(rlp::raw_list_items(items[1]).unwrap().len(), 1);

        // Unheld start, exotic shapes (skip/reverse), and malformed → None (empty answer path).
        assert!(serve_headers(&ctx, &messages::encode_get_block_headers_by_number(1, 990, 3, 0, false)).is_none());
        assert!(serve_headers(&ctx, &messages::encode_get_block_headers_by_number(1, 101, 3, 1, false)).is_none());
        assert!(serve_headers(&ctx, &messages::encode_get_block_headers_by_number(1, 101, 3, 0, true)).is_none());
        // Exotic shapes are unserved on the by-hash arm too (docs: skip/reverse
        // always fall through to the empty answer).
        assert!(serve_headers(&ctx, &messages::encode_get_block_headers_by_hash(1, &hash(104), 1, 1, false)).is_none());
        assert!(serve_headers(&ctx, &messages::encode_get_block_headers_by_hash(1, &hash(104), 1, 0, true)).is_none());
        assert!(serve_headers(&ctx, b"junk").is_none());
    }

    #[test]
    fn leading_request_id_reads_reqid() {
        let msg = rlp::encode(&rlp::Item::List(vec![
            rlp::Item::Bytes(rlp::u64_to_minimal_be(4242)),
            rlp::Item::List(vec![]),
        ]));
        assert_eq!(leading_request_id(&msg), Some(4242));
        // A bare byte string is not a `[reqId, …]` list.
        assert_eq!(leading_request_id(&[0x80]), None);
    }

    #[test]
    fn empty_answer_maps_eth_get_star() {
        let req = rlp::encode(&rlp::Item::List(vec![
            rlp::Item::Bytes(rlp::u64_to_minimal_be(7)),
            rlp::Item::List(vec![]),
        ]));
        let (code, body) = empty_answer(messages::GET_BLOCK_HEADERS, &None, &req).unwrap();
        assert_eq!(code, messages::BLOCK_HEADERS);
        assert_eq!(leading_request_id(&body), Some(7));

        let (code, _) = empty_answer(messages::GET_RECEIPTS, &None, &req).unwrap();
        assert_eq!(code, messages::RECEIPTS);

        // A response code is not an inbound request.
        assert!(empty_answer(messages::BLOCK_HEADERS, &None, &req).is_none());
    }

    #[test]
    fn empty_answer_maps_snap_get_star() {
        let codes = snap::SnapCodes::for_eth_version(68);
        let req = rlp::encode(&rlp::Item::List(vec![
            rlp::Item::Bytes(rlp::u64_to_minimal_be(9)),
            rlp::Item::List(vec![]),
        ]));
        let (code, body) = empty_answer(codes.get_account_range, &Some(codes), &req).unwrap();
        assert_eq!(code, codes.account_range);
        assert_eq!(leading_request_id(&body), Some(9));

        let (code, _) = empty_answer(codes.get_byte_codes, &Some(codes), &req).unwrap();
        assert_eq!(code, codes.byte_codes);

        // Without snap negotiated, snap codes aren't answered.
        assert!(empty_answer(codes.get_account_range, &None, &req).is_none());
    }
}
