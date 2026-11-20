//! Swarm retrieval protocol client.
//!
//! Implements the **dialer** side of `bee` `pkg/retrieval`
//! (`/swarm/retrieval/1.4.0/retrieval`): given a chunk address and a peer
//! we have a live BZZ connection to, open a libp2p stream, exchange the
//! mandatory bee-headers preamble, send a `retrieval.Request{Addr}`, read
//! a `retrieval.Delivery{Data, Err}`, and verify the returned bytes are
//! a valid content-addressed chunk (CAC) for the requested address.
//!
//! # Wire shape
//!
//! Every bee protocol stream (except `/swarm/handshake/14.0.0/handshake`)
//! is wrapped with two varint-length-delimited `headers.Headers` messages
//! exchanged before the protocol body — this is what `bee`
//! `pkg/p2p/libp2p/headers.go` does in `sendHeaders` (dialer) and
//! `handleHeaders` (listener). The dialer writes first, then reads:
//!
//! ```text
//! us → bee : varint(0) || empty pb.Headers     // sendHeaders write
//! bee → us : varint(0) || empty pb.Headers     // sendHeaders read
//! us → bee : varint(N) || retrieval.Request    // protocol body out
//! bee → us : varint(M) || retrieval.Delivery   // protocol body in
//! us → bee : (close write half)                // bee FullClose expects EOF
//! ```
//!
//! Bee passes `nil` for retrieval headers, so an empty `pb.Headers`
//! encodes to zero bytes and the wire varint length is `0x00`. We send the
//! same and accept any size from bee (it might add tracing headers in
//! future). Going the other way: dropping our write side before bee's
//! `sendHeaders` read returns triggers `Disconnect(peer, "could not fully
//! close stream on retrieval")` ~80 ms later — same gotcha we already
//! handle on the BZZ handshake.
//!
//! # Why not push payment?
//!
//! Bee's retrieval handler calls `accounting.PrepareDebit(peer, price)`
//! before writing the delivery and applies it after a successful write.
//! For *small* origin requests under the per-peer `paymentThreshold`
//! (currently 100M PLUR per chunk price; payment threshold is 100GB BZZ
//! by default) bee just builds up debt against us and never demands a
//! cheque, so a one-off chunk fetch works without SWAP wired up. A
//! sustained reader would need to honor SWAP debits (M3 territory); we
//! deliberately don't here.

pub mod push_load;
pub mod push_skip_cache;
pub mod pushsync;
pub mod pushsync_settlement;

pub mod accounting;
pub mod act;
pub mod cache;
pub mod cache_control;
pub mod counters;
pub mod disk_cache;
pub mod enc_split;
pub mod feed;
pub mod fetcher;
pub mod frame;
pub mod joiner;
pub mod manifest_writer;
pub mod mantaray;
pub mod priority;
pub mod progress;
pub mod rs;
pub mod rs_encode;
pub mod shallow_neighbourhoods;
pub mod splitter;
pub mod traversal;

pub use accounting::{Accounting, DebitGuard, HotHint, OVERDRAFT_REFRESH};
pub use cache::{InMemoryChunkCache, DEFAULT_CAPACITY as DEFAULT_CACHE_CAPACITY};
pub use cache_control::{
    clamp_capacity, ChunkCaches, SetCapacityError, CACHE_CAPACITY_MAX_BYTES,
    CACHE_CAPACITY_MIN_BYTES,
};
pub use counters::{ChunkSource, RetrievalCounters, RetrievalCountersSnapshot};
pub use disk_cache::{
    ClearReport, DiskCacheError, DiskCacheTuning, DiskChunkCache, DEFAULT_DISK_CACHE_BYTES,
};
pub use enc_split::{
    split_bytes_encrypted, split_bytes_encrypted_with_keys, EncryptedSplitResult, ENC_REF_SIZE,
};
pub use feed::{
    feed_from_metadata, resolve_sequence_feed, resolve_sequence_feed_after,
    resolve_sequence_feed_exact, resolve_sequence_feed_full, resolve_sequence_feed_hinted,
    sequence_update_address, sequence_update_id, Feed, FeedError, FeedHints, FeedResolution,
    FeedType, FEED_OWNER_KEY, FEED_TOPIC_KEY, FEED_TYPE_KEY,
};
pub use fetcher::{Overlay, RoutingFetcher};
pub use joiner::{
    enumerate_chunk_tree, join, join_encrypted, join_to_sender, join_to_sender_range,
    join_with_options, ByteRange, ChunkInventory, JoinError, JoinOptions, DEFAULT_MAX_FILE_BYTES,
    DURABILITY_MAX_FILE_BYTES, ENCRYPTED_REF_SIZE,
};
pub use manifest_writer::{
    build_collection_manifest, build_entries_manifest, build_feed_manifest,
    build_single_file_manifest, IndexAnchor, ManifestFile, ManifestWriteError, ManifestWriteResult,
    RawManifestEntry, MAX_FILENAME_BYTES,
};
pub use mantaray::{
    list_manifest, list_manifest_page, lookup_path, lookup_path_with_credit,
    lookup_path_with_hints, resolve_feed_root, LookupResult, ManifestEntry, ManifestError,
    ManifestPage, ManifestPageQuery, ReplicaSweeps, ResolvedFeed, MANIFEST_PAGE_DEFAULT_LIMIT,
    MANIFEST_PAGE_MAX_DEPTH, MANIFEST_PAGE_MAX_LIMIT, MANIFEST_PAGE_SIZES_BUDGET,
    MANIFEST_PAGE_WALK_BUDGET, MANTARAY_CONTENT_TYPE_KEY, MANTARAY_ERROR_DOC_KEY,
    MANTARAY_INDEX_DOC_KEY,
};
pub use progress::{estimate_total_chunks, ProgressSample, ProgressTracker};
pub use push_load::{PushLoadGuard, PushLoadTracker};
pub use push_skip_cache::{PushSkipCache, DEFAULT_SKIP_TTL};
pub use pushsync_settlement::{peer_chunk_price, PushCredit, PushCreditAction, PushsyncSettlement};
pub use rs::{fetch_root_with_replicas, replica_addresses, REPLICAS_OWNER, REPLICA_COUNTS};
pub use rs_encode::{
    replica_chunks, split_bytes_with_redundancy, RedundantSplitResult, RedundantSplitter,
};
pub use shallow_neighbourhoods::ShallowNeighbourhoods;
pub use splitter::{split_bytes, SplitChunk, SplitResult, StreamingSplitter, BRANCHES};
pub use traversal::{traverse_chunk_addresses, traverse_encrypted_chunk_addresses, TraversalError};

use ant_crypto::{cac_valid, soc_valid, CHUNK_SIZE, SOC_HEADER_SIZE, SPAN_SIZE};
use async_trait::async_trait;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::Control;
use prost::Message;
use std::error::Error as StdError;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, trace};

/// Abstract chunk store used by [`join`] and [`lookup_path`].
///
/// Production callers wrap a `libp2p_stream::Control` with a routing-table
/// lookup so each `fetch` resolves to "ask the closest peer over
/// `/swarm/retrieval/1.4.0`" via [`retrieve_chunk`]. Tests can supply a
/// `HashMap` and exercise the joiner / mantaray decoder offline.
///
/// `&self` (rather than `&mut self`) lets the joiner fan out concurrent
/// fetches against the same fetcher: sibling chunks of an intermediate
/// node can be retrieved in parallel without contention. Implementations
/// that need to mutate per-call state (e.g. a peer blacklist) wrap it in
/// interior mutability.
// `#[async_trait]` marks each boxed-future method `#[must_use]`, and
// clippy 1.99's `double_must_use` flags that expansion, not our code.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait ChunkFetcher: Send + Sync {
    /// Fetch the wire bytes (`span (8 LE) || payload`) of the chunk at
    /// `addr`, validating its CAC. Implementations should retry across
    /// peers if needed; the joiner / mantaray code treats a single
    /// failure here as a fatal error for the file.
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>>;

    /// Like [`ChunkFetcher::fetch`], but when every candidate peer is
    /// overdraft-skipped, wait up to `credit_budget` in total for peer
    /// credit to come free instead of failing at once (issue #117; bee's
    /// `RetrieveChunk` sleeps `overDraftRefresh` and retries the same
    /// way). Plain `fetch` never waits.
    ///
    /// Opt-in, because a wait inside a fan-out or a retry loop multiplies:
    /// only callers that need the chunk, fetch it once per attempt, and
    /// bound their retries by a window ([`crate::accounting::CreditWindow`])
    /// use it. Those are the joiners' data-chunk fetches, the `/bytes`
    /// / `/bzz` data-root fetch, and the `/bzz` manifest walk's node
    /// loads and raw-bytes sniff; see
    /// [`crate::accounting::CREDIT_WAIT_BUDGET`] for the full list and
    /// bounds. Default is plain `fetch`, right for every fetcher that has
    /// no credit to wait for (and for wrappers that must not wait, like
    /// the manifest sniff).
    async fn fetch_waiting_for_credit(
        &self,
        addr: [u8; 32],
        _credit_budget: Duration,
    ) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        self.fetch(addr).await
    }

    /// Does [`ChunkFetcher::fetch_waiting_for_credit`] actually wait for
    /// peer credit on this fetcher? Retry loops bound a starved miss's
    /// retries by their [`crate::accounting::CreditWindow`] only when it
    /// does: that bound exists so credit waits can't stack, and a fetcher
    /// that never waits has no wait to stack — its starved misses keep the
    /// loop's full retry count, as before #117, so the retries themselves
    /// are what gives pseudosettle time to refill the pool. Default
    /// `false`, matching the default `fetch_waiting_for_credit`; an
    /// implementation that overrides that to wait (or a wrapper that
    /// forwards it) must say `true` here too.
    fn waits_for_credit(&self) -> bool {
        false
    }

    /// Offer a chunk that was *reconstructed locally* (Reed-Solomon
    /// recovery of a missing data shard, or a root rebuilt from a
    /// dispersed replica) so the implementation can store it exactly
    /// like a fetched chunk — bee likewise `Put`s recovered shards into
    /// its local store (`pkg/file/redundancy/getter::save`). The wire
    /// bytes are already CAC-validated against `addr` by the caller.
    /// Default is a no-op for map-backed test fetchers.
    async fn put_recovered(&self, _addr: [u8; 32], _wire: &[u8]) {}

    /// An owned handle onto this fetcher, for a fetch that has to outlive
    /// the `&self` borrow: a speculative feed probe past the head runs its
    /// fetch in a detached task, so when the probe hits its deadline the
    /// fetch keeps going and the update still lands in the node's chunk
    /// caches for the next resolution (issue #190, see
    /// [`feed::resolve_sequence_feed_hinted`]). The handle must store
    /// what it fetches in the same caches `self` does. `None` (the
    /// default) means the fetcher can't be detached, and such a probe is
    /// simply cut off at its deadline, as before.
    fn detached(&self) -> Option<std::sync::Arc<dyn ChunkFetcher>> {
        None
    }
}

/// A [`ChunkFetcher`] view that never waits for peer credit: it forwards
/// `fetch` and `put_recovered`, and leaves
/// [`ChunkFetcher::fetch_waiting_for_credit`] at the trait default
/// (plain `fetch`). Wrap a fetcher in it before handing it to a joiner on
/// a path that must stay non-waiting: the encrypted joiner (including an
/// encrypted manifest node's join, even inside the `/bzz` walk, whose
/// plain node loads do wait), traversal, ACT; see
/// [`accounting::CREDIT_WAIT_BUDGET`]. Manifest walks outside `/bzz`
/// don't need it — they use the non-waiting [`mantaray::lookup_path`].
pub struct NoCreditWait<'a>(pub &'a dyn ChunkFetcher);

#[async_trait]
impl ChunkFetcher for NoCreditWait<'_> {
    async fn fetch(&self, addr: [u8; 32]) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        self.0.fetch(addr).await
    }

    async fn put_recovered(&self, addr: [u8; 32], wire: &[u8]) {
        self.0.put_recovered(addr, wire).await;
    }

    fn detached(&self) -> Option<std::sync::Arc<dyn ChunkFetcher>> {
        self.0.detached()
    }
}

/// Bee `pkg/retrieval` protocol id. Unchanged between bee 2.7.x and
/// 2.8.0 — the 2.8 release reshapes the handshake (see
/// `ant-p2p::handshake`) but leaves the retrieval wire format alone,
/// so we keep talking `1.4.0/retrieval` across the cutover.
pub const PROTOCOL_RETRIEVAL: &str = "/swarm/retrieval/1.4.0/retrieval";

/// 32-byte Swarm chunk address (content-addressed root or single-owner).
pub type ChunkAddr = [u8; 32];

/// Total wall-clock cap on a single retrieve attempt: open stream, headers
/// roundtrip, request, delivery. Bee's own `RetrieveChunkTimeout` is 30 s
/// because a peer typically has to forward our request a few hops deeper
/// into the neighbourhood before someone with the chunk actually answers.
/// Our previous 10 s / 20 s caps were aggressive enough that we
/// routinely cancelled peers mid-forward — bee logged the chunk as
/// unretrievable even though the same chunk fetched fine via a
/// longer-running client. Match Bee's origin retrieval timeout so
/// forwarded neighbourhood lookups get the same chance to complete.
const RETRIEVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Max bytes for the bee-headers preamble. Bee tags retrieval streams
/// with at most a couple of small tracing headers (current default is
/// none); 8 KiB is more than enough and matches our existing cap on the
/// inbound hive/pricing sinks.
pub(crate) const HEADERS_MAX: usize = 8 * 1024;
/// Max bytes for a `retrieval.Delivery` message. The data field tops out
/// at `ChunkSize + SpanSize = 4104`; the postage stamp adds another
/// ~149 bytes (`BatchID` 32 + Index 8 + Timestamp 8 + Sig 65 + frame).
/// 16 KiB gives plenty of headroom for protobuf framing without
/// accepting obviously-malicious payloads.
const DELIVERY_MAX: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum RetrievalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("open retrieval stream: {0}")]
    OpenStream(String),
    #[error("protobuf encode: {0}")]
    ProstEncode(#[from] prost::EncodeError),
    #[error("protobuf decode: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    #[error("retrieval timed out after {0:?}")]
    Timeout(Duration),
    #[error("message too large: {got} bytes (cap {cap})")]
    MessageTooLarge { got: usize, cap: usize },
    /// The remote sent back a `Delivery.Err` payload; the chunk is not
    /// retrievable from this peer (often `not found` or `forbidden`).
    #[error("remote: {0}")]
    Remote(String),
    /// Delivery decoded fine but `Data` did not BMT-hash to the requested
    /// chunk address. The peer is either misbehaving or relaying a
    /// corrupted chunk; the caller should skip this peer and retry.
    #[error("chunk failed CAC validation")]
    InvalidChunk,
    /// Delivery payload is shorter than the mandatory 8-byte span prefix
    /// or longer than `ChunkSize + SpanSize`. Almost always paired with
    /// a malformed remote.
    #[error("delivery payload size out of range: {0} bytes")]
    BadPayloadSize(usize),
}

impl RetrievalError {
    /// Did the peer answer that the chunk is missing? Bee has two such
    /// answers, both a `Delivery.Err` string (so the only place left to
    /// read them is here, where the peer's reply is decoded):
    ///
    /// - `storage: not found`: the peer looked in its reserve
    ///   (`storage.ErrNotFound`);
    /// - `no peer found`: a forwarder had no peer closer to the chunk
    ///   to forward to (`topology.ErrNotFound`). Bee's own `/bytes` and
    ///   `/bzz` answer 404 for this one too (issue #123).
    ///
    /// Transport failures (timeouts, dropped streams, …) are not.
    #[must_use]
    pub fn is_chunk_not_found(&self) -> bool {
        match self {
            Self::Remote(msg) => {
                let msg = msg.to_ascii_lowercase();
                msg.contains("not found") || msg.contains("no peer found")
            }
            _ => false,
        }
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct PbHeaders {
    #[prost(message, repeated, tag = "1")]
    headers: Vec<PbHeader>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct PbHeader {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct PbRequest {
    #[prost(bytes = "vec", tag = "1")]
    addr: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct PbDelivery {
    #[prost(bytes = "vec", tag = "1")]
    data: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    stamp: Vec<u8>,
    #[prost(string, tag = "3")]
    err: String,
}

/// Successful retrieval result: the verified chunk's wire bytes
/// (`span || payload`) so the caller doesn't have to recompute the span
/// to feed it into a joiner / mantaray decoder.
#[derive(Debug, Clone)]
pub struct RetrievedChunk {
    pub address: ChunkAddr,
    /// `span (8 LE) || payload (<= 4096)` — exactly the bytes a CAC chunk
    /// would have if reconstituted with `ant_crypto::cac_new(payload)`.
    pub data: Vec<u8>,
}

impl RetrievedChunk {
    /// Payload bytes (without the span prefix), ready for the caller.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.data[SPAN_SIZE..]
    }

    /// Raw little-endian span bytes (the first 8 bytes of the wire chunk).
    /// Useful when feeding the chunk back into the joiner, which expects
    /// `span || payload`.
    #[must_use]
    pub fn span_bytes(&self) -> [u8; SPAN_SIZE] {
        let mut out = [0u8; SPAN_SIZE];
        out.copy_from_slice(&self.data[..SPAN_SIZE]);
        out
    }
}

/// Retrieve `address` from a single peer over a libp2p stream.
///
/// `control` is the shared `libp2p_stream::Control` from the swarm — same
/// one used for the BZZ handshake, so we reuse libp2p's existing
/// connection muxing and don't need to know anything about the underlying
/// transport here. The caller is responsible for picking `peer` (typically
/// via `RoutingTable::closest_peer`).
///
/// On `Ok`, the returned `RetrievedChunk` is CAC-verified: `data` BMT-hashes
/// to `address` and is at most one chunk in size. On `Err(RetrievalError)`,
/// caller should skip this peer and try the next-closest.
pub async fn retrieve_chunk(
    control: &mut Control,
    peer: PeerId,
    address: ChunkAddr,
) -> Result<RetrievedChunk, RetrievalError> {
    tokio::time::timeout(
        RETRIEVE_TIMEOUT,
        retrieve_chunk_inner(control, peer, address),
    )
    .await
    .map_err(|_| RetrievalError::Timeout(RETRIEVE_TIMEOUT))?
}

async fn retrieve_chunk_inner(
    control: &mut Control,
    peer: PeerId,
    address: ChunkAddr,
) -> Result<RetrievedChunk, RetrievalError> {
    let proto = StreamProtocol::new(PROTOCOL_RETRIEVAL);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| RetrievalError::OpenStream(e.to_string()))?;

    // Bee-headers preamble (dialer side). We never set any headers, so we
    // send a length-prefixed empty `pb.Headers` (a single 0x00 byte) and
    // accept whatever bee sends back.
    write_delimited(&mut stream, &PbHeaders::default()).await?;
    let _their_headers = read_delimited::<PbHeaders>(&mut stream, HEADERS_MAX).await?;
    trace!(target: "ant_retrieval", %peer, "bee headers exchanged");

    let req = PbRequest {
        addr: address.to_vec(),
    };
    write_delimited(&mut stream, &req).await?;
    trace!(target: "ant_retrieval", %peer, "request sent");

    let delivery = read_delimited::<PbDelivery>(&mut stream, DELIVERY_MAX).await?;

    // Half-close our write side so bee's `stream.FullClose()` returns
    // promptly. Drop in `Err` paths is fine; libp2p's stream Drop sends
    // a Reset which bee handles.
    let _ = stream.close().await;

    if !delivery.err.is_empty() {
        debug!(target: "ant_retrieval", %peer, err = %delivery.err, "remote returned error");
        return Err(RetrievalError::Remote(delivery.err));
    }

    // Size envelope covers both chunk types. CAC is `span(8) ‖
    // payload` (≤ 4104). SOC is `id(32) ‖ sig(65) ‖ inner_cac` and the
    // inner CAC can itself be up to `SPAN_SIZE + CHUNK_SIZE` (≤ 4201
    // total). Use the SOC max as the cap; the lower cap is the
    // smallest possible CAC (span only).
    if delivery.data.len() < SPAN_SIZE
        || delivery.data.len() > SOC_HEADER_SIZE + SPAN_SIZE + CHUNK_SIZE
    {
        return Err(RetrievalError::BadPayloadSize(delivery.data.len()));
    }
    // Bee accepts both content-addressed chunks (BMT-bound) and
    // single-owner chunks (signature + owner-bound). The retrieval
    // protocol returns the same `Delivery` shape for both — see
    // `bee/pkg/retrieval/retrieval.go`, where the validator chain is
    // `if !cac.Valid { if !soc.Valid { invalid } }`. SOC chunks carry
    // feed updates and other mutable references, so a gateway that
    // only accepts CAC silently breaks every feed-backed `.eth` site.
    if !cac_valid(&address, &delivery.data) && !soc_valid(&address, &delivery.data) {
        return Err(RetrievalError::InvalidChunk);
    }

    // Bee's `pb.Delivery` reserves a `stamp` field, but the live
    // `/swarm/retrieval/1.4.0` handler never populates it (see
    // `pkg/retrieval/retrieval.go::handler`). Stamps travel with
    // pushsync, not retrieval. We surface what we got so a caller
    // running with `RUST_LOG=ant_retrieval=debug` can spot the rare
    // peer that does attach one.
    if !delivery.stamp.is_empty() {
        debug!(
            target: "ant_retrieval",
            chunk = %hex::encode(address),
            stamp_len = delivery.stamp.len(),
            "retrieval delivery carried a postage stamp (uncommon)",
        );
    }

    Ok(RetrievedChunk {
        address,
        data: delivery.data,
    })
}

pub(crate) async fn write_delimited<W, M>(w: &mut W, msg: &M) -> Result<(), RetrievalError>
where
    W: AsyncWriteExt + Unpin,
    M: Message,
{
    let mut buf = Vec::with_capacity(msg.encoded_len() + 10);
    msg.encode_length_delimited(&mut buf)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub(crate) async fn read_delimited<M: Message + Default>(
    r: &mut (impl AsyncReadExt + Unpin),
    cap: usize,
) -> Result<M, RetrievalError> {
    let len = read_varint_len(r).await?;
    if len > cap {
        return Err(RetrievalError::MessageTooLarge { got: len, cap });
    }
    // Grows with the bytes that arrive, not the declared `len` (#203).
    let buf = frame::read_frame_body(r, len).await?;
    Ok(M::decode(buf.as_slice())?)
}

pub(crate) async fn read_varint_len<R: AsyncReadExt + Unpin>(
    r: &mut R,
) -> Result<usize, RetrievalError> {
    let mut byte = [0u8; 1];
    let mut acc: Vec<u8> = Vec::with_capacity(10);
    loop {
        r.read_exact(&mut byte).await?;
        acc.push(byte[0]);
        match unsigned_varint::decode::u64(&acc) {
            Ok((v, [])) => {
                return usize::try_from(v).map_err(|_| {
                    RetrievalError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint overflow",
                    ))
                });
            }
            Ok(_) => {
                return Err(RetrievalError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid varint framing",
                )));
            }
            Err(unsigned_varint::decode::Error::Insufficient) => {
                if acc.len() > 10 {
                    return Err(RetrievalError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint too long",
                    )));
                }
            }
            Err(e) => {
                return Err(RetrievalError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varint: {e}"),
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::cac_new;
    use futures::io::Cursor;

    /// Round-trip the `PbDelivery` framing through prost using a real CAC
    /// chunk: encode → length-delimited bytes → decode → verify CAC. This
    /// is what the live retrieval client does end-to-end, minus the
    /// libp2p stream and bee-headers wrapper.
    #[tokio::test]
    async fn delivery_decode_and_cac_verify() {
        let payload = b"hello swarm".to_vec();
        let (addr, wire) = cac_new(&payload).unwrap();
        let delivery = PbDelivery {
            data: wire.clone(),
            stamp: vec![],
            err: String::new(),
        };

        let mut buf = Vec::new();
        delivery.encode_length_delimited(&mut buf).unwrap();

        let mut cur = Cursor::new(buf);
        let decoded: PbDelivery = read_delimited(&mut cur, DELIVERY_MAX).await.unwrap();
        assert_eq!(decoded.data, wire);
        assert_eq!(decoded.err, "");
        assert!(cac_valid(&addr, &decoded.data));
    }

    /// A `Delivery.Err` from the remote becomes `RetrievalError::Remote` —
    /// the caller can pattern-match on this to drop the peer from a skip
    /// list and try the next one without treating it as a hard failure.
    #[test]
    fn remote_error_message_propagates() {
        let e = RetrievalError::Remote("not found".to_string());
        assert_eq!(e.to_string(), "remote: not found");
    }

    /// Tampered chunk data is rejected: even if the protobuf decodes
    /// cleanly, `cac_valid` catches the mismatch. This is the critical
    /// safety property — without it a malicious peer could feed us
    /// arbitrary bytes for a popular reference.
    #[tokio::test]
    async fn invalid_cac_is_rejected() {
        let (addr, mut wire) = cac_new(b"trust me").unwrap();
        wire[SPAN_SIZE] ^= 0x01; // flip a bit in the payload
        assert!(!cac_valid(&addr, &wire));
    }

    /// Oversize delivery is rejected by the size cap before we attempt
    /// to allocate or hash. Defends against a stuck stream that sends a
    /// huge varint length followed by garbage.
    #[tokio::test]
    async fn oversize_delivery_is_rejected() {
        // Build a varint header claiming a 1 MiB body, then nothing.
        let mut buf = Vec::new();
        let mut encbuf = unsigned_varint::encode::usize_buffer();
        let prefix = unsigned_varint::encode::usize(1024 * 1024, &mut encbuf);
        buf.extend_from_slice(prefix);
        let mut cur = Cursor::new(buf);
        let res: Result<PbDelivery, _> = read_delimited(&mut cur, DELIVERY_MAX).await;
        match res {
            Err(RetrievalError::MessageTooLarge { got, cap }) => {
                assert_eq!(got, 1024 * 1024);
                assert_eq!(cap, DELIVERY_MAX);
            }
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
    }
}
