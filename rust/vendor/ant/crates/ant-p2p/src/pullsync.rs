//! Pullsync **client** — the syncing side of Swarm's `pullsync/1.4.0`
//! protocol, used by ant to *pull* chunks out of a target neighborhood
//! bin from bee full nodes (the "lurker" receive path for GSOC and PSS).
//!
//! Ant is a light node and never *serves* pullsync; here it only dials.
//! Bee's pullsync server handler has no peer-mode gate (it does not
//! require the requester to be a full node or in-neighborhood — verified
//! in `bee/pkg/pullsync/pullsync.go`), so a light peer that has completed
//! the swarm handshake can request any bin, subject only to the server's
//! 250-chunk/s rate limit.
//!
//! Two streams, both client-initiated, each request/response with a
//! libp2p headers preamble first (mirroring [`crate::pseudosettle`]):
//!
//! - `/swarm/pullsync/1.4.0/cursors`: `Syn{}` → `Ack{cursors[32], epoch}`.
//!   `cursors[bin]` is the peer's highest reserve binID in that bin;
//!   `epoch` changing means the peer wiped its reserve (drop saved
//!   intervals).
//! - `/swarm/pullsync/1.4.0/pullsync`: `Get{bin, start}` →
//!   `Offer{topmost, chunks[]}` → `Want{bitvector}` →
//!   `Delivery × popcount(bitvector)`. One page per stream.
//!
//! Live reception is a poll loop: repeatedly `sync_once(bin, start)` with
//! `start = prev_topmost + 1`; the server blocks server-side until a new
//! chunk in that bin arrives, so the loop parks rather than busy-spins.
//! That driver lives in the lurker layer; this module is the single-round
//! wire codec + exchange.

use crate::sinks::HEADERS_MAX;
use ant_crypto::{cac_valid, soc_valid};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::Control;
use prost::Message;
use std::collections::HashMap;

/// Cursor stream protocol id.
pub const PROTOCOL_PULLSYNC_CURSORS: &str = "/swarm/pullsync/1.4.0/cursors";
/// Sync stream protocol id.
pub const PROTOCOL_PULLSYNC: &str = "/swarm/pullsync/1.4.0/pullsync";

/// Bee's `delimitedReaderMaxSize` — reject frames larger than this.
const MAX_FRAME: usize = 128 * 1024;
/// A serialized postage stamp is exactly 113 bytes.
const STAMP_SIZE: usize = 113;
/// Number of proximity-order bins (`swarm.MaxBins`).
pub const MAX_BINS: usize = 32;

// --- protobuf messages (bee pkg/pullsync/pb/pullsync.proto) ---

/// `Syn{}` — empty cursor request.
#[derive(Clone, PartialEq, Message)]
struct Syn {}

/// `Ack{ repeated uint64 Cursors = 1; uint64 Epoch = 2 }`.
#[derive(Clone, PartialEq, Message)]
struct Ack {
    #[prost(uint64, repeated, tag = "1")]
    cursors: Vec<u64>,
    #[prost(uint64, tag = "2")]
    epoch: u64,
}

/// `Get{ int32 Bin = 1; uint64 Start = 2 }`.
#[derive(Clone, PartialEq, Message)]
struct Get {
    #[prost(int32, tag = "1")]
    bin: i32,
    #[prost(uint64, tag = "2")]
    start: u64,
}

/// `Chunk{ bytes Address = 1; bytes BatchID = 2; bytes StampHash = 3 }`.
#[derive(Clone, PartialEq, Message)]
struct ChunkRef {
    #[prost(bytes = "vec", tag = "1")]
    address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    batch_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    stamp_hash: Vec<u8>,
}

/// `Offer{ uint64 Topmost = 1; repeated Chunk Chunks = 2 }`.
#[derive(Clone, PartialEq, Message)]
struct Offer {
    #[prost(uint64, tag = "1")]
    topmost: u64,
    #[prost(message, repeated, tag = "2")]
    chunks: Vec<ChunkRef>,
}

/// `Want{ bytes BitVector = 1 }`.
#[derive(Clone, PartialEq, Message)]
struct Want {
    #[prost(bytes = "vec", tag = "1")]
    bit_vector: Vec<u8>,
}

/// `Delivery{ bytes Address = 1; bytes Data = 2; bytes Stamp = 3 }`.
#[derive(Clone, PartialEq, Message)]
struct Delivery {
    #[prost(bytes = "vec", tag = "1")]
    address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    data: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    stamp: Vec<u8>,
}

/// One offered chunk reference (address + its postage identity).
#[derive(Clone, Debug)]
pub struct OfferedChunk {
    pub address: [u8; 32],
    pub batch_id: [u8; 32],
    pub stamp_hash: [u8; 32],
}

/// A chunk delivered over pullsync: address, `span ‖ payload` data, and
/// the 113-byte stamp. Already vetted by [`accept_delivery`]: solicited
/// in this page's Want, stamp well-sized, and the data hashes to the
/// address (valid CAC or self-bound SOC).
#[derive(Clone, Debug)]
pub struct DeliveredChunk {
    pub address: [u8; 32],
    pub data: Vec<u8>,
    pub stamp: Vec<u8>,
}

/// The result of one `sync_once` page.
#[derive(Clone, Debug)]
pub struct SyncPage {
    /// Highest binID covered by this page; the next round starts at
    /// `topmost + 1`.
    pub topmost: u64,
    /// Chunks the caller wanted and the server delivered (placeholders
    /// for dropped chunks are skipped).
    pub chunks: Vec<DeliveredChunk>,
}

/// Per-peer reserve cursors from the cursor stream.
#[derive(Clone, Debug)]
pub struct Cursors {
    /// Highest binID per bin (index = bin), length up to [`MAX_BINS`].
    pub cursors: Vec<u64>,
    /// Reserve epoch; a change invalidates previously saved intervals.
    pub epoch: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PullsyncError {
    #[error("open stream: {0}")]
    OpenStream(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("protocol: {0}")]
    Protocol(String),
}

// --- framing (length-delimited protobuf + bee headers preamble) ---

async fn write_empty_headers<W: AsyncWriteExt + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[0u8]).await?;
    w.flush().await?;
    Ok(())
}

async fn read_varint_len<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<usize> {
    let mut byte = [0u8; 1];
    let mut acc: Vec<u8> = Vec::with_capacity(10);
    loop {
        r.read_exact(&mut byte).await?;
        acc.push(byte[0]);
        match unsigned_varint::decode::u64(&acc) {
            Ok((v, _)) => {
                return usize::try_from(v).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "varint overflow")
                });
            }
            Err(unsigned_varint::decode::Error::Insufficient) => {
                if acc.len() > 10 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint too long",
                    ));
                }
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varint: {e}"),
                ));
            }
        }
    }
}

async fn read_delimited<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    let len = read_varint_len(r).await?;
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (cap {max})"),
        ));
    }
    // Grows with the bytes that arrive, not the declared `len`, so a peer
    // can't pin the cap per stream by declaring a frame and stalling (#203).
    ant_retrieval::frame::read_frame_body(r, len).await
}

async fn write_delimited<W, M>(w: &mut W, msg: &M) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    M: Message,
{
    let mut buf = Vec::with_capacity(msg.encoded_len() + 10);
    msg.encode_length_delimited(&mut buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Exchange the libp2p headers preamble: dialer writes its (empty)
/// headers first, then reads the peer's.
async fn headers_preamble(stream: &mut libp2p_swarm::Stream) -> Result<(), PullsyncError> {
    write_empty_headers(stream).await?;
    let _their = read_delimited(stream, HEADERS_MAX).await?;
    Ok(())
}

fn to_32(v: &[u8]) -> Option<[u8; 32]> {
    v.try_into().ok()
}

/// Solicited deliveries, keyed by address → the offered `(batchID,
/// stampHash)` identities we set a want bit for. A delivery is accepted
/// only if its address is present and its stamp matches one of these
/// tuples (bee binds the full identity, not just the address).
type WantedIdentities = HashMap<[u8; 32], Vec<([u8; 32], [u8; 32])>>;

// --- client exchanges ---

/// Deadline on the whole `/cursors` round-trip. Unlike the live-bin
/// Offer read (which legitimately blocks indefinitely on a quiet bin),
/// the cursor exchange is a quick request/response: a peer that hasn't
/// answered by now is silent, and without a bound here the stream and
/// its driving task leak forever. Callers may impose tighter budgets.
const CURSORS_RTT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-frame deadline after the server has already committed to a page.
/// Once the `Offer` has arrived the server has materialized its chunk
/// list, so the `Want` write and every subsequent `Delivery` frame
/// should flow promptly — a peer that stalls mid-page would otherwise
/// hold the stream (and the puller's slot in the covering set) forever.
const POST_OFFER_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Fetch the peer's per-bin reserve cursors and epoch. Bounded by
/// [`CURSORS_RTT_TIMEOUT`]; the cursor list is validated to at most
/// [`MAX_BINS`] entries so downstream `cursors[bin]` indexing can't be
/// grown into a lie by a malicious peer.
pub async fn get_cursors(control: &mut Control, peer: PeerId) -> Result<Cursors, PullsyncError> {
    tokio::time::timeout(CURSORS_RTT_TIMEOUT, async {
        let proto = StreamProtocol::new(PROTOCOL_PULLSYNC_CURSORS);
        let mut stream = control
            .open_stream(peer, proto)
            .await
            .map_err(|e| PullsyncError::OpenStream(e.to_string()))?;
        headers_preamble(&mut stream).await?;

        write_delimited(&mut stream, &Syn {}).await?;
        let ack_bytes = read_delimited(&mut stream, MAX_FRAME).await?;
        let ack = Ack::decode(ack_bytes.as_slice())?;
        let _ = stream.close().await;
        if ack.cursors.len() > MAX_BINS {
            return Err(PullsyncError::Protocol(format!(
                "peer sent {} cursors (max {MAX_BINS})",
                ack.cursors.len()
            )));
        }
        Ok(Cursors {
            cursors: ack.cursors,
            epoch: ack.epoch,
        })
    })
    .await
    .map_err(|_| PullsyncError::Protocol("cursors round-trip timed out".into()))?
}

/// Run one pullsync page against `peer` for `bin` starting at binID
/// `start`. `want` decides, per offered chunk, whether to request its
/// delivery — a lurker returns `true` only for the SOC/trojan addresses
/// it watches, so Delivery bandwidth stays near zero when nothing
/// matches. Returns the page's `topmost` and the delivered chunks.
///
/// `on_ready` fires once the stream is open and the `Get` has been sent
/// and flushed — i.e. the peer accepted our request and we're now
/// *waiting* for data. This is the point a lurker can treat the puller
/// as "covering", **before** the server long-blocks on a quiet bin:
/// the block is deliberate (the server holds the stream until a chunk
/// with `binID >= start` arrives, or it's dropped), so callers must not
/// impose a short read deadline on live bins, and readiness must not
/// wait for the first `Offer` or it would never fire on a quiet bin.
pub async fn sync_once<F, R>(
    control: &mut Control,
    peer: PeerId,
    bin: u8,
    start: u64,
    want: F,
    on_ready: R,
) -> Result<SyncPage, PullsyncError>
where
    F: Fn(&OfferedChunk) -> bool,
    R: FnOnce(),
{
    let proto = StreamProtocol::new(PROTOCOL_PULLSYNC);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| PullsyncError::OpenStream(e.to_string()))?;
    headers_preamble(&mut stream).await?;

    write_delimited(
        &mut stream,
        &Get {
            bin: i32::from(bin),
            start,
        },
    )
    .await?;
    // Stream is live and the request is sent — the puller is covering
    // this bin now, even if the server holds the Offer back until a
    // chunk arrives. Signal before the (possibly indefinite) Offer read.
    on_ready();

    let offer_bytes = read_delimited(&mut stream, MAX_FRAME).await?;
    let offer = Offer::decode(offer_bytes.as_slice())?;

    // No chunks in the interval: the page is empty, advance to topmost.
    if offer.chunks.is_empty() {
        let _ = stream.close().await;
        return Ok(SyncPage {
            topmost: offer.topmost,
            chunks: Vec::new(),
        });
    }

    // Decide wants; build the LSB-first bit vector bee expects, and keep
    // the full offered identity — (address, batchID, stampHash), exactly
    // what bee's own client matches deliveries against — so each
    // delivery can be checked against what was actually solicited. Keyed
    // by address (that's all a Delivery carries directly) with the
    // offered stamp identities behind it; a SOC updated mid-page can
    // legitimately appear twice under one address with two identities.
    let mut bits = BitVec::with_len(offer.chunks.len());
    let mut wanted: WantedIdentities = HashMap::new();
    let mut want_count: usize = 0;
    for (i, c) in offer.chunks.iter().enumerate() {
        match (to_32(&c.address), to_32(&c.batch_id), to_32(&c.stamp_hash)) {
            (Some(address), Some(batch_id), Some(stamp_hash)) if address != [0u8; 32] => {
                let oc = OfferedChunk {
                    address,
                    batch_id,
                    stamp_hash,
                };
                if want(&oc) {
                    bits.set(i);
                    wanted
                        .entry(address)
                        .or_default()
                        .push((batch_id, stamp_hash));
                    want_count += 1;
                }
            }
            (None, _, _) => {
                // Bee rejects an offer entry whose address isn't 32 bytes.
                let _ = stream.close().await;
                return Err(PullsyncError::Protocol("offer address not 32 bytes".into()));
            }
            _ => {} // zero-address / malformed identity: skip (never wanted)
        }
    }
    tracing::debug!(
        target: "ant_p2p::pullsync",
        peer = %peer, bin, start, topmost = offer.topmost,
        offered = offer.chunks.len(), wanted = want_count,
        "pullsync page",
    );

    // From here the server has committed to a page, so every frame is
    // bounded: a peer stalling after its Offer must not hold the stream
    // (and this puller's covering-set slot) forever.
    let stalled = || PullsyncError::Protocol("peer stalled after Offer".into());
    tokio::time::timeout(
        POST_OFFER_FRAME_TIMEOUT,
        write_delimited(
            &mut stream,
            &Want {
                bit_vector: bits.into_bytes(),
            },
        ),
    )
    .await
    .map_err(|_| stalled())??;

    // Read exactly popcount(bitvector) deliveries, in offer order over the
    // set bits. A dropped chunk arrives as an empty placeholder that still
    // consumes a slot. Every real delivery must be one we solicited and
    // must validate against its own address (see `accept_delivery`).
    //
    // A delivery that fails vetting is **skipped, not fatal** — bee's
    // client likewise joins per-chunk errors and keeps consuming the
    // page. Erroring out here would refuse to advance `topmost`, so a
    // peer injecting one junk chunk per page could park the puller on
    // the same interval forever. Framing/decode failures still abort:
    // after those the stream can't be resynchronized.
    let mut chunks = Vec::with_capacity(want_count);
    let mut rejected: usize = 0;
    for _ in 0..want_count {
        let d_bytes = tokio::time::timeout(
            POST_OFFER_FRAME_TIMEOUT,
            read_delimited(&mut stream, MAX_FRAME),
        )
        .await
        .map_err(|_| stalled())??;
        let d = Delivery::decode(d_bytes.as_slice())?;
        match accept_delivery(&mut wanted, d) {
            Ok(Some(chunk)) => chunks.push(chunk),
            Ok(None) => {} // placeholder: server no longer holds it
            Err(e) => {
                rejected += 1;
                tracing::debug!(
                    target: "ant_p2p::pullsync",
                    peer = %peer, bin, error = %e,
                    "rejecting invalid delivery (page continues)",
                );
            }
        }
    }
    if rejected > 0 {
        tracing::warn!(
            target: "ant_p2p::pullsync",
            peer = %peer, bin, rejected,
            "peer sent invalid deliveries in a pullsync page",
        );
    }

    let _ = stream.close().await;
    Ok(SyncPage {
        topmost: offer.topmost,
        chunks,
    })
}

/// Vet one Delivery frame against the solicited set: `Ok(None)` for a
/// placeholder (server no longer holds the chunk), `Ok(Some)` for a
/// solicited, well-formed, content-valid chunk, `Err` for anything a
/// well-behaved bee never sends — an address we didn't ask for (or asked
/// for and already received), a malformed stamp, a stamp that doesn't
/// carry the *offered* postage identity, or chunk bytes that don't hash
/// to the claimed address. Identity matching mirrors bee's client
/// (`pkg/pullsync/pullsync.go`): the delivered stamp's batch ID and its
/// keccak hash must equal the `(batchID, stampHash)` from the Offer
/// entry we set the want bit for. The content check (CAC BMT or SOC
/// self-binding, bee's own put-time validation) is what stops a
/// malicious peer replaying one captured chunk under ever-fresh
/// addresses to bypass downstream dedup.
fn accept_delivery(
    wanted: &mut WantedIdentities,
    d: Delivery,
) -> Result<Option<DeliveredChunk>, PullsyncError> {
    if d.address.is_empty() {
        return Ok(None);
    }
    let Some(address) = to_32(&d.address) else {
        return Err(PullsyncError::Protocol(
            "delivery address not 32 bytes".into(),
        ));
    };
    let Some(identities) = wanted.get_mut(&address) else {
        return Err(PullsyncError::Protocol(format!(
            "unsolicited delivery for {}",
            hex::encode(address)
        )));
    };
    if d.stamp.len() != STAMP_SIZE {
        return Err(PullsyncError::Protocol(format!(
            "delivery stamp is {} bytes, expected {STAMP_SIZE}",
            d.stamp.len()
        )));
    }
    // Bind the delivered stamp to the offered (batchID, stampHash) —
    // bee's stampHash is keccak over the 113-byte marshaled stamp.
    let batch_id: [u8; 32] = d.stamp[0..32].try_into().expect("stamp layout");
    let stamp_hash = ant_crypto::keccak256(&d.stamp);
    let Some(pos) = identities
        .iter()
        .position(|id| *id == (batch_id, stamp_hash))
    else {
        return Err(PullsyncError::Protocol(format!(
            "delivery stamp does not match the offered identity for {}",
            hex::encode(address)
        )));
    };
    identities.swap_remove(pos);
    if identities.is_empty() {
        wanted.remove(&address);
    }
    if !cac_valid(&address, &d.data) && !soc_valid(&address, &d.data) {
        return Err(PullsyncError::Protocol(
            "delivery data does not hash to its address".into(),
        ));
    }
    Ok(Some(DeliveredChunk {
        address,
        data: d.data,
        stamp: d.stamp,
    }))
}

/// A little bit vector with bee's layout: `len/8 + 1` bytes, bit `i` at
/// byte `i/8` mask `1 << (i%8)` (LSB-first within each byte).
struct BitVec {
    bytes: Vec<u8>,
}

impl BitVec {
    fn with_len(bit_len: usize) -> Self {
        Self {
            bytes: vec![0u8; bit_len / 8 + 1],
        }
    }
    fn set(&mut self, i: usize) {
        self.bytes[i / 8] |= 1 << (i % 8);
    }
    #[cfg(test)]
    fn get(&self, i: usize) -> bool {
        self.bytes[i / 8] & (1 << (i % 8)) != 0
    }
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- negative framing: what a malicious/broken peer can send ---

    /// An advertised frame length past the cap must be refused before a
    /// single body byte is read (no allocation, no draining).
    #[tokio::test]
    async fn read_delimited_rejects_oversized_frame() {
        // varint 0xFFFF (65535) > max 1024.
        let mut wire: &[u8] = &[0xFF, 0xFF, 0x03, 0x00];
        let err = read_delimited(&mut wire, 1024).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("too large"));
    }

    /// A frame that promises more bytes than the stream delivers fails
    /// with a clean EOF error, not a hang or a short read.
    #[tokio::test]
    async fn read_delimited_rejects_truncated_frame() {
        let mut wire: &[u8] = &[10, 0xAA, 0xBB]; // says 10, carries 2
        let err = read_delimited(&mut wire, 1024).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// A varint that never terminates (all continuation bits) is cut
    /// off at 10 bytes — the u64 maximum — instead of read forever.
    #[tokio::test]
    async fn read_delimited_rejects_runaway_varint() {
        let mut wire: &[u8] = &[0x80; 16];
        let err = read_delimited(&mut wire, 1024).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Junk bytes in place of a protobuf Offer must decode-fail (the
    /// caller aborts the page — framing can't be resynchronized).
    #[test]
    fn offer_decode_rejects_junk() {
        assert!(Offer::decode(&[0xC7u8, 0x01, 0xFF, 0xFF][..]).is_err());
    }

    // Golden protobuf vectors from bee's own pb types (cmd/pullvec).

    #[test]
    fn get_encodes_like_bee() {
        let mut buf = Vec::new();
        Get {
            bin: 8,
            start: 1000,
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(hex::encode(&buf), "080810e807");
    }

    #[test]
    fn ack_decodes_bee_bytes() {
        // Ack{Cursors=[0,5,250], Epoch=1234567}.
        let bytes = hex::decode("0a040005fa011087ad4b").unwrap();
        let ack = Ack::decode(bytes.as_slice()).unwrap();
        assert_eq!(ack.cursors, vec![0, 5, 250]);
        assert_eq!(ack.epoch, 1_234_567);
    }

    #[test]
    fn chunk_ref_matches_bee_layout() {
        let c = ChunkRef {
            address: vec![0xab; 32],
            batch_id: vec![0xcd; 32],
            stamp_hash: vec![0xef; 32],
        };
        let mut buf = Vec::new();
        c.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 102);
        assert_eq!(&hex::encode(&buf)[..6], "0a20ab");
    }

    #[test]
    fn offer_round_trips_bee_bytes() {
        let hexs = "08e80712660a20abababababababababababababababababababababababababababababababab1220cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd1a20efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
        let bytes = hex::decode(hexs).unwrap();
        let offer = Offer::decode(bytes.as_slice()).unwrap();
        assert_eq!(offer.topmost, 1000);
        assert_eq!(offer.chunks.len(), 1);
        assert_eq!(offer.chunks[0].address, vec![0xab; 32]);
        let mut re = Vec::new();
        offer.encode(&mut re).unwrap();
        assert_eq!(re, bytes, "re-encode must be byte-identical");
    }

    #[test]
    fn want_bitvector_is_lsb_first() {
        let mut bv = BitVec::with_len(1);
        bv.set(0);
        let w = Want {
            bit_vector: bv.into_bytes(),
        };
        let mut buf = Vec::new();
        w.encode(&mut buf).unwrap();
        // bee: Want{BitVector: 0x01} → 0a0101
        assert_eq!(hex::encode(&buf), "0a0101");
    }

    #[test]
    fn accept_delivery_vets_solicitation_stamp_identity_and_content() {
        let (address, wire) = ant_crypto::cac_new(b"pullsync delivery").unwrap();
        let delivery = |addr: Vec<u8>, data: Vec<u8>, stamp: Vec<u8>| Delivery {
            address: addr,
            data,
            stamp,
        };
        // The stamp a well-behaved server would deliver, and the offered
        // identity that must match it: (batchID = stamp[0..32],
        // stampHash = keccak(stamp)).
        let stamp = vec![0u8; STAMP_SIZE];
        let identity = ([0u8; 32], ant_crypto::keccak256(&stamp));
        let want_one = |addr: [u8; 32], id: ([u8; 32], [u8; 32])| HashMap::from([(addr, vec![id])]);

        // Placeholder (empty address): skipped, not an error.
        let mut wanted = want_one(address, identity);
        let got = accept_delivery(&mut wanted, delivery(Vec::new(), Vec::new(), Vec::new()));
        assert!(matches!(got, Ok(None)));

        // Solicited, identity-matched, content-valid: accepted and
        // consumed from the wanted set.
        let ok = accept_delivery(
            &mut wanted,
            delivery(address.to_vec(), wire.clone(), stamp.clone()),
        )
        .unwrap()
        .expect("valid delivery");
        assert_eq!(ok.address, address);
        assert!(wanted.is_empty());

        // The same address again is a replay: no longer solicited.
        let replay = accept_delivery(
            &mut wanted,
            delivery(address.to_vec(), wire.clone(), stamp.clone()),
        );
        assert!(replay.is_err(), "duplicate delivery must be rejected");

        // Unsolicited address outright.
        let mut wanted = want_one(address, identity);
        let unsolicited = accept_delivery(
            &mut wanted,
            delivery(vec![0x77; 32], wire.clone(), stamp.clone()),
        );
        assert!(unsolicited.is_err());

        // Solicited but the stamp is malformed (empty included — bee
        // always sends a 113-byte stamp).
        let short_stamp = accept_delivery(
            &mut wanted,
            delivery(address.to_vec(), wire.clone(), Vec::new()),
        );
        assert!(short_stamp.is_err());

        // Solicited address, but the delivered stamp is not the one the
        // Offer promised — a substituted batch/stamp must be rejected
        // (bee matches the full (address, batchID, stampHash) tuple).
        let mut wanted = want_one(address, identity);
        let mut other_stamp = vec![0u8; STAMP_SIZE];
        other_stamp[0] = 0xEE; // different batch id → different identity
        let substituted = accept_delivery(
            &mut wanted,
            delivery(address.to_vec(), wire.clone(), other_stamp),
        );
        assert!(substituted.is_err(), "stamp identity must match the offer");

        // Solicited, stamped, but the data doesn't hash to the address —
        // a captured chunk replayed under a fresh (solicited) address.
        let forged_addr = [0x55u8; 32];
        let mut wanted = want_one(forged_addr, identity);
        let forged = accept_delivery(&mut wanted, delivery(forged_addr.to_vec(), wire, stamp));
        assert!(forged.is_err(), "content must hash to the claimed address");
    }

    #[test]
    fn syn_is_single_zero_frame() {
        let mut buf = Vec::new();
        Syn {}.encode_length_delimited(&mut buf).unwrap();
        assert_eq!(buf, vec![0u8]);
    }

    #[test]
    fn bitvector_layout_and_size() {
        // 9 bits → 2 bytes (len/8 + 1). Bit 8 sits in byte 1, mask 0x01.
        let mut bv = BitVec::with_len(9);
        assert_eq!(bv.bytes.len(), 2);
        bv.set(8);
        assert!(bv.get(8));
        assert_eq!(bv.bytes[1], 0x01);
        // exact multiple of 8 still gets the extra byte, matching bee.
        assert_eq!(BitVec::with_len(8).bytes.len(), 2);
    }
}
