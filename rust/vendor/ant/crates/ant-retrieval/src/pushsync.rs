//! Pushsync dialer (`/swarm/pushsync/1.3.1/pushsync`) — bee `pkg/pushsync`.

use ant_crypto::{
    ethereum_address_from_public_key, overlay_from_ethereum_address, recover_public_key,
    OVERLAY_NONCE_LEN,
};
use futures::io::AsyncWriteExt;
use libp2p::{PeerId, StreamProtocol};
use libp2p_stream::Control;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, trace};

use crate::{read_delimited, write_delimited, PbHeaders, RetrievalError, HEADERS_MAX};

/// Bee `pkg/pushsync/pushsync.go` pinned protocol id.
pub const PROTOCOL_PUSH: &str = "/swarm/pushsync/1.3.1/pushsync";

const RECEIPT_MAX: usize = 4 * 1024;

/// Single-attempt pushsync envelope. Was 30 s (mirroring our
/// retrieval timeout); raised to 45 s when the bee 2.7→2.8 cutover
/// surfaced a reproducible class of receipt-batching tail-stalls
/// where a Bee 2.8.0 storer acknowledges the chunk but holds the
/// final receipt for ~25-35 s before issuing it. The 30 s wall was
/// firing on those before the receipt landed, marking the peer as
/// failed and re-routing — only for the *same* slow path to repeat
/// on the next-closest storer.
///
/// The outer upload-driver wall in `ant_node::uploads` is 60 s per
/// chunk-emit; 45 s here leaves the outer 15 s to either accept a
/// late receipt mid-retry or move on cleanly. We never want this to
/// exceed the outer wall — if it did, the outer retry would never
/// fire because the inner would still be parked on a single peer's
/// timer.
///
/// Reverting to 30 s is safe (just slower under cutover load); raising
/// further than ~50 s causes the outer 60 s wall to fire mid-receipt
/// and we never see the late ack.
const PUSHSYNC_TIMEOUT: Duration = Duration::from_secs(45);

/// The error a push walk gives up with when every candidate peer stayed
/// at its credit limit for the whole credit budget (issue #128). One
/// constructor, so the upload job's string classifiers
/// (`ant-node::uploads::is_fatal_push_error` / `is_no_peer_error`, which
/// see it as `pushsync: <this>`) can be pinned against the real text: it
/// must stay transient: the chunk is re-queued, not the job failed.
#[must_use]
pub fn no_push_credit_error(overdrawn: usize, waited: Duration) -> PushSyncError {
    PushSyncError::Remote(format!(
        "no pushsync peer has credit: {overdrawn} candidate peer(s) at their credit limit after waiting {waited:?}",
    ))
}

#[derive(Debug, Error)]
pub enum PushSyncError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protobuf encode: {0}")]
    ProstEncode(#[from] prost::EncodeError),
    #[error("protobuf decode: {0}")]
    ProstDecode(#[from] prost::DecodeError),
    #[error("open pushsync stream: {0}")]
    OpenStream(String),
    #[error("timed out pushsync after {0:?}")]
    Timeout(Duration),
    #[error("{0}")]
    Remote(String),
    /// Storer peers rejected the postage stamp itself — the batch is
    /// not in their chain-synced batchstore (never created on this
    /// chain, expired and evicted, or not yet synced). Unlike every
    /// other variant this is NOT retryable against more peers: every
    /// honest storer validates stamps against the same chain state.
    /// Surfaced distinctly so the gateway can answer with an
    /// actionable, non-retryable error instead of a generic 502, and
    /// so the patience loop doesn't burn its budget re-walking
    /// (phantom-batch report, 2026-07-12).
    #[error(
        "postage batch 0x{} rejected by {rejections} peer(s) as not found on-chain (peer said: {sample})",
        hex::encode(batch_id)
    )]
    StampRejected {
        batch_id: [u8; 32],
        rejections: u32,
        sample: String,
    },
    #[error("receipt mismatch")]
    ReceiptMismatch,
    /// The receipt's storer signature could not be recovered, or the
    /// nonce/signature fields were the wrong length. A peer that ACKs a
    /// chunk address without a valid storer signature is not proof the
    /// chunk was stored anywhere; treat it as a failed push.
    #[error("unverifiable receipt: {0}")]
    UnverifiableReceipt(String),
    /// The receipt recovered a real storer, but that storer sits
    /// *shallower* to the chunk than its own reported storage radius —
    /// i.e. it is not actually in the chunk's neighbourhood, so the
    /// chunk did not durably land where it can be retrieved. Mirrors
    /// bee `pushsync.ErrShallowReceipt`.
    #[error("shallow receipt: storer proximity {po} < storage radius {storage_radius}")]
    ShallowReceipt { po: u8, storage_radius: u32 },
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct PbPushDelivery {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) data: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) stamp: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(crate) struct PbPushReceipt {
    #[prost(bytes = "vec", tag = "1")]
    pub(crate) address: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub(crate) signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(crate) nonce: Vec<u8>,
    #[prost(string, tag = "4")]
    pub(crate) err: String,
    #[prost(uint32, tag = "5")]
    pub(crate) storage_radius: u32,
}

/// Push one CAC chunk to a single peer — headers + protobuf `Delivery` + read `Receipt`.
///
/// Returns `Ok(())` only when the peer returns a receipt that both
/// names our chunk address *and* (when `network_id` is `Some`) carries
/// a storer signature that recovers an overlay genuinely inside the
/// chunk's neighbourhood. Without that check a peer could ACK the
/// address without any storer actually keeping the chunk, so the
/// upload would falsely report success while the content never became
/// retrievable. Pass `None` to skip verification (unit tests with a
/// mock peer that can't produce real signatures).
pub async fn push_chunk_to_peer(
    control: &mut Control,
    peer: PeerId,
    chunk_addr: [u8; 32],
    wire_span_payload: &[u8],
    stamp_binary: &[u8; ant_postage::STAMP_SIZE],
    network_id: Option<u64>,
) -> Result<(), PushSyncError> {
    push_chunk_to_peer_with_timeout(
        control,
        peer,
        chunk_addr,
        wire_span_payload,
        stamp_binary,
        network_id,
        PUSHSYNC_TIMEOUT,
    )
    .await
}

/// The default ceiling a single pushsync attempt is allowed to run for
/// (see [`PUSHSYNC_TIMEOUT`]).
pub const DEFAULT_PUSHSYNC_TIMEOUT: Duration = PUSHSYNC_TIMEOUT;

/// Like [`push_chunk_to_peer`] but with a caller-chosen per-attempt
/// deadline. The uploader uses a short "hedge" deadline for the early,
/// closest candidates so a single peer that opens the stream but then
/// stalls forwarding the chunk deeper (and never relays a receipt)
/// doesn't pin the whole chunk — and therefore the whole upload, which
/// waits on its slowest chunk — for the full 45 s. A healthy push acks
/// in well under a second, so a peer that hasn't answered in the hedge
/// window is almost certainly wedged; moving to the next-closest peer
/// is both faster and what bee's pusher effectively does. The full
/// [`PUSHSYNC_TIMEOUT`] is still available as the last-candidate
/// ceiling so a genuinely slow-but-correct neighbourhood is not
/// abandoned prematurely.
pub async fn push_chunk_to_peer_with_timeout(
    control: &mut Control,
    peer: PeerId,
    chunk_addr: [u8; 32],
    wire_span_payload: &[u8],
    stamp_binary: &[u8; ant_postage::STAMP_SIZE],
    network_id: Option<u64>,
    attempt_timeout: Duration,
) -> Result<(), PushSyncError> {
    tokio::time::timeout(
        attempt_timeout,
        push_chunk_inner(
            control,
            peer,
            chunk_addr,
            wire_span_payload,
            stamp_binary,
            network_id,
        ),
    )
    .await
    .map_err(|_| PushSyncError::Timeout(attempt_timeout))?
}

async fn push_chunk_inner(
    control: &mut Control,
    peer: PeerId,
    chunk_addr: [u8; 32],
    wire_span_payload: &[u8],
    stamp_binary: &[u8; ant_postage::STAMP_SIZE],
    network_id: Option<u64>,
) -> Result<(), PushSyncError> {
    let proto = StreamProtocol::new(PROTOCOL_PUSH);
    let mut stream = control
        .open_stream(peer, proto)
        .await
        .map_err(|e| PushSyncError::OpenStream(e.to_string()))?;

    write_delimited(&mut stream, &PbHeaders::default())
        .await
        .map_err(map_retrieval)?;
    let _their_headers = read_delimited::<PbHeaders>(&mut stream, HEADERS_MAX)
        .await
        .map_err(map_retrieval)?;

    trace!(target: "ant_pushsync", %peer, addr=%hex::encode(chunk_addr), "bee headers exchanged (push)");

    let delivery = PbPushDelivery {
        address: chunk_addr.to_vec(),
        data: wire_span_payload.to_vec(),
        stamp: stamp_binary.to_vec(),
    };

    write_delimited(&mut stream, &delivery)
        .await
        .map_err(map_retrieval)?;
    trace!(target: "ant_pushsync", %peer, "delivery sent");

    let receipt = read_delimited::<PbPushReceipt>(&mut stream, RECEIPT_MAX)
        .await
        .map_err(map_retrieval)?;

    let _ = stream.close().await;

    if !receipt.err.is_empty() {
        debug!(target: "ant_pushsync", %peer, err=%receipt.err, "pushsync remote error");
        return Err(PushSyncError::Remote(receipt.err.clone()));
    }

    let rep_addr: [u8; 32] = receipt
        .address
        .as_slice()
        .try_into()
        .map_err(|_| PushSyncError::ReceiptMismatch)?;
    if rep_addr != chunk_addr {
        return Err(PushSyncError::ReceiptMismatch);
    }

    if let Some(network_id) = network_id {
        verify_receipt(&rep_addr, &receipt, network_id)?;
    }

    Ok(())
}

/// Verify a pushsync receipt the way bee's `pushsync.checkReceipt`
/// does: recover the storer's public key from the signature over the
/// chunk address, derive its overlay (`keccak256(eth ‖ network_id_le ‖
/// nonce)`, the same scheme as the BZZ handshake), and confirm that
/// overlay is at least as close to the chunk as the storer's reported
/// `storage_radius`. An honest storer only keeps a chunk when its own
/// proximity to it is `>= radius`, so a genuine receipt always passes;
/// an ACK from a peer that didn't actually store the chunk (no
/// signature, a self-signature far from the chunk, …) does not.
///
/// Bee signs the receipt with its default `crypto.Signer`, which is the
/// same EIP-191-prefixed scheme `recover_public_key` inverts (verified
/// against a live SOC fixture in `ant_crypto::soc`), so we recover over
/// the raw 32-byte chunk address — exactly bee's
/// `crypto.Recover(receipt.Signature, addr.Bytes())`.
fn verify_receipt(
    chunk_addr: &[u8; 32],
    receipt: &PbPushReceipt,
    network_id: u64,
) -> Result<(), PushSyncError> {
    let signature: [u8; 65] = receipt
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PushSyncError::UnverifiableReceipt("signature not 65 bytes".into()))?;
    let nonce: [u8; OVERLAY_NONCE_LEN] = receipt
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| PushSyncError::UnverifiableReceipt("nonce not 32 bytes".into()))?;

    let pubkey = recover_public_key(&signature, chunk_addr)
        .map_err(|e| PushSyncError::UnverifiableReceipt(format!("recover storer key: {e}")))?;
    let storer_eth = ethereum_address_from_public_key(&pubkey);
    let storer_overlay = overlay_from_ethereum_address(&storer_eth, network_id, &nonce);

    let po = proximity(chunk_addr, &storer_overlay);
    if u32::from(po) < receipt.storage_radius {
        return Err(PushSyncError::ShallowReceipt {
            po,
            storage_radius: receipt.storage_radius,
        });
    }
    Ok(())
}

/// XOR-distance proximity order between two 32-byte addresses, matching
/// `bee/pkg/swarm/swarm.go::Proximity`: the number of leading zero bits
/// in `a XOR b`, capped at `MAX_PO = 31` (storage radii on mainnet are
/// far below this, so the cap never interferes with the shallow check).
pub(crate) fn proximity(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    const MAX_PO: u8 = 31;
    let mut po = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        let xor = x ^ y;
        if xor == 0 {
            po = po.saturating_add(8);
            if po >= MAX_PO {
                return MAX_PO;
            }
            continue;
        }
        po = po.saturating_add(xor.leading_zeros() as u8);
        return po.min(MAX_PO);
    }
    MAX_PO
}

fn map_retrieval(e: RetrievalError) -> PushSyncError {
    match e {
        RetrievalError::Io(io) => PushSyncError::Io(io),
        RetrievalError::ProstEncode(pe) => PushSyncError::ProstEncode(pe),
        RetrievalError::ProstDecode(pe) => PushSyncError::ProstDecode(pe),
        RetrievalError::MessageTooLarge { got, cap } => {
            PushSyncError::Remote(format!("message too large: {got} (cap {cap})"))
        }
        RetrievalError::OpenStream(s) => PushSyncError::OpenStream(s),
        RetrievalError::Timeout(d) => PushSyncError::Timeout(d),
        RetrievalError::Remote(s) => PushSyncError::Remote(s),
        RetrievalError::InvalidChunk => PushSyncError::Remote("invalid chunk hint".into()),
        RetrievalError::BadPayloadSize(_) => PushSyncError::Remote("bad payload size".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::sign_handshake_data;
    use k256::ecdsa::{SigningKey, VerifyingKey};

    const NETWORK_ID: u64 = 1;

    /// Storer Ethereum address for a test secret.
    fn storer_eth(secret: &[u8; 32]) -> [u8; 20] {
        let sk = SigningKey::from_bytes(secret.into()).unwrap();
        ethereum_address_from_public_key(&VerifyingKey::from(&sk))
    }

    /// Build a receipt the way an honest bee storer does: sign the
    /// chunk address with the storer's key (EIP-191, bee's
    /// `crypto.Signer.Sign`) and stamp it with the storer's nonce +
    /// reported storage radius.
    fn signed_receipt(
        secret: &[u8; 32],
        chunk_addr: &[u8; 32],
        nonce: &[u8; OVERLAY_NONCE_LEN],
        storage_radius: u32,
    ) -> PbPushReceipt {
        let sig = sign_handshake_data(secret, chunk_addr).unwrap();
        PbPushReceipt {
            address: chunk_addr.to_vec(),
            signature: sig.to_vec(),
            nonce: nonce.to_vec(),
            err: String::new(),
            storage_radius,
        }
    }

    #[test]
    fn proximity_identical_is_max() {
        let a = [0x5cu8; 32];
        assert_eq!(proximity(&a, &a), 31);
    }

    #[test]
    fn proximity_first_bit_differs_is_zero() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 0x80; // differ in the most-significant bit
        assert_eq!(proximity(&a, &b), 0);
    }

    /// A genuine storer (its overlay *is* the chunk's neighbourhood)
    /// returning a properly-signed receipt is accepted.
    #[test]
    fn accepts_genuine_storer_receipt() {
        let secret = [7u8; 32];
        let nonce = [0xabu8; OVERLAY_NONCE_LEN];
        // Put the chunk exactly at the storer's overlay so proximity is
        // maximal — the storer is unambiguously responsible for it.
        let chunk_addr = overlay_from_ethereum_address(&storer_eth(&secret), NETWORK_ID, &nonce);
        let receipt = signed_receipt(&secret, &chunk_addr, &nonce, 10);
        assert!(verify_receipt(&chunk_addr, &receipt, NETWORK_ID).is_ok());
    }

    /// A correctly-signed receipt whose storer sits *outside* the
    /// chunk's neighbourhood (shallower than its own reported radius) is
    /// a shallow receipt: the chunk did not land where it's retrievable.
    #[test]
    fn rejects_shallow_receipt() {
        let secret = [9u8; 32];
        let nonce = [0x11u8; OVERLAY_NONCE_LEN];
        let overlay = overlay_from_ethereum_address(&storer_eth(&secret), NETWORK_ID, &nonce);
        // Chunk differs from the storer in the top bit → proximity 0.
        let mut chunk_addr = overlay;
        chunk_addr[0] ^= 0x80;
        let receipt = signed_receipt(&secret, &chunk_addr, &nonce, 5);
        match verify_receipt(&chunk_addr, &receipt, NETWORK_ID) {
            Err(PushSyncError::ShallowReceipt { po, storage_radius }) => {
                assert_eq!(po, 0);
                assert_eq!(storage_radius, 5);
            }
            other => panic!("expected ShallowReceipt, got {other:?}"),
        }
    }

    /// A peer that ACKs the address with no usable signature can't prove
    /// any storer kept the chunk; the receipt is unverifiable.
    #[test]
    fn rejects_short_signature() {
        let nonce = [0x22u8; OVERLAY_NONCE_LEN];
        let chunk_addr = [0x33u8; 32];
        let receipt = PbPushReceipt {
            address: chunk_addr.to_vec(),
            signature: vec![0u8; 10],
            nonce: nonce.to_vec(),
            err: String::new(),
            storage_radius: 0,
        };
        assert!(matches!(
            verify_receipt(&chunk_addr, &receipt, NETWORK_ID),
            Err(PushSyncError::UnverifiableReceipt(_)),
        ));
    }

    /// A receipt whose nonce isn't 32 bytes can't yield a storer overlay.
    #[test]
    fn rejects_bad_nonce_length() {
        let secret = [4u8; 32];
        let chunk_addr = [0x44u8; 32];
        let sig = sign_handshake_data(&secret, &chunk_addr).unwrap();
        let receipt = PbPushReceipt {
            address: chunk_addr.to_vec(),
            signature: sig.to_vec(),
            nonce: vec![0u8; 8],
            err: String::new(),
            storage_radius: 0,
        };
        assert!(matches!(
            verify_receipt(&chunk_addr, &receipt, NETWORK_ID),
            Err(PushSyncError::UnverifiableReceipt(_)),
        ));
    }
}
