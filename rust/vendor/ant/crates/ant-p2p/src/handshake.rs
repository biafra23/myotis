//! Swarm BZZ handshake (`bee` `pkg/p2p/libp2p/internal/handshake`),
//! length-delimited protobuf. Speaks both wire versions:
//!
//! * **v14** (bee 2.7.x) — preimage `bee-handshake- ‖ underlay ‖ overlay
//!   ‖ network_id_be`, with `Nonce` next to the signature in the `Ack`
//!   message.
//! * **v15** (bee 2.8.0) — preimage extended with `‖ nonce ‖
//!   timestamp_be ‖ chequebook(20B)`, with `Nonce`, `Timestamp` and
//!   `ChequebookAddress` moved inside `BzzAddress`.
//!
//! The libp2p substream is negotiated under one of two distinct
//! protocol ids — bee runs at most one of `15.0.0` or `14.0.0` so the
//! caller picks the version up-front and we encode/decode strictly to
//! that schema. The dialer in `behaviour.rs` falls back from V15 to
//! V14 when the remote rejects the V15 protocol id (multistream-select
//! `na`), so the cutover is transparent across the mainnet rolling
//! upgrade.

use crate::underlay::{
    deserialize_underlays, serialize_underlays, serialize_underlays_checked, truncate_underlays,
    UnderlayError,
};
use ant_crypto::{
    overlay_from_ethereum_address, sign_handshake_data, verify_bzz_address_signature, CryptoError,
    HandshakeWireVersion, HANDSHAKE_CHEQUEBOOK_LEN, OVERLAY_NONCE_LEN, SECP256K1_SECRET_LEN,
};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use k256::ecdsa::SigningKey;
use libp2p::core::multiaddr::Protocol;
use libp2p::identity::PeerId;
use libp2p::multiaddr::Multiaddr;
use prost::Message;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::debug;

/// bee 2.8.0 protocol id. New deployments speak this first.
pub const PROTOCOL_HANDSHAKE_V15: &str = "/swarm/handshake/15.0.0/handshake";
/// bee 2.7.x protocol id. Kept for the cutover window; we open this
/// only after V15 negotiation fails.
pub const PROTOCOL_HANDSHAKE_V14: &str = "/swarm/handshake/14.0.0/handshake";

/// Backward-compatible alias — older callers expect a single
/// [`PROTOCOL_HANDSHAKE`] constant. It points at the V15 protocol id
/// now that 2.8.0 is the default.
pub const PROTOCOL_HANDSHAKE: &str = PROTOCOL_HANDSHAKE_V15;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROTO_MESSAGE: usize = 128 * 1024;

/// Bee 2.8 rejects records dated `> now + MAX_CLOCK_SKEW` — see
/// [pkg/bzz/timestamp.go](../bee/pkg/bzz/timestamp.go). We mirror
/// the same window on the receive side so we surface the rejection
/// locally rather than letting bee bounce us mid-handshake.
const MAX_CLOCK_SKEW: i64 = 60;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("protobuf: {0}")]
    Prost(#[from] prost::DecodeError),
    #[error("protobuf encode: {0}")]
    ProstEncode(#[from] prost::EncodeError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("underlay: {0}")]
    Underlay(#[from] UnderlayError),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("ecdsa: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
    #[error("network id mismatch")]
    NetworkId,
    #[error("expected full node")]
    NotFullNode,
    #[error("invalid syn: observed peer id does not match ours")]
    SynPeerId,
    #[error("missing syn or ack in SynAck")]
    IncompleteSynAck,
    #[error("missing fields in ack")]
    IncompleteAck,
    #[error("handshake timed out")]
    Timeout,
    #[error("message too large")]
    MessageTooLarge,
    #[error("invalid remote nonce length (got {0}, expected 32)")]
    NonceLen(usize),
    #[error("invalid remote chequebook length (got {0}, expected 0 or 20)")]
    ChequebookLen(usize),
    #[error("remote timestamp invalid (got {0}, must be > 0)")]
    TimestampInvalid(i64),
    #[error("remote timestamp in future (got {0}, now {1})")]
    TimestampInFuture(i64, i64),
}

#[derive(Clone, Debug)]
pub struct HandshakeInfo {
    pub remote_overlay: [u8; 32],
    pub remote_full_node: bool,
    /// Ethereum address (20 bytes) of the peer's node identity. Bee's
    /// SWAP layer uses this as the **beneficiary** of cheques: when we
    /// owe a peer, the cheque we emit has `beneficiary = this`. We
    /// recover it here by re-deriving the secp256k1 verifying key
    /// from the `BzzAddress` signature against the same digest the
    /// peer signed during handshake.
    pub remote_eth_address: [u8; 20],
    /// Welcome message string the remote sent in its handshake Ack.
    /// Bee uses this as a free-form node banner; we surface it so
    /// callers can log / display it without re-parsing the
    /// protobuf. Empty when the remote opted out.
    pub remote_welcome: String,
    /// Wire version negotiated for this handshake. Populated so the
    /// caller can decide whether to expect `remote_timestamp` /
    /// `remote_chequebook` to be present.
    pub wire_version: HandshakeWireVersion,
    /// V15-only: peer-declared unix timestamp of the signed
    /// `BzzAddress`. Zero for V14 peers (which don't carry it on the
    /// wire) so the caller can detect "field absent" without an
    /// Option dance.
    pub remote_timestamp: i64,
    /// V15-only: peer-declared chequebook contract address. `None`
    /// for V14 peers, and for V15 peers that explicitly advertised an
    /// empty chequebook (light nodes pre-deployment).
    pub remote_chequebook: Option<[u8; 20]>,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Syn {
    #[prost(bytes = "vec", tag = "1")]
    pub observed_underlay: Vec<u8>,
}

/// Union over the V14 and V15 `BzzAddress` wire shapes. Prost ignores
/// fields the peer didn't send, so:
///
/// * V14 dialers populate tags 1-3 only;
/// * V15 dialers also populate tags 4 (nonce), 5 (timestamp), and 6
///   (`chequebook_address` — zero-length when the peer has no
///   chequebook).
///
/// The `nonce` field shares tag 4 with the V14 `Ack.nonce` slot — we
/// emit/decode it inside `BzzAddress` for V15 and inside `Ack` for
/// V14, never both, so there is no collision on the wire.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct BzzAddress {
    #[prost(bytes = "vec", tag = "1")]
    pub underlay: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub overlay: Vec<u8>,
    /// V15 only.
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
    /// V15 only.
    #[prost(int64, tag = "5")]
    pub timestamp: i64,
    /// V15 only. Either empty or exactly 20 bytes; bee rejects other
    /// lengths up-front.
    #[prost(bytes = "vec", tag = "6")]
    pub chequebook_address: Vec<u8>,
}

/// Union of V14 and V15 `Ack`. Tag 4 (`nonce`) is only populated on
/// V14; V15 moves it into `BzzAddress.nonce` and the `Ack.nonce` slot
/// stays at proto-default (empty). The wire shapes are unambiguous
/// because we negotiate the version via the libp2p protocol id (V14 vs.
/// V15) before either side writes its `Ack`.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Ack {
    #[prost(message, optional, tag = "1")]
    pub address: Option<BzzAddress>,
    #[prost(uint64, tag = "2")]
    pub network_id: u64,
    #[prost(bool, tag = "3")]
    pub full_node: bool,
    /// V14 only — see [`BzzAddress.nonce`] for V15.
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
    #[prost(string, tag = "99")]
    pub welcome_message: String,
}

#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct SynAck {
    #[prost(message, optional, tag = "1")]
    pub syn: Option<Syn>,
    #[prost(message, optional, tag = "2")]
    pub ack: Option<Ack>,
}

async fn write_delimited(
    w: &mut (impl AsyncWriteExt + Unpin),
    msg: &impl Message,
) -> Result<(), HandshakeError> {
    let mut buf = Vec::new();
    msg.encode_length_delimited(&mut buf)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

async fn read_delimited(r: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>, HandshakeError> {
    let len = read_varint_len(r).await?;
    if len > MAX_PROTO_MESSAGE {
        return Err(HandshakeError::MessageTooLarge);
    }
    // Grows with the bytes that arrive, not the declared `len`, so a peer
    // can't pin the cap per stream by declaring a frame and stalling (#203).
    Ok(ant_retrieval::frame::read_frame_body(r, len).await?)
}

async fn read_varint_len(r: &mut (impl AsyncReadExt + Unpin)) -> Result<usize, HandshakeError> {
    let mut b = [0u8; 1];
    let mut buf = Vec::with_capacity(8);
    loop {
        r.read_exact(&mut b).await?;
        buf.push(b[0]);
        match unsigned_varint::decode::u64(&buf) {
            Ok((v, [])) => return Ok(v as usize),
            Ok(_) => {
                return Err(HandshakeError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid varint framing",
                )));
            }
            Err(unsigned_varint::decode::Error::Insufficient) => {
                if buf.len() > 10 {
                    return Err(HandshakeError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "varint too long",
                    )));
                }
            }
            Err(e) => {
                return Err(HandshakeError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("varint: {e}"),
                )));
            }
        }
    }
}

/// Outbound handshake (we are the dialer). `remote_peer_addrs` are
/// dial addresses for the **remote** peer. The libp2p protocol id was
/// already negotiated by the caller, who passes `version` so we know
/// which wire schema to emit / expect.
#[allow(clippy::too_many_arguments)]
pub async fn handshake_outbound<S>(
    stream: S,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    signing_secret: &[u8; SECP256K1_SECRET_LEN],
    overlay_nonce: &[u8; OVERLAY_NONCE_LEN],
    network_id: u64,
    remote_peer_addrs: &[Multiaddr],
    local_listen_addrs: Vec<Multiaddr>,
    version: HandshakeWireVersion,
) -> Result<HandshakeInfo, HandshakeError>
where
    S: AsyncReadExt + AsyncWriteExt + Send + Unpin,
{
    handshake_outbound_with_role(
        stream,
        local_peer_id,
        remote_peer_id,
        signing_secret,
        overlay_nonce,
        network_id,
        remote_peer_addrs,
        local_listen_addrs,
        advertise_full_node_from_env(),
        version,
    )
    .await
}

/// Perf-lab Experiment 7, **DEFAULT OFF** since 2026-07-07: outbound
/// BZZ handshakes advertise the honest `full_node = false`.
/// `ANT_ADVERTISE_FULL_NODE=1` opts back into advertising
/// `full_node = true`.
///
/// The misdeclaration was default-ON for one day (2026-07-06, project
/// owner's decision) for bee's 10× wider per-peer accounting budget
/// for full peers (4.5 M vs 450 K PLUR/s refresh, 13.5 M vs 1.35 M
/// payment threshold) — measured on mainnet as 2.5× upload throughput
/// with 12× fewer connection kills during sustained pushes
/// (PERF-LAB.md exp 7). It was flipped back off because of what it
/// does to bootstrap on a NAT-ed light client (measured 2026-07-07,
/// interleaved cold starts): remote bees admit the "full" peer and
/// then reset it within ~0.3 s (506 resets across 607 handshakes vs
/// 38/148 honest — reachability checks and reserve/pullsync
/// expectations we can't meet), and the bee bootnode handshake sits
/// its full 10 s peerstore stall. Cold 0→100 peers: ~10 s honest vs
/// ~30 s misdeclared. Set the env flag for upload-heavy sessions where
/// the throughput trade wins; a future ramp-light-then-full hybrid
/// could recover both. Read once per process.
fn advertise_full_node_from_env() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| match std::env::var("ANT_ADVERTISE_FULL_NODE") {
        Err(_) => false,
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
        }
    })
}

/// Like [`handshake_outbound`] but lets the caller pick the
/// `full_node` flag advertised in our `Ack`. The default
/// [`handshake_outbound`] declares `false` (we're a light node);
/// flipping this is only useful for the SWAP interop smoke test
/// where bee's swap handler refuses cheques from light peers.
#[allow(clippy::too_many_arguments)]
pub async fn handshake_outbound_with_role<S>(
    mut stream: S,
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    signing_secret: &[u8; SECP256K1_SECRET_LEN],
    overlay_nonce: &[u8; OVERLAY_NONCE_LEN],
    network_id: u64,
    remote_peer_addrs: &[Multiaddr],
    local_listen_addrs: Vec<Multiaddr>,
    advertise_full_node: bool,
    version: HandshakeWireVersion,
) -> Result<HandshakeInfo, HandshakeError>
where
    S: AsyncReadExt + AsyncWriteExt + Send + Unpin,
{
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_outbound_inner(
            &mut stream,
            local_peer_id,
            remote_peer_id,
            signing_secret,
            overlay_nonce,
            network_id,
            remote_peer_addrs,
            local_listen_addrs,
            advertise_full_node,
            version,
        ),
    )
    .await
    .map_err(|_| HandshakeError::Timeout)?
}

#[allow(clippy::too_many_arguments)]
async fn handshake_outbound_inner(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    local_peer_id: PeerId,
    remote_peer_id: PeerId,
    signing_secret: &[u8; SECP256K1_SECRET_LEN],
    overlay_nonce: &[u8; OVERLAY_NONCE_LEN],
    network_id: u64,
    remote_peer_addrs: &[Multiaddr],
    local_listen_addrs: Vec<Multiaddr>,
    advertise_full_node: bool,
    version: HandshakeWireVersion,
) -> Result<HandshakeInfo, HandshakeError> {
    let sk = SigningKey::from_bytes(signing_secret.into())?;
    let vk = k256::ecdsa::VerifyingKey::from(&sk);
    let eth = ant_crypto::ethereum_address_from_public_key(&vk);
    let overlay: [u8; 32] = overlay_from_ethereum_address(&eth, network_id, overlay_nonce);

    let remote_mas = build_full_peer_maddrs(remote_peer_addrs, remote_peer_id)?;
    let syn = Syn {
        observed_underlay: serialize_underlays(&remote_mas),
    };
    let t0 = Instant::now();
    write_delimited(stream, &syn).await?;
    debug!(target: "ant_p2p::handshake", elapsed_ms = t0.elapsed().as_millis() as u64, "syn sent");

    let buf = read_delimited(stream).await?;
    debug!(target: "ant_p2p::handshake", elapsed_ms = t0.elapsed().as_millis() as u64, bytes = buf.len(), "syn-ack received");
    let syn_ack = SynAck::decode(&buf[..])?;
    let resp_syn = syn_ack
        .syn
        .as_ref()
        .ok_or(HandshakeError::IncompleteSynAck)?;
    let resp_ack = syn_ack
        .ack
        .as_ref()
        .ok_or(HandshakeError::IncompleteSynAck)?;

    let observed = deserialize_underlays(&resp_syn.observed_underlay)?;
    for o in &observed {
        let info = o.iter().find_map(|p| match p {
            Protocol::P2p(pid) => Some(pid),
            _ => None,
        });
        if info != Some(local_peer_id) {
            return Err(HandshakeError::SynPeerId);
        }
    }

    let mut advertisable: Vec<Multiaddr> = observed
        .into_iter()
        .map(resolve_advertisable)
        .collect::<Vec<_>>();
    for a in local_listen_addrs {
        if !is_loopback(&a) {
            advertisable.push(build_full_ma(&a, local_peer_id)?);
        }
    }
    sort_dedupe_maddrs(&mut advertisable);
    // Bee 2.8 caps the underlay payload at 20 entries / 2048 bytes and
    // rejects out-of-bound records. `truncate_underlays` drops the
    // lowest-priority entries first (IPv6 / private / loopback) so we
    // surface our best-reachable underlay set within the cap.
    advertisable = truncate_underlays(&advertisable);

    let underlay_bytes = serialize_underlays_checked(&advertisable)?;
    let our_timestamp = match version {
        HandshakeWireVersion::V14 => 0,
        HandshakeWireVersion::V15 => unix_now_i64(),
    };
    // We do not deploy a chequebook today — bee 2.8 accepts zero-length
    // chequebooks unless an operator flips `--chequebook-verification`.
    let our_chequebook: &[u8] = &[];
    let sign_data = ant_crypto::handshake_sign_data(
        version,
        &underlay_bytes,
        &overlay,
        network_id,
        overlay_nonce,
        our_timestamp,
        our_chequebook,
    );
    let sig = sign_handshake_data(signing_secret, &sign_data)?;

    if resp_ack.network_id != network_id {
        return Err(HandshakeError::NetworkId);
    }
    if !resp_ack.full_node {
        return Err(HandshakeError::NotFullNode);
    }

    let addr = resp_ack
        .address
        .as_ref()
        .ok_or(HandshakeError::IncompleteAck)?;
    if addr.overlay.len() != 32 || addr.signature.len() != 65 {
        return Err(HandshakeError::IncompleteAck);
    }
    let mut remote_overlay = [0u8; 32];
    remote_overlay.copy_from_slice(&addr.overlay);
    let mut remote_sig = [0u8; 65];
    remote_sig.copy_from_slice(&addr.signature);

    // V14 ships the nonce next to the signature on `Ack`; V15 ships it
    // inside `BzzAddress`. Pull from the correct slot so we can recover
    // the signature against the wire-specific preimage.
    let remote_nonce_bytes: &[u8] = match version {
        HandshakeWireVersion::V14 => &resp_ack.nonce,
        HandshakeWireVersion::V15 => &addr.nonce,
    };
    if remote_nonce_bytes.len() != OVERLAY_NONCE_LEN {
        return Err(HandshakeError::NonceLen(remote_nonce_bytes.len()));
    }
    let mut remote_nonce = [0u8; OVERLAY_NONCE_LEN];
    remote_nonce.copy_from_slice(remote_nonce_bytes);

    let (remote_timestamp, remote_chequebook): (i64, Option<[u8; 20]>) = match version {
        HandshakeWireVersion::V14 => (0, None),
        HandshakeWireVersion::V15 => {
            if addr.timestamp <= 0 {
                return Err(HandshakeError::TimestampInvalid(addr.timestamp));
            }
            let now = unix_now_i64();
            if addr.timestamp > now.saturating_add(MAX_CLOCK_SKEW) {
                return Err(HandshakeError::TimestampInFuture(addr.timestamp, now));
            }
            let cb = match addr.chequebook_address.len() {
                0 => None,
                HANDSHAKE_CHEQUEBOOK_LEN => {
                    let mut a = [0u8; HANDSHAKE_CHEQUEBOOK_LEN];
                    a.copy_from_slice(&addr.chequebook_address);
                    Some(a)
                }
                n => return Err(HandshakeError::ChequebookLen(n)),
            };
            (addr.timestamp, cb)
        }
    };

    let remote_eth_address = verify_bzz_address_signature(
        version,
        &addr.underlay,
        &remote_overlay,
        &remote_sig,
        &remote_nonce,
        network_id,
        remote_timestamp,
        addr.chequebook_address.as_slice(),
    )?;

    if !resp_ack.welcome_message.is_empty() {
        debug!(
            target: "ant_p2p::handshake",
            welcome = %resp_ack.welcome_message,
            "remote welcome message",
        );
    }

    let our_bzz = BzzAddress {
        underlay: underlay_bytes,
        signature: sig.to_vec(),
        overlay: overlay.to_vec(),
        // V14 keeps these at proto-default (empty / zero) — V14 peers
        // ignore them on decode anyway, and we don't want to spend
        // extra bytes per Ack.
        nonce: match version {
            HandshakeWireVersion::V14 => Vec::new(),
            HandshakeWireVersion::V15 => overlay_nonce.to_vec(),
        },
        timestamp: our_timestamp,
        chequebook_address: Vec::new(),
    };
    let our_ack = Ack {
        address: Some(our_bzz),
        network_id,
        full_node: advertise_full_node,
        // Mirror the wire-version split: V14 keeps `nonce` on `Ack`;
        // V15 leaves it at proto-default.
        nonce: match version {
            HandshakeWireVersion::V14 => overlay_nonce.to_vec(),
            HandshakeWireVersion::V15 => Vec::new(),
        },
        welcome_message: String::new(),
    };
    write_delimited(stream, &our_ack).await?;
    // Half-close the write side so bee's `handshakeStream.FullClose()`
    // gets a clean `io.EOF` on its `Read([]byte{0})`. Dropping the stream
    // handle instead makes yamux send a Reset, which bee interprets as a
    // protocol error and disconnects us with
    // `"could not fully close stream on handshake"` ~80 ms after the Ack.
    stream.close().await?;
    debug!(target: "ant_p2p::handshake", elapsed_ms = t0.elapsed().as_millis() as u64, "ack sent");

    Ok(HandshakeInfo {
        remote_overlay,
        remote_full_node: resp_ack.full_node,
        remote_eth_address,
        remote_welcome: resp_ack.welcome_message.clone(),
        wire_version: version,
        remote_timestamp,
        remote_chequebook,
    })
}

fn unix_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

const fn resolve_advertisable(observed: Multiaddr) -> Multiaddr {
    observed
}

fn is_loopback(addr: &Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, Protocol::Ip4(ip) if ip.is_loopback()))
        || addr
            .iter()
            .any(|p| matches!(p, Protocol::Ip6(ip) if ip.is_loopback()))
}

fn build_full_ma(addr: &Multiaddr, peer: PeerId) -> Result<Multiaddr, HandshakeError> {
    if addr.iter().any(|p| matches!(p, Protocol::P2p(_))) {
        return Ok(addr.clone());
    }
    format!("{addr}/p2p/{peer}")
        .parse()
        .map_err(|e| HandshakeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

fn build_full_peer_maddrs(
    addrs: &[Multiaddr],
    remote: PeerId,
) -> Result<Vec<Multiaddr>, HandshakeError> {
    let mut v = Vec::new();
    for a in addrs {
        v.push(build_full_ma(a, remote)?);
    }
    if v.is_empty() {
        return Err(HandshakeError::IncompleteAck);
    }
    Ok(v)
}

fn sort_dedupe_maddrs(addrs: &mut Vec<Multiaddr>) {
    addrs.sort_by_key(std::string::ToString::to_string);
    addrs.dedup_by(|a, b| a == b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// Encode the bee 2.8 Ack shape (V15: nonce / timestamp /
    /// chequebook inside `BzzAddress`, `Ack.nonce` empty) and decode it
    /// back — verifies the prost field-tag layout matches what bee
    /// emits on the wire.
    #[test]
    fn ack_v15_round_trip() {
        let bzz = BzzAddress {
            underlay: b"/ip4/1.2.3.4/tcp/1634".to_vec(),
            signature: vec![0u8; 65],
            overlay: vec![0xab; 32],
            nonce: vec![0xcd; OVERLAY_NONCE_LEN],
            timestamp: 1_715_000_000,
            chequebook_address: vec![0xef; HANDSHAKE_CHEQUEBOOK_LEN],
        };
        let ack = Ack {
            address: Some(bzz.clone()),
            network_id: 1,
            full_node: true,
            nonce: Vec::new(),
            welcome_message: "welcome".to_string(),
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let decoded = Ack::decode(&buf[..]).unwrap();
        assert_eq!(decoded.address.as_ref().unwrap().timestamp, 1_715_000_000);
        assert_eq!(
            decoded.address.as_ref().unwrap().chequebook_address.len(),
            20
        );
        assert_eq!(
            decoded.address.as_ref().unwrap().nonce.len(),
            OVERLAY_NONCE_LEN
        );
        assert!(decoded.nonce.is_empty(), "V15 leaves Ack.nonce empty");
        assert_eq!(decoded.welcome_message, "welcome");
    }

    /// V14 shape: nonce lives on `Ack`, `BzzAddress` only carries the
    /// underlay / signature / overlay tags. The new V15 fields stay
    /// at proto-default so old bee 2.7 decoders read them as absent.
    #[test]
    fn ack_v14_round_trip() {
        let bzz = BzzAddress {
            underlay: b"/ip4/1.2.3.4/tcp/1634".to_vec(),
            signature: vec![0u8; 65],
            overlay: vec![0xab; 32],
            nonce: Vec::new(),
            timestamp: 0,
            chequebook_address: Vec::new(),
        };
        let ack = Ack {
            address: Some(bzz),
            network_id: 1,
            full_node: true,
            nonce: vec![0xcd; OVERLAY_NONCE_LEN],
            welcome_message: String::new(),
        };
        let mut buf = Vec::new();
        ack.encode(&mut buf).unwrap();
        let decoded = Ack::decode(&buf[..]).unwrap();
        assert_eq!(decoded.nonce.len(), OVERLAY_NONCE_LEN);
        let addr = decoded.address.unwrap();
        assert_eq!(addr.nonce, [] as [u8; 0]);
        assert_eq!(addr.timestamp, 0);
        assert_eq!(addr.chequebook_address, [] as [u8; 0]);
    }

    /// `HandshakeError` carries the field-length and timestamp-gate
    /// variants the spec calls out so callers can attribute remote
    /// rejections precisely.
    #[test]
    fn error_variants_carry_diagnostic_data() {
        let e = HandshakeError::NonceLen(31);
        assert!(format!("{e}").contains("31"));
        let e = HandshakeError::ChequebookLen(19);
        assert!(format!("{e}").contains("19"));
        let e = HandshakeError::TimestampInvalid(-1);
        assert!(format!("{e}").contains("-1"));
        let e = HandshakeError::TimestampInFuture(2, 1);
        let s = format!("{e}");
        assert!(s.contains('2') && s.contains('1'));
    }
}
