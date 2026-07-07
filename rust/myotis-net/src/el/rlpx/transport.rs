//! RLPx TCP transport: dial a peer, run the EIP-8 handshake to FRAMED, and
//! exchange framed p2p messages (EL-A4). Twin of the Java `RLPxConnector` /
//! `RLPxHandler` state machine (`HANDSHAKE_WRITE → HANDSHAKE_READ → FRAMED`).
//!
//! This is the only part of the RLPx module that touches sockets and OS
//! entropy; the crypto lives in the pure [`super::ecies`]/[`super::handshake`]/
//! [`super::frame`] modules. EL-A5 layers the eth handshake on top of the Hello
//! exchange started here.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use myotis_core::nodekey::NodeKey;

use super::frame::{DecodedFrame, FrameCodec, FrameDecoder, FrameEncoder};
use super::handshake::Initiator;

/// p2p base message codes (shared prefix below the eth sub-protocol).
pub const P2P_HELLO: u64 = 0x00;
pub const P2P_DISCONNECT: u64 = 0x01;
pub const P2P_PING: u64 = 0x02;
pub const P2P_PONG: u64 = 0x03;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// EIP-8 ack size cap (padding can push it to ~600 bytes; be generous).
const MAX_ACK_SIZE: usize = 2048;
/// Once a frame HEADER has arrived, its body must follow promptly — a peer that
/// declares a large body then stalls would otherwise pin the connection and the
/// body buffer. (Waiting on the header itself is a legitimate idle state and is
/// NOT bounded here.)
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound a single frame write. A peer that advertises a zero receive window and
/// stops reading would otherwise block `write_all` forever — and with the split
/// connection's shared writer, that stalls every other request and the read
/// loop's Pong. A write timeout means the egress frame stream is in an
/// indeterminate state, so callers must treat it as a fatal connection error.
const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A live framed RLPx connection: the TCP stream plus the session's stateful
/// [`FrameCodec`]. Read/write are serialized through `&mut self` (the codec is
/// position-dependent), matching the Java single-event-loop contract.
pub struct RlpxConnection {
    stream: TcpStream,
    codec: FrameCodec,
    /// The peer's static public key (its enode id).
    peer_pubkey: [u8; 64],
}

impl RlpxConnection {
    /// Dial `addr`, perform the initiator handshake against `peer_pubkey`, and
    /// return a FRAMED connection. Entropy (handshake + ecies ephemerals,
    /// nonces, IV, EIP-8 padding) is drawn from the OS here.
    pub async fn dial(
        local_key: Arc<NodeKey>,
        addr: std::net::SocketAddr,
        peer_pubkey: [u8; 64],
    ) -> Result<RlpxConnection, String> {
        let fut = Self::dial_inner(local_key, addr, peer_pubkey);
        tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
            .await
            .map_err(|_| "rlpx handshake timed out".to_string())?
    }

    async fn dial_inner(
        local_key: Arc<NodeKey>,
        addr: std::net::SocketAddr,
        peer_pubkey: [u8; 64],
    ) -> Result<RlpxConnection, String> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("rlpx connect: {e}"))?;
        stream.set_nodelay(true).ok();

        // Fresh entropy for this handshake.
        let eph_secret = random32();
        let local_nonce = random32();
        let ecies_eph = random32();
        let ecies_iv = random16();
        let padding = random_padding();

        let mut initiator = Initiator::new(&local_key, peer_pubkey, &eph_secret, local_nonce)
            .map_err(|e| format!("rlpx init: {}", e.0))?;
        let auth_wire = initiator
            .build_auth(&ecies_eph, &ecies_iv, &padding)
            .map_err(|e| format!("rlpx auth: {}", e.0))?;
        stream
            .write_all(&auth_wire)
            .await
            .map_err(|e| format!("rlpx write auth: {e}"))?;

        // Read the EIP-8 ack: 2-byte size prefix, then that many bytes.
        let ack_wire = read_ack(&mut stream).await?;
        let secrets = initiator
            .process_ack(&ack_wire)
            .map_err(|e| format!("rlpx ack: {}", e.0))?;

        Ok(RlpxConnection {
            stream,
            codec: FrameCodec::new(&secrets),
            peer_pubkey,
        })
    }

    pub fn peer_pubkey(&self) -> [u8; 64] {
        self.peer_pubkey
    }

    /// Split into independent read/write halves for the managed-peer's separate
    /// tasks (the frame codec's egress/ingress state are independent).
    pub fn split(self) -> (RlpxReader, RlpxWriter, [u8; 64]) {
        let (read_half, write_half) = self.stream.into_split();
        let (encoder, decoder) = self.codec.split();
        (
            RlpxReader { read_half, decoder },
            RlpxWriter { write_half, encoder },
            self.peer_pubkey,
        )
    }

    /// Frame and send one message (bounded by [`FRAME_WRITE_TIMEOUT`]).
    pub async fn send(&mut self, message_code: u64, body: &[u8]) -> Result<(), String> {
        let frame = self.codec.encode_frame(message_code, body);
        write_frame(&mut self.stream, &frame).await
    }

    /// Read and decode the next frame. Blocks indefinitely waiting for the next
    /// frame's header (a legitimate idle state); once the header arrives, the
    /// body must follow within [`FRAME_BODY_TIMEOUT`].
    pub async fn recv(&mut self) -> Result<DecodedFrame, String> {
        let mut header = [0u8; 16];
        let mut header_mac = [0u8; 16];
        self.read_exact(&mut header).await?;
        self.read_exact(&mut header_mac).await?;
        let body_len = self
            .codec
            .decode_header(&header, &header_mac)
            .map_err(|e| format!("rlpx header: {}", e.0))?;
        let padded = (body_len + 15) & !15;
        let mut enc_body = vec![0u8; padded];
        let mut body_mac = [0u8; 16];
        tokio::time::timeout(FRAME_BODY_TIMEOUT, async {
            self.read_exact(&mut enc_body).await?;
            self.read_exact(&mut body_mac).await
        })
        .await
        .map_err(|_| "rlpx frame body timed out".to_string())??;
        self.codec
            .decode_body(&enc_body, &body_mac, body_len)
            .map_err(|e| format!("rlpx body: {}", e.0))
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.stream
            .read_exact(buf)
            .await
            .map(|_| ())
            .map_err(|e| format!("rlpx read: {e}"))
    }
}

/// The write half of a split [`RlpxConnection`] — owns the egress cipher/MAC.
/// Serialize all sends through `&mut self`.
pub struct RlpxWriter {
    write_half: OwnedWriteHalf,
    encoder: FrameEncoder,
}

impl RlpxWriter {
    /// Frame and send one message (bounded by [`FRAME_WRITE_TIMEOUT`]).
    pub async fn send(&mut self, message_code: u64, body: &[u8]) -> Result<(), String> {
        let frame = self.encoder.encode_frame(message_code, body);
        write_frame(&mut self.write_half, &frame).await
    }
}

/// Write a full frame, bounded by [`FRAME_WRITE_TIMEOUT`]. A timeout leaves the
/// egress stream mid-frame (the codec's MAC has already advanced), so it is a
/// fatal error for the connection — the caller must not reuse the writer.
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, frame: &[u8]) -> Result<(), String> {
    tokio::time::timeout(FRAME_WRITE_TIMEOUT, w.write_all(frame))
        .await
        .map_err(|_| "rlpx write frame timed out".to_string())?
        .map_err(|e| format!("rlpx write frame: {e}"))
}

/// The read half of a split [`RlpxConnection`] — owns the ingress cipher/MAC.
pub struct RlpxReader {
    read_half: OwnedReadHalf,
    decoder: FrameDecoder,
}

impl RlpxReader {
    /// Read and decode the next frame. Blocks indefinitely on the header (a
    /// legitimate idle state); once it arrives the body must follow within
    /// [`FRAME_BODY_TIMEOUT`].
    pub async fn recv(&mut self) -> Result<DecodedFrame, String> {
        let mut header = [0u8; 16];
        let mut header_mac = [0u8; 16];
        self.read_half
            .read_exact(&mut header)
            .await
            .map_err(|e| format!("rlpx read: {e}"))?;
        self.read_half
            .read_exact(&mut header_mac)
            .await
            .map_err(|e| format!("rlpx read: {e}"))?;
        let body_len = self
            .decoder
            .decode_header(&header, &header_mac)
            .map_err(|e| format!("rlpx header: {}", e.0))?;
        let padded = (body_len + 15) & !15;
        let mut enc_body = vec![0u8; padded];
        let mut body_mac = [0u8; 16];
        tokio::time::timeout(FRAME_BODY_TIMEOUT, async {
            self.read_half.read_exact(&mut enc_body).await?;
            self.read_half.read_exact(&mut body_mac).await
        })
        .await
        .map_err(|_| "rlpx frame body timed out".to_string())?
        .map_err(|e| format!("rlpx read: {e}"))?;
        self.decoder
            .decode_body(&enc_body, &body_mac, body_len)
            .map_err(|e| format!("rlpx body: {}", e.0))
    }
}

/// Read one EIP-8 ack: the 2-byte big-endian size prefix names the encrypted
/// body length; the full wire (prefix included) seeds the frame MACs.
async fn read_ack(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut size_prefix = [0u8; 2];
    stream
        .read_exact(&mut size_prefix)
        .await
        .map_err(|e| format!("rlpx read ack size: {e}"))?;
    let body_size = usize::from(u16::from_be_bytes(size_prefix));
    if body_size == 0 || body_size > MAX_ACK_SIZE {
        return Err(format!("rlpx implausible ack size {body_size}"));
    }
    let mut wire = vec![0u8; 2 + body_size];
    wire[..2].copy_from_slice(&size_prefix);
    stream
        .read_exact(&mut wire[2..])
        .await
        .map_err(|e| format!("rlpx read ack body: {e}"))?;
    Ok(wire)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS entropy");
    b
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("OS entropy");
    b
}

/// EIP-8 padding: 100-300 random bytes (a trailing auth-body list element).
fn random_padding() -> Vec<u8> {
    let mut len_byte = [0u8; 1];
    getrandom::getrandom(&mut len_byte).expect("OS entropy");
    let len = 100 + usize::from(len_byte[0]) % 201; // 100..=300, matching the reference
    let mut pad = vec![0u8; len];
    getrandom::getrandom(&mut pad).expect("OS entropy");
    pad
}

/// Build a p2p Hello body: `[protocolVersion, clientId, [[cap,ver]…], listenPort, nodeId]`.
/// Advertises eth/66-69 + snap/1 (ascending), matching the Java `HelloMessage`.
pub fn encode_hello(node_pubkey: &[u8; 64], listen_port: u16) -> Vec<u8> {
    use myotis_core::rlp::{self, Item};
    let cap = |name: &str, ver: u64| {
        Item::List(vec![
            Item::Bytes(name.as_bytes().to_vec()),
            Item::Bytes(rlp::u64_to_minimal_be(ver)),
        ])
    };
    rlp::encode(&Item::List(vec![
        Item::Bytes(rlp::u64_to_minimal_be(5)), // protocol version
        Item::Bytes(b"myotis/0.1.0".to_vec()),
        Item::List(vec![
            cap("eth", 66),
            cap("eth", 67),
            cap("eth", 68),
            cap("eth", 69),
            cap("snap", 1),
        ]),
        Item::Bytes(rlp::u64_to_minimal_be(u64::from(listen_port))),
        Item::Bytes(node_pubkey.to_vec()),
    ]))
}

/// One negotiated capability from a peer's Hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
    pub version: u64,
}

/// A decoded p2p Hello. Full eth capability negotiation is EL-A5; this is
/// enough to confirm FRAMED and read the peer's advertised caps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: u64,
    pub client_id: String,
    pub capabilities: Vec<Capability>,
    pub listen_port: u64,
    pub node_id: Vec<u8>,
}

/// Decode a p2p Hello body.
pub fn decode_hello(body: &[u8]) -> Result<Hello, String> {
    use myotis_core::rlp;
    let top = rlp::decode(body).map_err(|e| format!("hello: {}", e.0))?;
    let items = top.as_list().map_err(|e| format!("hello: {}", e.0))?;
    if items.len() < 5 {
        return Err(format!("hello: expected 5 fields, got {}", items.len()));
    }
    let protocol_version = items[0].as_u64().map_err(|e| e.0)?;
    let client_id = String::from_utf8_lossy(items[1].as_bytes().map_err(|e| e.0)?).into_owned();
    let mut capabilities = Vec::new();
    for c in items[2].as_list().map_err(|e| e.0)? {
        let fields = c.as_list().map_err(|e| e.0)?;
        if fields.len() >= 2 {
            capabilities.push(Capability {
                name: String::from_utf8_lossy(fields[0].as_bytes().map_err(|e| e.0)?).into_owned(),
                version: fields[1].as_u64().map_err(|e| e.0)?,
            });
        }
    }
    let listen_port = items[3].as_u64().map_err(|e| e.0)?;
    let node_id = items[4].as_bytes().map_err(|e| e.0)?.to_vec();
    Ok(Hello {
        protocol_version,
        client_id,
        capabilities,
        listen_port,
        node_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip() {
        let pubkey = [0x11u8; 64];
        let body = encode_hello(&pubkey, 30303);
        let hello = decode_hello(&body).unwrap();
        assert_eq!(hello.protocol_version, 5);
        assert_eq!(hello.client_id, "myotis/0.1.0");
        assert_eq!(hello.listen_port, 30303);
        assert_eq!(hello.node_id, pubkey.to_vec());
        assert_eq!(hello.capabilities.len(), 5);
        assert_eq!(hello.capabilities[3], Capability { name: "eth".into(), version: 69 });
        assert_eq!(hello.capabilities[4], Capability { name: "snap".into(), version: 1 });
    }
}
