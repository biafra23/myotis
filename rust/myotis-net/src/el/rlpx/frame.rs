//! RLPx framed channel (EL-A4), twin of the Java `rlpx.FrameCodec`
//! (docs/reimplementation/02 §5.3, §9.5-6).
//!
//! Frame: `header(16) ‖ header-mac(16) ‖ body(padded to 16) ‖ body-mac(16)`.
//! Header (16, encrypted): `body-size(3 BE) ‖ 0xc0 (RLP empty list) ‖ zeros`.
//!
//! Two AES-256-CTR ciphers (egress encrypt / ingress decrypt), both keyed with
//! `aesSecret`, **zero IV, one continuous keystream per direction**. The MAC is
//! a streaming Keccak-256 chain per direction seeded from the handshake, with a
//! separate AES-256-ECB cipher keyed `macSecret`:
//! ```text
//! egress-mac:  keccak.update(macSecret XOR respNonce); keccak.update(authWire)   [initiator]
//! ingress-mac: keccak.update(macSecret XOR initNonce); keccak.update(ackWire)
//! updateMac(seed16): aesbuf = AES256-ECB(digest[:16]) XOR seed[:16];
//!                    keccak.update(aesbuf); return keccak.digest[:16]
//! ```
//! Payloads are Snappy-compressed EXCEPT Hello (code 0x00), with a raw fallback
//! on decode (some peers send Disconnect/Ping/Pong uncompressed).

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;

use myotis_core::rlp;
use myotis_core::CoreError;

use super::handshake::SessionSecrets;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// 10 MiB frame-body cap (Java `MAX_FRAME_BODY_SIZE`).
pub const MAX_FRAME_BODY_SIZE: usize = 10 * 1024 * 1024;

/// A decoded frame: the p2p/eth message code and its (decompressed) payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub message_code: u64,
    pub payload: Vec<u8>,
}

/// The EGRESS half of the frame codec (outbound): AES-256-CTR keystream +
/// keccak MAC chain. Independent of the ingress half, so the two can live on
/// separate tokio tasks / socket halves (the managed-peer read/write split).
pub struct FrameEncoder {
    encrypt: Aes256Ctr,
    egress_mac: KeccakMac,
}

/// The INGRESS half (inbound): AES-256-CTR + keccak MAC chain.
pub struct FrameDecoder {
    decrypt: Aes256Ctr,
    ingress_mac: KeccakMac,
}

/// Stateful RLPx frame codec — NOT thread-safe (the ciphers and MAC chains are
/// position-dependent; all sends/receives must be serialized, as on the Java
/// side). Composes the two independent halves; [`FrameCodec::split`] hands them
/// out for the managed-peer read/write tasks.
pub struct FrameCodec {
    encoder: FrameEncoder,
    decoder: FrameDecoder,
}

impl FrameCodec {
    /// Initiator-side codec. (For the responder, pass a `SessionSecrets` with
    /// nonce and auth/ack-wire roles swapped — see the handshake tests.)
    pub fn new(secrets: &SessionSecrets) -> FrameCodec {
        let zero_iv = [0u8; 16];
        // egress:  keccak(macSecret XOR ingressNonce ‖ authWire)  [initiator]
        // ingress: keccak(macSecret XOR egressNonce  ‖ ackWire)
        let egress_seed = xor(&secrets.mac_secret, &secrets.ingress_nonce);
        let ingress_seed = xor(&secrets.mac_secret, &secrets.egress_nonce);
        FrameCodec {
            encoder: FrameEncoder {
                encrypt: Aes256Ctr::new((&secrets.aes_secret).into(), (&zero_iv).into()),
                egress_mac: KeccakMac::new(&egress_seed, &secrets.mac_secret, &secrets.auth_wire),
            },
            decoder: FrameDecoder {
                decrypt: Aes256Ctr::new((&secrets.aes_secret).into(), (&zero_iv).into()),
                ingress_mac: KeccakMac::new(&ingress_seed, &secrets.mac_secret, &secrets.ack_wire),
            },
        }
    }

    /// Split into the independent egress/ingress halves for the managed peer's
    /// separate read and write tasks.
    pub fn split(self) -> (FrameEncoder, FrameDecoder) {
        (self.encoder, self.decoder)
    }

    /// Encode one message into a full frame (delegates to the egress half).
    pub fn encode_frame(&mut self, message_code: u64, body: &[u8]) -> Vec<u8> {
        self.encoder.encode_frame(message_code, body)
    }

    /// Verify + decrypt a 16-byte encrypted header (delegates to the ingress half).
    pub fn decode_header(&mut self, enc_header: &[u8], header_mac: &[u8]) -> Result<usize, CoreError> {
        self.decoder.decode_header(enc_header, header_mac)
    }

    /// Verify + decrypt a frame body (delegates to the ingress half).
    pub fn decode_body(
        &mut self,
        enc_body: &[u8],
        body_mac: &[u8],
        body_len: usize,
    ) -> Result<DecodedFrame, CoreError> {
        self.decoder.decode_body(enc_body, body_mac, body_len)
    }
}

impl FrameEncoder {
    /// Encode one message into a full frame (header ‖ header-mac ‖ body ‖ body-mac).
    pub fn encode_frame(&mut self, message_code: u64, body: &[u8]) -> Vec<u8> {
        // Snappy-compress everything except Hello.
        let payload = if message_code == 0 {
            body.to_vec()
        } else {
            snap::raw::Encoder::new()
                .compress_vec(body)
                .unwrap_or_else(|_| body.to_vec())
        };

        let rlp_code = rlp::encode_u64(message_code); // canonical RLP int
        let mut coded_body = Vec::with_capacity(rlp_code.len() + payload.len());
        coded_body.extend_from_slice(&rlp_code);
        coded_body.extend_from_slice(&payload);

        let body_len = coded_body.len();
        let padded_len = (body_len + 15) & !15;
        coded_body.resize(padded_len, 0);

        // Header: body-size(3 BE) ‖ 0xc0 ‖ zeros.
        let mut header = [0u8; 16];
        header[0] = (body_len >> 16) as u8;
        header[1] = (body_len >> 8) as u8;
        header[2] = body_len as u8;
        header[3] = 0xc0;
        self.encrypt.apply_keystream(&mut header);
        let header_mac = self.egress_mac.update_header(&header);

        self.encrypt.apply_keystream(&mut coded_body);
        let body_mac = self.egress_mac.update_body(&coded_body);

        let mut frame = Vec::with_capacity(32 + padded_len + 16);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&header_mac);
        frame.extend_from_slice(&coded_body);
        frame.extend_from_slice(&body_mac);
        frame
    }
}

impl FrameDecoder {
    /// Verify + decrypt a 16-byte encrypted header, returning the body length.
    pub fn decode_header(&mut self, enc_header: &[u8], header_mac: &[u8]) -> Result<usize, CoreError> {
        if enc_header.len() != 16 || header_mac.len() != 16 {
            return Err(CoreError("RLPx: bad header sizes".into()));
        }
        let expected = self.ingress_mac.update_header(enc_header);
        if !bool::from(header_mac.ct_eq(&expected)) {
            return Err(CoreError("RLPx: header MAC mismatch".into()));
        }
        let mut header = [0u8; 16];
        header.copy_from_slice(enc_header);
        self.decrypt.apply_keystream(&mut header);
        let body_len =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        if body_len > MAX_FRAME_BODY_SIZE {
            return Err(CoreError(format!(
                "RLPx: frame body size {body_len} exceeds maximum"
            )));
        }
        Ok(body_len)
    }

    /// Verify + decrypt a frame body (already padded to 16). `body_len` is the
    /// unpadded length from [`decode_header`].
    pub fn decode_body(
        &mut self,
        enc_body: &[u8],
        body_mac: &[u8],
        body_len: usize,
    ) -> Result<DecodedFrame, CoreError> {
        if body_mac.len() != 16 || enc_body.len() % 16 != 0 || body_len > enc_body.len() {
            return Err(CoreError("RLPx: bad body framing".into()));
        }
        let expected = self.ingress_mac.update_body(enc_body);
        if !bool::from(body_mac.ct_eq(&expected)) {
            return Err(CoreError("RLPx: body MAC mismatch".into()));
        }
        let mut body = enc_body.to_vec();
        self.decrypt.apply_keystream(&mut body);

        // Strip the RLP msg-id.
        let (code, offset) = decode_msg_id(&body)?;
        if offset > body_len {
            return Err(CoreError("RLPx: msg-id overruns body".into()));
        }
        let raw = &body[offset..body_len];
        // Snappy-decompress except Hello; raw fallback for uncompressed control
        // msgs. Bound the DECOMPRESSED length first: snappy's header carries a
        // decoded-length varint an attacker can inflate to ~4 GiB from a tiny
        // frame, and `decompress_vec` allocates that up front — under
        // panic="abort" a failed giant allocation kills the process. Cap it at
        // the same 10 MiB ceiling as the compressed frame.
        let decompressable = code != 0
            && !raw.is_empty()
            && snap::raw::decompress_len(raw).map_or(false, |n| n <= MAX_FRAME_BODY_SIZE);
        let payload = if decompressable {
            snap::raw::Decoder::new()
                .decompress_vec(raw)
                .unwrap_or_else(|_| raw.to_vec())
        } else {
            raw.to_vec()
        };
        Ok(DecodedFrame {
            message_code: code,
            payload,
        })
    }
}

/// Decode the RLP-encoded message id at the front of a decrypted body.
fn decode_msg_id(body: &[u8]) -> Result<(u64, usize), CoreError> {
    let first = *body.first().ok_or_else(|| CoreError("RLPx: empty body".into()))?;
    match first {
        0x00..=0x7f => Ok((u64::from(first), 1)),
        0x80 => Ok((0, 1)), // canonical RLP zero
        0x81..=0x88 => {
            let len = usize::from(first - 0x80);
            if 1 + len > body.len() {
                return Err(CoreError("RLPx: truncated msg-id".into()));
            }
            let mut code = 0u64;
            for &b in &body[1..1 + len] {
                code = (code << 8) | u64::from(b);
            }
            Ok((code, 1 + len))
        }
        _ => Err(CoreError("RLPx: unsupported msg-id encoding".into())),
    }
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Streaming Keccak-256 MAC chain (go-eth compatible). The AES here is a
/// SEPARATE AES-256-ECB cipher keyed with `macSecret`; the keccak digest is
/// read non-destructively (RustCrypto `Keccak256` is `Clone`).
struct KeccakMac {
    keccak: Keccak256,
    aes: Aes256,
}

impl KeccakMac {
    fn new(seed: &[u8; 32], mac_secret: &[u8; 32], handshake_wire: &[u8]) -> KeccakMac {
        let mut keccak = Keccak256::new();
        keccak.update(seed);
        keccak.update(handshake_wire);
        KeccakMac {
            keccak,
            aes: Aes256::new(mac_secret.into()),
        }
    }

    /// Header MAC step: `updateMac(encHeader)`.
    fn update_header(&mut self, enc_header: &[u8]) -> [u8; 16] {
        self.update_mac(enc_header)
    }

    /// Body MAC step: feed the encrypted body, then `updateMac(digest[:16])`.
    fn update_body(&mut self, enc_body: &[u8]) -> [u8; 16] {
        self.keccak.update(enc_body);
        let seed = self.current_digest_16();
        self.update_mac(&seed)
    }

    /// `aesbuf = AES256-ECB(digest[:16]) XOR seed[:16]; keccak.update(aesbuf);
    /// return keccak.digest[:16]`.
    fn update_mac(&mut self, seed16: &[u8]) -> [u8; 16] {
        let digest = self.current_digest_16();
        let mut block = digest;
        self.aes.encrypt_block((&mut block).into());
        for i in 0..16 {
            block[i] ^= seed16[i];
        }
        self.keccak.update(block);
        self.current_digest_16()
    }

    /// First 16 bytes of the current keccak digest, non-destructively.
    fn current_digest_16(&self) -> [u8; 16] {
        let full = self.keccak.clone().finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use myotis_core::keccak::keccak256;

    fn pair() -> (FrameCodec, FrameCodec) {
        // Fixed channel material; auth/ack "wire" are opaque MAC seeds here.
        let aes_secret = keccak256(b"frame:aes");
        let mac_secret = keccak256(b"frame:mac");
        let a_nonce = keccak256(b"frame:A-nonce");
        let b_nonce = keccak256(b"frame:B-nonce");
        let auth_wire = b"AUTH-wire-bytes-opaque".to_vec();
        let ack_wire = b"ACK-wire-bytes-opaque".to_vec();
        let initiator = SessionSecrets {
            aes_secret,
            mac_secret,
            egress_nonce: a_nonce,
            ingress_nonce: b_nonce,
            auth_wire: auth_wire.clone(),
            ack_wire: ack_wire.clone(),
        };
        // Responder: swap nonce + wire roles.
        let responder = SessionSecrets {
            aes_secret,
            mac_secret,
            egress_nonce: b_nonce,
            ingress_nonce: a_nonce,
            auth_wire: ack_wire,
            ack_wire: auth_wire,
        };
        (FrameCodec::new(&initiator), FrameCodec::new(&responder))
    }

    fn split(frame: &[u8]) -> (&[u8], &[u8], &[u8], &[u8]) {
        let body_end = frame.len() - 16;
        (
            &frame[..16],
            &frame[16..32],
            &frame[32..body_end],
            &frame[body_end..],
        )
    }

    #[test]
    fn hello_frame_round_trip_uncompressed() {
        let (mut a, mut b) = pair();
        let frame = a.encode_frame(0x00, &[0xc0]); // Hello, RLP empty list
        let (h, hm, bod, bm) = split(&frame);
        let len = b.decode_header(h, hm).unwrap();
        let decoded = b.decode_body(bod, bm, len).unwrap();
        assert_eq!(decoded.message_code, 0);
        assert_eq!(decoded.payload, vec![0xc0]);
    }

    #[test]
    fn compressed_message_round_trip_and_chain() {
        let (mut a, mut b) = pair();
        // Two frames in a row exercise the continuous keystream + MAC chain.
        let payload1 = vec![0x42u8; 300];
        let f1 = a.encode_frame(0x10, &payload1);
        let payload2 = b"second".to_vec();
        let f2 = a.encode_frame(0x11, &payload2);

        for (frame, code, want) in [(f1, 0x10u64, payload1), (f2, 0x11, payload2)] {
            let (h, hm, bod, bm) = split(&frame);
            let len = b.decode_header(h, hm).unwrap();
            let decoded = b.decode_body(bod, bm, len).unwrap();
            assert_eq!(decoded.message_code, code);
            assert_eq!(decoded.payload, want);
        }
    }

    #[test]
    fn oversized_snappy_declared_length_does_not_allocate_in_decode_body() {
        // Drive a HOSTILE payload — a snappy header declaring ~4 GiB decoded
        // length from 6 bytes — all the way through decode_body. It must not
        // try to allocate 4 GiB (panic="abort" would kill the process); it
        // falls back to the raw bytes, which the upper RLP layer then rejects.
        // bomb = varint(0xFFFFFFFF) ‖ 0x00 — a well-formed snappy header.
        let bomb = vec![0xffu8, 0xff, 0xff, 0xff, 0x0f, 0x00];
        assert!(snap::raw::decompress_len(&bomb).map_or(false, |n| n > MAX_FRAME_BODY_SIZE));

        // Frame it by hand so the payload region is EXACTLY the bomb (encode_frame
        // would re-compress it). The initiator MACs it; the responder decodes.
        let (mut a, mut b) = pair();
        let mut coded = rlp::encode_u64(0x10); // non-Hello code → decompress path
        coded.extend_from_slice(&bomb);
        let body_len = coded.len();
        coded.resize((body_len + 15) & !15, 0);

        let mut header = [0u8; 16];
        header[0] = (body_len >> 16) as u8;
        header[1] = (body_len >> 8) as u8;
        header[2] = body_len as u8;
        header[3] = 0xc0;
        a.encoder.encrypt.apply_keystream(&mut header);
        let header_mac = a.encoder.egress_mac.update_header(&header);
        a.encoder.encrypt.apply_keystream(&mut coded);
        let body_mac = a.encoder.egress_mac.update_body(&coded);

        let len = b.decode_header(&header, &header_mac).unwrap();
        // The key assertion: this returns (raw fallback) rather than aborting.
        let decoded = b.decode_body(&coded, &body_mac, len).unwrap();
        assert_eq!(decoded.message_code, 0x10);
        assert_eq!(decoded.payload, bomb); // raw fallback, not a 4 GiB allocation
    }

    #[test]
    fn tampered_mac_is_rejected() {
        let (mut a, mut b) = pair();
        let mut frame = a.encode_frame(0x00, &[0xc0]);
        frame[20] ^= 0x01; // corrupt the header MAC
        let (h, hm, _, _) = split(&frame);
        assert!(b.decode_header(h, hm).is_err());
    }
}
