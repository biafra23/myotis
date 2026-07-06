//! Eth2 req/resp wire framing — the Rust twin of the Java `ReqRespCodec` (plus the
//! multi-chunk scanner that lives in `BeaconP2PService.decodeMultiChunkResponse` /
//! `skipSnappyFrames`). Byte-for-byte the same wire format:
//!
//! Request:  `unsigned_varint(UNCOMPRESSED ssz len) || snappy_frame_compressed(ssz)`.
//! An empty request encodes as the single byte `0x00` (varint(0), no snappy data)
//! — but note the finality/optimistic protocols send NO bytes at all (the Java
//! `requestFinalityUpdate` passes an empty payload straight to `doReqResp`, which
//! writes nothing and just half-closes); that choice lives in the transport layer
//! ([`crate::reqresp`]), not here.
//!
//! Response chunk: `result_byte || [context_bytes(4, fork digest)] ||
//! varint(uncompressed len) || snappy_frames`. Context bytes are present for the
//! fork-dependent SSZ types (`light_client_*`) and absent for the fixed ones
//! (status/ping/metadata/goodbye) — see [`crate::protocols`].

use std::io::{Read, Write};

/// Result codes per the eth2 req/resp spec.
pub const RESULT_SUCCESS: u8 = 0;
pub const RESULT_INVALID_REQUEST: u8 = 1;
pub const RESULT_SERVER_ERROR: u8 = 2;
pub const RESULT_RESOURCE_UNAVAILABLE: u8 = 3;

#[derive(Debug, PartialEq, Eq)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CodecError {}

fn err<T>(msg: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(msg.into()))
}

// -------------------------------------------------------------------------
// Varint (protobuf-style unsigned) — mirrors ReqRespCodec.writeVarint/readVarint
// -------------------------------------------------------------------------

/// Append a protobuf-style unsigned varint. varint(0) is the single byte 0x00.
pub fn write_varint(out: &mut Vec<u8>, value: u64) {
    let mut v = value;
    loop {
        if v & !0x7F == 0 {
            out.push(v as u8);
            return;
        }
        out.push(((v & 0x7F) | 0x80) as u8);
        v >>= 7;
    }
}

/// Read a varint at `pos`; returns `(value, next_pos)`. Mirrors the Java reader,
/// including the 5-byte (shift >= 35) overflow guard — lengths on this wire fit
/// in an i32 there and the guard is part of the pinned behavior.
pub fn read_varint(data: &[u8], pos: usize) -> Result<(u64, usize), CodecError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut pos = pos;
    while pos < data.len() {
        let b = data[pos];
        pos += 1;
        result |= u64::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((result, pos));
        }
        if shift >= 35 {
            return err(format!("Varint too long (overflow at shift {shift})"));
        }
    }
    err(format!("Truncated varint at position {pos}"))
}

// -------------------------------------------------------------------------
// Snappy framing helpers (the FRAMED format, not raw snappy blocks)
// -------------------------------------------------------------------------

/// Compress with the snappy FRAMING format (stream identifier + frames) —
/// the same format the Java side's iq80 `SnappyFramedOutputStream` writes.
pub fn snappy_compress(input: &[u8]) -> Vec<u8> {
    let mut enc = snap::write::FrameEncoder::new(Vec::new());
    // Writing to a Vec cannot fail.
    enc.write_all(input).expect("Vec write cannot fail");
    enc.into_inner().expect("Vec flush cannot fail")
}

/// eth2 RPC ceiling on any single decompressed payload — the spec's MAX_PAYLOAD_SIZE
/// (10 MiB). Light-client updates are ~27 KB, bootstraps ~25 KB, so this is pure
/// headroom; the point is to reject an attacker's declared length BEFORE allocating.
pub const MAX_UNCOMPRESSED_PAYLOAD: usize = 10 * 1024 * 1024;

/// Decompress a snappy framed stream, BOUNDED by the wire's declared uncompressed
/// length. A malicious peer can otherwise force a multi-hundred-MiB allocation from
/// a 16 MiB frame of max-ratio copy ops (snappy expands up to ~21x) — an OOM vector
/// on mobile, amplified by the catch-up fan-out. The eth2 spec REQUIRES the varint
/// to equal the real uncompressed length, so we cap the reader at `declared` (+1 to
/// detect overrun) and reject any mismatch.
pub fn snappy_decompress(input: &[u8], declared_len: usize) -> Result<Vec<u8>, CodecError> {
    if declared_len == 0 || declared_len > MAX_UNCOMPRESSED_PAYLOAD {
        return Err(CodecError(format!(
            "declared uncompressed length {declared_len} outside (0, {MAX_UNCOMPRESSED_PAYLOAD}]"
        )));
    }
    let mut out = Vec::with_capacity(declared_len);
    // take(declared+1): a well-formed frame yields exactly `declared`; anything
    // longer trips the mismatch check below instead of allocating unbounded.
    snap::read::FrameDecoder::new(input)
        .take(declared_len as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| CodecError(format!("snappy decompress failed: {e}")))?;
    if out.len() != declared_len {
        return Err(CodecError(format!(
            "snappy output {} bytes != declared {declared_len}",
            out.len()
        )));
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// Request framing
// -------------------------------------------------------------------------

/// `varint(uncompressed ssz len) || snappy_frame_compressed(ssz)`.
/// An empty payload returns [`encode_empty_request`] (single 0x00 byte).
pub fn encode_request(ssz_payload: &[u8]) -> Vec<u8> {
    if ssz_payload.is_empty() {
        return encode_empty_request();
    }
    let compressed = snappy_compress(ssz_payload);
    let mut out = Vec::with_capacity(compressed.len() + 5);
    write_varint(&mut out, ssz_payload.len() as u64);
    out.extend_from_slice(&compressed);
    out
}

/// varint(0) = single byte 0x00, no snappy data follows.
pub fn encode_empty_request() -> Vec<u8> {
    vec![0x00]
}

/// Decode an inbound request body: `varint(len) || snappy_frames` → ssz bytes.
/// Mirrors the Java responder's `parseRequestSsz` (None on anything unparseable).
pub fn parse_request_ssz(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 2 {
        return None;
    }
    let (uncompressed_len, snappy_start) = read_varint(raw, 0).ok()?;
    if uncompressed_len == 0 || snappy_start >= raw.len() {
        return None;
    }
    snappy_decompress(&raw[snappy_start..], uncompressed_len as usize).ok()
}

// -------------------------------------------------------------------------
// Single-chunk response decode — mirrors ReqRespCodec.decodeResponse
// -------------------------------------------------------------------------

#[derive(Debug)]
pub struct DecodeResult {
    pub result_code: u8,
    /// 4 bytes when `has_context_bytes`, empty otherwise.
    pub fork_digest: Vec<u8>,
    pub ssz_payload: Vec<u8>,
}

/// Decode a single-chunk response frame. `has_context_bytes` is true for the
/// fork-dependent protocols (`light_client_*`), false for status/ping/metadata/
/// goodbye. A non-zero result code returns `Err` carrying the error type and
/// any trailing UTF-8 message, exactly like the Java decoder throwing.
pub fn decode_response(raw: &[u8], has_context_bytes: bool) -> Result<DecodeResult, CodecError> {
    if raw.is_empty() {
        return err("Response too short: no result byte");
    }
    let mut pos = 0usize;
    let result_code = raw[pos];
    pos += 1;

    if result_code != 0 {
        // Best-effort error message from the remaining bytes (raw UTF-8, like Java).
        let error_msg = if pos + 4 < raw.len() {
            String::from_utf8_lossy(&raw[pos..]).trim().to_string()
        } else {
            String::new()
        };
        let error_type = match result_code {
            1 => "InvalidRequest".to_string(),
            2 => "ServerError".to_string(),
            3 => "ResourceUnavailable".to_string(),
            other => format!("Unknown({other})"),
        };
        return err(if error_msg.is_empty() {
            format!("Peer returned error: {error_type}")
        } else {
            format!("Peer returned error: {error_type} — {error_msg}")
        });
    }

    let fork_digest = if has_context_bytes {
        if raw.len() < pos + 4 {
            return err(format!(
                "Response too short: missing fork digest (need 4 bytes after result, have {})",
                raw.len() - pos
            ));
        }
        let fd = raw[pos..pos + 4].to_vec();
        pos += 4;
        fd
    } else {
        Vec::new()
    };

    let (uncompressed_len, next) = read_varint(raw, pos)?;
    pos = next;

    if uncompressed_len == 0 {
        return Ok(DecodeResult { result_code, fork_digest, ssz_payload: Vec::new() });
    }
    if pos >= raw.len() {
        return err("Response truncated: no compressed data after header");
    }
    let ssz_payload = snappy_decompress(&raw[pos..], uncompressed_len as usize)?;
    Ok(DecodeResult { result_code, fork_digest, ssz_payload })
}

// -------------------------------------------------------------------------
// Multi-chunk response decode (updates_by_range) — mirrors
// BeaconP2PService.decodeMultiChunkResponse + skipSnappyFrames
// -------------------------------------------------------------------------

/// Decode a multi-chunk response: each chunk is
/// `result(1) || fork_digest(4) || varint(uncompressed len) || snappy_frames`.
/// Stops at the first error chunk (logging it) or after `expected_count` items,
/// returning whatever decoded cleanly — the same salvage behavior as the Java.
pub fn decode_multi_chunk_response(
    raw: &[u8],
    expected_count: usize,
) -> Result<Vec<Vec<u8>>, CodecError> {
    let mut items: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() && items.len() < expected_count {
        let result_code = raw[pos];
        if result_code != 0 {
            // Error chunk: <result><varint(len)><snappy(error_msg)>, no fork digest.
            let err_body = decode_error_chunk_message(raw, pos + 1);
            tracing::info!(
                item = items.len(),
                code = result_code,
                raw_len = raw.len(),
                msg = %err_body,
                "multi-chunk response item carries an error code"
            );
            break;
        }
        pos += 1;
        if pos + 4 > raw.len() {
            break;
        }
        pos += 4; // fork digest (per-chunk; the payload's own fork sniffing governs decode)
        let (uncompressed_len, next) = read_varint(raw, pos)?;
        pos = next;
        let uncompressed_len = uncompressed_len as usize;
        if uncompressed_len == 0 {
            tracing::info!(item = items.len(), raw_len = raw.len(),
                "multi-chunk item has uncompressedLength=0");
            items.push(Vec::new());
            continue;
        }
        let snappy_start = pos;
        pos = skip_snappy_frames(raw, pos, uncompressed_len);
        if pos <= snappy_start {
            tracing::info!(item = items.len(), raw_len = raw.len(),
                "multi-chunk skip_snappy_frames returned empty span");
            break;
        }
        let decompressed = snappy_decompress(&raw[snappy_start..pos], uncompressed_len)?;
        if decompressed.is_empty() {
            tracing::info!(
                item = items.len(),
                varint_len = uncompressed_len,
                compressed_len = pos - snappy_start,
                raw_len = raw.len(),
                "multi-chunk snappy decompress returned 0 bytes"
            );
            break;
        }
        items.push(decompressed);
    }
    Ok(items)
}

/// Best-effort decode of an error chunk's message: `varint(len) || snappy(msg)`,
/// falling back to raw UTF-8 when the snappy frame is missing/corrupt.
fn decode_error_chunk_message(raw: &[u8], err_start: usize) -> String {
    if err_start >= raw.len() {
        return String::new();
    }
    if let Ok((declared, msg_start)) = read_varint(raw, err_start) {
        if msg_start < raw.len() {
            // eth2 caps error strings at 256 bytes; use the declared length as the
            // bound but never trust it past that ceiling.
            let cap = (declared as usize).min(256);
            if cap > 0 {
                if let Ok(decompressed) = snappy_decompress(&raw[msg_start..], cap) {
                    return String::from_utf8_lossy(&decompressed).trim().to_string();
                }
            }
            return format!("[raw] {}", String::from_utf8_lossy(&raw[msg_start..]).trim());
        }
    }
    String::new()
}

/// Skip past one complete snappy framed stream, mirroring the Java
/// `skipSnappyFrames`: frame types 0xFF (stream identifier), 0x00 (compressed,
/// CRC32C + snappy block whose leading varint is the decompressed size), 0x01
/// (uncompressed, CRC32C + raw data). Tracks decompressed output so a following
/// chunk's 0x00 result byte isn't mistaken for another compressed frame.
fn skip_snappy_frames(data: &[u8], start: usize, uncompressed_len: usize) -> usize {
    let mut pos = start;
    let mut decompressed_so_far = 0usize;
    while pos < data.len() {
        let chunk_type = data[pos];
        if chunk_type != 0xFF && chunk_type != 0x00 && chunk_type != 0x01 {
            break; // next response chunk's result code
        }
        if pos + 4 > data.len() {
            break;
        }
        let frame_len = data[pos + 1] as usize
            | (data[pos + 2] as usize) << 8
            | (data[pos + 3] as usize) << 16;
        if pos + 4 + frame_len > data.len() {
            // Truncated frame — consume remaining data.
            pos = data.len();
            break;
        }
        if chunk_type == 0x01 && frame_len > 4 {
            decompressed_so_far += frame_len - 4;
        } else if chunk_type == 0x00 && frame_len > 4 {
            let snappy_block_start = pos + 4 + 4; // frame header (4) + CRC32C (4)
            match read_varint(data, snappy_block_start) {
                Ok((block_size, _)) => decompressed_so_far += block_size as usize,
                Err(_) => break, // not a real snappy frame
            }
        }
        // 0xFF stream identifier contributes 0 decompressed bytes.
        pos += 4 + frame_len;
        if decompressed_so_far >= uncompressed_len && uncompressed_len > 0 {
            break;
        }
    }
    pos
}

// -------------------------------------------------------------------------
// Response encoding (responder side) — mirrors ResponderController
// -------------------------------------------------------------------------

/// `0x00 || [fork_digest] || varint(ssz len) || snappy_frames(ssz)`.
pub fn encode_success_response(ssz: &[u8], fork_digest: Option<[u8; 4]>) -> Vec<u8> {
    let compressed = snappy_compress(ssz);
    let mut out = Vec::with_capacity(compressed.len() + 16);
    out.push(RESULT_SUCCESS);
    if let Some(fd) = fork_digest {
        out.extend_from_slice(&fd);
    }
    write_varint(&mut out, ssz.len() as u64);
    out.extend_from_slice(&compressed);
    out
}

/// Error response: `result || varint(msg len) || snappy_frames(msg)` (no fork
/// digest on error responses, per spec — same as the Java `writeError`).
pub fn encode_error_response(result_code: u8, msg: &str) -> Vec<u8> {
    let utf8 = msg.as_bytes();
    let mut out = Vec::with_capacity(utf8.len() + 16);
    out.push(result_code);
    write_varint(&mut out, utf8.len() as u64);
    out.extend_from_slice(&snappy_compress(utf8));
    out
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_zero_is_single_zero_byte() {
        let mut out = Vec::new();
        write_varint(&mut out, 0);
        assert_eq!(out, vec![0x00]);
        assert_eq!(encode_empty_request(), vec![0x00]);
        assert_eq!(read_varint(&[0x00], 0).unwrap(), (0, 1));
    }

    #[test]
    fn varint_round_trip() {
        for v in [0u64, 1, 127, 128, 300, 16384, 25_000, u32::MAX as u64] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let (decoded, next) = read_varint(&out, 0).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(next, out.len());
        }
        // Same fixed encodings the protobuf spec defines.
        let mut out = Vec::new();
        write_varint(&mut out, 300);
        assert_eq!(out, vec![0xAC, 0x02]);
    }

    #[test]
    fn varint_guards_mirror_java() {
        assert!(read_varint(&[0x80], 0).is_err()); // truncated
        assert!(read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01], 0).is_err()); // shift >= 35
    }

    #[test]
    fn request_round_trip() {
        let root = [0x11u8; 32];
        let wire = encode_request(&root);
        // varint(32) = 0x20, then a snappy framed stream starting with the
        // stream identifier ff 06 00 00 73 4e 61 50 70 59 ("sNaPpY").
        assert_eq!(wire[0], 0x20);
        assert_eq!(&wire[1..11], &[0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50, 0x70, 0x59]);
        let parsed = parse_request_ssz(&wire).unwrap();
        assert_eq!(parsed, root);
    }

    /// Golden vectors generated by the JAVA `ReqRespCodec.encodeRequest` (jshell
    /// against the compiled :consensus classes + iq80 snappy 0.4, 2026-07-06):
    ///
    /// ```text
    /// encodeRequest(32 x 0x11)            = 20ff060000734e61507059000a00000eb49f4d2000117a0100
    /// encodeRequest(LE64(1777)||LE64(16)) = 10ff060000734e6150705901140000de50a893f10600000000000010000000 00000000
    /// encodeRequest(bytes 0x00..0x5b)     = 5cff060000734e6150705901600000cf4ded1a<92 raw bytes>
    /// encodeEmptyRequest()                = 00
    /// ```
    ///
    /// Pins that the Rust codec DECODES exactly what the Java encoder emits, and
    /// asserts full byte equality of the Rust encoder against the Java bytes
    /// (both sides implement the reference snappy framing; equality verified to
    /// hold for these inputs — if a future snap version changes its compression
    /// choices, decode-equality is the interop-critical half).
    #[test]
    fn java_golden_request_vectors() {
        // ReqRespCodec.encodeRequest(32 x 0x11): varint(32) || compressed frame.
        let java_root_frame = hex("20ff060000734e61507059000a00000eb49f4d2000117a0100");
        let root = [0x11u8; 32];
        assert_eq!(parse_request_ssz(&java_root_frame).unwrap(), root);
        assert_eq!(encode_request(&root), java_root_frame);

        // updates_by_range request body (startPeriod=1777, count=16): varint(16)
        // || uncompressed frame (16 LE bytes don't compress).
        let java_range_frame =
            hex("10ff060000734e6150705901140000de50a893f1060000000000001000000000000000");
        let mut range_ssz = Vec::new();
        range_ssz.extend_from_slice(&1777u64.to_le_bytes());
        range_ssz.extend_from_slice(&16u64.to_le_bytes());
        assert_eq!(parse_request_ssz(&java_range_frame).unwrap(), range_ssz);
        assert_eq!(encode_request(&range_ssz), java_range_frame);

        // 92-byte status-shaped payload (bytes 0x00..0x5b): varint(92) ||
        // uncompressed frame.
        let mut java_status_frame = hex("5cff060000734e6150705901600000cf4ded1a");
        let status_ssz: Vec<u8> = (0u8..92).collect();
        java_status_frame.extend_from_slice(&status_ssz);
        assert_eq!(parse_request_ssz(&java_status_frame).unwrap(), status_ssz);
        assert_eq!(encode_request(&status_ssz), java_status_frame);

        // Java encodeEmptyRequest() == 0x00 == our encode_empty_request.
        assert_eq!(encode_request(&[]), hex("00"));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn single_response_round_trip_with_context() {
        let ssz = vec![0xABu8; 100];
        let wire = encode_success_response(&ssz, Some([1, 2, 3, 4]));
        let decoded = decode_response(&wire, true).unwrap();
        assert_eq!(decoded.result_code, 0);
        assert_eq!(decoded.fork_digest, vec![1, 2, 3, 4]);
        assert_eq!(decoded.ssz_payload, ssz);
    }

    #[test]
    fn single_response_round_trip_without_context() {
        let ssz = vec![0x42u8; 92];
        let wire = encode_success_response(&ssz, None);
        let decoded = decode_response(&wire, false).unwrap();
        assert_eq!(decoded.fork_digest, Vec::<u8>::new());
        assert_eq!(decoded.ssz_payload, ssz);
    }

    #[test]
    fn error_response_surfaces_type_and_message() {
        let wire = encode_error_response(RESULT_RESOURCE_UNAVAILABLE, "pruned");
        let e = decode_response(&wire, true).unwrap_err();
        assert!(e.0.contains("ResourceUnavailable"), "{e}");
    }

    #[test]
    fn multi_chunk_round_trip() {
        // Three chunks of distinct sizes back to back, as updates_by_range returns.
        let payloads: Vec<Vec<u8>> = vec![vec![0x01; 500], vec![0x02; 25_000], vec![0x03; 7]];
        let mut wire = Vec::new();
        for p in &payloads {
            wire.extend_from_slice(&encode_success_response(p, Some([0xAA, 0xBB, 0xCC, 0xDD])));
        }
        let items = decode_multi_chunk_response(&wire, payloads.len()).unwrap();
        assert_eq!(items, payloads);
    }

    #[test]
    fn multi_chunk_stops_at_error_chunk() {
        let good = vec![0x05u8; 64];
        let mut wire = encode_success_response(&good, Some([0; 4]));
        wire.extend_from_slice(&encode_error_response(RESULT_RESOURCE_UNAVAILABLE, "no more"));
        let items = decode_multi_chunk_response(&wire, 5).unwrap();
        assert_eq!(items, vec![good]);
    }

    #[test]
    fn multi_chunk_respects_expected_count() {
        let p = vec![0x09u8; 32];
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.extend_from_slice(&encode_success_response(&p, Some([0; 4])));
        }
        let items = decode_multi_chunk_response(&wire, 2).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn malformed_inputs_never_panic() {
        assert!(decode_response(&[], true).is_err());
        assert!(decode_response(&[0x00], true).is_err()); // missing digest
        assert!(decode_response(&[0x00, 1, 2, 3, 4], true).is_err()); // truncated varint region
        assert!(decode_response(&[0x00, 1, 2, 3, 4, 0x05], true).is_err()); // no snappy data
        assert!(parse_request_ssz(&[]).is_none());
        assert!(parse_request_ssz(&[0x00]).is_none());
        let _ = decode_multi_chunk_response(&[0x00, 0, 0], 3);
        let _ = decode_multi_chunk_response(&[0xFF; 40], 3);
    }

    #[test]
    fn snappy_decompress_enforces_declared_bound() {
        let payload = vec![0x42u8; 1000];
        let framed = snappy_compress(&payload);
        // Correct declared length round-trips.
        assert_eq!(snappy_decompress(&framed, 1000).unwrap(), payload);
        // A declared length that disagrees with the real output is rejected —
        // this is what stops an attacker's inflated varint from mattering.
        assert!(snappy_decompress(&framed, 999).is_err());
        assert!(snappy_decompress(&framed, 1001).is_err());
        // Over-ceiling declared length is rejected BEFORE any decompression work.
        assert!(snappy_decompress(&framed, MAX_UNCOMPRESSED_PAYLOAD + 1).is_err());
        assert!(snappy_decompress(&framed, 0).is_err());
    }
}
