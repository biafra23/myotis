//! Snappy *raw* format (no framing) for RLPx message payloads.
//!
//! With `std` this is the `snap` crate, exactly as `myotis-net` always used
//! it. Without `std` (`snap` needs it) a small built-in codec stands in:
//!
//! - a complete decoder for the raw format (literals and all three copy forms,
//!   overlapping copies included);
//! - an encoder that emits literals only. That is valid Snappy -- every
//!   decoder accepts it -- it just does not compress. RLPx payloads a light
//!   client sends are a few hundred bytes of requests, so the lost ratio is
//!   irrelevant, and no match-finder means nothing to get wrong.

use alloc::{format, string::{String, ToString}, vec::Vec};

/// Compress `input`.
pub fn compress(input: &[u8]) -> Vec<u8> {
    #[cfg(feature = "std")]
    {
        snap::raw::Encoder::new().compress_vec(input).unwrap_or_else(|_| input.to_vec())
    }
    #[cfg(not(feature = "std"))]
    {
        compress_literal(input)
    }
}

/// The decoded length a payload declares, without decoding it.
pub fn decompress_len(input: &[u8]) -> Option<usize> {
    #[cfg(feature = "std")]
    {
        snap::raw::decompress_len(input).ok()
    }
    #[cfg(not(feature = "std"))]
    {
        read_varint(input).map(|(n, _)| n)
    }
}

/// Decompress `input`; `None` if it is not valid raw Snappy.
pub fn decompress(input: &[u8]) -> Option<Vec<u8>> {
    #[cfg(feature = "std")]
    {
        snap::raw::Decoder::new().decompress_vec(input).ok()
    }
    #[cfg(not(feature = "std"))]
    {
        decompress_builtin(input, MAX_RAW_LEN)
    }
}

/// Ceiling for one raw block decoded by the built-in codec. RLPx callers
/// check the declared length against their own (smaller) frame limit first;
/// this keeps the decoder itself from honouring an absurd declaration.
#[cfg_attr(feature = "std", allow(dead_code))]
const MAX_RAW_LEN: usize = 16 * 1024 * 1024;
/// The framing format's own ceiling on one chunk's uncompressed data.
const MAX_CHUNK_DATA: usize = 65_536;

// ---------------------------------------------------------------------------
// Framed format (eth2 req/resp): stream identifier, then chunks of
// type(1) || len(3 LE) || masked CRC32C(4) || data.
// ---------------------------------------------------------------------------

/// Compress with the snappy FRAMING format. Without `std`, data goes out as
/// uncompressed chunks (type 0x01) -- valid framed snappy every reader accepts.
/// Empty input encodes as nothing at all, exactly as `snap`'s encoder does.
pub fn compress_framed(input: &[u8]) -> Vec<u8> {
    #[cfg(feature = "std")]
    {
        use std::io::Write;
        let mut enc = snap::write::FrameEncoder::new(Vec::new());
        enc.write_all(input).expect("Vec write cannot fail");
        enc.into_inner().expect("Vec flush cannot fail")
    }
    #[cfg(not(feature = "std"))]
    {
        compress_framed_builtin(input)
    }
}

/// Decompress a framed stream, producing at most `limit` bytes (the caller
/// passes declared+1 to detect overrun). The error carries the reason.
pub fn decompress_framed(input: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    #[cfg(feature = "std")]
    {
        use std::io::Read;
        let mut out = Vec::with_capacity(limit.min(1 << 20));
        snap::read::FrameDecoder::new(input)
            .take(limit as u64)
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
    #[cfg(not(feature = "std"))]
    {
        decompress_framed_builtin(input, limit)
    }
}

const STREAM_ID: [u8; 10] = [0xff, 0x06, 0x00, 0x00, b's', b'N', b'a', b'P', b'p', b'Y'];

/// CRC-32C (Castagnoli), bitwise. Payloads here are tens of KB, so a table
/// buys nothing worth its 1 KiB.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}
fn masked_crc(data: &[u8]) -> u32 {
    let c = crc32c(data);
    c.rotate_right(15).wrapping_add(0xa282_ead8)
}

#[cfg_attr(feature = "std", allow(dead_code))]
pub(crate) fn compress_framed_builtin(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new(); // as snap's FrameEncoder: no stream identifier either
    }
    let mut out = Vec::with_capacity(input.len() + 10 + 8 * (input.len() / MAX_CHUNK_DATA + 1));
    out.extend_from_slice(&STREAM_ID);
    for chunk in input.chunks(MAX_CHUNK_DATA) {
        let len = chunk.len() + 4;
        out.push(0x01);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
        out.extend_from_slice(&masked_crc(chunk).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Built-in framed decoder, with snap's acceptance rules: the stream must open
/// with the stream identifier, each data chunk carries at most 64 KiB of
/// uncompressed data (so no chunk can declare its way into a large
/// allocation), CRCs must match, reserved unskippable chunk types are errors.
#[cfg_attr(feature = "std", allow(dead_code))]
pub(crate) fn decompress_framed_builtin(input: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(1 << 20));
    let mut pos = 0usize;
    let mut seen_stream_id = false;
    while pos < input.len() && out.len() < limit {
        let hdr = input.get(pos..pos + 4).ok_or("truncated chunk header")?;
        let kind = hdr[0];
        let len = hdr[1] as usize | (hdr[2] as usize) << 8 | (hdr[3] as usize) << 16;
        let end = pos.checked_add(4 + len).ok_or("chunk length overflow")?;
        let body = input.get(pos + 4..end).ok_or("truncated chunk")?;
        pos = end;
        if kind != 0xff && !seen_stream_id {
            return Err(format!("stream does not start with the stream identifier (chunk type {kind:#04x})"));
        }
        match kind {
            0xff => {
                if body != &STREAM_ID[4..] {
                    return Err("bad stream identifier".into());
                }
                seen_stream_id = true;
            }
            0x00 | 0x01 => {
                if body.len() < 4 || body.len() - 4 > MAX_CHUNK_DATA + MAX_CHUNK_DATA / 6 + 32 {
                    return Err(format!("unsupported chunk length {}", body.len()));
                }
                let want = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                let data = if kind == 0x00 {
                    decompress_builtin(&body[4..], MAX_CHUNK_DATA).ok_or("bad compressed chunk")?
                } else {
                    if body.len() - 4 > MAX_CHUNK_DATA {
                        return Err(format!("unsupported chunk length {}", body.len()));
                    }
                    body[4..].to_vec()
                };
                if masked_crc(&data) != want {
                    return Err("chunk CRC mismatch".into());
                }
                out.extend_from_slice(&data);
            }
            0x80..=0xfe => {} // padding / skippable
            _ => return Err(format!("reserved unskippable chunk type {kind:#04x}")),
        }
    }
    out.truncate(limit);
    Ok(out)
}

fn read_varint(b: &[u8]) -> Option<(usize, usize)> {
    let mut v: u64 = 0;
    for (i, byte) in b.iter().enumerate().take(5) {
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return usize::try_from(v).ok().map(|n| (n, i + 1));
        }
    }
    None
}

/// Literal-only encoding: `varint(len)` then literal elements of up to 64 KiB.
#[cfg_attr(feature = "std", allow(dead_code))]
pub(crate) fn compress_literal(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 65536 * 3 + 8);
    let mut n = input.len();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    for chunk in input.chunks(65536) {
        let len1 = chunk.len() - 1;
        if len1 < 60 {
            out.push((len1 as u8) << 2);
        } else if len1 < 256 {
            out.push(60 << 2);
            out.push(len1 as u8);
        } else {
            out.push(61 << 2);
            out.extend_from_slice(&(len1 as u16).to_le_bytes());
        }
        out.extend_from_slice(chunk);
    }
    out
}

/// Full raw-format decoder. Refuses a declared length above `max` before
/// allocating; bounds every read and copy with checked arithmetic; never panics.
#[cfg_attr(feature = "std", allow(dead_code))]
pub(crate) fn decompress_builtin(input: &[u8], max: usize) -> Option<Vec<u8>> {
    let (len, mut pos) = read_varint(input)?;
    if len > max {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while pos < input.len() {
        let tag = input[pos];
        pos += 1;
        match tag & 0x03 {
            0 => {
                let mut l = (tag >> 2) as usize;
                if l >= 60 {
                    let extra = l - 59;
                    let b = input.get(pos..pos.checked_add(extra)?)?;
                    l = b.iter().rev().fold(0usize, |a, x| (a << 8) | *x as usize);
                    pos += extra;
                }
                let l = l.checked_add(1)?;
                let end = pos.checked_add(l)?;
                out.extend_from_slice(input.get(pos..end)?);
                pos = end;
            }
            kind => {
                let (l, off) = match kind {
                    1 => {
                        let b = *input.get(pos)? as usize;
                        pos += 1;
                        (4 + ((tag >> 2) & 0x07) as usize, (((tag >> 5) as usize) << 8) | b)
                    }
                    2 => {
                        let b = input.get(pos..pos.checked_add(2)?)?;
                        pos += 2;
                        (1 + (tag >> 2) as usize, u16::from_le_bytes([b[0], b[1]]) as usize)
                    }
                    _ => {
                        let b = input.get(pos..pos.checked_add(4)?)?;
                        pos += 4;
                        (1 + (tag >> 2) as usize, u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                    }
                };
                if off == 0 || off > out.len() {
                    return None;
                }
                if out.len().checked_add(l)? > len {
                    return None;
                }
                let start = out.len() - off;
                for i in 0..l {
                    let b = out[start + i];
                    out.push(b);
                }
            }
        }
        if out.len() > len {
            return None;
        }
    }
    (out.len() == len).then_some(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn samples() -> Vec<Vec<u8>> {
        let mut v = vec![Vec::new(), b"a".to_vec(), vec![0u8; 100_000], (0..=255u8).collect()];
        let mut x = 7u32;
        let mut rnd = Vec::new();
        for _ in 0..70_000 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            rnd.push((x >> 16) as u8 & 0x0f);
        }
        v.push(rnd);
        v.push(b"abcabcabcabcabcabcabcabcabcabc hello hello hello".repeat(500));
        v
    }

    #[test]
    fn builtin_decoder_reads_what_snap_writes() {
        for s in samples() {
            let c = snap::raw::Encoder::new().compress_vec(&s).unwrap();
            assert_eq!(decompress_builtin(&c, usize::MAX).as_deref(), Some(&s[..]));
        }
    }

    #[test]
    fn snap_reads_the_literal_encoder() {
        for s in samples() {
            let c = compress_literal(&s);
            assert_eq!(snap::raw::Decoder::new().decompress_vec(&c).unwrap(), s);
            assert_eq!(decompress_builtin(&c, usize::MAX).as_deref(), Some(&s[..]));
        }
    }

    #[test]
    fn framed_builtin_and_snap_agree_both_ways() {
        use std::io::{Read, Write};
        for s in samples() {
            let mut enc = snap::write::FrameEncoder::new(Vec::new());
            enc.write_all(&s).unwrap();
            let c = enc.into_inner().unwrap();
            assert_eq!(decompress_framed_builtin(&c, s.len() + 1).as_deref(), Ok(&s[..]));
            let b = compress_framed_builtin(&s);
            let mut out = Vec::new();
            snap::read::FrameDecoder::new(&b[..]).read_to_end(&mut out).unwrap();
            assert_eq!(out, s);
        }
    }

    #[test]
    fn framed_builtin_rejects_a_bad_crc() {
        let mut b = compress_framed_builtin(b"hello world");
        let n = b.len();
        b[n - 1] ^= 1;
        assert!(decompress_framed_builtin(&b, 100).is_err());
    }

    #[test]
    fn framed_builtin_matches_snap_on_empty_input() {
        use std::io::Write;
        let mut enc = snap::write::FrameEncoder::new(Vec::new());
        enc.write_all(&[]).unwrap();
        assert_eq!(compress_framed_builtin(&[]), enc.into_inner().unwrap());
        assert!(compress_framed_builtin(&[]).is_empty());
    }

    #[test]
    fn framed_builtin_requires_the_stream_identifier_like_snap() {
        let data = b"hi";
        let mut no_id = vec![0x01u8, 6, 0, 0];
        no_id.extend_from_slice(&masked_crc(data).to_le_bytes());
        no_id.extend_from_slice(data);
        assert!(decompress_framed_builtin(&no_id, 100).is_err());
        let mut out = Vec::new();
        use std::io::Read;
        assert!(snap::read::FrameDecoder::new(&no_id[..]).read_to_end(&mut out).is_err());
    }

    #[test]
    fn framed_builtin_refuses_a_chunk_declaring_a_huge_length() {
        // A compressed chunk whose raw varint declares ~4 GiB: refused before
        // any allocation, as snap refuses chunks over 64 KiB.
        let raw = [0xff, 0xff, 0xff, 0xff, 0x0f, 0x00];
        let mut s = STREAM_ID.to_vec();
        s.push(0x00);
        s.extend_from_slice(&((raw.len() + 4) as u32).to_le_bytes()[..3]);
        s.extend_from_slice(&[0, 0, 0, 0]);
        s.extend_from_slice(&raw);
        assert!(decompress_framed_builtin(&s, 101).is_err());
    }

    #[test]
    fn raw_builtin_never_overflows_on_absurd_literal_lengths() {
        // tag 0xfc: literal with a 4-byte length = u32::MAX.
        let bad = [0x05u8, 0xfc, 0xff, 0xff, 0xff, 0xff, 0x00];
        assert!(decompress_builtin(&bad, usize::MAX).is_none());
    }

    #[test]
    fn builtin_decoder_rejects_garbage_without_panicking() {
        for bad in [&[0x05u8, 0x01][..], &[0x0a, 0x09, 0x00][..], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..], &[0x04, 0x0d, 0x05][..]] {
            assert!(decompress_builtin(bad, usize::MAX).is_none());
        }
    }
}
