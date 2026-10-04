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

use alloc::vec::Vec;

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
        decompress_builtin(input)
    }
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

/// Full raw-format decoder. Bounds every read and copy; never panics.
#[cfg_attr(feature = "std", allow(dead_code))]
pub(crate) fn decompress_builtin(input: &[u8]) -> Option<Vec<u8>> {
    let (len, mut pos) = read_varint(input)?;
    let mut out: Vec<u8> = Vec::with_capacity(len);
    while pos < input.len() {
        let tag = input[pos];
        pos += 1;
        match tag & 0x03 {
            0 => {
                let mut l = (tag >> 2) as usize;
                if l >= 60 {
                    let extra = l - 59;
                    let b = input.get(pos..pos + extra)?;
                    l = b.iter().rev().fold(0usize, |a, x| (a << 8) | *x as usize);
                    pos += extra;
                }
                let l = l + 1;
                out.extend_from_slice(input.get(pos..pos + l)?);
                pos += l;
            }
            kind => {
                let (l, off) = match kind {
                    1 => {
                        let b = *input.get(pos)? as usize;
                        pos += 1;
                        (4 + ((tag >> 2) & 0x07) as usize, (((tag >> 5) as usize) << 8) | b)
                    }
                    2 => {
                        let b = input.get(pos..pos + 2)?;
                        pos += 2;
                        (1 + (tag >> 2) as usize, u16::from_le_bytes([b[0], b[1]]) as usize)
                    }
                    _ => {
                        let b = input.get(pos..pos + 4)?;
                        pos += 4;
                        (1 + (tag >> 2) as usize, u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                    }
                };
                if off == 0 || off > out.len() {
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
            assert_eq!(decompress_builtin(&c).as_deref(), Some(&s[..]));
        }
    }

    #[test]
    fn snap_reads_the_literal_encoder() {
        for s in samples() {
            let c = compress_literal(&s);
            assert_eq!(snap::raw::Decoder::new().decompress_vec(&c).unwrap(), s);
            assert_eq!(decompress_builtin(&c).as_deref(), Some(&s[..]));
        }
    }

    #[test]
    fn builtin_decoder_rejects_garbage_without_panicking() {
        for bad in [&[0x05u8, 0x01][..], &[0x0a, 0x09, 0x00][..], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..], &[0x04, 0x0d, 0x05][..]] {
            assert!(decompress_builtin(bad).is_none());
        }
    }
}
