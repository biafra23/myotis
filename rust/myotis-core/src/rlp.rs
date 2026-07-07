//! RLP (Recursive Length Prefix) — hand-rolled, mirroring how the Java side
//! uses Tuweni `RLP` (docs/reimplementation/02 §1, §6).
//!
//! Decided here per plan EL-A1: hand codec, not `alloy-rlp`. The EL wire
//! layer needs (a) tolerant list-remainder decoding (headers grow trailing
//! fields per fork, unknown ones must be skippable), (b) the raw input kept
//! for `keccak256(rlp)` hashing, and (c) owned item trees for message
//! dispatch — a ~250-line codec fits those exactly, keeps the dependency
//! set flat, and is pinned by the cross-language corpus like the hand-rolled
//! SSZ in `myotis-consensus`.
//!
//! Decoding is strict about STRUCTURE (minimal length prefixes, exact
//! consumption, bounded depth) — the same inputs Tuweni rejects, we reject.
//! Interpretation of scalar VALUES (e.g. `as_u64`) is strict about leading
//! zeros, matching Tuweni's canonical-int readers.

use crate::{err, CoreError};

/// Decoded RLP item: a byte string or a list. Owned — decode copies out of
/// the input buffer (EL messages are small; headers ~600 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

/// Recursion guard for untrusted input. Real EL payloads nest ≤ 5 deep
/// (ENR `eth` field: list-in-list-in-record); 32 leaves huge headroom while
/// keeping a hostile deep-nest packet from touching the real stack limit.
const MAX_DEPTH: usize = 32;

impl Item {
    /// Byte-string payload, or an error for a list.
    pub fn as_bytes(&self) -> Result<&[u8], CoreError> {
        match self {
            Item::Bytes(b) => Ok(b),
            Item::List(_) => err("RLP: expected bytes, found list"),
        }
    }

    /// List elements, or an error for a byte string.
    pub fn as_list(&self) -> Result<&[Item], CoreError> {
        match self {
            Item::List(items) => Ok(items),
            Item::Bytes(_) => err("RLP: expected list, found bytes"),
        }
    }

    /// Byte string of exactly `n` bytes (Tuweni `Bytes32.wrap` semantics:
    /// wrong size is an error, not a truncation).
    pub fn as_fixed_bytes(&self, n: usize) -> Result<&[u8], CoreError> {
        let b = self.as_bytes()?;
        if b.len() != n {
            return err(format!("RLP: expected {n}-byte value, got {} bytes", b.len()));
        }
        Ok(b)
    }

    /// Canonical unsigned integer ≤ 8 bytes, big-endian, no leading zeros
    /// (Tuweni `readLong` semantics).
    pub fn as_u64(&self) -> Result<u64, CoreError> {
        let b = self.as_bytes()?;
        if b.len() > 8 {
            return err(format!("RLP: integer too large ({} bytes)", b.len()));
        }
        if !b.is_empty() && b[0] == 0 {
            return err("RLP: integer has leading zero byte");
        }
        let mut v: u64 = 0;
        for &x in b {
            v = (v << 8) | u64::from(x);
        }
        Ok(v)
    }

    /// Like [`Item::as_u64`], additionally capped to `i64::MAX`. Java-parity
    /// guard: the twins read these fields with Tuweni's SIGNED `readLong`,
    /// where an 8-byte high-bit scalar would go negative (and 2^64-1 would
    /// collide with the -1 "absent" sentinel for the EIP-4844 pair). Both
    /// sides now reject the signed-overflow range — no real chain value
    /// (block number, gas, timestamp, ENR seq) comes near 2^63.
    pub fn as_u64_fitting_long(&self) -> Result<u64, CoreError> {
        let v = self.as_u64()?;
        if v > i64::MAX as u64 {
            return err(format!("RLP: integer {v} exceeds signed-64 range"));
        }
        Ok(v)
    }

    pub fn is_list(&self) -> bool {
        matches!(self, Item::List(_))
    }
}

/// Decode exactly one RLP item consuming the whole input (trailing garbage is
/// an error — wire messages are framed, so slack bytes mean corruption).
pub fn decode(data: &[u8]) -> Result<Item, CoreError> {
    let (item, used) = decode_at(data, 0)?;
    if used != data.len() {
        return err(format!(
            "RLP: {} trailing bytes after top-level item",
            data.len() - used
        ));
    }
    Ok(item)
}

/// Decode one item starting at `pos`; returns `(item, end_pos)`. Used by wire
/// layers that read a prefix (e.g. the framed msg-id byte before a payload).
pub fn decode_at(data: &[u8], pos: usize) -> Result<(Item, usize), CoreError> {
    decode_item(data, pos, 0)
}

fn decode_item(data: &[u8], pos: usize, depth: usize) -> Result<(Item, usize), CoreError> {
    if depth > MAX_DEPTH {
        return err("RLP: nesting too deep");
    }
    let first = match data.get(pos) {
        Some(&b) => b,
        None => return err("RLP: truncated (empty input)"),
    };
    match first {
        // Single byte, value 0x00..=0x7f: the byte is its own encoding.
        0x00..=0x7f => Ok((Item::Bytes(vec![first]), pos + 1)),
        // Short string: 0-55 bytes.
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let payload = slice(data, pos + 1, len)?;
            if len == 1 && payload[0] < 0x80 {
                return err("RLP: non-canonical single byte (should be encoded as itself)");
            }
            Ok((Item::Bytes(payload.to_vec()), pos + 1 + len))
        }
        // Long string: length-of-length 1-8.
        0xb8..=0xbf => {
            let (len, header) = read_long_length(data, pos, first - 0xb7)?;
            let payload = slice(data, pos + header, len)?;
            Ok((Item::Bytes(payload.to_vec()), pos + header + len))
        }
        // Short list: total payload 0-55 bytes.
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            decode_list_payload(data, pos + 1, len, depth)
        }
        // Long list.
        0xf8..=0xff => {
            let (len, header) = read_long_length(data, pos, first - 0xf7)?;
            decode_list_payload(data, pos + header, len, depth)
        }
    }
}

/// Long-form length: 1-8 big-endian bytes, canonical (no leading zero, and the
/// value must not have fit the short form). Returns `(payload_len, header_len)`.
fn read_long_length(data: &[u8], pos: usize, len_of_len: u8) -> Result<(usize, usize), CoreError> {
    let n = len_of_len as usize;
    let len_bytes = slice(data, pos + 1, n)?;
    if len_bytes[0] == 0 {
        return err("RLP: length has leading zero byte");
    }
    // Accumulate in u64 so a hostile 8-byte length can't overflow usize on
    // 32-bit targets before the bounds check below.
    let mut len: u64 = 0;
    for &b in len_bytes {
        len = (len << 8) | u64::from(b);
    }
    if len <= 55 {
        return err("RLP: non-canonical long-form length <= 55");
    }
    if len > data.len() as u64 {
        return err("RLP: truncated (declared length exceeds input)");
    }
    Ok((len as usize, 1 + n))
}

fn decode_list_payload(
    data: &[u8],
    start: usize,
    len: usize,
    depth: usize,
) -> Result<(Item, usize), CoreError> {
    let end = match start.checked_add(len) {
        Some(e) if e <= data.len() => e,
        _ => return err("RLP: truncated list payload"),
    };
    let mut items = Vec::new();
    let mut pos = start;
    while pos < end {
        let (item, next) = decode_item(data, pos, depth + 1)?;
        if next > end {
            return err("RLP: list element overruns list payload");
        }
        items.push(item);
        pos = next;
    }
    Ok((Item::List(items), end))
}

fn slice(data: &[u8], start: usize, len: usize) -> Result<&[u8], CoreError> {
    match start.checked_add(len) {
        Some(end) if end <= data.len() => Ok(&data[start..end]),
        _ => err("RLP: truncated"),
    }
}

// ---------------------------------------------------------------------------
// Encoding (canonical by construction).
// ---------------------------------------------------------------------------

/// Encode a byte string.
pub fn encode_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    write_bytes(&mut out, payload);
    out
}

/// Encode a list from already-encoded element bytes (concatenated).
pub fn encode_list_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    write_header(&mut out, 0xc0, payload.len());
    out.extend_from_slice(payload);
    out
}

/// Encode an [`Item`] tree canonically.
pub fn encode(item: &Item) -> Vec<u8> {
    match item {
        Item::Bytes(b) => encode_bytes(b),
        Item::List(items) => {
            let mut payload = Vec::new();
            for it in items {
                payload.extend_from_slice(&encode(it));
            }
            encode_list_payload(&payload)
        }
    }
}

/// Canonical scalar: minimal big-endian, zero encodes as the empty string.
pub fn encode_u64(value: u64) -> Vec<u8> {
    encode_bytes(&u64_to_minimal_be(value))
}

/// Minimal big-endian bytes of a u64 (empty for zero) — the RLP scalar form.
pub fn u64_to_minimal_be(value: u64) -> Vec<u8> {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    be[skip..].to_vec()
}

fn write_bytes(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.len() == 1 && payload[0] < 0x80 {
        out.push(payload[0]);
    } else {
        write_header(out, 0x80, payload.len());
        out.extend_from_slice(payload);
    }
}

fn write_header(out: &mut Vec<u8>, base: u8, len: usize) {
    if len <= 55 {
        out.push(base + len as u8);
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(base + 55 + (8 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples_round_trip() {
        // The canonical examples from the RLP spec.
        let cases: Vec<(Item, Vec<u8>)> = vec![
            (Item::Bytes(b"dog".to_vec()), vec![0x83, b'd', b'o', b'g']),
            (Item::Bytes(vec![]), vec![0x80]),
            (Item::Bytes(vec![0x0f]), vec![0x0f]),
            (Item::Bytes(vec![0x04, 0x00]), vec![0x82, 0x04, 0x00]),
            (Item::List(vec![]), vec![0xc0]),
            (
                Item::List(vec![
                    Item::Bytes(b"cat".to_vec()),
                    Item::Bytes(b"dog".to_vec()),
                ]),
                vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'],
            ),
        ];
        for (item, wire) in cases {
            assert_eq!(encode(&item), wire);
            assert_eq!(decode(&wire).unwrap(), item);
        }
    }

    #[test]
    fn long_string_round_trip() {
        let payload = vec![0xabu8; 300];
        let wire = encode_bytes(&payload);
        assert_eq!(wire[0], 0xb9); // long form, 2 length bytes
        assert_eq!(decode(&wire).unwrap(), Item::Bytes(payload));
    }

    #[test]
    fn rejects_malformed() {
        // Truncated payloads, non-canonical forms, trailing bytes, deep nesting.
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x83, b'd', b'o']).is_err()); // truncated short string
        assert!(decode(&[0x81, 0x05]).is_err()); // non-canonical single byte
        assert!(decode(&[0xb8, 0x01, 0xff]).is_err()); // long form for len 1
        assert!(decode(&[0xb9, 0x00, 0x38]).is_err()); // leading-zero length
        assert!(decode(&[0x80, 0x00]).is_err()); // trailing byte
        assert!(decode(&[0xc2, 0x83, b'a']).is_err()); // element overruns list
        let mut deep = vec![0xc1u8; 40];
        deep.push(0xc0);
        assert!(decode(&deep).is_err()); // nesting past MAX_DEPTH
    }

    #[test]
    fn u64_semantics() {
        assert_eq!(decode(&encode_u64(0)).unwrap().as_u64().unwrap(), 0);
        assert_eq!(
            decode(&encode_u64(u64::MAX)).unwrap().as_u64().unwrap(),
            u64::MAX
        );
        // Leading zero rejected, 9-byte integer rejected.
        assert!(Item::Bytes(vec![0x00, 0x01]).as_u64().is_err());
        assert!(Item::Bytes(vec![1; 9]).as_u64().is_err());
    }
}
