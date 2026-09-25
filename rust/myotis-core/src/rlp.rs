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

use alloc::{format, vec};
use alloc::{vec::Vec};
use crate::{err, CoreError};

/// Decoded RLP item: a byte string or a list. Owned — decode copies out of
/// the input buffer (EL messages are small; headers ~600 bytes). A peer's
/// message need not be: a tree costs about 50 heap bytes per input byte, so
/// cap the size of peer bytes before decoding them, or walk them with
/// [`validate`] and [`raw_list_prefix`] instead (#454).
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

/// Check that `data` is exactly one well-formed item, accepting and rejecting
/// exactly what [`decode`] does, without building anything. Use it on peer
/// bytes whose tree is never read: [`decode`] spends about 50 heap bytes per
/// input byte on a list of one-byte elements (#454), while this allocates
/// nothing and runs in linear time.
pub fn validate(data: &[u8]) -> Result<(), CoreError> {
    let used = skip_item(data, 0, 0)?;
    if used != data.len() {
        return err(format!(
            "RLP: {} trailing bytes after top-level item",
            data.len() - used
        ));
    }
    Ok(())
}

/// Split an RLP list into the RAW byte sub-slices of its elements (header +
/// payload each), without copying — the Rust twin of the Java
/// `core.trie.RlpItems.split`. The eth wire layer needs this to hash a header
/// or capture a receipt's exact trie-value bytes: for canonical input the
/// sub-slice IS the canonical encoding, and a non-canonical peer encoding
/// simply hashes to something that won't match the trusted value (correct
/// rejection). Structure is validated (each element fully inside the payload);
/// the list must consume `data` exactly.
///
/// This still keeps one 16-byte slice per element. For a peer list whose tail
/// is never read, use [`raw_list_prefix`].
pub fn raw_list_items(data: &[u8]) -> Result<Vec<&[u8]>, CoreError> {
    raw_list_prefix(data, usize::MAX)
}

/// [`raw_list_items`], keeping only the first `max` elements. The rest are
/// still validated, so it accepts and rejects exactly what [`raw_list_items`]
/// does, but they are walked instead of collected. A peer can pack a 10 MiB
/// frame with millions of one-byte elements, so this is the call for a peer
/// list whose tail is never read.
pub fn raw_list_prefix(data: &[u8], max: usize) -> Result<Vec<&[u8]>, CoreError> {
    let first = *data.first().ok_or_else(|| CoreError("RLP: empty".into()))?;
    let (payload_start, payload_len) = match first {
        0xc0..=0xf7 => (1usize, usize::from(first - 0xc0)),
        0xf8..=0xff => {
            let (len, header) = read_long_length(data, 0, first - 0xf7)?;
            (header, len)
        }
        _ => return err("RLP: not a list"),
    };
    let end = payload_start
        .checked_add(payload_len)
        .filter(|&e| e == data.len())
        .ok_or_else(|| CoreError("RLP: list length does not match input".into()))?;
    let mut items = Vec::new();
    let mut pos = payload_start;
    while pos < end {
        let next = skip_item(data, pos, 0)?;
        if next > end {
            return err("RLP: element overruns list payload");
        }
        if items.len() < max {
            items.push(&data[pos..next]);
        }
        pos = next;
    }
    Ok(items)
}

/// The payload of a byte-string item (strips the RLP header). For a list item
/// returns the whole thing unchanged (the caller distinguishes via [`is_list_prefix`]).
/// Used to unwrap a typed-tx / typed-receipt envelope (`type ‖ rlp(...)`) whose
/// byte-string CONTENT is the trie value.
pub fn strip_bytes_header(item: &[u8]) -> Result<&[u8], CoreError> {
    let first = match item.first() {
        Some(&b) => b,
        None => return Ok(item),
    };
    match first {
        0x00..=0x7f => Ok(item),
        0x80..=0xb7 => {
            let len = usize::from(first - 0x80);
            item.get(1..1 + len)
                .ok_or_else(|| CoreError("RLP: truncated string".into()))
        }
        0xb8..=0xbf => {
            let (len, header) = read_long_length(item, 0, first - 0xb7)?;
            item.get(header..header + len)
                .ok_or_else(|| CoreError("RLP: truncated string".into()))
        }
        _ => Ok(item), // a list — caller handles
    }
}

/// True if the RLP item's first byte marks a list (`0xc0..=0xff`).
pub fn is_list_prefix(item: &[u8]) -> bool {
    matches!(item.first(), Some(&b) if b >= 0xc0)
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

/// Walk one item exactly as [`decode_item`] does, with the same canonical-form,
/// bounds and depth checks failing with the same errors, but build nothing and
/// return only the end offset. `skip_item_agrees_with_decode_item` pins the two
/// together, so a change to either one's checks must be made to both.
fn skip_item(data: &[u8], pos: usize, depth: usize) -> Result<usize, CoreError> {
    if depth > MAX_DEPTH {
        return err("RLP: nesting too deep");
    }
    let first = match data.get(pos) {
        Some(&b) => b,
        None => return err("RLP: truncated (empty input)"),
    };
    match first {
        0x00..=0x7f => Ok(pos + 1),
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let payload = slice(data, pos + 1, len)?;
            if len == 1 && payload[0] < 0x80 {
                return err("RLP: non-canonical single byte (should be encoded as itself)");
            }
            Ok(pos + 1 + len)
        }
        0xb8..=0xbf => {
            let (len, header) = read_long_length(data, pos, first - 0xb7)?;
            slice(data, pos + header, len)?;
            Ok(pos + header + len)
        }
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            skip_list_payload(data, pos + 1, len, depth)
        }
        0xf8..=0xff => {
            let (len, header) = read_long_length(data, pos, first - 0xf7)?;
            skip_list_payload(data, pos + header, len, depth)
        }
    }
}

/// [`decode_list_payload`]'s walk for [`skip_item`].
fn skip_list_payload(data: &[u8], start: usize, len: usize, depth: usize) -> Result<usize, CoreError> {
    let end = match start.checked_add(len) {
        Some(e) if e <= data.len() => e,
        _ => return err("RLP: truncated list payload"),
    };
    let mut pos = start;
    while pos < end {
        let next = skip_item(data, pos, depth + 1)?;
        if next > end {
            return err("RLP: list element overruns list payload");
        }
        pos = next;
    }
    Ok(end)
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

    // --- The allocation-free walkers (#454) must be exactly as strict as the
    // decoder: the same end offset, or the same error, on every input.

    #[test]
    fn skip_item_agrees_with_decode_item() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        each_differential_input(|input| {
            // Every offset of a short input; the start and a few random
            // offsets of a long one (all of them would be quadratic).
            let mut offsets: Vec<usize> = if input.len() <= 64 {
                (0..=input.len()).collect()
            } else {
                (0..8).map(|_| rng.below(input.len())).collect()
            };
            offsets.push(0);
            for pos in offsets {
                assert_eq!(
                    skip_item(input, pos, 0),
                    decode_item(input, pos, 0).map(|(_, end)| end),
                    "input {input:02x?} at offset {pos}"
                );
            }
        });
    }

    #[test]
    fn validate_agrees_with_decode() {
        let (mut accepted, mut rejected) = (0, 0);
        each_differential_input(|input| {
            let verdict = decode(input).map(|_| ());
            assert_eq!(validate(input), verdict, "input {input:02x?}");
            if verdict.is_ok() { accepted += 1 } else { rejected += 1 }
        });
        // Not vacuous: both verdicts in bulk (about 10k and 90k today).
        assert!(accepted > 5_000 && rejected > 5_000, "accepted={accepted} rejected={rejected}");
    }

    #[test]
    fn corpus_is_found_when_present() {
        // A moved `testdata` must fail here, not quietly shrink the
        // differential tests to their generated inputs.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el");
        if root.is_dir() {
            assert!(corpus_files().len() >= 20, "found {}", corpus_files().len());
        }
    }

    #[test]
    fn raw_list_prefix_agrees_with_decoding_every_element() {
        each_differential_input(|input| {
            let reference = raw_list_items_by_decoding(input);
            assert_eq!(raw_list_items(input), reference, "input {input:02x?}");
            for max in [0, 1, 2, 3, 256] {
                assert_eq!(
                    raw_list_prefix(input, max),
                    reference.clone().map(|items| items.into_iter().take(max).collect()),
                    "input {input:02x?}, max {max}"
                );
            }
        });
    }

    #[test]
    fn raw_list_prefix_still_rejects_a_bad_element_past_the_prefix() {
        // [0x01, 0x02, 0x81 0x05] — the third element is a non-canonical
        // single byte, so keeping just the first must not accept the list.
        let data = [0xc4, 0x01, 0x02, 0x81, 0x05];
        assert!(raw_list_items(&data).is_err());
        assert!(raw_list_prefix(&data, 1).is_err());
    }

    /// The pre-#454 `raw_list_items`, which decoded every element into an
    /// owned tree just to learn where it ends: the oracle the walk must match.
    fn raw_list_items_by_decoding(data: &[u8]) -> Result<Vec<&[u8]>, CoreError> {
        let first = *data.first().ok_or_else(|| CoreError("RLP: empty".into()))?;
        let (payload_start, payload_len) = match first {
            0xc0..=0xf7 => (1usize, usize::from(first - 0xc0)),
            0xf8..=0xff => {
                let (len, header) = read_long_length(data, 0, first - 0xf7)?;
                (header, len)
            }
            _ => return err("RLP: not a list"),
        };
        let end = payload_start
            .checked_add(payload_len)
            .filter(|&e| e == data.len())
            .ok_or_else(|| CoreError("RLP: list length does not match input".into()))?;
        let mut items = Vec::new();
        let mut pos = payload_start;
        while pos < end {
            let (_item, next) = decode_item(data, pos, 0)?;
            if next > end {
                return err("RLP: element overruns list payload");
            }
            items.push(&data[pos..next]);
            pos = next;
        }
        Ok(items)
    }

    /// Feed `check` the differential tests' inputs, one at a time: every
    /// string of up to two bytes, nesting and long-form lengths either side
    /// of their bounds, and the shared EL corpora plus seeded random trees,
    /// each with truncations and header mutations. A checkout without
    /// `testdata` still runs the generated part.
    fn each_differential_input(mut check: impl FnMut(&[u8])) {
        check(&[]);
        for a in 0..=255u8 {
            check(&[a]);
            for b in 0..=255u8 {
                check(&[a, b]);
            }
        }

        for depth in MAX_DEPTH - 2..=MAX_DEPTH + 3 {
            let mut short = vec![0xc1; depth];
            short.push(0xc0);
            check(&short);
            // The same chain in long list form, 56 one-byte elements at the
            // bottom (every payload stays within a one-byte length).
            let mut long = vec![0x01; 56];
            for _ in 0..depth {
                let mut wrapped = vec![0xf8, long.len() as u8];
                wrapped.extend_from_slice(&long);
                long = wrapped;
            }
            check(&long);
        }
        for (prefix, len) in [(0xb8u8, 55usize), (0xb8, 56), (0xf8, 55), (0xf8, 56)] {
            let mut data = vec![prefix, len as u8];
            data.resize(2 + len, 0x01);
            check(&data);
        }
        check(&[0xb9, 0x00, 0x38]); // leading-zero length
        check(&[0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // absurd length
        check(&[0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut seeds = corpus_files();
        for _ in 0..400 {
            seeds.push(encode(&random_item(&mut rng, 0)));
        }
        for seed in seeds {
            check(&seed);
            for _ in 0..16 {
                check(&seed[..rng.below(seed.len() + 1)]);
            }
            let positions = header_positions(&seed);
            for _ in 0..positions.len().min(12) {
                let pos = positions[rng.below(positions.len())];
                let mut m = seed.clone();
                for byte in [0x00, 0x7f, 0x80, 0x81, 0xb7, 0xb8, 0xbf, 0xc0, 0xc1, 0xf7, 0xf8, 0xff] {
                    m[pos] = byte;
                    check(&m);
                }
                m[pos] = seed[pos];
                if pos + 1 < seed.len() {
                    for byte in [0x00, 0x01, 0x37, 0x38, 0x7f, 0x80, 0xff] {
                        m[pos + 1] = byte;
                        check(&m);
                    }
                }
                let mut dropped = seed.clone();
                dropped.remove(pos);
                check(&dropped);
            }
        }
    }

    /// Every `.rlp` and `.bin` file under `rust/testdata/el` (not all of them
    /// are well-formed RLP, which suits a differential test).
    fn corpus_files() -> Vec<Vec<u8>> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el");
        let mut out = Vec::new();
        let mut dirs = vec![root];
        while let Some(dir) = dirs.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for path in entries.flatten().map(|e| e.path()) {
                if path.is_dir() {
                    dirs.push(path);
                } else if matches!(path.extension().and_then(|e| e.to_str()), Some("rlp" | "bin")) {
                    out.push(std::fs::read(&path).expect("read corpus file"));
                }
            }
        }
        out
    }

    /// Start offsets of every item header in a well-formed prefix of `data`.
    fn header_positions(data: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut ranges = vec![(0, data.len())];
        while let Some((mut pos, end)) = ranges.pop() {
            while pos < end {
                let Ok(next) = skip_item(data, pos, 0) else { break };
                out.push(pos);
                match data[pos] {
                    0xc0..=0xf7 => ranges.push((pos + 1, next)),
                    b @ 0xf8..=0xff => ranges.push((pos + 1 + usize::from(b - 0xf7), next)),
                    _ => {}
                }
                pos = next;
            }
        }
        out
    }

    /// A random tree of at most four levels. Only the top level ever gets a
    /// long list (long enough to need the long list form); deeper lists stay
    /// short, so a tree stays around a few KiB.
    fn random_item(rng: &mut Rng, depth: usize) -> Item {
        if depth < 4 && rng.below(3) == 0 {
            let n = if depth == 0 && rng.below(4) == 0 { 20 + rng.below(40) } else { rng.below(5) };
            return Item::List((0..n).map(|_| random_item(rng, depth + 1)).collect());
        }
        let len = match rng.below(6) {
            0 => 0,
            1 | 2 => 1,
            3 => rng.below(56),
            4 => 56 + rng.below(200),
            _ => rng.below(9),
        };
        Item::Bytes((0..len).map(|_| rng.next() as u8).collect())
    }

    /// xorshift64* — seeded, so a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }
}
