//! The minimal Solidity ABI subset ENS resolution needs — hand-rolled (mirrors
//! the Java `abi/AbiEncoder`/`AbiDecoder`), covering only `bytes32`, `bytes4`,
//! `address`, `bool`, and dynamic `bytes` head-tail encode/decode. All decoders
//! are bounds-checked and panic-free on adversarial return data.

use myotis_core::keccak::keccak256;

/// A dynamic length/offset that would exceed this is rejected rather than
/// allocated — a return-data length bomb. 64 MiB (matches the Java `MAX_INDEX`).
const MAX_INDEX: usize = 64 * 1024 * 1024;

/// The 4-byte function selector `keccak256(signature)[..4]`.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// A big-endian 32-byte word holding `v` in its low 8 bytes.
fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `selector(signature) ‖ bytes32(value)` — a call with one static 32-byte arg
/// (`resolver(bytes32)`, `addr(bytes32)`, `name(bytes32)`).
pub fn encode_call_bytes32(signature: &str, value: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(value);
    out
}

/// `supportsInterface(bytes4)`: selector ‖ the interface id left-aligned in a
/// 32-byte word.
pub fn encode_supports_interface(interface_id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&selector("supportsInterface(bytes4)"));
    let mut w = [0u8; 32];
    w[..4].copy_from_slice(&interface_id);
    out.extend_from_slice(&w);
    out
}

/// `resolve(bytes,bytes)`: selector ‖ head-tail encoding of two dynamic `bytes`
/// args (the DNS-encoded name and the inner resolver call).
pub fn encode_resolve(dns_name: &[u8], inner_call: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&selector("resolve(bytes,bytes)"));
    out.extend_from_slice(&encode_bytes_args(&[dns_name, inner_call]));
    out
}

/// Head-tail encoding of N dynamic `bytes` args: N offset words, then each arg as
/// `length ‖ data ‖ zero-pad-to-32`.
fn encode_bytes_args(args: &[&[u8]]) -> Vec<u8> {
    let mut head = Vec::new();
    let mut tail = Vec::new();
    let mut offset = args.len() * 32;
    for arg in args {
        head.extend_from_slice(&word(offset as u64));
        tail.extend_from_slice(&word(arg.len() as u64));
        tail.extend_from_slice(arg);
        let pad = (32 - (arg.len() % 32)) % 32;
        tail.extend(std::iter::repeat_n(0u8, pad));
        offset += 32 + arg.len() + pad;
    }
    head.extend_from_slice(&tail);
    head
}

/// Read the 32-byte word at `pos` as a `usize`, or `None` if out of bounds or the
/// value exceeds [`MAX_INDEX`] (so a huge offset/length can't drive an OOB read or
/// allocation).
fn read_index(data: &[u8], pos: usize) -> Option<usize> {
    let word = data.get(pos..pos + 32)?;
    // High 24 bytes must be zero for the value to fit a sane index.
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let v = u64::from_be_bytes(word[24..32].try_into().ok()?) as usize;
    (v <= MAX_INDEX).then_some(v)
}

/// Decode a 20-byte address from the first 32-byte word of `data` (left-padded).
/// `None` if `data` is too short or the upper 12 bytes are non-zero (not a clean
/// address). A zero address is returned as `Some([0;20])` — callers treat that as
/// "no record".
pub fn decode_address(data: &[u8]) -> Option<[u8; 20]> {
    let word = data.get(..32)?;
    if word[..12].iter().any(|&b| b != 0) {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&word[12..32]);
    Some(addr)
}

/// Decode a `bool` from the first word of `data` (any non-zero → true).
pub fn decode_bool(data: &[u8]) -> bool {
    match data.get(..32) {
        Some(word) => word.iter().any(|&b| b != 0),
        None => false,
    }
}

/// Decode the dynamic `bytes` at head slot `arg_index` (offset word → length word
/// → data). `None` on any out-of-bounds / oversized field.
pub fn decode_dynamic_bytes(data: &[u8], arg_index: usize) -> Option<Vec<u8>> {
    let offset = read_index(data, arg_index * 32)?;
    let len = read_index(data, offset)?;
    let start = offset.checked_add(32)?;
    let end = start.checked_add(len)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_correct() {
        assert_eq!(selector("addr(bytes32)"), [0x3b, 0x3b, 0x57, 0xde]);
        assert_eq!(selector("resolver(bytes32)"), [0x01, 0x78, 0xb8, 0xbf]);
        assert_eq!(selector("supportsInterface(bytes4)"), [0x01, 0xff, 0xc9, 0xa7]);
        assert_eq!(selector("name(bytes32)"), [0x69, 0x1f, 0x34, 0x31]);
    }

    #[test]
    fn encode_call_bytes32_shape() {
        let node = [0xABu8; 32];
        let enc = encode_call_bytes32("addr(bytes32)", &node);
        assert_eq!(&enc[..4], &[0x3b, 0x3b, 0x57, 0xde]);
        assert_eq!(&enc[4..36], &node);
    }

    #[test]
    fn decode_address_round_trips_and_rejects_dirty_padding() {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&[0x11u8; 20]);
        assert_eq!(decode_address(&word), Some([0x11u8; 20]));
        // dirty upper byte → not a clean address
        word[0] = 1;
        assert_eq!(decode_address(&word), None);
        // too short
        assert_eq!(decode_address(&[0u8; 20]), None);
    }

    #[test]
    fn dynamic_bytes_round_trip() {
        // Encode two bytes args, decode each back.
        let a = b"hello world, this is arg zero!!!".as_slice(); // 32 bytes
        let b = b"arg one".as_slice(); // 7 bytes
        let enc = encode_bytes_args(&[a, b]);
        assert_eq!(decode_dynamic_bytes(&enc, 0).unwrap(), a);
        assert_eq!(decode_dynamic_bytes(&enc, 1).unwrap(), b);
    }

    #[test]
    fn decode_dynamic_bytes_is_bounds_safe() {
        // An offset pointing past the buffer must be rejected, not panic.
        let mut data = vec![0u8; 32];
        data[31] = 0xff; // offset = 255, out of bounds
        assert_eq!(decode_dynamic_bytes(&data, 0), None);
        // an absurd length is capped by MAX_INDEX
        let mut huge = word(32).to_vec();
        huge.extend_from_slice(&word(u64::MAX >> 1)); // length word > MAX_INDEX
        assert_eq!(decode_dynamic_bytes(&huge, 0), None);
    }
}
