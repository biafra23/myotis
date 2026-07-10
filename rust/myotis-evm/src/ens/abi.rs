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

/// `selector ‖ bytes32 ‖ head-tail(string)` — one static node + one dynamic
/// string arg (`text(bytes32,string)`). The string's offset is relative to the
/// start of the args (after the selector), so with one static word ahead of it
/// the offset is 0x40.
pub fn encode_call_bytes32_string(signature: &str, node: &[u8; 32], s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(4 + 32 * 3 + bytes.len().next_multiple_of(32));
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(node);
    out.extend_from_slice(&word(0x40)); // offset: past node word + offset word
    out.extend_from_slice(&word(bytes.len() as u64));
    out.extend_from_slice(bytes);
    let pad = (32 - (bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// `selector ‖ bytes32 ‖ uint256(v)` — one static node + one static uint arg
/// (`addr(bytes32,uint256)` multi-coin, `ABI(bytes32,uint256)`).
pub fn encode_call_bytes32_u64(signature: &str, node: &[u8; 32], v: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(node);
    out.extend_from_slice(&word(v));
    out
}

/// `selector ‖ bytes32 ‖ offset ‖ uint(v) ‖ len‖data‖pad` — one static node, one
/// dynamic `bytes`, one static uint (`dnsRecord(bytes32,bytes,uint16)` — the
/// JAVA ENGINE's signature, selector 0xee8de1f7, taking the RAW DNS wire name;
/// note this differs from the mainnet PublicResolver ABI, which takes
/// `keccak256(wireName)` as `bytes32` — ported byte-for-byte for parity).
pub fn encode_call_bytes32_bytes_u64(
    signature: &str,
    node: &[u8; 32],
    dyn_bytes: &[u8],
    v: u64,
) -> Vec<u8> {
    let pad = (32 - (dyn_bytes.len() % 32)) % 32;
    let mut out = Vec::with_capacity(4 + 32 * 4 + dyn_bytes.len() + pad);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(node);
    out.extend_from_slice(&word(0x60)); // offset: past the three head words
    out.extend_from_slice(&word(v));
    out.extend_from_slice(&word(dyn_bytes.len() as u64));
    out.extend_from_slice(dyn_bytes);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// `selector ‖ bytes32 ‖ bytes4-left-aligned` —
/// `interfaceImplementer(bytes32,bytes4)`.
pub fn encode_call_bytes32_bytes4(signature: &str, node: &[u8; 32], id: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(node);
    let mut w = [0u8; 32];
    w[..4].copy_from_slice(&id);
    out.extend_from_slice(&w);
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
    let word = data.get(pos..pos.checked_add(32)?)?;
    // High 24 bytes must be zero for the value to fit a sane index.
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    // Bound-check in the u64 domain BEFORE casting: on a 32-bit target
    // (armeabi-v7a Android), `as usize` would truncate — e.g. 2^32 → 0 — and
    // silently bypass the MAX_INDEX guard.
    let v = u64::from_be_bytes(word[24..32].try_into().ok()?);
    (v <= MAX_INDEX as u64).then_some(v as usize)
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

/// Decode a `bool` from the first word of `data`. Solidity's bool convention is
/// the LAST byte of the word — only that byte is read (matching the Java
/// `decodeBool`'s `result[31] != 0`), so a dirty word with a zero last byte is
/// `false`, not misclassified as `true`.
pub fn decode_bool(data: &[u8]) -> bool {
    match data.get(..32) {
        Some(word) => word[31] != 0,
        None => false,
    }
}

/// Decode the dynamic `bytes` at head slot `arg_index` (offset word → length word
/// → data). `None` on any out-of-bounds / oversized field.
pub fn decode_dynamic_bytes(data: &[u8], arg_index: usize) -> Option<Vec<u8>> {
    let offset = read_index(data, arg_index.checked_mul(32)?)?;
    let len = read_index(data, offset)?;
    let start = offset.checked_add(32)?;
    let end = start.checked_add(len)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

/// Decode the dynamic `string` at head slot 0 (offset → length → UTF-8 data,
/// invalid sequences replaced — Java `new String(bytes, UTF_8)` parity).
pub fn decode_string(data: &[u8]) -> Option<String> {
    decode_dynamic_bytes(data, 0).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Decode the two static 32-byte words of a `(bytes32,bytes32)` return
/// (`pubkey(bytes32)` → x, y). `None` if shorter than 64 bytes.
pub fn decode_two_words(data: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let x: [u8; 32] = data.get(..32)?.try_into().ok()?;
    let y: [u8; 32] = data.get(32..64)?.try_into().ok()?;
    Some((x, y))
}

/// Decode a `(uint256, bytes)` return (`ABI(bytes32,uint256)` → contentType,
/// data). The uint must fit u64 (ENS content types are a small bitmask —
/// anything larger is not a real record). `None` on malformed data.
/// Known micro-divergence: a contentType in [2^63, 2^64) decodes here but makes
/// Java's `longValueExact()` throw → empty there vs an error result here; only
/// an adversarial resolver can produce it and no wrong value is delivered.
pub fn decode_uint_bytes(data: &[u8]) -> Option<(u64, Vec<u8>)> {
    let word = data.get(..32)?;
    if word[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let v = u64::from_be_bytes(word[24..32].try_into().ok()?);
    let bytes = decode_dynamic_bytes(data, 1)?;
    Some((v, bytes))
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
    fn decode_bool_reads_only_the_last_byte() {
        let mut dirty = [0u8; 32];
        dirty[0] = 0xff; // dirty high byte, last byte zero → false (Solidity/Java)
        assert!(!decode_bool(&dirty));
        let mut truthy = [0u8; 32];
        truthy[31] = 1;
        assert!(decode_bool(&truthy));
        assert!(!decode_bool(&[])); // short data → false
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
    fn record_selectors_are_correct() {
        // The ENSIP record-profile selectors, pinned against their published ids.
        assert_eq!(selector("text(bytes32,string)"), [0x59, 0xd1, 0xd4, 0x3c]);
        assert_eq!(selector("contenthash(bytes32)"), [0xbc, 0x1c, 0x58, 0xd1]);
        assert_eq!(selector("addr(bytes32,uint256)"), [0xf1, 0xcb, 0x7e, 0x06]);
        assert_eq!(selector("pubkey(bytes32)"), [0xc8, 0x69, 0x02, 0x33]);
        assert_eq!(selector("ABI(bytes32,uint256)"), [0x22, 0x03, 0xab, 0x56]);
        // The JAVA ENGINE's dnsRecord signature (raw wire name as `bytes`) — NOT
        // the mainnet PublicResolver's dnsRecord(bytes32,bytes32,uint16) 0xa8fa5682.
        assert_eq!(selector("dnsRecord(bytes32,bytes,uint16)"), [0xee, 0x8d, 0xe1, 0xf7]);
        assert_eq!(selector("interfaceImplementer(bytes32,bytes4)"), [0x12, 0x4a, 0x31, 0x9c]);
    }

    #[test]
    fn encode_bytes32_string_shape() {
        let node = [0xABu8; 32];
        let enc = encode_call_bytes32_string("text(bytes32,string)", &node, "avatar");
        assert_eq!(&enc[..4], &[0x59, 0xd1, 0xd4, 0x3c]);
        assert_eq!(&enc[4..36], &node);
        assert_eq!(enc[36..68], word(0x40)); // offset past the two head words
        assert_eq!(enc[68..100], word(6)); // "avatar".len()
        assert_eq!(&enc[100..106], b"avatar");
        assert_eq!(enc.len(), 4 + 32 * 3 + 32); // padded to a full word
        assert!(enc[106..].iter().all(|&b| b == 0));
    }

    #[test]
    fn encode_bytes32_u64_and_bytes4_shapes() {
        let node = [0x11u8; 32];
        let mc = encode_call_bytes32_u64("addr(bytes32,uint256)", &node, 60);
        assert_eq!(&mc[..4], &[0xf1, 0xcb, 0x7e, 0x06]);
        assert_eq!(mc[36..68], word(60));

        let ii = encode_call_bytes32_bytes4(
            "interfaceImplementer(bytes32,bytes4)",
            &node,
            [0x5b, 0x5e, 0x13, 0x9f],
        );
        assert_eq!(&ii[..4], &[0x12, 0x4a, 0x31, 0x9c]);
        assert_eq!(&ii[36..40], &[0x5b, 0x5e, 0x13, 0x9f]); // left-aligned
        assert!(ii[40..68].iter().all(|&b| b == 0));

        // dnsRecord: node ‖ offset(0x60) ‖ resource ‖ len ‖ wire ‖ pad
        let wire = [0x07u8, b'v', b'i', b't', b'a', b'l', b'i', b'k', 0x03, b'e', b't', b'h', 0x00];
        let dr = encode_call_bytes32_bytes_u64("dnsRecord(bytes32,bytes,uint16)", &node, &wire, 1);
        assert_eq!(&dr[..4], &[0xee, 0x8d, 0xe1, 0xf7]);
        assert_eq!(dr[36..68], word(0x60));
        assert_eq!(dr[68..100], word(1)); // A record
        assert_eq!(dr[100..132], word(wire.len() as u64));
        assert_eq!(&dr[132..132 + wire.len()], &wire);
        assert_eq!(dr.len(), 132 + 32); // wire padded to one word
    }

    #[test]
    fn decode_two_words_and_uint_bytes() {
        let mut pk = vec![0x0Au8; 32];
        pk.extend_from_slice(&[0x0Bu8; 32]);
        assert_eq!(decode_two_words(&pk), Some(([0x0A; 32], [0x0B; 32])));
        assert_eq!(decode_two_words(&pk[..40]), None);

        // (uint256=1, bytes="hi")
        let mut ab = word(1).to_vec();
        ab.extend_from_slice(&word(0x40)); // offset of the bytes
        ab.extend_from_slice(&word(2));
        ab.extend_from_slice(b"hi");
        ab.extend_from_slice(&[0u8; 30]);
        assert_eq!(decode_uint_bytes(&ab), Some((1, b"hi".to_vec())));
        // dirty high bytes in the uint word → None
        let mut dirty = ab.clone();
        dirty[0] = 1;
        assert_eq!(decode_uint_bytes(&dirty), None);
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
