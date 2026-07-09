//! ENS name hashing (ENSIP-1) and DNS wire encoding (ENSIP-10).
//!
//! Normalization is **lowercase-only** — full UTS-46 / IDNA is NOT applied, a
//! deliberate parity gap with the Java engine (`Namehash.java`). A name that a
//! UTS-46-normalizing client would fold differently (non-ASCII, disallowed code
//! points) may hash to a different node here; ASCII names are unaffected.

use myotis_core::keccak::{keccak256, keccak256_concat};

use super::EnsError;

/// The ENSIP-1 namehash of `name` (the 32-byte trie node). `namehash("") == 0`;
/// otherwise `keccak256(namehash(parent) ‖ keccak256(label))` over labels
/// right-to-left. Trailing dots are ignored (the root has no label), matching the
/// Java `split(".")` trailing-empty removal.
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    let lower = name.to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    if trimmed.is_empty() {
        return node;
    }
    for label in trimmed.split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        node = keccak256_concat(&node, &label_hash);
    }
    node
}

/// The ENSIP-10 DNS wire encoding of `name`: each label as `<len><utf8>`,
/// terminated by a `0x00` root byte. The root name encodes as `{0x00}`. Rejects
/// an empty interior label or a label longer than 63 bytes (a malformed name a
/// gateway would reject anyway).
pub fn dns_encode(name: &str) -> Result<Vec<u8>, EnsError> {
    let lower = name.to_lowercase();
    let trimmed = lower.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(vec![0x00]);
    }
    let mut out = Vec::new();
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(EnsError::InvalidName("empty label"));
        }
        if bytes.len() > 63 {
            return Err(EnsError::InvalidName("label exceeds 63 bytes"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0x00);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn namehash_known_vectors() {
        // The canonical ENSIP-1 vectors.
        assert_eq!(namehash(""), [0u8; 32]);
        assert_eq!(
            namehash("eth"),
            hex32("93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")
        );
        assert_eq!(
            namehash("vitalik.eth"),
            hex32("ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835")
        );
    }

    #[test]
    fn namehash_lowercases_and_ignores_trailing_dot() {
        assert_eq!(namehash("VITALIK.ETH"), namehash("vitalik.eth"));
        assert_eq!(namehash("eth."), namehash("eth"));
        assert_eq!(namehash("vitalik.eth."), namehash("vitalik.eth"));
    }

    #[test]
    fn dns_encode_vectors() {
        // "vitalik.eth" → 07 'vitalik' 03 'eth' 00
        let mut expected = vec![7u8];
        expected.extend_from_slice(b"vitalik");
        expected.push(3);
        expected.extend_from_slice(b"eth");
        expected.push(0);
        assert_eq!(dns_encode("vitalik.eth").unwrap(), expected);
        // root
        assert_eq!(dns_encode("").unwrap(), vec![0u8]);
        assert_eq!(dns_encode(".").unwrap(), vec![0u8]);
    }

    #[test]
    fn dns_encode_rejects_bad_labels() {
        assert!(dns_encode("a..b").is_err()); // empty interior label
        let long = "x".repeat(64);
        assert!(dns_encode(&format!("{long}.eth")).is_err()); // > 63 bytes
    }
}
