//! Ethereum Node Record (EIP-778) — twin of `core.enr.Enr` (Java).
//!
//! Wire form `RLP([signature, seq, k, v, k, v, …])`; the text form is
//! `enr:` + base64url (no padding). Matching the Java decoder
//! (docs/reimplementation/02 §1.3): the SIGNATURE IS NOT VERIFIED on this
//! path (it is verified in the EIP-1459 DNS path, EL-A8); simple
//! bytes-valued pairs are kept, list-valued pairs (`eth`, `attnets`, …) are
//! skipped in the generic map and re-parsed on demand.

use std::collections::BTreeMap;

use crate::nodekey::decompress_public_key;
use crate::rlp::{self, Item};
use crate::{err, CoreError};

/// Decoded ENR: sequence number, the bytes-valued key/value pairs, and the
/// raw encoding (kept for on-demand re-parses and re-gossip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enr {
    seq: u64,
    pairs: BTreeMap<String, Vec<u8>>,
    raw_rlp: Vec<u8>,
}

/// Decoded CL `eth2` ENR field: `fork_digest(4) ‖ next_fork_version(4) ‖
/// next_fork_epoch(u64 LE)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eth2Field {
    pub fork_digest: [u8; 4],
    pub next_fork_version: [u8; 4],
    pub next_fork_epoch: u64,
}

impl Enr {
    /// Decode from an `enr:…` base64url string (EIP-778 text form).
    pub fn from_enr_string(enr_string: &str) -> Result<Enr, CoreError> {
        let data = enr_string.strip_prefix("enr:").unwrap_or(enr_string);
        let rlp_bytes = base64url_decode(data)?;
        Enr::decode(&rlp_bytes)
    }

    /// Decode from raw RLP bytes (as received in discv4 Neighbors / discv5).
    pub fn decode(rlp_bytes: &[u8]) -> Result<Enr, CoreError> {
        let top = rlp::decode(rlp_bytes)?;
        let items = top.as_list()?;
        if items.len() < 2 {
            return err("ENR: record must contain signature and seq");
        }
        // items[0] = signature: skipped (see module docs).
        let seq = items[1]
            .as_u64_fitting_long()
            .map_err(|e| CoreError(format!("ENR: seq: {}", e.0)))?;
        // Remaining items are key/value pairs.
        let kv = &items[2..];
        if kv.len() % 2 != 0 {
            return err("ENR: dangling key without value");
        }
        let mut pairs = BTreeMap::new();
        for pair in kv.chunks_exact(2) {
            let key_bytes = pair[0]
                .as_bytes()
                .map_err(|e| CoreError(format!("ENR: key: {}", e.0)))?;
            let key = String::from_utf8_lossy(key_bytes).into_owned();
            // Keep simple bytes values; skip list values (eth2/attnets/… are
            // re-parsed on demand from raw_rlp).
            if let Item::Bytes(value) = &pair[1] {
                pairs.insert(key, value.clone());
            }
        }
        Ok(Enr {
            seq,
            pairs,
            raw_rlp: rlp_bytes.to_vec(),
        })
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn raw_rlp(&self) -> &[u8] {
        &self.raw_rlp
    }

    /// Raw value of a bytes-valued pair.
    pub fn value(&self, key: &str) -> Option<&[u8]> {
        self.pairs.get(key).map(|v| v.as_slice())
    }

    /// Compressed 33-byte secp256k1 public key, if present.
    pub fn compressed_secp256k1(&self) -> Option<&[u8]> {
        self.value("secp256k1")
    }

    /// Node public key, decompressed to the 64-byte uncompressed form.
    /// `None` when absent or not a valid curve point (Java returns empty).
    pub fn public_key_uncompressed(&self) -> Option<[u8; 64]> {
        decompress_public_key(self.compressed_secp256k1()?).ok()
    }

    /// IP address bytes (4 for v4, 16 for v6), if present.
    pub fn ip(&self) -> Option<&[u8]> {
        self.value("ip")
    }

    pub fn tcp_port(&self) -> Option<u16> {
        self.port("tcp")
    }

    pub fn udp_port(&self) -> Option<u16> {
        self.port("udp")
    }

    fn port(&self, key: &str) -> Option<u16> {
        let b = self.value(key)?;
        // Java `Bytes.toInt` accepts up to 4 bytes; a port is at most 2. Be
        // strict: 1-2 bytes big-endian (0 bytes = port 0 never appears).
        match b.len() {
            1 => Some(u16::from(b[0])),
            2 => Some(u16::from_be_bytes([b[0], b[1]])),
            _ => None,
        }
    }

    /// CL `eth2` field, when present and well-formed (16+ bytes).
    pub fn eth2(&self) -> Option<Eth2Field> {
        let raw = self.value("eth2")?;
        if raw.len() < 16 {
            return None;
        }
        let mut fork_digest = [0u8; 4];
        fork_digest.copy_from_slice(&raw[0..4]);
        let mut next_fork_version = [0u8; 4];
        next_fork_version.copy_from_slice(&raw[4..8]);
        let mut epoch_le = [0u8; 8];
        epoch_le.copy_from_slice(&raw[8..16]);
        Some(Eth2Field {
            fork_digest,
            next_fork_version,
            next_fork_epoch: u64::from_le_bytes(epoch_le),
        })
    }

    /// EL `eth` field (EIP-868): the 4-byte EIP-2124 fork hash. Layout is
    /// `eth = [[fork_hash, fork_next], …]` — list-valued, so this re-parses
    /// the raw record (fully guarded: malformed yields `None`, never errors).
    /// Stops at the first `eth` key; a duplicate-key record (invalid per
    /// EIP-778) could differ from Java, which keeps scanning for an
    /// `eth`+list pair — not worth modeling.
    pub fn eth_fork_id_hash(&self) -> Option<[u8; 4]> {
        let top = rlp::decode(&self.raw_rlp).ok()?;
        let items = top.as_list().ok()?;
        let kv = items.get(2..)?;
        for pair in kv.chunks_exact(2) {
            let key = pair[0].as_bytes().ok()?;
            if key == b"eth" {
                // eth -> [[fork_hash, fork_next], …] — first tuple, first element.
                let outer = pair[1].as_list().ok()?;
                let tuple = outer.first()?.as_list().ok()?;
                let fork_hash = tuple.first()?.as_bytes().ok()?;
                if fork_hash.len() >= 4 {
                    let mut out = [0u8; 4];
                    out.copy_from_slice(&fork_hash[0..4]);
                    return Some(out);
                }
                return None;
            }
        }
        None
    }
}

/// base64url (RFC 4648 §5) decode. The ENR text form is unpadded; padding is
/// tolerated only when it is CORRECT for the body length, matching Java's
/// `Base64.getUrlDecoder` (which rejects wrong-count padding like `"QQ="`).
fn base64url_decode(input: &str) -> Result<Vec<u8>, CoreError> {
    let trimmed = input.trim_end_matches('=');
    let pad = input.len() - trimmed.len();
    let valid_padding = match (trimmed.len() % 4, pad) {
        (_, 0) => true, // unpadded (the ENR convention)
        (2, 2) | (3, 1) => true,
        _ => false,
    };
    if !valid_padding {
        return err("ENR: malformed base64url padding");
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4 + 3);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in trimmed.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return err(format!("ENR: invalid base64url character 0x{c:02x}")),
        };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // A dangling 6-bit group can't encode a byte (RFC 4648 forbids it).
    if bits == 6 {
        return err("ENR: truncated base64url input");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EIP-778 example record (seq 1, ip4 127.0.0.1, udp 30303).
    const EIP778_EXAMPLE: &str = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

    #[test]
    fn decodes_the_eip778_example() {
        let enr = Enr::from_enr_string(EIP778_EXAMPLE).unwrap();
        assert_eq!(enr.seq(), 1);
        assert_eq!(enr.ip(), Some(&[127, 0, 0, 1][..]));
        assert_eq!(enr.udp_port(), Some(30303));
        assert_eq!(enr.tcp_port(), None);
        assert_eq!(enr.value("id"), Some(&b"v4"[..]));
        // The example's known compressed key.
        let key = enr.compressed_secp256k1().unwrap();
        assert_eq!(key[0], 0x03);
        assert!(enr.public_key_uncompressed().is_some());
        assert_eq!(enr.eth2(), None);
        assert_eq!(enr.eth_fork_id_hash(), None);
    }

    #[test]
    fn base64url_rejects_invalid() {
        assert!(base64url_decode("abc/").is_err()); // standard-alphabet char
        assert!(base64url_decode("a").is_err()); // dangling 6 bits
        assert!(Enr::from_enr_string("enr:!!!").is_err());
    }

    #[test]
    fn rejects_structurally_broken_records() {
        assert!(Enr::decode(&[0xc0]).is_err()); // empty list
        // [sig, seq, "key"] — dangling key without a value.
        let broken = rlp::encode(&Item::List(vec![
            Item::Bytes(vec![0u8; 64]),
            Item::Bytes(vec![1]),
            Item::Bytes(b"id".to_vec()),
        ]));
        assert!(Enr::decode(&broken).is_err());
    }
}
