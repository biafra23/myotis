//! EIP-2124 fork-id pre-filter for discv4 (#539, part 2): decide from a node's
//! EIP-868 ENR — before any TCP dial — whether it can be on our chain.
//!
//! discv4 is one DHT for every Ethereum network, so a NEIGHBORS reply mixes
//! mainnet, testnet, Gnosis and other nodes. Until now the pool learned a
//! node's network only after a full TCP + ECIES + Hello + Status handshake,
//! then blacklisted it (3311 foreign nodes in 18.8 h on Sepolia). A node's ENR
//! carries its fork id in the `eth` entry (EIP-2124: `[[fork-hash, fork-next]]`),
//! and discv4 can ask for the ENR over UDP (EIP-868 ENRRequest/ENRResponse —
//! see `discv4.rs`).
//!
//! The engine pins one fork id per network ([`myotis_core::forkid`]), not a
//! fork schedule, so the filter accepts a fork hash equal to the pinned one or
//! to its successor (the hash the pinned `next` activation produces): a node on
//! our chain announces one of the two, whether or not it has crossed the
//! pending fork. Anything else is another chain — or a node a fork behind,
//! which `peer::refusing_lag` would refuse at admission anyway. A node with no
//! `eth` entry, or one that does not parse, is UNKNOWN and dialed as before:
//! the filter only ever skips a node it has positively placed on another
//! chain, and the eth Status check stays the authority.

use discv5::enr::{CombinedKey, Enr, EnrPublicKey};
use myotis_core::forkid;
use myotis_core::nodekey::{compress_public_key, NodeKey};
use myotis_core::rlp::{self, Item};

/// What a node's ENR says about its chain, relative to ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Its fork hash is ours or our successor's: hand it to the pool.
    Compatible,
    /// Its fork hash is neither: another chain. Never dialed.
    Foreign,
    /// No `eth` entry, or one that does not parse: dialed as before.
    Unknown,
}

/// Our chain's acceptable fork hashes, from the pinned fork id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkFilter {
    pinned: [u8; 4],
    next: u64,
    accepted: Vec<[u8; 4]>,
}

impl ForkFilter {
    /// The pinned fork hash and, when a `next` activation is pinned, the hash
    /// that activation produces (`forkid::successor`).
    pub fn for_chain(pinned: [u8; 4], next: u64) -> ForkFilter {
        let mut accepted = vec![pinned];
        if next != 0 {
            accepted.push(forkid::successor(u32::from_be_bytes(pinned), next).to_be_bytes());
        }
        ForkFilter {
            pinned,
            next,
            accepted,
        }
    }

    /// The hashes a compatible node may announce.
    pub fn accepted(&self) -> &[[u8; 4]] {
        &self.accepted
    }

    /// Judge a node by the raw RLP of its ENR `eth` entry (`None` = no entry).
    pub fn verdict(&self, eth_entry_rlp: Option<&[u8]>) -> Verdict {
        match eth_entry_rlp.and_then(parse_eth_entry) {
            None => Verdict::Unknown,
            Some((hash, _next)) if self.accepted.contains(&hash) => Verdict::Compatible,
            Some(_) => Verdict::Foreign,
        }
    }

    /// The `eth` entry OUR ENR announces at `now` — the fork id the eth
    /// handshake announces too (`EthConfig::fork_id_at`): the pin with its
    /// next until that passes, then the successor with none.
    pub fn local_eth_entry(&self, now: u64) -> Vec<u8> {
        let (hash, next) = forkid::fork_id_at(u32::from_be_bytes(self.pinned), self.next, now);
        eth_entry_rlp(hash.to_be_bytes(), next)
    }
}

/// Decode an EIP-2124 ENR `eth` entry, `[[fork-hash, fork-next]]`, to its
/// 4-byte hash and next activation. `None` for any other shape.
pub fn parse_eth_entry(raw: &[u8]) -> Option<([u8; 4], u64)> {
    let outer = rlp::decode(raw).ok()?;
    let fork = outer.as_list().ok()?.first()?.as_list().ok()?;
    let mut hash = [0u8; 4];
    hash.copy_from_slice(fork.first()?.as_fixed_bytes(4).ok()?);
    let next = fork.get(1)?.as_u64().ok()?;
    Some((hash, next))
}

/// Encode an EIP-2124 ENR `eth` entry.
pub fn eth_entry_rlp(hash: [u8; 4], next: u64) -> Vec<u8> {
    rlp::encode(&Item::List(vec![Item::List(vec![
        Item::Bytes(hash.to_vec()),
        Item::Bytes(rlp::u64_to_minimal_be(next)),
    ])]))
}

/// What the filter reads from a remote ENR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEnr {
    pub seq: u64,
    /// The raw RLP of the `eth` entry, if any.
    pub eth: Option<Vec<u8>>,
}

/// Decode a remote ENR from its RLP, check its signature (the `enr` crate
/// does, on decode), and require its identity key to be `signer` — the key
/// that signed the discv4 packet carrying it — so a node cannot answer with
/// someone else's record.
pub fn decode_enr(raw: &[u8], signer: &[u8; 64]) -> Result<RemoteEnr, String> {
    use alloy_rlp::Decodable;
    let enr = Enr::<CombinedKey>::decode(&mut &raw[..]).map_err(|e| format!("enr: {e}"))?;
    let signer = compress_public_key(signer).map_err(|e| format!("signer key: {}", e.0))?;
    if enr.public_key().encode() != signer.to_vec() {
        return Err("enr identity differs from the packet signer".to_string());
    }
    Ok(RemoteEnr {
        seq: enr.seq(),
        eth: enr.get_raw_rlp("eth").map(<[u8]>::to_vec),
    })
}

/// Our own ENR as RLP: identity from `key`, the given sequence number and
/// `eth` entry, no endpoint — a light client behind NAT does not know its
/// address, and a record without one is valid.
pub fn local_enr_rlp(key: &NodeKey, seq: u64, eth_entry_rlp: &[u8]) -> Result<Vec<u8>, String> {
    let mut secret = key.secret_bytes();
    let signing =
        CombinedKey::secp256k1_from_bytes(&mut secret).map_err(|e| format!("enr key: {e}"))?;
    let enr = Enr::<CombinedKey>::builder()
        .seq(seq)
        .add_value_rlp("eth", alloy_rlp::Bytes::copy_from_slice(eth_entry_rlp))
        .build(&signing)
        .map_err(|e| format!("enr build: {e:?}"))?;
    Ok(alloy_rlp::encode(&enr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> NodeKey {
        let mut secret = [0u8; 32];
        secret[31] = n;
        NodeKey::from_secret_bytes(&secret).unwrap()
    }

    #[test]
    fn the_eth_entry_round_trips() {
        let raw = eth_entry_rlp([0x26, 0x89, 0x56, 0xb6], 1_791_294_816);
        assert_eq!(
            parse_eth_entry(&raw),
            Some(([0x26, 0x89, 0x56, 0xb6], 1_791_294_816))
        );
        // No next activation encodes as the empty quantity and reads back as 0.
        let raw = eth_entry_rlp([7, 0xc9, 0x46, 0x2e], 0);
        assert_eq!(parse_eth_entry(&raw), Some(([7, 0xc9, 0x46, 0x2e], 0)));
    }

    #[test]
    fn malformed_eth_entries_parse_to_nothing() {
        for bad in [
            &b""[..],
            &rlp::encode(&Item::Bytes(vec![1, 2, 3, 4]))[..],
            &rlp::encode(&Item::List(vec![Item::Bytes(vec![1, 2, 3, 4])]))[..],
            &rlp::encode(&Item::List(vec![Item::List(vec![Item::Bytes(vec![
                1, 2, 3,
            ])])]))[..],
        ] {
            assert_eq!(parse_eth_entry(bad), None);
        }
    }

    #[test]
    fn the_filter_accepts_the_pin_and_its_successor_only() {
        let pinned = forkid::SEPOLIA_FORK_ID_HASH;
        let next = forkid::SEPOLIA_FORK_NEXT;
        let f = ForkFilter::for_chain(pinned, next);
        let successor = forkid::successor(u32::from_be_bytes(pinned), next).to_be_bytes();
        assert_eq!(f.accepted(), &[pinned, successor]);
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(pinned, next))),
            Verdict::Compatible
        );
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(successor, 0))),
            Verdict::Compatible
        );
        // Mainnet's pin on a Sepolia filter: another chain.
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(forkid::MAINNET_FORK_ID_HASH, 0))),
            Verdict::Foreign
        );
        // No entry, or one that does not parse: unknown, never foreign.
        assert_eq!(f.verdict(None), Verdict::Unknown);
        assert_eq!(f.verdict(Some(b"\x01")), Verdict::Unknown);
        // No pinned next: the pin alone.
        let m = ForkFilter::for_chain(forkid::MAINNET_FORK_ID_HASH, 0);
        assert_eq!(m.accepted(), &[forkid::MAINNET_FORK_ID_HASH]);
    }

    #[test]
    fn our_eth_entry_follows_the_fork_schedule() {
        let f = ForkFilter::for_chain(forkid::SEPOLIA_FORK_ID_HASH, forkid::SEPOLIA_FORK_NEXT);
        let before = parse_eth_entry(&f.local_eth_entry(forkid::SEPOLIA_FORK_NEXT - 1)).unwrap();
        assert_eq!(
            before,
            (forkid::SEPOLIA_FORK_ID_HASH, forkid::SEPOLIA_FORK_NEXT)
        );
        let after = parse_eth_entry(&f.local_eth_entry(forkid::SEPOLIA_FORK_NEXT)).unwrap();
        assert_eq!(after, (f.accepted()[1], 0));
        // Both are what the filter itself accepts.
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(before.0, before.1))),
            Verdict::Compatible
        );
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(after.0, after.1))),
            Verdict::Compatible
        );
    }

    #[test]
    fn a_local_enr_decodes_under_its_own_key_only() {
        let k = key(1);
        let eth = eth_entry_rlp([1, 2, 3, 4], 0);
        let raw = local_enr_rlp(&k, 7, &eth).unwrap();
        let remote = decode_enr(&raw, &k.public_key_bytes()).unwrap();
        assert_eq!(remote.seq, 7);
        assert_eq!(remote.eth.as_deref(), Some(&eth[..]));
        // Carried in a packet another node signed: refused.
        assert!(decode_enr(&raw, &key(2).public_key_bytes()).is_err());
        // Tampered: the signature no longer verifies.
        let mut tampered = raw.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decode_enr(&tampered, &k.public_key_bytes()).is_err());
        assert!(decode_enr(b"", &k.public_key_bytes()).is_err());
    }
}
