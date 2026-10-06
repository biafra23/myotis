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
//! pending fork.
//!
//! A hash that is neither may still be OUR chain, a fork ahead of this build:
//! after a fork the pin does not know, every upgraded node announces
//! `successor(our hash, T)` for the activation `T`. Those nodes must stay
//! dialable — the fork watch (#491, `fork_watch.rs`) learns of the fork only
//! from the Status such a node sends, and a stale build that could not reach
//! them would show no `upgradeAdvisory` and an empty pool. So a hash whose
//! activation (`forkid::activation_of`, the one `T` that turns our hash into
//! it) is a plausible fork time — on the beacon epoch grid, within the fork
//! watch's lookback and horizon — is UNKNOWN, not foreign. Another chain's hash
//! places at a random `T`, so it passes only by the chance a 32-bit value lands
//! on an epoch boundary inside an 800-day window: about one in 25,000 with the
//! grid and one in 60 without it per baseline, twice that where a pinned
//! `next` gives two. The placement starts from every hash we
//! may announce — the pin and its successor — so a pinned fork the network
//! rescheduled, whose live nodes stay on the pin past the pinned time and
//! then fork from it, is placed too. A node two or more forks BEHIND is still
//! judged foreign — `peer::refusing_lag` would refuse it at admission anyway
//! (one behind the successor is the pin, which is accepted). A node
//! with no `eth` entry, or one that does not parse, is UNKNOWN and dialed as
//! before: the filter only ever skips a node it has positively placed on
//! another chain, and the eth Status check stays the authority.

use discv5::enr::{CombinedKey, Enr, EnrPublicKey};
use myotis_core::forkid;

use crate::el::fork_watch::{LOOKBACK_SECONDS, MAX_HORIZON_SECONDS};
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

/// Our chain's acceptable fork hashes, from the pinned fork id, and the beacon
/// epoch grid a plausible fork ahead of the pin would sit on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkFilter {
    pinned: [u8; 4],
    next: u64,
    accepted: Vec<[u8; 4]>,
    /// Beacon genesis time and epoch length; 0 = no grid, any activation inside
    /// the window is plausible.
    genesis_time: u64,
    epoch_seconds: u64,
}

impl ForkFilter {
    /// The pinned fork hash and, when a `next` activation is pinned, the hash
    /// that activation produces (`forkid::successor`). No epoch grid until
    /// [`with_epoch_grid`](Self::with_epoch_grid).
    pub fn for_chain(pinned: [u8; 4], next: u64) -> ForkFilter {
        let mut accepted = vec![pinned];
        if next != 0 {
            accepted.push(forkid::successor(u32::from_be_bytes(pinned), next).to_be_bytes());
        }
        ForkFilter {
            pinned,
            next,
            accepted,
            genesis_time: 0,
            epoch_seconds: 0,
        }
    }

    /// The beacon epoch grid (genesis time, seconds per epoch) EL fork
    /// timestamps sit on — the same grid the fork watch places with.
    pub fn with_epoch_grid(mut self, genesis_time: u64, epoch_seconds: u64) -> ForkFilter {
        self.genesis_time = genesis_time;
        self.epoch_seconds = epoch_seconds;
        self
    }

    /// The hashes a compatible node may announce.
    pub fn accepted(&self) -> &[[u8; 4]] {
        &self.accepted
    }

    /// Judge a node at `now` (unix seconds) by the raw RLP of its ENR `eth`
    /// entry (`None` = no entry).
    pub fn verdict(&self, eth_entry_rlp: Option<&[u8]>, now: u64) -> Verdict {
        match eth_entry_rlp.and_then(parse_eth_entry) {
            None => Verdict::Unknown,
            Some((hash, _next)) if self.accepted.contains(&hash) => Verdict::Compatible,
            Some((hash, _next)) if self.plausible_successor(hash, now) => Verdict::Unknown,
            Some(_) => Verdict::Foreign,
        }
    }

    /// Whether `hash` could be our chain a fork AHEAD of what we announce: the
    /// one activation that turns one of our accepted hashes into it is a
    /// plausible fork time — at or past EIP-2124's timestamp threshold, within
    /// the fork watch's lookback and horizon, and on the beacon epoch grid when
    /// one is configured. Placed from the pin AND its successor, as the fork
    /// watch judges from both baselines: past the pinned time we announce the
    /// successor, but a network that rescheduled that fork keeps its nodes on
    /// the pin, and their next fork follows the pin.
    pub fn plausible_successor(&self, hash: [u8; 4], now: u64) -> bool {
        let hash = u32::from_be_bytes(hash);
        self.accepted
            .iter()
            .map(|ours| forkid::activation_of(u32::from_be_bytes(*ours), hash))
            .any(|t| self.plausible_time(t, now))
    }

    fn plausible_time(&self, t: u64, now: u64) -> bool {
        if t < forkid::TIMESTAMP_THRESHOLD
            || t < now.saturating_sub(LOOKBACK_SECONDS)
            || t > now.saturating_add(MAX_HORIZON_SECONDS)
        {
            return false;
        }
        self.epoch_seconds == 0
            || (t >= self.genesis_time
                && (t - self.genesis_time).is_multiple_of(self.epoch_seconds))
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
    /// The record's `tcp` and `tcp6` ports, if any: the node's own word on
    /// where it listens, which beats a NEIGHBORS entry's hearsay.
    pub tcp4: Option<u16>,
    pub tcp6: Option<u16>,
}

impl RemoteEnr {
    /// The TCP port to dial a node reached at `ip` (4 or 16 bytes): the
    /// family's own entry first, the other as a fallback; never 0.
    pub fn tcp_port_for(&self, ip: &[u8]) -> Option<u16> {
        let (own, other) = if ip.len() == 16 {
            (self.tcp6, self.tcp4)
        } else {
            (self.tcp4, self.tcp6)
        };
        own.or(other).filter(|&p| p != 0)
    }
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
        tcp4: enr.tcp4(),
        tcp6: enr.tcp6(),
    })
}

/// Our own ENR as RLP: identity from `key`, the given sequence number and
/// `eth` entry, no endpoint — a light client behind NAT does not know its
/// address, and a record without one is valid. It exists so the exchange is
/// symmetric (EIP-868 nodes answer bonded requesters); nobody asks for it in
/// practice, because our Ping/Pong carry no `enr-seq` and geth requests a
/// record only when an advertised seq is newer than the one it holds (and
/// keeps a record without an address at arm's length). Its seq restarts at 1
/// each process.
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

    const SEPOLIA_GENESIS: u64 = 1_655_733_600;
    const MAINNET_GENESIS: u64 = 1_606_824_023;
    const EPOCH: u64 = 32 * 12;
    const DAY: u64 = 24 * 3600;

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
        let f = ForkFilter::for_chain(pinned, next).with_epoch_grid(SEPOLIA_GENESIS, EPOCH);
        let successor = forkid::successor(u32::from_be_bytes(pinned), next).to_be_bytes();
        assert_eq!(f.accepted(), &[pinned, successor]);
        let now = next - 1;
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(pinned, next)), now),
            Verdict::Compatible
        );
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(successor, 0)), now),
            Verdict::Compatible
        );
        // A hash whose activation sits 500 days back, off any grid: another chain.
        let far = forkid::successor(u32::from_be_bytes(pinned), now - 500 * DAY + 1).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(far, 0)), now),
            Verdict::Foreign
        );
        // No entry, or one that does not parse: unknown, never foreign.
        assert_eq!(f.verdict(None, now), Verdict::Unknown);
        assert_eq!(f.verdict(Some(b"\x01"), now), Verdict::Unknown);
        // No pinned next: the pin alone.
        let m = ForkFilter::for_chain(forkid::MAINNET_FORK_ID_HASH, 0);
        assert_eq!(m.accepted(), &[forkid::MAINNET_FORK_ID_HASH]);
    }

    #[test]
    fn a_plausible_fork_ahead_of_the_pin_is_unknown_not_foreign() {
        // Mainnet pins no next fork; a fork this build does not know activates
        // at an epoch boundary two days from now and every upgraded node then
        // announces its successor hash. Those nodes must stay dialable (#491).
        let pin = forkid::MAINNET_FORK_ID_HASH;
        let f = ForkFilter::for_chain(pin, 0).with_epoch_grid(MAINNET_GENESIS, EPOCH);
        let now = MAINNET_GENESIS + 1_000_000 * EPOCH + 17;
        let aligned = MAINNET_GENESIS + (1_000_000 + 450) * EPOCH; // two days on, on the grid
        let ahead = forkid::successor(u32::from_be_bytes(pin), aligned).to_be_bytes();
        assert!(f.plausible_successor(ahead, now));
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(ahead, 0)), now),
            Verdict::Unknown
        );
        // The same activation one second off the grid: not a fork time.
        let off_grid = forkid::successor(u32::from_be_bytes(pin), aligned + 1).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(off_grid, 0)), now),
            Verdict::Foreign
        );
        // Past the horizon, or before the lookback: not plausible either.
        let too_far = forkid::successor(u32::from_be_bytes(pin), aligned + 401 * DAY).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(too_far, 0)), now),
            Verdict::Foreign
        );
        let too_old = forkid::successor(u32::from_be_bytes(pin), now - 401 * DAY).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(too_old, 0)), now),
            Verdict::Foreign
        );
        // Without a grid, any activation inside the window is plausible.
        let no_grid = ForkFilter::for_chain(pin, 0);
        assert_eq!(
            no_grid.verdict(Some(&eth_entry_rlp(off_grid, 0)), now),
            Verdict::Unknown
        );
        assert_eq!(
            no_grid.verdict(Some(&eth_entry_rlp(too_far, 0)), now),
            Verdict::Foreign
        );
    }

    #[test]
    fn plausibility_is_judged_from_the_hash_we_announce_now() {
        // Past the pinned next fork we announce the successor, so a fork
        // beyond THAT is placed from the successor, not from the pin.
        let pin = forkid::SEPOLIA_FORK_ID_HASH;
        let next = forkid::SEPOLIA_FORK_NEXT;
        let f = ForkFilter::for_chain(pin, next).with_epoch_grid(SEPOLIA_GENESIS, EPOCH);
        let successor = forkid::successor(u32::from_be_bytes(pin), next);
        let later = next + 100 * EPOCH;
        let beyond = forkid::successor(successor, later).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(beyond, 0)), next + 1),
            Verdict::Unknown
        );
    }

    #[test]
    fn a_rescheduled_pinned_fork_is_placed_from_the_pin() {
        // The build pins (pin, T); the network moves the fork to T' ten epochs
        // later. Past T we announce successor(pin, T), a hash no live node has;
        // after T' the nodes announce successor(pin, T') — placed from the
        // PIN, that is plausible, so they stay dialable.
        let pin = forkid::SEPOLIA_FORK_ID_HASH;
        let t = forkid::SEPOLIA_FORK_NEXT;
        let f = ForkFilter::for_chain(pin, t).with_epoch_grid(SEPOLIA_GENESIS, EPOCH);
        let moved = t + 10 * EPOCH;
        let after_move = forkid::successor(u32::from_be_bytes(pin), moved).to_be_bytes();
        let now = moved + 1;
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(after_move, 0)), now),
            Verdict::Unknown
        );
        // Two forks ahead of anything we announce: not placed.
        let twice =
            forkid::successor(u32::from_be_bytes(after_move), moved + 100 * EPOCH).to_be_bytes();
        assert_eq!(
            f.verdict(Some(&eth_entry_rlp(twice, 0)), now),
            Verdict::Foreign
        );
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
        // Both are what the filter itself accepts, on either side of the fork.
        for now in [forkid::SEPOLIA_FORK_NEXT - 1, forkid::SEPOLIA_FORK_NEXT] {
            assert_eq!(
                f.verdict(Some(&eth_entry_rlp(before.0, before.1)), now),
                Verdict::Compatible
            );
            assert_eq!(
                f.verdict(Some(&eth_entry_rlp(after.0, after.1)), now),
                Verdict::Compatible
            );
        }
    }

    #[test]
    fn a_local_enr_decodes_under_its_own_key_only() {
        let k = key(1);
        let eth = eth_entry_rlp([1, 2, 3, 4], 0);
        let raw = local_enr_rlp(&k, 7, &eth).unwrap();
        let remote = decode_enr(&raw, &k.public_key_bytes()).unwrap();
        assert_eq!(remote.seq, 7);
        assert_eq!(remote.eth.as_deref(), Some(&eth[..]));
        assert_eq!(remote.tcp_port_for(&[127, 0, 0, 1]), None, "our record names no endpoint");
        // Carried in a packet another node signed: refused.
        assert!(decode_enr(&raw, &key(2).public_key_bytes()).is_err());
        // Tampered: the signature no longer verifies.
        let mut tampered = raw.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(decode_enr(&tampered, &k.public_key_bytes()).is_err());
        assert!(decode_enr(b"", &k.public_key_bytes()).is_err());
    }

    #[test]
    fn a_records_tcp_port_is_read_by_address_family() {
        let k = key(3);
        let mut secret = k.secret_bytes();
        let signing = CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
        let build = |tcp4: Option<u16>, tcp6: Option<u16>| {
            let mut b = Enr::<CombinedKey>::builder();
            b.seq(1);
            if let Some(p) = tcp4 {
                b.tcp4(p);
            }
            if let Some(p) = tcp6 {
                b.tcp6(p);
            }
            let raw = alloy_rlp::encode(&b.build(&signing).unwrap());
            decode_enr(&raw, &k.public_key_bytes()).unwrap()
        };
        let v4 = [10, 0, 0, 1];
        let v6 = [0u8; 16];
        // Both named: each family its own.
        let both = build(Some(30303), Some(30306));
        assert_eq!(both.tcp_port_for(&v4), Some(30303));
        assert_eq!(both.tcp_port_for(&v6), Some(30306));
        // One named: the other family falls back to it.
        assert_eq!(build(Some(30303), None).tcp_port_for(&v6), Some(30303));
        assert_eq!(build(None, Some(30306)).tcp_port_for(&v4), Some(30306));
        // None named, or 0: no port to dial — the caller keeps what it has.
        assert_eq!(build(None, None).tcp_port_for(&v4), None);
        assert_eq!(build(Some(0), None).tcp_port_for(&v4), None);
        assert!(build(None, None).eth.is_none());
    }
}
