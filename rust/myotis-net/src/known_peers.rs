//! Long-known peers confirm a fresh checkpoint — the eclipse guard on the
//! STALE_ANCHOR recovery (docs/how-it-works/stale-anchor.md, *Confirmed by
//! long-known peers*).
//!
//! The checkpointz round ([`crate::checkpointz`]) is HTTPS: a network attacker
//! who controls this device's view of the internet can answer it, and one who
//! surrounds the node with its own libp2p peers (an eclipse) can make every
//! peer it meets agree. What such an attacker cannot do is answer as a peer
//! whose identity this node already knew: a libp2p peer ID is the hash of the
//! node's public key, and the Noise handshake proves possession of the key, so
//! a known ID can only be spoken for by its owner.
//!
//! So a fresh checkpoint is applied only when, besides every answering
//! checkpoint-sync server, at least one LONG-KNOWN peer names the same
//! finalized epoch and root in its `Status` (asked fresh, at the time of the
//! round). Long-known means (owner's ruling on #761, 2026-11-13):
//!
//! - **pinned**: the light-client peers this release pins by peer ID
//!   ([`crate::sync::release_pins`] — the compiled-in list, NOT
//!   `ChainConfig::static_peers`, which `MYOTIS_CL_STATIC_PEERS` may replace at
//!   runtime) — reviewed, and known before the anchor;
//! - **cached**: a peer in this device's CL peer cache whose ID was first seen
//!   at least [`LONG_KNOWN_MIN_AGE`] ago (the cache's `s<unix secs>` token).
//!
//! A long-known peer naming ANOTHER root for the same epoch is an alarm and
//! refuses the round, whatever else agreed; no override. A peer at another
//! epoch (finality moved during the round, or it lags) does not confirm; the
//! round is asked once more after a short wait, and long-known peers that
//! answered but still sit at other epochs refuse it too, with no override —
//! the servers and the peers this node trusts most disagree. Only when NO
//! long-known peer answered at all (none known, none reachable) is the
//! checkpoint refused as UNCONFIRMED and flagged by the host: an eclipse cannot
//! be ruled out. The user may then apply it anyway, explicitly; a remembered
//! choice never does.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};

use crate::checkpointz::FreshCheckpoint;
use crate::codec;
use crate::protocols;
use crate::reqresp::{ReqRespClient, RequestError};
use crate::status::StatusMessage;
use crate::sync::ChainConfig;

/// How long a cached peer's ID must have been known to count: a week. An
/// attacker would have had to sit in this device's cache, answering as a
/// light-client server, since a week before the park.
pub const LONG_KNOWN_MIN_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

/// How long one peer's Status may take, dial included.
const STATUS_DEADLINE: Duration = Duration::from_secs(15);

/// The wait before the one re-ask when peers only disagreed on the epoch.
const EPOCH_SKEW_RETRY: Duration = Duration::from_secs(20);

/// Peers asked at most, pinned first: the round is a check, not a census.
const MAX_ASKED: usize = 24;

/// Why a peer counts as long-known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownBecause {
    /// Pinned by peer ID in this release.
    Pinned,
    /// In this device's CL peer cache since `first_seen` (unix seconds).
    Cached { first_seen: u64 },
}

/// One long-known peer and where to reach it.
#[derive(Debug, Clone)]
pub struct KnownPeer {
    pub id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub because: KnownBecause,
}

impl KnownPeer {
    /// A short, stable label for logs and the host: `pinned 16Uiu2…a1b2c3`.
    pub fn label(&self) -> String {
        let id = self.id.to_string();
        let short = if id.len() > 14 { format!("{}…{}", &id[..6], &id[id.len() - 6..]) } else { id };
        match self.because {
            KnownBecause::Pinned => format!("pinned {short}"),
            KnownBecause::Cached { .. } => format!("known {short}"),
        }
    }
}

/// Split a `/…/p2p/<id>` multiaddr into the peer ID and its dial address.
fn split_peer(multiaddr: &str) -> Option<(PeerId, Multiaddr)> {
    let addr: Multiaddr = multiaddr.parse().ok()?;
    let mut base = Multiaddr::empty();
    let mut id = None;
    for proto in addr.iter() {
        if let libp2p::multiaddr::Protocol::P2p(p) = proto {
            id = Some(p);
        } else {
            base.push(proto);
        }
    }
    Some((id?, base))
}

/// The long-known peers of this network, pinned first, then cached ones by
/// age (oldest first). `cached` is `(multiaddr, first_seen)` from the CL peer
/// cache; one peer ID under several addresses is one peer, known since its
/// earliest sighting. Pure, for tests.
pub fn select(static_peers: &[String], cached: &[(String, u64)], now_secs: u64) -> Vec<KnownPeer> {
    let mut out: Vec<KnownPeer> = Vec::new();
    let mut seen: HashSet<PeerId> = HashSet::new();
    for s in static_peers {
        let Some((id, addr)) = split_peer(s) else { continue };
        if let Some(p) = out.iter_mut().find(|p| p.id == id) {
            p.addrs.push(addr);
            continue;
        }
        seen.insert(id);
        out.push(KnownPeer { id, addrs: vec![addr], because: KnownBecause::Pinned });
    }
    let cutoff = now_secs.saturating_sub(LONG_KNOWN_MIN_AGE.as_secs());
    let mut by_id: BTreeMap<String, (PeerId, Vec<Multiaddr>, u64)> = BTreeMap::new();
    for (s, first_seen) in cached {
        let Some((id, addr)) = split_peer(s) else { continue };
        if seen.contains(&id) {
            continue;
        }
        let e = by_id.entry(id.to_string()).or_insert((id, Vec::new(), *first_seen));
        e.1.push(addr);
        e.2 = e.2.min(*first_seen);
    }
    let mut cached_known: Vec<KnownPeer> = by_id
        .into_values()
        .filter(|(_, _, first)| *first <= cutoff)
        .map(|(id, addrs, first_seen)| KnownPeer { id, addrs, because: KnownBecause::Cached { first_seen } })
        .collect();
    cached_known.sort_by_key(|p| match p.because {
        KnownBecause::Cached { first_seen } => first_seen,
        KnownBecause::Pinned => 0,
    });
    out.extend(cached_known);
    out.truncate(MAX_ASKED);
    out
}

/// This network's long-known peers right now: its pins and the aged entries
/// of its CL peer cache file (read, never written, here).
pub fn long_known_peers(config: &ChainConfig) -> Vec<KnownPeer> {
    // Read-only: the first-seen tokens alone, no cache instance (whose load
    // stamps and marks dirty) and no log line per round.
    let cached = config
        .cl_peer_cache_path
        .as_ref()
        .map(|p| crate::clcache::read_first_seen(p))
        .unwrap_or_default();
    let pins: Vec<String> = crate::sync::release_pins(&config.name).iter().map(|s| s.to_string()).collect();
    select(&pins, &cached, unix_now())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What one long-known peer said about the candidate checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerVerdict {
    /// Same finalized epoch and root.
    Confirms,
    /// Same finalized epoch, ANOTHER root: the alarm.
    Contradicts { root: [u8; 32] },
    /// Another finalized epoch: neither.
    OtherEpoch { epoch: u64 },
    /// No usable Status.
    NoAnswer { why: String },
}

/// The verdict of one peer's finalized `(epoch, root)` against the candidate.
pub fn judge(reported: Result<(u64, [u8; 32]), String>, epoch: u64, root: [u8; 32]) -> PeerVerdict {
    match reported {
        Ok((e, r)) if e == epoch && r == root => PeerVerdict::Confirms,
        Ok((e, r)) if e == epoch => PeerVerdict::Contradicts { root: r },
        Ok((e, _)) => PeerVerdict::OtherEpoch { epoch: e },
        Err(why) => PeerVerdict::NoAnswer { why },
    }
}

enum AskError {
    Request(RequestError),
    Deadline,
}

impl std::fmt::Display for AskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(e) => write!(f, "{e}"),
            Self::Deadline => write!(f, "no answer in time"),
        }
    }
}

/// Ask one peer for its Status (v2, then v1) and return its finalized
/// `(epoch, root)`.
pub async fn peer_finalized(
    client: &ReqRespClient,
    ours: &StatusMessage,
    peer: &KnownPeer,
) -> Result<(u64, [u8; 32]), String> {
    let ask = |protocol: &'static str, wire: Vec<u8>| {
        let client = client.clone();
        let (id, addrs) = (peer.id, peer.addrs.clone());
        async move {
            match tokio::time::timeout(STATUS_DEADLINE, client.request_raw_at(id, addrs, protocol, wire)).await {
                Ok(Ok(raw)) => Ok(raw),
                Ok(Err(e)) => Err(AskError::Request(e)),
                Err(_) => Err(AskError::Deadline),
            }
        }
    };
    let decoded = match ask(protocols::STATUS_V2, codec::encode_request(&ours.encode())).await {
        Ok(raw) => codec::decode_response(&raw, false)
            .map_err(|e| format!("{e:?}"))
            .and_then(|d| StatusMessage::decode(&d.ssz_payload)),
        // v1 only for a peer that does not speak v2 — a timeout or a failed
        // dial would only fail again and double this peer's wait.
        Err(AskError::Request(RequestError::UnsupportedProtocol)) => {
            match ask(protocols::STATUS_V1, codec::encode_request(&ours.encode_v1())).await {
                Ok(raw) => codec::decode_response(&raw, false)
                    .map_err(|e| format!("{e:?}"))
                    .and_then(|d| StatusMessage::decode_v1(&d.ssz_payload)),
                Err(e) => Err(format!("status v1: {e}")),
            }
        }
        Err(e) => Err(format!("status: {e}")),
    }?;
    Ok((decoded.finalized_epoch, decoded.finalized_root))
}

/// Every asked peer's verdict, in the order asked.
#[derive(Debug, Clone, Default)]
pub struct Confirmation {
    pub verdicts: Vec<(String, PeerVerdict)>,
}

impl Confirmation {
    pub fn confirmed_by(&self) -> Vec<String> {
        self.verdicts.iter().filter(|(_, v)| *v == PeerVerdict::Confirms).map(|(l, _)| l.clone()).collect()
    }
    pub fn contradictions(&self) -> Vec<(String, [u8; 32])> {
        self.verdicts
            .iter()
            .filter_map(|(l, v)| match v {
                PeerVerdict::Contradicts { root } => Some((l.clone(), *root)),
                _ => None,
            })
            .collect()
    }
    fn any_other_epoch(&self) -> bool {
        self.verdicts.iter().any(|(_, v)| matches!(v, PeerVerdict::OtherEpoch { .. }))
    }
    /// One line for the user: who confirmed, who was elsewhere, who did not answer.
    pub fn summary(&self) -> String {
        let (mut other, mut silent) = (0, 0);
        for (_, v) in &self.verdicts {
            match v {
                PeerVerdict::OtherEpoch { .. } => other += 1,
                PeerVerdict::NoAnswer { .. } => silent += 1,
                _ => {}
            }
        }
        format!(
            "{} long-known peer(s) asked: {} confirmed, {} at another epoch, {} did not answer",
            self.verdicts.len(),
            self.confirmed_by().len(),
            other,
            silent
        )
    }
}

/// Ask every peer at once and judge each against `(epoch, root)`.
pub async fn confirm(
    client: &ReqRespClient,
    ours: &StatusMessage,
    peers: &[KnownPeer],
    epoch: u64,
    root: [u8; 32],
) -> Confirmation {
    let asks = peers.iter().map(|p| async move {
        let r = peer_finalized(client, ours, p).await;
        (p.label(), judge(r, epoch, root))
    });
    Confirmation { verdicts: futures::future::join_all(asks).await }
}

/// A fresh checkpoint the servers agree on AND long-known peers confirm.
#[derive(Debug, Clone)]
pub struct ConfirmedCheckpoint {
    pub fresh: FreshCheckpoint,
    /// The long-known peers that named the same epoch and root. Empty only
    /// when the caller allowed an unconfirmed checkpoint.
    pub confirmed_by: Vec<String>,
}

/// Why a fresh checkpoint was not applied.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub reason: String,
    /// The servers agreed but no long-known peer confirmed (and none
    /// contradicted): the host flags it and may offer "use it anyway".
    pub unconfirmed: bool,
}

impl Refusal {
    fn plain(reason: String) -> Self {
        Self { reason, unconfirmed: false }
    }
}

fn hex(root: &[u8; 32]) -> String {
    let s: String = root.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…{}", &s[..8], &s[56..])
}

/// The whole recovery round: the servers' unanimous checkpoint
/// ([`crate::checkpointz::fetch_checked`]), then the Status of every
/// long-known peer; asked once more after [`EPOCH_SKEW_RETRY`] when peers were
/// only at another epoch and `reask` (the sync loop's unattended path passes
/// false: it must not hold the park, and it retries on its own schedule).
///
/// - A long-known peer naming another root for the epoch refuses: an alarm,
///   never overridable.
/// - Long-known peers that answered, but none at the servers' epoch even after
///   the re-ask, refuse too: the peers this node trusts most and the servers
///   disagree, which no click may outweigh (an attacker answering the HTTPS
///   round can name an epoch the honest peers never reach).
/// - Only when NO long-known peer answered at all (none known, none
///   reachable) is the refusal UNCONFIRMED, which `allow_unconfirmed` — the
///   user's explicit "use it anyway" — may override.
pub async fn fetch_confirmed(
    config: &ChainConfig,
    client: &ReqRespClient,
    ours: &StatusMessage,
    allow_unconfirmed: bool,
    reask: bool,
) -> Result<ConfirmedCheckpoint, Refusal> {
    let peers = long_known_peers(config);
    let mut last: Option<(FreshCheckpoint, Confirmation)> = None;
    for round in 0..(if reask { 2 } else { 1 }) {
        if round > 0 {
            tokio::time::sleep(EPOCH_SKEW_RETRY).await;
        }
        // The servers' answer comes first; the peers are asked with the
        // epoch it names as soon as it is known, and the HTTPS round is
        // seconds, so both describe the same moment of the chain.
        let fresh = crate::checkpointz::fetch_checked(config).await.map_err(Refusal::plain)?;
        let c = confirm(client, ours, &peers, fresh.epoch, fresh.root).await;
        let contradictions = c.contradictions();
        if !contradictions.is_empty() {
            let named: Vec<String> = contradictions.iter().map(|(l, r)| format!("{l} names {}", hex(r))).collect();
            return Err(Refusal::plain(format!(
                "ALARM: long-known peers name another finalized root for epoch {} than every \
                 checkpoint-sync server ({}): {}. Nothing applied.",
                fresh.epoch,
                hex(&fresh.root),
                named.join("; ")
            )));
        }
        let confirmed_by = c.confirmed_by();
        if !confirmed_by.is_empty() {
            tracing::info!(epoch = fresh.epoch, confirmed_by = ?confirmed_by,
                "fresh checkpoint confirmed by long-known peers");
            return Ok(ConfirmedCheckpoint { fresh, confirmed_by });
        }
        let retry = c.any_other_epoch();
        last = Some((fresh, c));
        if !retry {
            break;
        }
    }
    let Some((fresh, c)) = last else {
        return Err(Refusal::plain("no round completed".into()));
    };
    settle(fresh, &c, peers.len(), allow_unconfirmed)
}

/// The last round's outcome when nothing confirmed and nothing contradicted:
/// long-known peers that answered at other epochs refuse (no override); none
/// answering refuses as UNCONFIRMED unless `allow_unconfirmed`. Pure, for tests.
fn settle(
    fresh: FreshCheckpoint,
    c: &Confirmation,
    known: usize,
    allow_unconfirmed: bool,
) -> Result<ConfirmedCheckpoint, Refusal> {
    if c.any_other_epoch() {
        let named: Vec<String> = c
            .verdicts
            .iter()
            .filter_map(|(l, v)| match v {
                PeerVerdict::OtherEpoch { epoch } => Some(format!("{l} at epoch {epoch}")),
                _ => None,
            })
            .collect();
        return Err(Refusal::plain(format!(
            "long-known peers disagree with the checkpoint-sync servers: the servers name epoch {} \
             ({}), the peers this node has long known name other epochs ({}). Nothing applied — \
             try again in a minute; if it persists, the servers or this network connection \
             cannot be trusted.",
            fresh.epoch,
            hex(&fresh.root),
            named.join("; ")
        )));
    }
    if allow_unconfirmed {
        tracing::warn!(epoch = fresh.epoch, summary = %c.summary(),
            "fresh checkpoint applied WITHOUT long-known peer confirmation, on the user's explicit request");
        return Ok(ConfirmedCheckpoint { fresh, confirmed_by: Vec::new() });
    }
    let why = if known == 0 {
        "this node knows no long-known peer for this network (none pinned in this release, none \
         in its peer cache for a week)"
            .to_string()
    } else {
        format!("none of the {} it knows answered", known)
    };
    Err(Refusal {
        reason: format!(
            "UNCONFIRMED: every checkpoint-sync server names epoch {} ({}), but no long-known peer \
             confirmed it — {why}. An eclipse attack cannot be ruled out.",
            fresh.epoch,
            hex(&fresh.root)
        ),
        unconfirmed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> PeerId {
        let kp = libp2p::identity::Keypair::ed25519_from_bytes([n; 32]).unwrap();
        kp.public().to_peer_id()
    }

    fn maddr(n: u8) -> String {
        format!("/ip4/10.0.0.{n}/tcp/9000/p2p/{}", id(n))
    }

    #[test]
    fn pinned_first_cached_only_when_a_week_old_and_one_entry_per_id() {
        let now = 10 * 24 * 3600;
        let week = LONG_KNOWN_MIN_AGE.as_secs();
        let pinned = vec![maddr(1)];
        let cached = vec![
            (maddr(1), 0),                                       // pinned already: not twice
            (maddr(2), now - week),                              // exactly a week: counts
            (maddr(3), now - week + 1),                          // a second short: does not
            (format!("/ip4/10.9.9.9/tcp/1/p2p/{}", id(2)), now), // same ID, newer address: one peer
            ("/ip4/1.2.3.4/tcp/1".into(), 0),                    // no peer ID: ignored
        ];
        let got = select(&pinned, &cached, now);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].id, id(1));
        assert_eq!(got[0].because, KnownBecause::Pinned);
        assert_eq!(got[1].id, id(2));
        assert_eq!(got[1].because, KnownBecause::Cached { first_seen: now - week });
        assert_eq!(got[1].addrs.len(), 2, "both addresses of the one ID are dialable");
        assert!(got[0].label().starts_with("pinned "));
        assert!(got[1].label().starts_with("known "));
    }

    #[test]
    fn a_fresh_install_knows_only_the_pins() {
        assert!(select(&[], &[(maddr(4), 1_000)], 1_000).is_empty());
        assert_eq!(select(&[maddr(5)], &[], 0).len(), 1);
    }

    #[test]
    fn verdicts() {
        let r = [7u8; 32];
        assert_eq!(judge(Ok((5, r)), 5, r), PeerVerdict::Confirms);
        assert_eq!(judge(Ok((5, [8; 32])), 5, r), PeerVerdict::Contradicts { root: [8; 32] });
        assert_eq!(judge(Ok((6, [8; 32])), 5, r), PeerVerdict::OtherEpoch { epoch: 6 });
        assert!(matches!(judge(Err("x".into()), 5, r), PeerVerdict::NoAnswer { .. }));
    }

    fn fresh() -> FreshCheckpoint {
        FreshCheckpoint { root: [7; 32], epoch: 5, slot: 160, operators: vec!["a.io".into(), "b.io".into()] }
    }

    #[test]
    fn peers_that_answered_at_other_epochs_refuse_even_the_override() {
        let c = Confirmation { verdicts: vec![("pinned x".into(), PeerVerdict::OtherEpoch { epoch: 9 })] };
        let r = settle(fresh(), &c, 1, true).unwrap_err();
        assert!(!r.unconfirmed, "no override for a disagreement: {}", r.reason);
        assert!(r.reason.contains("pinned x at epoch 9"), "{}", r.reason);
    }

    #[test]
    fn nobody_answering_is_unconfirmed_and_only_the_override_applies_it() {
        let c = Confirmation { verdicts: vec![("pinned x".into(), PeerVerdict::NoAnswer { why: "timeout".into() })] };
        let r = settle(fresh(), &c, 1, false).unwrap_err();
        assert!(r.unconfirmed, "{}", r.reason);
        assert!(r.reason.contains("none of the 1 it knows answered"), "{}", r.reason);
        let ok = settle(fresh(), &c, 1, true).unwrap();
        assert!(ok.confirmed_by.is_empty());
        let none_known = settle(fresh(), &Confirmation::default(), 0, false).unwrap_err();
        assert!(none_known.unconfirmed && none_known.reason.contains("knows no long-known peer"));
    }

    #[test]
    fn the_summary_counts_each_kind() {
        let c = Confirmation {
            verdicts: vec![
                ("a".into(), PeerVerdict::Confirms),
                ("b".into(), PeerVerdict::OtherEpoch { epoch: 9 }),
                ("c".into(), PeerVerdict::NoAnswer { why: "timeout".into() }),
            ],
        };
        assert_eq!(c.confirmed_by(), vec!["a".to_string()]);
        assert!(c.contradictions().is_empty());
        assert_eq!(c.summary(), "3 long-known peer(s) asked: 1 confirmed, 1 at another epoch, 1 did not answer");
    }
}
