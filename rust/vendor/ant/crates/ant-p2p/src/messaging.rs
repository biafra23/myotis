//! Message dispatch for the GSOC/PSS lurker.
//!
//! The lurker pulls chunks out of a target neighborhood bin (see
//! [`crate::pullsync`]) and hands each one here. This module is the pure,
//! side-effect-free classifier that turns a delivered chunk into a
//! decoded application message — the same decision bee makes in its
//! pushsync/pullsync handlers, where a valid CAC goes to `pss.TryUnwrap`
//! and a valid SOC goes to the `gsoc` dispatcher.
//!
//! Two subscriptions drive it:
//!
//! - **GSOC**: a set of watched SOC addresses (`keccak256(id ‖ owner)`).
//!   A delivered SOC whose address is watched yields its inner CAC
//!   payload (bee's gsoc handler strips the 8-byte span and delivers the
//!   rest). We re-validate the SOC signature so a peer can't inject a
//!   payload under someone else's address.
//! - **PSS**: this node's PSS secret plus the registered topics. A
//!   delivered CAC is run through [`ant_crypto::pss::unwrap`]; a hit
//!   yields the decrypted message and the matching topic.
//!
//! Matching is by content, not by trusting the delivering peer: GSOC
//! addresses are recomputed from the chunk's own id+owner and PSS
//! messages must pass the topic hint + integrity check.

use ant_crypto::pss;
use ant_crypto::{keccak256, soc_valid, SOC_HEADER_SIZE, SOC_ID_SIZE, SPAN_SIZE};
use std::collections::{BTreeSet, HashSet};

/// What the lurker is currently listening for.
#[derive(Clone, Default)]
pub struct WatchState {
    /// Watched GSOC SOC addresses (`keccak256(id ‖ owner)`).
    pub gsoc_addresses: HashSet<[u8; 32]>,
    /// Registered PSS topics (`keccak256(topic_string)`).
    pub pss_topics: Vec<[u8; 32]>,
    /// This node's PSS secret, for messages encrypted directly to the
    /// node's key. `None` still receives **topic-broadcast** PSS (messages
    /// with no explicit recipient, decryptable via the topic-derived key).
    pub pss_secret: Option<[u8; 32]>,
    /// **Mailbox mode** request (a subscriber's own watch): sweep a
    /// bounded trojan-bin backlog on subscribe, so PSS messages sent
    /// while this receiver was offline are recovered — a recent-history
    /// window whose reach depends on how busy the swept bin is (see
    /// `lurker::HISTORY_BACKLOG`). It is **per subscriber**: the registry
    /// stamps the request with a [`Self::history_seq`] ticket and the
    /// shared lurker opens a mailbox *campaign* for it (also when the
    /// subscriber attaches to an already-running lurker). A campaign is
    /// not a single pass: it sweeps each covering PSS (peer, bin) once,
    /// **including peers that join the covering set within
    /// `lurker::MAILBOX_SETTLE` of its first sweep** (the neighborhood's
    /// storers typically connect seconds after a cold subscribe), and
    /// re-sweeps (a bounded number of times) a (peer, bin) whose sweep
    /// ended early, even if that failure is reported just after the window
    /// closed. Past the window, peer churn only starts live pullers
    /// (they always tail from the cursor), never another backlog sweep.
    /// A campaign whose ticket holders have all unsubscribed is
    /// cancelled (see [`Self::history_held`]). The swept messages go only
    /// to the subscriber(s) whose ticket the campaign serves — never to
    /// live-only or GSOC subscribers on the same lurker. PSS only: a GSOC
    /// watcher wants the latest SOC value, not every historical version.
    /// Not merged into the union watch (the union carries tickets only).
    pub history: bool,
    /// Registry-assigned mailbox ticket for a [`Self::history`] request
    /// (`0` = none). Tickets are monotonic per registry; on the union
    /// watch this is the **highest** outstanding ticket, and the lurker
    /// opens a campaign whenever it exceeds the last ticket it already
    /// opened one for.
    pub history_seq: u64,
    /// **Union watch only:** the tickets of the history subscribers still
    /// attached. The lurker cancels a mailbox campaign none of whose
    /// tickets is in here any more — its output would be routed to
    /// nobody. Empty on a subscriber's own watch.
    pub history_held: BTreeSet<u64>,
}

impl WatchState {
    /// Whether anything is being watched — lets the driver skip the pull
    /// loop entirely when idle. Registered topics count even without a
    /// node secret (topic-broadcast reception needs none).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.gsoc_addresses.is_empty() && self.pss_topics.is_empty()
    }

    /// Grow this watch to also cover `other` — the union operation the
    /// lurker registry applies when a subscriber attaches to an
    /// existing neighborhood lurker.
    pub fn merge_from(&mut self, other: &WatchState) {
        self.gsoc_addresses
            .extend(other.gsoc_addresses.iter().copied());
        for t in &other.pss_topics {
            if !self.pss_topics.contains(t) {
                self.pss_topics.push(*t);
            }
        }
        if self.pss_secret.is_none() {
            self.pss_secret = other.pss_secret;
        }
        // The union carries the newest mailbox ticket, so the lurker
        // sees a fresh request and runs one sweep for it. `history`
        // itself is per-subscriber and deliberately NOT unioned.
        self.history_seq = self.history_seq.max(other.history_seq);
        // ...and every still-attached subscriber's ticket, so the lurker
        // can cancel campaigns whose requesters have all left.
        self.history_held.extend(other.history_held.iter().copied());
        if other.history_seq != 0 {
            self.history_held.insert(other.history_seq);
        }
    }
}

/// A decoded message ready to hand to a subscriber.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedMessage {
    /// A GSOC update to a watched address; `payload` is the inner CAC
    /// content (span stripped).
    Gsoc { address: [u8; 32], payload: Vec<u8> },
    /// A PSS message decrypted under one of our topics.
    Pss { topic: [u8; 32], message: Vec<u8> },
}

/// Classify one delivered chunk against the watch state. Returns the
/// decoded message if it matches a GSOC address or a PSS topic, else
/// `None` (the overwhelmingly common case for neighborhood traffic we
/// aren't the target of).
///
/// `address` is the chunk's routed address; `data` is its wire data
/// (`span(8) ‖ payload` for a CAC, or `id(32) ‖ sig(65) ‖ inner_cac` for
/// a SOC — the two forms bee's handlers distinguish).
///
/// Callers must hand in chunks whose `data` has already been validated
/// against `address` (pullsync's `accept_delivery` does — CAC BMT or SOC
/// self-binding), so `address` here is a genuine content binding; GSOC
/// additionally re-verifies the SOC signature below.
#[must_use]
pub fn classify(address: &[u8; 32], data: &[u8], watch: &WatchState) -> Option<DecodedMessage> {
    // GSOC: a single-owner chunk whose self-bound address we watch.
    if let Some(msg) = classify_gsoc(address, data, watch) {
        return Some(msg);
    }
    // PSS: a trojan CAC addressed to one of our topics.
    classify_pss(data, watch)
}

fn classify_gsoc(address: &[u8; 32], data: &[u8], watch: &WatchState) -> Option<DecodedMessage> {
    if watch.gsoc_addresses.is_empty() || !watch.gsoc_addresses.contains(address) {
        return None;
    }
    // Re-validate the SOC self-binding: the delivered wire must actually
    // hash+recover to this address, or a peer is spoofing.
    if !soc_valid(address, data) {
        return None;
    }
    // Inner CAC = data[SOC_HEADER..]; its payload is everything past the
    // 8-byte span (bee's gsoc handler: `WrappedChunk().Data()[SpanSize:]`).
    let inner = data.get(SOC_HEADER_SIZE..)?;
    let payload = inner.get(SPAN_SIZE..)?.to_vec();
    Some(DecodedMessage::Gsoc {
        address: *address,
        payload,
    })
}

fn classify_pss(data: &[u8], watch: &WatchState) -> Option<DecodedMessage> {
    if watch.pss_topics.is_empty() || data.len() != pss::TROJAN_DATA_SIZE {
        return None;
    }
    // With no node secret, `unwrap` still tries the topic-derived key, so
    // topic-broadcast messages are received; a zero secret is rejected by
    // the direct ECDH path and falls through to that fallback.
    let secret = watch.pss_secret.unwrap_or([0u8; 32]);
    let (topic, message) = pss::unwrap(&secret, data, &watch.pss_topics)?;
    Some(DecodedMessage::Pss { topic, message })
}

/// Convenience: the SOC address an `(identifier, owner)` pair resolves
/// to, for callers building a GSOC watch set — `keccak256(id ‖ owner)`.
#[must_use]
pub fn gsoc_watch_address(identifier: &[u8; SOC_ID_SIZE], owner: &[u8; 20]) -> [u8; 32] {
    let mut input = [0u8; SOC_ID_SIZE + 20];
    input[..SOC_ID_SIZE].copy_from_slice(identifier);
    input[SOC_ID_SIZE..].copy_from_slice(owner);
    keccak256(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_crypto::gsoc::{build_gsoc_chunk, gsoc_mine};
    use ant_crypto::pss::{topic_from_string, wrap, Recipient};
    use ant_crypto::{ethereum_address_from_public_key, SECP256K1_SECRET_LEN};
    use k256::ecdsa::{SigningKey, VerifyingKey};

    fn owner_of(secret: &[u8; SECP256K1_SECRET_LEN]) -> [u8; 20] {
        let sk = SigningKey::from_bytes(secret.into()).unwrap();
        ethereum_address_from_public_key(&VerifyingKey::from(&sk))
    }

    #[test]
    fn decodes_a_watched_gsoc_update() {
        // A sender mines a key into some target neighborhood and signs an
        // update; the lurker watching that SOC address decodes it.
        let overlay = [0x42u8; 32];
        let identifier = [0x11u8; 32];
        let secret = gsoc_mine(&overlay, &identifier, 8).unwrap();
        let chunk = build_gsoc_chunk(&secret, &identifier, b"gsoc payload").unwrap();

        let watch = WatchState {
            gsoc_addresses: HashSet::from([chunk.address]),
            ..Default::default()
        };
        let got = classify(&chunk.address, &chunk.wire, &watch);
        assert_eq!(
            got,
            Some(DecodedMessage::Gsoc {
                address: chunk.address,
                payload: b"gsoc payload".to_vec(),
            })
        );

        // The watch address matches the (identifier, owner) helper.
        let owner = owner_of(&secret);
        assert_eq!(gsoc_watch_address(&identifier, &owner), chunk.address);
    }

    #[test]
    fn ignores_unwatched_gsoc_and_spoofed_address() {
        let overlay = [0x42u8; 32];
        let identifier = [0x22u8; 32];
        let secret = gsoc_mine(&overlay, &identifier, 8).unwrap();
        let chunk = build_gsoc_chunk(&secret, &identifier, b"x").unwrap();

        // Not watching this address → ignored.
        let empty = WatchState::default();
        assert!(classify(&chunk.address, &chunk.wire, &empty).is_none());

        // Watching a different address, but delivered under it → soc_valid
        // fails the self-bind, so no spoof leaks through.
        let watch = WatchState {
            gsoc_addresses: HashSet::from([[0x99u8; 32]]),
            ..Default::default()
        };
        assert!(classify(&[0x99u8; 32], &chunk.wire, &watch).is_none());
    }

    #[test]
    fn decodes_a_pss_message_for_registered_topic() {
        let topic = topic_from_string("lurker-topic");
        let secret = [0x07u8; 32];
        let sk = SigningKey::from_bytes(&secret.into()).unwrap();
        let pk = k256::PublicKey::from(&VerifyingKey::from(&sk));
        let (address, data) =
            wrap(&topic, b"secret pss", &Recipient::Key(pk), &[vec![0x00]]).unwrap();

        let watch = WatchState {
            pss_topics: vec![topic],
            pss_secret: Some(secret),
            ..Default::default()
        };
        let got = classify(&address, &data, &watch);
        assert_eq!(
            got,
            Some(DecodedMessage::Pss {
                topic,
                message: b"secret pss".to_vec(),
            })
        );

        // Wrong secret / unregistered topic → nothing.
        let other = WatchState {
            pss_topics: vec![topic_from_string("different")],
            pss_secret: Some(secret),
            ..Default::default()
        };
        assert!(classify(&address, &data, &other).is_none());
    }

    #[test]
    fn merge_from_unions_topics_secret_and_newest_history_ticket() {
        let mut base = WatchState {
            pss_topics: vec![[1u8; 32]],
            ..Default::default()
        };
        // A mailbox subscriber attaches: the union picks up its ticket
        // (so the lurker runs a sweep for it) and grows its topics.
        base.merge_from(&WatchState {
            pss_topics: vec![[2u8; 32]],
            pss_secret: Some([9u8; 32]),
            history: true,
            history_seq: 7,
            ..Default::default()
        });
        assert_eq!(base.history_seq, 7);
        assert!(!base.history, "the per-subscriber request is not unioned");
        assert_eq!(base.pss_topics, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(base.pss_secret, Some([9u8; 32]));

        // An older ticket (or none) never rolls the union's ticket back.
        base.merge_from(&WatchState {
            gsoc_addresses: HashSet::from([[3u8; 32]]),
            history_seq: 3,
            ..Default::default()
        });
        assert_eq!(base.history_seq, 7);
        assert_eq!(base.history_held, BTreeSet::from([3, 7]));
        assert!(base.gsoc_addresses.contains(&[3u8; 32]));
    }

    #[test]
    fn empty_watch_short_circuits() {
        assert!(WatchState::default().is_empty());
        // Registered topics count as active even without a node secret —
        // topic-broadcast reception needs none.
        let only_topic = WatchState {
            pss_topics: vec![[0u8; 32]],
            pss_secret: None,
            ..Default::default()
        };
        assert!(!only_topic.is_empty());
    }

    #[test]
    fn decodes_topic_broadcast_pss_without_node_secret() {
        // A sender broadcasts to a topic (no recipient); a lurker with the
        // topic registered but NO node secret still decodes it.
        let topic = topic_from_string("broadcast-room");
        let (address, data) = wrap(
            &topic,
            b"hello room",
            &Recipient::TopicDerived,
            &[vec![0x00]],
        )
        .unwrap();
        let watch = WatchState {
            pss_topics: vec![topic],
            pss_secret: None,
            ..Default::default()
        };
        assert_eq!(
            classify(&address, &data, &watch),
            Some(DecodedMessage::Pss {
                topic,
                message: b"hello room".to_vec(),
            })
        );
    }
}
