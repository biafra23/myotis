//! Shared lurker registry — one pull pipeline per neighborhood, fanned
//! out to every subscriber.
//!
//! Without this, N WebSocket subscriptions on the same rendezvous room
//! each ran their own lurker: N × (covering peers × bins) pull streams
//! and, in PSS mode, N copies of every candidate chunk download. The
//! registry keys lurkers by **target neighborhood**: the first
//! subscriber spawns the lurker, later ones attach to it, and a
//! dispatcher forwards each decoded message to exactly the subscribers
//! whose watch matches it. The lurker itself watches the **union** of
//! all subscribers' watch sets (shared `RwLock<WatchState>`, re-read
//! per pull round, so joins and leaves take effect without restarting
//! pullers or losing resume positions).
//!
//! Budgets enforced here:
//! - at most [`MAX_LURKER_NEIGHBORHOODS`] distinct targets have live
//!   pull pipelines (subscribers per target are unbounded — attaching
//!   is just a channel);
//! - a slow subscriber sheds: fan-out uses `try_send`, so a client
//!   that stopped draining its 64-message buffer loses messages
//!   instead of head-of-line-blocking every other subscriber. Shedding
//!   is **silent by design**: the WebSocket wire carries bee-compatible
//!   binary payload frames only, so there is no in-band "you lagged"
//!   signal to send without breaking bee-js clients — delivery is
//!   documented as best-effort/at-least-once and dropped messages are
//!   logged server-side.
//!
//! Known limitation: the union watch carries at most one `pss_secret`
//! ([`WatchState::merge_from`] keeps the first) — moot today because
//! every subscription on one node shares the node's secret (or none),
//! but a future per-subscriber-key design would need a `Vec` here.

use crate::messaging::{DecodedMessage, WatchState};
use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Cap on distinct neighborhoods with live pull pipelines. Each one is
/// multi-peer pull streams and (PSS mode) whole-bin downloads; more
/// subscribers on an existing neighborhood cost nothing extra *to pull*.
pub const MAX_LURKER_NEIGHBORHOODS: usize = 8;
/// Cap on subscribers attached to one neighborhood. "Attaching is
/// cheap" only for the shared pull; each subscriber still adds a
/// fan-out channel and a routing pass per delivered message, and its
/// topics widen the per-candidate PSS unwrap work — so it isn't *free*.
/// Bounds an unauthenticated same-neighborhood subscription flood.
const MAX_SUBSCRIBERS_PER_TARGET: usize = 64;
/// Cap on the size of a lurker's union watch (distinct GSOC addresses +
/// PSS topics). Every registered PSS topic is one more ECDH/unwrap
/// attempt on *every* candidate chunk in the neighborhood, so an
/// unbounded topic set is a CPU-amplification vector; refuse a
/// subscription that would push the union past this.
const MAX_UNION_WATCH: usize = 256;
/// Per-subscriber fan-out buffer. A subscriber this far behind sheds.
const SUBSCRIBER_BUFFER: usize = 64;
/// How often the dispatcher sweeps for subscribers that left silently
/// (receiver dropped with no message ever flowing to notice it by). It
/// bounds how long a departed subscriber's mailbox ticket stays in the
/// union's `history_held` — i.e. how long an orphaned campaign keeps
/// sweeping for nobody (plus the lurker's own `MAILBOX_POLL`) — and how
/// long a quiet lurker outlives its last subscriber. Each tick rebuilds
/// the union from at most `MAX_SUBSCRIBERS_PER_TARGET` small watches —
/// cheap. (A departure `subscribe` pruned itself while attaching is
/// also folded in here: that path doesn't rebuild the union.)
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// The union watch a registry lurker follows, shared so the registry
/// can grow/shrink it as subscribers come and go.
pub type SharedWatch = Arc<RwLock<WatchState>>;

/// One decoded message out of a lurker, with its audience.
#[derive(Clone, Debug)]
pub struct Delivery {
    pub msg: DecodedMessage,
    /// `None`: live traffic, for every subscriber whose watch matches.
    /// `Some(tickets)`: a mailbox-sweep (backlog) message, only for
    /// subscribers whose [`WatchState::history_seq`] ticket that sweep
    /// served — a live-only or GSOC subscriber on the same lurker must
    /// never receive messages from before it subscribed.
    pub backlog_for: Option<RangeInclusive<u64>>,
}

impl Delivery {
    /// A live message (every matching subscriber).
    #[must_use]
    pub fn live(msg: DecodedMessage) -> Self {
        Self {
            msg,
            backlog_for: None,
        }
    }
}

/// One subscriber: its own (non-union) watch, used to route messages,
/// and the channel its gateway forwarder drains.
struct Subscriber {
    watch: WatchState,
    tx: mpsc::Sender<DecodedMessage>,
}

struct Entry {
    subscribers: Arc<Mutex<Vec<Subscriber>>>,
    watch: SharedWatch,
    lurker: JoinHandle<()>,
}

/// Cheap-to-clone handle on the per-node registry. Deliberately not a
/// process-wide static: tests run several nodes in one process and
/// their lurkers must not cross-wire.
#[derive(Clone, Default)]
pub struct Registry {
    entries: Arc<Mutex<HashMap<[u8; 32], Entry>>>,
    /// Last mailbox ticket issued (see [`WatchState::history_seq`]).
    history_tickets: Arc<AtomicU64>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a subscriber to `target`'s lurker, spawning it via
    /// `spawn_lurker(shared_watch, out_tx)` if this is the first
    /// subscriber for the neighborhood. Returns the subscriber's
    /// message stream, or `None` when the neighborhood cap is reached
    /// (the caller should refuse the subscription).
    ///
    /// A `watch.history` (mailbox) request is stamped with a fresh
    /// ticket here, whether the subscriber spawns the lurker or attaches
    /// to a running one: the union's ticket then exceeds what the lurker
    /// last swept for, so it runs one backlog sweep whose messages are
    /// routed to this subscriber only.
    pub fn subscribe<F>(
        &self,
        target: [u8; 32],
        mut watch: WatchState,
        spawn_lurker: F,
    ) -> Option<mpsc::Receiver<DecodedMessage>>
    where
        F: FnOnce(SharedWatch, mpsc::Sender<Delivery>) -> JoinHandle<()>,
    {
        // Callers don't pick tickets; only an *admitted* history request
        // gets one (issued below, once every cap check has passed, so a
        // refused subscribe doesn't burn one).
        watch.history_seq = 0;
        let wants_ticket = watch.history && !watch.pss_topics.is_empty();
        let issue_ticket = |w: &mut WatchState| {
            if wants_ticket {
                w.history_seq = self.history_tickets.fetch_add(1, Ordering::Relaxed) + 1;
            }
        };
        // Reject an over-large single watch outright (before any lock
        // work) — one subscription can't monopolize the union budget.
        if watch_len(&watch) > MAX_UNION_WATCH {
            return None;
        }
        let (sub_tx, sub_rx) = mpsc::channel(SUBSCRIBER_BUFFER);
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);

        if let Some(entry) = entries.get(&target) {
            // Attach — but bound the subscriber count and the union
            // watch size first, so a same-neighborhood flood can't grow
            // either without limit. A refused attach drops `sub_tx`;
            // the caller closes the subscriber's stream.
            {
                let mut subs = entry
                    .subscribers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                // Count only live subscribers toward the cap: the
                // dispatcher's prune runs every PRUNE_INTERVAL, so
                // without this a burst of connect/disconnect could hold
                // slots for dead receivers until the next tick and refuse
                // a legitimate attach.
                subs.retain(|s| !s.tx.is_closed());
                if subs.len() >= MAX_SUBSCRIBERS_PER_TARGET {
                    return None;
                }
            }
            {
                let mut union = entry.watch.write().unwrap_or_else(PoisonError::into_inner);
                // Would this attach push the union past the cap? Refuse
                // rather than partially merge.
                let mut probe = union.clone();
                probe.merge_from(&watch);
                if watch_len(&probe) > MAX_UNION_WATCH {
                    return None;
                }
                // Admitted. Stamp the ticket under the union's write lock
                // (and the entries lock), so the union never advertises a
                // ticket whose subscriber isn't about to be pushed.
                issue_ticket(&mut watch);
                probe.history_seq = probe.history_seq.max(watch.history_seq);
                if watch.history_seq != 0 {
                    probe.history_held.insert(watch.history_seq);
                }
                *union = probe;
            }
            entry
                .subscribers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Subscriber { watch, tx: sub_tx });
            return Some(sub_rx);
        }

        if entries.len() >= MAX_LURKER_NEIGHBORHOODS {
            return None;
        }
        issue_ticket(&mut watch);

        // First subscriber: spawn the lurker on the union watch (== this
        // watch, for now) and the dispatcher that fans its output out.
        let mut union = watch.clone();
        if watch.history_seq != 0 {
            union.history_held.insert(watch.history_seq);
        }
        let shared: SharedWatch = Arc::new(RwLock::new(union));
        let subscribers = Arc::new(Mutex::new(vec![Subscriber { watch, tx: sub_tx }]));
        let (out_tx, out_rx) = mpsc::channel::<Delivery>(SUBSCRIBER_BUFFER);
        let lurker = spawn_lurker(Arc::clone(&shared), out_tx);
        tokio::spawn(dispatch(
            Arc::clone(&self.entries),
            target,
            out_rx,
            Arc::clone(&subscribers),
            Arc::clone(&shared),
        ));
        entries.insert(
            target,
            Entry {
                subscribers,
                watch: shared,
                lurker,
            },
        );
        Some(sub_rx)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// Total watched items (GSOC addresses + PSS topics) — the union-budget
/// measure. Each PSS topic is one more ECDH/unwrap attempt per candidate
/// chunk, so both kinds count toward the same cap.
fn watch_len(w: &WatchState) -> usize {
    w.gsoc_addresses.len() + w.pss_topics.len()
}

/// Whether a delivery is for this subscriber: its watch matches the
/// message, and a backlog (mailbox-sweep) message additionally only goes
/// to the subscribers whose ticket the sweep served.
fn matches(d: &Delivery, watch: &WatchState) -> bool {
    let wanted = match &d.msg {
        DecodedMessage::Gsoc { address, .. } => watch.gsoc_addresses.contains(address),
        DecodedMessage::Pss { topic, .. } => watch.pss_topics.contains(topic),
    };
    wanted
        && d.backlog_for
            .as_ref()
            .is_none_or(|tickets| watch.history_seq != 0 && tickets.contains(&watch.history_seq))
}

/// Fan the lurker's decoded messages out to matching subscribers, prune
/// the ones that left, and tear the whole entry down when the last one
/// goes. Dropping `out_rx` on exit is what stops the lurker (it selects
/// on its sender's closure), so no abort is needed for the graceful
/// path; the handle is aborted too, belt-and-braces.
async fn dispatch(
    entries: Arc<Mutex<HashMap<[u8; 32], Entry>>>,
    target: [u8; 32],
    mut out_rx: mpsc::Receiver<Delivery>,
    subscribers: Arc<Mutex<Vec<Subscriber>>>,
    shared: SharedWatch,
) {
    let mut prune_tick = tokio::time::interval(PRUNE_INTERVAL);
    prune_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = out_rx.recv() => {
                let Some(msg) = msg else { break }; // lurker gone (peer source ended)
                let mut subs = subscribers.lock().unwrap_or_else(PoisonError::into_inner);
                subs.retain(|s| {
                    if !matches(&msg, &s.watch) {
                        return !s.tx.is_closed();
                    }
                    match s.tx.try_send(msg.msg.clone()) {
                        Ok(()) => true,
                        // Shed the slow: a subscriber 64 messages behind
                        // loses this one rather than blocking the rest.
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                target: "ant_p2p::lurker",
                                "subscriber buffer full; dropping one message for it",
                            );
                            true
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => false,
                    }
                });
                drop(subs);
            }
            _ = prune_tick.tick() => {
                subscribers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retain(|s| !s.tx.is_closed());
            }
        }

        // Shrink the union watch to the remaining subscribers; if none
        // remain, remove the entry (re-checking emptiness under both
        // locks so a subscriber attaching right now isn't torn down).
        let mut entries_guard = entries.lock().unwrap_or_else(PoisonError::into_inner);
        let subs = subscribers.lock().unwrap_or_else(PoisonError::into_inner);
        if subs.is_empty() {
            if let Some(entry) = entries_guard.remove(&target) {
                entry.lurker.abort();
            }
            return; // drops out_rx → lurker halts even if abort raced
        }
        let mut union = WatchState::default();
        for s in subs.iter() {
            union.merge_from(&s.watch);
        }
        *shared.write().unwrap_or_else(PoisonError::into_inner) = union;
    }

    // Lurker ended on its own (peer source gone): drop the entry so a
    // future subscribe can start fresh.
    let mut entries_guard = entries.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(entry) = entries_guard.remove(&target) {
        entry.lurker.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    fn gsoc_watch(addr: [u8; 32]) -> WatchState {
        WatchState {
            gsoc_addresses: HashSet::from([addr]),
            ..Default::default()
        }
    }

    /// A stub lurker: forwards messages from a side channel into the
    /// registry's out channel, standing in for the real pull pipeline.
    fn stub_lurker(
        feed: &mut Option<mpsc::Sender<DecodedMessage>>,
    ) -> impl FnOnce(SharedWatch, mpsc::Sender<Delivery>) -> JoinHandle<()> + '_ {
        move |_watch, out_tx| {
            let (feed_tx, mut feed_rx) = mpsc::channel::<DecodedMessage>(16);
            *feed = Some(feed_tx);
            tokio::spawn(async move {
                while let Some(m) = feed_rx.recv().await {
                    if out_tx.send(Delivery::live(m)).await.is_err() {
                        return;
                    }
                }
            })
        }
    }

    fn gsoc_msg(addr: [u8; 32]) -> DecodedMessage {
        DecodedMessage::Gsoc {
            address: addr,
            payload: b"m".to_vec(),
        }
    }

    #[tokio::test]
    async fn one_lurker_fans_out_selectively() {
        let reg = Registry::new();
        let target = [7u8; 32];
        let (addr_a, addr_b) = ([0xaa; 32], [0xbb; 32]);

        let mut feed = None;
        let mut rx_a = reg
            .subscribe(target, gsoc_watch(addr_a), stub_lurker(&mut feed))
            .unwrap();
        let feed = feed.expect("first subscriber spawns the lurker");
        // Second subscriber on the same target: NO second lurker.
        let mut spawned_again = false;
        let mut rx_b = reg
            .subscribe(target, gsoc_watch(addr_b), |_w, _tx| {
                spawned_again = true;
                tokio::spawn(async {})
            })
            .unwrap();
        assert!(
            !spawned_again,
            "same-target subscriber must attach, not spawn"
        );
        assert_eq!(reg.len(), 1);

        feed.send(gsoc_msg(addr_a)).await.unwrap();
        feed.send(gsoc_msg(addr_b)).await.unwrap();

        // Each subscriber gets exactly its own address's message.
        let got_a = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(got_a, DecodedMessage::Gsoc { address, .. } if address == addr_a));
        let got_b = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(got_b, DecodedMessage::Gsoc { address, .. } if address == addr_b));
        assert!(rx_a.try_recv().is_err(), "A must not see B's message");
    }

    #[tokio::test]
    async fn union_watch_grows_and_shrinks_and_entry_tears_down() {
        let reg = Registry::new();
        let target = [9u8; 32];
        let (addr_a, addr_b) = ([0x11; 32], [0x22; 32]);

        let mut feed = None;
        let mut shared_probe = None;
        let rx_a = reg
            .subscribe(target, gsoc_watch(addr_a), |w, tx| {
                shared_probe = Some(Arc::clone(&w));
                let mut slot = Some(tx);
                let (feed_tx, mut feed_rx) = mpsc::channel::<DecodedMessage>(16);
                feed = Some(feed_tx);
                let out_tx = slot.take().unwrap();
                tokio::spawn(async move {
                    while let Some(m) = feed_rx.recv().await {
                        if out_tx.send(Delivery::live(m)).await.is_err() {
                            return;
                        }
                    }
                })
            })
            .unwrap();
        let shared = shared_probe.unwrap();
        let feed = feed.unwrap();
        let rx_b = reg
            .subscribe(target, gsoc_watch(addr_b), |_w, _tx| tokio::spawn(async {}))
            .unwrap();

        // Union now contains both addresses.
        {
            let w = shared.read().unwrap();
            assert!(w.gsoc_addresses.contains(&addr_a) && w.gsoc_addresses.contains(&addr_b));
        }

        // B leaves; the next dispatched message triggers the prune and
        // the union shrinks back to A only.
        drop(rx_b);
        feed.send(gsoc_msg(addr_a)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !shared.read().unwrap().gsoc_addresses.contains(&addr_b) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("union must shrink after B leaves");

        // A leaves too: entry is removed and a new subscribe respawns.
        drop(rx_a);
        feed.send(gsoc_msg(addr_a)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if reg.len() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("entry must tear down after the last subscriber leaves");

        let mut respawned = false;
        let _rx = reg
            .subscribe(target, gsoc_watch(addr_a), |_w, _tx| {
                respawned = true;
                tokio::spawn(async {})
            })
            .unwrap();
        assert!(
            respawned,
            "fresh subscribe after teardown spawns a new lurker"
        );
    }

    #[tokio::test]
    async fn neighborhood_cap_refuses_new_targets_only() {
        let reg = Registry::new();
        for i in 0..MAX_LURKER_NEIGHBORHOODS {
            let mut t = [0u8; 32];
            t[0] = u8::try_from(i).unwrap();
            assert!(reg
                .subscribe(t, gsoc_watch([1; 32]), |_w, _tx| tokio::spawn(async {}))
                .is_some());
        }
        // A new target is refused…
        assert!(reg
            .subscribe([0xff; 32], gsoc_watch([1; 32]), |_w, _tx| tokio::spawn(
                async {}
            ))
            .is_none());
        // …but attaching to an existing one still works.
        assert!(reg
            .subscribe([0u8; 32], gsoc_watch([2; 32]), |_w, _tx| tokio::spawn(
                async {}
            ))
            .is_some());
    }

    #[tokio::test]
    async fn per_target_subscriber_cap_bounds_a_flood() {
        let reg = Registry::new();
        let target = [3u8; 32];
        // First subscriber spawns; the rest attach up to the cap.
        let mut keep = Vec::new();
        for i in 0..MAX_SUBSCRIBERS_PER_TARGET {
            let mut a = [0u8; 32];
            a[0] = u8::try_from(i % 251).unwrap();
            a[1] = u8::try_from(i / 251).unwrap();
            let rx = reg
                .subscribe(target, gsoc_watch(a), |_w, _tx| tokio::spawn(async {}))
                .expect("under the cap must attach");
            keep.push(rx); // hold receivers so pruning can't free slots
        }
        // One past the cap is refused (same target).
        assert!(reg
            .subscribe(target, gsoc_watch([0xfe; 32]), |_w, _tx| tokio::spawn(
                async {}
            ))
            .is_none());
    }

    #[tokio::test]
    async fn union_watch_cap_refuses_oversize_and_overflowing_merges() {
        let reg = Registry::new();
        let target = [4u8; 32];

        // A single oversize watch is refused outright.
        let big = WatchState {
            gsoc_addresses: (0..=MAX_UNION_WATCH as u32)
                .map(|i| {
                    let mut a = [0u8; 32];
                    a[..4].copy_from_slice(&i.to_be_bytes());
                    a
                })
                .collect(),
            ..Default::default()
        };
        assert!(reg
            .subscribe(target, big, |_w, _tx| tokio::spawn(async {}))
            .is_none());

        // Fill the union to the cap across many subscribers, then the
        // next attach that would overflow it is refused.
        let mut watch_full = WatchState::default();
        for i in 0..MAX_UNION_WATCH as u32 {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_be_bytes());
            watch_full.gsoc_addresses.insert(a);
        }
        let _rx = reg
            .subscribe(target, watch_full, |_w, _tx| tokio::spawn(async {}))
            .expect("exactly at the cap is allowed");
        // One more distinct address would overflow the union → refused.
        assert!(reg
            .subscribe(target, gsoc_watch([0xab; 32]), |_w, _tx| tokio::spawn(
                async {}
            ))
            .is_none());
    }

    /// R2-M2: a history subscribe refused by a cap doesn't burn a ticket
    /// — the next admitted one still gets ticket 1.
    #[tokio::test]
    async fn refused_history_subscribes_issue_no_ticket() {
        let reg = Registry::new();
        let topic = [0x42; 32];
        let mut shared = None;
        let _keep = reg
            .subscribe([0u8; 32], gsoc_watch([1; 32]), |w, _tx| {
                shared = Some(w);
                tokio::spawn(async {})
            })
            .unwrap();
        let shared = shared.unwrap();
        for i in 1..MAX_LURKER_NEIGHBORHOODS {
            let mut t = [0u8; 32];
            t[0] = u8::try_from(i).unwrap();
            assert!(reg
                .subscribe(t, gsoc_watch([1; 32]), |_w, _tx| tokio::spawn(async {}))
                .is_some());
        }
        // Refused: neighborhood cap (new target) …
        assert!(reg
            .subscribe([0xff; 32], pss_watch(topic, true), |_w, _tx| tokio::spawn(
                async {}
            ))
            .is_none());
        // … and union-watch cap (attach overflowing the union).
        let mut over = pss_watch(topic, true);
        over.gsoc_addresses = (0..MAX_UNION_WATCH as u32)
            .map(|i| {
                let mut a = [0u8; 32];
                a[..4].copy_from_slice(&i.to_be_bytes());
                a
            })
            .collect();
        assert!(reg
            .subscribe([0u8; 32], over, |_w, _tx| tokio::spawn(async {}))
            .is_none());
        assert_eq!(shared.read().unwrap().history_seq, 0);
        assert_eq!(reg.history_tickets.load(Ordering::Relaxed), 0);
        // Admitted: gets the first ticket.
        let _h = reg
            .subscribe([0u8; 32], pss_watch(topic, true), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        assert_eq!(shared.read().unwrap().history_seq, 1);
    }

    async fn recv(rx: &mut mpsc::Receiver<DecodedMessage>) -> DecodedMessage {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("delivery")
            .expect("open")
    }

    fn pss_watch(topic: [u8; 32], history: bool) -> WatchState {
        WatchState {
            pss_topics: vec![topic],
            history,
            ..Default::default()
        }
    }

    fn pss_msg(topic: [u8; 32], body: &[u8]) -> DecodedMessage {
        DecodedMessage::Pss {
            topic,
            message: body.to_vec(),
        }
    }

    /// Mailbox mode on a SHARED lurker: a history subscriber that attaches
    /// to an already-running lurker still gets a ticket above what the
    /// lurker swept for (so it triggers a sweep — R1-F1), and the swept
    /// backlog reaches only the ticket holder(s) that sweep served — never
    /// the live-only PSS subscriber or the GSOC subscriber sharing the
    /// lurker, nor an earlier history subscriber already served (R1-F2,
    /// R1-M4). Live traffic still reaches everyone matching.
    #[tokio::test]
    async fn mailbox_tickets_and_backlog_route_only_to_their_requester() {
        let reg = Registry::new();
        let target = [5u8; 32];
        let topic = [0x70; 32];
        let gsoc_addr = [0x60; 32];

        let mut feed: Option<mpsc::Sender<Delivery>> = None;
        let mut shared_probe = None;
        // L: live-only PSS subscriber, spawns the lurker. No ticket.
        let mut rx_live = reg
            .subscribe(target, pss_watch(topic, false), |w, out_tx| {
                shared_probe = Some(Arc::clone(&w));
                let (feed_tx, mut feed_rx) = mpsc::channel::<Delivery>(16);
                feed = Some(feed_tx);
                tokio::spawn(async move {
                    while let Some(d) = feed_rx.recv().await {
                        if out_tx.send(d).await.is_err() {
                            return;
                        }
                    }
                })
            })
            .unwrap();
        let shared = shared_probe.unwrap();
        let feed = feed.unwrap();
        assert_eq!(shared.read().unwrap().history_seq, 0);

        // G: a GSOC subscriber that (wrongly) asks for history gets no
        // ticket — GSOC has no mailbox.
        let mut g_watch = gsoc_watch(gsoc_addr);
        g_watch.history = true;
        let mut rx_gsoc = reg
            .subscribe(target, g_watch, |_w, _tx| tokio::spawn(async {}))
            .unwrap();
        assert_eq!(shared.read().unwrap().history_seq, 0);

        // H1 then H2 attach to the RUNNING lurker with history: each gets
        // a fresh ticket and the union advertises the newest.
        let mut rx_h1 = reg
            .subscribe(target, pss_watch(topic, true), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        assert_eq!(shared.read().unwrap().history_seq, 1);
        let mut rx_h2 = reg
            .subscribe(target, pss_watch(topic, true), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        assert_eq!(shared.read().unwrap().history_seq, 2);

        // A sweep that served only ticket 2 (ticket 1 was swept before).
        feed.send(Delivery {
            msg: pss_msg(topic, b"old"),
            backlog_for: Some(2..=2),
        })
        .await
        .unwrap();
        // Then live traffic.
        feed.send(Delivery::live(pss_msg(topic, b"new")))
            .await
            .unwrap();
        feed.send(Delivery::live(gsoc_msg(gsoc_addr)))
            .await
            .unwrap();

        // H2 (the served ticket) gets the backlog, then live.
        assert_eq!(recv(&mut rx_h2).await, pss_msg(topic, b"old"));
        assert_eq!(recv(&mut rx_h2).await, pss_msg(topic, b"new"));
        // H1 and L get ONLY the live message — no stale backlog.
        assert_eq!(recv(&mut rx_h1).await, pss_msg(topic, b"new"));
        assert_eq!(recv(&mut rx_live).await, pss_msg(topic, b"new"));
        // G gets only its GSOC update.
        assert!(matches!(
            recv(&mut rx_gsoc).await,
            DecodedMessage::Gsoc { .. }
        ));
        for rx in [&mut rx_h1, &mut rx_live, &mut rx_gsoc, &mut rx_h2] {
            assert!(rx.try_recv().is_err(), "no extra deliveries");
        }
    }

    /// R3-M2: the union watch lists the tickets of the history
    /// subscribers still attached, and drops a ticket once its holder
    /// leaves — the lurker's cue to cancel that ticket's campaign.
    #[tokio::test]
    async fn union_tracks_held_history_tickets_as_subscribers_leave() {
        let reg = Registry::new();
        let target = [6u8; 32];
        let topic = [0x71; 32];

        let mut feed: Option<mpsc::Sender<Delivery>> = None;
        let mut shared_probe = None;
        // H1 spawns the lurker with history: ticket 1 is held from the
        // start (not only after the first attach).
        let rx_h1 = reg
            .subscribe(target, pss_watch(topic, true), |w, out_tx| {
                shared_probe = Some(Arc::clone(&w));
                let (feed_tx, mut feed_rx) = mpsc::channel::<Delivery>(16);
                feed = Some(feed_tx);
                tokio::spawn(async move {
                    while let Some(d) = feed_rx.recv().await {
                        if out_tx.send(d).await.is_err() {
                            return;
                        }
                    }
                })
            })
            .unwrap();
        let shared = shared_probe.unwrap();
        let feed = feed.unwrap();
        assert_eq!(shared.read().unwrap().history_held, BTreeSet::from([1]));

        let mut rx_live = reg
            .subscribe(target, pss_watch(topic, false), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        let rx_h2 = reg
            .subscribe(target, pss_watch(topic, true), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        assert_eq!(shared.read().unwrap().history_held, BTreeSet::from([1, 2]));

        // H1 leaves; the next dispatcher pass shrinks the union.
        drop(rx_h1);
        feed.send(Delivery::live(pss_msg(topic, b"x")))
            .await
            .unwrap();
        assert_eq!(recv(&mut rx_live).await, pss_msg(topic, b"x"));
        wait_for(|| shared.read().unwrap().history_held == BTreeSet::from([2])).await;
        assert_eq!(shared.read().unwrap().history_seq, 2);

        // H2 leaves too: no ticket is held; the live subscriber keeps the
        // lurker alive but no campaign has anyone to serve.
        drop(rx_h2);
        feed.send(Delivery::live(pss_msg(topic, b"y")))
            .await
            .unwrap();
        assert_eq!(recv(&mut rx_live).await, pss_msg(topic, b"y"));
        wait_for(|| shared.read().unwrap().history_held.is_empty()).await;
    }

    /// R4-M3: on a quiet topic (no delivery to trigger a rebuild) a
    /// departed history subscriber's ticket still leaves the union within
    /// about a `PRUNE_INTERVAL`, so the lurker cancels the orphaned campaign
    /// promptly instead of sweeping for nobody for ~10s.
    #[tokio::test]
    async fn departed_ticket_leaves_the_union_without_any_delivery() {
        let reg = Registry::new();
        let target = [5u8; 32];
        let topic = [0x72; 32];
        let mut shared_probe = None;
        let mut feed_keepalive: Option<mpsc::Sender<Delivery>> = None;
        let _rx_live = reg
            .subscribe(target, pss_watch(topic, false), |w, out_tx| {
                shared_probe = Some(Arc::clone(&w));
                let (feed_tx, mut feed_rx) = mpsc::channel::<Delivery>(1);
                feed_keepalive = Some(feed_tx);
                tokio::spawn(async move {
                    while let Some(d) = feed_rx.recv().await {
                        if out_tx.send(d).await.is_err() {
                            return;
                        }
                    }
                })
            })
            .unwrap();
        let shared = shared_probe.unwrap();
        let rx_h = reg
            .subscribe(target, pss_watch(topic, true), |_w, _tx| {
                tokio::spawn(async {})
            })
            .unwrap();
        assert_eq!(shared.read().unwrap().history_held, BTreeSet::from([1]));

        let left = std::time::Instant::now();
        drop(rx_h);
        wait_for(|| shared.read().unwrap().history_held.is_empty()).await;
        assert!(left.elapsed() <= PRUNE_INTERVAL + Duration::from_millis(500));
    }

    async fn wait_for(cond: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition within 2s");
    }
}
