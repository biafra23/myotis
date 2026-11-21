//! Connection liveness (issue #83): notice dead peer sockets on our own,
//! without waiting for the host to call `ant_resume`.
//!
//! A connection whose socket was reaped while the app was frozen, or whose
//! NAT mapping expired, is *half-open*: our side never sees a FIN, so libp2p
//! keeps it, the peer counter keeps counting it and retrievals keep being
//! routed into it. rust-libp2p's ping behaviour notices the missing pongs
//! but, since libp2p-ping 0.43, only reports them; closing the connection is
//! up to us. Before this module nothing did, so such a connection lived until
//! the kernel gave up retransmitting (~15 min on Linux).
//!
//! The rules, all driven by successful outbound pings:
//!
//! * a connection is **live** while its last pong is younger than
//!   [`LivenessConfig::live_window`]; [`Liveness::stale_peers`] lists the
//!   peers none of whose connections is live, and the status snapshot's
//!   `peers.connected` (`ant_peer_count`) doesn't count them;
//! * a connection that stays silent [`LivenessConfig::close_grace`] past
//!   that is **dead**: the swarm loop closes it
//!   ([`Liveness::dead_connections`]), which drops the peer from routing and
//!   lets the top-up guards redial;
//! * the ping handler's own failure report (two consecutive failed pings)
//!   closes the connection at once.
//!
//! A close on a dead link finishes within `bounded_close::CLOSE_TIMEOUT`
//! even when unsent data fills the socket's send buffer (the muxer's
//! graceful flush is abandoned then), so `ConnectionClosed` and its peer
//! teardown follow the close by at most that long. A connection being
//! closed counts as stale and is closed only once.
//!
//! **Freezes.** After the process was frozen (iOS / Android background
//! suspension), every pong is old, live sockets included: the pings that
//! would have refreshed them never ran. [`Liveness::tick`] notices the swarm
//! loop's own stall and gives every connection
//! [`LivenessConfig::resume_verify`] from the moment the loop runs again to
//! answer a ping before it counts as stale, rather than closing the live
//! connections along with the dead ones. A suspension that also stops the
//! monotonic clock (Linux/Android system suspend) leaves no visible gap, but
//! then the pongs don't look old either: the regular rules apply in awake
//! time and close the dead sockets within one `live_window + close_grace`.
//!
//! **Our own link (issue #90).** The same pongs tell whether *our* network
//! works at all: [`Liveness::network_unproven`] is true while no connection
//! has answered within [`LivenessConfig::proof_window`], or none has since
//! the network was last suspected to have changed under us (a loop stall,
//! or a `Resume` / self-heal, see [`Liveness::suspect_network`]). The swarm
//! loop doesn't charge outbound dial failures to the remote peer then:
//! with zombie sockets still in `bzz_peers` after a suspend or a handover,
//! a non-empty peer set says nothing about whether the link works.

use libp2p::swarm::ConnectionId;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::time::Instant;

/// Timing knobs. Production uses [`LivenessConfig::DEFAULT`]; tests shrink
/// them so a real-socket test runs in a second.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LivenessConfig {
    /// Outbound ping interval. Must stay well under bee's ping handler
    /// idle timeout (go-libp2p `pingTimeout`, 10 s): bee resets a ping
    /// stream that stays idle that long, and the next ping on it fails
    /// with `UnexpectedEof`. At libp2p's default 15 s every second ping
    /// failed that way, so a live bee answered only every ~30 s.
    pub ping_interval: Duration,
    /// How long one ping waits for its pong.
    pub ping_timeout: Duration,
    /// A connection counts as live while its last pong is younger than
    /// this. Covers one ping that times out (`interval + timeout`) plus
    /// the handler's re-open after it.
    pub live_window: Duration,
    /// After a loop stall, how long each connection gets, from the moment
    /// the loop runs again, to answer a ping before it counts as stale.
    pub resume_verify: Duration,
    /// How long past its liveness deadline a silent connection is kept
    /// before it is closed as dead.
    pub close_grace: Duration,
    /// A gap this long between two swarm-loop iterations (which run at
    /// least every 250 ms) means the process was frozen.
    pub stall_gap: Duration,
    /// Consecutive retrieval link failures (timeouts / stream-open
    /// errors, see `RetrievalCounters::record_link_failure`) with no chunk
    /// delivered from the network in between that trigger a self-heal.
    pub self_heal_streak: u32,
    /// At most one self-heal per this window, so a genuinely unreachable
    /// chunk can't cause a redial storm.
    pub self_heal_cooldown: Duration,
    /// Our own network counts as working while some connection answered a
    /// ping (or was established) within this window. Two ping intervals:
    /// with any live peer a pong arrives at least every `ping_interval`,
    /// so a gap of two means none of them got through. Erring short only
    /// stops charging dial failures to peers for a moment.
    pub proof_window: Duration,
}

impl LivenessConfig {
    pub(crate) const DEFAULT: Self = Self {
        ping_interval: Duration::from_secs(5),
        ping_timeout: Duration::from_secs(10),
        live_window: Duration::from_secs(20),
        resume_verify: Duration::from_secs(12),
        close_grace: Duration::from_secs(10),
        stall_gap: Duration::from_secs(10),
        self_heal_streak: 8,
        self_heal_cooldown: Duration::from_mins(1),
        proof_window: Duration::from_secs(10),
    };
}

#[derive(Debug, Clone, Copy)]
struct Conn {
    peer: PeerId,
    /// Last successful outbound ping, or the connection's establishment.
    last_ok: Instant,
    /// The remote doesn't speak `/ipfs/ping/1.0.0`: we can't judge it,
    /// so it is always counted and never closed by this module.
    ping_unsupported: bool,
    /// We already asked the swarm to close it; its `ConnectionClosed` is
    /// pending (bounded by `bounded_close::CLOSE_TIMEOUT`). Not named
    /// again by [`Liveness::dead_connections`] /
    /// [`Liveness::stale_connections`], so the pass doesn't re-issue the
    /// close every 500 ms.
    closing: bool,
}

/// Per-connection ping bookkeeping, owned by the swarm loop.
#[derive(Debug)]
pub(crate) struct Liveness {
    cfg: LivenessConfig,
    conns: HashMap<ConnectionId, Conn>,
    /// When the loop last came back from a stall (see [`Self::tick`]).
    resumed_at: Option<Instant>,
    last_tick: Instant,
    last_self_heal: Option<Instant>,
    /// Last moment the network answered us: a pong on any connection, or
    /// a connection established. See [`Self::network_unproven`].
    last_proof: Option<Instant>,
    /// Last moment our network was suspected to have changed under us
    /// (loop stall, `Resume`, self-heal). A proof older than this doesn't
    /// count.
    suspect_since: Option<Instant>,
}

impl Liveness {
    pub(crate) fn new(cfg: LivenessConfig, now: Instant) -> Self {
        Self {
            cfg,
            conns: HashMap::new(),
            resumed_at: None,
            last_tick: now,
            last_self_heal: None,
            last_proof: None,
            suspect_since: None,
        }
    }

    pub(crate) fn on_established(&mut self, conn: ConnectionId, peer: PeerId, now: Instant) {
        self.conns.insert(
            conn,
            Conn {
                peer,
                last_ok: now,
                ping_unsupported: false,
                closing: false,
            },
        );
        self.last_proof = Some(now);
    }

    pub(crate) fn on_closed(&mut self, conn: ConnectionId) {
        self.conns.remove(&conn);
    }

    pub(crate) fn on_pong(&mut self, conn: ConnectionId, now: Instant) {
        if let Some(c) = self.conns.get_mut(&conn) {
            c.last_ok = now;
        }
        self.last_proof = Some(now);
    }

    /// Our network may have changed under us (the host's `Resume` after a
    /// suspend or a network change, or a self-heal on failing retrievals):
    /// until a connection answers again, [`Self::network_unproven`] holds.
    pub(crate) fn suspect_network(&mut self, now: Instant) {
        self.suspect_since = Some(now);
    }

    /// Is there no recent evidence that our own network works? True when
    /// no connection answered a ping or was established within
    /// [`LivenessConfig::proof_window`], or none did since
    /// [`Self::suspect_network`] / a loop stall. Connections whose peer
    /// doesn't speak ping never prove anything here (bee always does).
    pub(crate) fn network_unproven(&self, now: Instant) -> bool {
        let Some(proof) = self.last_proof else {
            return true;
        };
        now.saturating_duration_since(proof) > self.cfg.proof_window
            || self.suspect_since.is_some_and(|s| proof < s)
    }

    /// Did a suspected network change ([`Self::suspect_network`] or a loop
    /// stall) happen at or after `at`? Then something begun at `at` (a
    /// dial) ran on the network as it was before the change, and its
    /// failure says nothing about the remote side, even if the link has
    /// been proven again since.
    pub(crate) fn suspected_since(&self, at: Instant) -> bool {
        self.suspect_since.is_some_and(|s| at <= s)
    }

    /// The swarm was asked to close `conn`; see [`Conn::closing`].
    pub(crate) fn on_closing(&mut self, conn: ConnectionId) {
        if let Some(c) = self.conns.get_mut(&conn) {
            c.closing = true;
        }
    }

    pub(crate) fn on_ping_unsupported(&mut self, conn: ConnectionId) {
        if let Some(c) = self.conns.get_mut(&conn) {
            c.ping_unsupported = true;
        }
    }

    /// Call on every swarm-loop iteration. Returns `true` when the gap
    /// since the previous call shows the process was frozen; from then on
    /// every connection that hasn't answered since gets
    /// [`LivenessConfig::resume_verify`] to do so.
    pub(crate) fn tick(&mut self, now: Instant) -> bool {
        let gap = now.saturating_duration_since(self.last_tick);
        self.last_tick = now;
        if gap >= self.cfg.stall_gap {
            self.resumed_at = Some(now);
            self.suspect_network(now);
            true
        } else {
            false
        }
    }

    /// When `c` stops counting as live (`None`: never, ping unsupported).
    fn deadline(&self, c: &Conn) -> Option<Instant> {
        if c.ping_unsupported {
            return None;
        }
        Some(match self.resumed_at {
            Some(r) if r > c.last_ok => {
                (r + self.cfg.resume_verify).max(c.last_ok + self.cfg.live_window)
            }
            _ => c.last_ok + self.cfg.live_window,
        })
    }

    fn is_live(&self, c: &Conn, now: Instant) -> bool {
        !c.closing && self.deadline(c).is_none_or(|d| now <= d)
    }

    /// Peers with at least one connection and no live one. These are not
    /// counted by `ant_peer_count`.
    pub(crate) fn stale_peers(&self, now: Instant) -> HashSet<PeerId> {
        let mut live = HashSet::new();
        let mut all = HashSet::new();
        for c in self.conns.values() {
            all.insert(c.peer);
            if self.is_live(c, now) {
                live.insert(c.peer);
            }
        }
        all.retain(|p| !live.contains(p));
        all
    }

    /// Connections silent for [`LivenessConfig::close_grace`] past their
    /// liveness deadline. The swarm loop closes them.
    pub(crate) fn dead_connections(&self, now: Instant) -> Vec<(ConnectionId, PeerId)> {
        self.conns
            .iter()
            .filter(|(_, c)| {
                !c.closing
                    && self
                        .deadline(c)
                        .is_some_and(|d| now > d + self.cfg.close_grace)
            })
            .map(|(id, c)| (*id, c.peer))
            .collect()
    }

    /// Connections past their liveness deadline (not yet dead). A
    /// self-heal closes these too: retrievals are failing, and these are
    /// the connections that haven't proven they work.
    pub(crate) fn stale_connections(&self, now: Instant) -> Vec<(ConnectionId, PeerId)> {
        self.conns
            .iter()
            .filter(|(_, c)| !c.closing && !self.is_live(c, now))
            .map(|(id, c)| (*id, c.peer))
            .collect()
    }

    /// Whether `streak` consecutive retrieval link failures call for a
    /// self-heal now. Records the self-heal when it does, which starts
    /// the cooldown.
    pub(crate) fn take_self_heal(&mut self, streak: u32, now: Instant) -> bool {
        if streak < self.cfg.self_heal_streak {
            return false;
        }
        if self
            .last_self_heal
            .is_some_and(|t| now.saturating_duration_since(t) < self.cfg.self_heal_cooldown)
        {
            return false;
        }
        self.last_self_heal = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: LivenessConfig = LivenessConfig::DEFAULT;

    fn conn(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    #[test]
    fn answering_connection_stays_live_silent_one_goes_stale_then_dead() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let (a, b) = (PeerId::random(), PeerId::random());
        l.on_established(conn(1), a, t0);
        l.on_established(conn(2), b, t0);
        // `a` answers every ping interval, `b` goes silent at t0.
        let mut now = t0;
        while now < t0 + CFG.live_window + CFG.close_grace + Duration::from_secs(1) {
            now += CFG.ping_interval;
            assert!(!l.tick(now));
            l.on_pong(conn(1), now);
        }
        assert_eq!(l.stale_peers(now), HashSet::from([b]));
        assert_eq!(l.dead_connections(now), vec![(conn(2), b)]);
        // Just inside the window: counted, not closed.
        let edge = t0 + CFG.live_window;
        assert!(l.stale_peers(edge).is_empty());
        assert_eq!(l.dead_connections(edge + CFG.close_grace), vec![]);
        assert_eq!(
            l.stale_connections(edge + Duration::from_millis(1)).len(),
            1
        );
    }

    /// The freeze case: after a long stall every pong is old, but a live
    /// connection must not be closed (or uncounted) before it had its
    /// chance to answer; one that doesn't answer is closed after
    /// `resume_verify + close_grace`.
    #[test]
    fn loop_stall_gives_every_connection_a_fresh_chance() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let (a, b) = (PeerId::random(), PeerId::random());
        l.on_established(conn(1), a, t0);
        l.on_established(conn(2), b, t0);
        let resumed = t0 + Duration::from_mins(10);
        assert!(l.tick(resumed), "a 10 min gap is a stall");
        assert!(l.stale_peers(resumed).is_empty());
        assert_eq!(l.dead_connections(resumed), vec![]);
        l.on_pong(conn(1), resumed + Duration::from_secs(1));
        let later = resumed + CFG.resume_verify + Duration::from_secs(1);
        assert_eq!(l.stale_peers(later), HashSet::from([b]));
        assert_eq!(l.dead_connections(later), vec![]);
        let dead_at = resumed + CFG.resume_verify + CFG.close_grace + Duration::from_secs(1);
        assert_eq!(l.dead_connections(dead_at), vec![(conn(2), b)]);
        // `a` keeps answering and is fine on the normal window again.
        l.on_pong(conn(1), dead_at);
        assert!(!l.stale_peers(dead_at).contains(&a));
    }

    #[test]
    fn a_closing_connection_is_named_once() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let a = PeerId::random();
        l.on_established(conn(1), a, t0);
        let now = t0 + CFG.live_window + CFG.close_grace + Duration::from_secs(1);
        assert_eq!(l.dead_connections(now), vec![(conn(1), a)]);
        l.on_closing(conn(1));
        assert_eq!(l.dead_connections(now), vec![]);
        assert_eq!(l.stale_connections(now), vec![]);
        // Still uncounted until `ConnectionClosed` removes it.
        assert_eq!(l.stale_peers(now), HashSet::from([a]));
    }

    #[test]
    fn regular_loop_iterations_are_not_a_stall() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        assert!(!l.tick(t0 + Duration::from_millis(250)));
        assert!(!l.tick(t0 + Duration::from_secs(5)));
        assert!(l.tick(t0 + Duration::from_secs(5) + CFG.stall_gap));
    }

    #[test]
    fn a_peer_is_stale_only_when_none_of_its_connections_is_live() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let a = PeerId::random();
        l.on_established(conn(1), a, t0);
        l.on_established(conn(2), a, t0);
        let now = t0 + CFG.live_window + CFG.close_grace + Duration::from_secs(1);
        l.on_pong(conn(1), now);
        assert!(l.stale_peers(now).is_empty());
        // The silent duplicate is still closed on its own.
        assert_eq!(l.dead_connections(now), vec![(conn(2), a)]);
    }

    #[test]
    fn ping_unsupported_connections_are_never_judged() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let a = PeerId::random();
        l.on_established(conn(1), a, t0);
        l.on_ping_unsupported(conn(1));
        let now = t0 + Duration::from_hours(1);
        assert!(l.stale_peers(now).is_empty());
        assert_eq!(l.dead_connections(now), vec![]);
        assert_eq!(l.stale_connections(now), vec![]);
        l.on_closed(conn(1));
        assert!(l.conns.is_empty());
    }

    /// Issue #90: a populated peer set doesn't prove our link works. The
    /// network is proven only by a recent pong or a new connection, and a
    /// suspected change (stall, `Resume`) voids the proofs before it.
    #[test]
    fn network_is_proven_only_by_recent_answers() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        let a = PeerId::random();
        assert!(l.network_unproven(t0), "nothing answered yet");
        l.on_established(conn(1), a, t0);
        assert!(!l.network_unproven(t0));
        // Zombie socket: still connected, but no pong for a while.
        let quiet = t0 + CFG.proof_window + Duration::from_millis(1);
        assert!(l.network_unproven(quiet));
        assert!(
            l.stale_peers(quiet).is_empty(),
            "noticed before the peer stops counting"
        );
        l.on_pong(conn(1), quiet);
        assert!(!l.network_unproven(quiet));

        // `Resume`: earlier answers no longer count, the next one does.
        let resume = quiet + Duration::from_secs(1);
        l.suspect_network(resume);
        assert!(l.network_unproven(resume));
        l.on_pong(conn(1), resume + Duration::from_millis(100));
        assert!(!l.network_unproven(resume + Duration::from_millis(100)));

        // A loop stall does the same.
        let thawed = resume + Duration::from_secs(3);
        assert!(l.tick(thawed));
        assert!(l.network_unproven(thawed));
        let b = PeerId::random();
        l.on_established(conn(2), b, thawed + Duration::from_secs(1));
        assert!(!l.network_unproven(thawed + Duration::from_secs(1)));
    }

    #[test]
    fn self_heal_needs_a_streak_and_respects_the_cooldown() {
        let t0 = Instant::now();
        let mut l = Liveness::new(CFG, t0);
        assert!(!l.take_self_heal(CFG.self_heal_streak - 1, t0));
        assert!(l.take_self_heal(CFG.self_heal_streak, t0));
        assert!(!l.take_self_heal(100, t0 + Duration::from_secs(59)));
        assert!(l.take_self_heal(100, t0 + CFG.self_heal_cooldown));
    }
}
