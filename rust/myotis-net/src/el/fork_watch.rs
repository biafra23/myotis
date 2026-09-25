//! EIP-2124 stale-software detection for a binary that PINS its fork id — twin
//! of Java `networking.eth.ForkWatch` (same constants, same rules, same
//! Sepolia vectors in the tests).
//!
//! Notices, from the fork ids peers present in their eth Status, that the
//! network has scheduled — or already activated — an execution-layer fork this
//! build does not implement, so hosts can say "update required" instead of the
//! wallet going mute at the fork (verification fails closed, so the only symptom
//! would otherwise be a node that looks stuck syncing).
//!
//! Evidence comes from peers already confirmed on our chain (network id +
//! genesis — the pool only reports completed handshakes):
//! - **Announced**: a peer presents OUR fork hash with `forkNext = T`, a
//!   timestamp this build does not know (announced weeks ahead).
//! - **Placed**: a peer presents the hash that FOLLOWS ours once a fork at some
//!   `T` has passed: [`forkid::activation_of`] recovers `T`, and a real one was
//!   announced or sits on the beacon epoch grid within [`LOOKBACK_SECONDS`] — so
//!   a wallet offline for the whole announcement window still recognises the
//!   fork. Placing tells a successor apart from another chain's hash; it is NOT
//!   proof — any hash places somewhere.
//!
//! Peers can lie, so the vote is built to be expensive to fake: one vote per
//! SOURCE network ([`source_of`]: IPv4 /24, IPv6 /48), not per node id — ids
//! are free; and an advisory needs [`MIN_PEERS`] sources behind one activation
//! AND more of them than sources on our hash announcing no unknown fork.
//! ADVISORY ONLY: nothing in verification reads it, so a false one is a wrong
//! banner, never a wrong answer (hosts escalate ACTIVE to "can no longer
//! verify" only when the node's own verified state agrees). A source's evidence
//! stays fresh while one of its peers is connected ([`ForkWatch::touch`]) and
//! for [`OBSERVATION_TTL_SECONDS`] after. A fork this build knows (its own
//! `fork_next`) never raises one, and once it passes the watch measures from
//! its successor ([`forkid::fork_id_at`]), exactly as our own Status does —
//! while peers still on the pinned hash keep being judged against the pinned
//! fork id, so a date moved after this build shipped stays news past ours. Not
//! covered: a peer two or more forks ahead (placement is one step from a
//! baseline).
//!
//! One instance per HANDLE, owned by the engine host so it survives pause/resume
//! (the Java twin is ChainStack-owned for the same reason). Clock values are
//! parameters on the `*_at` methods; the plain ones read the wall clock.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use myotis_core::forkid;

/// Distinct source networks that must agree before an advisory is raised.
pub const MIN_PEERS: usize = 3;
/// A source's last presented fork id stops counting this long after the source
/// was last seen connected (observed, or touched).
pub const OBSERVATION_TTL_SECONDS: u64 = 24 * 3600;
/// A passed announcement of `T` keeps counting this long past `T`: bridges the
/// rollover from "forkNext = T" to the successor hash, and ages out a
/// rescheduled date's stale announcements. Exempt: an announcement made before
/// `T` by a source still seen connected after it — that peer passed `T` with
/// the fork configured, so it counts for as long as it stays fresh.
pub const ACTIVATION_GRACE_SECONDS: u64 = 6 * 3600;
/// Announcements further out than this are treated as garbage.
pub const MAX_HORIZON_SECONDS: u64 = 400 * 24 * 3600;
/// How far back a placed activation that was never announced may lie.
pub const LOOKBACK_SECONDS: u64 = 400 * 24 * 3600;
/// Bound on tracked sources; the least recently seen is evicted.
pub const MAX_TRACKED: usize = 512;

/// Networks the watch runs on. Staged rollout: Sepolia first — its Glamsterdam
/// activation (2026-10-06, epoch 353024) is the first fork this detector meets;
/// mainnet and Gnosis follow once validated there. Keep in sync with the Java
/// `ForkWatch.ENABLED_NETWORKS`.
pub const ENABLED_NETWORKS: &[&str] = &["sepolia"];

/// Whether the watch runs on this (canonical) network.
pub fn enabled_for(network: &str) -> bool {
    ENABLED_NETWORKS.contains(&network)
}

/// Wall clock, unix seconds (fork activations are wall-clock times). 0 if the
/// clock reads before the epoch, which simply makes every observation stale.
pub fn wall_clock_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The vote key for a peer at `ip`: its IPv4 /24 or IPv6 /48 (an IPv4-mapped
/// IPv6 address counts as IPv4). Same strings as Java `ForkWatch.sourceOf`.
pub fn source_of(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4_source(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4_source(v4),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
        },
    }
}

fn v4_source(v4: Ipv4Addr) -> String {
    let [a, b, c, _] = v4.octets();
    format!("{a}.{b}.{c}.0/24")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Announced; activation ahead.
    Scheduled,
    /// Passed on the wall clock, or placed from [`MIN_PEERS`] successor hashes.
    Active,
}

impl Phase {
    /// The status-JSON / API enum name.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Scheduled => "SCHEDULED",
            Phase::Active => "ACTIVE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advisory {
    pub phase: Phase,
    /// Unix seconds of the fork's activation.
    pub activation_time: u64,
    /// The fork hash upgraded peers use once it is active.
    pub fork_hash: u32,
    /// Distinct source networks backing it.
    pub peers: usize,
}

impl Advisory {
    /// `0x` + 8 lowercase hex digits — the form clients log fork ids in.
    pub fn fork_hash_hex(&self) -> String {
        format!("0x{:08x}", self.fork_hash)
    }

    /// Transition identity for logging: a changed peer count is not news.
    fn same_fork(a: Option<&Advisory>, b: Option<&Advisory>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.phase == b.phase
                    && a.activation_time == b.activation_time
                    && a.fork_hash == b.fork_hash
            }
            _ => false,
        }
    }
}

struct Observation {
    hash: u32,
    next: u64,
    /// When the Status was presented.
    observed_at: u64,
    /// When the source was last seen connected.
    seen_at: u64,
}

/// Votes for one activation, in distinct sources.
#[derive(Default)]
struct Support {
    placed: usize,
    announced: usize,
}

impl Support {
    fn total(&self) -> usize {
        self.placed.saturating_add(self.announced)
    }
}

/// A fork id the watch measures from, and the foreign activations announced on it.
struct Baseline {
    hash: u32,
    next: u64,
    announced: HashSet<u64>,
}

impl Baseline {
    fn new(hash: u32, next: u64) -> Baseline {
        Baseline {
            hash,
            next,
            announced: HashSet::new(),
        }
    }
}

#[derive(Default)]
struct Inner {
    /// Latest observation per source network.
    by_source: HashMap<String, Observation>,
    last_logged: Option<Advisory>,
}

pub struct ForkWatch {
    label: String,
    /// Our pinned fork id; the baseline at a given time is
    /// [`forkid::fork_id_at`] of it, plus the pin itself once `pinned_next`
    /// has passed.
    pinned_hash: u32,
    pinned_next: u64,
    genesis_time: u64,
    epoch_seconds: u64,
    inner: Mutex<Inner>,
}

impl ForkWatch {
    /// `local_fork_hash`/`local_fork_next`: what WE announce (the `ElConfig` pin
    /// — the wire value, not `forkid`'s conformance copy); once `local_fork_next`
    /// passes, the watch measures from its successor, as our Status does, and
    /// from the pin for peers still on it.
    /// `genesis_time` + `epoch_seconds`: the beacon epoch grid activations sit on
    /// (0 = only announced activations place).
    pub fn new(
        label: &str,
        local_fork_hash: [u8; 4],
        local_fork_next: u64,
        genesis_time: u64,
        epoch_seconds: u64,
    ) -> ForkWatch {
        ForkWatch {
            label: label.to_string(),
            pinned_hash: u32::from_be_bytes(local_fork_hash),
            pinned_next: local_fork_next,
            genesis_time,
            epoch_seconds,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Record the fork id a peer from `source` ([`source_of`]) presented in its
    /// eth Status, on the wall clock.
    pub fn observe(&self, source: &str, fork_hash: [u8; 4], fork_next: u64) {
        self.observe_at(source, fork_hash, fork_next, wall_clock_secs());
    }

    /// [`observe`](Self::observe) at `now` (unix seconds). Logs when this
    /// changes the advisory, so the operator log carries it even if nobody
    /// polls status.
    pub fn observe_at(&self, source: &str, fork_hash: [u8; 4], fork_next: u64, now: u64) {
        self.update(now, |inner| {
            if inner.by_source.len() >= MAX_TRACKED && !inner.by_source.contains_key(source) {
                // Evict the least recently seen source (the Java twin's LRU bound).
                if let Some(stalest) = inner
                    .by_source
                    .iter()
                    .min_by_key(|(_, o)| o.seen_at)
                    .map(|(k, _)| k.clone())
                {
                    inner.by_source.remove(&stalest);
                }
            }
            inner.by_source.insert(
                source.to_string(),
                Observation {
                    hash: u32::from_be_bytes(fork_hash),
                    next: fork_next,
                    observed_at: now,
                    seen_at: now,
                },
            );
        });
    }

    /// Mark `sources` as still connected, on the wall clock. Their evidence
    /// stays fresh for as long as a peer of theirs is — a full pool dials nobody
    /// new, and its peers' word is exactly what matters across the fork.
    /// Sources never observed are ignored.
    pub fn touch(&self, sources: &[String]) {
        self.touch_at(sources, wall_clock_secs());
    }

    /// [`touch`](Self::touch) at `now` (unix seconds).
    pub fn touch_at(&self, sources: &[String], now: u64) {
        self.update(now, |inner| {
            for source in sources {
                if let Some(o) = inner.by_source.get_mut(source) {
                    o.seen_at = o.seen_at.max(now);
                }
            }
        });
    }

    /// The current advisory on the wall clock, if any.
    pub fn advisory(&self) -> Option<Advisory> {
        self.evaluate(wall_clock_secs())
    }

    /// The advisory as of `now` (unix seconds), if any.
    pub fn evaluate(&self, now: u64) -> Option<Advisory> {
        let mut inner = self.inner.lock().ok()?;
        self.evaluate_locked(&mut inner, now)
    }

    /// Apply `mutate` at `now`, then log if the advisory changed.
    fn update(&self, now: u64, mutate: impl FnOnce(&mut Inner)) {
        let current = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            mutate(&mut inner);
            let current = self.evaluate_locked(&mut inner, now);
            if Advisory::same_fork(inner.last_logged.as_ref(), current.as_ref()) {
                return;
            }
            inner.last_logged = current;
            current
        };
        match current {
            None => tracing::info!(network = %self.label, "fork-watch: upgrade advisory cleared"),
            Some(a) if a.phase == Phase::Scheduled => tracing::warn!(
                network = %self.label,
                sources = a.peers,
                activation = a.activation_time,
                fork_id = %a.fork_hash_hex(),
                "fork-watch: peers announce a network upgrade this build does not support — update before then"
            ),
            Some(a) => tracing::warn!(
                network = %self.label,
                sources = a.peers,
                activation = a.activation_time,
                fork_id = %a.fork_hash_hex(),
                "fork-watch: peers report the network upgraded — this build cannot follow it; update required"
            ),
        }
    }

    fn evaluate_locked(&self, inner: &mut Inner, now: u64) -> Option<Advisory> {
        let cutoff = now.saturating_sub(OBSERVATION_TTL_SECONDS);
        inner.by_source.retain(|_, o| o.seen_at >= cutoff);

        // Our baseline follows our own schedule: once the fork we know passes,
        // peers on its successor are on OUR chain, and a further fork they
        // announce is the news. The pin stays a second baseline for peers still
        // on its hash: their Status doesn't change at OUR date, so neither does
        // its verdict. A date moved after this build shipped keeps counting
        // (announced, then placed from the pin once it passes), and peers on
        // our date, or on none, keep dissenting.
        let (local_hash, local_next) = forkid::fork_id_at(self.pinned_hash, self.pinned_next, now);
        let mut baselines = vec![Baseline::new(local_hash, local_next)];
        if local_hash != self.pinned_hash {
            baselines.push(Baseline::new(self.pinned_hash, self.pinned_next));
        }

        for o in inner.by_source.values() {
            for b in &mut baselines {
                if o.hash == b.hash && is_foreign_activation(o.next, now, b.next) {
                    b.announced.insert(o.next);
                }
            }
        }
        // Keyed by (baseline hash, activation): one fork.
        let mut support: HashMap<(u32, u64), Support> = HashMap::new();
        let mut dissent = 0usize;
        // One entry per source ⇒ counts are distinct sources.
        for o in inner.by_source.values() {
            if let Some(on) = baselines.iter().find(|b| b.hash == o.hash) {
                let t = o.next;
                if t == 0 || t == on.next {
                    dissent += 1; // on a baseline, no unknown fork ahead
                } else if is_foreign_activation(t, now, on.next) && still_counts(o, t, now) {
                    support.entry((on.hash, t)).or_default().announced += 1;
                }
                continue;
            }
            // The current baseline first: one vote per source.
            for b in &baselines {
                let t = forkid::activation_of(b.hash, o.hash);
                if b.next != 0 && t == b.next {
                    dissent += 1; // past a fork we DO know: not news
                    break;
                }
                if self.plausible_placement(t, &b.announced, now, b.next) {
                    support.entry((b.hash, t)).or_default().placed += 1;
                    break;
                }
            }
        }

        // Most-backed fork; ties → more placed, then earliest, then the current
        // baseline's. It must clear both the absolute floor and the dissent: a
        // minority can't outvote the peers it contradicts. The same date from
        // two baselines is two forks: never pooled.
        let ((base, t), best) = support
            .into_iter()
            .filter(|(_, s)| s.total() >= MIN_PEERS && s.total() > dissent)
            .max_by(|((ba, ta), a), ((bb, tb), b)| {
                a.total()
                    .cmp(&b.total())
                    .then(a.placed.cmp(&b.placed))
                    .then(tb.cmp(ta))
                    .then((*ba == local_hash).cmp(&(*bb == local_hash)))
            })?;
        let phase = if t <= now || best.placed >= MIN_PEERS {
            Phase::Active
        } else {
            Phase::Scheduled
        };
        Some(Advisory {
            phase,
            activation_time: t,
            fork_hash: forkid::successor(base, t),
            peers: best.total(),
        })
    }

    /// Whether `t`, where [`forkid::activation_of`] put a foreign hash, is a
    /// real activation: announced by a source on the baseline it was placed
    /// from, or epoch-aligned within the lookback (EL fork timestamps track the
    /// CL fork epoch; one epoch of slack for a clock running behind).
    fn plausible_placement(
        &self,
        t: u64,
        announced: &HashSet<u64>,
        now: u64,
        local_next: u64,
    ) -> bool {
        if t < forkid::TIMESTAMP_THRESHOLD || t == local_next {
            return false;
        }
        if announced.contains(&t) {
            return true;
        }
        let epoch = self.epoch_seconds;
        epoch > 0
            && t >= self.genesis_time
            && (t - self.genesis_time).is_multiple_of(epoch)
            && t >= now.saturating_sub(LOOKBACK_SECONDS)
            && t <= now.saturating_add(epoch)
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().map(|i| i.by_source.len()).unwrap_or(0)
    }
}

/// A timestamp activation this build doesn't know, within a plausible horizon.
fn is_foreign_activation(t: u64, now: u64, local_next: u64) -> bool {
    t != 0
        && t != local_next
        && t >= forkid::TIMESTAMP_THRESHOLD
        && t <= now.saturating_add(MAX_HORIZON_SECONDS)
}

/// Whether an announcement of `t` still counts: ahead; or made before `t` by a
/// source seen connected since (it passed the fork configured for it); or
/// within the grace. A long-passed `t` announced AFTER the fact is a peer far
/// behind or garbage, not evidence.
fn still_counts(o: &Observation, t: u64, now: u64) -> bool {
    t > now
        || (o.observed_at < t && o.seen_at >= t)
        || now.saturating_sub(t) < ACTIVATION_GRACE_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEPOLIA_PIN: [u8; 4] = [0x26, 0x89, 0x56, 0xb6];
    const SEPOLIA_GENESIS: u64 = 1_655_733_600;
    const EPOCH: u64 = 32 * 12;
    const DAY: u64 = 24 * 3600;
    /// Sepolia's Glamsterdam activation (ethereum/pm#2205) and its fork id.
    const T: u64 = 1_791_294_816;
    const SUCCESSOR: [u8; 4] = [0x6c, 0x1d, 0x94, 0x23];
    const BEFORE: u64 = T - 14 * DAY;
    /// A made-up hash that places on the epoch grid (see forkid's tests).
    const FORGED: [u8; 4] = [0x47, 0xe1, 0x2c, 0x82];
    const FORGED_AT: u64 = 1_790_207_712;

    fn watch(local_next: u64) -> ForkWatch {
        ForkWatch::new("sepolia", SEPOLIA_PIN, local_next, SEPOLIA_GENESIS, EPOCH)
    }

    /// `n` sources named `{prefix}0..` each presenting `(hash, next)` at `now`.
    fn announce(
        w: &ForkWatch,
        prefix: &str,
        n: usize,
        hash: [u8; 4],
        next: u64,
        now: u64,
    ) -> Vec<String> {
        let sources: Vec<String> = (0..n).map(|i| format!("{prefix}{i}")).collect();
        for s in &sources {
            w.observe_at(s, hash, next, now);
        }
        sources
    }

    #[test]
    fn enabled_on_sepolia_only() {
        assert!(enabled_for("sepolia"));
        assert!(!enabled_for("mainnet"));
        assert!(!enabled_for("gnosis"));
    }

    #[test]
    fn constants_match_the_shared_twin_pins() {
        // The Java twin asserts the same file, so the engines can't drift apart silently.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/el/fork_watch/params.txt");
        let text = std::fs::read_to_string(&path).expect("shared twin pins");
        let p: HashMap<&str, &str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| l.split_once('='))
            .collect();
        let num = |k: &str| p[k].parse::<u64>().expect(k);
        assert_eq!(num("min_peers"), MIN_PEERS as u64);
        assert_eq!(num("observation_ttl_seconds"), OBSERVATION_TTL_SECONDS);
        assert_eq!(num("activation_grace_seconds"), ACTIVATION_GRACE_SECONDS);
        assert_eq!(num("max_horizon_seconds"), MAX_HORIZON_SECONDS);
        assert_eq!(num("lookback_seconds"), LOOKBACK_SECONDS);
        assert_eq!(num("max_tracked"), MAX_TRACKED as u64);
        let mut pinned: Vec<&str> = p["enabled_networks"].split(',').collect();
        let mut ours = ENABLED_NETWORKS.to_vec();
        pinned.sort_unstable();
        ours.sort_unstable();
        assert_eq!(pinned, ours);
    }

    #[test]
    fn quiet_network_raises_nothing() {
        let w = watch(0);
        assert_eq!(w.evaluate(BEFORE), None);
        announce(&w, "on-our-fork", 8, SEPOLIA_PIN, 0, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn scheduled_needs_three_distinct_sources() {
        let w = watch(0);
        announce(&w, "s", 2, SEPOLIA_PIN, T, BEFORE);
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "two sources are below the threshold"
        );
        for _ in 0..5 {
            w.observe_at("s0", SEPOLIA_PIN, T, BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "re-observing a source must not count it twice"
        );
        w.observe_at("s2", SEPOLIA_PIN, T, BEFORE);
        let a = w.evaluate(BEFORE).expect("advisory");
        assert_eq!(a.phase, Phase::Scheduled);
        assert_eq!(a.activation_time, T);
        assert_eq!(a.fork_hash_hex(), "0x6c1d9423");
        assert_eq!(a.peers, 3);
    }

    #[test]
    fn one_network_is_one_vote() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let a = source_of(ip("203.0.113.5"));
        assert_eq!(a, "203.0.113.0/24");
        assert_eq!(a, source_of(ip("203.0.113.250")));
        assert_ne!(a, source_of(ip("203.0.114.5")));
        assert_eq!(source_of(ip("2001:db8:abcd:12::1")), "2001:db8:abcd::/48");
        assert_eq!(source_of(ip("2001:db8:abcd:ffff::9")), "2001:db8:abcd::/48");
        assert_eq!(source_of(ip("::ffff:198.51.100.9")), "198.51.100.0/24");

        // Many node ids behind one /24 are one voice.
        let w = watch(0);
        for host in 1..=5 {
            w.observe_at(
                &source_of(ip(&format!("198.51.100.{host}"))),
                SEPOLIA_PIN,
                T,
                BEFORE,
            );
        }
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn active_is_placed_from_successor_hashes_without_any_announcement() {
        // Offline for the whole announcement window: only upgraded peers after the fork.
        let now = T + 3 * DAY;
        let w = watch(0);
        announce(&w, "upgraded", 3, SUCCESSOR, 0, now);
        let a = w.evaluate(now).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(a.activation_time, T);
        assert_eq!(a.fork_hash, u32::from_be_bytes(SUCCESSOR));
    }

    #[test]
    fn a_minority_cannot_outvote_the_peers_it_contradicts() {
        let now = FORGED_AT + DAY;
        let w = watch(0);
        announce(&w, "honest", 5, SEPOLIA_PIN, 0, now);
        announce(&w, "forger", 3, FORGED, 0, now);
        assert_eq!(w.evaluate(now), None);
        announce(&w, "forger", 5, FORGED, 0, now);
        assert_eq!(w.evaluate(now), None, "a tie is not a majority");
        w.observe_at("forger5", FORGED, 0, now);
        let a = w.evaluate(now).expect("a majority raises it");
        assert_eq!(a.activation_time, FORGED_AT);
        assert_eq!(a.peers, 6);
    }

    #[test]
    fn announcement_turns_active_at_its_time_then_ages_out_if_its_sources_left() {
        let w = watch(0);
        // Seen an hour before activation — within the observation TTL throughout.
        announce(&w, "s", 3, SEPOLIA_PIN, T, T - 3600);
        assert_eq!(w.evaluate(T - 1).unwrap().phase, Phase::Scheduled);
        assert_eq!(w.evaluate(T + 3600).unwrap().phase, Phase::Active);
        assert_eq!(w.evaluate(T + ACTIVATION_GRACE_SECONDS + 1), None);
    }

    #[test]
    fn connected_announcers_keep_an_active_fork_alive() {
        // A stable pool: the announcers stay connected across the fork and
        // nobody new handshakes (the pool stops dialing at its target).
        let w = watch(0);
        let sources = announce(&w, "s", 3, SEPOLIA_PIN, T, T - 3600);
        let touched = T + 60;
        w.touch_at(&sources, touched);
        let a = w
            .evaluate(T + ACTIVATION_GRACE_SECONDS + 1)
            .expect("seen connected past T");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(
            w.evaluate(touched + OBSERVATION_TTL_SECONDS + 1),
            None,
            "expires once they're gone"
        );
    }

    #[test]
    fn a_passed_date_announced_after_the_fact_is_not_evidence() {
        let now = T + 2 * DAY;
        let w = watch(0);
        let sources = announce(&w, "behind", 3, SEPOLIA_PIN, T, now);
        w.touch_at(&sources, now);
        assert_eq!(w.evaluate(now), None);
    }

    #[test]
    fn touch_keeps_a_stable_pool_fresh_and_ignores_strangers() {
        let touched = watch(0);
        let untouched = watch(0);
        let sources = announce(&touched, "s", 3, SEPOLIA_PIN, T, BEFORE);
        announce(&untouched, "s", 3, SEPOLIA_PIN, T, BEFORE);
        touched.touch_at(&sources, BEFORE + 20 * 3600);
        touched.touch_at(&["never-observed".to_string()], BEFORE + 20 * 3600);
        let later = BEFORE + 30 * 3600;
        assert_eq!(touched.evaluate(later).unwrap().phase, Phase::Scheduled);
        assert_eq!(
            untouched.evaluate(later),
            None,
            "the TTL runs from the last sighting"
        );
        assert_eq!(touched.tracked(), 3, "touch must not create entries");
    }

    #[test]
    fn placed_and_announced_evidence_add_up() {
        let w = watch(0);
        let announcers = announce(&w, "announcer", 2, SEPOLIA_PIN, T, T - 3600);
        let now = T + 3600;
        w.touch_at(&announcers, now);
        w.observe_at("upgraded0", SUCCESSOR, 0, now);
        let a = w.evaluate(now).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(a.peers, 3);
    }

    #[test]
    fn the_best_backed_activation_wins_and_placements_break_ties() {
        let now = T + DAY;
        let later = T + 30 * DAY;
        let w = watch(0);
        announce(&w, "announcer", 4, SEPOLIA_PIN, later, now);
        announce(&w, "upgraded", 3, SUCCESSOR, 0, now);
        let a = w.evaluate(now).unwrap();
        assert_eq!(
            a.phase,
            Phase::Scheduled,
            "a placement is not proof: 4 beat 3"
        );
        assert_eq!(a.activation_time, later);
        w.observe_at("upgraded3", SUCCESSOR, 0, now);
        let a = w.evaluate(now).unwrap();
        assert_eq!(a.phase, Phase::Active, "on a tie, placed evidence wins");
        assert_eq!(a.activation_time, T);
    }

    #[test]
    fn rescheduled_date_follows_the_sources_latest_announcements() {
        let projected = T - 15 * DAY;
        let now = projected - 7 * DAY;
        let w = watch(0);
        announce(&w, "s", 3, SEPOLIA_PIN, projected, now);
        assert_eq!(w.evaluate(now).unwrap().activation_time, projected);
        announce(&w, "s", 3, SEPOLIA_PIN, T, now);
        assert_eq!(w.evaluate(now).unwrap().activation_time, T);
    }

    #[test]
    fn a_fork_this_build_knows_is_not_news() {
        let w = watch(T);
        announce(&w, "announcer", 5, SEPOLIA_PIN, T, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
        announce(&w, "upgraded", 5, SUCCESSOR, 0, T + DAY);
        assert_eq!(w.evaluate(T + DAY), None);
    }

    #[test]
    fn the_baseline_follows_our_own_known_fork() {
        // A build that carries Glamsterdam: past it, peers on its successor are
        // on OUR chain, and a further fork they announce is what the watch reports.
        let next_fork = T + 60 * DAY;
        let now = T + DAY;
        let w = watch(T);
        announce(&w, "upgraded", 3, SUCCESSOR, 0, now);
        assert_eq!(
            w.evaluate(now),
            None,
            "our own fork's successor is not news"
        );
        announce(&w, "upgraded", 3, SUCCESSOR, next_fork, now);
        let a = w.evaluate(now).expect("advisory");
        assert_eq!(a.phase, Phase::Scheduled);
        assert_eq!(a.activation_time, next_fork);
        assert_eq!(
            a.fork_hash,
            forkid::successor(u32::from_be_bytes(SUCCESSOR), next_fork)
        );
    }

    #[test]
    fn a_rescheduled_fork_stays_news_past_the_date_this_build_knows() {
        // Glamsterdam moves AFTER this build shipped (it moved once already,
        // 09-21 → 10-06). Past OUR date we present its successor, which peers
        // on the new date reject — but they show their Status first, still on
        // the pin: that is the whole signal then.
        let moved = T + 7 * DAY;
        let moved_fork_id = forkid::successor(u32::from_be_bytes(SEPOLIA_PIN), moved);
        let w = watch(T);
        announce(&w, "upgraded", 3, SEPOLIA_PIN, moved, T - 3600);
        let scheduled = Advisory {
            phase: Phase::Scheduled,
            activation_time: moved,
            fork_hash: moved_fork_id,
            peers: 3,
        };
        assert_eq!(w.evaluate(T - 3600), Some(scheduled));
        assert_eq!(
            w.evaluate(T + 3600),
            Some(scheduled),
            "past our date the pin still measures them: their fork id, not a successor of ours"
        );
        let now = moved + DAY;
        announce(&w, "upgraded", 3, moved_fork_id.to_be_bytes(), 0, now);
        assert_eq!(
            w.evaluate(now),
            Some(Advisory {
                phase: Phase::Active,
                ..scheduled
            }),
            "once their date passed, their hash places from the pin"
        );
    }

    #[test]
    fn the_pool_from_before_our_date_still_dissents_past_it() {
        // A stable pool that handshook before our date and stays connected
        // across it. Its Status is still on the pin — four on our date, one on
        // none — and right after T it is most of what we know: if its verdict
        // lapsed at OUR date, a few fresh sources minting a "successor of ours"
        // would face no dissent at all.
        let w = watch(T);
        let mut pool = announce(&w, "on-our-date", 4, SEPOLIA_PIN, T, T - 3600);
        pool.extend(announce(&w, "not-upgraded", 1, SEPOLIA_PIN, 0, T - 3600));
        let now = T + 3600;
        w.touch_at(&pool, now);
        let forged_at = T + EPOCH; // grid-aligned, one epoch past ours
        let forged = forkid::successor(u32::from_be_bytes(SUCCESSOR), forged_at).to_be_bytes();
        announce(&w, "forger", 3, forged, 0, now);
        assert_eq!(w.evaluate(now), None);
        announce(&w, "forger", 5, forged, 0, now);
        assert_eq!(w.evaluate(now), None, "a tie is not a majority");
        w.observe_at("forger5", forged, 0, now);
        let a = w.evaluate(now).expect("a majority raises it");
        assert_eq!(a.activation_time, forged_at);
        assert_eq!(a.fork_hash, u32::from_be_bytes(forged));
        assert_eq!(a.peers, 6);
    }

    #[test]
    fn the_same_date_from_either_baseline_is_two_forks() {
        // Past our date, "a fork after ours at t" (announced on its successor)
        // and "our fork moved to t" (announced on the pin) are different forks
        // with different ids: they must not pool their sources into one vote.
        let later = T + 30 * DAY;
        let now = T + DAY;
        let w = watch(T);
        announce(&w, "after-ours", 3, SUCCESSOR, later, now);
        announce(&w, "moved", 3, SEPOLIA_PIN, later, now);
        assert_eq!(
            w.evaluate(now).map(|a| a.fork_hash),
            Some(forkid::successor(u32::from_be_bytes(SUCCESSOR), later)),
            "on a full tie, the current baseline's reading wins"
        );
        announce(&w, "current", 3, SUCCESSOR, 0, now);
        assert_eq!(w.evaluate(now), None, "three and three are not six");
        w.observe_at("moved3", SEPOLIA_PIN, later, now);
        assert_eq!(
            w.evaluate(now),
            Some(Advisory {
                phase: Phase::Scheduled,
                activation_time: later,
                fork_hash: forkid::successor(u32::from_be_bytes(SEPOLIA_PIN), later),
                peers: 4,
            })
        );
    }

    #[test]
    fn implausible_announcements_are_ignored() {
        let w = watch(0);
        for bad in [
            1_150_000,
            BEFORE + MAX_HORIZON_SECONDS + DAY,
            BEFORE - 30 * DAY,
            u64::MAX,
        ] {
            announce(&w, "s", 4, SEPOLIA_PIN, bad, BEFORE);
            assert_eq!(w.evaluate(BEFORE), None, "forkNext {bad}");
        }
    }

    #[test]
    fn foreign_hashes_that_are_not_our_successor_are_ignored() {
        let w = watch(0);
        // Stale peers still on Sepolia's BPO1 (the fork BEFORE ours, announcing
        // BPO2's activation), and one on some unrelated id: neither places.
        announce(
            &w,
            "stale",
            4,
            [0x56, 0x07, 0x8a, 0x1e],
            1_761_607_008,
            BEFORE,
        );
        w.observe_at("odd", [0xde, 0xad, 0xbe, 0xef], 0, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn observations_expire() {
        let w = watch(0);
        announce(&w, "s", 3, SEPOLIA_PIN, T, BEFORE);
        assert!(w.evaluate(BEFORE).is_some());
        assert_eq!(w.evaluate(BEFORE + OBSERVATION_TTL_SECONDS + 1), None);
    }

    #[test]
    fn tracked_sources_are_bounded() {
        let w = watch(0);
        for i in 0..(MAX_TRACKED as u64 + 10) {
            w.observe_at(&format!("s{i}"), SEPOLIA_PIN, 0, BEFORE + i);
        }
        assert_eq!(w.tracked(), MAX_TRACKED);
    }
}
