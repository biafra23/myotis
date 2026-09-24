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
//! Both signals come from peers already confirmed on our chain (network id +
//! genesis — the pool only reports completed handshakes):
//! - **Scheduled**: a peer presents OUR fork hash with `forkNext = T`, a
//!   timestamp this build does not know (announced weeks ahead).
//! - **Active**: a peer presents the hash that FOLLOWS ours once a fork at some
//!   `T` has passed ([`forkid::successor`]) — proof, not a guess. `T` comes from
//!   announcements seen earlier, else from a search over the epoch-aligned
//!   activation times of the last [`SEARCH_WINDOW_SECONDS`], so a wallet that
//!   was offline for the whole announcement window still recognises the fork.
//!
//! An advisory needs [`MIN_PEERS`] distinct peers. ADVISORY ONLY: nothing in
//! verification reads it, so a lying peer can at worst cause a false warning,
//! never a wrong answer. A fork this build knows (its own `fork_next`) never
//! raises one; a peer two or more forks ahead is not covered (single-step proof).
//!
//! One instance per HANDLE, owned by the engine host so it survives pause/resume
//! (the Java twin is ChainStack-owned for the same reason). Clock values are
//! parameters on the pure methods; the `*_now` conveniences read the wall clock.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use myotis_core::forkid;

/// Distinct peers that must agree before an advisory is raised.
pub const MIN_PEERS: usize = 3;
/// A peer's last presented fork id stops counting after this long.
pub const OBSERVATION_TTL_SECONDS: u64 = 24 * 3600;
/// An announced activation keeps its advisory this long past `T` without a
/// successor proof: bridges the rollover from "forkNext = T" to the successor
/// hash, and ages out a rescheduled date's stale announcements.
pub const ACTIVATION_GRACE_SECONDS: u64 = 6 * 3600;
/// Announcements further out than this are treated as garbage.
pub const MAX_HORIZON_SECONDS: u64 = 400 * 24 * 3600;
/// How far back the successor search looks for an activation never seen announced.
pub const SEARCH_WINDOW_SECONDS: u64 = 400 * 24 * 3600;
/// A hash the search could not place is searched again after this.
pub const NEGATIVE_RECHECK_SECONDS: u64 = 3600;
/// Bound on tracked peers (stalest evicted) and on cached placements.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Announced; activation ahead.
    Scheduled,
    /// Passed: proven by successor hashes, or announced and past its time.
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
    /// Distinct peers corroborating it.
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
    seen_at: u64,
}

#[derive(Default)]
struct Inner {
    /// Latest observation per peer node id.
    by_peer: HashMap<[u8; 64], Observation>,
    /// Foreign hash → (activation or None, when searched).
    placements: HashMap<u32, (Option<u64>, u64)>,
    last_logged: Option<Advisory>,
}

pub struct ForkWatch {
    label: String,
    local_hash: u32,
    local_next: u64,
    genesis_time: u64,
    epoch_seconds: u64,
    inner: Mutex<Inner>,
}

impl ForkWatch {
    /// `local_fork_hash`/`local_fork_next`: what WE announce (the `ElConfig` pin
    /// — the wire value, not `forkid`'s conformance copy); `genesis_time` +
    /// `epoch_seconds`: the beacon epoch grid activations sit on (0 disables it).
    pub fn new(
        label: &str,
        local_fork_hash: [u8; 4],
        local_fork_next: u64,
        genesis_time: u64,
        epoch_seconds: u64,
    ) -> ForkWatch {
        ForkWatch {
            label: label.to_string(),
            local_hash: u32::from_be_bytes(local_fork_hash),
            local_next: local_fork_next,
            genesis_time,
            epoch_seconds,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Record the fork id a peer presented in its eth Status, on the wall clock.
    pub fn observe(&self, peer: &[u8; 64], fork_hash: [u8; 4], fork_next: u64) {
        self.observe_at(peer, fork_hash, fork_next, wall_clock_secs());
    }

    /// [`observe`](Self::observe) at `now` (unix seconds). Logs when this
    /// changes the advisory, so the operator log carries it even if nobody
    /// polls status.
    pub fn observe_at(&self, peer: &[u8; 64], fork_hash: [u8; 4], fork_next: u64, now: u64) {
        let current = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            if inner.by_peer.len() >= MAX_TRACKED && !inner.by_peer.contains_key(peer) {
                // Evict the stalest peer (the Java twin's LRU bound).
                if let Some(stalest) = inner
                    .by_peer
                    .iter()
                    .min_by_key(|(_, o)| o.seen_at)
                    .map(|(k, _)| *k)
                {
                    inner.by_peer.remove(&stalest);
                }
            }
            inner.by_peer.insert(
                *peer,
                Observation {
                    hash: u32::from_be_bytes(fork_hash),
                    next: fork_next,
                    seen_at: now,
                },
            );
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
                peers = a.peers,
                activation = a.activation_time,
                fork_id = %a.fork_hash_hex(),
                "fork-watch: peers announce a network upgrade this build does not support — update before then"
            ),
            Some(a) => tracing::warn!(
                network = %self.label,
                peers = a.peers,
                activation = a.activation_time,
                fork_id = %a.fork_hash_hex(),
                "fork-watch: the network upgraded — this build can no longer follow it; update required"
            ),
        }
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

    fn evaluate_locked(&self, inner: &mut Inner, now: u64) -> Option<Advisory> {
        let cutoff = now.saturating_sub(OBSERVATION_TTL_SECONDS);
        inner.by_peer.retain(|_, o| o.seen_at >= cutoff);

        // Announced activation times double as the fast path of the successor search.
        let announced: HashSet<u64> = inner
            .by_peer
            .values()
            .filter(|o| o.hash == self.local_hash && self.is_foreign_activation(o.next, now))
            .map(|o| o.next)
            .collect();
        let grace_floor = now.saturating_sub(ACTIVATION_GRACE_SECONDS);
        let mut proven: HashMap<u64, usize> = HashMap::new();
        let mut scheduled: HashMap<u64, usize> = HashMap::new();
        let foreign: Vec<u32> = inner
            .by_peer
            .values()
            .filter(|o| o.hash != self.local_hash)
            .map(|o| o.hash)
            .collect();
        // One entry per peer ⇒ counts are distinct peers.
        for o in inner.by_peer.values() {
            if o.hash == self.local_hash
                && self.is_foreign_activation(o.next, now)
                && o.next > grace_floor
            {
                *scheduled.entry(o.next).or_default() += 1;
            }
        }
        for hash in foreign {
            if let Some(t) = self.place(inner, hash, &announced, now) {
                *proven.entry(t).or_default() += 1;
            }
        }

        if let Some((t, peers)) = strongest(&proven) {
            return Some(Advisory {
                phase: Phase::Active,
                activation_time: t,
                fork_hash: forkid::successor(self.local_hash, t),
                peers,
            });
        }
        strongest(&scheduled).map(|(t, peers)| Advisory {
            phase: if t > now {
                Phase::Scheduled
            } else {
                Phase::Active
            },
            activation_time: t,
            fork_hash: forkid::successor(self.local_hash, t),
            peers,
        })
    }

    /// A timestamp activation this build doesn't know, within a plausible horizon.
    fn is_foreign_activation(&self, t: u64, now: u64) -> bool {
        t != 0
            && t != self.local_next
            && t >= forkid::TIMESTAMP_THRESHOLD
            && t <= now.saturating_add(MAX_HORIZON_SECONDS)
    }

    /// The activation that turns our hash into `hash`, cached.
    fn place(
        &self,
        inner: &mut Inner,
        hash: u32,
        announced: &HashSet<u64>,
        now: u64,
    ) -> Option<u64> {
        if let Some(&(activation, computed_at)) = inner.placements.get(&hash) {
            if activation.is_some() || now.saturating_sub(computed_at) < NEGATIVE_RECHECK_SECONDS {
                return activation;
            }
        }
        let activation = self.search(hash, announced, now);
        if inner.placements.len() >= MAX_TRACKED {
            inner.placements.clear();
        }
        inner.placements.insert(hash, (activation, now));
        activation
    }

    fn search(&self, hash: u32, announced: &HashSet<u64>, now: u64) -> Option<u64> {
        // A peer past a fork we DO know (our announced forkNext) is not news.
        if self.local_next != 0 && forkid::successor(self.local_hash, self.local_next) == hash {
            return None;
        }
        if let Some(&t) = announced
            .iter()
            .find(|&&t| forkid::successor(self.local_hash, t) == hash)
        {
            return Some(t);
        }
        let epoch = self.epoch_seconds;
        if epoch == 0 || now.saturating_add(epoch) < self.genesis_time {
            return None;
        }
        // Forks activate on epoch boundaries (EL timestamps track the CL fork
        // epoch), so genesis + k·epoch covers every real activation.
        let lo = self
            .genesis_time
            .max(now.saturating_sub(SEARCH_WINDOW_SECONDS));
        let k_lo = (lo - self.genesis_time).div_ceil(epoch);
        let k_hi = (now.saturating_add(epoch) - self.genesis_time) / epoch;
        (k_lo..=k_hi)
            .rev() // newest first: the likeliest match
            .map(|k| self.genesis_time + k * epoch)
            .find(|&t| t != self.local_next && forkid::successor(self.local_hash, t) == hash)
    }
}

/// Most-corroborated activation with at least [`MIN_PEERS`]; ties → earliest.
fn strongest(counts: &HashMap<u64, usize>) -> Option<(u64, usize)> {
    counts
        .iter()
        .filter(|(_, &n)| n >= MIN_PEERS)
        .map(|(&t, &n)| (t, n))
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
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

    fn watch(local_next: u64) -> ForkWatch {
        ForkWatch::new("sepolia", SEPOLIA_PIN, local_next, SEPOLIA_GENESIS, EPOCH)
    }

    fn peer(i: u8) -> [u8; 64] {
        [i; 64]
    }

    fn announce(w: &ForkWatch, peers: u8, hash: [u8; 4], next: u64, now: u64) {
        for i in 0..peers {
            w.observe_at(&peer(i), hash, next, now);
        }
    }

    #[test]
    fn enabled_on_sepolia_only() {
        assert!(enabled_for("sepolia"));
        assert!(!enabled_for("mainnet"));
        assert!(!enabled_for("gnosis"));
    }

    #[test]
    fn quiet_network_raises_nothing() {
        let w = watch(0);
        assert_eq!(w.evaluate(BEFORE), None);
        announce(&w, 8, SEPOLIA_PIN, 0, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn scheduled_needs_three_distinct_peers() {
        let w = watch(0);
        announce(&w, 2, SEPOLIA_PIN, T, BEFORE);
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "two peers are below the threshold"
        );
        for _ in 0..5 {
            w.observe_at(&peer(0), SEPOLIA_PIN, T, BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "re-observing a peer must not count it twice"
        );
        w.observe_at(&peer(2), SEPOLIA_PIN, T, BEFORE);
        let a = w.evaluate(BEFORE).expect("advisory");
        assert_eq!(a.phase, Phase::Scheduled);
        assert_eq!(a.activation_time, T);
        assert_eq!(a.fork_hash_hex(), "0x6c1d9423");
        assert_eq!(a.peers, 3);
    }

    #[test]
    fn active_is_proven_from_successor_hashes_without_any_announcement() {
        // Offline for the whole announcement window: only upgraded peers after the fork.
        let now = T + 3 * DAY;
        let w = watch(0);
        announce(&w, 3, SUCCESSOR, 0, now);
        let a = w.evaluate(now).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(a.activation_time, T);
        assert_eq!(a.fork_hash, u32::from_be_bytes(SUCCESSOR));
    }

    #[test]
    fn announcement_turns_active_at_its_time_then_ages_out_without_proof() {
        let w = watch(0);
        // Seen an hour before activation — within the observation TTL throughout.
        announce(&w, 3, SEPOLIA_PIN, T, T - 3600);
        assert_eq!(w.evaluate(T - 1).unwrap().phase, Phase::Scheduled);
        assert_eq!(w.evaluate(T + 3600).unwrap().phase, Phase::Active);
        assert_eq!(w.evaluate(T + ACTIVATION_GRACE_SECONDS + 1), None);
    }

    #[test]
    fn proof_outranks_announcements() {
        let now = T + DAY;
        let later = T + 30 * DAY;
        let w = watch(0);
        for i in 10..14 {
            w.observe_at(&peer(i), SEPOLIA_PIN, later, now);
        }
        announce(&w, 3, SUCCESSOR, 0, now);
        let a = w.evaluate(now).unwrap();
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(a.activation_time, T);
    }

    #[test]
    fn rescheduled_date_follows_the_peers_latest_announcements() {
        let projected = T - 15 * DAY;
        let now = projected - 7 * DAY;
        let w = watch(0);
        announce(&w, 3, SEPOLIA_PIN, projected, now);
        assert_eq!(w.evaluate(now).unwrap().activation_time, projected);
        announce(&w, 3, SEPOLIA_PIN, T, now);
        assert_eq!(w.evaluate(now).unwrap().activation_time, T);
    }

    #[test]
    fn a_fork_this_build_knows_is_not_news() {
        let w = watch(T);
        announce(&w, 5, SEPOLIA_PIN, T, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
        for i in 20..25 {
            w.observe_at(&peer(i), SUCCESSOR, 0, T + DAY);
        }
        assert_eq!(w.evaluate(T + DAY), None);
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
            announce(&w, 4, SEPOLIA_PIN, bad, BEFORE);
            assert_eq!(w.evaluate(BEFORE), None, "forkNext {bad}");
        }
    }

    #[test]
    fn foreign_hashes_that_are_not_our_successor_are_ignored() {
        let w = watch(0);
        announce(&w, 4, [0x1d, 0xd8, 0xe8, 0xd9], 1_760_000_000, BEFORE);
        w.observe_at(&peer(99), [0xde, 0xad, 0xbe, 0xef], 0, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn observations_expire() {
        let w = watch(0);
        announce(&w, 3, SEPOLIA_PIN, T, BEFORE);
        assert!(w.evaluate(BEFORE).is_some());
        assert_eq!(w.evaluate(BEFORE + OBSERVATION_TTL_SECONDS + 1), None);
    }

    #[test]
    fn tracked_peers_are_bounded() {
        let w = watch(0);
        for i in 0..(MAX_TRACKED as u32 + 10) {
            let mut id = [0u8; 64];
            id[..4].copy_from_slice(&i.to_be_bytes());
            w.observe_at(&id, SEPOLIA_PIN, 0, BEFORE + i as u64);
        }
        assert_eq!(w.inner.lock().unwrap().by_peer.len(), MAX_TRACKED);
    }
}
