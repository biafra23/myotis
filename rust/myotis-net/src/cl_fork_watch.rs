//! Consensus-layer stale-software detection — the CL twin of
//! [`crate::el::fork_watch`] (same vote rules, same constants, same Sepolia
//! vectors in the tests; Java twin: `networking.discv5.ClForkWatch`).
//!
//! Notices, from what consensus peers advertise, that the beacon chain has
//! scheduled — or already activated — a fork this build's [`ForkSchedule`]
//! does not carry. The EL watch needs eth peers past the handshake; this one
//! needs only a discv5 table and a Status exchange, so it also fires on a
//! network where the wallet holds no EL peer yet, and on a CL-only fork.
//!
//! Evidence:
//! - **Announced** — a discv5 ENR whose `eth2` field (SSZ `ENRForkID`:
//!   `fork_digest || next_fork_version || next_fork_epoch`) carries one of OUR
//!   digests with a `next_fork_epoch` this schedule does not know. Upgraded
//!   clients publish it from the day their release carries the fork.
//! - **Placed** — an ENR on a digest we do not know whose `next_fork_version`
//!   REPRODUCES that digest under this chain's genesis root and blob params
//!   (a client with no further fork scheduled publishes its CURRENT version
//!   there, per the spec), and whose version is NEWER than ours: the peer is
//!   on a fork past this build. Also a Status `fork_digest` — or an ENR
//!   digest — that reproduces from a version some source announced: the peer
//!   has crossed the announced fork. Placing separates "a later fork of this
//!   chain" from another chain's digest; it is not proof — a lying peer can
//!   mint a self-consistent record for any version.
//!
//! The vote mirrors the EL watch exactly: one vote per SOURCE network
//! ([`source_of`]: IPv4 /24, IPv6 /48) — node ids are free; an advisory needs
//! [`MIN_PEERS`] sources behind one fork AND more of them than sources on our
//! chain announcing nothing unknown (a known transition — a scheduled fork or
//! the configured blob-parameter epoch — is nothing unknown). ADVISORY ONLY:
//! nothing in verification reads it. Evidence ages out [`OBSERVATION_TTL_SECONDS`]
//! after it was presented; a passed announcement keeps counting
//! [`ACTIVATION_GRACE_SECONDS`] past its activation (bridges the rollover to
//! the new digest, ages out a moved date).
//!
//! A Status carrying one of our digests says nothing about what lies ahead,
//! so it is neither support nor dissent — otherwise every exchange before the
//! fork would outvote the announcements. The activation time of a fork known
//! only from placement is unknown (reported as 0): the digest is a truncated
//! hash and does not encode the epoch.
//!
//! One instance per HANDLE, owned by the engine host so it survives
//! pause/resume (the Java twin is ChainStack-owned for the same reason).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use myotis_consensus::fork::ForkSchedule;

use crate::el::fork_watch::{
    self, Advisory, Phase, ACTIVATION_GRACE_SECONDS, MAX_HORIZON_SECONDS, MAX_TRACKED, MIN_PEERS,
    OBSERVATION_TTL_SECONDS,
};
use crate::status::fork_digest_bpo;

/// `FAR_FUTURE_EPOCH`: the ENR's "no next fork scheduled".
pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;

/// The vote key for a peer at `ip` — the EL watch's, so one host's EL and CL
/// records are the same source in both detectors.
pub fn source_of(ip: IpAddr) -> String {
    fork_watch::source_of(ip)
}

/// The IP a libp2p multiaddr names (`/ip4/…` or `/ip6/…`), if any.
pub fn multiaddr_ip(addr: &libp2p::Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// The one advisory a host reports when both detectors have one: ACTIVE over
/// SCHEDULED; then a known activation time over an unknown one; then more
/// sources; then the EL's. Java twin: `ClForkWatch.merge`.
pub fn merge_advisories(el: Option<Advisory>, cl: Option<Advisory>) -> Option<Advisory> {
    match (el, cl) {
        (None, cl) => cl,
        (el, None) => el,
        (Some(e), Some(c)) => {
            let rank = |a: &Advisory| (a.phase == Phase::Active, a.activation_time != 0, a.peers);
            if rank(&c) > rank(&e) {
                Some(c)
            } else {
                Some(e)
            }
        }
    }
}

struct EnrObservation {
    digest: [u8; 4],
    next_version: [u8; 4],
    next_epoch: u64,
    observed_at: u64,
}

struct StatusObservation {
    digest: [u8; 4],
    observed_at: u64,
}

#[derive(Default)]
struct Inner {
    enr_by_source: HashMap<String, EnrObservation>,
    status_by_source: HashMap<String, StatusObservation>,
    last_logged: Option<Advisory>,
}

/// What one source's evidence says, after classification.
enum Vote {
    Dissent,
    Announced { version: [u8; 4], epoch: u64 },
    Placed { version: [u8; 4] },
}

pub struct ClForkWatch {
    label: &'static str,
    schedule: ForkSchedule,
    genesis_validators_root: [u8; 32],
    blob_params_epoch: u64,
    blob_params_max_blobs: u64,
    genesis_time: u64,
    seconds_per_slot: u64,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for ClForkWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClForkWatch")
            .field("label", &self.label)
            .finish()
    }
}

impl ClForkWatch {
    /// A watch over `schedule`: the forks this build knows, judged on the
    /// chain's genesis root, blob params and slot timing. `blob_params_epoch`
    /// is also a KNOWN transition (a peer announcing it announces nothing
    /// unknown).
    pub fn new(
        label: &'static str,
        schedule: ForkSchedule,
        genesis_validators_root: [u8; 32],
        blob_params_epoch: u64,
        blob_params_max_blobs: u64,
        genesis_time: u64,
        seconds_per_slot: u64,
    ) -> ClForkWatch {
        ClForkWatch {
            label,
            schedule,
            genesis_validators_root,
            blob_params_epoch,
            blob_params_max_blobs,
            genesis_time,
            seconds_per_slot,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The digest a fork `version` yields on this chain (with the configured
    /// blob params folded in, as every digest since Fulu is).
    pub fn digest_of(&self, version: [u8; 4]) -> [u8; 4] {
        fork_digest_bpo(
            version,
            self.genesis_validators_root,
            self.blob_params_epoch,
            self.blob_params_max_blobs,
        )
    }

    /// Record a discv5 ENR's `eth2` field from `source` ([`source_of`]), on the
    /// wall clock. Cheap; logs when it changes the advisory.
    pub fn observe_enr(
        &self,
        source: &str,
        digest: [u8; 4],
        next_version: [u8; 4],
        next_epoch: u64,
    ) {
        self.observe_enr_at(
            source,
            digest,
            next_version,
            next_epoch,
            fork_watch::wall_clock_secs(),
        );
    }

    /// [`observe_enr`](Self::observe_enr) as of `now` (unix seconds).
    pub fn observe_enr_at(
        &self,
        source: &str,
        digest: [u8; 4],
        next_version: [u8; 4],
        next_epoch: u64,
        now: u64,
    ) {
        if source.is_empty() {
            return;
        }
        self.update(now, |inner| {
            inner.enr_by_source.insert(
                source.to_string(),
                EnrObservation {
                    digest,
                    next_version,
                    next_epoch,
                    observed_at: now,
                },
            );
            evict_oldest(&mut inner.enr_by_source, |o| o.observed_at);
        });
    }

    /// Record the `fork_digest` a peer from `source` presented in its Status.
    pub fn observe_status(&self, source: &str, digest: [u8; 4]) {
        self.observe_status_at(source, digest, fork_watch::wall_clock_secs());
    }

    /// [`observe_status`](Self::observe_status) as of `now`.
    pub fn observe_status_at(&self, source: &str, digest: [u8; 4], now: u64) {
        if source.is_empty() {
            return;
        }
        self.update(now, |inner| {
            inner.status_by_source.insert(
                source.to_string(),
                StatusObservation {
                    digest,
                    observed_at: now,
                },
            );
            evict_oldest(&mut inner.status_by_source, |o| o.observed_at);
        });
    }

    /// Tracked sources (ENR + Status) — for tests of the [`MAX_TRACKED`] bound.
    pub fn tracked(&self) -> usize {
        let inner = self.inner.lock().expect("cl fork watch");
        inner.enr_by_source.len() + inner.status_by_source.len()
    }

    /// The current advisory on the wall clock, or None.
    pub fn advisory(&self) -> Option<Advisory> {
        self.evaluate(fork_watch::wall_clock_secs())
    }

    /// The advisory as of `now` (unix seconds), or None.
    pub fn evaluate(&self, now: u64) -> Option<Advisory> {
        let mut inner = self.inner.lock().expect("cl fork watch");
        self.evaluate_locked(&mut inner, now)
    }

    fn update(&self, now: u64, mutation: impl FnOnce(&mut Inner)) {
        let current = {
            let mut inner = self.inner.lock().expect("cl fork watch");
            mutation(&mut inner);
            let current = self.evaluate_locked(&mut inner, now);
            if same_fork(inner.last_logged.as_ref(), current.as_ref()) {
                return;
            }
            inner.last_logged = current;
            current
        };
        match current {
            None => tracing::info!(
                network = self.label,
                "[cl-fork-watch] upgrade advisory cleared"
            ),
            Some(a) if a.phase == Phase::Scheduled => tracing::warn!(
                network = self.label, peers = a.peers, activation = a.activation_time,
                fork_digest = %a.fork_hash_hex(),
                "[cl-fork-watch] consensus peers announce a network upgrade this build does not \
                 support — update before then"
            ),
            Some(a) => tracing::warn!(
                network = self.label, peers = a.peers, activation = a.activation_time,
                fork_digest = %a.fork_hash_hex(),
                "[cl-fork-watch] consensus peers are on a fork this build does not support — \
                 update required"
            ),
        }
    }

    fn wall_epoch(&self, now: u64) -> u64 {
        let epoch_seconds = self.epoch_seconds();
        if epoch_seconds == 0 {
            return 0;
        }
        now.saturating_sub(self.genesis_time) / epoch_seconds
    }

    fn epoch_seconds(&self) -> u64 {
        self.schedule
            .slots_per_epoch()
            .saturating_mul(self.seconds_per_slot)
    }

    /// Unix seconds at which `epoch` starts; None past the plausible horizon
    /// (an announcement that far out is garbage, and the multiply could wrap).
    fn activation_time(&self, epoch: u64, now: u64) -> Option<u64> {
        let seconds = epoch.checked_mul(self.epoch_seconds())?;
        let t = self.genesis_time.checked_add(seconds)?;
        (t <= now.saturating_add(MAX_HORIZON_SECONDS)).then_some(t)
    }

    /// Whether `epoch` is a transition this build knows: a scheduled fork's
    /// activation or the configured blob-parameter epoch.
    fn known_transition(&self, epoch: u64) -> bool {
        epoch == self.blob_params_epoch
            || self
                .schedule
                .forks()
                .iter()
                .any(|(activation, _)| *activation == epoch)
    }

    fn evaluate_locked(&self, inner: &mut Inner, now: u64) -> Option<Advisory> {
        let fresh = now.saturating_sub(OBSERVATION_TTL_SECONDS);
        inner.enr_by_source.retain(|_, o| o.observed_at >= fresh);
        inner.status_by_source.retain(|_, o| o.observed_at >= fresh);

        // Every digest this schedule can produce is "ours": a peer on an older
        // scheduled fork is behind, not news.
        let known_digests: Vec<[u8; 4]> = self
            .schedule
            .forks()
            .iter()
            .map(|(_, v)| self.digest_of(*v))
            .collect();
        let current_version =
            u32::from_be_bytes(self.schedule.version_at_epoch(self.wall_epoch(now)));

        // Pass 1: ENR evidence — the only kind that names the fork ahead.
        let mut votes: HashMap<&str, Vote> = HashMap::new();
        let mut announced_versions: Vec<[u8; 4]> = Vec::new();
        for (source, o) in &inner.enr_by_source {
            let on_ours = known_digests.contains(&o.digest);
            let vote = if self.known_transition(o.next_epoch) {
                Some(Vote::Dissent)
            } else if o.next_epoch == FAR_FUTURE_EPOCH {
                if on_ours {
                    Some(Vote::Dissent)
                } else if self.digest_of(o.next_version) == o.digest
                    && u32::from_be_bytes(o.next_version) > current_version
                {
                    Some(Vote::Placed {
                        version: o.next_version,
                    })
                } else {
                    None
                }
            } else {
                match self.activation_time(o.next_epoch, now) {
                    Some(t) if on_ours && (t > now || now - t < ACTIVATION_GRACE_SECONDS) => {
                        if !announced_versions.contains(&o.next_version) {
                            announced_versions.push(o.next_version);
                        }
                        Some(Vote::Announced {
                            version: o.next_version,
                            epoch: o.next_epoch,
                        })
                    }
                    // A foreign digest announcing a further fork: placeable
                    // only against a version someone announced (pass 2).
                    _ => None,
                }
            };
            if let Some(v) = vote {
                votes.insert(source.as_str(), v);
            }
        }
        // Pass 2: digests alone (a Status, or an ENR that was not placeable
        // above) place against the versions in play.
        let mut versions_in_play: Vec<[u8; 4]> = announced_versions.clone();
        for v in votes.values() {
            if let Vote::Placed { version } = v {
                if !versions_in_play.contains(version) {
                    versions_in_play.push(*version);
                }
            }
        }
        let place = |digest: [u8; 4]| -> Option<[u8; 4]> {
            versions_in_play
                .iter()
                .copied()
                .find(|v| self.digest_of(*v) == digest)
        };
        for (source, o) in &inner.enr_by_source {
            if votes.contains_key(source.as_str()) {
                continue;
            }
            if let Some(version) = place(o.digest) {
                votes.insert(source.as_str(), Vote::Placed { version });
            }
        }
        for (source, o) in &inner.status_by_source {
            if votes.contains_key(source.as_str()) || known_digests.contains(&o.digest) {
                continue;
            }
            if let Some(version) = place(o.digest) {
                votes.insert(source.as_str(), Vote::Placed { version });
            }
        }

        // Tally per version; the activation epoch is the most-announced one
        // (ties → earliest), unknown when nobody announced it.
        let mut dissent = 0usize;
        let mut announced: HashMap<([u8; 4], u64), usize> = HashMap::new();
        let mut placed: HashMap<[u8; 4], usize> = HashMap::new();
        for v in votes.values() {
            match v {
                Vote::Dissent => dissent += 1,
                Vote::Announced { version, epoch } => {
                    *announced.entry((*version, *epoch)).or_default() += 1
                }
                Vote::Placed { version } => *placed.entry(*version).or_default() += 1,
            }
        }
        struct Claim {
            version: [u8; 4],
            epoch: Option<u64>,
            announced: usize,
            placed: usize,
        }
        let mut claims: Vec<Claim> = Vec::new();
        for version in &versions_in_play {
            let mut best_epoch: Option<(u64, usize)> = None;
            for ((v, epoch), n) in &announced {
                if v != version {
                    continue;
                }
                let better = match best_epoch {
                    None => true,
                    Some((e, m)) => *n > m || (*n == m && *epoch < e),
                };
                if better {
                    best_epoch = Some((*epoch, *n));
                }
            }
            claims.push(Claim {
                version: *version,
                epoch: best_epoch.map(|(e, _)| e),
                announced: best_epoch.map(|(_, n)| n).unwrap_or(0),
                placed: placed.get(version).copied().unwrap_or(0),
            });
        }
        let total = |c: &Claim| c.announced + c.placed;
        let mut best: Option<&Claim> = None;
        for c in &claims {
            if total(c) < MIN_PEERS || total(c) <= dissent {
                continue;
            }
            let better = match best {
                None => true,
                Some(b) => {
                    (
                        total(c),
                        c.placed,
                        c.epoch.is_some(),
                        std::cmp::Reverse(c.epoch.unwrap_or(u64::MAX)),
                    ) > (
                        total(b),
                        b.placed,
                        b.epoch.is_some(),
                        std::cmp::Reverse(b.epoch.unwrap_or(u64::MAX)),
                    )
                }
            };
            if better {
                best = Some(c);
            }
        }
        let best = best?;
        let activation_time = best
            .epoch
            .and_then(|e| self.activation_time(e, now))
            .unwrap_or(0);
        let phase = if (activation_time != 0 && activation_time <= now) || best.placed >= MIN_PEERS
        {
            Phase::Active
        } else {
            Phase::Scheduled
        };
        Some(Advisory {
            phase,
            activation_time,
            fork_hash: u32::from_be_bytes(self.digest_of(best.version)),
            peers: total(best),
        })
    }
}

/// Keep the map under [`MAX_TRACKED`] by dropping the stalest observation.
fn evict_oldest<T>(map: &mut HashMap<String, T>, at: impl Fn(&T) -> u64) {
    while map.len() > MAX_TRACKED {
        let Some(stalest) = map
            .iter()
            .min_by_key(|(_, o)| at(o))
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        map.remove(&stalest);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::ChainConfig;

    /// Sepolia on the schedule a build shipped BEFORE Glamsterdam carried:
    /// genesis through Fulu, no Gloas.
    fn pre_gloas_sepolia() -> ClForkWatch {
        let c = ChainConfig::sepolia();
        let forks: Vec<(u64, [u8; 4])> = c
            .fork_schedule
            .forks()
            .iter()
            .copied()
            .filter(|(_, v)| *v != GLOAS_VERSION)
            .collect();
        assert_eq!(
            forks.len() + 1,
            c.fork_schedule.forks().len(),
            "the real schedule carries Gloas"
        );
        ClForkWatch::new(
            "sepolia",
            ForkSchedule::new(c.slots_per_epoch, &forks),
            c.genesis_validators_root,
            c.blob_params_epoch,
            c.blob_params_max_blobs,
            c.genesis_time,
            c.seconds_per_slot,
        )
    }

    /// Sepolia on the schedule this build ships (Gloas included).
    fn current_sepolia() -> ClForkWatch {
        let c = ChainConfig::sepolia();
        ClForkWatch::new(
            "sepolia",
            c.fork_schedule.clone(),
            c.genesis_validators_root,
            c.blob_params_epoch,
            c.blob_params_max_blobs,
            c.genesis_time,
            c.seconds_per_slot,
        )
    }

    const FULU_VERSION: [u8; 4] = [0x90, 0x00, 0x00, 0x75];
    const GLOAS_VERSION: [u8; 4] = [0x90, 0x00, 0x00, 0x76];
    /// Sepolia's Fulu digest with BPO2 folded in (the live wire value).
    const FULU_DIGEST: [u8; 4] = [0x74, 0xD0, 0x14, 0x59];
    /// Sepolia's Gloas digest (same blob params).
    const GLOAS_DIGEST: [u8; 4] = [0x66, 0x9E, 0x6C, 0x11];
    const GLOAS_EPOCH: u64 = 353_024;
    /// Sepolia's Glamsterdam activation, unix seconds (epoch 353024).
    const T: u64 = 1_791_294_816;
    const DAY: u64 = 24 * 3600;
    const BEFORE: u64 = T - 14 * DAY;
    const AFTER: u64 = T + DAY;

    fn announce(w: &ClForkWatch, prefix: &str, n: usize, now: u64) -> Vec<String> {
        let sources: Vec<String> = (0..n).map(|i| format!("{prefix}{i}")).collect();
        for s in &sources {
            w.observe_enr_at(s, FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH, now);
        }
        sources
    }

    fn quiet(w: &ClForkWatch, prefix: &str, n: usize, now: u64) {
        for i in 0..n {
            w.observe_enr_at(
                &format!("{prefix}{i}"),
                FULU_DIGEST,
                FULU_VERSION,
                FAR_FUTURE_EPOCH,
                now,
            );
        }
    }

    fn upgraded(w: &ClForkWatch, prefix: &str, n: usize, now: u64) {
        for i in 0..n {
            w.observe_enr_at(
                &format!("{prefix}{i}"),
                GLOAS_DIGEST,
                GLOAS_VERSION,
                FAR_FUTURE_EPOCH,
                now,
            );
        }
    }

    #[test]
    fn digests_reproduce_the_pinned_wire_values() {
        let w = pre_gloas_sepolia();
        assert_eq!(w.digest_of(FULU_VERSION), FULU_DIGEST);
        assert_eq!(w.digest_of(GLOAS_VERSION), GLOAS_DIGEST);
        assert_eq!(w.activation_time(GLOAS_EPOCH, BEFORE), Some(T));
    }

    #[test]
    fn constants_match_the_shared_twin_pins() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/lc/fork_watch/params.txt");
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
        assert_eq!(num("max_tracked"), MAX_TRACKED as u64);
        assert_eq!(p["enabled_networks"], "mainnet,sepolia,gnosis");
        assert_eq!(p["sepolia_fulu_digest"], "0x74d01459");
        assert_eq!(p["sepolia_gloas_digest"], "0x669e6c11");
        assert_eq!(num("sepolia_gloas_activation"), T);
    }

    #[test]
    fn quiet_network_raises_nothing() {
        let w = pre_gloas_sepolia();
        assert_eq!(w.evaluate(BEFORE), None);
        quiet(&w, "q", 8, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn a_fork_this_build_knows_is_not_news() {
        let w = current_sepolia();
        announce(&w, "a", 6, BEFORE);
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "Gloas is on the schedule: nothing unknown ahead"
        );
        upgraded(&w, "u", 6, AFTER);
        assert_eq!(
            w.evaluate(AFTER),
            None,
            "peers on Gloas are on OUR chain after the fork"
        );
        // The configured blob-parameter epoch is a known transition too.
        let w = pre_gloas_sepolia();
        for i in 0..4 {
            w.observe_enr_at(&format!("b{i}"), FULU_DIGEST, FULU_VERSION, 275_712, BEFORE);
        }
        assert_eq!(w.evaluate(BEFORE), None);
    }

    #[test]
    fn scheduled_needs_three_distinct_sources() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 2, BEFORE);
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "two sources are below the threshold"
        );
        for _ in 0..5 {
            w.observe_enr_at("s0", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH, BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "re-observing a source must not count it twice"
        );
        w.observe_enr_at("s2", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH, BEFORE);
        let a = w.evaluate(BEFORE).expect("advisory");
        assert_eq!(a.phase, Phase::Scheduled);
        assert_eq!(a.activation_time, T);
        assert_eq!(a.fork_hash_hex(), "0x669e6c11");
        assert_eq!(a.peers, 3);
    }

    #[test]
    fn a_minority_cannot_outvote_the_peers_it_contradicts() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, BEFORE);
        quiet(&w, "q", 3, BEFORE);
        assert_eq!(w.evaluate(BEFORE), None, "3 for, 3 against: not a majority");
        w.observe_enr_at("s3", FULU_DIGEST, GLOAS_VERSION, GLOAS_EPOCH, BEFORE);
        assert_eq!(w.evaluate(BEFORE).map(|a| a.peers), Some(4));
    }

    #[test]
    fn status_digests_alone_neither_support_nor_dissent() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, BEFORE);
        for i in 0..20 {
            w.observe_status_at(&format!("st{i}"), FULU_DIGEST, BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE).map(|a| a.peers),
            Some(3),
            "our own digest says nothing about ahead"
        );
        for i in 0..20 {
            w.observe_status_at(&format!("x{i}"), [0xde, 0xad, 0xbe, 0xef], BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE).map(|a| a.peers),
            Some(3),
            "an unplaceable digest is ignored"
        );
    }

    #[test]
    fn announced_becomes_active_on_the_wall_clock() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, T - 3600);
        assert_eq!(w.evaluate(T - 1).map(|a| a.phase), Some(Phase::Scheduled));
        let a = w.evaluate(T).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(a.activation_time, T);
        // The grace bridges the rollover; after it a stale announcement ages out.
        assert!(w.evaluate(T + ACTIVATION_GRACE_SECONDS - 1).is_some());
        assert_eq!(w.evaluate(T + ACTIVATION_GRACE_SECONDS), None);
    }

    #[test]
    fn upgraded_peers_place_the_fork_without_an_announcement() {
        // A wallet started after the fork: every ENR it sees carries the new
        // digest with the new version and no further fork scheduled.
        let w = pre_gloas_sepolia();
        upgraded(&w, "u", 2, AFTER);
        assert_eq!(w.evaluate(AFTER), None);
        upgraded(&w, "u", 3, AFTER);
        let a = w.evaluate(AFTER).expect("advisory");
        assert_eq!(a.phase, Phase::Active, "placed by three sources");
        assert_eq!(a.activation_time, 0, "a digest does not encode its epoch");
        assert_eq!(a.fork_hash_hex(), "0x669e6c11");
        assert_eq!(a.peers, 3);
    }

    #[test]
    fn placement_requires_a_self_consistent_newer_version() {
        let w = pre_gloas_sepolia();
        // Digest and version disagree: another chain, or a lie — unplaceable.
        for i in 0..4 {
            w.observe_enr_at(
                &format!("lie{i}"),
                GLOAS_DIGEST,
                [0x90, 0, 0, 0x77],
                FAR_FUTURE_EPOCH,
                AFTER,
            );
        }
        assert_eq!(w.evaluate(AFTER), None);
        // Self-consistent but OLDER than our fork (a peer left behind): not news.
        let electra = [0x90, 0x00, 0x00, 0x74];
        let electra_digest = w.digest_of(electra);
        for i in 0..4 {
            w.observe_enr_at(
                &format!("old{i}"),
                electra_digest,
                electra,
                FAR_FUTURE_EPOCH,
                AFTER,
            );
        }
        assert_eq!(w.evaluate(AFTER), None);
    }

    #[test]
    fn a_status_on_an_announced_fork_places_the_peer() {
        let w = pre_gloas_sepolia();
        let now = T + 3600;
        announce(&w, "s", 2, now);
        assert_eq!(
            w.evaluate(now),
            None,
            "two announcements are below the threshold"
        );
        // A third source answers a Status on the digest the announced version
        // yields: it has crossed the fork.
        w.observe_status_at("st0", GLOAS_DIGEST, now);
        let a = w.evaluate(now).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(
            a.activation_time, T,
            "the announcement names the epoch the Status cannot"
        );
        assert_eq!(a.peers, 3);
        // Past the grace the announcements stop counting; the Status alone is
        // then unplaceable (no version left in play).
        assert_eq!(w.evaluate(T + ACTIVATION_GRACE_SECONDS), None);
    }

    #[test]
    fn an_announcement_pins_the_epoch_for_placed_peers() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, BEFORE);
        upgraded(&w, "u", 3, AFTER);
        let a = w.evaluate(AFTER).expect("advisory");
        assert_eq!(a.phase, Phase::Active);
        assert_eq!(
            a.activation_time, 0,
            "the announcements aged out a day after T"
        );
        assert_eq!(a.peers, 3);
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, T + 1800);
        upgraded(&w, "u", 3, T + 3600);
        let a = w.evaluate(T + 3600).expect("advisory");
        assert_eq!((a.phase, a.activation_time, a.peers), (Phase::Active, T, 6));
    }

    #[test]
    fn one_vote_per_source_across_both_feeds() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, T + 60);
        // The same three sources also answer a Status on the new digest: still 3.
        for i in 0..3 {
            w.observe_status_at(&format!("s{i}"), GLOAS_DIGEST, T + 60);
        }
        assert_eq!(w.evaluate(T + 60).map(|a| a.peers), Some(3));
    }

    #[test]
    fn evidence_ages_out() {
        let w = pre_gloas_sepolia();
        announce(&w, "s", 3, BEFORE);
        assert!(w.evaluate(BEFORE + OBSERVATION_TTL_SECONDS - 1).is_some());
        assert_eq!(w.evaluate(BEFORE + OBSERVATION_TTL_SECONDS + 1), None);
    }

    #[test]
    fn garbage_epochs_are_ignored() {
        let w = pre_gloas_sepolia();
        for i in 0..4 {
            w.observe_enr_at(
                &format!("g{i}"),
                FULU_DIGEST,
                GLOAS_VERSION,
                u64::MAX - 1,
                BEFORE,
            );
        }
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "an epoch past the horizon (or overflowing) is garbage"
        );
        for i in 0..4 {
            w.observe_enr_at(&format!("h{i}"), FULU_DIGEST, GLOAS_VERSION, 1, BEFORE);
        }
        assert_eq!(
            w.evaluate(BEFORE),
            None,
            "a long-passed epoch announced now is not evidence"
        );
    }

    #[test]
    fn tracked_sources_are_bounded() {
        let w = pre_gloas_sepolia();
        for i in 0..(MAX_TRACKED + 50) {
            w.observe_enr_at(
                &format!("e{i}"),
                FULU_DIGEST,
                FULU_VERSION,
                FAR_FUTURE_EPOCH,
                BEFORE + i as u64,
            );
        }
        for i in 0..(MAX_TRACKED + 50) {
            w.observe_status_at(&format!("s{i}"), FULU_DIGEST, BEFORE + i as u64);
        }
        assert_eq!(w.tracked(), 2 * MAX_TRACKED);
    }

    #[test]
    fn merge_prefers_active_then_a_known_time_then_more_peers_then_el() {
        let el = |phase, t, peers| Advisory {
            phase,
            activation_time: t,
            fork_hash: 0x6c1d_9423,
            peers,
        };
        let cl = |phase, t, peers| Advisory {
            phase,
            activation_time: t,
            fork_hash: 0x669e_6c11,
            peers,
        };
        assert_eq!(merge_advisories(None, None), None);
        assert_eq!(
            merge_advisories(Some(el(Phase::Scheduled, T, 3)), None).map(|a| a.fork_hash),
            Some(0x6c1d_9423)
        );
        assert_eq!(
            merge_advisories(None, Some(cl(Phase::Scheduled, T, 3))).map(|a| a.fork_hash),
            Some(0x669e_6c11)
        );
        assert_eq!(
            merge_advisories(
                Some(el(Phase::Scheduled, T, 9)),
                Some(cl(Phase::Active, 0, 3))
            )
            .map(|a| a.fork_hash),
            Some(0x669e_6c11),
            "ACTIVE outranks SCHEDULED regardless of peers"
        );
        assert_eq!(
            merge_advisories(Some(el(Phase::Active, T, 3)), Some(cl(Phase::Active, 0, 9)))
                .map(|a| a.fork_hash),
            Some(0x6c1d_9423),
            "a known activation time outranks an unknown one"
        );
        assert_eq!(
            merge_advisories(Some(el(Phase::Active, T, 3)), Some(cl(Phase::Active, T, 9)))
                .map(|a| a.fork_hash),
            Some(0x669e_6c11),
            "then more sources"
        );
        assert_eq!(
            merge_advisories(Some(el(Phase::Active, T, 3)), Some(cl(Phase::Active, T, 3)))
                .map(|a| a.fork_hash),
            Some(0x6c1d_9423),
            "a full tie goes to the EL"
        );
    }

    #[test]
    fn multiaddr_ip_reads_ip4_and_ip6() {
        let a: libp2p::Multiaddr = "/ip4/1.2.3.4/tcp/9000".parse().unwrap();
        assert_eq!(multiaddr_ip(&a), Some("1.2.3.4".parse().unwrap()));
        let b: libp2p::Multiaddr = "/ip6/2001:db8::1/tcp/9000".parse().unwrap();
        assert_eq!(multiaddr_ip(&b), Some("2001:db8::1".parse().unwrap()));
        let c: libp2p::Multiaddr = "/dns4/example.org/tcp/9000".parse().unwrap();
        assert_eq!(multiaddr_ip(&c), None);
    }
}
