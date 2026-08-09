//! The chain's fork and blob schedule, and the fork digest for a given slot.
//!
//! # Why this exists
//!
//! Every fork-dependent light-client response carries 4 **context bytes** — the
//! fork digest of the object being served. Until now roost re-used the digest
//! from the newest `updates` chunk for everything, which is correct for the
//! `updates` protocol (the source frames a real digest per chunk, and re-emitting
//! it is the robust path) and an approximation everywhere else.
//!
//! It cannot be derived from a fork *name*. Since EIP-7892 the digest folds in
//! the active blob parameters, so one fork name has as many digests as it has
//! BPO entries — `myotis-net`'s own test pins mainnet Fulu at `0x82FAE541` base
//! versus `0x8C9F62FE` with BPO2. A name→digest table built today would emit a
//! stale digest indefinitely after the next blob-parameter-only fork, while the
//! upstream kept returning 200s.
//!
//! So it is computed, per the spec:
//!
//! ```text
//! fork_digest = (fork_data_root(fork_version, gvr)
//!                XOR sha256(u64_le(bpo_epoch) || u64_le(max_blobs)))[0..4]
//! ```
//!
//! with `fork_version` and `bpo_epoch`/`max_blobs` selected for the object's own
//! epoch. `myotis-net::status::fork_digest_bpo` does the arithmetic; this module
//! supplies the schedule and the selection.
//!
//! # Why the schedule comes from the upstream
//!
//! `/eth/v1/config/spec` is chain *configuration*, not consensus data: fork
//! versions, activation epochs, `SLOTS_PER_EPOCH` and `BLOB_SCHEDULE`. Reading
//! it from the node roost already follows means roost cannot disagree with its
//! own upstream about what fork it is on, and it needs no per-network table here
//! — which matters because gnosis has its own beacon chain with 16-slot epochs.
//!
//! A wrong digest is self-limiting rather than dangerous: peers answer a
//! mismatched `status` with Goodbye(IrrelevantNetwork) and myotis wallets filter
//! on `accepted_fork_digests`. It costs reachability, never correctness — no
//! wallet accepts anything on the strength of a digest.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context, Result};
use myotis_net::status::fork_digest_bpo;

use crate::rest::NimbusRest;

/// A fork's activation epoch and version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    pub epoch: u64,
    pub version: [u8; 4],
}

/// An EIP-7892 blob-parameter-only entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobParams {
    pub epoch: u64,
    pub max_blobs: u64,
}

/// Everything needed to compute a fork digest for any slot on this chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    genesis_validators_root: [u8; 32],
    /// Ascending by activation epoch.
    forks: Vec<Fork>,
    /// Ascending by activation epoch. Empty ⇒ no BPO active, pre-Fulu formula.
    blob_schedule: Vec<BlobParams>,
    slots_per_epoch: u64,
}

impl ForkSchedule {
    /// Read the whole schedule — forks and blob parameters — from the
    /// upstream's `/eth/v1/config/spec`, in one request.
    pub async fn fetch(client: &NimbusRest, genesis_validators_root: [u8; 32]) -> Result<Self> {
        let (spec, blobs) = client.config_spec().await?;
        Ok(Self::from_spec(&spec, genesis_validators_root)?.with_blob_schedule(blobs))
    }

    /// Build from a decoded `config/spec` map.
    ///
    /// Forks are discovered by key shape (`<NAME>_FORK_VERSION` paired with
    /// `<NAME>_FORK_EPOCH`) rather than from a hardcoded list, so a fork added
    /// by a client upgrade is picked up without a code change here.
    ///
    /// `GENESIS_FORK_VERSION` is the ONLY version legitimately without an epoch
    /// key. Any other unpaired version is refused rather than defaulted: a
    /// partial or half-published fork entry silently defaulting to epoch 0 would
    /// sort ahead of the real schedule and could win for early epochs, producing
    /// a wrong digest instead of an obvious failure. An unusable schedule should
    /// fail loudly — roost then falls back to the observed digest and says so.
    pub fn from_spec(
        spec: &BTreeMap<String, String>,
        genesis_validators_root: [u8; 32],
    ) -> Result<Self> {
        // (fork, is_genesis) — the flag drives the tie-break below.
        let mut forks: Vec<(Fork, bool)> = Vec::new();
        for (key, value) in spec {
            let Some(name) = key.strip_suffix("_FORK_VERSION") else {
                continue;
            };
            let version = parse_version(value)
                .with_context(|| format!("parsing {key} = {value}"))?;
            let epoch = match spec.get(&format!("{name}_FORK_EPOCH")) {
                Some(e) => e
                    .parse::<u64>()
                    .with_context(|| format!("parsing {name}_FORK_EPOCH = {e}"))?,
                None if name == "GENESIS" => 0,
                None => {
                    return Err(anyhow!(
                        "config/spec has {key} but no {name}_FORK_EPOCH — refusing a schedule \
                         that would silently activate {name} from genesis"
                    ))
                }
            };
            forks.push((Fork { epoch, version }, name == "GENESIS"));
        }
        if forks.is_empty() {
            return Err(anyhow!("config/spec exposed no *_FORK_VERSION entries"));
        }

        // Tie-break: GENESIS sorts FIRST within an epoch, everything else after.
        //
        // `fork_at_epoch` takes the LAST entry with `epoch <= target`, and the
        // input order is `BTreeMap` key order — lexicographic. Ethereum's fork
        // names happen to be alphabetical in chronological order (ALTAIR <
        // BELLATRIX < CAPELLA < DENEB < ELECTRA < FULU < GLOAS), so real forks
        // tie correctly by luck. `GENESIS` is the one name that breaks it: it
        // sorts between FULU and GLOAS, and its epoch is forced to 0.
        //
        // Without this, ANY chain with a non-genesis fork activated at epoch 0
        // would resolve to GENESIS_FORK_VERSION for every epoch below the next
        // distinctly-scheduled fork — the normal shape for a network launched
        // after a fork rather than before it (a devnet with everything at 0
        // would stamp every response, `status.fork_digest` included, with the
        // genesis digest). mainnet/sepolia/gnosis are unaffected only because
        // GENESIS alone sits at epoch 0 there.
        //
        // The residual assumption — that among NON-genesis forks tying at one
        // epoch, lexicographic order matches chronological order — is left
        // standing deliberately: encoding a fork-rank table here would
        // reintroduce exactly the per-network hardcoding this module exists to
        // avoid. It holds for every fork name shipped to date.
        forks.sort_by_key(|(f, is_genesis)| (f.epoch, !*is_genesis));
        let forks: Vec<Fork> = forks.into_iter().map(|(f, _)| f).collect();

        let slots_per_epoch = spec
            .get("SLOTS_PER_EPOCH")
            .ok_or_else(|| anyhow!("config/spec has no SLOTS_PER_EPOCH"))?
            .parse::<u64>()
            .context("parsing SLOTS_PER_EPOCH")?;
        if slots_per_epoch == 0 {
            return Err(anyhow!("config/spec reports SLOTS_PER_EPOCH = 0"));
        }

        Ok(Self {
            genesis_validators_root,
            forks,
            blob_schedule: Vec::new(),
            slots_per_epoch,
        })
    }

    /// Attach the `BLOB_SCHEDULE` array, which `config/spec` returns as objects
    /// rather than scalars and so arrives separately.
    pub fn with_blob_schedule(mut self, mut entries: Vec<BlobParams>) -> Self {
        entries.sort_by_key(|b| b.epoch);
        self.blob_schedule = entries;
        self
    }

    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    /// The fork active at `epoch` — the latest whose activation is not in the
    /// future. Forks scheduled at `u64::MAX` (a placeholder for "not scheduled",
    /// e.g. GLOAS today) never win, which falls out of the comparison.
    pub fn fork_at_epoch(&self, epoch: u64) -> Fork {
        self.forks
            .iter()
            .rfind(|f| f.epoch <= epoch)
            .copied()
            // Before the first scheduled fork, genesis governs.
            .unwrap_or(self.forks[0])
    }

    /// The blob parameters active at `epoch`, if any.
    pub fn blob_params_at_epoch(&self, epoch: u64) -> Option<BlobParams> {
        self.blob_schedule
            .iter()
            .rfind(|b| b.epoch <= epoch)
            .copied()
    }

    /// The fork digest an object in `epoch` must carry.
    pub fn digest_for_epoch(&self, epoch: u64) -> [u8; 4] {
        let fork = self.fork_at_epoch(epoch);
        match self.blob_params_at_epoch(epoch) {
            // epoch 0 is the sentinel fork_digest_bpo reads as "no BPO active",
            // so a BPO genuinely scheduled at epoch 0 would be indistinguishable
            // from none — harmless, since a BPO at genesis is the base case.
            Some(bp) => fork_digest_bpo(
                fork.version,
                self.genesis_validators_root,
                bp.epoch,
                bp.max_blobs,
            ),
            None => fork_digest_bpo(fork.version, self.genesis_validators_root, 0, 0),
        }
    }

    /// The next scheduled transition after `epoch` — a regular fork OR a BPO
    /// boundary — and the fork version that applies at it.
    ///
    /// Two corrections over the obvious implementation, both from review:
    ///
    /// 1. **A fork parked at `u64::MAX` is not scheduled.** That is the
    ///    placeholder every live spec uses for a fork with no date (GLOAS
    ///    today), and [`ForkSchedule::fork_at_epoch`] already treats it that way.
    ///    Returning it here would have made the documented no-future-fork
    ///    fallback dead code on every real chain.
    /// 2. **A BPO counts as a transition.** Nimbus and Lighthouse both take
    ///    `next_fork_epoch` as the next regular *or* BPO fork, while
    ///    `next_fork_version` stays the CURRENT version across a BPO — because a
    ///    blob-parameter-only boundary changes the digest, not the version.
    ///    Emitting GLOAS/far-future in front of an imminent BPO would disagree
    ///    with every peer that implements it that way.
    pub fn next_transition_after(&self, epoch: u64) -> Option<(u64, [u8; 4])> {
        let next_fork = self
            .forks
            .iter()
            .find(|f| f.epoch > epoch && f.epoch != u64::MAX)
            .copied();
        let next_bpo = self
            .blob_schedule
            .iter()
            .find(|b| b.epoch > epoch && b.epoch != u64::MAX)
            .copied();

        match (next_fork, next_bpo) {
            // Whichever comes first. A BPO keeps the current version; a regular
            // fork brings its own.
            (Some(f), Some(b)) if b.epoch < f.epoch => {
                Some((b.epoch, self.fork_at_epoch(epoch).version))
            }
            (Some(f), _) => Some((f.epoch, f.version)),
            (None, Some(b)) => Some((b.epoch, self.fork_at_epoch(epoch).version)),
            (None, None) => None,
        }
    }

    /// The 16-byte SSZ `ENRForkID` for `epoch`:
    /// `fork_digest(4) || next_fork_version(4) || next_fork_epoch(u64 LE)`.
    ///
    /// This is the ENR's `eth2` field — the thing that makes a published record
    /// findable by the clients it is meant for, and invisible to them if it is
    /// wrong. A TRUNCATED field (just the 4-byte digest) is malformed and
    /// standard clients reject the record outright.
    ///
    /// With no future fork scheduled, the spec's convention is
    /// `next_fork_version = current_fork_version` and
    /// `next_fork_epoch = FAR_FUTURE_EPOCH` (`u64::MAX`).
    ///
    /// # BPO boundaries count as transitions
    ///
    /// `next_fork_epoch` is the next regular *or* BPO fork, matching Nimbus and
    /// Lighthouse; `next_fork_version` stays the current version across a BPO,
    /// because a blob-parameter-only boundary changes the digest and not the
    /// version. See [`ForkSchedule::next_transition_after`] — an earlier draft
    /// of this walked only the fork schedule, which would have advertised
    /// GLOAS/far-future in front of an imminent BPO.
    pub fn enr_fork_id(&self, epoch: u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&self.digest_for_epoch(epoch));
        match self.next_transition_after(epoch) {
            Some((next_epoch, version)) => {
                out[4..8].copy_from_slice(&version);
                out[8..].copy_from_slice(&next_epoch.to_le_bytes());
            }
            None => {
                out[4..8].copy_from_slice(&self.fork_at_epoch(epoch).version);
                out[8..].copy_from_slice(&u64::MAX.to_le_bytes());
            }
        }
        out
    }

    /// The fork digest an object at `slot` must carry.
    pub fn digest_for_slot(&self, slot: u64) -> [u8; 4] {
        self.digest_for_epoch(slot / self.slots_per_epoch)
    }
}

fn parse_version(raw: &str) -> Result<[u8; 4]> {
    let bytes = hex::decode(raw.trim().trim_start_matches("0x"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("fork version is {} bytes, want 4", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        v.as_slice().try_into().unwrap()
    }

    fn sepolia_gvr() -> [u8; 32] {
        hex32("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
    }

    /// The spec keys zbox's Nimbus v26.7.0 actually returns for sepolia.
    fn sepolia_spec() -> BTreeMap<String, String> {
        [
            ("GENESIS_FORK_VERSION", "0x90000069"),
            ("ALTAIR_FORK_VERSION", "0x90000070"),
            ("ALTAIR_FORK_EPOCH", "50"),
            ("BELLATRIX_FORK_VERSION", "0x90000071"),
            ("BELLATRIX_FORK_EPOCH", "100"),
            ("CAPELLA_FORK_VERSION", "0x90000072"),
            ("CAPELLA_FORK_EPOCH", "56832"),
            ("DENEB_FORK_VERSION", "0x90000073"),
            ("DENEB_FORK_EPOCH", "132608"),
            ("ELECTRA_FORK_VERSION", "0x90000074"),
            ("ELECTRA_FORK_EPOCH", "222464"),
            ("FULU_FORK_VERSION", "0x90000075"),
            ("FULU_FORK_EPOCH", "272640"),
            ("GLOAS_FORK_VERSION", "0x07000000"),
            ("GLOAS_FORK_EPOCH", "18446744073709551615"),
            ("SLOTS_PER_EPOCH", "32"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn sepolia() -> ForkSchedule {
        ForkSchedule::from_spec(&sepolia_spec(), sepolia_gvr())
            .unwrap()
            .with_blob_schedule(vec![
                BlobParams { epoch: 274_176, max_blobs: 15 },
                BlobParams { epoch: 275_712, max_blobs: 21 },
            ])
    }

    /// THE test: the digest computed from the schedule must equal the one the
    /// live node framed on the wire. Observed on zbox at head slot 10,873,925
    /// (epoch 339,810) — `0x74d01459`, straight out of the `updates` chunk.
    #[test]
    fn computed_digest_matches_the_live_sepolia_wire_value() {
        assert_eq!(sepolia().digest_for_slot(10_873_925), [0x74, 0xd0, 0x14, 0x59]);
    }

    #[test]
    fn selects_the_active_bpo_entry_not_merely_the_fork() {
        let s = sepolia();
        // Fulu is live from epoch 272640, but the digest changes twice more as
        // each BPO activates — the whole reason a name→digest table is wrong.
        let fulu_no_bpo = s.digest_for_epoch(272_640);
        let bpo1 = s.digest_for_epoch(274_176);
        let bpo2 = s.digest_for_epoch(275_712);
        assert_ne!(fulu_no_bpo, bpo1, "BPO1 must change the digest");
        assert_ne!(bpo1, bpo2, "BPO2 must change it again");
        assert_eq!(bpo2, [0x74, 0xd0, 0x14, 0x59]);
        // One epoch before each boundary still carries the previous value.
        assert_eq!(s.digest_for_epoch(274_175), fulu_no_bpo);
        assert_eq!(s.digest_for_epoch(275_711), bpo1);
    }

    #[test]
    fn matches_the_mainnet_values_pinned_in_myotis_net() {
        // myotis-net's own status.rs test pins mainnet Fulu at 0x82FAE541 base
        // and 0x8C9F62FE with BPO2 (epoch 419072, 21 blobs). Reaching the same
        // answers through the schedule proves the selection, not just the hash.
        let gvr = hex32("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95");
        let spec: BTreeMap<String, String> = [
            ("FULU_FORK_VERSION", "0x06000000"),
            ("FULU_FORK_EPOCH", "0"),
            ("SLOTS_PER_EPOCH", "32"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let base = ForkSchedule::from_spec(&spec, gvr).unwrap();
        assert_eq!(base.digest_for_epoch(1), [0x82, 0xFA, 0xE5, 0x41]);

        let with_bpo = base.with_blob_schedule(vec![BlobParams {
            epoch: 419_072,
            max_blobs: 21,
        }]);
        assert_eq!(with_bpo.digest_for_epoch(419_072), [0x8C, 0x9F, 0x62, 0xFE]);
        // Before BPO2 activates, the base digest still applies.
        assert_eq!(with_bpo.digest_for_epoch(419_071), [0x82, 0xFA, 0xE5, 0x41]);
    }

    #[test]
    fn a_fork_activated_at_genesis_beats_the_genesis_version() {
        // The shape of any network launched after a fork: several forks live
        // from epoch 0. GENESIS must not win those ties, or every response
        // below the next distinctly-scheduled fork carries the genesis digest.
        let mut spec = sepolia_spec();
        spec.insert("ALTAIR_FORK_EPOCH".into(), "0".into());
        spec.insert("BELLATRIX_FORK_EPOCH".into(), "0".into());
        spec.insert("CAPELLA_FORK_EPOCH".into(), "0".into());
        spec.insert("DENEB_FORK_EPOCH".into(), "0".into());
        let s = ForkSchedule::from_spec(&spec, sepolia_gvr()).unwrap();

        // DENEB is the latest fork at epoch 0 and must win — not GENESIS, which
        // sorts after FULU lexicographically and would otherwise take the tie.
        assert_eq!(s.fork_at_epoch(0).version, [0x90, 0, 0, 0x73], "want DENEB");
        assert_eq!(s.fork_at_epoch(1000).version, [0x90, 0, 0, 0x73]);
        // The later, distinctly-scheduled forks still take over on time.
        assert_eq!(s.fork_at_epoch(222_464).version, [0x90, 0, 0, 0x74]);
    }

    #[test]
    fn genesis_still_wins_when_it_is_alone_at_epoch_zero() {
        let s = sepolia();
        assert_eq!(s.fork_at_epoch(0).version, [0x90, 0, 0, 0x69]);
        assert_eq!(s.fork_at_epoch(49).version, [0x90, 0, 0, 0x69]);
        assert_eq!(s.fork_at_epoch(50).version, [0x90, 0, 0, 0x70], "ALTAIR");
    }

    /// The PRODUCTION path: the live sepolia schedule, at the epoch this was
    /// verified against the wire. Previously only a hand-built spec with GLOAS
    /// deleted exercised the no-future-fork branch — a shape no beacon node
    /// returns — so the branch that actually runs was untested.
    #[test]
    fn enr_fork_id_on_the_live_sepolia_schedule() {
        let s = sepolia();
        let id = s.enr_fork_id(339_810);
        assert_eq!(id.len(), 16, "a truncated eth2 field is malformed");
        assert_eq!(&id[..4], &[0x74, 0xd0, 0x14, 0x59], "current digest");
        // Both BPOs are already past and GLOAS sits at u64::MAX — i.e. NOT
        // scheduled — so there is no future transition at all.
        assert_eq!(&id[4..8], &[0x90, 0, 0, 0x75], "current (FULU) version");
        assert_eq!(
            u64::from_le_bytes(id[8..].try_into().unwrap()),
            u64::MAX,
            "a u64::MAX placeholder is not a scheduled fork"
        );
    }

    #[test]
    fn enr_fork_id_names_the_next_scheduled_fork() {
        let s = sepolia();
        // Before ELECTRA, the next transition is ELECTRA at its own epoch.
        let id = s.enr_fork_id(222_000);
        assert_eq!(&id[4..8], &[0x90, 0, 0, 0x74], "ELECTRA version");
        assert_eq!(u64::from_le_bytes(id[8..].try_into().unwrap()), 222_464);
    }

    #[test]
    fn a_bpo_is_the_next_transition_and_keeps_the_current_version() {
        // Nimbus and Lighthouse both count a BPO as next_fork_epoch while
        // leaving next_fork_version at the current fork.
        let s = sepolia();
        // Just after FULU activates, BPO1 (274176) is the next transition.
        let id = s.enr_fork_id(272_640);
        assert_eq!(
            u64::from_le_bytes(id[8..].try_into().unwrap()),
            274_176,
            "the imminent BPO, not GLOAS/far-future"
        );
        assert_eq!(&id[4..8], &[0x90, 0, 0, 0x75], "version stays FULU across a BPO");

        // Between the two BPOs, BPO2 is next.
        let id = s.enr_fork_id(274_176);
        assert_eq!(u64::from_le_bytes(id[8..].try_into().unwrap()), 275_712);
    }

    #[test]
    fn enr_fork_id_falls_back_to_the_current_fork_when_nothing_is_scheduled() {
        // No future fork at all: spec convention is current version + far-future
        // epoch, NOT a zeroed version.
        let spec: BTreeMap<String, String> = [
            ("GENESIS_FORK_VERSION", "0x90000069"),
            ("FULU_FORK_VERSION", "0x90000075"),
            ("FULU_FORK_EPOCH", "272640"),
            ("SLOTS_PER_EPOCH", "32"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let s = ForkSchedule::from_spec(&spec, sepolia_gvr()).unwrap();
        let id = s.enr_fork_id(300_000);
        assert_eq!(&id[4..8], &[0x90, 0, 0, 0x75], "current version, not zeros");
        assert_eq!(u64::from_le_bytes(id[8..].try_into().unwrap()), u64::MAX);
    }

    #[test]
    fn an_unscheduled_fork_never_activates() {
        // GLOAS sits at u64::MAX. It must not win for any real epoch, and must
        // not panic at the boundary either.
        let s = sepolia();
        assert_eq!(s.fork_at_epoch(u64::MAX - 1).version, [0x90, 0, 0, 0x75]);
        assert_eq!(s.fork_at_epoch(0).version, [0x90, 0, 0, 0x69]);
    }

    #[test]
    fn honours_a_non_mainnet_epoch_length() {
        // Gnosis runs 16-slot epochs on its own beacon chain, so slot→epoch is
        // not a mainnet constant. Reading SLOTS_PER_EPOCH from the upstream is
        // what keeps this network-agnostic.
        let mut spec = sepolia_spec();
        spec.insert("SLOTS_PER_EPOCH".into(), "16".into());
        let s = ForkSchedule::from_spec(&spec, sepolia_gvr()).unwrap();
        assert_eq!(s.slots_per_epoch(), 16);
        assert_eq!(s.digest_for_slot(16), s.digest_for_epoch(1));
    }

    #[test]
    fn refuses_a_fork_version_with_no_epoch() {
        // A half-published fork entry must fail loudly, not default to genesis
        // and quietly outrank the real schedule for early epochs.
        let mut spec = sepolia_spec();
        spec.insert("NEWFORK_FORK_VERSION".into(), "0x90000099".into());
        let err = ForkSchedule::from_spec(&spec, sepolia_gvr()).unwrap_err().to_string();
        assert!(err.contains("NEWFORK_FORK_EPOCH"), "got: {err}");

        // GENESIS remains the one legitimate exception.
        let mut only_genesis = sepolia_spec();
        only_genesis.remove("ALTAIR_FORK_EPOCH");
        only_genesis.remove("ALTAIR_FORK_VERSION");
        assert!(ForkSchedule::from_spec(&only_genesis, sepolia_gvr()).is_ok());
    }

    #[test]
    fn refuses_a_spec_it_cannot_use() {
        let empty: BTreeMap<String, String> = BTreeMap::new();
        assert!(ForkSchedule::from_spec(&empty, sepolia_gvr()).is_err());

        let mut no_epoch_len = sepolia_spec();
        no_epoch_len.remove("SLOTS_PER_EPOCH");
        assert!(ForkSchedule::from_spec(&no_epoch_len, sepolia_gvr()).is_err());

        let mut zero = sepolia_spec();
        zero.insert("SLOTS_PER_EPOCH".into(), "0".into());
        assert!(
            ForkSchedule::from_spec(&zero, sepolia_gvr()).is_err(),
            "a zero epoch length would divide by zero in digest_for_slot"
        );
    }
}
