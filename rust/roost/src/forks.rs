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
        let mut forks: Vec<Fork> = Vec::new();
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
            forks.push(Fork { epoch, version });
        }
        if forks.is_empty() {
            return Err(anyhow!("config/spec exposed no *_FORK_VERSION entries"));
        }
        forks.sort_by_key(|f| f.epoch);

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
