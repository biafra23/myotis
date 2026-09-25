//! #423, finality path: a finality update is signed by the committee of its
//! signature slot's period too. Built from the committed mainnet update corpus
//! (a finality update is the finality-relevant subset of an update), with the
//! store left at period 1777 holding the next committee — no force-rotation.

use std::{fs, path::PathBuf};

use myotis_consensus::fork::ForkSchedule;
use myotis_consensus::{
    spec,
    store::{LightClientProcessor, LightClientStore},
    types::{LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate},
};

const FORK: [u8; 4] = [6, 0, 0, 0];
const GENESIS: &str = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

fn root(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

fn corpus(name: &str) -> Vec<u8> {
    fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/lc/mainnet").join(name)).unwrap()
}

fn update(name: &str) -> LightClientUpdate {
    LightClientUpdate::decode(&corpus(name)).unwrap()
}

fn finality_of(u: &LightClientUpdate) -> LightClientFinalityUpdate {
    LightClientFinalityUpdate {
        attested_header: u.attested_header.clone(),
        finalized_header: u.finalized_header.clone(),
        finality_branch: u.finality_branch.clone(),
        sync_aggregate: u.sync_aggregate.clone(),
        signature_slot: u.signature_slot,
    }
}

fn processor() -> LightClientProcessor {
    let b = LightClientBootstrap::decode(&corpus("bootstrap.ssz")).unwrap();
    let mut store = LightClientStore::new_mainnet_preset();
    store.initialize(b.header, b.current_sync_committee);
    LightClientProcessor::new(store, ForkSchedule::single(FORK), root(GENESIS))
}

fn with_next() -> LightClientProcessor {
    let mut p = processor();
    assert!(p.process_update(&update("001-update.ssz")));
    assert_eq!(p.store.current_period(), 1777);
    assert!(p.store.next_sync_committee().is_some());
    p
}

#[test]
fn next_period_finality_update_is_accepted_before_rotation() {
    let mut p = with_next();
    let fin = finality_of(&update("002-update.ssz"));
    assert_eq!(spec::compute_sync_committee_period(fin.signature_slot), 1778);
    assert!(p.process_finality_update(&fin), "signed by the held next committee");
    assert_eq!(p.store.finalized_slot(), fin.finalized_header.beacon.slot);
    // Its finalized slot is the first of period 1778, so the store rotated on apply.
    assert_eq!(p.store.current_period(), 1778);
    assert!(p.store.next_sync_committee().is_none());
}

#[test]
fn relabelled_current_committee_finality_update_is_rejected() {
    let mut p = with_next();
    let mut fin = finality_of(&update("001-update.ssz"));
    fin.signature_slot += spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    assert!(!p.process_finality_update(&fin), "current keys must not authenticate next-period participation");
}

#[test]
fn next_period_finality_update_without_a_next_committee_is_rejected() {
    // Bootstrapped only: no next committee held, so period 1778 is not admissible.
    let mut p = processor();
    let fin = finality_of(&update("002-update.ssz"));
    assert!(!p.process_finality_update(&fin));
    // Two periods ahead is never admissible, next committee or not.
    let mut p = with_next();
    let mut far = finality_of(&update("002-update.ssz"));
    far.signature_slot += spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    assert!(!p.process_finality_update(&far));
}

#[test]
fn current_period_finality_update_still_verifies() {
    let mut p = with_next();
    let fin = finality_of(&update("001-update.ssz"));
    assert_eq!(spec::compute_sync_committee_period(fin.signature_slot), 1777);
    assert!(p.process_finality_update(&fin));
}
