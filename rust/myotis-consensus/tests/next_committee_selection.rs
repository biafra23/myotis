//! Network-free regression using the committed, genuinely signed mainnet corpus.
//! Do not force-rotate between updates: process_update explicitly admits a next
//! period signature when the current store already holds its next committee.

use std::{fs, path::PathBuf};

use myotis_consensus::fork::ForkSchedule;
use myotis_consensus::{
    spec, ssz,
    store::{LightClientProcessor, LightClientStore},
    types::{LightClientBootstrap, LightClientUpdate, SyncCommittee},
    verify,
};

const FORK: [u8; 4] = [6, 0, 0, 0];
const GENESIS: &str = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

fn root(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

fn corpus(name: &str) -> Vec<u8> {
    fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/lc/mainnet").join(name)).unwrap()
}

fn update(name: &str) -> LightClientUpdate {
    LightClientUpdate::decode(&corpus(name)).unwrap()
}

fn processor() -> LightClientProcessor {
    let b = LightClientBootstrap::decode(&corpus("bootstrap.ssz")).unwrap();
    assert_eq!(b.header.beacon.hash_tree_root(),
        root("58cb432571912a434ab7fb83317bb60d09632cce53839fc2541417710465b42e"));
    let depth = b.current_sync_committee_branch.len();
    assert!(ssz::verify_merkle_branch(
        &b.current_sync_committee.hash_tree_root(), &b.current_sync_committee_branch,
        depth, spec::sync_committee_gindex(depth), &b.header.beacon.state_root,
    ));
    assert!(LightClientProcessor::verify_execution_branch(&b.header));
    let mut store = LightClientStore::new_mainnet_preset();
    store.initialize(b.header, b.current_sync_committee);
    LightClientProcessor::new(store, ForkSchedule::single(FORK), root(GENESIS))
}

fn signature_valid(u: &LightClientUpdate, committee: &SyncCommittee) -> bool {
    verify::verify_sync_aggregate(
        &u.sync_aggregate, committee, &u.attested_header.beacon, &FORK, &root(GENESIS),
    )
}

fn assert_proofs(u: &LightClientUpdate) {
    assert!(u.signature_slot > u.attested_header.beacon.slot);
    assert!(u.attested_header.beacon.slot >= u.finalized_header.beacon.slot);
    assert!(LightClientProcessor::verify_execution_branch(&u.attested_header));
    assert!(LightClientProcessor::verify_execution_branch(&u.finalized_header));
    let depth = u.finality_branch.len();
    assert!(ssz::verify_merkle_branch(
        &u.finalized_header.beacon.hash_tree_root(), &u.finality_branch,
        depth, spec::finalized_root_gindex(depth), &u.attested_header.beacon.state_root,
    ));
    let depth = u.next_sync_committee_branch.len();
    assert!(ssz::verify_merkle_branch(
        &u.next_sync_committee.hash_tree_root(), &u.next_sync_committee_branch,
        depth, spec::next_sync_committee_gindex(depth), &u.attested_header.beacon.state_root,
    ));
}

fn with_next() -> LightClientProcessor {
    let mut p = processor();
    let first = update("001-update.ssz");
    assert_proofs(&first);
    assert!(signature_valid(&first, p.store.current_sync_committee().unwrap()));
    assert!(p.process_update(&first));
    assert_eq!(p.store.current_period(), 1777);
    assert_ne!(p.store.current_sync_committee().unwrap().hash_tree_root(),
        p.store.next_sync_committee().unwrap().hash_tree_root());
    p
}

#[test]
fn current_period_signature_uses_current_committee() {
    let mut p = with_next();
    let first = update("001-update.ssz");
    assert_eq!(spec::compute_sync_committee_period(first.signature_slot), 1777);
    assert!(!signature_valid(&first, p.store.next_sync_committee().unwrap()));
    assert!(p.process_update(&first));
}

#[test]
fn next_period_signature_uses_next_committee() {
    let mut p = with_next();
    let second = update("002-update.ssz");
    assert_proofs(&second);
    assert_eq!(spec::compute_sync_committee_period(second.signature_slot), 1778);
    assert!(!signature_valid(&second, p.store.current_sync_committee().unwrap()));
    assert!(signature_valid(&second, p.store.next_sync_committee().unwrap()));
    println!("valid real update: store={}, signature_slot={}, signature_period={}, finalized_slot={}",
        p.store.current_period(), second.signature_slot,
        spec::compute_sync_committee_period(second.signature_slot), second.finalized_header.beacon.slot);
    let held_next_root = p.store.next_sync_committee().unwrap().hash_tree_root();
    assert!(p.process_update(&second), "valid next-committee signature must be accepted");
    assert_eq!(p.store.current_period(), 1778);
    assert_eq!(p.store.finalized_slot(), second.finalized_header.beacon.slot);
    // The rotation installed the HELD next committee, not the P+2 committee this
    // update carries (process_update stores an embedded next only when none is held).
    assert_eq!(p.store.current_sync_committee().unwrap().hash_tree_root(), held_next_root);
    assert!(p.store.next_sync_committee().is_none());
}

#[test]
fn wrong_committee_signature_is_rejected() {
    let mut p = with_next();
    let mut first = update("001-update.ssz");
    // Signature slot is not itself signed. Claiming next-period participation
    // must select next keys, rather than accept an old-committee signature.
    first.signature_slot += spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    assert_proofs(&first);
    assert!(signature_valid(&first, p.store.current_sync_committee().unwrap()));
    assert!(!signature_valid(&first, p.store.next_sync_committee().unwrap()));
    assert!(!p.process_update(&first), "current keys must not authenticate next-period participation");
}

#[test]
fn corrupted_signatures_are_rejected_in_both_periods() {
    for name in ["001-update.ssz", "002-update.ssz"] {
        let mut p = with_next();
        let mut u = update(name);
        u.sync_aggregate.sync_committee_signature = [0; 96];
        assert!(!p.process_update(&u));
    }
}

#[test]
fn unknown_next_committee_and_out_of_range_period_are_rejected() {
    let second = update("002-update.ssz");
    assert!(!processor().process_update(&second));
    let mut p = with_next();
    let mut too_far = second;
    too_far.signature_slot += spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD;
    assert!(!p.process_update(&too_far));
}

#[test]
fn ordinary_catch_up_force_rotation_avoids_next_selection_branch() {
    let mut p = with_next();
    // The real catch-up caller uses its wall-slot estimate after every apply.
    p.store.force_rotate_if_past_period(14_704_714);
    assert_eq!(p.store.current_period(), 1778);
    assert!(p.store.next_sync_committee().is_none());
    let second = update("002-update.ssz");
    assert!(signature_valid(&second, p.store.current_sync_committee().unwrap()));
    assert!(p.process_update(&second));
}

#[test]
fn invalid_required_proof_branches_are_rejected_in_both_periods() {
    for name in ["001-update.ssz", "002-update.ssz"] {
        for branch in ["finality", "attested_execution", "finalized_execution"] {
            let mut p = with_next();
            let mut u = update(name);
            match branch {
                "finality" => u.finality_branch[0][0] ^= 1,
                "attested_execution" => u.attested_header.execution_branch[0][0] ^= 1,
                _ => u.finalized_header.execution_branch[0][0] ^= 1,
            }
            assert!(!p.process_update(&u), "{name}: {branch}");
        }
    }
    // The next-committee proof is required when the store does not hold it yet.
    let mut first = update("001-update.ssz");
    first.next_sync_committee_branch[0][0] ^= 1;
    assert!(!processor().process_update(&first));
}

