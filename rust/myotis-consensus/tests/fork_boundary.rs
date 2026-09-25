//! #295: the processor must verify each update under the fork version active
//! at ITS `signature_slot`, not one fixed version. Synthetic committee, real
//! BLS: one finality update signed on each side of a schedule boundary, plus
//! the cross-signed variants that must be rejected. Java twin:
//! `LightClientProcessorTest.verifiesAcrossForkBoundary`.

use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
use myotis_consensus::fork::ForkSchedule;
use myotis_consensus::spec;
use myotis_consensus::ssz::{self, Root};
use myotis_consensus::store::{LightClientProcessor, LightClientStore};
use myotis_consensus::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, LightClientFinalityUpdate, LightClientHeader,
    LightClientUpdate, SyncAggregate, SyncCommittee, SYNC_COMMITTEE_SIZE,
};
use myotis_consensus::verify;

const OLD: [u8; 4] = [0x05, 0, 0, 0];
const NEW: [u8; 4] = [0x06, 0, 0, 0];
const GVR: Root = [0u8; 32];
/// Boundary epoch 10 = slot 320 on the mainnet preset.
const BOUNDARY_EPOCH: u64 = 10;

fn keys() -> Vec<SecretKey> {
    (0..SYNC_COMMITTEE_SIZE)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&(8000 + i as u64).to_le_bytes());
            SecretKey::key_gen(&ikm, &[]).unwrap()
        })
        .collect()
}

fn committee(keys: &[SecretKey]) -> SyncCommittee {
    let pks: Vec<_> = keys.iter().map(|k| k.sk_to_pk()).collect();
    let mut flat = Vec::with_capacity(SYNC_COMMITTEE_SIZE * 48);
    for pk in &pks {
        flat.extend_from_slice(&pk.compress());
    }
    let refs: Vec<_> = pks.iter().collect();
    let agg = AggregatePublicKey::aggregate(&refs, false).unwrap().to_public_key();
    SyncCommittee { pubkeys: flat, aggregate_pubkey: agg.compress() }
}

/// Full binary tree over `leaves` (a power of two): level 0 = leaves.
fn levels(leaves: Vec<Root>) -> Vec<Vec<Root>> {
    let mut out = vec![leaves];
    while out.last().unwrap().len() > 1 {
        let prev = out.last().unwrap();
        let next: Vec<Root> =
            prev.chunks(2).map(|p| ssz::sha256_pair(&p[0], &p[1])).collect();
        out.push(next);
    }
    out
}

/// Sibling path for leaf `idx`, bottom-up — the order `verify_merkle_branch` walks.
fn branch(levels: &[Vec<Root>], mut idx: usize) -> Vec<Root> {
    let mut b = Vec::new();
    for level in &levels[..levels.len() - 1] {
        b.push(level[idx ^ 1]);
        idx /= 2;
    }
    b
}

fn execution_header() -> ExecutionPayloadHeader {
    // Any consistent header will do; only the bloom needs its real width.
    ExecutionPayloadHeader { logs_bloom: vec![0; 256], ..Default::default() }
}

/// A header whose execution payload is genuinely committed to its body root
/// (gindex 25 = leaf 9 of a depth-4 body tree).
fn header(slot: u64, state_root: Root) -> LightClientHeader {
    let execution = execution_header();
    let mut leaves = vec![[0u8; 32]; 1 << spec::EXECUTION_PAYLOAD_DEPTH];
    let leaf = (spec::EXECUTION_PAYLOAD_GINDEX as usize) - (1 << spec::EXECUTION_PAYLOAD_DEPTH);
    leaves[leaf] = execution.hash_tree_root();
    let lv = levels(leaves);
    LightClientHeader {
        beacon: BeaconBlockHeader {
            slot,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root,
            body_root: lv.last().unwrap()[0],
        },
        execution,
        execution_branch: branch(&lv, leaf),
    }
}

/// A finality update with a valid depth-7 (Electra) finality branch, signed by
/// the whole committee under `fork_version`.
fn finality_update(
    keys: &[SecretKey],
    finalized_slot: u64,
    signature_slot: u64,
    fork_version: [u8; 4],
) -> LightClientFinalityUpdate {
    let finalized_header = header(finalized_slot, [0; 32]);
    const DEPTH: usize = 7;
    let leaf = (spec::finalized_root_gindex(DEPTH) as usize) - (1 << DEPTH);
    let mut leaves = vec![[0u8; 32]; 1 << DEPTH];
    leaves[leaf] = finalized_header.beacon.hash_tree_root();
    let lv = levels(leaves);
    let attested_header = header(signature_slot, lv.last().unwrap()[0]);
    let sync_aggregate = sign(keys, &attested_header, fork_version);
    LightClientFinalityUpdate {
        attested_header,
        finalized_header,
        finality_branch: branch(&lv, leaf),
        sync_aggregate,
        signature_slot,
    }
}

/// The whole committee signs `attested` under `fork_version`.
fn sign(keys: &[SecretKey], attested: &LightClientHeader, fork_version: [u8; 4]) -> SyncAggregate {
    let domain = verify::compute_domain(&spec::DOMAIN_SYNC_COMMITTEE, &fork_version, &GVR);
    let signing_root = verify::compute_signing_root(&attested.beacon.hash_tree_root(), &domain);
    let sigs: Vec<_> = keys.iter().map(|k| k.sign(&signing_root, myotis_bls::DST, &[])).collect();
    let refs: Vec<_> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, false).unwrap().to_signature();
    SyncAggregate { sync_committee_bits: [0xff; 64], sync_committee_signature: agg.compress() }
}

/// A catch-up update whose finality branch (depth 6, gindex 105) and
/// next-sync-committee branch (depth 5, gindex 55) both verify against ONE
/// attested state root: a 32-leaf state tree with the Checkpoint container at
/// field 20 (epoch root || finalized root) and the committee at field 23.
fn catch_up_update(
    keys: &[SecretKey],
    finalized_slot: u64,
    signature_slot: u64,
    fork_version: [u8; 4],
) -> LightClientUpdate {
    let finalized_header = header(finalized_slot, [0; 32]);
    let next = committee(keys);
    let zero = [0u8; 32];
    let mut leaves = vec![zero; 32];
    leaves[20] = ssz::sha256_pair(&zero, &finalized_header.beacon.hash_tree_root()); // Checkpoint{epoch, root}
    leaves[23] = next.hash_tree_root();
    let lv = levels(leaves);
    let mut finality_branch = vec![zero]; // the epoch leaf, sibling of root inside Checkpoint
    finality_branch.extend(branch(&lv, 20));
    assert_eq!(finality_branch.len(), 6);
    let next_sync_committee_branch = branch(&lv, 23);
    let attested_header = header(signature_slot, lv.last().unwrap()[0]);
    let sync_aggregate = sign(keys, &attested_header, fork_version);
    LightClientUpdate {
        attested_header,
        next_sync_committee: next,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate,
        signature_slot,
    }
}

fn processor(keys: &[SecretKey], schedule: ForkSchedule) -> LightClientProcessor {
    let mut store = LightClientStore::new_mainnet_preset();
    store.initialize(header(100, [0; 32]), committee(keys));
    LightClientProcessor::new(store, schedule, GVR)
}

#[test]
fn verifies_one_update_on_each_side_of_a_fork_boundary() {
    let keys = keys();
    let schedule = ForkSchedule::new(32, &[(0, OLD), (BOUNDARY_EPOCH, NEW)]);
    let boundary_slot = BOUNDARY_EPOCH * 32; // 320
    let mut p = processor(&keys, schedule);

    // signature_slot 320: spec verifies epoch(319) = 9 -> still OLD.
    assert!(p.process_finality_update(&finality_update(&keys, 200, boundary_slot, OLD)));
    assert_eq!(p.store.finalized_slot(), 200);
    // signature_slot 321: epoch(320) = 10 -> NEW.
    assert!(p.process_finality_update(&finality_update(&keys, 300, boundary_slot + 1, NEW)));
    assert_eq!(p.store.finalized_slot(), 300);
}

/// The catch-up path (`LightClientUpdate`) — how a pre-fork checkpoint walks
/// across the boundary. Java twin: `catchUpUpdatesVerifyAcrossForkBoundary`.
#[test]
fn catch_up_updates_verify_across_a_fork_boundary() {
    let keys = keys();
    let schedule = ForkSchedule::new(32, &[(0, OLD), (BOUNDARY_EPOCH, NEW)]);
    let boundary_slot = BOUNDARY_EPOCH * 32;
    let mut p = processor(&keys, schedule);

    assert!(p.process_update(&catch_up_update(&keys, 200, boundary_slot, OLD)));
    assert!(p.store.next_sync_committee().is_some(), "first update proves the next committee");
    assert!(p.process_update(&catch_up_update(&keys, 300, boundary_slot + 1, NEW)));
    assert_eq!(p.store.finalized_slot(), 300);
    // Cross-signed: rejected on both sides.
    assert!(!p.process_update(&catch_up_update(&keys, 400, boundary_slot, NEW)));
    assert!(!p.process_update(&catch_up_update(&keys, 400, boundary_slot + 1, OLD)));
    assert_eq!(p.store.finalized_slot(), 300);
}

#[test]
fn rejects_an_update_signed_under_the_other_sides_version() {
    let keys = keys();
    let schedule = ForkSchedule::new(32, &[(0, OLD), (BOUNDARY_EPOCH, NEW)]);
    let boundary_slot = BOUNDARY_EPOCH * 32;
    let mut p = processor(&keys, schedule);

    // NEW at the last OLD slot, OLD at the first NEW slot: both must fail.
    assert!(!p.process_finality_update(&finality_update(&keys, 200, boundary_slot, NEW)));
    assert!(!p.process_finality_update(&finality_update(&keys, 200, boundary_slot + 1, OLD)));
    assert_eq!(p.store.finalized_slot(), 100, "nothing applied");
}

/// The pre-#295 behaviour, pinned as a regression: a single-version schedule
/// cannot cross the boundary in either direction.
#[test]
fn single_version_schedule_stalls_at_the_boundary() {
    let keys = keys();
    let boundary_slot = BOUNDARY_EPOCH * 32;

    let mut old_only = processor(&keys, ForkSchedule::single(OLD));
    assert!(old_only.process_finality_update(&finality_update(&keys, 200, boundary_slot, OLD)));
    assert!(!old_only.process_finality_update(&finality_update(&keys, 300, boundary_slot + 1, NEW)));

    let mut new_only = processor(&keys, ForkSchedule::single(NEW));
    assert!(!new_only.process_finality_update(&finality_update(&keys, 200, boundary_slot, OLD)));
}
