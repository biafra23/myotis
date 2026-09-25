//! The processor across the Fulu→Gloas boundary: synthetic committee, real BLS,
//! synthetic state/body trees with the leaves at the Gloas gindices. Covers the
//! shape gate, the per-slot proof selection (2856 for a Gloas header, 812 with
//! zero padding for a pre-Gloas finalized header in the Gloas shape), the Gloas
//! state gindices (735 / 2946 / 2945), and the rejections around each.
//! Java twin: `GloasBoundaryTest`.

use std::collections::HashMap;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
use myotis_consensus::fork::{ForkSchedule, LcFork};
use myotis_consensus::spec;
use myotis_consensus::ssz::{self, Root};
use myotis_consensus::store::{BootstrapReject, LightClientProcessor, LightClientStore};
use myotis_consensus::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, HeaderExecution, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
    SYNC_COMMITTEE_SIZE,
};
use myotis_consensus::verify;

const FULU: [u8; 4] = [0x06, 0, 0, 0];
const GLOAS: [u8; 4] = [0x07, 0, 0, 0];
const GVR: Root = [0u8; 32];
/// Gloas at epoch 10 = slot 320 on the mainnet preset.
const GLOAS_EPOCH: u64 = 10;
const G: u64 = GLOAS_EPOCH * 32;

fn schedule() -> ForkSchedule {
    ForkSchedule::new(32, &[(0, FULU), (GLOAS_EPOCH, GLOAS)]).with_gloas_epoch(GLOAS_EPOCH)
}

fn keys() -> Vec<SecretKey> {
    (0..SYNC_COMMITTEE_SIZE)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&(9000 + i as u64).to_le_bytes());
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
    let agg = AggregatePublicKey::aggregate(&refs, false)
        .unwrap()
        .to_public_key();
    SyncCommittee {
        pubkeys: flat,
        aggregate_pubkey: agg.compress(),
    }
}

/// A Merkle tree given by the nodes we care about, at any depths; every other
/// subtree is a zero leaf. Enough to prove several gindices of different
/// depths against ONE root, as a real (progressive) state or body does.
struct Sparse(HashMap<u64, Root>);

impl Sparse {
    fn new(leaves: &[(u64, Root)]) -> Self {
        Sparse(leaves.iter().copied().collect())
    }
    fn covers(&self, g: u64) -> bool {
        self.0.keys().any(|&k| {
            let mut k = k;
            while k > g {
                k /= 2;
            }
            k == g
        })
    }
    fn node(&self, g: u64) -> Root {
        if let Some(v) = self.0.get(&g) {
            *v
        } else if self.covers(g) {
            ssz::sha256_pair(&self.node(2 * g), &self.node(2 * g + 1))
        } else {
            [0u8; 32]
        }
    }
    fn root(&self) -> Root {
        self.node(1)
    }
    /// Bottom-up sibling path of `g`.
    fn branch(&self, mut g: u64) -> Vec<Root> {
        let mut b = Vec::new();
        while g > 1 {
            b.push(self.node(g ^ 1));
            g /= 2;
        }
        b
    }
}

fn payload() -> ExecutionPayloadHeader {
    ExecutionPayloadHeader {
        logs_bloom: vec![0; 256],
        block_hash: [0xee; 32],
        ..Default::default()
    }
}

fn beacon(slot: u64, state_root: Root, body_root: Root) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot,
        proposer_index: 0,
        parent_root: [0; 32],
        state_root,
        body_root,
    }
}

/// Pre-Gloas shape: the payload header at gindex 25.
fn payload_header(slot: u64, state_root: Root) -> LightClientHeader {
    let p = payload();
    let body = Sparse::new(&[(spec::EXECUTION_PAYLOAD_GINDEX, p.hash_tree_root())]);
    LightClientHeader {
        beacon: beacon(slot, state_root, body.root()),
        execution_branch: body.branch(spec::EXECUTION_PAYLOAD_GINDEX),
        execution: HeaderExecution::Payload(Box::new(p)),
    }
}

/// Gloas shape at a Gloas slot: the block hash at 2856.
fn gloas_header(slot: u64, state_root: Root, block_hash: Root) -> LightClientHeader {
    let g = spec::EXECUTION_BLOCK_HASH_GINDEX_GLOAS;
    let body = Sparse::new(&[(g, block_hash)]);
    LightClientHeader {
        beacon: beacon(slot, state_root, body.root()),
        execution: HeaderExecution::BlockHash(block_hash),
        execution_branch: body.branch(g),
    }
}

/// Gloas shape of a PRE-Gloas header: the block hash at 812, zero-padded to 11.
fn upgraded_header(slot: u64, block_hash: Root) -> LightClientHeader {
    let g = spec::EXECUTION_BLOCK_HASH_GINDEX_DENEB;
    let body = Sparse::new(&[(g, block_hash)]);
    let mut branch = vec![[0u8; 32]; 2];
    branch.extend(body.branch(g));
    LightClientHeader {
        beacon: beacon(slot, [0; 32], body.root()),
        execution: HeaderExecution::BlockHash(block_hash),
        execution_branch: branch,
    }
}

fn sign(keys: &[SecretKey], attested: &LightClientHeader, fork_version: [u8; 4]) -> SyncAggregate {
    let domain = verify::compute_domain(&spec::DOMAIN_SYNC_COMMITTEE, &fork_version, &GVR);
    let signing_root = verify::compute_signing_root(&attested.beacon.hash_tree_root(), &domain);
    let sigs: Vec<_> = keys
        .iter()
        .map(|k| k.sign(&signing_root, myotis_bls::DST, &[]))
        .collect();
    let refs: Vec<_> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&refs, false)
        .unwrap()
        .to_signature();
    SyncAggregate {
        sync_committee_bits: [0xff; 64],
        sync_committee_signature: agg.compress(),
    }
}

/// A Gloas-format finality update: attested (Gloas shape, at `attested_slot`)
/// whose state holds `finalized`'s root at `finality_gindex`.
fn gloas_finality(
    keys: &[SecretKey],
    finalized: LightClientHeader,
    attested_slot: u64,
    finality_gindex: u64,
) -> LightClientFinalityUpdate {
    let state = Sparse::new(&[(finality_gindex, finalized.beacon.hash_tree_root())]);
    let attested = gloas_header(attested_slot, state.root(), [0xaa; 32]);
    let signature_slot = attested_slot + 1;
    let version = schedule().version_for_signature_slot(signature_slot);
    LightClientFinalityUpdate {
        sync_aggregate: sign(keys, &attested, version),
        finality_branch: state.branch(finality_gindex),
        attested_header: attested,
        finalized_header: finalized,
        signature_slot,
    }
}

/// A pre-Gloas (Electra-format) finality update, depth-7 finality branch.
fn electra_finality(
    keys: &[SecretKey],
    finalized_slot: u64,
    attested_slot: u64,
) -> LightClientFinalityUpdate {
    let finalized = payload_header(finalized_slot, [0; 32]);
    let g = spec::finalized_root_gindex(7);
    let state = Sparse::new(&[(g, finalized.beacon.hash_tree_root())]);
    let attested = payload_header(attested_slot, state.root());
    let signature_slot = attested_slot + 1;
    let version = schedule().version_for_signature_slot(signature_slot);
    LightClientFinalityUpdate {
        sync_aggregate: sign(keys, &attested, version),
        finality_branch: state.branch(g),
        attested_header: attested,
        finalized_header: finalized,
        signature_slot,
    }
}

fn processor(keys: &[SecretKey]) -> LightClientProcessor {
    let mut store = LightClientStore::new_mainnet_preset();
    store.initialize(payload_header(100, [0; 32]), committee(keys));
    LightClientProcessor::new(store, schedule(), GVR)
}

#[test]
fn finality_walks_from_fulu_into_gloas() {
    let keys = keys();
    let mut p = processor(&keys);

    // Last Fulu finality: Electra format, payload-shaped headers.
    assert!(p.process_finality_update(&electra_finality(&keys, 256, G - 8)));
    assert_eq!(p.store.finalized_slot(), 256);

    // First Gloas finality: Gloas format, but the finalized header is still a
    // Fulu block — in the Gloas shape, proving its block hash at 812.
    let fin = upgraded_header(G - 32, [0xf1; 32]);
    let u = gloas_finality(&keys, fin, G + 2, spec::FINALIZED_ROOT_GINDEX_GLOAS);
    assert!(p.process_finality_update(&u));
    assert_eq!(p.store.finalized_slot(), G - 32);
    let held = p.store.finalized_header().unwrap();
    assert_eq!(held.shape(), LcFork::Gloas);
    assert_eq!(held.execution_block_hash(), [0xf1; 32]);
    assert_eq!(
        p.store.optimistic_header().unwrap().execution_block_hash(),
        [0xaa; 32]
    );

    // Then a Gloas block finalizes: block hash at 2856.
    let fin = gloas_header(G, [0; 32], [0xf2; 32]);
    assert!(p.process_finality_update(&gloas_finality(
        &keys,
        fin,
        G + 64,
        spec::FINALIZED_ROOT_GINDEX_GLOAS
    )));
    assert_eq!(p.store.finalized_slot(), G);
    assert_eq!(
        p.store.finalized_header().unwrap().execution_block_hash(),
        [0xf2; 32]
    );
}

#[test]
fn a_gloas_catch_up_update_proves_the_next_committee_at_2946() {
    let keys = keys();
    let mut p = processor(&keys);
    let next = committee(&keys);
    let fin = gloas_header(G, [0; 32], [0xf3; 32]);
    let fg = spec::FINALIZED_ROOT_GINDEX_GLOAS;
    let ng = spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS;
    // One attested state proving both leaves, at depths 9 and 11.
    let state = Sparse::new(&[
        (fg, fin.beacon.hash_tree_root()),
        (ng, next.hash_tree_root()),
    ]);
    let attested = gloas_header(G + 40, state.root(), [0xab; 32]);
    let update = LightClientUpdate {
        sync_aggregate: sign(&keys, &attested, GLOAS),
        next_sync_committee_branch: state.branch(ng),
        finality_branch: state.branch(fg),
        next_sync_committee: next,
        attested_header: attested,
        finalized_header: fin,
        signature_slot: G + 41,
    };
    assert_eq!(update.next_sync_committee_branch.len(), 11);
    assert_eq!(update.finality_branch.len(), 9);
    assert!(p.process_update(&update));
    assert!(p.store.next_sync_committee().is_some());
    assert_eq!(p.store.finalized_slot(), G);
}

#[test]
fn rejects_what_is_not_the_attested_slots_forks_shape_or_proof() {
    let keys = keys();
    let mut p = processor(&keys);

    // Gloas format with a pre-Gloas attested slot: the shape gate (before BLS).
    let fin = upgraded_header(G - 64, [0xf1; 32]);
    let u = gloas_finality(
        &keys,
        fin.clone(),
        G - 10,
        spec::FINALIZED_ROOT_GINDEX_GLOAS,
    );
    assert!(
        !p.process_finality_update(&u),
        "Gloas shape at a Fulu attested slot"
    );

    // Electra format with a Gloas attested slot.
    assert!(
        !p.process_finality_update(&electra_finality(&keys, 256, G + 2)),
        "payload shape at a Gloas slot"
    );

    // Gloas format, finality proven at the depth-derived gindex (553).
    let u = gloas_finality(&keys, fin.clone(), G + 2, spec::finalized_root_gindex(9));
    assert!(
        !p.process_finality_update(&u),
        "the depth-derived gindex is not Gloas'"
    );

    // The pre-Gloas finalized header with a non-zero pad node.
    let mut dirty = fin.clone();
    dirty.execution_branch[1][0] = 1;
    let u = gloas_finality(&keys, dirty, G + 2, spec::FINALIZED_ROOT_GINDEX_GLOAS);
    assert!(
        !p.process_finality_update(&u),
        "a non-zero pad is not padding"
    );

    // A Gloas-slot finalized header proven at 812 instead of 2856.
    let mut at_812 = upgraded_header(G + 1, [0xf4; 32]);
    at_812.beacon.slot = G + 1;
    let u = gloas_finality(&keys, at_812, G + 40, spec::FINALIZED_ROOT_GINDEX_GLOAS);
    assert!(
        !p.process_finality_update(&u),
        "812 is the pre-Gloas slots' rule only"
    );

    // A payload-shaped finalized header inside a Gloas-format update.
    let u = gloas_finality(
        &keys,
        payload_header(G - 32, [0; 32]),
        G + 2,
        spec::FINALIZED_ROOT_GINDEX_GLOAS,
    );
    assert!(
        !p.process_finality_update(&u),
        "every header of a Gloas update is Gloas-shaped"
    );

    assert_eq!(p.store.finalized_slot(), 100, "nothing applied");
}

#[test]
fn a_gloas_bootstrap_verifies_at_2945_and_2856() {
    let keys = keys();
    let p = processor(&keys);
    let current = committee(&keys);
    let cg = spec::CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS;
    let state = Sparse::new(&[(cg, current.hash_tree_root())]);
    let bootstrap = LightClientBootstrap {
        header: gloas_header(G + 32, state.root(), [0xbb; 32]),
        current_sync_committee_branch: state.branch(cg),
        current_sync_committee: current.clone(),
    };
    assert_eq!(p.verify_bootstrap(&bootstrap), Ok(()));

    // The committee at the depth-derived gindex (2070) instead.
    let wrong = Sparse::new(&[(spec::sync_committee_gindex(11), current.hash_tree_root())]);
    let bad = LightClientBootstrap {
        header: gloas_header(G + 32, wrong.root(), [0xbb; 32]),
        current_sync_committee_branch: wrong.branch(spec::sync_committee_gindex(11)),
        current_sync_committee: current.clone(),
    };
    assert_eq!(
        p.verify_bootstrap(&bad),
        Err(BootstrapReject::SyncCommitteeBranch)
    );

    // A Gloas-shaped bootstrap at a Fulu slot.
    let mut early = bootstrap.clone();
    early.header.beacon.slot = G - 1;
    assert_eq!(
        p.verify_bootstrap(&early),
        Err(BootstrapReject::ShapeNotItsForks)
    );

    // A forged block hash under a genuine body root.
    let mut forged = bootstrap;
    forged.header.execution = HeaderExecution::BlockHash([0xcc; 32]);
    assert_eq!(
        p.verify_bootstrap(&forged),
        Err(BootstrapReject::ExecutionBranch)
    );
}
