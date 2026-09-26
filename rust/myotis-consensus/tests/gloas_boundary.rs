//! The processor across the Fulu→Gloas boundary: synthetic committee, real BLS,
//! synthetic state/body trees with the leaves at the Gloas gindices. Covers the
//! shape gate (and that it runs before the BLS verify), the per-slot proof
//! selection (2856 for a Gloas header, 812 with zero padding for a pre-Gloas
//! finalized header in the Gloas shape), the Gloas state gindices
//! (735 / 2946 / 2945), and the rejections around each.
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
    keys_from(9000)
}

fn keys_from(seed: u64) -> Vec<SecretKey> {
    (0..SYNC_COMMITTEE_SIZE)
        .map(|i| {
            let mut ikm = [0u8; 32];
            ikm[..8].copy_from_slice(&(seed + i as u64).to_le_bytes());
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
    upgraded_header_at(slot, [0; 32], block_hash)
}

/// [`upgraded_header`] over a given state root.
fn upgraded_header_at(slot: u64, state_root: Root, block_hash: Root) -> LightClientHeader {
    let g = spec::EXECUTION_BLOCK_HASH_GINDEX_DENEB;
    let body = Sparse::new(&[(g, block_hash)]);
    let mut branch = vec![[0u8; 32]; 2];
    branch.extend(body.branch(g));
    LightClientHeader {
        beacon: beacon(slot, state_root, body.root()),
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

/// A Gloas-format finality update at a FULU attested slot, built to pass every
/// check the processor runs after its shape gate: the finality leaf sits at the
/// gindex a pre-Gloas slot derives from the 9-node branch (553, not 735), and
/// the attested header proves its block hash at 812, the pre-Gloas slots' rule.
fn gloas_format_at_a_fulu_slot(keys: &[SecretKey]) -> LightClientFinalityUpdate {
    let finalized = upgraded_header(G - 64, [0xf1; 32]);
    let fg = spec::finalized_root_gindex(spec::GLOAS_FINALITY_BRANCH_LEN);
    let state = Sparse::new(&[(fg, finalized.beacon.hash_tree_root())]);
    let attested = upgraded_header_at(G - 10, state.root(), [0xaa; 32]);
    let signature_slot = G - 9;
    let version = schedule().version_for_signature_slot(signature_slot);
    LightClientFinalityUpdate {
        sync_aggregate: sign(keys, &attested, version),
        finality_branch: state.branch(fg),
        attested_header: attested,
        finalized_header: finalized,
        signature_slot,
    }
}

/// A Gloas-format catch-up update attested at G + 40 whose state proves
/// `finalized` at 735 and `next` at 2946 (depths 9 and 11, one root).
fn gloas_catch_up(
    keys: &[SecretKey],
    finalized: LightClientHeader,
    next: &SyncCommittee,
) -> LightClientUpdate {
    let fg = spec::FINALIZED_ROOT_GINDEX_GLOAS;
    let ng = spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS;
    let state = Sparse::new(&[
        (fg, finalized.beacon.hash_tree_root()),
        (ng, next.hash_tree_root()),
    ]);
    let attested = gloas_header(G + 40, state.root(), [0xab; 32]);
    LightClientUpdate {
        sync_aggregate: sign(keys, &attested, GLOAS),
        next_sync_committee_branch: state.branch(ng),
        finality_branch: state.branch(fg),
        next_sync_committee: next.clone(),
        attested_header: attested,
        finalized_header: finalized,
        signature_slot: G + 41,
    }
}

/// Asserts that every check the processor runs AFTER its shape gate passes: the
/// signature under the signature slot's version, the finality branch at the
/// gindex the attested slot's fork selects, and each header's execution proof
/// under its own slot's rule. An update like this can only be refused by the
/// gate (the committee gate before it passes for every update in this file).
fn passes_every_check_after_the_shape_gate(
    p: &LightClientProcessor,
    attested: &LightClientHeader,
    finalized: &LightClientHeader,
    finality_branch: &[Root],
    sync_aggregate: &SyncAggregate,
    signature_slot: u64,
) {
    assert!(verify::verify_sync_aggregate(
        sync_aggregate,
        p.store.current_sync_committee().unwrap(),
        &attested.beacon,
        &schedule().version_for_signature_slot(signature_slot),
        &GVR,
    ));
    let (depth, gindex) = match p.lc_fork_at_slot(attested.beacon.slot) {
        LcFork::Gloas => (
            spec::GLOAS_FINALITY_BRANCH_LEN,
            spec::FINALIZED_ROOT_GINDEX_GLOAS,
        ),
        LcFork::PreGloas => (
            finality_branch.len(),
            spec::finalized_root_gindex(finality_branch.len()),
        ),
    };
    assert!(ssz::verify_merkle_branch(
        &finalized.beacon.hash_tree_root(),
        finality_branch,
        depth,
        gindex,
        &attested.beacon.state_root,
    ));
    assert!(p.verify_header(attested));
    assert!(p.verify_header(finalized));
}

/// The message of every event logged on this thread while `f` runs. The
/// processor logs one debug line per rejection, naming the check that refused
/// it, and nothing for a signature that verifies.
fn logged_during<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Message(String);
    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().unwrap().push(message.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let out = tracing::subscriber::with_default(Capture(log.clone()), f);
    let messages = log.lock().unwrap().clone();
    (out, messages)
}

/// The shape gate refused, and no BLS verify failed before it.
fn refused_by_the_gate(log: &[String]) -> bool {
    log.iter().any(|m| m.contains("wire shape")) && !log.iter().any(|m| m.contains("BLS"))
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
    // Not the store's own committee, so storing the wrong one would show.
    let next = committee(&keys_from(20_000));
    assert_ne!(next.hash_tree_root(), committee(&keys).hash_tree_root());
    let update = gloas_catch_up(&keys, gloas_header(G, [0; 32], [0xf3; 32]), &next);
    assert_eq!(update.next_sync_committee_branch.len(), 11);
    assert_eq!(update.finality_branch.len(), 9);
    assert!(p.process_update(&update));
    assert_eq!(
        p.store.next_sync_committee().map(|c| c.hash_tree_root()),
        Some(next.hash_tree_root())
    );
    assert_eq!(p.store.finalized_slot(), G);
}

#[test]
fn rejects_what_is_not_the_attested_slots_forks_shape_or_proof() {
    let keys = keys();
    let mut p = processor(&keys);

    // Gloas format at a Fulu attested slot, with the proofs a Fulu slot's rules
    // check: only the shape gate can refuse it.
    let u = gloas_format_at_a_fulu_slot(&keys);
    passes_every_check_after_the_shape_gate(
        &p,
        &u.attested_header,
        &u.finalized_header,
        &u.finality_branch,
        &u.sync_aggregate,
        u.signature_slot,
    );
    assert!(
        !p.process_finality_update(&u),
        "Gloas shape at a Fulu attested slot"
    );

    // Electra format with a Gloas attested slot. No build of this passes the
    // later checks — a payload header at a Gloas slot fails its execution proof
    // by construction — so the gate's part is pinned by the ORDER test below.
    assert!(
        !p.process_finality_update(&electra_finality(&keys, 256, G + 2)),
        "payload shape at a Gloas slot"
    );

    let fin = upgraded_header(G - 64, [0xf1; 32]);

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

    // A payload-shaped finalized header inside a Gloas-format update: its proof
    // is the one its pre-Gloas slot uses, so again only the gate refuses it.
    let u = gloas_finality(
        &keys,
        payload_header(G - 32, [0; 32]),
        G + 2,
        spec::FINALIZED_ROOT_GINDEX_GLOAS,
    );
    passes_every_check_after_the_shape_gate(
        &p,
        &u.attested_header,
        &u.finalized_header,
        &u.finality_branch,
        &u.sync_aggregate,
        u.signature_slot,
    );
    assert!(
        !p.process_finality_update(&u),
        "every header of a Gloas update is Gloas-shaped"
    );

    // The same in a catch-up update, whose next committee also proves at 2946:
    // process_update runs the same gate.
    let u = gloas_catch_up(&keys, payload_header(G - 32, [0; 32]), &committee(&keys));
    passes_every_check_after_the_shape_gate(
        &p,
        &u.attested_header,
        &u.finalized_header,
        &u.finality_branch,
        &u.sync_aggregate,
        u.signature_slot,
    );
    assert!(ssz::verify_merkle_branch(
        &u.next_sync_committee.hash_tree_root(),
        &u.next_sync_committee_branch,
        spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
        spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS,
        &u.attested_header.beacon.state_root,
    ));
    assert!(
        !p.process_update(&u),
        "every header of a Gloas catch-up update is Gloas-shaped"
    );

    assert_eq!(p.store.finalized_slot(), 100, "nothing applied");
    assert!(p.store.next_sync_committee().is_none());
}

/// The shape gate runs BEFORE the BLS verify: that is its value on Android,
/// where one verify costs ~17-30 s on ART. No verdict shows the order, so every
/// misrouted update here carries a signature that does NOT verify — a gate after
/// the verify, or none, would have it refused by BLS and log that reason
/// instead. (The reason is what `store.rs` logs at debug; there is no BLS call
/// counter to read.) This is the only way to pin the payload-at-a-Gloas-slot
/// case, which fails its execution proof after the verify whatever it carries.
#[test]
fn the_shape_gate_runs_before_the_bls_verify() {
    let keys = keys();
    let mut p = processor(&keys);
    // A genuine aggregate over another header: well-formed, full participation,
    // the wrong message for every update below.
    let foreign = sign(&keys, &gloas_header(G + 7, [0x77; 32], [0x77; 32]), GLOAS);

    // Control: a well-shaped update carrying it is refused by BLS, and says so.
    let fin = upgraded_header(G - 32, [0xf1; 32]);
    let mut u = gloas_finality(&keys, fin, G + 2, spec::FINALIZED_ROOT_GINDEX_GLOAS);
    u.sync_aggregate = foreign.clone();
    let (applied, log) = logged_during(|| p.process_finality_update(&u));
    assert!(!applied);
    assert!(log.iter().any(|m| m.contains("BLS")), "{log:?}");

    let misrouted = [
        (
            "Gloas shape at a Fulu attested slot",
            gloas_format_at_a_fulu_slot(&keys),
        ),
        (
            "payload shape at a Gloas slot",
            electra_finality(&keys, 256, G + 2),
        ),
        (
            "a payload-shaped finalized header in a Gloas update",
            gloas_finality(
                &keys,
                payload_header(G - 32, [0; 32]),
                G + 2,
                spec::FINALIZED_ROOT_GINDEX_GLOAS,
            ),
        ),
    ];
    for (name, mut u) in misrouted {
        u.sync_aggregate = foreign.clone();
        let (applied, log) = logged_during(|| p.process_finality_update(&u));
        assert!(!applied, "{name}");
        assert!(refused_by_the_gate(&log), "{name}: {log:?}");
    }

    let mut u = gloas_catch_up(&keys, payload_header(G - 32, [0; 32]), &committee(&keys));
    u.sync_aggregate = foreign;
    let (applied, log) = logged_during(|| p.process_update(&u));
    assert!(!applied);
    assert!(refused_by_the_gate(&log), "{log:?}");
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
