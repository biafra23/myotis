//! Which update may supply the next sync committee. An update carries the
//! `next_sync_committee` of its ATTESTED state — the committee of
//! period(attested) + 1 — so a store at period P, holding no next committee,
//! may adopt it only from an update attested in P (spec
//! `validate_light_client_update`: `update_attested_period == store_period`).
//!
//! The update this pins: the last block of P−1, signed at the first slot of P.
//! It passes the committee gate (signature period P), its BLS verifies against
//! our current committee, and its attested state's genuine next committee is
//! committee(P) — ours — with a genuine branch. Honest servers leave it empty
//! for such an update, but it is public chain data, so any server can fill it
//! in; adopting it installs committee(P) as P+1's at the next rotation, and
//! every genuine P+1 update then fails BLS. Synthetic committees, real BLS.
//! Java twin: `LightClientProcessorTest.aCrossPeriodUpdateDoesNotSupplyTheNextCommittee`
//! and `...theStoreStillRotatesIntoTheRightCommitteeAfterACrossPeriodUpdate`.

use std::collections::HashMap;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, SecretKey};
use myotis_consensus::fork::ForkSchedule;
use myotis_consensus::spec;
use myotis_consensus::ssz::{self, Root};
use myotis_consensus::store::{LightClientProcessor, LightClientStore};
use myotis_consensus::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, HeaderExecution, LightClientHeader,
    LightClientUpdate, SyncAggregate, SyncCommittee, SYNC_COMMITTEE_SIZE,
};
use myotis_consensus::verify;

const FORK: [u8; 4] = [0x05, 0, 0, 0];
const GVR: Root = [0u8; 32];
const PERIOD: u64 = spec::SLOTS_PER_SYNC_COMMITTEE_PERIOD;
/// The store's period.
const P: u64 = 2;

fn keys(seed: u64) -> Vec<SecretKey> {
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

/// A Merkle tree given by the nodes we care about; every other subtree is a
/// zero leaf. Enough to prove two state fields against ONE root.
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

/// A payload-shaped header whose payload is committed to its body at gindex 25.
fn header(slot: u64, state_root: Root) -> LightClientHeader {
    let payload = ExecutionPayloadHeader {
        logs_bloom: vec![0; 256],
        ..Default::default()
    };
    let body = Sparse::new(&[(spec::EXECUTION_PAYLOAD_GINDEX, payload.hash_tree_root())]);
    LightClientHeader {
        beacon: BeaconBlockHeader {
            slot,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root,
            body_root: body.root(),
        },
        execution_branch: body.branch(spec::EXECUTION_PAYLOAD_GINDEX),
        execution: HeaderExecution::Payload(Box::new(payload)),
    }
}

fn sign(keys: &[SecretKey], attested: &LightClientHeader) -> SyncAggregate {
    let domain = verify::compute_domain(&spec::DOMAIN_SYNC_COMMITTEE, &FORK, &GVR);
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

/// An Electra-format catch-up update attested at `attested_slot` and signed one
/// slot later by `signers`, whose attested state proves the finalized header
/// (depth 7, gindex 169) and `next` (depth 6, gindex 87). Every proof in it is
/// genuine; only the periods differ between the cases below.
fn update(
    signers: &[SecretKey],
    attested_slot: u64,
    finalized_slot: u64,
    next: &SyncCommittee,
) -> LightClientUpdate {
    let finalized = header(finalized_slot, [0; 32]);
    let fg = spec::finalized_root_gindex(7);
    let ng = spec::next_sync_committee_gindex(6);
    let state = Sparse::new(&[
        (fg, finalized.beacon.hash_tree_root()),
        (ng, next.hash_tree_root()),
    ]);
    let attested = header(attested_slot, state.root());
    LightClientUpdate {
        sync_aggregate: sign(signers, &attested),
        next_sync_committee: next.clone(),
        next_sync_committee_branch: state.branch(ng),
        finality_branch: state.branch(fg),
        attested_header: attested,
        finalized_header: finalized,
        signature_slot: attested_slot + 1,
    }
}

/// A store bootstrapped at period P with `current` as its committee.
fn processor(current: &SyncCommittee) -> LightClientProcessor {
    let mut store = LightClientStore::new_mainnet_preset();
    store.initialize(header(P * PERIOD + 100, [0; 32]), current.clone());
    LightClientProcessor::new(store, ForkSchedule::single(FORK), GVR)
}

/// The last block of P−1, signed at the first slot of P by committee(P), with
/// its attested state's genuine next committee — committee(P) — filled in.
fn cross_period_update(keys_p: &[SecretKey], committee_p: &SyncCommittee) -> LightClientUpdate {
    let u = update(keys_p, P * PERIOD - 1, P * PERIOD - 64, committee_p);
    assert_eq!(
        spec::compute_sync_committee_period(u.attested_header.beacon.slot),
        P - 1
    );
    assert_eq!(spec::compute_sync_committee_period(u.signature_slot), P);
    u
}

#[test]
fn a_cross_period_update_does_not_supply_the_next_committee() {
    let keys_p = keys(30_000);
    let committee_p = committee(&keys_p);
    let mut p = processor(&committee_p);

    let cross = cross_period_update(&keys_p, &committee_p);
    // Everything in it verifies — that is what made it dangerous.
    assert!(verify::verify_sync_aggregate(
        &cross.sync_aggregate,
        &committee_p,
        &cross.attested_header.beacon,
        &FORK,
        &GVR,
    ));
    assert!(ssz::verify_merkle_branch(
        &cross.next_sync_committee.hash_tree_root(),
        &cross.next_sync_committee_branch,
        6,
        spec::next_sync_committee_gindex(6),
        &cross.attested_header.beacon.state_root,
    ));

    assert!(
        !p.process_update(&cross),
        "an update attested in P-1 carries committee(P), not committee(P+1)"
    );
    assert!(p.store.next_sync_committee().is_none());
    assert_eq!(p.store.current_period(), P);
    assert_eq!(p.store.finalized_slot(), P * PERIOD + 100);
}

/// The consequence, end to end: after a cross-period update was offered, the
/// store still adopts the genuine next committee from P's own update, and the
/// rotation installs THAT committee for P+1 — the one every P+1 update is signed
/// by. With committee(P) adopted instead, the rotation would install our own
/// committee again and the walk would stall at P+1.
#[test]
fn the_store_still_rotates_into_the_right_committee_after_a_cross_period_update() {
    let keys_p = keys(30_000);
    let committee_p = committee(&keys_p);
    let committee_p1 = committee(&keys(31_000));
    assert_ne!(committee_p.hash_tree_root(), committee_p1.hash_tree_root());
    let mut p = processor(&committee_p);

    let _ = p.process_update(&cross_period_update(&keys_p, &committee_p));

    // P's own update: attested and signed in P, finalized in P.
    let own = update(&keys_p, P * PERIOD + 300, P * PERIOD + 256, &committee_p1);
    assert!(p.process_update(&own));
    assert_eq!(
        p.store.next_sync_committee().map(|c| c.hash_tree_root()),
        Some(committee_p1.hash_tree_root()),
        "the next committee is the one P's own update proves"
    );

    p.store.force_rotate_if_past_period((P + 1) * PERIOD + 1);
    assert_eq!(p.store.current_period(), P + 1);
    assert_eq!(
        p.store.current_sync_committee().unwrap().hash_tree_root(),
        committee_p1.hash_tree_root(),
        "P+1 is verified against committee(P+1)"
    );
}
