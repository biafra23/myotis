//! Sync-committee signature verification — Rust twin of the Java
//! `SyncCommitteeVerifier` + `ForkData.computeDomain`, over the shared
//! [`myotis_bls::fast_aggregate_verify`] core (production POP DST).

use crate::spec;
use crate::ssz::{self, Root};
use crate::types::{BeaconBlockHeader, SyncAggregate, SyncCommittee, PUBKEY_SIZE};

/// compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root):
/// 4 domain-type bytes || first 28 bytes of hash_tree_root(ForkData).
pub fn compute_domain(
    domain_type: &[u8; 4],
    fork_version: &[u8; 4],
    genesis_validators_root: &Root,
) -> Root {
    let fork_data_root = ssz::container_root(&[
        ssz::padded_root(fork_version),
        *genesis_validators_root,
    ]);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(domain_type);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// compute_signing_root(object_root, domain) — a 2-field container root.
pub fn compute_signing_root(object_root: &Root, domain: &Root) -> Root {
    ssz::container_root(&[*object_root, *domain])
}

/// Verify a sync aggregate over an attested header (mirrors
/// `SyncCommitteeVerifier.verify`): ≥2/3 participation, then
/// fast_aggregate_verify of the participating pubkeys over the signing root.
pub fn verify_sync_aggregate(
    sync_aggregate: &SyncAggregate,
    committee: &SyncCommittee,
    attested_header: &BeaconBlockHeader,
    fork_version: &[u8; 4],
    genesis_validators_root: &Root,
) -> bool {
    let participants = sync_aggregate.count_participants();
    if participants * 3 < spec::SYNC_COMMITTEE_SIZE * 2 {
        return false;
    }

    let mut pubkeys = Vec::with_capacity(participants * PUBKEY_SIZE);
    for i in 0..spec::SYNC_COMMITTEE_SIZE {
        if sync_aggregate.get_bit(i) {
            pubkeys.extend_from_slice(committee.pubkey(i));
        }
    }

    let domain = compute_domain(
        &spec::DOMAIN_SYNC_COMMITTEE,
        fork_version,
        genesis_validators_root,
    );
    let signing_root = compute_signing_root(&attested_header.hash_tree_root(), &domain);

    myotis_bls::fast_aggregate_verify(
        &pubkeys,
        participants,
        &signing_root,
        &sync_aggregate.sync_committee_signature,
    )
}
