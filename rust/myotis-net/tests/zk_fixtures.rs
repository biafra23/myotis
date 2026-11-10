//! Colibri's ZK sync proofs, as served from `period_store/<N>/zk_proof.ssz`
//! (rust/testdata/zk, fetched 2026-11-10), verify under this engine's own pinned
//! chain parameters — and stop verifying the moment any input moves.

use myotis_consensus::zk::{self, ZkChain, ZkReject, ZkSyncData};
use myotis_net::sync::ChainConfig;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../testdata/zk/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn chain(config: &ChainConfig, anchor: [u8; 32]) -> ZkChain<'_> {
    ZkChain {
        anchor_keys_root: anchor,
        fork_schedule: &config.fork_schedule,
        genesis_validators_root: config.genesis_validators_root,
        slots_per_period: config.slots_per_period(),
    }
}

fn check(config: ChainConfig, anchor: [u8; 32], file: &str, period: u64) {
    let data = ZkSyncData::decode(&fixture(file)).expect("decodes");
    let proven = zk::verify_zk_sync_data(&data, period, &chain(&config, anchor))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(proven.period, period);
    assert_eq!(proven.committee.pubkeys.len(), 512 * 48);

    // The period is an input, not something the file gets to pick.
    assert_eq!(
        zk::verify_zk_sync_data(&data, period + 1, &chain(&config, anchor)).unwrap_err(),
        ZkReject::WrongPeriod { requested: period + 1, proven: period }
    );
    // Another network's anchor (or any other root) refuses the same proof.
    let mut other = anchor;
    other[0] ^= 1;
    assert_eq!(
        zk::verify_zk_sync_data(&data, period, &chain(&config, other)).unwrap_err(),
        ZkReject::InvalidProof
    );
    // One flipped pubkey bit changes the committee root the proof is checked for.
    let mut forged = data.clone();
    forged.pubkeys[100] ^= 1;
    assert!(zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).is_err());
    // A different attested header (its root is a public value).
    let mut forged = data.clone();
    forged.attested_header.proposer_index ^= 1;
    assert_eq!(
        zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).unwrap_err(),
        ZkReject::InvalidProof
    );
    // A tampered proof: a moved C coordinate is off the curve, a changed nonce
    // is a different public input.
    let mut forged = data.clone();
    forged.proof[300] ^= 1;
    assert!(zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).is_err());
    let mut forged = data.clone();
    forged.proof[99] ^= 1;
    assert_eq!(
        zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).unwrap_err(),
        ZkReject::InvalidProof
    );
    // A non-zero exit code is refused before any pairing.
    let mut forged = data.clone();
    forged.proof[35] = 1;
    assert_eq!(
        zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).unwrap_err(),
        ZkReject::BadProofHeader
    );
    // A proof for another SP1 verifier release.
    let mut forged = data.clone();
    forged.proof[0] ^= 1;
    assert_eq!(
        zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).unwrap_err(),
        ZkReject::BadProofHeader
    );
    // An unpinned program.
    let mut forged = data;
    forged.vk_hash[5] ^= 1;
    assert_eq!(
        zk::verify_zk_sync_data(&forged, period, &chain(&config, anchor)).unwrap_err(),
        ZkReject::UnknownProgram
    );
}

#[test]
fn mainnet_proof_verifies() {
    check(ChainConfig::mainnet(), zk::anchors::MAINNET, "mainnet-1907.ssz", 1907);
}

#[test]
fn gnosis_proof_verifies() {
    check(ChainConfig::gnosis(), zk::anchors::GNOSIS, "gnosis-3792.ssz", 3792);
}

#[test]
fn sepolia_proof_verifies() {
    check(ChainConfig::sepolia(), zk::anchors::SEPOLIA, "sepolia-1410.ssz", 1410);
}

#[test]
fn a_proof_of_one_network_is_refused_on_another() {
    let data = ZkSyncData::decode(&fixture("mainnet-1907.ssz")).unwrap();
    let sepolia = ChainConfig::sepolia();
    // Even with mainnet's anchor: sepolia's domain is not mainnet's.
    assert_eq!(
        zk::verify_zk_sync_data(&data, 1907, &chain(&sepolia, zk::anchors::MAINNET)).unwrap_err(),
        ZkReject::InvalidProof
    );
}

#[test]
fn truncated_files_are_malformed() {
    let bytes = fixture("gnosis-3792.ssz");
    assert!(matches!(ZkSyncData::decode(&bytes[..1000]), Err(ZkReject::Malformed(_))));
    assert!(matches!(ZkSyncData::decode(&[]), Err(ZkReject::Malformed(_))));
}

/// The whole ZK start, offline: the proof of the current period's committee
/// plus a finality update that committee signed (`<net>-finality.ssz`, from
/// `/eth/v1/beacon/light_client/finality_update` in the same minute as the
/// proof) initialize a store — no bootstrap, no update walk — and the same
/// update is refused for any other committee.
fn initializes_a_store(config: ChainConfig, anchor: [u8; 32], proof: &str, finality: &str, period: u64) {
    use myotis_consensus::store::{LightClientProcessor, LightClientStore, ProvenInitReject};
    use myotis_consensus::types::LightClientFinalityUpdate;

    let data = ZkSyncData::decode(&fixture(proof)).unwrap();
    let proven = zk::verify_zk_sync_data(&data, period, &chain(&config, anchor)).unwrap();
    let update = LightClientFinalityUpdate::decode(&fixture(finality)).unwrap_or_else(|e| panic!("{finality}: {e:?}"));
    let new_processor = || {
        LightClientProcessor::new(
            LightClientStore::new(config.slots_per_period()),
            config.fork_schedule.clone(),
            config.genesis_validators_root,
        )
    };

    // A committee whose pubkeys are not the proven ones does not sign it.
    let mut wrong = proven.committee.clone();
    wrong.pubkeys.swap(0, 48);
    let mut p = new_processor();
    assert_eq!(
        p.initialize_from_proven_committee(wrong, period, &update),
        Err(ProvenInitReject::Signature)
    );
    assert!(!p.store.is_initialized());
    // Claimed for the wrong period.
    assert_eq!(
        p.initialize_from_proven_committee(proven.committee.clone(), period + 1, &update),
        Err(ProvenInitReject::SignedInAnotherPeriod)
    );

    p.initialize_from_proven_committee(proven.committee.clone(), period, &update).unwrap();
    assert!(p.store.is_initialized());
    assert_eq!(p.store.current_period(), period);
    assert_eq!(p.store.finalized_slot(), update.finalized_header.beacon.slot);
    // The container root is the spec's: the recomputed aggregate key is the
    // committee's real one, so a later update's next-committee branch for this
    // committee and the persisted snapshot both hold.
    assert_eq!(p.store.current_sync_committee().unwrap().aggregate_pubkey, proven.committee.aggregate_pubkey);
    // It replaces a bootstrap, never overrides a store.
    assert_eq!(
        p.initialize_from_proven_committee(proven.committee, period, &update),
        Err(ProvenInitReject::AlreadyInitialized)
    );
}

#[test]
fn mainnet_proof_initializes_a_store() {
    initializes_a_store(ChainConfig::mainnet(), zk::anchors::MAINNET, "mainnet-1907.ssz", "mainnet-finality.ssz", 1907);
}

#[test]
fn gnosis_proof_initializes_a_store() {
    initializes_a_store(ChainConfig::gnosis(), zk::anchors::GNOSIS, "gnosis-3792.ssz", "gnosis-finality.ssz", 3792);
}
