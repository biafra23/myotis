//! Replays the committed light-client corpus (`rust/testdata/lc/mainnet` — raw SSZ
//! captured from live mainnet) through the RUST verify path and asserts the exact
//! verdicts `expected.txt` records, which the Java `LcVectorConformanceTest`
//! replays and asserts on every JVM build. Identical bytes in → identical verdicts
//! out, on both engines — this test is the plan's PR-4 exit criterion.
//!
//! The corpus is loaded via `CARGO_MANIFEST_DIR` (not `include_bytes!`) so a corpus
//! refresh doesn't force a rebuild; the file set is enumerated from expected.txt's
//! own counts, so a vector added without regenerated verdicts fails loudly here
//! exactly like it does on the Java side.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use myotis_consensus::spec;
use myotis_consensus::ssz;
use myotis_consensus::store::{LightClientProcessor, LightClientStore};
use myotis_consensus::types::{
    LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate,
};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("lc")
        .join("mainnet")
}

fn parse_kv(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex in expected.txt"))
        .collect()
}

#[test]
fn replay_reproduces_recorded_verdicts() {
    let dir = corpus_dir();
    let expected = parse_kv(
        &fs::read_to_string(dir.join("expected.txt"))
            .expect("expected.txt missing — the corpus ships with recorded verdicts"),
    );

    // ---- bootstrap: same branch checks the Java replay (and live client) makes ----
    let bootstrap_ssz = fs::read(dir.join("bootstrap.ssz")).expect("bootstrap.ssz");
    let bootstrap = LightClientBootstrap::decode(&bootstrap_ssz).expect("bootstrap decodes");

    let sc_depth = bootstrap.current_sync_committee_branch.len();
    assert!(
        ssz::verify_merkle_branch(
            &bootstrap.current_sync_committee.hash_tree_root(),
            &bootstrap.current_sync_committee_branch,
            sc_depth,
            spec::sync_committee_gindex(sc_depth),
            &bootstrap.header.beacon.state_root,
        ),
        "bootstrap sync-committee branch must verify"
    );
    assert!(
        LightClientProcessor::verify_execution_branch(&bootstrap.header),
        "bootstrap execution branch must verify"
    );

    let mut actual: BTreeMap<String, String> = BTreeMap::new();
    actual.insert("bootstrap.slot".into(), bootstrap.header.beacon.slot.to_string());
    actual.insert(
        "bootstrap.headerRoot".into(),
        hex(&bootstrap.header.beacon.hash_tree_root()),
    );

    // ---- context recorded in expected.txt ----
    let fork_version: [u8; 4] = unhex(&expected["forkVersion"]).try_into().unwrap();
    let gvr: [u8; 32] = unhex(&expected["genesisValidatorsRoot"]).try_into().unwrap();
    let slot_estimate: u64 = expected["input.currentSlotEstimate"].parse().unwrap();
    actual.insert("forkVersion".into(), expected["forkVersion"].clone());
    actual.insert("genesisValidatorsRoot".into(), expected["genesisValidatorsRoot"].clone());
    actual.insert("input.currentSlotEstimate".into(), slot_estimate.to_string());

    let mut store = LightClientStore::new();
    store.initialize(bootstrap.header.clone(), bootstrap.current_sync_committee.clone());
    let mut processor = LightClientProcessor::new(store, fork_version, gvr);

    // ---- catch-up updates, filename order (3-digit corpus convention) ----
    let mut update_files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with("-update.ssz")
            && n.len() == "000-update.ssz".len()
            && n[..3].chars().all(|c| c.is_ascii_digit()))
        .collect();
    update_files.sort();
    actual.insert("updates.count".into(), update_files.len().to_string());
    for (i, name) in update_files.iter().enumerate() {
        let update = LightClientUpdate::decode(&fs::read(dir.join(name)).unwrap())
            .unwrap_or_else(|e| panic!("{name} decodes: {e}"));
        let applied = processor.process_update(&update);
        if applied {
            // Mirrors the live applyCatchUpResponses loop (and the Java replay).
            processor.store.force_rotate_if_past_period(slot_estimate);
        }
        actual.insert(format!("update.{i}.applied"), applied.to_string());
        actual.insert(
            format!("update.{i}.finalizedSlot"),
            processor.store.finalized_slot().to_string(),
        );
    }

    // ---- finality updates, filename order ----
    let mut finality_files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with("-finality.ssz")
            && n.len() == "000-finality.ssz".len()
            && n[..3].chars().all(|c| c.is_ascii_digit()))
        .collect();
    finality_files.sort();
    actual.insert("finality.count".into(), finality_files.len().to_string());
    for (i, name) in finality_files.iter().enumerate() {
        let update = LightClientFinalityUpdate::decode(&fs::read(dir.join(name)).unwrap())
            .unwrap_or_else(|e| panic!("{name} decodes: {e}"));
        let applied = processor.process_finality_update(&update);
        actual.insert(format!("finality.{i}.applied"), applied.to_string());
    }

    actual.insert(
        "final.finalizedSlot".into(),
        processor.store.finalized_slot().to_string(),
    );
    actual.insert(
        "final.finalizedExecStateRoot".into(),
        hex(&processor.store.finalized_header().unwrap().execution.state_root),
    );

    assert_eq!(
        expected, actual,
        "Rust replay verdicts diverge from expected.txt (the Java-recorded truth)"
    );
}
