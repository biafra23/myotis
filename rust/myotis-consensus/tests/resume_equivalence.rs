//! Resume-equivalence over the committed mainnet corpus — the deterministic
//! half of the on-device "restored snapshot failed verification" investigation
//! (a resumed store poisoned itself at a period boundary and deleted a good
//! snapshot; task #6). For EVERY split point k in the accepted catch-up chain,
//! this replays updates 0..k organically, round-trips the store through the
//! LCSS snapshot codec (serialize → deserialize → restore into a FRESH store),
//! then continues k..end — asserting byte-identical verdicts and final state
//! to the uninterrupted replay. Splits land in every state the store passes
//! through on a real catch-up: mid-period, immediately after a force-rotate,
//! with and without a next committee. If restore dropped or mangled anything
//! verification needs, some split here fails on real mainnet data — no phone
//! wedge required.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use myotis_consensus::snapshot;
use myotis_consensus::store::{LightClientProcessor, LightClientStore};
use myotis_consensus::types::{LightClientBootstrap, LightClientFinalityUpdate, LightClientUpdate};

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
        .map(|l| {
            let (k, v) = l.split_once('=').expect("malformed expected.txt line");
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex in expected.txt: {s:?}");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn sorted_files(dir: &PathBuf, suffix: &str, len: usize) -> Vec<String> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(suffix)
            && n.len() == len
            && n.chars().take(3).all(|c| c.is_ascii_digit()))
        .collect();
    files.sort();
    files
}

struct Corpus {
    bootstrap: LightClientBootstrap,
    updates: Vec<LightClientUpdate>,
    finalities: Vec<LightClientFinalityUpdate>,
    fork_version: [u8; 4],
    gvr: [u8; 32],
    slot_estimate: u64,
}

fn load_corpus() -> Corpus {
    let dir = corpus_dir();
    let expected = parse_kv(&fs::read_to_string(dir.join("expected.txt")).expect("expected.txt"));
    let bootstrap = LightClientBootstrap::decode(&fs::read(dir.join("bootstrap.ssz")).unwrap())
        .expect("bootstrap decodes");
    let updates = sorted_files(&dir, "-update.ssz", "000-update.ssz".len())
        .iter()
        .map(|n| LightClientUpdate::decode(&fs::read(dir.join(n)).unwrap()).expect("update decodes"))
        .collect();
    let finalities = sorted_files(&dir, "-finality.ssz", "000-finality.ssz".len())
        .iter()
        .map(|n| {
            LightClientFinalityUpdate::decode(&fs::read(dir.join(n)).unwrap())
                .expect("finality decodes")
        })
        .collect();
    Corpus {
        bootstrap,
        updates,
        finalities,
        fork_version: unhex(&expected["forkVersion"]).try_into().unwrap(),
        gvr: unhex(&expected["genesisValidatorsRoot"]).try_into().unwrap(),
        slot_estimate: expected["input.currentSlotEstimate"].parse().unwrap(),
    }
}

/// (applied verdicts for updates[from..], then finality verdicts, then the
/// final observable store state).
fn replay_from(
    processor: &mut LightClientProcessor,
    c: &Corpus,
    from: usize,
) -> (Vec<bool>, Vec<bool>, (u64, u64, u64, bool)) {
    let mut verdicts = Vec::new();
    for update in &c.updates[from..] {
        let applied = processor.process_update(update);
        if applied {
            processor.store.force_rotate_if_past_period(c.slot_estimate);
        }
        verdicts.push(applied);
    }
    let mut fin_verdicts = Vec::new();
    for f in &c.finalities {
        fin_verdicts.push(processor.process_finality_update(f));
    }
    let s = &processor.store;
    let state = (
        s.current_period(),
        s.finalized_slot(),
        s.optimistic_slot(),
        s.next_sync_committee().is_some(),
    );
    (verdicts, fin_verdicts, state)
}

fn organic_processor(c: &Corpus) -> LightClientProcessor {
    let mut store = LightClientStore::new();
    store.initialize(c.bootstrap.header.clone(), c.bootstrap.current_sync_committee.clone());
    LightClientProcessor::new(store, c.fork_version, c.gvr)
}

#[test]
fn resume_at_every_split_point_matches_uninterrupted_replay() {
    let c = load_corpus();
    assert!(!c.updates.is_empty(), "corpus has updates");

    // Uninterrupted baseline — cross-checked against the conformance oracle
    // (expected.txt's update.N.applied), so this test can never pass
    // vacuously with an all-false baseline from a broken setup.
    let mut baseline_proc = organic_processor(&c);
    let (baseline_verdicts, baseline_fin, baseline_state) = replay_from(&mut baseline_proc, &c, 0);
    let expected = parse_kv(
        &fs::read_to_string(corpus_dir().join("expected.txt")).expect("expected.txt"),
    );
    for (i, verdict) in baseline_verdicts.iter().enumerate() {
        assert_eq!(
            verdict.to_string(),
            expected[&format!("update.{i}.applied")],
            "baseline verdict {i} diverges from the conformance oracle"
        );
    }
    assert!(
        baseline_verdicts.iter().any(|v| *v),
        "baseline must apply at least one update"
    );

    for k in 1..=c.updates.len() {
        // Organic replay up to the split.
        let mut proc = organic_processor(&c);
        for update in &c.updates[..k] {
            if proc.process_update(update) {
                proc.store.force_rotate_if_past_period(c.slot_estimate);
            }
        }

        // Snapshot → bytes → restore into a FRESH store (the resume path).
        let snap = proc.store.snapshot().expect("initialized store snapshots");
        let bytes = snapshot::serialize(&snap, &c.gvr);
        let restored = snapshot::deserialize(&bytes, &c.gvr)
            .unwrap_or_else(|| panic!("split {k}: snapshot must deserialize"));
        let mut resumed_store = LightClientStore::new();
        resumed_store.restore(restored);
        let mut resumed = LightClientProcessor::new(resumed_store, c.fork_version, c.gvr);

        // Continue from the split; verdicts and final state must match the
        // uninterrupted replay exactly.
        let (verdicts, fin_verdicts, state) = replay_from(&mut resumed, &c, k);
        assert_eq!(
            verdicts,
            baseline_verdicts[k..].to_vec(),
            "split {k}: post-resume update verdicts diverged"
        );
        assert_eq!(fin_verdicts, baseline_fin, "split {k}: finality verdicts diverged");
        assert_eq!(state, baseline_state, "split {k}: final store state diverged");
    }
}
