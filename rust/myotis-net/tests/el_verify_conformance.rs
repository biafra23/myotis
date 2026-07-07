//! Replays the EL-A7 verified-read conformance corpus (`rust/testdata/el/verify/`)
//! and asserts the verdicts recorded in `expected.txt` — the same files the
//! Java side generates and asserts via `ElVerifyVectorConformanceTest`
//! (`:node-core`). Pins the load-bearing `verify_header_chain` crypto (Rust
//! decodes Java's committed BlockHeaders messages and must agree on the
//! boolean) and the stable ladder token set.
//!
//! Regenerate from the Java side:
//! `./gradlew :node-core:test --tests "*ElVerifyVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_net::el::eth::messages::decode_block_headers;
use myotis_net::el::verify::{verify_header_chain, ChainHeader};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/verify")
}

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/verify corpus not present at {corpus:?} — skipping");
        return;
    }
    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let beacon_root = hex32(&expected["beaconRoot"]);
    let peer_root = hex32(&expected["peerRoot"]);
    let mut actual: BTreeMap<String, String> = BTreeMap::new();
    actual.insert("beaconRoot".into(), hex(&beacon_root));
    actual.insert("peerRoot".into(), hex(&peer_root));

    // --- headerChain verification over Java's committed BlockHeaders messages ---
    for (base, bytes) in chain_vectors(&corpus) {
        let (_id, headers) = decode_block_headers(&bytes).unwrap();
        let chain: Vec<ChainHeader> = headers
            .into_iter()
            .map(|vh| ChainHeader { hash: vh.hash, header: vh.header })
            .collect();
        let ok = verify_header_chain(&chain, &beacon_root, &peer_root);
        actual.insert(format!("chain.{base}"), ok.to_string());
    }

    // --- the stable ladder token set (must match the Java literals verbatim) ---
    actual.insert("tokens.verifyMethod".into(), VERIFY_METHODS.join(","));
    actual.insert("tokens.failReason".into(), FAIL_REASONS.join(","));

    for (k, want) in &expected {
        match actual.get(k) {
            Some(got) => assert_eq!(got, want, "verdict diverges for {k}"),
            None => panic!("expected key {k} missing from Rust replay"),
        }
    }
    assert_eq!(
        expected, actual,
        "Rust replay produced keys the recorded expected.txt does not have"
    );
}

/// The token strings the Rust ladder emits — kept sorted to match the Java
/// corpus. A drift here (a renamed token) fails the corpus, catching an
/// operator-visible incompatibility.
const VERIFY_METHODS: &[&str] = &["headerChain", "stateRootMatch"];
const FAIL_REASONS: &[&str] = &[
    "beaconBlockUnavailable",
    "beaconNotSynced",
    "headerChainError",
    "headerChainGapTooLarge",
    "headerChainInvalid",
    "noPeerBlockNumber",
    "noPeerStateRoot",
    "peerBlockBehindFinalized",
    "peerProofInvalid",
];

fn chain_vectors(corpus: &Path) -> Vec<(String, Vec<u8>)> {
    let mut names: Vec<String> = fs::read_dir(corpus)
        .expect("corpus dir listable")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            n.len() > 3
                && n.as_bytes()[..3].iter().all(u8::is_ascii_digit)
                && n[3..].starts_with("-chain-")
                && n.ends_with(".rlp")
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let bytes = fs::read(corpus.join(&n)).expect("vector readable");
            (n[..n.len() - 4].to_string(), bytes)
        })
        .collect()
}

fn parse_expected(path: &Path) -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.to_string(), v.to_string());
        }
    }
    out
}

fn hex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
