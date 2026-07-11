//! Replays the EL-A2 MPT conformance corpus (`rust/testdata/el/mpt/`) and
//! asserts the verdicts recorded in `expected.txt` — the exact same files the
//! Java side generates and asserts via `ElMptVectorConformanceTest`
//! (`:consensus`). One corpus, two implementations, byte-identical verdicts.
//!
//! Regenerate from the Java side:
//! `./gradlew :consensus:test --tests "*ElMptVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::bloom::{accrue, EMPTY_BLOOM};
use myotis_core::keccak::keccak256;
use myotis_core::trie::{decode_account_leaf, decode_storage_leaf, verify_proof, ProofResult};
use myotis_core::triehash::ordered_trie_root;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/mpt")
}

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/mpt conformance corpus not present at {corpus:?} — skipping");
        return;
    }

    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let mut actual: BTreeMap<String, String> = BTreeMap::new();

    // --- proof vectors: line 1 root hex, line 2 key hex, rest node hex ---
    for (base, text) in proof_vectors(&corpus) {
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let root = hex32(lines[0]);
        let key = unhex(lines[1]);
        let nodes: Vec<Vec<u8>> = lines[2..].iter().map(|l| unhex(l)).collect();

        let k = |f: &str| format!("mpt.{base}.{f}");
        match verify_proof(&root, &key, &nodes) {
            ProofResult::Found(value) => {
                actual.insert(k("result"), "found".into());
                actual.insert(k("value"), hex(&value));
                // Leaf-decode pins — base-name rule duplicated from the Java
                // test; keep in lockstep.
                if base.contains("account") {
                    let acct = decode_account_leaf(&value)
                        .expect("account vector must decode as an account leaf");
                    actual.insert(k("account.nonce"), acct.nonce.to_string());
                    actual.insert(k("account.balance"), scalar_hex(&acct.balance));
                    actual.insert(k("account.storageRoot"), hex(&acct.storage_root));
                    actual.insert(k("account.codeHash"), hex(&acct.code_hash));
                }
                if base.contains("storage-leaf") {
                    let slot = decode_storage_leaf(&value)
                        .expect("storage vector must decode as a storage leaf");
                    actual.insert(k("storage.value"), scalar_hex(&slot));
                }
            }
            ProofResult::Absent => {
                actual.insert(k("result"), "absent".into());
            }
            ProofResult::Invalid(_) => {
                actual.insert(k("result"), "invalid".into());
            }
        }
    }

    // --- ordered-trie-root pins (lists derived from strings shared with Java) ---
    actual.insert("triehash.empty".into(), hex(&ordered_trie_root(&[])));
    actual.insert(
        "triehash.single".into(),
        hex(&ordered_trie_root(&[b"myotis-tx-0".to_vec()])),
    );
    actual.insert(
        "triehash.three".into(),
        hex(&ordered_trie_root(&[
            keccak256(b"mpt:item:0").to_vec(),
            keccak256(b"mpt:item:1")[..8].to_vec(),
            Vec::new(),
        ])),
    );
    let spanning: Vec<Vec<u8>> = (0..200)
        .map(|i| keccak256(format!("mpt:span:{i}").as_bytes()).to_vec())
        .collect();
    actual.insert("triehash.spanning".into(), hex(&ordered_trie_root(&spanning)));

    // --- logs-bloom pins (M3:2048) ---
    let mut bloom = EMPTY_BLOOM;
    accrue(&mut bloom, &keccak256(b"mpt:bloom:addr")[..20]);
    actual.insert("bloom.single".into(), hex(&bloom));
    accrue(&mut bloom, &keccak256(b"mpt:bloom:t1"));
    accrue(&mut bloom, &keccak256(b"mpt:bloom:t2"));
    actual.insert("bloom.multi".into(), hex(&bloom));

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

fn proof_vectors(corpus: &Path) -> Vec<(String, String)> {
    let mut names: Vec<String> = fs::read_dir(corpus)
        .expect("corpus dir must be listable")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            n.len() > 3
                && n.as_bytes()[..3].iter().all(u8::is_ascii_digit)
                && n[3..].starts_with("-proof-")
                && n.ends_with(".txt")
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let text = fs::read_to_string(corpus.join(&n)).expect("vector must be readable");
            (n.trim_end_matches(".txt").to_string(), text)
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex in corpus"))
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Java `BigInteger.toString(16)` shape: minimal hex digits, `"0"` for zero.
fn scalar_hex(b: &[u8]) -> String {
    let full = hex(b);
    let trimmed = full.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".into()
    } else {
        trimmed.into()
    }
}
