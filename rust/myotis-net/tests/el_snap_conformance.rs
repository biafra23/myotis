//! Replays the EL-A6 snap/1 conformance corpus (`rust/testdata/el/snap/`) and
//! asserts the verdicts recorded in `expected.txt` — the same files the Java
//! side generates and asserts via `ElSnapVectorConformanceTest` (`:networking`).
//!
//! The strong pin: Rust decodes Java's committed AccountRange / StorageRanges
//! MESSAGE bytes and runs the verify-on-fetch path (decode + MPT proof verify)
//! against the committed roots, and the proof-verified account fields / slot
//! value must match Java's — proving both languages extract the same
//! source-of-truth from the same snap proof.
//!
//! Regenerate from the Java side:
//! `./gradlew :networking:test --tests "*ElSnapVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::keccak::keccak256;
use myotis_net::el::snap::fetch::{self, AccountOutcome};
use myotis_net::el::snap::messages as snap;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/snap")
}

// Deterministic inputs shared with the Java test.
fn address() -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&keccak256(b"snap:account")[..20]);
    a
}
fn slot() -> [u8; 32] {
    keccak256(b"snap:slot")
}

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/snap corpus not present at {corpus:?} — skipping");
        return;
    }
    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let mut actual: BTreeMap<String, String> = BTreeMap::new();

    // --- (1) request encode bytes ---
    let state_root = hex32(&expected["account.stateRoot"]);
    let account_hash = keccak256(&address());
    actual.insert(
        "encode.getAccountRange".into(),
        hex(&snap::encode_get_account(1, &state_root, &account_hash, 4096)),
    );
    let slot_hash = keccak256(&slot());
    let all_ff = [0xffu8; 32];
    actual.insert(
        "encode.getStorageRanges".into(),
        hex(&snap::encode_get_storage_ranges(2, &state_root, &account_hash, &slot_hash, &all_ff, 4096)),
    );
    let code_hash = keccak256(b"snap:some-code");
    actual.insert(
        "encode.getByteCodes".into(),
        hex(&snap::encode_get_byte_codes(3, &[code_hash], 262144)),
    );

    // --- (2) verify-on-fetch: decode Java's AccountRange, verify vs state root ---
    let acct_msg = fs::read(corpus.join("001-accountrange.bin")).expect("accountrange vector");
    let ar = snap::decode_account_range(&acct_msg).unwrap();
    actual.insert("account.stateRoot".into(), hex(&state_root));
    match fetch::verify_account(&state_root, &address(), &ar).unwrap() {
        AccountOutcome::Present(acct) => {
            actual.insert("account.verified".into(), "found".into());
            actual.insert("account.nonce".into(), acct.nonce.to_string());
            actual.insert("account.balance".into(), scalar_hex(&acct.balance));
            actual.insert("account.storageRoot".into(), hex(&acct.storage_root));
            actual.insert("account.codeHash".into(), hex(&acct.code_hash));
        }
        AccountOutcome::Absent => {
            actual.insert("account.verified".into(), "Absent".into());
        }
    }

    // --- (3) verify-on-fetch: decode Java's StorageRanges, verify vs storageRoot ---
    let stg_msg = fs::read(corpus.join("002-storageranges.bin")).expect("storageranges vector");
    let sr = snap::decode_storage_ranges(&stg_msg).unwrap();
    let storage_root = hex32(&expected["storage.storageRoot"]);
    actual.insert("storage.storageRoot".into(), hex(&storage_root));
    // Build the account leaf carrying that storage root (verify_storage anchors there).
    let account = myotis_core::trie::AccountLeaf {
        nonce: 0,
        balance: Vec::new(),
        storage_root,
        code_hash: myotis_core::trie::EMPTY_CODE_HASH,
    };
    let value = fetch::verify_storage(&account, &slot(), &sr).unwrap();
    actual.insert("storage.verified".into(), "found".into());
    actual.insert("storage.value".into(), scalar_hex(&value));

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

/// Java `BigInteger.toString(16)` shape: minimal hex, `"0"` for zero.
fn scalar_hex(b: &[u8]) -> String {
    let trimmed = hex(b);
    let t = trimmed.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}
