//! Replays the EL-A5 eth/66-69 conformance corpus (`rust/testdata/el/eth/`)
//! and asserts the verdicts recorded in `expected.txt` — the same files the
//! Java side generates and asserts via `ElEthVectorConformanceTest`
//! (`:networking`).
//!
//! Regenerate from the Java side:
//! `./gradlew :networking:test --tests "*ElEthVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::keccak::keccak256;
use myotis_net::el::eth::messages;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/eth")
}

const GENESIS: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
const FORK: [u8; 4] = [0x07, 0xc9, 0x46, 0x2e];

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/eth corpus not present at {corpus:?} — skipping");
        return;
    }
    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let genesis = hex32(GENESIS);
    let best = keccak256(b"eth:best-hash");
    let mut actual: BTreeMap<String, String> = BTreeMap::new();

    // (1) Status encode bytes + decode round-trip.
    let s68 = messages::encode_status(68, 1, &genesis, &best, &FORK, 0);
    actual.insert("status.eth68.bytes".into(), hex(&s68));
    let d68 = messages::decode_status(&s68, 68).unwrap();
    actual.insert("status.eth68.networkId".into(), d68.network_id.to_string());
    actual.insert("status.eth68.genesis".into(), hex(&d68.genesis_hash));

    let s69 = messages::encode_status69(69, 100, &genesis, &best, &FORK, 0, 21_000_000);
    actual.insert("status.eth69.bytes".into(), hex(&s69));
    let d69 = messages::decode_status(&s69, 69).unwrap();
    actual.insert(
        "status.eth69.latestBlock".into(),
        d69.latest_block.unwrap().to_string(),
    );
    actual.insert("status.eth69.latestHash".into(), hex(&d69.best_hash));

    // (2) BlockHeaders decode → per-header hashes (committed message bytes).
    let headers_msg = fs::read(corpus.join("001-blockheaders.rlp")).expect("headers vector");
    let (req_id, headers) = messages::decode_block_headers(&headers_msg).unwrap();
    actual.insert("headers.reqId".into(), req_id.to_string());
    actual.insert("headers.count".into(), headers.len().to_string());
    for (i, vh) in headers.iter().enumerate() {
        actual.insert(format!("headers.{i}.hash"), hex(&vh.hash));
        actual.insert(format!("headers.{i}.number"), vh.header.number.to_string());
    }

    // (3) eth/69 bloomless receipts → recomputed-bloom canonical bytes.
    let receipts_msg = fs::read(corpus.join("002-receipts69.rlp")).expect("receipts vector");
    let (_id, blocks) = messages::decode_receipts69(&receipts_msg).unwrap();
    actual.insert("receipts69.blocks".into(), blocks.len().to_string());
    for (b, block) in blocks.iter().enumerate() {
        for (r, receipt) in block.iter().enumerate() {
            actual.insert(format!("receipts69.{b}.{r}.canonical"), hex(receipt));
        }
    }

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
