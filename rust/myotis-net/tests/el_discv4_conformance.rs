//! Replays the EL-A3 discv4 conformance corpus (`rust/testdata/el/discv4/`)
//! and asserts the verdicts recorded in `expected.txt` — the exact same files
//! the Java side generates and asserts via `ElDiscv4VectorConformanceTest`
//! (`:networking`). Because both `Packet.encode` (Tuweni `signHashed`) and the
//! Rust `NodeKey::sign_hash` (k256) produce deterministic RFC-6979 low-s
//! signatures, the signed packet BYTES are identical — this test re-encodes
//! with the same fixed key + expiry and byte-matches the committed vectors,
//! not just a decode round-trip.
//!
//! Regenerate from the Java side:
//! `./gradlew :networking:test --tests "*ElDiscv4VectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::discv4::{
    decode_neighbors, encode_find_node, encode_ping, encode_pong, parse, TYPE_FIND_NODE,
    TYPE_PING, TYPE_PONG,
};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/discv4")
}

const EXPIRY: u64 = 1_700_000_020;

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/discv4 corpus not present at {corpus:?} — skipping");
        return;
    }
    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    // Same deterministic identity as the Java generator.
    let secret = keccak256(b"myotis-el-a3:discv4-key");
    let key = NodeKey::from_secret_bytes(&secret).expect("valid secret");

    let mut actual: BTreeMap<String, String> = BTreeMap::new();
    actual.insert("key.pubkey".into(), hex(&key.public_key_bytes()));

    // --- signed packet byte pins: re-encode here, byte-match the vectors ---
    // (from = 0.0.0.0:30303, to = 192.0.2.1:30304 — the Java generator's values.)
    let ping = encode_ping(&key, &[0, 0, 0, 0], 30303, &[192, 0, 2, 1], 30304, EXPIRY).unwrap();
    let mut ping_hash = [0u8; 32];
    ping_hash.copy_from_slice(&ping[..32]);
    let pong = encode_pong(&key, &[192, 0, 2, 1], 30304, &ping_hash, EXPIRY).unwrap();
    let findnode = encode_find_node(&key, &key.public_key_bytes(), EXPIRY).unwrap();

    record_packet(&mut actual, "001-packet-ping", &ping, TYPE_PING);
    record_packet(&mut actual, "002-packet-pong", &pong, TYPE_PONG);
    record_packet(&mut actual, "003-packet-findnode", &findnode, TYPE_FIND_NODE);

    // Byte-identity against the committed vectors (the strongest pin).
    assert_eq!(ping, read_vector(&corpus, "001-packet-ping.bin"), "ping bytes");
    assert_eq!(pong, read_vector(&corpus, "002-packet-pong.bin"), "pong bytes");
    assert_eq!(
        findnode,
        read_vector(&corpus, "003-packet-findnode.bin"),
        "findnode bytes"
    );

    // --- inbound parse verdicts ---
    for (base, raw) in vectors(&corpus, "-parse-", ".bin") {
        let k = format!("parse.{base}.result");
        match parse(&raw) {
            Ok(p) => {
                actual.insert(k, "ok".into());
                actual.insert(format!("parse.{base}.sender"), hex(&p.sender_pubkey));
            }
            Err(_) => {
                actual.insert(k, "error".into());
            }
        }
    }

    // --- Neighbors decode verdicts (skip-vs-break leniency) ---
    for (base, raw) in vectors(&corpus, "-neighbors-", ".bin") {
        let peers = decode_neighbors(&raw).unwrap_or_default();
        let ids = peers
            .iter()
            .map(|p| hex(&p.node_id))
            .collect::<Vec<_>>()
            .join(",");
        actual.insert(format!("neighbors.{base}.ids"), ids);
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

fn record_packet(out: &mut BTreeMap<String, String>, base: &str, packet: &[u8], expected_type: u8) {
    let parsed = parse(packet).expect("own packet must parse");
    assert_eq!(parsed.packet_type, expected_type);
    out.insert(format!("packet.{base}.bytes"), hex(packet));
    out.insert(
        format!("packet.{base}.type"),
        (parsed.packet_type as u32).to_string(),
    );
    out.insert(format!("packet.{base}.hash"), hex(&parsed.hash));
    out.insert(format!("packet.{base}.sender"), hex(&parsed.sender_pubkey));
}

fn read_vector(corpus: &Path, name: &str) -> Vec<u8> {
    fs::read(corpus.join(name)).expect("vector must be readable")
}

fn vectors(corpus: &Path, infix: &str, ext: &str) -> Vec<(String, Vec<u8>)> {
    let mut names: Vec<String> = fs::read_dir(corpus)
        .expect("corpus dir listable")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            n.len() > 3
                && n.as_bytes()[..3].iter().all(u8::is_ascii_digit)
                && n[3..].starts_with(infix)
                && n.ends_with(ext)
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let bytes = fs::read(corpus.join(&n)).expect("vector readable");
            (n[..n.len() - ext.len()].to_string(), bytes)
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
