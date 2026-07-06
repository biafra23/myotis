//! Replays the EL-core conformance corpus (`rust/testdata/el/core/`) and
//! asserts the verdicts recorded in `expected.txt` — the exact same files the
//! Java side generates and asserts via `ElCoreVectorConformanceTest`
//! (`:networking`). One corpus, two implementations, byte-identical verdicts.
//!
//! Regenerate the corpus from the Java side:
//! `./gradlew :networking:test --tests "*ElCoreVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::enr::Enr;
use myotis_core::forkid;
use myotis_core::header::{self, BlockHeader};
use myotis_core::keccak::keccak256;
use myotis_core::nodekey::{recover_public_key, NodeKey};
use myotis_core::rlp;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/core")
}

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        // Mirrors the Java assumeTrue: a wholly absent corpus skips (fresh
        // checkout without testdata); a present-but-broken one fails below.
        eprintln!("el/core conformance corpus not present at {corpus:?} — skipping");
        return;
    }

    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let mut actual: BTreeMap<String, String> = BTreeMap::new();

    // --- headers ---
    for (base, bytes) in vectors(&corpus, "-header-", ".rlp") {
        match BlockHeader::decode(&bytes) {
            Ok(h) => {
                let k = |f: &str| format!("header.{base}.{f}");
                actual.insert(k("decode"), "ok".into());
                actual.insert(k("hash"), hex(&header::hash(&bytes)));
                actual.insert(k("parentHash"), hex(&h.parent_hash));
                actual.insert(k("stateRoot"), hex(&h.state_root));
                actual.insert(k("transactionsRoot"), hex(&h.transactions_root));
                actual.insert(k("receiptsRoot"), hex(&h.receipts_root));
                actual.insert(k("beneficiary"), hex(&h.beneficiary));
                actual.insert(k("difficulty"), scalar_hex(&h.difficulty));
                actual.insert(k("number"), h.number.to_string());
                actual.insert(k("gasLimit"), h.gas_limit.to_string());
                actual.insert(k("gasUsed"), h.gas_used.to_string());
                actual.insert(k("timestamp"), h.timestamp.to_string());
                actual.insert(k("extraData"), hex(&h.extra_data));
                actual.insert(k("mixHash"), hex(&h.mix_hash_or_prev_randao));
                actual.insert(k("nonce"), hex(&h.nonce));
                actual.insert(
                    k("baseFee"),
                    h.base_fee_per_gas
                        .as_deref()
                        .map_or("absent".into(), scalar_hex),
                );
                actual.insert(
                    k("withdrawalsRoot"),
                    h.withdrawals_root.map_or("absent".into(), |v| hex(&v)),
                );
                // Java uses a -1 sentinel for the EIP-4844 pair.
                actual.insert(
                    k("blobGasUsed"),
                    h.blob_gas_used.map_or("-1".into(), |v| v.to_string()),
                );
                actual.insert(
                    k("excessBlobGas"),
                    h.excess_blob_gas.map_or("-1".into(), |v| v.to_string()),
                );
                actual.insert(
                    k("parentBeaconBlockRoot"),
                    h.parent_beacon_block_root
                        .map_or("absent".into(), |v| hex(&v)),
                );

                // Rust-only invariant (Java has no encoder): the canonical
                // re-encode reproduces the input whenever every field is
                // modeled, i.e. the list has no discarded trailing items
                // (requestsHash and beyond → > 20 items).
                let fully_modeled = rlp::decode(&bytes)
                    .ok()
                    .and_then(|top| top.as_list().map(|l| l.len() <= 20).ok())
                    .unwrap_or(false);
                if fully_modeled {
                    assert_eq!(
                        h.encode(),
                        bytes,
                        "canonical re-encode must reproduce {base} byte-for-byte"
                    );
                }
            }
            Err(_) => {
                actual.insert(format!("header.{base}.decode"), "error".into());
            }
        }
    }

    // --- ENRs ---
    for (base, bytes) in vectors(&corpus, "-enr-", ".txt") {
        let text = String::from_utf8_lossy(&bytes);
        match Enr::from_enr_string(text.trim()) {
            Ok(enr) => {
                let k = |f: &str| format!("enr.{base}.{f}");
                actual.insert(k("decode"), "ok".into());
                actual.insert(k("seq"), enr.seq().to_string());
                actual.insert(k("ip"), enr.ip().map_or("absent".into(), hex));
                actual.insert(
                    k("tcp"),
                    enr.tcp_port().map_or("absent".into(), |p| p.to_string()),
                );
                actual.insert(
                    k("udp"),
                    enr.udp_port().map_or("absent".into(), |p| p.to_string()),
                );
                actual.insert(
                    k("secp256k1"),
                    enr.compressed_secp256k1().map_or("absent".into(), hex),
                );
                actual.insert(
                    k("pubkey"),
                    enr.public_key_uncompressed()
                        .map_or("absent".into(), |v| hex(&v)),
                );
                actual.insert(
                    k("eth2ForkDigest"),
                    enr.eth2().map_or("absent".into(), |f| hex(&f.fork_digest)),
                );
                actual.insert(
                    k("ethForkIdHash"),
                    enr.eth_fork_id_hash().map_or("absent".into(), |v| hex(&v)),
                );
            }
            Err(_) => {
                actual.insert(format!("enr.{base}.decode"), "error".into());
            }
        }
    }

    // --- keys: identity, signing, recovery, ECDH ---
    // Derivation strings duplicated verbatim from the Java test; change only
    // in lockstep.
    let secret1 = keccak256(b"myotis-el-a1:secret-1");
    let secret2 = keccak256(b"myotis-el-a1:secret-2");
    let msg_hash = keccak256(b"myotis-el-a1:message");
    let key1 = NodeKey::from_secret_bytes(&secret1).expect("secret1 must be a valid scalar");
    let key2 = NodeKey::from_secret_bytes(&secret2).expect("secret2 must be a valid scalar");
    actual.insert("key.secret1".into(), hex(&secret1));
    actual.insert("key.secret2".into(), hex(&secret2));
    actual.insert("key.msgHash".into(), hex(&msg_hash));
    actual.insert("key.pubkey1".into(), hex(&key1.public_key_bytes()));
    actual.insert("key.pubkey2".into(), hex(&key2.public_key_bytes()));
    actual.insert("key.nodeId1".into(), hex(&key1.node_id()));
    actual.insert("key.nodeId2".into(), hex(&key2.node_id()));
    let sig = key1.sign_hash(&msg_hash).expect("signing must succeed");
    actual.insert("key.sig1".into(), hex(&sig));
    actual.insert(
        "key.recovered1".into(),
        recover_public_key(&msg_hash, &sig).map_or("error".into(), |v| hex(&v)),
    );
    let ecdh12 = key1.ecdh_x(&key2.public_key_bytes()).unwrap();
    let ecdh21 = key2.ecdh_x(&key1.public_key_bytes()).unwrap();
    assert_eq!(ecdh12, ecdh21, "ECDH must be symmetric");
    actual.insert("key.ecdh".into(), hex(&ecdh12));

    // --- fork-id pins (Java asserts the same values against NetworkConfig) ---
    actual.insert("forkid.mainnet".into(), hex(&forkid::MAINNET_FORK_ID_HASH));
    actual.insert("forkid.gnosis".into(), hex(&forkid::GNOSIS_FORK_ID_HASH));
    actual.insert("forkid.sepolia".into(), hex(&forkid::SEPOLIA_FORK_ID_HASH));
    for net in ["mainnet", "gnosis", "sepolia"] {
        actual.insert(
            format!("forkid.forkNext.{net}"),
            forkid::FORK_NEXT.to_string(),
        );
    }

    // Per-key diff first for readable failures, then full equality.
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

/// Vector files `NNN<infix>*<ext>` in name order, as `(basename, bytes)`.
fn vectors(corpus: &Path, infix: &str, ext: &str) -> Vec<(String, Vec<u8>)> {
    let mut names: Vec<String> = fs::read_dir(corpus)
        .expect("corpus dir must be listable")
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
            let bytes = fs::read(corpus.join(&n)).expect("vector file must be readable");
            let base = n[..n.len() - ext.len()].to_string();
            (base, bytes)
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
