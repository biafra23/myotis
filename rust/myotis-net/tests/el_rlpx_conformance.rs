//! Replays the EL-A4 RLPx conformance corpus (`rust/testdata/el/rlpx/`) and
//! asserts the verdicts recorded in `expected.txt` — the same files the Java
//! side generates and asserts via `ElRlpxVectorConformanceTest` (`:networking`).
//!
//! Three deterministic cross-language pins: ECIES decrypt of the canonical
//! EIP-8 auth vectors, session-secret derivation from the EIP-8 ephemerals +
//! nonces (which must reproduce the spec's published aes/mac secrets), and
//! byte-identical frame output from fixed session secrets.
//!
//! Regenerate from the Java side:
//! `./gradlew :networking:test --tests "*ElRlpxVectorConformanceTest*"
//!  -Dmyotis.el.writeExpected=true`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use myotis_core::keccak::keccak256;
use myotis_core::nodekey::NodeKey;
use myotis_net::el::rlpx::ecies;
use myotis_net::el::rlpx::frame::FrameCodec;
use myotis_net::el::rlpx::handshake::{derive_secrets, SessionSecrets};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el/rlpx")
}

// EIP-8 test key material.
const STATIC_B: &str = "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291";
const A_EPH: &str = "869d6ecf5211f1cc60418a13b9d870b22959d0c16f02bec714c960dd2298a32d";
const B_EPH: &str = "e238eb8e04fee6511ab04c6dd3c89ce097b11f25d584863ac2b6d5b35b1847e4";
const A_NONCE: &str = "7e968bba13b6c50e2c4cd7f241cc0d64d1ac25c7f5952df231ac6a2bda8ee5d6";
const B_NONCE: &str = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";

const AUTH1_LEGACY_HEX: &str = concat!(
    "048ca79ad18e4b0659fab4853fe5bc58eb83992980f4c9cc147d2aa31532efd29a3d3dc6a3d89eaf",
    "913150cfc777ce0ce4af2758bf4810235f6e6ceccfee1acc6b22c005e9e3a49d6448610a58e98744",
    "ba3ac0399e82692d67c1f58849050b3024e21a52c9d3b01d871ff5f210817912773e610443a9ef14",
    "2e91cdba0bd77b5fdf0769b05671fc35f83d83e4d3b0b000c6b2a1b1bba89e0fc51bf4e460df310",
    "5c444f14be226458940d6061c296350937ffd5e3acaceeaaefd3c6f74be8e23e0f45163cc7ebd762",
    "20f0128410fd05250273156d548a414444ae2f7dea4dfca2d43c057adb701a715bf59f6fb66b2d1d",
    "20f2c703f851cbf5ac47396d9ca65b6260bd141ac4d53e2de585a73d1750780db4c9ee4cd4d22517",
    "3a4592ee77e2bd94d0be3691f3b406f9bba9b591fc63facc016bfa8",
);
const AUTH2_EIP8_HEX: &str = concat!(
    "01b304ab7578555167be8154d5cc456f567d5ba302662433674222360f08d5f1534499d3678b513b",
    "0fca474f3a514b18e75683032eb63fccb16c156dc6eb2c0b1593f0d84ac74f6e475f1b8d56116b849",
    "634a8c458705bf83a626ea0384d4d7341aae591fae42ce6bd5c850bfe0b999a694a49bbbaf3ef6c",
    "da61110601d3b4c02ab6c30437257a6e0117792631a4b47c1d52fc0f8f89caadeb7d02770bf999cc",
    "147d2df3b62e1ffb2c9d8c125a3984865356266bca11ce7d3a688663a51d82defaa8aad69da39ab6",
    "d5470e81ec5f2a7a47fb865ff7cca21516f9299a07b1bc63ba56c7a1a892112841ca44b6e0034dee",
    "70c9adabc15d76a54f443593fafdc3b27af8059703f88928e199cb122362a4b35f62386da7caad09",
    "c001edaeb5f8a06d2b26fb6cb93c52a9fca51853b68193916982358fe1e5369e249875bb8d0d0ec3",
    "6f917bc5e1eafd5896d46bd61ff23f1a863a8a8dcd54c7b109b771c8e61ec9c8908c733c0263440e",
    "2aa067241aaa433f0bb053c7b31a838504b148f570c0ad62837129e547678c5190341e4f1693956c",
    "3bf7678318e2d5b5340c9e488eefea198576344afbdf66db5f51204a6961a63ce072c8926c",
);

#[test]
fn replay_reproduces_recorded_verdicts() {
    let corpus = corpus_dir();
    if !corpus.is_dir() {
        eprintln!("el/rlpx corpus not present at {corpus:?} — skipping");
        return;
    }
    let expected = parse_expected(&corpus.join("expected.txt"));
    assert!(
        !expected.is_empty(),
        "corpus present but expected.txt missing/empty — regenerate on the Java side"
    );

    let mut actual: BTreeMap<String, String> = BTreeMap::new();

    // (1) ECIES decrypt of the canonical EIP-8 vectors.
    let priv_b = NodeKey::from_secret_bytes(&hex32(STATIC_B)).unwrap();
    let auth1 = unhex(AUTH1_LEGACY_HEX);
    let plain1 = ecies::decrypt(&auth1, &priv_b, &[]).unwrap();
    actual.insert("ecies.auth1-legacy.plaintext".into(), hex(&plain1));

    let auth2 = unhex(AUTH2_EIP8_HEX);
    let aad2 = &auth2[..2];
    let plain2 = ecies::decrypt(&auth2[2..], &priv_b, aad2).unwrap();
    actual.insert("ecies.auth2-eip8.plaintext".into(), hex(&plain2));

    // (2) Session-secret derivation — must reproduce the EIP-8 published secrets.
    let a_eph = NodeKey::from_secret_bytes(&hex32(A_EPH)).unwrap();
    let b_eph = NodeKey::from_secret_bytes(&hex32(B_EPH)).unwrap();
    let derived = derive_secrets(
        &a_eph,
        &b_eph.public_key_bytes(),
        &hex32(A_NONCE),
        &hex32(B_NONCE),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    actual.insert("secrets.aes".into(), hex(&derived.aes_secret));
    actual.insert("secrets.mac".into(), hex(&derived.mac_secret));

    // (3a) Hello frame is uncompressed → Rust re-encodes and byte-matches
    // Java's committed bytes.
    let mut enc = FrameCodec::new(&frame_secrets(true));
    let hello_body = [0xc0u8];
    let hello_frame = enc.encode_frame(0x00, &hello_body);
    actual.insert("frame.hello.bytes".into(), hex(&hello_frame));

    // (3b) Both frame .bin files are Java's ACTUAL output — decode them with a
    // Rust responder codec (the cross-language interop proof; snappy encoders
    // differ, so we don't byte-compare the compressed frame).
    let mut dec = FrameCodec::new(&frame_secrets(false));
    let hello_committed = fs::read(corpus.join("001-frame-hello.bin")).expect("hello frame");
    actual.insert(
        "frame.hello.decode".into(),
        decode_verdict(&mut dec, &hello_committed, 0x00, &hello_body),
    );
    let msg_body: Vec<u8> = (0..300u32).map(|i| (i & 0xff) as u8).collect();
    let msg_committed = fs::read(corpus.join("002-frame-compressed.bin")).expect("compressed frame");
    actual.insert(
        "frame.compressed.decode".into(),
        decode_verdict(&mut dec, &msg_committed, 0x10, &msg_body),
    );

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

fn frame_secrets(initiator: bool) -> SessionSecrets {
    let aes_secret = keccak256(b"rlpx:frame:aes");
    let mac_secret = keccak256(b"rlpx:frame:mac");
    let a_nonce = keccak256(b"rlpx:frame:A-nonce");
    let b_nonce = keccak256(b"rlpx:frame:B-nonce");
    let auth_wire = b"RLPX-AUTH-WIRE-OPAQUE".to_vec();
    let ack_wire = b"RLPX-ACK-WIRE-OPAQUE".to_vec();
    if initiator {
        SessionSecrets {
            aes_secret,
            mac_secret,
            egress_nonce: a_nonce,
            ingress_nonce: b_nonce,
            auth_wire,
            ack_wire,
        }
    } else {
        SessionSecrets {
            aes_secret,
            mac_secret,
            egress_nonce: b_nonce,
            ingress_nonce: a_nonce,
            auth_wire: ack_wire,
            ack_wire: auth_wire,
        }
    }
}

fn decode_verdict(dec: &mut FrameCodec, frame: &[u8], want_code: u64, want_body: &[u8]) -> String {
    let body_end = frame.len() - 16;
    let len = match dec.decode_header(&frame[..16], &frame[16..32]) {
        Ok(l) => l,
        Err(_) => return "HEADER_FAIL".into(),
    };
    match dec.decode_body(&frame[32..body_end], &frame[body_end..], len) {
        Ok(d) if d.message_code == want_code && d.payload == want_body => "ok".into(),
        _ => "MISMATCH".into(),
    }
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
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
