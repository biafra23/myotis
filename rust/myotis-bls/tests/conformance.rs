//! Conformance tests over the SAME fixture corpus the Java side pins
//! (`consensus/src/test/resources/bls_fixtures.txt` + `bls_real_failure.txt`,
//! embedded at compile time so `cargo test` needs no working-dir assumptions).
//!
//! The Java `BlsFixtureTest` uses these files to regression-test Milagro AGAINST
//! blst-generated reference values; here the roles flip — this crate IS blst, so
//! the aggregate/single vectors prove the `fast_aggregate_verify` plumbing
//! (flattening, caps, decompression, subgroup policy) reproduces the recorded
//! verdicts, and the captured mainnet triple proves the production POP path keeps
//! rejecting a real invalid signature. The `h2g2.*`/`sk2pk.*`/`aggpk.*` vectors are
//! deliberately NOT consumed here: they exercise Milagro's curve internals against
//! blst output, which is a tautology for a blst-backed crate.
//!
//! The fixture corpus (minus the real-failure triple) was generated under the NUL
//! ciphersuite; production uses POP. `fast_aggregate_verify_with_dst` exists
//! exactly for this, mirroring the Java `BlsVerifier` overload.

use std::collections::HashMap;

use myotis_bls::{fast_aggregate_verify, fast_aggregate_verify_with_dst, PK_LEN, SIG_LEN};

const NUL_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

const FIXTURES: &str = include_str!("../../../consensus/src/test/resources/bls_fixtures.txt");
const REAL_FAILURE: &str =
    include_str!("../../../consensus/src/test/resources/bls_real_failure.txt");

fn parse_kv(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex in fixture"))
        .collect()
}

fn fixture(map: &HashMap<&str, &str>, key: &str) -> Vec<u8> {
    hex(map.get(key).unwrap_or_else(|| panic!("missing fixture key {key}")))
}

#[test]
fn aggregate_vectors_verify_under_nul_dst() {
    let m = parse_kv(FIXTURES);
    for n in [2usize, 4, 16] {
        let msg = fixture(&m, &format!("agg.{n}.msg"));
        let sig = fixture(&m, &format!("agg.{n}.sig"));
        let mut pks = Vec::with_capacity(n * PK_LEN);
        for i in 0..n {
            pks.extend_from_slice(&fixture(&m, &format!("agg.{n}.pk.{i}")));
        }
        assert!(
            fast_aggregate_verify_with_dst(&pks, n, &msg, &sig, NUL_DST),
            "aggregate verify must pass for n={n}"
        );
        // Same vector under the WRONG (production POP) DST must fail — guards
        // against the DST parameter being silently ignored.
        assert!(
            !fast_aggregate_verify(&pks, n, &msg, &sig),
            "NUL-ciphersuite vector must not verify under the POP DST (n={n})"
        );
        // Corrupted signature must fail.
        let mut bad_sig = sig.clone();
        bad_sig[SIG_LEN - 1] ^= 0x01;
        assert!(
            !fast_aggregate_verify_with_dst(&pks, n, &msg, &bad_sig, NUL_DST),
            "corrupted signature must be rejected (n={n})"
        );
    }
}

#[test]
fn single_signer_vectors_verify_under_nul_dst() {
    let m = parse_kv(FIXTURES);
    for i in 0..3 {
        let msg = fixture(&m, &format!("single.{i}.msg"));
        let pk = fixture(&m, &format!("single.{i}.pk"));
        let sig = fixture(&m, &format!("single.{i}.sig"));
        assert!(
            fast_aggregate_verify_with_dst(&pk, 1, &msg, &sig, NUL_DST),
            "single-signer verify must pass for fixture single.{i}"
        );
    }
}

/// Real mainnet sync-committee triple (511-of-512 signers) captured from libp2p.
/// It is genuinely invalid — the wrong committee was used to verify — and both
/// Milagro and jblst rejected it during the original investigation. The PRODUCTION
/// path (POP DST) must keep rejecting it; silently accepting would be the exact
/// class of regression the light client cannot survive.
#[test]
fn production_path_rejects_captured_mainnet_failure() {
    let m = parse_kv(REAL_FAILURE);
    let n: usize = m.get("n").unwrap().parse().unwrap();
    assert_eq!(n, 511);
    let msg = fixture(&m, "msg");
    let sig = fixture(&m, "sig");
    let mut pks = Vec::with_capacity(n * PK_LEN);
    for i in 0..n {
        pks.extend_from_slice(&fixture(&m, &format!("pk.{i}")));
    }
    assert!(
        !fast_aggregate_verify(&pks, n, &msg, &sig),
        "the captured invalid mainnet triple must be rejected on the production path"
    );
}

/// Identity-element encodings: parity with the Java side's explicit rejections
/// (`fastAggregateVerify_rejectsInfinitySignature` / `...InfinityPubkey`). blst
/// reaches the same verdicts (an infinity signature fails the pairing/group
/// policy; an infinity pubkey can never satisfy the pairing for a real message).
#[test]
fn identity_encodings_are_rejected() {
    let m = parse_kv(FIXTURES);
    let msg = fixture(&m, "single.0.msg");
    let pk = fixture(&m, "single.0.pk");
    let sig = fixture(&m, "single.0.sig");

    let mut inf_sig = vec![0u8; SIG_LEN];
    inf_sig[0] = 0xC0; // canonical compressed infinity
    assert!(
        !fast_aggregate_verify_with_dst(&pk, 1, &msg, &inf_sig, NUL_DST),
        "identity-encoded signature must be rejected"
    );

    let mut inf_pk = vec![0u8; PK_LEN];
    inf_pk[0] = 0xC0;
    assert!(
        !fast_aggregate_verify_with_dst(&inf_pk, 1, &msg, &sig, NUL_DST),
        "identity-encoded pubkey must be rejected"
    );
}
