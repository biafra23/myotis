//! Cross-implementation vectors for BMT chunk addressing, from a
//! generator that is neither bee nor ant (issue #62).
//!
//! `swarmfs_bmt.jsonl` was produced by `scripts/swarmfs_vectors.py` with
//! swarmfs (<https://github.com/petfold/swarmfs>, Python, pinned commit in
//! each line's `generator`): every line is chunk data (`span(8 LE) ‖
//! payload`) and the address swarmfs's `bmt.chunk_address` gives it.
//! `trojan_interop.rs` proves ant agrees with bee; this proves ant agrees
//! with an implementation written independently from the format, which is
//! what catches ant and bee drifting from the spec together.
//!
//! Covers content-addressed chunks of every interesting payload length
//! (empty, sub-segment, segment boundaries, full) and intermediate chunks
//! whose span is the content length beneath them, including a
//! redundancy-flagged span.

use ant_crypto::{bmt_hash_with_span, cac_new, cac_valid, SPAN_SIZE};

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn bmt_addresses_match_swarmfs() {
    let raw = include_str!("swarmfs_bmt.jsonl");
    let mut n = 0;
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let case = v["case"].as_str().unwrap();
        let data = hex::decode(v["chunk_data_hex"].as_str().unwrap()).unwrap();
        let want = h32(v["address_hex"].as_str().unwrap());

        let (span, payload) = data.split_at(SPAN_SIZE);
        let got = bmt_hash_with_span(span.try_into().unwrap(), payload)
            .unwrap_or_else(|| panic!("bmt hash failed on {case}"));
        assert_eq!(
            hex::encode(got),
            hex::encode(want),
            "address mismatch on {case}"
        );
        assert!(cac_valid(&want, &data), "cac_valid rejected {case}");

        // A content-addressed chunk (span == payload length) must come out
        // of ant's own chunk builder byte-identical, address included.
        if u64::from_le_bytes(span.try_into().unwrap()) == payload.len() as u64 {
            let (addr, wire) = cac_new(payload).unwrap();
            assert_eq!(addr, want, "cac_new address mismatch on {case}");
            assert_eq!(wire, data, "cac_new data mismatch on {case}");
        }
        n += 1;
    }
    assert!(n >= 24, "expected the full swarmfs BMT vector set, got {n}");
}
