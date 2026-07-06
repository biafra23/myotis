//! The Myotis sync-committee light client, in Rust.
//!
//! Grown through the Rust-engine PR series (see docs/reimplementation/05 and the
//! phase-1 plan). This stage (plan PR 4) is the VERIFICATION CORE: SSZ decoding of
//! the light-client wire containers, hash_tree_root merkleization, Merkle-branch /
//! gindex checks, and sync-committee signature verification over
//! [`myotis_bls::fast_aggregate_verify`] — proven equivalent to the Java
//! implementation by replaying `rust/testdata/lc/mainnet` to the verdicts recorded
//! in `expected.txt` (see `tests/lc_conformance.rs`). Networking (discv5 + libp2p
//! req/resp) is the next stage; no I/O lives in this crate yet.
//!
//! This is a pure-Rust library crate — no JNI here; the JVM boundary lives in
//! `myotis-engine`.

pub mod snapshot;
pub mod spec;
pub mod ssz;
pub mod store;
pub mod types;
pub mod verify;

/// The production BLS DST (re-exported for callers that log/compare it).
pub fn bls_dst() -> &'static [u8] {
    myotis_bls::DST
}

#[cfg(test)]
mod tests {
    #[test]
    fn dst_is_the_pop_ciphersuite() {
        assert_eq!(
            super::bls_dst(),
            b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
        );
    }

    #[test]
    fn malformed_inputs_never_panic() {
        assert!(!myotis_bls::fast_aggregate_verify(&[], 0, &[], &[]));
        assert!(!myotis_bls::fast_aggregate_verify(&[0u8; 48], 1, &[0u8; 32], &[0u8; 96]));
        assert!(!myotis_bls::fast_aggregate_verify(&[0u8; 47], 1, &[0u8; 32], &[0u8; 96]));
        assert!(!myotis_bls::fast_aggregate_verify(&[0u8; 48], 5000, &[0u8; 32], &[0u8; 96]));
    }
}
