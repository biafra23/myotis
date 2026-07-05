//! The Myotis sync-committee light client, in Rust.
//!
//! Grows through the Rust-engine PR series (see docs/reimplementation/05 and the
//! phase-1 plan): SSZ types + tree_hash merkleization, checkpoint-pinned bootstrap,
//! sync-committee verification (over [`myotis_bls::fast_aggregate_verify`]),
//! catch-up via libp2p req/resp, discv5 CL discovery.
//!
//! This is a pure-Rust library crate — no JNI here; the JVM boundary lives in
//! `myotis-engine`.

/// Placeholder proving the workspace wiring (myotis-bls rlib reuse without JNI).
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
