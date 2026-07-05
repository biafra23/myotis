//! Native BLS12-381 `fast_aggregate_verify` (Ethereum sync-committee path) over
//! Supranational's `blst`.
//!
//! Two consumers:
//! * the JVM/Android, via the single JNI entry point in [`jni_shim`] (feature `jni`,
//!   on by default — this is what the `cdylib` ships);
//! * in-workspace Rust (`myotis-consensus`), which calls [`fast_aggregate_verify`]
//!   directly with `default-features = false` (pure `rlib`, no JNI).
//!
//! Mirrors `BlsVerifier`/`NativeBlsBackend`: minimal-pubkey-size variant (48-byte G1
//! pubkeys, 96-byte G2 signatures), POP ciphersuite DST. Pubkeys arrive Merkle-proven,
//! so we `uncompress` them without the per-key subgroup check (same trade-off the Java
//! path makes); the attacker-controlled signature IS subgroup-checked.

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;

/// Ethereum consensus POP ciphersuite DST (matches the Java side).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const PK_LEN: usize = 48;
pub const SIG_LEN: usize = 96;
/// A sync committee is 512 pubkeys; this is a generous, safe upper bound.
pub const MAX_PUBKEYS: usize = 4096;

/// Verify an Ethereum sync-committee aggregate signature (production path: POP
/// ciphersuite [`DST`]).
///
/// * `pubkeys` — the committee flattened into one contiguous `48 * n` buffer.
/// * `n`       — number of participating pubkeys (bounded to [1, 4096]).
/// * `message` — the 32-byte signing root.
/// * `signature` — the 96-byte compressed G2 aggregate signature.
///
/// Returns `false` (never panics) on any malformed input: bad counts, length
/// mismatches, decompression failures, subgroup-check failures.
pub fn fast_aggregate_verify(pubkeys: &[u8], n: usize, message: &[u8], signature: &[u8]) -> bool {
    fast_aggregate_verify_with_dst(pubkeys, n, message, signature, DST)
}

/// [`fast_aggregate_verify`] with an explicit DST. Exists for conformance tests
/// only: the committed BLS fixture corpus (consensus/src/test/resources) was
/// generated under the NUL ciphersuite, mirroring the Java side's
/// `BlsVerifier.fastAggregateVerify(pks, msg, sig, DST)` overload. Production
/// callers use [`fast_aggregate_verify`] (POP) — same as the Java engine.
pub fn fast_aggregate_verify_with_dst(
    pubkeys: &[u8],
    n: usize,
    message: &[u8],
    signature: &[u8],
    dst: &[u8],
) -> bool {
    // Cap n before any `n * PK_LEN` arithmetic or `Vec::with_capacity(n)`: on 32-bit
    // targets usize is 32-bit, so a huge count could overflow the length check and
    // trigger a massive allocation.
    if n == 0 || n > MAX_PUBKEYS {
        return false;
    }
    if pubkeys.len() != n * PK_LEN {
        return false;
    }

    // Decompress committee pubkeys (trusted: no per-key subgroup check — the fast path).
    let mut pks: Vec<PublicKey> = Vec::with_capacity(n);
    for chunk in pubkeys.chunks_exact(PK_LEN) {
        match PublicKey::uncompress(chunk) {
            Ok(pk) => pks.push(pk),
            Err(_) => return false,
        }
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    // Signature is attacker-controlled → uncompress + subgroup-check it.
    let sig = match Signature::uncompress(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // fast_aggregate_verify: sig_groupcheck=true, all signers over the same message.
    sig.fast_aggregate_verify(true, message, dst, &pk_refs) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(feature = "jni")]
mod jni_shim {
    use jni::objects::{JByteArray, JClass};
    use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
    use jni::JNIEnv;

    /// JNI entry: `NativeBlsBackend.nativeFastAggregateVerify(byte[] pubkeys48xN, int n, byte[] msg, byte[] sig)`.
    /// `pubkeys` is the committee flattened into one contiguous `48*n` buffer — one
    /// boundary crossing for the whole verify.
    #[no_mangle]
    pub extern "system" fn Java_com_jaeckel_ethp2p_consensus_bls_NativeBlsBackend_nativeFastAggregateVerify<
        'local,
    >(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        pubkeys: JByteArray<'local>,
        count: jint,
        message: JByteArray<'local>,
        signature: JByteArray<'local>,
    ) -> jboolean {
        match verify(&mut env, pubkeys, count, message, signature) {
            Some(true) => JNI_TRUE,
            _ => JNI_FALSE,
        }
    }

    fn verify(
        env: &mut JNIEnv,
        pubkeys: JByteArray,
        count: jint,
        message: JByteArray,
        signature: JByteArray,
    ) -> Option<bool> {
        let n = count.max(0) as usize;
        // Same cap the core enforces — checked here first so an absurd count is
        // rejected before paying for three JNI array copies.
        if n == 0 || n > crate::MAX_PUBKEYS {
            return Some(false);
        }
        let pk_bytes = env.convert_byte_array(&pubkeys).ok()?;
        let msg = env.convert_byte_array(&message).ok()?;
        let sig_bytes = env.convert_byte_array(&signature).ok()?;
        Some(crate::fast_aggregate_verify(&pk_bytes, n, &msg, &sig_bytes))
    }
}
