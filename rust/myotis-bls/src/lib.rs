//! Native BLS12-381 `fast_aggregate_verify` (Ethereum sync-committee path) over
//! Supranational's `blst`, exposed to the JVM/Android via a single JNI entry point.
//!
//! Mirrors `BlsVerifier`/`NativeBlsBackend`: minimal-pubkey-size variant (48-byte G1
//! pubkeys, 96-byte G2 signatures), POP ciphersuite DST. Pubkeys arrive Merkle-proven,
//! so we `uncompress` them without the per-key subgroup check (same trade-off the Java
//! path makes); the attacker-controlled signature IS subgroup-checked.

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

/// Ethereum consensus POP ciphersuite DST (matches the Java side).
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const PK_LEN: usize = 48;

/// JNI entry: `NativeBlsBackend.nativeFastAggregateVerify(byte[] pubkeys48xN, int n, byte[] msg, byte[] sig)`.
/// `pubkeys` is the committee flattened into one contiguous `48*n` buffer — one boundary
/// crossing for the whole verify.
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
    // Cap n before any `n * PK_LEN` arithmetic or `Vec::with_capacity(n)`: on 32-bit ABIs
    // (armeabi-v7a) usize is 32-bit, so a huge `count` could overflow the length check and
    // trigger a massive allocation / OOM panic that crashes the host. A sync committee is
    // 512 pubkeys; 4096 is a generous, safe upper bound.
    let n = count.max(0) as usize;
    if n == 0 || n > 4096 {
        return Some(false);
    }
    let pk_bytes = env.convert_byte_array(&pubkeys).ok()?;
    let msg = env.convert_byte_array(&message).ok()?;
    let sig_bytes = env.convert_byte_array(&signature).ok()?;
    if pk_bytes.len() != n * PK_LEN {
        return Some(false);
    }

    // Decompress committee pubkeys (trusted: no per-key subgroup check — the fast path).
    let mut pks: Vec<PublicKey> = Vec::with_capacity(n);
    for chunk in pk_bytes.chunks_exact(PK_LEN) {
        match PublicKey::uncompress(chunk) {
            Ok(pk) => pks.push(pk),
            Err(_) => return Some(false),
        }
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().collect();

    // Signature is attacker-controlled → uncompress + subgroup-check it.
    let sig = match Signature::uncompress(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return Some(false),
    };

    // fast_aggregate_verify: sig_groupcheck=true, all signers over the same message.
    let err = sig.fast_aggregate_verify(true, &msg, DST, &pk_refs);
    Some(err == BLST_ERROR::BLST_SUCCESS)
}
