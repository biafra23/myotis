# myotis-bls: BLS through blst

*Stop 3 · crate `myotis-bls`* · 2 files · 271 lines · about 40 minutes

The smallest real crate, and a good warm-up. It verifies a sync-committee aggregate signature with Supranational's `blst`. The Java engine calls it through JNI, and `myotis-consensus` calls it as a plain Rust function. You will see slices, a `Vec` of references that borrows another `Vec`, a JNI export that needs no `unsafe`, and, new since September, the two lines that let the crate build without the standard library.

## Rust you will practise

- **Slices and chunks** `&[u8]` parameters, `chunks_exact`, and a `Vec<&T>` that borrows another `Vec`.
- **Features and FFI** `#[cfg(feature = "jni")]`, `#![cfg_attr(not(feature = "std"), no_std)]`, `#[no_mangle]`, `extern "system"` and lifetimes on JNI handles.
- **Never-panic style** — Early `return false`, and `Option` with `.ok()?` instead of exceptions.

Some domain first. An Ethereum **sync committee** is 512 validators chosen for about 27 hours. Every slot, the members that saw the block sign its root, and their signatures are combined into one **BLS aggregate signature**. A light client checks that single signature against the participating members' public keys. That one check, `fast_aggregate_verify`, is all this crate does. BLS keys and signatures are points on the BLS12-381 curve, sent in compressed form: 48 bytes for a public key, 96 for a signature. The **DST** (domain separation tag) is a fixed byte string mixed into the hash-to-curve step, so a signature made for one scheme cannot be replayed under another. Ethereum uses the "proof of possession" (POP) variant.

<a id="f-myotis-bls-src-lib-rs"></a>

### myotis-bls/src/lib.rs

*library · 133 lines · Java twin · BlsVerifier / NativeBlsBackend*

Two public functions and a feature-gated JNI module. `fast_aggregate_verify` is the production entry: the POP ciphersuite, with the committee flattened into one `48 × n` byte buffer. It forwards to `fast_aggregate_verify_with_dst`, which exists so the conformance tests can use the NUL ciphersuite the fixtures were generated with. Any malformed input gives `false`, never a panic.

| Lines | What happens |
|---|---|
| 1–13 | Crate docs: the two consumers and the subgroup-check trade-off. |
| 15–24 | The `no_std` switch, `extern crate alloc`, and the imports. |
| 26–31 | The `DST` byte-string constant and the size limits (`PK_LEN` 48, `SIG_LEN` 96, `MAX_PUBKEYS` 4096). |
| 33–45 | `fast_aggregate_verify`, the production entry point. |
| 47–87 | The verify core: cap the count, decompress the public keys (no subgroup check, because they are Merkle-proven), decompress and subgroup-check the untrusted signature, call blst. |
| 89–133 | `mod jni_shim`, compiled only with the `jni` feature: the exported JNI symbol and a helper that copies the three Java arrays. |

#### Building without `std`

`rust/myotis-bls/src/lib.rs` · lines 15–24

```rust
// no_std + alloc when built without the `std` feature (`jni` implies `std`):
// the verify core is pure, and firmware links it via myotis-consensus with
// default-features = false.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Macros & attributes](01-primer.md#primer-macros)* **A crate-level conditional attribute.** `#![...]` with a `!` applies to the enclosing item, here the whole crate. `cfg_attr(condition, attr)` adds `attr` only when the condition holds. So the crate is `#![no_std]` exactly when the `std` feature is off, which happens only when a dependent turns the defaults off and does not ask for `std` ([Stop 2](02-workspace.md) shows how `myotis-consensus` forwards it). `jni` implies `std` in the manifest, so the JNI build always has the standard library.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`alloc::vec::Vec`.** `extern crate alloc;` makes the allocation layer of the standard library available by name. `std::vec::Vec` is only a re-export of `alloc::vec::Vec`, so importing it from `alloc` gives the same type in both builds, and the function bodies do not change.

#### The verify core

`rust/myotis-bls/src/lib.rs` · lines 59–87

```rust
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
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* **Read-only parameters.** All four byte parameters are `&[u8]`: the function only reads. The caller keeps ownership, and nothing is copied at the call. A `&[u8]` is a pointer plus a length, a view into someone else's bytes, a bit like a read-only `ByteBuffer` slice.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* **A vector of references into another vector.** `pks` *owns* the decoded keys. `pk_refs: Vec<&PublicKey>` is a second vector of *references into `pks`*, because blst's API wants a slice of references. The compiler guarantees that `pks` outlives `pk_refs` and is not changed while `pk_refs` is in use. Drop or push to `pks` before the last use of `pk_refs` and it will not compile. Both vectors are dropped at the end of the function; no key is ever copied.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* **`chunks_exact(48)`** yields 48-byte sub-slices without copying. The length check just above guarantees there is no remainder. `pks.iter().collect()` builds the reference vector, and the target type comes from the annotation on the left.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Manual early return.** `match … { Ok(pk) => …, Err(_) => return false }` is the manual version of `?`. It is needed because the function returns `bool`, not `Result`, so `?` has nothing to convert the error into.
- *[Protocol & domain](01-primer.md#primer-domain)* **Two trust levels.** `PublicKey::uncompress` skips the subgroup check, which is expensive and repeated 512 times, because the keys arrive Merkle-proven against a header the client already trusts. The signature comes from a peer, so the final call passes `true` for `sig_groupcheck`. The crate docs (lines 11–13) say the Java path makes the same trade-off.

> [!WARNING]
> **Design decision**<br>
>
> The count is capped *before* `n * PK_LEN` is computed. On a 32-bit Android device `usize` is 32 bits, so a huge count could wrap around the length check and trigger a gigantic `with_capacity`. Under the workspace's `panic = "abort"` that would end the host app, not throw an exception it could catch.

#### The JNI export

`rust/myotis-bls/src/lib.rs` · lines 89–133

```rust
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
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A feature-gated module.** `#[cfg(feature = "jni")]` removes the whole module when the feature is off, which is how `myotis-consensus` gets a JNI-free build. The `use jni::…` lines inside the module disappear with it, so the optional `jni` crate is never referenced.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **An exported symbol.** `#[no_mangle]` keeps the symbol name exactly as the JVM expects (`Java_<package>_<Class>_<method>`), and `extern "system"` selects JNI's calling convention. There is no `unsafe` block: the `jni` crate wraps the raw pointers in typed handles.
- *[Lifetimes](01-primer.md#primer-lifetimes)* **`'local`.** It ties every handle (`JByteArray<'local>`) to this call's JNI local-reference frame. Storing one in a global for later would not compile, which rules out a whole class of JNI crash bugs at compile time. In `verify` the lifetimes are elided: the compiler fills them in, and they still cannot escape.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* **`&mut env`.** The export lends its `JNIEnv` to `verify` as `&mut` for the duration of the call; the borrow ends when `verify` returns. In `jni` 0.21 the methods that create new local references take `&mut self`, but `convert_byte_array` takes only `&self`, and a `&mut` reference can always be used where a shared one is wanted.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **`.ok()?`.** `env.convert_byte_array(&pubkeys)` copies a Java `byte[]` into a Rust `Vec<u8>` and returns a `Result`. `.ok()` turns it into an `Option`, and `?` returns `None` early on failure. `Some(true) => JNI_TRUE, _ => JNI_FALSE` maps `None` and `Some(false)` alike to `false`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **A signed count.** Java has no unsigned `int`, so the count arrives as `jint` (`i32`). `count.max(0) as usize` clamps a negative value to 0 before the cast; a plain `as usize` on `-1` would produce a huge number. The cap is checked here too, so an absurd count is refused before three array copies.

> [!NOTE]
> **JVM lens**<br>
>
> On the Java side this is a `static native boolean nativeFastAggregateVerify(byte[] pubkeys, int n, byte[] msg, byte[] sig)` in `NativeBlsBackend`, loaded with `System.loadLibrary("myotis_bls")`. Passing the whole committee as one flat array means a single boundary crossing per verification.

<a id="f-myotis-bls-tests-conformance-rs"></a>

### myotis-bls/tests/conformance.rs

*integration test · 138 lines · Java twin · BlsFixtureTest*

Replays the same fixture files the Java tests use (`consensus/src/test/resources/bls_fixtures.txt` and a captured real mainnet failure), embedded at compile time. It covers NUL-ciphersuite aggregate and single-signer vectors, and a real 511-of-512 signature that must be *rejected* on the POP path. It also checks that each aggregate vector fails under POP, which proves the DST parameter is really used, that a corrupted signature fails, and that infinity encodings are rejected. Vectors that would only test blst against itself are skipped on purpose.

`rust/myotis-bls/tests/conformance.rs` · lines 24–35

```rust
const FIXTURES: &str = include_str!("../../../consensus/src/test/resources/bls_fixtures.txt");
const REAL_FAILURE: &str =
    include_str!("../../../consensus/src/test/resources/bls_real_failure.txt");

fn parse_kv(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect()
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Lifetimes](01-primer.md#primer-lifetimes)* **`include_str!`** pastes the file into the binary as a `&'static str`, so the test never depends on the working directory. The path is relative to the source file, and it reaches into the Java module's test resources.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **A map of views.** `parse_kv` returns `HashMap<&str, &str>`: every key and value is a *view* into `text`, and no characters are copied. `trim` and `split_once` return sub-slices of their input. Lifetime elision ties the map's lifetime to `text`, which is fine here because the input is `'static`.
- *[Tests](01-primer.md#primer-testing)* **An integration test.** The file lives in `tests/`, so cargo compiles it as a separate crate. It can only call the crate's public API (`fast_aggregate_verify`, `fast_aggregate_verify_with_dst`, the constants). It is built with the default features, so the library it links has `std` and `jni` on.

`rust/myotis-bls/tests/conformance.rs` · lines 48–76

```rust
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
```

*[Tests](01-primer.md#primer-testing) · [Ownership & moves](01-primer.md#primer-ownership)* `let mut bad_sig = sig.clone();` makes an owned copy so the test can flip one bit without touching `sig`. `Vec::with_capacity(n * PK_LEN)` plus `extend_from_slice` rebuilds the flat committee buffer the production function expects. The `fixture(...)` call returns a temporary `Vec<u8>`; `&` borrows it for the copy, and it is dropped at the end of the statement.

## Checkpoint

9 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-bls-q1"></a>

**Q1** · Multiple choice

`let pk_refs: Vec<&PublicKey> = pks.iter().collect();`. What does `pk_refs` contain, and what does the compiler enforce?

- **A.** Copies of every key; nothing is enforced
- **B.** References to the keys stored in `pks`; `pks` must stay alive and unmodified while `pk_refs` is used
- **C.** Pointers into the Java heap
- **D.** A second owner of each key, like `Arc`

[Answer →](answers.md#a-bls-q1)

<a id="q-bls-q2"></a>

**Q2** · Multiple choice

How does `myotis-consensus` use this crate without compiling any JNI code?

- **A.** It calls `jni_shim` with a null env
- **B.** It depends on `myotis-bls` with `default-features = false`, so `#[cfg(feature = "jni")] mod jni_shim` and the `jni` dependency are compiled out
- **C.** It loads the cdylib at run time
- **D.** It copies the source file

[Answer →](answers.md#a-bls-q2)

<a id="q-bls-q3"></a>

**Q3** · Multiple choice

What does the `'local` lifetime on `JByteArray<'local>` prevent?

- **A.** Arrays longer than 4096 bytes
- **B.** Keeping a JNI local reference after the native call has returned, for example by storing it in a global
- **C.** Calling the function from Kotlin
- **D.** Garbage collection of the array during the call

[Answer →](answers.md#a-bls-q3)

<a id="q-bls-q4"></a>

**Q4** · Written answer

Why does `fast_aggregate_verify_with_dst` check `n > MAX_PUBKEYS` before computing `n * PK_LEN`, and why does it matter more in this project than in a typical Java library?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-bls-q4)

<a id="q-bls-q5"></a>

**Q5** · Multiple choice

Why can `parse_kv(text: &str)` return `HashMap<&str, &str>` instead of `HashMap<String, String>`?

- **A.** Because `&str` is always `'static`
- **B.** The keys and values are sub-slices of `text`; the map borrows from it and may not outlive it, and nothing needs copying
- **C.** Because `HashMap` copies the strings internally
- **D.** It cannot; this is a compile error

[Answer →](answers.md#a-bls-q5)

<a id="q-bls-q6"></a>

**Q6** · Multiple choice

`#![cfg_attr(not(feature = "std"), no_std)]` sits at the top of `lib.rs`. When is the crate `no_std`?

- **A.** Always; `cfg_attr` is applied unconditionally
- **B.** Only when the `std` feature is off, which needs a dependent to disable the defaults and not request `std` (directly or through `jni`)
- **C.** Only on Android
- **D.** Only in release builds

[Answer →](answers.md#a-bls-q6)

<a id="q-bls-q7"></a>

**Q7** · Written answer

The verify core uses `Vec` in both the `std` and the `no_std` build, with the same code. Explain what `extern crate alloc;` and `use alloc::vec::Vec;` do, and why the function bodies did not need to change.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-bls-q7)

<a id="q-bls-q8"></a>

**Q8** · Multiple choice

The public keys are decompressed with `PublicKey::uncompress` and no subgroup check, but the signature is subgroup-checked. Why the difference?

- **A.** blst cannot subgroup-check public keys
- **B.** The keys arrive Merkle-proven against a trusted header, while the signature comes from a peer and is attacker-controlled
- **C.** Signatures are smaller, so checking them is cheaper and keys are skipped only for speed with no other reason
- **D.** The Java side does it the other way round and this crate compensates

[Answer →](answers.md#a-bls-q8)

<a id="q-bls-q9"></a>

**Q9** · Written answer

The aggregate-vector test checks each vector twice: once with `fast_aggregate_verify_with_dst(..., NUL_DST)`, expecting `true`, and once with `fast_aggregate_verify(...)`, expecting `false`. What bug does the second assertion catch, and why is it needed?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-bls-q9)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
