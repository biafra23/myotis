# Deep dive: how UniFFI connects Kotlin to Rust

*Stop 17 · crate `uniffi-bindgen`* · 1 file · 3 lines, plus the uniffi crates, the generated Kotlin and its callers · about 355 minutes (nearly six hours: read it in several sittings)

You asked how the UniFFI API works and what it looks like. This stop follows one call, `requestAccountJson`, from a Java caller through generated Kotlin, JNA and a macro-generated `extern "C"` function into `host.rs`, and back. On the way you will see every piece of code involved: what you write in Rust, what the macros turn it into, the `uniffi_core` runtime, the generator, the 2,384-line Kotlin file it produces, the Java that calls it, and the Gradle tasks that tie them together. You will see who allocates and who frees each buffer, which thread runs what, what a panic does, and how a checksum per function stops a stale library from being called. The stop is long on purpose. Afterwards you should be able to explain UniFFI to someone else on a whiteboard.

## Rust you will practise

- **Ownership without a destructor** `RustBuffer` is a `Vec<u8>` taken apart into pointer, length and capacity, with `ManuallyDrop` and `Vec::from_raw_parts` moving ownership across the C boundary.
- **Code that writes code** — What a function-like macro (`setup_scaffolding!`) and an attribute macro (`#[uniffi::export]`) expand to, how `quote!` builds Rust code, and how a `const fn` computes a checksum at compile time.
- **Traits as a conversion vocabulary** `FfiConverter`, `Lift`, `Lower` and `LowerReturn`, generic over a crate-local tag type because of the orphan rule, derived with a `macro_rules!` macro; and `catch_unwind` versus `panic = "abort"`.

## The short answer

UniFFI is a code generator for both sides of a C interface. You write ordinary Rust functions and mark them `#[uniffi::export]`. At compile time the macro writes, for each one, a C-callable wrapper, a byte-encoded description of its signature (the *metadata*) and a checksum of that description, all as exported symbols of the compiled library. A separate tool, `uniffi-bindgen`, reads the metadata out of the compiled `.so` or `.dylib` and writes a Kotlin file: JNA declarations for the C functions, converters for each type, and one idiomatic Kotlin function per export. At run time the Kotlin side loads the library through JNA, compares every checksum with the value it was generated from, and then calls through.

So two generated halves must agree byte for byte. The Rust half is regenerated on every `cargo build`; the Kotlin half only when someone runs `./gradlew uniffiGenerateKotlin`. The checksums catch the moment they stop agreeing.

In Myotis the exported surface is deliberately simple. The 55 functions in `ffi.rs` take and return only `i32`, `i64`, `bool`, `String` and `Option<String>` (or return nothing). Anything compound (an account proof, a block, a status) is a JSON string. That keeps UniFFI's job small and makes its machinery easy to see.

| Piece | Where | Written by | Role |
|---|---|---|---|
| `#[uniffi::export] fn …` | `rust/myotis-engine/src/ffi.rs` | you | The API: 55 one-line functions calling into `host.rs`. |
| `uniffi::setup_scaffolding!()` | `rust/myotis-engine/src/lib.rs` | you (one line) | Expands to the crate-wide glue: the tag type, buffer alloc/free functions, the contract version. |
| scaffolding functions, metadata, checksums | inside the compiled library | `uniffi_macros`, at compile time | The C-callable side of every export. |
| `RustBuffer`, `RustCallStatus`, `Lift`/`Lower`, `rust_call` | `uniffi_core` crate | UniFFI | The runtime the scaffolding calls. |
| `uniffi-bindgen` binary | `rust/uniffi-bindgen/` | you (three lines) | Runs `uniffi_bindgen` against the built library. |
| `myotis_engine.kt` (2,384 lines) | `myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/` | `uniffi_bindgen`, committed | JNA declarations, converters, checksum checks, 55 Kotlin functions. |
| JNA | `com.sun.jna` jar + `libjnidispatch` | third party | Calls C functions from the JVM without hand-written JNI. |
| `RustEngineNative`, `RustChainHandle` | `myotis-engine-rust/src/main/java/…` | you | Load and validate the library, call the Kotlin functions, parse the JSON into `io.myotis.api` records. |
| `uniffiGenerateKotlin`, `cargoNdkAndroid`, `verifyAndroidJniLibs` | root `build.gradle.kts`, wired from `myotis-engine/build.gradle.kts` | you | Build the libraries, regenerate and patch the bindings, check the Android libraries. |

> [!NOTE]
> **If you know JNI**<br>
>
> With JNI you declare `native` methods in Java and write a C (or Rust) function per method named `Java_pkg_Class_method`, which receives a `JNIEnv*` and converts every `jstring` by hand. Myotis did exactly that until July 2026. UniFFI removes both hand-written halves. The Kotlin `external fun` declarations are still JVM `native` methods, but JNA's `Native.register` supplies their implementation at run time: a generic dispatcher in `libjnidispatch` converts each argument according to its declared Java type and calls the C symbol with the same name. Nothing on the Rust side knows about the JVM.

![Sequence of one requestAccountJson call. The Java caller sanitizes its strings. For each string argument, Kotlin asks Rust to allocate a RustBuffer, then writes UTF-8 bytes into it. Kotlin calls the scaffolding function with an i64, two RustBuffers and a pointer to a call status; the buffers now belong to Rust. The scaffolding lifts the buffers into Strings without copying and calls ffi.rs inside catch_unwind. host.rs blocks the caller's thread in rt.block_on while tokio worker threads do the network I/O. The JSON String is lowered into a RustBuffer that Rust stops tracking, returned to Kotlin, copied into a Kotlin String, and freed by calling back into Rust. The Java side parses the JSON. A panic in a release build aborts the process.](img/17-uniffi-1.svg)

*One verified account read, end to end. Solid arrows are calls, dashed arrows are returns, and dots mark where JNA converts. Every native call from Kotlin (②, ④, ⑪) gets its own call-status struct. Only ⑦ involves other threads: the caller's thread waits in `block_on` while the runtime's worker threads move packets.*

### Who allocates, who frees

The one rule behind every row: **memory goes back to the allocator it came from**. A `RustBuffer` always holds memory from Rust's allocator, so only Rust may free it, even when Kotlin decides when.

| Buffer | Allocated by | Filled by | Freed by, and when |
|---|---|---|---|
| A `String` argument (`address`, `block`) | Rust, through `ffi_myotis_engine_rustbuffer_alloc` called from Kotlin | Kotlin (UTF-8 bytes) | Rust: the bytes become the `String` parameter of `ffi::request_account_json`, which is dropped when that function returns. |
| An `Option<String>` argument (`holder`) | Rust, same call, sized by Kotlin's pessimistic `allocationSize` | Kotlin (tag byte, length, bytes) | Rust: `try_lift_from_rust_buffer` rebuilds the `Vec`, copies the string out, and drops the `Vec` before the function runs. |
| The returned JSON | Rust (it is the `String`'s own heap buffer) | Rust | Rust, when Kotlin calls `ffi_myotis_engine_rustbuffer_free` in the `finally` of `FfiConverterString.lift`, right after copying. |
| `error_buf` in the call status | Rust, only on an error or a caught panic | Rust (a message) | Rust, when Kotlin lifts the message into an exception (lift frees). |
| The call-status struct itself | JNA (native memory behind the Kotlin `UniffiRustCallStatus` object) | Rust writes into it through `&mut` | The JVM, when the Kotlin object is garbage-collected. |
| `i64`, `i32`, `bool` | Nothing is allocated. They travel in registers. A `bool` is an `i8` (0 or 1), because JVM languages have no C `bool`. |   |   |

## 1. What you write in Rust

Stop 16 covers these files as part of the engine ([ffi.rs](16-engine.md#f-myotis-engine-src-ffi-rs), [host.rs](16-engine.md#f-myotis-engine-src-host-rs), [capi.rs](16-engine.md#f-myotis-engine-src-capi-rs)); here they are the two ends of the bridge. Start with the module doc of `ffi.rs`, which states the whole design in a few lines.

`rust/myotis-engine/src/ffi.rs` · lines 1–21

```rust
//! The UniFFI export surface for the JVM hosts (`:myotis-engine-rust`'s generated
//! Kotlin bindings + the `RustEngineNative` delegator).
//!
//! TRANSPORT SWAP ONLY: these functions mirror the old hand-JNI natives 1:1 —
//! compound values still cross as JSON strings with the exact shapes the golden
//! tests pin on both sides. What UniFFI replaces is the byte-shoveling layer:
//! no hand-written `JNIEnv` code, and the generated bindings verify a per-function
//! API checksum at load time, so a stale library fails loudly at initialization
//! instead of segfaulting on a reshaped symbol.
//!
//! Conventions carried over from the JNI shims:
//! - Panic-free by construction (the workspace builds `panic = "abort"`, so a
//!   panic aborts the host process — same contract as before). All fallible
//!   paths return sentinel values or `{"error": ...}` JSON.
//! - `Option<String>` where the old surface used null (unknown canonical name;
//!   the optional ERC-20 `holder`).
//! - The iOS plain C ABI in `capi.rs` shares the same `host`/`catalog`/`ringlog`
//!   internals and is deliberately NOT expressed through UniFFI.
//!
//! (`uniffi::setup_scaffolding!()` lives in lib.rs — the macro must run at the
//! crate root because `#[uniffi::export]` resolves its `UniFfiTag` there.)
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Result, ? and panics](01-primer.md#primer-error-handling)* Three conventions you will see enforced later: compound values cross as JSON ("transport swap only"), every function is panic-free because the workspace builds with `panic = "abort"` (section 4), and `null` in the old surface became `Option<String>`. The iOS C ABI shares the internals but deliberately does not use UniFFI (section 11).

Here is the function this stop follows. It is an ordinary Rust function with an attribute on top. Nothing in it mentions pointers, buffers or the JVM.

`rust/myotis-engine/src/ffi.rs` · lines 180–189

```rust
/// Verified account query (`AccountProofResult` shape). `address` is 0x-hex;
/// `block` is the RPC block selector (ABI ≥ 32): empty or a head tag proves at
/// the verified head, `finalized` at the beacon-finalized block, a number only
/// inside the window around the head — refused (`{"error","code":-32602}`)
/// otherwise, never answered from the head. The result names the anchor
/// (`anchor`).
#[uniffi::export]
pub fn request_account_json(handle: i64, address: String, block: String) -> String {
    crate::host::request_account_json(handle, &address, &block)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Owned in, borrowed onward.** UniFFI hands the function owned `String`s. The function lends them to `host` as `&address` and `&block` (`&String` coerces to `&str`). When the function returns, both `String`s go out of scope and are dropped, which is where the argument buffers Kotlin filled are finally freed. The returned `String` is moved out to the scaffolding.
- *[Macros & attributes](01-primer.md#primer-macros)* **The doc comment is part of the API.** The `///` lines are copied into the generated Kotlin as KDoc and, as section 2 shows, they are also part of the checksum.

`rust/myotis-engine/src/ffi.rs` · lines 191–201

```rust
/// Verified storage-slot query (`StorageProofResult` shape). A non-None `holder`
/// selects the ERC-20 mapping key `keccak256(pad32(holder) ‖ uint256(slot))`.
#[uniffi::export]
pub fn get_storage_proof_json(
    handle: i64,
    address: String,
    slot: i64,
    holder: Option<String>,
) -> String {
    crate::host::get_storage_proof_json(handle, &address, slot, holder.as_deref())
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* The one non-trivial argument type in the surface. `Option<String>` becomes Kotlin's `String?`. `holder.as_deref()` turns `Option<String>` into `Option<&str>` without allocating: it borrows the string inside the option, if there is one.

`rust/myotis-engine/src/ffi.rs` · lines 47–52

```rust
/// Canonical name for a name/alias, or None when unknown (the Java wrapper
/// raises `EngineException`).
#[uniffi::export]
pub fn canonical_network_name(name_or_alias: String) -> Option<String> {
    crate::catalog::canonical_network_name(&name_or_alias).map(str::to_owned)
}
```

*[Lifetimes](01-primer.md#primer-lifetimes) · [Ownership & moves](01-primer.md#primer-ownership)* `Option<String>` as a *return* type. `catalog::canonical_network_name` returns `Option<&'static str>`, a borrowed literal. UniFFI can only hand over owned data, so `.map(str::to_owned)` copies it into a `String`. Kotlin sees `String?`.

`rust/myotis-engine/src/ffi.rs` · lines 132–136

```rust
/// Remove and shut down a handle's sync loop. No-op for an unknown id.
#[uniffi::export]
pub fn stop_handle(handle: i64) {
    crate::host::stop(handle);
}
```

`rust/myotis-engine/src/ffi.rs` · lines 409–422

```rust
/// Verified `eth_getRawTransactionByBlock{Number,Hash}AndIndex` (ABI ≥ 53,
/// #715): the raw bytes of the transaction at `index` of the block `selector`
/// names (a tag, a 0x number or a 0x block hash) as `"0x…"`, the literal
/// `"null"`, `{"error"}`, or the permanent `{"error","code":-32602}`; see
/// `crate::host::get_raw_transaction_by_block_json`. `index` is signed as every
/// UniFFI integer here is (a JVM `long`, no `ULong`); a negative one is refused
/// for good.
#[uniffi::export]
pub fn get_raw_transaction_by_block_json(handle: i64, selector: String, index: i64) -> String {
    match u64::try_from(index) {
        Ok(index) => crate::host::get_raw_transaction_by_block_json(handle, &selector, index),
        Err(_) => crate::eljson::invalid_params_json("negative transaction index"),
    }
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `stop_handle` returns `()`. The scaffolding then returns nothing, and the Kotlin wrapper returns `Unit` (section 6).
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* The doc comment of `get_raw_transaction_by_block_json` explains a design constraint: every integer in this surface is signed, because the JVM `long` is, and UniFFI's `u64` would surface as Kotlin's `ULong`, which the Java callers cannot use comfortably. The body checks the sign with `u64::try_from` instead of a cast that would wrap. This body is also an example of an edit that does *not* change the checksum (section 10).

`rust/myotis-engine/src/lib.rs` · lines 27–35

```rust
// UniFFI scaffolding (checksums, FFI glue) for the `ffi` exports; must be invoked
// at the crate root — `#[uniffi::export]` resolves its `UniFfiTag` here.
uniffi::setup_scaffolding!();

/// Bumped whenever the FFI surface changes shape. On the JVM this is now a
/// belt-and-braces guard: UniFFI's generated bindings verify a per-function API
/// checksum at load time (a stale .so fails initialization loudly), and the
/// wrapper's availability probe (`engine_init`) additionally compares this coarse
/// version for its log line. The iOS C ABI (`capi`) still relies on it directly.
```

*[Macros & attributes](01-primer.md#primer-macros) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* `setup_scaffolding!` must be invoked at the crate root because every `#[uniffi::export]` expands to code that names `crate::UniFfiTag`, and this macro is what defines that type. Called with no argument, it takes the *namespace* from the crate name (`myotis_engine`), which ends up in every symbol name and in the Kotlin package `uniffi.myotis_engine`. Below it starts the doc of `ABI_VERSION` (now 55, line 397), a coarse hand-bumped version that section 10 puts next to UniFFI's own checks.

`rust/myotis-engine/Cargo.toml` · lines 9–14

```toml
[lib]
# libmyotis_engine.{so,dylib,dll} — loaded by :myotis-engine-rust's RustEngineNative.
# The iOS static archive is NOT listed here: the cargoBuildIos* Gradle tasks
# build it with `cargo rustc --crate-type staticlib` (which overrides this
# list), so host/Android builds don't pay for an archive they never consume.
crate-type = ["cdylib", "rlib"]
```

`rust/myotis-engine/Cargo.toml` · lines 36–41

```toml
# The JVM boundary: UniFFI proc-macro scaffolding (replaces the old hand-JNI —
# the generated Kotlin bindings live in :myotis-engine-rust and are pinned to this
# uniffi version by UniFFI's own per-function API checksums). Compound values
# still cross as JSON strings (transport swap only; shapes unchanged and pinned
# by the golden tests on both sides). The iOS C ABI (capi.rs) is untouched.
uniffi = "0.32"
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `cdylib` is a C-style dynamic library (`.so`, `.dylib`, `.dll`): the artifact JNA loads. Its exported symbols are the `#[no_mangle]` functions and statics. `rlib` is the normal Rust library format that other crates link (`myotis-node` and `myotis-rpcd` do). The iOS static archive is produced separately, as the comment says. The engine depends on `uniffi = "0.32"` without the `cli` feature; only the bindgen binary needs that.

### Where the call lands

`rust/myotis-engine/src/host.rs` · lines 1537–1570

```rust
/// Verified account query as JSON (`AccountProofResult` shape / an
/// `{"error": ...}` object) — `nativeRequestAccountJson`. `block` is the RPC
/// block selector, applied or refused ([`read_anchor`]).
pub fn request_account_json(handle: i64, address_hex: &str, block: &str) -> String {
    let Some(address) = parse_address(address_hex) else {
        return eljson::error_json("invalid address (expected 20-byte hex)");
    };
    let selector = match parse_read_block(block) {
        Ok(selector) => selector,
        Err(json) => return json,
    };
    let Some(engine) = engine() else {
        return eljson::error_json("engine unavailable");
    };
    // Snapshot the reader + the CL status/config under the lock, then release it
    // before the (potentially slow) query — never hold the map lock across a
    // verified read.
    let (reader, finalized_period, wall_period) = match snapshot_reader(engine, handle) {
        Ok(snap) => snap,
        Err(msg) => return eljson::error_json(msg),
    };
    let anchor = match read_anchor(selector, &reader) {
        Ok(anchor) => anchor,
        Err(json) => return json,
    };
    let pin = match selector {
        BlockSelector::Number(n) => Some(n),
        _ => None,
    };
    match engine.rt.block_on(reader.request(async { reader.get_account_pinned(anchor, address, pin).await })) {
        Ok(account) => eljson::account_json(address_hex, &account, finalized_period, wall_period),
        Err(e) => eljson::error_json(&e),
    }
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* This is the end of the bridge, covered in detail in [Stop 16](16-engine.md). Every failure is a `return eljson::error_json(…)` or a pre-built refusal string, never a panic and never a `Result` crossing the boundary: `let … else { return …; }` is the pattern for "parse or bail out".
- *[async/await & tokio](01-primer.md#primer-async) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* `engine.rt.block_on(…)` is the only place the call meets the async world. The thread that came in from Kotlin blocks here while the runtime's worker threads move packets. The `async` block may borrow `reader` and `address` because `block_on` does not return before the future completes.

## 2. What the macros write

Rust macros run inside the compiler and emit ordinary Rust code. `setup_scaffolding!` is a function-like macro invoked once. `#[uniffi::export]` is an attribute macro: it receives the function's source as tokens and returns the function plus new items next to it. Both live in the `uniffi_macros` crate, a *proc-macro* crate: a compiler plugin written in Rust, compiled for the build machine and run by `rustc`.

`cargo registry: uniffi_macros-0.32.0/src/lib.rs` · lines 61–98

```rust
#[proc_macro]
pub fn setup_scaffolding(tokens: TokenStream) -> TokenStream {
    let namespace = match syn::parse_macro_input!(tokens as Option<LitStr>) {
        Some(lit_str) => lit_str.value(),
        None => match util::mod_path() {
            Ok(v) => v,
            Err(e) => return e.into_compile_error().into(),
        },
    };
    setup_scaffolding::setup_scaffolding(namespace)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn export(attr_args: TokenStream, input: TokenStream) -> TokenStream {
    do_export(attr_args, input, true, false)
}

fn do_export(
    attr_args: TokenStream,
    input: TokenStream,
    keep_input: bool,
    udl_mode: bool,
) -> TokenStream {
    let gen_output = || {
        let item = syn::parse(input)?;
        let altered_input = keep_input.then(|| export::alter_input(&item));
        let output = expand_export(item, attr_args, udl_mode)?;
        Ok(quote! {
            #altered_input
            #output
        })
    };
    gen_output()
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
```

- *[Macros & attributes](01-primer.md#primer-macros)* `#[proc_macro]` and `#[proc_macro_attribute]` mark the entry points. Each receives a `TokenStream` (the tokens inside the parentheses, or the item under the attribute) and returns a new one. `syn` parses tokens into a syntax tree; `quote!` turns a template back into tokens.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Macros & attributes](01-primer.md#primer-macros)* Errors become `compile_error!` invocations (`into_compile_error`), so a misuse shows up as an ordinary compiler error at your code, not as a crash of the macro.
- *[Macros & attributes](01-primer.md#primer-macros)* `do_export` keeps your function (`altered_input`) and appends the generated items (`output`). For a free function, `expand_export` (`export.rs`, lines 45–50) dispatches to `gen_fn_scaffolding`, shown below.

### The crate-wide glue

`cargo registry: uniffi_macros-0.32.0/src/setup_scaffolding.rs` · lines 12–46

```rust
pub fn setup_scaffolding(namespace: String) -> Result<TokenStream> {
    let module_path = mod_path()?;
    let normalized_module_path = module_path.replace("::", "__");
    let ffi_contract_version_ident =
        format_ident!("ffi_{normalized_module_path}_uniffi_contract_version");
    let namespace_upper = namespace.to_ascii_uppercase();
    let namespace_const_ident = format_ident!("UNIFFI_META_CONST_NAMESPACE_{namespace_upper}");
    let namespace_static_ident = format_ident!("UNIFFI_META_NAMESPACE_{namespace_upper}");
    let ffi_rustbuffer_alloc_ident = format_ident!("ffi_{normalized_module_path}_rustbuffer_alloc");
    let ffi_rustbuffer_from_bytes_ident =
        format_ident!("ffi_{normalized_module_path}_rustbuffer_from_bytes");
    let ffi_rustbuffer_free_ident = format_ident!("ffi_{normalized_module_path}_rustbuffer_free");
    let ffi_rustbuffer_reserve_ident =
        format_ident!("ffi_{normalized_module_path}_rustbuffer_reserve");
    let reexport_hack_ident = format_ident!("{normalized_module_path}_uniffi_reexport_hack");
    let ffi_rust_future_scaffolding_fns = rust_future_scaffolding_fns(&normalized_module_path);

    Ok(quote! {
        // Unit struct to parameterize the FfiConverter trait.
        //
        // We use FfiConverter<UniFfiTag> to handle lowering/lifting/serializing types for this crate.  See
        // https://mozilla.github.io/uniffi-rs/internals/lifting_and_lowering.html#code-generation-and-the-fficonverter-trait
        // for details.
        //
        // This is pub, since we need to access it to support external types
        #[allow(clippy::exhaustive_structs)]
        #[doc(hidden)]
        pub struct UniFfiTag;

        #[allow(clippy::missing_safety_doc, missing_docs)]
        #[doc(hidden)]
        #[unsafe(no_mangle)]
        pub extern "C" fn #ffi_contract_version_ident() -> ::std::primitive::u32 {
            #UNIFFI_CONTRACT_VERSION
        }
```

- *[Macros & attributes](01-primer.md#primer-macros)* `quote! { … }` builds the output tokens, and `#name` splices in a value, like a template engine for Rust code. `format_ident!` builds identifiers such as `ffi_myotis_engine_uniffi_contract_version`. `#UNIFFI_CONTRACT_VERSION` becomes the literal `30`, a constant in `uniffi_meta` 0.32 that identifies the FFI conventions of this UniFFI release.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `#[unsafe(no_mangle)]` keeps the symbol name exactly as written instead of Rust's mangled form, so C (and JNA) can find it by name. It is spelled `unsafe(…)` because two crates exporting the same unmangled name would silently collide at link time. `extern "C"` selects the C calling convention.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `pub struct UniFfiTag;` is a unit struct: a type with no fields and no size. It exists only to be named as a type parameter, explained below.

`cargo registry: uniffi_macros-0.32.0/src/setup_scaffolding.rs` · lines 63–106

```rust
// Everybody gets basic buffer support, since it's needed for passing complex types over the FFI.
//
// See `uniffi/src/ffi/rustbuffer.rs` for documentation on these functions

#[allow(clippy::missing_safety_doc, missing_docs)]
#[doc(hidden)]
#[unsafe(no_mangle)]
pub extern "C" fn #ffi_rustbuffer_alloc_ident(
    size: ::std::primitive::u64,
    call_status: &mut ::uniffi::RustCallStatus,
) -> ::uniffi::RustBuffer {
    ::uniffi::ffi::uniffi_rustbuffer_alloc(size, call_status)
}

#[allow(clippy::missing_safety_doc, missing_docs)]
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn #ffi_rustbuffer_from_bytes_ident(
    bytes: ::uniffi::ForeignBytes,
    call_status: &mut ::uniffi::RustCallStatus,
) -> ::uniffi::RustBuffer {
    ::uniffi::ffi::uniffi_rustbuffer_from_bytes(bytes, call_status)
}

#[allow(clippy::missing_safety_doc, missing_docs)]
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn #ffi_rustbuffer_free_ident(
    buf: ::uniffi::RustBuffer,
    call_status: &mut ::uniffi::RustCallStatus,
) {
    ::uniffi::ffi::uniffi_rustbuffer_free(buf, call_status);
}

#[allow(clippy::missing_safety_doc, missing_docs)]
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn #ffi_rustbuffer_reserve_ident(
    buf: ::uniffi::RustBuffer,
    additional: ::std::primitive::u64,
    call_status: &mut ::uniffi::RustCallStatus,
) -> ::uniffi::RustBuffer {
    ::uniffi::ffi::uniffi_rustbuffer_reserve(buf, additional, call_status)
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* The four per-crate buffer functions: `ffi_myotis_engine_rustbuffer_alloc`, `_from_bytes`, `_free` and `_reserve`. Each is a two-line forwarder to `uniffi_core` (section 3). Each library gets its own copies, with the crate name in the symbol, because each `cdylib` carries its own allocator: a buffer must go back to the library that made it. Notice that `_alloc` is a safe `extern "C" fn`, while the three that receive a buffer or foreign bytes are `unsafe extern "C" fn`: they rely on the caller's promise that the buffer came from this library. The same macro emits `rust_future_*` functions (line 108) for async exports, which Myotis does not use, and a re-export hack for builds that combine several UniFFI crates in one library.

> [!TIP]
> **Why a tag type: the orphan rule**<br>
>
> Rust lets you write `impl Trait for Type` only if your crate defines the trait or the type. Otherwise two crates could provide conflicting impls. UniFFI wants every consumer crate to be able to implement its conversion traits, even for types from third crates. The trick: the traits take a type parameter, `FfiConverter<UT>`, and the generated code always uses `FfiConverter<crate::UniFfiTag>`. Because `UniFfiTag` is local to `myotis_engine`, an impl mentioning it is allowed there. For built-in types, `uniffi_core` writes blanket impls such as `unsafe impl<UT> FfiConverter<UT> for String`, which apply to every tag. Java has no orphan rule, because Java has no impls outside a class; the nearest analogy is a type-class instance.

### What `#[uniffi::export]` writes for one function

`cargo registry: uniffi_macros-0.32.0/src/export/scaffolding.rs` · lines 237–270

```rust
Ok(if !sig.is_async {
    let scaffolding_fn_ffi_buffer_version =
        ffi_buffer_scaffolding_fn(&ffi_ident, &ffi_return_ty, &param_types, true);
    quote! {
        #[doc(hidden)]
        #[unsafe(no_mangle)]
        pub extern "C" fn #ffi_ident(
            #(#param_names: #param_types,)*
            call_status: &mut ::uniffi::RustCallStatus,
        ) -> #ffi_return_ty {
            #use_trait
            ::uniffi::deps::trace!("calling: {}", #ffi_fn_name);
            let uniffi_lift_args = #lift_closure;
            ::uniffi::rust_call(call_status, || {
                let result = match uniffi_lift_args() {
                    ::std::result::Result::Ok(uniffi_args) => {
                        ::uniffi::deps::trace!("lift_args success: {}", #ffi_fn_name);
                        let uniffi_result = #rust_fn_call;
                        ::uniffi::deps::trace!("call success: {}", #ffi_fn_name);
                        let uniffi_lowered_return = #lower_return(#convert_result);
                        ::uniffi::deps::trace!("lower_return success: {}", #ffi_fn_name);
                        uniffi_lowered_return
                    }
                    ::std::result::Result::Err((arg_name, error)) => {
                        ::uniffi::deps::trace!("lift_args error: {}", #ffi_fn_name);
                        #handle_failed_lift(::uniffi::LiftArgsError { arg_name, error} )
                    },
                };
                result
            })
        }

        #scaffolding_fn_ffi_buffer_version
    }
```

- *[Macros & attributes](01-primer.md#primer-macros) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The C entry point.** One `pub extern "C" fn` per export, named by `uniffi_meta::fn_symbol_name`: `uniffi_<crate>_fn_func_<name>`. Its parameters have the *FFI types* of the Rust parameters, plus a trailing `call_status: &mut RustCallStatus`. It is not declared `unsafe` even though it trusts the buffers it receives; that trust is pushed into the `unsafe trait` impls of section 3.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Lift, call, lower.** Inside `rust_call`, a successful lift calls the real function (`#rust_fn_call`), then `lower_return` turns the result into its FFI type. A failed lift becomes `handle_failed_lift`, an internal error naming the argument.
- *[Macros & attributes](01-primer.md#primer-macros)* The `#scaffolding_fn_ffi_buffer_version` splice produces nothing here: it is only generated with the `scaffolding-ffi-buffer-fns` cargo feature (lines 306–367), which Myotis does not enable. The async branch after line 270 is unused too.

`cargo registry: uniffi_macros-0.32.0/src/fnsig.rs` · lines 187–212

```rust
/// Generate a closure that tries to lift all arguments into a tuple.
///
/// The closure moves all scaffolding arguments into itself and returns:
///   - The lifted argument tuple on success
///   - The field name and error on failure (`Err(&'static str, anyhow::Error>`)
pub fn lift_closure(&self, self_lift: Option<TokenStream>) -> TokenStream {
    let arg_lifts = self.args.iter().map(|arg| {
        let ident = &arg.ident;
        let try_lift = ffiops::try_lift(&arg.ty);
        let name = &arg.name;
        quote! {
            match #try_lift(#ident) {
                ::std::result::Result::Ok(v) => v,
                ::std::result::Result::Err(e) => {
                    return ::std::result::Result::Err((#name, e))
                }
            }
        }
    });
    let all_lifts = self_lift.into_iter().chain(arg_lifts);
    quote! {
        move || ::std::result::Result::Ok((
            #(#all_lifts,)*
        ))
    }
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Ownership & moves](01-primer.md#primer-ownership) · [Result, ? and panics](01-primer.md#primer-error-handling)* **The lift closure.** For each argument the macro emits a `match` on `try_lift`; a failure `return`s from the closure with the argument's name and the error. `move ||` makes the closure take ownership of every scaffolding parameter, so each buffer is consumed exactly once. The closure is built outside `rust_call` but only *called* inside it, so a panic during lifting is also caught (in an unwinding build).

Filling in both templates for `request_account_json` gives roughly the following. This listing is written by hand from the macro source, not cut from a file. The `trace!` calls and the unused ffi-buffer variant are left out.

*hand-expanded and simplified: the items #\[uniffi::export\] adds next to request\_account\_json not verbatim*

```text
#[unsafe(no_mangle)]
pub extern "C" fn uniffi_myotis_engine_fn_func_request_account_json(
    handle: <i64 as Lift<crate::UniFfiTag>>::FfiType,     // = i64
    address: <String as Lift<crate::UniFfiTag>>::FfiType, // = RustBuffer
    block: <String as Lift<crate::UniFfiTag>>::FfiType,   // = RustBuffer
    call_status: &mut ::uniffi::RustCallStatus,
) -> <String as LowerReturn<crate::UniFfiTag>>::ReturnType { // = RustBuffer
    let uniffi_lift_args = move || Ok((
        match <i64 as Lift<crate::UniFfiTag>>::try_lift(handle) {
            Ok(v) => v,
            Err(e) => return Err(("handle", e)),
        },
        match <String as Lift<crate::UniFfiTag>>::try_lift(address) {
            Ok(v) => v,
            Err(e) => return Err(("address", e)),
        },
        match <String as Lift<crate::UniFfiTag>>::try_lift(block) {
            Ok(v) => v,
            Err(e) => return Err(("block", e)),
        },
    ));
    ::uniffi::rust_call(call_status, || match uniffi_lift_args() {
        Ok(uniffi_args) => {
            let uniffi_result =
                request_account_json(uniffi_args.0, uniffi_args.1, uniffi_args.2);
            <String as LowerReturn<crate::UniFfiTag>>::lower_return(uniffi_result)
        }
        Err((arg_name, error)) => <String as LowerReturn<crate::UniFfiTag>>::handle_failed_lift(
            ::uniffi::LiftArgsError { arg_name, error }),
    })
}

// The signature as bytes, for uniffi-bindgen to read out of the library.
const UNIFFI_META_CONST_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON: MetadataBuffer = /* see below */;
#[unsafe(no_mangle)]
pub static UNIFFI_META_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON: [u8; N] =
    UNIFFI_META_CONST_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON.into_array();

// The checksum of those bytes, computed by the compiler.
#[unsafe(no_mangle)]
pub extern "C" fn uniffi_myotis_engine_checksum_func_request_account_json() -> u16 {
    const CHECKSUM: u16 = UNIFFI_META_CONST_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON.checksum();
    CHECKSUM
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Associated types pick the wire type.** `<String as Lift<crate::UniFfiTag>>::FfiType` is "the `FfiType` that `String`'s `Lift` impl declares", which is `RustBuffer`. The macro never needs to know that; it only names the trait. Java generics cannot express a type that depends on another type like this.
- *[Ownership & moves](01-primer.md#primer-ownership)* **Each argument is moved exactly once.** The closure is `move`, so it takes ownership of `address` and `block`; `try_lift` consumes each `RustBuffer` and returns an owned `String`; `uniffi_args.1` moves that `String` into the call. No step copies the bytes.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* I checked the symbol names with `nm -gU` against a `libmyotis_engine.dylib` built from the main checkout in October: `_uniffi_myotis_engine_fn_func_request_account_json`, `_uniffi_myotis_engine_checksum_func_request_account_json` and the read-only static `_UNIFFI_META_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON` are all there, next to the hand-written `_myotis_request_account_json` of the C ABI. One library serves both routes.

### The metadata, and why a doc comment changes the checksum

`cargo registry: uniffi_macros-0.32.0/src/fnsig.rs` · lines 300–310

```rust
FnKind::Function => Ok(quote! {
    ::uniffi::MetadataBuffer::from_code(::uniffi::metadata::codes::FUNC)
        .concat_str(module_path!())
        .concat_str(#name)
        #orig_name
        .concat_bool(#is_async)
        .concat_value(#args_len)
        #(#arg_metadata_calls)*
        .concat(#type_id_meta)
        .concat_long_str(#docstring)
}),
```

*[Macros & attributes](01-primer.md#primer-macros)* This is the whole description of a function: its module path (`myotis_engine::ffi`), its name, whether it was renamed, whether it is async, the argument count, then per argument its name, type code, by-reference flag and default (`arg_metadata`, lines 532–543), then the return type and finally the doc comment (`concat_long_str(#docstring)`). `MetadataBuffer` has only `const fn` methods, so the whole chain is evaluated by the compiler into a fixed byte array.

`cargo registry: uniffi_macros-0.32.0/src/util.rs` · lines 101–137

```rust
pub fn create_metadata_items(
    kind: &str,
    name: &str,
    metadata_expr: TokenStream,
    checksum_fn_name: Option<String>,
) -> TokenStream {
    let crate_name = crate_name();
    let crate_name_upper = crate_name.to_uppercase();
    let kind_upper = kind.to_uppercase();
    let name_upper = name.to_uppercase();
    let const_ident =
        format_ident!("UNIFFI_META_CONST_{crate_name_upper}_{kind_upper}_{name_upper}");
    let static_ident = format_ident!("UNIFFI_META_{crate_name_upper}_{kind_upper}_{name_upper}");
    let checksum_fn = checksum_fn_name.map(|name| {
        let ident = Ident::new(&name, Span::call_site());
        quote! {
            #[doc(hidden)]
            #[unsafe(no_mangle)]
            pub extern "C" fn #ident() -> u16 {
                // Force constant evaluation to ensure:
                // 1. The checksum is computed at compile time; and
                // 2. The metadata buffer is not embedded into the binary.
                const CHECKSUM: u16 = #const_ident.checksum();
                CHECKSUM
            }
        }
    });

    quote! {
        const #const_ident: ::uniffi::MetadataBuffer = #metadata_expr;
        #[unsafe(no_mangle)]
        #[doc(hidden)]
        pub static #static_ident: [u8; #const_ident.size] = #const_ident.into_array();

        #checksum_fn
    }
}
```

- *[Macros & attributes](01-primer.md#primer-macros) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Two artifacts from one buffer.** The `const` holds the metadata at compile time. The `#[no_mangle] pub static` copies it into the binary under the name `UNIFFI_META_MYOTIS_ENGINE_FUNC_REQUEST_ACCOUNT_JSON`, where the generator will find it (section 5). The checksum function returns `u16` and is exported as `uniffi_myotis_engine_checksum_func_request_account_json`.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **`const CHECKSUM: u16 = …` inside the function** forces the compiler to compute the hash during compilation. A plain expression might be evaluated at run time; a `const` item must be known at compile time. The comment says this also keeps the checksum function from referencing the buffer at run time.
- *[Protocol & domain](01-primer.md#primer-domain)* The checksum covers exactly the metadata bytes. So renaming a parameter, changing a type, moving the function to another module, or editing a single word of its `///` comment changes the checksum. Changing the function's *body* does not.

## 3. The wire vocabulary: `RustBuffer` and the converter traits

### `RustBuffer`

`cargo registry: uniffi_core-0.32.0/src/ffi/rustbuffer.rs` · lines 7–62

```rust
/// Support for passing an allocated-by-Rust buffer of bytes over the FFI.
///
/// We can pass a `Vec<u8>` to foreign language code by decomposing it into
/// its raw parts (buffer pointer, length, and capacity) and passing those
/// around as a struct. Naturally, this can be tremendously unsafe! So here
/// are the details:
///
///   * `RustBuffer` structs must only ever be constructed from a `Vec<u8>`,
///     either explicitly via `RustBuffer::from_vec` or indirectly by calling
///     one of the `RustBuffer::new*` constructors.
///
///   * `RustBuffer` structs do not implement `Drop`, since they are intended
///     to be passed to foreign-language code outside of the control of Rust's
///     ownership system. To avoid memory leaks they *must* passed back into
///     Rust and either explicitly destroyed using `RustBuffer::destroy`, or
///     converted back to a `Vec<u8>` using `RustBuffer::destroy_into_vec`
///     (which will then be dropped via Rust's usual ownership-tracking system).
///
/// Foreign-language code should not construct `RustBuffer` structs other than
/// by receiving them from a call into the Rust code, and should not modify them
/// apart from the following safe operations:
///
///   * Writing bytes into the buffer pointed to by `data`, without writing
///     beyond the indicated `capacity`.
///
///   * Adjusting the `len` property to indicate the amount of data written,
///     while ensuring that 0 <= `len` <= `capacity`.
///
///   * As a special case, constructing a `RustBuffer` with zero capacity, zero
///     length, and a null `data` pointer to indicate an empty buffer.
///
/// In particular, it is not safe for foreign-language code to construct a `RustBuffer`
/// that points to its own allocated memory; use the `ForeignBytes` struct to
/// pass a view of foreign-owned memory in to Rust code.
///
/// Implementation note: all the fields of this struct are private, so you can't
/// manually construct instances that don't come from a `Vec<u8>`. If you've got
/// a `RustBuffer` then it either came from a public constructor (all of which
/// are safe) or it came from foreign-language code (which should have in turn
/// received it by calling some Rust function, and should be respecting the
/// invariants listed above).
///
/// This struct is based on `ByteBuffer` from the `ffi-support` crate, but modified
/// to retain unallocated capacity rather than truncating to the occupied length.
#[repr(C)]
#[derive(Debug)]
pub struct RustBuffer {
    /// The allocated capacity of the underlying `Vec<u8>`.
    /// In Rust this is a `usize`, but we use an `u64` to keep the foreign binding code simple.
    pub(crate) capacity: u64,
    /// The occupied length of the underlying `Vec<u8>`.
    /// In Rust this is a `usize`, but we use an `u64` to keep the foreign binding code simple.
    pub(crate) len: u64,
    /// The pointer to the allocated buffer of the `Vec<u8>`.
    pub(crate) data: *mut u8,
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The rules, in the type's own doc comment.** A `RustBuffer` is only ever made from a `Vec<u8>`; it has no `Drop`; it must come back to Rust to be destroyed; the foreign side may only write bytes up to `capacity` and adjust `len`; and the foreign side must never wrap its own memory in one (that is what `ForeignBytes` is for).
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **`#[repr(C)]` fixes the layout.** Without it, Rust may reorder struct fields. With it, the layout is exactly a C struct `{ uint64_t capacity; uint64_t len; uint8_t *data; }`, which is what the Kotlin `RustBuffer` declares field by field (section 6). The fields are `pub(crate)`, so no other crate can build an invalid one.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `unsafe impl Send for RustBuffer {}` (line 67): a struct holding a raw pointer is not `Send` by default, because the compiler cannot know who else uses the pointer. UniFFI asserts it is safe to move between threads, which async futures need.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustbuffer.rs` · lines 124–151

```rust
/// Creates a `RustBuffer` zero-filed to the requested size.
///
/// The resulting vector will not be automatically dropped; you must
/// arrange to call `destroy` or `destroy_into_vec` when finished with it.
///
/// # Panics
///
/// Panics if the requested size is too large to fit in an `u64`, and
/// hence would risk incompatibility with some foreign-language code.
pub fn new_with_size(size: u64) -> Self {
    Self::from_vec(vec![0u8; size as usize])
}

/// Consumes a `Vec<u8>` and returns its raw parts as a `RustBuffer`.
///
/// The resulting vector will not be automatically dropped; you must
/// arrange to call `destroy` or `destroy_into_vec` when finished with it.
///
/// # Panics
///
/// Panics if the vector's length or capacity are too large to fit in an `u64`,
/// and hence would risk incompatibility with some foreign-language code.
pub fn from_vec(v: Vec<u8>) -> Self {
    let capacity = u64::try_from(v.capacity()).expect("buffer capacity cannot fit into a u64.");
    let len = u64::try_from(v.len()).expect("buffer length cannot fit into a u64.");
    let mut v = std::mem::ManuallyDrop::new(v);
    unsafe { Self::from_raw_parts(v.as_mut_ptr(), len, capacity) }
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Giving up ownership.** `new_with_size` allocates a zero-filled `Vec` of the requested length; this is what Kotlin's `alloc` gets. `from_vec` records the three parts. `ManuallyDrop::new(v)` wraps the vector so that its destructor will not run when `v` goes out of scope. Without it, the `Vec` would free its buffer at the closing brace and the returned `RustBuffer` would point to freed memory. The `try_from(…).expect(…)` calls can only panic on a platform whose `usize` is wider than 64 bits.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustbuffer.rs` · lines 153–192

```rust
/// Converts this `RustBuffer` back into an owned `Vec<u8>`.
///
/// This restores ownership of the underlying buffer to Rust, meaning it will
/// be dropped when the `Vec<u8>` is dropped. The `RustBuffer` *must* have been
/// previously obtained from a valid `Vec<u8>` owned by this Rust code.
///
/// # Panics
///
/// Panics if called on an invalid struct obtained from foreign-language code,
/// which does not respect the invairiants on `len` and `capacity`.
pub fn destroy_into_vec(self) -> Vec<u8> {
    // Rust will never give us a null `data` pointer for a `Vec`, but
    // foreign-language code can use it to cheaply pass an empty buffer.
    if self.data.is_null() {
        assert!(self.capacity == 0, "null RustBuffer had non-zero capacity");
        assert!(self.len == 0, "null RustBuffer had non-zero length");
        vec![]
    } else {
        let capacity: usize = self
            .capacity
            .try_into()
            .expect("buffer capacity negative or overflowed");
        let len: usize = self
            .len
            .try_into()
            .expect("buffer length negative or overflowed");
        assert!(len <= capacity, "RustBuffer length exceeds capacity");
        unsafe { Vec::from_raw_parts(self.data, len, capacity) }
    }
}

/// Reclaim memory stored in this `RustBuffer`.
///
/// # Panics
///
/// Panics if called on an invalid struct obtained from foreign-language code,
/// which does not respect the invairiants on `len` and `capacity`.
pub fn destroy(self) {
    drop(self.destroy_into_vec());
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Taking ownership back.** `destroy_into_vec(self)` consumes the buffer and rebuilds an owning `Vec` with `Vec::from_raw_parts(data, len, capacity)`, which then frees normally when dropped. It is the only place a buffer's memory is reclaimed. The checks are defensive: a null pointer is accepted only with zero length and capacity (a foreign side may send an empty buffer that way), and `len <= capacity` is asserted. `destroy` is `drop(self.destroy_into_vec())`. In Java terms, `from_vec` detaches an off-heap buffer from its cleaner, and `destroy_into_vec` re-attaches it.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustbuffer.rs` · lines 201–244

```rust
// Functions for the RustBuffer functionality.
//
// The scaffolding code re-exports these functions, prefixed with the component name and UDL hash
// This creates a separate set of functions for each UniFFIed component, which is needed in the
// case where we create multiple dylib artifacts since each dylib will have its own allocator.

/// This helper allocates a new byte buffer owned by the Rust code, and returns it
/// to the foreign-language code as a `RustBuffer` struct. Callers must eventually
/// free the resulting buffer, either by explicitly calling [`uniffi_rustbuffer_free`] defined
/// below, or by passing ownership of the buffer back into Rust code.
pub fn uniffi_rustbuffer_alloc(size: u64, call_status: &mut RustCallStatus) -> RustBuffer {
    rust_call(call_status, || Ok(RustBuffer::new_with_size(size)))
}

/// This helper copies bytes owned by the foreign-language code into a new byte buffer owned
/// by the Rust code, and returns it as a `RustBuffer` struct. Callers must eventually
/// free the resulting buffer, either by explicitly calling the destructor defined below,
/// or by passing ownership of the buffer back into Rust code.
///
/// # Safety
/// This function will dereference a provided pointer in order to copy bytes from it, so
/// make sure the `ForeignBytes` struct contains a valid pointer and length.
pub fn uniffi_rustbuffer_from_bytes(
    bytes: ForeignBytes,
    call_status: &mut RustCallStatus,
) -> RustBuffer {
    rust_call(call_status, || {
        let bytes = bytes.as_slice();
        Ok(RustBuffer::from_vec(bytes.to_vec()))
    })
}

/// Free a byte buffer that had previously been passed to the foreign language code.
///
/// # Safety
/// The argument *must* be a uniquely-owned `RustBuffer` previously obtained from a call
/// into the Rust code that returned a buffer, or you'll risk freeing unowned memory or
/// corrupting the allocator state.
pub fn uniffi_rustbuffer_free(buf: RustBuffer, call_status: &mut RustCallStatus) {
    rust_call(call_status, || {
        RustBuffer::destroy(buf);
        Ok(())
    })
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Result, ? and panics](01-primer.md#primer-error-handling)* The runtime behind the four per-crate functions of section 2. Each wraps its work in `rust_call`, so even buffer management reports failures through a call status. `uniffi_rustbuffer_from_bytes` copies foreign memory into a new Rust buffer (`as_slice().to_vec()`); the Kotlin bindings declare it but do not use it.

### The conversion traits

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 5–51

````rust
//! Traits that define how to transfer values via the FFI layer.
//!
//! These traits define how to pass values over the FFI in various ways: as arguments or as return
//! values, from Rust to the foreign side and vice-versa.  These traits are mainly used by the
//! proc-macro generated code.  The goal is to allow the proc-macros to go from a type name to the
//! correct function for a given FFI operation.
//!
//! The main traits form a sort-of tree structure from general to specific:
//! ```ignore
//!
//!                         [FfiConverter]
//!                               |
//!            -----------------------------------------
//!            |                                       |
//!         [Lower]                                  [Lift]
//!            |                                       |
//!        -----------------                    --------------
//!        |               |                    |            |
//!   [LowerReturn]  [LowerError]          [LiftRef]  [LiftReturn]
//! ```
//!
//! There's also:
//!   - [TypeId], which is implemented for all types that implement any of the above traits.
//!   - [ConvertError], which is implement for errors that can be used in callback interfaces.
//!
//! The `derive_ffi_traits` macro can be used to derive the specific traits from the general ones.
//! Here's the main ways we implement these traits:
//!
//! * For most types we implement [FfiConverter] and use [derive_ffi_traits] to implement the rest
//! * If a type can only be lifted/lowered, then we implement [Lift] or [Lower] and use
//!   [derive_ffi_traits] to implement the rest
//! * If a type needs special-case handling, like `Result<>` and `()`, we implement the traits
//!   directly.
//!
//! FfiConverter has a generic parameter, that's filled in with a type local to the UniFFI consumer crate.
//! This allows us to work around the Rust orphan rules for remote types. See
//! `https://mozilla.github.io/uniffi-rs/internals/lifting_and_lowering.html#code-generation-and-the-fficonverter-trait`
//! for details.
//!
//! ## Safety
//!
//! Most traits are unsafe (implementing it requires `unsafe impl`) because we can't guarantee
//! that it's safe to pass your type out to foreign-language code and back again. Buggy
//! implementations of this trait might violate some assumptions made by the generated code,
//! or might not match with the corresponding code in the generated foreign-language bindings.
//! These traits should not be used directly, only in generated code, and the generated code should
//! have fixture tests to test that everything works correctly together.
````

*[Traits, generics & dyn](01-primer.md#primer-traits-generics)* The module doc draws the family tree. `FfiConverter` is the general trait you implement; the generated code uses only the narrower ones: `Lift` for arguments coming in, `Lower` for values going out, `LowerReturn` for return values (which lets `Result` and `()` be handled specially), `LiftReturn`/`LowerError` for callbacks and errors, and `TypeId` for the metadata. `derive_ffi_traits!` generates the narrow impls from the general one.

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 76–136

```rust
pub unsafe trait FfiConverter<UT>: Sized {
    /// The low-level type used for passing values of this type over the FFI.
    ///
    /// This must be a C-compatible type (e.g. a numeric primitive, a `#[repr(C)]` struct) into
    /// which values of the target rust type can be converted.
    ///
    /// For complex data types, we currently recommend using `RustBuffer` and serializing
    /// the data for transfer. In theory it could be possible to build a matching
    /// `#[repr(C)]` struct for a complex data type and pass that instead, but explicit
    /// serialization is simpler and safer as a starting point.
    ///
    /// If a type implements multiple FFI traits, `FfiType` must be the same for all of them.
    type FfiType: FfiDefault;

    /// Lower a rust value of the target type, into an FFI value of type Self::FfiType.
    ///
    /// This trait method is used for sending data from rust to the foreign language code,
    /// by (hopefully cheaply!) converting it into something that can be passed over the FFI
    /// and reconstructed on the other side.
    ///
    /// Note that this method takes an owned value; this allows it to transfer ownership in turn to
    /// the foreign language code, e.g. by boxing the value and passing a pointer.
    fn lower(obj: Self) -> Self::FfiType;

    /// Lift a rust value of the target type, from an FFI value of type Self::FfiType.
    ///
    /// This trait method is used for receiving data from the foreign language code in rust,
    /// by (hopefully cheaply!) converting it from a low-level FFI value of type Self::FfiType
    /// into a high-level rust value of the target type.
    ///
    /// Since we cannot statically guarantee that the foreign-language code will send valid
    /// values of type Self::FfiType, this method is fallible.
    fn try_lift(v: Self::FfiType) -> Result<Self>;

    /// Write a rust value into a buffer, to send over the FFI in serialized form.
    ///
    /// This trait method can be used for sending data from rust to the foreign language code,
    /// in cases where we're not able to use a special-purpose FFI type and must fall back to
    /// sending serialized bytes.
    ///
    /// Note that this method takes an owned value because it's transferring ownership
    /// to the foreign language code via the RustBuffer.
    fn write(obj: Self, buf: &mut Vec<u8>);

    /// Read a rust value from a buffer, received over the FFI in serialized form.
    ///
    /// This trait method can be used for receiving data from the foreign language code in rust,
    /// in cases where we're not able to use a special-purpose FFI type and must fall back to
    /// receiving serialized bytes.
    ///
    /// Since we cannot statically guarantee that the foreign-language code will send valid
    /// serialized bytes for the target type, this method is fallible.
    ///
    /// Note the slightly unusual type here - we want a mutable reference to a slice of bytes,
    /// because we want to be able to advance the start of the slice after reading an item
    /// from it (but will not mutate the actual contents of the slice).
    fn try_read(buf: &mut &[u8]) -> Result<Self>;

    /// Type ID metadata, serialized into a [MetadataBuffer].
    const TYPE_ID_META: MetadataBuffer;
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **An associated type plus five items.** `type FfiType` is the C-compatible type (a number, or `RustBuffer`). `lower` goes Rust → foreign; `try_lift` goes foreign → Rust and returns a `Result` because the foreign side might send something invalid. `write` and `try_read` serialize a value *into* a byte buffer when it is nested inside something else, such as the `String` inside an `Option<String>`. `TYPE_ID_META` is the type's code in the metadata.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `lower(obj: Self)` takes the value by value: lowering may hand ownership to the foreign side, so the Rust value must be consumed. `try_read(buf: &mut &[u8])` is a mutable reference to a slice: the reader moves the slice's start forward after each item without touching the bytes, like a cursor.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* The trait is `pub unsafe trait`. An `unsafe trait` means implementing it is a promise the compiler cannot check, here that the impl matches what the generated foreign code does. `FfiType: FfiDefault` is a bound: every FFI type must have a placeholder value to return when a call fails (see `ffidefault.rs` in the deep dive below).

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 223–240

```rust
pub unsafe trait Lift<UT>: Sized {
    type FfiType;

    fn try_lift(v: Self::FfiType) -> Result<Self>;

    fn try_read(buf: &mut &[u8]) -> Result<Self>;

    /// Convenience method
    fn try_lift_from_rust_buffer(v: RustBuffer) -> Result<Self> {
        let vec = v.destroy_into_vec();
        let mut buf = vec.as_slice();
        let value = Self::try_read(&mut buf)?;
        match Buf::remaining(&buf) {
            0 => Ok(value),
            n => bail!("junk data left in buffer after lifting (count: {n})",),
        }
    }
}
```

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 257–270

```rust
pub unsafe trait Lower<UT>: Sized {
    type FfiType: FfiDefault;

    fn lower(obj: Self) -> Self::FfiType;

    fn write(obj: Self, buf: &mut Vec<u8>);

    /// Convenience method
    fn lower_into_rust_buffer(obj: Self) -> RustBuffer {
        let mut buf = ::std::vec::Vec::new();
        Self::write(obj, &mut buf);
        RustBuffer::from_vec(buf)
    }
}
```

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 284–311

```rust
pub unsafe trait LowerReturn<UT>: Sized {
    /// The type that should be returned by scaffolding functions for this type.
    ///
    /// When derived, it's the same as `FfiType`.
    type ReturnType: FfiDefault;

    /// Lower the return value from an scaffolding call
    ///
    /// Returns values that [rust_call] expects:
    ///
    /// - Ok(v) for `Ok` returns and non-result returns, where v is the lowered return value
    /// - `Err(RustCallError::Error(buf))` for `Err` returns where `buf` is serialized error value.
    fn lower_return(v: Self) -> Result<Self::ReturnType, RustCallError>;

    /// Lower the return value for failed argument lifts
    ///
    /// This is called when we fail to make a scaffolding call, because of an error lifting an
    /// argument.  It should return a value that [rust_call] expects:
    ///
    /// - By default, this is `Err(RustCallError::InternalError(msg))` where `msg` is message
    ///   describing the failed lift.
    /// - For Result types, if we can downcast the error to the `Err` value, then return
    ///   `Err(RustCallError::Error(buf))`. This results in better exception throws on the foreign
    ///   side.
    fn handle_failed_lift(error: LiftArgsError) -> Result<Self::ReturnType, RustCallError> {
        Err(error.to_internal_error())
    }
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Default methods.** `Lift::try_lift_from_rust_buffer` and `Lower::lower_into_rust_buffer` have bodies in the trait, like Java `default` methods. They are how compound values travel: write everything into a fresh `Vec`, hand it out as a `RustBuffer`; on the way in, rebuild the `Vec`, read one value, and refuse leftover bytes (`bail!` from `anyhow` returns an error early).
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **`LowerReturn`** returns `Result<Self::ReturnType, RustCallError>`. For a plain type it is always `Ok`. For a `Result<T, E>` return type, its impl turns `Err(e)` into `RustCallError::Error(buffer)`, which becomes status code 1 and a typed Kotlin exception. Myotis has no such export. `handle_failed_lift` has a default body: every failed lift becomes an internal error with a message.

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 513–523

```rust
macro_rules! derive_ffi_traits {
    (blanket $ty:ty) => {
        $crate::derive_ffi_traits!(impl<UT> Lower<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> Lift<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> LowerReturn<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> LowerError<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> LiftReturn<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> LiftRef<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> ConvertError<UT> for $ty);
        $crate::derive_ffi_traits!(impl<UT> TypeId<UT> for $ty);
    };
```

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_traits.rs` · lines 566–575

```rust
(impl $(<$($generic:ident),*>)? $(::uniffi::)? LowerReturn<$ut:path> for $ty:ty $(where $($where:tt)*)?) => {
    unsafe impl $(<$($generic),*>)* $crate::LowerReturn<$ut> for $ty $(where $($where)*)*
    {
        type ReturnType = <Self as $crate::Lower<$ut>>::FfiType;

        fn lower_return(v: Self) -> $crate::deps::anyhow::Result<Self::ReturnType, $crate::RustCallError> {
            ::std::result::Result::Ok(<Self as $crate::Lower<$ut>>::lower(v))
        }
    }
};
```

*[Macros & attributes](01-primer.md#primer-macros) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* **A `macro_rules!` macro deriving trait impls.** This is the other kind of Rust macro: pattern-matching on tokens, with no compiler plugin. `derive_ffi_traits!(blanket String)` (in `ffi_converter_impls.rs`, line 450) expands to eight `unsafe impl<UT> … for String` blocks, each delegating to `FfiConverter`. The `LowerReturn` arm shows the plain case: `ReturnType` is the `Lower` type, and `lower_return` wraps `lower` in `Ok`. `$crate` refers to `uniffi_core` wherever the macro is used.

### The impls Myotis uses

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_impls.rs` · lines 39–79

```rust
/// Blanket implementation of `FfiConverter` for numeric primitives.
///
/// Numeric primitives have a straightforward mapping into C-compatible numeric types,
/// sice they are themselves a C-compatible numeric type!
macro_rules! impl_ffi_converter_for_num_primitive {
    ($T:ty, $type_code:expr, $get:ident, $put:ident) => {
        unsafe impl<UT> FfiConverter<UT> for $T {
            type FfiType = $T;

            fn lower(obj: $T) -> Self::FfiType {
                obj
            }

            fn try_lift(v: Self::FfiType) -> Result<$T> {
                Ok(v)
            }

            fn write(obj: $T, buf: &mut Vec<u8>) {
                buf.$put(obj);
            }

            fn try_read(buf: &mut &[u8]) -> Result<$T> {
                check_remaining(buf, std::mem::size_of::<$T>())?;
                Ok(buf.$get())
            }

            const TYPE_ID_META: MetadataBuffer = MetadataBuffer::from_code($type_code);
        }
    };
}

impl_ffi_converter_for_num_primitive!(u8, metadata::codes::TYPE_U8, get_u8, put_u8);
impl_ffi_converter_for_num_primitive!(i8, metadata::codes::TYPE_I8, get_i8, put_i8);
impl_ffi_converter_for_num_primitive!(u16, metadata::codes::TYPE_U16, get_u16, put_u16);
impl_ffi_converter_for_num_primitive!(i16, metadata::codes::TYPE_I16, get_i16, put_i16);
impl_ffi_converter_for_num_primitive!(u32, metadata::codes::TYPE_U32, get_u32, put_u32);
impl_ffi_converter_for_num_primitive!(i32, metadata::codes::TYPE_I32, get_i32, put_i32);
impl_ffi_converter_for_num_primitive!(u64, metadata::codes::TYPE_U64, get_u64, put_u64);
impl_ffi_converter_for_num_primitive!(i64, metadata::codes::TYPE_I64, get_i64, put_i64);
impl_ffi_converter_for_num_primitive!(f32, metadata::codes::TYPE_F32, get_f32, put_f32);
impl_ffi_converter_for_num_primitive!(f64, metadata::codes::TYPE_F64, get_f64, put_f64);
```

*[Macros & attributes](01-primer.md#primer-macros) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Numbers are their own FFI type.** One `macro_rules!` template stamps out the impl for all ten numeric types. `lower` and `try_lift` are the identity: an `i64` travels as an `i64`. `write` and `try_read` go through the `bytes` crate's `put_i64`/`get_i64`, which are big-endian. `check_remaining` turns a short buffer into an error instead of a panic.

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_impls.rs` · lines 81–110

```rust
/// Support for passing boolean values via the FFI.
///
/// Booleans are passed as an `i8` in order to avoid problems with handling
/// C-compatible boolean values on JVM-based languages.
unsafe impl<UT> FfiConverter<UT> for bool {
    type FfiType = i8;

    fn lower(obj: bool) -> Self::FfiType {
        i8::from(obj)
    }

    fn try_lift(v: Self::FfiType) -> Result<bool> {
        Ok(match v {
            0 => false,
            1 => true,
            _ => bail!("unexpected byte for Boolean"),
        })
    }

    fn write(obj: bool, buf: &mut Vec<u8>) {
        buf.put_i8(<Self as FfiConverter<UT>>::lower(obj));
    }

    fn try_read(buf: &mut &[u8]) -> Result<bool> {
        check_remaining(buf, 1)?;
        <Self as FfiConverter<UT>>::try_lift(buf.get_i8())
    }

    const TYPE_ID_META: MetadataBuffer = MetadataBuffer::from_code(metadata::codes::TYPE_BOOL);
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling)* `bool` crosses as `i8` "to avoid problems with handling C-compatible boolean values on JVM-based languages". Lifting is strict: anything other than 0 or 1 is an error. The Kotlin side is lenient in the other direction (section 6).

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_impls.rs` · lines 112–167

```rust
/// Support for passing Strings via the FFI.
///
/// Unlike many other implementations of `FfiConverter`, this passes a struct containing
/// a raw pointer rather than copying the data from one side to the other. This is a
/// safety hazard, but turns out to be pretty nice for useability. This struct
/// *must* be a valid `RustBuffer` and it *must* contain valid utf-8 data (in other
/// words, it *must* be a `Vec<u8>` suitable for use as an actual rust `String`).
///
/// When serialized in a buffer, strings are represented as a i32 byte length
/// followed by utf8-encoded bytes. (It's a signed integer because unsigned types are
/// currently experimental in Kotlin).
unsafe impl<UT> FfiConverter<UT> for String {
    type FfiType = RustBuffer;

    // This returns a struct with a raw pointer to the underlying bytes, so it's very
    // important that it consume ownership of the String, which is relinquished to the
    // foreign language code (and can be restored by it passing the pointer back).
    fn lower(obj: String) -> Self::FfiType {
        RustBuffer::from_vec(obj.into_bytes())
    }

    // The argument here *must* be a uniquely-owned `RustBuffer` previously obtained
    // from `lower` above, and hence must be the bytes of a valid rust string.
    fn try_lift(v: Self::FfiType) -> Result<String> {
        let v = v.destroy_into_vec();
        // This turns the buffer back into a `String` without copying the data
        // and without re-checking it for validity of the utf8. If the `RustBuffer`
        // came from a valid String then there's no point in re-checking the utf8,
        // and if it didn't then bad things are probably going to happen regardless
        // of whether we check for valid utf8 data or not.
        Ok(unsafe { String::from_utf8_unchecked(v) })
    }

    fn write(obj: String, buf: &mut Vec<u8>) {
        // N.B. `len()` gives us the length in bytes, not in chars or graphemes.
        // TODO: it would be nice not to panic here.
        let len = i32::try_from(obj.len()).unwrap();
        buf.put_i32(len); // We limit strings to u32::MAX bytes
        buf.put(obj.as_bytes());
    }

    fn try_read(buf: &mut &[u8]) -> Result<String> {
        check_remaining(buf, 4)?;
        let len = usize::try_from(buf.get_i32())?;
        check_remaining(buf, len)?;
        // N.B: In the general case `Buf::chunk()` may return partial data.
        // But in the specific case of `<&[u8] as Buf>` it returns the full slice,
        // so there is no risk of having less than `len` bytes available here.
        let bytes = &buf.chunk()[..len];
        let res = String::from_utf8(bytes.to_vec())?;
        buf.advance(len);
        Ok(res)
    }

    const TYPE_ID_META: MetadataBuffer = MetadataBuffer::from_code(metadata::codes::TYPE_STRING);
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Ownership & moves](01-primer.md#primer-ownership)* **Zero-copy in both directions.** A Rust `String` is a `Vec<u8>` that is guaranteed to hold UTF-8. `obj.into_bytes()` converts it into that vector without copying, and `from_vec` hands it out. On the way in, `destroy_into_vec` rebuilds the vector and `String::from_utf8_unchecked` relabels it as a `String`, again without copying. At the top level the buffer's own `len` is the string length, so no length prefix is written.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **`from_utf8_unchecked` trusts Kotlin.** Rust's safe code assumes every `String` is valid UTF-8; an invalid one is undefined behavior. This lift does not check. It is sound only because the generated Kotlin encodes strings with an encoder that *refuses* malformed input (section 6). That refusal is why `RustEngineNative` sanitizes strings first (section 7).
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Nested strings are different.** `write` puts a big-endian `i32` length in front of the bytes, and `try_read` copies the bytes out (`to_vec`) and *validates* them with `String::from_utf8`. The comment on `write` admits the `unwrap` could panic for a string over 2 GiB.

`cargo registry: uniffi_core-0.32.0/src/ffi_converter_impls.rs` · lines 254–287

```rust
unsafe impl<UT, T: Lower<UT>> Lower<UT> for Option<T> {
    type FfiType = RustBuffer;

    fn write(obj: Option<T>, buf: &mut Vec<u8>) {
        match obj {
            None => buf.put_i8(0),
            Some(v) => {
                buf.put_i8(1);
                T::write(v, buf);
            }
        }
    }

    fn lower(obj: Option<T>) -> RustBuffer {
        Self::lower_into_rust_buffer(obj)
    }
}

unsafe impl<UT, T: Lift<UT>> Lift<UT> for Option<T> {
    type FfiType = RustBuffer;

    fn try_read(buf: &mut &[u8]) -> Result<Option<T>> {
        check_remaining(buf, 1)?;
        Ok(match buf.get_i8() {
            0 => None,
            1 => Some(T::try_read(buf)?),
            _ => bail!("unexpected tag byte for Option"),
        })
    }

    fn try_lift(buf: RustBuffer) -> Result<Option<T>> {
        Self::try_lift_from_rust_buffer(buf)
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **`Option<T>`** cannot be one pointer, so it is always *serialized* into a `RustBuffer`: one tag byte (0 = `None`, 1 = `Some`), then `T`'s own `write` format. For `holder: Option<String>` that is tag, big-endian `i32` length, UTF-8 bytes. `impl<UT, T: Lower<UT>> Lower<UT> for Option<T>` reads "for any `T` that can be lowered, `Option<T>` can be lowered too": a generic impl with a trait bound, resolved at compile time. Any tag byte other than 0 or 1 is an error.

<details>
<summary>Deeper: FfiDefault and ForeignBytes</summary>

`cargo registry: uniffi_core-0.32.0/src/ffi/ffidefault.rs` · lines 5–54

```rust
//! FfiDefault trait
//!
//! When we make a FFI call into Rust we always need to return a value, even if that value will be
//! ignored because we're flagging an exception.  This trait defines what that value is for our
//! supported FFI types.

pub trait FfiDefault {
    fn ffi_default() -> Self;
}

// Most types can be handled by delegating to Default
macro_rules! impl_ffi_default_with_default {
    ($($T:ty,)+) => { impl_ffi_default_with_default!($($T),+); };
    ($($T:ty),*) => {
            $(
                impl FfiDefault for $T {
                    fn ffi_default() -> Self {
                        <$T>::default()
                    }
                }
            )*
    };
}

impl_ffi_default_with_default! {
    bool, i8, u8, i16, u16, i32, u32, i64, u64, f32, f64
}

// Implement FfiDefault for the remaining types
impl FfiDefault for () {
    fn ffi_default() {}
}

impl FfiDefault for crate::Handle {
    fn ffi_default() -> Self {
        Self::default()
    }
}

impl FfiDefault for *const std::ffi::c_void {
    fn ffi_default() -> Self {
        std::ptr::null()
    }
}

impl FfiDefault for crate::RustBuffer {
    fn ffi_default() -> Self {
        unsafe { Self::from_raw_parts(std::ptr::null_mut(), 0, 0) }
    }
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Result, ? and panics](01-primer.md#primer-error-handling)* A C function must return *something* even when it failed. `FfiDefault` names that placeholder: `0`, `false`, `()`, a null pointer, or an empty `RustBuffer` with a null data pointer (which `destroy_into_vec` accepts as empty). The foreign side ignores it because the status says the call failed.

`ForeignBytes` (`ffi/foreignbytes.rs`, lines 25–32) is the opposite of `RustBuffer`: a read-only view of memory the *foreign* side owns, valid only for the duration of one call, with an `i32` length "for compatibility with JNA". The generated Kotlin declares it, and its comment there says it is not used, because copying into a `RustBuffer` is just as cheap from the JVM.

</details>

## 4. Errors and panics

`cargo registry: uniffi_core-0.32.0/src/ffi/rustcalls.rs` · lines 18–53

````rust
/// Represents the success/error of a rust call
///
/// ## Usage
///
/// - The consumer code creates a [RustCallStatus] with an empty [RustBuffer] and
///   [RustCallStatusCode::Success] (0) as the status code
/// - A pointer to this object is passed to the rust FFI function.  This is an
///   "out parameter" which will be updated with any error that occurred during the function's
///   execution.
/// - After the call, if `code` is [RustCallStatusCode::Error] or [RustCallStatusCode::UnexpectedError]
///   then `error_buf` will be updated to contain a serialized error object.   See
///   [RustCallStatusCode] for what gets serialized. The consumer is responsible for freeing `error_buf`.
///
/// ## Layout/fields
///
/// The layout of this struct is important since consumers on the other side of the FFI need to
/// construct it.  If this were a C struct, it would look like:
///
/// ```c,no_run
/// struct RustCallStatus {
///     int8_t code;
///     RustBuffer error_buf;
/// };
/// ```
#[repr(C)]
pub struct RustCallStatus {
    pub code: RustCallStatusCode,
    // error_buf is owned by the foreign side.
    // - Whatever we are passed, we must never free. This however implies we must be passed
    //   an empty `RustBuffer` otherwise it would leak when we replace it with our own.
    // - On error we will set it to a `RustBuffer` we expect the foreign side to free.
    // We assume initialization, which means we can use `ManuallyDrop` instead of
    // `MaybeUninit`, which avoids unsafe code and clarifies ownership.
    // We must take care to not set this twice to avoid leaking the first `RustBuffer`.
    pub error_buf: ManuallyDrop<RustBuffer>,
}
````

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Result, ? and panics](01-primer.md#primer-error-handling)* **An out-parameter instead of exceptions.** C has no exceptions, so every scaffolding function takes a pointer to this struct. The caller initializes `code` to 0 (success) with an empty buffer. Rust overwrites it only when something went wrong.
- *[Ownership & moves](01-primer.md#primer-ownership)* The comment spells out the ownership: `error_buf` belongs to the foreign side. Rust never frees what it was given and sets it at most once, so the empty buffer it replaces cannot leak. `ManuallyDrop` here documents that this field is never dropped by Rust.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustcalls.rs` · lines 80–143

```rust
/// Result of a FFI call to a Rust function
/// Value is signed to avoid Kotlin's experimental unsigned types.
#[repr(i8)]
#[derive(Debug, PartialEq, Eq)]
pub enum RustCallStatusCode {
    /// Successful call.
    Success = 0,
    /// Expected error, corresponding to the `Result::Err` variant.  [RustCallStatus::error_buf]
    /// will contain the serialized error.
    Error = 1,
    /// Unexpected error.  [RustCallStatus::error_buf] will contain a serialized message string
    UnexpectedError = 2,
    /// Async function cancelled.  [RustCallStatus::error_buf] will be empty and does not need to
    /// be freed.
    ///
    /// This is only returned for async functions and only if the bindings code uses the
    /// [rust_future_cancel] call.
    Cancelled = 3,
}

impl TryFrom<i8> for RustCallStatusCode {
    type Error = i8;

    fn try_from(value: i8) -> Result<Self, i8> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::Error),
            2 => Ok(Self::UnexpectedError),
            3 => Ok(Self::Cancelled),
            n => Err(n),
        }
    }
}

/// Error type for Rust scaffolding calls
///
/// This enum represents the fact that there are two ways for a scaffolding call to fail:
/// - Expected errors (the Rust function returned an `Err` value).
/// - Unexpected errors (there was a failure calling the Rust function, for example the failure to
///   lift the arguments).
pub enum RustCallError {
    /// The Rust function returned an `Err` value.
    ///
    /// The associated value is the serialized `Err` value.
    Error(RustBuffer),
    /// There was a failure to call the Rust function, for example a failure to lift the arguments.
    ///
    /// The associated value is a message string for the error.
    InternalError(String),
}

/// Error when trying to lift arguments to pass to the scaffolding call
pub struct LiftArgsError {
    pub arg_name: &'static str,
    pub error: anyhow::Error,
}

impl LiftArgsError {
    pub fn to_internal_error(self) -> RustCallError {
        let LiftArgsError { arg_name, error } = self;

        RustCallError::InternalError(format!("Failed to convert arg '{arg_name}':\n{error:?}"))
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `#[repr(i8)]` gives the enum a fixed one-byte representation with the listed values: 0 success, 1 a returned `Err`, 2 an unexpected error, 3 cancelled (async only). `TryFrom<i8>` converts back, returning the unknown byte as the error. `RustCallError` is what the generated closure produces on failure: `Error(RustBuffer)` for a serialized `Err` value, `InternalError(String)` for everything else, such as the `LiftArgsError` message `"Failed to convert arg '…'"`.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustcalls.rs` · lines 145–170

```rust
/// Handle a scaffolding calls
///
/// `callback` is responsible for making the actual Rust call and returning a special result type:
///   - For successful calls, return `Ok(value)`
///   - For errors that should be translated into thrown exceptions in the foreign code, serialize
///     the error into a `RustBuffer`, then return `Ok(buf)`
///   - The success type, must implement `FfiDefault`.
///   - `Return::lower_return` returns `Result<>` types that meet the above criteria>
/// - If the function returns a `Ok` value it will be unwrapped and returned
/// - If the function returns a `Err` value:
///     - `out_status.code` will be set to [RustCallStatusCode::Error].
///     - `out_status.error_buf` will be set to a newly allocated `RustBuffer` containing the error.  The calling
///       code is responsible for freeing the `RustBuffer`
///     - `FfiDefault::ffi_default()` is returned, although foreign code should ignore this value
/// - If the function panics:
///     - `out_status.code` will be set to `CALL_PANIC`
///     - `out_status.error_buf` will be set to a newly allocated `RustBuffer` containing a
///       serialized error message.  The calling code is responsible for freeing the `RustBuffer`
///     - `FfiDefault::ffi_default()` is returned, although foreign code should ignore this value
pub fn rust_call<F, R>(out_status: &mut RustCallStatus, callback: F) -> R
where
    F: panic::UnwindSafe + FnOnce() -> Result<R, RustCallError>,
    R: FfiDefault,
{
    rust_call_with_out_status(out_status, callback).unwrap_or_else(R::ffi_default)
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `rust_call` is what every scaffolding function calls. The bounds say: the callback runs once (`FnOnce`), may be unwound through (`UnwindSafe`, a marker that the closure leaves no broken shared state behind if it panics), and returns either the value or a `RustCallError`. On failure it returns `R::ffi_default()`.

`cargo registry: uniffi_core-0.32.0/src/ffi/rustcalls.rs` · lines 194–222

```rust
/// Make a Rust call and update `RustCallStatus` based on the result.
///
/// If the call succeeds this returns Some(v) and doesn't touch out_status
/// If the call fails (including Err results), this returns None and updates out_status
///
/// This contains the shared code between `rust_call` and `rustfuture::do_wake`.
pub(crate) fn rust_call_with_out_status<F, R>(
    out_status: &mut RustCallStatus,
    callback: F,
) -> Option<R>
where
    F: panic::UnwindSafe + FnOnce() -> Result<R, RustCallError>,
{
    let result = panic::catch_unwind(callback);
    match result {
        // Happy path.  Note: no need to update out_status in this case because the calling code
        // initializes it to [RustCallStatusCode::Success]
        Ok(Ok(v)) => Some(v),
        // Callback returned an Err.
        Ok(Err(RustCallError::Error(buf))) => {
            out_status.code = RustCallStatusCode::Error;
            *out_status.error_buf = buf;
            None
        }
        Ok(Err(RustCallError::InternalError(msg))) => {
            out_status.code = RustCallStatusCode::UnexpectedError;
            *out_status.error_buf = <String as Lower<UniFfiTag>>::lower(msg);
            None
        }
```

`cargo registry: uniffi_core-0.32.0/src/ffi/rustcalls.rs` · lines 223–251

```rust
        // Callback panicked
        Err(cause) => {
            out_status.code = RustCallStatusCode::UnexpectedError;
            // Try to coerce the cause into a RustBuffer containing a String.  Since this code can
            // panic, we need to use a second catch_unwind().
            let message_result = panic::catch_unwind(panic::AssertUnwindSafe(move || {
                // The documentation suggests that it will *usually* be a str or String.
                let message = if let Some(s) = cause.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else if let Some(s) = cause.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Unknown panic!".to_string()
                };
                trace!("Caught a panic calling rust code: {:?}", message);
                <String as Lower<UniFfiTag>>::lower(message)
            }));
            if let Ok(buf) = message_result {
                // If this was ever set twice we'd leak the old value - but because this is the only
                // place where it is set, and this is only called once, no leaks should exist in practice.
                *out_status.error_buf = buf;
            }
            // Ignore the error case.  We've done all that we can at this point.  In the bindings
            // code, we handle this by checking if `error_buf` still has an empty `RustBuffer` and
            // using a generic message.
            None
        }
    }
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **`catch_unwind`** runs the closure and returns `Err(payload)` if it panics, like a `try { } catch (Throwable t)` around the call. The nested patterns `Ok(Ok(v))`, `Ok(Err(…))` and `Err(cause)` separate "returned normally", "returned an error" and "panicked".
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Result, ? and panics](01-primer.md#primer-error-handling)* A panic payload is a `Box<dyn Any + Send>`: a value of unknown type. `downcast_ref::<&'static str>()` and `downcast_ref::<String>()` try the two types `panic!` usually produces, like an `instanceof` check. The message is lowered inside a second `catch_unwind` (with `AssertUnwindSafe`, a wrapper that overrides the `UnwindSafe` check), so even a panic while formatting cannot escape across the C boundary.

`rust/Cargo.toml` · lines 76–82

```toml
# Release profile is workspace-owned (crate-level [profile.*] is ignored in a
# workspace): same tuning myotis-bls always shipped with.
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* **But in Myotis the catch never happens.** With `panic = "abort"` a panic does not unwind at all: the process is aborted on the spot, and `catch_unwind` has nothing to catch. This profile applies to every `--release` build of the workspace, which is how `cargoBuildHost` and `rust/build-android.sh` build the library the hosts load. Only an unwinding build (the default dev profile, for example a plain `cargo test`) would turn a panic into status code 2 and a Kotlin `InternalException`. That is why the `ffi.rs` module doc insists on "panic-free by construction": every failure in `host.rs` is returned as a sentinel or an `{"error": …}` JSON string, and none of the 55 exports returns a `Result`, so code 1 never occurs either.

> [!NOTE]
> **Two kinds of failure, two channels**<br>
>
> For Myotis, the UniFFI status channel is a safety net for bugs. Ordinary failures travel *inside* the JSON: `{"error": "…"}` for "could not answer" (Java raises `EngineException`), and a complete result with `failReason` set for "answered, but could not verify". UniFFI could map a Rust `Result<String, MyError>` to a typed Kotlin exception (code 1); the engine does not use that.

## 5. Build time: from the compiled library to Kotlin

So far everything happened inside `cargo build`. The Kotlin half is produced by a second program that reads the result. This is the one Rust file this stop covers.

<a id="f-uniffi-bindgen-src-main-rs"></a>

### uniffi-bindgen/src/main.rs

*binary crate · 3 lines*

The smallest crate in the workspace: a binary whose `main` runs UniFFI's bindings generator. It exists so that the generator always comes from the same `uniffi` version as the scaffolding the engine is compiled with: both are workspace members and resolve `uniffi 0.32` through the one `rust/Cargo.lock`. Gradle's `uniffiGenerateKotlin` runs it against the built host library and writes the committed Kotlin bindings into `:myotis-engine-rust`.

`rust/uniffi-bindgen/src/main.rs` · lines 1–3

```rust
fn main() {
    uniffi::uniffi_bindgen_main()
}
```

`cargo registry: uniffi-0.32.0/src/cli/mod.rs` · lines 1–20

```rust
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod swift;
mod uniffi_bindgen;

pub fn uniffi_bindgen_main() {
    if let Err(e) = uniffi_bindgen::run_main() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}

pub fn uniffi_bindgen_swift() {
    if let Err(e) = swift::run_main() {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
}
```

- *[Binaries, CLIs & signals](01-primer.md#primer-cli) · [Crates, modules & features](01-primer.md#primer-modules-cargo)* A binary crate starts at `fn main()`. The whole program is one call into the `uniffi` crate's CLI module, which parses the arguments (`generate --library … --language kotlin --out-dir …`), prints any error with `{e:?}` (the `Debug` format, which for `anyhow` errors includes the cause chain) and exits with status 1. `mod swift;` and `mod uniffi_bindgen;` declare submodules in files next to `mod.rs`. The separate Swift entry point is unused here.

`rust/uniffi-bindgen/Cargo.toml` · lines 1–26

```toml
[package]
name = "uniffi-bindgen"
version = "0.1.0"
edition = "2021"
rust-version.workspace = true
description = "Workspace-local UniFFI bindings generator CLI (cargo run -p uniffi-bindgen)"
license = "MIT OR Apache-2.0"
publish = false

# The standard UniFFI pattern: a tiny workspace-local bin wrapping the bindgen
# CLI, so binding generation is pinned to the exact uniffi version the engine
# links against (a version skew between scaffolding and generator is a build
# error by design). Regenerate the COMMITTED Kotlin bindings only through the
# root Gradle task `uniffiGenerateKotlin`: it also masks the generated u16
# checksum comparisons to 16 bits (see the task), which a direct run does not do,
# and the APK workflow's drift check fails on unmasked bindings. A direct run is
# for inspecting output:
#   cargo run -p uniffi-bindgen -- generate \
#     --library target/release/libmyotis_engine.so --language kotlin --out-dir <dir>

[[bin]]
name = "uniffi-bindgen"
path = "src/main.rs"

[dependencies]
uniffi = { version = "0.32", features = ["cli"] }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `features = ["cli"]` switches on the parts of `uniffi` that only a generator needs (argument parsing, `uniffi_bindgen` with its templates). The engine crate does not enable it, so none of that code ends up in `libmyotis_engine`. `[[bin]]` names the executable; `publish = false` keeps the tool off crates.io; `version = "0.1.0"` stays fixed because this is a tool, not a release artifact (workspace `Cargo.toml`).
- *[Protocol & domain](01-primer.md#primer-domain)* The comment's warning matters: regenerate through Gradle, because the Gradle task post-processes the output (below). A direct `cargo run -p uniffi-bindgen` is for looking at the output only.

#### Library mode: reading the metadata back out of the binary

`cargo registry: uniffi_bindgen-0.32.0/src/macro_metadata/extract.rs` · lines 18–36

```rust
/// Extract metadata written by the `uniffi::export` macro from a library file
///
/// In addition to generating the scaffolding, that macro and also encodes the
/// `uniffi_meta::Metadata` for the components which can be used to generate the bindings side of
/// the interface.
pub fn extract_from_library(path: &Utf8Path) -> anyhow::Result<Vec<Metadata>> {
    extract_from_bytes(&fs::read(path)?)
}

pub fn extract_from_bytes(file_data: &[u8]) -> anyhow::Result<Vec<Metadata>> {
    match Object::parse(file_data)? {
        Object::Elf(elf) => extract_from_elf(elf, file_data),
        Object::PE(pe) => extract_from_pe(pe, file_data),
        Object::Mach(mach) => extract_from_mach(mach, file_data),
        Object::Archive(archive) => extract_from_archive(archive, file_data),
        Object::COFF(coff) => extract_from_coff(coff, file_data),
        _ => bail!("Unknown library format"),
    }
}
```

`cargo registry: uniffi_bindgen-0.32.0/src/macro_metadata/extract.rs` · lines 279–283

```rust
pub fn is_metadata_symbol(name: &str) -> bool {
    // Skip the "_" char that Darwin prepends, if present
    let name = name.strip_prefix('_').unwrap_or(name);
    name.starts_with("UNIFFI_META")
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `--library` selects UniFFI's library mode. `extract.rs` parses the compiled file with the `goblin` crate; the `match` on `Object::parse` covers ELF (Linux, Android), Mach-O (macOS, iOS), PE (Windows), static archives and COFF. It then walks the symbol table and collects every symbol whose name starts with `UNIFFI_META` (macOS prefixes symbols with `_`, hence the `strip_prefix`). The bytes of each static are the metadata buffers from section 2. The generator never parses Rust source: what it sees is what the compiler built, so the two halves cannot disagree at generation time.

`cargo registry: uniffi_meta-0.32.0/src/reader.rs` · lines 532–536

```rust
fn calc_checksum(&self) -> Option<u16> {
    let bytes_read = self.initial_data.len() - self.buf.len();
    let metadata_buf = &self.initial_data[..bytes_read];
    Some(checksum_metadata(metadata_buf))
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `uniffi_meta`'s reader decodes each buffer into a `FnMetadata` and, at the end of every item, recomputes the checksum over exactly the bytes it consumed. That number is what the generator writes into the Kotlin as the expected value.

`cargo registry: uniffi_core-0.32.0/src/metadata.rs` · lines 268–291

```rust
// Create a checksum for a MetadataBuffer
//
// This is used by the bindings code to verify that the library they link to is the same one
// that the bindings were generated from.
pub const fn checksum_metadata(buf: &[u8]) -> u16 {
    calc_checksum(buf, buf.len())
}

const fn calc_checksum(bytes: &[u8], size: usize) -> u16 {
    // Taken from the fnv_hash() function from the FNV crate (https://github.com/servo/rust-fnv/blob/master/lib.rs).
    // fnv_hash() hasn't been released in a version yet.
    const INITIAL_STATE: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;

    let mut hash = INITIAL_STATE;
    let mut i = 0;
    while i < size {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(PRIME);
        i += 1;
    }
    // Convert the 64-bit hash to a 16-bit hash by XORing everything together
    (hash ^ (hash >> 16) ^ (hash >> 32) ^ (hash >> 48)) as u16
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **The checksum hash.** 64-bit FNV-1a (start at `0xcbf29ce484222325`; for each byte, XOR it in and multiply by `0x100000001b3` with `wrapping_mul`, which wraps on overflow instead of panicking in debug builds), folded to 16 bits by XOR-ing the four 16-bit quarters. It is a `while` loop because `for` loops over iterators are not allowed in a `const fn`. `uniffi_meta/src/metadata.rs` has a hand-kept copy of this function for the generator. A 16-bit checksum catches accidental drift, not tampering: each changed function has a 1-in-65,536 chance of going unnoticed.

![Build-time pipeline. ffi.rs is compiled by cargo build release; the macros put, per function, an extern C function, a UNIFFI_META static and a checksum function into the library. uniffi-bindgen in library mode reads the UNIFFI_META statics and recomputes the checksums, then writes myotis_engine.kt with the expected values; Gradle masks the comparisons to 16 bits. At load time the Kotlin compares the contract version and every checksum against the loaded library, then RustEngineNative compares ABI_VERSION.](img/17-uniffi-2.svg)

*The two halves meet twice: at generation time (bindgen reads the compiled library) and at load time (Kotlin compares its constants with whatever library it actually loaded). The second check is the one that matters, because the committed Kotlin can be months older than the library next to it.*

#### The Gradle task that runs it, in full

`build.gradle.kts` · lines 711–734

```kotlin
// Regenerate the UniFFI Kotlin bindings for the Rust engine into :myotis-engine-rust's
// source tree. The generated file is COMMITTED (like the Android jniLibs) so
// cargo-less machines still compile the pure-Java/Kotlin build; re-run this task
// whenever rust/myotis-engine/src/ffi.rs changes shape. Library mode: bindgen
// reads the metadata baked into the built .so, so scaffolding and bindings can
// never disagree silently (UniFFI additionally checksum-verifies at load time).
tasks.register<Exec>("uniffiGenerateKotlin") {
    group = "rust"
    description = "Regenerate the committed UniFFI Kotlin bindings in :myotis-engine-rust (self-skips without cargo)"
    onlyIf { rustAvailable }
    dependsOn(tasks.named("cargoBuildHost"))
    workingDir = file("rust")
    rustToolchainPath?.let { environment("PATH", it) }
    commandLine(
        rustTool("cargo"), "run", "--release", "-p", "uniffi-bindgen", "--",
        "generate", "--library", "$rustReleaseDir/${hostLibNames.last()}".removePrefix("rust/"),
        "--language", "kotlin", "--no-format",
        "--out-dir", project(":myotis-engine-rust").projectDir.resolve("src/main/kotlin").absolutePath,
    )
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.property("cargoVersion", cargoVersion)
    val bindingsFile = project(":myotis-engine-rust").projectDir
        .resolve("src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt")
    outputs.files(bindingsFile)
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `dependsOn(cargoBuildHost)`: the generator needs a fresh `cargo build --release` of the host library first. `hostLibNames.last()` is the engine library's file name for this OS. `cargo run --release -p uniffi-bindgen` builds and runs the three-line binary. `--no-format` skips running a Kotlin formatter over the output, which is why the generated wrappers have their odd indentation.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `onlyIf { rustAvailable }`: without cargo the task skips, and the committed file stays as it is. That is the reason the file is committed at all: a JVM-only machine compiles the Kotlin without ever running Rust. `inputs` (the Rust sources and the cargo version) and `outputs` (the `.kt` file) let Gradle skip the task when nothing changed.

`build.gradle.kts` · lines 735–763

```kotlin
    // UniFFI 0.32's Kotlin generator reads each u16 API checksum through a 32-bit
    // `Int` (JNA direct mapping) and compares it UNMASKED, so the integrity check
    // passes only while the native side happens to leave the upper 16 bits zero —
    // which the x86-64 ABIs do not promise. A debug Linux build returns 0x5DB5166E
    // for checksum 5742 (0x166E), and the Windows msi's engine failed every check,
    // so the app fell back to the Java engine (desktop-windows-msi.yml). The checksum
    // is the low 16 bits, so compare those. Applied here, at generation, because the
    // APK workflow regenerates the committed file and fails on any drift. Fail-loud:
    // a UniFFI upgrade that changes this output shape must be looked at, not skipped.
    doLast {
        val unmasked = Regex("""if \(lib\.(\w+_checksum_\w+)\(\) != (\d+)\)""")
        val text = bindingsFile.readText()
        val count = unmasked.findAll(text).count()
        val masked = unmasked.replace(text) { m ->
            "if ((lib.${m.groupValues[1]}() and 0xFFFF) != ${m.groupValues[2]})"
        }
        // Every declared checksum function must have exactly one comparison, and it
        // must now be masked: a partly changed output shape must not pass as success.
        val declared = Regex("""fun \w+_checksum_\w+\(""").findAll(masked).count()
        val leftover = Regex("""_checksum_\w+\(\)\s*!=""").findAll(masked).count()
        check(count > 0 && count == declared && leftover == 0) {
            "uniffiGenerateKotlin: $count checksum comparisons rewritten, $declared checksum " +
                "functions declared, $leftover comparisons left unmasked in $bindingsFile — " +
                "UniFFI's output changed; check whether it still reads u16 checksums as Int"
        }
        bindingsFile.writeText(masked)
        logger.lifecycle("uniffiGenerateKotlin: masked $count checksum comparisons to 16 bits")
    }
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **A fix applied after generation.** The Rust checksum functions return `u16`, but UniFFI 0.32's Kotlin template declares them as returning `Int` (a 32-bit JVM int) and compares the full value. A 16-bit return value only occupies the low half of the return register, and the x86-64 calling conventions do not promise that the upper half is zero. The comment records a debug Linux build returning `0x5DB5166E` for checksum 5742 (`0x166E`), and a Windows build that failed every check and silently fell back to the Java engine. The `doLast` block rewrites each comparison to `(… and 0xFFFF) != N` with a regex, then checks that the number of rewritten comparisons equals the number of declared checksum functions and that none is left unmasked, so a future UniFFI with a different output shape fails the task instead of passing half-fixed. The triple-quoted `"""…"""` strings are Kotlin raw strings, so the regex needs no double escaping.

## 6. The Kotlin side

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1–18

```kotlin
// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!

@file:Suppress("NAME_SHADOWING")

package uniffi.myotis_engine

// Common helper code.
//
// Ideally this would live in a separate .kt file where it can be unittested etc
// in isolation, and perhaps even published as a re-useable package.
//
// However, it's important that the details of how this helper code works (e.g. the
// way that different builtin types are passed across the FFI) exactly match what's
// expected by the Rust code on the other side of the interface. In practice right
// now that means coming from the exact some version of `uniffi` that was used to
// compile the Rust component. The easiest way to ensure this is to bundle the Kotlin
// helpers directly inline like we're doing here.
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* The generated file is 2,384 lines. Its header explains why all helper code is inline: the helpers must match the exact `uniffi` version that compiled the Rust side. Most of the file is generic support that Myotis never calls (async futures, callback interfaces, a handle map, `Disposable`). The parts this API uses are below, roughly in file order, followed by the wrapper functions.

### The buffer types

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 34–86

```kotlin
// This is a helper for safely working with byte buffers returned from the Rust code.
// A rust-owned buffer is represented by its capacity, its current length, and a
// pointer to the underlying data.

/**
 * @suppress
 */
@Structure.FieldOrder("capacity", "len", "data")
open class RustBuffer : Structure() {
    // Note: `capacity` and `len` are actually `ULong` values, but JVM only supports signed values.
    // When dealing with these fields, make sure to call `toULong()`.
    @JvmField var capacity: Long = 0
    @JvmField var len: Long = 0
    @JvmField var data: Pointer? = null

    class ByValue: RustBuffer(), Structure.ByValue
    class ByReference: RustBuffer(), Structure.ByReference

   internal fun setValue(other: RustBuffer) {
        capacity = other.capacity
        len = other.len
        data = other.data
    }

    companion object {
        internal fun alloc(size: ULong = 0UL) = uniffiRustCall() { status ->
            // Note: need to convert the size to a `Long` value to make this work with JVM.
            UniffiLib.ffi_myotis_engine_rustbuffer_alloc(size.toLong(), status)
        }.also {
            if(it.data == null) {
               throw RuntimeException("RustBuffer.alloc() returned null data pointer (size=${size})")
           }
        }

        internal fun create(capacity: ULong, len: ULong, data: Pointer?): RustBuffer.ByValue {
            var buf = RustBuffer.ByValue()
            buf.capacity = capacity.toLong()
            buf.len = len.toLong()
            buf.data = data
            return buf
        }

        internal fun free(buf: RustBuffer.ByValue) = uniffiRustCall() { status ->
            UniffiLib.ffi_myotis_engine_rustbuffer_free(buf, status)
        }
    }

    @Suppress("TooGenericExceptionThrown")
    fun asByteBuffer() =
        this.data?.getByteBuffer(0, this.len)?.also {
            it.order(ByteOrder.BIG_ENDIAN)
        }
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The same struct, seen from JNA.** A JNA `Structure` subclass describes a C struct; `@Structure.FieldOrder` fixes the field order to match Rust's `#[repr(C)]` (`capacity`, `len`, `data`). Unsigned `u64` becomes a signed `Long` because the JVM has no unsigned 64-bit type, as the comment notes. `@JvmField` makes the Kotlin properties plain Java fields, which is what JNA reads by reflection.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **`ByValue` versus a plain `Structure`.** The nested `ByValue` class tells JNA to pass and return the struct by value (copied into registers or the stack), as the Rust signatures expect for `RustBuffer`. A plain `Structure` parameter is passed as a pointer, which is how the call status travels.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* `alloc` and `free` in the `companion object` (Kotlin's place for static members) are thin calls to the two Rust functions that `setup_scaffolding!` generated, each through `uniffiRustCall`. `alloc` also refuses a null data pointer. Kotlin never frees native memory itself.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `asByteBuffer()` wraps the native memory in a direct `java.nio.ByteBuffer` of length `len`, without copying. Reads and writes through it touch Rust's memory directly. `ByteOrder.BIG_ENDIAN` matches the `bytes` crate on the Rust side.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 88–100

```kotlin
// This is a helper for safely passing byte references into the rust code.
// It's not actually used at the moment, because there aren't many things that you
// can take a direct pointer to in the JVM, and if we're going to copy something
// then we might as well copy it into a `RustBuffer`. But it's here for API
// completeness.

@Structure.FieldOrder("len", "data")
internal open class ForeignBytes : Structure() {
    @JvmField var len: Int = 0
    @JvmField var data: Pointer? = null

    class ByValue : ForeignBytes(), Structure.ByValue
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `ForeignBytes`, the Kotlin twin of the Rust struct, with the generator's own comment that it is "not actually used at the moment". Its `len` is an `Int`, matching Rust's `i32`.

### The converter interface

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 146–168

```kotlin
public interface FfiConverter<KotlinType, FfiType> {
    // Convert an FFI type to a Kotlin type
    fun lift(value: FfiType): KotlinType

    // Convert an Kotlin type to an FFI type
    fun lower(value: KotlinType): FfiType

    // Read a Kotlin type from a `ByteBuffer`
    fun read(buf: ByteBuffer): KotlinType

    // Calculate bytes to allocate when creating a `RustBuffer`
    //
    // This must return at least as many bytes as the write() function will
    // write. It can return more bytes than needed, for example when writing
    // Strings we can't know the exact bytes needed until we the UTF-8
    // encoding, so we pessimistically allocate the largest size possible (3
    // bytes per codepoint).  Allocating extra bytes is not really a big deal
    // because the `RustBuffer` is short-lived.
    fun allocationSize(value: KotlinType): ULong

    // Write a Kotlin type to a `ByteBuffer`
    fun write(value: KotlinType, buf: ByteBuffer)

```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 169–216

```kotlin
    // Lower a value into a `RustBuffer`
    //
    // This method lowers a value into a `RustBuffer` rather than the normal
    // FfiType.  It's used by the callback interface code.  Callback interface
    // returns are always serialized into a `RustBuffer` regardless of their
    // normal FFI type.
    fun lowerIntoRustBuffer(value: KotlinType): RustBuffer.ByValue {
        val rbuf = RustBuffer.alloc(allocationSize(value))
        try {
            val bbuf = rbuf.data!!.getByteBuffer(0, rbuf.capacity).also {
                it.order(ByteOrder.BIG_ENDIAN)
            }
            write(value, bbuf)
            rbuf.writeField("len", bbuf.position().toLong())
            return rbuf
        } catch (e: Throwable) {
            RustBuffer.free(rbuf)
            throw e
        }
    }

    // Lift a value from a `RustBuffer`.
    //
    // This here mostly because of the symmetry with `lowerIntoRustBuffer()`.
    // It's currently only used by the `FfiConverterRustBuffer` class below.
    fun liftFromRustBuffer(rbuf: RustBuffer.ByValue): KotlinType {
        val byteBuf = rbuf.asByteBuffer()!!
        try {
           val item = read(byteBuf)
           if (byteBuf.hasRemaining()) {
               throw RuntimeException("junk remaining in buffer after lifting, something is very wrong!!")
           }
           return item
        } finally {
            RustBuffer.free(rbuf)
        }
    }
}

/**
 * FfiConverter that uses `RustBuffer` as the FfiType
 *
 * @suppress
 */
public interface FfiConverterRustBuffer<KotlinType>: FfiConverter<KotlinType, RustBuffer.ByValue> {
    override fun lift(value: RustBuffer.ByValue) = liftFromRustBuffer(value)
    override fun lower(value: KotlinType) = lowerIntoRustBuffer(value)
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **The Kotlin mirror of Rust's `FfiConverter`.** `FfiConverter<KotlinType, FfiType>` has `lift`/`lower` for top-level values and `read`/`write` for nested ones, the same split as on the Rust side. One addition: `allocationSize`, because Kotlin must ask Rust for a buffer of a known size *before* writing into it. The comment explains the pessimistic estimate for strings (3 bytes per UTF-16 code unit).
- *[Ownership & moves](01-primer.md#primer-ownership) · [Result, ? and panics](01-primer.md#primer-error-handling)* **`lowerIntoRustBuffer`** asks Rust for `allocationSize` bytes, writes through a `ByteBuffer` view, then sets `len` to the number of bytes actually written with `writeField` (which also copies the field into the native struct). If writing throws, it frees the buffer before rethrowing. **`liftFromRustBuffer`** reads one value, insists that nothing is left over (the twin of Rust's leftover-bytes check), and frees the buffer in `finally`.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `FfiConverterRustBuffer` supplies `lift` and `lower` as default methods for every type that travels serialized, such as `String?`.

### The call status and the call helpers

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 220–262

```kotlin
internal const val UNIFFI_CALL_SUCCESS = 0.toByte()
internal const val UNIFFI_CALL_ERROR = 1.toByte()
internal const val UNIFFI_CALL_UNEXPECTED_ERROR = 2.toByte()

@Structure.FieldOrder("code", "error_buf")
internal open class UniffiRustCallStatus : Structure() {
    @JvmField var code: Byte = 0
    @JvmField var error_buf: RustBuffer.ByValue = RustBuffer.ByValue()

    class ByValue: UniffiRustCallStatus(), Structure.ByValue

    fun isSuccess(): Boolean {
        return code == UNIFFI_CALL_SUCCESS
    }

    fun isError(): Boolean {
        return code == UNIFFI_CALL_ERROR
    }

    fun isPanic(): Boolean {
        return code == UNIFFI_CALL_UNEXPECTED_ERROR
    }

    companion object {
        fun create(code: Byte, errorBuf: RustBuffer.ByValue): UniffiRustCallStatus.ByValue {
            val callStatus = UniffiRustCallStatus.ByValue()
            callStatus.code = code
            callStatus.error_buf = errorBuf
            return callStatus
        }
    }
}

class InternalException(message: String) : kotlin.Exception(message)

/**
 * Each top-level error class has a companion object that can lift the error from the call status's rust buffer
 *
 * @suppress
 */
interface UniffiRustCallStatusErrorHandler<E> {
    fun lift(error_buf: RustBuffer.ByValue): E;
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `UniffiRustCallStatus` mirrors the Rust struct: a `Byte` code and an embedded `RustBuffer.ByValue` (a struct inside a struct, not a pointer). The three constants are the Rust enum's values. It is passed as a plain `Structure`, so JNA gives Rust a pointer to native memory it manages for this object, and Rust's `&mut RustCallStatus` points there. JNA writes the Java fields into that memory before the call and reads them back after it. `InternalException` is the one exception type this API can throw.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 264–294

```kotlin
// Helpers for calling Rust
// In practice we usually need to be synchronized to call this safely, so it doesn't
// synchronize itself

// Call a rust function that returns a Result<>.  Pass in the Error class companion that corresponds to the Err
private inline fun <U, E: kotlin.Exception> uniffiRustCallWithError(errorHandler: UniffiRustCallStatusErrorHandler<E>, callback: (UniffiRustCallStatus) -> U): U {
    var status = UniffiRustCallStatus()
    val return_value = callback(status)
    uniffiCheckCallStatus(errorHandler, status)
    return return_value
}

// Check UniffiRustCallStatus and throw an error if the call wasn't successful
private fun<E: kotlin.Exception> uniffiCheckCallStatus(errorHandler: UniffiRustCallStatusErrorHandler<E>, status: UniffiRustCallStatus) {
    if (status.isSuccess()) {
        return
    } else if (status.isError()) {
        throw errorHandler.lift(status.error_buf)
    } else if (status.isPanic()) {
        // when the rust code sees a panic, it tries to construct a rustbuffer
        // with the message.  but if that code panics, then it just sends back
        // an empty buffer.
        if (status.error_buf.len > 0) {
            throw InternalException(FfiConverterString.lift(status.error_buf))
        } else {
            throw InternalException("Rust panic")
        }
    } else {
        throw InternalException("Unknown rust call status: $status.code")
    }
}
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 296–311

```kotlin
/**
 * UniffiRustCallStatusErrorHandler implementation for times when we don't expect a CALL_ERROR
 *
 * @suppress
 */
object UniffiNullRustCallStatusErrorHandler: UniffiRustCallStatusErrorHandler<InternalException> {
    override fun lift(error_buf: RustBuffer.ByValue): InternalException {
        RustBuffer.free(error_buf)
        return InternalException("Unexpected CALL_ERROR")
    }
}

// Call a rust function that returns a plain value
private inline fun <U> uniffiRustCall(callback: (UniffiRustCallStatus) -> U): U {
    return uniffiRustCallWithError(UniffiNullRustCallStatusErrorHandler, callback)
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Turning the status into exceptions.** `uniffiRustCallWithError` creates a fresh status object for every call, runs the native call (passed as a lambda that receives the status), then checks it. `inline fun` copies the function body into each caller at compile time, so the lambda costs no object allocation, a Kotlin feature with no Java equivalent.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `uniffiCheckCallStatus` maps 1 to the error handler's exception and 2 to `InternalException` carrying the lifted message (or `"Rust panic"` if Rust could not even build one). `uniffiRustCall` uses `UniffiNullRustCallStatusErrorHandler`, which frees the buffer and reports "Unexpected CALL\_ERROR", since no export returns `Result`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* The comment at the top ("we usually need to be synchronized to call this safely") is generic. Each call creates its own status object, and nothing here is shared between threads, so concurrent calls from several JVM threads are fine.

### Loading, and the integrity gate

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 386–395

```kotlin
// Contains loading, initialization code,
// and the FFI Function declarations in a com.sun.jna.Library.
@Synchronized
private fun findLibraryName(componentName: String): String {
    val libOverride = System.getProperty("uniffi.component.$componentName.libraryOverride")
    if (libOverride != null) {
        return libOverride
    }
    return "myotis_engine"
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* `findLibraryName` returns the system property `uniffi.component.myotis_engine.libraryOverride` if set, otherwise `"myotis_engine"`, which JNA maps to `libmyotis_engine.dylib`, `.so` or `myotis_engine.dll`. `RustEngineNative` sets the override for a development build (section 7).

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 653–676

```kotlin
// A JNA Library to expose the extern-C FFI definitions.
// This is an implementation detail which will be called internally by the public API.

// For large crates we prevent `MethodTooLargeException` (see #2340)
// N.B. the name of the extension is very misleading, since it is
// rather `InterfaceTooLargeException`, caused by too many methods
// in the interface for large crates.
//
// By splitting the otherwise huge interface into two parts
// * UniffiLib (this)
// * IntegrityCheckingUniffiLib
// And all checksum methods are put into `IntegrityCheckingUniffiLib`
// we allow for ~2x as many methods in the UniffiLib interface.
//
// Note: above all written when we used JNA's `loadIndirect` etc.
// We now use JNA's "direct mapping" - unclear if same considerations apply exactly.
internal object IntegrityCheckingUniffiLib {
    init {
        Native.register(IntegrityCheckingUniffiLib::class.java, findLibraryName(componentName = "myotis_engine"))
        uniffiCheckContractApiVersion(this)
        uniffiCheckApiChecksums(this)
    }
    external fun uniffi_myotis_engine_checksum_func_accept_stale_anchor(
    ): Int
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **JNA direct mapping.** `Native.register(Class, name)` loads the library and binds every `external fun` of that class to the native symbol with the same name, eagerly: a missing symbol fails here with `UnsatisfiedLinkError`, not at the first call. Kotlin's `external` is Java's `native`.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* **A Kotlin `object`'s `init`** runs in the class's static initializer, exactly once, under the JVM's class-initialization lock. If it throws, the JVM wraps the exception in `ExceptionInInitializerError`, and every later use of the class fails with `NoClassDefFoundError`. The checks are in an `init` block, so a mismatch makes the whole integrity class unusable.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* The checksum functions live in their own object, apart from `UniffiLib`. The generated comment explains the split: one interface with all methods once exceeded a JVM size limit for large crates, and it notes this reasoning predates direct mapping.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 791–799

```kotlin
internal object UniffiLib {
    

    init {
        Native.register(UniffiLib::class.java, findLibraryName(componentName = "myotis_engine"))
        
    }
    external fun uniffi_myotis_engine_fn_func_accept_stale_anchor(`handle`: Long,uniffi_out_err: UniffiRustCallStatus, 
    ): Byte
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 872–873

```kotlin
external fun uniffi_myotis_engine_fn_func_request_account_json(`handle`: Long,`address`: RustBuffer.ByValue,`block`: RustBuffer.ByValue,uniffi_out_err: UniffiRustCallStatus, 
): RustBuffer.ByValue
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 908–915

```kotlin
external fun ffi_myotis_engine_rustbuffer_alloc(`size`: Long,uniffi_out_err: UniffiRustCallStatus, 
): RustBuffer.ByValue
external fun ffi_myotis_engine_rustbuffer_from_bytes(`bytes`: ForeignBytes.ByValue,uniffi_out_err: UniffiRustCallStatus, 
): RustBuffer.ByValue
external fun ffi_myotis_engine_rustbuffer_free(`buf`: RustBuffer.ByValue,uniffi_out_err: UniffiRustCallStatus, 
): Unit
external fun ffi_myotis_engine_rustbuffer_reserve(`buf`: RustBuffer.ByValue,`additional`: Long,uniffi_out_err: UniffiRustCallStatus, 
): RustBuffer.ByValue
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The declarations JNA binds.** Compare with the Rust scaffolding: `handle: i64` is `Long`, each `RustBuffer` is `RustBuffer.ByValue`, `&mut RustCallStatus` is a plain `UniffiRustCallStatus`, and `bool` returns are `Byte`. The buffer functions follow, with `u64` sizes as `Long`. If any of these types disagreed with the Rust side, JNA would pass the wrong bits and nothing would notice except the checksums. The rest of `UniffiLib` declares the unused `rust_future_*` functions.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1016–1032

```kotlin
private fun uniffiCheckContractApiVersion(lib: IntegrityCheckingUniffiLib) {
    // Get the bindings contract version from our ComponentInterface
    val bindings_contract_version = 30
    // Get the scaffolding contract version by calling the into the dylib
    val scaffolding_contract_version = lib.ffi_myotis_engine_uniffi_contract_version()
    if (bindings_contract_version != scaffolding_contract_version) {
        throw RuntimeException("UniFFI contract version mismatch: try cleaning and rebuilding your project")
    }
}
@Suppress("UNUSED_PARAMETER")
private fun uniffiCheckApiChecksums(lib: IntegrityCheckingUniffiLib) {
    if ((lib.uniffi_myotis_engine_checksum_func_accept_stale_anchor() and 0xFFFF) != 5742) {
        throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
    }
    if ((lib.uniffi_myotis_engine_checksum_func_address_activity_json() and 0xFFFF) != 44174) {
        throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
    }
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1138–1140

```kotlin
if ((lib.uniffi_myotis_engine_checksum_func_request_account_json() and 0xFFFF) != 48343) {
    throw RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
}
```

*[Macros & attributes](01-primer.md#primer-macros) · [Protocol & domain](01-primer.md#primer-domain)* `bindings_contract_version = 30` and the 55 numbers such as `48343` are literals the generator wrote from the metadata it read. The library loaded at run time answers `ffi_myotis_engine_uniffi_contract_version()` and `uniffi_myotis_engine_checksum_func_request_account_json()`. If either disagrees, the library was compiled from different source (or a different UniFFI) than the bindings, and the code refuses to continue. Note the `and 0xFFFF` from the Gradle post-processing, and the unhelpful message "try cleaning and rebuilding your project": in Myotis the fix is usually `./gradlew uniffiGenerateKotlin` or a rebuilt library.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1194–1202

```kotlin
/**
 * @suppress
 */
public fun uniffiEnsureInitialized() {
    IntegrityCheckingUniffiLib
    // UniffiLib() initialized as objects are used, but we still need to explicitly
    // reference it so initialization across crates works as expected.
    UniffiLib
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The checks only run if someone asks.** Mentioning an `object` forces its initialization. A plain call like `requestAccountJson` touches only `UniffiLib`, which registers its functions *without* the checksum checks. So a host must call `uniffiEnsureInitialized()` before anything else, which is the first thing `RustEngineNative` does.

### The type converters

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1308–1329

```kotlin
/**
 * @suppress
 */
public object FfiConverterLong: FfiConverter<Long, Long> {
    override fun lift(value: Long): Long {
        return value
    }

    override fun read(buf: ByteBuffer): Long {
        return buf.getLong()
    }

    override fun lower(value: Long): Long {
        return value
    }

    override fun allocationSize(value: Long) = 8UL

    override fun write(value: Long, buf: ByteBuffer) {
        buf.putLong(value)
    }
}
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1334–1352

```kotlin
public object FfiConverterBoolean: FfiConverter<Boolean, Byte> {
    override fun lift(value: Byte): Boolean {
        return value.toInt() != 0
    }

    override fun read(buf: ByteBuffer): Boolean {
        return lift(buf.get())
    }

    override fun lower(value: Boolean): Byte {
        return if (value) 1.toByte() else 0.toByte()
    }

    override fun allocationSize(value: Boolean) = 1UL

    override fun write(value: Boolean, buf: ByteBuffer) {
        buf.put(lower(value))
    }
}
```

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `FfiConverterLong` is the identity, like Rust's numeric impl, with 8-byte `getLong`/`putLong` for nested use. `FfiConverterBoolean` lowers to 1 or 0, but lifts *any* non-zero byte as `true`: more lenient than Rust's lift, which refuses anything but 0 and 1. That is harmless here, since Rust only ever sends 0 or 1.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1357–1409

```kotlin
public object FfiConverterString: FfiConverter<String, RustBuffer.ByValue> {
    // Note: we don't inherit from FfiConverterRustBuffer, because we use a
    // special encoding when lowering/lifting.  We can use `RustBuffer.len` to
    // store our length and avoid writing it out to the buffer.
    override fun lift(value: RustBuffer.ByValue): String {
        try {
            val byteArr = ByteArray(value.len.toInt())
            value.asByteBuffer()!!.get(byteArr)
            return byteArr.toString(Charsets.UTF_8)
        } finally {
            RustBuffer.free(value)
        }
    }

    override fun read(buf: ByteBuffer): String {
        val len = buf.getInt()
        val byteArr = ByteArray(len)
        buf.get(byteArr)
        return byteArr.toString(Charsets.UTF_8)
    }

    fun toUtf8(value: String): ByteBuffer {
        // Make sure we don't have invalid UTF-16, check for lone surrogates.
        return Charsets.UTF_8.newEncoder().run {
            onMalformedInput(CodingErrorAction.REPORT)
            encode(CharBuffer.wrap(value))
        }
    }

    override fun lower(value: String): RustBuffer.ByValue {
        val byteBuf = toUtf8(value)
        // Ideally we'd pass these bytes to `ffi_bytebuffer_from_bytes`, but doing so would require us
        // to copy them into a JNA `Memory`. So we might as well directly copy them into a `RustBuffer`.
        val rbuf = RustBuffer.alloc(byteBuf.limit().toULong())
        rbuf.asByteBuffer()!!.put(byteBuf)
        return rbuf
    }

    // We aren't sure exactly how many bytes our string will be once it's UTF-8
    // encoded.  Allocate 3 bytes per UTF-16 code unit which will always be
    // enough.
    override fun allocationSize(value: String): ULong {
        val sizeForLength = 4UL
        val sizeForString = value.length.toULong() * 3UL
        return sizeForLength + sizeForString
    }

    override fun write(value: String, buf: ByteBuffer) {
        val byteBuf = toUtf8(value)
        buf.putInt(byteBuf.limit())
        buf.put(byteBuf)
    }
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Ownership & moves](01-primer.md#primer-ownership)* **`lift`, Rust → Kotlin.** It copies `len` bytes out of native memory into a JVM `ByteArray`, decodes them, and in `finally` calls `RustBuffer.free`, a native call back into Rust that rebuilds and drops the `Vec`. After that line no Rust memory is referenced from Kotlin, and the `finally` frees the buffer even if decoding throws.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Ownership & moves](01-primer.md#primer-ownership)* **`lower`, Kotlin → Rust.** `toUtf8` encodes the UTF-16 Kotlin string into UTF-8 with `CodingErrorAction.REPORT`, so a lone surrogate throws `MalformedInputException` instead of being replaced. This is what makes Rust's unchecked lift sound. Then `RustBuffer.alloc` makes a native call into Rust for memory of exactly that size, and `put` copies the bytes into it. One string argument costs one extra native round trip.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Top-level versus nested**, as in Rust: `lift`/`lower` use the buffer's own length, while `read`/`write` use an `Int` length prefix. The comment at the top says so: `FfiConverterString` deliberately does not extend `FfiConverterRustBuffer`.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1414–1441

```kotlin
/**
 * @suppress
 */
public object FfiConverterOptionalString: FfiConverterRustBuffer<kotlin.String?> {
    override fun read(buf: ByteBuffer): kotlin.String? {
        if (buf.get().toInt() == 0) {
            return null
        }
        return FfiConverterString.read(buf)
    }

    override fun allocationSize(value: kotlin.String?): ULong {
        if (value == null) {
            return 1UL
        } else {
            return 1UL + FfiConverterString.allocationSize(value)
        }
    }

    override fun write(value: kotlin.String?, buf: ByteBuffer) {
        if (value == null) {
            buf.put(0)
        } else {
            buf.put(1)
            FfiConverterString.write(value, buf)
        }
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `String?` uses the serialized path: `FfiConverterRustBuffer`'s default `lower` calls `lowerIntoRustBuffer`, which allocates `allocationSize` bytes (1 for the tag, plus 4 + 3 per code unit for a string), writes tag 0, or tag 1 and the prefixed string, then sets `len`. The buffer's capacity is usually larger than its length, which is why `RustBuffer` carries both: Rust must free the whole capacity.

### The public wrapper functions

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 2089–2107

```kotlin
        /**
         * Verified account query (`AccountProofResult` shape). `address` is 0x-hex;
         * `block` is the RPC block selector (ABI ≥ 32): empty or a head tag proves at
         * the verified head, `finalized` at the beacon-finalized block, a number only
         * inside the window around the head — refused (`{"error","code":-32602}`)
         * otherwise, never answered from the head. The result names the anchor
         * (`anchor`).
         */ fun `requestAccountJson`(`handle`: kotlin.Long, `address`: kotlin.String, `block`: kotlin.String): kotlin.String {
            return FfiConverterString.lift(
    uniffiRustCall() { _status ->
    UniffiLib.uniffi_myotis_engine_fn_func_request_account_json(
    
        
        FfiConverterLong.lower(`handle`),
        FfiConverterString.lower(`address`),
        FfiConverterString.lower(`block`),_status)
}
    )
    }
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Read it inside out.** Each argument is lowered (`FfiConverterLong.lower` returns the `Long` unchanged; `FfiConverterString.lower` allocates and fills a `RustBuffer`). `uniffiRustCall { _status -> … }` creates a fresh status object and passes it as the last argument. `UniffiLib.uniffi_myotis_engine_fn_func_request_account_json` is the JNA-bound native function. Its `RustBuffer.ByValue` result goes to `FfiConverterString.lift`.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A top-level function.** Kotlin functions outside a class compile into a JVM class named after the file, here `Myotis_engineKt`, as static methods. That is why the Java caller writes `Myotis_engineKt.requestAccountJson(…)`. Names are converted from `snake_case` to `camelCase`, the backticks around every name protect against Kotlin keywords, and the Rust doc comment became KDoc.

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 1945–1960

```kotlin
        /**
         * Verified storage-slot query (`StorageProofResult` shape). A non-None `holder`
         * selects the ERC-20 mapping key `keccak256(pad32(holder) ‖ uint256(slot))`.
         */ fun `getStorageProofJson`(`handle`: kotlin.Long, `address`: kotlin.String, `slot`: kotlin.Long, `holder`: kotlin.String?): kotlin.String {
            return FfiConverterString.lift(
    uniffiRustCall() { _status ->
    UniffiLib.uniffi_myotis_engine_fn_func_get_storage_proof_json(
    
        
        FfiConverterLong.lower(`handle`),
        FfiConverterString.lower(`address`),
        FfiConverterLong.lower(`slot`),
        FfiConverterOptionalString.lower(`holder`),_status)
}
    )
    }
```

`myotis-engine-rust/src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt` · lines 2357–2366

```kotlin
        /**
         * Remove and shut down a handle's sync loop. No-op for an unknown id.
         */ fun `stopHandle`(`handle`: kotlin.Long)
        = 
    uniffiRustCall() { _status ->
    UniffiLib.uniffi_myotis_engine_fn_func_stop_handle(
    
        
        FfiConverterLong.lower(`handle`),_status)
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* Two variations. `getStorageProofJson` lowers its `String?` through `FfiConverterOptionalString`. `stopHandle`, whose Rust function returns `()`, has no lift at all: its body is the `uniffiRustCall` expression, which returns `Unit`.

<details>
<summary>Deeper: two small flaws in the generated code</summary>

**A leak on a failed lowering.** In `requestAccountJson`, the arguments are lowered left to right inside the call expression. If lowering `block` throws (a malformed string), the `RustBuffer` already allocated for `address` is never passed to Rust and never freed: a small native leak per failed call. As far as I can read the code, nothing in the generated file guards against this. In Myotis it cannot happen through `RustEngineNative`, which replaces every malformed string with `""` before the call (section 7).

**A message template.** Line 292 builds `"Unknown rust call status: $status.code"`. A Kotlin string template `$status` ends at the identifier, so this prints the whole status object followed by the literal text `.code`; `${status.code}` was meant. It only matters for a status code Rust never sends.

</details>

## 7. The Java callers

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustEngineNative.java` · lines 8–48

```java
/**
 * The FFI boundary to {@code libmyotis_engine} ({@code rust/myotis-engine}), since the
 * UniFFI migration a thin STATIC DELEGATOR over the generated Kotlin bindings
 * ({@code uniffi.myotis_engine} — committed at src/main/kotlin, regenerated via the
 * root {@code uniffiGenerateKotlin} task). Compound values still cross as JSON strings
 * (transport swap only — the hand-JNI is gone but the shapes are unchanged and stay
 * pinned by the golden tests on both sides).
 *
 * <p>Availability = the bindings initialized (UniFFI verifies a per-function API
 * checksum against the loaded library — the stale-.so guard is now structural) AND
 * {@link #nativeInit()} returned the coarse ABI version this class was compiled
 * against (kept as a belt-and-braces check + the log line).
 *
 * <p>Load order: an explicit absolute path in {@code -Dmyotis.engine.lib=...} (how the
 * desktop `run` task injects the dev build) is forwarded to the bindings via UniFFI's
 * {@code uniffi.component.myotis_engine.libraryOverride} property; otherwise JNA
 * resolves {@code myotis_engine} from {@code jna.library.path} + system paths — it
 * does NOT consult {@code java.library.path}, so {@link #load()} mirrors that
 * property into {@code jna.library.path} when the latter is unset (the daemon's run
 * task and the module's tests point java.library.path at the cargo build dir). A
 * host that sets {@code jna.library.path} itself owns the full search path. On
 * Android JNA resolves the bundled jniLibs on its own.
 *
 * <p>Every method keeps the old hand-JNI null tolerance: null String arguments are
 * normalized to {@code ""} (the Rust side used {@code unwrap_or_default}) — except
 * the genuinely optional {@code holderOrNull}, which maps to Kotlin's {@code String?}.
 */
final class RustEngineNative {

    private static final Logger log = LoggerFactory.getLogger(RustEngineNative.class);

    /** Must match {@code ABI_VERSION} in rust/myotis-engine/src/lib.rs. */
    static final int EXPECTED_ABI_VERSION = 55; // 55: simulate_v1_json (#716); 54: debug_trace_call_json (#716); 53: get_raw_transaction_by_hash_json + get_raw_transaction_by_block_json (#715); 52: account and call JSON carry the proven blockHash; 51: set_activity_watch + address_activity_json (#691); 50: dataUsage + networkMetering in the status, set_network_metering; 49: ens offchain envelope carries reverseClaim; 48: log-index topic entries (#673); 47: resolve_block_hash_json, get_proof_json takes a block hash; 46: get_proof_json; 45: check_raw_transaction_json; 44: send_raw_transaction_json refuses non-transactions (-32602)

    private static final boolean AVAILABLE = load();

    private RustEngineNative() {}

    static boolean isAvailable() {
        return AVAILABLE;
    }
```

- *[Protocol & domain](01-primer.md#primer-domain)* **A static delegator.** The class doc summarizes this stop from the Java side: compound values are still JSON, availability means "the bindings initialized and the ABI handshake matched", and every string argument keeps the old hand-JNI null tolerance. `EXPECTED_ABI_VERSION` is a hand-kept copy of the Rust constant; the trailing comment is its changelog.
- *[Threads, Send & Sync](01-primer.md#primer-concurrency)* `private static final boolean AVAILABLE = load();` runs `load()` once, in the class's static initializer, under the JVM's class-initialization lock: the Java equivalent of a lazily initialized `static` in Rust.

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustEngineNative.java` · lines 50–104

```java
private static boolean load() {
    String explicit = System.getProperty("myotis.engine.lib");
    if (explicit != null && !explicit.isBlank()) {
        // Forward the dev-build path to the generated bindings' loader. Set-if-absent
        // so an explicitly configured override always wins.
        if (System.getProperty("uniffi.component.myotis_engine.libraryOverride") == null) {
            System.setProperty("uniffi.component.myotis_engine.libraryOverride", explicit);
        }
    } else if (System.getProperty("jna.library.path") == null) {
        // JNA searches jna.library.path (plus system paths), NOT java.library.path —
        // which is where the daemon's run task and :myotis-engine-rust's test task put the
        // cargo build dir. Mirror it so the pre-UniFFI lookup contract keeps holding.
        // (Android ignores this: JNA resolves bundled jniLibs on its own.)
        String jlp = System.getProperty("java.library.path");
        if (jlp != null && !jlp.isBlank()) {
            System.setProperty("jna.library.path", jlp);
        }
    }
    try {
        // Run UniFFI's integrity gate FIRST: uniffiEnsureInitialized() loads the
        // library and validates the bindings-contract version plus a per-function
        // API checksum against the loaded .so. It must be called explicitly —
        // plain binding calls like engineInit() register the functions WITHOUT
        // checksum validation, so skipping this line would let a reshaped symbol
        // segfault at first use instead of failing loudly here.
        Myotis_engineKt.uniffiEnsureInitialized();
        int abi = Myotis_engineKt.engineInit();
        if (abi != EXPECTED_ABI_VERSION) {
            log.warn("[engines] libmyotis_engine ABI {} != expected {} (stale library?); "
                    + "Rust engine unavailable", abi, EXPECTED_ABI_VERSION);
            return false;
        }
    } catch (UnsatisfiedLinkError e) {
        // The normal cargo-less case: no library on the search path (or one so old
        // it predates UniFFI and lacks the uniffi_* symbols entirely).
        log.info("[engines] libmyotis_engine not loaded ({}); Rust engine unavailable",
                e.toString());
        return false;
    } catch (Throwable t) {
        // Library FOUND but failed UniFFI's contract/checksum validation (stale or
        // reshaped .so) — louder than the missing-library case on purpose. The
        // bindings run those checks in a static initializer, so what arrives here is
        // usually an ExceptionInInitializerError that says nothing by itself: name its
        // cause, and log the trace (the trailing throwable) for anything else.
        Throwable reason = t instanceof ExceptionInInitializerError && t.getCause() != null
                ? t.getCause() : t;
        log.warn("[engines] libmyotis_engine failed UniFFI validation ({}); "
                + "Rust engine unavailable — rebuild the library (cargoBuildHost / "
                + "cargoNdkAndroid) or regenerate the bindings (uniffiGenerateKotlin)",
                reason.toString(), t);
        return false;
    }
    log.info("[engines] libmyotis_engine loaded via UniFFI (ABI {})", EXPECTED_ABI_VERSION);
    return true;
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Finding the library** (lines 51–67). An explicit `-Dmyotis.engine.lib` path is forwarded to UniFFI's `libraryOverride` property. Otherwise `java.library.path`, where the run and test tasks put `rust/target/release`, is copied into `jna.library.path`, because JNA only reads the latter.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Three outcomes, all non-fatal.** No library on the search path gives `UnsatisfiedLinkError`, logged at info level: the normal case on a machine without cargo. A library that fails the contract or checksum check arrives as `ExceptionInInitializerError`, so the code unwraps its cause for the warning. A library that passes but reports a different `ABI_VERSION` is also refused. In every case `isAvailable()` returns `false`, and the `:myotis-engines` selector serves the Java engine instead (the comment in `AbiVersionMirrorTest`, section 10, describes this fallback). `engineInit()` also installs the ring-buffer log subscriber (`ffi.rs` lines 23–31), so the handshake is the first real call into the engine.

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustEngineNative.java` · lines 106–133

```java
private static String nz(String s) {
    return s == null || !wellFormed(s) ? "" : s;
}

/** The old hand-JNI surface degraded malformed UTF-16 (unpaired surrogates —
 *  attacker-reachable via JSON-RPC string params) to an absent/empty string on
 *  the Rust side (CESU-8 decode failure → {@code unwrap_or_default}). The
 *  generated bindings instead throw {@code MalformedInputException} from their
 *  UTF-8 lowering; probe first so the pre-UniFFI semantics keep holding.
 *
 *  <p>Hand-rolled surrogate-pairing scan rather than {@code CharsetEncoder.canEncode}:
 *  this runs on every FFI string argument, and the encoder probe allocates per call.
 *  The O(n) walk itself is inherent to validating (the bindings' UTF-8 lowering
 *  re-scans the same chars right after). */
private static boolean wellFormed(String s) {
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) {
            if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) {
                return false;
            }
            i++; // consume the low half of a well-formed pair
        } else if (Character.isLowSurrogate(c)) {
            return false; // low surrogate with no preceding high
        }
    }
    return true;
}
```

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Keeping the generated encoder from throwing.** `nz()` turns `null`, and any string with an unpaired surrogate (which a JSON-RPC client can send), into `""`. Without it, `FfiConverterString.lower` would throw `MalformedInputException`. The old hand-JNI layer behaved like `nz()`, and the delegator keeps that behavior. `wellFormed` is a hand-written scan instead of an encoder probe because it runs on every argument; the comment counts the cost.

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustEngineNative.java` · lines 285–299

```java
/** Verified account query as JSON (AccountProofResult shape / {@code error} object);
 *  {@code block} is the RPC block selector the engine applies or refuses (ABI >= 32:
 *  the contract is {@code myotis_engine.h}'s). */
static String nativeRequestAccountJson(long handle, String address, String block) {
    return Myotis_engineKt.requestAccountJson(handle, nz(address), nz(block));
}

/** Verified storage-slot query as JSON; non-null {@code holderOrNull} selects the
 *  ERC-20 mapping key {@code keccak256(pad32(holder) ‖ uint256(slot))}. */
static String nativeGetStorageProofJson(
        long handle, String address, long slot, String holderOrNull) {
    // Malformed holder → null, matching the old shim (decode failure → None).
    String holder = (holderOrNull != null && wellFormed(holderOrNull)) ? holderOrNull : null;
    return Myotis_engineKt.getStorageProofJson(handle, nz(address), slot, holder);
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* The two delegators this stop follows. For the optional `holder`, a malformed string becomes `null` rather than `""`, matching what the old shim did (a decode failure was `None`). Java's `null` reaches Kotlin as a `String?` that is `null`, which lowers to tag byte 0.

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustChainHandle.java` · lines 323–339

```java
/**
 * The wake-on-request choke point every verified read crosses before its JNI
 * call (the Rust-engine twin of ChainStack.awaitReadyForReads + the
 * begin/endRequest in-flight guard): stamps activity, wakes a paused stack,
 * holds (bounded) while the stack is waking — paused, or in a start/resume
 * warm-up — and marks the request in flight so the host idle timer can't pause
 * the stack mid-query.
 */
private <T> T gated(java.util.function.Supplier<T> nativeCall) {
    awaitWake();
    inFlight.incrementAndGet();
    try {
        return nativeCall.get();
    } finally {
        inFlight.decrementAndGet();
    }
}
```

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustChainHandle.java` · lines 869–912

```java
@Override
public AccountProofResult requestAccount(String hexAddress) {
    return accountVerified(hexAddress, "");
}

/** Package-private test seam: JSON → {@link AccountProofResult} without JNI. */
static AccountProofResult accountFromJson(String hexAddress, String json) {
    return accountFromJson(hexAddress, parseResultOrThrow(json, "account"));
}

private static AccountProofResult accountFromJson(String hexAddress, JsonObject o) {
    try {
    return new AccountProofResult(
            o.getString("address", hexAddress),
            o.getBoolean("exists", false),
            o.getLong("nonce", -1L),
            stringOrNull(o, "balanceWei"),
            stringOrNull(o, "storageRootHex"),
            stringOrNull(o, "codeHashHex"),
            o.getLong("blockNumber", 0L),
            stringOrNull(o, "peerStateRootHex"),
            o.getBoolean("peerProofValid", false),
            o.getBoolean("beaconChainVerified", false),
            o.getBoolean("blsVerified", false),
            o.getLong("matchedBeaconSlot", -1L),
            stringOrNull(o, "verifyMethod"),
            stringOrNull(o, "failReason"),
            stringOrNull(o, "accountHashHex"),
            stringList(o, "proofNodesHex"),
            o.getBoolean("beaconSynced", false),
            o.getLong("finalizedPeriod", 0L),
            o.getLong("wallClockPeriod", 0L),
            o.getLong("finalizedBlockNumber", 0L),
            o.getLong("optimisticBlockNumber", 0L),
            // ABI >= 41: the proven block timestamp, null when none is proven.
            longOrMinusOne(o, "blockTimestamp"),
            // ABI >= 52: the proven block hash, null when none is proven.
            stringOrNull(o, "blockHash"));
    } catch (RuntimeException e) {
        // A type-mismatched field (Rust-side shape drift) surfaces as an
        // EngineException, never a raw UnsupportedOperationException.
        throw new EngineException("malformed account JSON from the Rust engine: " + e.getMessage(), e);
    }
}
```

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustChainHandle.java` · lines 938–943

```java
AccountProofResult accountVerified(String hexAddress, String block) {
    JsonObject o = parseResultOrThrow(
            gated(() -> RustEngineNative.nativeRequestAccountJson(handle, hexAddress, block)),
            "account");
    return accountFromJson(hexAddress, o);
}
```

- *[Threads, Send & Sync](01-primer.md#primer-concurrency) · [Protocol & domain](01-primer.md#primer-domain)* **`gated(…)`** wakes a paused chain, waits (bounded) while it warms up, and counts the call as in flight so the idle timer cannot pause the chain mid-read. `Supplier<T>` defers the native call until the gate opens.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* **Where the boundary is type-checked.** `accountFromJson` fills the 23-argument `io.myotis.api` record `AccountProofResult` field by field, with defaults for missing keys, and turns a type mismatch into an `EngineException`. Field names and types are checked here, at run time, in Java, not by any compiler. The `// ABI >= 41` and `// ABI >= 52` comments mark keys added as payload extensions.

`myotis-engine-rust/src/main/java/io/myotis/engines/rust/RustChainHandle.java` · lines 1852–1888

```java
/**
 * Parse a native verified-read payload. A {@code {"error": "..."}} object (a
 * transport / not-running / bad-input failure) becomes an {@link EngineException};
 * a null/blank/malformed payload likewise. A verification FAILURE is NOT an error —
 * it is a full result whose {@code failReason} is set, and is returned normally.
 */
private static JsonObject parseResultOrThrow(String json, String what) {
    JsonObject o = parseJsonObject(json, what);
    throwIfError(o);
    return o;
}

/** The first half of {@link #parseResultOrThrow}: a null/blank/malformed
 *  payload throws, an error envelope is returned like any other object. */
private static JsonObject parseJsonObject(String json, String what) {
    if (json == null || json.isBlank()) {
        throw new EngineException((json == null ? "null" : "blank") + " " + what
                + " JSON from the Rust engine (native failure?)");
    }
    try {
        return Json.parse(json).asObject();
    } catch (RuntimeException e) {
        throw new EngineException(
                "malformed " + what + " JSON from the Rust engine: " + e.getMessage(), e);
    }
}

/** The second half of {@link #parseResultOrThrow}: an {@code {"error": ...}}
 *  envelope becomes an {@link EngineException} carrying its message. */
private static void throwIfError(JsonObject o) {
    var error = o.get("error");
    if (error != null && !error.isNull()) {
        // The Rust side always emits a string error, but tolerate a
        // structured value rather than throwing a raw library exception.
        throw new EngineException(error.isString() ? error.asString() : error.toString());
    }
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling)* `parseResultOrThrow` in two halves: parse with minimal-json (a null, blank or malformed string throws), then turn `{"error": …}` into `EngineException`. A verification failure is *not* an error here: it is a normal result with `failReason` set.

## 8. How the library reaches the JVM and Android

JNA has to find a file called `libmyotis_engine.*` at run time. There are three situations.

- **Development (daemon, desktop app, tests).** `cargoBuildHost` writes the library to `rust/target/release/`, and `RustEngineNative.load()` bridges `java.library.path` to `jna.library.path`, as shown above.
- **A desktop consumer of the engine library.** The jar does not contain the native library; a separate artifact carries it, as the consumer documentation explains:

`docs/android-library.md` · lines 196–223

````text
`eth.myotis:myotis-engine-jvm` is the same entry point for a JVM host. The jar
does not contain the host library, which is built per OS and architecture;
`eth.myotis:myotis-engine-natives-<platform>` carries it, one artifact per
platform in `myotis-engine-natives/platforms.txt`. Put the one for the host on
the runtime classpath, at the same version as the engine:

```kotlin
dependencies {
    implementation("eth.myotis:myotis-engine:0.1.16")
    runtimeOnly("eth.myotis:myotis-engine-natives-darwin-aarch64:0.1.16") // the host's platform
}
```

JNA then loads `libmyotis_engine` from the jar's `<platform>/` entry (it
extracts it to a temporary file first) whenever `jna.library.path` has none,
so nothing has to be set; a library found on that path, or named by
`-Dmyotis.engine.lib=<file>`, still wins, which is how a development build is
tried. Keep both artifacts on one version (one catalog entry): a library whose FFI
differs from the bindings is refused at load (the ABI version and UniFFI's
checksums), and `Myotis.isAvailable()` says false, but a library from another
release with the same FFI loads and runs that release's engine, its checkpoints
and bootnodes included, with nothing to say so. The artifacts are
built on one runner per platform from the tag's tree: macOS 15 for both Mac
architectures, Ubuntu 22.04 for Linux (so glibc 2.35 or newer). A signed and
notarized macOS app with the hardened runtime may refuse a library extracted
at run time; such an app ships the library inside its bundle, signed with it,
as the Myotis desktop app does (`appResources`), and points
`jna.library.path` there. Windows has no artifact yet.
````

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* The natives jar puts `<platform>/libmyotis_engine.*` on the classpath, where JNA finds it, extracts it to a temporary file and loads it. Note the warning in the middle: a library from another release with the *same* FFI passes every check, because the checks compare shapes, not versions.

- **Android.** The `.so` files are packed into the AAR and from there into the APK, where the system's dynamic linker finds them by name. In `RustEngineNative`'s words, "On Android JNA resolves the bundled jniLibs on its own."

### Building the Android libraries

`build.gradle.kts` · lines 923–956

```kotlin
tasks.register<Exec>("cargoNdkAndroid") {
    group = "rust"
    description = "Cross-compile the Android jniLibs (the Rust engine + native BLS) from source via rust/build-android.sh; skipped by -PskipRustEngine"
    onlyIf { androidRustToolchainReady && !skipRustEngine }
    workingDir = file("rust")
    rustToolchainPath?.let { environment("PATH", it) }
    androidNdkDir?.let { environment("ANDROID_NDK_HOME", it.absolutePath) }
    // -PtorEngine links Arti into the Android engine too (build-android.sh reads
    // the variable; docs/privacy-and-tor.md). Set either way, so a value
    // inherited from the developer's shell cannot flip the build behind the flag.
    environment("MYOTIS_TOR_ENGINE", if (torEngine) "1" else "0")
    // Windows can't exec a .sh directly (CreateProcess error=193); route it
    // through bash there (Git for Windows ships one alongside git itself).
    if (isWindowsHost) {
        commandLine("bash", "./build-android.sh")
    } else {
        commandLine("./build-android.sh")
    }
    inputs.files(rustSources).withPathSensitivity(PathSensitivity.RELATIVE)
    // Toolchain identity as inputs: switching rustc, cargo-ndk, or the NDK must
    // re-run the build AND its 16 KB alignment check — that check exists to
    // catch exactly these toolchain swaps.
    inputs.property("cargoVersion", cargoVersion)
    inputs.property("cargoNdkVersion", cargoNdkVersion)
    inputs.property("ndkDir", androidNdkDir?.absolutePath ?: "")
    // The Tor feature flips the libs' contents, so it must key UP-TO-DATE too.
    inputs.property("torEngine", torEngine)
    outputs.files(
        file("myotis-engine/src/androidMain/jniLibs/arm64-v8a/libmyotis_bls.so"),
        file("myotis-engine/src/androidMain/jniLibs/x86_64/libmyotis_bls.so"),
        file("myotis-engine/src/androidMain/jniLibs/arm64-v8a/libmyotis_engine.so"),
        file("myotis-engine/src/androidMain/jniLibs/x86_64/libmyotis_engine.so"),
    )
}
```

`rust/build-android.sh` · line 50

```text
cargo ndk -t arm64-v8a -t x86_64 -o "$jniLibs" build --release -p myotis-bls -p myotis-engine $tor_features
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* `cargoNdkAndroid` runs `rust/build-android.sh` when the Android toolchain is present and `-PskipRustEngine` is not set. Its inputs include the cargo, cargo-ndk and NDK versions, so a toolchain change rebuilds. `cargo ndk` cross-compiles the engine (and the BLS library) with the NDK's linker for two ABIs and writes `<abi>/libmyotis_engine.so` into `myotis-engine/src/androidMain/jniLibs`, the layout Android's Gradle plugin expects. Nothing there is committed. The script then deletes any other `.so` it produced and checks that every library is 16 KB aligned.

`myotis-engine/build.gradle.kts` · lines 109–123

```kotlin
    sourceSets.getByName("main") {
        // cargoNdkAndroid's output: <abi>/libmyotis_engine.so + libmyotis_bls.so.
        // -PskipRustEngine means "no Rust engine in this AAR": the directory is then
        // NOT a source at all. The libs live in the source tree, outside build/, so
        // a lib left there by an earlier toolchain build is not removed by `clean`,
        // by .gitignore, or by cargoNdkAndroid being skipped — AGP would happily
        // package it, and on-device it would fail UniFFI validation (bindings vs a
        // stale .so) and silently fall back to Java. Gating the SOURCE (rather than
        // a packaging exclude) keeps a leftover out of every consumer's merge — the
        // bundled AAR and a project dependency alike, which AGP feeds from this
        // module's intermediate JNI artifact, not from the AAR. The app adds its
        // own exclude on the same flag as a second line, at the APK merge.
        if (!skipRustEngine) jniLibs.srcDir("src/androidMain/jniLibs")
    }
}
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* The jniLibs directory is a source of the AAR only when the Rust engine is wanted. The comment explains why the gate is on the source rather than a packaging filter: a leftover `.so` from an earlier build would otherwise ship, fail UniFFI validation on the device, and silently fall back to the Java engine.

### JNA's own native half

`myotis-engine/build.gradle.kts` · lines 146–181

```kotlin
// === JNA's Android dispatcher, inside the AAR ==================================
// The engine's UniFFI bindings load through JNA. com.sun.jna.* comes from the
// plain jna JAR (:myotis-engine-rust's dependency, so every consumer has it), but
// that jar carries desktop natives only (win32/darwin/linux/aix) —
// jni/<abi>/libjnidispatch.so, without which JNA cannot dispatch at all, ships
// exclusively in jna-<v>.aar. Take ONLY the natives from the aar, into this
// module's jniLibs, so the AAR a consumer gets is complete on its own: no
// consumer has to know about the aar, and none can hit the duplicate-class
// failure of putting it on a classpath next to the jar. A detached,
// non-consumable configuration keeps the aar off every classpath.
//
// The classpath jar and the extracted natives MUST be the same version: JNA's
// Native.<clinit> compares its own version against the native library's and
// throws on a major/minor mismatch. Both come from the one catalog entry, and the
// jar side is pinned by a STRICT constraint that lands in the published POM, so a
// consumer whose graph wants another jna (a BOM, another library) gets a
// resolution error at build time instead of an engine that cannot load on every
// device. (The Myotis app additionally forces the same value against Besu's BOM.)
val jnaVersion = libs.versions.jna.get()
dependencies {
    constraints {
        "jvmSharedMainApi"("net.java.dev.jna:jna") {
            version { strictly(jnaVersion) }
            because("libjnidispatch.so inside the AAR is jna $jnaVersion; JNA refuses a mismatched jar")
        }
    }
}

val jnaAndroidNatives: Configuration by configurations.creating {
    isTransitive = false
    isCanBeConsumed = false
}

dependencies {
    jnaAndroidNatives("net.java.dev.jna:jna:$jnaVersion@aar")
}
```

`myotis-engine/build.gradle.kts` · lines 183–219

```kotlin
// Every ABI that gets libmyotis_engine.so needs a matching libjnidispatch.so,
// or UniFFI cannot load and that ABI silently falls back to the Java engine —
// hence the root's one shippedAbis list (read above), which cargoNdkAndroid's
// outputs and `cargo ndk -t ...` in rust/build-android.sh follow too. What
// actually enforces the invariant is the APK post-condition in
// .github/workflows/android-apk.yml, which checks the built Myotis app.

// aar layout is jni/<abi>/lib*.so; the jniLibs source set wants <abi>/lib*.so.
// Sync, not Copy: Copy leaves behind files no longer in the spec, so a narrowed
// abi list (or a jna upgrade dropping one) would keep packaging a stale .so.
// NOT configuration-cache compatible, knowingly (the lambdas capture the build
// script); CC is off project-wide today.
val extractJnaAndroidNatives = tasks.register<Sync>("extractJnaAndroidNatives") {
    from(jnaAndroidNatives.elements.map { zipTree(it.single().asFile) }) {
        shippedAbis.forEach { abi -> include("jni/$abi/**") }
    }
    eachFile { path = path.substringAfter("jni/") }
    includeEmptyDirs = false
    into(layout.buildDirectory.dir("jna-android-natives"))
    // Gradle does not warn about include patterns that match nothing, so an ABI
    // the aar has never carried would extract silently to nothing and that ABI
    // would ship an engine with no dispatcher.
    doLast {
        val got = destinationDir.listFiles { f: java.io.File -> f.isDirectory }
            ?.map { it.name }.orEmpty().toSet()
        val missing = shippedAbis.filterNot { it in got }
        check(missing.isEmpty()) {
            "jna-$jnaVersion.aar carries no libjnidispatch.so for $missing — those ABIs " +
                "would ship libmyotis_engine.so with no JNA dispatcher, so the Rust engine " +
                "could not load at runtime (a silent Java fallback on API 33+, a failed boot below)."
        }
    }
}

android {
    sourceSets.getByName("main").jniLibs.srcDir(extractJnaAndroidNatives)
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* JNA itself needs a native library, `libjnidispatch.so`, to call anything. The plain JNA jar carries only desktop dispatchers; the Android ones ship in `jna-<v>.aar`. A detached configuration (`isCanBeConsumed = false`, not on any classpath) downloads that aar, and `extractJnaAndroidNatives` copies only `jni/<abi>/…` into this module's jniLibs, renaming paths to `<abi>/…`.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* The JNA jar version is pinned with `strictly`, so the published POM carries the constraint too: JNA refuses to run when its jar and its native dispatcher differ. `Sync` rather than `Copy` removes files no longer in the spec, and the `doLast` check fails the build if an ABI got no dispatcher.

### The Android build regenerates the bindings

`myotis-engine/build.gradle.kts` · lines 221–272

```kotlin
// === The Rust engine, built from source into this module's jniLibs ===========
// requireAndroidRustEngine enforces the contract: with the toolchain present,
// cargoNdkAndroid cross-compiles the jniLibs and uniffiGenerateKotlin refreshes
// the committed bindings (:myotis-engine-rust) from the same source; without it,
// the build fails and names `-PskipRustEngine`. verifyAndroidJniLibs is the
// post-build backstop that the produced .so exports every UniFFI symbol the
// (now-fresh) bindings require. Auto-regen is scoped to the Android build ON
// PURPOSE — the JVM hosts must stay buildable without cargo (see
// myotis-engine-rust/build.gradle.kts), and CI enforces bindings freshness for
// everyone via the regenerate-and-diff step in android-apk.yml. Root
// build.gradle.kts owns the tasks.
tasks.matching { it.name == "preBuild" }.configureEach {
    // JNA's Android dispatcher (the extraction task is defined above):
    // srcDir(<TaskProvider>) registers the DIRECTORY but does NOT carry a task
    // dependency through AGP's source sets, so on a clean build the jniLib merge
    // would run before anything has extracted and the AAR would silently ship
    // without libjnidispatch.so. preBuild runs ahead of every merge/assemble/
    // bundle path.
    dependsOn(extractJnaAndroidNatives)
    // Always run the gate: with -PskipRustEngine it just logs the opt-out.
    dependsOn(rootProject.tasks.named("requireAndroidRustEngine"))
    // Only pull the Rust build tasks into the graph when we actually want the
    // engine — under -PskipRustEngine they'd only self-skip anyway, and keeping
    // them out avoids the JVM build touching cargo/bindings at all.
    if (!skipRustEngine) {
        dependsOn(rootProject.tasks.named("uniffiGenerateKotlin"))
        dependsOn(rootProject.tasks.named("cargoNdkAndroid"))
        dependsOn(rootProject.tasks.named("verifyAndroidJniLibs"))
    }
}
// The backstop must see the FRESH outputs of BOTH producers: cargoNdkAndroid's
// .so and uniffiGenerateKotlin's regenerated bindings (which verifyAndroidJniLibs
// reads as an input — without this ordering Gradle fails the build with an
// implicit-dependency validation error, and the check could otherwise validate
// against the stale .kt it is about to replace). The gate should fail first
// (before we spend time cross-compiling) when the toolchain is missing.
rootProject.tasks.named("verifyAndroidJniLibs").configure {
    mustRunAfter(rootProject.tasks.named("cargoNdkAndroid"))
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}
// Both expensive Rust producers run AFTER the gate, so a machine with cargo but
// without the Android toolchain (cargo-ndk / NDK / targets) fails fast instead of
// first building the whole host workspace: cargoNdkAndroid directly, and
// cargoBuildHost because uniffiGenerateKotlin dependsOn it (ordering the generator
// alone wouldn't hold cargoBuildHost back). Both edges are inert off-Android,
// where requireAndroidRustEngine isn't in the graph.
rootProject.tasks.named("cargoNdkAndroid").configure {
    mustRunAfter(rootProject.tasks.named("requireAndroidRustEngine"))
}
rootProject.tasks.named("cargoBuildHost").configure {
    mustRunAfter(rootProject.tasks.named("requireAndroidRustEngine"))
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Everything hangs off `preBuild`**, the first task of every Android build path. It always extracts the JNA dispatcher and runs the toolchain gate; unless `-PskipRustEngine` is set, it also runs `uniffiGenerateKotlin`, `cargoNdkAndroid` and `verifyAndroidJniLibs`. The comment on line 234 explains why the explicit `dependsOn(extractJnaAndroidNatives)` is needed: a task registered as a source directory does not carry a dependency through the Android plugin.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Generated from the host library.** `uniffiGenerateKotlin` depends on `cargoBuildHost`, so the Android bindings are generated from the macOS or Linux library, not from the Android `.so`. That works because the metadata comes from the source, which is the same for both targets (`ffi.rs` has no `#[cfg]`-gated exports).
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `mustRunAfter` orders tasks without adding them: the symbol check must see the fresh `.so` and the fresh `.kt`, and both expensive Rust builds wait for the cheap toolchain gate, so a machine without the NDK fails fast.

`build.gradle.kts` · lines 995–1031

```kotlin
// Post-build sanity check on the jniLibs that will actually ship. With the libs
// built from source (not committed) this normally can't drift, but it's a cheap
// backstop against a partial/interrupted cargoNdkAndroid or a bindings/scaffolding
// skew, turning a broken .so into a build failure instead of a silent runtime
// fallback — the failure class this whole contract exists to prevent. Two checks:
//   • libmyotis_engine.so exports every UniFFI symbol the committed bindings
//     require (else the Rust engine fails UniFFI validation on-device → Java);
//   • libmyotis_bls.so is present and a valid ELF for each shipped ABI (else the
//     native BLS backend is unavailable on-device → the slower JVM BLS).
// The BLS lib carries no UniFFI surface to check, so presence + ELF magic is the
// meaningful signal there. Skipped with -PskipRustEngine (nothing is built).
//
// Symbol PRESENCE (one scan of the .so for the required names), not a full ELF
// .dynsym parse: a missing export is simply absent from the .so's string table,
// which a byte scan catches with no external tools. A same-name signature change
// (checksum drift, no new symbol) is still caught at load time by UniFFI's
// checksum gate and, in CI, by the regenerate-and-diff step in android-apk.yml.
val shippedAbis = listOf("arm64-v8a", "x86_64")
// :myotis-engine extracts JNA's dispatcher for exactly these ABIs (rootProject.extra):
// one list, so an ABI added here cannot ship an engine with no dispatcher there.
extra["myotis.shippedAbis"] = shippedAbis
val engineJniLibs = shippedAbis.map { file("myotis-engine/src/androidMain/jniLibs/$it/libmyotis_engine.so") }
val blsJniLibs = shippedAbis.map { file("myotis-engine/src/androidMain/jniLibs/$it/libmyotis_bls.so") }
val committedBindings = project(":myotis-engine-rust").projectDir
    .resolve("src/main/kotlin/uniffi/myotis_engine/myotis_engine.kt")
tasks.register("verifyAndroidJniLibs") {
    group = "verification"
    description =
        "Fail if the built Android jniLibs are broken — engine .so missing a required UniFFI " +
            "symbol, or BLS .so missing/not an ELF (post-build backstop; skipped by -PskipRustEngine)"
    onlyIf { !skipRustEngine }
    inputs.file(committedBindings).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(engineJniLibs).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.files(blsJniLibs).withPathSensitivity(PathSensitivity.RELATIVE)
    val marker = layout.buildDirectory.file("verifyAndroidJniLibs.ok")
    outputs.file(marker)
    doLast {
```

`build.gradle.kts` · lines 1032–1078

```kotlin
        fun requireElf(so: File, hint: String) {
            check(so.exists()) {
                "verifyAndroidJniLibs: missing jniLib $so — cargoNdkAndroid did not produce it$hint. " +
                    "Run `./gradlew cargoNdkAndroid` (needs the Android Rust toolchain), or build " +
                    "without the native libs via -PskipRustEngine."
            }
            val magic = so.inputStream().use { ins -> ByteArray(4).also { ins.read(it) } }
            check(magic.contentEquals(byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))) {
                "verifyAndroidJniLibs: ${so.parentFile.name}/${so.name} is not an ELF binary " +
                    "(truncated/corrupt build?). Rebuild with `./gradlew cargoNdkAndroid`."
            }
        }
        // Every native symbol JNA's Native.register resolves eagerly at load:
        // both the uniffi_* (per-function + per-function-checksum) and the
        // ffi_* (rustbuffer/contract-version/future runtime) external funcs.
        val required = Regex("""external fun (uniffi_myotis_engine_\w+|ffi_myotis_engine_\w+)\s*\(""")
            .findAll(committedBindings.readText())
            .map { it.groupValues[1] }
            .toSortedSet()
        check(required.isNotEmpty()) {
            "verifyAndroidJniLibs: found no UniFFI symbols in $committedBindings — " +
                "the bindings file moved or its shape changed; update this task."
        }
        val symbol = Regex("""uniffi_myotis_engine_\w+|ffi_myotis_engine_\w+""")
        engineJniLibs.forEach { so ->
            requireElf(so, " (the Rust engine)")
            // ISO-8859-1 maps each byte 1:1 to a char; one scan collects every
            // engine symbol present (they live in .dynstr), then set-diff vs required.
            val present = symbol.findAll(String(so.readBytes(), Charsets.ISO_8859_1))
                .map { it.value }.toHashSet()
            val missing = required.filterNot { it in present }
            check(missing.isEmpty()) {
                "verifyAndroidJniLibs: ${so.parentFile.name}/${so.name} is missing " +
                    "${missing.size} UniFFI symbol(s) the bindings require, e.g. " +
                    "${missing.take(3)}. The Rust engine would fail UniFFI validation on-device " +
                    "and silently fall back to Java. Rebuild with `./gradlew cargoNdkAndroid`; if " +
                    "the bindings are the stale side, regenerate them with " +
                    "`./gradlew uniffiGenerateKotlin`."
            }
        }
        // The native BLS lib has no UniFFI surface — presence + ELF is the signal.
        blsJniLibs.forEach { requireElf(it, " (native BLS)") }
        marker.get().asFile.apply { parentFile.mkdirs(); writeText("ok") }
        logger.lifecycle("[rust] verifyAndroidJniLibs: engine jniLibs export all " +
            "${required.size} required UniFFI symbols; native BLS present for ${shippedAbis.joinToString(", ")}")
    }
}
```

*[Tests](01-primer.md#primer-testing) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **`verifyAndroidJniLibs`** collects, with a regex over the committed Kotlin, every `uniffi_myotis_engine_*` and `ffi_myotis_engine_*` name that `Native.register` will bind, then reads each built `.so` as ISO-8859-1 text (one char per byte) and checks that every name occurs. It is a build-time version of the eager binding JNA does on the device. As the comment says, it catches a missing symbol, not a changed signature under the same name; that is left to the checksums and to CI's regenerate-and-diff. It also checks that each library starts with the ELF magic bytes.

### Desktop builds do not regenerate

`myotis-engine-rust/build.gradle.kts` · lines 41–64

```kotlin
// The committed UniFFI bindings are NOT force-regenerated from compileKotlin:
// a `dependsOn(uniffiGenerateKotlin)` would drag a full `cargo build --release`
// (via cargoBuildHost) in front of every JVM host's Kotlin compile and make a
// broken rust/ break the JVM build — violating "Rust is OPTIONAL for the JVM
// hosts". Auto-regeneration is scoped to the Android build (:myotis-engine's
// preBuild, where cargo is already required); CI enforces freshness everywhere
// via the regenerate-and-diff step in android-apk.yml; regenerate manually
// elsewhere with `./gradlew uniffiGenerateKotlin`.
//
// mustRunAfter (NOT dependsOn) is ORDERING ONLY — inert when uniffiGenerateKotlin
// isn't in the graph (every non-Android build: no cargo pulled in), and, when it
// IS (an Android build regenerating the bindings), it makes compileKotlin read
// the fresh .kt and satisfies Gradle's implicit-dependency validation, since
// compileKotlin consumes uniffiGenerateKotlin's declared output.
tasks.named("compileKotlin") {
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}
// The sources jars of the publication (root build.gradle.kts, `Publishing`)
// read the same committed bindings, so they need the same ordering for the
// same reason — in an Android build Gradle refuses a sources jar that reads
// uniffiGenerateKotlin's output without it (implicit-dependency validation).
tasks.matching { it.name == "sourcesJar" || it.name == "kotlinSourcesJar" }.configureEach {
    mustRunAfter(rootProject.tasks.named("uniffiGenerateKotlin"))
}
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* A `dependsOn` here would put a release cargo build in front of every JVM compile and break the rule that Rust is optional for the JVM hosts. `mustRunAfter` only orders the two tasks when both are in one build. Freshness for everyone is enforced by CI: the comment says the APK workflow regenerates the bindings and fails on any difference.

## 9. Why compound values cross as JSON

UniFFI can pass structured data. A `#[derive(uniffi::Record)]` struct becomes a Kotlin `data class`, serialized into a `RustBuffer` field by field with `write`/`try_read`, exactly as `Option<String>` is above. The project's design notes describe that typed mapping for the whole `io.myotis.api` contract, and then explain what was built instead:

`docs/reimplementation/05-engine-api-bindings.md` · lines 31–50

```text
> **Status (as built).** The Rust engine is complete and is the default engine
> (see the repo README, *Engines*). The JVM boundary is **UniFFI + JSON**: the
> first Rust-engine PRs bound via hand-JNI, and that decision was reversed in
> 2026-07 as a transport swap only (see [06](06-rust-phase-notes.md)) —
> `#[uniffi::export]` functions in `rust/myotis-engine/src/ffi.rs`, generated Kotlin
> bindings committed in `:myotis-engine-rust` (`./gradlew uniffiGenerateKotlin`
> regenerates them; an Android build does so automatically), `RustEngineNative`
> reduced to a static delegator, and `:myotis-engines` selecting the engine
> (`Engines.engine()`, `myotis.engine=java|rust|auto`). Compound values still cross
> as JSON strings whose schemas are pinned by golden tests on BOTH sides
> (`rust/testdata/networks_catalog.json` ⇄ `catalog::tests` ⇄ `NetworksJsonGoldenTest`),
> so the "cargo strictly optional" requirement holds for the JVM hosts: the committed
> bindings need no bindgen step, and UniFFI's per-function checksums replace the old
> hand-rolled ABI probe as the stale-library guard (`RustEngineNative` keeps the coarse
> `ABI_VERSION` handshake as a second check). The non-JVM hosts — the iOS app (`:app-ios`,
> Kotlin/Native cinterop) and the Node.js addon (`rust/myotis-node`, napi-rs) — consume the same
> engine over its plain C ABI (`rust/myotis-engine/src/capi.rs`,
> `rust/include/myotis_engine.h`), gated on the header's `MYOTIS_ABI_VERSION`. The
> typed-record UniFFI mapping below remains the reference path if the JSON transport
> is ever retired.
```

The reasons, from the code and these notes:

- **It was a transport swap.** The `ffi.rs` module doc: "TRANSPORT SWAP ONLY: these functions mirror the old hand-JNI natives 1:1". The JSON shapes already existed, Java already parsed them, and golden tests on both sides (`rust/testdata/…`, `RustVerifiedReadJsonTest` and others) pinned them. Replacing hand-JNI with UniFFI changed how bytes move, not what they mean.
- **One schema for three routes.** The iOS C ABI and the Node addon can only pass `char*`. Because the UniFFI route also passes JSON, `eljson.rs` serializes each result once for all hosts, and the same golden files cover them.
- **A small, stable FFI surface.** With only integers and strings crossing, a checksum changes only when a function is added or its parameters change. Adding a field to a result is a payload change: no signature changes, no regeneration, and older readers ignore the new key (the `ABI_VERSION` history in `lib.rs` records many such "payload extension, no signature change" steps).

The costs are real. A result is serialized to text in Rust, copied across, and parsed again in Java. The compiler no longer checks that both sides agree on a field's name or type; the golden tests and the defensive parsing in `RustChainHandle` do that instead. And the `ABI_VERSION` number has to be bumped by hand for every payload change.

## 10. The safety net, and when to run `uniffiGenerateKotlin`

| Check | What it compares | What it catches | What it misses |
|---|---|---|---|
| Contract version | Kotlin literal 30 vs `ffi_myotis_engine_uniffi_contract_version()` | Bindings and library from UniFFI versions with different FFI conventions. | Anything about Myotis's own functions. |
| Per-function checksum (55) | Kotlin literal vs `uniffi_myotis_engine_checksum_func_*()` | Any change to a function's metadata: name, module, parameter names, types and order, return type, async, doc comment. | The function body; JSON payload changes; a function added to Rust but not to Kotlin (Kotlin simply cannot call it). |
| Symbol binding | `Native.register` on load; `verifyAndroidJniLibs` at build | A function the Kotlin declares but the library lacks (removed, or a pre-UniFFI library). | Signature changes under the same name. |
| `ABI_VERSION` | `engineInit()` vs `RustEngineNative.EXPECTED_ABI_VERSION` (55) | Behavior and payload changes that someone remembered to bump, for example "a proof names its block's hash" (v52). | Anything nobody bumped. |
| JSON golden tests | Fixed JSON files, parsed on both sides | Shape drift in the payloads. | Code paths without a golden file. |
| CI regenerate-and-diff | Freshly generated `.kt` vs the committed one | Forgetting to regenerate. | Only runs in the APK workflow. |

`myotis-engine-rust/src/test/java/io/myotis/engines/rust/AbiVersionMirrorTest.java` · lines 15–34

```java
/**
 * The ABI handshake constant is copied by hand into every host that gates on it, and a
 * copy that falls behind is worse here than anywhere else: {@link RustEngineNative}
 * turns a mismatch into {@code isAvailable() == false}, which {@code Engines} reads as
 * "no Rust engine" and silently serves the Java one instead — {@code myotis.engine=rust}
 * quietly not being honoured, behind a single {@code log.warn}.
 *
 * <p>UniFFI's per-function checksums do NOT cover this. They catch a library whose SHAPE
 * disagrees with the bindings (a stale {@code .so}); they pass cleanly when the library
 * is current and correct and only the hand-copied integer is behind — which is exactly
 * the drift this pins.
 *
 * <p>Deliberately reads the Rust tree as TEXT, the same trick
 * {@code NetworksJsonGoldenTest} uses for the catalog golden: no native library, no
 * cargo, so this runs in the plain {@code ./gradlew build} CI job. That matters because
 * the Rust-side twin of this check ({@code capi::tests::header_pins_the_current_abi_version})
 * sits behind {@code cargoTest}'s {@code onlyIf { rustAvailable }} and can silently skip.
 * Checking the header here too makes the whole chain — crate constant, C header, JVM
 * mirror — verified unconditionally.
 */
```

*[Tests](01-primer.md#primer-testing)* The checksums cannot see a hand-copied integer that fell behind, so this test reads `lib.rs` and the C header as text and compares them with `EXPECTED_ABI_VERSION`. It runs without cargo, unlike its Rust twin in `capi.rs`.

**Run `./gradlew uniffiGenerateKotlin`**, and commit the changed `myotis_engine.kt`, whenever you:

- add, remove or rename a `#[uniffi::export]` function in `ffi.rs`;
- change a parameter's name, type or position, or the return type;
- edit the `///` doc comment of an exported function, even one word;
- move an exported function to another module;
- upgrade `uniffi`.

You do **not** need it when you change only function bodies (`host.rs`, `eljson.rs`, or the inside of an `ffi.rs` function such as the `u64::try_from` in `get_raw_transaction_by_block_json`), or anything in `capi.rs` and the C header. A payload change needs an `ABI_VERSION` bump and golden-test updates instead. Always regenerate through Gradle, never with a direct `cargo run`, so the checksum masking is applied.

> [!WARNING]
> **What forgetting looks like**<br>
>
> Say you add a parameter to `request_account_json` and forget. On the desktop, the stale Kotlin compiles and the new library loads, but `uniffiCheckApiChecksums` throws for that one function, `RustEngineNative` logs "failed UniFFI validation", and the app quietly runs on the Java engine. In an Android build, `preBuild` regenerates the Kotlin, the wrapper gains the parameter, and the unchanged Java call in `RustEngineNative` no longer compiles: the failure moves to compile time, which is the better place.

## 11. The iOS route, for contrast

iOS does not use UniFFI. `capi.rs` exports a hand-written C interface over the same `host` functions, declared in `rust/include/myotis_engine.h`. Kotlin/Native reads that header with `cinterop` and generates Kotlin declarations for it at build time. There is no JNA, no JVM and no `RustBuffer`: strings are NUL-terminated C strings.

`rust/myotis-engine/src/capi.rs` · lines 1–41

```rust
//! Plain C ABI over the same `host` functions the JNI shim wraps — the iOS
//! (Kotlin/Native cinterop) seam. Mirrors the JVM FFI surface (`ffi`, UniFFI)
//! one-to-one — plus the host knobs the JVM hosts have no surface for yet
//! (`myotis_set_boot_enodes`, #465), which the Node addon also wraps: compound values
//! cross as JSON strings with the exact same shapes the golden tests pin, and the
//! sentinel conventions are identical (negative handle ids, `"{}"` status for an
//! unknown handle, `{"error": ...}` objects). The header consumed by cinterop is
//! `rust/include/myotis_engine.h` — keep both in sync and bump `ABI_VERSION` on
//! any shape change (`myotis_init` is the handshake, exactly like `nativeInit`).
//!
//! Memory contract: every `*mut c_char` this module returns is owned by the
//! caller and MUST be released via `myotis_string_free` (it is a `CString`
//! allocated by Rust — freeing it with `free(3)` is undefined behavior).
//!
//! Panic-freedom matters as much as in the JNI shim: the workspace builds with
//! `panic = "abort"`, so any panic kills the host app. Every failure path here
//! returns a sentinel (null / false / -1) instead of unwrapping.

use std::ffi::{c_char, CStr, CString};

/// Read a C string into an owned Rust `String`. Null → `None`; invalid UTF-8 is
/// replaced lossily (panic-free) rather than rejected — same spirit as the JNI
/// shim's `read_string`, which tolerates whatever the JVM hands it.
///
/// # Safety
/// `p` must be null or a valid null-terminated C string.
unsafe fn read_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    Some(CStr::from_ptr(p).to_string_lossy().into_owned())
}

/// Hand a Rust `String` to the caller as a `CString`. Interior NUL bytes cannot
/// occur in the engine's JSON/log output, but if one ever did, return null
/// instead of panicking (the caller already treats null as unavailable).
fn into_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **Incoming: copy and repair.** `CStr::from_ptr` borrows the caller's bytes up to the NUL, `to_string_lossy` replaces invalid UTF-8 with U+FFFD instead of trusting it, and `into_owned` copies, so Rust does not depend on how long the caller keeps its buffer. Compare UniFFI's `from_utf8_unchecked`, which neither copies nor checks.
- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* **Outgoing: the same allocator rule.** `CString::into_raw` gives up ownership exactly like `RustBuffer::from_vec`. An interior NUL makes `into_c` return null instead of panicking.

`rust/myotis-engine/src/capi.rs` · lines 44–52

```rust
/// The availability + ABI handshake (`nativeInit` twin). Installs the tracing
/// subscriber feeding the drainable ring (idempotent) and returns `ABI_VERSION`;
/// hosts must refuse to call anything else if the value doesn't match the header
/// they compiled against.
#[no_mangle]
pub extern "C" fn myotis_init() -> i32 {
    crate::ringlog::init();
    crate::ABI_VERSION
}
```

`rust/myotis-engine/src/capi.rs` · lines 254–271

```rust
/// Verified account read (`nativeRequestAccountJson` twin). Blocking — may take
/// up to ~90 s for a header-chain walk; never call from the UI thread. `block`
/// (ABI ≥ 32) is the RPC block selector the engine applies or refuses: NULL or
/// empty proves at the verified head, `finalized` at the beacon-finalized
/// block, a number only inside the window around the head.
///
/// # Safety
/// `address` and `block` must each be null or a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn myotis_request_account_json(
    handle: i64,
    address: *const c_char,
    block: *const c_char,
) -> *mut c_char {
    let address = read_string(address).unwrap_or_default();
    let block = read_string(block).unwrap_or_default();
    into_c(crate::host::request_account_json(handle, &address, &block))
}
```

`rust/myotis-engine/src/capi.rs` · lines 797–810

```rust
/// Release a string previously returned by any `myotis_*` function. Null is a
/// no-op.
///
/// # Safety
/// `s` must be null or a pointer previously returned by this module and not yet
/// freed. Passing anything else (including a pointer freed twice) is undefined
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn myotis_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi) · [Ownership & moves](01-primer.md#primer-ownership)* The same three moves as UniFFI, written by hand: a handshake (`myotis_init`, the twin of `engine_init`), a function that converts its arguments, calls `host` and hands back an owned string, and a free function. `myotis_string_free` takes the pointer back with `CString::from_raw` and drops it, like `rustbuffer_free`. Calling `free(3)` on the pointer would be undefined behavior. `#[no_mangle]` (edition 2021 spelling) here does what `#[unsafe(no_mangle)]` does in the macro output.

`rust/include/myotis_engine.h` · lines 1–23

```c
/*
 * Plain C ABI of the Myotis Rust engine (rust/myotis-engine/src/capi.rs).
 * Consumed by the Kotlin/Native cinterop of :myotis-engine-ios (published as
 * eth.myotis:myotis-engine-ios; :app-ios links it from there); keep in lockstep
 * with capi.rs and bump MYOTIS_ABI_VERSION expectations on any shape change. A
 * JSON shape change also moves the module's typed API and its EngineDecodingTest.
 *
 * Conventions (identical to the hand-JNI surface):
 *  - Compound values cross as JSON strings; schemas are pinned by the golden
 *    tests on both sides of the JNI seam and shared verbatim here.
 *  - Every char* RETURNED by these functions is owned by the caller and must
 *    be released with myotis_string_free (never free(3)).
 *  - Errors are sentinels, not exceptions: negative handle ids from
 *    myotis_create, false from start/pause/resume, "{}" status for an unknown
 *    handle, {"error": "..."} objects from the verified reads.
 *  - Verified reads are BLOCKING with a cooperative ~90 s operation budget.
 *    Cancellation drains started native execution; indivisible native work may
 *    overrun the budget. Call off the UI thread.
 *  - EVM execution admits at most eight actual closures process-wide; further
 *    execution fails immediately with "native execution busy". Hosts must bound
 *    their queues and retry busy reads within their own deadline; there is no
 *    additional native semaphore-wait queue.
 */
```

`rust/include/myotis_engine.h` · lines 35–44

```c
/* The ABI version this header describes. Mirrors ABI_VERSION in
 * rust/myotis-engine/src/lib.rs and is pinned to it by a capi.rs unit test
 * (header_pins_the_current_abi_version), so a bump that forgets this file
 * fails `cargo test`. Gate on this macro — do not copy the number. */
#define MYOTIS_ABI_VERSION 55

/* Availability + ABI handshake. Installs the log ring subscriber (idempotent)
 * and returns the engine's ABI version; refuse to call anything else if it
 * differs from MYOTIS_ABI_VERSION. */
int32_t myotis_init(void);
```

`rust/include/myotis_engine.h` · lines 150–165

```c
/* Verified reads — JSON results; {"error": "..."} on transport/not-running/
 * bad-input failures; verification failures carry a `failReason` inside the
 * normal result shape instead.
 * v32: the account, code and storage-position reads take the RPC block
 * selector and APPLY OR REFUSE it, as eth_call has since v27: NULL or "" and
 * the head tags prove at the verified head, "finalized" at the beacon-
 * finalized block (the proof is verified against the finalized state root;
 * refused, retryably, while no finalized block has landed or no peer still
 * serves that state), a number only inside [head-64, head+16] (head state),
 * anything else {"error","code":-32602}. Every result names the block it
 * proved at: "anchor": "head" | "finalized".
 * v41: the account read carries "blockTimestamp" (unix seconds) when that
 * block's timestamp is PROVEN — the read ran against the beacon-attested
 * block and its verdict holds — else null. */
char *myotis_request_account_json(int64_t handle, const char *address,
                                  const char *block);
```

`rust/include/myotis_engine.h` · lines 393–394

```c
/* Release any char* returned by the functions above. NULL is a no-op. */
void myotis_string_free(char *s);
```

*[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* The header is the hand-written equivalent of UniFFI's metadata. It states the memory contract in prose, carries the payload history in comments, and defines `MYOTIS_ABI_VERSION`, which a `capi.rs` test and `AbiVersionMirrorTest` pin to the crate constant. (Lines 19–22 are out of date; see the callout below.)

`myotis-engine-ios/src/nativeInterop/cinterop/myotis_engine.def` · lines 1–10

```text
# Kotlin/Native cinterop over the Rust engine's plain C ABI (rust/myotis-engine/
# src/capi.rs). staticLibraries absorbs libmyotis_engine.a into the klib — the one
# published as eth.myotis:myotis-engine-ios — and from there into whichever
# framework links it (MyotisKit here), so no Xcode project links Rust directly. The library search path is passed per-target from build.gradle.kts
# (-libraryPath): device and simulator archives live in different cargo dirs.
# The include dir (rust/include) is likewise supplied from build.gradle.kts.
package = io.myotis.engine.capi
headers = myotis_engine.h
headerFilter = myotis_engine.h
staticLibraries = libmyotis_engine.a
```

`myotis-engine-ios/src/iosMain/kotlin/io/myotis/engine/ios/RustEngine.kt` · lines 59–109

```kotlin
/**
 * Thin Kotlin face over the Rust engine's C ABI — the iOS twin of
 * `RustEngineNative` on the JVM side. Owns exactly two concerns: the
 * string-memory contract (every `char*` the engine returns is copied to a
 * Kotlin String and immediately released via `myotis_string_free`) and the
 * ABI handshake. The JSON decoding and the lifecycle bookkeeping live above it:
 * in the typed API ([MyotisEngine], from `Myotis.newEngine()`), or in a host that
 * reads the JSON itself (`:app-ios`'s `IosNodeController`).
 *
 * All calls are BLOCKING (verified reads up to ~90 s) — callers stay off the
 * main thread, same rule as every other host.
 */
@OptIn(ExperimentalForeignApi::class)
object RustEngine {

    /** The ABI this host was built against, taken from the C header itself
     *  (`MYOTIS_ABI_VERSION` in rust/include/myotis_engine.h) rather than
     *  copied — the header instructs consumers to gate on the macro, and a
     *  capi.rs test pins it to `ABI_VERSION` in rust/myotis-engine/src/lib.rs.
     *  So there is no number to keep in sync here; cinterop reads it from the
     *  same header it generates these bindings from. The JVM twin
     *  `RustEngineNative.EXPECTED_ABI_VERSION` still mirrors by hand (UniFFI,
     *  no header in the loop). */
    const val EXPECTED_ABI_VERSION = MYOTIS_ABI_VERSION

    private val abiVersion: Int by lazy { myotis_init() }

    /**
     * Throws when the linked engine's ABI differs from what this host was built
     * against — fail loudly with a clear message instead of on drifted JSON or a
     * missing symbol. EVERY public entry point below calls this first (cheap
     * after the lazy first call), so no construction order can slip an FFI call
     * past the handshake — the header's contract is "refuse to call anything
     * else if the version differs".
     */
    fun requireAbi() {
        val v = abiVersion
        check(v == EXPECTED_ABI_VERSION) {
            "Rust engine ABI mismatch: expected $EXPECTED_ABI_VERSION, linked $v"
        }
    }

    /** Copy + free an engine-owned C string. Null stays null (the sentinel). */
    private fun take(p: CPointer<ByteVar>?): String? {
        if (p == null) return null
        return try {
            p.toKString()
        } finally {
            myotis_string_free(p)
        }
    }
```

`myotis-engine-ios/src/iosMain/kotlin/io/myotis/engine/ios/RustEngine.kt` · lines 240–246

```kotlin
/** AccountProofResult JSON, or `{"error": ...}`; `block` (ABI >= 32) is the RPC
 *  selector the engine applies or refuses (the contract is `myotis_engine.h`'s). */
fun requestAccountJson(handle: Long, address: String, block: String = ""): String {
    requireAbi()
    return take(myotis_request_account_json(handle, address, block))
        ?: """{"error":"engine returned no result"}"""
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **The hand-written twin of `FfiConverterString.lift`.** `take` copies the C string into a Kotlin `String` (`toKString`) and frees it in `finally`. For the arguments, cinterop maps a `const char*` parameter to Kotlin `String?` and converts the Kotlin string to a temporary C string for the duration of the call; the Rust side copies it (`into_owned`) before that memory goes away.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Static linking.** `staticLibraries = libmyotis_engine.a` puts the Rust archive inside the cinterop klib, so the header and the library always travel together. `EXPECTED_ABI_VERSION` is the header's `MYOTIS_ABI_VERSION` macro, read by cinterop, and every public function calls `requireAbi()`, which compares it with `myotis_init()` once (`by lazy` is Kotlin's thread-safe lazy initialization).

|   | JVM and Android (UniFFI) | iOS (C ABI) |
|---|---|---|
| Rust side | generated by `#[uniffi::export]` | hand-written `#[no_mangle] extern "C"` in `capi.rs` |
| Foreign side | generated by `uniffi-bindgen` from the library, committed | generated by `cinterop` from the header, at build time |
| String in | Rust-allocated `RustBuffer`, filled by Kotlin, no copy in Rust, no UTF-8 check | caller's C string, copied and repaired by `read_string` |
| String out | `RustBuffer`, freed by `rustbuffer_free` | `char*`, freed by `myotis_string_free` |
| Errors | call-status struct (unused in practice) + JSON | null / false / −1 + JSON |
| Stale-library guard | contract version, 55 checksums, eager binding, `ABI_VERSION` | `MYOTIS_ABI_VERSION` only; static linking makes a mismatch unlikely |
| Loading | JNA at run time | linked into the app binary |

> [!WARNING]
> **Stale or inaccurate comments**<br>
>
> - `rust/myotis-engine/Cargo.toml` line 6 describes the crate as a "JNI cdylib", and lines 27–30 speak of "the JNI natives" and claim this is the only crate that pulls in tokio. The JNI layer is gone (UniFFI over JNA), and `myotis-net` depends on tokio as well.
> - `capi.rs` line 1 calls itself a C ABI "over the same `host` functions the JNI shim wraps", and `read_string`'s doc compares itself with "the JNI shim's `read_string`". Neither shim exists any more.
> - `uniffi-bindgen/Cargo.toml` lines 11–13 say a version skew between scaffolding and generator "is a build error by design". In the code I read, nothing fails at build time: the shared lock file keeps one `uniffi` version, and a skew would be caught at load time by the contract-version check.
> - The comment on `uniffiGenerateKotlin` (root `build.gradle.kts` line 714) says to re-run it "whenever `ffi.rs` changes shape". Doc comments are part of the checksummed metadata (`fnsig.rs` line 309), so a doc-only edit needs it too.
> - `rust/include/myotis_engine.h` lines 19–22 say "there is no additional native semaphore-wait queue" for EVM execution. `myotis-net/src/el/request.rs`'s `blocking` now waits FIFO for a slot for up to `BLOCKING_WAIT` (5 s), with at most 32 waiters, before refusing.

### What changed since September

The mechanism is the same, but the surface grew from 38 to 55 exports and `ABI_VERSION` from 26 to 55. The bindings now live in `:myotis-engine-rust` (previously `:myotis-engines`). Gradle now masks the checksum comparisons to 16 bits after generation. Android builds regenerate the bindings in `:myotis-engine`'s `preBuild`, and the AAR carries JNA's Android dispatcher itself.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-uniffi-q1"></a>

**Q1** · Multiple choice

Kotlin receives the `RustBuffer` holding the JSON result of `requestAccountJson`. Who frees that memory, and how?

- **A.** The JVM garbage collector, once the `RustBuffer.ByValue` object is unreachable
- **B.** `FfiConverterString.lift` copies the bytes into a `ByteArray` and, in `finally`, calls `ffi_myotis_engine_rustbuffer_free`; Rust rebuilds the `Vec` with `from_raw_parts` and drops it
- **C.** Rust frees it when the scaffolding function returns, so Kotlin must copy it before the call ends
- **D.** Kotlin calls `free(3)` through JNA

[Answer →](answers.md#a-uniffi-q1)

<a id="q-uniffi-q2"></a>

**Q2** · Multiple choice

Which of these edits to `ffi.rs` does NOT require running `./gradlew uniffiGenerateKotlin`?

- **A.** Fixing a typo in the `///` doc comment of `request_account_json`
- **B.** Renaming the parameter `block` to `selector`
- **C.** Changing the `match` inside the body of `get_raw_transaction_by_block_json`
- **D.** Moving `request_account_json` into a new module `ffi::reads`

[Answer →](answers.md#a-uniffi-q2)

<a id="q-uniffi-q3"></a>

**Q3** · Multiple choice

A bug makes `host::request_account_json` panic in the shipped Android app. What happens?

- **A.** The process aborts. The release profile sets `panic = "abort"`, so no unwinding happens and `catch_unwind` never gets control
- **B.** `catch_unwind` in `rust_call` catches it, sets status code 2, and Kotlin throws `InternalException`
- **C.** The function returns `{"error": "panic"}`
- **D.** JNA converts the panic into an `UnsatisfiedLinkError`

[Answer →](answers.md#a-uniffi-q3)

<a id="q-uniffi-q4"></a>

**Q4** · Multiple choice

Why are UniFFI's conversion traits generic over a tag type (`FfiConverter<UT>`), with `UniFfiTag` defined in each crate by `setup_scaffolding!`?

- **A.** To make the conversions faster through monomorphization
- **B.** So that Kotlin can choose the conversion at run time
- **C.** Because `String` cannot implement non-generic traits
- **D.** Because of the orphan rule: a crate may implement a foreign trait for a foreign type only if a local type appears in the impl. `FfiConverter<crate::UniFfiTag>` contains a local type, so each consumer crate can write impls for types it does not own

[Answer →](answers.md#a-uniffi-q4)

<a id="q-uniffi-q5"></a>

**Q5** · Multiple choice

A JSON-RPC worker thread calls `RustChainHandle.accountVerified`. On which thread does the Rust code of `request_account_json` run?

- **A.** On a JNA worker thread; the JVM thread waits on a future
- **B.** On the tokio runtime's worker threads only; the scaffolding hands the call over
- **C.** On the calling JVM thread itself. JNA calls the C function directly, and `host.rs` blocks that thread in `rt.block_on` while tokio's worker threads drive the spawned network tasks
- **D.** On the Android main thread

[Answer →](answers.md#a-uniffi-q5)

<a id="q-uniffi-q6"></a>

**Q6** · Multiple choice

The committed Kotlin compares checksums as `(lib.uniffi_myotis_engine_checksum_func_…() and 0xFFFF) != N`. Why the mask?

- **A.** The Rust function returns a `u16`, but the bindings read it as a 32-bit `Int`. The x86-64 calling conventions do not promise that the upper 16 bits of the return register are zero, so an unmasked compare can fail on a correct library. The root Gradle task adds the mask after generation
- **B.** The checksum is 32 bits, and only the low half is meaningful
- **C.** JNA sign-extends every return value
- **D.** UniFFI's template always masks

[Answer →](answers.md#a-uniffi-q6)

<a id="q-uniffi-q7"></a>

**Q7** · Written answer

Trace the memory of the `address` argument from the Kotlin `String` in `requestAccountJson` to the moment it is freed. Name who allocates, who writes, how ownership moves, and where the bytes are dropped.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-uniffi-q7)

<a id="q-uniffi-q8"></a>

**Q8** · Written answer

Describe everything `#[uniffi::export]` adds to the crate for one function such as `request_account_json`, and what each item is for.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-uniffi-q8)

<a id="q-uniffi-q9"></a>

**Q9** · Written answer

You add a parameter to an exported function in `ffi.rs`, update `RustEngineNative`'s call, and forget `uniffiGenerateKotlin`. What happens in a desktop build and in an Android build, and which mechanisms notice?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-uniffi-q9)

<a id="q-uniffi-q10"></a>

**Q10** · Written answer

UniFFI could pass typed records. Why does the Myotis engine pass compound values as JSON strings instead, and what does that cost?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-uniffi-q10)

<a id="q-uniffi-q11"></a>

**Q11** · Multiple choice

`<String as FfiConverter>::try_lift` uses `String::from_utf8_unchecked`. What makes that sound?

- **A.** Rust checks UTF-8 again later, when the string is first used
- **B.** JNA validates UTF-8 for every `Structure`
- **C.** Invalid UTF-8 in a `String` is harmless in Rust
- **D.** The generated Kotlin encodes every string with a UTF-8 encoder set to `CodingErrorAction.REPORT`, so it throws before sending malformed data. The traits are `unsafe trait` precisely because their soundness depends on the foreign code matching them

[Answer →](answers.md#a-uniffi-q11)

<a id="q-uniffi-q12"></a>

**Q12** · Multiple choice

How does the `holder: Option<String>` argument of `get_storage_proof_json` cross the boundary?

- **A.** As a nullable pointer to a C string
- **B.** As two arguments: a flag and a `RustBuffer`
- **C.** Serialized into one `RustBuffer`: a tag byte (0 for `None`, 1 for `Some`), then a big-endian `i32` byte length and the UTF-8 bytes. Rust reads it with `try_read`, which validates the UTF-8 and copies
- **D.** As JSON

[Answer →](answers.md#a-uniffi-q12)

<a id="q-uniffi-q13"></a>

**Q13** · Multiple choice

`RustEngineNative.load()` calls `Myotis_engineKt.uniffiEnsureInitialized()` before `engineInit()`. What would change if that line were removed?

- **A.** Nothing: every generated wrapper checks the checksums before calling
- **B.** The checksums and the contract version would never be checked. A wrapper call touches only the `UniffiLib` object, whose `init` registers the functions without checks; the checks live in the `init` of `IntegrityCheckingUniffiLib`, which runs only when that object is referenced
- **C.** The library would not be loaded at all, so every call would throw `UnsatisfiedLinkError`
- **D.** The checks would run on every call instead of once, which is slower

[Answer →](answers.md#a-uniffi-q13)

<a id="q-uniffi-q14"></a>

**Q14** · Written answer

List what an Android build of `:myotis-engine` does, before compiling anything, so that the AAR can run the Rust engine through UniFFI, and say what would break on a device if each step were missing.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-uniffi-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
