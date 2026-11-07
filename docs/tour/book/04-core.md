# myotis-core: bytes, hashes and tries

*Stop 4 · crate `myotis-core`* · 14 files · 3,603 lines · about 135 minutes

RLP, keccak-256, secp256k1 identities, block headers, ENRs, fork ids, Merkle-Patricia proofs, blooms and the EIP-1559 base fee. These are the pure primitives under every execution-layer (EL) network message. There are no threads, no `Arc` and no `async` in this crate, and since September it also compiles **without the standard library**. It is the best place to get comfortable with **which bytes are borrowed and which are owned**, and with lifetimes that point at a caller's buffer.

## Rust you will practise

- **Borrowed views** — a `View<'a>` whose accessors return slices of the caller's buffer, next to an owned `Item` tree, and when the compiler forces a copy.
- **no\_std and features** `core`, `alloc` and `std` as three layers, a Cargo feature that switches between them, and how features unify across a build.
- **Errors as values** — a one-field error type, `?`, `map_err`, `ok_or_else`, and a proof verdict enum that never panics.

> [!TIP]
> **The crate's promise**<br>
>
> “Sans-I/O by rule” (lib.rs, lines 4–7): every function is a pure function over caller-supplied bytes. There are no sockets, files, clocks or entropy. That is why key *generation* is not here, and why `k256` is built without its `std` feature. Decoding untrusted bytes never panics, because the workspace's release profile sets `panic = "abort"` and a panic would end the host process. The newer half of the promise is `no_std`: with the `std` feature off, the compiler itself refuses any use of the standard library.

> [!WARNING]
> **What changed since September**<br>
>
> The crate became `no_std` + `alloc` with a default `std` feature. `rlp.rs` grew allocation-free readers (`View`, `ViewIter`, `ListBuf`, `validate`, `raw_list_prefix`) after a 10 MiB peer frame cost 547 MB of heap (#454), plus differential tests that pin them to the decoder. `header.rs` decodes through a `View` and reads Amsterdam's two new fields. `forkid.rs` now computes CRC32 to step the pinned fork id across one known fork and to invert it. `trie.rs` can return the `eth_getProof` path, and uses a `BTreeMap` instead of a `HashMap`. `fees.rs` and `tests/rlp_alloc_bound.rs` are new.

### Cargo.toml: one feature, three layers of library

Rust's standard library is really three crates stacked on each other. `core` needs nothing from the machine: slices, arrays, `Option`, `Result`, iterators, formatting traits. `alloc` adds what needs a heap: `Vec`, `String`, `Box`, `BTreeMap`, the `format!` and `vec!` macros. `std` adds what needs an operating system: files, sockets, threads, clocks, and `HashMap`, whose default hasher is seeded from OS randomness. A crate marked `#![no_std]` links only `core` (plus `alloc` if it asks), so it can run on firmware or a bare-metal target. There is no JVM equivalent: a Java library always gets the whole JDK.

A **Cargo feature** is a named compile-time switch, declared in `[features]`. Code tests it with `#[cfg(feature = "std")]`, and the compiler removes the code that is switched off before type checking. Think of a Gradle build variant, except that it works per crate and inside the source file. myotis-core declares one feature, on by default:

![Three nested boxes. The innermost is core: slices, arrays, Option, Result, iterators, fmt and core::error::Error. Around it is alloc: Vec, String, Box, BTreeMap, format! and vec!. Around that is std: HashMap, fs, net, thread, time and OS randomness. To the right: with the std feature on, the default, myotis-core links std like any crate. With it off, the crate is no_std, uses only core and alloc, and a bare-metal program that links it must provide a global allocator.](img/04-core-1.svg)

*The three layers of Rust's standard library. myotis-core stays inside the inner two unless its `std` feature is on.*

`rust/myotis-core/Cargo.toml` · lines 23–32

```toml
[features]
default = ["std"]
std = ["sha3/std"]

[dependencies]
# keccak-256 (EL hashing — never mix with the CL's SHA-256, see docs/reimplementation README §11.6)
# default-features off: sha3's default `std` (→ digest/std → `extern crate std`)
# comes through this crate's `std` feature instead, so `--no-default-features`
# really is std-free.
sha3 = { version = "=0.10.9", default-features = false }
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **A feature can switch on features of dependencies.** `std = ["sha3/std"]` means “when my `std` is on, turn on sha3's `std`”. sha3 is declared with `default-features = false` so that its own default does not pull `std` in behind the crate's back. `k256` (line 39) gets no `std` at all, because that chain would end in `getrandom`, an entropy source.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Features unify.** Within one build, Cargo compiles each crate once, with the union of every feature any dependent asked for. `myotis-wire` depends on myotis-core with `default-features = false` and forwards its own `std` (`myotis-wire/Cargo.toml`, lines 19 and 29). `myotis-net` and `myotis-evm` depend with defaults, so any build that contains them gets myotis-core with `std` on. Features are additive switches, never exclusions.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* `version.workspace = true` and `rust-version.workspace = true` (lines 3 and 5) inherit the values from the workspace's `Cargo.toml`, so every member reports one version and one minimum compiler.

`rust/myotis-core/Cargo.toml` · lines 41–53

```toml
# Bare-metal targets: UEFI firmware and x86_64-unknown-none. sha2 arrives
# transitively — k256's `ecdsa` feature turns on its `sha256` feature — and its
# x86 backend enables SSE per function with `#[target_feature]`. Those targets
# build with SSE off and soft-float, and rustc fails at codegen with
#   rustc-LLVM ERROR: Do not know how to split the result of this operator!
# A global `-C target-feature=-sse2` cannot override a per-function enable, so
# the fix is sha2's `force-soft` backend, steered here for these targets only.
# (`target_os = "none"` also matches non-x86 bare metal, where sha2 is soft
# without its `asm` feature anyway, so the steer is a no-op there.) Workspace
# resolver 2: a target-specific feature never unifies into other targets'
# builds, so every other target keeps the fast default backend.
[target.'cfg(any(target_os = "uefi", target_os = "none"))'.dependencies]
sha2 = { version = "=0.10.9", default-features = false, features = ["force-soft"] }
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo)* A **target-specific dependency**: the `[target.'cfg(…)'.dependencies]` table applies only when compiling for a matching target. myotis-core never uses sha2 itself. The entry exists to set a feature (`force-soft`) on a crate that arrives transitively through k256, and only for bare-metal targets. The comment records why: sha2's SIMD code fails at codegen there. The promise is checked by the root Gradle task `cargoBuildNoStd` (`build.gradle.kts`, lines 869–892). It runs `cargo build --target x86_64-unknown-none -p myotis-core -p myotis-wire --no-default-features`, a target that has no `std` at all. A stray `std::` import or a `HashMap` fails there and nowhere else, because every host builds the crate with `std` on.

<a id="f-myotis-core-src-lib-rs"></a>

### myotis-core/src/lib.rs

*library root · 58 lines · Java twin · :core module*

Turns `no_std` on when the `std` feature is off, declares the ten modules, and documents nine Java twins (lines 9–18, a handy lookup table). It defines the crate's single error type: a tuple struct holding a message, deliberately flat so it crosses FFI easily.

`rust/myotis-core/src/lib.rs` · lines 24–58

```rust
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;

pub mod bloom;
pub mod enr;
pub mod fees;
pub mod forkid;
pub mod header;
pub mod keccak;
pub mod nodekey;
pub mod rlp;
pub mod trie;
pub mod triehash;

/// Single error type for this crate, mirroring `SszError(String)` in
/// `myotis-consensus`: a message, no hierarchy (FFI-flat by design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError(pub String);

impl core::fmt::Display for CoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// `core::error::Error` is stable since Rust 1.81 and is the no_std-clean spelling;
// it is the same trait `std::error::Error` re-exports, so std hosts are unaffected.
impl core::error::Error for CoreError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, CoreError> {
    Err(CoreError(msg.into()))
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Macros & attributes](01-primer.md#primer-macros)* **`#![cfg_attr(not(feature = "std"), no_std)]`** is a conditional attribute: “if the `std` feature is off, apply `#![no_std]` to this crate”. The `!` means it applies to the enclosing item, here the whole crate.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **`extern crate alloc;`** makes the `alloc` crate nameable. Unlike `core` and `std`, it is not in scope by default, even in a `std` build. That is why every module starts with lines such as `use alloc::vec::Vec;` or `use alloc::format;`: a `no_std` crate's prelude has no `Vec`, `String` or `format!`. In a `std` build the same imports are harmless, because `std::vec::Vec` is the very same type re-exported.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* A type becomes an “error” by implementing two traits, `Display` (the message) and `Error` (a marker with default methods). There is no inheritance hierarchy. It implements `core::error::Error` rather than `std::error::Error`; the comment on lines 52–53 explains these are the same trait, the `core` spelling being usable without `std`.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `err<T>(msg: impl Into<String>)` is generic twice. `T` is inferred from the caller's return type, so `return err("…")` fits any `Result<X, CoreError>`. `impl Into<String>` accepts both `&str` and `String`. `pub(crate)` makes it visible to every module in this crate and invisible outside it.

<a id="f-myotis-core-src-keccak-rs"></a>

### myotis-core/src/keccak.rs

*library · 49 lines · Java twin · Tuweni Hash.keccak256*

keccak-256, the execution-layer hash. The doc comment warns not to mix it with the consensus layer's SHA-256. `keccak256_concat` hashes `a ‖ b` by feeding the hasher twice, so no joined buffer is allocated.

`rust/myotis-core/src/keccak.rs` · lines 8–24

```rust
/// `keccak256(data)` — 32 bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// `keccak256(a ‖ b)` without an intermediate concatenation buffer — the
/// discv4 packet layout hashes two-part messages everywhere.
pub fn keccak256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(a);
    hasher.update(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* Returning `[u8; 32]` by value costs nothing on the heap: the 32 bytes are written into the caller's stack slot. In Java, `byte[]` is always a heap object. `copy_from_slice` panics only if the lengths differ, and here both are 32 by construction. The test module (line 26) is compiled only for `cargo test`, and it imports `format` and `String` from `alloc` (line 29) because, in a `no_std` test build, the prelude does not provide them.

<a id="f-myotis-core-src-fees-rs"></a>

### myotis-core/src/fees.rs

*library · 40 lines*

New since September. EIP-1559's base-fee update: the next block's base fee follows from the parent's base fee, gas limit and gas used, rising when the parent was more than half full and falling when it was less. The module doc says it is the one copy for the fee estimates in `myotis-net` (`el/reader.rs`, [stop 14](14-el-reader.md)) and the simulated blocks in `myotis-evm` (`simulate.rs`, [stop 7](07-evm.md)).

`rust/myotis-core/src/fees.rs` · lines 10–23

```rust
pub fn next_base_fee(parent_base_fee: u128, gas_limit: u64, gas_used: u64) -> u128 {
    let gas_target = gas_limit / 2;
    if gas_target == 0 || gas_used == gas_target {
        return parent_base_fee;
    }
    let target = u128::from(gas_target);
    if gas_used > gas_target {
        let delta = (parent_base_fee.saturating_mul(u128::from(gas_used - gas_target)) / target / 8).max(1);
        parent_base_fee.saturating_add(delta)
    } else {
        let delta = parent_base_fee.saturating_mul(u128::from(gas_target - gas_used)) / target / 8;
        parent_base_fee.saturating_sub(delta)
    }
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* **`u128::from(gas_target)`** widens a `u64` through the `From` trait, which exists only for conversions that cannot lose information. `as` would also compile, but `as` truncates silently when it narrows, so `From` documents “this is lossless”.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Saturating arithmetic.** `saturating_mul`, `saturating_add` and `saturating_sub` clamp at `u128::MAX` or 0 instead of overflowing. In Rust a plain `*` that overflows panics in a debug build and wraps in release; Java's `*` always wraps. With saturation no input can do either. The `.max(1)` makes a rise at least one wei, which the test on line 34 attributes to geth.

<a id="f-myotis-core-src-rlp-rs"></a>

### myotis-core/src/rlp.rs

*library · 966 lines · Java twin · Tuweni RLP / RlpItems.split*

A hand-written RLP codec. RLP encodes two kinds of value, byte strings and lists, each behind a one- to nine-byte header that gives its kind and length. This file now offers **three ways to read** the same bytes. `decode` builds an owned `Item` tree. `View` checks the bytes once, then reads them in place. `raw_list_items` and `raw_list_prefix` split a list into sub-slices of the input, because the wire layer must hash exactly the bytes a peer sent, never a re-encoding. All of them are strict about structure: minimal length prefixes, exact consumption, nesting depth at most 32, and no leading zeros in integers. The module docs (lines 4–10) explain why this is not `alloy-rlp`.

| Lines | What happens |
|---|---|
| 1–35 | Docs, imports, `enum Item { Bytes(Vec<u8>), List(Vec<Item>) }`, `MAX_DEPTH`. |
| 37–109 | `Item`'s borrowing accessors, and the scalar readers it shares with `View`: `fixed_bytes`, `scalar_u64`, `fitting_long` (capped at `i64::MAX` for Java parity). |
| 111–196 | `View<'a>` and `ViewIter<'a>`: a checked, borrowed item and the iterator over a list's elements. |
| 198–268 | `ListBuf` (an owned list kept as one buffer of encodings) and `header`, the unchecked header reader the views use. |
| 270–382 | Public entry points: `decode`, `decode_at`, `validate`, `raw_list_items`, `raw_list_prefix`, `strip_bytes_header`, `is_list_prefix`. |
| 384–529 | Decoder core (`decode_item`, `read_long_length`, `decode_list_payload`), its allocation-free twin (`skip_item`, `skip_list_payload`), and `slice`, the one place sub-views are cut. |
| 531–594 | Encoders, which append to a caller-owned `&mut Vec<u8>`. |
| 596–656 | Unit tests: spec examples, long strings, malformed inputs, 40 nested lists. |
| 658–787 | Differential tests (#454): every walker must give the decoder's verdict on every input. |
| 789–965 | Test helpers: the old `raw_list_items` as an oracle, the input generator, the corpus reader, a seeded `Rng`. |

![A nine-byte buffer holding the RLP list cat, dog: c8 83 63 61 74 83 64 6f 67, owned by the caller. Left: rlp::decode copies it into an Item::List that owns two Item::Bytes vectors; the buffer may be dropped. Middle: View::new checks the buffer and keeps a pointer and length into it; its iterator yields Views of bytes 1 to 4 and 5 to 8; the buffer must outlive them. Right: ListBuf::push_view copies the two element encodings into one owned Vec of eight bytes with len 2: one allocation, not one per item.](img/04-core-2.svg)

*Three representations of the same RLP list. Only the middle one has a lifetime parameter, because only it points into somebody else's memory.*

#### Owned tree

`rust/myotis-core/src/rlp.rs` · lines 26–44

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

/// Recursion guard for untrusted input. Real EL payloads nest ≤ 5 deep
/// (ENR `eth` field: list-in-list-in-record); 32 leaves huge headroom while
/// keeping a hostile deep-nest packet from touching the real stack limit.
const MAX_DEPTH: usize = 32;

impl Item {
    /// Byte-string payload, or an error for a list.
    pub fn as_bytes(&self) -> Result<&[u8], CoreError> {
        match self {
            Item::Bytes(b) => Ok(b),
            Item::List(_) => err("RLP: expected bytes, found list"),
        }
    }
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Item` owns its bytes. It has no lifetime parameter, so a decoded tree can outlive the network frame it came from. `as_bytes(&self) -> Result<&[u8], _>` lends a view *into the tree*: matching on `self: &Item` binds `b: &Vec<u8>`, which automatically dereferences to `&[u8]`. The elided lifetime ties that slice to `&self`, so it is valid only while the `Item` lives. The doc comment above the enum now warns that this is expensive for peer bytes and points to the alternatives below.

#### A checked, borrowed view

`rust/myotis-core/src/rlp.rs` · lines 118–157

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View<'a> {
    /// The item's whole encoding, header included.
    raw: &'a [u8],
}

impl<'a> View<'a> {
    /// A view of `data`, which must be exactly one well-formed item: the same
    /// check, and the same errors, as [`decode`] (see [`validate`]).
    pub fn new(data: &'a [u8]) -> Result<View<'a>, CoreError> {
        validate(data)?;
        Ok(View { raw: data })
    }

    /// The item's whole encoding, header included: the bytes to hash or to
    /// copy into a re-encoding.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn is_list(&self) -> bool {
        is_list_prefix(self.raw)
    }

    /// Byte-string payload, or an error for a list.
    pub fn as_bytes(&self) -> Result<&'a [u8], CoreError> {
        if self.is_list() {
            return err("RLP: expected bytes, found list");
        }
        let (start, len) = header(self.raw);
        Ok(self.raw.get(start..).and_then(|p| p.get(..len)).unwrap_or_default())
    }

    /// The list's elements, walked in place, or an error for a byte string.
    pub fn as_list(&self) -> Result<ViewIter<'a>, CoreError> {
        if !self.is_list() {
            return err("RLP: expected list, found bytes");
        }
        Ok(ViewIter { list: self.raw, pos: header(self.raw).0 })
    }
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* **`View<'a>` holds one field, `raw: &'a [u8]`.** The `'a` is a name for “however long the caller's buffer lives”. The struct is two machine words (pointer and length), owns nothing, and derives `Copy`, so passing it by value is free and leaves the original usable.
- *[Lifetimes](01-primer.md#primer-lifetimes)* **Look at the return types.** `raw(&self) -> &'a [u8]` and `as_bytes(&self) -> Result<&'a [u8], _>` name `'a` explicitly. Without the annotation the result would be tied to `&self`, the borrow of the small `View` value. With it, the slice is tied to the *buffer*, and stays usable after the `View` itself has gone. Compare `Item::as_bytes` above, which must be tied to `&self` because the bytes live inside the tree.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `View::new` runs `validate` once. After that, the accessors trust the structure and read headers with the unchecked `header` helper. `.get(start..).and_then(|p| p.get(..len)).unwrap_or_default()` still cannot panic: if the impossible happens, it yields an empty slice (the default `&[u8]`).

`rust/myotis-core/src/rlp.rs` · lines 184–196

```rust
impl<'a> Iterator for ViewIter<'a> {
    type Item = View<'a>;

    fn next(&mut self) -> Option<View<'a>> {
        let rest = self.list.get(self.pos..).filter(|r| !r.is_empty())?;
        let (start, len) = header(rest);
        let raw = rest.get(..start.checked_add(len)?)?;
        self.pos += raw.len();
        Some(View { raw })
    }
}

impl core::iter::FusedIterator for ViewIter<'_> {}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **Implementing `Iterator`** takes one associated type (`type Item = View<'a>`) and one method, `next`. Every adaptor (`map`, `take`, `count`, `collect`…) then comes for free, like a Kotlin `Sequence`. Note that `Item` here is the trait's associated type, not the `rlp::Item` enum.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* `next(&mut self)` borrows the iterator only for the call, yet it returns a `View<'a>` that lives longer. That is legal because the bytes do not belong to the iterator: `self.list` is a `&'a [u8]`, and slicing it gives another `&'a [u8]`. An iterator that handed out slices of its *own* buffer could not do this.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* Each `?` on an `Option` returns `None`, ending the iteration. `FusedIterator` is a marker trait with no methods: a promise that after the first `None` every later call also returns `None`, which some adaptors use to skip a check.

*[Ownership & moves](01-primer.md#primer-ownership)* `ListBuf` (lines 198–245) is the owned counterpart. It keeps the encodings of its items back to back in one `Vec<u8>` plus a count, and `iter()` hands out a `ViewIter` over its own buffer. Here the lifetime is elided: `iter(&self) -> ViewIter<'_>` ties the views to the `ListBuf`. In this snapshot it has no users outside its own test.

#### The unchecked header reader

`rust/myotis-core/src/rlp.rs` · lines 247–268

```rust
/// `(payload offset, payload length)` of the item heading `raw`, which a
/// [`View`] has already checked: no validation here, and no panic should that
/// ever not hold (a bad header reads as an empty payload).
fn header(raw: &[u8]) -> (usize, usize) {
    let Some(&first) = raw.first() else {
        return (0, 0);
    };
    let long = |len_of_len: u8| {
        let n = usize::from(len_of_len);
        let len = raw
            .get(1..1 + n)
            .map_or(0, |b| b.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x)));
        (1 + n, len)
    };
    match first {
        0x00..=0x7f => (0, 1),
        0x80..=0xb7 => (1, usize::from(first - 0x80)),
        0xb8..=0xbf => long(first - 0xb7),
        0xc0..=0xf7 => (1, usize::from(first - 0xc0)),
        0xf8..=0xff => long(first - 0xf7),
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **`let Some(&first) = raw.first() else { return (0, 0); };`** is a let-else: bind the pattern or run the `else` block, which must leave the function. It replaces a nested `if let`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match first` uses **integer ranges**. The five arms cover all 256 values of `u8`, and the compiler proves it, so no `_` arm is needed. The same five ranges appear in `decode_item` and `skip_item`.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* The closure `long` captures `raw` by shared reference. It folds the big-endian length bytes into a `usize`, and `map_or(0, …)` gives 0 when they are missing.

#### Where the bytes become owned

`rust/myotis-core/src/rlp.rs` · lines 384–421

```rust
fn decode_item(data: &[u8], pos: usize, depth: usize) -> Result<(Item, usize), CoreError> {
    if depth > MAX_DEPTH {
        return err("RLP: nesting too deep");
    }
    let first = match data.get(pos) {
        Some(&b) => b,
        None => return err("RLP: truncated (empty input)"),
    };
    match first {
        // Single byte, value 0x00..=0x7f: the byte is its own encoding.
        0x00..=0x7f => Ok((Item::Bytes(vec![first]), pos + 1)),
        // Short string: 0-55 bytes.
        0x80..=0xb7 => {
            let len = (first - 0x80) as usize;
            let payload = slice(data, pos + 1, len)?;
            if len == 1 && payload[0] < 0x80 {
                return err("RLP: non-canonical single byte (should be encoded as itself)");
            }
            Ok((Item::Bytes(payload.to_vec()), pos + 1 + len))
        }
        // Long string: length-of-length 1-8.
        0xb8..=0xbf => {
            let (len, header) = read_long_length(data, pos, first - 0xb7)?;
            let payload = slice(data, pos + header, len)?;
            Ok((Item::Bytes(payload.to_vec()), pos + header + len))
        }
        // Short list: total payload 0-55 bytes.
        0xc0..=0xf7 => {
            let len = (first - 0xc0) as usize;
            decode_list_payload(data, pos + 1, len, depth)
        }
        // Long list.
        0xf8..=0xff => {
            let (len, header) = read_long_length(data, pos, first - 0xf7)?;
            decode_list_payload(data, pos + header, len, depth)
        }
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership)* `payload` is a temporary view into `data`. `payload.to_vec()` is the exact moment bytes are copied into the tree. The new position travels back in a tuple `(Item, usize)`, like threading an `int offset` through Java code.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `data.get(pos)` returns `Option<&u8>`, and `Some(&b)` copies the byte out. Plain `data[pos]` would panic on truncated input. The `depth` guard exists because a stack overflow aborts the process; there is no catchable `StackOverflowError`.

*[Result, ? and panics](01-primer.md#primer-error-handling)* `skip_item` (lines 469–505) is the same function with every `Item` removed: the same checks in the same order with the same error strings, returning only the end offset. `validate` (lines 289–303) is `skip_item` plus the “no trailing bytes” rule, so it accepts exactly what `decode` accepts while allocating nothing. The cost of that design is duplicated logic, which the differential tests below keep honest.

#### Zero-copy splitting, with a cap

`rust/myotis-core/src/rlp.rs` · lines 320–352

```rust
/// [`raw_list_items`], keeping only the first `max` elements. The rest are
/// still validated, so it accepts and rejects exactly what [`raw_list_items`]
/// does, but they are walked instead of collected. A peer can pack a 10 MiB
/// frame with millions of one-byte elements, so this is the call for a peer
/// list whose tail is never read.
pub fn raw_list_prefix(data: &[u8], max: usize) -> Result<Vec<&[u8]>, CoreError> {
    let first = *data.first().ok_or_else(|| CoreError("RLP: empty".into()))?;
    let (payload_start, payload_len) = match first {
        0xc0..=0xf7 => (1usize, usize::from(first - 0xc0)),
        0xf8..=0xff => {
            let (len, header) = read_long_length(data, 0, first - 0xf7)?;
            (header, len)
        }
        _ => return err("RLP: not a list"),
    };
    let end = payload_start
        .checked_add(payload_len)
        .filter(|&e| e == data.len())
        .ok_or_else(|| CoreError("RLP: list length does not match input".into()))?;
    let mut items = Vec::new();
    let mut pos = payload_start;
    while pos < end {
        let next = skip_item(data, pos, 0)?;
        if next > end {
            return err("RLP: element overruns list payload");
        }
        if items.len() < max {
            items.push(&data[pos..next]);
        }
        pos = next;
    }
    Ok(items)
}
```

- *[Lifetimes](01-primer.md#primer-lifetimes) · [Borrowing & slices](01-primer.md#primer-borrowing)* Spelled out, the signature is `fn raw_list_prefix<'a>(data: &'a [u8], max: usize) -> Result<Vec<&'a [u8]>, CoreError>`. Each element (`&data[pos..next]`) points into the caller's frame, so the caller cannot drop the frame while using the list. The eth layer does exactly that: split a response into raw headers, hash each raw slice, then copy what it keeps.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `checked_add(…).filter(…).ok_or_else(…)?` turns an overflowing or mismatched length into an `Err`. `*data.first().ok_or_else(…)?` dereferences the `&u8` to copy the byte.
- *[Protocol & domain](01-primer.md#primer-domain)* **Why `max`.** Every element is still walked and checked, but only the first `max` are kept. A `Vec` of slices costs 16 bytes per element, and a peer can pack millions of one-byte elements into one frame. `raw_list_items(data)` (line 316) is simply `raw_list_prefix(data, usize::MAX)`. `myotis-wire`'s gossip handlers call it with a cap ([stop 5](05-wire.md)).

*[Borrowing & slices](01-primer.md#primer-borrowing)* `slice` (lines 524–529) is where sub-views are cut for the decoder. Its guard `Some(end) if end <= data.len()` makes the indexing `&data[start..end]` provably in bounds.

#### Differential tests

`rust/myotis-core/src/rlp.rs` · lines 661–681

```rust
#[test]
fn skip_item_agrees_with_decode_item() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    each_differential_input(|input| {
        // Every offset of a short input; the start and a few random
        // offsets of a long one (all of them would be quadratic).
        let mut offsets: Vec<usize> = if input.len() <= 64 {
            (0..=input.len()).collect()
        } else {
            (0..8).map(|_| rng.below(input.len())).collect()
        };
        offsets.push(0);
        for pos in offsets {
            assert_eq!(
                skip_item(input, pos, 0),
                decode_item(input, pos, 0).map(|(_, end)| end),
                "input {input:02x?} at offset {pos}"
            );
        }
    });
}
```

- *[Tests](01-primer.md#primer-testing) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `each_differential_input(|input| { … })` takes a closure of type `impl FnMut(&[u8])` and calls it on about 100,000 inputs: every string of up to two bytes, nesting either side of `MAX_DEPTH`, the shared EL corpus, and seeded random trees with truncations and header mutations. `FnMut` because the closures mutate captured state (`rng` here, counters in `validate_agrees_with_decode`).
- *[Tests](01-primer.md#primer-testing) · [Result, ? and panics](01-primer.md#primer-error-handling)* `decode_item(…).map(|(_, end)| end)` turns `Result<(Item, usize), _>` into `Result<usize, _>`, dropping the tree. Comparing two `Result`s with `assert_eq!` compares the error messages too, so the two walkers must fail with the same text, not just both fail.
- *[Tests](01-primer.md#primer-testing)* `validate_agrees_with_decode` (lines 683–693) ends with `assert!(accepted > 5_000 && rejected > 5_000)`. A differential test whose inputs were all rejected would pass while checking nothing; this line makes it fail instead.

`rust/myotis-core/src/rlp.rs` · lines 887–912

```rust
/// Every `.rlp` and `.bin` file under `rust/testdata/el` (not all of them
/// are well-formed RLP, which suits a differential test). Reading them
/// takes `std`: the no_std test run (no-std-canary.yml) gets only the
/// generated inputs, and the std run replays the corpus as well.
#[cfg(not(feature = "std"))]
fn corpus_files() -> Vec<Vec<u8>> {
    Vec::new()
}

#[cfg(feature = "std")]
fn corpus_files() -> Vec<Vec<u8>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/el");
    let mut out = Vec::new();
    let mut dirs = vec![root];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                dirs.push(path);
            } else if matches!(path.extension().and_then(|e| e.to_str()), Some("rlp" | "bin")) {
                out.push(std::fs::read(&path).expect("read corpus file"));
            }
        }
    }
    out
}
```

*[Crates, modules & features](01-primer.md#primer-modules-cargo) · [Tests](01-primer.md#primer-testing)* **Feature gating inside a file.** Two functions with the same name, each behind an opposite `#[cfg]`, so exactly one exists in any build. The `std` one reads files with `std::fs`; the `no_std` one returns nothing, and the generated inputs still run. The `while let Some(dir) = dirs.pop()` loop walks directories with an explicit stack instead of recursion, and `let Ok(entries) = … else { continue };` skips an unreadable directory. `env!("CARGO_MANIFEST_DIR")` is expanded at compile time to the crate's directory.

<a id="f-myotis-core-src-nodekey-rs"></a>

### myotis-core/src/nodekey.rs

*library · 203 lines · Java twin · core.crypto.NodeKey*

The node's secp256k1 identity, built from caller-supplied secret bytes. It provides the 64-byte public key and `nodeId = keccak256(pubkey)`, signing of 32-byte prehashes as `r ‖ s ‖ v` (low-s, RFC 6979), public-key recovery, raw ECDH (the X coordinate, no KDF), and SEC1 compression. discv4, RLPx, ENR handling and `tor-poc` all use it. Unchanged since September apart from one `alloc` import.

`rust/myotis-core/src/nodekey.rs` · lines 23–37

```rust
/// secp256k1 identity key pair.
pub struct NodeKey {
    signing: SigningKey,
    /// Cached uncompressed public key, without the 0x04 prefix.
    pubkey64: [u8; 64],
}

impl NodeKey {
    /// Build from a 32-byte secret. Rejects zero / out-of-range scalars.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<NodeKey, CoreError> {
        let signing = SigningKey::from_bytes(secret.into())
            .map_err(|_| CoreError("secp256k1: invalid secret scalar".into()))?;
        let pubkey64 = encode_uncompressed(signing.verifying_key());
        Ok(NodeKey { signing, pubkey64 })
    }
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Invariant through privacy.** The fields are private and the only constructor validates the scalar, so every `NodeKey` in existence is valid. The type derives nothing: it cannot be `Clone`d or printed with `{:?}`. The file does not say why.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `.map_err(|_| CoreError(…))?` converts k256's error type into this crate's, then propagates it.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `secret: &[u8; 32]` puts the length in the type, so a 31-byte input is a compile error rather than a runtime check. `secret.into()` converts that array reference into k256's own fixed-size byte type.

`rust/myotis-core/src/nodekey.rs` · lines 95–100

```rust
pub fn recover_public_key(hash: &[u8; 32], sig65: &[u8; 65]) -> Result<[u8; 64], CoreError> {
    let recid = match sig65[64] {
        v @ 0..=1 => RecoveryId::from_byte(v)
            .ok_or_else(|| CoreError("secp256k1: bad recovery id".into()))?,
        v => return err(format!("secp256k1: recovery id {v} out of range")),
    };
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `v @ 0..=1` matches a range and binds the matched value to `v`. The `match` is an expression producing `recid`, yet each arm can still leave the function (`?` or `return`). `sig65[64]` cannot panic, because the type guarantees 65 bytes.

<a id="f-myotis-core-src-header-rs"></a>

### myotis-core/src/header.rs

*library · 373 lines · Java twin · core.types.BlockHeader*

Decodes an execution block header. The 15 mandatory fields come first, then the optional fork fields are read *by what remains in the list*, not by fork detection. `requestsHash` must be a byte string and is then discarded. Since September the decoder also reads Amsterdam's `blockAccessListHash` and `slotNumber` when they are well-formed, and tolerates anything after them. `hash()` always hashes the **raw** bytes as received; `encode()` re-encodes only the fields through `parentBeaconBlockRoot`.

`rust/myotis-core/src/header.rs` · lines 25–63

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockHeader {
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    /// 20 bytes on every real header (length not enforced, matching Java).
    pub beneficiary: Vec<u8>,
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    /// 256 bytes on every real header (length not enforced, matching Java).
    pub logs_bloom: Vec<u8>,
    /// Minimal big-endian scalar (empty = zero, the post-Merge value).
    pub difficulty: Vec<u8>,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash_or_prev_randao: [u8; 32],
    /// 8 bytes on every real header (length not enforced, matching Java).
    pub nonce: Vec<u8>,
    /// EIP-1559; `None` pre-London. Minimal big-endian scalar.
    pub base_fee_per_gas: Option<Vec<u8>>,
    /// EIP-4895; `None` pre-Shanghai.
    pub withdrawals_root: Option<[u8; 32]>,
    /// EIP-4844; `None` pre-Cancun (Java uses a -1 sentinel).
    pub blob_gas_used: Option<u64>,
    /// EIP-4844; `None` pre-Cancun.
    pub excess_blob_gas: Option<u64>,
    /// EIP-4788; `None` pre-Cancun.
    pub parent_beacon_block_root: Option<[u8; 32]>,
    /// EIP-7928 (Amsterdam): keccak of the block access list; `None` before
    /// Amsterdam. Rust-only: the Java twin never reads past requestsHash.
    pub block_access_list_hash: Option<[u8; 32]>,
    /// EIP-7843 (Amsterdam): the beacon slot of this block, which the SLOTNUM
    /// opcode returns; `None` before Amsterdam (or when the pair after
    /// requestsHash isn't well-formed — see [`BlockHeader::decode`]). Rust-only.
    pub slot_number: Option<u64>,
}
```

- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* Three storage choices appear in the struct: `[u8; 32]` for roots (inline), `Vec<u8>` for big scalars kept as minimal big-endian bytes (Java uses `BigInteger`), and `Option<…>` for fork-dependent fields, where Java uses a `-1` sentinel.
- *[Macros & attributes](01-primer.md#primer-macros) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* The struct derives `Debug, Clone, PartialEq, Eq, Default` (line 25). `Default` gives a zeroed header, and the tests use it with struct-update syntax, `..BlockHeader::default()` (line 284), to fill the fields they do not name.
- *[Protocol & domain](01-primer.md#primer-domain)* `slot_number` is the beacon slot that the EVM's `SLOTNUM` opcode returns. Its doc says the EVM refuses an Amsterdam block whose slot is `None` rather than guessing.

`rust/myotis-core/src/header.rs` · lines 73–101

```rust
pub fn decode(rlp_bytes: &[u8]) -> Result<BlockHeader, CoreError> {
    Self::decode_view(rlp::View::new(rlp_bytes)?)
}

/// [`BlockHeader::decode`] of an already-checked item, such as one header
/// of a peer's BlockHeaders response. The fields are read in place, and
/// fields past the ones understood are walked, never built (#454).
pub fn decode_view(top: rlp::View<'_>) -> Result<BlockHeader, CoreError> {
    let mut f = top.as_list()?;
    let count = f.clone().take(15).count();
    if count < 15 {
        return err(format!("header: expected >= 15 RLP fields, got {count}"));
    }
    // The 15 always-present fields.
    let parent_hash = fixed32(f.next(), "parentHash")?;
    let ommers_hash = fixed32(f.next(), "ommersHash")?;
    let beneficiary = any_bytes(f.next(), "beneficiary")?;
    let state_root = fixed32(f.next(), "stateRoot")?;
    let transactions_root = fixed32(f.next(), "transactionsRoot")?;
    let receipts_root = fixed32(f.next(), "receiptsRoot")?;
    let logs_bloom = any_bytes(f.next(), "logsBloom")?;
    let difficulty = scalar_bytes(f.next(), "difficulty")?;
    let number = u64_field(f.next(), "number")?;
    let gas_limit = u64_field(f.next(), "gasLimit")?;
    let gas_used = u64_field(f.next(), "gasUsed")?;
    let timestamp = u64_field(f.next(), "timestamp")?;
    let extra_data = any_bytes(f.next(), "extraData")?;
    let mix_hash_or_prev_randao = fixed32(f.next(), "mixHash")?;
    let nonce = any_bytes(f.next(), "nonce")?;
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* **Two doors, one implementation.** `decode(&[u8])` builds a `View` and calls `decode_view`. A caller that already holds a checked `View`, such as one header inside a peer's `BlockHeaders` response, calls `decode_view` directly and skips a second validation. `rlp::View<'_>` says “a view of some buffer; the name of its lifetime does not matter here”.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `let mut f = top.as_list()?;` is a `ViewIter` used as a cursor: each `f.next()` yields the next field, and once the list ends, the optional fields become `None`. `f.clone().take(15).count()` counts up to 15 fields on a *copy* of the cursor, so `f` itself has not moved. `ViewIter` derives `Clone` but not `Copy`, the usual choice for iterators, so a copy is always visible in the source.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Lifetimes](01-primer.md#primer-lifetimes)* **The header copies every field.** `BlockHeader` has no lifetime parameter, so it can hold only owned data. It cannot keep the `&'a [u8]` slices the view hands out, and the helpers copy each field into an array or a `Vec`. This is a choice: a `BlockHeader<'a>` would avoid the copies but could never outlive the frame it came from.

`rust/myotis-core/src/header.rs` · lines 139–147

```rust
let block_access_list_hash = f.next().and_then(|it| it.as_fixed_bytes(32).ok()).map(|b| {
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    out
});
let slot_number = match block_access_list_hash {
    Some(_) => f.next().and_then(|it| it.as_u64().ok()),
    None => None,
};
```

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Result, ? and panics](01-primer.md#primer-error-handling)* **Tolerant by design.** `Option` combinators instead of `?`: `f.next()` may be `None`, `.and_then(|it| it.as_fixed_bytes(32).ok())` turns a wrong-sized field into `None` too, and `.map(|b| …)` copies the 32 bytes out. Nothing here can return an error. The comment above (lines 129–138) explains why: everything after `requestsHash` must stay tolerated, as the corpus vector `006-header-future-extra` pins. The slot is read only when a 32-byte hash came first.

`rust/myotis-core/src/header.rs` · lines 219–227

```rust
fn fixed32(item: Option<rlp::View<'_>>, name: &str) -> Result<[u8; 32], CoreError> {
    let it = item.ok_or_else(|| CoreError(format!("header: missing field {name}")))?;
    let b = it
        .as_fixed_bytes(32)
        .map_err(|e| CoreError(format!("header: {name}: {}", e.0)))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Ownership & moves](01-primer.md#primer-ownership)* `ok_or_else` turns the `Option` into a `Result` so `?` can bail. `b` is a slice of the caller's input, and `copy_from_slice` copies it into an array this function owns and returns by value. The `encode` method (lines 176–216) drops `requestsHash` and the Amsterdam pair rather than shifting them, so a re-encode matches the input only for pre-Prague headers; its doc says so, and the test on line 316 asserts the hashes differ.

<a id="f-myotis-core-src-enr-rs"></a>

### myotis-core/src/enr.rs

*library · 264 lines · Java twin · core.enr.Enr*

Decodes Ethereum Node Records (EIP-778) from `enr:` base64url text or raw RLP: sequence number, a sorted map of key/value pairs, and the raw encoding. Accessors parse ip, ports, the secp256k1 key and the consensus-layer `eth2` field. The list-valued `eth` fork id is re-parsed from the raw bytes on demand. The record signature is *not* verified here; the updated module doc explains that these records only seed dials, and that `myotis-net`'s own DNS walk uses the `enr` crate, which does verify. `base64url_decode` became public for that DNS walk.

`rust/myotis-core/src/enr.rs` · lines 157–177

```rust
pub fn eth_fork_id_hash(&self) -> Option<[u8; 4]> {
    let top = rlp::decode(&self.raw_rlp).ok()?;
    let items = top.as_list().ok()?;
    let kv = items.get(2..)?;
    for pair in kv.chunks_exact(2) {
        let key = pair[0].as_bytes().ok()?;
        if key == b"eth" {
            // eth -> [[fork_hash, fork_next], …] — first tuple, first element.
            let outer = pair[1].as_list().ok()?;
            let tuple = outer.first()?.as_list().ok()?;
            let fork_hash = tuple.first()?.as_bytes().ok()?;
            if fork_hash.len() >= 4 {
                let mut out = [0u8; 4];
                out.copy_from_slice(&fork_hash[0..4]);
                return Some(out);
            }
            return None;
        }
    }
    None
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling)* A chain of `.ok()?`: every `Result` becomes an `Option`, and any malformed piece yields `None`. There is not a single `if` for error handling.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `items.get(2..)?` is the panic-free form of `&items[2..]`. Every variable here (`kv`, `pair`, `outer`, `tuple`, `fork_hash`) is a view into the local tree `top`. Only the final 4 bytes are copied out into an owned array, and `top` is dropped when the function returns.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* In `decode` (line 70), `String::from_utf8_lossy` returns a `Cow<str>`, “clone on write”: borrowed if the bytes were valid UTF-8, owned only if characters had to be replaced. `.into_owned()` then forces a `String`. The map is a `BTreeMap`, imported from `alloc::collections`.

`rust/myotis-core/src/enr.rs` · lines 185–195

```rust
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, CoreError> {
    let trimmed = input.trim_end_matches('=');
    let pad = input.len() - trimmed.len();
    let valid_padding = match (trimmed.len() % 4, pad) {
        (_, 0) => true, // unpadded (the ENR convention)
        (2, 2) | (3, 1) => true,
        _ => false,
    };
    if !valid_padding {
        return err("ENR: malformed base64url padding");
    }
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* Matching on a tuple, `match (trimmed.len() % 4, pad)`, checks two values at once. `(_, 0)` accepts any length without padding; `(2, 2) | (3, 1)` are the only correct padded shapes. The rest of the function (to line 220) decodes six bits per character into a `u32` buffer and emits a byte whenever eight bits are ready.

<a id="f-myotis-core-src-forkid-rs"></a>

### myotis-core/src/forkid.rs

*library · 296 lines · Java twin · NetworkConfig fork-id pins / ForkIds*

EIP-2124 fork ids. Every node announces a 4-byte fork hash (a CRC32 over the genesis hash and every past fork's activation) and a `forkNext`, and peers disconnect on a mismatch. myotis does not compute its hash from genesis. It **pins** one per network (mainnet, gnosis, chiado, sepolia, lines 29–46) together with the one next fork it knows. What changed since September is that the CRC32 arithmetic now lives here too, for two narrow jobs: stepping the pin across that one known fork (`fork_id_at`), and, for `myotis-net`'s fork watch, recovering the activation that would turn our hash into a peer's unknown one (`activation_of`).

`rust/myotis-core/src/forkid.rs` · lines 69–80

```rust
/// The fork id `(hash, next)` in effect at `now` for a build pinned to
/// `pinned_hash` that knows one more timestamp fork at `pinned_next`: announced
/// ahead of time (EIP-2124 lets upgraded peers keep us), then folded into the
/// hash once it passes. A block-number `pinned_next` never switches — every
/// live fork is timestamped. Twin: Java `ForkIds.effective`.
pub fn fork_id_at(pinned_hash: u32, pinned_next: u64, now: u64) -> (u32, u64) {
    if pinned_next >= TIMESTAMP_THRESHOLD && now >= pinned_next {
        (successor(pinned_hash, pinned_next), 0)
    } else {
        (pinned_hash, pinned_next)
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain)* Sepolia's `SEPOLIA_FORK_NEXT` is Amsterdam at 2026-10-06 13:53:36 UTC, so a Sepolia node has announced the successor hash since then (the doc on line 45 gives it as `0x6c1d9423`), while mainnet, gnosis and chiado have `forkNext = 0` and keep their pins. Activation values below `TIMESTAMP_THRESHOLD` are block numbers and never switch here.

`rust/myotis-core/src/forkid.rs` · lines 87–123

```rust
/// IEEE CRC32 table (reflected polynomial 0xEDB88320), built at compile time.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

/// CRC32 of `data` continued from the checksum `crc` (0 = a fresh CRC) — the
/// resumable form `java.util.zip.CRC32` lacks (twin: Java `ForkIds.update`).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The fork hash in effect once a fork activating at `activation` has passed,
/// given the hash `hash` in effect before it (EIP-2124: CRC32 continued over
/// the big-endian uint64 activation value).
pub fn successor(hash: u32, activation: u64) -> u32 {
    crc32_update(hash, &activation.to_be_bytes())
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* **Computed at compile time.** A `const` initialiser is evaluated by the compiler, and the 256-entry table ends up as data in the binary, like a Java `static final` array that needs no static initialiser. Const evaluation allows `while` but not `for`, because a `for` loop calls `Iterator::next`, a trait method that cannot run at compile time. Hence the hand-counted `n` and `k`.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `!crc` is bitwise NOT on an integer (Java's `~`). `b as u32` widens a byte. `activation.to_be_bytes()` gives the 8 big-endian bytes EIP-2124 feeds into the CRC.
- *[Protocol & domain](01-primer.md#primer-domain)* The comment on `crc32_update` names the point: it resumes from a previous checksum, which `java.util.zip.CRC32` cannot do. So the hash after a fork follows from the hash before it plus the activation alone.

`rust/myotis-core/src/forkid.rs` · lines 143–160

```rust
pub fn activation_of(hash: u32, next: u32) -> u64 {
    let mut a = !hash;
    for _ in 0..4 {
        a = CRC32_TABLE[(a & 0xff) as usize] ^ (a >> 8); // be64(T)'s zero high bytes
    }
    let mut z = !next;
    let mut idx = [0u8; 4];
    for slot in idx.iter_mut().rev() {
        *slot = TOP_INDEX[(z >> 24) as usize];
        z = (z ^ CRC32_TABLE[usize::from(*slot)]) << 8;
    }
    let mut t = 0u64;
    for i in idx {
        t = (t << 8) | u64::from((a ^ u32::from(i)) & 0xff);
        a = CRC32_TABLE[usize::from(i)] ^ (a >> 8);
    }
    t
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Running CRC32 backwards.** One CRC step is `new = T[idx] ^ (old >> 8)`. The top byte of `old >> 8` is zero, so the top byte of `new` is the top byte of `T[idx]`, and the 256 table entries all have distinct top bytes (`TOP_INDEX`, lines 125–135). So the target fixes each step's table index. The first loop feeds the four zero high bytes of a 32-bit activation; the second walks the target back four steps to learn the indices; the third picks each activation byte so that `(a ^ byte) & 0xff` lands on its index.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `for slot in idx.iter_mut().rev()` yields `&mut u8` references into the array, last to first, and `*slot = …` writes through each one.

> [!WARNING]
> **A placement is not proof**<br>
>
> The module doc (lines 22–23) and the test `every_hash_places_somewhere_so_a_placement_is_not_proof` make the limit explicit: every 32-bit hash has exactly one activation below 232 that produces it. Inverting a peer's hash tells you *where* a fork would have to be, not that one exists. The test's comment adds that the fork watch votes by network and weighs dissent instead of trusting one placement.

<a id="f-myotis-core-src-trie-rs"></a>

### myotis-core/src/trie.rs

*library · 525 lines · Java twin · MerklePatriciaProofVerifier + HexPrefix*

Verifies Merkle-Patricia proofs. This is the state trust anchor for everything snap peers serve. Input: a trusted root, the un-hashed key (callers pass `keccak(address)` or `keccak(slot)`), and a peer's node list. Output: `Found(value)`, `Absent` or `Invalid(reason)`. It never panics and never returns `Err`. The walk is *iterative*, unlike the recursive Java one, so a hostile proof cannot grow the stack. New since September: `verify_proof_path` also returns the nodes the walk visited, root first, in the shape `eth_getProof` (EIP-1186) lists them. The file also decodes verified account and storage leaves; per its docs, it is “THE ONLY legitimate source of `storage_root`/`code_hash`”.

| Lines | What happens |
|---|---|
| 1–34 | Docs; the well-known empty-trie and empty-code roots. |
| 36–73 | `ProofResult`, `verify_proof` and `verify_proof_path`, two thin wrappers around one walk. |
| 75–155 | `walk`: hash index of nodes, bounded iterative descent, a `visit` callback. |
| 157–211 | `AccountLeaf`, `decode_account_leaf`, `decode_storage_leaf`. Stricter than Java: leading-zero scalars are rejected. |
| 213–315 | `enum Step` and `interpret` / `interpret_branch` / `interpret_short`. |
| 317–374 | Hex-prefix helpers and `to_nibbles` (`pub(crate)`, reused by `triehash`). |
| 376–525 | Tests, including the proof-path shapes. |

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Result, ? and panics](01-primer.md#primer-error-handling)* `ProofResult` (lines 36–46) is an error-as-data sum type, like a Kotlin sealed class with three subclasses. Callers must handle all three outcomes, and there is no exception path at all.

`rust/myotis-core/src/trie.rs` · lines 62–73

```rust
pub fn verify_proof_path(
    root: &[u8; 32],
    key: &[u8],
    proof_nodes: &[Vec<u8>],
) -> (ProofResult, Vec<Vec<u8>>) {
    let mut path = Vec::new();
    let result = walk(root, key, proof_nodes, |node| path.push(node.to_vec()));
    if matches!(result, ProofResult::Invalid(_)) {
        path.clear();
    }
    (result, path)
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Borrowing & slices](01-primer.md#primer-borrowing)* **A closure that borrows mutably.** `walk` takes `mut visit: impl FnMut(&[u8])`. `verify_proof` passes `|_| {}`, which does nothing. Here the closure `|node| path.push(node.to_vec())` captures `path` by *mutable* borrow, so while `walk` runs nobody else may touch `path`. The closure is a temporary argument, dropped when `walk` returns, which ends the borrow and makes `path.clear()` legal on the next line. A Java lambda cannot assign a captured local at all; it would mutate a list object instead, and nothing would stop two parties mutating it at once.
- *[Ownership & moves](01-primer.md#primer-ownership)* `node.to_vec()` copies each visited node: the path outlives the borrowed `proof_nodes`, so it must own its bytes. Only nodes looked up by hash are visited, so an embedded child stays inside its parent, which the doc compares to geth's `trie.Prove`.

`rust/myotis-core/src/trie.rs` · lines 113–155

```rust
    let mut expected_hash = *root;
    let mut idx = 0usize;
    let mut lookups = 0usize;
    loop {
        lookups += 1;
        if lookups > by_hash.len() {
            return ProofResult::Invalid(
                "proof walk exceeded the supplied node count (cycle)".into(),
            );
        }
        let node_rlp = match by_hash.get(&expected_hash) {
            Some(n) => *n,
            None => {
                return ProofResult::Invalid(format!(
                    "missing node {} (path idx={idx})",
                    hex32(&expected_hash)
                ))
            }
        };
        visit(node_rlp);
        let item = match rlp::decode(node_rlp) {
            Ok(it) => it,
            Err(e) => return ProofResult::Invalid(format!("malformed node RLP: {}", e.0)),
        };
        // Interpret this node, following embedded children in-line until we
        // either terminate or reach the next hash reference.
        let mut current = item;
        loop {
            match interpret(&current, &path, idx) {
                Step::Done(result) => return result,
                Step::Hash(h, new_idx) => {
                    expected_hash = h;
                    idx = new_idx;
                    break; // back to the by-hash lookup
                }
                Step::Embedded(child, new_idx) => {
                    current = child;
                    idx = new_idx;
                }
            }
        }
    }
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* The index above this excerpt (lines 97–100) is a `BTreeMap<[u8; 32], &[u8]>`. The *keys* are owned arrays, compared by content. The *values* are views into `proof_nodes`, so no node bytes are copied, and the map cannot outlive the node list. A Java `HashMap<byte[], byte[]>` would compare keys by identity, which is a classic bug.
- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Why `BTreeMap`?** In September this was a `HashMap`. `HashMap` exists only in `std`, since its default hasher is seeded from OS randomness, and the `no_std` build forbids it. A sorted tree map lives in `alloc`. For the handful of nodes in a proof, its O(log n) lookup costs nothing noticeable.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `by_hash.get(&expected_hash)` returns `Option<&&[u8]>`, a reference to the stored reference. `Some(n) => *n` copies the inner `&[u8]`, which is cheap because shared references are `Copy`.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* **The owned state machine.** `interpret(&current, …)` borrows `current` only for the call and returns an *owned* `Step`. So `current = child;` is legal, and it drops the old subtree. If `Step::Embedded` held a *reference* into `current`, the assignment would be rejected. That is why the child is cloned:

`rust/myotis-core/src/trie.rs` · lines 242–266

```rust
fn interpret_branch(items: &[Item], path: &[u8], idx: usize) -> Step {
    if idx == path.len() {
        // Path exhausted; the value lives at slot 16. (Java parity: a list in
        // the value slot passes through as its raw encoding.)
        return Step::Done(match &items[16] {
            Item::Bytes(v) if v.is_empty() => ProofResult::Absent,
            Item::Bytes(v) => ProofResult::Found(v.clone()),
            it @ Item::List(_) => ProofResult::Found(rlp::encode(it)),
        });
    }
    let nibble = (path[idx] & 0x0f) as usize;
    match &items[nibble] {
        it @ Item::List(_) => Step::Embedded(it.clone(), idx + 1),
        Item::Bytes(child) if child.is_empty() => Step::Done(ProofResult::Absent),
        Item::Bytes(child) if child.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(child);
            Step::Hash(h, idx + 1)
        }
        Item::Bytes(child) => Step::Done(ProofResult::Invalid(format!(
            "branch child {nibble} is {} bytes; expected 32-byte hash or embedded list",
            child.len()
        ))),
    }
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `it @ Item::List(_)` binds the whole matched value to `it`. `Item::Bytes(child) if child.is_empty()` is a *guard*. Arms are tried top to bottom, so the unguarded `Item::Bytes(child)` at the end catches every remaining length. `it.clone()` produces an independent subtree the loop can own.

> [!WARNING]
> **Design decision**<br>
>
> The `lookups` counter guarantees termination structurally, even though a keccak cycle is cryptographically infeasible (the comment on lines 107–112 says so). When the consequence of a bug is an app abort or a hang, the code prefers guarantees it can see to arguments it has to trust.

<a id="f-myotis-core-src-triehash-rs"></a>

### myotis-core/src/triehash.rs

*library · 144 lines · Java twin · consensus.proof.OrderedTrieRoot*

Builds an ordered trie root bottom-up, with keys `RLP(index)` (not hashed). This is how a block's `transactionsRoot` and `receiptsRoot` are checked against a trusted header without trusting the peer that served the body or receipts. Children under 32 bytes are inlined; larger ones are referenced by hash. Since September it accepts any iterator of slices instead of a `&[Vec<u8>]`.

`rust/myotis-core/src/triehash.rs` · lines 21–36

```rust
pub fn ordered_trie_root<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut entries: Vec<(Vec<u8>, &[u8])> = items
        .into_iter()
        .enumerate()
        .map(|(i, v)| {
            let key = rlp::encode_bytes(&rlp::u64_to_minimal_be(i as u64));
            (to_nibbles(&key), v)
        })
        .collect();
    if entries.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    // Trie shape follows key-nibble order, not insertion order.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    keccak256(&build_node(&entries, 0))
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Lifetimes](01-primer.md#primer-lifetimes)* **`items: impl IntoIterator<Item = &'a [u8]>`** accepts anything that can be iterated into byte slices, such as an array of slices or `vec.iter().map(Vec::as_slice)`. The caller no longer has to build a `Vec<Vec<u8>>` first, which would copy every transaction. The named `'a` lets the slices be stored in `entries`.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `Vec<(Vec<u8>, &[u8])>` pairs a freshly *owned* nibble key with a *borrowed* item, so no transaction bytes are copied while building.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `into_iter().enumerate().map(|(i, v)| …).collect()` is a Kotlin `mapIndexed`. `sort_by(|a, b| a.0.cmp(&b.0))` sorts by key because the trie shape follows nibble order, not index order: `RLP(0) = 0x80` sorts after `RLP(1..=127)`. The empty check moved after `collect`, because an `IntoIterator` does not tell its length up front.

`rust/myotis-core/src/triehash.rs` · lines 56–65

```rust
// Branch node: 16 child slots + a value slot (key ending exactly here).
let mut branch_value: &[u8] = &[];
let mut groups: [Vec<(Vec<u8>, &[u8])>; 16] = Default::default();
for (path, value) in entries {
    if path.len() == depth {
        branch_value = value;
    } else {
        groups[path[depth] as usize].push((path.clone(), value));
    }
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* `let mut branch_value: &[u8] = &[];` starts as an empty `'static` slice. `Default::default()` builds an array of 16 empty `Vec`s. Keys are `clone`d into the groups because each group owns its entries, while values stay borrowed. The doc on lines 18–20 adds a warning: it allocates per item, so callers must bound how many items a peer can hand it.

<a id="f-myotis-core-src-bloom-rs"></a>

### myotis-core/src/bloom.rs

*library · 103 lines · Java twin · ReceiptsMessage bloom accrual*

The 2048-bit logs bloom. Each log address and topic sets three bits chosen by its keccak hash. eth/69 receipts arrive *without* a bloom, so it is recomputed from the logs before the receipt can be re-encoded for the `receiptsRoot` check. `may_contain` is the dual probe the `eth_getLogs` indexer uses to skip blocks: `false` means definitely absent, `true` means maybe. New since September: `BloomProbe`, which computes an item's three bits once.

`rust/myotis-core/src/bloom.rs` · lines 36–56

```rust
/// [`may_contain`] with the item's three bits computed once: for a caller that
/// probes one item against many blooms, so each probe costs no Keccak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BloomProbe([usize; 3]);

impl BloomProbe {
    /// The bits [`accrue`] would set for `item`.
    pub fn of(item: &[u8]) -> Self {
        let h = keccak256(item);
        let mut bits = [0usize; 3];
        for (k, i) in (0..6).step_by(2).enumerate() {
            bits[k] = ((usize::from(h[i]) << 8) | usize::from(h[i + 1])) & 0x7ff;
        }
        BloomProbe(bits)
    }

    /// [`may_contain`]'s answer for the item this probe was made of.
    pub fn may_match(&self, bloom: &LogsBloom) -> bool {
        self.0.iter().all(|&bit| bloom[255 - bit / 8] & (1 << (bit % 8)) != 0)
    }
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Methods & self](01-primer.md#primer-methods)* `BloomProbe([usize; 3])` is a tuple struct around three bit positions, and it derives `Copy`: 24 bytes, no heap. `BloomProbe::of(item)` hashes once; `may_match(&self, bloom)` then costs three bit tests. `myotis-net`'s address-activity code (`el/activity.rs`) keeps two probes per watched address, one for the address as a log's emitter and one for it as an indexed topic, and tests blooms against them.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `(0..6).step_by(2).enumerate()` yields `(0, 0), (1, 2), (2, 4)`: the probe slot and the hash offset. `self.0.iter().all(|&bit| …)` short-circuits at the first unset bit; the `&bit` pattern copies each `usize` out of the reference.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `type LogsBloom = [u8; 256]` (line 10) is only an alias, not a new type. `accrue(bloom: &mut LogsBloom, …)` (lines 18–24) modifies the caller's array in place.

`rust/myotis-core/src/bloom.rs` · lines 62–72

```rust
#[test]
fn accrue_sets_at_most_three_bits() {
    let mut bloom = EMPTY_BLOOM;
    accrue(&mut bloom, b"myotis");
    let bits: u32 = bloom.iter().map(|b| b.count_ones()).sum();
    assert!((1..=3).contains(&bits));
    // Idempotent: accruing the same item again changes nothing.
    let snapshot = bloom;
    accrue(&mut bloom, b"myotis");
    assert_eq!(bloom, snapshot);
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* `let snapshot = bloom;` **copies** all 256 bytes, because arrays of `Copy` elements are `Copy`. The final assertion is meaningful for exactly that reason. The same line in Java would alias the array, and the test would pass vacuously. The test lends `&mut bloom` explicitly at each call.

<a id="f-myotis-core-tests-el-conformance-rs"></a>

### myotis-core/tests/el\_conformance.rs

*integration test · 262 lines · Java twin · ElCoreVectorConformanceTest*

“One corpus, two implementations, byte-identical verdicts.” The test replays `rust/testdata/el/core/` (headers, ENRs, key/sign/recover/ECDH vectors, fork-id pins) and asserts that the verdict map equals the Java-generated `expected.txt`. A missing corpus is skipped, like Java's `assumeTrue`; a present but empty oracle fails. A per-key diff is printed before the whole-map assertion, so failures are readable. Files under `tests/` are integration tests: each compiles to its own binary and sees the crate only through its public API, as `myotis_core::…`.

`rust/myotis-core/tests/el_conformance.rs` · lines 63–72

```rust
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
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `map_or` *consumes* its `Option`. `base_fee_per_gas: Option<Vec<u8>>` is not `Copy`, so line 66 first borrows it with `as_deref()` (giving `Option<&[u8]>`). Without that, the `Vec` would be moved out of `h`. `withdrawals_root: Option<[u8; 32]>` is `Copy`, so line 71 consumes a copy.

`rust/myotis-core/tests/el_conformance.rs` · lines 182–193

```rust
for net in ["mainnet", "gnosis", "sepolia", "chiado"] {
    let pin = u32::from_be_bytes(forkid::fork_id_hash(net).expect("known network"));
    let next = forkid::fork_next(net).expect("known network");
    actual.insert(format!("forkid.forkNext.{net}"), next.to_string());
    // The fork id once `next` has passed: both engines' CRC32 must agree on it.
    let after = if next == 0 {
        "none".to_string()
    } else {
        format!("{:08x}", forkid::fork_id_at(pin, next, next).0)
    };
    actual.insert(format!("forkid.afterNext.{net}"), after);
}
```

*[Tests](01-primer.md#primer-testing) · [Protocol & domain](01-primer.md#primer-domain)* New since September: chiado joins the pins, and for each network the corpus records `forkNext` and the hash once it has passed, so both engines' CRC32 must agree on the successor. `fork_id_at(pin, next, next).0` evaluates “now” at exactly the activation time and takes the first tuple field.

<a id="f-myotis-core-tests-el-mpt-conformance-rs"></a>

### myotis-core/tests/el\_mpt\_conformance.rs

*integration test · 185 lines · Java twin · ElMptVectorConformanceTest*

The same golden-corpus technique for the trie code (`rust/testdata/el/mpt/`). It replays proof vectors through `verify_proof`, decodes the account and storage leaves chosen by file name, and pins ordered-trie roots and bloom accruals. Its `match` on `ProofResult` (lines 51–77) moves the `Vec` out of `Found(value)` and ignores the reason in `Invalid(_)`: only the verdict class is pinned, since error messages differ between languages. Lines are read as `Vec<&str>` views into the file text. The only change since September is the call shape of `ordered_trie_root`: `[&b"myotis-tx-0"[..]]` or `spanning.iter().map(Vec::as_slice)` (lines 81–97), where `Vec::as_slice` is a method used as a function value.

*[Tests](01-primer.md#primer-testing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)*

<a id="f-myotis-core-tests-rlp-alloc-bound-rs"></a>

### myotis-core/tests/rlp\_alloc\_bound.rs

*integration test · 135 lines*

New since September. The regression test for #454: a 492 KB snappy frame decompressed to a 10 MiB list of one-byte elements, and building its tree cost 547 MB of heap in about ten million allocations (module doc, lines 1–4). The test installs a counting allocator and asserts that `validate`, `raw_list_items` on a nested list and `raw_list_prefix` allocate (almost) nothing on a list of just under 10 MiB. A control test first proves the counter works: an owned `decode` of 4,096 elements must show at least 4,096 allocations.

`rust/myotis-core/tests/rlp_alloc_bound.rs` · lines 14–55

```rust
thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Counts every allocation and reallocation made on the calling thread.
struct Counting;

fn note(bytes: usize) {
    // `try_with`: allocations can happen while the thread's locals are torn down.
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
    let _ = BYTES.try_with(|n| n.set(n.get() + bytes));
}

// SAFETY: every call is forwarded unchanged to `System`, which upholds the
// `GlobalAlloc` contract; the counters are const-initialised thread-locals
// without destructors, so touching them never allocates or re-enters.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// `(allocations, bytes requested)` made by `f` on this thread, and its result.
fn counted<T>(f: impl FnOnce() -> T) -> (usize, usize, T) {
    let (a0, b0) = (ALLOCATIONS.with(Cell::get), BYTES.with(Cell::get));
    let out = f();
    (ALLOCATIONS.with(Cell::get) - a0, BYTES.with(Cell::get) - b0, out)
}
```

- *[unsafe & FFI](01-primer.md#primer-unsafe-ffi)* **Replacing the allocator.** `#[global_allocator]` on a `static` makes every heap allocation in the binary go through `Counting`. That is why this test lives in its own file: each file under `tests/` is a separate binary, so the counting allocator does not slow the other tests. `GlobalAlloc` is an `unsafe trait`: the compiler trusts an implementation to return valid memory and cannot check it, so the implementer writes `unsafe impl` and a `SAFETY:` comment saying why the contract holds. Here every call is forwarded to `System`, the platform allocator. See [the primer](01-primer.md#primer-unsafe-ffi).
- *[Interior mutability](01-primer.md#primer-interior-mutability) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* **Per-thread counters.** `thread_local!` gives each thread its own `Cell<usize>`, so tests running in parallel threads do not see each other's allocations. A `Cell` allows `set` through a shared reference without a lock, which is safe because a thread-local is never shared. The `const { Cell::new(0) }` initialiser avoids lazy setup, which could itself allocate inside the allocator. Java's `ThreadLocal<Long>` is the closest twin.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `try_with` instead of `with`: during thread teardown the locals may already be gone, and `try_with` returns an error there instead of panicking. `let _ =` discards it on purpose.
- *[Iterators & closures](01-primer.md#primer-iterators-closures) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* `counted<T>(f: impl FnOnce() -> T)` runs the closure once and returns the counter differences with its result. `FnOnce` is the most permissive closure bound, since a closure called once may even move what it captured. `ALLOCATIONS.with(Cell::get)` passes the method `Cell::get` as the function to apply.

## Checkpoint

13 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-core-q1"></a>

**Q1** · Multiple choice

`rlp::decode` returns an `Item` (no lifetime); `rlp::raw_list_items` returns `Vec<&[u8]>`. What does each mean for the caller's input buffer?

- **A.** Both require the buffer to stay alive
- **B.** Both copy the buffer
- **C.** `Item` owns copies, so the buffer may be dropped immediately; the slices borrow the buffer, so it must stay alive and unmodified while they are used
- **D.** `Item` borrows the buffer; the slices own copies

[Answer →](answers.md#a-core-q1)

<a id="q-core-q2"></a>

**Q2** · Multiple choice

`View::as_bytes(&self)` returns `Result<&'a [u8], CoreError>`, where `'a` is the struct's lifetime parameter. What does writing `'a` (instead of letting the lifetime be elided) allow?

- **A.** The returned slice may outlive the `View` value itself, as long as the underlying buffer is still alive
- **B.** The slice may outlive the buffer
- **C.** The slice becomes an owned copy
- **D.** Nothing; elision would give the same lifetime

[Answer →](answers.md#a-core-q2)

<a id="q-core-q3"></a>

**Q3** · Written answer

`BlockHeader::decode_view` reads every field through a `View` that borrows the caller's bytes, yet it copies each field (`copy_from_slice`, `to_vec`). Explain why, and name the alternative and its cost.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-core-q3)

<a id="q-core-q4"></a>

**Q4** · Multiple choice

In the trie walk, why does `Step::Embedded` carry a *cloned* `Item` rather than `&Item`?

- **A.** Cloning is faster than borrowing
- **B.** Because `Item` is `Copy`
- **C.** To keep the parent alive for the garbage collector
- **D.** The loop does `current = child;`. A child borrowed from `current` would make that reassignment a borrow error, so the child must be owned

[Answer →](answers.md#a-core-q4)

<a id="q-core-q5"></a>

**Q5** · Multiple choice

The trie walk's node index changed from `HashMap` to `BTreeMap<[u8; 32], &[u8]>`. What is the reason in this crate?

- **A.** `BTreeMap` compares keys by content and `HashMap` by identity
- **B.** `HashMap` lives in `std` (its default hasher is seeded from OS randomness), and the crate must build as `no_std` + `alloc`, where only `BTreeMap` is available
- **C.** `BTreeMap` lookups are O(1)
- **D.** `HashMap` cannot store references as values

[Answer →](answers.md#a-core-q5)

<a id="q-core-q6"></a>

**Q6** · Multiple choice

In `bloom.rs`'s test, `let snapshot = bloom; accrue(&mut bloom, …); assert_eq!(bloom, snapshot);`. Why is `snapshot` unaffected by the second `accrue`?

- **A.** `snapshot` is a reference that the compiler freezes
- **B.** `accrue` works on a copy
- **C.** `[u8; 256]` is `Copy`: the assignment copied all 256 bytes
- **D.** It is affected; the assert compares the same array

[Answer →](answers.md#a-core-q6)

<a id="q-core-q7"></a>

**Q7** · Written answer

Explain what `#![cfg_attr(not(feature = "std"), no_std)]` and `extern crate alloc;` in `lib.rs` do, and why nearly every module starts with imports such as `use alloc::vec::Vec;`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-core-q7)

<a id="q-core-q8"></a>

**Q8** · Multiple choice

`myotis-wire` depends on myotis-core with `default-features = false`; `myotis-net` depends on it with defaults. When you build `myotis-net` (which also pulls in myotis-wire), how is myotis-core compiled?

- **A.** Twice, once with std and once without
- **B.** With `std` on: Cargo compiles it once with the union of all requested features
- **C.** Without `std`, because one dependent turned the default off
- **D.** The build fails because the requests conflict

[Answer →](answers.md#a-core-q8)

<a id="q-core-q9"></a>

**Q9** · Written answer

Why does `trie.rs` walk proofs iteratively with a lookup counter, and why does `rlp.rs` have `MAX_DEPTH`? What would happen without these guards?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-core-q9)

<a id="q-core-q10"></a>

**Q10** · Multiple choice

`forkid.rs` builds `CRC32_TABLE` in a `const` initialiser using `while` loops with hand-counted indices. Why not `for n in 0..256`?

- **A.** A `for` loop calls `Iterator::next`, a trait method that cannot run during compile-time evaluation
- **B.** `for` loops are slower
- **C.** Ranges cannot contain 256
- **D.** `while` loops produce a smaller table

[Answer →](answers.md#a-core-q10)

<a id="q-core-q11"></a>

**Q11** · Multiple choice

In `verify_proof_path`, `walk(root, key, proof_nodes, |node| path.push(node.to_vec()))` is followed by `path.clear()`. Why is that second use of `path` allowed?

- **A.** The closure captured `path` by value, so it holds a copy
- **B.** `Vec` allows any number of mutable borrows
- **C.** The closure was a temporary argument; it was dropped when `walk` returned, which ended its mutable borrow of `path`
- **D.** `path.clear()` does not need a borrow

[Answer →](answers.md#a-core-q11)

<a id="q-core-q12"></a>

**Q12** · Written answer

`skip_item` repeats every check of `decode_item` without building anything. What risk does that duplication create, how do the tests in `rlp.rs` control it, and why does `validate_agrees_with_decode` also count accepted and rejected inputs?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-core-q12)

<a id="q-core-q13"></a>

**Q13** · Written answer

`tests/rlp_alloc_bound.rs` counts allocations. Explain why it is a separate test file, why the counters are thread-local `Cell`s, why the `impl` is `unsafe`, and what the test `the_counter_sees_a_per_element_decode` is for.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-core-q13)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
