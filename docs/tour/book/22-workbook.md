# Workbook: ten exercises you can run offline

*Stop 22 · hands-on* · 10 exercises · about 2½ hours

Reading Rust and writing it are different skills, and the borrow checker teaches the second one fastest. Each exercise below re-builds, in 30 to 80 lines, one mechanism you met in Myotis: the snapshot cursor, the engine's handle map, the peer's drop guard, the reader's hedged race. Every exercise comes with tests. The crate needs only the standard library, tokio and futures, at the exact versions Myotis uses, and those are already in your local cargo cache, so `cargo test --offline` works with no network at all. This was verified with cargo 1.99.

## How to use this stop

- **Write, compile, test** — Fill in each `todo!()`, run the exercise's tests, and read every compiler error to the end: they are written to teach.
- **Hints before solutions** — Each exercise has hints and a solution, folded away. Open the hints when you are stuck for more than ten minutes.
- **Then predict** — Several exercises end with a "break it on purpose" step: change one line, predict the compiler error, then check.

## Setup (two minutes, works on the plane)

The starter crate is already on your Mac, next to this tour:

```text
cd docs/tour/workbook
cp -R starter mine        # keep a pristine copy; work in "mine"
cd mine
cargo test --offline e01  # one exercise: tests whose path contains "e01"
cargo test --offline      # everything (26 tests)
```

Or open `docs/tour/workbook/mine` in RustRover (File → Open) and use the green run arrows next to each `#[test]`. Before you start, every test fails with `not yet implemented: your code here`, and the compiler warns about unused variables and imports. Both are expected: the bodies are `todo!()`, a macro that compiles to a panic. The full solutions are in `docs/tour/workbook/solution`, and below each exercise.

If the folder is missing (a different machine), create the crate from these two files, then paste each exercise file into `src/`:

**Cargo.toml** · `docs/tour/workbook/starter/Cargo.toml`

```toml
[package]
name = "myotis-workbook"
version = "1.0.0"
edition = "2021"
publish = false

# Same versions as the Myotis workspace, so `cargo test --offline` finds them
# in your local cargo cache (~/.cargo/registry) with no network.
[dependencies]
tokio = { version = "=1.52.3", features = ["macros", "rt", "time"] }
futures = "=0.3.32"

[dev-dependencies]
tokio = { version = "=1.52.3", features = ["macros", "rt", "time", "test-util"] }
```

**src/lib.rs** · `docs/tour/workbook/starter/src/lib.rs`

```rust
//! Myotis Rust Tour workbook. One module per exercise; run one with
//! `cargo test --offline e01` (or all with `cargo test --offline`).
pub mod e01_cursor;
pub mod e02_hex;
pub mod e03_errors;
pub mod e04_methods;
pub mod e05_registry;
pub mod e06_guard;
pub mod e07_weak;
pub mod e08_chain;
pub mod e09_hedge;
pub mod e10_traits;
```

> [!NOTE]
> **JVM lens**
>
> `#[cfg(test)] mod tests` is a test class that lives in the same file, compiled only for `cargo test`, and it may see private items (like package-private access). `assert_eq!` is `assertEquals`, and a test passes if and only if it does not panic. `cargo test e05` filters by test path the way Gradle's `--tests` does.

### 1 · A panic-free byte cursor

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* From [the primer](01-primer.md#primer-borrowing) and [Stop 6](06-consensus.md): the snapshot decoder's `Reader<'a>`. Implement `fixed`, `u32_be`, `u64_le` and `prefixed`. The point of the exercise is the return type `Option<&'a [u8]>`: a returned slice borrows the *buffer*, not the reader, so you can hold two of them while reading on. The tests also feed a hostile length (`0xffffffff`) and `usize::MAX`, so nothing may panic. Use `checked_add`, `get(a..b)`, `try_into` and `?`.

**src/e01\_cursor.rs (starter)** · `docs/tour/workbook/starter/src/e01_cursor.rs`

```rust
//! Exercise 1: a panic-free byte cursor (borrowing, slices, lifetimes).
//! Modelled on `Reader<'a>` in myotis-consensus/src/snapshot.rs.

/// Reads fields from a byte buffer it borrows; it owns nothing.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The next `len` bytes, borrowed from the ORIGINAL buffer (lifetime `'a`),
    /// not from the reader. `None`, without moving `pos`, if fewer remain or if
    /// `pos + len` would overflow. Must never panic.
    pub fn fixed(&mut self, len: usize) -> Option<&'a [u8]> {
        todo!("your code here")
    }

    /// A big-endian u32 (4 bytes).
    pub fn u32_be(&mut self) -> Option<u32> {
        todo!("your code here")
    }

    /// A little-endian u64 (8 bytes).
    pub fn u64_le(&mut self) -> Option<u64> {
        todo!("your code here")
    }

    /// A length-prefixed field: a big-endian u32 length, then that many bytes.
    pub fn prefixed(&mut self) -> Option<&'a [u8]> {
        todo!("your code here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_borrow_the_buffer_not_the_reader() {
        let buf = vec![1u8, 2, 3, 4, 5, 6];
        let mut r = Reader::new(&buf);
        let a = r.fixed(2).unwrap();
        let b = r.fixed(2).unwrap(); // `a` is still alive here: only possible with `'a`
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[3, 4]);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn short_reads_fail_without_moving() {
        let buf = [9u8, 9, 9];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32_be(), None);
        assert_eq!(r.remaining(), 3, "a failed read must not consume bytes");
        assert_eq!(r.fixed(usize::MAX), None, "overflow is None, not a panic");
    }

    #[test]
    fn numbers_and_prefixed_fields() {
        let mut buf = vec![0, 0, 0, 3, b'a', b'b', b'c'];
        buf.extend_from_slice(&7u64.to_le_bytes());
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), Some(&b"abc"[..]));
        assert_eq!(r.u64_le(), Some(7));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn hostile_length_prefix_is_refused() {
        let buf = [0xff, 0xff, 0xff, 0xff, 1, 2];
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), None);
    }
}
```

<details>
<summary>Hints</summary>

- `self.pos.checked_add(len)?` gives you the end, or returns `None` on overflow.
- `self.data.get(self.pos..end)?` is the panic-free form of `&self.data[self.pos..end]`.
- Only move `pos` after both have succeeded.
- `slice.try_into()` converts `&[u8]` to `[u8; 4]` and is fallible; `.ok()?` turns its `Result` into an early `None`.

</details>

<details>
<summary>Break it on purpose</summary>

Change the signature of `fixed` to `-> Option<&[u8]>` (no `'a`) and run the tests. The test `slices_borrow_the_buffer_not_the_reader` stops compiling with "cannot borrow `r` as mutable more than once at a time". Lifetime elision tied the result to `&mut self`, so the first slice keeps the reader mutably borrowed. That is exactly the argument the primer makes about `snapshot.rs`.

</details>

<details>
<summary>Solution</summary>

**src/e01\_cursor.rs (solution)** · `docs/tour/workbook/solution/src/e01_cursor.rs`

```rust
//! Exercise 1: a panic-free byte cursor (borrowing, slices, lifetimes).
//! Modelled on `Reader<'a>` in myotis-consensus/src/snapshot.rs.

/// Reads fields from a byte buffer it borrows; it owns nothing.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The next `len` bytes, borrowed from the ORIGINAL buffer (lifetime `'a`),
    /// not from the reader. `None`, without moving `pos`, if fewer remain or if
    /// `pos + len` would overflow. Must never panic.
    pub fn fixed(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// A big-endian u32 (4 bytes).
    pub fn u32_be(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))
    }

    /// A little-endian u64 (8 bytes).
    pub fn u64_le(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.fixed(8)?.try_into().ok()?))
    }

    /// A length-prefixed field: a big-endian u32 length, then that many bytes.
    pub fn prefixed(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32_be()?).ok()?;
        self.fixed(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_borrow_the_buffer_not_the_reader() {
        let buf = vec![1u8, 2, 3, 4, 5, 6];
        let mut r = Reader::new(&buf);
        let a = r.fixed(2).unwrap();
        let b = r.fixed(2).unwrap(); // `a` is still alive here: only possible with `'a`
        assert_eq!(a, &[1, 2]);
        assert_eq!(b, &[3, 4]);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn short_reads_fail_without_moving() {
        let buf = [9u8, 9, 9];
        let mut r = Reader::new(&buf);
        assert_eq!(r.u32_be(), None);
        assert_eq!(r.remaining(), 3, "a failed read must not consume bytes");
        assert_eq!(r.fixed(usize::MAX), None, "overflow is None, not a panic");
    }

    #[test]
    fn numbers_and_prefixed_fields() {
        let mut buf = vec![0, 0, 0, 3, b'a', b'b', b'c'];
        buf.extend_from_slice(&7u64.to_le_bytes());
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), Some(&b"abc"[..]));
        assert_eq!(r.u64_le(), Some(7));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn hostile_length_prefix_is_refused() {
        let buf = [0xff, 0xff, 0xff, 0xff, 1, 2];
        let mut r = Reader::new(&buf);
        assert_eq!(r.prefixed(), None);
    }
}
```

</details>

### 2 · Hex parsing with const generics

*[Bytes, strings & formatting](01-primer.md#primer-bytes-strings) · [Result, ? and panics](01-primer.md#primer-error-handling) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* From [Stop 16](16-engine.md) (`host.rs`'s `parse_hex_fixed`) and the multi-byte trap in the reader's `parse_boot_enodes`. `parse_hex_fixed::<N>` returns a stack array whose length is a compile-time parameter, something Java generics cannot express. Then write `to_hex` so that it fills one pre-sized `String` with `write!`, with no `format!` per byte.

**src/e02\_hex.rs (starter)** · `docs/tour/workbook/starter/src/e02_hex.rs`

```rust
//! Exercise 2: panic-free hex parsing with const generics (bytes and strings).
//! Modelled on `parse_hex_fixed` in myotis-engine/src/host.rs and the
//! `is_ascii()` lesson in `parse_boot_enodes` (myotis-net/src/el/reader.rs).

/// Parse `0x`-prefixed or bare hex into exactly `N` bytes. `None` for anything
/// malformed: wrong length, non-hex characters, multi-byte UTF-8. Never panics.
pub fn parse_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    todo!("your code here")
}

/// Lowercase `0x`-prefixed hex, built in ONE `String` (no per-byte allocation).
pub fn to_hex(bytes: &[u8]) -> String {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let a: [u8; 4] = parse_hex_fixed("0xDEADbeef").unwrap();
        assert_eq!(a, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(to_hex(&a), "0xdeadbeef");
        assert_eq!(parse_hex_fixed::<2>("0102"), Some([1, 2]));
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(parse_hex_fixed::<2>("0x01"), None, "too short");
        assert_eq!(parse_hex_fixed::<2>("0x0g01"), None, "not hex");
        assert_eq!(parse_hex_fixed::<1>(""), None);
    }

    #[test]
    fn multibyte_utf8_does_not_panic() {
        // "éé" is FOUR bytes, so a naive length check passes and naive slicing
        // at byte 1 would panic inside a character.
        assert_eq!(parse_hex_fixed::<2>("éé"), None);
    }
}
```

<details>
<summary>Hints</summary>

- `s.strip_prefix("0x")` returns `Option<&str>`; chain `.or_else(…)` and `.unwrap_or(s)`.
- Check `s.len() == 2 * N` *and* that every byte is an ASCII hex digit before slicing. `len()` counts bytes, so `"éé"` has length 4.
- `for (i, byte) in out.iter_mut().enumerate()` gives you `&mut u8` slots to fill.
- For `write!` into a `String`, you need `use std::fmt::Write;` in scope.

</details>

<details>
<summary>Solution</summary>

**src/e02\_hex.rs (solution)** · `docs/tour/workbook/solution/src/e02_hex.rs`

```rust
//! Exercise 2: panic-free hex parsing with const generics (bytes and strings).
//! Modelled on `parse_hex_fixed` in myotis-engine/src/host.rs and the
//! `is_ascii()` lesson in `parse_boot_enodes` (myotis-net/src/el/reader.rs).

/// Parse `0x`-prefixed or bare hex into exactly `N` bytes. `None` for anything
/// malformed: wrong length, non-hex characters, multi-byte UTF-8. Never panics.
pub fn parse_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Lowercase `0x`-prefixed hex, built in ONE `String` (no per-byte allocation).
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips() {
        let a: [u8; 4] = parse_hex_fixed("0xDEADbeef").unwrap();
        assert_eq!(a, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(to_hex(&a), "0xdeadbeef");
        assert_eq!(parse_hex_fixed::<2>("0102"), Some([1, 2]));
    }

    #[test]
    fn refuses_bad_input() {
        assert_eq!(parse_hex_fixed::<2>("0x01"), None, "too short");
        assert_eq!(parse_hex_fixed::<2>("0x0g01"), None, "not hex");
        assert_eq!(parse_hex_fixed::<1>(""), None);
    }

    #[test]
    fn multibyte_utf8_does_not_panic() {
        // "éé" is FOUR bytes, so a naive length check passes and naive slicing
        // at byte 1 would panic inside a character.
        assert_eq!(parse_hex_fixed::<2>("éé"), None);
    }
}
```

</details>

### 3 · Errors as values: enums, `From` and `?`

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* From [Stop 7](07-evm.md): `OracleError` and `EvmError`. Write the `From` impl, a `Display` with one `match` covering every case, and `total_balance` using only `?`: no `match`, no `map_err`. The `From` impl is what lets `?` convert the error on its way out.

**src/e03\_errors.rs (starter)** · `docs/tour/workbook/starter/src/e03_errors.rs`

```rust
//! Exercise 3: errors as values: enums, `From`, `?` and `Display`.
//! Modelled on `OracleError` / `EvmError` in myotis-evm (oracle.rs, error.rs).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    StateUnavailable { address: [u8; 20] },
    InvalidProof { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmError {
    Oracle(OracleError),
    Reverted { data: Vec<u8> },
    OutOfGas,
}

/// Lets `?` turn an `OracleError` into an `EvmError` automatically.
impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        todo!("your code here")
    }
}

/// Human-readable messages:
/// - `StateUnavailable` → "state unavailable for 0x<first 2 address bytes in hex>…"
/// - `InvalidProof` → "invalid proof: <detail>"
/// - `Reverted` → "reverted with <n> bytes of data"
/// - `OutOfGas` → "out of gas"
impl fmt::Display for EvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("your code here")
    }
}

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError>;
}

/// Sum the balances of `addrs`, stopping at the first one that can't be read.
/// Use `?` (no `match`, no `map_err`): the `From` impl above does the work.
pub fn total_balance(src: &dyn StateSource, addrs: &[[u8; 20]]) -> Result<u64, EvmError> {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl StateSource for Fixed {
        fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError> {
            match address[0] {
                0 => Err(OracleError::StateUnavailable { address }),
                n => Ok(u64::from(n)),
            }
        }
    }

    #[test]
    fn question_mark_converts_and_stops_early() {
        assert_eq!(total_balance(&Fixed, &[[1; 20], [2; 20]]), Ok(3));
        let err = total_balance(&Fixed, &[[1; 20], [0; 20], [5; 20]]).unwrap_err();
        assert_eq!(err, EvmError::Oracle(OracleError::StateUnavailable { address: [0; 20] }));
    }

    #[test]
    fn display_messages() {
        let e: EvmError = OracleError::StateUnavailable { address: [0xab; 20] }.into();
        assert_eq!(e.to_string(), "state unavailable for 0xabab…");
        assert_eq!(EvmError::Reverted { data: vec![0; 4] }.to_string(), "reverted with 4 bytes of data");
        assert_eq!(EvmError::OutOfGas.to_string(), "out of gas");
        assert_eq!(
            EvmError::from(OracleError::InvalidProof { detail: "bad node".into() }).to_string(),
            "invalid proof: bad node"
        );
    }
}
```

<details>
<summary>Hints</summary>

- Patterns can nest: `EvmError::Oracle(OracleError::StateUnavailable { address })` matches and binds in one arm.
- `write!(f, "out of gas")` returns the `fmt::Result` that `fmt` must return.
- In `total_balance`, `src.balance(*a)?` has type `u64`. `*a` copies the 20-byte array out of the slice (arrays of `Copy` are `Copy`).

</details>

<details>
<summary>Break it on purpose</summary>

Delete the `From` impl and compile. The error at the `?` says that `?` couldn't convert the error to `EvmError`, and suggests implementing `From<OracleError>`. Then add a fourth variant to `EvmError` and watch the `match` in `Display` fail with "non-exhaustive patterns". That is the compiler keeping every error path honest.

</details>

<details>
<summary>Solution</summary>

**src/e03\_errors.rs (solution)** · `docs/tour/workbook/solution/src/e03_errors.rs`

```rust
//! Exercise 3: errors as values: enums, `From`, `?` and `Display`.
//! Modelled on `OracleError` / `EvmError` in myotis-evm (oracle.rs, error.rs).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    StateUnavailable { address: [u8; 20] },
    InvalidProof { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmError {
    Oracle(OracleError),
    Reverted { data: Vec<u8> },
    OutOfGas,
}

/// Lets `?` turn an `OracleError` into an `EvmError` automatically.
impl From<OracleError> for EvmError {
    fn from(e: OracleError) -> EvmError {
        EvmError::Oracle(e)
    }
}

/// Human-readable messages:
/// - `StateUnavailable` → "state unavailable for 0x<first 2 address bytes in hex>…"
/// - `InvalidProof` → "invalid proof: <detail>"
/// - `Reverted` → "reverted with <n> bytes of data"
/// - `OutOfGas` → "out of gas"
impl fmt::Display for EvmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvmError::Oracle(OracleError::StateUnavailable { address }) => {
                write!(f, "state unavailable for 0x{:02x}{:02x}…", address[0], address[1])
            }
            EvmError::Oracle(OracleError::InvalidProof { detail }) => write!(f, "invalid proof: {detail}"),
            EvmError::Reverted { data } => write!(f, "reverted with {} bytes of data", data.len()),
            EvmError::OutOfGas => write!(f, "out of gas"),
        }
    }
}

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError>;
}

/// Sum the balances of `addrs`, stopping at the first one that can't be read.
/// Use `?` (no `match`, no `map_err`): the `From` impl above does the work.
pub fn total_balance(src: &dyn StateSource, addrs: &[[u8; 20]]) -> Result<u64, EvmError> {
    let mut sum = 0u64;
    for a in addrs {
        sum += src.balance(*a)?;
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;
    impl StateSource for Fixed {
        fn balance(&self, address: [u8; 20]) -> Result<u64, OracleError> {
            match address[0] {
                0 => Err(OracleError::StateUnavailable { address }),
                n => Ok(u64::from(n)),
            }
        }
    }

    #[test]
    fn question_mark_converts_and_stops_early() {
        assert_eq!(total_balance(&Fixed, &[[1; 20], [2; 20]]), Ok(3));
        let err = total_balance(&Fixed, &[[1; 20], [0; 20], [5; 20]]).unwrap_err();
        assert_eq!(err, EvmError::Oracle(OracleError::StateUnavailable { address: [0; 20] }));
    }

    #[test]
    fn display_messages() {
        let e: EvmError = OracleError::StateUnavailable { address: [0xab; 20] }.into();
        assert_eq!(e.to_string(), "state unavailable for 0xabab…");
        assert_eq!(EvmError::Reverted { data: vec![0; 4] }.to_string(), "reverted with 4 bytes of data");
        assert_eq!(EvmError::OutOfGas.to_string(), "out of gas");
        assert_eq!(
            EvmError::from(OracleError::InvalidProof { detail: "bad node".into() }).to_string(),
            "invalid proof: bad node"
        );
    }
}
```

</details>

### 4 · Methods and receivers

*[Methods & self](01-primer.md#primer-methods) · [Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* From [the primer's methods section](01-primer.md#primer-methods): roost's `EnrSeq`, and `SyncHandle::stop(self)`. The four functions differ only in how they receive the counter: not at all (`start`), shared (`&self`), exclusive (`&mut self`) and by value (`self`). Note the test that calls `Counter::bump(&mut c)`: that is what the dot desugars to.

**src/e04\_methods.rs (starter)** · `docs/tour/workbook/starter/src/e04_methods.rs`

```rust
//! Exercise 4: methods and receivers (`&self`, `&mut self`, `self`).
//! Modelled on `EnrSeq` in roost/src/enr.rs and `SyncHandle::stop(self)`.

/// A strictly increasing sequence number that remembers what it did.
pub struct Counter {
    current: u64,
    log: Vec<String>,
}

impl Counter {
    /// Associated function (no `self`): a new counter starting at 1.
    pub fn start() -> Counter {
        todo!("your code here")
    }

    /// Shared borrow: read only.
    pub fn current(&self) -> u64 {
        todo!("your code here")
    }

    /// Exclusive borrow: advance by one and log "bump to N".
    /// `Err("overflow")` instead of wrapping when already at `u64::MAX`.
    pub fn bump(&mut self) -> Result<u64, String> {
        todo!("your code here")
    }

    /// By value: consumes the counter and hands its log to the caller.
    /// After `finish`, the counter can no longer be used (the compiler checks).
    pub fn finish(self) -> Vec<String> {
        todo!("your code here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receivers() {
        let mut c = Counter::start();
        assert_eq!(c.bump(), Ok(2));
        assert_eq!(Counter::bump(&mut c), Ok(3), "the dot is sugar for this");
        assert_eq!(c.current(), 3);
        let log = c.finish();
        assert_eq!(log, vec!["bump to 2".to_string(), "bump to 3".to_string()]);
        // c.current();  // <- uncomment: "borrow of moved value: `c`"
    }

    #[test]
    fn methods_are_functions() {
        let maybe: Option<Counter> = Some(Counter::start());
        // A method passed where a function is expected, as roost does with
        // `enr_seq.as_ref().map(EnrSeq::current)`.
        assert_eq!(maybe.as_ref().map(Counter::current), Some(1));
    }

    #[test]
    fn overflow_is_an_error() {
        let mut c = Counter { current: u64::MAX, log: Vec::new() };
        assert_eq!(c.bump(), Err("overflow".to_string()));
        assert_eq!(c.current(), u64::MAX);
    }
}
```

<details>
<summary>Hints</summary>

- `checked_add(1)` returns an `Option`; `.ok_or_else(|| "overflow".to_string())?` turns `None` into an early `Err`.
- In `finish(self)`, the whole struct is yours: return the field (`self.log`) by moving it out. You can't do that from `&self`.

</details>

<details>
<summary>Break it on purpose</summary>

Uncomment `c.current();` after `finish` in the test `receivers`: "borrow of moved value: `c`". Then change `finish(self)` to `finish(&self)` and see why returning `self.log` no longer compiles ("cannot move out of `self.log` which is behind a shared reference"). The fix the compiler suggests, `.clone()`, would copy the log, which is precisely what a consuming method avoids.

</details>

<details>
<summary>Solution</summary>

**src/e04\_methods.rs (solution)** · `docs/tour/workbook/solution/src/e04_methods.rs`

```rust
//! Exercise 4: methods and receivers (`&self`, `&mut self`, `self`).
//! Modelled on `EnrSeq` in roost/src/enr.rs and `SyncHandle::stop(self)`.

/// A strictly increasing sequence number that remembers what it did.
pub struct Counter {
    current: u64,
    log: Vec<String>,
}

impl Counter {
    /// Associated function (no `self`): a new counter starting at 1.
    pub fn start() -> Counter {
        Counter { current: 1, log: Vec::new() }
    }

    /// Shared borrow: read only.
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Exclusive borrow: advance by one and log "bump to N".
    /// `Err("overflow")` instead of wrapping when already at `u64::MAX`.
    pub fn bump(&mut self) -> Result<u64, String> {
        let next = self.current.checked_add(1).ok_or_else(|| "overflow".to_string())?;
        self.current = next;
        self.log.push(format!("bump to {next}"));
        Ok(next)
    }

    /// By value: consumes the counter and hands its log to the caller.
    /// After `finish`, the counter can no longer be used (the compiler checks).
    pub fn finish(self) -> Vec<String> {
        self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receivers() {
        let mut c = Counter::start();
        assert_eq!(c.bump(), Ok(2));
        assert_eq!(Counter::bump(&mut c), Ok(3), "the dot is sugar for this");
        assert_eq!(c.current(), 3);
        let log = c.finish();
        assert_eq!(log, vec!["bump to 2".to_string(), "bump to 3".to_string()]);
        // c.current();  // <- uncomment: "borrow of moved value: `c`"
    }

    #[test]
    fn methods_are_functions() {
        let maybe: Option<Counter> = Some(Counter::start());
        // A method passed where a function is expected, as roost does with
        // `enr_seq.as_ref().map(EnrSeq::current)`.
        assert_eq!(maybe.as_ref().map(Counter::current), Some(1));
    }

    #[test]
    fn overflow_is_an_error() {
        let mut c = Counter { current: u64::MAX, log: Vec::new() };
        assert_eq!(c.bump(), Err("overflow".to_string()));
        assert_eq!(c.current(), u64::MAX);
    }
}
```

</details>

### 5 · A thread-safe registry, and the lock scope

*[Interior mutability](01-primer.md#primer-interior-mutability) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* From [Stop 16](16-engine.md): the engine's handle map and `spin_up`. `create` must work from eight threads at once through `&self`, which is why the ids come from an atomic. `start` must copy the `Arc<Config>` out under the lock, *release* the lock, run the slow part, and re-check before publishing. One test calls `try_lock()` from inside `slow_start` and fails if you still hold the lock. Another stops the entry in the middle of a start, and expects your code not to bring it back.

**src/e05\_registry.rs (starter)** · `docs/tour/workbook/starter/src/e05_registry.rs`

```rust
//! Exercise 5: a thread-safe registry (Mutex, atomics, Arc, lock scope).
//! Modelled on the handle map in myotis-engine/src/host.rs (`spin_up`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

pub struct Config {
    pub name: String,
}

pub enum Entry {
    Created(Arc<Config>),
    Running(Arc<Config>, u64),
}

pub struct Registry {
    handles: Mutex<HashMap<i64, Entry>>,
    next_id: AtomicI64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Registry {
        todo!("your code here")
    }

    /// Store `cfg` as `Created` under a fresh id (1, 2, 3, …) and return it.
    /// Must be safe to call from many threads at once through `&self`.
    pub fn create(&self, cfg: Config) -> i64 {
        todo!("your code here")
    }

    /// 1. Under the lock, copy the `Arc<Config>` out of a `Created` entry
    ///    (return `false` for an unknown id or any other state).
    /// 2. RELEASE the lock, then call `slow_start(&config)`: it may take seconds,
    ///    and other threads must not wait for it.
    /// 3. Re-lock and publish `Running(config, started)` only if the entry is
    ///    still `Created` (another thread may have stopped it meanwhile).
    pub fn start(&self, id: i64, slow_start: impl FnOnce(&Config) -> u64) -> bool {
        todo!("your code here")
    }

    pub fn is_running(&self, id: i64) -> bool {
        matches!(self.handles.lock().unwrap().get(&id), Some(Entry::Running(..)))
    }

    /// Remove the entry whatever its state and return its config.
    pub fn stop(&self, id: i64) -> Option<Arc<Config>> {
        todo!("your code here")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_across_threads() {
        let reg = Registry::new();
        let mut ids: Vec<i64> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|i| { let reg = &reg; s.spawn(move || reg.create(Config { name: format!("c{i}") })) })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        ids.sort();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
    }

    #[test]
    fn slow_start_runs_without_the_lock() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "mainnet".into() });
        let ok = reg.start(id, |cfg| {
            assert_eq!(cfg.name, "mainnet");
            assert!(reg.handles.try_lock().is_ok(), "the map lock is still held during slow_start");
            42
        });
        assert!(ok);
        assert!(reg.is_running(id));
        assert!(!reg.start(id, |_| 0), "already running");
    }

    #[test]
    fn stop_during_start_wins() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "gnosis".into() });
        let ok = reg.start(id, |_| {
            reg.stop(id); // a racing stop()
            1
        });
        assert!(!ok, "must not resurrect a stopped entry");
        assert!(!reg.is_running(id));
        assert!(reg.stop(id).is_none());
    }
}
```

<details>
<summary>Hints</summary>

- `let config = { let map = self.handles.lock().unwrap(); match map.get(&id) { … } };`: the guard `map` is dropped at the block's closing brace.
- `Arc::clone(c)` copies a pointer and increments a counter; the `Config` itself is not copied.
- In `stop`, `remove` hands you the owned `Entry`; an or-pattern `Entry::Created(c) | Entry::Running(c, _)` binds `c` in both cases.

</details>

<details>
<summary>Break it on purpose</summary>

Move `slow_start(&config)` inside the block, so that it runs while `map` is still alive. The `try_lock` assertion fails. With a plain `lock()` instead of `try_lock()`, the same thread would deadlock against itself: `std::sync::Mutex` is not reentrant, unlike Java's `synchronized`.

</details>

<details>
<summary>Solution</summary>

**src/e05\_registry.rs (solution)** · `docs/tour/workbook/solution/src/e05_registry.rs`

```rust
//! Exercise 5: a thread-safe registry (Mutex, atomics, Arc, lock scope).
//! Modelled on the handle map in myotis-engine/src/host.rs (`spin_up`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

pub struct Config {
    pub name: String,
}

pub enum Entry {
    Created(Arc<Config>),
    Running(Arc<Config>, u64),
}

pub struct Registry {
    handles: Mutex<HashMap<i64, Entry>>,
    next_id: AtomicI64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Registry {
        Registry { handles: Mutex::new(HashMap::new()), next_id: AtomicI64::new(1) }
    }

    /// Store `cfg` as `Created` under a fresh id (1, 2, 3, …) and return it.
    /// Must be safe to call from many threads at once through `&self`.
    pub fn create(&self, cfg: Config) -> i64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.handles.lock().unwrap().insert(id, Entry::Created(Arc::new(cfg)));
        id
    }

    /// 1. Under the lock, copy the `Arc<Config>` out of a `Created` entry
    ///    (return `false` for an unknown id or any other state).
    /// 2. RELEASE the lock, then call `slow_start(&config)`: it may take seconds,
    ///    and other threads must not wait for it.
    /// 3. Re-lock and publish `Running(config, started)` only if the entry is
    ///    still `Created` (another thread may have stopped it meanwhile).
    pub fn start(&self, id: i64, slow_start: impl FnOnce(&Config) -> u64) -> bool {
        let config = {
            let map = self.handles.lock().unwrap();
            match map.get(&id) {
                Some(Entry::Created(c)) => Arc::clone(c),
                _ => return false,
            }
        }; // <- the guard is dropped here: the lock is free during slow_start
        let started = slow_start(&config);
        let mut map = self.handles.lock().unwrap();
        match map.get(&id) {
            Some(Entry::Created(_)) => {
                map.insert(id, Entry::Running(config, started));
                true
            }
            _ => false,
        }
    }

    pub fn is_running(&self, id: i64) -> bool {
        matches!(self.handles.lock().unwrap().get(&id), Some(Entry::Running(..)))
    }

    /// Remove the entry whatever its state and return its config.
    pub fn stop(&self, id: i64) -> Option<Arc<Config>> {
        match self.handles.lock().unwrap().remove(&id)? {
            Entry::Created(c) | Entry::Running(c, _) => Some(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_across_threads() {
        let reg = Registry::new();
        let mut ids: Vec<i64> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|i| { let reg = &reg; s.spawn(move || reg.create(Config { name: format!("c{i}") })) })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        ids.sort();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
    }

    #[test]
    fn slow_start_runs_without_the_lock() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "mainnet".into() });
        let ok = reg.start(id, |cfg| {
            assert_eq!(cfg.name, "mainnet");
            assert!(reg.handles.try_lock().is_ok(), "the map lock is still held during slow_start");
            42
        });
        assert!(ok);
        assert!(reg.is_running(id));
        assert!(!reg.start(id, |_| 0), "already running");
    }

    #[test]
    fn stop_during_start_wins() {
        let reg = Registry::new();
        let id = reg.create(Config { name: "gnosis".into() });
        let ok = reg.start(id, |_| {
            reg.stop(id); // a racing stop()
            1
        });
        assert!(!ok, "must not resurrect a stopped entry");
        assert!(!reg.is_running(id));
        assert!(reg.stop(id).is_none());
    }
}
```

</details>

### 6 · An RAII drop guard

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Interior mutability](01-primer.md#primer-interior-mutability) · [Result, ? and panics](01-primer.md#primer-error-handling)* From [Stop 11](11-el-transport.md): the managed peer's `PendingGuard`. The guard registers a pending request and removes it again in `Drop`, unless the request finished through another path and the guard was disarmed. The test `early_return_cleans_up_and_success_keeps` leaves through `?`: cleanup happens anyway, with no `try/finally`.

**src/e06\_guard.rs (starter)** · `docs/tour/workbook/starter/src/e06_guard.rs`

```rust
//! Exercise 6: an RAII drop guard (Drop, Arc, Mutex).
//! Modelled on `PendingGuard` in myotis-net/src/el/peer.rs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Pending = Arc<Mutex<HashMap<u64, String>>>;

/// Registers a pending request and removes it again when dropped, unless
/// `disarm` was called. Cleanup then happens on EVERY exit path: normal
/// return, early `return`, `?`, or a panic that unwinds.
pub struct PendingGuard {
    pending: Pending,
    id: u64,
    armed: bool,
}

impl PendingGuard {
    /// Insert `what` under `id` and return an armed guard. The guard keeps its
    /// own `Arc` clone of the map.
    pub fn register(pending: &Pending, id: u64, what: &str) -> PendingGuard {
        todo!("your code here")
    }

    /// The request completed through another path: keep the entry.
    pub fn disarm(&mut self) {
        todo!("your code here")
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        todo!("your code here")
    }
}

/// Registers request `id`, then fails half-way with `?` when `fail` is true.
pub fn request(pending: &Pending, id: u64, fail: bool) -> Result<(), String> {
    let mut guard = PendingGuard::register(pending, id, "GetBlockHeaders");
    let check: Result<(), String> = if fail { Err("peer closed".into()) } else { Ok(()) };
    check?; // an early return: the guard still runs
    guard.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_guard_removes_its_entry() {
        let p: Pending = Arc::default();
        {
            let _g = PendingGuard::register(&p, 1, "a");
            assert_eq!(p.lock().unwrap().len(), 1);
        } // <- _g dropped here
        assert!(p.lock().unwrap().is_empty());
    }

    #[test]
    fn early_return_cleans_up_and_success_keeps() {
        let p: Pending = Arc::default();
        assert!(request(&p, 7, true).is_err());
        assert!(!p.lock().unwrap().contains_key(&7), "the ? path must clean up");
        request(&p, 8, false).unwrap();
        assert!(p.lock().unwrap().contains_key(&8), "disarmed: entry kept");
    }

    #[test]
    fn guard_holds_its_own_arc() {
        let p: Pending = Arc::default();
        let g = PendingGuard::register(&p, 3, "x");
        assert_eq!(Arc::strong_count(&p), 2);
        drop(g);
        assert_eq!(Arc::strong_count(&p), 1);
    }
}
```

<details>
<summary>Hints</summary>

- `register` stores `Arc::clone(pending)` in the guard, so the guard keeps the map alive on its own; the test `guard_holds_its_own_arc` counts that.
- In `drop`, prefer `if let Ok(mut map) = self.pending.lock()` to `unwrap()`: a panic inside `drop` during unwinding aborts the process.

</details>

<details>
<summary>Solution</summary>

**src/e06\_guard.rs (solution)** · `docs/tour/workbook/solution/src/e06_guard.rs`

```rust
//! Exercise 6: an RAII drop guard (Drop, Arc, Mutex).
//! Modelled on `PendingGuard` in myotis-net/src/el/peer.rs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Pending = Arc<Mutex<HashMap<u64, String>>>;

/// Registers a pending request and removes it again when dropped, unless
/// `disarm` was called. Cleanup then happens on EVERY exit path: normal
/// return, early `return`, `?`, or a panic that unwinds.
pub struct PendingGuard {
    pending: Pending,
    id: u64,
    armed: bool,
}

impl PendingGuard {
    /// Insert `what` under `id` and return an armed guard. The guard keeps its
    /// own `Arc` clone of the map.
    pub fn register(pending: &Pending, id: u64, what: &str) -> PendingGuard {
        pending.lock().unwrap().insert(id, what.to_string());
        PendingGuard { pending: Arc::clone(pending), id, armed: true }
    }

    /// The request completed through another path: keep the entry.
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut map) = self.pending.lock() {
                map.remove(&self.id);
            }
        }
    }
}

/// Registers request `id`, then fails half-way with `?` when `fail` is true.
pub fn request(pending: &Pending, id: u64, fail: bool) -> Result<(), String> {
    let mut guard = PendingGuard::register(pending, id, "GetBlockHeaders");
    let check: Result<(), String> = if fail { Err("peer closed".into()) } else { Ok(()) };
    check?; // an early return: the guard still runs
    guard.disarm();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_guard_removes_its_entry() {
        let p: Pending = Arc::default();
        {
            let _g = PendingGuard::register(&p, 1, "a");
            assert_eq!(p.lock().unwrap().len(), 1);
        } // <- _g dropped here
        assert!(p.lock().unwrap().is_empty());
    }

    #[test]
    fn early_return_cleans_up_and_success_keeps() {
        let p: Pending = Arc::default();
        assert!(request(&p, 7, true).is_err());
        assert!(!p.lock().unwrap().contains_key(&7), "the ? path must clean up");
        request(&p, 8, false).unwrap();
        assert!(p.lock().unwrap().contains_key(&8), "disarmed: entry kept");
    }

    #[test]
    fn guard_holds_its_own_arc() {
        let p: Pending = Arc::default();
        let g = PendingGuard::register(&p, 3, "x");
        assert_eq!(Arc::strong_count(&p), 2);
        drop(g);
        assert_eq!(Arc::strong_count(&p), 1);
    }
}
```

</details>

### 7 · A worker that doesn't keep its owner alive

*[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Threads, Send & Sync](01-primer.md#primer-concurrency)* From [Stop 14](14-el-reader.md): the reader's log-index appender holds a `Weak`. Spawn a thread that upgrades a `Weak<Service>` on every tick, does its work, drops the upgraded `Arc` *before* it sleeps, and exits when `upgrade()` returns `None`. The test drops the last strong `Arc` and then waits for the thread with `join()`. If your thread keeps a strong reference, that `join` never returns.

**src/e07\_weak.rs (starter)** · `docs/tour/workbook/starter/src/e07_weak.rs`

```rust
//! Exercise 7: a background worker that must not keep its owner alive (Weak).
//! Modelled on `ensure_log_index_appender` in myotis-net/src/el/reader.rs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Service {
    pub ticks: AtomicU64,
}

/// Spawn a thread that every `period` upgrades a `Weak<Service>`, increments
/// `ticks`, and drops the upgraded `Arc` again before sleeping. When `upgrade`
/// fails (the last strong owner is gone) the thread returns the number of
/// ticks it performed. The thread must never hold a strong `Arc` while asleep.
pub fn spawn_ticker(svc: &Arc<Service>, period: Duration) -> JoinHandle<u64> {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_stops_when_the_owner_drops() {
        let svc = Arc::new(Service { ticks: AtomicU64::new(0) });
        let h = spawn_ticker(&svc, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(60));
        assert!(svc.ticks.load(Ordering::Relaxed) > 0);
        assert_eq!(Arc::weak_count(&svc), 1, "the worker holds exactly one Weak");
        drop(svc); // the last strong owner
        let n = h.join().unwrap(); // returns: upgrade() now fails
        assert!(n > 0);
    }
}
```

<details>
<summary>Hints</summary>

- `Arc::downgrade(svc)` makes the `Weak`; move it into the thread with `std::thread::spawn(move || …)`.
- `let Some(s) = weak.upgrade() else { return done };` inside an inner block `{ … }`, so that `s` is dropped before `sleep`.

</details>

<details>
<summary>Break it on purpose</summary>

Move `Arc::clone(svc)` into the thread instead of a `Weak`. The test hangs at `join()`: the thread is now an owner, so the service never dies and the loop never ends. In the reader, the same mistake would leak an entire peer pool every time a host paused a chain. Stop the run with Ctrl-C.

</details>

<details>
<summary>Solution</summary>

**src/e07\_weak.rs (solution)** · `docs/tour/workbook/solution/src/e07_weak.rs`

```rust
//! Exercise 7: a background worker that must not keep its owner alive (Weak).
//! Modelled on `ensure_log_index_appender` in myotis-net/src/el/reader.rs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Service {
    pub ticks: AtomicU64,
}

/// Spawn a thread that every `period` upgrades a `Weak<Service>`, increments
/// `ticks`, and drops the upgraded `Arc` again before sleeping. When `upgrade`
/// fails (the last strong owner is gone) the thread returns the number of
/// ticks it performed. The thread must never hold a strong `Arc` while asleep.
pub fn spawn_ticker(svc: &Arc<Service>, period: Duration) -> JoinHandle<u64> {
    let weak: Weak<Service> = Arc::downgrade(svc);
    std::thread::spawn(move || {
        let mut done = 0;
        loop {
            {
                let Some(s) = weak.upgrade() else { return done };
                s.ticks.fetch_add(1, Ordering::Relaxed);
                done += 1;
            } // <- the temporary Arc `s` is dropped here
            std::thread::sleep(period);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_stops_when_the_owner_drops() {
        let svc = Arc::new(Service { ticks: AtomicU64::new(0) });
        let h = spawn_ticker(&svc, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(60));
        assert!(svc.ticks.load(Ordering::Relaxed) > 0);
        assert_eq!(Arc::weak_count(&svc), 1, "the worker holds exactly one Weak");
        drop(svc); // the last strong owner
        let n = h.join().unwrap(); // returns: upgrade() now fails
        assert!(n > 0);
    }
}
```

</details>

### 8 · Verify a header chain

*[Iterators & closures](01-primer.md#primer-iterators-closures) · [Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Protocol & domain](01-primer.md#primer-domain)* From [Stop 12](12-el-pool.md) and [Stop 14](14-el-reader.md): the header trust gate. Headers arrive newest first. The first must hash to the trusted anchor, and each must be the parent of the one before. `windows(2)` yields overlapping pairs as slices, and a slice pattern `let [child, parent] = w else { … }` names them. Then write `zero_prefixed` as a single iterator chain.

**src/e08\_chain.rs (starter)** · `docs/tour/workbook/starter/src/e08_chain.rs`

```rust
//! Exercise 8: verify a header chain with slices and iterators.
//! Modelled on `fetch_anchored_window` (myotis-net/src/el/reader.rs) and
//! `verify_header_chain` (myotis-net/src/el/verify.rs).

#[derive(Clone, Debug)]
pub struct Header {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    WrongHead,
    BrokenLink { at: u64 },
}

/// `headers` is NEWEST FIRST. Accept only if the first header's hash equals
/// `anchor` (the trusted head) and every header is the parent of the one
/// before it: `child.parent_hash == parent.hash` and
/// `child.number == parent.number + 1`. Report the first bad link by the
/// child's number. Hint: `headers.windows(2)`.
pub fn verify_chain(headers: &[Header], anchor: &[u8; 32]) -> Result<(), ChainError> {
    todo!("your code here")
}

/// Numbers of the headers whose hash starts with a zero byte, in input order,
/// as ONE iterator chain (`iter`, `filter`, `map`, `collect`).
pub fn zero_prefixed(headers: &[Header]) -> Vec<u64> {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<Header> {
        // newest first: numbers n-1 .. 0, hash = [number; 32], parent = [number-1; 32]
        (0..n)
            .rev()
            .map(|i| Header { number: i, hash: [i as u8; 32], parent_hash: [i.wrapping_sub(1) as u8; 32] })
            .collect()
    }

    #[test]
    fn good_chain_passes() {
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[4; 32]), Ok(()));
        assert_eq!(zero_prefixed(&c), vec![0]);
    }

    #[test]
    fn bad_chains_fail() {
        assert_eq!(verify_chain(&[], &[0; 32]), Err(ChainError::Empty));
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[9; 32]), Err(ChainError::WrongHead));
        let mut broken = c.clone();
        broken[2].parent_hash = [77; 32];
        assert_eq!(verify_chain(&broken, &[4; 32]), Err(ChainError::BrokenLink { at: 2 }));
    }
}
```

<details>
<summary>Hints</summary>

- `headers.first().ok_or(ChainError::Empty)?` gives you the head or returns early.
- Compare numbers with `parent.number.checked_add(1) != Some(child.number)` so that `u64::MAX` can't overflow.
- `headers.iter().filter(|h| h.hash[0] == 0).map(|h| h.number).collect()`: the return type tells `collect` to build a `Vec<u64>`.

</details>

<details>
<summary>Solution</summary>

**src/e08\_chain.rs (solution)** · `docs/tour/workbook/solution/src/e08_chain.rs`

```rust
//! Exercise 8: verify a header chain with slices and iterators.
//! Modelled on `fetch_anchored_window` (myotis-net/src/el/reader.rs) and
//! `verify_header_chain` (myotis-net/src/el/verify.rs).

#[derive(Clone, Debug)]
pub struct Header {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    Empty,
    WrongHead,
    BrokenLink { at: u64 },
}

/// `headers` is NEWEST FIRST. Accept only if the first header's hash equals
/// `anchor` (the trusted head) and every header is the parent of the one
/// before it: `child.parent_hash == parent.hash` and
/// `child.number == parent.number + 1`. Report the first bad link by the
/// child's number. Hint: `headers.windows(2)`.
pub fn verify_chain(headers: &[Header], anchor: &[u8; 32]) -> Result<(), ChainError> {
    let first = headers.first().ok_or(ChainError::Empty)?;
    if &first.hash != anchor {
        return Err(ChainError::WrongHead);
    }
    for w in headers.windows(2) {
        let [child, parent] = w else { unreachable!("windows(2) yields pairs") };
        if child.parent_hash != parent.hash || parent.number.checked_add(1) != Some(child.number) {
            return Err(ChainError::BrokenLink { at: child.number });
        }
    }
    Ok(())
}

/// Numbers of the headers whose hash starts with a zero byte, in input order,
/// as ONE iterator chain (`iter`, `filter`, `map`, `collect`).
pub fn zero_prefixed(headers: &[Header]) -> Vec<u64> {
    headers.iter().filter(|h| h.hash[0] == 0).map(|h| h.number).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<Header> {
        // newest first: numbers n-1 .. 0, hash = [number; 32], parent = [number-1; 32]
        (0..n)
            .rev()
            .map(|i| Header { number: i, hash: [i as u8; 32], parent_hash: [i.wrapping_sub(1) as u8; 32] })
            .collect()
    }

    #[test]
    fn good_chain_passes() {
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[4; 32]), Ok(()));
        assert_eq!(zero_prefixed(&c), vec![0]);
    }

    #[test]
    fn bad_chains_fail() {
        assert_eq!(verify_chain(&[], &[0; 32]), Err(ChainError::Empty));
        let c = chain(5);
        assert_eq!(verify_chain(&c, &[9; 32]), Err(ChainError::WrongHead));
        let mut broken = c.clone();
        broken[2].parent_hash = [77; 32];
        assert_eq!(verify_chain(&broken, &[4; 32]), Err(ChainError::BrokenLink { at: 2 }));
    }
}
```

</details>

### 9 · A hedged race with tokio

*[async/await & tokio](01-primer.md#primer-async) · [Ownership & moves](01-primer.md#primer-ownership)* From [Stop 14](14-el-reader.md): `hedged_race`. Start attempt 0. Whenever `delay` passes without an answer, or an attempt fails, start the next one *alongside* the running ones. Return the first `Ok`. The tests run on tokio's paused clock (`#[tokio::test(start_paused = true)]`) and assert exact elapsed times: a slow but working peer that answers at 4 s still wins, and a silent peer does not hold up the read past the hedge. This is the hardest exercise. Budget 30 to 45 minutes.

**src/e09\_hedge.rs (starter)** · `docs/tour/workbook/starter/src/e09_hedge.rs`

```rust
//! Exercise 9: a hedged race with tokio (futures, select!, cancellation).
//! Modelled on `hedged_race` in myotis-net/src/el/reader.rs.

use std::future::Future;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

/// Try up to `attempts` peers. Start attempt 0 at once. Start the NEXT attempt
/// (alongside the ones still running, never instead of them) whenever `delay`
/// passes without a result, and immediately whenever an attempt fails.
/// Return the first `Ok` as `(index, value)`, or `None` once every attempt
/// has failed. Returning drops the attempts still in flight: that is how
/// the losers are cancelled.
pub async fn hedged<T, F, Fut>(attempts: usize, delay: Duration, mut make: F) -> Option<(usize, T)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[derive(Clone)]
    enum Peer {
        Answers(Duration, u32),
        FailsNow,
    }

    async fn race(plan: Vec<Peer>) -> Option<(usize, u32)> {
        let n = plan.len();
        hedged(n, Duration::from_secs(3), |i| {
            let p = plan[i].clone(); // each future owns its copy
            async move {
                match p {
                    Peer::Answers(d, v) => {
                        tokio::time::sleep(d).await;
                        Ok(v)
                    }
                    Peer::FailsNow => Err("peer failed".to_string()),
                }
            }
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn slow_peer_still_wins_when_others_fail() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(4), 7), Peer::FailsNow, Peer::FailsNow]).await;
        assert_eq!(out, Some((0, 7)));
        assert_eq!(t.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_does_not_hold_the_read() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(600), 1), Peer::Answers(Duration::from_millis(50), 2)]).await;
        assert_eq!(out, Some((1, 2)));
        assert_eq!(t.elapsed(), Duration::from_millis(3050));
    }

    #[tokio::test(start_paused = true)]
    async fn all_fail() {
        assert_eq!(race(vec![Peer::FailsNow, Peer::FailsNow]).await, None);
    }
}
```

<details>
<summary>Hints</summary>

- Keep all running attempts in one `FuturesUnordered`. Because every `async move` block has its own anonymous type, push from exactly *one* place: `in_flight.push(async move { (idx, fut.await) })`.
- `tokio::select!` over `in_flight.next()` and `tokio::time::sleep(delay)`. A guard `, if next < attempts` disables the timer branch when there is nothing left to start.
- Each way the loop continues, a failure or the timer firing, is a reason to start one more attempt, so start one at the top of each turn while any remain.
- You never cancel anything explicitly: `return` drops `in_flight`, and dropping a future is cancellation.

</details>

<details>
<summary>Why the test can use the closure the way it does</summary>

The test passes `|i| { let p = plan[i].clone(); async move { … } }`. The closure borrows `plan`, but each future it returns *owns* its clone `p`. That's needed because the futures outlive each closure call. They don't need to be `'static`, though: `hedged` awaits them in place and never spawns them, as `get_account`'s closure in the reader does.

</details>

<details>
<summary>Solution</summary>

**src/e09\_hedge.rs (solution)** · `docs/tour/workbook/solution/src/e09_hedge.rs`

```rust
//! Exercise 9: a hedged race with tokio (futures, select!, cancellation).
//! Modelled on `hedged_race` in myotis-net/src/el/reader.rs.

use std::future::Future;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

/// Try up to `attempts` peers. Start attempt 0 at once. Start the NEXT attempt
/// (alongside the ones still running, never instead of them) whenever `delay`
/// passes without a result, and immediately whenever an attempt fails.
/// Return the first `Ok` as `(index, value)`, or `None` once every attempt
/// has failed. Returning drops the attempts still in flight: that is how
/// the losers are cancelled.
pub async fn hedged<T, F, Fut>(attempts: usize, delay: Duration, mut make: F) -> Option<(usize, T)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut in_flight = FuturesUnordered::new();
    let mut next = 0usize;
    // Every way the loop continues (a failure, the hedge timer) is a reason
    // to start one more attempt, so no flag is needed: start one per turn.
    loop {
        if next < attempts {
            let idx = next;
            let fut = make(idx);
            in_flight.push(async move { (idx, fut.await) });
            next += 1;
        }
        if in_flight.is_empty() {
            return None;
        }
        tokio::select! {
            Some((idx, res)) = in_flight.next() => {
                if let Ok(v) = res {
                    return Some((idx, v)); // drops in_flight: the losers are cancelled
                }
            }
            _ = tokio::time::sleep(delay), if next < attempts => {}
            else => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[derive(Clone)]
    enum Peer {
        Answers(Duration, u32),
        FailsNow,
    }

    async fn race(plan: Vec<Peer>) -> Option<(usize, u32)> {
        let n = plan.len();
        hedged(n, Duration::from_secs(3), |i| {
            let p = plan[i].clone(); // each future owns its copy
            async move {
                match p {
                    Peer::Answers(d, v) => {
                        tokio::time::sleep(d).await;
                        Ok(v)
                    }
                    Peer::FailsNow => Err("peer failed".to_string()),
                }
            }
        })
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn slow_peer_still_wins_when_others_fail() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(4), 7), Peer::FailsNow, Peer::FailsNow]).await;
        assert_eq!(out, Some((0, 7)));
        assert_eq!(t.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_does_not_hold_the_read() {
        let t = Instant::now();
        let out = race(vec![Peer::Answers(Duration::from_secs(600), 1), Peer::Answers(Duration::from_millis(50), 2)]).await;
        assert_eq!(out, Some((1, 2)));
        assert_eq!(t.elapsed(), Duration::from_millis(3050));
    }

    #[tokio::test(start_paused = true)]
    async fn all_fail() {
        assert_eq!(race(vec![Peer::FailsNow, Peer::FailsNow]).await, None);
    }
}
```

</details>

### 10 · Traits: generics, `dyn` and a decorator

*[Traits, generics & dyn](01-primer.md#primer-traits-generics) · [Methods & self](01-primer.md#primer-methods) · [Interior mutability](01-primer.md#primer-interior-mutability)* From [the primer](01-primer.md#primer-traits-generics) and [Stop 7](07-evm.md): `SnapStateOracle`, and the `Counting { inner, fetches }` wrapper in the executor tests. Implement the fixture, a generic decorator `Counting<S>`, one function with static dispatch (`total<S: StateSource + ?Sized>`) and one with dynamic dispatch over a slice of trait objects (`richest`).

**src/e10\_traits.rs (starter)** · `docs/tour/workbook/starter/src/e10_traits.rs`

```rust
//! Exercise 10: traits, generics vs `dyn`, and a decorator.
//! Modelled on `SnapStateOracle` (myotis-evm/src/oracle.rs) and the
//! `Counting { inner, fetches }` test helper in myotis-evm/src/executor.rs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Option<u64>;

    /// A default method: implementors may override it.
    fn label(&self) -> String {
        "source".to_string()
    }
}

pub struct Fixture {
    pub balances: HashMap<[u8; 20], u64>,
}

impl StateSource for Fixture {
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        todo!("your code here")
    }
}

/// Wraps any source, counts calls, and forwards to `inner`.
pub struct Counting<S> {
    pub inner: S,
    pub calls: AtomicUsize,
}

impl<S: StateSource> StateSource for Counting<S> {
    /// Count the call (through `&self`!), then forward to `self.inner`.
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        todo!("your code here")
    }

    /// "counting(<inner label>)".
    fn label(&self) -> String {
        todo!("your code here")
    }
}

/// Static dispatch: compiled once per concrete `S`. `?Sized` also allows
/// `S = dyn StateSource`.
pub fn total<S: StateSource + ?Sized>(src: &S, addrs: &[[u8; 20]]) -> u64 {
    todo!("your code here")
}

/// Dynamic dispatch: the sources have different types, so they are trait
/// objects. Return the label and balance of the source that reports the most
/// for `address`, or `None` if none knows it.
pub fn richest(sources: &[&dyn StateSource], address: [u8; 20]) -> Option<(String, u64)> {
    todo!("your code here")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(v: u64) -> Fixture {
        Fixture { balances: HashMap::from([([1; 20], v)]) }
    }

    #[test]
    fn decorator_counts_and_forwards() {
        let c = Counting { inner: fixture(5), calls: AtomicUsize::new(0) };
        assert_eq!(total(&c, &[[1; 20], [2; 20]]), 5);
        assert_eq!(c.calls.load(Ordering::Relaxed), 2);
        assert_eq!(c.label(), "counting(source)");
    }

    #[test]
    fn dyn_mixes_types() {
        let a = fixture(5);
        let b = Counting { inner: fixture(9), calls: AtomicUsize::new(0) };
        let srcs: [&dyn StateSource; 2] = [&a, &b];
        assert_eq!(richest(&srcs, [1; 20]), Some(("counting(source)".to_string(), 9)));
        assert_eq!(richest(&srcs, [7; 20]), None);
        let as_dyn: &dyn StateSource = &a;
        assert_eq!(total(as_dyn, &[[1; 20]]), 5);
    }
}
```

<details>
<summary>Hints</summary>

- `self.balances.get(&address).copied()` turns `Option<&u64>` into `Option<u64>`.
- `self.calls.fetch_add(1, Ordering::Relaxed)` works through `&self`, because atomics are interior mutability.
- `?Sized` lets `S` be `dyn StateSource`, a type with no size known at compile time, which can only sit behind a pointer.
- `max_by_key(|(_, b)| *b)` picks the largest balance.

</details>

<details>
<summary>Solution</summary>

**src/e10\_traits.rs (solution)** · `docs/tour/workbook/solution/src/e10_traits.rs`

```rust
//! Exercise 10: traits, generics vs `dyn`, and a decorator.
//! Modelled on `SnapStateOracle` (myotis-evm/src/oracle.rs) and the
//! `Counting { inner, fetches }` test helper in myotis-evm/src/executor.rs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

pub trait StateSource {
    fn balance(&self, address: [u8; 20]) -> Option<u64>;

    /// A default method: implementors may override it.
    fn label(&self) -> String {
        "source".to_string()
    }
}

pub struct Fixture {
    pub balances: HashMap<[u8; 20], u64>,
}

impl StateSource for Fixture {
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        self.balances.get(&address).copied()
    }
}

/// Wraps any source, counts calls, and forwards to `inner`.
pub struct Counting<S> {
    pub inner: S,
    pub calls: AtomicUsize,
}

impl<S: StateSource> StateSource for Counting<S> {
    /// Count the call (through `&self`!), then forward to `self.inner`.
    fn balance(&self, address: [u8; 20]) -> Option<u64> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.balance(address)
    }

    /// "counting(<inner label>)".
    fn label(&self) -> String {
        format!("counting({})", self.inner.label())
    }
}

/// Static dispatch: compiled once per concrete `S`. `?Sized` also allows
/// `S = dyn StateSource`.
pub fn total<S: StateSource + ?Sized>(src: &S, addrs: &[[u8; 20]]) -> u64 {
    addrs.iter().filter_map(|a| src.balance(*a)).sum()
}

/// Dynamic dispatch: the sources have different types, so they are trait
/// objects. Return the label and balance of the source that reports the most
/// for `address`, or `None` if none knows it.
pub fn richest(sources: &[&dyn StateSource], address: [u8; 20]) -> Option<(String, u64)> {
    sources
        .iter()
        .filter_map(|s| s.balance(address).map(|b| (s.label(), b)))
        .max_by_key(|(_, b)| *b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(v: u64) -> Fixture {
        Fixture { balances: HashMap::from([([1; 20], v)]) }
    }

    #[test]
    fn decorator_counts_and_forwards() {
        let c = Counting { inner: fixture(5), calls: AtomicUsize::new(0) };
        assert_eq!(total(&c, &[[1; 20], [2; 20]]), 5);
        assert_eq!(c.calls.load(Ordering::Relaxed), 2);
        assert_eq!(c.label(), "counting(source)");
    }

    #[test]
    fn dyn_mixes_types() {
        let a = fixture(5);
        let b = Counting { inner: fixture(9), calls: AtomicUsize::new(0) };
        let srcs: [&dyn StateSource; 2] = [&a, &b];
        assert_eq!(richest(&srcs, [1; 20]), Some(("counting(source)".to_string(), 9)));
        assert_eq!(richest(&srcs, [7; 20]), None);
        let as_dyn: &dyn StateSource = &a;
        assert_eq!(total(as_dyn, &[[1; 20]]), 5);
    }
}
```

</details>

## Checkpoint

5 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-wb-q1"></a>

**Q1** · Written answer

Exercise 1: explain why `fixed(&mut self, len) -> Option<&'a [u8]>` lets the caller keep two returned slices at once, and what goes wrong with `-> Option<&[u8]>`.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wb-q1)

<a id="q-wb-q2"></a>

**Q2** · Written answer

Exercise 5: why must `start` release the map lock before calling `slow_start`, and why does it re-check the entry afterwards?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wb-q2)

<a id="q-wb-q3"></a>

**Q3** · Multiple choice

Exercise 7: the worker thread moves a `Weak<Service>` into its closure. What happens if you move an `Arc<Service>` clone instead?

- **A.** Nothing changes; Arc and Weak behave the same
- **B.** The thread becomes an owner: dropping the test's Arc no longer frees the service, upgrade never fails, the loop never ends and join() hangs
- **C.** It doesn't compile, because Arc is not Send
- **D.** The service is freed twice

[Answer →](answers.md#a-wb-q3)

<a id="q-wb-q4"></a>

**Q4** · Written answer

Exercise 9: how are the losing attempts cancelled when `hedged` returns the first `Ok`, and why don't the futures need to be `'static`?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-wb-q4)

<a id="q-wb-q5"></a>

**Q5** · Multiple choice

Exercise 10: `total<S: StateSource + ?Sized>(src: &S, …)` is called with a `Counting<Fixture>` and with a `&dyn StateSource`. How many copies of `total` does the compiler produce, and how is `balance` called in each?

- **A.** One copy; both calls go through a vtable
- **B.** Two copies (monomorphisation): for Counting&amp;lt;Fixture> the call to balance is static and can be inlined; for dyn StateSource it goes through the trait object's vtable
- **C.** Two copies, both using vtables
- **D.** It doesn't compile, because generics can't take dyn

[Answer →](answers.md#a-wb-q5)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
