<a id="progress"></a>

# Reading list

*After the tour*

Every checkpoint question is tagged with the Rust concepts it tests. When a concept keeps tripping you up, read the chapters listed under it. The Rust documentation links go to doc.rust-lang.org. The same books ship with every Rust toolchain: `rustup doc --book` (or `--std`, `--rust-by-example`) opens your local copy, offline.

## By concept

### Ownership & moves

Every value has exactly one owner. Passing or assigning by value moves it, and the old name can no longer be used. The value is dropped when its owner goes out of scope. [Stop 1 · Ownership](01-primer.md#primer-ownership)

- **Rust Book**: [4.1 What Is Ownership?](https://doc.rust-lang.org/book/ch04-01-what-is-ownership.html)
- **Rust by Example**: [Scoping rules → RAII, Ownership and moves](https://doc.rust-lang.org/rust-by-example/scope/move.html)
- **Rust for Rustaceans (EPUB)**: Ch. 1 Foundations — “Memory Regions” and “Ownership” *(— the clearest model of stack, heap and static memory)*
- **Hands-on Rust (EPUB)**: Ch. 2 First Steps with Rust — “Moving Input to a Function” *(— a gentle first contact with moves)*

### Borrowing & slices

&T is a shared, read-only loan; &mut T is an exclusive one. Slices (&\[u8\], &str) are borrowed views into a buffer somebody else owns. [Stop 1 · Borrowing](01-primer.md#primer-borrowing)

- **Rust Book**: [4.2 References and Borrowing](https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html)
- **Rust Book**: [4.3 The Slice Type](https://doc.rust-lang.org/book/ch04-03-slices.html)
- **Rust by Example**: [Scoping rules → Borrowing (incl. Aliasing)](https://doc.rust-lang.org/rust-by-example/scope/borrow.html)
- **Rust for Rustaceans (EPUB)**: Ch. 1 Foundations — “Borrowing and Lifetimes”: Shared References, Mutable References
- **Programming Rust (your early-release copy)**: Ch. 2 Basic Types — “Arrays, Vectors, and Slices”

### Lifetimes

A lifetime is the compiler's name for how long a borrow stays valid. Annotations like &amp;lt;'a> change no behaviour; they say which input an output borrows from. [Stop 1 · Lifetimes](01-primer.md#primer-lifetimes)

- **Rust Book**: [10.3 Validating References with Lifetimes](https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html)
- **Rust by Example**: [Scoping rules → Lifetimes](https://doc.rust-lang.org/rust-by-example/scope/lifetime.html)
- **Rust by Example**: [Lifetimes → Static](https://doc.rust-lang.org/rust-by-example/scope/lifetime/static_lifetime.html) *(— what 'static really means in a bound)*
- **Rust for Rustaceans (EPUB)**: Ch. 1 Foundations — “Lifetimes”

### Box, Rc, Arc & Drop

Box&amp;lt;T> is one owner of a heap value. Rc&amp;lt;T> and Arc&amp;lt;T> share ownership through a reference count; Arc is the thread-safe one. Drop runs cleanup at a known point. [Stop 1 · Smart pointers](01-primer.md#primer-smart-pointers)

- **Rust Book**: [Ch. 15 Smart Pointers (15.1 Box, 15.3 Drop, 15.4 Rc)](https://doc.rust-lang.org/book/ch15-00-smart-pointers.html)
- **Rust by Example**: [Std library types → Box, stack and heap](https://doc.rust-lang.org/rust-by-example/std/box.html)
- **Rust by Example**: [Std library types → Arc](https://doc.rust-lang.org/rust-by-example/std/arc.html)
- **Rust for Rustaceans (EPUB)**: Ch. 2 Types — “Dynamically Sized Types and Wide Pointers” *(— why Arc&amp;lt;dyn Trait> is two words wide)*
- **Programming Rust (your early-release copy)**: Ch. 2 Basic Types — “Pointer Types” (References, Boxes, Raw Pointers)
- **std docs**: [std::sync::Arc](https://doc.rust-lang.org/std/sync/struct.Arc.html)

### Interior mutability

How code holding only a shared reference (&self) can still change things: Mutex and RwLock guard the data itself, atomics update single numbers, OnceLock initialises exactly once. [Stop 1 · Interior mutability](01-primer.md#primer-interior-mutability)

- **Rust Book**: [15.5 RefCell&amp;lt;T> and the Interior Mutability Pattern](https://doc.rust-lang.org/book/ch15-05-interior-mutability.html)
- **Rust Book**: [16.3 Shared-State Concurrency](https://doc.rust-lang.org/book/ch16-03-shared-state.html)
- **Rust for Rustaceans (EPUB)**: Ch. 1 Foundations — “Interior Mutability”
- **Rust for Rustaceans (EPUB)**: Ch. 10 Concurrency — “Atomic Types”, “Memory Ordering”
- **std docs**: [std::sync::Mutex](https://doc.rust-lang.org/std/sync/struct.Mutex.html)
- **std docs**: [std::sync::atomic](https://doc.rust-lang.org/std/sync/atomic/index.html)

### Threads, Send & Sync

Send means a value may move to another thread; Sync means it may be shared between threads. The compiler checks both, which is why shared state is wrapped in Arc&amp;lt;Mutex&amp;lt;…>>. [Stop 1 · Send & Sync](01-primer.md#primer-concurrency)

- **Rust Book**: [Ch. 16 Fearless Concurrency](https://doc.rust-lang.org/book/ch16-00-concurrency.html)
- **Rust Book**: [16.4 Extensible Concurrency with Send and Sync](https://doc.rust-lang.org/book/ch16-04-extensible-concurrency-sync-and-send.html)
- **Rust by Example**: [Std misc → Channels](https://doc.rust-lang.org/rust-by-example/std_misc/channels.html)
- **Rust for Rustaceans (EPUB)**: Ch. 10 Concurrency (and Parallelism) — “Concurrency Models”: Shared Memory, Worker Pools, Actors
- **Rust for Rustaceans (EPUB)**: Ch. 2 Types — “Marker Traits” *(— Send and Sync are marker traits)*

### async/await & tokio

An async fn returns a Future that does nothing until it is polled. tokio polls thousands of them on a few threads. A spawned task must own everything it uses ('static). [Stop 1 · async](01-primer.md#primer-async)

- **Rust Book**: [Ch. 17 Fundamentals of Asynchronous Programming](https://doc.rust-lang.org/book/ch17-00-async-await.html)
- **Rust Book**: [17.6 Futures, Tasks, and Threads](https://doc.rust-lang.org/book/ch17-06-futures-tasks-threads.html)
- **Rust for Rustaceans (EPUB)**: Ch. 8 Asynchronous Programming — “Ergonomic Futures”, “Pin and Unpin”, “Tying It All Together with spawn”
- **Rust for Rustaceans (EPUB)**: Ch. 10 Concurrency — “Asynchrony and Parallelism”
- **std docs**: [std::future::Future](https://doc.rust-lang.org/std/future/trait.Future.html)

### Methods & self

impl blocks, receivers (&self, &mut self, self) and what the dot desugars to. [Primer: methods and self](01-primer.md#primer-methods)

- **Rust Book**: [5.3 Method Syntax](https://doc.rust-lang.org/book/ch05-03-method-syntax.html)
- **Rust by Example**: [Functions → Associated functions & Methods](https://doc.rust-lang.org/rust-by-example/fn/methods.html)
- **Rust Book**: [10.2 Traits — implementing a trait on a type](https://doc.rust-lang.org/book/ch10-02-traits.html)
- **Rust for Rustaceans (EPUB)**: Ch. 3 Designing Interfaces — “Borrowed vs. Owned” (choosing self, &self, &mut self)

### Traits, generics & dyn

Traits are interfaces. Generics (T: Trait) are resolved at compile time; dyn Trait is resolved at run time through a vtable, like a Java interface call. [Stop 1 · Traits](01-primer.md#primer-traits-generics)

- **Rust Book**: [10.2 Defining Shared Behavior with Traits](https://doc.rust-lang.org/book/ch10-02-traits.html)
- **Rust Book**: [18.2 Using Trait Objects to Abstract over Shared Behavior](https://doc.rust-lang.org/book/ch18-02-trait-objects.html)
- **Rust by Example**: [Traits → Returning Traits with dyn](https://doc.rust-lang.org/rust-by-example/trait/dyn.html)
- **Rust by Example**: [Generics → Bounds](https://doc.rust-lang.org/rust-by-example/generics/bounds.html)
- **Rust for Rustaceans (EPUB)**: Ch. 2 Types — “Traits and Trait Bounds” (Compilation and Dispatch)
- **Rust for Rustaceans (EPUB)**: Ch. 3 Designing Interfaces — “Object Safety”, “Borrowed vs. Owned”
- **Hands-on Rust (EPUB)**: Ch. 11 More Interesting Dungeons — “Creating Traits”

### Enums & pattern matching

Rust enums carry data per variant, like Kotlin sealed classes, and match must cover every case. Most state machines in this codebase are enums. [Stop 1 · Enums](01-primer.md#primer-enums-patterns)

- **Rust Book**: [Ch. 6 Enums and Pattern Matching (incl. 6.3 if let and let…else)](https://doc.rust-lang.org/book/ch06-00-enums.html)
- **Rust Book**: [Ch. 19 Patterns and Matching](https://doc.rust-lang.org/book/ch19-00-patterns.html)
- **Rust by Example**: [Flow of Control → match](https://doc.rust-lang.org/rust-by-example/flow_control/match.html)
- **Hands-on Rust (EPUB)**: Ch. 2 First Steps with Rust — “Categorizing with Enumerations”
- **Hands-on Rust (EPUB)**: Ch. 3 Build Your First Game with Rust — “Creating Different Game Modes” *(— an enum-driven state machine)*

### Result, ? and panics

Errors are values: Result&amp;lt;T, E>. The ? operator returns early and converts the error with From. A panic is a crash, and with panic = "abort" it takes the host process with it. [Stop 1 · Errors](01-primer.md#primer-error-handling)

- **Rust Book**: [Ch. 9 Error Handling (9.2 Result, 9.3 To panic! or Not to panic!)](https://doc.rust-lang.org/book/ch09-00-error-handling.html)
- **Rust by Example**: [Error handling → Introducing ?](https://doc.rust-lang.org/rust-by-example/error/result/enter_question_mark.html)
- **Rust by Example**: [Error handling → abort & unwind](https://doc.rust-lang.org/rust-by-example/error/abort_unwind.html)
- **Rust for Rustaceans (EPUB)**: Ch. 4 Error Handling — Enumeration vs. Opaque Errors, Propagating Errors
- **Command-Line Rust (EPUB)**: Ch. 2 Test for Echo — “Using the Result Type”; Ch. 4 Head Aches — “Converting Strings into Errors”
- **CLI book**: [1.4 Nicer error reporting (anyhow)](https://rust-cli.github.io/book/tutorial/errors.html) *(— (online only))* *((online only))*

### Iterators & closures

Iterator chains are lazy, like Kotlin sequences. Closures borrow what they capture unless they are marked move, in which case they take ownership. [Stop 1 · Closures](01-primer.md#primer-iterators-closures)

- **Rust Book**: [Ch. 13 Functional Language Features: Iterators and Closures](https://doc.rust-lang.org/book/ch13-00-functional-features.html)
- **Rust by Example**: [Functions → Closures → Capturing](https://doc.rust-lang.org/rust-by-example/fn/closures/capture.html)
- **Rust by Example**: [Traits → Iterators](https://doc.rust-lang.org/rust-by-example/trait/iter.html)
- **Command-Line Rust (EPUB)**: Ch. 5 Word to Your Mother — “Iterating the Files”

### Crates, modules & features

A workspace holds crates, and each crate is a tree of modules. Cargo features and #\[cfg\] switch code on or off at compile time. [Stop 2 · The workspace](02-workspace.md)

- **Rust Book**: [Ch. 7 Packages, Crates, and Modules](https://doc.rust-lang.org/book/ch07-00-managing-growing-projects-with-packages-crates-and-modules.html)
- **Rust Book**: [14.3 Cargo Workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html)
- **Rust by Example**: [Attributes → cfg](https://doc.rust-lang.org/rust-by-example/attribute/cfg.html)
- **Rust for Rustaceans (EPUB)**: Ch. 5 Project Structure — Features, Workspaces, Conditional Compilation
- **Hands-on Rust (EPUB)**: Ch. 5 Build a Dungeon Crawler — “Dividing Your Code Into Modules”
- **Command-Line Rust (EPUB)**: Ch. 1 Truth or Consequences — “Organizing a Rust Project Directory”

### unsafe & FFI

unsafe marks code whose memory safety you vouch for yourself. At an FFI boundary the compiler cannot see who owns what, so every allocation needs an agreed owner and a matching free. [Stop 17 · UniFFI deep dive](17-uniffi.md)

- **Rust Book**: [20.1 Unsafe Rust (incl. “Using extern Functions to Call External Code”)](https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html)
- **Rust by Example**: [Std misc → Foreign Function Interface](https://doc.rust-lang.org/rust-by-example/std_misc/ffi.html)
- **Rust for Rustaceans (EPUB)**: Ch. 11 Foreign Function Interfaces — “Types Across Language Boundaries”, “Allocations”, “Safety”
- **Rust for Rustaceans (EPUB)**: Ch. 9 Unsafe Code — “Juggling Raw Pointers”, “Panics”
- **std docs**: [std::ffi::CString](https://doc.rust-lang.org/std/ffi/struct.CString.html)
- **Programming Rust (your early-release copy)**: Ch. 2 Basic Types — “Raw Pointers”

### Macros & attributes

println!, vec!, #\[derive(…)\], #\[tokio::main\] and #\[uniffi::export\] are code generators that run at compile time. [Stop 1 · Macros](01-primer.md#primer-macros)

- **Rust Book**: [20.5 Macros](https://doc.rust-lang.org/book/ch20-05-macros.html)
- **Rust Book**: [Appendix C: Derivable Traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html)
- **Rust by Example**: [Hello World → Formatted print](https://doc.rust-lang.org/rust-by-example/hello/print.html)
- **Rust for Rustaceans (EPUB)**: Ch. 7 Macros — Declarative vs. Procedural

### Tests

\#\[test\] functions live next to the code (unit tests) or in tests/ (integration tests that see only the public API). #\[ignore\] keeps live-network tests out of the default run. [Stop 15 · The test suite](15-net-tests.md)

- **Rust Book**: [Ch. 11 Writing Automated Tests (11.2 Running, 11.3 Organization)](https://doc.rust-lang.org/book/ch11-00-testing.html)
- **Rust by Example**: [Testing → Integration testing](https://doc.rust-lang.org/rust-by-example/testing/integration_testing.html)
- **Rust for Rustaceans (EPUB)**: Ch. 6 Testing
- **Command-Line Rust (EPUB)**: Ch. 1 Truth or Consequences — “Writing and Running Integration Tests”

### Bytes, strings & formatting

String owns UTF-8 text and &str borrows it. Vec&amp;lt;u8>, \[u8; N\] and &\[u8\] are the byte versions. Most protocol code in this project is byte slicing. [Stop 1 · Bytes](01-primer.md#primer-bytes-strings)

- **Rust Book**: [8.2 Storing UTF-8 Encoded Text with Strings](https://doc.rust-lang.org/book/ch08-02-strings.html)
- **Rust by Example**: [Std library types → Strings](https://doc.rust-lang.org/rust-by-example/std/str.html)
- **Rust by Example**: [Hello World → Formatted print](https://doc.rust-lang.org/rust-by-example/hello/print.html)
- **Programming Rust (your early-release copy)**: Ch. 2 Basic Types — “String Types”: Byte Strings, Strings in Memory
- **Command-Line Rust (EPUB)**: Ch. 4 Head Aches — “Reading Bytes Versus Characters”

### Binaries, CLIs & signals

A binary crate has a main(); daemons parse arguments, report errors with anyhow and shut down cleanly on Ctrl-C. [Stop 20 · roost](20-roost.md)

- **Command-Line Rust (EPUB)**: Ch. 2 Test for Echo — “Parsing Command-Line Arguments Using clap”
- **CLI book**: [1.2 Parsing command line arguments](https://rust-cli.github.io/book/tutorial/cli-args.html) *(— (online only))* *((online only))*
- **CLI book**: [2.1 Signal handling](https://rust-cli.github.io/book/in-depth/signals.html) *(— (online only))* *((online only))*
- **CLI book**: [2.3 Exit codes](https://rust-cli.github.io/book/in-depth/exit-code.html) *(— (online only))* *((online only))*

### Protocol & domain

The Ethereum knowledge the code assumes. The project's own design documents are the best source here. [Stop 0 · The map](00-map.md)

- **Repo docs**: [docs/spec/01-consensus-light-client.md](../../spec/01-consensus-light-client.md) *(— sync committees, updates, the store)* *((online only))*
- **Repo docs**: [docs/spec/02-execution-networking.md](../../spec/02-execution-networking.md) *(— discv4, RLPx, eth, snap)* *((online only))*
- **Repo docs**: [docs/spec/03-state-verification-and-evm.md](../../spec/03-state-verification-and-evm.md) *((online only))*
- **Repo docs**: [docs/spec/05-engine-api-bindings.md and 07-el-implementation-plan.md](../../spec/05-engine-api-bindings.md) *((online only))*

## The library

The Rust books below ship with every toolchain too: `rustup doc --book` opens your local copy.

- **The Rust Programming Language** [online](https://doc.rust-lang.org/book/index.html) — The current edition. Chapter numbers here follow it: 4 ownership, 10 generics, traits and lifetimes, 15 smart pointers, 16 concurrency, 17 async, 18 trait objects, 19 patterns, 20 unsafe code and macros.
- **Rust by Example** [online](https://doc.rust-lang.org/rust-by-example/index.html) — Short runnable pages. “Scoping rules” (RAII, moves, borrowing, lifetimes) is the memory-model core.
- **The standard library docs** [online](https://doc.rust-lang.org/std/index.html) — For the exact types this code uses: Arc, Mutex, atomics, CString, Future. The search box works offline too.
- **The Rustonomicon** [online](https://doc.rust-lang.org/nomicon/index.html) — The book on unsafe Rust. Read “FFI” and “Ownership Based Resource Management” after Stops 16 and 17.
- **Rust for Rustaceans** (Jon Gjengset)*(EPUB · complete ·)* — Written for experienced programmers. Chapter 1 “Foundations” is the best single read on the memory model. Chapters 8, 10 and 11 cover async, concurrency and FFI.
- **Hands-on Rust** (Herbert Wolverson)*(EPUB · complete ·)* — A game-building book. Chapter 2 is a gentle introduction to structs, vectors and enums, and Chapter 3 shows an enum-driven state machine.
- **Command-Line Rust** and **Systems Programming with Rust** (Ken Youens-Clark)*(EPUB · early release, ch. 1–10 ·)* — These are the same book: “Systems Programming with Rust” was the early-release title. Both of your copies stop at chapter 10, so only chapters 1–10 are recommended.
- **Programming Rust, 2nd Edition** (Blandy, Orendorff, Tindall)*(EPUB · early release, ch. 1–2 ·)* — Your copy contains only “Why Rust?” and “Basic Types”. “Basic Types” is still useful here: its sections on pointer types, slices and byte strings come up throughout this code.
- **The Myotis docs** [on GitHub, and under docs/ in your checkout](../../README.md) — The documents the code refers to, grouped by kind: `spec/` (the re-implementation specification), `how-it-works/privacy-and-tor.md`, `design-history/lc-server-design.md`, `guides/android-library.md`. The tour quotes the code at `5263a421`, when these lived directly under `docs/`; your checkout is newer.
- **Command Line Applications in Rust** *(online only)* — rust-cli.github.io/book: argument parsing, anyhow errors, signal handling. Relevant for roost, rpcd and tor-poc. It is not installed locally.

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
