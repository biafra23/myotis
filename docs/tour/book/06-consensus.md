# myotis-consensus: the light client as a state machine

*Stop 6 · crate `myotis-consensus`* · 16 files · 5,103 lines · about 3 hours

SSZ decoding, `hash_tree_root`, Merkle branches, fork versions, sync-committee signatures, and the store that ties them together. The store is a small state machine: it holds one committee, then two, then rotates. Every update passes a fixed sequence of gates before it may move it. Since the last edition the crate has learned the Gloas fork, where a light-client header stops carrying the execution payload. Like `myotis-core`, the crate performs no I/O and never reads a clock: `myotis-net` passes “what time is it” in as a slot number. Watch how `Option::take`, `Box`, `clone` and borrow scopes move a 24 KB committee and a 470-byte payload header around without surprises.

## Rust you will practise

- **Enums that carry data** — `HeaderExecution` holds either a boxed payload header or a 32-byte hash, and every reader has to `match` on which one it got.
- **Moving big values** — `Option::take` instead of cloning, a builder that consumes `self`, a consuming `restore`, and a `Box` that keeps a large variant out of line.
- **Borrow scopes and panics by policy** — a borrow from a `&self` method ending before a `&mut` call, `assert!` for configuration, `Err` or `false` for peer data, and `const` asserts that fail the build.

## How the files fit

Bytes from a peer are decoded by `types`. Before Gloas the decoders sniff the fork layout from offsets. From Gloas on they cannot, so the caller names the format with an `LcFork` value from `fork`. `LightClientProcessor` in `store` first runs the cheap gates: the sync-committee period (which also picks the verifying committee), the next-committee adoption rule, and the wire-shape check. Only then does it call `verify`, which checks the BLS aggregate through `myotis-bls` under the fork version that `fork` picks for the signature slot. `ssz` and `spec` check the Merkle branches against the gindices of the right fork, and the result updates `LightClientStore`. `snapshot` persists the store in a byte format the Java engine reads too.

The crate is now `no_std`-capable: with `default-features = false` it builds on bare-metal targets with only the `alloc` crate. That is why every module opens with an `alloc::…` import line (see [lib.rs](#f-myotis-consensus-src-lib-rs)).

## What Gloas changes for a light client

Gloas is the consensus fork that brings enshrined proposer-builder separation (EIP-7732) and progressive SSZ containers (EIP-7688). The code shows four consequences for a light client, and each one lands in a different file.

1. **The header proves a block hash, not a payload.** A Gloas beacon block body carries a signed payload *bid* instead of the execution payload. The payload itself is revealed separately and may be withheld. So a Gloas `LightClientHeader` carries only a 32-byte execution block hash, and that hash is the bid's `parent_block_hash`: the payload of the *parent*, which the chain has already imported. There is no state root, block number or timestamp in it any more. Those have to come from the execution header that this hash pins. In the code this is the new enum `HeaderExecution` in [types.rs](#f-myotis-consensus-src-types-rs).
2. **Everything is fixed-size, so nothing can be sniffed.** With no variable-length payload header left, every Gloas container has no offsets. The only honest way to know the format is the fork of the object's slot, which the req/resp context bytes tell the caller. The decoders gained `decode_for(LcFork, bytes)`, and the store checks that each header has the shape of its attested slot's fork.
3. **The proof indices move and stop being derivable.** The Gloas `BeaconState` is a progressive container. The field indices of `finalized_checkpoint`, `current_sync_committee` and `next_sync_committee` (20, 22, 23) are the same, but their generalized indices are not `(1 << depth) + field` any more. [spec.rs](#f-myotis-consensus-src-spec-rs) pins them as constants, and the store selects them by the fork of the attested slot.
4. **The transition needs a padded proof.** In the first epochs after the fork, a Gloas update's finalized header is still a Fulu block. It travels in the Gloas shape, and it proves its block hash at the Deneb-era gindex 812 (depth 9), padded with two leading zero nodes to the 11-node vector. `ssz::verify_normalized_merkle_branch` accepts the padding only if the extra nodes are all zero.

|   | Capella to Fulu (`LcFork::PreGloas`) | Gloas (`LcFork::Gloas`) |
|---|---|---|
| Header execution part | whole execution payload header (584 or 680 bytes plus extra data), 4-node branch | 32-byte block hash, 11-node branch; header is 496 bytes |
| Execution proof | payload header root at gindex 25 | block hash at 2856; a pre-Gloas-slot header in the Gloas shape at 812, zero-padded |
| Finality branch | 6 or 7 nodes, gindex 105 or 169 (derived from depth) | 9 nodes, gindex 735 (constant) |
| Sync-committee branches | 5 or 6 nodes, gindex 54/55 or 86/87 | 11 nodes, gindex 2945/2946 |
| How the decoder knows the format | sniffed from leading offsets | told by the caller (fork of the attested or header slot) |
| Snapshot file | LCSS v1 | LCSS v2, a shape tag per header |

One thing does not change: the signing domain. A signature is still verified under the fork version of the epoch of `max(signature_slot, 1) − 1`, while the wire format follows the slot's own fork with no off-by-one. At the first Gloas slot the objects are Gloas-shaped, but a signature made *at* that slot still uses the Fulu domain ([fork.rs](#f-myotis-consensus-src-fork-rs) pins both in one test).

> [!TIP]
> **What changed since September**Gloas support (`LcFork`, `HeaderExecution`, `decode_for`, the Gloas gindices, the normalized branch check, the shape gate, `verify_bootstrap` with `BootstrapReject`, snapshot v2). A new adoption rule for the next committee (`tests/next_committee_adoption.rs`). `apply_finality_update` and `FinalityOutcome`, which tell a stale but valid finality update from one that advanced the store. A doc note that `optimistic_slot` is the *signature* slot (#658). And `no_std` + `alloc` support.

<a id="f-myotis-consensus-src-lib-rs"></a>

### myotis-consensus/src/lib.rs

*crate root · 49 lines · Java twin · consensus module*

Crate root: seven modules, a re-export of the BLS domain-separation tag, and two unit tests. One test asserts that `fast_aggregate_verify` returns `false` for empty input, all-zero keys, a 47-byte key and a count of 5000, without panicking. The doc comment records the crate's proof of correctness: replaying `rust/testdata/lc/mainnet` reproduces the Java verdicts in `expected.txt`.

`rust/myotis-consensus/src/lib.rs` · lines 15–30

```rust
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod fork;
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
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* **Conditional `no_std`.** `#![cfg_attr(not(feature = "std"), no_std)]` applies the crate attribute `no_std` only when the `std` feature is off. `extern crate alloc;` then brings in the heap types (`Vec`, `String`, `Box`) that `core` lacks. In a `no_std` build those names are not in the prelude, so every module imports them from `alloc` with `#[allow(unused_imports)]`. In a normal `std` build the same names are already in the prelude, the import becomes redundant, and the attribute silences the warning.
- *[Lifetimes](01-primer.md#primer-lifetimes) · [Tests](01-primer.md#primer-testing)* `&'static [u8]`: the DST is a byte-string literal compiled into the binary, so the reference is valid for the whole run. `#[cfg(test)] mod tests` with `super::bls_dst()` is the standard unit-test layout.

> [!WARNING]
> **Stale or inaccurate comments**The module doc still says this is “plan PR 4” and that networking “is the next stage; no I/O lives in this crate yet”. Networking landed long ago, in `myotis-net`, and this crate stays I/O-free by design: its `Cargo.toml` calls the light-client core sans-I/O.

<a id="f-myotis-consensus-src-spec-rs"></a>

### myotis-consensus/src/spec.rs

*library · 158 lines · Java twin · BeaconChainSpec*

Mainnet-preset constants, the Gloas gindex constants, generalized-index (gindex) helpers for the pre-Gloas branch depths, and the sync-committee period math. A gindex numbers the nodes of a binary Merkle tree: the root is 1, and the children of node *g* are 2*g* and 2*g*+1. So its bit length minus one is the node's depth, which is exactly what `gindex_depth` computes.

`rust/myotis-consensus/src/spec.rs` · lines 14–47

```rust
// Gloas (EIP-7732 ePBS + EIP-7688 progressive containers), consensus-specs
// v1.7.0-beta.2 `specs/gloas/light-client/sync-protocol.md`. The body carries a
// payload BID instead of the payload, so a header proves only the execution
// block hash — `signed_execution_payload_bid.message.parent_block_hash` — and
// the Gloas `BeaconState` is a progressive container, so the state gindices move
// even though the field indices (20, 22, 23) do not. They are NOT derivable from
// a branch length the way the pre-Gloas ones are (the depth-derived formulas
// below give 553/2070/2071 for depths 9/11/11): select them by the fork of the
// attested slot, as the spec's `*_gindex_at_slot` helpers do.

/// `get_generalized_index(BeaconState, 'finalized_checkpoint', 'root')` (Gloas).
pub const FINALIZED_ROOT_GINDEX_GLOAS: u64 = 735;
/// `get_generalized_index(BeaconState, 'current_sync_committee')` (Gloas).
pub const CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS: u64 = 2945;
/// `get_generalized_index(BeaconState, 'next_sync_committee')` (Gloas).
pub const NEXT_SYNC_COMMITTEE_GINDEX_GLOAS: u64 = 2946;
/// `get_generalized_index(BeaconBlockBody, 'signed_execution_payload_bid',
/// 'message', 'parent_block_hash')` (Gloas).
pub const EXECUTION_BLOCK_HASH_GINDEX_GLOAS: u64 = 2856;
/// `get_generalized_index(deneb.BeaconBlockBody, 'execution_payload',
/// 'block_hash')`: where a pre-Gloas header carried in the Gloas shape proves
/// its block hash (normalized to the Gloas branch length with leading zeros).
pub const EXECUTION_BLOCK_HASH_GINDEX_DENEB: u64 = 812;

/// `floorlog2` of a generalized index: the depth of the node it names.
pub const fn gindex_depth(gindex: u64) -> usize {
    (63 - gindex.leading_zeros()) as usize
}

/// Gloas branch lengths — the SSZ vector lengths on the wire, all fixed.
pub const GLOAS_EXECUTION_BRANCH_LEN: usize = gindex_depth(EXECUTION_BLOCK_HASH_GINDEX_GLOAS); // 11
pub const GLOAS_SYNC_COMMITTEE_BRANCH_LEN: usize =
    gindex_depth(CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS); // 11
pub const GLOAS_FINALITY_BRANCH_LEN: usize = gindex_depth(FINALIZED_ROOT_GINDEX_GLOAS); // 9
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Why constants.** The comment says it: the Gloas state is a progressive container, so the depth-derived formulas below give 553, 2070 and 2071 for the Gloas depths, not 735, 2945 and 2946. A unit test (`gloas_gindices_are_constants_not_depth_derived`) pins both the values and the mismatch.
- *[Methods & self](01-primer.md#primer-methods)* `pub const fn` can run at compile time, so `GLOAS_EXECUTION_BRANCH_LEN` is *computed* from the gindex instead of being typed in a second time. `leading_zeros` is a single CPU instruction on a `u64`.

`rust/myotis-consensus/src/spec.rs` · lines 53–81

```rust
// Depths reaching these helpers come from decode-validated branch lengths (4..=7),
// but a shift-overflow panic on a wild depth would be a DoS foothold — guard and
// return gindex 0, which can never satisfy verify_merkle_branch (safe rejection).

/// Generalized index of current_sync_committee for a fork-dependent branch depth.
pub fn sync_committee_gindex(branch_depth: usize) -> u64 {
    if branch_depth >= 64 {
        return 0;
    }
    (1u64 << branch_depth) + CURRENT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of next_sync_committee for a fork-dependent branch depth.
pub fn next_sync_committee_gindex(branch_depth: usize) -> u64 {
    if branch_depth >= 64 {
        return 0;
    }
    (1u64 << branch_depth) + NEXT_SYNC_COMMITTEE_FIELD_INDEX
}

/// Generalized index of finalized_checkpoint.root — the branch depth includes the
/// extra level into the Checkpoint container (root = field 1).
pub fn finalized_root_gindex(branch_depth: usize) -> u64 {
    if branch_depth == 0 || branch_depth >= 64 {
        return 0;
    }
    let checkpoint_gindex = (1u64 << (branch_depth - 1)) + FINALIZED_CHECKPOINT_FIELD_INDEX;
    checkpoint_gindex * 2 + 1
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling)* **Two kinds of failure, two tools.** A bad branch depth comes from data, so it returns gindex 0, which can never verify: a safe rejection. `1u64 << 64` would overflow, and with overflow checks enabled that panics.
- *[Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* A function body's final expression without a semicolon is its return value: `checkpoint_gindex * 2 + 1`. The `u64` suffix fixes the literal's width before the shift. The `* 2 + 1` steps one level further down into the `Checkpoint` container, to its field 1 (`root`).

`rust/myotis-consensus/src/spec.rs` · lines 105–117

```rust
/// Note the wallet must be TOLD this, never ask a node for it: it is a
/// verification input, and asking the thing being verified is not a check.
///
/// PANICS on a zero period length, in every build. `debug_assert!` plus
/// `.max(1)` would have silently treated an invalid configuration as one slot
/// per period in release — selecting a different committee than the caller
/// asked for, which is exactly the "accepted and silently ignored" failure
/// CLAUDE.md forbids for anything that can change the answer. A zero here is a
/// build-time configuration error, not a runtime condition to paper over.
pub fn compute_sync_committee_period_with(slot: u64, slots_per_period: u64) -> u64 {
    assert!(slots_per_period > 0, "slots_per_period must be non-zero");
    slot / slots_per_period
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* The earlier part of this doc comment (lines 92–103) explains that 8192 slots per period is right on gnosis only *by coincidence* (16-slot epochs × 512 epochs), so the period length must be configuration the wallet is *told*. A zero period is a build-time configuration mistake, so it gets `assert!`, which stays on in release builds, unlike `debug_assert!`.

<a id="f-myotis-consensus-src-ssz-rs"></a>

### myotis-consensus/src/ssz.rs

*library · 238 lines · Java twin · SszUtil*

Hand-written SSZ primitives: SHA-256 pair hashing, merkleization with padding, container and list roots, Merkle-branch verification (now in two flavors), and *checked* little-endian readers. Hand-written because the pre-Gloas light-client wire types are fork-polymorphic, with sizes sniffed at run time, which derive-based SSZ libraries can't express.

`rust/myotis-consensus/src/ssz.rs` · lines 44–58

```rust
pub fn merkleize_with_limit(chunks: &[Root], limit: usize) -> Root {
    let size = next_power_of_two(chunks.len()).max(next_power_of_two(limit));
    let mut layer: Vec<Root> = Vec::with_capacity(size);
    layer.extend_from_slice(chunks);
    layer.resize(size, zero_hash(0));
    // In-place pairwise reduction: no per-level reallocation.
    let mut len = size;
    while len > 1 {
        for i in 0..len / 2 {
            layer[i] = sha256_pair(&layer[2 * i], &layer[2 * i + 1]);
        }
        len /= 2;
    }
    layer[0]
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* `layer[i] = sha256_pair(&layer[2 * i], &layer[2 * i + 1]);` The two shared borrows on the right end when the call returns, before the indexed write happens. That's why an in-place reduction compiles.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* In `sha256_pair` (line 21), `h.finalize().into()` converts the digest into `[u8; 32]`. The target type is inferred from the function's return type.

`rust/myotis-consensus/src/ssz.rs` · lines 124–166

```rust
/// Verify an SSZ Merkle inclusion proof (mirrors `SszUtil.verifyMerkleBranch`).
pub fn verify_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    depth: usize,
    index: u64,
    root: &Root,
) -> bool {
    if branch.len() != depth {
        return false;
    }
    let mut value = *leaf;
    for (i, node) in branch.iter().enumerate() {
        value = if (index >> i) & 1 == 1 {
            sha256_pair(node, &value)
        } else {
            sha256_pair(&value, node)
        };
    }
    value == *root
}

/// `is_valid_normalized_merkle_branch` (consensus-specs, Electra light client):
/// a branch LONGER than the depth of `gindex` is accepted only when every extra
/// leading node is zero — how an object carried in a later fork's shape pads a
/// shallower proof (a Gloas update's pre-Gloas finalized header proves its block
/// hash at depth 9 inside an 11-node vector). A shorter branch is a rejection.
pub fn verify_normalized_merkle_branch(
    leaf: &Root,
    branch: &[Root],
    gindex: u64,
    root: &Root,
) -> bool {
    if gindex < 2 {
        return false; // gindex 1 is the root itself; 0 names nothing
    }
    let depth = (63 - gindex.leading_zeros()) as usize;
    let Some(extra) = branch.len().checked_sub(depth) else {
        return false;
    };
    branch[..extra].iter().all(|node| *node == [0u8; 32])
        && verify_merkle_branch(leaf, &branch[extra..], depth, gindex, root)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* `let mut value = *leaf;` copies 32 bytes out of the reference, since `Root = [u8; 32]` is `Copy`, then the loop overwrites the local copy. Bit *i* of the index says whether the running value is the right or the left child at level *i*. Only the low `depth` bits are read, so passing the full gindex works.
- *[Protocol & domain](01-primer.md#primer-domain)* **The normalized check is new.** It accepts a branch that is *longer* than the gindex's depth only when every extra leading node is zero, then verifies the rest normally. That is how a Fulu header in the Gloas shape fits its 9-level proof into an 11-node vector.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let Some(extra) = branch.len().checked_sub(depth) else { return false; };` turns “shorter than the depth” (an underflow) into a rejection. `&&` short-circuits, so the hashing never runs on a dirty pad.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `branch[..extra].iter().all(|node| *node == [0u8; 32])`: a sub-slice, an iterator over references, and a closure that dereferences each one to compare the arrays by value.

`rust/myotis-consensus/src/ssz.rs` · lines 168–182

```rust
// ---- little-endian readers over untrusted input (checked) ----

pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

pub fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

pub fn read_root(data: &[u8], offset: usize) -> Option<Root> {
    data.get(offset..offset + 32).map(|b| b.try_into().unwrap())
}
```

*[Result, ? and panics](01-primer.md#primer-error-handling) · [Bytes, strings & formatting](01-primer.md#primer-bytes-strings)* `data.get(offset..offset + 4)` is `None` when out of range. Inside `.map(…)` the slice is guaranteed to be exactly 4 bytes, so `try_into().unwrap()` cannot fail. This is an `unwrap` with a proof beside it.

<a id="f-myotis-consensus-src-types-rs"></a>

### myotis-consensus/src/types.rs

*library · 943 lines · Java twin · consensus.types decoders*

SSZ decoders and `hash_tree_root` for the light-client containers. The pre-Gloas decoders, like the Java ones, *sniff* pre-Electra vs Electra layouts from leading offsets. The Gloas decoders take an exact size and nothing else. Malformed input returns `Err(SszError)`, never panics. The unit tests reproduce panics that were fixed earlier and pin the Gloas sizes.

| Lines | What happens |
|---|---|
| 1–31 | Module doc, `SszError` (with `Display` and, under `std`, `std::error::Error`), the `err` helper. |
| 33–86 | `BeaconBlockHeader` (112 bytes), with `encode` returning `[u8; Self::ENCODED_SIZE]`. |
| 88–148 | `SyncCommittee` (24,624 bytes), with a hand-written `Debug`. |
| 150–186 | `SyncAggregate` (160 bytes), `count_participants`, `get_bit`. |
| 188–301 | `ExecutionPayloadHeader`: Deneb 584 / Electra 680 bytes; request roots are `Option`. |
| 303–437 | `HeaderExecution`, `LightClientHeader` in both shapes, `read_roots`. |
| 439–524 | `LightClientBootstrap`: Gloas 25,472 bytes; pre-Gloas branch of 5 or 6 nodes. |
| 526–664 | `LightClientUpdate`: Gloas 26,424 bytes; pre-Gloas branches 5/6 and 6/7. |
| 666–783 | `LightClientFinalityUpdate`: Gloas 1,448 bytes; pre-Gloas branch 6 or 7. |
| 785–812 | Compile-time proof that a Gloas object is never the size of a pre-Gloas one. |
| 814–943 | Tests. |

`rust/myotis-consensus/src/types.rs` · lines 95–123

```rust
#[derive(Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// The 512 pubkeys flattened (512 * 48 bytes) — the layout myotis-bls consumes.
    pub pubkeys: Vec<u8>,
    pub aggregate_pubkey: [u8; PUBKEY_SIZE],
}

impl SyncCommittee {
    pub const ENCODED_SIZE: usize = SYNC_COMMITTEE_SIZE * PUBKEY_SIZE + PUBKEY_SIZE; // 24624

    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::ENCODED_SIZE {
            return err(format!(
                "SyncCommittee requires {} bytes, got {}",
                Self::ENCODED_SIZE,
                ssz_bytes.len()
            ));
        }
        let pubkeys = ssz_bytes[..SYNC_COMMITTEE_SIZE * PUBKEY_SIZE].to_vec();
        let aggregate_pubkey = ssz_bytes
            [SYNC_COMMITTEE_SIZE * PUBKEY_SIZE..Self::ENCODED_SIZE]
            .try_into()
            .unwrap();
        Ok(Self { pubkeys, aggregate_pubkey })
    }

    pub fn pubkey(&self, i: usize) -> &[u8] {
        &self.pubkeys[i * PUBKEY_SIZE..(i + 1) * PUBKEY_SIZE]
    }
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers)* **Heap vs inline.** `pubkeys: Vec<u8>` is 24,576 bytes on the heap; `aggregate_pubkey: [u8; 48]` sits inside the struct. Cloning a `SyncCommittee` copies the whole `Vec`, which is why `store.rs` prefers moving committees.
- *[Borrowing & slices](01-primer.md#primer-borrowing)* `pubkey(&self, i) -> &[u8]` lends a 48-byte window into the flat buffer, with no copy.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* The type derives `Clone, PartialEq, Eq` but implements `Debug` by hand (lines 144–148), the Rust spelling of overriding `toString()`, so a log line doesn't print 24 KB of hex.

#### One header, two shapes

`rust/myotis-consensus/src/types.rs` · lines 309–334

```rust
/// What a light-client header proves about the execution layer. The shape is its
/// fork's ([`LcFork`]), and so is the proof: see
/// `LightClientProcessor::verify_execution_branch_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderExecution {
    /// Capella..Fulu: the whole execution payload header, bound to the beacon
    /// body at `EXECUTION_PAYLOAD_GINDEX` (25) by a 4-node branch. Boxed: it is
    /// ~20× the other variant.
    Payload(Box<ExecutionPayloadHeader>),
    /// Gloas shape: the execution block hash alone, bound at
    /// `EXECUTION_BLOCK_HASH_GINDEX_GLOAS` (2856) by an 11-node branch — or, for a
    /// pre-Gloas header carried in the Gloas shape (a Gloas update's finalized
    /// header in the first epochs after the fork), at
    /// `EXECUTION_BLOCK_HASH_GINDEX_DENEB` (812) normalized to 11 nodes. At a
    /// Gloas slot it is the PARENT payload's hash (`bid.parent_block_hash`): the
    /// slot's own payload is revealed separately and may be withheld, the parent
    /// is one the chain has imported. No state root, number or timestamp: those
    /// come from the execution header this hash pins.
    BlockHash(Root),
}

impl Default for HeaderExecution {
    fn default() -> Self {
        HeaderExecution::Payload(Box::default())
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **A sum type.** In Kotlin you would write a `sealed class` with two subclasses; in Java a sealed interface with two records. A Rust `enum` variant can carry data, and a value is exactly one variant at a time. The compiler forces every `match` to handle both, so no code path can forget that a Gloas header has no state root.
- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Ownership & moves](01-primer.md#primer-ownership)* **Why `Box`.** An enum is as large as its largest variant. An `ExecutionPayloadHeader` is about 470 bytes inline (eight roots, two `Vec` handles, six `u64`, three `Option<Root>`), against 32 for the hash. `Box<ExecutionPayloadHeader>` moves the payload to the heap and leaves an 8-byte pointer in the enum, so a Gloas header doesn't pay for space it never uses. The `Box` owns its contents: dropping the header frees them, and `clone()` deep-copies them.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl Default for HeaderExecution` is written by hand because `#[derive(Default)]` on an enum needs a `#[default]` unit variant. `Box::default()` builds a boxed `ExecutionPayloadHeader::default()`, which is what lets `LightClientHeader` keep its `#[derive(Default)]`.

`rust/myotis-consensus/src/types.rs` · lines 398–430

```rust
    /// Decode in the wire format of `fork`.
    pub fn decode_for(fork: LcFork, ssz_bytes: &[u8]) -> Result<Self, SszError> {
        match fork {
            LcFork::PreGloas => Self::decode(ssz_bytes),
            LcFork::Gloas => Self::decode_gloas(ssz_bytes),
        }
    }

    /// The execution block hash this header proves, in either shape.
    pub fn execution_block_hash(&self) -> Root {
        match &self.execution {
            HeaderExecution::Payload(p) => p.block_hash,
            HeaderExecution::BlockHash(h) => *h,
        }
    }

    /// The execution payload header, when this is the pre-Gloas shape.
    pub fn execution_payload(&self) -> Option<&ExecutionPayloadHeader> {
        match &self.execution {
            HeaderExecution::Payload(p) => Some(p.as_ref()),
            HeaderExecution::BlockHash(_) => None,
        }
    }

    /// Which wire shape this header was decoded from — NOT the fork of its slot:
    /// a Gloas update carries a pre-Gloas finalized header in the Gloas shape.
    pub fn shape(&self) -> LcFork {
        match self.execution {
            HeaderExecution::Payload(_) => LcFork::PreGloas,
            HeaderExecution::BlockHash(_) => LcFork::Gloas,
        }
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* `match &self.execution` matches through a reference, so `p` binds as `&Box<ExecutionPayloadHeader>` and `h` as `&Root`. `*h` copies the 32 bytes out. `p.as_ref()` turns the `&Box<T>` into a plain `&T`.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Ownership & moves](01-primer.md#primer-ownership)* `shape()` writes `match self.execution` *without* `&`, even though `self` is only borrowed. That compiles because the patterns use `_`, which binds nothing, so nothing is moved out. Write `Payload(p)` there and the compiler refuses: it would have to move the `Box` out of borrowed data.
- *[Protocol & domain](01-primer.md#primer-domain)* `shape()` is the shape the bytes were decoded from, *not* the fork of the header's slot. The two differ for exactly one case: a Fulu finalized header carried by a Gloas update.

*[Result, ? and panics](01-primer.md#primer-error-handling)* `decode_gloas` just above (lines 379–396) requires `len() == GLOAS_SIZE` exactly, not “at least”. One byte short or one byte long is an `Err`: there is no tail to silently ignore. It reads the 11 branch nodes with `read_roots`, which collects into an `Option<Vec<Root>>` (lines 433–437).

#### Sniffing a pre-Gloas bootstrap

`rust/myotis-consensus/src/types.rs` · lines 488–524

```rust
    pub fn decode(ssz_bytes: &[u8]) -> Result<Self, SszError> {
        if ssz_bytes.len() < Self::MIN_FIXED_SIZE {
            return err(format!(
                "LightClientBootstrap requires at least {} bytes, got {}",
                Self::MIN_FIXED_SIZE,
                ssz_bytes.len()
            ));
        }
        let header_offset = ssz::read_u32(ssz_bytes, 0).unwrap() as usize;
        // The header offset IS the fixed size; derive the fork-dependent branch len.
        let branch_bytes = header_offset
            .checked_sub(4 + SyncCommittee::ENCODED_SIZE)
            .unwrap_or(0);
        let branch_nodes = branch_bytes / 32;
        if !(5..=6).contains(&branch_nodes) || branch_bytes % 32 != 0 {
            return err(format!(
                "Invalid branch size: {branch_bytes} bytes (expected 160 or 192) in LightClientBootstrap"
            ));
        }
        let current_sync_committee =
            SyncCommittee::decode(&ssz_bytes[4..4 + SyncCommittee::ENCODED_SIZE])?;
        let branch_start = 4 + SyncCommittee::ENCODED_SIZE;
        // branch_nodes was sniffed from the ATTACKER-CONTROLLED offset: a 6-node
        // claim on a 5-node-sized buffer must reject, not panic (checked reads).
        let current_sync_committee_branch: Vec<Root> = (0..branch_nodes)
            .map(|i| ssz::read_root(ssz_bytes, branch_start + i * 32))
            .collect::<Option<_>>()
            .ok_or_else(|| SszError("LightClientBootstrap: truncated branch".into()))?;
        if header_offset > ssz_bytes.len() {
            return err(format!(
                "Invalid header offset {header_offset} in LightClientBootstrap"
            ));
        }
        let header = LightClientHeader::decode(&ssz_bytes[header_offset..])?;
        Ok(Self { header, current_sync_committee, current_sync_committee_branch })
    }
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `.collect::<Option<_>>()` on an iterator of `Option<Root>` yields `Some(Vec)` if *every* read succeeded and `None` at the first gap: all or nothing, for free. `ok_or_else(…)?` turns the gap into an early `Err`.
- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Protocol & domain](01-primer.md#primer-domain)* `branch_nodes` comes from an **attacker-controlled offset**, so the branch reads are checked. The fixed-position read `read_u32(ssz_bytes, 0).unwrap()` is safe because the length was checked first. Note also `checked_sub(…).unwrap_or(0)`: an underflow becomes 0, which then fails the 5-or-6 check.

*[Iterators & closures](01-primer.md#primer-iterators-closures)* In the payload header (lines 271–273), `is_electra.then(|| g(584))` reads the Electra request roots *only when* the flag is true. `bool::then` takes a closure, so nothing is evaluated eagerly.

#### A Gloas update: offsets as constants

`rust/myotis-consensus/src/types.rs` · lines 562–594

```rust
/// Decode the Gloas format: exactly [`Self::GLOAS_SIZE`] bytes.
pub fn decode_gloas(ssz_bytes: &[u8]) -> Result<Self, SszError> {
    if ssz_bytes.len() != Self::GLOAS_SIZE {
        return err(format!(
            "Gloas LightClientUpdate requires {} bytes, got {}",
            Self::GLOAS_SIZE,
            ssz_bytes.len()
        ));
    }
    const H: usize = LightClientHeader::GLOAS_SIZE;
    const NSC: usize = H;
    const NSC_BRANCH: usize = NSC + SyncCommittee::ENCODED_SIZE;
    const FINALIZED: usize = NSC_BRANCH + spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN * 32;
    const FIN_BRANCH: usize = FINALIZED + H;
    const AGG: usize = FIN_BRANCH + spec::GLOAS_FINALITY_BRANCH_LEN * 32;
    const SLOT: usize = AGG + SyncAggregate::ENCODED_SIZE;
    let truncated = || SszError("Gloas LightClientUpdate: truncated".into());
    Ok(Self {
        attested_header: LightClientHeader::decode_gloas(&ssz_bytes[..H])?,
        next_sync_committee: SyncCommittee::decode(&ssz_bytes[NSC..NSC_BRANCH])?,
        next_sync_committee_branch: read_roots(
            ssz_bytes,
            NSC_BRANCH,
            spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
        )
        .ok_or_else(truncated)?,
        finalized_header: LightClientHeader::decode_gloas(&ssz_bytes[FINALIZED..FIN_BRANCH])?,
        finality_branch: read_roots(ssz_bytes, FIN_BRANCH, spec::GLOAS_FINALITY_BRANCH_LEN)
            .ok_or_else(truncated)?,
        sync_aggregate: SyncAggregate::decode(&ssz_bytes[AGG..SLOT])?,
        signature_slot: ssz::read_u64(ssz_bytes, SLOT).ok_or_else(truncated)?,
    })
}
```

- *[Crates, modules & features](01-primer.md#primer-modules-cargo)* A `const` inside a function is still a compile-time constant. Each offset is built from the previous one, so the layout reads top to bottom like the spec's container definition.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `let truncated = || SszError(…);` captures nothing, and a closure that captures nothing is `Copy`. That is why the same `truncated` can be passed by value to `ok_or_else` four times.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The slices `&ssz_bytes[..H]` and so on index directly, which would panic out of range. They cannot: every bound is a constant below the exact length checked on line 564.

`rust/myotis-consensus/src/types.rs` · lines 789–812

```rust
/// The smallest canonical pre-Gloas header of the forks these decoders serve:
/// the fixed part plus a Capella payload header with empty `extra_data` (568
/// bytes; Deneb's and Electra's are larger).
const MIN_PRE_GLOAS_HEADER_SIZE: usize = LightClientHeader::FIXED_SIZE + 568; // 812

// Every Gloas container is fixed-size and smaller than the smallest canonical
// pre-Gloas encoding of the same type, so a payload of exactly the Gloas size
// is a Gloas object whatever its context bytes say. That is what lets the sync
// loop read a Gloas object under a fork digest it does not compute (a later
// blob-parameter fork) without ever misreading a pre-Gloas one
// (`ChainConfig::lc_fork_of_chunk` in myotis-net).
const _: () = assert!(LightClientHeader::GLOAS_SIZE < MIN_PRE_GLOAS_HEADER_SIZE);
const _: () = assert!(
    LightClientBootstrap::GLOAS_SIZE
        < LightClientBootstrap::MIN_FIXED_SIZE + MIN_PRE_GLOAS_HEADER_SIZE
);
const _: () = assert!(
    LightClientUpdate::GLOAS_SIZE
        < LightClientUpdate::MIN_FIXED_SIZE + 2 * MIN_PRE_GLOAS_HEADER_SIZE
);
const _: () = assert!(
    LightClientFinalityUpdate::GLOAS_SIZE
        < LightClientFinalityUpdate::MIN_FIXED_SIZE + 2 * MIN_PRE_GLOAS_HEADER_SIZE
);
```

*[Macros & attributes](01-primer.md#primer-macros) · [Protocol & domain](01-primer.md#primer-domain)* `const _: () = assert!(…);` is Rust's static assert. The expression is evaluated at compile time, and a failing `assert!` in a const context is a build error. The fact being proven is that a Gloas object is always smaller than the smallest canonical pre-Gloas one. So if the sync loop receives an object under a fork digest it does not recognize, the size alone tells the two formats apart without misreading. The comment names the consumer, `ChainConfig::lc_fork_of_chunk` in `myotis-net`.

<a id="f-myotis-consensus-src-verify-rs"></a>

### myotis-consensus/src/verify.rs

*library · 68 lines · Java twin · SyncCommitteeVerifier + ForkData.computeDomain*

Signature verification in three functions: `compute_domain`, `compute_signing_root`, and `verify_sync_aggregate`. The last requires at least 2/3 participation using integer math, flattens the participating pubkeys, and makes a single `myotis_bls` call. Gloas changed nothing here: the signature still covers only the beacon header.

`rust/myotis-consensus/src/verify.rs` · lines 33–68

```rust
/// Verify a sync aggregate over an attested header (mirrors
/// `SyncCommitteeVerifier.verify`): ≥2/3 participation, then
/// fast_aggregate_verify of the participating pubkeys over the signing root.
pub fn verify_sync_aggregate(
    sync_aggregate: &SyncAggregate,
    committee: &SyncCommittee,
    attested_header: &BeaconBlockHeader,
    fork_version: &[u8; 4],
    genesis_validators_root: &Root,
) -> bool {
    let participants = sync_aggregate.count_participants();
    if participants * 3 < spec::SYNC_COMMITTEE_SIZE * 2 {
        return false;
    }

    let mut pubkeys = Vec::with_capacity(participants * PUBKEY_SIZE);
    for i in 0..spec::SYNC_COMMITTEE_SIZE {
        if sync_aggregate.get_bit(i) {
            pubkeys.extend_from_slice(committee.pubkey(i));
        }
    }

    let domain = compute_domain(
        &spec::DOMAIN_SYNC_COMMITTEE,
        fork_version,
        genesis_validators_root,
    );
    let signing_root = compute_signing_root(&attested_header.hash_tree_root(), &domain);

    myotis_bls::fast_aggregate_verify(
        &pubkeys,
        participants,
        &signing_root,
        &sync_aggregate.sync_committee_signature,
    )
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing)* A borrow-only API: every parameter is `&`. The function reads and allocates only its own scratch buffer.
- *[Ownership & moves](01-primer.md#primer-ownership)* `pubkeys.extend_from_slice(committee.pubkey(i))` copies each borrowed 48-byte window into an owned, pre-sized buffer. That flat layout is exactly what `fast_aggregate_verify` expects.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* `&attested_header.hash_tree_root()` borrows a *temporary*. Temporaries live until the end of the enclosing statement, so the reference stays valid during the call.
- *[Protocol & domain](01-primer.md#primer-domain)* `participants * 3 < 512 * 2` is the 2/3 threshold without floating point.

<a id="f-myotis-consensus-src-fork-rs"></a>

### myotis-consensus/src/fork.rs

*library · 314 lines · Java twin · ForkSchedule*

A network's append-only list of `(activation_epoch, fork_version)`, that chain's slots per epoch, and now the epoch at which Gloas activates. It answers two different questions. “Which version signed an aggregate at `signature_slot`?” uses the epoch of `max(slot, 1) − 1`. “Which wire format do this slot's objects use?” uses the slot's own epoch. The module docs explain the #295 bug the schedule fixed: with a single configured version, sync stalled at every fork boundary.

`rust/myotis-consensus/src/fork.rs` · lines 37–52

```rust
/// The light-client wire format of a slot's objects.
///
/// Before Gloas a `LightClientHeader` carries the whole execution payload header
/// (Capella through Fulu; the decoders tell those shapes apart by their offsets,
/// as they always have). From Gloas on it carries only the execution block hash
/// (EIP-7732: the body holds a payload bid, not a payload), and every container
/// is fixed-size — nothing left to sniff. Which one an object uses is decided by
/// the fork of its attested slot (a bootstrap's: its header's slot), exactly as
/// the spec's `*_gindex_at_slot` helpers and the req/resp context bytes do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcFork {
    /// Capella..Fulu: execution payload header, depth-derived state gindices.
    PreGloas,
    /// Gloas: execution block hash, fixed Gloas gindices.
    Gloas,
}
```

*[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Traits, generics & dyn](01-primer.md#primer-traits-generics)* A data-less enum that derives `Copy`, `PartialEq` and `Eq` behaves like a Java enum constant: it is passed by value, compared with `==`, and costs one byte. There are only two variants because the pre-Gloas decoders still tell Capella through Fulu apart by sniffing; only Gloas has to be named.

`rust/myotis-consensus/src/fork.rs` · lines 54–72

```rust
/// Ordered fork schedule for one chain. Constructed once per network from
/// compile-time constants; invalid geometry is a build error surfacing, so the
/// constructor panics rather than returning a `Result` nobody would handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Slots per epoch for THIS chain (32 on the mainnet preset, 16 on
    /// gnosis). Needed to map a signature slot to the epoch the schedule is
    /// keyed by. Bundled here — rather than passed alongside every lookup —
    /// so a schedule can never be read with another chain's geometry.
    slots_per_epoch: u64,
    /// `(activation_epoch, fork_version)`, strictly ascending by epoch, first
    /// entry at epoch 0 (the genesis fork).
    forks: Vec<(u64, [u8; 4])>,
    /// Activation epoch of Gloas, `None` while this chain has none scheduled.
    /// Always one of `forks`' epochs (see [`Self::with_gloas_epoch`]): the
    /// version list says WHICH domain signs a slot, this says which wire format
    /// and which proof indices its light-client objects use.
    gloas_epoch: Option<u64>,
}
```

- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* **Invariants through privacy.** The fields are private and `new` (lines 80–97) is the only constructor. It asserts a non-zero slot length, a non-empty list, a genesis entry at epoch 0, and strictly ascending epochs (using `forks.windows(2)`). That is what makes `newest()`'s `self.forks[self.forks.len() - 1]` safe.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* The constructor *panics* on invalid geometry, deliberately. These values come from compile-time constants, and a `Result` nobody could meaningfully handle would just hide the mistake.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* `new(…, forks: &[(u64, [u8; 4])])` borrows the caller's constant list and stores an owned copy (`forks.to_vec()`).

`rust/myotis-consensus/src/fork.rs` · lines 99–131

```rust
/// Mark the scheduled fork activating at `epoch` as Gloas. PANICS unless
/// `epoch` is one of the schedule's activation epochs: a Gloas epoch that
/// disagrees with the version list would decode and verify a slot's objects
/// in one fork's format while signing them under another's domain.
pub fn with_gloas_epoch(mut self, epoch: u64) -> Self {
    assert!(
        self.forks
            .iter()
            .any(|(activation, _)| *activation == epoch),
        "fork schedule: the Gloas epoch {epoch} must be a scheduled activation"
    );
    self.gloas_epoch = Some(epoch);
    self
}

/// Gloas' activation epoch, if this chain has one scheduled.
pub fn gloas_epoch(&self) -> Option<u64> {
    self.gloas_epoch
}

/// The light-client wire format of objects at `epoch`.
pub fn lc_fork_at_epoch(&self, epoch: u64) -> LcFork {
    match self.gloas_epoch {
        Some(gloas) if epoch >= gloas => LcFork::Gloas,
        _ => LcFork::PreGloas,
    }
}

/// The light-client wire format of objects at `slot` (an update's attested
/// slot, a bootstrap's header slot, a header's own slot).
pub fn lc_fork_at_slot(&self, slot: u64) -> LcFork {
    self.lc_fork_at_epoch(slot / self.slots_per_epoch)
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Methods & self](01-primer.md#primer-methods)* **A consuming builder.** `with_gloas_epoch(mut self, epoch) -> Self` takes the schedule *by value*, changes one field, and hands it back. A caller writes `ForkSchedule::new(…).with_gloas_epoch(10)`. The original binding is moved into the call, so no other code can hold a half-configured copy. The `mut` belongs to the parameter binding, not to the type.
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Some(gloas) if epoch >= gloas => LcFork::Gloas` is a match arm with a *guard*. If the guard is false the arm doesn't match and `_` catches it, which also covers `None`: a chain with no Gloas date is pre-Gloas forever.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `.any(|(activation, _)| *activation == epoch)` destructures each borrowed tuple in the closure's parameter. `activation` is a `&u64`, hence the `*`.

`rust/myotis-consensus/src/fork.rs` · lines 164–194

```rust
/// The version of the fork BEFORE the one active at `epoch`, or `None`
/// when that is the genesis fork — the discv5 prior-digest fallback input.
pub fn prior_version_at_epoch(&self, epoch: u64) -> Option<[u8; 4]> {
    let i = self.index_at_epoch(epoch);
    (i >= 1).then(|| self.forks[i - 1].1)
}

fn index_at_epoch(&self, epoch: u64) -> usize {
    // Ascending list; the last entry with activation <= epoch wins.
    let mut idx = 0;
    for (i, (activation, _)) in self.forks.iter().enumerate() {
        if *activation <= epoch {
            idx = i;
        } else {
            break;
        }
    }
    idx
}

/// The fork version a sync aggregate signed at `signature_slot` must be
/// verified under — spec `validate_light_client_update`:
/// `compute_fork_version(compute_epoch_at_slot(max(signature_slot, 1) - 1))`.
///
/// The `- 1` is not a detail: the aggregate is over the block of the
/// PREVIOUS slot, so a signature at the first slot of a fork's activation
/// epoch still uses the old version, and only the next slot switches.
pub fn version_for_signature_slot(&self, signature_slot: u64) -> [u8; 4] {
    // slots_per_epoch is non-zero by construction (see `new`).
    self.version_at_epoch((signature_slot.max(1) - 1) / self.slots_per_epoch)
}
```

- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `(i >= 1).then(|| self.forks[i - 1].1)` only evaluates the closure when `i ≥ 1`. `then_some(self.forks[i - 1].1)` would evaluate the argument first, underflow `usize` for `i == 0`, and crash.
- *[Protocol & domain](01-primer.md#primer-domain)* `signature_slot.max(1) - 1` is the spec's `max(signature_slot, 1) - 1`. The aggregate signs the block of the previous slot, so the first slot of a new fork's epoch still signs under the old version.

`rust/myotis-consensus/src/fork.rs` · lines 291–307

```rust
#[test]
fn the_lc_format_switches_at_the_gloas_epoch() {
    let s = three();
    assert_eq!(s.gloas_epoch(), None);
    assert_eq!(s.lc_fork_at_epoch(u64::MAX), LcFork::PreGloas, "no date is not a far-future date");
    let s = three().with_gloas_epoch(20);
    assert_eq!(s.gloas_epoch(), Some(20));
    assert_eq!(s.lc_fork_at_epoch(19), LcFork::PreGloas);
    assert_eq!(s.lc_fork_at_epoch(20), LcFork::Gloas);
    assert_eq!(s.lc_fork_at_slot(639), LcFork::PreGloas); // epoch 19
    assert_eq!(s.lc_fork_at_slot(640), LcFork::Gloas); // epoch 20

    // Unlike the signing domain, the format is the slot's own fork — no
    // off-by-one: the first Gloas slot's objects are Gloas-shaped even
    // though a signature AT that slot still verifies under the old domain.
    assert_eq!(s.version_for_signature_slot(640), B);
}
```

*[Tests](01-primer.md#primer-testing) · [Protocol & domain](01-primer.md#primer-domain)* The two rules side by side: slot 640 is the first Gloas slot, its objects are Gloas-shaped, and a signature at that slot still verifies under version B (the fork before). The message on the second assert (“no date is not a far-future date”) records a design choice: a missing Gloas epoch is `None`, never `u64::MAX`.

<a id="f-myotis-consensus-src-store-rs"></a>

### myotis-consensus/src/store.rs

*library · 636 lines · Java twin · LightClientStore / LightClientProcessor*

Two types and a free function. `LightClientStore` is the state: finalized and optimistic headers and slots, the current and next committees, the current period, and this chain's slots per period. `LightClientProcessor` owns a store and applies updates through a fixed sequence of gates. `verify_execution_branch_at` binds a signed beacon header to the execution layer, in either shape. The single clock input (`force_rotate_if_past_period`) is a plain parameter.

![The order of checks in process_update. Row one: 1 committee gate, 2 adoption gate, 3 shape gate, 4 BLS verify. Row two: 5 finality branch, 6 execution branches, 7 next-committee branch, 8 apply and rotate. Steps 1 to 3 are cheap and run before the expensive BLS verify.](img/06-consensus-1.svg)

*The order inside `process_update`. Any failed step returns `false` and leaves the store untouched. Steps 1 to 3 are cheap and run before the BLS verify, which a doc comment in `tests/gloas_boundary.rs` puts at about 17 to 30 seconds per verify on Android's runtime (ART). `process_finality_update` runs the same order without steps 2 and 7.*

| Lines | What happens |
|---|---|
| 17–63 | The store struct, `new` (refuses a zero period), `new_mainnet_preset`, `period_of`. |
| 65–121 | `initialize`, monotonic header updates, and the two rotation paths. |
| 123–180 | Lending getters, `snapshot()`, consuming `restore(s)`. |
| 182–196 | `headers_in_attested_forks_shape`: the shape gate as a public free function, so diagnostics in `myotis-net` (`period_census`, the live pin check) reuse it. |
| 198–287 | `LightClientProcessor`, the two header checks, `verify_bootstrap`. |
| 289–312 | `verify_finality_branch`: the gindex by the attested slot's fork. |
| 314–455 | `process_update`. |
| 457–470 | `committee_for`: the period gate and key selection in one place. |
| 472–558 | `process_finality_update` and `apply_finality_update`. |
| 560–592 | `FinalityOutcome`, `BootstrapReject` and its `Display`. |
| 594–636 | `verify_execution_branch_at`. |

#### The state and how it rotates

`rust/myotis-consensus/src/store.rs` · lines 65–74

```rust
pub fn initialize(&mut self, header: LightClientHeader, committee: SyncCommittee) {
    self.finalized_slot = header.beacon.slot;
    self.optimistic_slot = header.beacon.slot;
    self.current_sync_committee_period =
        self.period_of(self.finalized_slot);
    self.finalized_header = Some(header.clone());
    self.optimistic_header = Some(header);
    self.current_sync_committee = Some(committee);
    self.next_sync_committee = None;
}
```

*[Ownership & moves](01-primer.md#primer-ownership)* `initialize` takes the header and committee **by value**. It needs the header twice, so it clones once (line 70) and moves the original (line 71). After line 71, `header` can't be used. In Java, both fields would simply alias one object. The constructor above it, `Self { slots_per_period, ..Self::default() }`, uses *struct update syntax*: every field not listed comes from `Default`.

`rust/myotis-consensus/src/store.rs` · lines 98–121

```rust
pub fn apply_next_when_period_changes(&mut self, old_finalized_slot: u64, new_finalized_slot: u64) {
    if self.next_sync_committee.is_none() {
        return;
    }
    let old_period = self.period_of(old_finalized_slot);
    let new_period = self.period_of(new_finalized_slot);
    if new_period > old_period {
        self.current_sync_committee = self.next_sync_committee.take();
        self.current_sync_committee_period += 1;
    }
}

/// Mirrors `LightClientStore.forceRotateIfPastPeriod` (the live loop's — and the
/// conformance corpus's — recorded-slot-estimate rotation between updates).
pub fn force_rotate_if_past_period(&mut self, current_slot_estimate: u64) {
    if self.next_sync_committee.is_none() {
        return;
    }
    let wall_period = self.period_of(current_slot_estimate);
    if wall_period > self.current_sync_committee_period {
        self.current_sync_committee = self.next_sync_committee.take();
        self.current_sync_committee_period += 1;
    }
}
```

- *[Ownership & moves](01-primer.md#primer-ownership) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `self.next_sync_committee.take()` moves the 24 KB committee out and leaves `None`, exactly the state the store needs next, with no copy. It's `mem::replace(&mut x, None)` with a friendlier name. The old current committee is dropped when it's overwritten.
- *[Protocol & domain](01-primer.md#primer-domain)* Two triggers, one effect. `apply_next_when_period_changes` rotates when an applied update's finalized slot crosses into a later period. `force_rotate_if_past_period` rotates when the caller's wall-clock estimate is past the store's period. Both need a held next committee: without one there is nothing to rotate into.

![Store state machine. Uninitialized moves to period P without next committee through initialize or restore. A verified update attested in P whose next-committee branch checks out moves it to period P with next committee held. When the finalized slot crosses into a later period, or the wall clock is past P, next is taken into current and the period increments, returning to the no-next state at P plus one.](img/06-consensus-2.svg)

*Selecting the committee *is* the gate: a signature from period P is checked with the current committee, one from P+1 only with a *held* next committee, and anything else is rejected before any BLS work (#423). The middle arrow is narrower than it was in September: only an update *attested* in P may supply the next committee (see [next\_committee\_adoption.rs](#f-myotis-consensus-tests-next-committee-adoption-rs)).*

#### The bootstrap check

`rust/myotis-consensus/src/store.rs` · lines 250–281

```rust
pub fn verify_bootstrap(
    &self,
    bootstrap: &LightClientBootstrap,
) -> Result<(), BootstrapReject> {
    let fork = self.lc_fork_at_slot(bootstrap.header.beacon.slot);
    if bootstrap.header.shape() != fork {
        return Err(BootstrapReject::ShapeNotItsForks);
    }
    let (depth, gindex) = match fork {
        LcFork::Gloas => (
            spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
            spec::CURRENT_SYNC_COMMITTEE_GINDEX_GLOAS,
        ),
        LcFork::PreGloas => {
            let depth = bootstrap.current_sync_committee_branch.len();
            (depth, spec::sync_committee_gindex(depth))
        }
    };
    if !ssz::verify_merkle_branch(
        &bootstrap.current_sync_committee.hash_tree_root(),
        &bootstrap.current_sync_committee_branch,
        depth,
        gindex,
        &bootstrap.header.beacon.state_root,
    ) {
        return Err(BootstrapReject::SyncCommitteeBranch);
    }
    if !self.verify_header(&bootstrap.header) {
        return Err(BootstrapReject::ExecutionBranch);
    }
    Ok(())
}
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `Result<(), BootstrapReject>` is Rust's “success with no value, or one of three reasons”. The caller in `myotis-net/src/sync.rs` writes `if let Err(reason) = processor.verify_bootstrap(&bootstrap)` and logs the reason through its `Display` impl (lines 584–592).
- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let (depth, gindex) = match fork { … };` A `match` is an expression, here producing a tuple that is destructured right away. The Gloas arm uses constants; the pre-Gloas arm derives both from the branch's length.
- *[Protocol & domain](01-primer.md#primer-domain)* The checkpoint pin itself (does this header's root equal the root we trust?) is the caller's job, as the doc comment says. This function proves everything else.

#### process\_update, gate by gate

`rust/myotis-consensus/src/store.rs` · lines 314–339

```rust
pub fn process_update(&mut self, update: &LightClientUpdate) -> bool {
    if self.store.current_sync_committee().is_none() {
        tracing::debug!("update rejected: store has no current sync committee");
        return false;
    }

    // Applicability gate BEFORE the expensive BLS verify (per spec
    // validate_light_client_update; mirrors the Java gate exactly).
    let store_period = self.store.current_period();
    let sig_period = self.store.period_of(update.signature_slot);
    // The aggregate is signed by the committee of signature_slot's PERIOD
    // (spec validate_light_client_update): our current committee for
    // store_period, the held next committee for store_period + 1, nothing
    // for anything else. Selecting the keys IS the gate. Verifying both
    // admitted periods with the current keys rejected genuine
    // next-committee updates before rotation and accepted a
    // current-committee signature whose unsigned signature_slot had been
    // relabelled into the next period (#423).
    let Some(committee) = self.committee_for(sig_period) else {
        tracing::debug!(store_period, sig_period,
            have_next = self.store.next_sync_committee().is_some(),
            signature_slot = update.signature_slot,
            attested_slot = update.attested_header.beacon.slot,
            "update rejected: not applicable to the store's period");
        return false;
    };
```

- *[Result, ? and panics](01-primer.md#primer-error-handling) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `let Some(committee) = self.committee_for(sig_period) else { …; return false; };` binds the reference or leaves. The `else` block must diverge (return, break, panic), which the compiler checks.
- *[Macros & attributes](01-primer.md#primer-macros)* `tracing::debug!(store_period, sig_period, have_next = …, "…")` logs structured fields. A bare name like `store_period` is shorthand for `store_period = store_period`, and `?` (used further down) means “format with `Debug`”.

`rust/myotis-consensus/src/store.rs` · lines 341–370

```rust
// A store holding no next committee adopts the one this update carries
// (below): the next committee of the ATTESTED state, i.e. of
// period(attested) + 1. So only an update attested in the store's own
// period can supply it (spec validate_light_client_update counts it
// only when update_attested_period == store_period). The last block of
// P−1 signed at the first slot of P passes the gate above and verifies,
// and its genuine next committee is committee(P) — ours: the rotation
// would install it for P+1, and every P+1 update would then fail BLS.
// Honest servers send that update without a committee (spec
// create_light_client_update), which the branch check below would
// refuse anyway, so this changes no honest verdict. Not required: the
// spec's apply_light_client_update also wants the FINALIZED header in
// the store period. This client adopts from the attested state, as the
// spec's force-update path does, having no best-valid-update timeout:
// requiring finality would stall catch-up at a period that never
// finalized. Java twin: LightClientProcessor.processUpdate.
if self.store.next_sync_committee().is_none() {
    let attested_period = self.store.period_of(update.attested_header.beacon.slot);
    if attested_period != store_period {
        tracing::debug!(
            store_period,
            attested_period,
            sig_period,
            attested_slot = update.attested_header.beacon.slot,
            "update rejected: attested outside the store's period, so its next \
             committee is not the store's next"
        );
        return false;
    }
}
```

*[Protocol & domain](01-primer.md#primer-domain)* **The adoption gate (new).** An update carries the next committee of its *attested* state, which is the committee of period(attested) + 1. The update that slipped through before is the last block of P−1, signed at the first slot of P. It passes the committee gate, its signature verifies against our current keys, and its next committee is genuinely committee(P), with a genuine branch. Adopting it would install committee(P) as P+1's keys at the next rotation, and every P+1 update would fail BLS from then on. The comment also explains a conscious deviation: the spec's apply step wants the *finalized* header in the store's period too, but this client adopts from the attested state so catch-up doesn't stall at a period that never finalized.

`rust/myotis-consensus/src/store.rs` · lines 372–395

```rust
if !self.update_shape_ok(&update.attested_header, &update.finalized_header) {
    tracing::debug!(attested_slot = update.attested_header.beacon.slot,
        attested_shape = ?update.attested_header.shape(),
        finalized_shape = ?update.finalized_header.shape(),
        "update rejected: wire shape is not the attested slot's fork's");
    return false;
}

let fork_version = self.fork_schedule.version_for_signature_slot(update.signature_slot);
if !verify::verify_sync_aggregate(
    &update.sync_aggregate,
    committee,
    &update.attested_header.beacon,
    &fork_version,
    &self.genesis_validators_root,
) {
    tracing::debug!(store_period, sig_period, used_next = sig_period != store_period,
        signature_slot = update.signature_slot,
        attested_slot = update.attested_header.beacon.slot,
        participants = update.sync_aggregate.count_participants(),
        fork_version = ?fork_version,
        "update rejected: sync-aggregate BLS verification failed");
    return false;
}
```

- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* **Non-lexical lifetimes.** `committee` is a `&SyncCommittee` borrowed through `&self`. While it is alive, nothing may mutate `self`. Its last use is the BLS call (line 383), so the borrow ends there, and the `&mut` call `self.store.update_next_sync_committee(…)` on line 445 is allowed. Move a use of `committee` below line 445 and the code stops compiling. The `&self` calls in between (`verify_finality_branch`, `verify_header`) are shared borrows, which may overlap freely.
- *[Protocol & domain](01-primer.md#primer-domain)* `used_next = sig_period != store_period` computes a `bool` just for the log line, so a reader of a failure knows which committee's keys were tried.

`rust/myotis-consensus/src/store.rs` · lines 421–455

```rust
    // Next sync committee: verify + store when we don't already hold one.
    if self.store.next_sync_committee().is_none() {
        let (depth, gindex) = match self.lc_fork_at_slot(update.attested_header.beacon.slot) {
            LcFork::Gloas => (
                spec::GLOAS_SYNC_COMMITTEE_BRANCH_LEN,
                spec::NEXT_SYNC_COMMITTEE_GINDEX_GLOAS,
            ),
            LcFork::PreGloas => {
                let depth = update.next_sync_committee_branch.len();
                (depth, spec::next_sync_committee_gindex(depth))
            }
        };
        if !ssz::verify_merkle_branch(
            &update.next_sync_committee.hash_tree_root(),
            &update.next_sync_committee_branch,
            depth,
            gindex,
            &update.attested_header.beacon.state_root,
        ) {
            tracing::debug!(depth,
                attested_slot = update.attested_header.beacon.slot,
                "update rejected: next-sync-committee branch does not verify");
            return false;
        }
        self.store
            .update_next_sync_committee(update.next_sync_committee.clone());
    }

    let old_finalized = self.store.finalized_slot();
    let finalized_slot = update.finalized_header.beacon.slot;
    self.store.update_finalized(&update.finalized_header, finalized_slot);
    self.store.update_optimistic(&update.attested_header, update.signature_slot);
    self.store.apply_next_when_period_changes(old_finalized, finalized_slot);
    true
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* `update.next_sync_committee.clone()` copies 24 KB because the update is only *borrowed* (`&LightClientUpdate`); its fields can't be moved out. The alternative signature, `process_update(&mut self, update: LightClientUpdate)`, would let the store move the committee but would force every caller to give up its update.
- *[Protocol & domain](01-primer.md#primer-domain)* The order matters: a held next committee is never overwritten. The execution branches are checked separately (step 6, lines 411–419) because the sync-committee signature does not cover the execution part of the header.
- *[Protocol & domain](01-primer.md#primer-domain)* `update_optimistic` receives the *signature* slot, not the attested header's slot. The doc on `optimistic_slot()` (lines 138–146) says why: the value orders updates, and a slot to show the user is `optimistic_header().beacon.slot` (#658).

`rust/myotis-consensus/src/store.rs` · lines 457–470

```rust
/// The committee that signs `sig_period`: the store's current committee
/// for its own period, the held next committee for the period after,
/// `None` otherwise (spec validate_light_client_update's applicability +
/// key selection in one place).
fn committee_for(&self, sig_period: u64) -> Option<&SyncCommittee> {
    let store_period = self.store.current_period();
    if sig_period == store_period {
        self.store.current_sync_committee()
    } else if sig_period == store_period + 1 {
        self.store.next_sync_committee()
    } else {
        None
    }
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing)* `Option<&SyncCommittee>` lends, never copies. The returned reference's lifetime is tied to `&self` by lifetime elision, which is exactly why the NLL point above matters.

#### Stale is not a win

`rust/myotis-consensus/src/store.rs` · lines 536–571

```rust
    /// [`process_finality_update`](Self::process_finality_update), telling a
    /// verified update that ADVANCED the store apart from one that verified
    /// but moved nothing — the store already held a finalized and an
    /// optimistic header at least as new (a server re-serving the same update,
    /// or one that stopped producing them). The sync loop's finality poll
    /// takes the first response that verifies; counting a stale one as the
    /// win let a stalled server outrun a current one every round (Sepolia,
    /// Glamsterdam day: every Lighthouse light-client server stopped at the
    /// fork and kept answering first, so roost's current update was never
    /// read). Java twin: the poll's "did not advance" branch.
    pub fn apply_finality_update(&mut self, update: &LightClientFinalityUpdate) -> FinalityOutcome {
        let before = (self.store.finalized_slot(), self.store.optimistic_slot());
        if !self.process_finality_update(update) {
            return FinalityOutcome::Rejected;
        }
        let after = (self.store.finalized_slot(), self.store.optimistic_slot());
        if after.0 > before.0 || after.1 > before.1 {
            FinalityOutcome::Advanced
        } else {
            FinalityOutcome::Stale
        }
    }
}

/// What a finality update did to the store (see
/// [`LightClientProcessor::apply_finality_update`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalityOutcome {
    /// Verified, and the finalized or optimistic header moved forward.
    Advanced,
    /// Verified, but the store already held headers at least as new: not a
    /// win, not a strike — the server is behind, not wrong.
    Stale,
    /// Did not verify (period, shape, signature or branch).
    Rejected,
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* A three-way answer instead of `bool`. Tuples compare field by field, so `(finalized, optimistic)` snapshots before and after tell whether anything moved.
- *[Protocol & domain](01-primer.md#primer-domain)* The doc tells the incident: on Sepolia's Gloas fork day, every Lighthouse light-client server stopped at the fork but kept answering first, with an update that still verified. Counting that as the poll's win hid the one server (roost) that was current.

#### Binding the beacon header to the execution layer

`rust/myotis-consensus/src/store.rs` · lines 594–636

```rust
/// `is_valid_light_client_header` for a header whose OWN slot is in `slot_fork`.
///
/// This is the whole binding between the sync-committee-signed beacon header and
/// the execution layer: the signature covers only `beacon`, so without it a peer
/// could pair a genuine signed header with an execution payload or block hash of
/// its choosing, and every state proof downstream would verify against it.
///
/// - Pre-Gloas shape at a pre-Gloas slot: the payload header's root at gindex 25.
/// - Gloas shape at a Gloas slot: the block hash at 2856 — the payload bid's
///   `parent_block_hash`.
/// - Gloas shape at a pre-Gloas slot (a Gloas update's finalized header in the
///   first epochs after the fork): the payload's block hash at 812 (Deneb+),
///   normalized to 11 nodes with zero padding. Capella's 412 is not accepted: no
///   header this client meets is pre-Deneb (every network's checkpoint and every
///   Gloas update's finalized header are far past it), and a Capella header's
///   genuine proof simply fails here — a rejection, never an acceptance.
/// - A pre-Gloas shape at a Gloas slot is never genuine: rejected.
pub fn verify_execution_branch_at(header: &LightClientHeader, slot_fork: LcFork) -> bool {
    let body_root = &header.beacon.body_root;
    match (&header.execution, slot_fork) {
        (HeaderExecution::Payload(payload), LcFork::PreGloas) => ssz::verify_merkle_branch(
            &payload.hash_tree_root(),
            &header.execution_branch,
            spec::EXECUTION_PAYLOAD_DEPTH,
            spec::EXECUTION_PAYLOAD_GINDEX,
            body_root,
        ),
        (HeaderExecution::Payload(_), LcFork::Gloas) => false,
        (HeaderExecution::BlockHash(hash), fork) => {
            let gindex = match fork {
                LcFork::Gloas => spec::EXECUTION_BLOCK_HASH_GINDEX_GLOAS,
                LcFork::PreGloas => spec::EXECUTION_BLOCK_HASH_GINDEX_DENEB,
            };
            header.execution_branch.len() == spec::GLOAS_EXECUTION_BRANCH_LEN
                && ssz::verify_normalized_merkle_branch(
                    hash,
                    &header.execution_branch,
                    gindex,
                    body_root,
                )
        }
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns) · [Borrowing & slices](01-primer.md#primer-borrowing)* **Matching a tuple.** `match (&header.execution, slot_fork)` builds a temporary tuple of a reference and a `Copy` enum, then matches both at once. Four combinations, four arms; one of them is a flat `false`. `payload` binds as `&Box<ExecutionPayloadHeader>`, and `payload.hash_tree_root()` works anyway because method calls auto-dereference through `&` and `Box`.
- *[Protocol & domain](01-primer.md#primer-domain)* The doc bullet list is the clearest statement of the Gloas rules in the crate. Note the limit it records: Capella's own block-hash gindex (412) is not accepted, because no header this client meets is older than Deneb, and a Capella header's genuine proof simply fails here.

*[Protocol & domain](01-primer.md#primer-domain)* `verify_execution_branch` (the associated function at lines 227–229, still used by the corpus tests) is kept for callers that hold no fork schedule. It now refuses a Gloas-shaped header outright, so a call site that should have moved to `verify_header` fails loudly instead of guessing.

> [!WARNING]
> **A back door around “refuses zero”**The doc on `LightClientStore::new` says the store refuses a zero period length instead of defaulting to the mainnet preset. But the struct also derives a public `Default`, which sets `slots_per_period` to 0, and the getter `slots_per_period()` (lines 53–59) maps 0 to the mainnet preset. So `LightClientStore::default()` quietly gets mainnet geometry. Nothing in the snapshot calls `default()` directly; `new` uses it only as the base for struct update syntax.

<a id="f-myotis-consensus-src-snapshot-rs"></a>

### myotis-consensus/src/snapshot.rs

*library · 550 lines · Java twin · LightClientStoreSnapshot (LCSS v1/v2)*

A byte-exact codec for the verified store, shared with the Java engine: switching engines resumes from the same file instead of re-bootstrapping. Top-level integers are big-endian (Java `DataOutputStream`), the beacon header is embedded as SSZ, and the file is bound to its chain by the genesis validators root. Version 2 adds a one-byte shape tag per header for Gloas, and is written only when a header needs it. Any malformed, foreign or unknown-version input decodes to `None`, and the caller falls back to the checkpoint.

`rust/myotis-consensus/src/snapshot.rs` · lines 60–89

```rust
/// Serialize a snapshot bound to `genesis_validators_root`. Byte-identical to
/// the Java `LightClientStoreSnapshot.serialize` for the same logical state.
pub fn serialize(s: &StoreSnapshot, genesis_validators_root: &[u8; 32]) -> Vec<u8> {
    // ~50 KiB with both committees; reserve to avoid regrowth.
    let mut out = Vec::with_capacity(52 * 1024);
    let version = if s.finalized_header.execution_payload().is_some()
        && s.optimistic_header.execution_payload().is_some()
    {
        VERSION_V1
    } else {
        VERSION_V2
    };
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(version);
    out.extend_from_slice(genesis_validators_root);
    out.extend_from_slice(&s.current_sync_committee_period.to_be_bytes());
    out.extend_from_slice(&s.finalized_slot.to_be_bytes());
    out.extend_from_slice(&s.optimistic_slot.to_be_bytes());
    write_header(&mut out, &s.finalized_header, version);
    write_header(&mut out, &s.optimistic_header, version);
    write_committee(&mut out, &s.current_sync_committee);
    match &s.next_sync_committee {
        Some(next) => {
            out.push(1);
            write_committee(&mut out, next);
        }
        None => out.push(0),
    }
    out
}
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Forward compatibility by restraint.** v1 is chosen whenever both headers are payload-shaped, so a store that never saw Gloas writes the same bytes as before and an older build can still resume it. v2 appears only once a Gloas-shaped header is held, which is state an older build couldn't follow anyway.
- *[Borrowing & slices](01-primer.md#primer-borrowing) · [Enums & pattern matching](01-primer.md#primer-enums-patterns)* `match &s.next_sync_committee` matches through a reference because `SyncCommittee` isn't `Copy`; moving it out of borrowed `s` is illegal. Compare the Electra tail in `write_execution` (line 228), where `e.deposit_requests_root` *is* `Copy` and is matched by value.

`rust/myotis-consensus/src/snapshot.rs` · lines 125–162

```rust
// ---- LightClientHeader: beacon(112 SSZ) + [v2: shape tag] + execution part ----
//
// Payload shape: 4×32 branch + custom EPH (the v1 framing). Block-hash shape
// (v2 only): 32-byte hash + 11×32 branch.

fn write_header(out: &mut Vec<u8>, h: &LightClientHeader, version: u8) {
    out.extend_from_slice(&h.beacon.encode());
    match &h.execution {
        HeaderExecution::Payload(payload) => {
            if version == VERSION_V2 {
                out.push(SHAPE_PAYLOAD);
            }
            write_branch(out, &h.execution_branch, 4);
            write_execution(out, payload);
        }
        HeaderExecution::BlockHash(hash) => {
            // serialize() picks v2 whenever a header is block-hash-shaped.
            debug_assert_eq!(version, VERSION_V2);
            out.push(SHAPE_BLOCK_HASH);
            out.extend_from_slice(hash);
            write_branch(out, &h.execution_branch, GLOAS_EXECUTION_BRANCH_LEN);
        }
    }
}

/// The framing is EXACTLY `len` branch nodes (the reader consumes exactly that
/// many). A verified header always has them; tolerate any malformed in-memory
/// value by clamping — truncate extras, zero-pad missing — rather than emitting
/// an unreadable file (Java would have thrown on its own writer — we must never
/// panic and never shift the framing).
fn write_branch(out: &mut Vec<u8>, branch: &[[u8; 32]], len: usize) {
    for node in branch.iter().take(len) {
        out.extend_from_slice(node);
    }
    for _ in branch.len()..len {
        out.extend_from_slice(&[0u8; 32]);
    }
}
```

- *[Macros & attributes](01-primer.md#primer-macros)* `debug_assert_eq!` documents an invariant that `serialize` guarantees, and checks it only in debug builds.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `write_branch` writes exactly `len` nodes whatever it is given: `.take(len)` truncates, and `for _ in branch.len()..len` zero-pads. When `branch.len() > len` that range is empty, not an error: a Rust range whose start is past its end simply yields nothing.

`rust/myotis-consensus/src/snapshot.rs` · lines 164–192

```rust
fn read_header(r: &mut Reader<'_>, version: u8) -> Option<LightClientHeader> {
    let beacon = BeaconBlockHeader::decode(r.fixed(112)?).ok()?;
    let shape = if version == VERSION_V2 {
        r.u8()?
    } else {
        SHAPE_PAYLOAD
    };
    match shape {
        SHAPE_PAYLOAD => {
            let execution_branch = read_branch(r, 4)?;
            let execution = HeaderExecution::Payload(Box::new(read_execution(r)?));
            Some(LightClientHeader {
                beacon,
                execution,
                execution_branch,
            })
        }
        SHAPE_BLOCK_HASH => {
            let execution = HeaderExecution::BlockHash(r.root()?);
            let execution_branch = read_branch(r, GLOAS_EXECUTION_BRANCH_LEN)?;
            Some(LightClientHeader {
                beacon,
                execution,
                execution_branch,
            })
        }
        _ => None, // unknown shape: a corrupt or future file, never a guess
    }
}
```

- *[Enums & pattern matching](01-primer.md#primer-enums-patterns)* **Constants as patterns.** `SHAPE_PAYLOAD =>` compares against the `const`. That works because the name refers to a constant in scope. A lowercase name that isn't a constant would instead *bind* any value and match everything, which is why Rust insists on `UPPER_CASE` for constants. The `_ => None` arm refuses an unknown tag rather than guessing.
- *[Result, ? and panics](01-primer.md#primer-error-handling)* `BeaconBlockHeader::decode(…).ok()?` converts a `Result` into an `Option` and then propagates `None`, so a decode error becomes “not a valid snapshot” without a message.

`rust/myotis-consensus/src/snapshot.rs` · lines 315–342

```rust
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn fixed(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.fixed(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.fixed(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.fixed(8)?.try_into().ok()?))
    }
    fn root(&mut self) -> Option<[u8; 32]> {
        self.fixed(32)?.try_into().ok()
    }
}
```

*[Lifetimes](01-primer.md#primer-lifetimes)* This is the `Reader<'a>` from the primer, and the stop's clearest lifetime lesson: `impl<'a>` names the buffer's lifetime, and `fixed` returns slices tied to the buffer, not to `&mut self`. So a returned slice may outlive the `&mut` borrow of the reader, and a caller could keep it while it reads on. Helper functions take `r: &mut Reader<'_>`, where `'_` means “some lifetime I don't need to name”. `self.pos.checked_add(len)?` makes even a wild length from a corrupt file a clean `None`.

## The test suite

Eight integration tests, all network-free. Two replay the committed mainnet corpus end to end, one reads the official consensus-specs Gloas vectors, and five are regression tests for real bugs or forks (#295, #423 on two paths, the adoption rule, and Gloas). Three of them build synthetic 512-key committees and sign with real BLS through the `blst` dev-dependency; the #423 tests reuse genuinely signed updates from the mainnet corpus.

<a id="f-myotis-consensus-tests-lc-conformance-rs"></a>

### myotis-consensus/tests/lc\_conformance.rs

*integration test · 177 lines · Java twin · LcVectorConformanceTest*

The plan's PR-4 exit criterion. It replays the committed mainnet corpus (bootstrap, then numbered updates, then finality updates) through Rust decode and verify, and asserts the whole verdict map equals Java's `expected.txt`. It mirrors the live loop by calling `force_rotate_if_past_period` after each applied update. A malformed oracle line panics instead of being skipped.

`rust/myotis-consensus/tests/lc_conformance.rs` · lines 101–131

```rust
let mut store = LightClientStore::new_mainnet_preset();
store.initialize(bootstrap.header.clone(), bootstrap.current_sync_committee.clone());
// The corpus was recorded under one version — a schedule with no boundary.
let mut processor =
    LightClientProcessor::new(store, ForkSchedule::single(fork_version), gvr);

// ---- catch-up updates, filename order (3-digit corpus convention) ----
let mut update_files: Vec<_> = fs::read_dir(&dir)
    .unwrap()
    .filter_map(|e| e.ok())
    .map(|e| e.file_name().to_string_lossy().into_owned())
    .filter(|n| n.ends_with("-update.ssz")
        && n.len() == "000-update.ssz".len()
        && n.chars().take(3).all(|c| c.is_ascii_digit()))
    .collect();
update_files.sort();
actual.insert("updates.count".into(), update_files.len().to_string());
for (i, name) in update_files.iter().enumerate() {
    let update = LightClientUpdate::decode(&fs::read(dir.join(name)).unwrap())
        .unwrap_or_else(|e| panic!("{name} decodes: {e}"));
    let applied = processor.process_update(&update);
    if applied {
        // Mirrors the live applyCatchUpResponses loop (and the Java replay).
        processor.store.force_rotate_if_past_period(slot_estimate);
    }
    actual.insert(format!("update.{i}.applied"), applied.to_string());
    actual.insert(
        format!("update.{i}.finalizedSlot"),
        processor.store.finalized_slot().to_string(),
    );
}
```

- *[Ownership & moves](01-primer.md#primer-ownership)* After line 105, `store` has been *moved into* the processor. From then on it is reached as `processor.store` (a public field).
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* A directory listing becomes sorted file names in one chain: `filter_map(|e| e.ok())` drops unreadable entries, and `to_string_lossy().into_owned()` produces an owned `String`.

`rust/myotis-consensus/tests/lc_conformance.rs` · lines 154–162

```rust
// A server re-serving an update the store already holds verifies but moves
// nothing: the outcome the finality poll must not count as a win.
if let Some(update) = &last_applied {
    assert_eq!(
        processor.apply_finality_update(update),
        FinalityOutcome::Stale,
        "re-applying the last applied finality update is Stale, not Advanced"
    );
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Ownership & moves](01-primer.md#primer-ownership) · [Tests](01-primer.md#primer-testing)* New since September. In the loop above, `last_applied = Some(update)` *moves* each applied update into the `Option`; the previous value is dropped. Here `if let Some(update) = &last_applied` borrows it back out, so `update` is a `&LightClientFinalityUpdate`, which is what `apply_finality_update` takes.

> [!WARNING]
> **Stale or inaccurate comments**The module doc says the file set “is enumerated from expected.txt's own counts”. The code enumerates the directory (lines 108–116) and records the count under `updates.count`, so a mismatch shows up in the final map comparison. The effect the comment promises is real; the mechanism is different.

<a id="f-myotis-consensus-tests-fork-boundary-rs"></a>

### myotis-consensus/tests/fork\_boundary.rs

*integration test · 228 lines · Java twin · verifiesAcrossForkBoundary*

Regression test for #295. It builds a synthetic 512-key committee with deterministic keys, hand-built Merkle trees with genuinely valid branches, and real BLS signatures. It checks that updates signed on either side of a fork boundary (slot 320 vs 321) verify under a two-entry schedule, that cross-signed updates are rejected, and that a single-version schedule stalls at the boundary. Its headers are now built as `HeaderExecution::Payload(Box::new(…))`.

`rust/myotis-consensus/tests/fork_boundary.rs` · lines 45–55

```rust
/// Full binary tree over `leaves` (a power of two): level 0 = leaves.
fn levels(leaves: Vec<Root>) -> Vec<Vec<Root>> {
    let mut out = vec![leaves];
    while out.last().unwrap().len() > 1 {
        let prev = out.last().unwrap();
        let next: Vec<Root> =
            prev.chunks(2).map(|p| ssz::sha256_pair(&p[0], &p[1])).collect();
        out.push(next);
    }
    out
}
```

*[Borrowing & slices](01-primer.md#primer-borrowing) · [Lifetimes](01-primer.md#primer-lifetimes)* `prev` borrows `out`, and `out.push(next)` needs a mutable borrow that may *reallocate* the outer vector. It compiles only because `prev`'s last use is before the push. Use `prev` after the push and the compiler refuses. That refusal is exactly what prevents a dangling pointer into the old buffer.

<a id="f-myotis-consensus-tests-gloas-boundary-rs"></a>

### myotis-consensus/tests/gloas\_boundary.rs

*integration test · 619 lines · Java twin · GloasBoundaryTest*

The processor across the Fulu-to-Gloas boundary, with a synthetic committee, real BLS, and synthetic state and body trees that put each leaf at its Gloas gindex. It walks finality from Fulu into Gloas (including the padded 812 proof), proves a next committee at 2946 and a bootstrap at 2945 and 2856, and rejects every mismatch: the depth-derived gindex, a non-zero pad node, 812 at a Gloas slot, and wrong shapes. The last test proves that the shape gate runs *before* BLS.

`rust/myotis-consensus/tests/gloas_boundary.rs` · lines 64–103

```rust
/// A Merkle tree given by the nodes we care about, at any depths; every other
/// subtree is a zero leaf. Enough to prove several gindices of different
/// depths against ONE root, as a real (progressive) state or body does.
struct Sparse(HashMap<u64, Root>);

impl Sparse {
    fn new(leaves: &[(u64, Root)]) -> Self {
        Sparse(leaves.iter().copied().collect())
    }
    fn covers(&self, g: u64) -> bool {
        self.0.keys().any(|&k| {
            let mut k = k;
            while k > g {
                k /= 2;
            }
            k == g
        })
    }
    fn node(&self, g: u64) -> Root {
        if let Some(v) = self.0.get(&g) {
            *v
        } else if self.covers(g) {
            ssz::sha256_pair(&self.node(2 * g), &self.node(2 * g + 1))
        } else {
            [0u8; 32]
        }
    }
    fn root(&self) -> Root {
        self.node(1)
    }
    /// Bottom-up sibling path of `g`.
    fn branch(&self, mut g: u64) -> Vec<Root> {
        let mut b = Vec::new();
        while g > 1 {
            b.push(self.node(g ^ 1));
            g /= 2;
        }
        b
    }
}
```

- *[Protocol & domain](01-primer.md#primer-domain) · [Iterators & closures](01-primer.md#primer-iterators-closures)* **A sparse Merkle tree in 40 lines.** Only the leaves you name exist; every other subtree is a zero leaf. `covers(g)` asks whether any named node lies below `g` by halving its gindex until it is no larger than `g`. `node(g)` recurses only into covered subtrees. That is enough to prove leaves at depths 9 and 11 against one root, as a progressive state does.
- *[Iterators & closures](01-primer.md#primer-iterators-closures)* `leaves.iter().copied().collect()` turns a slice of `(u64, Root)` tuples into a `HashMap`: `collect` picks the `FromIterator` impl from the target type. `|&k|` destructures the borrowed key in the closure's parameter.

`rust/myotis-consensus/tests/gloas_boundary.rs` · lines 308–348

```rust
/// The message of every event logged on this thread while `f` runs. The
/// processor logs one debug line per rejection, naming the check that refused
/// it, and nothing for a signature that verifies.
fn logged_during<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Message(String);
    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().unwrap().push(message.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let log = Arc::new(Mutex::new(Vec::new()));
    let out = tracing::subscriber::with_default(Capture(log.clone()), f);
    let messages = log.lock().unwrap().clone();
    (out, messages)
}
```

- *[Box, Rc, Arc & Drop](01-primer.md#primer-smart-pointers) · [Interior mutability](01-primer.md#primer-interior-mutability)* **Sharing a log with a subscriber.** `Arc<Mutex<Vec<String>>>` is the Rust spelling of a thread-safe shared list. `log.clone()` clones the `Arc`, which bumps a reference count; both handles point at the same `Vec`. `self.0.lock().unwrap().push(…)` mutates it through a shared `&self`, which the `Mutex` makes safe. At the end, `.clone()` on the locked guard copies the `Vec` out, and the guard drops at the end of that statement.
- *[Traits, generics & dyn](01-primer.md#primer-traits-generics)* `impl Visit for Message` and `impl Subscriber for Capture` implement `tracing`'s traits: a minimal subscriber that keeps only each event's `message` field. `f: impl FnOnce() -> T` takes any closure that runs once, and `with_default` installs the subscriber for the current thread while it runs.

`rust/myotis-consensus/tests/gloas_boundary.rs` · lines 544–568

```rust
let misrouted = [
    (
        "Gloas shape at a Fulu attested slot",
        gloas_format_at_a_fulu_slot(&keys),
    ),
    (
        "payload shape at a Gloas slot",
        electra_finality(&keys, 256, G + 2),
    ),
    (
        "a payload-shaped finalized header in a Gloas update",
        gloas_finality(
            &keys,
            payload_header(G - 32, [0; 32]),
            G + 2,
            spec::FINALIZED_ROOT_GINDEX_GLOAS,
        ),
    ),
];
for (name, mut u) in misrouted {
    u.sync_aggregate = foreign.clone();
    let (applied, log) = logged_during(|| p.process_finality_update(&u));
    assert!(!applied, "{name}");
    assert!(refused_by_the_gate(&log), "{name}: {log:?}");
}
```

*[Tests](01-primer.md#primer-testing) · [Protocol & domain](01-primer.md#primer-domain)* **Proving an order without a counter.** Every misrouted update carries a genuine aggregate over the *wrong* header, so it would fail BLS if it ever got that far. The test then reads the debug log: a refusal by the gate says “wire shape” and nothing says “BLS”. A control case just above shows that a well-shaped update with the same signature does log a BLS failure. `for (name, mut u) in misrouted` consumes the array by value, and `mut u` makes each moved-out update mutable inside the loop.

<a id="f-myotis-consensus-tests-gloas-spec-vectors-rs"></a>

### myotis-consensus/tests/gloas\_spec\_vectors.rs

*integration test · 399 lines · Java twin · GloasSpecVectorTest*

The crate against consensus-specs v1.7.0-beta.2 vectors in `rust/testdata/lc/gloas-spec`. The mainnet-preset `ssz_static` containers must decode with the production Gloas decoders, and the container root recomputed from the decoded fields must equal the spec's, so every field sits where the decoder reads it. The minimal-preset vectors (32-member committee, 8-slot epochs, Gloas at epoch 3) are sliced by hand and checked with the production gindices and `verify_execution_branch_at`. The depth-derived gindices must fail on them.

`rust/myotis-consensus/tests/gloas_spec_vectors.rs` · lines 356–385

```rust
// Proof of field 12 (block_hash) in the 32-leaf payload-header tree.
let mut level: Vec<Root> = fields.to_vec();
level.resize(32, [0u8; 32]);
let (mut idx, mut proof) = (12usize, Vec::new());
while level.len() > 1 {
    proof.push(level[idx ^ 1]);
    level = level
        .chunks(2)
        .map(|c| ssz::sha256_pair(&c[0], &c[1]))
        .collect();
    idx /= 2;
}
assert_eq!(level[0], p.hash_tree_root());

let mut branch = vec![[0u8; 32]; 2];
branch.extend(proof);
branch.extend(pre.execution_branch.iter().copied());
let upgraded = LightClientHeader {
    beacon: pre.beacon.clone(),
    execution: HeaderExecution::BlockHash(p.block_hash),
    execution_branch: branch,
};
assert!(
    verify_execution_branch_at(&upgraded, LcFork::PreGloas),
    "slot {slot}: 812, normalized"
);
assert!(
    !verify_execution_branch_at(&upgraded, LcFork::Gloas),
    "slot {slot}: not at 2856"
);
```

- *[Protocol & domain](01-primer.md#primer-domain)* **Building the 812 proof by hand.** The spec's upgrade of a Fulu header to the Gloas shape is the computation a serving node performs. The test does it itself: a 5-node proof of `block_hash` (field 12) inside the payload-header tree, then the payload's own 4-node branch into the body, then two zero pads in front. The vectors contain no Gloas update with a non-genesis Fulu finalized header, so this is the genuine input for that path.
- *[Ownership & moves](01-primer.md#primer-ownership) · [Iterators & closures](01-primer.md#primer-iterators-closures)* `level = level.chunks(2).map(…).collect();` builds a new, half-length `Vec` and rebinds `level` to it. The old `Vec` is dropped at that moment. `let (mut idx, mut proof) = (12usize, Vec::new());` declares two mutable bindings by destructuring a tuple.

<a id="f-myotis-consensus-tests-next-committee-selection-rs"></a>

### myotis-consensus/tests/next\_committee\_selection.rs

*integration test · 175 lines*

A #423 regression test on two real mainnet updates (periods 1777 and 1778), with the store at P = 1777 holding the next committee. Each period's signature must be checked with that period's keys. Rotation installs the *held* committee, not the P+2 one an update carries. A relabelled `signature_slot` is rejected, and corrupted signatures or branches are rejected in both periods. Table-driven mutation loops cover the variants.

`rust/myotis-consensus/tests/next_committee_selection.rs` · lines 18–20

```rust
fn root(hex: &str) -> [u8; 32] {
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}
```

*[Iterators & closures](01-primer.md#primer-iterators-closures)* `std::array::from_fn` calls the closure once per index; the array length (32) comes from the return type. The file also shows a *partial move*, `initialize(b.header, b.current_sync_committee)`, which moves two fields out of `b`.

<a id="f-myotis-consensus-tests-next-committee-finality-rs"></a>

### myotis-consensus/tests/next\_committee\_finality.rs

*integration test · 113 lines*

\#423 on the finality path: a next-period finality update is accepted and rotates the store; relabelled updates and periods the store can't verify are rejected; current-period updates still verify. New since September: a test that `apply_finality_update` reports `Advanced`, then `Stale` for the same update, then `Rejected` for a tampered branch, with the store unchanged after the first.

`rust/myotis-consensus/tests/next_committee_finality.rs` · lines 30–38

```rust
fn finality_of(u: &LightClientUpdate) -> LightClientFinalityUpdate {
    LightClientFinalityUpdate {
        attested_header: u.attested_header.clone(),
        finalized_header: u.finalized_header.clone(),
        finality_branch: u.finality_branch.clone(),
        sync_aggregate: u.sync_aggregate.clone(),
        signature_slot: u.signature_slot,
    }
}
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Borrowing & slices](01-primer.md#primer-borrowing)* Fields cannot be moved out of `&LightClientUpdate`. The two options are to clone them, as here, or to take the update by value. The `u64` slot is simply copied.

<a id="f-myotis-consensus-tests-next-committee-adoption-rs"></a>

### myotis-consensus/tests/next\_committee\_adoption.rs

*integration test · 250 lines · Java twin · LightClientProcessorTest.aCrossPeriodUpdateDoesNotSupplyTheNextCommittee*

The adoption rule from `process_update`, with synthetic committees and real BLS. The dangerous update is built so that *everything in it verifies*: the signature against our current committee, and the next-committee branch against the attested state. The first test asserts that the processor refuses it anyway and leaves the store as it was. The second shows the consequence end to end: after the cross-period update was offered, the store still adopts committee(P+1) from P's own update, and rotation installs that committee.

`rust/myotis-consensus/tests/next_committee_adoption.rs` · lines 177–185

```rust
fn cross_period_update(keys_p: &[SecretKey], committee_p: &SyncCommittee) -> LightClientUpdate {
    let u = update(keys_p, P * PERIOD - 1, P * PERIOD - 64, committee_p);
    assert_eq!(
        spec::compute_sync_committee_period(u.attested_header.beacon.slot),
        P - 1
    );
    assert_eq!(spec::compute_sync_committee_period(u.signature_slot), P);
    u
}
```

`rust/myotis-consensus/tests/next_committee_adoption.rs` · lines 210–216

```rust
assert!(
    !p.process_update(&cross),
    "an update attested in P-1 carries committee(P), not committee(P+1)"
);
assert!(p.store.next_sync_committee().is_none());
assert_eq!(p.store.current_period(), P);
assert_eq!(p.store.finalized_slot(), P * PERIOD + 100);
```

*[Tests](01-primer.md#primer-testing) · [Protocol & domain](01-primer.md#primer-domain)* The helper asserts its own premise (attested in P−1, signed in P) before returning, so the test can't pass because the fixture drifted. The module doc notes that honest servers send this update with an empty next committee, but the committee is public chain data, so any server can fill it in.

<a id="f-myotis-consensus-tests-resume-equivalence-rs"></a>

### myotis-consensus/tests/resume\_equivalence.rs

*integration test · 186 lines*

The deterministic half of an on-device investigation (“restored snapshot failed verification”). For *every* split point k, the test replays updates 0..k, snapshots, serializes, deserializes and restores into a fresh store, then continues. Verdicts and final state must equal an uninterrupted replay, and that baseline is itself checked against `expected.txt`, so the test can't pass vacuously. The corpus is pre-Gloas, so this exercises the v1 file format.

`rust/myotis-consensus/tests/resume_equivalence.rs` · lines 166–184

```rust
// Snapshot → bytes → restore into a FRESH store (the resume path).
let snap = proc.store.snapshot().expect("initialized store snapshots");
let bytes = snapshot::serialize(&snap, &c.gvr);
let restored = snapshot::deserialize(&bytes, &c.gvr)
    .unwrap_or_else(|| panic!("split {k}: snapshot must deserialize"));
let mut resumed_store = LightClientStore::new_mainnet_preset();
resumed_store.restore(restored);
let mut resumed = LightClientProcessor::new(resumed_store, ForkSchedule::single(c.fork_version), c.gvr);

// Continue from the split; verdicts and final state must match the
// uninterrupted replay exactly.
let (verdicts, fin_verdicts, state) = replay_from(&mut resumed, &c, k);
assert_eq!(
    verdicts,
    baseline_verdicts[k..].to_vec(),
    "split {k}: post-resume update verdicts diverged"
);
assert_eq!(fin_verdicts, baseline_fin, "split {k}: finality verdicts diverged");
assert_eq!(state, baseline_state, "split {k}: final store state diverged");
```

*[Ownership & moves](01-primer.md#primer-ownership) · [Tests](01-primer.md#primer-testing)* The whole resume path in a few lines. `snap` is an owned deep copy; `bytes` is only borrowed by `deserialize`; `restored` moves into the store, and the store moves into the processor. `replay_from(&mut resumed, …)` lends the processor mutably, and `baseline_verdicts[k..].to_vec()` copies a sub-slice for the comparison.

## Checkpoint

14 questions. Decide on your answer before you follow the link: the answers are collected in the appendix “Checkpoint answers”, each with a link back here.

<a id="q-cons-q1"></a>

**Q1** · Multiple choice

During rotation, the store does `self.current_sync_committee = self.next_sync_committee.take();`. Why `take()` rather than `clone()`?

- **A.** `clone()` doesn't compile for `Option`
- **B.** `take()` is thread-safe
- **C.** `clone()` would share the committee between the two fields
- **D.** `take()` moves the committee out and leaves `None`, exactly the desired new state, without copying 24 KB

[Answer →](answers.md#a-cons-q1)

<a id="q-cons-q2"></a>

**Q2** · Written answer

In `process_update`, `committee` is a reference obtained through `&self`, yet later the method calls `self.store.update_next_sync_committee(…)`, which needs `&mut`. Why does this compile, and what change would break it?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-cons-q2)

<a id="q-cons-q3"></a>

**Q3** · Multiple choice

`read_roots` is `(0..n).map(|i| ssz::read_root(data, offset + i * 32)).collect()` with return type `Option<Vec<Root>>`. What does it produce when the buffer is two nodes short?

- **A.** `None`, because collecting into `Option` stops at the first `None`
- **B.** `Some` of a vector with `n − 2` nodes
- **C.** `Some` of a vector with two zero nodes at the end
- **D.** It panics on the first failed read

[Answer →](answers.md#a-cons-q3)

<a id="q-cons-q4"></a>

**Q4** · Multiple choice

Why do the Gloas decoders take an `LcFork` from the caller instead of sniffing the layout from offsets, as the pre-Gloas decoders do?

- **A.** Sniffing is too slow for a phone
- **B.** Gloas containers carry a version byte that only the caller can read
- **C.** Every Gloas container is fixed-size with no offsets left to sniff, so the only honest source of the format is the fork of the object's slot, which the req/resp context bytes give
- **D.** The Java engine sniffs and the Rust engine must differ

[Answer →](answers.md#a-cons-q4)

<a id="q-cons-q5"></a>

**Q5** · Multiple choice

Why are the Gloas gindices (735, 2945, 2946) constants in `spec.rs`, while the pre-Gloas ones are computed from the branch length?

- **A.** The Gloas `BeaconState` is a progressive container, so a field's gindex is no longer `(1 << depth) + field_index`; the formula gives 553, 2070 and 2071 instead
- **B.** Gloas renumbered the state fields 20, 22 and 23
- **C.** Constants are faster than a shift
- **D.** Gloas branches have variable length, so the length cannot be used

[Answer →](answers.md#a-cons-q5)

<a id="q-cons-q6"></a>

**Q6** · Multiple choice

`HeaderExecution` is `Payload(Box<ExecutionPayloadHeader>)` or `BlockHash(Root)`. What does the `Box` buy?

- **A.** It makes the payload shareable between threads
- **B.** An enum is as large as its largest variant; boxing puts the ~470-byte payload on the heap and leaves an 8-byte pointer, so a Gloas header doesn't carry unused space
- **C.** It lets two headers point at the same payload without cloning
- **D.** It is required because enums can't hold structs directly

[Answer →](answers.md#a-cons-q6)

<a id="q-cons-q7"></a>

**Q7** · Written answer

A Gloas finality update arrives in the first epochs after the fork. Its attested header is at a Gloas slot, its finalized header is a Fulu block. Describe how the processor checks the finalized header's execution data, and which rules each header must satisfy.

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-cons-q7)

<a id="q-cons-q8"></a>

**Q8** · Multiple choice

Gloas activates at epoch 20 on a 32-slot chain, so slot 640 is its first slot. An update has attested slot 640 and signature slot 640. Which format and which signing version apply?

- **A.** Pre-Gloas format, pre-Gloas version
- **B.** Gloas format, Gloas version
- **C.** Pre-Gloas format, Gloas version
- **D.** Gloas format, but the signature verifies under the version before Gloas

[Answer →](answers.md#a-cons-q8)

<a id="q-cons-q9"></a>

**Q9** · Written answer

`next_committee_adoption.rs` builds an update whose signature and next-committee branch both genuinely verify, and expects the processor to reject it. What is the update, why is adopting its committee harmful, and which check refuses it?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-cons-q9)

<a id="q-cons-q10"></a>

**Q10** · Multiple choice

`shape(&self)` writes `match self.execution { HeaderExecution::Payload(_) => …, HeaderExecution::BlockHash(_) => … }` with no `&`. Why does that compile even though `self` is only borrowed?

- **A.** `match` always borrows its scrutinee automatically
- **B.** The `_` patterns bind nothing, so nothing is moved out of the borrowed value
- **C.** `HeaderExecution` is `Copy`
- **D.** The compiler inserts a clone

[Answer →](answers.md#a-cons-q10)

<a id="q-cons-q11"></a>

**Q11** · Multiple choice

`types.rs` contains `const _: () = assert!(LightClientHeader::GLOAS_SIZE < MIN_PRE_GLOAS_HEADER_SIZE);`. What happens if someone changes a size so the condition becomes false?

- **A.** The build fails, because the assert is evaluated at compile time
- **B.** The program panics at startup
- **C.** The assert is skipped in release builds
- **D.** A warning is printed

[Answer →](answers.md#a-cons-q11)

<a id="q-cons-q12"></a>

**Q12** · Written answer

`the_shape_gate_runs_before_the_bls_verify` cannot read a BLS call counter. How does it prove the order of the checks, and how does `logged_during` share its log with the subscriber?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-cons-q12)

<a id="q-cons-q13"></a>

**Q13** · Multiple choice

Why does `apply_finality_update` return `FinalityOutcome` rather than the `bool` from `process_finality_update`?

- **A.** A `bool` can't cross the FFI boundary
- **B.** To report which committee verified the update
- **C.** A re-served update verifies but moves nothing; the sync loop must not count that as the poll's win, or a stalled server keeps outrunning a current one
- **D.** To let the caller retry rejected updates

[Answer →](answers.md#a-cons-q13)

<a id="q-cons-q14"></a>

**Q14** · Written answer

When does `snapshot::serialize` write format version 2 instead of 1, and why is that choice made per file rather than always writing v2?

Answer it in your own words first, on paper or out loud. Then compare it with the model answer and its key points.

[Answer →](answers.md#a-cons-q14)

---

*Myotis Rust Tour 1.0 · code at `5263a421` · [contents](README.md)*
