//! Allocation regression test for #454: the RLP calls that read peer lists must
//! not allocate per element. A 492 KB snappy frame decodes to a 10 MiB list of
//! one-byte elements. Building that list's tree cost 547 MB of heap in about
//! ten million allocations. The walkers asserted on here must stay flat.
//!
//! Its own test binary, since a `#[global_allocator]` applies to the whole
//! binary. Counts are per thread, so tests running in parallel don't mix.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use myotis_core::rlp;

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

/// Just under the 10 MiB decompressed-frame cap, as in the #454 report.
const N: usize = 10 * 1024 * 1024 - 64;

fn list_header(payload_len: usize) -> Vec<u8> {
    let be = (payload_len as u64).to_be_bytes();
    let skip = be.iter().take_while(|&&b| b == 0).count();
    let mut h = vec![0xf7 + (8 - skip) as u8];
    h.extend_from_slice(&be[skip..]);
    h
}

/// `[0x01; n]`: a flat list of `n` one-byte elements.
fn flat(n: usize) -> Vec<u8> {
    let mut out = list_header(n);
    out.resize(out.len() + n, 0x01);
    out
}

/// `[0x01, [0x01; n]]`: the `[reqId, …]` shape from the report.
fn nested(n: usize) -> Vec<u8> {
    let inner = flat(n);
    let mut out = list_header(1 + inner.len());
    out.push(0x01);
    out.extend_from_slice(&inner);
    out
}

#[test]
fn the_counter_sees_a_per_element_decode() {
    // Control: an owned decode allocates at least once per element, so a
    // counter that saw nothing would make the checks below vacuous.
    let small = flat(4096);
    let (allocations, _, decoded) = counted(|| rlp::decode(&small));
    assert!(decoded.is_ok());
    assert!(allocations >= 4096, "only {allocations} allocations");
}

#[test]
fn validate_allocates_nothing() {
    for payload in [flat(N), nested(N)] {
        let (allocations, bytes, verdict) = counted(|| rlp::validate(&payload));
        assert_eq!(verdict, Ok(()));
        assert_eq!((allocations, bytes), (0, 0));
    }
}

#[test]
fn splitting_a_nested_list_allocates_only_its_top_level() {
    let payload = nested(N);
    let (allocations, bytes, items) = counted(|| rlp::raw_list_items(&payload));
    assert_eq!(items.map(|i| i.len()), Ok(2));
    assert!(allocations <= 2 && bytes <= 256, "{allocations} allocations, {bytes} bytes");
}

#[test]
fn a_prefix_of_a_flat_list_allocates_only_the_prefix() {
    let payload = flat(N);
    let (allocations, bytes, items) = counted(|| rlp::raw_list_prefix(&payload, 256));
    assert_eq!(items.map(|i| i.len()), Ok(256));
    // Growing a Vec to 256 slices: a handful of reallocations, a few KiB.
    assert!(allocations <= 16 && bytes <= 64 * 1024, "{allocations} allocations, {bytes} bytes");

    let (allocations, _, head) = counted(|| rlp::raw_list_prefix(&payload, 1));
    assert_eq!(head.map(|i| i.len()), Ok(1));
    assert!(allocations <= 1, "{allocations} allocations");
}

#[test]
fn a_rejected_list_is_still_walked_without_allocating() {
    // The same flat list with its last element made non-canonical: rejected
    // at the very end of the walk, without allocating along the way.
    let mut payload = flat(N);
    let last = payload.len() - 2;
    payload[last] = 0x81; // `0x81 0x01` — a single byte below 0x80 in long form
    let (allocations, _, verdict) = counted(|| rlp::validate(&payload));
    assert!(verdict.is_err());
    // Formatting the error message is the only allocation.
    assert!(allocations <= 2, "{allocations} allocations");
}
