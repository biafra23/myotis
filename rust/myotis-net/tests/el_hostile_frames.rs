//! Allocation regression test for #454 at the eth wire. Every decoder a peer
//! reaches without being asked anything (the handshake, and the read loop's
//! request-id, gossip and control paths) must stay flat on the frames from the
//! report. Those are 10 MiB lists of one-byte elements, 492 KB as snappy on the
//! wire, and decoding one into an owned tree cost 547 MB of heap.
//!
//! Its own test binary, since a `#[global_allocator]` applies to the whole
//! binary. Counts are per thread, so tests running in parallel don't mix.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use myotis_net::el::eth::messages;
use myotis_net::el::rlpx::transport::decode_hello;

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

/// `[0x01; N]`: a flat list of one-byte elements.
fn flat() -> Vec<u8> {
    let mut out = list_header(N);
    out.resize(out.len() + N, 0x01);
    out
}

/// `[0x01, [0x01; N]]`: the `[reqId, …]` shape from the report.
fn nested() -> Vec<u8> {
    let inner = flat();
    let mut out = list_header(1 + inner.len());
    out.push(0x01);
    out.extend_from_slice(&inner);
    out
}

/// Few enough allocations to rule out one per element: the frames have ten
/// million of them.
fn assert_flat(what: &str, allocations: usize, bytes: usize) {
    assert!(
        allocations <= 16 && bytes <= 64 * 1024,
        "{what}: {allocations} allocations, {bytes} bytes"
    );
}

#[test]
fn the_request_id_read_on_every_frame_is_flat() {
    for (shape, payload) in [("nested", nested()), ("flat", flat())] {
        let (allocations, bytes, id) = counted(|| messages::leading_request_id(&payload));
        assert_eq!(id, Some(1), "{shape}");
        assert_flat(shape, allocations, bytes);
    }
}

#[test]
fn control_messages_over_the_cap_are_refused_unbuilt() {
    for (shape, payload) in [("nested", nested()), ("flat", flat())] {
        let (a, b, hello) = counted(|| decode_hello(&payload));
        assert!(hello.is_err(), "{shape} Hello");
        assert_flat("Hello", a, b);

        let (a, b, status) = counted(|| messages::decode_status(&payload, 69));
        assert!(status.is_err(), "{shape} Status");
        assert_flat("Status", a, b);

        let (a, b, range) = counted(|| messages::decode_block_range_update(&payload));
        assert!(range.is_err(), "{shape} BlockRangeUpdate");
        assert_flat("BlockRangeUpdate", a, b);

        let (a, b, get) = counted(|| messages::decode_get_block_headers(&payload));
        assert!(get.is_err(), "{shape} GetBlockHeaders");
        assert_flat("GetBlockHeaders", a, b);
    }
}

#[test]
fn gossip_decoders_cost_their_cap_not_the_frame() {
    for (shape, payload) in [("nested", nested()), ("flat", flat())] {
        let (a, b, hashes) = counted(|| messages::decode_new_pooled_tx_hashes(&payload));
        assert!(hashes.is_empty(), "{shape}: no 32-byte strings in the frame");
        assert_flat("NewPooledTransactionHashes", a, b);

        // Hashes each of the first MAX_GOSSIP_HASHES_PER_MSG elements, so up to
        // a few allocations per hashed element, and none for the rest.
        let (a, b, hashes) = counted(|| messages::transactions_gossip_hashes(&payload));
        assert!(hashes.len() <= messages::MAX_GOSSIP_HASHES_PER_MSG, "{shape}");
        let cap = messages::MAX_GOSSIP_HASHES_PER_MSG;
        assert!(a <= 4 * cap + 16 && b <= 1024 * 1024, "{shape} Transactions: {a} allocations, {b} bytes");
    }
}
