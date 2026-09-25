//! Binary codec for the persisted light-client store snapshot — the byte-exact
//! Rust twin of the Java `LightClientStoreSnapshot` ("LCSS" v1). The SAME file
//! is read and written by both engines under the host's dataDir, so switching
//! the engine (Java ↔ Rust) resumes verified sync state instead of
//! re-bootstrapping from the months-old embedded checkpoint.
//!
//! Framing (mirrors Java's DataOutputStream layout exactly):
//!   - top-level integers are BIG-endian (DataOutputStream semantics);
//!   - the embedded 112-byte BeaconBlockHeader is SSZ (little-endian), as
//!     produced by `BeaconBlockHeader.encode()` on the Java side;
//!   - booleans are one byte, 0/1;
//!   - ExecutionPayloadHeader is field-by-field custom framing (NOT wire SSZ)
//!     with an int-length-prefixed extraData (capped 1 MiB) and an Electra
//!     optional tail (flag byte + 3×32-byte request roots).
//!
//! v2 (Gloas) adds a one-byte shape tag in front of each header's execution
//! part: 0 = the v1 framing above (4 branch nodes + execution payload header),
//! 1 = the Gloas shape (32-byte execution block hash + 11 branch nodes). A store
//! whose headers are all payload-shaped still writes v1, byte-identical to
//! before, so an older build can resume it; v2 appears only once a Gloas-shaped
//! header is held — state no older build could follow anyway. Both versions are
//! read.
//!
//! TRUST: a snapshot is only ever produced from a BLS-verified store, and it is
//! bound to the chain via the genesis-validators-root. Callers must only resume
//! from a snapshot STRICTLY NEWER than the embedded trusted checkpoint; a
//! corrupt/foreign/old snapshot decodes to `None` and the caller falls back to
//! the checkpoint. Panic-free by construction (checked reads, no indexing).

use crate::spec::GLOAS_EXECUTION_BRANCH_LEN;
use crate::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, HeaderExecution, LightClientHeader, SyncCommittee,
    PUBKEY_SIZE, SYNC_COMMITTEE_SIZE,
};

/// "LCSS" — same magic as the Java codec.
const MAGIC: u32 = 0x4C43_5353;
/// Payload-shaped headers only (every build since the format existed).
const VERSION_V1: u8 = 1;
/// A shape tag per header — written only when a header needs it.
const VERSION_V2: u8 = 2;
const SHAPE_PAYLOAD: u8 = 0;
const SHAPE_BLOCK_HASH: u8 = 1;
const MAX_EXTRA_DATA: usize = 1 << 20;

/// The persisted store state — field-for-field the Java `LightClientStore.Snapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSnapshot {
    pub finalized_header: LightClientHeader,
    pub optimistic_header: LightClientHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: Option<SyncCommittee>,
    pub finalized_slot: u64,
    pub optimistic_slot: u64,
    pub current_sync_committee_period: u64,
}

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

/// Deserialize a snapshot; `None` on any malformed/foreign/wrong-version input
/// (the caller falls back to the embedded checkpoint, exactly like Java).
pub fn deserialize(data: &[u8], expected_gvr: &[u8; 32]) -> Option<StoreSnapshot> {
    let mut r = Reader { data, pos: 0 };
    if r.u32()? != MAGIC {
        return None;
    }
    let version = r.u8()?;
    if version != VERSION_V1 && version != VERSION_V2 {
        return None;
    }
    if r.fixed(32)? != expected_gvr {
        return None; // different chain
    }
    let period = r.u64()?;
    let finalized_slot = r.u64()?;
    let optimistic_slot = r.u64()?;
    let finalized_header = read_header(&mut r, version)?;
    let optimistic_header = read_header(&mut r, version)?;
    let current = read_committee(&mut r)?;
    // Java DataInputStream.readBoolean is `byte != 0` — match it exactly so a
    // corrupted flag byte can't desynchronize the two readers differently.
    let next = if r.u8()? != 0 { Some(read_committee(&mut r)?) } else { None };
    Some(StoreSnapshot {
        finalized_header,
        optimistic_header,
        current_sync_committee: current,
        next_sync_committee: next,
        finalized_slot,
        optimistic_slot,
        current_sync_committee_period: period,
    })
}

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

fn read_branch(r: &mut Reader<'_>, len: usize) -> Option<Vec<[u8; 32]>> {
    (0..len).map(|_| r.root()).collect()
}

// ---- ExecutionPayloadHeader (field-by-field, Java framing) ----

fn write_execution(out: &mut Vec<u8>, e: &ExecutionPayloadHeader) {
    out.extend_from_slice(&e.parent_hash);
    out.extend_from_slice(&e.fee_recipient);
    out.extend_from_slice(&e.state_root);
    out.extend_from_slice(&e.receipts_root);
    // logsBloom is fixed 256 in the framing; pad/truncate defensively so a
    // malformed in-memory value can't corrupt the file layout.
    let mut bloom = [0u8; 256];
    let n = e.logs_bloom.len().min(256);
    bloom[..n].copy_from_slice(&e.logs_bloom[..n]);
    out.extend_from_slice(&bloom);
    out.extend_from_slice(&e.prev_randao);
    out.extend_from_slice(&e.block_number.to_be_bytes());
    out.extend_from_slice(&e.gas_limit.to_be_bytes());
    out.extend_from_slice(&e.gas_used.to_be_bytes());
    out.extend_from_slice(&e.timestamp.to_be_bytes());
    let extra = if e.extra_data.len() <= MAX_EXTRA_DATA { &e.extra_data[..] } else { &[] };
    out.extend_from_slice(&(extra.len() as u32).to_be_bytes());
    out.extend_from_slice(extra);
    out.extend_from_slice(&e.base_fee_per_gas);
    out.extend_from_slice(&e.block_hash);
    out.extend_from_slice(&e.transactions_root);
    out.extend_from_slice(&e.withdrawals_root);
    out.extend_from_slice(&e.blob_gas_used.to_be_bytes());
    out.extend_from_slice(&e.excess_blob_gas.to_be_bytes());
    // Electra tail: the Java writer keys on depositRequestsRoot alone and the
    // Java reader restores all three together — mirror that, defaulting a
    // (never-expected) missing sibling root to zeroes instead of panicking.
    match e.deposit_requests_root {
        Some(deposit) => {
            out.push(1);
            out.extend_from_slice(&deposit);
            out.extend_from_slice(&e.withdrawal_requests_root.unwrap_or([0u8; 32]));
            out.extend_from_slice(&e.consolidation_requests_root.unwrap_or([0u8; 32]));
        }
        None => out.push(0),
    }
}

fn read_execution(r: &mut Reader<'_>) -> Option<ExecutionPayloadHeader> {
    let parent_hash = r.root()?;
    let fee_recipient: [u8; 20] = r.fixed(20)?.try_into().ok()?;
    let state_root = r.root()?;
    let receipts_root = r.root()?;
    let logs_bloom = r.fixed(256)?.to_vec();
    let prev_randao = r.root()?;
    let block_number = r.u64()?;
    let gas_limit = r.u64()?;
    let gas_used = r.u64()?;
    let timestamp = r.u64()?;
    let extra_len = r.u32()? as usize;
    if extra_len > MAX_EXTRA_DATA {
        return None; // same cap as the Java reader
    }
    let extra_data = r.fixed(extra_len)?.to_vec();
    let base_fee_per_gas = r.root()?;
    let block_hash = r.root()?;
    let transactions_root = r.root()?;
    let withdrawals_root = r.root()?;
    let blob_gas_used = r.u64()?;
    let excess_blob_gas = r.u64()?;
    // Boolean framing parity with Java's readBoolean: any non-zero is true.
    let (deposit, withdrawal, consolidation) = if r.u8()? != 0 {
        (Some(r.root()?), Some(r.root()?), Some(r.root()?))
    } else {
        (None, None, None)
    };
    Some(ExecutionPayloadHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions_root,
        withdrawals_root,
        blob_gas_used,
        excess_blob_gas,
        deposit_requests_root: deposit,
        withdrawal_requests_root: withdrawal,
        consolidation_requests_root: consolidation,
    })
}

// ---- SyncCommittee: 512×48 pubkeys + 48 aggregate (same as its SSZ layout) ----

fn write_committee(out: &mut Vec<u8>, c: &SyncCommittee) {
    let want = SYNC_COMMITTEE_SIZE * PUBKEY_SIZE;
    if c.pubkeys.len() == want {
        out.extend_from_slice(&c.pubkeys);
    } else {
        // Defensive (a store committee always has 512): pad/truncate to keep
        // the fixed framing intact rather than panic or corrupt offsets.
        let n = c.pubkeys.len().min(want);
        out.extend_from_slice(&c.pubkeys[..n]);
        out.resize(out.len() + (want - n), 0);
    }
    out.extend_from_slice(&c.aggregate_pubkey);
}

fn read_committee(r: &mut Reader<'_>) -> Option<SyncCommittee> {
    let pubkeys = r.fixed(SYNC_COMMITTEE_SIZE * PUBKEY_SIZE)?.to_vec();
    let aggregate_pubkey: [u8; PUBKEY_SIZE] = r.fixed(PUBKEY_SIZE)?.try_into().ok()?;
    Some(SyncCommittee { pubkeys, aggregate_pubkey })
}

// ---- checked big-endian reader ----

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

#[cfg(test)]
mod tests {
    use super::*;

    fn patterned(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
    }

    fn root(seed: u8) -> [u8; 32] {
        patterned(seed, 32).try_into().unwrap()
    }

    fn header(seed: u8, electra: bool) -> LightClientHeader {
        LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: 14_600_000 + seed as u64,
                proposer_index: 42 + seed as u64,
                parent_root: root(seed),
                state_root: root(seed.wrapping_add(1)),
                body_root: root(seed.wrapping_add(2)),
            },
            execution: HeaderExecution::Payload(Box::new(ExecutionPayloadHeader {
                parent_hash: root(seed.wrapping_add(3)),
                fee_recipient: patterned(seed, 20).try_into().unwrap(),
                state_root: root(seed.wrapping_add(4)),
                receipts_root: root(seed.wrapping_add(5)),
                logs_bloom: patterned(seed, 256),
                prev_randao: root(seed.wrapping_add(6)),
                block_number: 23_000_000 + seed as u64,
                gas_limit: 30_000_000,
                gas_used: 12_345_678,
                timestamp: 1_751_000_000 + seed as u64,
                extra_data: patterned(seed, 11),
                base_fee_per_gas: root(seed.wrapping_add(7)),
                block_hash: root(seed.wrapping_add(8)),
                transactions_root: root(seed.wrapping_add(9)),
                withdrawals_root: root(seed.wrapping_add(10)),
                blob_gas_used: 131_072,
                excess_blob_gas: 0,
                deposit_requests_root: electra.then(|| root(seed.wrapping_add(11))),
                withdrawal_requests_root: electra.then(|| root(seed.wrapping_add(12))),
                consolidation_requests_root: electra.then(|| root(seed.wrapping_add(13))),
            })),
            execution_branch: (0..4).map(|i| root(seed.wrapping_add(20 + i))).collect(),
        }
    }

    /// A Gloas-shaped header: block hash + 11 branch nodes.
    fn gloas_header(seed: u8) -> LightClientHeader {
        LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: 11_296_768 + seed as u64,
                proposer_index: 7 + seed as u64,
                parent_root: root(seed),
                state_root: root(seed.wrapping_add(1)),
                body_root: root(seed.wrapping_add(2)),
            },
            execution: HeaderExecution::BlockHash(root(seed.wrapping_add(3))),
            execution_branch: (0..11).map(|i| root(seed.wrapping_add(30 + i))).collect(),
        }
    }

    /// Finalized header still payload-shaped (the first epochs after the fork),
    /// optimistic header Gloas-shaped — the mixed state v2 exists for.
    fn gloas_snapshot() -> StoreSnapshot {
        StoreSnapshot {
            finalized_header: header(1, true),
            optimistic_header: gloas_header(60),
            current_sync_committee: committee(3),
            next_sync_committee: Some(committee(7)),
            finalized_slot: 11_296_700,
            optimistic_slot: 11_296_829,
            current_sync_committee_period: 1379,
        }
    }

    fn committee(seed: u8) -> SyncCommittee {
        SyncCommittee {
            pubkeys: patterned(seed, SYNC_COMMITTEE_SIZE * PUBKEY_SIZE),
            aggregate_pubkey: patterned(seed.wrapping_add(1), PUBKEY_SIZE).try_into().unwrap(),
        }
    }

    fn snapshot(next: bool) -> StoreSnapshot {
        StoreSnapshot {
            finalized_header: header(1, true),
            optimistic_header: header(50, false),
            current_sync_committee: committee(3),
            next_sync_committee: next.then(|| committee(7)),
            finalized_slot: 14_600_001,
            optimistic_slot: 14_600_033,
            current_sync_committee_period: 1795,
        }
    }

    #[test]
    fn round_trips_with_and_without_next_committee() {
        for next in [true, false] {
            let s = snapshot(next);
            let gvr = root(99);
            let bytes = serialize(&s, &gvr);
            let back = deserialize(&bytes, &gvr).expect("round trip");
            assert_eq!(s, back);
        }
    }

    /// Rust half of the LCSS-v1 cross-engine golden contract. The fixture is
    /// generated by the Java codec (SnapshotGoldenConformanceTest builds the
    /// IDENTICAL patterned snapshot); both suites pin the same committed bytes,
    /// so a one-byte layout drift on either side fails one of the two.
    #[test]
    fn golden_fixture_matches_java_codec() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/snapshot/lcss-v1-golden.bin"
        );
        let bytes = std::fs::read(path)
            .expect("golden fixture missing — run the Java SnapshotGoldenConformanceTest to generate it");
        let gvr = root(99);
        let snap = deserialize(&bytes, &gvr).expect("golden fixture must decode");
        assert_eq!(snap, snapshot(true), "decoded fixture != the shared patterned snapshot");
        assert_eq!(serialize(&snap, &gvr), bytes, "re-encode must be byte-identical to the fixture");
    }

    /// Payload-shaped state keeps writing v1 byte-for-byte (an older build can
    /// still resume it); a Gloas-shaped header switches the file to v2, which
    /// round-trips both shapes.
    #[test]
    fn v2_only_when_a_header_needs_it() {
        let gvr = root(99);
        assert_eq!(serialize(&snapshot(true), &gvr)[4], VERSION_V1);
        let s = gloas_snapshot();
        let bytes = serialize(&s, &gvr);
        assert_eq!(bytes[4], VERSION_V2);
        assert_eq!(deserialize(&bytes, &gvr).expect("round trip"), s);
        let mut both = gloas_snapshot();
        both.finalized_header = gloas_header(2);
        assert_eq!(
            deserialize(&serialize(&both, &gvr), &gvr).expect("round trip"),
            both
        );
    }

    /// Rust half of the LCSS-v2 cross-engine golden: the Java codec must encode
    /// the IDENTICAL patterned Gloas snapshot to these committed bytes
    /// (SnapshotGoldenConformanceTest), and decode them back to it.
    #[test]
    fn v2_golden_fixture_is_the_shared_gloas_snapshot() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/snapshot/lcss-v2-golden.bin"
        );
        let bytes = std::fs::read(path).expect("v2 golden fixture missing");
        let gvr = root(99);
        assert_eq!(
            deserialize(&bytes, &gvr).expect("v2 golden must decode"),
            gloas_snapshot()
        );
        assert_eq!(serialize(&gloas_snapshot(), &gvr), bytes);
    }

    /// An unknown shape tag is a corrupt (or future) file: refuse, don't guess.
    #[test]
    fn v2_rejects_an_unknown_shape_tag() {
        let gvr = root(99);
        let mut bytes = serialize(&gloas_snapshot(), &gvr);
        // magic 4 + version 1 + gvr 32 + 3 × u64 + finalized beacon 112.
        let tag_at = 4 + 1 + 32 + 24 + 112;
        assert_eq!(bytes[tag_at], SHAPE_PAYLOAD);
        bytes[tag_at] = 2;
        assert!(deserialize(&bytes, &gvr).is_none());
    }

    #[test]
    fn rejects_foreign_gvr_wrong_magic_and_truncation() {
        let s = snapshot(true);
        let gvr = root(99);
        let bytes = serialize(&s, &gvr);
        assert!(deserialize(&bytes, &root(42)).is_none(), "foreign chain must be rejected");
        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 0xFF;
        assert!(deserialize(&bad_magic, &gvr).is_none());
        // Every truncation must decode to None, never panic.
        for cut in [0, 4, 5, 36, 60, 200, bytes.len() - 1] {
            assert!(deserialize(&bytes[..cut], &gvr).is_none(), "cut at {cut}");
        }
        let v2 = serialize(&gloas_snapshot(), &gvr);
        for cut in [5, 173, 174, 700, v2.len() - 1] {
            assert!(deserialize(&v2[..cut], &gvr).is_none(), "v2 cut at {cut}");
        }
        let mut wrong_version = bytes.clone();
        wrong_version[4] = 3;
        assert!(deserialize(&wrong_version, &gvr).is_none());
    }

    /// Writes the v2 golden fixture. Run once when the format changes, then
    /// commit the file; the Java suite pins the same bytes.
    #[test]
    #[ignore = "generator: writes rust/testdata/snapshot/lcss-v2-golden.bin"]
    fn write_v2_golden_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/snapshot/lcss-v2-golden.bin"
        );
        std::fs::write(path, serialize(&gloas_snapshot(), &root(99))).unwrap();
    }
}
