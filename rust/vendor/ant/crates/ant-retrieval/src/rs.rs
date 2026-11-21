//! Reed-Solomon erasure recovery and dispersed-replica root fallback.
//!
//! Bee protects uploads made with `swarm-redundancy-level` 1–4 in two
//! complementary ways (`pkg/file/redundancy`, `pkg/replicas`):
//!
//! 1. **Erasure coding of intermediate nodes.** Every intermediate chunk
//!    of the file tree carries `shardCnt` data references followed by
//!    `parityCnt` parity references. The parity chunks are Reed-Solomon
//!    (GF(2^8), klauspost/Backblaze construction) encodings of the *full
//!    wire bytes* (`span(8 LE) ‖ payload`) of the data children, each
//!    shard zero-padded to `CHUNK_WITH_SPAN_SIZE` (4104) bytes. Any
//!    `shardCnt` of the `shardCnt + parityCnt` children reconstruct the
//!    missing data children byte-for-byte. The redundancy level itself
//!    is carried in the top byte of the intermediate chunk's span
//!    (`level | 0x80`, see [`decode_span`]).
//!
//! 2. **Dispersed replicas of the root chunk.** The root's span can't
//!    tell a downloader anything if the root itself is unretrievable, so
//!    bee additionally uploads 2^level single-owner-chunk copies of the
//!    root whose addresses are *derivable from the root address alone*:
//!    `id = root_addr with id[0] = entropy`, `owner = ReplicasOwner`,
//!    `soc_addr = keccak256(id ‖ owner)` (see [`replica_addresses`]).
//!
//! This module implements the *read* side of both: the per-node
//! [`RsDecoder`] used by the joiner to recover missing data children
//! from parities, and [`fetch_root_with_replicas`] used wherever a
//! bytes/bzz data root is fetched. The *write* side lives in
//! [`crate::rs_encode`] (redundant splitting + replica SOC minting)
//! and reuses this module's tables and geometry. Encrypted trees
//! (64-byte references) use the separate encrypted erasure tables
//! ([`get_enc_parities`] / [`max_enc_shards`]); their write side is
//! [`crate::enc_split`] and their read side [`crate::joiner`]'s
//! `join_encrypted`, which routes data-child fetches of redundant
//! nodes through an [`RsDecoder`] in encrypted mode
//! ([`RsDecoder::new_encrypted`]): parities are Reed-Solomon encodings
//! of the children's *ciphertext* wires (every stored encrypted chunk
//! is exactly 4104 bytes), so recovery reconstructs the ciphertext,
//! CAC-validates it against the 32-byte address half of the child's
//! 64-byte reference, and only then does the joiner decrypt with the
//! key half.
//!
//! The Reed-Solomon backend is the `reed-solomon-erasure` crate, which
//! uses the same Backblaze/klauspost matrix construction as bee's
//! `github.com/klauspost/reedsolomon`; byte-compatibility is proven
//! against bee-generated parities by `crates/ant-conformance/tests/rs.rs`
//! (vectors in `conformance/vectors/rs_files.json`).

use crate::ChunkFetcher;
use ant_crypto::{cac_valid, keccak256, soc_valid, CHUNK_SIZE, SOC_HEADER_SIZE, SPAN_SIZE};
use futures::stream::{self, StreamExt};
use tokio::sync::Mutex;

/// Full RS shard size: a chunk's wire bytes (`span ‖ payload`) padded to
/// the maximum. Mirrors bee's `swarm.ChunkWithSpanSize`.
pub const CHUNK_WITH_SPAN_SIZE: usize = CHUNK_SIZE + SPAN_SIZE;

/// Highest defined redundancy level (bee `redundancy.PARANOID`).
pub const MAX_LEVEL: u8 = 4;

/// Dispersed replica counts per level (bee `redundancy.GetReplicaCounts`).
pub const REPLICA_COUNTS: [usize; 5] = [0, 2, 4, 8, 16];

/// Owner address of every dispersed replica SOC and its well-known
/// private key. They live in [`ant_crypto::soc`] (where `soc_valid`
/// enforces the replica id rule) and are re-exported here so existing
/// paths keep working.
pub use ant_crypto::soc::{REPLICAS_OWNER, REPLICAS_OWNER_SECRET};

/// How many sibling shard fetches a recovery sweep keeps in flight at
/// once. The sweep touches at most 128 chunks; 16 matches the joiner's
/// own subtree fanout so a recovery doesn't hog the process-wide
/// retrieval semaphore.
const RECOVERY_FETCH_FANOUT: usize = 16;

/// How many replica candidates [`fetch_root_with_replicas`] keeps in
/// flight at once. Ordered (`buffered`, not `buffer_unordered`) so the
/// dispersal order stays the preference order, like bee's batched
/// replica getter (2, then 4, then 8 … per `RetryInterval`).
const REPLICA_FETCH_FANOUT: usize = 4;

// --- redundancy level tables (bee pkg/file/redundancy/level.go) ---------

/// Erasure table rows: `(min_shards, parities)`, descending. For `n`
/// data shards the parity count is the first row with `n >= min_shards`.
/// The non-encrypted tables come first, then the encrypted ones
/// (`encMediumEt` … `encParanoidEt`, appendix F table 6) used when a
/// tree carries 64-byte encrypted references. All are pinned against
/// bee in `conformance/vectors/redundancy.json`.
const MEDIUM_TABLE: &[(usize, usize)] = &[
    (95, 9),
    (69, 8),
    (47, 7),
    (29, 6),
    (15, 5),
    (6, 4),
    (2, 3),
    (1, 2),
];
const STRONG_TABLE: &[(usize, usize)] = &[
    (105, 21),
    (96, 20),
    (87, 19),
    (78, 18),
    (70, 17),
    (62, 16),
    (54, 15),
    (47, 14),
    (40, 13),
    (33, 12),
    (27, 11),
    (21, 10),
    (16, 9),
    (11, 8),
    (7, 7),
    (4, 6),
    (2, 5),
    (1, 4),
];
const INSANE_TABLE: &[(usize, usize)] = &[
    (93, 31),
    (88, 30),
    (83, 29),
    (78, 28),
    (74, 27),
    (69, 26),
    (64, 25),
    (60, 24),
    (55, 23),
    (51, 22),
    (46, 21),
    (42, 20),
    (38, 19),
    (34, 18),
    (30, 17),
    (27, 16),
    (23, 15),
    (20, 14),
    (17, 13),
    (14, 12),
    (11, 11),
    (9, 10),
    (6, 9),
    (4, 8),
    (3, 7),
    (2, 6),
    (1, 5),
];
const PARANOID_TABLE: &[(usize, usize)] = &[
    (37, 89),
    (36, 87),
    (35, 86),
    (34, 84),
    (33, 83),
    (32, 81),
    (31, 80),
    (30, 78),
    (29, 76),
    (28, 75),
    (27, 73),
    (26, 71),
    (25, 70),
    (24, 68),
    (23, 66),
    (22, 65),
    (21, 63),
    (20, 61),
    (19, 59),
    (18, 58),
    (17, 56),
    (16, 54),
    (15, 52),
    (14, 50),
    (13, 48),
    (12, 47),
    (11, 45),
    (10, 43),
    (9, 40),
    (8, 38),
    (7, 36),
    (6, 34),
    (5, 31),
    (4, 29),
    (3, 26),
    (2, 23),
    (1, 19),
];

const ENC_MEDIUM_TABLE: &[(usize, usize)] =
    &[(47, 9), (34, 8), (23, 7), (14, 6), (7, 5), (3, 4), (1, 3)];
const ENC_STRONG_TABLE: &[(usize, usize)] = &[
    (52, 21),
    (48, 20),
    (43, 19),
    (39, 18),
    (35, 17),
    (31, 16),
    (27, 15),
    (23, 14),
    (20, 13),
    (16, 12),
    (13, 11),
    (10, 10),
    (8, 9),
    (5, 8),
    (3, 7),
    (2, 6),
    (1, 5),
];
const ENC_INSANE_TABLE: &[(usize, usize)] = &[
    (46, 31),
    (44, 30),
    (41, 29),
    (39, 28),
    (37, 27),
    (34, 26),
    (32, 25),
    (30, 24),
    (27, 23),
    (25, 22),
    (23, 21),
    (21, 20),
    (19, 19),
    (17, 18),
    (15, 17),
    (13, 16),
    (11, 15),
    (10, 14),
    (8, 13),
    (7, 12),
    (5, 11),
    (4, 10),
    (3, 9),
    (2, 8),
    (1, 6),
];
const ENC_PARANOID_TABLE: &[(usize, usize)] = &[
    (18, 87),
    (17, 84),
    (16, 81),
    (15, 78),
    (14, 75),
    (13, 71),
    (12, 68),
    (11, 65),
    (10, 61),
    (9, 58),
    (8, 54),
    (7, 50),
    (6, 47),
    (5, 43),
    (4, 38),
    (3, 34),
    (2, 29),
    (1, 23),
];

fn table_parities(table: &[(usize, usize)], shards: usize) -> usize {
    for &(min_shards, parities) in table {
        if shards >= min_shards {
            return parities;
        }
    }
    0
}

/// Parity count for `shards` data shards at `level` (bee
/// `Level.GetParities`). Level 0 (or out-of-range) has no parities.
#[must_use]
pub fn get_parities(level: u8, shards: usize) -> usize {
    let table = match level {
        1 => MEDIUM_TABLE,
        2 => STRONG_TABLE,
        3 => INSANE_TABLE,
        4 => PARANOID_TABLE,
        _ => return 0,
    };
    table_parities(table, shards)
}

/// Parity count for `shards` *encrypted* data shards at `level` (bee
/// `Level.GetEncParities`, appendix F table 6). Level 0 → 0.
#[must_use]
pub fn get_enc_parities(level: u8, shards: usize) -> usize {
    let table = match level {
        1 => ENC_MEDIUM_TABLE,
        2 => ENC_STRONG_TABLE,
        3 => ENC_INSANE_TABLE,
        4 => ENC_PARANOID_TABLE,
        _ => return 0,
    };
    table_parities(table, shards)
}

/// Maximum number of *data* references in one intermediate chunk at
/// `level` (bee `Level.GetMaxShards`): 128 slots minus the parities a
/// full chunk carries. Level 0 → 128.
#[must_use]
pub fn max_shards(level: u8) -> usize {
    128 - get_parities(level, 128)
}

/// Maximum number of encrypted (64-byte) data references in one
/// intermediate chunk at `level` (bee `Level.GetMaxEncShards`):
/// `(128 - GetEncParities(64)) / 2` — each data reference occupies two
/// 32-byte slots, each parity reference one. Level 0 → 64.
#[must_use]
pub fn max_enc_shards(level: u8) -> usize {
    (128 - get_enc_parities(level, 64)) / 2
}

/// True when the span's top byte carries a redundancy level
/// (bee `redundancy.IsLevelEncoded`: strictly greater than 128 — a top
/// byte of 1..=128 is just an implausibly-huge plain span).
#[must_use]
pub const fn is_level_encoded(span: &[u8; SPAN_SIZE]) -> bool {
    span[SPAN_SIZE - 1] > 128
}

/// Split a chunk span into `(redundancy level, plain span bytes)`
/// (bee `redundancy.DecodeSpan`). Non-encoded spans return level 0
/// unchanged.
#[must_use]
pub const fn decode_span(mut span: [u8; SPAN_SIZE]) -> (u8, [u8; SPAN_SIZE]) {
    if !is_level_encoded(&span) {
        return (0, span);
    }
    let level = span[SPAN_SIZE - 1] & 0x7f;
    span[SPAN_SIZE - 1] = 0;
    (level, span)
}

/// Data-shard and parity count of the intermediate chunk that roots a
/// subtree of `span` bytes at `level` (bee `file.ReferenceCount`,
/// non-encrypted). Assumes `span > CHUNK_SIZE` (the chunk is an
/// intermediate node); brute-forces the BMT level whose per-reference
/// capacity covers `span`, counts the references needed, and reads the
/// parity count off the level's erasure table.
#[must_use]
pub fn reference_count(span: u64, level: u8) -> (usize, usize) {
    let data_shards = count_data_shards(span, max_shards(level) as u64);
    (data_shards, get_parities(level, data_shards))
}

/// [`reference_count`] for trees carrying 64-byte *encrypted*
/// references (bee `file.ReferenceCount` with `encryptedChunk = true`):
/// branching and parities come from the encrypted tables
/// ([`max_enc_shards`] / [`get_enc_parities`]).
#[must_use]
pub fn reference_count_enc(span: u64, level: u8) -> (usize, usize) {
    let data_shards = count_data_shards(span, max_enc_shards(level) as u64);
    (data_shards, get_enc_parities(level, data_shards))
}

/// Shared geometry of `reference_count`(`_enc`): brute-force the BMT
/// level whose per-reference capacity covers `span`, then count the
/// references needed on that level.
///
/// All arithmetic saturates (bee v2.8.3's security fix,
/// <https://github.com/ethersphere/bee/pull/5664>, and the same shape as
/// `ant-crypto`'s `enc_reference_count`). `span` is untrusted: besides
/// fetched chunks, [`recovered_wire_len`] calls this on an RS-reconstructed
/// shard *before* its content address is checked, and an uploader picks
/// those bytes through the parities. With plain `*=` a span above 2^61
/// (branching 128) wrapped `branch_size` to 0, so the first loop never
/// ended — a busy loop with no await point that pinned a tokio worker
/// (release) or panicked (debug). Saturating stops the walk at
/// `u64::MAX`; results for every span that didn't overflow are unchanged,
/// and an oversized span yields at most `branching` shards.
fn count_data_shards(span: u64, branching: u64) -> usize {
    let mut branch_size = CHUNK_SIZE as u64;
    let mut branch_level: u32 = 1;
    while branch_size < span {
        branch_size = branch_size.saturating_mul(branching);
        branch_level += 1;
    }
    // Capacity of one reference at this node's level:
    // CHUNK_SIZE * branching^(branch_level - 2).
    let mut reference_size = CHUNK_SIZE as u64;
    let mut i = 1;
    while i + 1 < branch_level {
        reference_size = reference_size.saturating_mul(branching);
        i += 1;
    }
    let mut data_shards = 1usize;
    let mut span_offset = reference_size;
    while span_offset < span {
        span_offset = span_offset.saturating_add(reference_size);
        data_shards += 1;
    }
    data_shards
}

/// Redundancy metadata of a fetched chunk's wire bytes: `(level, plain
/// span value, parity count)`. Leaf chunks (span ≤ one chunk) never
/// carry parities; intermediate chunks derive theirs from their own
/// decoded span + level, exactly like bee's joiner does per child.
#[must_use]
pub fn chunk_meta(wire: &[u8]) -> Option<(u8, u64, usize)> {
    let span_bytes: [u8; SPAN_SIZE] = wire.get(..SPAN_SIZE)?.try_into().ok()?;
    let (level, plain) = decode_span(span_bytes);
    let span = u64::from_le_bytes(plain);
    let parity = if level != 0 && span > CHUNK_SIZE as u64 {
        reference_count(span, level).1
    } else {
        0
    };
    Some((level, span, parity))
}

/// True wire length of a *recovered* RS data shard. Reconstruction
/// yields the zero-padded 4104-byte shard; only the span tells us where
/// the real chunk ends (bee sidesteps this with `lastLen`, recorded off
/// a fetched sibling — we recompute instead so recovery of the last
/// shard works even when it was never fetched):
///
/// - span ≤ 4096 → leaf → `8 + span`;
/// - span > 4096 → intermediate → `8 + 32 * (shards + parities)` from
///   [`reference_count`] on the shard's own decoded span.
fn recovered_wire_len(shard: &[u8]) -> Option<usize> {
    let span_bytes: [u8; SPAN_SIZE] = shard.get(..SPAN_SIZE)?.try_into().ok()?;
    let (level, plain) = decode_span(span_bytes);
    let span = u64::from_le_bytes(plain);
    if span <= CHUNK_SIZE as u64 {
        return Some(SPAN_SIZE + span as usize);
    }
    let (shards, parities) = reference_count(span, level);
    let refs = shards + parities;
    if refs * 32 > CHUNK_SIZE {
        return None;
    }
    Some(SPAN_SIZE + refs * 32)
}

/// Per-intermediate-node erasure decoder: the read-path equivalent of
/// bee's `pkg/file/redundancy/getter` with the `DATA` strategy — serve
/// data children from the network, and on the first miss sweep *all*
/// siblings (data + parity, bounded concurrency) and Reed-Solomon
/// reconstruct the missing data shards.
///
/// One decoder is created per redundant intermediate node and shared by
/// that node's child fetches. Concurrent child misses coalesce onto one
/// recovery sweep. A *final* outcome (all data shard wires, or a
/// permanent [`RecoveryError`]) is cached, so repeated fetches of
/// recovered chunks are served from memory and real data loss fails
/// every sibling at once. A *transient* failure — too few shards
/// arrived, but enough of the misses were the fetcher never reaching a
/// peer (`no BZZ peers available`, timeouts), or peers answering "not
/// found" for less than [`MISS_CONFIRM_AFTER`] (issue #79) —
/// is not cached: it is handed to the callers
/// that were waiting on that sweep, and the next call sweeps afresh
/// (issue #114). Shards the failed sweep did fetch sit in the
/// fetcher's caches, so a re-sweep only goes to the network for the
/// rest. Recovered chunks are CAC-validated
/// against their parent references (a mismatch would mean an RS matrix
/// incompatibility or corrupted parities — never silently returned) and
/// handed to [`ChunkFetcher::put_recovered`] so they land in the same
/// caches a network fetch would.
pub struct RsDecoder {
    /// All child references of the node: `shard_cnt` data refs followed
    /// by parity refs. For encrypted trees these are the 32-byte
    /// *address halves* of the 64-byte data references plus the bare
    /// 32-byte parity references — the decoder never sees a key.
    addrs: Vec<[u8; 32]>,
    shard_cnt: usize,
    /// Encrypted-tree mode: shards are the children's *ciphertext*
    /// wires, which are all exactly [`CHUNK_WITH_SPAN_SIZE`] bytes (the
    /// encrypted splitter pads every stored chunk), so a reconstructed
    /// shard is returned whole — its span bytes are ciphertext and
    /// cannot (and need not) drive a truncation like the plain path's
    /// [`recovered_wire_len`].
    encrypted: bool,
    /// Outcome of the latest recovery sweep; see [`SweepState`].
    recovered: Mutex<SweepState>,
}

/// How long peers must keep answering "not found" for a shard, from
/// the first sweep that heard it, before the shard counts as missing
/// (issue #79). On a cold node a fetch that runs out of peers on
/// `storage: not found` / `no peer found` answers is not the network's
/// last word: forwarders without credit or a route answer that for
/// chunks that exist. On a fresh mainnet node, of 20 chunks whose fetch
/// had exhausted all 32 peers on such answers, 11 were served within
/// 8.5 s of that first exhausted fetch (one to four fetches later), 2
/// only minutes later and 7 not at all. A plain child retries that miss
/// in place ([`crate::joiner`]'s subtree retries); a redundant node used
/// to end the join on the first sweep's answer, cutting the body short
/// a few chunks in. Until this long has passed, such a shortfall is
/// transient and the caller's recovery retries sweep again.
///
/// 10 s covers the 8.5 s above (each re-sweep starts after the caller's
/// back-off, 0.5 s growing to 4 s), and still fails real loss well
/// inside the caller's 60 s recovery budget, and sooner than a lost
/// chunk of a plain tree, which the gateway only gives up on after its
/// 90 s stall timeout. Wall-clock, not a sweep count: sibling children
/// of one node retry on their own schedules, so several sweeps can run
/// back to back within milliseconds and would confirm a miss before
/// anything had a chance to change. The window covers one episode of
/// denials: a shard a sweep serves starts over, and so does one whose
/// last denial is more than this long before the caller of the next
/// denying sweep asked for its shard, so a miss that a later direct
/// fetch got past can't make a new miss of the same node final on its
/// first sweep. The gap is measured to when the caller asked, not to
/// when its sweep ended: a retry loop asks again one back-off (≤ 4 s)
/// after its last sweep, however long its direct fetch and sweep then
/// take, so slow denials (several seconds a fetch on mainnet) keep one
/// episode going instead of restarting it every sweep.
pub const MISS_CONFIRM_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// A failed [`RsDecoder`] recovery. `transient` says whether the
/// failure could clear on a later sweep (see
/// [`RsDecoder::fetch_data_shard`]); callers retry those with back-off
/// and treat the rest as final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryError {
    pub detail: String,
    pub transient: bool,
}

impl RecoveryError {
    fn permanent(detail: String) -> Self {
        Self {
            detail,
            transient: false,
        }
    }
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// What an [`RsDecoder`] remembers between calls.
#[derive(Default)]
struct SweepState {
    /// How many sweeps have finished. A caller that read `n` before it
    /// queued on the lock and finds `sweeps > n` knows a sweep finished
    /// while it waited, and takes that sweep's outcome instead of
    /// starting another one straight away.
    sweeps: u64,
    /// Outcome of the latest sweep. `Ok` and permanent errors are final;
    /// a transient error is only kept to answer the callers that were
    /// waiting on that sweep.
    outcome: Option<Result<Vec<Vec<u8>>, RecoveryError>>,
    /// Per shard index (data and parity), when sweeps first and last
    /// heard peers deny that shard ("not found") in its current episode
    /// of denials ([`MISS_CONFIRM_AFTER`]). Empty until the first sweep.
    denied: Vec<Option<Denied>>,
    /// Whether the latest sweep ran at the head of a streaming join's
    /// window ([`crate::priority`], issue #46). The sweep runs under the
    /// rank of the caller that triggered it; a look-ahead-ranked sweep
    /// leaves every peer a head reserve and queues for its request's
    /// permits, so its transient shortfall is no answer for a head
    /// caller, which sweeps again at its own rank instead.
    head_ranked: bool,
}

/// One shard's current episode of "not found" answers.
#[derive(Clone, Copy)]
struct Denied {
    first: tokio::time::Instant,
    last: tokio::time::Instant,
}

impl Denied {
    /// Record a denial heard at `now` by a sweep whose caller asked for
    /// its shard at `asked`; whether the shard has now been denied for
    /// [`MISS_CONFIRM_AFTER`]. A previous denial more than that long
    /// before `asked` ends the episode and this one starts a new one.
    fn confirm(
        slot: &mut Option<Self>,
        asked: tokio::time::Instant,
        now: tokio::time::Instant,
    ) -> bool {
        let d = match slot {
            Some(d) if asked.saturating_duration_since(d.last) <= MISS_CONFIRM_AFTER => {
                d.last = now;
                *d
            }
            _ => *slot.insert(Self {
                first: now,
                last: now,
            }),
        };
        now.duration_since(d.first) >= MISS_CONFIRM_AFTER
    }
}

impl SweepState {
    /// The cached outcome if it is final (success or permanent error).
    fn final_outcome(&self) -> Option<&Result<Vec<Vec<u8>>, RecoveryError>> {
        match &self.outcome {
            Some(Err(e)) if e.transient => None,
            other => other.as_ref(),
        }
    }
}

impl RsDecoder {
    /// `addrs` is the node's full reference list (data shards first,
    /// then parities); `shard_cnt` how many of them are data.
    #[must_use]
    pub fn new(addrs: Vec<[u8; 32]>, shard_cnt: usize) -> Self {
        debug_assert!(shard_cnt >= 1 && shard_cnt < addrs.len());
        Self {
            addrs,
            shard_cnt,
            encrypted: false,
            recovered: Mutex::new(SweepState::default()),
        }
    }

    /// [`RsDecoder::new`] for an **encrypted** intermediate node: `addrs`
    /// holds the 32-byte address halves of the node's 64-byte data
    /// references followed by its bare 32-byte parity references.
    /// Recovery runs entirely in ciphertext space (bee's redundancy
    /// getter is encryption-agnostic the same way: `file.ChunkAddresses`
    /// strips the key halves before the decoder ever sees the refs);
    /// the caller decrypts a returned wire with the key half of the
    /// reference it followed.
    #[must_use]
    pub fn new_encrypted(addrs: Vec<[u8; 32]>, shard_cnt: usize) -> Self {
        debug_assert!(shard_cnt >= 1 && shard_cnt < addrs.len());
        Self {
            addrs,
            shard_cnt,
            encrypted: true,
            recovered: Mutex::new(SweepState::default()),
        }
    }

    /// Fetch data shard `index` (< `shard_cnt`), recovering it from the
    /// node's parities when the direct fetch fails. Returns the exact
    /// wire bytes (`span ‖ payload`) the chunk was uploaded with.
    ///
    /// A recovery that came up short is `transient` when the shards that
    /// failed for want of a reachable peer (anything but peers
    /// confirming the chunk missing, see [`shard_confirmed_missing`]),
    /// plus those peers have denied for less than [`MISS_CONFIRM_AFTER`]
    /// across this decoder's sweeps, would have been enough to decode: a
    /// later call may succeed, so the caller should back off and call
    /// again. It is permanent when the shards denied for that long
    /// already exceed the parity count, or when the shards were all
    /// there but reconstruction or CAC validation failed.
    ///
    /// The direct fetch waits up to `credit_budget` for peer credit
    /// ([`ChunkFetcher::fetch_waiting_for_credit`]); the recovery sweep
    /// never waits (issue #117): a starved shard counts as unreached, so
    /// the sweep comes up short as `transient` and the caller's retry
    /// window decides.
    pub async fn fetch_data_shard(
        &self,
        fetcher: &dyn ChunkFetcher,
        index: usize,
        credit_budget: std::time::Duration,
    ) -> Result<Vec<u8>, RecoveryError> {
        // When this caller asked: the start of its gap since the last
        // denial ([`Denied::confirm`]), before the lock and the direct
        // fetch, whose time doesn't count as a gap in the denials.
        let asked = tokio::time::Instant::now();
        let seen = {
            let state = self.recovered.lock().await;
            if let Some(outcome) = state.final_outcome() {
                return match outcome {
                    Ok(shards) => Ok(shards[index].clone()),
                    Err(e) => Err(e.clone()),
                };
            }
            state.sweeps
        };
        match fetcher
            .fetch_waiting_for_credit(self.addrs[index], credit_budget)
            .await
        {
            Ok(wire) => Ok(wire),
            Err(fetch_err) => {
                let shards = self
                    .recover(fetcher, &fetch_err.to_string(), seen, asked)
                    .await?;
                Ok(shards[index].clone())
            }
        }
    }

    /// Run (or join) a recovery sweep and return every data shard.
    /// `seen` is the sweep count the caller read before its direct
    /// fetch: if a sweep finished since, its outcome is the answer.
    /// `asked` is when the caller asked for its shard.
    async fn recover(
        &self,
        fetcher: &dyn ChunkFetcher,
        trigger: &str,
        seen: u64,
        asked: tokio::time::Instant,
    ) -> Result<Vec<Vec<u8>>, RecoveryError> {
        let mut state = self.recovered.lock().await;
        if let Some(outcome) = state.final_outcome() {
            return outcome.clone();
        }
        // A sweep that finished while we waited answers us too, unless
        // we are the head and it ran at a lower rank: then its transient
        // shortfall may only be the head reserve it had to leave, and
        // we sweep again at head rank (a final outcome returned above).
        let head = crate::priority::current() == crate::priority::Priority::Head;
        if state.sweeps > seen && (state.head_ranked || !head) {
            if let Some(outcome) = state.outcome.as_ref() {
                return outcome.clone();
            }
        }
        let outcome = self
            .recover_inner(fetcher, trigger, asked, &mut state.denied)
            .await;
        state.sweeps += 1;
        state.outcome = Some(outcome.clone());
        // The rank only ever rises (the read head only moves on), so a
        // sweep that started at the head ran at the head throughout.
        state.head_ranked = head;
        outcome
    }

    async fn recover_inner(
        &self,
        fetcher: &dyn ChunkFetcher,
        trigger: &str,
        asked: tokio::time::Instant,
        denied: &mut Vec<Option<Denied>>,
    ) -> Result<Vec<Vec<u8>>, RecoveryError> {
        let total = self.addrs.len();
        denied.resize(total, None);
        let parity_cnt = total - self.shard_cnt;
        tracing::debug!(
            target: "ant_retrieval::rs",
            shards = total,
            "erasure recovery sweep started; trigger: {trigger}",
        );

        // Sweep every sibling (the one that just failed included — the
        // fetcher may reach a different peer this time), bounded.
        let mut wires: Vec<Option<Vec<u8>>> = vec![None; total];
        let fetched: Vec<(usize, Result<Vec<u8>, bool>)> = stream::iter(
            self.addrs
                .iter()
                .copied()
                .enumerate()
                .map(|(i, addr)| async move {
                    // On failure keep only whether a peer confirmed the
                    // chunk missing ("not found"), as opposed to the fetch
                    // never getting an answer (no admissible peer, timeouts,
                    // dropped streams).
                    let r = fetcher
                        .fetch(addr)
                        .await
                        .map_err(|e| shard_confirmed_missing(e.as_ref()));
                    (i, r)
                }),
        )
        .buffer_unordered(RECOVERY_FETCH_FANOUT)
        .collect()
        .await;
        let mut not_found = 0usize;
        let mut unreached = 0usize;
        // Denied ("not found") in this sweep, but for less than
        // `MISS_CONFIRM_AFTER` so far: not yet the network's answer, so
        // it counts towards a transient shortfall.
        let mut unconfirmed = 0usize;
        let now = tokio::time::Instant::now();
        for (i, wire) in fetched {
            match wire {
                Ok(w) if w.len() <= CHUNK_WITH_SPAN_SIZE => {
                    // Served: any denials of it so far were not the
                    // network's answer, and a later one starts over.
                    denied[i] = None;
                    wires[i] = Some(w);
                }
                // An oversized wire is not a shard of this node; no
                // retry changes that.
                Ok(_) => not_found += 1,
                Err(true) => {
                    if Denied::confirm(&mut denied[i], asked, now) {
                        not_found += 1;
                    } else {
                        unconfirmed += 1;
                    }
                }
                Err(false) => unreached += 1,
            }
        }

        let present = wires.iter().filter(|w| w.is_some()).count();
        if present < self.shard_cnt {
            // Transient when the shards we never reached, or that peers
            // have denied for too short a while to trust, would make up the
            // shortfall: the peer pool, not the content, is short.
            let transient = present + unreached + unconfirmed >= self.shard_cnt;
            tracing::debug!(
                target: "ant_retrieval::rs",
                present,
                not_found,
                unconfirmed,
                unreached,
                need = self.shard_cnt,
                transient,
                "erasure recovery sweep came up short",
            );
            return Err(RecoveryError {
                detail: format!(
                    "erasure recovery impossible: {present} of {total} shards retrievable, \
                     need {} ({} data + {parity_cnt} parity refs; {not_found} confirmed \
                     missing, {unconfirmed} denied for less than {}s, {unreached} \
                     unreached); trigger: {trigger}",
                    self.shard_cnt,
                    self.shard_cnt,
                    MISS_CONFIRM_AFTER.as_secs(),
                ),
                transient,
            });
        }

        let missing: Vec<usize> = (0..self.shard_cnt)
            .filter(|&i| wires[i].is_none())
            .collect();
        if !missing.is_empty() {
            let mut shards: Vec<Option<Vec<u8>>> = wires
                .iter()
                .map(|w| {
                    w.as_ref().map(|wire| {
                        let mut padded = wire.clone();
                        padded.resize(CHUNK_WITH_SPAN_SIZE, 0);
                        padded
                    })
                })
                .collect();
            let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(self.shard_cnt, parity_cnt)
                .map_err(|e| {
                RecoveryError::permanent(format!(
                    "reed-solomon init ({}+{parity_cnt}): {e}",
                    self.shard_cnt
                ))
            })?;
            rs.reconstruct_data(&mut shards)
                .map_err(|e| RecoveryError::permanent(format!("reed-solomon reconstruct: {e}")))?;

            for &i in &missing {
                let mut wire = shards[i].take().ok_or_else(|| {
                    RecoveryError::permanent("reconstruct left a data shard empty".into())
                })?;
                if !self.encrypted {
                    // Plain trees: the shard was zero-padded to 4104 for
                    // the RS matrix; its own (plaintext) span says where
                    // the real chunk ends. Encrypted trees skip this —
                    // every stored ciphertext wire is exactly 4104 bytes
                    // and the span bytes are ciphertext.
                    let len = recovered_wire_len(&wire).ok_or_else(|| {
                        RecoveryError::permanent(format!(
                            "recovered shard {i} has an undecodable span"
                        ))
                    })?;
                    if len > wire.len() {
                        return Err(RecoveryError::permanent(format!(
                            "recovered shard {i} shorter than its span implies"
                        )));
                    }
                    wire.truncate(len);
                }
                if !cac_valid(&self.addrs[i], &wire) {
                    return Err(RecoveryError::permanent(format!(
                        "recovered shard {i} failed CAC validation against {} \
                         (RS output does not match bee's encoding)",
                        hex::encode(self.addrs[i]),
                    )));
                }
                fetcher.put_recovered(self.addrs[i], &wire).await;
                tracing::debug!(
                    target: "ant_retrieval::rs",
                    chunk = %hex::encode(self.addrs[i]),
                    "recovered data chunk from parities",
                );
                wires[i] = Some(wire);
            }
        }

        Ok(wires
            .into_iter()
            .take(self.shard_cnt)
            .map(|w| w.expect("all data shards present after reconstruct"))
            .collect())
    }
}

/// Did a sweep's shard fetch fail because peers confirmed the chunk
/// missing (`storage: not found` / `no peer found`)? In a sweep that is
/// one denial: the shard only counts as missing once such answers have
/// held for [`MISS_CONFIRM_AFTER`] (issue #79). For the fetcher's
/// own error this is the typed
/// [`crate::fetcher::FetchExhausted::confirmed_missing`]: not when its
/// peer pool was starved, since on a cold node one peer can answer "not
/// found" and every other candidate be overdraft-skipped, which says
/// nothing about the chunk (issue #114). Other fetchers' errors fall
/// back to the message ([`crate::feed::is_chunk_not_found`]). Also the
/// test `ant-p2p`'s `/bytes` and `/bzz` root retries use to stop at a
/// real miss.
pub fn shard_confirmed_missing(e: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    match crate::fetcher::FetchExhausted::find(e) {
        Some(x) => x.confirmed_missing(),
        None => crate::feed::is_chunk_not_found(e),
    }
}

// --- dispersed replicas (bee pkg/replicas) -------------------------------

/// SOC addresses of the dispersed replicas of `addr` at `level`, in
/// bee's dispersal order (`pkg/replicas/replicas.go::replicator`): the
/// first 2 candidates cover distinct 1-bit address prefixes, the next 2
/// complete the 2-bit prefixes, then 4 for 3-bit, then 8 for 4-bit —
/// so any prefix of the list is maximally spread over the address space.
#[must_use]
pub fn replica_addresses(addr: &[u8; 32], level: u8) -> Vec<[u8; 32]> {
    replica_identities(addr, level)
        .into_iter()
        .map(|(_, soc_addr)| soc_addr)
        .collect()
}

/// Like [`replica_addresses`], but also returning each replica's SOC
/// id (`addr` with `id[0] = entropy`) — what the upload side needs to
/// mint the replica SOC chunks (`crate::rs_encode::replica_chunks`).
#[must_use]
pub fn replica_identities(addr: &[u8; 32], level: u8) -> Vec<([u8; 32], [u8; 32])> {
    let level = level.min(MAX_LEVEL);
    let count = REPLICA_COUNTS[level as usize];
    if count == 0 {
        return Vec::new();
    }

    // `exist` maps the 1..4-bit prefixes of a replica's first address
    // byte per level; `sizes` are the insertion cursors of each level's
    // queue block (level ℓ block starts at REPLICA_COUNTS[ℓ-1]).
    let mut exist = [false; 30];
    let mut sizes = [0usize, 2, 4, 8];
    const BASES: [usize; 4] = [0, 2, 6, 14];
    let mut queue: [Option<([u8; 32], [u8; 32])>; 16] = [None; 16];

    let mut inserted = 0usize;
    let mut entropy: u16 = 0;
    while inserted < count && entropy < 255 {
        let mut id = *addr;
        id[0] = entropy as u8;
        let mut input = [0u8; 52];
        input[..32].copy_from_slice(&id);
        input[32..].copy_from_slice(&REPLICAS_OWNER);
        let soc_addr = keccak256(&input);
        entropy += 1;

        // bee's recursive `replicator.add`, iteratively: walk from the
        // deepest prefix down; a duplicate at the top level rejects the
        // candidate, otherwise mark each new prefix and insert into the
        // block of the level just above the first already-seen prefix
        // (or level 1 if every prefix is new).
        let mut insert_level = None;
        for l in (1..=level).rev() {
            let nh = BASES[(l - 1) as usize] + (soc_addr[0] >> (8 - l)) as usize;
            if exist[nh] {
                if l == level {
                    insert_level = None;
                } else {
                    insert_level = Some(l + 1);
                }
                break;
            }
            exist[nh] = true;
            insert_level = Some(1);
        }
        if let Some(l) = insert_level {
            let d = (l - 1) as usize;
            queue[sizes[d]] = Some((id, soc_addr));
            sizes[d] += 1;
            inserted += 1;
        }
    }

    queue.iter().take(count).filter_map(|q| *q).collect()
}

/// Fetch the chunk at `addr`, falling back to its dispersed replicas
/// when the direct fetch fails.
///
/// This is the read-path mirror of bee's `replicas.NewGetter` wrapped
/// around the root-chunk fetch of every bytes/bzz download: the replica
/// SOC addresses are derived from `addr` alone, tried in dispersal
/// order with bounded concurrency, SOC-validated, unwrapped, and the
/// inner content CAC-validated against `addr` before being returned as
/// the chunk's wire bytes. Since the uploader's redundancy level isn't
/// knowable before the root is read, candidates for every level are
/// tried (PARANOID's 16 first, then the lower levels' orderings,
/// deduplicated — bee instead takes the level from a request header and
/// defaults to PARANOID for downloads). A found root is stored via
/// [`ChunkFetcher::put_recovered`] so later fetches hit the cache.
///
/// On total failure the *original* fetch error is returned, so callers'
/// error messages still describe the direct root miss.
///
/// The direct fetch waits up to `credit_budget` for peer credit
/// ([`ChunkFetcher::fetch_waiting_for_credit`]; zero means plain
/// `fetch`). The replica probes never wait (issue #117): most replica
/// addresses hold nothing, and up to 30 waits at fanout 4 would stack.
pub async fn fetch_root_with_replicas(
    fetcher: &dyn ChunkFetcher,
    addr: [u8; 32],
    credit_budget: std::time::Duration,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let direct_err = match fetcher.fetch_waiting_for_credit(addr, credit_budget).await {
        Ok(wire) => return Ok(wire),
        Err(e) => e,
    };
    recover_from_replicas(fetcher, addr).await.ok_or(direct_err)
}

/// The replica half of [`fetch_root_with_replicas`], for a caller that
/// has already tried the direct fetch its own way: try `addr`'s
/// dispersed replicas and return the original chunk's wire bytes from
/// the first valid one, stored via [`ChunkFetcher::put_recovered`].
/// `None` when no replica could be fetched. The probes never wait for
/// credit.
pub(crate) async fn recover_from_replicas(
    fetcher: &dyn ChunkFetcher,
    addr: [u8; 32],
) -> Option<Vec<u8>> {
    recover_from_replicas_classified(fetcher, addr).await.ok()
}

/// How a replica sweep that recovered nothing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SweepMiss {
    /// Every replica address answered with the network's final word:
    /// a corroborated miss
    /// ([`crate::fetcher::FetchExhausted::corroborated_missing`]) or a
    /// chunk that isn't a valid replica of `addr`. Sweeping again in the
    /// same request won't change that.
    Final,
    /// At least one probe failed in a way a later try can change: a
    /// starved pool, a miss only one or two peers answered (a cold
    /// node), a transport error.
    Transient,
}

/// [`recover_from_replicas`], reporting on failure whether the sweep's
/// miss was final or may clear on a later sweep (R2-F1 on PR #155: a
/// manifest node load memoizes only a final miss across a request's
/// retries, so a replica-only node whose first sweep lost a credit race
/// is swept again on the next attempt).
pub(crate) async fn recover_from_replicas_classified(
    fetcher: &dyn ChunkFetcher,
    addr: [u8; 32],
) -> Result<Vec<u8>, SweepMiss> {
    let mut candidates: Vec<[u8; 32]> = Vec::with_capacity(REPLICA_COUNTS[4]);
    for level in (1..=MAX_LEVEL).rev() {
        for soc_addr in replica_addresses(&addr, level) {
            if !candidates.contains(&soc_addr) {
                candidates.push(soc_addr);
            }
        }
    }

    tracing::debug!(
        target: "ant_retrieval::rs",
        chunk = %hex::encode(addr),
        candidates = candidates.len(),
        "root fetch failed; trying dispersed replicas",
    );

    let mut attempts = stream::iter(candidates.into_iter().map(|soc_addr| async move {
        let wire = match fetcher.fetch(soc_addr).await {
            Ok(wire) => wire,
            Err(e) => {
                let final_miss = crate::fetcher::FetchExhausted::find(e.as_ref())
                    .is_some_and(crate::fetcher::FetchExhausted::corroborated_missing);
                return Err(if final_miss {
                    SweepMiss::Final
                } else {
                    SweepMiss::Transient
                });
            }
        };
        if !soc_valid(&soc_addr, &wire) || wire.len() <= SOC_HEADER_SIZE {
            return Err(SweepMiss::Final);
        }
        // The replica's wrapped CAC *is* the original chunk: same wire
        // bytes, and its BMT address is the address we were asked for.
        let inner = wire[SOC_HEADER_SIZE..].to_vec();
        if !cac_valid(&addr, &inner) {
            return Err(SweepMiss::Final);
        }
        Ok(inner)
    }))
    .buffered(REPLICA_FETCH_FANOUT);

    let mut miss = SweepMiss::Final;
    while let Some(outcome) = attempts.next().await {
        match outcome {
            Ok(inner) => {
                fetcher.put_recovered(addr, &inner).await;
                tracing::debug!(
                    target: "ant_retrieval::rs",
                    chunk = %hex::encode(addr),
                    "recovered root chunk from a dispersed replica",
                );
                return Ok(inner);
            }
            Err(SweepMiss::Transient) => miss = SweepMiss::Transient,
            Err(SweepMiss::Final) => {}
        }
    }
    Err(miss)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fetch is unreached (a starved pool): the direct fetch fails
    /// after 10 ms, a sweep fetch after 50 ms. Records each sweep fetch's
    /// rank.
    struct UnreachedFetcher(std::sync::Mutex<Vec<crate::priority::Priority>>);

    #[async_trait::async_trait]
    impl ChunkFetcher for UnreachedFetcher {
        async fn fetch(
            &self,
            _addr: [u8; 32],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            self.0.lock().unwrap().push(crate::priority::current());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Err("no BZZ peers available".into())
        }

        async fn fetch_waiting_for_credit(
            &self,
            _addr: [u8; 32],
            _credit_budget: std::time::Duration,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Err("no BZZ peers available".into())
        }
    }

    /// R1-M1 on PR #135: a head shard that misses while a look-ahead
    /// sibling's sweep is running does not take that look-ahead-ranked
    /// sweep's transient shortfall as its answer; it sweeps again at
    /// head rank. A look-ahead caller still shares a finished sweep.
    #[tokio::test(start_paused = true)]
    async fn head_shard_resweeps_after_a_look_ahead_sweep() {
        use crate::priority::{at_offset, with_read_head, Priority, ReadHead, HEAD_WINDOW};
        let addrs: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let total = addrs.len();
        let dec = RsDecoder::new(addrs, 3);
        let fetcher = UnreachedFetcher(std::sync::Mutex::new(Vec::new()));
        let read_head = ReadHead::new(0);
        let shard = |index: usize, offset: u64, delay_ms: u64| {
            let (dec, fetcher, read_head) = (&dec, &fetcher, read_head.clone());
            with_read_head(
                read_head,
                at_offset(offset, async move {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    dec.fetch_data_shard(fetcher, index, std::time::Duration::ZERO)
                        .await
                }),
            )
        };
        // All three read the sweep count before any sweep; look-ahead
        // shard 2's direct fetch misses first and starts the sweep, and
        // head shard 0 and look-ahead shard 1 miss while it runs.
        let (ahead, head, ahead2) = tokio::join!(
            shard(2, 4 * HEAD_WINDOW, 0),
            shard(0, 0, 5),
            shard(1, 4 * HEAD_WINDOW, 6),
        );
        for r in [&ahead, &head, &ahead2] {
            assert!(r.as_ref().is_err_and(|e| e.transient), "{r:?}");
        }
        let ranks = fetcher.0.lock().unwrap().clone();
        assert_eq!(
            ranks.len(),
            2 * total,
            "one look-ahead sweep, one head sweep; the second look-ahead caller shares a sweep: {ranks:?}",
        );
        assert_eq!(
            ranks.iter().filter(|r| **r == Priority::Head).count(),
            total,
            "the head shard's own sweep runs at head rank: {ranks:?}",
        );
    }

    /// Every fetch is denied: peers answer `storage: not found`.
    struct DeniedFetcher;

    #[async_trait::async_trait]
    impl ChunkFetcher for DeniedFetcher {
        async fn fetch(
            &self,
            _addr: [u8; 32],
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            Err("remote: retrieve chunk: storage: not found".into())
        }
    }

    /// Issue #79: a shortfall of denied shards is transient until the
    /// denials have held for `MISS_CONFIRM_AFTER`, then final. A denial
    /// after a longer gap starts a new episode, so an old episode can't
    /// make a later miss of the same node final on its first sweep.
    #[tokio::test(start_paused = true)]
    async fn denied_shards_are_confirmed_missing_per_episode() {
        let addrs: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let dec = RsDecoder::new(addrs, 3);
        let sweep = || dec.fetch_data_shard(&DeniedFetcher, 0, std::time::Duration::ZERO);
        let step = std::time::Duration::from_secs(4);

        // First episode, then a gap longer than the window: the next
        // miss is a new episode and starts out transient again.
        let r = sweep().await;
        assert!(r.as_ref().is_err_and(|e| e.transient), "{r:?}");
        tokio::time::sleep(MISS_CONFIRM_AFTER * 3).await;
        let started = tokio::time::Instant::now();
        let r = sweep().await;
        assert!(r.as_ref().is_err_and(|e| e.transient), "{r:?}");
        assert!(
            r.as_ref()
                .is_err_and(|e| e.detail.contains("5 denied for less than 10s")),
            "{r:?}",
        );

        // Denials that keep coming confirm the loss once they have held
        // for the window, and the outcome is then final.
        loop {
            tokio::time::sleep(step).await;
            let r = sweep().await;
            let e = r.expect_err("every shard is denied");
            if !e.transient {
                assert!(
                    started.elapsed() >= MISS_CONFIRM_AFTER,
                    "{:?}",
                    started.elapsed()
                );
                assert!(
                    started.elapsed() < MISS_CONFIRM_AFTER + step,
                    "{:?}",
                    started.elapsed()
                );
                assert!(e.detail.contains("5 confirmed missing"), "{}", e.detail);
                assert!(!e.detail.contains("not found;"), "{}", e.detail);
                break;
            }
        }
        let r = sweep().await;
        assert!(r.is_err_and(|e| !e.transient), "a final outcome is cached");
    }

    /// A shard counts as confirmed missing only when peers said so and
    /// the fetcher wasn't cut short by an overdraft-starved pool. Both of
    /// bee's miss answers count (issue #123), read from the typed error
    /// the fetcher builds from the peer's last answer.
    #[test]
    fn shard_confirmed_missing_needs_an_unstarved_not_found() {
        let exhausted = |tail: &str, pool_starved| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(crate::fetcher::exhausted(
                [0xab; 32],
                3,
                Some(crate::RetrievalError::Remote(tail.to_string())),
                pool_starved,
                1,
            ))
        };
        for tail in [
            "retrieve chunk: storage: not found",
            "retrieve chunk: no peer found",
        ] {
            assert!(
                shard_confirmed_missing(exhausted(tail, false).as_ref()),
                "{tail}"
            );
            assert!(
                !shard_confirmed_missing(exhausted(tail, true).as_ref()),
                "{tail}"
            );
        }
        assert!(!shard_confirmed_missing(
            exhausted("retrieve chunk: forbidden", false).as_ref()
        ));
        let timeout: Box<dyn std::error::Error + Send + Sync> =
            Box::new(crate::fetcher::exhausted(
                [0xab; 32],
                3,
                Some(crate::RetrievalError::Timeout(
                    std::time::Duration::from_secs(5),
                )),
                false,
                0,
            ));
        assert!(!shard_confirmed_missing(timeout.as_ref()));
        let no_peers: Box<dyn std::error::Error + Send + Sync> = "no BZZ peers available".into();
        assert!(!shard_confirmed_missing(no_peers.as_ref()));
        // Still found when wrapped, as the joiner and manifest walk do.
        let wrapped = crate::JoinError::FetchChunk {
            addr: "ab".into(),
            source: exhausted("retrieve chunk: no peer found", false),
        };
        let wrapped: Box<dyn std::error::Error + Send + Sync> =
            Box::new(crate::ManifestError::Fetch(wrapped));
        assert!(shard_confirmed_missing(wrapped.as_ref()));
    }

    /// Level tables agree with bee's documented shape: parities for a
    /// full 128-slot chunk, and the derived max data shard counts.
    #[test]
    fn parity_tables_match_bee_constants() {
        assert_eq!(get_parities(1, 128), 9);
        assert_eq!(get_parities(2, 128), 21);
        assert_eq!(get_parities(3, 128), 31);
        assert_eq!(get_parities(4, 128), 89);
        assert_eq!(max_shards(0), 128);
        assert_eq!(max_shards(1), 119);
        assert_eq!(max_shards(2), 107);
        assert_eq!(max_shards(3), 97);
        assert_eq!(max_shards(4), 39);
        // Below the smallest table row there are no parities.
        assert_eq!(get_parities(1, 0), 0);
    }

    /// Span level encoding: bee sets `level | 0x80` in the top byte and
    /// only bytes strictly greater than 128 decode as levels.
    #[test]
    fn span_level_encoding_round_trip() {
        for level in 1..=MAX_LEVEL {
            let mut span = 153_600u64.to_le_bytes();
            span[7] = level | 0x80;
            assert!(is_level_encoded(&span));
            let (l, plain) = decode_span(span);
            assert_eq!(l, level);
            assert_eq!(u64::from_le_bytes(plain), 153_600);
        }
        // Plain span, and the >128 boundary.
        let span = 4096u64.to_le_bytes();
        assert_eq!(decode_span(span), (0, span));
        let mut top128 = [0u8; 8];
        top128[7] = 128;
        assert!(!is_level_encoded(&top128));
    }

    /// `reference_count` against values derived from the `rs_files`
    /// vectors (medium-150k root: 38 data + 6 parity refs; medium-600k
    /// root: 2 + 3; paranoid-50k root: 13 + 48).
    #[test]
    fn reference_count_matches_vector_geometry() {
        assert_eq!(reference_count(153_600, 1), (38, 6));
        assert_eq!(reference_count(153_600, 2), (38, 12));
        assert_eq!(reference_count(153_600, 3), (38, 19));
        assert_eq!(reference_count(51_200, 4), (13, 48));
        assert_eq!(reference_count(614_400, 1), (2, 3));
        // Exactly one full branch.
        assert_eq!(reference_count(4096 * 119, 1), (119, 9));
    }

    /// Spans that used to overflow `count_data_shards`' unchecked
    /// arithmetic (bee#5664): above 2^61, `branch_size` wrapped to 0 and
    /// the level walk spun forever. Every level must now return a shard
    /// count within its branching, and a recovered shard carrying such a
    /// span must get a wire length (or `None`) instead of hanging.
    #[test]
    fn reference_count_saturates_on_huge_spans() {
        for level in 0..=MAX_LEVEL {
            for span in [1u64 << 62, u64::MAX] {
                let (shards, _) = reference_count(span, level);
                assert!(
                    (1..=128).contains(&shards),
                    "plain level {level} span {span}: {shards}"
                );
                assert!(
                    shards <= max_shards(level),
                    "plain level {level} span {span}: {shards}"
                );
                let (shards, _) = reference_count_enc(span, level);
                assert!(
                    (1..=64).contains(&shards),
                    "enc level {level} span {span}: {shards}"
                );
                assert!(
                    shards <= max_enc_shards(level),
                    "enc level {level} span {span}: {shards}"
                );
            }
        }
        // The recovered-shard path from the issue: a zero-padded 4104-byte
        // shard whose span reads 2^62 (`00 .. 00 40`). A level-encoded span
        // can't carry that bit (the top byte holds the level), so the plain
        // span is the one that reached the overflow.
        let mut shard = vec![0u8; SPAN_SIZE + CHUNK_SIZE];
        shard[..SPAN_SIZE].copy_from_slice(&(1u64 << 62).to_le_bytes());
        let len = recovered_wire_len(&shard).expect("2^62 span fits a chunk");
        assert!(len <= SPAN_SIZE + CHUNK_SIZE);
    }

    /// Replica derivation matches the pinned bee vector for the base
    /// address in `conformance/vectors/replicas.json` (entropy 0's SOC
    /// address; full-set equality is asserted by the conformance tests).
    #[test]
    fn replica_address_derivation() {
        let base: [u8; 32] =
            hex::decode("72c604a12ad8f5c791d98f92f6ea171ece602580e1a33a567a98c0c1b5d0b872")
                .unwrap()
                .try_into()
                .unwrap();
        let expected0: [u8; 32] =
            hex::decode("c096a4fd9a7ca8b765b4ee2b5f00857e2ae1a5c9c2dad5f1d2ba91343bc6568d")
                .unwrap()
                .try_into()
                .unwrap();
        for level in 1..=MAX_LEVEL {
            let addrs = replica_addresses(&base, level);
            assert_eq!(addrs.len(), REPLICA_COUNTS[level as usize]);
            // Entropy 0 is always accepted first, so every level's list
            // starts with its SOC address.
            assert_eq!(addrs[0], expected0);
            // Dispersal property: the first two replicas differ in the
            // top bit of their first address byte.
            assert_ne!(addrs[0][0] >> 7, addrs[1][0] >> 7);
        }
        assert_eq!(replica_addresses(&base, 0), [] as [[u8; 32]; 0]);
    }
}
