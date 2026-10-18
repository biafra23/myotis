//! The CL→EL execution anchor (EL-A7), twin of the Java
//! `consensus.BeaconSyncState` — the SOLE trust hand-off from the beacon light
//! client to the execution layer (docs/reimplementation/07, *The CL→EL anchor
//! (`ExecAnchor`)*; README §3; docs/verification.md).
//!
//! Holds the beacon-verified execution anchor: the finalized execution
//! `{block_number, block_hash, state_root, slot}`, the optimistic (attested)
//! equivalent, and a bounded window of BLS-attested `(slot, state_root)` pairs
//! for the `stateRootMatch` fast path. It is fed by the CL sync loop
//! (`sync.rs`, wired in EL-A7b) and read by the verified query ladder
//! ([`super::verify`]). Every field here is BLS-sync-committee-verified before
//! it lands — it is the only thing the EL trusts.
//!
//! # Gloas: the hash first, the header after
//!
//! From Gloas (EIP-7732) a light-client header proves only an execution BLOCK
//! HASH — no state root, number or timestamp is committed anywhere on the
//! consensus side any more. The CL loop records such a hash as PENDING
//! ([`ExecAnchor::note_finalized_hash`] / [`ExecAnchor::note_optimistic_hash`]);
//! the EL peer pool fetches the header by that hash and offers it
//! ([`ExecAnchor::resolve_header`]), and the anchor adopts it only when the
//! keccak of the header's own RLP IS the pending hash. The chain of custody is
//! sync-committee signature → beacon header → body root → block hash → keccak →
//! header fields: one hop longer, still nothing taken on a peer's word. Until a
//! pending finality resolves, the anchor keeps serving the last resolved one —
//! still final, only older — and does not call it current.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::el::eth::messages::VerifiedHeader;

/// Window cap (twin of `BeaconSyncState.MAX_KNOWN_ROOTS`), matching
/// `MAX_HEADER_CHAIN_GAP` so the fast-path window and the header-chain bound
/// cover the same span.
pub const MAX_KNOWN_ROOTS: usize = 8192;

/// How many recent optimistic heads [`ExecAnchor::optimistic_root_at`]
/// remembers by block number — about as many blocks as execution clients keep
/// state for (geth's 128 diff layers), so a remembered head's state is still
/// one peers serve: 25.6 minutes of mainnet heads, 10.7 of Gnosis.
pub const RECENT_HEADS: usize = 128;

/// One of [`Inner::recent_heads`]: an optimistic head as the update that made
/// it the head attested it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecentHead {
    number: u64,
    hash: [u8; 32],
    /// The head's parent block hash, proven with it (the light-client payload
    /// header carries it; a resolved Gloas header is the one that hashes to the
    /// proven block hash): the link [`ExecAnchor::optimistic_root_at`] follows
    /// to tell an ancestor of the current head from a replaced sibling.
    parent_hash: [u8; 32],
    state_root: [u8; 32],
}

/// One of the recent heads at a number, as [`ExecAnchor::recent_head_at`]
/// finds it: the block that was the head there, its attested state root, and
/// whether the ring itself links it to the current head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecentHeadAt {
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    /// Every head between it and the current one is in the ring and each is
    /// the proven parent of the one above it: the block IS an ancestor of the
    /// current head, canonical with it. False past a break — a head the light
    /// client skipped (a gap whose link cannot be checked here), or a head a
    /// sibling chain replaced — where only a header window anchored at the
    /// current head can say whether this block is still canonical.
    pub linked: bool,
}

/// A BLS-attested `(slot, state_root)` pair in the fast-path window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlottedStateRoot {
    pub slot: u64,
    pub state_root: [u8; 32],
    pub bls_verified: bool,
}

/// The finalized execution anchor: the block number, its beacon-verified
/// execution state root, AND its block hash — read together so a query never
/// pairs fields from different finalized payloads. The `block_hash` is THE
/// trust anchor for the header-chain walk: it is the keccak of the whole
/// finalized header, so it pins that header completely (a peer can copy the
/// public `state_root` into a fabricated header, but cannot forge one whose
/// keccak equals `block_hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedExecution {
    /// The beacon slot whose finality update carried this execution block —
    /// the `matchedBeaconSlot` of a proof verified against `state_root`.
    pub slot: u64,
    pub block_number: u64,
    pub state_root: [u8; 32],
    pub block_hash: [u8; 32],
    /// The block's own timestamp (unix seconds), proven with it: the
    /// light-client payload header carries it, and a resolved Gloas header is
    /// the one that hashes to `block_hash`. 0 when unknown.
    pub timestamp: u64,
}

/// The optimistic execution head as [`ExecAnchor::optimistic_head_state`]
/// reads it (#531).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadState {
    pub number: u64,
    /// The head's BLS-attested state root: a read proven against it is a read
    /// of the head's own state, whatever block number a peer labelled it with.
    pub state_root: [u8; 32],
    /// The block's own timestamp (unix seconds), proven with it.
    pub timestamp: u64,
    /// When this node learned the block advancing the head (monotonic), or
    /// `None`: the first head after a start, or one that did not advance.
    pub adopted: Option<std::time::Instant>,
}

#[derive(Default)]
struct Inner {
    finalized_slot: u64,
    execution_state_root: Option<[u8; 32]>,
    execution_block_number: u64,
    execution_block_hash: Option<[u8; 32]>,
    /// The finalized execution block's own timestamp (unix seconds), proven
    /// with it, as for the optimistic head below. 0 until known.
    execution_timestamp: u64,
    optimistic_slot: u64,
    optimistic_block_number: u64,
    optimistic_block_hash: Option<[u8; 32]>,
    optimistic_state_root: Option<[u8; 32]>,
    /// The optimistic execution block's own timestamp (unix seconds), proven
    /// with it: the light-client payload header carries it, and a resolved
    /// Gloas header is the one that hashes to the proven block hash. 0 until
    /// a head lands.
    optimistic_timestamp: u64,
    /// When this node learned the current optimistic block, if it was seen to
    /// ADVANCE past an earlier head live (monotonic; see [`set_optimistic`]):
    /// a head's age by our own clock, which a wall clock set wrong cannot
    /// fake. `None` for the first head after a start — a restored snapshot's,
    /// fed before any live update — and for one at or below the head before.
    optimistic_adopted: Option<std::time::Instant>,
    /// When the pending optimistic hash was noted: a Gloas head counts from
    /// when the light client proved it, not from when its header resolved.
    pending_optimistic_noted: Option<std::time::Instant>,
    known_roots: VecDeque<SlottedStateRoot>,
    /// The last [`RECENT_HEADS`] optimistic heads, oldest first — each one
    /// BLS-attested when it was the head. Kept for `eth_getProof`, which may
    /// serve only a root attested for exactly the block it names
    /// ([`ExecAnchor::optimistic_root_at`]), and for resolving a block hash a
    /// client pins a read to ([`ExecAnchor::attested_block_of`], #641).
    recent_heads: VecDeque<RecentHead>,
    finality_current: bool,
    /// Gloas: a finalized execution block hash the light client proved at this
    /// beacon slot whose header has not been resolved yet. Never older than the
    /// resolved finality; cleared when resolved or superseded.
    pending_finalized: Option<(u64, [u8; 32])>,
    /// The optimistic twin of `pending_finalized`.
    pending_optimistic: Option<(u64, [u8; 32])>,
}

/// Shared, mutable execution anchor. Cloneable handle over one `Mutex` — the
/// CL loop writes, the EL query path reads (both off their own threads).
pub struct ExecAnchor {
    inner: Mutex<Inner>,
    /// Wakes the pool's resolver when a hash becomes pending (`notify_one`
    /// stores a permit, so a hash noted between two waits is not missed).
    pending_changed: tokio::sync::Notify,
}

impl Default for ExecAnchor {
    fn default() -> Self {
        ExecAnchor {
            inner: Mutex::new(Inner::default()),
            pending_changed: tokio::sync::Notify::new(),
        }
    }
}

impl ExecAnchor {
    pub fn new() -> ExecAnchor {
        ExecAnchor::default()
    }

    /// Record a finalized update (on every beacon finality step), with the
    /// execution block's timestamp from the same proven payload header. Also
    /// appends the finalized `(slot, state_root)` to the fast-path window as
    /// BLS-verified.
    pub fn update_finalized(
        &self,
        finalized_slot: u64,
        execution_state_root: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
        execution_timestamp: u64,
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        set_finalized(
            &mut inner,
            finalized_slot,
            execution_state_root,
            execution_block_number,
            execution_block_hash,
            execution_timestamp,
        );
    }

    /// Record the optimistic (attested) execution head (~1-2 slots behind wall
    /// clock, vs ~2 epochs for finalized), with its parent block hash and its
    /// execution timestamp, all from the same proven payload header. Also
    /// appends to the window.
    pub fn update_optimistic(
        &self,
        optimistic_slot: u64,
        optimistic_block_number: u64,
        optimistic_block_hash: [u8; 32],
        optimistic_parent_hash: [u8; 32],
        optimistic_state_root: [u8; 32],
        optimistic_timestamp: u64,
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        set_optimistic(
            &mut inner,
            optimistic_slot,
            optimistic_block_number,
            optimistic_block_hash,
            optimistic_parent_hash,
            optimistic_state_root,
            optimistic_timestamp,
            Some(std::time::Instant::now()),
        );
    }

    /// Gloas: the light client proved `block_hash` as the finalized execution
    /// block at beacon slot `slot`. Nothing about that block but its hash is
    /// known yet, so it waits for [`Self::resolve_header`]. The same hash as the
    /// resolved finality (payloads empty or withheld since) only moves its slot
    /// forward; a finality older than the one resolved or pending is ignored.
    pub fn note_finalized_hash(&self, slot: u64, block_hash: [u8; 32]) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        if inner.execution_block_hash == Some(block_hash) {
            if slot > inner.finalized_slot {
                inner.finalized_slot = slot;
                if let Some(root) = inner.execution_state_root {
                    push_root(&mut inner.known_roots, slot, root, true);
                }
            }
            // This IS the newest finality — unless a newer one is already pending.
            if inner.pending_finalized.is_some_and(|(s, _)| s <= slot) {
                inner.pending_finalized = None;
            }
            return;
        }
        if slot < inner.finalized_slot || inner.pending_finalized.is_some_and(|(s, _)| s > slot) {
            return;
        }
        if inner.pending_finalized.map(|(_, h)| h) != Some(block_hash) {
            self.pending_changed.notify_one();
        }
        inner.pending_finalized = Some((slot, block_hash));
    }

    /// The optimistic twin of [`Self::note_finalized_hash`].
    pub fn note_optimistic_hash(&self, slot: u64, block_hash: [u8; 32]) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        if inner.optimistic_block_hash == Some(block_hash) {
            if slot > inner.optimistic_slot {
                inner.optimistic_slot = slot;
                if let Some(root) = inner.optimistic_state_root {
                    push_root(&mut inner.known_roots, slot, root, true);
                }
            }
            if inner.pending_optimistic.is_some_and(|(s, _)| s <= slot) {
                inner.pending_optimistic = None;
            }
            return;
        }
        if slot < inner.optimistic_slot || inner.pending_optimistic.is_some_and(|(s, _)| s > slot) {
            return;
        }
        if inner.pending_optimistic.map(|(_, h)| h) != Some(block_hash) {
            self.pending_changed.notify_one();
            inner.pending_optimistic_noted = Some(std::time::Instant::now());
        }
        inner.pending_optimistic = Some((slot, block_hash));
    }

    /// The block hashes waiting for their header — the pending finality first
    /// (what finalized reads anchor on), then the pending optimistic head (what
    /// the header-chain walk anchors on).
    pub fn pending_hashes(&self) -> Vec<[u8; 32]> {
        let inner = self.inner.lock().expect("anchor mutex");
        let mut out = Vec::with_capacity(2);
        out.extend(inner.pending_finalized.map(|(_, h)| h));
        if let Some((_, h)) = inner.pending_optimistic {
            if !out.contains(&h) {
                out.push(h);
            }
        }
        out
    }

    /// Resolves when a hash has become pending since the last wait (or at once,
    /// if one did while nobody was waiting).
    pub async fn pending_changed(&self) {
        self.pending_changed.notified().await;
    }

    /// Offer an execution header fetched by one of the pending hashes. Adopted
    /// only if the keccak of ITS RAW RLP is a pending hash — recomputed here,
    /// not taken from the decoder's `hash` field alone — and then for every
    /// pending slot that hash names (the finalized and optimistic heads can be
    /// the same block). Its number and state root become the anchor's, and the
    /// root joins the `stateRootMatch` window as verified: the hash was proven
    /// under a sync-committee signature, and only one header hashes to it.
    /// Returns whether anything was adopted; a header nobody asked for, or for a
    /// head since superseded, changes nothing.
    pub fn resolve_header(&self, header: &VerifiedHeader) -> bool {
        let hash = myotis_core::keccak::keccak256(&header.raw_rlp);
        if hash != header.hash {
            return false;
        }
        let (number, root, timestamp) = (header.header.number, header.header.state_root, header.header.timestamp);
        let parent = header.header.parent_hash;
        let mut inner = self.inner.lock().expect("anchor mutex");
        let mut adopted = false;
        if let Some((slot, pending)) = inner.pending_finalized {
            if pending == hash {
                set_finalized(&mut inner, slot, root, number, hash, timestamp);
                inner.pending_finalized = None;
                adopted = true;
            }
        }
        if let Some((slot, pending)) = inner.pending_optimistic {
            if pending == hash {
                let learned = inner.pending_optimistic_noted;
                set_optimistic(&mut inner, slot, number, hash, parent, root, timestamp, learned);
                inner.pending_optimistic = None;
                adopted = true;
            }
        }
        adopted
    }

    /// Record a standalone BLS-attested `(slot, state_root)` into the window
    /// (the catch-up path records 40-80 per invocation).
    pub fn record_state_root(&self, slot: u64, state_root: [u8; 32], bls_verified: bool) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        push_root(&mut inner.known_roots, slot, state_root, bls_verified);
    }

    /// SYNCED once a finalized execution state root has landed — DERIVED, not a
    /// separate flag (twin of `BeaconSyncState.isSynced() == executionStateRoot
    /// != null`). This keeps `is_synced()` and `finalized_execution()` from ever
    /// disagreeing, which the verify ladder relies on.
    pub fn is_synced(&self) -> bool {
        self.inner
            .lock()
            .expect("anchor mutex")
            .execution_state_root
            .is_some()
    }

    /// The finalized execution `(block_number, state_root, block_hash)` read
    /// atomically. `None` until the first finalized update lands (root AND hash
    /// are set together by [`Self::update_finalized`]).
    pub fn finalized_execution(&self) -> Option<FinalizedExecution> {
        finalized_of(&self.inner.lock().expect("anchor mutex"))
    }

    /// [`Self::finalized_execution`] and [`Self::finality_is_current`] read
    /// under ONE lock. A caller that weighs one against the other must not
    /// pair a finality with the currency of a later update: the CL loop sets
    /// the finality first and the flag after, so two separate reads can see an
    /// old catch-up finality flagged current. One read sees at worst a new
    /// finality with the previous flag.
    pub fn finalized_execution_with_currency(&self) -> (Option<FinalizedExecution>, bool) {
        let inner = self.inner.lock().expect("anchor mutex");
        (finalized_of(&inner), is_current(&inner))
    }

    pub fn finalized_slot(&self) -> u64 {
        self.inner.lock().expect("anchor mutex").finalized_slot
    }

    /// The beacon slot of the optimistic head's own block — the attested
    /// header's `beacon.slot`, never the light client's signature slot one or
    /// more above it — so a read anchored at the current head reports it as
    /// its `matchedBeaconSlot` (#658). Trails the light client's head while a
    /// Gloas head's header is still being resolved, as
    /// [`Self::finalized_slot`] does. 0 until a head lands.
    pub fn optimistic_slot(&self) -> u64 {
        self.inner.lock().expect("anchor mutex").optimistic_slot
    }

    /// Record whether the beacon light client considers its finality CURRENT —
    /// its `SYNCED` gate: committee period current and the finalized header
    /// within a few epochs of the wall clock. Set by the CL loop on every
    /// status publish.
    pub fn set_finality_current(&self, current: bool) {
        self.inner.lock().expect("anchor mutex").finality_current = current;
    }

    /// Whether [`Self::finalized_execution`] is the network's finality give or
    /// take a few epochs, rather than a value restored from a snapshot or left
    /// behind by a light client still catching up. False until the CL loop says
    /// otherwise — and while a newer finality is pending resolution (Gloas): the
    /// finality served then is the light client's previous one. Not the same
    /// question as [`Self::is_synced`], which only asks whether ANY finalized
    /// root has landed.
    pub fn finality_is_current(&self) -> bool {
        is_current(&self.inner.lock().expect("anchor mutex"))
    }

    /// The optimistic head block hash, for anchoring a header-chain walk at the
    /// beacon-attested block (`None` until an optimistic update lands).
    pub fn optimistic_block_hash(&self) -> Option<[u8; 32]> {
        self.inner.lock().expect("anchor mutex").optimistic_block_hash
    }

    pub fn optimistic_block_number(&self) -> u64 {
        self.inner.lock().expect("anchor mutex").optimistic_block_number
    }

    /// The optimistic head `(block_number, block_hash)` read under ONE lock,
    /// for anchoring a header-chain walk — a number from one update paired
    /// with the hash of the next would make a peer's correct header fail
    /// verification. `None` until an optimistic update with a nonzero block
    /// number lands.
    pub fn optimistic_head(&self) -> Option<(u64, [u8; 32])> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .optimistic_block_hash
            .filter(|_| inner.optimistic_block_number > 0)
            .map(|hash| (inner.optimistic_block_number, hash))
    }

    /// [`Self::optimistic_head`] with the beacon slot that attested it,
    /// `(block_number, block_hash, slot)` under ONE lock — the anchor a
    /// verified read's header-chain walk ends at (`verify::ladder_precheck`),
    /// which reports the slot as the read's `matchedBeaconSlot`.
    pub fn optimistic_anchor(&self) -> Option<(u64, [u8; 32], u64)> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .optimistic_block_hash
            .filter(|_| inner.optimistic_block_number > 0)
            .map(|hash| (inner.optimistic_block_number, hash, inner.optimistic_slot))
    }

    /// The state root of block `number` if one of the last [`RECENT_HEADS`]
    /// optimistic heads this anchor held is the CANONICAL block at that number
    /// — the current head, or an ancestor of it — attested for exactly that
    /// block, by the update that made it the head.
    ///
    /// Canonical is checked, not assumed. The ring keeps a head until a later
    /// head at or below its number replaces it, so a head replaced by a sibling
    /// chain WITHOUT the head stepping back (11A, then 12B built on an 11B the
    /// light client never reported) would otherwise stay and answer for 11 with
    /// 11A's root — a proof the caller's check against block 11's stateRoot
    /// rejects. So the ring is walked down from the current head through each
    /// head's proven parent hash, and only a head that walk reaches counts; it
    /// stops at the first break: a sibling (the parent hash is another block's)
    /// or a gap (a head the light client skipped, whose link cannot be
    /// checked), and nothing below a break is answered by number. Such a block
    /// can still be named by its HASH ([`Self::attested_block_of`]), whose
    /// root is that block's own whatever chain it is on, and a caller that can
    /// fetch headers confirms it against the current head instead
    /// ([`Self::recent_head_at`]).
    pub fn optimistic_root_at(&self, number: u64) -> Option<[u8; 32]> {
        self.recent_head_at(number).filter(|h| h.linked).map(|h| h.state_root)
    }

    /// The recent head at `number`, linked or not ([`RecentHeadAt::linked`]):
    /// for a caller that can confirm an unlinked one itself, against a header
    /// window anchored at the current head, rather than refuse it — a gap in
    /// the ring is a skipped light-client update far more often than a reorg.
    pub fn recent_head_at(&self, number: u64) -> Option<RecentHeadAt> {
        let inner = self.inner.lock().expect("anchor mutex");
        recent_head_at(&inner.recent_heads, number)
    }

    /// The block `hash` names as this anchor holds it attested — its number
    /// and its BLS-attested state root, read under ONE lock — if it is the
    /// beacon-finalized block or one of the last [`RECENT_HEADS`] optimistic
    /// heads (the current one included). `None` for any other hash: one this
    /// anchor never held, one older than its window, or one it stepped back
    /// from (a reorged-out head is forgotten, as for
    /// [`Self::optimistic_root_at`]), so a hash is never answered with another
    /// block's root. Attested is not CANONICAL: a head replaced by a sibling
    /// chain without the head stepping back (the next head builds on a block
    /// the light client never reported) stays until it ages out — its root is
    /// still that block's own, which is all a proof at its hash needs, but a
    /// caller asking which block is canonical must not take it from here.
    ///
    /// No I/O: the hash is the update's own, proven under a sync-committee
    /// signature, so a client pinning a read to the head it was just handed
    /// (EIP-1898, #641) is placed at once, and a proof at that hash is pinned
    /// to that block's root in the same read — no window in which a reorg
    /// can swap the block between resolving the hash and proving at it.
    pub fn attested_block_of(&self, hash: &[u8; 32]) -> Option<(u64, [u8; 32])> {
        let inner = self.inner.lock().expect("anchor mutex");
        if let Some(h) = inner.recent_heads.iter().rev().find(|h| &h.hash == hash) {
            return Some((h.number, h.state_root));
        }
        finalized_of(&inner)
            .filter(|fin| &fin.block_hash == hash)
            .map(|fin| (fin.block_number, fin.state_root))
    }

    /// The optimistic execution `(block_number, state_root, timestamp)` read
    /// atomically — the CURRENT beacon-attested head state, at most a couple of
    /// slots old, and the block's own timestamp proven with it (0 while
    /// unknown). `None` until the first optimistic update lands. This is the
    /// root snap queries should prefer: it is BLS-verified and recent enough
    /// that every honest synced peer still retains it in its snap serve window
    /// (unlike a peer's handshake-time head, which post-merge never refreshes).
    pub fn optimistic_execution(&self) -> Option<(u64, [u8; 32], u64)> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .optimistic_state_root
            .map(|root| (inner.optimistic_block_number, root, inner.optimistic_timestamp))
    }

    /// The optimistic execution head as a send is judged by (#531), read
    /// under ONE lock: its number, its BLS-attested state root, its own
    /// timestamp and when this node learned it advancing. `None` until a head
    /// with its timestamp lands.
    pub fn optimistic_head_state(&self) -> Option<HeadState> {
        let inner = self.inner.lock().expect("anchor mutex");
        match inner.optimistic_state_root {
            Some(state_root) if inner.optimistic_timestamp > 0 => Some(HeadState {
                number: inner.optimistic_block_number,
                state_root,
                timestamp: inner.optimistic_timestamp,
                adopted: inner.optimistic_adopted,
            }),
            _ => None,
        }
    }

    /// The `stateRootMatch` fast-path lookup: is `state_root` a root the beacon
    /// client already recorded? Searches NEWEST-first (twin of
    /// `findStateRoot`'s `descendingIterator`) so the freshest/best match wins.
    pub fn find_state_root(&self, state_root: &[u8; 32]) -> Option<SlottedStateRoot> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .known_roots
            .iter()
            .rev()
            .find(|r| &r.state_root == state_root)
            .cloned()
    }

    pub fn known_root_count(&self) -> usize {
        self.inner.lock().expect("anchor mutex").known_roots.len()
    }
}

/// Currency as [`ExecAnchor::finality_is_current`] defines it.
fn is_current(inner: &Inner) -> bool {
    inner.finality_current && inner.pending_finalized.is_none()
}

fn set_finalized(
    inner: &mut Inner,
    slot: u64,
    state_root: [u8; 32],
    number: u64,
    hash: [u8; 32],
    timestamp: u64,
) {
    inner.finalized_slot = slot;
    inner.execution_state_root = Some(state_root);
    inner.execution_block_number = number;
    inner.execution_block_hash = Some(hash);
    inner.execution_timestamp = timestamp;
    push_root(&mut inner.known_roots, slot, state_root, true);
}

#[allow(clippy::too_many_arguments)]
fn set_optimistic(
    inner: &mut Inner,
    slot: u64,
    number: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    state_root: [u8; 32],
    timestamp: u64,
    learned: Option<std::time::Instant>,
) {
    // Adopted (#531) only when the block changes — the light-client loop
    // re-offers the same head on every poll, and that is no newer a head —
    // and only when it ADVANCES past a head this anchor already had: the
    // first head after a start is a restored snapshot's (fed before any live
    // update), and a step back is no fresher. It counts from when it was
    // `learned`, which for a Gloas head is when its hash was proven.
    if inner.optimistic_block_hash != Some(hash) {
        let advanced = inner.optimistic_block_hash.is_some() && number > inner.optimistic_block_number;
        inner.optimistic_adopted = if advanced { learned } else { None };
    }
    inner.optimistic_slot = slot;
    inner.optimistic_block_number = number;
    inner.optimistic_block_hash = Some(hash);
    inner.optimistic_state_root = Some(state_root);
    inner.optimistic_timestamp = timestamp;
    push_root(&mut inner.known_roots, slot, state_root, true);
    remember_head(&mut inner.recent_heads, RecentHead { number, hash, parent_hash, state_root });
}

/// [`ExecAnchor::recent_head_at`]'s walk: from the newest head in `heads` (the
/// current one) down to `number`, noting whether every step is a proven parent
/// link. The ring's numbers strictly ascend ([`remember_head`] drops every
/// head at or above a new one), so each step is the next head down; one that
/// is not the parent of the head above it — a sibling, or a gap — unlinks it
/// and everything below it.
fn recent_head_at(heads: &VecDeque<RecentHead>, number: u64) -> Option<RecentHeadAt> {
    let mut walk = heads.iter().rev();
    let mut child = walk.next()?;
    let mut linked = true;
    loop {
        if child.number == number {
            return Some(RecentHeadAt { hash: child.hash, state_root: child.state_root, linked });
        }
        let head = walk.next().filter(|h| h.number >= number)?;
        linked &= head.number + 1 == child.number && head.hash == child.parent_hash;
        child = head;
    }
}

/// Append a head to [`Inner::recent_heads`] (a re-offered head is no new
/// entry), first dropping every remembered head at or above its number: a
/// head that does not advance replaces what was remembered there, so a
/// reorged-out block is never served by number. Then cap to [`RECENT_HEADS`].
fn remember_head(heads: &mut VecDeque<RecentHead>, head: RecentHead) {
    if heads.back() == Some(&head) {
        return;
    }
    while heads.back().is_some_and(|h| h.number >= head.number) {
        heads.pop_back();
    }
    heads.push_back(head);
    while heads.len() > RECENT_HEADS {
        heads.pop_front();
    }
}

/// The finalized execution anchor held in `inner`, if root AND hash have landed.
fn finalized_of(inner: &Inner) -> Option<FinalizedExecution> {
    match (inner.execution_state_root, inner.execution_block_hash) {
        (Some(state_root), Some(block_hash)) => Some(FinalizedExecution {
            slot: inner.finalized_slot,
            block_number: inner.execution_block_number,
            state_root,
            block_hash,
            timestamp: inner.execution_timestamp,
        }),
        _ => None,
    }
}

/// Append `(slot, state_root)`, then cap the window to `MAX_KNOWN_ROOTS`
/// (oldest dropped). Dedup keys on `(slot, state_root)` and only ever UPGRADES
/// `bls_verified` (unverified → verified), never downgrades — exact twin of
/// `BeaconSyncState.recordStateRoot` (a root at two slots stays two entries).
fn push_root(roots: &mut VecDeque<SlottedStateRoot>, slot: u64, state_root: [u8; 32], bls_verified: bool) {
    if let Some(pos) = roots
        .iter()
        .position(|r| r.slot == slot && r.state_root == state_root)
    {
        if bls_verified && !roots[pos].bls_verified {
            roots.remove(pos); // re-add as verified below
        } else {
            return; // already present with same or better verification
        }
    }
    roots.push_back(SlottedStateRoot {
        slot,
        state_root,
        bls_verified,
    });
    while roots.len() > MAX_KNOWN_ROOTS {
        roots.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(n: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = n;
        r
    }

    /// The hash of head `n` on a chain of linked heads (`tag` tells chains apart).
    fn head_hash(tag: u8, n: u64) -> [u8; 32] {
        let mut h = root(tag);
        h[1..9].copy_from_slice(&n.to_be_bytes());
        h
    }

    /// Head `n` of chain `tag`, built on head `n - 1` of the same chain.
    fn linked(anchor: &ExecAnchor, tag: u8, n: u64, state_root: [u8; 32]) {
        anchor.update_optimistic(n, n, head_hash(tag, n), head_hash(tag, n - 1), state_root, 0);
    }

    #[test]
    fn recent_heads_are_remembered_by_number_and_forgotten_on_a_step_back() {
        let anchor = ExecAnchor::new();
        assert_eq!(anchor.optimistic_root_at(10), None);
        for n in 10..=12u64 {
            linked(&anchor, 0xa0, n, root(0x80 + n as u8));
            // Re-offered on every poll: still one entry.
            linked(&anchor, 0xa0, n, root(0x80 + n as u8));
        }
        assert_eq!(anchor.optimistic_root_at(11), Some(root(0x8b)));
        assert_eq!(anchor.optimistic_root_at(12), Some(root(0x8c)));
        // A reorg at 11 (built on 10): the replaced 11 and the 12 built on it
        // are forgotten, and 10 is still the new head's parent.
        anchor.update_optimistic(13, 11, root(0x21), head_hash(0xa0, 10), root(0x91), 0);
        assert_eq!(anchor.optimistic_root_at(11), Some(root(0x91)));
        assert_eq!(anchor.optimistic_root_at(12), None);
        assert_eq!(anchor.optimistic_root_at(10), Some(root(0x8a)));
        // The window is capped, oldest first out.
        anchor.update_optimistic(99, 99, head_hash(0xb0, 99), root(0x21), root(1), 0);
        for n in 100..100 + RECENT_HEADS as u64 {
            linked(&anchor, 0xb0, n, root(2));
        }
        assert_eq!(anchor.optimistic_root_at(10), None);
        assert_eq!(anchor.optimistic_root_at(99), None);
        assert_eq!(anchor.optimistic_root_at(100), Some(root(2)));
    }

    #[test]
    fn a_head_replaced_without_a_step_back_is_never_answered_by_number() {
        let anchor = ExecAnchor::new();
        for n in 10..=11u64 {
            linked(&anchor, 0xa0, n, root(0x80 + n as u8));
        }
        // 12B arrives built on an 11B the light client never reported: 11A
        // stays in the ring (nothing at or above 12 to drop), but it is not
        // 12B's parent, so neither it nor anything below it answers by number.
        anchor.update_optimistic(12, 12, head_hash(0xbb, 12), head_hash(0xbb, 11), root(0x9c), 0);
        assert_eq!(anchor.optimistic_root_at(12), Some(root(0x9c)));
        assert_eq!(anchor.optimistic_root_at(11), None);
        assert_eq!(anchor.optimistic_root_at(10), None);
        assert!(anchor.recent_head_at(11).is_some_and(|h| !h.linked && h.hash == head_hash(0xa0, 11)));
        // By hash, 11A is still its own attested block, with its own root.
        assert_eq!(anchor.attested_block_of(&head_hash(0xa0, 11)), Some((11, root(0x8b))));
        // Once 11B is reported (a head stepping back to it), the chain links
        // again from 11B up — and 12B, at its number, was dropped with it.
        anchor.update_optimistic(13, 11, head_hash(0xbb, 11), head_hash(0xa0, 10), root(0x9b), 0);
        assert_eq!(anchor.optimistic_root_at(11), Some(root(0x9b)));
        assert_eq!(anchor.optimistic_root_at(10), Some(root(0x8a)));
    }

    #[test]
    fn a_gap_in_the_heads_stops_the_walk_below_it() {
        let anchor = ExecAnchor::new();
        for n in 10..=11u64 {
            linked(&anchor, 0xa0, n, root(0x80 + n as u8));
        }
        // 12 was never reported: 13's parent link cannot be checked against 11.
        linked(&anchor, 0xa0, 13, root(0x8d));
        linked(&anchor, 0xa0, 14, root(0x8e));
        assert_eq!(anchor.optimistic_root_at(14), Some(root(0x8e)));
        assert_eq!(anchor.optimistic_root_at(13), Some(root(0x8d)));
        assert_eq!(anchor.optimistic_root_at(12), None);
        assert_eq!(anchor.optimistic_root_at(11), None);
        // A number above the head, or no head at all: nothing.
        assert_eq!(anchor.optimistic_root_at(15), None);
        assert_eq!(ExecAnchor::new().optimistic_root_at(14), None);
        // Below the gap the heads are still there, marked unlinked, for a
        // caller that can confirm them against a header window.
        let unlinked = anchor.recent_head_at(11).expect("11 is in the ring");
        assert_eq!((unlinked.hash, unlinked.state_root, unlinked.linked), (head_hash(0xa0, 11), root(0x8b), false));
        assert!(anchor.recent_head_at(13).is_some_and(|h| h.linked));
        assert_eq!(anchor.recent_head_at(12), None);
    }

    #[test]
    fn attested_blocks_are_placed_by_hash_and_forgotten_with_their_head() {
        let anchor = ExecAnchor::new();
        assert_eq!(anchor.attested_block_of(&root(11)), None);
        for n in 10..=12u64 {
            anchor.update_optimistic(n, n, root(n as u8), [0; 32], root(0x80 + n as u8), 0);
        }
        // The current head and a recent one: number and attested root together.
        assert_eq!(anchor.attested_block_of(&root(12)), Some((12, root(0x8c))));
        assert_eq!(anchor.attested_block_of(&root(11)), Some((11, root(0x8b))));
        // A reorg at 11: the replaced 11 and the 12 built on it are no longer
        // placed; the block that replaced 11 is, with its own root.
        anchor.update_optimistic(13, 11, root(0x21), [0; 32], root(0x91), 0);
        assert_eq!(anchor.attested_block_of(&root(11)), None);
        assert_eq!(anchor.attested_block_of(&root(12)), None);
        assert_eq!(anchor.attested_block_of(&root(0x21)), Some((11, root(0x91))));
        assert_eq!(anchor.attested_block_of(&root(10)), Some((10, root(0x8a))));
        // The finalized block is placed too, with its own root.
        anchor.update_finalized(9, root(0x70), 5, root(0x55), 0);
        assert_eq!(anchor.attested_block_of(&root(0x55)), Some((5, root(0x70))));
        // Out of the window: forgotten, oldest first.
        for n in 100..100 + RECENT_HEADS as u64 {
            let mut h = root(0xa0);
            h[1..9].copy_from_slice(&n.to_be_bytes());
            anchor.update_optimistic(n, n, h, [0; 32], root(2), 0);
        }
        assert_eq!(anchor.attested_block_of(&root(10)), None);
        assert_eq!(anchor.attested_block_of(&root(0x55)), Some((5, root(0x70))));
    }

    #[test]
    fn optimistic_execution_none_until_first_update() {
        let anchor = ExecAnchor::new();
        // Before the first optimistic update the accessor must be None — the
        // snap-root selection falls back to the peer handshake head then.
        assert_eq!(anchor.optimistic_execution(), None);
    }

    #[test]
    fn finalized_and_optimistic_updates() {
        let anchor = ExecAnchor::new();
        assert_eq!(anchor.finalized_execution(), None);
        assert!(!anchor.is_synced());

        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1), 1_699_999_000);
        assert!(anchor.is_synced()); // derived: a finalized exec root landed
        let fin = anchor.finalized_execution().unwrap();
        assert_eq!(fin.block_number, 21_000_000);
        assert_eq!(fin.state_root, root(1));
        // The finalized block's own proven timestamp travels with it.
        assert_eq!(fin.timestamp, 1_699_999_000);
        assert_eq!(anchor.finalized_slot(), 100);

        assert_eq!(anchor.optimistic_head(), None); // no optimistic update yet
        assert_eq!(anchor.optimistic_head_state(), None);
        anchor.update_optimistic(102, 21_000_005, root(0xf2), [0; 32], root(2), 1_700_000_000);
        // The head's root and age come with it, under the same lock (#531).
        let head = anchor.optimistic_head_state().expect("a head");
        assert_eq!((head.number, head.state_root, head.timestamp), (21_000_005, root(2), 1_700_000_000));
        assert_eq!(anchor.optimistic_block_hash(), Some(root(0xf2)));
        assert_eq!(anchor.optimistic_block_number(), 21_000_005);
        assert_eq!(anchor.optimistic_head(), Some((21_000_005, root(0xf2))));
        // The atomic (number, root) pair snap queries prefer (issue #355).
        assert_eq!(anchor.optimistic_execution(), Some((21_000_005, root(2), 1_700_000_000)));

        // Both roots are in the fast-path window.
        assert!(anchor.find_state_root(&root(1)).is_some());
        assert_eq!(anchor.find_state_root(&root(2)).unwrap().slot, 102);
        assert!(anchor.find_state_root(&root(9)).is_none());
    }

    #[test]
    fn finality_is_not_current_until_the_light_client_says_so() {
        let anchor = ExecAnchor::new();
        assert!(!anchor.finality_is_current());
        // A finalized root landing (e.g. a restored snapshot) is not currency.
        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1), 0);
        assert!(anchor.is_synced());
        assert!(!anchor.finality_is_current());
        anchor.set_finality_current(true);
        assert!(anchor.finality_is_current());
        // ...and it can fall behind again (a doze, a starved pool).
        anchor.set_finality_current(false);
        assert!(!anchor.finality_is_current());
    }

    #[test]
    fn finality_and_its_currency_read_as_one_pair() {
        let anchor = ExecAnchor::new();
        assert_eq!(anchor.finalized_execution_with_currency(), (None, false));
        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1), 0);
        anchor.set_finality_current(true);
        let (fin, current) = anchor.finalized_execution_with_currency();
        assert_eq!(fin, anchor.finalized_execution());
        assert_eq!(fin.map(|f| f.block_number), Some(21_000_000));
        assert!(current);
    }

    #[test]
    fn window_dedup_is_slot_root_keyed_and_upgrade_only() {
        let anchor = ExecAnchor::new();
        // Same root at TWO slots → two entries (Java keeps both).
        anchor.record_state_root(1, root(5), true);
        anchor.record_state_root(2, root(5), true);
        assert_eq!(anchor.known_root_count(), 2);
        // find_state_root searches newest-first → the slot-2 entry.
        assert_eq!(anchor.find_state_root(&root(5)).unwrap().slot, 2);

        // Same (slot, root): unverified first, then verified → UPGRADE in place.
        anchor.record_state_root(3, root(6), false);
        anchor.record_state_root(3, root(6), true);
        assert_eq!(anchor.known_root_count(), 3);
        assert!(anchor.find_state_root(&root(6)).unwrap().bls_verified);
        // A subsequent unverified record must NOT downgrade it.
        anchor.record_state_root(3, root(6), false);
        assert!(anchor.find_state_root(&root(6)).unwrap().bls_verified);
        assert_eq!(anchor.known_root_count(), 3);
    }

    #[test]
    fn only_a_head_seen_to_advance_counts_as_adopted() {
        // #531: the first head after a start is a restored snapshot's (fed
        // before any live update), so it carries no adoption time.
        let anchor = ExecAnchor::new();
        anchor.update_optimistic(102, 21_000_005, root(0xf2), [0; 32], root(2), 1_700_000_000);
        assert_eq!(anchor.optimistic_head_state().map(|h| h.adopted), Some(None));
        // A live head past it is adopted.
        anchor.update_optimistic(103, 21_000_006, root(0xf3), [0; 32], root(3), 1_700_000_012);
        let first = anchor.optimistic_head_state().and_then(|h| h.adopted).expect("adopted");
        // The light-client loop offers its head on every poll; the same block
        // again is no newer a head, so a stalled light client's head ages.
        std::thread::sleep(std::time::Duration::from_millis(5));
        anchor.update_optimistic(104, 21_000_006, root(0xf3), [0; 32], root(3), 1_700_000_012);
        assert_eq!(anchor.optimistic_head_state().and_then(|h| h.adopted), Some(first));
        // The next block is adopted anew; a step back (a reorg to an older
        // block, an older restore) is not adopted at all.
        anchor.update_optimistic(105, 21_000_007, root(0xf4), [0; 32], root(4), 1_700_000_024);
        assert!(anchor.optimistic_head_state().and_then(|h| h.adopted).is_some_and(|at| at > first));
        anchor.update_optimistic(106, 21_000_006, root(0xf5), [0; 32], root(5), 1_700_000_012);
        assert_eq!(anchor.optimistic_head_state().map(|h| h.adopted), Some(None));
    }

    #[test]
    fn a_gloas_head_counts_from_when_its_hash_was_proven() {
        // A header can resolve long after the light client proved its hash:
        // the head is as old as the proof, not the fetch (PR #537 review).
        let anchor = ExecAnchor::new();
        let (a, b) = (header(1, root(1)), header(2, root(2)));
        anchor.note_optimistic_hash(10, a.hash);
        assert!(anchor.resolve_header(&a));
        let before_note = std::time::Instant::now();
        anchor.note_optimistic_hash(20, b.hash);
        let after_note = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(anchor.resolve_header(&b));
        let adopted = anchor.optimistic_head_state().and_then(|h| h.adopted).expect("advanced");
        assert!(adopted >= before_note && adopted <= after_note, "stamped at the note, not the resolution");
    }

    /// A genuine header (raw RLP, keccak hash) with this number and state
    /// root, timestamped 12 s per block from 1 700 000 000.
    fn header(number: u64, state_root: [u8; 32]) -> VerifiedHeader {
        let (_, genesis) = crate::el::served::mainnet_genesis().expect("embedded genesis");
        let mut h = myotis_core::header::BlockHeader::decode(&genesis).expect("genesis decodes");
        h.number = number;
        h.state_root = state_root;
        h.timestamp = 1_700_000_000 + 12 * number;
        let raw_rlp = h.encode();
        VerifiedHeader {
            hash: myotis_core::keccak::keccak256(&raw_rlp),
            raw_rlp,
            header: h,
        }
    }

    #[test]
    fn a_gloas_finality_waits_for_its_header_then_adopts_it() {
        let anchor = ExecAnchor::new();
        let h = header(21_000_000, root(1));
        anchor.note_finalized_hash(100, h.hash);
        assert_eq!(anchor.pending_hashes(), vec![h.hash]);
        assert!(!anchor.is_synced(), "a hash alone is not an anchor");
        assert_eq!(anchor.finalized_execution(), None);

        assert!(anchor.resolve_header(&h));
        let fin = anchor.finalized_execution().expect("resolved");
        assert_eq!(
            (fin.slot, fin.block_number, fin.state_root, fin.block_hash),
            (100, 21_000_000, root(1), h.hash)
        );
        assert!(anchor.pending_hashes().is_empty());
        assert!(anchor
            .find_state_root(&root(1))
            .is_some_and(|r| r.bls_verified && r.slot == 100));
        assert!(!anchor.resolve_header(&h), "nothing pending any more");
    }

    #[test]
    fn a_header_is_adopted_only_under_its_own_hash() {
        let anchor = ExecAnchor::new();
        let wanted = header(21_000_000, root(1));
        anchor.note_finalized_hash(100, wanted.hash);
        // A different block entirely.
        assert!(!anchor.resolve_header(&header(21_000_000, root(2))));
        // The pending hash CLAIMED over another header's bytes: the recomputed
        // keccak disagrees with the claim, so it is refused before any lookup.
        let mut forged = header(21_000_000, root(2));
        forged.hash = wanted.hash;
        assert!(!anchor.resolve_header(&forged));
        assert_eq!(anchor.finalized_execution(), None);
        assert_eq!(anchor.pending_hashes(), vec![wanted.hash]);
    }

    #[test]
    fn a_newer_finality_supersedes_and_an_older_one_is_ignored() {
        let anchor = ExecAnchor::new();
        let (a, b) = (header(1, root(1)), header(2, root(2)));
        anchor.note_finalized_hash(10, a.hash);
        anchor.note_finalized_hash(20, b.hash);
        assert_eq!(anchor.pending_hashes(), vec![b.hash]);
        anchor.note_finalized_hash(15, a.hash);
        assert_eq!(
            anchor.pending_hashes(),
            vec![b.hash],
            "an older finality never replaces a newer one"
        );
        assert!(!anchor.resolve_header(&a), "superseded");
        assert!(anchor.resolve_header(&b));
        assert_eq!(anchor.finalized_slot(), 20);
        anchor.note_finalized_hash(10, a.hash);
        assert!(
            anchor.pending_hashes().is_empty(),
            "nothing older than the resolved finality"
        );
    }

    #[test]
    fn the_same_block_under_a_newer_slot_needs_no_fetch() {
        // Payloads empty or withheld for a while: consecutive finalized beacon
        // blocks name the same parent payload.
        let anchor = ExecAnchor::new();
        let h = header(7, root(7));
        anchor.note_finalized_hash(100, h.hash);
        assert!(anchor.resolve_header(&h));
        anchor.note_finalized_hash(132, h.hash);
        assert!(anchor.pending_hashes().is_empty());
        assert_eq!(
            anchor
                .finalized_execution()
                .map(|f| (f.slot, f.block_number)),
            Some((132, 7))
        );
    }

    /// Re-noting the resolved block at a slot below a NEWER pending finality
    /// must not clear it (the store only moves forward, so this is defensive).
    #[test]
    fn re_noting_the_resolved_block_keeps_a_newer_pending_one() {
        let anchor = ExecAnchor::new();
        let (a, b) = (header(1, root(1)), header(2, root(2)));
        anchor.note_finalized_hash(10, a.hash);
        assert!(anchor.resolve_header(&a));
        anchor.note_finalized_hash(20, b.hash);
        anchor.note_finalized_hash(15, a.hash);
        assert_eq!(anchor.pending_hashes(), vec![b.hash]);
        // ...while a re-note at or past the pending slot does supersede it.
        anchor.note_finalized_hash(20, a.hash);
        assert!(anchor.pending_hashes().is_empty());

        anchor.note_optimistic_hash(10, a.hash);
        assert!(anchor.resolve_header(&a));
        anchor.note_optimistic_hash(20, b.hash);
        anchor.note_optimistic_hash(15, a.hash);
        assert_eq!(anchor.pending_hashes(), vec![b.hash]);
    }

    #[test]
    fn a_pending_finality_is_not_current() {
        let anchor = ExecAnchor::new();
        let (a, b) = (header(1, root(1)), header(2, root(2)));
        anchor.note_finalized_hash(10, a.hash);
        assert!(anchor.resolve_header(&a));
        anchor.set_finality_current(true);
        assert!(anchor.finality_is_current());
        // The light client moved on; the EL still serves the previous finality.
        anchor.note_finalized_hash(42, b.hash);
        assert!(!anchor.finality_is_current());
        let (fin, current) = anchor.finalized_execution_with_currency();
        assert_eq!((fin.map(|f| f.block_number), current), (Some(1), false));
        assert!(anchor.resolve_header(&b));
        assert!(anchor.finality_is_current());
    }

    #[test]
    fn one_header_resolves_both_heads_when_they_name_the_same_block() {
        let anchor = ExecAnchor::new();
        let h = header(9, root(9));
        anchor.note_finalized_hash(64, h.hash);
        anchor.note_optimistic_hash(65, h.hash);
        assert_eq!(anchor.pending_hashes(), vec![h.hash], "fetched once");
        assert_eq!(anchor.optimistic_slot(), 0, "a pending head is not the anchor's yet");
        assert!(anchor.resolve_header(&h));
        assert_eq!(anchor.optimistic_head(), Some((9, h.hash)));
        // The slot a head-anchored read reports beside its matchedBeaconSlot
        // is the one the walk's anchor carries (#658).
        assert_eq!(anchor.optimistic_slot(), 65);
        assert_eq!(anchor.optimistic_anchor().map(|(_, _, slot)| slot), Some(65));
        assert_eq!(anchor.optimistic_execution().map(|(n, r, _)| (n, r)), Some((9, root(9))));
        // A Gloas head's age is its resolved header's own timestamp (#531).
        assert_eq!(
            anchor.optimistic_head_state().map(|h| (h.number, h.state_root, h.timestamp)),
            Some((9, root(9), 1_700_000_108))
        );
        // The finalized twin carries the same resolved header's timestamp.
        assert_eq!(
            anchor.finalized_execution().map(|f| (f.block_number, f.timestamp)),
            Some((9, 1_700_000_108))
        );
    }

    #[tokio::test]
    async fn a_new_pending_hash_wakes_the_resolver() {
        let anchor = std::sync::Arc::new(ExecAnchor::new());
        let waiter = {
            let anchor = std::sync::Arc::clone(&anchor);
            tokio::spawn(async move { anchor.pending_changed().await })
        };
        anchor.note_optimistic_hash(5, header(5, root(5)).hash);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("woken")
            .unwrap();
        // Noted while nobody waited: the stored permit wakes the next wait.
        anchor.note_optimistic_hash(6, header(6, root(6)).hash);
        tokio::time::timeout(std::time::Duration::from_secs(5), anchor.pending_changed())
            .await
            .expect("permit kept");
    }

    #[test]
    fn window_caps_at_max() {
        let anchor = ExecAnchor::new();
        for i in 0..(MAX_KNOWN_ROOTS as u64 + 10) {
            let mut r = [0u8; 32];
            r[..8].copy_from_slice(&i.to_be_bytes());
            anchor.record_state_root(i, r, true);
        }
        assert_eq!(anchor.known_root_count(), MAX_KNOWN_ROOTS);
    }
}
