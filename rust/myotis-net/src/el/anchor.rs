//! The CL→EL execution anchor (EL-A7), twin of the Java
//! `consensus.BeaconSyncState` — the SOLE trust hand-off from the beacon light
//! client to the execution layer (docs/reimplementation/04 §3, README §3).
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
}

#[derive(Default)]
struct Inner {
    finalized_slot: u64,
    execution_state_root: Option<[u8; 32]>,
    execution_block_number: u64,
    execution_block_hash: Option<[u8; 32]>,
    optimistic_slot: u64,
    optimistic_block_number: u64,
    optimistic_block_hash: Option<[u8; 32]>,
    optimistic_state_root: Option<[u8; 32]>,
    known_roots: VecDeque<SlottedStateRoot>,
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

    /// Record a finalized update (on every beacon finality step). Also appends
    /// the finalized `(slot, state_root)` to the fast-path window as
    /// BLS-verified.
    pub fn update_finalized(
        &self,
        finalized_slot: u64,
        execution_state_root: [u8; 32],
        execution_block_number: u64,
        execution_block_hash: [u8; 32],
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        set_finalized(
            &mut inner,
            finalized_slot,
            execution_state_root,
            execution_block_number,
            execution_block_hash,
        );
    }

    /// Record the optimistic (attested) execution head (~1-2 slots behind wall
    /// clock, vs ~2 epochs for finalized). Also appends to the window.
    pub fn update_optimistic(
        &self,
        optimistic_slot: u64,
        optimistic_block_number: u64,
        optimistic_block_hash: [u8; 32],
        optimistic_state_root: [u8; 32],
    ) {
        let mut inner = self.inner.lock().expect("anchor mutex");
        set_optimistic(
            &mut inner,
            optimistic_slot,
            optimistic_block_number,
            optimistic_block_hash,
            optimistic_state_root,
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
            inner.pending_finalized = None; // this IS the newest finality
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
            inner.pending_optimistic = None;
            return;
        }
        if slot < inner.optimistic_slot || inner.pending_optimistic.is_some_and(|(s, _)| s > slot) {
            return;
        }
        if inner.pending_optimistic.map(|(_, h)| h) != Some(block_hash) {
            self.pending_changed.notify_one();
        }
        inner.pending_optimistic = Some((slot, block_hash));
    }

    /// The block hashes waiting for their header — the pending finality first
    /// (what the header-chain walk anchors on), then the pending optimistic head.
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
        let (number, root) = (header.header.number, header.header.state_root);
        let mut inner = self.inner.lock().expect("anchor mutex");
        let mut adopted = false;
        if let Some((slot, pending)) = inner.pending_finalized {
            if pending == hash {
                set_finalized(&mut inner, slot, root, number, hash);
                inner.pending_finalized = None;
                adopted = true;
            }
        }
        if let Some((slot, pending)) = inner.pending_optimistic {
            if pending == hash {
                set_optimistic(&mut inner, slot, number, hash, root);
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

    /// The optimistic execution `(block_number, state_root)` read atomically —
    /// the CURRENT beacon-attested head state, at most a couple of slots old.
    /// `None` until the first optimistic update lands. This is the root snap
    /// queries should prefer: it is BLS-verified and recent enough that every
    /// honest synced peer still retains it in its snap serve window (unlike a
    /// peer's handshake-time head, which post-merge never refreshes).
    pub fn optimistic_execution(&self) -> Option<(u64, [u8; 32])> {
        let inner = self.inner.lock().expect("anchor mutex");
        inner
            .optimistic_state_root
            .map(|root| (inner.optimistic_block_number, root))
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

fn set_finalized(inner: &mut Inner, slot: u64, state_root: [u8; 32], number: u64, hash: [u8; 32]) {
    inner.finalized_slot = slot;
    inner.execution_state_root = Some(state_root);
    inner.execution_block_number = number;
    inner.execution_block_hash = Some(hash);
    push_root(&mut inner.known_roots, slot, state_root, true);
}

fn set_optimistic(inner: &mut Inner, slot: u64, number: u64, hash: [u8; 32], state_root: [u8; 32]) {
    inner.optimistic_slot = slot;
    inner.optimistic_block_number = number;
    inner.optimistic_block_hash = Some(hash);
    inner.optimistic_state_root = Some(state_root);
    push_root(&mut inner.known_roots, slot, state_root, true);
}

/// The finalized execution anchor held in `inner`, if root AND hash have landed.
fn finalized_of(inner: &Inner) -> Option<FinalizedExecution> {
    match (inner.execution_state_root, inner.execution_block_hash) {
        (Some(state_root), Some(block_hash)) => Some(FinalizedExecution {
            slot: inner.finalized_slot,
            block_number: inner.execution_block_number,
            state_root,
            block_hash,
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

        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1));
        assert!(anchor.is_synced()); // derived: a finalized exec root landed
        let fin = anchor.finalized_execution().unwrap();
        assert_eq!(fin.block_number, 21_000_000);
        assert_eq!(fin.state_root, root(1));
        assert_eq!(anchor.finalized_slot(), 100);

        assert_eq!(anchor.optimistic_head(), None); // no optimistic update yet
        anchor.update_optimistic(102, 21_000_005, root(0xf2), root(2));
        assert_eq!(anchor.optimistic_block_hash(), Some(root(0xf2)));
        assert_eq!(anchor.optimistic_block_number(), 21_000_005);
        assert_eq!(anchor.optimistic_head(), Some((21_000_005, root(0xf2))));
        // The atomic (number, root) pair snap queries prefer (issue #355).
        assert_eq!(anchor.optimistic_execution(), Some((21_000_005, root(2))));

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
        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1));
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
        anchor.update_finalized(100, root(1), 21_000_000, root(0xf1));
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

    /// A genuine header (raw RLP, keccak hash) with this number and state root.
    fn header(number: u64, state_root: [u8; 32]) -> VerifiedHeader {
        let (_, genesis) = crate::el::served::mainnet_genesis().expect("embedded genesis");
        let mut h = myotis_core::header::BlockHeader::decode(&genesis).expect("genesis decodes");
        h.number = number;
        h.state_root = state_root;
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
        assert!(anchor.resolve_header(&h));
        assert_eq!(anchor.optimistic_head(), Some((9, h.hash)));
        assert_eq!(anchor.optimistic_execution(), Some((9, root(9))));
        assert_eq!(
            anchor.finalized_execution().map(|f| f.block_number),
            Some(9)
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
