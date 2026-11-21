//! A lookup over Swarm: the head, the slices of its cover, an address's bucket in each, and
//! its entries, newest first, a page at a time (eth2swarm `docs/address-index.md`, "Client
//! lookup").
//!
//! Still free of I/O of its own: chunks come from a [`ChunkSource`] (the engine's embedded
//! `ant` node, or a test's map), and every chunk is checked here before use, with the checks of
//! [`crate::swarm`] and [`crate::records`]: a SOC against its address and its owner's
//! signature, a content-addressed chunk against its reference, each record by the decoder's
//! canonical checks. Swarm is transport only (`.claude/agent/data-sources.md`, the carve-out
//! for Swarm reads of the address index).
//!
//! What it does not do: say whether an entry is true. Every entry is a candidate; the caller
//! checks it against verified chain data. What it does say is which block range the page
//! rests on: the head's cover, minus the slices Swarm did not deliver ([`Gap`]).

use std::future::Future;

use crate::cover::{slices_to_read, units, SliceId};
use crate::lookup::{bucket_for, in_bucket, select, InBucket, InSlice};
use crate::records::{
    bucket_id, bucket_pages_records, check_head, check_page_boundary, check_slice, head_id,
    origin_id, slice_id, spill_page, BucketRecord, Entry, HeadRecord, SliceRecord, MAX_FILE,
    PAGE_SIZE, UNIT_BLOCKS,
};
use crate::swarm::{soc_address, verify_soc, FileChunk, Locate, MAX_SPAN};
use crate::Error;

/// Where chunks come from. `Ok(None)` is "not delivered": never proof that the chunk does not
/// exist. `expect_missing` marks a read whose miss is an expected answer (a head update not
/// published yet), which a source may answer faster.
pub trait ChunkSource: Sync {
    fn chunk(
        &self,
        address: [u8; 32],
        expect_missing: bool,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, SourceError>> + Send;
}

/// A source's failure, other than a miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// This one read failed (a timeout, a peer that reset the stream, no usable peers yet):
    /// the chunk was not delivered, and asking again may work.
    Transient(String),
    /// The source itself is gone (its node stopped): no read can work.
    Stopped(String),
}

/// Why a read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// A chunk the read needs was not delivered (retryable): what it was.
    Unavailable(String),
    /// A chunk was delivered and failed its checks: content its author (the importer) put
    /// there that the format does not allow. Not retryable from the same chunk.
    Invalid(Error),
    /// A read failed for now (`SourceError::Transient`): within a page, its slice is a gap.
    Transient(String),
    /// The source itself is gone (`SourceError::Stopped`).
    Source(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Unavailable(what) => write!(f, "not delivered by Swarm: {what}"),
            ReadError::Invalid(e) => write!(f, "invalid index data: {e}"),
            ReadError::Transient(e) => write!(f, "Swarm read failed for now: {e}"),
            ReadError::Source(e) => write!(f, "Swarm reader: {e}"),
        }
    }
}

impl From<SourceError> for ReadError {
    fn from(e: SourceError) -> Self {
        match e {
            SourceError::Transient(m) => ReadError::Transient(m),
            SourceError::Stopped(m) => ReadError::Source(m),
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        ReadError::Invalid(e)
    }
}

pub type ReadResult<T> = std::result::Result<T, ReadError>;

/// A block range a page could not read: a slice of the cover whose descriptor or bucket
/// Swarm did not deliver. Entries in it are missing from the answer, so the answer names it,
/// never a shorter list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub from_block: u64,
    pub to_block: u64,
}

/// Which entries a page holds: those with a role in `roles` (any of its bits), in block
/// `from_block` or later. Applied while reading, so a page is full whatever it leaves out,
/// and the reading stops at the first slice (or spill page) older than `from_block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filter {
    pub roles: u8,
    pub from_block: u64,
}

impl Default for Filter {
    fn default() -> Self {
        Filter { roles: 0xff, from_block: 0 }
    }
}

impl Filter {
    pub fn keeps(&self, e: &Entry) -> bool {
        e.roles & self.roles != 0 && e.block >= self.from_block
    }
}

/// A page of an address's entries, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// Newest first, all strictly older than the cursor the page was asked with.
    pub entries: Vec<Entry>,
    /// Where the next page starts: the oldest entry of this page, exclusive. `None` once the
    /// cover has been read to its start.
    pub next: Option<(u64, u32)>,
    /// The block range the index covers at this head: `from_block ..= to_block`.
    pub from_block: u64,
    pub to_block: u64,
    /// Slices of the cover this page reached but could not read.
    pub gaps: Vec<Gap>,
}

/// The index of one importer on one chain.
pub struct Index<'a, S> {
    src: &'a S,
    chain_id: u64,
    owner: [u8; 20],
}

impl<'a, S: ChunkSource> Index<'a, S> {
    pub fn new(src: &'a S, chain_id: u64, owner: [u8; 20]) -> Self {
        Self { src, chain_id, owner }
    }

    /// The payload of the importer's SOC `identifier`, checked, or `None` if not delivered.
    async fn soc(&self, identifier: [u8; 32], expect_missing: bool) -> ReadResult<Option<Vec<u8>>> {
        let address = soc_address(&identifier, &self.owner);
        match self.src.chunk(address, expect_missing).await {
            Err(e) => Err(e.into()),
            Ok(None) => Ok(None),
            Ok(Some(wire)) => Ok(Some(verify_soc(&wire, &address, &self.owner)?)),
        }
    }

    /// A content-addressed chunk, as delivered (checked by its decoder), or unavailable.
    async fn cac(&self, reference: [u8; 32], what: &str) -> ReadResult<Vec<u8>> {
        match self.src.chunk(reference, false).await {
            Err(e) => Err(e.into()),
            Ok(None) => Err(ReadError::Unavailable(format!("{what} chunk {}", crate::hex(&reference)))),
            Ok(Some(wire)) => Ok(wire),
        }
    }

    /// The origin: head update 0's twin, which fixes the index's start.
    pub async fn origin(&self) -> ReadResult<HeadRecord> {
        let payload = self
            .soc(origin_id(self.chain_id), false)
            .await?
            .ok_or_else(|| ReadError::Unavailable("the index's origin".to_string()))?;
        Ok(HeadRecord::decode(&payload)?)
    }

    /// Head update `n`, checked against the origin, or `None` if not delivered. `known` marks
    /// an update this reader found before: it is asked for in full, not as a likely miss.
    async fn head_update(&self, origin: &HeadRecord, n: u64, known: bool) -> ReadResult<Option<HeadRecord>> {
        let Some(payload) = self.soc(head_id(self.chain_id, n), !known).await? else {
            return Ok(None);
        };
        let head = HeadRecord::decode(&payload)?;
        check_head(&head, origin, n)?;
        Ok(Some(head))
    }

    /// The newest head update found, and its number: a gallop up from `hint` (an update known
    /// to exist, 0 for the origin), then a binary search. A withheld update makes the head
    /// found older than the newest, never wrong: every update is checked against the origin.
    pub async fn head(&self, origin: &HeadRecord, hint: u64) -> ReadResult<(u64, HeadRecord)> {
        let start = match self.head_update(origin, hint, true).await? {
            Some(h) => (hint, h),
            None => (0, origin.clone()),
        };
        let mut found = start;
        let mut step = 1u64;
        // Gallop: the first missing update above the last found one.
        let missing = loop {
            let n = found.0.saturating_add(step);
            match self.head_update(origin, n, false).await? {
                Some(h) => {
                    found = (n, h);
                    step = step.saturating_mul(2);
                }
                None => break n,
            }
        };
        // Binary search in (found, missing).
        let (mut lo, mut hi) = (found, missing);
        while hi - lo.0 > 1 {
            let mid = lo.0 + (hi - lo.0) / 2;
            match self.head_update(origin, mid, false).await? {
                Some(h) => lo = (mid, h),
                None => hi = mid,
            }
        }
        Ok(lo)
    }

    /// The descriptor of slice `s`, checked against the head's start, or `None`.
    async fn slice(&self, s: SliceId, first_unit: u64) -> ReadResult<Option<SliceRecord>> {
        let Some(payload) = self.soc(slice_id(self.chain_id, s.0, s.1), false).await? else {
            return Ok(None);
        };
        let rec = SliceRecord::decode(&payload)?;
        check_slice(&rec, s, first_unit)?;
        Ok(Some(rec))
    }

    /// The address's records in `slice`, or `None` if its bucket was not delivered.
    async fn in_slice(&self, address: &[u8; 20], slice: &SliceRecord) -> ReadResult<Option<InSlice>> {
        let k = bucket_for(address, slice);
        let id = bucket_id(self.chain_id, slice.level, slice.index, k);
        let Some(payload) = self.soc(id, false).await? else {
            return Ok(None);
        };
        let bucket = BucketRecord::decode(&payload, slice.first_block)?;
        Ok(Some(match in_bucket(address, slice, &bucket)? {
            InBucket::Records(r) => r,
            InBucket::Paged { pages_ref, pages, records } => {
                let max = (pages as u64).saturating_mul(PAGE_SIZE as u64).min(MAX_FILE as u64);
                let file = self.file(pages_ref, max, "bucket pages").await?;
                select(address, &bucket_pages_records(slice, &file, pages, records)?)
            }
        }))
    }

    /// A whole file of at most `max_span` bytes, every chunk checked through its parent.
    async fn file(&self, reference: [u8; 32], max_span: u64, what: &str) -> ReadResult<Vec<u8>> {
        let root = FileChunk::decode_root(&self.cac(reference, what).await?, &reference, max_span)?;
        let mut out = Vec::with_capacity(root.span() as usize);
        // Depth first, children in order: the leaves come out in file order.
        let mut stack = vec![root];
        while let Some(chunk) = stack.pop() {
            if let Some(leaf) = chunk.leaf() {
                out.extend_from_slice(leaf);
                continue;
            }
            let mut children = Vec::with_capacity(chunk.children());
            for k in 0..chunk.children() {
                let (r, _) = chunk.child(k).expect("k < children");
                children.push(chunk.decode_child(k, &self.cac(r, what).await?)?);
            }
            stack.extend(children.into_iter().rev());
        }
        Ok(out)
    }

    /// Leaf `leaf` of the file whose root is `root`.
    async fn leaf(&self, root: &FileChunk, leaf: u64, what: &str) -> ReadResult<Vec<u8>> {
        let mut chunk = root.clone();
        let mut leaf = leaf;
        loop {
            match chunk.locate(leaf)? {
                Locate::Here => return Ok(chunk.into_leaf().expect("a located leaf")),
                Locate::Down { child, below } => {
                    let (r, _) = chunk.child(child).expect("a located child");
                    chunk = chunk.decode_child(child, &self.cac(r, what).await?)?;
                    leaf = below;
                }
            }
        }
    }

    /// Up to `limit` entries of a spill file, newest first, strictly older than `before`.
    /// Reads the pages from the newest down; with a cursor, a binary search over the pages'
    /// first entries finds the page to start at first. Adjacent pages read are checked
    /// against each other ([`check_page_boundary`]), so what is returned is complete from its
    /// oldest entry on.
    async fn spill_newest(
        &self,
        slice: &SliceRecord,
        reference: [u8; 32],
        before: (u64, u32),
        limit: usize,
        filter: &(dyn Fn(&Entry) -> bool + Sync),
        from_block: u64,
    ) -> ReadResult<Vec<Entry>> {
        let root = FileChunk::decode_root(&self.cac(reference, "spill").await?, &reference, MAX_SPAN)?;
        let pages = root.span().div_ceil(PAGE_SIZE as u64);
        let last = pages.saturating_sub(1);
        let page = |i: u64| {
            let root = &root;
            async move {
                let bytes = self.leaf(root, i, "spill").await?;
                Ok::<_, ReadError>(spill_page(slice, &bytes, i == last)?)
            }
        };
        // The newest page whose first entry is older than `before`. The last page first: that
        // is the answer without a cursor, and for a cursor near the head.
        let (mut lo, mut hi) = (0u64, pages);
        let mut cached: Option<(u64, Vec<Entry>)> = None;
        if pages > 1 {
            let entries = page(last).await?;
            if key(&entries[0]) < before {
                (lo, hi) = (last, pages);
                cached = Some((last, entries));
            } else {
                hi = last;
            }
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            let entries = page(mid).await?;
            if key(&entries[0]) < before {
                lo = mid;
                cached = Some((mid, entries));
            } else {
                hi = mid;
            }
        }
        let mut out = Vec::new();
        let mut newer: Option<Vec<Entry>> = None;
        let mut i = lo;
        loop {
            let entries = match cached.take() {
                Some((n, e)) if n == i => e,
                _ => page(i).await?,
            };
            if let Some(newer) = &newer {
                check_page_boundary(&entries, newer)?;
            }
            out.extend(entries.iter().rev().filter(|e| key(e) < before && filter(e)));
            // Older pages hold only older entries: none of them in the range.
            if out.len() >= limit || i == 0 || entries[0].block < from_block {
                break;
            }
            newer = Some(entries);
            i -= 1;
        }
        out.truncate(limit);
        Ok(out)
    }

    /// Up to `want` entries of `address` in slice `s`, newest first, strictly older than
    /// `before`, merged by key; `None` if the descriptor or the bucket was not delivered.
    async fn slice_entries(
        &self,
        head: &HeadRecord,
        s: SliceId,
        address: &[u8; 20],
        before: (u64, u32),
        want: usize,
        plan: &crate::cover::Plan,
        filter: &Filter,
    ) -> ReadResult<Option<Vec<Entry>>> {
        let Some(slice) = self.slice(s, head.first_unit).await? else {
            return Ok(None);
        };
        let Some(found) = self.in_slice(address, &slice).await? else {
            return Ok(None);
        };
        // The roles filter applies to an entry as merged from every record of its key (an
        // inline record and a spill file can name one appearance with other roles): the
        // inline records are taken whole, a spill entry when its roles match or an inline
        // record shares its key, and the filter runs after the merge.
        let in_range = |e: &Entry| key(e) < before && plan.keep(e.block) && e.block >= filter.from_block;
        let mut here: Vec<Entry> = found.entries.iter().copied().filter(|e| in_range(e)).collect();
        let inline_keys: std::collections::HashSet<(u64, u32)> = here.iter().map(key).collect();
        let (roles, from) = (filter.roles, filter.from_block);
        let pick = move |e: &Entry| e.block >= from && (e.roles & roles != 0 || inline_keys.contains(&key(e)));
        for (reference, _count) in &found.spill_files {
            let spilled = self.spill_newest(&slice, *reference, before, want, &pick, filter.from_block).await?;
            here.extend(spilled.into_iter().filter(|e| plan.keep(e.block)));
        }
        Ok(Some(merge_by_key(here).into_iter().filter(|e| e.roles & roles != 0).collect()))
    }

    /// A page of `address`'s entries at `head`: up to `limit` that `filter` keeps, newest
    /// first, strictly older than `before` (`None`: from the head). The slices of the head's
    /// cover are read newest first until the page is full or the slices are older than the
    /// filter's first block; one that is not delivered becomes a [`Gap`].
    pub async fn page(
        &self,
        head: &HeadRecord,
        address: &[u8; 20],
        before: Option<(u64, u32)>,
        limit: usize,
        filter: &Filter,
    ) -> ReadResult<Page> {
        let plan = slices_to_read(head, None)?;
        let before = before.unwrap_or((u64::MAX, u32::MAX));
        let mut entries: Vec<Entry> = Vec::new();
        let mut gaps = Vec::new();
        let mut exhausted = true;
        for s in &plan.slices {
            let range = units(*s);
            let (first, last) = (range.start * UNIT_BLOCKS, range.end * UNIT_BLOCKS - 1);
            if (first, 0) >= before {
                continue; // nothing in it is older than the cursor
            }
            if last < filter.from_block {
                break; // this slice and every older one lie below the range
            }
            if entries.len() >= limit {
                exhausted = false;
                break;
            }
            let gap = Gap { from_block: first.max(plan.from_block), to_block: last };
            let want = limit - entries.len();
            // A chunk of this slice Swarm did not deliver (its descriptor, its bucket, a
            // pages or spill chunk) makes the slice a gap; invalid data stays an error.
            let here = match self.slice_entries(head, *s, address, before, want + 1, &plan, filter).await {
                Ok(Some(here)) => here,
                // Not delivered, or not delivered for now: a gap, never the whole page.
                Ok(None) | Err(ReadError::Unavailable(_)) | Err(ReadError::Transient(_)) => {
                    gaps.push(gap);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let mut here = here;
            if here.len() > want {
                here.truncate(want);
                exhausted = false;
            }
            entries.extend(here);
        }
        if entries.len() < limit {
            exhausted = true;
        }
        let next = if exhausted { None } else { entries.last().map(key) };
        Ok(Page { entries, next, from_block: plan.from_block, to_block: plan.to_block, gaps })
    }
}

fn key(e: &Entry) -> (u64, u32) {
    (e.block, e.slot)
}

/// Newest first, one entry per `(block, slot)`: two records of one fingerprint (an inline
/// one and a spill file, or two spill files) can name one appearance with other roles. They
/// are merged, so a page cut, which is by key, never splits one.
fn merge_by_key(mut entries: Vec<Entry>) -> Vec<Entry> {
    entries.sort_unstable_by(|a, b| key(b).cmp(&key(a)));
    let mut out: Vec<Entry> = Vec::with_capacity(entries.len());
    for e in entries {
        match out.last_mut() {
            Some(last) if key(last) == key(&e) => last.roles |= e.roles,
            _ => out.push(e),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::file_tree;
    use std::collections::HashMap;

    /// Content-addressed chunks only: what a file read needs.
    struct Map(HashMap<[u8; 32], Vec<u8>>);

    impl ChunkSource for Map {
        fn chunk(
            &self,
            address: [u8; 32],
            _expect_missing: bool,
        ) -> impl Future<Output = Result<Option<Vec<u8>>, SourceError>> + Send {
            let got = self.0.get(&address).cloned();
            async move { Ok(got) }
        }
    }

    /// A spill file of `n` entries in one slice, as Swarm serves it, and the slice.
    fn spill(n: u32) -> (Map, [u8; 32], SliceRecord, Vec<Entry>) {
        let entries: Vec<Entry> = (0..n).map(|i| Entry { block: 64_000 + (i as u64 / 3), slot: 1 + i % 3, roles: 1 }).collect();
        let data = crate::records::spill_file(&entries);
        let (map, root) = files(&data);
        let slice = SliceRecord {
            level: 10,
            index: 0,
            first_block: 0,
            last_block_hash: [0; 32],
            bucket_count: 1,
            addresses: 1,
            appearances: n as u64,
            buckets_root: [0; 32],
            roles: 1,
        };
        (map, root, slice, entries)
    }

    #[test]
    fn a_spill_file_of_many_pages_reads_newest_first_from_any_cursor() {
        let (map, root, slice, entries) = spill(4000);
        let pages = crate::records::spill_file(&entries).len().div_ceil(PAGE_SIZE);
        assert!(pages >= 3, "{pages} pages");
        let index = Index::new(&map, 1, [0; 20]);
        let newest: Vec<Entry> = entries.iter().rev().copied().collect();
        // No cursor: the newest entries.
        let got = block_on(index.spill_newest(&slice, root, (u64::MAX, u32::MAX), 10, &|_: &Entry| true, 0)).unwrap();
        assert_eq!(got, newest[..10]);
        // A cursor anywhere, and on either side of a page boundary: the entries below it.
        let firsts: Vec<usize> = {
            // The index (in `entries`) of each page's first entry.
            let mut out = vec![0];
            let mut seen = 0;
            for p in 0..pages {
                let start = p * PAGE_SIZE;
                let leaf = &crate::records::spill_file(&entries)[start..(start + PAGE_SIZE).min(crate::records::spill_file(&entries).len())];
                seen += spill_page(&slice, leaf, p + 1 == pages).unwrap().len();
                out.push(seen);
            }
            out
        };
        for &i in firsts.iter().take(pages) {
            for at in [i.saturating_sub(1), i, i + 1] {
                if at >= entries.len() {
                    continue;
                }
                let before = key(&entries[at]);
                let want: Vec<Entry> = entries[..at].iter().rev().take(25).copied().collect();
                let got = block_on(index.spill_newest(&slice, root, before, 25, &|_: &Entry| true, 0)).unwrap();
                assert_eq!(got, want, "cursor at entry {at}");
            }
        }
        // Everything, from the newest down.
        let all = block_on(index.spill_newest(&slice, root, (u64::MAX, u32::MAX), 10_000, &|_: &Entry| true, 0)).unwrap();
        assert_eq!(all, newest);
    }

    #[test]
    fn a_withheld_middle_page_is_not_delivered_not_invalid() {
        let (map, root, slice, entries) = spill(4000);
        let data = crate::records::spill_file(&entries);
        // The chunks of the middle page's leaf withheld.
        let mid = data.len().div_ceil(PAGE_SIZE) / 2;
        let leaf = &data[mid * PAGE_SIZE..(mid + 1) * PAGE_SIZE];
        let leaf_ref = crate::swarm::file_reference(leaf);
        let mut partial = map.0.clone();
        partial.remove(&leaf_ref);
        let partial = Map(partial);
        let index = Index::new(&partial, 1, [0; 20]);
        let r = block_on(index.spill_newest(&slice, root, (u64::MAX, u32::MAX), 10_000, &|_: &Entry| true, 0));
        assert!(matches!(r, Err(ReadError::Unavailable(_))), "{r:?}");
        // The newest pages above it still read.
        assert!(block_on(index.spill_newest(&slice, root, (u64::MAX, u32::MAX), 10, &|_: &Entry| true, 0)).is_ok());
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        // A tiny executor: every future here is ready at once (the map answers inline).
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn files(data: &[u8]) -> (Map, [u8; 32]) {
        let chunks = file_tree(data);
        let root = chunks.last().expect("a root").0;
        (Map(chunks.into_iter().collect()), root)
    }

    #[test]
    fn one_key_with_two_roles_is_one_entry() {
        let e = |block, slot, roles| Entry { block, slot, roles };
        let merged = merge_by_key(vec![e(100, 5, 0x01), e(101, 1, 0x04), e(100, 5, 0x02), e(99, 9, 0x10)]);
        assert_eq!(merged, vec![e(101, 1, 0x04), e(100, 5, 0x03), e(99, 9, 0x10)]);
    }

    #[test]
    fn a_file_reads_back_whole_and_by_leaf() {
        // Three levels of tree: more than 128 leaves.
        let data: Vec<u8> = (0..(130 * 4096 + 17)).map(|i| (i % 251) as u8).collect();
        let (map, root) = files(&data);
        let index = Index::new(&map, 1, [0; 20]);
        assert_eq!(block_on(index.file(root, MAX_FILE as u64, "test")).unwrap(), data);
        let wire = block_on(index.cac(root, "test")).unwrap();
        let root_chunk = FileChunk::decode_root(&wire, &root, MAX_SPAN).unwrap();
        for leaf in [0u64, 1, 127, 128, 129, 130] {
            let got = block_on(index.leaf(&root_chunk, leaf, "test")).unwrap();
            let start = leaf as usize * 4096;
            assert_eq!(got, data[start..(start + 4096).min(data.len())], "leaf {leaf}");
        }
        // A file above the bound is refused before any child is read.
        assert!(matches!(block_on(index.file(root, 4096, "test")), Err(ReadError::Invalid(_))));
        // A missing chunk is unavailable, not invalid.
        let mut partial = map.0.clone();
        partial.retain(|k, _| *k == root);
        let partial = Map(partial);
        let index = Index::new(&partial, 1, [0; 20]);
        assert!(matches!(block_on(index.file(root, MAX_FILE as u64, "test")), Err(ReadError::Unavailable(_))));
    }

    #[test]
    fn soc_reads_refuse_a_chunk_of_another_owner() {
        // Any bytes under the SOC address of owner [1; 20] are refused: they are not a SOC
        // that hashes to that address and is signed by that owner.
        let index_owner = [1u8; 20];
        let id = origin_id(1);
        let address = soc_address(&id, &index_owner);
        let map = Map(HashMap::from([(address, vec![0u8; 200])]));
        let index = Index::new(&map, 1, index_owner);
        assert!(matches!(block_on(index.origin()), Err(ReadError::Invalid(_))));
        let empty = Map(HashMap::new());
        let index = Index::new(&empty, 1, index_owner);
        assert!(matches!(block_on(index.origin()), Err(ReadError::Unavailable(_))));
    }
}
