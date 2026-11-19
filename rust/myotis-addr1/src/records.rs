//! Identifiers and records of the addr1 index (eth2swarm `docs/address-index.md`,
//! "Identifiers" and "Record formats").
//!
//! Decoders are strict: they reject what an encoder following the format would not produce,
//! as far as one record or page shows it (non-shortest varints, unsorted entries or records,
//! empty roles, an inline record that should have been spilled, an inline bucket that should
//! have been paged, non-zero padding). Whether a spill or pages file is canonical shows only
//! when the whole file is read, which [`spill_entries`] and [`bucket_pages_records`] do.

use myotis_core::keccak::keccak256;

use crate::{ensure, fail, Result};

/// Blocks per unit (`U`).
pub const UNIT_BLOCKS: u64 = 64;
/// Top level (`L_max`).
pub const L_MAX: u8 = 16;
/// Inline entry bytes of one address above which it is spilled to its own file.
pub const SPILL_INLINE_MAX: usize = 256;
/// Bucket payload limit (one chunk) and size of spill and bucket pages.
pub const PAGE_SIZE: usize = 4096;
/// Units the format allows (spill pages store block numbers as u32).
pub const MAX_UNITS: u64 = (1 << 32) / UNIT_BLOCKS;
/// Largest spill or pages file a client reads whole. A spill file above it (a busy address
/// in a top-level slice) is read page by page ([`SpillPageCheck`]); a pages file never is
/// that large (a bucket is bounded), and is refused.
pub const MAX_FILE: usize = 256 << 20;

const MAGIC: &[u8; 3] = b"E2S";
const VERSION: u8 = 1;
const KIND_SLICE: u8 = 4;
const KIND_BUCKET: u8 = 5;
const KIND_HEAD: u8 = 6;

/// First block of slice `(level, index)` on the grid from genesis.
pub fn first_block(level: u8, index: u32) -> u64 {
    ((index as u64) << level) * UNIT_BLOCKS
}

/// Last block of slice `(level, index)`.
pub fn last_block(level: u8, index: u32) -> u64 {
    ((index as u64 + 1) << level) * UNIT_BLOCKS - 1
}

/// First block slice `(level, index)` holds in an index from unit `first_unit` (only for a
/// slice that ends after it).
pub fn held_first_block(level: u8, index: u32, first_unit: u64) -> u64 {
    first_block(level, index).max(first_unit * UNIT_BLOCKS)
}

pub fn slice_id(chain_id: u64, level: u8, index: u32) -> [u8; 32] {
    keccak256(format!("eth:{chain_id}:addr1:slice:{level}:{index}").as_bytes())
}

pub fn bucket_id(chain_id: u64, level: u8, index: u32, bucket: u32) -> [u8; 32] {
    keccak256(format!("eth:{chain_id}:addr1:bucket:{level}:{index}:{bucket}").as_bytes())
}

pub fn head_topic(chain_id: u64) -> [u8; 32] {
    keccak256(format!("eth:{chain_id}:addr1:head").as_bytes())
}

/// Head feed update `n` (Bee's sequence-feed identifier scheme).
pub fn head_id(chain_id: u64, n: u64) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(&head_topic(chain_id));
    buf[32..].copy_from_slice(&n.to_be_bytes());
    keccak256(&buf)
}

pub fn origin_id(chain_id: u64) -> [u8; 32] {
    keccak256(format!("eth:{chain_id}:addr1:origin").as_bytes())
}

/// Unsigned LEB128, shortest form.
pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub(crate) fn varint_len(v: u64) -> usize {
    (64 - (v | 1).leading_zeros() as usize).div_ceil(7)
}

/// Reads a shortest-form varint; anything longer, or wider than 64 bits, is an error.
pub(crate) fn get_varint(buf: &mut &[u8]) -> Result<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let (&b, rest) = buf.split_first().ok_or_else(|| fail!("varint truncated"))?;
        *buf = rest;
        ensure!(i < 9 || b <= 1, "varint wider than 64 bits");
        v |= ((b & 0x7f) as u64) << (7 * i);
        if b & 0x80 == 0 {
            ensure!(i == 0 || b != 0, "varint not in shortest form");
            return Ok(v);
        }
    }
    Err(fail!("varint wider than 64 bits"))
}

/// One appearance of an address: the block, the slot (`0` for the block itself,
/// `txIndex + 1` for a transaction) and its role bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    pub block: u64,
    pub slot: u32,
    pub roles: u8,
}

/// The role bits (eth2swarm `docs/address-index.md`, Appearances).
pub mod role {
    pub const FROM: u8 = 0x01;
    pub const TO: u8 = 0x02;
    pub const EMITTER: u8 = 0x04;
    pub const TOPIC: u8 = 0x08;
    pub const WORD: u8 = 0x10;
    pub const TRACE: u8 = 0x20;
    pub const BLOCK: u8 = 0x40;
    pub const AUTH: u8 = 0x80;

    /// Names of the role bits set in `roles`, comma-separated.
    pub fn names(roles: u8) -> String {
        [
            (FROM, "from"),
            (TO, "to"),
            (EMITTER, "emitter"),
            (TOPIC, "topic"),
            (WORD, "word"),
            (TRACE, "trace"),
            (BLOCK, "block"),
            (AUTH, "auth"),
        ]
        .iter()
        .filter(|(bit, _)| roles & bit != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(",")
    }
}

pub(crate) fn entries_len(entries: &[Entry], base: u64) -> usize {
    let mut prev = base;
    entries
        .iter()
        .map(|e| {
            let n = varint_len(e.block - prev) + varint_len(e.slot as u64) + 1;
            prev = e.block;
            n
        })
        .sum()
}

fn put_entries(out: &mut Vec<u8>, entries: &[Entry], base: u64) {
    let mut prev = base;
    for e in entries {
        put_varint(out, e.block - prev);
        put_varint(out, e.slot as u64);
        out.push(e.roles);
        prev = e.block;
    }
}

/// Reads `n` entries: strictly ascending by (block, slot), non-empty roles, at or before
/// `last` (they cannot lie before `base`, deltas being unsigned).
fn get_entries(buf: &mut &[u8], n: u64, base: u64, last: u64) -> Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::with_capacity(n.min(4096) as usize);
    let mut prev = base;
    for _ in 0..n {
        let block = prev
            .checked_add(get_varint(buf)?)
            .ok_or_else(|| fail!("entry block overflows"))?;
        let slot =
            u32::try_from(get_varint(buf)?).map_err(|_| fail!("entry slot wider than 32 bits"))?;
        let (&roles, rest) = buf.split_first().ok_or_else(|| fail!("entry truncated"))?;
        *buf = rest;
        ensure!(roles != 0, "entry without roles");
        ensure!(
            block <= last,
            "entry in block {block}, after the slice's last block {last}"
        );
        let e = Entry { block, slot, roles };
        if let Some(l) = out.last() {
            ensure!(
                (l.block, l.slot) < (e.block, e.slot),
                "entries not strictly ascending"
            );
        }
        out.push(e);
        prev = block;
    }
    Ok(out)
}

/// The entries of an address: inline, or the reference of its spill file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entries {
    Inline(Vec<Entry>),
    Spilled { count: u64, spill_ref: [u8; 32] },
}

/// One address in a bucket. The address itself is not stored, only its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    pub fp: [u8; 8],
    pub entries: Entries,
}

impl AddressRecord {
    fn encode(&self, out: &mut Vec<u8>, base: u64) {
        out.extend_from_slice(&self.fp);
        match &self.entries {
            Entries::Inline(e) => {
                put_varint(out, (e.len() as u64) << 1);
                put_entries(out, e, base);
            }
            Entries::Spilled { count, spill_ref } => {
                put_varint(out, (count << 1) | 1);
                out.extend_from_slice(spill_ref);
            }
        }
    }

    /// Decodes a record of a slice whose blocks are `base..=last`.
    fn decode(buf: &mut &[u8], base: u64, last: u64) -> Result<Self> {
        ensure!(buf.len() >= 8, "address record truncated");
        let fp: [u8; 8] = buf[..8].try_into().expect("8 bytes");
        *buf = &buf[8..];
        let tag = get_varint(buf)?;
        let n = tag >> 1;
        let entries = if tag & 1 == 1 {
            ensure!(n > 0, "spilled address record without entries");
            ensure!(buf.len() >= 32, "spill reference truncated");
            let spill_ref: [u8; 32] = buf[..32].try_into().expect("32 bytes");
            *buf = &buf[32..];
            Entries::Spilled {
                count: n,
                spill_ref,
            }
        } else {
            ensure!(n > 0, "address record without entries");
            let entries = get_entries(buf, n, base, last)?;
            ensure!(
                entries_len(&entries, base) <= SPILL_INLINE_MAX,
                "inline entries over {SPILL_INLINE_MAX} bytes (should be spilled)"
            );
            Entries::Inline(entries)
        };
        Ok(Self { fp, entries })
    }
}

fn check_fp_order(records: &[AddressRecord]) -> Result<()> {
    ensure!(
        records.windows(2).all(|w| w[0].fp <= w[1].fp),
        "address records not ascending by fingerprint"
    );
    Ok(())
}

/// A record's header and fields.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], kind: u8) -> Result<Self> {
        ensure!(
            buf.len() >= 5 && &buf[..3] == MAGIC,
            "not an E2S record ({} bytes)",
            buf.len()
        );
        ensure!(buf[3] == VERSION, "unsupported record version {}", buf[3]);
        ensure!(buf[4] == kind, "record of kind {}, expected {kind}", buf[4]);
        Ok(Self(&buf[5..]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "record truncated");
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }

    fn hash(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32"))
    }

    fn finish(self) -> Result<()> {
        ensure!(self.0.is_empty(), "{} trailing bytes", self.0.len());
        Ok(())
    }
}

/// A slice can start at a unit boundary inside its own units, not before them and not after
/// its last unit.
fn valid_first_block(level: u8, index: u32, first: u64) -> bool {
    first.is_multiple_of(UNIT_BLOCKS)
        && (first_block(level, index)..=last_block(level, index)).contains(&first)
}

/// Descriptor of slice `(level, index)` (kind 4, 111 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceRecord {
    pub level: u8,
    pub index: u32,
    /// The first block the slice holds: its grid start, or the index's first block for the
    /// slice the start falls into.
    pub first_block: u64,
    pub last_block_hash: [u8; 32],
    pub bucket_count: u32,
    pub addresses: u32,
    pub appearances: u64,
    pub buckets_root: [u8; 32],
    pub roles: u8,
}

impl SliceRecord {
    pub fn last_block(&self) -> u64 {
        last_block(self.level, self.index)
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, KIND_SLICE)?;
        let unit = r.u32()?;
        ensure!(
            unit as u64 == UNIT_BLOCKS,
            "slice unit is {unit} blocks, not {UNIT_BLOCKS}"
        );
        let level = r.u8()?;
        ensure!(level <= L_MAX, "slice level {level} above {L_MAX}");
        let index = r.u32()?;
        let (first, last) = (r.u64()?, r.u64()?);
        ensure!(
            valid_first_block(level, index, first) && last == last_block(level, index),
            "slice ({level}, {index}) states blocks {first}..={last}"
        );
        let rec = Self {
            level,
            index,
            first_block: first,
            last_block_hash: r.hash()?,
            bucket_count: r.u32()?,
            addresses: r.u32()?,
            appearances: r.u64()?,
            buckets_root: r.hash()?,
            roles: r.u8()?,
        };
        ensure!(rec.bucket_count >= 1, "slice without buckets");
        r.finish()?;
        Ok(rec)
    }
}

/// What a bucket holds: its address records, or the reference of the pages file with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketBody {
    Inline(Vec<AddressRecord>),
    Paged {
        count: u32,
        pages: u32,
        pages_ref: [u8; 32],
    },
}

/// Bucket `bucket` of slice `(level, index)` (kind 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketRecord {
    pub level: u8,
    pub index: u32,
    pub bucket: u32,
    pub body: BucketBody,
}

impl BucketRecord {
    /// Decodes a bucket of a slice whose first block is `base` (its descriptor's).
    pub fn decode(buf: &[u8], base: u64) -> Result<Self> {
        ensure!(
            buf.len() <= PAGE_SIZE,
            "bucket of {} bytes (should have been paged)",
            buf.len()
        );
        let mut r = Reader::new(buf, KIND_BUCKET)?;
        let level = r.u8()?;
        ensure!(level <= L_MAX, "bucket level {level} above {L_MAX}");
        let index = r.u32()?;
        let bucket = r.u32()?;
        ensure!(
            valid_first_block(level, index, base),
            "bucket of slice ({level}, {index}) decoded from block {base}"
        );
        let last = last_block(level, index);
        let body = match r.u8()? {
            0 => {
                let count = r.u32()?;
                let mut rest = r.0;
                let records = (0..count)
                    .map(|_| AddressRecord::decode(&mut rest, base, last))
                    .collect::<Result<Vec<_>>>()?;
                r.0 = rest;
                check_fp_order(&records)?;
                BucketBody::Inline(records)
            }
            1 => {
                let (count, pages) = (r.u32()?, r.u32()?);
                ensure!(
                    count > 0 && pages > 0,
                    "paged bucket without records or pages"
                );
                ensure!(
                    pages <= count,
                    "paged bucket with {pages} pages for {count} records"
                );
                BucketBody::Paged {
                    count,
                    pages,
                    pages_ref: r.hash()?,
                }
            }
            p => return Err(fail!("bucket paged flag {p}")),
        };
        r.finish()?;
        Ok(Self {
            level,
            index,
            bucket,
            body,
        })
    }
}

/// A head feed update, or the origin (kind 6, 70 + 5·p bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRecord {
    /// `S`, the first unit the index covers (0: from genesis).
    pub first_unit: u64,
    /// `N`, the number of complete units.
    pub units: u64,
    pub last_block_hash: [u8; 32],
    pub last_block_timestamp: u64,
    /// Deferred merges `(level, index)`, strictly ascending by `(index·2^level, level)`.
    pub pending: Vec<(u8, u32)>,
}

fn pending_key(slice: &(u8, u32)) -> (u64, u8) {
    (first_block(slice.0, slice.1), slice.0)
}

impl HeadRecord {
    pub fn first_block(&self) -> u64 {
        self.first_unit * UNIT_BLOCKS
    }

    pub fn last_block(&self) -> u64 {
        self.units * UNIT_BLOCKS - 1
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, KIND_HEAD)?;
        let first = r.u64()?;
        ensure!(
            first.is_multiple_of(UNIT_BLOCKS),
            "head starting at block {first}, not at a unit boundary"
        );
        let first_unit = first / UNIT_BLOCKS;
        let units = r.u64()?;
        ensure!(
            (1..=MAX_UNITS).contains(&units),
            "head with {units} units (1..={MAX_UNITS})"
        );
        ensure!(
            first_unit < units,
            "head starting at unit {first_unit} with {units} units"
        );
        let last = r.u64()?;
        ensure!(
            units.checked_mul(UNIT_BLOCKS).map(|b| b - 1) == Some(last),
            "head for {units} units states last block {last}"
        );
        let last_block_hash = r.hash()?;
        let last_block_timestamp = r.u64()?;
        let n = r.u8()?;
        let pending = (0..n)
            .map(|_| {
                let (level, index) = (r.u8()?, r.u32()?);
                ensure!(
                    (1..=L_MAX).contains(&level),
                    "pending merge at level {level}"
                );
                Ok((level, index))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            pending
                .windows(2)
                .all(|w| pending_key(&w[0]) < pending_key(&w[1])),
            "pending merges not strictly ascending by (first unit, level)"
        );
        ensure!(
            pending
                .iter()
                .all(|(level, index)| ((*index as u64 + 1) << level) <= units),
            "a pending merge ends after unit {units}"
        );
        ensure!(
            pending
                .iter()
                .all(|(level, index)| ((*index as u64 + 1) << level) > first_unit),
            "a pending merge ends before the index starts at unit {first_unit}"
        );
        r.finish()?;
        Ok(Self {
            first_unit,
            units,
            last_block_hash,
            last_block_timestamp,
            pending,
        })
    }
}

/// Splits a pages file into its pages; only the last one may be shorter than [`PAGE_SIZE`].
fn pages(file: &[u8]) -> Result<Vec<&[u8]>> {
    let pages: Vec<&[u8]> = file.chunks(PAGE_SIZE).collect();
    ensure!(!pages.is_empty(), "empty pages file");
    Ok(pages)
}

fn check_padding(rest: &[u8], page_len: usize) -> Result<()> {
    if rest.is_empty() {
        return Ok(());
    }
    ensure!(
        page_len == PAGE_SIZE && rest.iter().all(|b| *b == 0),
        "page has trailing bytes that are not padding"
    );
    Ok(())
}

fn flush_page(file: &mut Vec<u8>, body: &[u8], count: u16, last: bool) {
    let start = file.len();
    file.extend(count.to_be_bytes());
    file.extend_from_slice(body);
    if !last {
        file.resize(start + PAGE_SIZE, 0);
    }
}

/// The canonical spill file of `entries` (pages of `count ‖ first_block ‖ entries`, filled
/// greedily): what [`spill_entries`] compares a read file with.
fn spill_file(entries: &[Entry]) -> Vec<u8> {
    let mut file = Vec::new();
    let mut body = Vec::new();
    let mut count = 0u16;
    let mut prev = 0;
    for e in entries {
        let len = if count == 0 {
            0
        } else {
            entries_len(std::slice::from_ref(e), prev)
        };
        if count == 0 || 2 + body.len() + len > PAGE_SIZE {
            if count > 0 {
                flush_page(&mut file, &body, count, false);
            }
            body.clear();
            count = 0;
            body.extend((e.block as u32).to_be_bytes());
            prev = e.block;
        }
        put_entries(&mut body, std::slice::from_ref(e), prev);
        count += 1;
        prev = e.block;
    }
    if count > 0 {
        flush_page(&mut file, &body, count, true);
    }
    file
}

fn decode_spill_page(page: &[u8], first: u64, last: u64) -> Result<Vec<Entry>> {
    ensure!(page.len() >= 6, "spill page truncated");
    let count = u16::from_be_bytes([page[0], page[1]]);
    ensure!(count > 0, "empty spill page");
    let page_first = u32::from_be_bytes(page[2..6].try_into().expect("4")) as u64;
    ensure!(
        page_first >= first,
        "spill page starts at block {page_first}, before the slice's first block {first}"
    );
    let mut rest = &page[6..];
    let entries = get_entries(&mut rest, count as u64, page_first, last)?;
    ensure!(
        entries[0].block == page_first,
        "first entry is not at first_block"
    );
    check_padding(rest, page.len())?;
    Ok(entries)
}

/// A spill file checked page by page, in order: for a file too large to read whole (above
/// [`MAX_FILE`]), whose pages are the leaves of its chunk tree, read one at a time
/// (`swarm::FileChunk::child`). The same checks as [`spill_entries`]: every page decodes,
/// the entries ascend across pages, every page but the last is full (the next page's first
/// entry did not fit) and the last unpadded and as long as the span says, the count is the
/// record's, and the entries do not fit inline. Memory is one page, whatever the file's size.
/// A page that fails leaves the check as it was.
#[derive(Debug, Clone)]
pub struct SpillPageCheck {
    first: u64,
    last: u64,
    count: u64,
    span: u64,
    pages: u64,
    /// Pages and entries checked so far.
    page: u64,
    seen: u64,
    /// The previous page's content length and last entry.
    prev: Option<(usize, Entry)>,
}

impl SpillPageCheck {
    /// For the spill file of a record of `count` entries of the slice `slice` describes,
    /// whose root chunk states `span` bytes.
    pub fn new(slice: &SliceRecord, count: u64, span: u64) -> Result<Self> {
        ensure!(count > 0 && span > 0, "an empty spill file");
        Ok(Self {
            first: slice.first_block,
            last: slice.last_block(),
            count,
            span,
            pages: span.div_ceil(PAGE_SIZE as u64),
            page: 0,
            seen: 0,
            prev: None,
        })
    }

    /// The pages of the file.
    pub fn pages(&self) -> u64 {
        self.pages
    }

    /// Checks the next page (leaf) and returns its entries. After the last page, the whole
    /// file has been checked.
    pub fn page(&mut self, page: &[u8]) -> Result<Vec<Entry>> {
        ensure!(self.page < self.pages, "a page after the last one");
        let last_page = self.page + 1 == self.pages;
        if last_page {
            let want = self.span - (self.pages - 1) * PAGE_SIZE as u64;
            ensure!(
                page.len() as u64 == want,
                "the last spill page has {} bytes, the span says {want}",
                page.len()
            );
        }
        let entries = spill_page_of(self.first, self.last, page, last_page)?;
        if let Some((prev_content, e)) = self.prev {
            let next = entries[0];
            ensure!(
                (e.block, e.slot) < (next.block, next.slot),
                "spill entries not ascending across pages {} and {}",
                self.page - 1,
                self.page
            );
            ensure!(
                prev_content + entries_len(std::slice::from_ref(&next), e.block) > PAGE_SIZE,
                "spill file not canonically encoded: page {} ends early",
                self.page - 1
            );
        }
        let seen = self.seen + entries.len() as u64;
        ensure!(
            seen <= self.count,
            "spill file holds more than the {} entries the record states",
            self.count
        );
        if last_page {
            ensure!(
                seen == self.count,
                "spill file holds {seen} entries, the record states {}",
                self.count
            );
            // An importer spills only entries too long to stay inline (with several pages,
            // they are).
            ensure!(
                self.pages > 1 || entries_len(&entries, self.first) > SPILL_INLINE_MAX,
                "a spill file of {} entries that fit inline",
                entries.len()
            );
        }
        // Only now, once the page is accepted.
        let content = 6 + entries_len(&entries, entries[0].block);
        self.prev = Some((content, *entries.last().expect("a page has entries")));
        self.seen = seen;
        self.page += 1;
        Ok(entries)
    }

    /// Whether every page has been checked.
    pub fn done(&self) -> bool {
        self.page == self.pages
    }
}

/// One page of a spill file read on its own (a client showing a busy address's newest
/// entries reads the last pages first): decoded and checked as far as one page can be. The
/// checks across pages need [`SpillPageCheck`], in order.
pub fn spill_page(slice: &SliceRecord, page: &[u8], last_page: bool) -> Result<Vec<Entry>> {
    spill_page_of(slice.first_block, slice.last_block(), page, last_page)
}

/// The checks of a page on its own: a full page unless it is the last, which is unpadded.
fn spill_page_of(first: u64, last: u64, page: &[u8], last_page: bool) -> Result<Vec<Entry>> {
    ensure!(
        last_page || page.len() == PAGE_SIZE,
        "spill page of {} bytes",
        page.len()
    );
    let entries = decode_spill_page(page, first, last)?;
    if last_page {
        ensure!(
            6 + entries_len(&entries, entries[0].block) == page.len(),
            "the last spill page is padded"
        );
    }
    Ok(entries)
}

/// The entries of a spilled address record of the slice `slice` describes, from its spill
/// file, checked: the record's count, ascending across pages, and the canonical encoding.
pub fn spill_entries(slice: &SliceRecord, file: &[u8], count: u64) -> Result<Vec<Entry>> {
    ensure!(file.len() <= MAX_FILE, "spill file of {} bytes", file.len());
    // One vector, extended page by page (a collect and concat would hold two copies).
    let mut entries = Vec::new();
    for p in pages(file)? {
        entries.extend(decode_spill_page(p, slice.first_block, slice.last_block())?);
    }
    ensure!(
        entries.len() as u64 == count,
        "spill file holds {} entries, the record states {count}",
        entries.len()
    );
    ensure!(
        entries
            .windows(2)
            .all(|w| (w[0].block, w[0].slot) < (w[1].block, w[1].slot)),
        "spill entries not ascending across pages"
    );
    ensure!(
        spill_file(&entries) == file,
        "spill file not canonically encoded"
    );
    // An importer spills only entries too long to stay inline.
    ensure!(
        entries_len(&entries, slice.first_block) > SPILL_INLINE_MAX,
        "a spill file of {} entries that fit inline",
        entries.len()
    );
    Ok(entries)
}

fn bucket_pages_file(records: &[AddressRecord], base: u64) -> Vec<u8> {
    let mut file = Vec::new();
    let mut body = Vec::new();
    let mut count = 0u16;
    for rec in records {
        let mut enc = Vec::new();
        rec.encode(&mut enc, base);
        if count > 0 && 2 + body.len() + enc.len() > PAGE_SIZE {
            flush_page(&mut file, &body, count, false);
            body.clear();
            count = 0;
        }
        body.extend(enc);
        count += 1;
    }
    if count > 0 {
        flush_page(&mut file, &body, count, true);
    }
    file
}

fn decode_bucket_page(page: &[u8], base: u64, last: u64) -> Result<Vec<AddressRecord>> {
    ensure!(page.len() >= 2, "bucket page truncated");
    let count = u16::from_be_bytes([page[0], page[1]]);
    ensure!(count > 0, "empty bucket page");
    let mut rest = &page[2..];
    let records = (0..count)
        .map(|_| AddressRecord::decode(&mut rest, base, last))
        .collect::<Result<Vec<_>>>()?;
    check_fp_order(&records)?;
    check_padding(rest, page.len())?;
    Ok(records)
}

/// The address records of a paged bucket of the slice `slice` describes, from its pages
/// file, checked: the bucket's page and record counts, ascending across pages, and the
/// canonical encoding.
pub fn bucket_pages_records(
    slice: &SliceRecord,
    file: &[u8],
    pages_count: u32,
    record_count: u32,
) -> Result<Vec<AddressRecord>> {
    ensure!(file.len() <= MAX_FILE, "pages file of {} bytes", file.len());
    let split = pages(file)?;
    ensure!(
        split.len() as u64 == pages_count as u64,
        "pages file has {} pages, the bucket states {pages_count}",
        split.len()
    );
    let mut records = Vec::new();
    for p in split {
        records.extend(decode_bucket_page(
            p,
            slice.first_block,
            slice.last_block(),
        )?);
    }
    ensure!(
        records.len() as u64 == record_count as u64,
        "pages file holds {} records, the bucket states {record_count}",
        records.len()
    );
    check_fp_order(&records)?;
    ensure!(
        bucket_pages_file(&records, slice.first_block) == file,
        "pages file not canonically encoded"
    );
    // An importer pages only a bucket too large to be one chunk inline.
    let inline: usize = INLINE_BUCKET_HEADER
        + records
            .iter()
            .map(|r| {
                let mut b = Vec::new();
                r.encode(&mut b, slice.first_block);
                b.len()
            })
            .sum::<usize>();
    ensure!(
        inline > PAGE_SIZE,
        "a paged bucket of {inline} bytes that fits one chunk inline"
    );
    Ok(records)
}

/// Header of an inline bucket (`MAGIC ‖ VERSION ‖ kind ‖ level ‖ index ‖ bucket ‖ paged ‖
/// count`).
const INLINE_BUCKET_HEADER: usize = 19;

/// `rec` is the descriptor of slice `s` in an index from unit `first_unit`: its level and
/// index, and the first block that start makes it hold. What a reader checks before it
/// decodes the slice's buckets from that first block.
pub fn check_slice(rec: &SliceRecord, s: (u8, u32), first_unit: u64) -> Result<()> {
    ensure!(
        (rec.level, rec.index) == s,
        "slice ({}, {}) holds the record of ({}, {})",
        s.0,
        s.1,
        rec.level,
        rec.index
    );
    let first = held_first_block(s.0, s.1, first_unit);
    ensure!(
        rec.first_block == first,
        "slice ({}, {}) starts at block {}, the index makes it start at {first}",
        s.0,
        s.1,
        rec.first_block
    );
    Ok(())
}

/// `head` is head update `n` of the index whose origin is `origin`: it announces
/// `origin.units + n` units and the origin's start, and update 0 is the origin itself.
pub fn check_head(head: &HeadRecord, origin: &HeadRecord, n: u64) -> Result<()> {
    let expected = origin.units.checked_add(n);
    ensure!(
        expected == Some(head.units),
        "head update {n} announces {} units, expected the origin's {} plus {n}",
        head.units,
        origin.units
    );
    ensure!(
        head.first_unit == origin.first_unit,
        "head update {n} starts at block {}, the origin at {}",
        head.first_block(),
        origin.first_block()
    );
    ensure!(
        n > 0 || head == origin,
        "head update 0 differs from the origin"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        let s = s.trim_start_matches("0x");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn unhex32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::unhex;
    use super::*;

    fn e(block: u64, slot: u32, roles: u8) -> Entry {
        Entry { block, slot, roles }
    }

    // Known answers of eth2swarm's layout.rs (`known_bytes`, commit a1b3923).
    const BUCKET_HEX: &str = "453253010501000000030000000200000000021111111111111111040001018201ac021822222222222222228d01abababababababababababababababababababababababababababababababab";
    const SPILL_HEX: &str = "000300001388000240000901640040";
    const SLICE_HEX: &str = "4532530104000000400100000003000000000000018000000000000001ffcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000003000000020000000000000048efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefdf";
    const HEAD_HEX: &str = "45325301060000000000000000000000000000000800000000000001ff01010101010101010101010101010101010101010101010101010101010101010000000060000000010200000001";
    const HEAD_LATE_HEX: &str = "453253010600000000000001c0000000000000000800000000000001ff01010101010101010101010101010101010101010101010101010101010101010000000060000000010200000001";
    const SLICE_LATE_HEX: &str = "453253010400000040010000000300000000000001c000000000000001ffcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000003000000020000000000000048efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefdf";
    const BUCKET_LATE_HEX: &str =
        "4532530105010000000300000002000000000111111111111111110402010132ac0218";

    #[test]
    fn golden_records_decode() {
        let head = HeadRecord::decode(&unhex(HEAD_HEX)).unwrap();
        assert_eq!(
            head,
            HeadRecord {
                first_unit: 0,
                units: 8,
                last_block_hash: [1; 32],
                last_block_timestamp: 0x6000_0000,
                pending: vec![(2, 1)],
            }
        );
        let late = HeadRecord::decode(&unhex(HEAD_LATE_HEX)).unwrap();
        assert_eq!((late.first_unit, late.first_block()), (7, 448));

        let slice = SliceRecord::decode(&unhex(SLICE_HEX)).unwrap();
        assert_eq!(
            slice,
            SliceRecord {
                level: 1,
                index: 3,
                first_block: 384,
                last_block_hash: [0xcd; 32],
                bucket_count: 3,
                addresses: 2,
                appearances: 72,
                buckets_root: [0xef; 32],
                roles: 0xdf,
            }
        );
        let held = SliceRecord::decode(&unhex(SLICE_LATE_HEX)).unwrap();
        assert_eq!(held.first_block, 448);

        // Deltas start from the held first block: 450 and 500.
        let b = BucketRecord::decode(&unhex(BUCKET_LATE_HEX), held.first_block).unwrap();
        assert_eq!(
            b.body,
            BucketBody::Inline(vec![AddressRecord {
                fp: [0x11; 8],
                entries: Entries::Inline(vec![e(450, 1, 1), e(500, 300, 0x18)]),
            }])
        );
        // eth2swarm's BUCKET_HEX encodes an entry at block 514, past slice (1, 3)'s last
        // block 511 (its known-answer test only encodes): the strict decoder refuses it.
        let err = BucketRecord::decode(&unhex(BUCKET_HEX), 384).unwrap_err();
        assert!(err.0.contains("after the slice's last block"), "{err}");

        // The spill file of three entries.
        let spill = unhex(SPILL_HEX);
        // Three entries fit inline: as a spill file they are refused (no importer writes it).
        let s = SliceRecord {
            first_block: 4096,
            level: 6,
            index: 1,
            ..slice.clone()
        };
        let err = spill_entries(&s, &spill, 3).unwrap_err();
        assert!(err.0.contains("fit inline"), "{err}");
        // Its one page decodes to the three entries.
        assert_eq!(
            decode_spill_page(&spill, 4096, s.last_block()).unwrap(),
            vec![e(5000, 2, 0x40), e(5000, 9, 1), e(5100, 0, 0x40)]
        );
        assert!(spill_entries(&s, &spill, 4).is_err());
    }

    #[test]
    fn decoders_refuse_what_no_importer_writes() {
        let head = unhex(HEAD_HEX);
        // Trailing bytes, another version, another kind.
        let mut longer = head.clone();
        longer.push(0);
        assert!(HeadRecord::decode(&longer).is_err());
        let mut v2 = head.clone();
        v2[3] = 2;
        assert!(HeadRecord::decode(&v2).is_err());
        assert!(SliceRecord::decode(&head).is_err());
        // A start off a unit boundary.
        let mut off = head.clone();
        off[12] = 1;
        assert!(HeadRecord::decode(&off).is_err());
        // A slice starting before its own first block.
        let mut s = unhex(SLICE_LATE_HEX);
        s[21] = 0x40; // first_block 0x140 = 320 < 384
        assert!(SliceRecord::decode(&s).is_err());
        // A bucket decoded from a base outside its slice.
        assert!(BucketRecord::decode(&unhex(BUCKET_LATE_HEX), 512).is_err());
        // A non-shortest varint.
        assert!(get_varint(&mut &[0x81u8, 0x00][..]).is_err());
    }

    #[test]
    fn identifiers() {
        assert_eq!(slice_id(1, 16, 6), keccak256(b"eth:1:addr1:slice:16:6"));
        assert_eq!(
            bucket_id(1337, 0, 12, 3),
            keccak256(b"eth:1337:addr1:bucket:0:12:3")
        );
        let mut buf = keccak256(b"eth:1:addr1:head").to_vec();
        buf.extend(5u64.to_be_bytes());
        assert_eq!(head_id(1, 5), keccak256(&buf));
        assert_ne!(origin_id(1), head_id(1, 0));
    }

    #[test]
    fn spill_and_bucket_pages_roundtrip() {
        let entries: Vec<Entry> = (0..3000).map(|i| e(1000 + i, 1, 1)).collect();
        let file = spill_file(&entries);
        let s = SliceRecord {
            level: 12,
            index: 0,
            first_block: 0,
            last_block_hash: [0; 32],
            bucket_count: 1,
            addresses: 1,
            appearances: 3000,
            buckets_root: [0; 32],
            roles: 1,
        };
        assert_eq!(spill_entries(&s, &file, 3000).unwrap(), entries);
        let mut bad = file.clone();
        bad[PAGE_SIZE - 1] = 1; // padding
        assert!(spill_entries(&s, &bad, 3000).is_err());

        let records: Vec<AddressRecord> = (0..600u64)
            .map(|i| AddressRecord {
                fp: i.to_be_bytes(),
                entries: Entries::Inline(vec![e(i, 2, 1)]),
            })
            .collect();
        let file = bucket_pages_file(&records, 0);
        let pages_count = file.len().div_ceil(PAGE_SIZE) as u32;
        assert_eq!(
            bucket_pages_records(&s, &file, pages_count, 600).unwrap(),
            records
        );
        assert!(bucket_pages_records(&s, &file, pages_count + 1, 600).is_err());
    }

    #[test]
    fn a_spill_file_checked_page_by_page() {
        let entries: Vec<Entry> = (0..3000).map(|i| e(1000 + i, 1, 1)).collect();
        let file = spill_file(&entries);
        let s = SliceRecord {
            level: 12,
            index: 0,
            first_block: 0,
            last_block_hash: [0; 32],
            bucket_count: 1,
            addresses: 1,
            appearances: 3000,
            buckets_root: [0; 32],
            roles: 1,
        };
        let pages: Vec<&[u8]> = file.chunks(PAGE_SIZE).collect();
        assert_eq!(pages.len(), 3);
        let check = |pages: &[&[u8]], count: u64, span: usize| -> Result<Vec<Entry>> {
            let mut c = SpillPageCheck::new(&s, count, span as u64)?;
            let mut out = Vec::new();
            for p in pages {
                out.extend(c.page(p)?);
            }
            ensure!(c.done(), "pages missing");
            Ok(out)
        };
        // Page by page gives what the whole-file check gives.
        assert_eq!(check(&pages, 3000, file.len()).unwrap(), entries);
        // Each refusal for its own reason.
        let refused = |pages: &[&[u8]], count: u64, span: usize, why: &str| {
            let err = check(pages, count, span).unwrap_err();
            assert!(err.0.contains(why), "expected {why:?}, got {:?}", err.0);
        };
        refused(
            &[pages[1], pages[0], pages[2]],
            3000,
            file.len(),
            "not ascending",
        );
        refused(&pages, 2999, file.len(), "more than the 2999");
        refused(&pages, 3001, file.len(), "the record states 3001");
        refused(&pages[..2], 3000, file.len(), "pages missing");
        // A page ending early (its last entry moved to the next page) is not canonical: the
        // greedy rule is checked across pages.
        let n0 = spill_page(&s, pages[0], false).unwrap().len();
        let mut short = spill_file(&entries[..n0 - 1]);
        short.resize(PAGE_SIZE, 0);
        let rest = spill_file(&entries[n0 - 1..]);
        let refit: Vec<&[u8]> = std::iter::once(&short[..])
            .chain(rest.chunks(PAGE_SIZE))
            .collect();
        refused(&refit, 3000, PAGE_SIZE + rest.len(), "page 0 ends early");
        // A padded last page is refused, alone and in order; so is one the span disagrees
        // with.
        let mut padded = pages[2].to_vec();
        padded.push(0);
        // (Trailing zeros on a short page are "not padding"; a full-length one would be.)
        assert!(spill_page(&s, &padded, true)
            .unwrap_err()
            .0
            .contains("padding"));
        refused(
            &[pages[0], pages[1], &padded],
            3000,
            file.len() + 1,
            "padding",
        );
        refused(&pages, 3000, file.len() + 1, "the span says");
        // A failed page leaves the check as it was: the right page is accepted after it.
        let mut c = SpillPageCheck::new(&s, 3000, file.len() as u64).unwrap();
        c.page(pages[0]).unwrap();
        assert!(c.page(pages[2]).is_err());
        c.page(pages[1]).unwrap();
        c.page(pages[2]).unwrap();
        assert!(c.done());
        // The last page alone, as a client reads the newest entries first.
        assert_eq!(
            spill_page(&s, pages[2], true).unwrap(),
            entries[3000 - spill_page(&s, pages[2], true).unwrap().len()..]
        );
    }
}
