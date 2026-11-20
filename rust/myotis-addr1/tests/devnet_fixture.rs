//! A whole lookup over a real index: the export eth2swarm wrote for the bee-factory chain
//! (`rust/testdata/addr1-devnet`, README there), read the way a client reads Swarm (origin,
//! head update, slices newest first, one bucket each, spill files), every SOC, chunk and file
//! checked, and the entries compared with what eth2swarm's own client found through Bee.

use std::collections::{BTreeMap, HashMap};

use myotis_addr1::cover::slices_to_read;
use myotis_addr1::lookup::{bucket_for, in_bucket, select, InBucket};
use myotis_addr1::records::{
    bucket_id, bucket_pages_records, check_head, check_slice, head_id, origin_id, slice_id,
    spill_entries, BucketRecord, Entry, HeadRecord, SliceRecord,
};
use myotis_addr1::swarm::{soc_address, verify_file, verify_soc};

const CHAIN: u64 = 1337;
const OWNER: &str = "ad85b9f14bd1be6a53b16f1e18015cc81a679b0f";

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/addr1-devnet")
}

/// The export log as a store: key → data (what Swarm would serve under that address).
fn store() -> HashMap<[u8; 32], Vec<u8>> {
    let log = std::fs::read(dir().join("addr1.export")).unwrap();
    let mut out = HashMap::new();
    let mut rest = &log[..];
    while !rest.is_empty() {
        let kind = rest[0];
        assert!(matches!(kind, 1..=3), "record kind {kind}");
        let key: [u8; 32] = rest[1..33].try_into().unwrap();
        let n = u32::from_be_bytes(rest[33..37].try_into().unwrap()) as usize;
        out.insert(key, rest[37..37 + n].to_vec());
        rest = &rest[37 + n..];
    }
    out
}

struct Reader {
    store: HashMap<[u8; 32], Vec<u8>>,
    owner: [u8; 20],
}

impl Reader {
    fn soc(&self, id: [u8; 32]) -> Vec<u8> {
        let address = soc_address(&id, &self.owner);
        verify_soc(&self.store[&address], &address, &self.owner).unwrap()
    }

    fn file(&self, reference: &[u8; 32]) -> Vec<u8> {
        let data = self.store[reference].clone();
        verify_file(&data, reference).unwrap();
        data
    }

    fn lookup(&self, address: &[u8; 20], head: &HeadRecord) -> Vec<Entry> {
        let mut out = Vec::new();
        let plan = slices_to_read(head, None).unwrap();
        for s in plan.slices.iter().copied() {
            let slice = SliceRecord::decode(&self.soc(slice_id(CHAIN, s.0, s.1))).unwrap();
            check_slice(&slice, s, head.first_unit).unwrap();
            let k = bucket_for(address, &slice);
            let bucket =
                BucketRecord::decode(&self.soc(bucket_id(CHAIN, s.0, s.1, k)), slice.first_block)
                    .unwrap();
            let found = match in_bucket(address, &slice, &bucket).unwrap() {
                InBucket::Records(found) => found,
                InBucket::Paged {
                    pages_ref,
                    pages,
                    records,
                } => select(
                    address,
                    &bucket_pages_records(&slice, &self.file(&pages_ref), pages, records).unwrap(),
                ),
            };
            out.extend(found.entries);
            for (spill_ref, count) in found.spill_files {
                out.extend(spill_entries(&slice, &self.file(&spill_ref), count).unwrap());
            }
        }
        out.retain(|e| plan.keep(e.block));
        out.sort();
        out
    }
}

fn expected() -> BTreeMap<[u8; 20], Vec<Entry>> {
    let mut out: BTreeMap<[u8; 20], Vec<Entry>> = BTreeMap::new();
    for line in std::fs::read_to_string(dir().join("expected.txt"))
        .unwrap()
        .lines()
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        let a: [u8; 20] = unhex(f[0]).try_into().unwrap();
        let list = out.entry(a).or_default();
        if f[1] != "-" {
            list.push(Entry {
                block: f[1].parse().unwrap(),
                slot: f[2].parse().unwrap(),
                roles: f[3].parse().unwrap(),
            });
        }
    }
    for l in out.values_mut() {
        l.sort();
    }
    out
}

#[test]
fn lookups_over_the_devnet_index_match_eth2swarm() {
    let r = Reader {
        store: store(),
        owner: unhex(OWNER).try_into().unwrap(),
    };
    let origin = HeadRecord::decode(&r.soc(origin_id(CHAIN))).unwrap();
    assert_eq!((origin.first_block(), origin.units), (1920, 32));
    // Head update n announces N0 + n units; the newest the fixture holds is update 1.
    let head = HeadRecord::decode(&r.soc(head_id(CHAIN, 1))).unwrap();
    check_head(&head, &origin, 1).unwrap();
    assert_eq!(head.units, 33);
    let head0 = HeadRecord::decode(&r.soc(head_id(CHAIN, 0))).unwrap();
    check_head(&head0, &origin, 0).unwrap();
    // Update 1 is not update 2, nor update 0.
    assert!(check_head(&head, &origin, 2).is_err());
    assert!(check_head(&head, &origin, 0).is_err());

    let want = expected();
    assert_eq!(want.len(), 5);
    let mut total = 0;
    for (address, entries) in &want {
        assert_eq!(&r.lookup(address, &head), entries, "address {address:02x?}");
        total += entries.len();
    }
    assert_eq!(total, 372);
}

#[test]
fn a_soc_of_another_owner_or_address_is_refused() {
    let store = store();
    let owner: [u8; 20] = unhex(OWNER).try_into().unwrap();
    let address = soc_address(&origin_id(CHAIN), &owner);
    let wire = &store[&address];
    assert!(verify_soc(wire, &address, &owner).is_ok());
    // Another owner: its address differs, and the signature is not its.
    let other = [0x11u8; 20];
    assert!(verify_soc(wire, &soc_address(&origin_id(CHAIN), &other), &other).is_err());
    // The right owner, but asked for head update 0's address: a valid record answering
    // another request is refused.
    let head0 = soc_address(&head_id(CHAIN, 0), &owner);
    assert!(verify_soc(wire, &head0, &owner).is_err());
    // A flipped payload byte breaks the signature.
    let mut bad = wire.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(verify_soc(&bad, &address, &owner).is_err());
}

/// The fixture as Swarm serves it, chunk by chunk: SOCs under their address, every file as
/// the chunks of its tree.
struct Chunks(HashMap<[u8; 32], Vec<u8>>);

impl Chunks {
    fn new() -> Self {
        let log = std::fs::read(dir().join("addr1.export")).unwrap();
        let mut out = HashMap::new();
        let mut rest = &log[..];
        while !rest.is_empty() {
            let kind = rest[0];
            let key: [u8; 32] = rest[1..33].try_into().unwrap();
            let n = u32::from_be_bytes(rest[33..37].try_into().unwrap()) as usize;
            let data = rest[37..37 + n].to_vec();
            if kind == 1 {
                for (r, wire) in myotis_addr1::swarm::file_tree(&data) {
                    out.insert(r, wire);
                }
            } else {
                out.insert(key, data);
            }
            rest = &rest[37 + n..];
        }
        Chunks(out)
    }
}

impl myotis_addr1::client::ChunkSource for Chunks {
    fn chunk(
        &self,
        address: [u8; 32],
        _expect_missing: bool,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, myotis_addr1::client::SourceError>> + Send {
        let got = self.0.get(&address).cloned();
        async move { Ok(got) }
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut f = std::pin::pin!(f);
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

#[test]
fn the_client_pages_every_address_newest_first_as_eth2swarm_found_it() {
    use myotis_addr1::client::Index;
    let chunks = Chunks::new();
    let owner: [u8; 20] = unhex(OWNER).try_into().unwrap();
    let index = Index::new(&chunks, CHAIN, owner);
    let origin = block_on(index.origin()).unwrap();
    // The head probe finds update 1, the newest the fixture holds.
    let (n, head) = block_on(index.head(&origin, 0)).unwrap();
    assert_eq!((n, head.units), (1, 33));
    for (address, want) in expected() {
        let newest_first: Vec<Entry> = want.iter().rev().copied().collect();
        // One page holds everything.
        let all = block_on(index.page(&head, &address, None, 10_000, &myotis_addr1::client::Filter::default())).unwrap();
        assert_eq!(all.entries, newest_first, "address {address:02x?}");
        assert_eq!((all.next, all.gaps.len()), (None, 0));
        assert_eq!((all.from_block, all.to_block), (1920, 33 * 64 - 1));
        // Small pages, followed by their cursors, give the same list.
        for size in [1usize, 3, 7] {
            let mut got = Vec::new();
            let mut cursor = None;
            loop {
                let page = block_on(index.page(&head, &address, cursor, size, &myotis_addr1::client::Filter::default())).unwrap();
                assert!(page.entries.len() <= size);
                got.extend(page.entries);
                match page.next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            assert_eq!(got, newest_first, "address {address:02x?}, pages of {size}");
        }
    }
    // An address the index never saw: an empty, complete answer.
    let none = block_on(index.page(&head, &[0x42; 20], None, 10, &myotis_addr1::client::Filter::default())).unwrap();
    assert!(none.entries.is_empty() && none.next.is_none() && none.gaps.is_empty());
}

#[test]
fn a_slice_swarm_does_not_deliver_is_a_gap() {
    use myotis_addr1::client::Index;
    let mut chunks = Chunks::new();
    let owner: [u8; 20] = unhex(OWNER).try_into().unwrap();
    let head = {
        let index = Index::new(&chunks, CHAIN, owner);
        let origin = block_on(index.origin()).unwrap();
        block_on(index.head(&origin, 0)).unwrap().1
    };
    // Withhold the newest slice's descriptor.
    let newest = slices_to_read(&head, None).unwrap().slices[0];
    chunks.0.remove(&soc_address(&slice_id(CHAIN, newest.0, newest.1), &owner));
    let index = Index::new(&chunks, CHAIN, owner);
    let (address, _) = expected().into_iter().next().unwrap();
    let page = block_on(index.page(&head, &address, None, 10_000, &myotis_addr1::client::Filter::default())).unwrap();
    assert_eq!(page.gaps.len(), 1);
    let range = myotis_addr1::cover::units(newest);
    assert_eq!(page.gaps[0].to_block, range.end * 64 - 1);
    assert!(page.entries.iter().all(|e| e.block < range.start * 64));
}

#[test]
fn a_spill_file_swarm_does_not_deliver_makes_its_slice_a_gap() {
    use myotis_addr1::client::Index;
    // Every content-addressed chunk withheld (the SOCs stay): the slices whose address
    // records spill, or whose bucket is paged, cannot be read.
    let log = std::fs::read(dir().join("addr1.export")).unwrap();
    let mut files = Vec::new();
    let mut rest = &log[..];
    while !rest.is_empty() {
        let n = u32::from_be_bytes(rest[33..37].try_into().unwrap()) as usize;
        if rest[0] == 1 {
            files.push(rest[37..37 + n].to_vec());
        }
        rest = &rest[37 + n..];
    }
    let mut chunks = Chunks::new();
    for data in &files {
        for (r, _) in myotis_addr1::swarm::file_tree(data) {
            chunks.0.remove(&r);
        }
    }
    let owner: [u8; 20] = unhex(OWNER).try_into().unwrap();
    let index = Index::new(&chunks, CHAIN, owner);
    let origin = block_on(index.origin()).unwrap();
    let (_, head) = block_on(index.head(&origin, 0)).unwrap();
    let mut gaps = 0;
    for (address, want) in expected() {
        // Never an error: what could be read, and a gap for each slice that could not.
        let page = block_on(index.page(&head, &address, None, 10_000, &myotis_addr1::client::Filter::default())).unwrap();
        if page.gaps.is_empty() {
            assert_eq!(page.entries.len(), want.len(), "address {address:02x?}");
        } else {
            assert!(page.entries.len() < want.len(), "address {address:02x?}");
            gaps += 1;
        }
    }
    assert!(gaps > 0, "the fixture's spill files make at least one gap");
}

#[test]
fn a_filtered_page_holds_only_what_the_filter_keeps_and_is_still_full() {
    use myotis_addr1::client::{Filter, Index};
    let chunks = Chunks::new();
    let owner: [u8; 20] = unhex(OWNER).try_into().unwrap();
    let index = Index::new(&chunks, CHAIN, owner);
    let origin = block_on(index.origin()).unwrap();
    let (_, head) = block_on(index.head(&origin, 0)).unwrap();
    for (address, want) in expected() {
        let mid = want.get(want.len() / 2).map_or(0, |e| e.block);
        for filter in [
            Filter { roles: 0x01, from_block: 0 },             // FROM only
            Filter { roles: 0x04 | 0x08, from_block: 0 },      // log roles
            Filter { roles: 0xff, from_block: mid },           // a block range
            Filter { roles: 0x02, from_block: mid },
        ] {
            let filtered: Vec<Entry> = want.iter().rev().copied().filter(|e| filter.keeps(e)).collect();
            // In pages of 3, followed by their cursors.
            let mut got = Vec::new();
            let mut cursor = None;
            loop {
                let page = block_on(index.page(&head, &address, cursor, 3, &filter)).unwrap();
                assert!(page.entries.len() <= 3);
                // Full until the last page.
                if page.next.is_some() {
                    assert_eq!(page.entries.len(), 3, "a filtered page is still full");
                }
                got.extend(page.entries);
                match page.next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            assert_eq!(got, filtered, "address {address:02x?}, {filter:?}");
        }
    }
}
