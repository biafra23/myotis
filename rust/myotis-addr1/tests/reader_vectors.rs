//! The reader against eth2swarm's conformance vectors (`rust/testdata/addr1-vectors`, README
//! there): slices at the edges of the encodings (multi-page spill and pages files, the inline
//! and paging limits and one byte over), every address's records and files decoded with the
//! reader's strict decoders and its entries compared with what eth2swarm built.

use std::collections::HashMap;

use myotis_addr1::lookup::{bucket_for, in_bucket, select, InBucket};
use myotis_addr1::records::{
    bucket_pages_records, check_slice, spill_entries, BucketRecord, Entry, SliceRecord,
    SpillPageCheck,
};
use myotis_addr1::swarm::{file_reference, file_tree, verify_file, FileChunk, Locate, MAX_SPAN};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[derive(Default)]
struct Case {
    name: String,
    /// The slice id, the first unit of its index, the descriptor.
    slice: Option<((u8, u32), u64, SliceRecord)>,
    buckets: HashMap<u32, Vec<u8>>,
    files: HashMap<[u8; 32], Vec<u8>>,
    /// address, record form, bucket form, entries
    addresses: Vec<([u8; 20], String, String, Vec<Entry>)>,
    /// Addresses the slice has no record of.
    absent: Vec<[u8; 20]>,
}

fn cases() -> Vec<Case> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/addr1-vectors/addr1-reader-vectors.txt");
    let mut out: Vec<Case> = Vec::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] == "case" {
            out.push(Case {
                name: f[1].to_string(),
                ..Default::default()
            });
            continue;
        }
        let c = out.last_mut().expect("a case first");
        match f[0] {
            "slice" => {
                let id = (f[1].parse().unwrap(), f[2].parse().unwrap());
                let first_unit = f[3].parse().unwrap();
                c.slice = Some((id, first_unit, SliceRecord::decode(&unhex(f[4])).unwrap()));
            }
            "bucket" => {
                c.buckets.insert(f[1].parse().unwrap(), unhex(f[2]));
            }
            "file" => {
                c.files.insert(unhex(f[1]).try_into().unwrap(), unhex(f[2]));
            }
            "address" => {
                let entries: Vec<Entry> = f[5]
                    .split(',')
                    .map(|e| {
                        let p: Vec<&str> = e.split('.').collect();
                        Entry {
                            block: p[0].parse().unwrap(),
                            slot: p[1].parse().unwrap(),
                            roles: p[2].parse().unwrap(),
                        }
                    })
                    .collect();
                assert_eq!(entries.len(), f[4].parse::<usize>().unwrap());
                c.addresses.push((
                    unhex(f[1]).try_into().unwrap(),
                    f[2].to_string(),
                    f[3].to_string(),
                    entries,
                ));
            }
            "absent" => c.absent.push(unhex(f[1]).try_into().unwrap()),
            other => panic!("unknown line kind {other}"),
        }
    }
    out
}

/// A spill file read leaf by leaf from its root, as a client reads one too large to fetch
/// whole: every chunk checked, each leaf a page, the pages checked in order.
fn read_paged(slice: &SliceRecord, file: &[u8], count: u64) -> Vec<Entry> {
    let tree: HashMap<[u8; 32], Vec<u8>> = file_tree(file).into_iter().collect();
    let root = file_reference(file);
    let top = FileChunk::decode_root(&tree[&root], &root, MAX_SPAN).unwrap();
    let mut check = SpillPageCheck::new(slice, count, top.span()).unwrap();
    let mut out = Vec::new();
    for i in 0..check.pages() {
        let (mut chunk, mut leaf) = (top.clone(), i);
        while let Locate::Down { child, below } = chunk.locate(leaf).unwrap() {
            let (r, _) = chunk.child(child).unwrap();
            chunk = chunk.decode_child(child, &tree[&r]).unwrap();
            leaf = below;
        }
        out.extend(check.page(chunk.leaf().unwrap()).unwrap());
    }
    assert!(check.done());
    out
}

#[test]
fn the_reader_decodes_eth2swarms_edge_cases() {
    let cases = cases();
    let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "spill-pages",
            "spill-page-full",
            "spill-limit",
            "bucket-4096",
            "bucket-4097",
            "bucket-pages",
            "bucket-page-full",
            "late-start",
            "mainnet-height"
        ]
    );
    let mut checked = 0;
    for c in &cases {
        let (id, first_unit, slice) = c.slice.as_ref().unwrap();
        check_slice(slice, *id, *first_unit).unwrap();
        for (r, data) in &c.files {
            verify_file(data, r).unwrap();
        }
        let wanted = c
            .addresses
            .iter()
            .map(|(a, r, b, e)| (a, Some((r, b, e))))
            .chain(c.absent.iter().map(|a| (a, None)));
        for (address, want) in wanted {
            let k = bucket_for(address, slice);
            let bucket = BucketRecord::decode(&c.buckets[&k], slice.first_block)
                .unwrap_or_else(|e| panic!("{}: bucket {k}: {e}", c.name));
            let (found, paged) = match in_bucket(address, slice, &bucket).unwrap() {
                InBucket::Records(found) => (found, false),
                InBucket::Paged {
                    pages_ref,
                    pages,
                    records,
                } => {
                    let recs = bucket_pages_records(slice, &c.files[&pages_ref], pages, records)
                        .unwrap_or_else(|e| panic!("{}: pages file: {e}", c.name));
                    (select(address, &recs), true)
                }
            };
            let Some((record_form, bucket_form, want)) = want else {
                assert_eq!(found, Default::default(), "{}: an absent address", c.name);
                continue;
            };
            assert_eq!(bucket_form == "paged", paged, "{}: bucket form", c.name);
            let spilled = !found.spill_files.is_empty();
            assert_eq!(record_form == "spilled", spilled, "{}: record form", c.name);
            let mut got = found.entries;
            for (r, count) in &found.spill_files {
                let whole = spill_entries(slice, &c.files[r], *count)
                    .unwrap_or_else(|e| panic!("{}: spill file: {e}", c.name));
                // Page by page through its chunk tree, as a file above MAX_FILE is read: the
                // same entries.
                assert_eq!(
                    read_paged(slice, &c.files[r], *count),
                    whole,
                    "{}: paged",
                    c.name
                );
                got.extend(whole);
            }
            assert_eq!(&got, want, "{}: entries", c.name);
            checked += 1;
        }
    }
    // Every address of every case was compared: 1 + 1 + 2 + 32 + 32 + 64 + 42 + 2 + 2.
    assert_eq!(checked, 178);
}
