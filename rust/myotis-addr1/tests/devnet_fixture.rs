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
