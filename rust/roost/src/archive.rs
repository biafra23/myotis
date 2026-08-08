//! The durable, append-only light-client archive.
//!
//! The two halves of roost's store have opposite recovery properties, and that
//! is the whole reason this file exists (docs/lc-server-design.md, "The archive
//! must be durable; the live window need not be"):
//!
//! - **Live window** (Nimbus's floor → head): disposable. Refetchable in seconds.
//! - **Back-archive** (below Nimbus's floor): **irreplaceable.** Nothing we
//!   operate can regenerate it — Nimbus never had the beacon states to derive
//!   those updates, so they are not "pruned", they were never derivable. Lose
//!   the file and it is gone.
//!
//! Hence the four properties below, which are the design's requirements 1–4:
//!
//! 1. **Persisted**, with memory as an accelerator in front of it.
//! 2. **Append-only.** Periods below the head never change, so a written record
//!    is never rewritten — a crash can only tear the *tail* record, never
//!    corrupt history.
//! 3. **Checksummed and self-validating on load**, so bit-rot is detected rather
//!    than served. Same discipline as the MLIX log index (magic, version,
//!    checksum) — and the same primitive, FNV-1a.
//! 4. **Backup-able**: at ~36 MB for every period from genesis, a copy on
//!    another disk *is* the answer to "what if it forgets". Restoring from an
//!    untrusted copy is safe, because clients verify every update against the
//!    sync committee established by the previous period, chaining from their own
//!    anchor. A bad archive entry is detected by the wallet, not relied upon.
//!
//! # What is stored: SSZ, not the encoded response
//!
//! Records hold the raw `LightClientUpdate` SSZ plus its fork digest — exactly
//! what Nimbus handed us. The *serving* cache holds the pre-encoded libp2p
//! response (see [`crate::store`]), which is what the capacity claim rests on;
//! that encoding is rebuilt from these records at load. Keeping the durable
//! format independent of our codec means a change to varint or snappy framing
//! never invalidates an irreplaceable archive.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

const MAGIC: &[u8; 8] = b"ROOSTLC1";
const VERSION: u32 = 1;
/// magic(8) + version(4) + reserved(4) + genesis_validators_root(32)
const HEADER_LEN: usize = 8 + 4 + 4 + 32;

/// Marks the start of a record, so a corrupt region can be scanned past rather
/// than costing every record after it.
const REC_MAGIC: &[u8; 4] = b"RREC";
const KIND_UPDATE: u8 = 1;

/// Upper bound on a record's declared SSZ length — same reasoning and same
/// value as the framing parser's chunk bound.
const MAX_RECORD_SSZ: usize = 1 << 20;

/// FNV-1a — integrity tag for bit-rot detection, not a security boundary.
/// Identical primitive to the log index's snapshot checksum.
fn fnv64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One archived period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedUpdate {
    pub period: u64,
    pub fork_digest: [u8; 4],
    pub ssz: Vec<u8>,
}

/// What a load found, beyond the records themselves.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoadReport {
    /// Records that checksummed cleanly.
    pub loaded: usize,
    /// Bytes discarded from a torn tail (interrupted write) and truncated away,
    /// so the file is appendable again.
    pub torn_tail_bytes: u64,
    /// Records lost to a corrupt region we had to scan past. Non-zero here is
    /// the "refetch what fails" signal — and for periods below Nimbus's floor,
    /// the signal to restore from backup.
    pub corrupt_regions: usize,
}

/// Append-only archive file.
#[derive(Debug)]
pub struct Archive {
    path: PathBuf,
    file: File,
}

impl Archive {
    /// Open (or create) the archive and load every intact record.
    ///
    /// `genesis_validators_root` identifies the chain. An archive built for one
    /// network must never load for another — the updates would be verified
    /// against the wrong sync committee and rejected by every wallet, which is
    /// a confusing way to discover you copied the wrong file. Same role the
    /// watch-list fingerprint plays for the log index.
    pub fn open(
        path: impl AsRef<Path>,
        genesis_validators_root: &[u8; 32],
    ) -> Result<(Self, BTreeMap<u64, ArchivedUpdate>, LoadReport)> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;

        let len = file.metadata()?.len();
        if len == 0 {
            write_header(&mut file, genesis_validators_root)?;
            return Ok((Self { path, file }, BTreeMap::new(), LoadReport::default()));
        }

        let mut buf = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;

        let (records, report) = parse(&buf, genesis_validators_root)
            .with_context(|| format!("parsing {}", path.display()))?;

        // A torn tail is the one thing we repair in place: appending after a
        // partial record would splice the next record into its remains.
        if report.torn_tail_bytes > 0 {
            let good = buf.len() as u64 - report.torn_tail_bytes;
            file.set_len(good)
                .with_context(|| format!("truncating torn tail of {}", path.display()))?;
            tracing::warn!(
                path = %path.display(),
                bytes = report.torn_tail_bytes,
                "archive had a torn tail record (interrupted write); truncated to the last intact record"
            );
        }
        if report.corrupt_regions > 0 {
            tracing::error!(
                path = %path.display(),
                regions = report.corrupt_regions,
                "archive has corrupt records — refetch the affected periods, and restore from \
                 backup for any below the upstream light-client floor"
            );
        }

        file.seek(SeekFrom::End(0))?;
        Ok((Self { path, file }, records, report))
    }

    /// Append one period. Never rewrites, so this cannot damage what is already
    /// stored — the worst an interrupted call can do is leave a torn tail that
    /// the next [`Archive::open`] truncates.
    pub fn append(&mut self, period: u64, fork_digest: [u8; 4], ssz: &[u8]) -> Result<()> {
        if ssz.len() > MAX_RECORD_SSZ {
            bail!(
                "period {period}: {} SSZ bytes exceeds MAX_RECORD_SSZ ({MAX_RECORD_SSZ})",
                ssz.len()
            );
        }
        let mut body = Vec::with_capacity(ssz.len() + 32);
        body.extend_from_slice(REC_MAGIC);
        body.push(KIND_UPDATE);
        body.extend_from_slice(&period.to_le_bytes());
        body.extend_from_slice(&fork_digest);
        body.extend_from_slice(&(ssz.len() as u32).to_le_bytes());
        body.extend_from_slice(ssz);
        let checksum = fnv64(&body);
        body.extend_from_slice(&checksum.to_le_bytes());

        self.file
            .write_all(&body)
            .with_context(|| format!("appending period {period} to {}", self.path.display()))?;
        Ok(())
    }

    /// Flush and fsync. Called per batch rather than per record: 1327 periods is
    /// one bulk collection, and a torn tail is recoverable by construction.
    pub fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn write_header(file: &mut File, gvr: &[u8; 32]) -> Result<()> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // reserved
    header.extend_from_slice(gvr);
    file.write_all(&header).context("writing archive header")?;
    file.flush()?;
    Ok(())
}

/// Walk the file. Every slice is checked; a bad length can never make us
/// allocate or index out of bounds.
fn parse(
    buf: &[u8],
    expect_gvr: &[u8; 32],
) -> Result<(BTreeMap<u64, ArchivedUpdate>, LoadReport)> {
    let header = buf
        .get(..HEADER_LEN)
        .ok_or_else(|| anyhow!("file is {} bytes, shorter than the header", buf.len()))?;
    if &header[..8] != MAGIC {
        bail!("bad magic — not a roost archive");
    }
    let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if version != VERSION {
        bail!("archive version {version}, this build understands {VERSION}");
    }
    let gvr = &header[16..48];
    if gvr != expect_gvr {
        bail!(
            "archive belongs to a different chain (genesis_validators_root 0x{}…, expected 0x{}…)",
            hex::encode(&gvr[..8]),
            hex::encode(&expect_gvr[..8])
        );
    }

    let mut records = BTreeMap::new();
    let mut report = LoadReport::default();
    let mut pos = HEADER_LEN;

    while pos < buf.len() {
        match read_record(buf, pos) {
            RecordRead::Ok { record, next } => {
                records.insert(record.period, record);
                report.loaded += 1;
                pos = next;
            }
            // Ran out of bytes mid-record. Usually the classic interrupted
            // write — but a CORRUPTED length field in a non-tail record looks
            // identical, and treating that as a torn tail would truncate the
            // file from here and delete every valid record after it. That is
            // exactly the salvage guarantee this format exists to provide, so
            // check before truncating: if an intact record follows, this is
            // corruption in the middle, not a torn tail.
            RecordRead::Torn => {
                if valid_record_follows(buf, pos) {
                    report.corrupt_regions += 1;
                    match find_next_valid_record(buf, pos + 1) {
                        Some(next) => {
                            pos = next;
                            continue;
                        }
                        // Unreachable given valid_record_follows, but falling
                        // through to truncation here would be the destructive
                        // branch, so stop instead.
                        None => break,
                    }
                }
                report.torn_tail_bytes = (buf.len() - pos) as u64;
                break;
            }
            // Checksum or framing failure with data still ahead: real
            // corruption. Scan forward to the next record magic rather than
            // abandoning everything after it — this file may be irreplaceable.
            RecordRead::Corrupt => {
                report.corrupt_regions += 1;
                match find_next_valid_record(buf, pos + 1) {
                    Some(next) => pos = next,
                    None => {
                        report.torn_tail_bytes = (buf.len() - pos) as u64;
                        break;
                    }
                }
            }
        }
    }

    Ok((records, report))
}

enum RecordRead {
    Ok { record: ArchivedUpdate, next: usize },
    Torn,
    Corrupt,
}

fn read_record(buf: &[u8], pos: usize) -> RecordRead {
    // rec_magic(4) + kind(1) + period(8) + digest(4) + ssz_len(4) = 21
    const FIXED: usize = 4 + 1 + 8 + 4 + 4;
    let Some(head) = buf.get(pos..pos.saturating_add(FIXED)) else {
        return RecordRead::Torn;
    };
    if &head[..4] != REC_MAGIC {
        return RecordRead::Corrupt;
    }
    if head[4] != KIND_UPDATE {
        return RecordRead::Corrupt;
    }
    let period = u64::from_le_bytes(head[5..13].try_into().unwrap());
    let mut fork_digest = [0u8; 4];
    fork_digest.copy_from_slice(&head[13..17]);
    let ssz_len = u32::from_le_bytes(head[17..21].try_into().unwrap()) as usize;
    if ssz_len == 0 || ssz_len > MAX_RECORD_SSZ {
        return RecordRead::Corrupt;
    }

    let Some(body_end) = pos.checked_add(FIXED).and_then(|p| p.checked_add(ssz_len)) else {
        return RecordRead::Corrupt;
    };
    let Some(ssz) = buf.get(pos + FIXED..body_end) else {
        return RecordRead::Torn;
    };
    let Some(sum_bytes) = buf.get(body_end..body_end.saturating_add(8)) else {
        return RecordRead::Torn;
    };
    let stored = u64::from_le_bytes(sum_bytes.try_into().unwrap());
    if fnv64(&buf[pos..body_end]) != stored {
        return RecordRead::Corrupt;
    }

    RecordRead::Ok {
        record: ArchivedUpdate {
            period,
            fork_digest,
            ssz: ssz.to_vec(),
        },
        next: body_end + 8,
    }
}

/// The next offset at which a record actually reads cleanly.
///
/// Scanning for `REC_MAGIC` alone is not enough: those four bytes can occur
/// inside a payload by chance, and resuming there would manufacture garbage
/// records. Each candidate is parsed and checksummed before it is accepted.
fn find_next_valid_record(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 4 <= buf.len() {
        if &buf[i..i + 4] == REC_MAGIC {
            if let RecordRead::Ok { .. } = read_record(buf, i) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Whether any intact record exists after `pos` — the test that separates a
/// torn tail (nothing follows) from mid-file corruption (something does).
fn valid_record_follows(buf: &[u8], pos: usize) -> bool {
    find_next_valid_record(buf, pos.saturating_add(1)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("roost-archive-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    const GVR: [u8; 32] = [7u8; 32];

    #[test]
    fn round_trips_through_a_reopen() {
        let path = tmp("roundtrip");
        {
            let (mut a, recs, report) = Archive::open(&path, &GVR).unwrap();
            assert!(recs.is_empty());
            assert_eq!(report, LoadReport::default());
            a.append(1323, [0x74, 0xd0, 0x14, 0x59], &[1u8; 64]).unwrap();
            a.append(1324, [0x74, 0xd0, 0x14, 0x59], &[2u8; 71]).unwrap();
            a.flush().unwrap();
        }
        let (_a, recs, report) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(report.loaded, 2);
        assert_eq!(report.torn_tail_bytes, 0);
        assert_eq!(report.corrupt_regions, 0);
        assert_eq!(recs[&1323].ssz, vec![1u8; 64]);
        assert_eq!(recs[&1324].ssz, vec![2u8; 71]);
        assert_eq!(recs[&1324].fork_digest, [0x74, 0xd0, 0x14, 0x59]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn appends_survive_across_sessions() {
        let path = tmp("append-sessions");
        {
            let (mut a, _, _) = Archive::open(&path, &GVR).unwrap();
            a.append(1, [1, 1, 1, 1], &[9u8; 16]).unwrap();
            a.flush().unwrap();
        }
        {
            let (mut a, recs, _) = Archive::open(&path, &GVR).unwrap();
            assert_eq!(recs.len(), 1);
            a.append(2, [2, 2, 2, 2], &[8u8; 16]).unwrap();
            a.flush().unwrap();
        }
        let (_a, recs, _) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(recs.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refuses_an_archive_from_another_chain() {
        let path = tmp("wrong-chain");
        {
            let (mut a, _, _) = Archive::open(&path, &GVR).unwrap();
            a.append(1, [1, 1, 1, 1], &[1u8; 8]).unwrap();
            a.flush().unwrap();
        }
        let err = format!("{:#}", Archive::open(&path, &[9u8; 32]).unwrap_err());
        assert!(err.contains("different chain"), "got: {err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn repairs_a_torn_tail_and_keeps_earlier_records() {
        let path = tmp("torn-tail");
        {
            let (mut a, _, _) = Archive::open(&path, &GVR).unwrap();
            a.append(10, [1, 1, 1, 1], &[3u8; 32]).unwrap();
            a.append(11, [1, 1, 1, 1], &[4u8; 32]).unwrap();
            a.flush().unwrap();
        }
        // Simulate a write interrupted partway through the last record.
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 20).unwrap();
        drop(f);

        let (_a, recs, report) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(report.loaded, 1, "the intact record must survive");
        assert!(report.torn_tail_bytes > 0);
        assert!(recs.contains_key(&10));
        assert!(!recs.contains_key(&11));

        // …and the file is appendable again: the torn bytes are gone, so the
        // next record cannot be spliced onto their remains.
        let (_a, recs2, report2) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(report2.torn_tail_bytes, 0);
        assert_eq!(recs2.len(), 1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn salvages_records_after_a_corrupt_one() {
        // The archive may be irreplaceable, so one bad record must not cost
        // every record behind it.
        let path = tmp("corrupt-middle");
        {
            let (mut a, _, _) = Archive::open(&path, &GVR).unwrap();
            for p in 0..4u64 {
                a.append(p, [1, 1, 1, 1], &[p as u8; 48]).unwrap();
            }
            a.flush().unwrap();
        }
        // Flip a byte inside the second record's payload.
        let mut bytes = std::fs::read(&path).unwrap();
        let second_payload = HEADER_LEN + (4 + 1 + 8 + 4 + 4 + 48 + 8) + 25;
        bytes[second_payload] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let (_a, recs, report) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(report.corrupt_regions, 1);
        assert_eq!(report.loaded, 3, "records after the corruption must survive");
        assert!(recs.contains_key(&0));
        assert!(!recs.contains_key(&1), "the corrupt period is the one lost");
        assert!(recs.contains_key(&2));
        assert!(recs.contains_key(&3));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_corrupt_length_mid_file_does_not_truncate_the_records_after_it() {
        // A corrupted length field runs past EOF exactly like a torn tail. If
        // that is misread as a torn tail, the file is truncated from there and
        // every valid record behind it is destroyed — in a file nothing can
        // regenerate.
        let path = tmp("corrupt-length-midfile");
        {
            let (mut a, _, _) = Archive::open(&path, &GVR).unwrap();
            for p in 0..4u64 {
                a.append(p, [1, 1, 1, 1], &[p as u8; 48]).unwrap();
            }
            a.flush().unwrap();
        }
        // Overwrite the SECOND record's ssz_len with something enormous.
        let rec_len = 4 + 1 + 8 + 4 + 4 + 48 + 8;
        let second = HEADER_LEN + rec_len;
        let mut bytes = std::fs::read(&path).unwrap();
        let len_at = second + 4 + 1 + 8 + 4;
        bytes[len_at..len_at + 4].copy_from_slice(&(900_000u32).to_le_bytes());
        let original_len = bytes.len();
        std::fs::write(&path, &bytes).unwrap();

        let (_a, recs, report) = Archive::open(&path, &GVR).unwrap();
        assert_eq!(report.corrupt_regions, 1, "must be classified as corruption");
        assert_eq!(report.torn_tail_bytes, 0, "must NOT be treated as a torn tail");
        assert!(recs.contains_key(&0));
        assert!(recs.contains_key(&2), "records after the bad length must survive");
        assert!(recs.contains_key(&3));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            original_len as u64,
            "the file must not be truncated"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn refuses_a_file_that_is_not_an_archive() {
        let path = tmp("not-an-archive");
        // Longer than HEADER_LEN, so this exercises the magic check rather than
        // the shorter-than-a-header branch.
        std::fs::write(
            &path,
            b"this is definitely not a roost archive at all, not even close",
        )
        .unwrap();
        let err = format!("{:#}", Archive::open(&path, &GVR).unwrap_err());
        assert!(err.contains("bad magic"), "got: {err}");
        std::fs::remove_file(&path).ok();
    }
}
