//! Disk cache throughput using **real file bytes** from the litter-ally.eth site
//! (via `litter-ally.eth.limo`): images, CSS, and WAV masters — chunked into
//! bee-compatible CAC segments (≤4 KiB payload each), written to
//! [`DiskChunkCache`], then hammered with concurrent reads.
//!
//! Fetch assets first (example paths), then run:
//!
//! ```text
//! LITTER_BENCH_DIR=/tmp/litter_bench \
//!   cargo run --release --example litter_disk_cache_bench -p ant-retrieval
//! ```
//!
//! Compare with bee's sharky + `LevelDB` retrieval path (same dataset) via
//! `scripts/run_bee_sharky_litter_bench.sh` after checking out bee.

use ant_crypto::{cac_new, CHUNK_SIZE};
use ant_retrieval::DiskChunkCache;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Chunks per `put_batch` (single WAL commit / transaction). Larger batches
/// reduce commit count during cold fill; 8k ≈ one transaction per ~33 MiB wire.
const POPULATE_BATCH: usize = 8192;

#[tokio::main(flavor = "multi_thread", worker_threads = 32)]
async fn main() {
    let base = std::env::var("LITTER_BENCH_DIR")
        .map_or_else(|_| PathBuf::from("/tmp/litter_bench"), PathBuf::from);

    let mut files = Vec::new();
    collect_files(&base, &mut files).expect("walk litter bench dir");

    if files.is_empty() {
        eprintln!(
            "no files under {} — download site assets from litter-ally.eth.limo into this directory",
            base.display()
        );
        std::process::exit(2);
    }

    let mut addrs = Vec::new();
    let mut total_source = 0u64;
    for path in &files {
        let data = std::fs::read(path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        });
        total_source += data.len() as u64;
        for chunk in data.chunks(CHUNK_SIZE) {
            let (addr, wire) = cac_new(chunk).expect("cac_new");
            addrs.push((addr, wire));
        }
    }

    let n = addrs.len();
    let total_wire: u64 = addrs.iter().map(|(_, w)| w.len() as u64).sum();
    println!(
        "source files: {}, source bytes: {:.2} MiB, CAC chunks: {}, wire bytes: {:.2} MiB",
        files.len(),
        total_source as f64 / (1024.0 * 1024.0),
        n,
        total_wire as f64 / (1024.0 * 1024.0),
    );

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ant_disk.sqlite");
    let cache = Arc::new(DiskChunkCache::open(&db, 16 * 1024 * 1024 * 1024).unwrap());

    println!("populating SQLite disk cache (put_batch ×{POPULATE_BATCH})...");
    let t0 = Instant::now();
    for chunk in addrs.chunks(POPULATE_BATCH) {
        let batch: Vec<([u8; 32], Vec<u8>)> = chunk.iter().map(|(a, w)| (*a, w.clone())).collect();
        cache.put_batch(batch).await.unwrap();
    }
    println!(
        "populate {} chunks in {:.2}s",
        n,
        t0.elapsed().as_secs_f64()
    );

    let addr_only: Vec<[u8; 32]> = addrs.iter().map(|(a, _)| *a).collect();
    drop(addrs);

    for k in [1usize, 2, 4, 8, 16, 32, 64] {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hits = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::with_capacity(k);
        let dur = Duration::from_secs(3);
        let started = Instant::now();
        for ti in 0..k {
            let cache = cache.clone();
            let stop = stop.clone();
            let hits = hits.clone();
            let addr_only = addr_only.clone();
            tasks.push(tokio::spawn(async move {
                let mut idx = ti;
                while !stop.load(Ordering::Relaxed) {
                    let a = addr_only[idx % addr_only.len()];
                    idx = idx.wrapping_add(1);
                    if cache.get(a).await.unwrap().is_some() {
                        hits.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        tokio::time::sleep(dur).await;
        stop.store(true, Ordering::Relaxed);
        for t in tasks {
            let _ = t.await;
        }
        let elapsed = started.elapsed();
        let total = hits.load(Ordering::Relaxed);
        let ops = total as f64 / elapsed.as_secs_f64();
        let mb_s = (ops * (total_wire as f64 / n as f64)) / (1024.0 * 1024.0);
        println!(
            "K={k:>2} ant DiskChunkCache: {ops:>10.0} ops/s  (~{mb_s:>6.1} MiB/s chunk wire throughput)",
        );
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if dir.is_file() {
        out.push(dir.to_path_buf());
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, out)?;
        } else {
            out.push(p);
        }
    }
    Ok(())
}
