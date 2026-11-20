//! Standalone throughput probe for `DiskChunkCache`. Pre-populates a
//! cache with a few thousand 4-KiB chunks, then hammers it from `K`
//! concurrent tasks for a fixed duration and reports the realised
//! ops/sec. Used to size the per-fetch latency budget against what
//! the daemon's joiner can keep up with — see PLAN §6.1.
//!
//! Run with:
//!
//!   cargo run --release --example `disk_cache_bench` -p ant-retrieval

use ant_crypto::cac_new;
use ant_retrieval::DiskChunkCache;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench.sqlite");
    let cache = Arc::new(DiskChunkCache::open(&path, 4 * 1024 * 1024 * 1024).unwrap());

    const N: usize = 4096;
    println!("populating {N} chunks...");
    let mut addrs = Vec::with_capacity(N);
    for i in 0..N {
        let payload = vec![(i & 0xff) as u8; 4096];
        let (addr, wire) = cac_new(&payload).unwrap();
        cache.put(addr, wire).await.unwrap();
        addrs.push(addr);
    }
    println!(
        "populated, used_bytes = {} MiB",
        cache.used_bytes() / 1024 / 1024
    );

    for k in [1usize, 4, 13, 32, 64] {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hits = Arc::new(AtomicU64::new(0));
        let dur = Duration::from_secs(2);
        let mut tasks = Vec::with_capacity(k);
        let started = Instant::now();
        for ti in 0..k {
            let cache = cache.clone();
            let stop = stop.clone();
            let hits = hits.clone();
            let addrs = addrs.clone();
            tasks.push(tokio::spawn(async move {
                let mut idx = ti;
                while !stop.load(Ordering::Relaxed) {
                    let a = addrs[idx % addrs.len()];
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
        println!(
            "K={k:>3} parallel: {total:>8} ops in {:.2}s = {:>9.0} ops/sec",
            elapsed.as_secs_f64(),
            total as f64 / elapsed.as_secs_f64(),
        );
    }
}
