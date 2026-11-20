//! Compares [`DiskCacheTuning`] profiles on one cache file larger than
//! the old desktop profile's 512 MiB mapping: random `get` throughput and
//! latency at several concurrency levels, plus how much address space
//! (`vsz`) and resident memory (`rss`) the open cache adds to the
//! process. On macOS it also reports the footprint: dirty memory, the
//! figure Activity Monitor shows and iOS's memory limit counts, which
//! leaves out the clean file pages `rss` includes for the mappings.
//!
//! ```text
//! BENCH_DB=/tmp/tuning_bench.sqlite BENCH_CHUNKS=262144 \
//!   cargo run --release --example disk_cache_tuning_bench -p ant-retrieval
//! ```
//!
//! `BENCH_DB` is kept between runs, so only the first run populates it
//! (`BENCH_CHUNKS` 4 KiB chunks; the default, 262 144, is about 1 GiB).
//! `BENCH_SECS` sets how long each concurrency level runs (default 3),
//! and `BENCH_ONLY` runs only the profiles whose name contains it.

use ant_crypto::cac_new;
use ant_retrieval::{DiskCacheTuning, DiskChunkCache};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let db = std::env::var("BENCH_DB").map_or_else(
        |_| std::env::temp_dir().join("ant_tuning_bench.sqlite"),
        PathBuf::from,
    );
    let chunks: usize = std::env::var("BENCH_CHUNKS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(262_144);
    let secs: u64 = std::env::var("BENCH_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let only = std::env::var("BENCH_ONLY").unwrap_or_default();

    let addrs: Arc<[[u8; 32]]> = populate(&db, chunks).await.into();
    let file_mib = std::fs::metadata(&db).map_or(0, |m| m.len()) / MIB;
    println!("{} chunks, file {file_mib} MiB", addrs.len());

    let profiles = [
        // The desktop tuning before #152, kept as the reference point.
        (
            "old desktop",
            DiskCacheTuning {
                read_workers: std::thread::available_parallelism()
                    .map_or(8, std::num::NonZero::get)
                    .clamp(8, 32),
                mmap_bytes: 512 * MIB,
                page_cache_bytes: 256 * MIB,
            },
        ),
        ("default", DiskCacheTuning::DEFAULT),
        (
            "default, 4 readers",
            DiskCacheTuning {
                read_workers: 4,
                ..DiskCacheTuning::DEFAULT
            },
        ),
        (
            "default, 64 MiB mmap",
            DiskCacheTuning {
                mmap_bytes: 64 * MIB,
                ..DiskCacheTuning::DEFAULT
            },
        ),
        (
            "default, 2 MiB page cache",
            DiskCacheTuning {
                page_cache_bytes: 2 * MIB,
                ..DiskCacheTuning::DEFAULT
            },
        ),
    ];
    for (name, tuning) in profiles {
        if !name.contains(only.as_str()) {
            continue;
        }
        let before = mem_kib();
        let cache = Arc::new(DiskChunkCache::open_with_tuning(&db, u64::MAX, tuning).unwrap());
        // Let the writer's startup backfill finish so it doesn't compete.
        while cache.used_rows() == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        run(&cache, &addrs, 16, Duration::from_secs(1)).await;
        println!("\n{name}: {tuning:?}");
        for k in [1usize, 4, 16, 64] {
            let (ops, p50, p99) = run(&cache, &addrs, k, Duration::from_secs(secs)).await;
            println!(
                "  K={k:>2}: {ops:>8.0} gets/s  p50 {p50:>6.1} µs  p99 {p99:>7.1} µs  \
                 ({:.0} MiB/s)",
                ops * 4104.0 / MIB as f64
            );
        }
        let after = mem_kib();
        println!(
            "  open cache adds: vsz {:+} MiB, rss {:+} MiB, footprint {}",
            (after.0 - before.0) / 1024,
            (after.1 - before.1) / 1024,
            match (before.2, after.2) {
                (Some(b), Some(a)) => format!("{:+} MiB", (a - b) / 1024),
                _ => "n/a".to_owned(),
            }
        );
        drop(cache);
    }
}

/// Fill `db` with `n` distinct chunks unless it already holds them, and
/// return their addresses in a shuffled order.
async fn populate(db: &PathBuf, n: usize) -> Vec<[u8; 32]> {
    let mut addrs = Vec::with_capacity(n);
    let fresh = !db.exists();
    let cache = fresh.then(|| DiskChunkCache::open(db, u64::MAX).unwrap());
    let started = Instant::now();
    let mut batch = Vec::with_capacity(8192);
    for i in 0..n {
        let mut payload = vec![0u8; 4096];
        for (j, b) in payload.iter_mut().enumerate() {
            *b = (i.wrapping_mul(31).wrapping_add(j * 7) >> (j % 13)) as u8;
        }
        payload[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let (addr, wire) = cac_new(&payload).unwrap();
        addrs.push(addr);
        if let Some(cache) = &cache {
            batch.push((addr, wire));
            if batch.len() == 8192 {
                cache.put_batch(std::mem::take(&mut batch)).await.unwrap();
            }
        }
    }
    if let Some(cache) = cache {
        if !batch.is_empty() {
            cache.put_batch(batch).await.unwrap();
        }
        drop(cache);
        println!("populated in {:.1}s", started.elapsed().as_secs_f64());
    }
    // Deterministic shuffle (xorshift) so reads land on random pages.
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    for i in (1..addrs.len()).rev() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        addrs.swap(i, (s % (i as u64 + 1)) as usize);
    }
    addrs
}

/// `k` tasks doing back-to-back `get`s for `dur`: (gets/s, p50 µs, p99 µs).
async fn run(
    cache: &Arc<DiskChunkCache>,
    addrs: &Arc<[[u8; 32]]>,
    k: usize,
    dur: Duration,
) -> (f64, f64, f64) {
    let stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(k);
    for t in 0..k {
        let (cache, addrs, stop) = (cache.clone(), addrs.clone(), stop.clone());
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            let mut i = t * 7919;
            while !stop.load(Ordering::Relaxed) {
                let a = addrs[i % addrs.len()];
                i += k;
                let t0 = Instant::now();
                assert!(cache.get(a).await.unwrap().is_some());
                lat.push(t0.elapsed().as_secs_f64() * 1e6);
            }
            lat
        }));
    }
    tokio::time::sleep(dur).await;
    stop.store(true, Ordering::Relaxed);
    let mut lat = Vec::new();
    for t in tasks {
        lat.extend(t.await.unwrap());
    }
    let ops = lat.len() as f64 / started.elapsed().as_secs_f64();
    lat.sort_by(f64::total_cmp);
    let pct = |p: f64| lat[((lat.len() - 1) as f64 * p) as usize];
    (ops, pct(0.5), pct(0.99))
}

/// This process's (vsz, rss, footprint) in KiB: the first two from
/// `ps`, the footprint from macOS's `footprint` (`None` elsewhere).
fn mem_kib() -> (i64, i64, Option<i64>) {
    let pid = std::process::id().to_string();
    let out = std::process::Command::new("ps")
        .args(["-o", "vsz=,rss=", "-p", &pid])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut it = text.split_whitespace().map(|v| v.parse().unwrap_or(0));
    let (vsz, rss) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    // "zsh [5295]: 64-bit    Footprint: 2096 KB (16384 bytes per page)"
    let footprint = std::process::Command::new("footprint")
        .arg(&pid)
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let rest = text.split("Footprint: ").nth(1)?.to_owned();
            let mut words = rest.split_whitespace();
            let n: f64 = words.next()?.parse().ok()?;
            let unit = match words.next()? {
                "B" => 1.0 / 1024.0,
                "KB" => 1.0,
                "MB" => 1024.0,
                "GB" => 1024.0 * 1024.0,
                _ => return None,
            };
            Some((n * unit) as i64)
        });
    (vsz, rss, footprint)
}
