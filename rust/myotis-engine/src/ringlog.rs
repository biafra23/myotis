//! Drainable ring buffer for the engine's `tracing` output — the on-device
//! observability seam (notes gap #2): the engine initializes no platform
//! logger, so on Android every `tracing` line was invisible; every incident so
//! far (discv5 wedge, snapshot deletion) had to be diagnosed blind. Hosts poll
//! [`drain`] over JNI (`nativeDrainLogs`) and feed the lines into their own
//! pipeline (Android `LogBuffer` → Logs tab + logcat; desktop → slf4j).
//!
//! A pull-based ring (not a platform appender) keeps the crate free of
//! Android-specific dependencies, needs no JNI upcalls, and bounds memory:
//! oldest lines drop when the ring is full — losing old debug lines is better
//! than growing without bound on a phone. Panic-free by construction (a
//! poisoned lock silently degrades to dropping lines, never aborts the app).

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Ring capacity — matches the spirit of the Android LogBuffer's bounded ring;
/// at typical sync-loop verbosity (~10 lines/min steady state) this holds
/// hours, and a 5 s host drain cadence never comes close to filling it.
const CAPACITY: usize = 4096;

static RING: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

fn ring() -> &'static Mutex<VecDeque<String>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(256)))
}

/// Install the global tracing subscriber writing into the ring. Idempotent:
/// repeated calls (e.g. a second `Engines.select`) are no-ops — `try_init`
/// simply fails if a global subscriber is already set, and that is fine.
pub fn init() {
    // Engine-owned crates at info; the dependency stack capped at warn so
    // network churn (libp2p session events, discv5 chatter) can't dilute
    // the ring/Logs tab or push out incident lines. RUST_LOG overrides
    // when set (desktop debugging); Android has no env — the default rules.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(
            "info,discv5=warn,libp2p=warn,libp2p_swarm=warn,libp2p_identify=warn,\
             yamux=warn,multistream_select=warn,netlink_proto=warn",
        ));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| RingWriter)
        .with_ansi(false)
        .with_target(true)
        .without_time() // hosts stamp arrival time; epoch-relative uptime is noise
        .try_init();
}

/// Drain up to `max` buffered lines, oldest first, newline-joined. Empty string
/// when nothing is buffered. Cheap to call on a poll loop.
pub fn drain(max: usize) -> String {
    let Ok(mut ring) = ring().lock() else {
        return String::new();
    };
    let n = ring.len().min(max);
    if n == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(n * 96);
    for _ in 0..n {
        // n <= len is checked above; pop_front can't fail here.
        if let Some(line) = ring.pop_front() {
            out.push_str(&line);
            out.push('\n');
        }
    }
    // Drop the trailing newline so the Java side can split('\n') cleanly.
    out.pop();
    out
}

/// `tracing_subscriber::fmt` writer: one `write` call per formatted event.
struct RingWriter;

impl Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        let trimmed = line.trim_end();
        if !trimmed.is_empty() {
            if let Ok(mut ring) = ring().lock() {
                if ring.len() >= CAPACITY {
                    ring.pop_front(); // oldest-out — bounded memory beats history
                }
                ring.push_back(trimmed.to_string());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test for the ring, written to survive company: the ring is a
    /// process-global (that's the point — one drain surface per engine), and
    /// the crate's test binary runs every #[test] in parallel threads, one of
    /// which (`capi::tests`, `myotis_init()`) installs the global tracing
    /// subscriber that writes into THIS ring. From that moment every tracing
    /// event any other test emits lands here too, interleaved with the lines
    /// below — so the assertions are about our own lines' order and the
    /// ring's bound, never about the ring holding exactly what we wrote
    /// (that version failed in CI whenever the scheduler let a foreign line
    /// in: run 35075614985, where one foreign entry evicted one extra line of
    /// ours and `drain(1)` returned "line 11"). It does assume no other test
    /// DRAINS the ring — nothing calls the drain FFI today; a test of that
    /// would have to serialize with this one.
    #[test]
    fn drains_oldest_first_bounded_and_empties() {
        // Write directly through the writer (installing the global subscriber
        // in tests would race other tests' tracing setup).
        let _ = drain(usize::MAX); // start from our own clean slate
        let mut w = RingWriter;
        w.write_all(b"first line\n").unwrap();
        w.write_all(b"second line\n").unwrap();
        let batch = drain(usize::MAX);
        let first = batch.find("first line").expect("first line drained");
        let second = batch.find("second line").expect("second line drained");
        assert!(first < second, "oldest first: {batch}");
        assert!(
            !batch.ends_with('\n'),
            "no trailing newline — the Java side splits on '\\n'"
        );
        assert!(
            !drain(usize::MAX).contains("first line"),
            "a drained line must not come back"
        );

        // Overflow the ring by 10 of our own lines: the oldest 10 (at least —
        // foreign lines can push out more of ours, never fewer) must be gone,
        // the newest must be there, and the ring must never hold more than
        // CAPACITY lines in total.
        for i in 0..(CAPACITY + 10) {
            w.write_all(format!("line {i}\n").as_bytes()).unwrap();
        }
        // The bound, checked on the ring itself: counting lines of the drained
        // string would miscount a foreign entry that carried an embedded
        // newline (the writer stores one entry per event, newlines and all).
        assert!(
            ring().lock().unwrap().len() <= CAPACITY,
            "the ring is bounded at CAPACITY"
        );
        let drained = drain(usize::MAX);
        let ours: Vec<usize> = drained
            .lines()
            .filter_map(|l| l.strip_prefix("line ").and_then(|n| n.parse().ok()))
            .collect();
        assert!(!ours.is_empty(), "our lines drained: {drained}");
        assert!(*ours.iter().min().unwrap() >= 10, "oldest 10 lines must have dropped: {ours:?}");
        assert_eq!(*ours.iter().max().unwrap(), CAPACITY + 9, "newest line kept");
        assert!(ours.windows(2).all(|p| p[0] < p[1]), "oldest first, in write order");
        let _ = drain(usize::MAX);
    }
}
