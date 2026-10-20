//! Data usage per handle: today's bytes in and out, how much of it went over
//! a metered network, and the network's current metering as the host reported
//! it (docs/data-usage.md).
//!
//! The byte counts come from the handle's [`TrafficMeter`]
//! (`myotis_net::traffic`), which only ever grows. A [`UsageLedger`] turns it
//! into per-day figures: each [`UsageLedger::tick`] adds the meter's growth
//! since the previous tick to the current LOCAL day, and to that day's metered
//! figures too when the host's last word was "metered". A tick runs on every
//! status read, every minute in the background, before a metering change
//! (so the bytes before it keep their old label), and at pause and stop.
//!
//! Today's figures survive a restart: the ledger keeps them in
//! `data-usage[-net].json` beside the handle's sync snapshot and picks them up
//! again when it is created on the same day. A previous day's file is ignored.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use myotis_net::traffic::{TrafficMeter, TrafficSnapshot};

/// The host's word on the network the device is on now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Metering {
    /// Never reported (the daemon, a host that does not know).
    #[default]
    Unknown = 0,
    /// Wi-Fi, Ethernet: no per-byte cost.
    Unmetered = 1,
    /// Cellular, a hotspot, or anything the OS marks as costly.
    Metered = 2,
}

impl Metering {
    pub fn from_code(code: i32) -> Option<Metering> {
        match code {
            0 => Some(Metering::Unknown),
            1 => Some(Metering::Unmetered),
            2 => Some(Metering::Metered),
            _ => None,
        }
    }

    /// The API's `NetworkMetering` constant name.
    pub fn as_str(self) -> &'static str {
        match self {
            Metering::Unknown => "UNKNOWN",
            Metering::Unmetered => "UNMETERED",
            Metering::Metered => "METERED",
        }
    }
}

static METERING: AtomicU8 = AtomicU8::new(Metering::Unknown as u8);

/// The metering the host reported last (engine-wide: it is the device's
/// network, not a chain's).
pub fn metering() -> Metering {
    Metering::from_code(METERING.load(Ordering::Relaxed) as i32).unwrap_or(Metering::Unknown)
}

/// Record the host's report. The caller ticks every ledger FIRST, so bytes
/// moved before the change are labelled by the old state.
pub fn set_metering(m: Metering) {
    METERING.store(m as u8, Ordering::Relaxed);
}

/// One day's figures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DayTotals {
    pub rx: u64,
    pub tx: u64,
    pub metered_rx: u64,
    pub metered_tx: u64,
}

/// What a status read reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageSnapshot {
    /// The meter's totals: everything since the handle was created.
    pub session: TrafficSnapshot,
    /// The local day `today` covers (`YYYY-MM-DD`).
    pub day: String,
    pub today: DayTotals,
}

struct LedgerState {
    /// The meter's totals at the last tick.
    seen: TrafficSnapshot,
    day: String,
    today: DayTotals,
    /// Changed since the file was last written.
    dirty: bool,
    last_write: Option<Instant>,
}

/// One handle's day ledger (module docs).
pub struct UsageLedger {
    meter: Arc<TrafficMeter>,
    /// `data-usage[-net].json`; None = memory only (no dataDir).
    path: Option<PathBuf>,
    state: Mutex<LedgerState>,
}

/// How often a busy ledger writes its file at most, outside pause, stop and a
/// new day. A crash loses at most this much accounting.
const WRITE_EVERY: Duration = Duration::from_secs(5 * 60);

impl UsageLedger {
    /// A ledger over `meter`, resuming today's figures from `path` when the
    /// file is today's. Everything the meter already counted is treated as
    /// accounted for (a fresh handle's meter is at zero).
    pub fn open(meter: Arc<TrafficMeter>, path: Option<PathBuf>) -> UsageLedger {
        Self::open_on(meter, path, &local_day_now())
    }

    fn open_on(meter: Arc<TrafficMeter>, path: Option<PathBuf>, day: &str) -> UsageLedger {
        let today = path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| parse_file(&s))
            .filter(|(d, _)| d == day)
            .map(|(_, t)| t)
            .unwrap_or_default();
        UsageLedger {
            state: Mutex::new(LedgerState {
                seen: meter.snapshot(),
                day: day.to_string(),
                today,
                dirty: false,
                last_write: None,
            }),
            meter,
            path,
        }
    }

    /// Account the meter's growth to today (module docs) and write the file
    /// when `force`, on a new day, or when [`WRITE_EVERY`] has passed.
    pub fn tick(&self, force: bool) -> UsageSnapshot {
        self.tick_on(&local_day_now(), metering(), force)
    }

    fn tick_on(&self, day: &str, metering: Metering, force: bool) -> UsageSnapshot {
        // The snapshot is taken under the lock: two ticks racing (the minute
        // ticker and a status read) must apply theirs in order, or `seen` could
        // step back and the bytes in between be counted twice.
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.meter.snapshot();
        let rx = now.rx().saturating_sub(st.seen.rx());
        let tx = now.tx().saturating_sub(st.seen.tx());
        st.seen = now;
        let new_day = st.day != day;
        if new_day {
            // The growth since the last tick lands on the new day: ticks are a
            // minute apart, so at most a minute's bytes cross midnight.
            st.day = day.to_string();
            st.today = DayTotals::default();
            st.dirty = true;
        }
        if rx > 0 || tx > 0 {
            st.today.rx = st.today.rx.saturating_add(rx);
            st.today.tx = st.today.tx.saturating_add(tx);
            if metering == Metering::Metered {
                st.today.metered_rx = st.today.metered_rx.saturating_add(rx);
                st.today.metered_tx = st.today.metered_tx.saturating_add(tx);
            }
            st.dirty = true;
        }
        let due = st.last_write.is_none_or(|t| t.elapsed() >= WRITE_EVERY);
        if st.dirty && (force || new_day || due) {
            if let Some(path) = &self.path {
                match write_file(path, &st.day, st.today) {
                    Ok(()) => {
                        st.dirty = false;
                        st.last_write = Some(Instant::now());
                    }
                    Err(e) => tracing::debug!(path = %path.display(), error = %e, "data-usage write failed"),
                }
            }
        }
        UsageSnapshot { session: now, day: st.day.clone(), today: st.today }
    }
}

fn parse_file(s: &str) -> Option<(String, DayTotals)> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    if v.get("version")?.as_u64()? != 1 {
        return None;
    }
    let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
    Some((
        v.get("day")?.as_str()?.to_string(),
        DayTotals {
            rx: n("bytesIn")?,
            tx: n("bytesOut")?,
            metered_rx: n("meteredBytesIn")?,
            metered_tx: n("meteredBytesOut")?,
        },
    ))
}

/// Write via a synced temp file + rename, so a crash mid-write leaves the old
/// file. (The directory is not synced: a power loss right after can still lose
/// the rename, and a damaged file is ignored — today restarts from zero. These
/// are display figures, not state.)
fn write_file(path: &std::path::Path, day: &str, t: DayTotals) -> std::io::Result<()> {
    let body = serde_json::json!({
        "version": 1,
        "day": day,
        "bytesIn": t.rx,
        "bytesOut": t.tx,
        "meteredBytesIn": t.metered_rx,
        "meteredBytesOut": t.metered_tx,
    })
    .to_string();
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Today's date in the device's time zone, `YYYY-MM-DD`.
pub fn local_day_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    local_day(secs)
}

/// `epoch_secs` as a local date (`localtime_r`, so the C library's notion of
/// the zone: `TZ`, `/etc/localtime`, Android's `persist.sys.timezone`, the iOS
/// system zone). UTC where that fails or there is no C library to ask.
fn local_day(epoch_secs: i64) -> String {
    #[cfg(unix)]
    {
        let t = epoch_secs as libc::time_t;
        // SAFETY: `tm` is plain old data, fully written by a successful
        // localtime_r, which reads only `t` and is thread-safe.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        }
    }
    utc_day(epoch_secs)
}

/// `epoch_secs` as a UTC date (Howard Hinnant's `civil_from_days`).
fn utc_day(epoch_secs: i64) -> String {
    let z = epoch_secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("myotis-usage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn utc_day_matches_known_dates() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(951_782_400), "2000-02-29");
        assert_eq!(utc_day(1_792_454_399), "2026-10-19");
        assert_eq!(utc_day(1_792_454_400), "2026-10-20");
        assert_eq!(utc_day(-1), "1969-12-31");
    }

    #[test]
    fn growth_lands_on_today_and_metered_only_while_metered() {
        let meter = TrafficMeter::new();
        let ledger = UsageLedger::open_on(Arc::clone(&meter), None, "2026-10-20");
        meter.el.add_rx(100);
        meter.cl.add_tx(40);
        let s = ledger.tick_on("2026-10-20", Metering::Unmetered, false);
        assert_eq!(s.today, DayTotals { rx: 100, tx: 40, metered_rx: 0, metered_tx: 0 });
        meter.cl.add_rx(7);
        meter.el.add_tx(3);
        let s = ledger.tick_on("2026-10-20", Metering::Metered, false);
        assert_eq!(s.today, DayTotals { rx: 107, tx: 43, metered_rx: 7, metered_tx: 3 });
        assert_eq!((s.session.rx(), s.session.tx()), (107, 43));
        // Unknown is not metered.
        meter.el.add_rx(1);
        let s = ledger.tick_on("2026-10-20", Metering::Unknown, false);
        assert_eq!(s.today.metered_rx, 7);
        assert_eq!(s.today.rx, 108);
    }

    #[test]
    fn a_new_day_starts_from_zero_but_the_session_keeps_counting() {
        let meter = TrafficMeter::new();
        let ledger = UsageLedger::open_on(Arc::clone(&meter), None, "2026-10-20");
        meter.el.add_rx(500);
        ledger.tick_on("2026-10-20", Metering::Metered, false);
        meter.el.add_rx(20);
        let s = ledger.tick_on("2026-10-21", Metering::Metered, false);
        assert_eq!(s.day, "2026-10-21");
        assert_eq!(s.today, DayTotals { rx: 20, tx: 0, metered_rx: 20, metered_tx: 0 });
        assert_eq!(s.session.rx(), 520);
    }

    #[test]
    fn todays_figures_survive_a_reopen_and_yesterdays_do_not() {
        let dir = tmpdir("reopen");
        let path = dir.join("data-usage.json");
        let meter = TrafficMeter::new();
        let ledger = UsageLedger::open_on(Arc::clone(&meter), Some(path.clone()), "2026-10-20");
        meter.cl.add_rx(1000);
        meter.cl.add_tx(10);
        ledger.tick_on("2026-10-20", Metering::Metered, true);

        // Same day, new handle (fresh meter): resumes.
        let meter2 = TrafficMeter::new();
        let again = UsageLedger::open_on(Arc::clone(&meter2), Some(path.clone()), "2026-10-20");
        meter2.el.add_tx(5);
        let s = again.tick_on("2026-10-20", Metering::Unmetered, false);
        assert_eq!(s.today, DayTotals { rx: 1000, tx: 15, metered_rx: 1000, metered_tx: 10 });
        assert_eq!(s.session.tx(), 5, "the session is this handle's alone");

        // Next day: the file is yesterday's.
        let fresh = UsageLedger::open_on(TrafficMeter::new(), Some(path.clone()), "2026-10-21");
        let s = fresh.tick_on("2026-10-21", Metering::Unknown, false);
        assert_eq!(s.today, DayTotals::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_are_batched_unless_forced_or_a_new_day() {
        let dir = tmpdir("batch");
        let path = dir.join("data-usage-gnosis.json");
        let meter = TrafficMeter::new();
        let ledger = UsageLedger::open_on(Arc::clone(&meter), Some(path.clone()), "2026-10-20");
        meter.el.add_rx(1);
        ledger.tick_on("2026-10-20", Metering::Unknown, false); // first write is due
        assert_eq!(parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap().1.rx, 1);
        meter.el.add_rx(1);
        ledger.tick_on("2026-10-20", Metering::Unknown, false); // within WRITE_EVERY: held
        assert_eq!(parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap().1.rx, 1);
        ledger.tick_on("2026-10-20", Metering::Unknown, true); // forced (pause/stop)
        assert_eq!(parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap().1.rx, 2);
        meter.el.add_rx(4);
        ledger.tick_on("2026-10-21", Metering::Unknown, false); // new day: written
        let (day, t) = parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!((day.as_str(), t.rx), ("2026-10-21", 4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_java_ledgers_file_reads_here() {
        // Byte-for-byte what the Java engine's DataUsageLedger writes: the two
        // engines share the file across an engine switch.
        let java = r#"{"version":1,"day":"2026-10-20","bytesIn":12,"bytesOut":3,"meteredBytesIn":2,"meteredBytesOut":1}"#;
        assert_eq!(
            parse_file(java),
            Some(("2026-10-20".to_string(), DayTotals { rx: 12, tx: 3, metered_rx: 2, metered_tx: 1 }))
        );
    }

    #[test]
    fn a_damaged_file_is_ignored() {
        assert!(parse_file("not json").is_none());
        assert!(parse_file(r#"{"version":2,"day":"2026-10-20","bytesIn":1,"bytesOut":1,"meteredBytesIn":0,"meteredBytesOut":0}"#).is_none());
        assert!(parse_file(r#"{"version":1,"day":"2026-10-20","bytesIn":1}"#).is_none());
    }

    #[test]
    fn metering_codes_round_trip() {
        for m in [Metering::Unknown, Metering::Unmetered, Metering::Metered] {
            assert_eq!(Metering::from_code(m as i32), Some(m));
        }
        assert_eq!(Metering::from_code(3), None);
        assert_eq!(Metering::from_code(-1), None);
    }
}
