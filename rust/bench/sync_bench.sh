#!/usr/bin/env bash
# Rust-vs-JVM light-client benchmark gate (plan phase-1 exit criterion).
#
# Measures, for each engine, a COLD sync of mainnet from the embedded checkpoint
# to SYNCED: wall-time, peak RSS, and steady-state RSS/CPU. Correctness (same
# verified state) is already pinned cryptographically by the conformance corpus
# (rust/testdata/lc/mainnet, replayed by BOTH engines) — this script measures
# only the numbers the "is Rust worth it" decision needs.
#
# Two framings, both reported:
#   (a) in-host  — the JVM daemon with -Pengine=java vs -Pengine=rust. This is the
#                  real deployment shape (Rust engine = JNI lib inside the JVM);
#                  the delta is what swapping the engine buys the host process.
#   (b) native   — the pure-Rust examples/live_sync binary (no JVM) vs the Java
#                  daemon. The intrinsic engine footprint — the ceiling of what a
#                  pure-native shell (future iOS/NM-host) could save.
#
# Usage: rust/bench/sync_bench.sh [java|rust|native|all]   (default: all)
# Output: appends a markdown row to docs/reimplementation/benchmarks.md and prints
# a summary. Peer-bound: a single run is noisy (8-18 min observed); run 2-3x per
# engine at similar hours for a fair read.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
WHICH="${1:-all}"
DEADLINE_S=1500   # 25 min hard cap per run
POLL_S=15

# --- helpers ---------------------------------------------------------------
now_ms() { date +%s%3N; }

# Sample RSS (KiB) of a pid tree (the process + children — the JVM spawns none
# relevant, the daemon is one JVM; the native binary is one process).
rss_kib() { ps -o rss= -p "$1" 2>/dev/null | awk '{s+=$1} END {print s+0}'; }
cpu_s()   { ps -o time= -p "$1" 2>/dev/null | awk -F: '{print ($1*3600)+($2*60)+$3}'; }

purge_state() {
  ./gradlew :app:run -Pargs=purge-cache >/dev/null 2>&1 || true
  # The daemon's working dir is the :app module, so the LC snapshot lives there.
  # Deleting it forces a genuine COLD sync from the embedded checkpoint.
  find "$REPO/app" -maxdepth 1 -name "sync-state.snapshot*" -delete 2>/dev/null || true
}

# The daemon JVM is the one launched with logback-daemon.xml; every -Pargs client
# invocation uses logback-client.xml, so this never races onto a transient client.
daemon_pid() { pgrep -f "logback-daemon.xml" | head -1; }

# Run one daemon-hosted engine (java|rust) to SYNCED; echo "wall_s peak_rss_kib steady_rss_kib cpu_s finalizedSlot finalizedPeriod"
bench_daemon() {
  local engine="$1"
  local log="/tmp/bench-$engine.log"
  # Guard against a stale daemon from a prior/other run — otherwise daemon_pid()
  # could sample its RSS/CPU instead of ours.
  if [ -n "$(daemon_pid)" ]; then
    ./gradlew :app:run -Pargs=stop >/dev/null 2>&1 || true
    sleep 3
    [ -n "$(daemon_pid)" ] && { echo "FAIL stale-daemon-running (stop it first)"; return 1; }
  fi
  purge_state
  ./gradlew :app:run -Pengine="$engine" >"$log" 2>&1 &
  local gradle_pid=$!
  # Find the daemon JVM (the JavaExec fork), not the gradle launcher.
  local jvm_pid="" t0 peak=0
  t0=$(now_ms)
  for _ in $(seq 1 40); do
    jvm_pid=$(daemon_pid)
    [ -n "$jvm_pid" ] && break
    sleep 1
  done
  [ -z "$jvm_pid" ] && { echo "FAIL no-jvm"; kill $gradle_pid 2>/dev/null; return 1; }

  local deadline=$(( $(date +%s) + DEADLINE_S )) state="" fslot=0 fperiod=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local r; r=$(rss_kib "$jvm_pid"); [ "$r" -gt "$peak" ] && peak=$r
    local js; js=$(./gradlew :app:run -Pargs=beacon-status 2>/dev/null | grep -oE '\{.*\}' | head -1)
    state=$(echo "$js" | grep -oE '"state":"[A-Z_]+"' | cut -d'"' -f4)
    if [ "$state" = "SYNCED" ]; then
      fslot=$(echo "$js" | grep -oE '"finalizedSlot":[0-9]+' | cut -d: -f2)
      fperiod=$(echo "$js" | grep -oE '"finalizedPeriod":[0-9]+' | cut -d: -f2)
      break
    fi
    sleep "$POLL_S"
  done
  local wall_s=$(( ($(now_ms) - t0) / 1000 ))
  local steady_rss cpu
  steady_rss=$(rss_kib "$jvm_pid"); cpu=$(cpu_s "$jvm_pid")
  ./gradlew :app:run -Pargs=stop >/dev/null 2>&1 || true
  sleep 3; kill $gradle_pid 2>/dev/null
  if [ "$state" != "SYNCED" ]; then
    echo "TIMEOUT state=$state wall_s=$wall_s"
    return 1
  fi
  echo "$wall_s $peak $steady_rss $cpu $fslot $fperiod"
}

# Pure-Rust native binary to SYNCED; echo "wall_s peak_rss_kib steady_rss_kib cpu_s"
bench_native() {
  local bin="$REPO/rust/target/release/examples/live_sync"
  local log="/tmp/bench-native.log"
  [ -x "$bin" ] || { echo "FAIL no-binary (cargo build --release -p myotis-net --examples)"; return 1; }
  RUST_LOG=info "$bin" >"$log" 2>&1 &   # runs until SYNCED (not --once, so we can sample steady state)
  local pid=$! t0 peak=0
  t0=$(now_ms)
  local deadline=$(( $(date +%s) + DEADLINE_S ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    kill -0 "$pid" 2>/dev/null || break
    local r; r=$(rss_kib "$pid"); [ "$r" -gt "$peak" ] && peak=$r
    grep -qa "state=SYNCED" "$log" && break
    sleep "$POLL_S"
  done
  local wall_s=$(( ($(now_ms) - t0) / 1000 ))
  local steady_rss cpu
  steady_rss=$(rss_kib "$pid"); cpu=$(cpu_s "$pid")
  # let it idle a moment at steady state, then stop
  kill "$pid" 2>/dev/null
  grep -qa "state=SYNCED" "$log" || { echo "TIMEOUT wall_s=$wall_s"; return 1; }
  echo "$wall_s $peak $steady_rss $cpu"
}

echo "=== Myotis sync benchmark ($(date -u +%FT%TZ)) ==="
for e in java rust; do
  case "$WHICH" in all|"$e") ;; *) continue ;; esac
  echo "--- daemon engine=$e (cold sync) ---"
  out=$(bench_daemon "$e") && \
    printf "engine=%s wall=%ss peakRSS=%sMiB steadyRSS=%sMiB cpu=%ss finalizedSlot=%s period=%s\n" \
      "$e" $(echo "$out" | awk '{printf "%d %d %d %d %d %d", $1, $2/1024, $3/1024, $4, $5, $6}') \
    || echo "engine=$e: $out"
done
if [ "$WHICH" = all ] || [ "$WHICH" = native ]; then
  echo "--- native pure-Rust (cold sync) ---"
  out=$(bench_native) && \
    printf "native wall=%ss peakRSS=%sMiB steadyRSS=%sMiB cpu=%ss\n" \
      $(echo "$out" | awk '{printf "%d %d %d %d", $1, $2/1024, $3/1024, $4}') \
    || echo "native: $out"
fi
