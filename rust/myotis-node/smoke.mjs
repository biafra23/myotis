// Standalone smoke test for the myotis-node addon: sync mainnet from plain
// Node, then run verified reads. Usage:
//   node smoke.mjs [dataDir] [addonPath]
//
// Exit codes — a peer-starved ENVIRONMENT and a broken ENGINE must not look
// the same (#372), because a red run then sends people hunting for a
// platform bug that isn't there:
//   0  all verified reads passed
//   1  the engine answered, but a check FAILED (a real regression signal)
//   2  never reached a usable PEER SET within the gate deadline (environment).
//      Only when every unmet condition is peer-side: a node that never syncs,
//      or whose EL reader is down, is an ENGINE result and still exits 1.
//
// The readiness gate deliberately demands MORE than "one snap peer": the
// reader rotates over the snap set, so with a single peer one dud peer is
// indistinguishable from a broken engine. Tunable for constrained runners:
//   MYOTIS_SMOKE_MIN_SNAP_PEERS  (default 2)  rotation needs somewhere to go
//   MYOTIS_SMOKE_REQUIRE_DISCOVERY (default 1) discovery must have produced
//       candidates — the CL discv5 table OR the EL's discovered-peer count —
//       so a warm start restoring a stale peer cache can't open the gate
//   MYOTIS_SMOKE_TIMEOUT_MIN     (default 15) overall budget, unchanged
//   MYOTIS_SMOKE_GATE_TIMEOUT_MIN (default 15, capped by the overall budget)
//       how long to wait before calling a PEER-STARVED gate early. Engine-side
//       shortfalls always get the full MYOTIS_SMOKE_TIMEOUT_MIN — a cold
//       checkpoint catch-up takes 30-40 min and must not be cut short

import { createRequire } from 'node:module';
import {
  gateShortfall, gateConfigFromEnv, describeShortfall, isPeerStarvation,
} from './smoke-gate.mjs';
const require = createRequire(import.meta.url);

const dataDir = process.argv[2] || './.smoke-data';
const addonPath = process.argv[3] || './target/debug/myotis-node.node';
const m = require(addonPath);

let GATE;
try {
  GATE = gateConfigFromEnv();
} catch (e) {
  console.error(`bad gate configuration: ${e.message}`);
  process.exit(1);
}
const SYNC_TIMEOUT_MS = GATE.overallMinutes * 60 * 1000;
// PEER-STARVATION deadline only. It reports a peer-starved runner in minutes
// instead of at the end of the budget — but it must never shorten the wait for
// an engine-side condition: a COLD checkpoint catch-up legitimately takes
// 30-40 min, and cutting it off at 15 would call a healthy engine broken (and,
// because actions/cache only saves on success, would never warm the cache
// again — permanently red with an engine label).
const GATE_TIMEOUT_MS = Math.min(GATE.gateMinutes * 60 * 1000, SYNC_TIMEOUT_MS);
const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
/** Exit code for "the environment never gave us a usable peer set". */
const EXIT_INSUFFICIENT_PEERS = 2;

const t0 = Date.now();
const elapsed = () => ((Date.now() - t0) / 1000).toFixed(1) + 's';
const log = (...a) => console.log(`[${elapsed()}]`, ...a);

// The addon is built from this same tree, so init() always returns the
// current crate ABI_VERSION — assert it's sane and log it. Hosts loading
// PREBUILT addons instead gate on the exact value pinned in the release
// notes of the release they downloaded from.
const abi = m.init();
if (!Number.isInteger(abi) || abi < 19) {
  console.error(`unexpected engine ABI: ${abi}`);
  process.exit(1);
}
log('abi ok:', abi);

const handle = m.create('mainnet', dataDir);
if (handle < 0) {
  console.error('create failed:', handle);
  process.exit(1);
}
if (!m.start(handle)) {
  console.error('start failed');
  process.exit(1);
}
log('started handle', handle, 'dataDir', dataDir);

let lastLine = '';
const poll = setInterval(() => {
  const s = JSON.parse(m.statusJson(handle));
  const line = `beacon=${s.beaconState} peers=${s.peerCount} snapPeers=${s.snapPeers} ` +
    `discv5=${s.discv5TableSize} period=${s.currentPeriod}/${s.targetPeriod} ` +
    `finalizedSlot=${s.finalizedSlot} el=${s.elReaderAvailable}`;
  if (line !== lastLine) { log(line); lastLine = line; }
  const logs = m.drainLogs(50);
  for (const l of logs.split('\n')) {
    if (/ERROR|WARN/.test(l)) console.log('   [engine]', l);
  }
  const unmet = gateShortfall(s, GATE);
  if (unmet.length === 0) {
    clearInterval(poll);
    queries(s).catch((e) => { console.error('queries failed:', e); shutdown(1); });
  } else if (isPeerStarvation(unmet) && Date.now() - t0 > GATE_TIMEOUT_MS) {
    // ONLY pure peer starvation exits early: nothing about the node is in
    // question, so more waiting cannot change the verdict.
    clearInterval(poll);
    console.error(`TIMEOUT waiting for a usable peer set — unmet: ${describeShortfall(unmet)}`);
    console.error('INSUFFICIENT PEERS (environment, not an engine failure); last status:',
      JSON.stringify(s));
    shutdown(EXIT_INSUFFICIENT_PEERS);
  } else if (Date.now() - t0 > SYNC_TIMEOUT_MS) {
    // The full budget elapsed with something engine-side still unmet (never
    // SYNCED, EL reader down). Calling that an environment result would invert
    // the misdirection this gate exists to remove — it is an engine verdict.
    clearInterval(poll);
    console.error(`TIMEOUT waiting for readiness — unmet: ${describeShortfall(unmet)}`);
    console.error('ENGINE did not become ready (not a peer-availability result); last status:',
      JSON.stringify(s));
    shutdown(1);
  }
}, 5000);

async function timed(label, promise) {
  const q0 = Date.now();
  const raw = await promise;
  const ms = Date.now() - q0;
  const json = JSON.parse(raw);
  log(`${label} (${ms} ms):`, JSON.stringify(json).slice(0, 400));
  return json;
}

async function queries(status) {
  log(`gate open (snapPeers=${status.snapPeers}>=${GATE.minSnapPeers}, ` +
    `discv5TableSize=${status.discv5TableSize}) — running verified reads`,
    JSON.stringify(status));
  let failures = 0;

  const ens = await timed('resolve-ens vitalik.eth', m.resolveEnsJson(handle, 'vitalik.eth'));
  if (ens.addressHex?.toLowerCase() !== VITALIK.toLowerCase()) {
    console.error('ENS MISMATCH: expected', VITALIK, 'got', JSON.stringify(ens)); failures++;
  }

  const ch = await timed('contenthash vitalik.eth',
    m.ensRecordJson(handle, JSON.stringify({ method: 'contenthash', name: 'vitalik.eth' })));
  if (ch.error || ch.resolved === false) {
    console.error('contenthash failed:', JSON.stringify(ch)); failures++;
  }

  const acct = await timed('get-account vitalik', m.requestAccountJson(handle, VITALIK));
  // Rust-engine account JSON carries verification fields FLAT (unlike the
  // Java daemon's nested `verification` object on the IPC surface).
  log('verification:', JSON.stringify({
    beaconChainVerified: acct.beaconChainVerified,
    blsVerified: acct.blsVerified,
    failReason: acct.failReason,
  }));
  if (!acct.beaconChainVerified) { console.error('account NOT beacon-verified'); failures++; }

  const fees = await timed('fee-estimate', m.feeEstimateJson(handle));
  if (fees.error) { console.error('fee estimate failed'); failures++; }

  // Warm-path timing: repeat the ENS resolve now that caches are hot.
  await timed('resolve-ens (warm) vitalik.eth', m.resolveEnsJson(handle, 'vitalik.eth'));

  // Reached only with a peer set that satisfied the gate, so a failure here
  // is a statement about the ENGINE, which is the whole point of exit 1.
  log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
  shutdown(failures === 0 ? 0 : 1);
}

function shutdown(code) {
  try { m.stop(handle); } catch {}
  process.exit(code);
}
