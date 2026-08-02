// Standalone smoke test for the myotis-node addon: sync mainnet from plain
// Node, then run verified reads. Usage:
//   node smoke.mjs [dataDir] [addonPath]
// Exits 0 when all reads returned verified data, 1 on timeout/failure.

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const dataDir = process.argv[2] || './.smoke-data';
const addonPath = process.argv[3] || './target/debug/myotis-node.node';
const m = require(addonPath);

const SYNC_TIMEOUT_MS = (Number(process.env.MYOTIS_SMOKE_TIMEOUT_MIN) || 15) * 60 * 1000;
const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

const t0 = Date.now();
const elapsed = () => ((Date.now() - t0) / 1000).toFixed(1) + 's';
const log = (...a) => console.log(`[${elapsed()}]`, ...a);

const abi = m.init();
if (abi !== 19) {
  console.error(`ABI mismatch: engine ${abi}, binding written against 19`);
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
    `period=${s.currentPeriod}/${s.targetPeriod} finalizedSlot=${s.finalizedSlot} el=${s.elReaderAvailable}`;
  if (line !== lastLine) { log(line); lastLine = line; }
  const logs = m.drainLogs(50);
  for (const l of logs.split('\n')) {
    if (/ERROR|WARN/.test(l)) console.log('   [engine]', l);
  }
  if (s.beaconState === 'SYNCED' && s.elReaderAvailable && s.snapPeers > 0) {
    clearInterval(poll);
    queries(s).catch((e) => { console.error('queries failed:', e); shutdown(1); });
  } else if (Date.now() - t0 > SYNC_TIMEOUT_MS) {
    console.error('TIMEOUT waiting for SYNCED+snap; last status:', JSON.stringify(s));
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
  log('SYNCED — running verified reads', JSON.stringify(status));
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

  log(failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`);
  shutdown(failures === 0 ? 0 : 1);
}

function shutdown(code) {
  try { m.stop(handle); } catch {}
  process.exit(code);
}
