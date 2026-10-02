// Addon-level API tests for createWithCheckpoint (ABI 26, #441), for
// ethCallJson's block check (ABI 27, #452), for the transaction-object
// refusals of estimateGasTxJson (ABI 34) and ethCallTxJson (ABI 35, #509), and
// for the rest of a provider's verified reads (#503).
// Run against a
// BUILT addon: node --test addon-api.test.mjs, with MYOTIS_NODE_ADDON pointing at
// the .node (or a cargo output: libmyotis_node.so/.dylib, myotis_node.dll);
// without one the tests skip rather than fail, so a cargo-less checkout still
// runs the pure-JS suites.
//
// What only this layer can cover: the camel-cased export and the f64 boundary —
// fractional, non-finite, negative, zero and unsafe-integer slots must come back
// as the in-band -1, never as a JS exception or a truncated u64. The generation
// semantics are re-asserted through the addon so the JSON/sentinel plumbing is
// tested end to end, not just host.rs.

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const here = new URL('.', import.meta.url).pathname;
// An explicit MYOTIS_NODE_ADDON is authoritative (skip if it is missing —
// never fall through to some other, possibly stale, build); auto-detection
// runs only when it is unset.
const candidates = process.env.MYOTIS_NODE_ADDON
  ? [process.env.MYOTIS_NODE_ADDON]
  : [
      join(here, 'myotis-node.node'),
      join(here, '..', 'target', 'release', 'libmyotis_node.so'),
      join(here, '..', 'target', 'debug', 'libmyotis_node.so'),
      join(here, '..', 'target', 'release', 'libmyotis_node.dylib'),
      join(here, '..', 'target', 'debug', 'libmyotis_node.dylib'),
    ];
const addonPath = candidates.find((p) => existsSync(p));
const skip = addonPath ? false : `no built addon at ${candidates.join(', ')} (set MYOTIS_NODE_ADDON)`;
// process.dlopen loads any extension; `require` would only dlopen `*.node`
// and parse a cargo `.so`/`.dylib` as JavaScript.
const m = addonPath ? (() => { const mod = { exports: {} }; process.dlopen(mod, resolve(addonPath)); return mod.exports; })() : null;

const ROOT = '0x' + '5a'.repeat(32);
const OTHER = '0x' + '6b'.repeat(32);
const SLOT = 8192 * 3 + 5; // deliberately not an epoch boundary

test('createWithCheckpoint is exported and init() reports ABI >= 26', { skip }, () => {
  assert.equal(typeof m.createWithCheckpoint, 'function');
  assert.ok(m.init() >= 26, `init()=${m.init()}`);
});

test('invalid slots and roots are refused in-band (-1) before the dataDir exists', { skip }, () => {
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  const dir = join(base, 'never-created');
  try {
    const bad = [
      ['fractional slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, 1.5)],
      ['NaN slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, NaN)],
      ['Infinity slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, Infinity)],
      ['zero slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, 0)],
      ['negative slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, -1)],
      ['2^53 slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, 2 ** 53)],
      ['future slot', () => m.createWithCheckpoint('mainnet', dir, ROOT, 9e15)],
      ['short root', () => m.createWithCheckpoint('mainnet', dir, '0xdead', SLOT)],
      ['zero root', () => m.createWithCheckpoint('mainnet', dir, '0x' + '00'.repeat(32), SLOT)],
      ['unknown network', () => m.createWithCheckpoint('nope', dir, ROOT, SLOT)],
      ['empty dataDir', () => m.createWithCheckpoint('mainnet', '', ROOT, SLOT)],
    ];
    for (const [label, call] of bad) {
      assert.equal(call(), -1, label);
    }
    assert.equal(existsSync(dir), false, 'a refused call must not create the dataDir');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a fresh dir binds to the anchor; only the same anchor resumes; others get -3', { skip }, () => {
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  const dir = join(base, 'gen');
  try {
    const h = m.createWithCheckpoint('mainnet', dir, ROOT, SLOT);
    assert.ok(h >= 1, `fresh bind failed: ${h}`);
    const marker = JSON.parse(readFileSync(join(dir, 'sync-anchor.json'), 'utf8'));
    assert.equal(marker.checkpointRoot, ROOT);
    assert.equal(marker.checkpointSlot, SLOT);
    assert.equal(m.createWithCheckpoint('mainnet', dir, ROOT, SLOT), -1, 'in use by a live handle');
    assert.equal(JSON.parse(m.statusJson(h)).beaconState, 'STARTING');
    m.stop(h);
    const again = m.createWithCheckpoint('mainnet', dir, ROOT, SLOT);
    assert.ok(again >= 1, `same-anchor resume failed: ${again}`);
    m.stop(again);
    assert.equal(m.createWithCheckpoint('mainnet', dir, OTHER, SLOT), -3, 'different root');
    assert.equal(m.createWithCheckpoint('mainnet', dir, ROOT, SLOT + 1), -3, 'different slot');
    assert.equal(m.create('mainnet', dir), -3, 'plain create on a marked dir');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// setBootEnodes (ABI 31, #465): a host's seed pins are applied or refused as
// a whole, and a handle that has not started keeps them for its start. No
// network is needed: a Created handle only stashes.
test('setBootEnodes applies or refuses a seed list as a whole (ABI 31)', { skip }, () => {
  assert.ok(m.init() >= 31, `init()=${m.init()}`);
  assert.equal(typeof m.setBootEnodes, 'function');
  const key = 'ab'.repeat(64);
  const pin = (host) => `enode://${key}@${host}`;
  assert.equal(m.setBootEnodes(-1, JSON.stringify([pin('1.2.3.4:30303')])), false, 'unknown handle');
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  let h = -1;
  try {
    h = m.create('mainnet', join(base, 'pins'));
    assert.ok(h >= 1, `create failed: ${h}`);
    // One accept, one refuse — the rule set itself is pinned in the engine's
    // own tests (host.rs); this layer proves the camel-cased export, the
    // ownership gate and the NUL byte.
    assert.equal(m.setBootEnodes(h, JSON.stringify([pin('1.2.3.4:30303')])), true);
    assert.equal(m.setBootEnodes(h, JSON.stringify([pin('1.2.3.4:1'), 7])), false,
      'one bad entry refuses the whole push');
    // A NUL byte is refused by the addon itself, before the engine.
    assert.equal(m.setBootEnodes(h, '["enode://\0"]'), false);
  } finally {
    if (h >= 1) m.stop(h);
    rmSync(base, { recursive: true, force: true });
  }
});

// #452: ethCallJson's `block` used to be ignored, so a historical block got
// head state back. The engine now refuses an unservable selector in-band, and
// marks the refusal permanent with the JSON-RPC invalid-params code.
test('ethCallJson refuses an unservable block as permanent invalid params (ABI 27)', { skip }, async () => {
  assert.ok(m.init() >= 27, `init()=${m.init()}`);
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  let h = -1;
  try {
    h = m.create('mainnet', join(base, 'call'));
    assert.ok(h >= 1, `create failed: ${h}`);
    const to = '0x' + '11'.repeat(20);
    for (const block of ['earliest', '0xzz', '0x' + 'ab'.repeat(32)]) {
      const r = JSON.parse(await m.ethCallJson(h, '', to, '', '', block));
      assert.equal(typeof r.error, 'string', `${block}: ${JSON.stringify(r)}`);
      assert.equal(r.code, -32602, `${block}: ${JSON.stringify(r)}`);
    }
    // A NUL byte is refused by the addon itself, before the engine, and is
    // just as permanent.
    for (const [from, block] of [['0x\0', 'latest'], ['', 'lat\0est']]) {
      const r = JSON.parse(await m.ethCallJson(h, from, to, '', '', block));
      assert.equal(r.error, 'argument contains NUL', JSON.stringify(r));
      assert.equal(r.code, -32602, JSON.stringify(r));
    }
    // A well-formed number passes the parse. This handle was never started,
    // so the call fails as a plain, retryable error, not with head state.
    const r = JSON.parse(await m.ethCallJson(h, '', to, '', '', '0x1'));
    assert.equal(typeof r.error, 'string', JSON.stringify(r));
    assert.equal(r.code, undefined, JSON.stringify(r));
  } finally {
    if (h >= 1) m.stop(h);
    rmSync(base, { recursive: true, force: true });
  }
});

// #509: estimateGasJson carries only from/to/data/value, so a type-4
// transaction estimated through it ignored its authorizations and came back
// far too low. estimateGasTxJson takes the whole transaction object, and an
// object no transaction could be is refused permanently — before the handle is
// consulted, so it holds for a stopped handle too.
test('estimateGasTxJson refuses a contradictory transaction object as permanent invalid params (ABI 34)', { skip }, async () => {
  assert.equal(typeof m.estimateGasTxJson, 'function');
  assert.ok(m.init() >= 34, `init()=${m.init()}`);
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  let h = -1;
  try {
    h = m.create('mainnet', join(base, 'estimate'));
    assert.ok(h >= 1, `create failed: ${h}`);
    const to = '0x' + '22'.repeat(20);
    for (const tx of [
      { to, type: '0x4' },                                // type 4 without authorizations
      { to, authorizationList: [] },                      // EIP-7702 forbids an empty list
      { to, gasPrice: '0x1', maxFeePerGas: '0x2' },       // two fee models at once
      { to, blobVersionedHashes: ['0x01'] },              // blob transactions are not simulated
    ]) {
      const r = JSON.parse(await m.estimateGasTxJson(h, JSON.stringify(tx), 'latest', ''));
      assert.equal(r.code, -32602, `${JSON.stringify(tx)}: ${JSON.stringify(r)}`);
      assert.match(r.error, /invalid transaction object/, JSON.stringify(r));
    }
    // A well-formed object passes the parse. This handle was never started,
    // so the estimate fails as a plain, retryable error, not with a number.
    const r = JSON.parse(await m.estimateGasTxJson(h, JSON.stringify({ to }), 'latest', ''));
    assert.equal(typeof r.error, 'string', JSON.stringify(r));
    assert.equal(r.code, undefined, JSON.stringify(r));
  } finally {
    if (h >= 1) m.stop(h);
    rmSync(base, { recursive: true, force: true });
  }
});

// #509: ethCallJson carries only from/to/data/value, so a wallet's simulation of
// its 7702 transaction had no way to hand the engine the authorizations.
// ethCallTxJson takes the whole object and refuses the same contradictions as
// estimateGasTxJson, permanently and before the handle is consulted.
test('ethCallTxJson refuses a contradictory transaction object as permanent invalid params (ABI 35)', { skip }, async () => {
  assert.equal(typeof m.ethCallTxJson, 'function');
  assert.ok(m.init() >= 35, `init()=${m.init()}`);
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  let h = -1;
  try {
    h = m.create('mainnet', join(base, 'call'));
    assert.ok(h >= 1, `create failed: ${h}`);
    const to = '0x' + '22'.repeat(20);
    for (const tx of [
      { to, type: '0x4' },                                // type 4 without authorizations
      { to, authorizationList: [] },                      // EIP-7702 forbids an empty list
      { to, gasPrice: '0x1', maxFeePerGas: '0x2' },       // two fee models at once
      { to, maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x2' }, // a tip above its cap
    ]) {
      const r = JSON.parse(await m.ethCallTxJson(h, JSON.stringify(tx), 'latest', ''));
      assert.equal(r.code, -32602, `${JSON.stringify(tx)}: ${JSON.stringify(r)}`);
      assert.match(r.error, /invalid transaction object/, JSON.stringify(r));
    }
    // A well-formed object passes the parse. This handle was never started,
    // so the call fails as a plain, retryable error, not with a result.
    const r = JSON.parse(await m.ethCallTxJson(h, JSON.stringify({ to, gas: '0x5208' }), 'latest', ''));
    assert.equal(typeof r.error, 'string', JSON.stringify(r));
    assert.equal(r.code, undefined, JSON.stringify(r));
  } finally {
    if (h >= 1) m.stop(h);
    rmSync(base, { recursive: true, force: true });
  }
});

// #503: the rest of a dApp provider's verified reads, the log index they serve
// eth_getLogs from, eth_call with a state override and the pending nonce. Each
// read resolves to the engine's JSON unchanged; these pin, on a handle that
// was never started (no network needed), the camel-cased exports, the
// unknown-handle sentinel, the NUL refusal, and the refusals the addon makes
// itself where the JSON-RPC routers would check before calling the engine.
// Every call is awaited before the next: a handle takes four requests at most.
const ADDR = '0x' + '11'.repeat(20);
const HASH = '0x' + 'cd'.repeat(32);
const SLOT0 = '0x' + '00'.repeat(32);
const FILTER = JSON.stringify({ address: ADDR, fromBlock: '0x1', toBlock: '0x2' });
const CONFIG = JSON.stringify({ enabled: true, watch: [{ address: ADDR, fromBlock: 1 }] });
// Each read, called with well-formed arguments, or with `arg` in place of its
// first string argument. `getBlockByNumberJson` omits `fullTransactions`,
// which defaults to false.
const READS = {
  getBlockByNumberJson: (h, arg = 'latest') => m.getBlockByNumberJson(h, arg),
  getBlockByHashJson: (h, arg = HASH) => m.getBlockByHashJson(h, arg, true),
  feeHistoryJson: (h, arg = 'latest') => m.feeHistoryJson(h, 4, arg, '[25,75]'),
  getTransactionReceiptJson: (h, arg = HASH) => m.getTransactionReceiptJson(h, arg),
  getBlockReceiptsJson: (h, arg = 'latest') => m.getBlockReceiptsJson(h, arg),
  getTransactionByHashJson: (h, arg = HASH) => m.getTransactionByHashJson(h, arg),
  getCodeJson: (h, arg = ADDR) => m.getCodeJson(h, arg, 'latest'),
  getStorageAtJson: (h, arg = ADDR) => m.getStorageAtJson(h, arg, SLOT0, 'latest'),
  getLogsJson: (h, arg = FILTER) => m.getLogsJson(h, arg),
  ethCallOverridesJson: (h, arg = 'latest') => m.ethCallOverridesJson(h, '', ADDR, '', '', arg, ''),
  importLogIndexFiles: (h, arg = JSON.stringify(['/nonexistent/logindex.db'])) => m.importLogIndexFiles(h, arg),
};
// What the engine answers on a handle that was never started — a message only
// the engine produces, so a read that gets it reached the engine. The log
// index's calls word it as its callers check it.
const NOT_STARTED = { error: 'handle not started' };
const NOT_RUNNING = { error: 'node is not running' };
const notStartedFor = (name) => (['getLogsJson', 'importLogIndexFiles'].includes(name) ? NOT_RUNNING : NOT_STARTED);
const invalid = (error) => ({ error, code: -32602 });

async function withCreatedHandle(fn) {
  const base = mkdtempSync(join(tmpdir(), 'myotis-addon-api-'));
  let h = -1;
  try {
    h = m.create('mainnet', join(base, 'reads'));
    assert.ok(h >= 1, `create failed: ${h}`);
    await fn(h);
  } finally {
    if (h >= 1) m.stop(h);
    rmSync(base, { recursive: true, force: true });
  }
}

test('the remaining verified reads are exported (#503)', { skip }, () => {
  for (const name of [...Object.keys(READS), 'logIndexStatusJson', 'setLogIndexConfig', 'pendingNonceOverlay']) {
    assert.equal(typeof m[name], 'function', name);
  }
});

test('an unknown handle gets the usual sentinel from every new call (#503)', { skip }, async () => {
  const notOurs = { error: 'handle does not belong to this environment' };
  for (const [name, read] of Object.entries(READS)) {
    assert.deepEqual(JSON.parse(await read(-1)), notOurs, name);
  }
  assert.deepEqual(JSON.parse(await m.logIndexStatusJson(-1)), notOurs);
  assert.deepEqual(JSON.parse(await m.setLogIndexConfig(-1, CONFIG)), notOurs);
  assert.equal(m.pendingNonceOverlay(-1, ADDR, 5), -1);
});

test('a well-formed read reaches the engine: a not-started handle is a plain, retryable error (#503)', { skip }, async () => {
  await withCreatedHandle(async (h) => {
    for (const [name, read] of Object.entries(READS)) {
      assert.deepEqual(JSON.parse(await read(h)), notStartedFor(name), name);
    }
    // What the addon passes on rather than refuses: a short storage position
    // (padded to its word), no reward column, and bare decimal digits where
    // the engine reads them as decimal.
    for (const [label, call] of [
      ['storage position 0x0', () => m.getStorageAtJson(h, ADDR, '0x0')],
      ['no reward column', () => m.feeHistoryJson(h, 4, 'latest', '[]')],
      ['omitted percentiles', () => m.feeHistoryJson(h, 4, 'latest')],
      ['code at decimal digits', () => m.getCodeJson(h, ADDR, '23500000')],
      ['override call at decimal digits', () => m.ethCallOverridesJson(h, '', ADDR, '', '', '23500000', '')],
    ]) {
      assert.deepEqual(JSON.parse(await call()), NOT_STARTED, label);
    }
    assert.deepEqual(JSON.parse(await m.logIndexStatusJson(h)), NOT_STARTED);
    // No EL reader to install it on: refused, which the engine logs.
    assert.deepEqual(JSON.parse(await m.setLogIndexConfig(h, CONFIG)), { ok: false });
    assert.equal(m.pendingNonceOverlay(h, ADDR, 5), -1, 'no reader: serve the mined nonce');
  });
});

test('a NUL byte in a string argument is a permanent refusal (#503)', { skip }, async () => {
  const nul = invalid('argument contains NUL');
  await withCreatedHandle(async (h) => {
    for (const [name, read] of Object.entries(READS)) {
      assert.deepEqual(JSON.parse(await read(h, 'x\0y')), nul, name);
    }
    assert.deepEqual(JSON.parse(await m.feeHistoryJson(h, 4, 'latest', '[25,\0]')), nul, 'percentiles');
    assert.deepEqual(JSON.parse(await m.getStorageAtJson(h, ADDR, '0x\0', 'latest')), nul, 'position');
    assert.deepEqual(JSON.parse(await m.getStorageAtJson(h, ADDR, SLOT0, 'lat\0est')), nul, 'block');
    assert.deepEqual(JSON.parse(await m.setLogIndexConfig(h, '{\0}')), nul);
    // The two older calls whose NUL refusal carried no code now match.
    assert.deepEqual(JSON.parse(await m.estimateGasJson(h, '\0', ADDR, '', '')), nul, 'estimateGasJson');
    assert.deepEqual(JSON.parse(await m.sendRawTransactionJson(h, '0x\0')), nul, 'sendRawTransactionJson');
    assert.equal(m.pendingNonceOverlay(h, '0x\0', 5), -1);
  });
});

test('a request that can never be served is refused permanently, before the handle (#503)', { skip }, async () => {
  await withCreatedHandle(async (h) => {
    const refusals = [
      // Bare digits where the engine would read them as hex.
      ['block number in digits', () => m.getBlockByNumberJson(h, '23500000'), invalid('a block number must be 0x-hex')],
      ['receipts selector in digits', () => m.getBlockReceiptsJson(h, '12'), invalid('a block number must be 0x-hex')],
      ['fee history newest in digits', () => m.feeHistoryJson(h, 4, '23500000', ''), invalid('a block number must be 0x-hex')],
      // A count that is no integer is refused, never truncated.
      ...[1.5, NaN, Infinity, 2 ** 53].map((count) =>
        [`blockCount ${count}`, () => m.feeHistoryJson(h, count, 'latest', ''), invalid('blockCount must be an integer')]),
      // Reward percentiles, checked as the routers check them.
      ['percentiles not json', () => m.feeHistoryJson(h, 4, 'latest', 'not json'), invalid('reward percentiles must be a JSON array')],
      ['percentiles as strings', () => m.feeHistoryJson(h, 4, 'latest', '["50"]'), invalid('reward percentiles must be JSON numbers')],
      ['percentile above 100', () => m.feeHistoryJson(h, 4, 'latest', '[101]'), invalid('reward percentile 101 is outside [0, 100]')],
      ['percentiles decreasing', () => m.feeHistoryJson(h, 4, 'latest', '[75,25]'), invalid('reward percentiles must be non-decreasing')],
      // A malformed address, hash or position.
      ['receipt hash', () => m.getTransactionReceiptJson(h, '0xdead'), invalid('invalid transaction hash (expected 32-byte hex)')],
      ['tx hash', () => m.getTransactionByHashJson(h, '0xdead'), invalid('invalid transaction hash (expected 32-byte hex)')],
      ['block hash', () => m.getBlockByHashJson(h, '0xdead'), invalid('invalid block hash (expected 32-byte hex)')],
      ['code address', () => m.getCodeJson(h, '0xdead', 'latest'), invalid('invalid address (expected 20-byte hex)')],
      ['storage address', () => m.getStorageAtJson(h, '0xdead', SLOT0), invalid('invalid address (expected 20-byte hex)')],
      ['storage position too long', () => m.getStorageAtJson(h, ADDR, '0x' + '1'.repeat(65)),
        invalid('invalid storage position (expected hex of at most 32 bytes)')],
      ['storage position not hex', () => m.getStorageAtJson(h, ADDR, '0xzz'),
        invalid('invalid storage position (expected hex of at most 32 bytes)')],
      ['empty import', () => m.importLogIndexFiles(h, '[]'), invalid('expected a non-empty JSON array of file paths')],
      ['import of a non-path', () => m.importLogIndexFiles(h, '[""]'), invalid('expected a non-empty JSON array of file paths')],
    ];
    for (const [label, call, expected] of refusals) {
      assert.deepEqual(JSON.parse(await call()), expected, label);
    }
    // The engine's own refusals, made before it consults the handle.
    for (const [label, call] of [
      ['block earliest', () => m.getBlockByNumberJson(h, 'earliest', false)],
      ['feeHistory blockCount 0', () => m.feeHistoryJson(h, 0, 'latest', '')],
      ['code at a block hash', () => m.getCodeJson(h, ADDR, HASH)],
      ['logs filter', () => m.getLogsJson(h, 'not json')],
      ['override call earliest', () => m.ethCallOverridesJson(h, '', ADDR, '', '', 'earliest', '')],
      ['override malformed', () => m.ethCallOverridesJson(h, '', ADDR, '', '', 'latest', '{"0x11":')],
    ]) {
      const r = JSON.parse(await call());
      assert.equal(r.code, -32602, `${label}: ${JSON.stringify(r)}`);
      assert.equal(typeof r.error, 'string', label);
    }
    // The pending nonce takes a non-negative safe integer.
    for (const nonce of [-1, 1.5, NaN, 2 ** 53]) {
      assert.equal(m.pendingNonceOverlay(h, ADDR, nonce), -1, String(nonce));
    }
  });
});
