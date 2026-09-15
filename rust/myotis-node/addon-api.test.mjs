// Addon-level API tests for createWithCheckpoint (ABI 26, #441). Run against a
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
