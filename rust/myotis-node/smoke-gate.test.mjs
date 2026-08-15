// Unit tests for the smoke readiness gate. Run: node --test rust/myotis-node
//
// The three status snapshots below are the ACTUAL runs recorded in #372 — the
// same addon version producing PASS / FAIL / FAIL on peer luck alone. They are
// the regression this gate exists to prevent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { gateShortfall, gateConfigFromEnv, GATE_DEFAULTS } from './smoke-gate.mjs';

const DEFAULTS = { minSnapPeers: GATE_DEFAULTS.minSnapPeers, requireDiscovery: true };

test('run A (linux, warm, 2 snap peers) — the run that passed — opens the gate', () => {
  assert.deepEqual(gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 2, discv5TableSize: 40 },
    DEFAULTS), []);
});

test('run B (windows, cold, 1 snap peer) is gated on rotation headroom', () => {
  const unmet = gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 1, discv5TableSize: 12 },
    DEFAULTS);
  assert.equal(unmet.length, 1);
  assert.match(unmet[0], /snapPeers=1 \(want >=2/);
});

test('run C (windows, warm, 1 cached peer, discovery never ran) is gated on BOTH counts', () => {
  const unmet = gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 1, discv5TableSize: 0 },
    DEFAULTS);
  assert.equal(unmet.length, 2);
  assert.match(unmet.join(' '), /snapPeers=1/);
  assert.match(unmet.join(' '), /discv5TableSize=0/);
});

test('sync state and EL readiness still gate, as before', () => {
  assert.match(gateShortfall(
    { beaconState: 'CATCHING_UP', elReaderAvailable: true, snapPeers: 5, discv5TableSize: 40 },
    DEFAULTS).join(' '), /beaconState=CATCHING_UP/);
  assert.match(gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: false, snapPeers: 5, discv5TableSize: 40 },
    DEFAULTS).join(' '), /elReaderAvailable=false/);
});

test('missing status fields fail CLOSED (an older addon must not open the gate)', () => {
  const unmet = gateShortfall({ beaconState: 'SYNCED', elReaderAvailable: true }, DEFAULTS);
  assert.ok(unmet.length >= 2);
  assert.doesNotThrow(() => gateShortfall(undefined, DEFAULTS));
  assert.ok(gateShortfall(undefined, DEFAULTS).length > 0);
});

test('a constrained runner can relax the gate explicitly, never by accident', () => {
  const relaxed = { minSnapPeers: 1, requireDiscovery: false };
  assert.deepEqual(gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 1, discv5TableSize: 0 },
    relaxed), []);
  // ...and the env parsing that produces such a config
  assert.deepEqual(
    gateConfigFromEnv({ MYOTIS_SMOKE_MIN_SNAP_PEERS: '1', MYOTIS_SMOKE_REQUIRE_DISCOVERY: '0' }),
    relaxed);
  // Defaults stay strict when the env says nothing.
  assert.deepEqual(gateConfigFromEnv({}), { minSnapPeers: 2, requireDiscovery: true });
});
