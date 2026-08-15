// Unit tests for the smoke readiness gate. Run: node --test smoke-gate.test.mjs
//
// The status snapshots below come from the three runs recorded in #372 — the
// same addon version producing PASS / FAIL / FAIL on peer luck alone. Fields
// the issue actually records are marked; where it does not record a field
// (discv5TableSize for runs A and B), the test asserts across BOTH values
// rather than inventing one.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  gateShortfall, gateConfigFromEnv, describeShortfall, isPeerStarvation, GATE_DEFAULTS,
} from './smoke-gate.mjs';

const DEFAULTS = { ...GATE_DEFAULTS };
const messages = (unmet) => unmet.map((u) => u.message).join(' ');

test('run A (linux, warm) — snapPeers=2, the run that passed — opens the gate', () => {
  // Recorded: snapPeers 2, peerCount 9, attemptedDials 19.
  assert.deepEqual(gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 2, discoveredPeers: 30 },
    DEFAULTS), []);
});

test('run B (windows, cold) — snapPeers=1 — is gated on rotation headroom either way', () => {
  // Recorded: snapPeers 1, peerCount 5, attemptedDials 7. discv5TableSize not
  // recorded, so assert the snapPeers gate holds regardless of it.
  for (const discovery of [{ discv5TableSize: 0, discoveredPeers: 0 }, { discv5TableSize: 12 }]) {
    const unmet = gateShortfall(
      { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 1, ...discovery }, DEFAULTS);
    assert.match(messages(unmet), /snapPeers=1 \(want >=2/);
    assert.ok(isPeerStarvation(unmet), 'a thin peer set is an environment result');
  }
});

test('run C (windows, warm) — 1 cached peer, discv5 table empty — is gated on both counts', () => {
  // Recorded verbatim: snapPeers 1, peerCount 1, attemptedDials 1,
  // discoveredPeers 3, discv5TableSize 0, elHunting false.
  const unmet = gateShortfall({
    beaconState: 'SYNCED', elReaderAvailable: true,
    snapPeers: 1, peerCount: 1, attemptedDials: 1, discoveredPeers: 3, discv5TableSize: 0,
  }, DEFAULTS);
  assert.match(messages(unmet), /snapPeers=1/);
  assert.ok(isPeerStarvation(unmet));
  // discoveredPeers=3 satisfies the discovery signal on its own, so snapPeers
  // is what holds this run back — exactly the condition that made it useless.
  assert.equal(unmet.length, 1);
});

test('a cache-only warm start with enough peers is still gated on discovery', () => {
  const unmet = gateShortfall({
    beaconState: 'SYNCED', elReaderAvailable: true,
    snapPeers: 3, discv5TableSize: 0, discoveredPeers: 0,
  }, DEFAULTS);
  assert.equal(unmet.length, 1);
  assert.match(unmet[0].message, /no discovery has produced candidates/);
  assert.ok(isPeerStarvation(unmet));
});

test('either discovery signal alone opens that condition (CL discv5 OR EL discovered)', () => {
  const base = { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 2 };
  assert.deepEqual(gateShortfall({ ...base, discv5TableSize: 5, discoveredPeers: 0 }, DEFAULTS), []);
  assert.deepEqual(gateShortfall({ ...base, discv5TableSize: 0, discoveredPeers: 5 }, DEFAULTS), []);
});

test('ENGINE-side shortfalls are never excused as peer starvation', () => {
  const notSynced = gateShortfall(
    { beaconState: 'CATCHING_UP', elReaderAvailable: true, snapPeers: 5, discv5TableSize: 40 },
    DEFAULTS);
  assert.match(messages(notSynced), /beaconState=CATCHING_UP/);
  assert.equal(isPeerStarvation(notSynced), false, 'a node that never syncs is an engine result');

  const readerDown = gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: false, snapPeers: 5, discv5TableSize: 40 },
    DEFAULTS);
  assert.match(messages(readerDown), /elReaderAvailable=false/);
  assert.equal(isPeerStarvation(readerDown), false);

  // Mixed: engine-side present ⇒ still not an environment verdict.
  const mixed = gateShortfall(
    { beaconState: 'SYNCING', elReaderAvailable: true, snapPeers: 0, discv5TableSize: 0 },
    DEFAULTS);
  assert.equal(isPeerStarvation(mixed), false);
});

test('missing status fields fail CLOSED and say what was observed', () => {
  const unmet = gateShortfall({ beaconState: 'SYNCED', elReaderAvailable: true }, DEFAULTS);
  assert.match(messages(unmet), /snapPeers=undefined/);
  assert.match(messages(unmet), /discv5TableSize=undefined discoveredPeers=undefined/);
  assert.doesNotThrow(() => gateShortfall(undefined, DEFAULTS));
  assert.ok(gateShortfall(undefined, DEFAULTS).length > 0);
});

test('describeShortfall renders every message', () => {
  const unmet = gateShortfall({ beaconState: 'SYNCING', elReaderAvailable: false }, DEFAULTS);
  const text = describeShortfall(unmet);
  for (const u of unmet) assert.ok(text.includes(u.message));
});

test('a constrained runner can relax the gate explicitly, never by accident', () => {
  const relaxed = { minSnapPeers: 1, requireDiscovery: false };
  assert.deepEqual(gateShortfall(
    { beaconState: 'SYNCED', elReaderAvailable: true, snapPeers: 1, discv5TableSize: 0 },
    relaxed), []);
  assert.deepEqual(
    gateConfigFromEnv({ MYOTIS_SMOKE_MIN_SNAP_PEERS: '1', MYOTIS_SMOKE_REQUIRE_DISCOVERY: '0' }),
    relaxed);
  for (const off of ['false', 'NO', 'Off']) {
    assert.equal(gateConfigFromEnv({ MYOTIS_SMOKE_REQUIRE_DISCOVERY: off }).requireDiscovery, false);
  }
  // Defaults stay strict when the env says nothing OR says empty string (an
  // unset Actions input expands to '' — that must not delete the peer floor).
  assert.deepEqual(gateConfigFromEnv({}), { minSnapPeers: 2, requireDiscovery: true });
  assert.deepEqual(
    gateConfigFromEnv({ MYOTIS_SMOKE_MIN_SNAP_PEERS: '', MYOTIS_SMOKE_REQUIRE_DISCOVERY: '' }),
    { minSnapPeers: 2, requireDiscovery: true });
});

test('a nonsense peer floor fails loudly at startup, not silently for 55 minutes', () => {
  for (const bad of ['abc', '0', '-1', '1.5']) {
    assert.throws(() => gateConfigFromEnv({ MYOTIS_SMOKE_MIN_SNAP_PEERS: bad }),
      /must be an integer >= 1/, `expected ${bad} to be rejected`);
  }
});
