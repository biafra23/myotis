// The smoke test's READINESS GATE, as a pure function so it can be tested
// without starting an engine (smoke.mjs self-starts one on import).
//
// Why this exists (#372): the old gate was "beacon SYNCED + at least one snap
// peer". The reader rotates over the snap-peer set, so with exactly one peer
// there is nowhere to rotate to and a single dud peer is indistinguishable
// from a broken engine — three runs of the same addon produced PASS / FAIL /
// FAIL purely on how many peers happened to be present. A CI result that
// turns on peer luck sends people hunting for platform defects that aren't
// there.
//
// Each unmet condition is CLASSIFIED, because the whole point is to stop
// conflating two different verdicts:
//   'peers'  — the environment never produced a peer set worth judging
//   'engine' — the node itself isn't getting there (never syncs, EL reader
//              down). Mislabelling this as an environment result would just
//              invert the original misdirection.

/** Defaults chosen so an open gate means "the engine can actually be judged". */
export const GATE_DEFAULTS = {
  /** >= 2 so the reader's rotation has somewhere to go. */
  minSnapPeers: 2,
  /** Discovery must have produced candidates — a warm start can restore a
   *  stale peer cache and never look for anything else. */
  requireDiscovery: true,
};

/** Env values that turn a boolean knob off (anything else leaves it on). */
const FALSEY = new Set(['0', 'false', 'no', 'off']);

/**
 * Read the gate config from the environment (see smoke.mjs's header).
 * Throws on a set-but-nonsense numeric value: `Number('')` is 0 and
 * `Number('abc')` is NaN, either of which would silently delete the peer floor
 * or wedge the gate shut for the whole run. Fail loudly at startup instead.
 */
export function gateConfigFromEnv(env = process.env) {
  const raw = env.MYOTIS_SMOKE_MIN_SNAP_PEERS;
  let minSnapPeers = GATE_DEFAULTS.minSnapPeers;
  if (raw !== undefined && raw !== '') {
    minSnapPeers = Number(raw);
    if (!Number.isInteger(minSnapPeers) || minSnapPeers < 1) {
      throw new Error(
        `MYOTIS_SMOKE_MIN_SNAP_PEERS must be an integer >= 1, got ${JSON.stringify(raw)}`);
    }
  }
  const discovery = env.MYOTIS_SMOKE_REQUIRE_DISCOVERY;
  return {
    minSnapPeers,
    requireDiscovery: discovery === undefined || discovery === ''
      ? GATE_DEFAULTS.requireDiscovery
      : !FALSEY.has(discovery.toLowerCase()),
  };
}

/**
 * Which readiness conditions are still unmet, as `{kind, message}` entries.
 * Empty ⇒ open the gate and run the verified reads.
 *
 * Returning the SHORTFALL rather than a boolean is deliberate: it makes a gate
 * timeout self-diagnosing, which is the difference between "insufficient
 * peers" and "the engine is broken" in a CI log.
 */
export function gateShortfall(status, config = gateConfigFromEnv()) {
  const s = status ?? {};
  const unmet = [];
  if (s.beaconState !== 'SYNCED') {
    unmet.push({ kind: 'engine', message: `beaconState=${s.beaconState} (want SYNCED)` });
  }
  if (!s.elReaderAvailable) {
    unmet.push({ kind: 'engine', message: `elReaderAvailable=${s.elReaderAvailable}` });
  }
  if (!(s.snapPeers >= config.minSnapPeers)) {
    unmet.push({
      kind: 'peers',
      message: `snapPeers=${s.snapPeers} (want >=${config.minSnapPeers}, `
        + 'so the reader has a peer to rotate to)',
    });
  }
  // "Discovery produced candidates" is satisfied by EITHER the CL discv5
  // routing table or the EL's own discovered-peer count. Keying on discv5
  // alone would wedge the gate shut on a node whose EL peering is perfectly
  // healthy but whose CL discv5 spawn failed (UDP blocked / port still bound,
  // which retries about once a minute) — discv5TableSize is a CL signal being
  // used as a proxy here, so it must not be the only accepted one.
  if (config.requireDiscovery && !(s.discv5TableSize > 0) && !(s.discoveredPeers > 0)) {
    unmet.push({
      kind: 'peers',
      message: `discv5TableSize=${s.discv5TableSize} discoveredPeers=${s.discoveredPeers} `
        + '(no discovery has produced candidates; peers are cache-restored only)',
    });
  }
  return unmet;
}

/** Render a shortfall for a log line. */
export function describeShortfall(unmet) {
  return unmet.map((u) => u.message).join(', ');
}

/**
 * True when EVERY unmet condition is about the peer set — the only case that
 * may be reported as an environment result. Anything engine-side present ⇒
 * this is a statement about the node, and must not be excused.
 */
export function isPeerStarvation(unmet) {
  return unmet.length > 0 && unmet.every((u) => u.kind === 'peers');
}
