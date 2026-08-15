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

/** Defaults chosen so the gate means "the engine can actually be judged". */
export const GATE_DEFAULTS = {
  /** >= 2 so the reader's rotation has somewhere to go. */
  minSnapPeers: 2,
  /** discv5 must have run — a warm start can restore a stale cache instead. */
  requireDiscovery: true,
};

/** Read the gate config from the environment (see smoke.mjs's header). */
export function gateConfigFromEnv(env = process.env) {
  return {
    minSnapPeers: Number(env.MYOTIS_SMOKE_MIN_SNAP_PEERS ?? GATE_DEFAULTS.minSnapPeers),
    requireDiscovery: env.MYOTIS_SMOKE_REQUIRE_DISCOVERY !== '0',
  };
}

/**
 * Which readiness conditions are still unmet, as human-readable strings.
 * Empty ⇒ open the gate and run the verified reads.
 *
 * Returning the SHORTFALL rather than a boolean is deliberate: it makes a
 * gate timeout self-diagnosing, which is the difference between "insufficient
 * peers" and "the engine is broken" in a CI log.
 */
export function gateShortfall(status, config = gateConfigFromEnv()) {
  const s = status ?? {};
  const unmet = [];
  if (s.beaconState !== 'SYNCED') unmet.push(`beaconState=${s.beaconState} (want SYNCED)`);
  if (!s.elReaderAvailable) unmet.push('elReaderAvailable=false');
  if (!(s.snapPeers >= config.minSnapPeers)) {
    unmet.push(`snapPeers=${s.snapPeers} (want >=${config.minSnapPeers}, `
      + 'so the reader has a peer to rotate to)');
  }
  // A warm start restores the peer cache without necessarily re-running
  // discovery; discv5TableSize == 0 means every peer we hold came from that
  // cache — exactly the run-C shape in #372 (1 cached peer, served nothing,
  // all four checks "failed" 1.4s later).
  if (config.requireDiscovery && !(s.discv5TableSize > 0)) {
    unmet.push('discv5TableSize=0 (discovery has not run; peers are cache-restored only)');
  }
  return unmet;
}
