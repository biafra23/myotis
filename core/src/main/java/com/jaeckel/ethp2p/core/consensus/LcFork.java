package com.jaeckel.ethp2p.core.consensus;

/**
 * The light-client wire format of a slot's objects. Java twin of the Rust
 * {@code myotis_consensus::fork::LcFork}.
 *
 * <p>Before Gloas a {@code LightClientHeader} carries the whole execution payload
 * header (Capella through Fulu; the decoders tell those shapes apart by their
 * offsets, as they always have). From Gloas on it carries only the execution block
 * hash (EIP-7732: the body holds a payload bid, not a payload), and every container
 * is fixed-size — nothing left to sniff. Which one an object uses is decided by the
 * fork of its attested slot (a bootstrap's: its header's slot), exactly as the
 * spec's {@code *_gindex_at_slot} helpers and the req/resp context bytes do — see
 * {@link ForkSchedule#lcForkAtSlot(long)}.
 */
public enum LcFork {
    /** Capella..Fulu: execution payload header, depth-derived state gindices. */
    PRE_GLOAS,
    /** Gloas: execution block hash, fixed Gloas gindices. */
    GLOAS
}
