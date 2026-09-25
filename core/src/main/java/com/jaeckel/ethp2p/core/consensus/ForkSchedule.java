package com.jaeckel.ethp2p.core.consensus;

import com.jaeckel.ethp2p.core.encoding.Hex;

import java.util.List;
import java.util.Objects;

/**
 * A beacon chain's fork schedule: the append-only, ascending list of
 * {@code (activation epoch, fork version)} pairs that selects the signing domain
 * for every sync-committee signature. Java twin of the Rust
 * {@code myotis_consensus::fork::ForkSchedule}.
 *
 * <p><b>Why a schedule and not one version.</b> The spec's
 * {@code validate_light_client_update} verifies a sync aggregate under
 * {@code compute_fork_version(compute_epoch_at_slot(max(signature_slot, 1) - 1))}
 * — the fork active when the signature was produced, not the network's current
 * fork. A store walking updates across a fork boundary needs both versions; a
 * single configured value verifies one side and rejects every update on the other,
 * stalling sync at every consensus fork on every install (#295).
 *
 * <p><b>Shippable ahead of activation.</b> The schedule may (and should) carry the
 * NEXT scheduled fork before it activates: signature verification is keyed by the
 * update's own slot, and the digest-side "active" version is read with
 * {@link #versionAtEpoch(long)} at the wall-clock epoch — see
 * {@code NetworkConfig.currentForkVersion()} — so a future entry changes nothing
 * until its epoch arrives. Only the blob-parameter (EIP-7892) digest fold remains a
 * single configured value.
 *
 * <p><b>Trust posture.</b> Consensus-critical configuration with the same standing
 * as the genesis validators root: embedded, never fetched at runtime. The beacon
 * API's {@code /eth/v1/config/fork_schedule} exposes the same data and is the
 * reference for the pinned lists in {@code NetworkConfig}.
 *
 * <p>Lives in {@code :core} because both {@code :networking} (the config) and
 * {@code :consensus} (the processor) need it and neither depends on the other.
 * Android-safe: arrays and {@link List} only.
 *
 * @param slotsPerEpoch slots per epoch for THIS chain (32 on the mainnet preset,
 *                      16 on gnosis). Bundled with the schedule so it can never be
 *                      read with another chain's geometry; {@code NetworkConfig}
 *                      refuses a schedule whose geometry differs from the chain's.
 * @param forks         the entries, ascending by activation epoch, genesis first
 */
public record ForkSchedule(int slotsPerEpoch, List<Fork> forks) {

    /**
     * One scheduled fork. The version is held as the {@code int} the usual hex
     * literal denotes — {@code fork(1714688, 0x06000064)} is Fulu on Gnosis — and
     * rendered big-endian by {@link #versionBytes()}, the spec's {@code Version}
     * byte order. An {@code int} rather than a {@code byte[]} so the record's
     * generated equality is by value.
     */
    public record Fork(long epoch, int version) {
        public Fork {
            if (epoch < 0) throw new IllegalArgumentException("fork epoch must be >= 0");
        }

        /** The 4-byte fork version, big-endian. A fresh array on every call. */
        public byte[] versionBytes() {
            return new byte[]{
                    (byte) (version >>> 24), (byte) (version >>> 16), (byte) (version >>> 8), (byte) version};
        }
    }

    /**
     * Validates on construction. Throws on: a non-positive {@code slotsPerEpoch},
     * an empty list, a first entry not at epoch 0, or epochs that are not strictly
     * ascending. Each would silently select a wrong signing domain for some slot —
     * the "accepted and silently ignored" failure CLAUDE.md forbids for anything that
     * can change the answer — so the constructor refuses rather than defaults.
     */
    public ForkSchedule {
        if (slotsPerEpoch <= 0)
            throw new IllegalArgumentException("fork schedule: slotsPerEpoch must be positive");
        if (forks == null || forks.isEmpty())
            throw new IllegalArgumentException("fork schedule: at least the genesis fork is required");
        for (Fork f : forks) Objects.requireNonNull(f, "fork schedule: null entry");
        if (forks.get(0).epoch() != 0)
            throw new IllegalArgumentException("fork schedule: the first entry must activate at epoch 0");
        for (int i = 1; i < forks.size(); i++) {
            if (forks.get(i - 1).epoch() >= forks.get(i).epoch())
                throw new IllegalArgumentException("fork schedule: activation epochs must be strictly ascending ("
                        + forks.get(i - 1).epoch() + " then " + forks.get(i).epoch() + ")");
        }
        forks = List.copyOf(forks);
    }

    /** Build a schedule from entries (see the canonical constructor for what is refused). */
    public static ForkSchedule of(int slotsPerEpoch, Fork... forks) {
        if (forks == null) throw new IllegalArgumentException("fork schedule: at least the genesis fork is required");
        for (Fork f : forks) {
            if (f == null) throw new IllegalArgumentException("fork schedule: null entry");
        }
        return new ForkSchedule(slotsPerEpoch, List.of(forks));
    }

    /** A fork entry: {@code fork(1714688, 0x06000064)} is Fulu on Gnosis. */
    public static Fork fork(long epoch, int version) {
        return new Fork(epoch, version);
    }

    /**
     * One version for every slot — a schedule with no boundary. For tests and for
     * replaying a corpus recorded under a single version. The slot geometry is
     * immaterial without a boundary; the mainnet preset is used so it is a real one.
     */
    public static ForkSchedule single(byte[] version) {
        if (version == null || version.length != 4)
            throw new IllegalArgumentException("fork version must be 4 bytes");
        int v = ((version[0] & 0xff) << 24) | ((version[1] & 0xff) << 16) | ((version[2] & 0xff) << 8) | (version[3] & 0xff);
        return of(32, fork(0, v));
    }

    /**
     * The newest scheduled fork's version — possibly not yet active. Callers that
     * need the fork active NOW (the digest, Status) must use
     * {@link #versionAtEpoch(long)} with the wall-clock epoch instead; this is for
     * pins and diagnostics.
     */
    public byte[] newest() {
        return forks.get(forks.size() - 1).versionBytes();
    }

    /**
     * {@code compute_fork_version(epoch)}: the version of the latest fork whose
     * activation epoch is {@code <= epoch}. Total — the genesis entry covers epoch 0.
     */
    public byte[] versionAtEpoch(long epoch) {
        return forkAtEpoch(epoch).versionBytes();
    }

    /**
     * The version of the fork BEFORE the one active at {@code epoch}, or
     * {@code null} when that is the genesis fork. The discv5 prior-digest fallback
     * input (see {@code NetworkConfig.acceptedForkDigests}).
     */
    public byte[] priorVersionAtEpoch(long epoch) {
        int i = forks.indexOf(forkAtEpoch(epoch));
        return i >= 1 ? forks.get(i - 1).versionBytes() : null;
    }

    private Fork forkAtEpoch(long epoch) {
        Fork chosen = forks.get(0);
        for (Fork f : forks) {
            if (f.epoch() <= epoch) chosen = f;
            else break;
        }
        return chosen;
    }

    /**
     * The fork version a sync aggregate signed at {@code signatureSlot} must be
     * verified under — spec {@code validate_light_client_update}:
     * {@code compute_fork_version(compute_epoch_at_slot(max(signature_slot, 1) - 1))}.
     *
     * <p>The {@code - 1} is not a detail: the aggregate is over the block of the
     * previous slot, so a signature at the first slot of a fork's activation epoch
     * still uses the old version, and only the next slot switches.
     *
     * <p>{@code signatureSlot} is an SSZ {@code uint64}; a value at or above
     * 2^63 arrives negative in a {@code long} and is treated as the far future
     * (newest fork), never as slot 0.
     */
    public byte[] versionForSignatureSlot(long signatureSlot) {
        if (signatureSlot < 0) return newest();
        long slot = Math.max(signatureSlot, 1L) - 1L;
        return versionAtEpoch(slot / slotsPerEpoch);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ForkSchedule{slotsPerEpoch=").append(slotsPerEpoch).append(", [");
        for (int i = 0; i < forks.size(); i++) {
            Fork f = forks.get(i);
            if (i > 0) sb.append(", ");
            sb.append(f.epoch()).append(':').append(Hex.formatHex(f.versionBytes()));
        }
        return sb.append("]}").toString();
    }
}
