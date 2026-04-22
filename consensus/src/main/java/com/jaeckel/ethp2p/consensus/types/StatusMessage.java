package com.jaeckel.ethp2p.consensus.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * SSZ container: {@code Status} (v2, post-Electra).
 *
 * <p>Layout per the CL p2p spec {@code /eth2/beacon_chain/req/status/2/ssz_snappy}:
 * <pre>
 *   fork_digest            : Bytes4   (4)
 *   finalized_root         : Root     (32)
 *   finalized_epoch        : Epoch    (uint64 LE, 8)
 *   head_root              : Root     (32)
 *   head_slot              : Slot     (uint64 LE, 8)
 *   earliest_available_slot: Slot     (uint64 LE, 8)
 * </pre>
 * Total fixed size: 92 bytes. We target v2 rather than v1 because recent
 * mainnet clients (observed Lodestar, likely others) no longer advertise
 * {@code /status/1/ssz_snappy} in their Identify protocol list — multistream
 * negotiation against v1 fails outright even when v2 would have worked.
 *
 * <p>Sent as the first request on every CL libp2p connection. Modern clients
 * (Lighthouse v8+, Teku, Prysm, Lodestar …) disconnect peers that don't send
 * a Status within a few seconds — without this handshake our bootstrap
 * streams get RST'd before they can complete.
 */
public record StatusMessage(
        byte[] forkDigest,
        byte[] finalizedRoot,
        long finalizedEpoch,
        byte[] headRoot,
        long headSlot,
        long earliestAvailableSlot
) {

    public static final int SSZ_SIZE = 92;

    public StatusMessage {
        if (forkDigest == null || forkDigest.length != 4)
            throw new IllegalArgumentException("forkDigest must be 4 bytes");
        if (finalizedRoot == null || finalizedRoot.length != 32)
            throw new IllegalArgumentException("finalizedRoot must be 32 bytes");
        if (headRoot == null || headRoot.length != 32)
            throw new IllegalArgumentException("headRoot must be 32 bytes");
    }

    public static StatusMessage decode(byte[] ssz) {
        if (ssz.length < SSZ_SIZE) {
            throw new IllegalArgumentException(
                    "Status requires " + SSZ_SIZE + " bytes, got " + ssz.length);
        }
        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);
        byte[] forkDigest = new byte[4];
        byte[] finalizedRoot = new byte[32];
        byte[] headRoot = new byte[32];
        buf.get(forkDigest);
        buf.get(finalizedRoot);
        long finalizedEpoch = buf.getLong();
        buf.get(headRoot);
        long headSlot = buf.getLong();
        long earliestAvailableSlot = buf.getLong();
        return new StatusMessage(forkDigest, finalizedRoot, finalizedEpoch,
                headRoot, headSlot, earliestAvailableSlot);
    }

    public byte[] encode() {
        ByteBuffer buf = ByteBuffer.allocate(SSZ_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(forkDigest);
        buf.put(finalizedRoot);
        buf.putLong(finalizedEpoch);
        buf.put(headRoot);
        buf.putLong(headSlot);
        buf.putLong(earliestAvailableSlot);
        return buf.array();
    }

    /** SSZ encoding for {@code /req/status/1/ssz_snappy} — 84 bytes, no earliest_available_slot. */
    public byte[] encodeV1() {
        ByteBuffer buf = ByteBuffer.allocate(84).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(forkDigest);
        buf.put(finalizedRoot);
        buf.putLong(finalizedEpoch);
        buf.put(headRoot);
        buf.putLong(headSlot);
        return buf.array();
    }

    /** SSZ decoding for {@code /req/status/1/ssz_snappy} — 84 bytes, earliest_available_slot defaulted to 0. */
    public static StatusMessage decodeV1(byte[] ssz) {
        if (ssz.length < 84) {
            throw new IllegalArgumentException(
                    "Status v1 requires 84 bytes, got " + ssz.length);
        }
        ByteBuffer buf = ByteBuffer.wrap(ssz).order(ByteOrder.LITTLE_ENDIAN);
        byte[] forkDigest = new byte[4];
        byte[] finalizedRoot = new byte[32];
        byte[] headRoot = new byte[32];
        buf.get(forkDigest);
        buf.get(finalizedRoot);
        long finalizedEpoch = buf.getLong();
        buf.get(headRoot);
        long headSlot = buf.getLong();
        return new StatusMessage(forkDigest, finalizedRoot, finalizedEpoch, headRoot, headSlot, 0L);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StatusMessage other)) return false;
        return finalizedEpoch == other.finalizedEpoch
                && headSlot == other.headSlot
                && earliestAvailableSlot == other.earliestAvailableSlot
                && Arrays.equals(forkDigest, other.forkDigest)
                && Arrays.equals(finalizedRoot, other.finalizedRoot)
                && Arrays.equals(headRoot, other.headRoot);
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(finalizedEpoch);
        result = 31 * result + Long.hashCode(headSlot);
        result = 31 * result + Long.hashCode(earliestAvailableSlot);
        result = 31 * result + Arrays.hashCode(forkDigest);
        result = 31 * result + Arrays.hashCode(finalizedRoot);
        result = 31 * result + Arrays.hashCode(headRoot);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Status{digest=0x");
        for (byte b : forkDigest) sb.append(String.format("%02x", b));
        sb.append(", finalizedEpoch=").append(finalizedEpoch);
        sb.append(", headSlot=").append(headSlot);
        sb.append(", earliest=").append(earliestAvailableSlot).append("}");
        return sb.toString();
    }
}
