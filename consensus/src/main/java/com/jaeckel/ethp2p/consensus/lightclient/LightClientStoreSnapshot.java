package com.jaeckel.ethp2p.consensus.lightclient;

import com.jaeckel.ethp2p.consensus.types.BeaconBlockHeader;
import com.jaeckel.ethp2p.consensus.types.ExecutionPayloadHeader;
import com.jaeckel.ethp2p.consensus.types.LightClientHeader;
import com.jaeckel.ethp2p.consensus.types.SyncCommittee;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Binary codec for {@link LightClientStore.Snapshot} — the verified sync-committee
 * state persisted between runs so day-to-day startups resume from where the last
 * run left off and only catch up the periods since, instead of re-bootstrapping
 * from the (months-old) embedded checkpoint and re-verifying every period.
 *
 * <p><b>Trust:</b> the snapshot is only ever produced from our own
 * BLS-verified store, and it is bound to the chain via the genesis-validators-root
 * so it can't be loaded against a different network. It is always <i>newer</i>
 * than the embedded checkpoint we already trust, so resuming from it is strictly
 * safer (less long-range exposure). A corrupt or wrong snapshot is self-correcting:
 * the next finality/catch-up update verified against it fails BLS and the caller
 * falls back to the embedded checkpoint. This is a private-storage performance
 * cache, not a new trust anchor.
 *
 * <p>This is a self-contained framing (not wire SSZ) — it only needs to round-trip
 * with itself. Components are reconstructed via the public constructors of the
 * consensus types, so it doesn't depend on (missing) wire encoders.
 */
public final class LightClientStoreSnapshot {

    /** "LCSS" — magic so a stray/foreign file is rejected fast. */
    private static final int MAGIC = 0x4C435353;
    private static final byte VERSION = 1;

    private LightClientStoreSnapshot() {}

    /**
     * Serialize a snapshot, bound to {@code genesisValidatorsRoot} (32B). Returns
     * null if there's nothing to persist.
     */
    public static byte[] serialize(LightClientStore.Snapshot s, byte[] genesisValidatorsRoot) {
        if (s == null) return null;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bos);
            out.writeInt(MAGIC);
            out.writeByte(VERSION);
            writeFixed(out, genesisValidatorsRoot, 32);
            out.writeLong(s.currentSyncCommitteePeriod());
            out.writeLong(s.finalizedSlot());
            out.writeLong(s.optimisticSlot());
            writeHeader(out, s.finalizedHeader());
            writeHeader(out, s.optimisticHeader());
            writeCommittee(out, s.currentSyncCommittee());
            if (s.nextSyncCommittee() != null) {
                out.writeBoolean(true);
                writeCommittee(out, s.nextSyncCommittee());
            } else {
                out.writeBoolean(false);
            }
            out.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            return null; // in-memory streams don't throw; defensive only
        }
    }

    /**
     * Deserialize a snapshot. Returns null if the bytes are absent, malformed, the
     * wrong version, or bound to a different chain than {@code expectedGvr} — in all
     * those cases the caller should fall back to the embedded checkpoint.
     */
    public static LightClientStore.Snapshot deserialize(byte[] data, byte[] expectedGvr) {
        if (data == null || data.length < 5) return null;
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
            if (in.readInt() != MAGIC) return null;
            if (in.readByte() != VERSION) return null;
            byte[] gvr = readFixed(in, 32);
            if (expectedGvr != null && !Arrays.equals(gvr, expectedGvr)) return null; // different chain
            long period = in.readLong();
            long finalizedSlot = in.readLong();
            long optimisticSlot = in.readLong();
            LightClientHeader finalizedHeader = readHeader(in);
            LightClientHeader optimisticHeader = readHeader(in);
            SyncCommittee current = readCommittee(in);
            SyncCommittee next = in.readBoolean() ? readCommittee(in) : null;
            return new LightClientStore.Snapshot(finalizedHeader, optimisticHeader,
                    current, next, finalizedSlot, optimisticSlot, period);
        } catch (Exception e) {
            return null; // any parse failure → fall back to embedded checkpoint
        }
    }

    // ---- LightClientHeader ----

    private static void writeHeader(DataOutputStream out, LightClientHeader h) throws IOException {
        writeFixed(out, h.beacon().encode(), 112);
        for (byte[] node : h.executionBranch()) writeFixed(out, node, 32);
        writeExecution(out, h.execution());
    }

    private static LightClientHeader readHeader(DataInputStream in) throws IOException {
        BeaconBlockHeader beacon = BeaconBlockHeader.decode(readFixed(in, 112));
        byte[][] branch = new byte[4][];
        for (int i = 0; i < 4; i++) branch[i] = readFixed(in, 32);
        ExecutionPayloadHeader exec = readExecution(in);
        return new LightClientHeader(beacon, exec, branch);
    }

    // ---- ExecutionPayloadHeader (field-by-field; reconstructed via constructor) ----

    private static void writeExecution(DataOutputStream out, ExecutionPayloadHeader e) throws IOException {
        writeFixed(out, e.parentHash(), 32);
        writeFixed(out, e.feeRecipient(), 20);
        writeFixed(out, e.stateRoot(), 32);
        writeFixed(out, e.receiptsRoot(), 32);
        writeFixed(out, e.logsBloom(), 256);
        writeFixed(out, e.prevRandao(), 32);
        out.writeLong(e.blockNumber());
        out.writeLong(e.gasLimit());
        out.writeLong(e.gasUsed());
        out.writeLong(e.timestamp());
        byte[] extra = e.extraData() != null ? e.extraData() : new byte[0];
        out.writeInt(extra.length);
        out.write(extra);
        writeFixed(out, e.baseFeePerGas(), 32);
        writeFixed(out, e.blockHash(), 32);
        writeFixed(out, e.transactionsRoot(), 32);
        writeFixed(out, e.withdrawalsRoot(), 32);
        out.writeLong(e.blobGasUsed());
        out.writeLong(e.excessBlobGas());
        boolean electra = e.depositRequestsRoot() != null;
        out.writeBoolean(electra);
        if (electra) {
            writeFixed(out, e.depositRequestsRoot(), 32);
            writeFixed(out, e.withdrawalRequestsRoot(), 32);
            writeFixed(out, e.consolidationRequestsRoot(), 32);
        }
    }

    private static ExecutionPayloadHeader readExecution(DataInputStream in) throws IOException {
        byte[] parentHash = readFixed(in, 32);
        byte[] feeRecipient = readFixed(in, 20);
        byte[] stateRoot = readFixed(in, 32);
        byte[] receiptsRoot = readFixed(in, 32);
        byte[] logsBloom = readFixed(in, 256);
        byte[] prevRandao = readFixed(in, 32);
        long blockNumber = in.readLong();
        long gasLimit = in.readLong();
        long gasUsed = in.readLong();
        long timestamp = in.readLong();
        int extraLen = in.readInt();
        if (extraLen < 0 || extraLen > 1 << 20) throw new IOException("bad extraData length");
        byte[] extraData = readFixed(in, extraLen);
        byte[] baseFeePerGas = readFixed(in, 32);
        byte[] blockHash = readFixed(in, 32);
        byte[] transactionsRoot = readFixed(in, 32);
        byte[] withdrawalsRoot = readFixed(in, 32);
        long blobGasUsed = in.readLong();
        long excessBlobGas = in.readLong();
        byte[] depositRequestsRoot = null, withdrawalRequestsRoot = null, consolidationRequestsRoot = null;
        if (in.readBoolean()) {
            depositRequestsRoot = readFixed(in, 32);
            withdrawalRequestsRoot = readFixed(in, 32);
            consolidationRequestsRoot = readFixed(in, 32);
        }
        return new ExecutionPayloadHeader(parentHash, feeRecipient, stateRoot, receiptsRoot,
                logsBloom, prevRandao, blockNumber, gasLimit, gasUsed, timestamp, extraData,
                baseFeePerGas, blockHash, transactionsRoot, withdrawalsRoot, blobGasUsed,
                excessBlobGas, depositRequestsRoot, withdrawalRequestsRoot, consolidationRequestsRoot);
    }

    // ---- SyncCommittee (512 pubkeys + aggregate, all 48B) ----

    private static void writeCommittee(DataOutputStream out, SyncCommittee c) throws IOException {
        byte[][] pks = c.pubkeys();
        for (byte[] pk : pks) writeFixed(out, pk, SyncCommittee.PUBKEY_SIZE);
        writeFixed(out, c.aggregatePubkey(), SyncCommittee.PUBKEY_SIZE);
    }

    private static SyncCommittee readCommittee(DataInputStream in) throws IOException {
        byte[][] pks = new byte[SyncCommittee.PUBKEY_COUNT][];
        for (int i = 0; i < SyncCommittee.PUBKEY_COUNT; i++) pks[i] = readFixed(in, SyncCommittee.PUBKEY_SIZE);
        byte[] aggregate = readFixed(in, SyncCommittee.PUBKEY_SIZE);
        return new SyncCommittee(pks, aggregate);
    }

    // ---- helpers ----

    private static void writeFixed(DataOutputStream out, byte[] b, int len) throws IOException {
        if (b == null || b.length != len) throw new IOException("expected " + len + " bytes");
        out.write(b);
    }

    private static byte[] readFixed(DataInputStream in, int len) throws IOException {
        byte[] b = new byte[len];
        in.readFully(b);
        return b;
    }
}
