package io.myotis.evm.prefetch;

import io.myotis.evm.world.AccessTracker;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.tracing.OperationTracer;

/**
 * Besu {@link OperationTracer} that observes opcode-level state accesses
 * during the Phase 2 sentinel-return convergence loop.
 *
 * <p>The {@link io.myotis.evm.PrefetchingEvmExecutor} runs the EVM with
 * this tracer attached and {@code SyncStateView.setSentinelOnMiss(true)};
 * cache misses return zero-shaped placeholders, the tracer (and the view
 * itself, via the same {@link AccessTracker}) records every access, and
 * the prefetch loop batch-fetches the recorded misses in parallel before
 * re-running for real. See {@code io.myotis.evm.PrefetchingEvmExecutor}'s
 * Javadoc for the full convergence-loop description.
 *
 * <p>The tracer is one of two recording sources — the other is
 * {@code SyncStateView}, which records every access the world updater
 * makes (including the implicit account/bytecode lookups Besu performs
 * when entering a CALL/STATICCALL/DELEGATECALL child frame). The two
 * overlap by design and {@link AccessTracker} de-dupes via {@code HashSet}.
 *
 * <p>Bytecode access is intentionally <em>not</em> recorded by this tracer:
 * {@code SyncStateView.bytecode()} already records via the access tracker
 * when the view is wired with one, so the EXTCODE* opcodes' targets get
 * captured downstream. {@link io.myotis.evm.world.AccessTracker} retains
 * the {@code recordBytecode}/{@code codeHashes} surface for future use.
 *
 * <p>Hook points (Yellow Paper opcode numbers):
 * <ul>
 *   <li>0x54 {@code SLOAD} — stack[0] is the slot key; storage owner is
 *       {@code frame.getRecipientAddress()} (which is the calling-contract's
 *       address for normal CALL and stays as-is for STATICCALL/DELEGATECALL
 *       per Besu's semantics — the recipient is the storage-owning account
 *       in Besu's MessageFrame model).
 *   <li>0x3b {@code EXTCODESIZE}, 0x3c {@code EXTCODECOPY},
 *       0x3f {@code EXTCODEHASH} — stack[0] is the target address whose code
 *       we may need.
 *   <li>0x39 {@code CODECOPY} — copies from the executing contract's own code,
 *       so no extra fetch is needed; the contract's code was already loaded
 *       when the frame started.
 * </ul>
 *
 * <p>The tracer is single-call: build a fresh one for each EVM run inside
 * the convergence loop. Snapshots are returned via {@link AccessTracker}
 * which is already in the codebase from Phase 0/1.
 *
 * <p>Limitation: the recorded slot is what {@code SLOAD} sees on the stack
 * before execution, but the EVM only actually reads it if the {@code SLOAD}
 * opcode runs to completion. If the surrounding bytecode reverts or runs
 * out of gas before the {@code SLOAD} retires, the tracer will have
 * recorded a slot the real run would never touch. The convergence loop
 * tolerates this — over-fetching is wasteful but harmless.
 */
public final class PrefetchingTracer implements OperationTracer {

    /** EVM opcode constants (kept here so we don't depend on Besu's enum). */
    private static final int OP_SLOAD        = 0x54;
    private static final int OP_EXTCODESIZE  = 0x3b;
    private static final int OP_EXTCODECOPY  = 0x3c;
    private static final int OP_EXTCODEHASH  = 0x3f;

    private final AccessTracker tracker;

    public PrefetchingTracer(AccessTracker tracker) {
        this.tracker = tracker;
    }

    @Override
    public void tracePreExecution(MessageFrame frame) {
        var op = frame.getCurrentOperation();
        if (op == null) return;
        int code = op.getOpcode();
        // Stack underflow = EVM is about to halt with INSUFFICIENT_STACK_ITEMS;
        // skip the trace and let the real run produce the halt.
        int needed = op.getStackItemsConsumed();
        if (frame.stackSize() < needed) return;

        switch (code) {
            case OP_SLOAD -> {
                UInt256 slot = UInt256.fromBytes(Bytes32.leftPad(frame.getStackItem(0)));
                io.myotis.evm.Address owner = io.myotis.evm.Address.of(
                        frame.getRecipientAddress().getBytes().toArrayUnsafe());
                tracker.recordStorage(owner, slot.toUnsignedBigInteger());
                tracker.recordAccount(owner);
            }
            case OP_EXTCODESIZE, OP_EXTCODECOPY, OP_EXTCODEHASH -> {
                io.myotis.evm.Address target = io.myotis.evm.Address.of(
                        rightmost20(frame.getStackItem(0)));
                tracker.recordAccount(target);
            }
            default -> {
                // SLOAD doesn't carry an account argument, but every other
                // opcode that touches off-frame state already had its account
                // fetched when the message frame entered. Nothing to record.
            }
        }
    }

    /**
     * Truncate a 32-byte stack item to its rightmost 20 bytes (the address
     * encoding used on the EVM stack: addresses are zero-padded to 256 bits).
     */
    private static byte[] rightmost20(org.apache.tuweni.bytes.Bytes raw) {
        byte[] padded = Bytes32.leftPad(raw).toArrayUnsafe();
        byte[] addr = new byte[20];
        System.arraycopy(padded, 12, addr, 0, 20);
        return addr;
    }
}
