package io.myotis.evm.besu;

import io.myotis.evm.BlockContext;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.frame.BlockValues;

import java.util.Optional;

/**
 * Adapter from {@link BlockContext} to Besu's {@link BlockValues} interface,
 * which the EVM consults for the {@code BLOCKHASH}, {@code COINBASE},
 * {@code TIMESTAMP}, {@code NUMBER}, {@code DIFFICULTY}/{@code PREVRANDAO},
 * {@code GASLIMIT}, and {@code BASEFEE} opcodes.
 */
public final class BlockContextValues implements BlockValues {

    private final BlockContext ctx;

    public BlockContextValues(BlockContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public Bytes getDifficultyBytes() {
        // Post-merge, DIFFICULTY shares its slot with PREVRANDAO. Returning the
        // verified RANDAO bytes is correct for both, since pre-merge ranges
        // are out of scope for this module.
        return Bytes.wrap(ctx.prevRandao());
    }

    @Override
    public Bytes32 getMixHashOrPrevRandao() {
        return Bytes32.wrap(ctx.prevRandao());
    }

    @Override
    public Optional<Wei> getBaseFee() {
        if (ctx.baseFeePerGas() == null) return Optional.empty();
        return Optional.of(Wei.of(ctx.baseFeePerGas()));
    }

    @Override
    public long getNumber() {
        return ctx.blockNumber();
    }

    @Override
    public long getTimestamp() {
        return ctx.timestamp();
    }

    @Override
    public long getGasLimit() {
        return ctx.gasLimit();
    }
}
