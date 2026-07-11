package io.myotis.evm.besu;

import io.myotis.evm.BlockContext;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.EvmSpecVersion;
import org.hyperledger.besu.evm.MainnetEVMs;
import org.hyperledger.besu.evm.gascalculator.CancunGasCalculator;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.gascalculator.LondonGasCalculator;
import org.hyperledger.besu.evm.gascalculator.PragueGasCalculator;
import org.hyperledger.besu.evm.gascalculator.OsakaGasCalculator;
import org.hyperledger.besu.evm.gascalculator.ShanghaiGasCalculator;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.precompile.MainnetPrecompiledContracts;
import org.hyperledger.besu.evm.precompile.PrecompileContractRegistry;

/**
 * Builds Besu {@link EVM} instances configured for the correct mainnet hard
 * fork at a given block.
 *
 * <p>Mainnet fork boundaries (block-number-keyed up through the Merge,
 * timestamp-keyed afterwards):
 * <ul>
 *   <li>London — {@code 12_965_000}
 *   <li>Paris (Merge) — {@code 15_537_394}
 *   <li>Shanghai — timestamp {@code 1_681_338_455} (block ~17_034_870)
 *   <li>Cancun — timestamp {@code 1_710_338_135} (block ~19_426_587)
 *   <li>Prague — timestamp {@code 1_746_612_311} (block ~22_431_084)
 *   <li>Osaka — timestamp {@code 1_764_798_551} (Fusaka's EL half: CLZ,
 *       P256VERIFY at 0x100, ModExp repricing)
 * </ul>
 *
 * <p>For pre-merge ranges we use the block number; for post-merge we use the
 * timestamp because a single block-number boundary doesn't cleanly capture
 * the timestamp-keyed forks.
 *
 * <p>Pre-London is intentionally not supported: the wallet only operates on
 * recent finalised heads. If a future caller needs older blocks, add the
 * earlier branches and verify the {@link GasCalculator}/precompile pairings
 * against the spec.
 */
public final class EvmFactory {

    // Mainnet fork-transition boundaries; revisit these whenever Besu is upgraded.
    public static final long LONDON_BLOCK   = 12_965_000L;
    public static final long PARIS_BLOCK    = 15_537_394L;
    public static final long SHANGHAI_TIME  = 1_681_338_455L;
    public static final long CANCUN_TIME    = 1_710_338_135L;
    public static final long PRAGUE_TIME    = 1_746_612_311L;
    /** Fusaka's EL fork (CLZ, P256VERIFY, ModExp repricing) — go-ethereum
     *  MainnetChainConfig.OsakaTime (2025-12-03). NOTE the known asymmetry:
     *  this table uses MAINNET times for every chain (the Rust engine's
     *  spec_for is per-chain); harmless at the beacon-anchored head since all
     *  hosted chains activated Osaka long ago, and the ≤256-block historical
     *  window can no longer straddle the boundary — full chain-awareness here
     *  remains a tracked follow-up. */
    public static final long OSAKA_TIME     = 1_764_798_551L;

    private EvmFactory() {}

    /** Build an {@link EVM} instance whose rules match the active fork at {@code ctx}. */
    public static EvmAndPrecompiles buildForBlock(BlockContext ctx) {
        EvmConfiguration cfg = EvmConfiguration.DEFAULT;
        java.math.BigInteger chainId = ctx.chainId();
        long blockNumber = ctx.blockNumber();
        long ts = ctx.timestamp();

        if (ts >= OSAKA_TIME) {
            EVM evm = MainnetEVMs.osaka(chainId, cfg);
            GasCalculator gc = new OsakaGasCalculator();
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.osaka(gc), gc, EvmSpecVersion.OSAKA);
        }
        if (ts >= PRAGUE_TIME) {
            EVM evm = MainnetEVMs.prague(chainId, cfg);
            GasCalculator gc = new PragueGasCalculator();
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.prague(gc), gc, EvmSpecVersion.PRAGUE);
        }
        if (ts >= CANCUN_TIME) {
            EVM evm = MainnetEVMs.cancun(chainId, cfg);
            GasCalculator gc = new CancunGasCalculator();
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.cancun(gc), gc, EvmSpecVersion.CANCUN);
        }
        if (ts >= SHANGHAI_TIME) {
            EVM evm = MainnetEVMs.shanghai(chainId, cfg);
            GasCalculator gc = new ShanghaiGasCalculator();
            // Shanghai uses Istanbul-vintage precompiles; cancun() includes the
            // post-merge surface but adds KZG point-evaluation, which is
            // post-Shanghai. Use istanbul() here to stay correct.
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.SHANGHAI);
        }
        if (blockNumber >= PARIS_BLOCK) {
            EVM evm = MainnetEVMs.paris(chainId, cfg);
            GasCalculator gc = new LondonGasCalculator();
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.PARIS);
        }
        if (blockNumber >= LONDON_BLOCK) {
            EVM evm = MainnetEVMs.london(chainId, cfg);
            GasCalculator gc = new LondonGasCalculator();
            return new EvmAndPrecompiles(evm, MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.LONDON);
        }
        throw new IllegalArgumentException(
                "pre-London blocks are not supported (blockNumber=" + blockNumber
                        + ", timestamp=" + ts + ")");
    }

    /**
     * Bundle returned from {@link #buildForBlock(BlockContext)}. The
     * {@link PrecompileContractRegistry} is fork-specific and must be paired
     * with the EVM that produced it.
     */
    public record EvmAndPrecompiles(
            EVM evm,
            PrecompileContractRegistry precompiles,
            GasCalculator gasCalculator,
            EvmSpecVersion specVersion) {}
}
