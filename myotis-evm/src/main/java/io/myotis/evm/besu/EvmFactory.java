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
 * Builds Besu {@link EVM} instances configured for the correct hard fork of
 * the TARGET CHAIN at a given block — per-chain cascades for mainnet, sepolia
 * and gnosis (the Rust {@code spec_for} twin); unknown chain ids fail closed.
 *
 * <p>Mainnet fork boundaries (block-number-keyed up through the Merge,
 * timestamp-keyed afterwards; sepolia/gnosis schedules live on their own
 * constants below, cross-base-pinned in ForkTimePinsTest):
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
     *  MainnetChainConfig.OsakaTime (2025-12-03). */
    public static final long OSAKA_TIME     = 1_764_798_551L;

    // Sepolia fork-activation timestamps (go-ethereum SepoliaChainConfig).
    // Sepolia merged before Shanghai; below Shanghai fails closed as too old.
    public static final long SEPOLIA_SHANGHAI_TIME = 1_677_557_088L;
    public static final long SEPOLIA_CANCUN_TIME   = 1_706_655_072L;
    public static final long SEPOLIA_PRAGUE_TIME   = 1_741_159_776L;
    public static final long SEPOLIA_OSAKA_TIME    = 1_760_427_360L;

    // Gnosis fork-activation timestamps (nethermind gnosis.json, hex-sourced:
    // 0x64c8edbc / 0x65ef4dbc / 0x68122dbc / 0x69de2dbc — pinned cross-base in
    // ForkTimePinsTest like every other constant here).
    public static final long GNOSIS_SHANGHAI_TIME = 1_690_889_660L;
    public static final long GNOSIS_CANCUN_TIME   = 1_710_181_820L;
    public static final long GNOSIS_PRAGUE_TIME   = 1_746_021_820L;
    public static final long GNOSIS_OSAKA_TIME    = 1_776_168_380L;

    private EvmFactory() {}

    /**
     * Build an {@link EVM} instance whose rules match the active fork at {@code ctx} —
     * PER CHAIN (the Rust {@code spec_for} twin, one cascade per hosted chain; an
     * unknown chain id fails closed exactly like the Rust engine's UnsupportedChain
     * rather than silently getting mainnet fork times).
     */
    public static EvmAndPrecompiles buildForBlock(BlockContext ctx) {
        final long chainId;
        try {
            chainId = ctx.chainId().longValueExact();
        } catch (ArithmeticException | NullPointerException e) {
            // Same friendly type as the unknown-id path — never leak the raw
            // ArithmeticException (module convention, see AbiDecoder).
            throw new IllegalArgumentException("unsupported chain id " + ctx.chainId(), e);
        }
        if (chainId == 1L) {
            return mainnetSpec(ctx);
        }
        if (chainId == 11_155_111L) {
            return sepoliaSpec(ctx);
        }
        if (chainId == 100L) {
            return gnosisSpec(ctx);
        }
        throw new IllegalArgumentException(
                "unsupported chain id " + chainId + " (no fork table — failing closed, "
                        + "never silently applying mainnet fork rules)");
    }

    /** Mainnet: pre-merge forks by block number, post-merge by timestamp. */
    private static EvmAndPrecompiles mainnetSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        long blockNumber = ctx.blockNumber();
        java.math.BigInteger chainId = ctx.chainId();
        EvmConfiguration cfg = EvmConfiguration.DEFAULT;
        if (ts >= OSAKA_TIME) return osaka(chainId, cfg);
        if (ts >= PRAGUE_TIME) return prague(chainId, cfg);
        if (ts >= CANCUN_TIME) return cancun(chainId, cfg);
        if (ts >= SHANGHAI_TIME) return shanghai(chainId, cfg);
        if (blockNumber >= PARIS_BLOCK) return paris(chainId, cfg);
        if (blockNumber >= LONDON_BLOCK) return london(chainId, cfg);
        throw tooOld(blockNumber, ts);
    }

    /** Sepolia: all timestamp-gated (merged pre-Shanghai; older is unservable). */
    private static EvmAndPrecompiles sepoliaSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        java.math.BigInteger chainId = ctx.chainId();
        EvmConfiguration cfg = EvmConfiguration.DEFAULT;
        if (ts >= SEPOLIA_OSAKA_TIME) return osaka(chainId, cfg);
        if (ts >= SEPOLIA_PRAGUE_TIME) return prague(chainId, cfg);
        if (ts >= SEPOLIA_CANCUN_TIME) return cancun(chainId, cfg);
        if (ts >= SEPOLIA_SHANGHAI_TIME) return shanghai(chainId, cfg);
        throw tooOld(ctx.blockNumber(), ts);
    }

    /** Gnosis: all timestamp-gated (merged pre-Shanghai; older is unservable). */
    private static EvmAndPrecompiles gnosisSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        java.math.BigInteger chainId = ctx.chainId();
        EvmConfiguration cfg = EvmConfiguration.DEFAULT;
        if (ts >= GNOSIS_OSAKA_TIME) return osaka(chainId, cfg);
        if (ts >= GNOSIS_PRAGUE_TIME) return prague(chainId, cfg);
        if (ts >= GNOSIS_CANCUN_TIME) return cancun(chainId, cfg);
        if (ts >= GNOSIS_SHANGHAI_TIME) return shanghai(chainId, cfg);
        throw tooOld(ctx.blockNumber(), ts);
    }

    // ---- one builder per rung (gas-calculator/precompile pairings unchanged) ----

    private static EvmAndPrecompiles osaka(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new OsakaGasCalculator();
        return new EvmAndPrecompiles(MainnetEVMs.osaka(chainId, cfg),
                MainnetPrecompiledContracts.osaka(gc), gc, EvmSpecVersion.OSAKA);
    }

    private static EvmAndPrecompiles prague(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new PragueGasCalculator();
        return new EvmAndPrecompiles(MainnetEVMs.prague(chainId, cfg),
                MainnetPrecompiledContracts.prague(gc), gc, EvmSpecVersion.PRAGUE);
    }

    private static EvmAndPrecompiles cancun(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new CancunGasCalculator();
        return new EvmAndPrecompiles(MainnetEVMs.cancun(chainId, cfg),
                MainnetPrecompiledContracts.cancun(gc), gc, EvmSpecVersion.CANCUN);
    }

    private static EvmAndPrecompiles shanghai(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new ShanghaiGasCalculator();
        // Shanghai uses Istanbul-vintage precompiles; cancun() would add KZG
        // point-evaluation, which is post-Shanghai.
        return new EvmAndPrecompiles(MainnetEVMs.shanghai(chainId, cfg),
                MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.SHANGHAI);
    }

    private static EvmAndPrecompiles paris(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new LondonGasCalculator();
        return new EvmAndPrecompiles(MainnetEVMs.paris(chainId, cfg),
                MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.PARIS);
    }

    private static EvmAndPrecompiles london(java.math.BigInteger chainId, EvmConfiguration cfg) {
        GasCalculator gc = new LondonGasCalculator();
        return new EvmAndPrecompiles(MainnetEVMs.london(chainId, cfg),
                MainnetPrecompiledContracts.istanbul(gc), gc, EvmSpecVersion.LONDON);
    }

    private static IllegalArgumentException tooOld(long blockNumber, long ts) {
        return new IllegalArgumentException(
                "pre-fork-floor blocks are not supported (blockNumber=" + blockNumber
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
