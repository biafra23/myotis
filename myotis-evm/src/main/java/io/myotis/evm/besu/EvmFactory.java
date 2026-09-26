package io.myotis.evm.besu;

import com.jaeckel.ethp2p.core.math.BigIntegers;
import io.myotis.evm.BlockContext;
import io.myotis.evm.EvmExecutionError;
import io.myotis.evm.EvmExecutionException;
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
 * <p>Amsterdam (Glamsterdam's EL fork) is REFUSED, not built: Sepolia blocks
 * at/after {@link #SEPOLIA_AMSTERDAM_TIME} fail with
 * {@link EvmExecutionError.UnsupportedFork} because Besu 26.4 cannot price
 * them, and falling through to the Osaka rung would price them with the wrong
 * gas model and nobody could tell. This is deliberately asymmetric with the
 * Rust {@code spec_for}, whose revm SERVES the rung; the Besu bump turns the
 * refusal into an {@code amsterdam()} builder.
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
    /** Sepolia Amsterdam — ethereum/pm#2205, epoch 353024 (2026-10-06 13:53:36
     *  UTC); the Rust {@code SEPOLIA_AMSTERDAM_TIME} twin. Blocks at/after it are
     *  REFUSED ({@link EvmExecutionError.UnsupportedFork}): Besu 26.4's early
     *  {@code MainnetEVMs.amsterdam} predates the schedule Sepolia activates (it
     *  has no EIP-2780 intrinsic-gas model), so neither it nor the Osaka rung may
     *  price them. Mainnet and gnosis have no Amsterdam date yet (both Osaka). */
    public static final long SEPOLIA_AMSTERDAM_TIME = 1_791_294_816L;

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
     * rather than silently getting mainnet fork times). Refuses exactly what
     * {@link #specFor} refuses.
     */
    public static EvmAndPrecompiles buildForBlock(BlockContext ctx) {
        EvmSpecVersion spec = specFor(ctx);
        java.math.BigInteger chainId = ctx.chainId();
        EvmConfiguration cfg = EvmConfiguration.DEFAULT;
        return switch (spec) {
            case OSAKA -> osaka(chainId, cfg);
            case PRAGUE -> prague(chainId, cfg);
            case CANCUN -> cancun(chainId, cfg);
            case SHANGHAI -> shanghai(chainId, cfg);
            case PARIS -> paris(chainId, cfg);
            case LONDON -> london(chainId, cfg);
            default -> throw new IllegalStateException("no EVM builder for " + spec);
        };
    }

    /**
     * Refuse {@code ctx} exactly as {@link #buildForBlock} would, without building
     * anything: for a caller that answers without running the EVM (the estimate's
     * plain-transfer fast path), so it applies the same refusals first — the Rust
     * estimate's {@code spec_for} twin. Void on purpose: callers outside this
     * module don't see Besu's types (see {@link #specFor}).
     */
    public static void requireSupported(BlockContext ctx) {
        specFor(ctx);
    }

    /**
     * The fork {@code ctx} executes under — the selection half of
     * {@link #buildForBlock}. Throws {@link IllegalArgumentException} for an
     * unknown chain or a pre-floor block, and {@link EvmExecutionException}
     * carrying {@link EvmExecutionError.UnsupportedFork} for a fork this engine
     * cannot price.
     */
    public static EvmSpecVersion specFor(BlockContext ctx) {
        java.util.Objects.requireNonNull(ctx, "ctx");
        final long chainId;
        try {
            chainId = BigIntegers.longValueExact(ctx.chainId());
        } catch (ArithmeticException e) {
            // Same friendly type as the unknown-id path — never leak the raw
            // ArithmeticException (module convention, see AbiDecoder).
            // BlockContext enforces a non-null chainId, so only overflow lands here.
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
    private static EvmSpecVersion mainnetSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        long blockNumber = ctx.blockNumber();
        if (ts >= OSAKA_TIME) return EvmSpecVersion.OSAKA;
        if (ts >= PRAGUE_TIME) return EvmSpecVersion.PRAGUE;
        if (ts >= CANCUN_TIME) return EvmSpecVersion.CANCUN;
        if (ts >= SHANGHAI_TIME) return EvmSpecVersion.SHANGHAI;
        if (blockNumber >= PARIS_BLOCK) return EvmSpecVersion.PARIS;
        if (blockNumber >= LONDON_BLOCK) return EvmSpecVersion.LONDON;
        throw tooOld(blockNumber, ts);
    }

    /** Sepolia: all timestamp-gated (merged pre-Shanghai; older is unservable).
     *  Amsterdam onward is refused (see {@link #SEPOLIA_AMSTERDAM_TIME}). */
    private static EvmSpecVersion sepoliaSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        if (ts >= SEPOLIA_AMSTERDAM_TIME) throw amsterdamUnsupported(ctx);
        if (ts >= SEPOLIA_OSAKA_TIME) return EvmSpecVersion.OSAKA;
        if (ts >= SEPOLIA_PRAGUE_TIME) return EvmSpecVersion.PRAGUE;
        if (ts >= SEPOLIA_CANCUN_TIME) return EvmSpecVersion.CANCUN;
        if (ts >= SEPOLIA_SHANGHAI_TIME) return EvmSpecVersion.SHANGHAI;
        throw tooOld(ctx.blockNumber(), ts);
    }

    /** Gnosis: all timestamp-gated (merged pre-Shanghai; older is unservable). */
    private static EvmSpecVersion gnosisSpec(BlockContext ctx) {
        long ts = ctx.timestamp();
        if (ts >= GNOSIS_OSAKA_TIME) return EvmSpecVersion.OSAKA;
        if (ts >= GNOSIS_PRAGUE_TIME) return EvmSpecVersion.PRAGUE;
        if (ts >= GNOSIS_CANCUN_TIME) return EvmSpecVersion.CANCUN;
        if (ts >= GNOSIS_SHANGHAI_TIME) return EvmSpecVersion.SHANGHAI;
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

    private static EvmExecutionException amsterdamUnsupported(BlockContext ctx) {
        return new EvmExecutionException(new EvmExecutionError.UnsupportedFork(
                "Amsterdam is not supported by the Java engine (Besu 26.4 cannot price it; "
                        + "the Rust engine serves it) — refusing blockNumber=" + ctx.blockNumber()
                        + ", timestamp=" + ctx.timestamp()
                        + " rather than executing it under Osaka rules"));
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
