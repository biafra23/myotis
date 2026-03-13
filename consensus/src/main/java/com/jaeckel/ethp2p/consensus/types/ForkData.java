package com.jaeckel.ethp2p.consensus.types;

import com.jaeckel.ethp2p.consensus.ssz.SszUtil;

import java.util.Arrays;

/**
 * SSZ container: ForkData
 * forkVersion (bytes4) | genesisValidatorsRoot (bytes32)
 */
public record ForkData(
        byte[] forkVersion,
        byte[] genesisValidatorsRoot
) {

    public ForkData {
        if (forkVersion.length != 4) throw new IllegalArgumentException("forkVersion must be 4 bytes");
        if (genesisValidatorsRoot.length != 32) throw new IllegalArgumentException("genesisValidatorsRoot must be 32 bytes");
    }

    /**
     * hash_tree_root of this container.
     * Field 0: forkVersion (4 bytes) zero-padded to 32
     * Field 1: genesisValidatorsRoot (32 bytes) direct
     */
    public byte[] hashTreeRoot() {
        return SszUtil.hashTreeRootContainer(
                SszUtil.hashTreeRootBytes4(forkVersion),
                SszUtil.hashTreeRootBytes32(genesisValidatorsRoot)
        );
    }

    /**
     * Compute the 32-byte signing domain.
     *
     * domain = domainType[0:4] || forkDataRoot[0:28]
     *
     * @param domainType4            4-byte domain type constant
     * @param forkVersion4           4-byte fork version
     * @param genesisValidatorsRoot32 32-byte genesis validators root
     * @return 32-byte domain
     */
    public static byte[] computeDomain(byte[] domainType4, byte[] forkVersion4, byte[] genesisValidatorsRoot32) {
        if (domainType4.length != 4) throw new IllegalArgumentException("domainType must be 4 bytes");
        ForkData forkData = new ForkData(forkVersion4, genesisValidatorsRoot32);
        byte[] forkDataRoot = forkData.hashTreeRoot();
        byte[] domain = new byte[32];
        System.arraycopy(domainType4, 0, domain, 0, 4);
        System.arraycopy(forkDataRoot, 0, domain, 4, 28);
        return domain;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof ForkData other)) return false;
        return Arrays.equals(forkVersion, other.forkVersion)
                && Arrays.equals(genesisValidatorsRoot, other.genesisValidatorsRoot);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(forkVersion) + Arrays.hashCode(genesisValidatorsRoot);
    }
}
