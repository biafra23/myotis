package com.jaeckel.ethp2p.consensus.types;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ForkData domain computation.
 */
class ForkDataTest {

    @Test
    void computeDomainIsDeterministic() {
        byte[] domainType = {0x07, 0x00, 0x00, 0x00};
        byte[] forkVersion = {0x05, 0x00, 0x00, 0x00};
        byte[] gvr = new byte[32];
        gvr[0] = 0x42;

        byte[] domain1 = ForkData.computeDomain(domainType, forkVersion, gvr);
        byte[] domain2 = ForkData.computeDomain(domainType, forkVersion, gvr);
        assertArrayEquals(domain1, domain2);
    }

    @Test
    void computeDomainDiffersWithDifferentForkVersion() {
        byte[] domainType = {0x07, 0x00, 0x00, 0x00};
        byte[] gvr = new byte[32];

        byte[] fv1 = {0x01, 0x00, 0x00, 0x00};
        byte[] fv2 = {0x02, 0x00, 0x00, 0x00};

        byte[] domain1 = ForkData.computeDomain(domainType, fv1, gvr);
        byte[] domain2 = ForkData.computeDomain(domainType, fv2, gvr);
        assertFalse(Arrays.equals(domain1, domain2));
    }

    @Test
    void computeDomainDiffersWithDifferentGvr() {
        byte[] domainType = {0x07, 0x00, 0x00, 0x00};
        byte[] forkVersion = {0x05, 0x00, 0x00, 0x00};

        byte[] gvr1 = new byte[32];
        byte[] gvr2 = new byte[32];
        gvr2[0] = 0x01;

        byte[] domain1 = ForkData.computeDomain(domainType, forkVersion, gvr1);
        byte[] domain2 = ForkData.computeDomain(domainType, forkVersion, gvr2);
        assertFalse(Arrays.equals(domain1, domain2));
    }

    @Test
    void computeDomainFirst4BytesAreDomainType() {
        byte[] domainType = {0x07, 0x00, 0x00, 0x00};
        byte[] forkVersion = {0x05, 0x00, 0x00, 0x00};
        byte[] gvr = new byte[32];

        byte[] domain = ForkData.computeDomain(domainType, forkVersion, gvr);

        assertEquals(32, domain.length);
        // First 4 bytes must equal the domain type per spec
        assertEquals(0x07, domain[0] & 0xFF);
        assertEquals(0x00, domain[1] & 0xFF);
        assertEquals(0x00, domain[2] & 0xFF);
        assertEquals(0x00, domain[3] & 0xFF);
    }
}
