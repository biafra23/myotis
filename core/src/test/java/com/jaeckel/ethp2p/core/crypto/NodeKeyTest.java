package com.jaeckel.ethp2p.core.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NodeKeyTest {

    @Test
    void generateProducesValidKey() {
        NodeKey key = NodeKey.generate();
        assertNotNull(key.publicKey());
        assertEquals(64, key.publicKeyBytes().size());
        assertEquals(32, key.nodeId().size());
    }

    @Test
    void twoGeneratedKeysAreDifferent() {
        NodeKey k1 = NodeKey.generate();
        NodeKey k2 = NodeKey.generate();
        assertNotEquals(k1.nodeId(), k2.nodeId());
    }
}
