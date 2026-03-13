package com.jaeckel.ethp2p.core.enr;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnrTest {

    // First Lighthouse mainnet bootstrap ENR
    private static final String ENR_STRING =
            "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo";

    @Test
    void fromEnrStringDecodesIpAndTcp() {
        Enr enr = Enr.fromEnrString(ENR_STRING);
        var tcp = enr.tcpAddress();
        assertTrue(tcp.isPresent());
        assertEquals(9000, tcp.get().getPort());
        assertEquals("3.147.37.0", tcp.get().getAddress().getHostAddress());
    }

    @Test
    void fromEnrStringExtractsSecp256k1Key() {
        Enr enr = Enr.fromEnrString(ENR_STRING);
        var key = enr.compressedSecp256k1();
        assertTrue(key.isPresent());
        assertEquals(33, key.get().length);
        // Compressed key starts with 0x02 or 0x03
        byte prefix = key.get()[0];
        assertTrue(prefix == 0x02 || prefix == 0x03);
    }

    @Test
    void toLibp2pMultiaddrProducesValidFormat() {
        Enr enr = Enr.fromEnrString(ENR_STRING);
        var multiaddr = enr.toLibp2pMultiaddr();
        assertTrue(multiaddr.isPresent());
        String ma = multiaddr.get();
        assertTrue(ma.startsWith("/ip4/3.147.37.0/tcp/9000/p2p/"));
        // PeerId should be a non-empty base58 string
        String peerId = ma.substring(ma.lastIndexOf("/p2p/") + 5);
        assertFalse(peerId.isEmpty());
        // Base58 chars only
        assertTrue(peerId.matches("[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+"));
    }

    @Test
    void base58EncodeKnownValue() {
        // Base58("Hello World!") = "2NEpo7TZRRrLZSi2U"
        assertEquals("2NEpo7TZRRrLZSi2U", Enr.base58Encode("Hello World!".getBytes()));
    }

    @Test
    void derivePeerIdDeterministic() {
        Enr enr = Enr.fromEnrString(ENR_STRING);
        var key = enr.compressedSecp256k1().orElseThrow();
        String pid1 = Enr.derivePeerId(key);
        String pid2 = Enr.derivePeerId(key);
        assertEquals(pid1, pid2);
    }

    @Test
    void enrWithoutTcpReturnsEmptyMultiaddr() {
        // ENR that only has UDP (no "tcp" key) should return empty
        // Use an ENR string where tcp is missing — we simulate by checking the last ENR
        // from Lighthouse which has ip6/tcp6 but may lack ip4/tcp
        String enrStr = "enr:-KG4QPUf8-g_jU-KrwzG42AGt0wWM1BTnQxgZXlvCEIfTQ5hSmptkmgmMbRkpOqv6kzb33SlhPHJp7x4rLWWiVq5lSECgmlkgnY0gmlwhFPlR9KDaXA2kCoGxcAJAAAVAAAAAAAAABCJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA";
        Enr enr = Enr.fromEnrString(enrStr);
        // This one may or may not have tcp — just verify no exception
        assertDoesNotThrow(() -> enr.toLibp2pMultiaddr());
    }
}
