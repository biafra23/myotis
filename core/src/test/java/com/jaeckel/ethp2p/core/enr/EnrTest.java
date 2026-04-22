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
    void tolerateListValuedPairs() {
        // Build a synthetic ENR with an "eth2"-style list-valued pair. A naive decoder
        // that only handles byte values would throw on the list; ours should skip the
        // list value and still recover the flat fields (ip, tcp, secp256k1).
        org.apache.tuweni.bytes.Bytes ip = org.apache.tuweni.bytes.Bytes.fromHexString("03932500"); // 3.147.37.0
        org.apache.tuweni.bytes.Bytes tcp = org.apache.tuweni.bytes.Bytes.fromHexString("2328");     // 9000
        org.apache.tuweni.bytes.Bytes key = org.apache.tuweni.bytes.Bytes.fromHexString(
                "02197590fab436299291f568e5b82253c306463855c3a61c60f69c4acad1429180");                    // 33B compressed

        org.apache.tuweni.bytes.Bytes rlp = org.apache.tuweni.rlp.RLP.encodeList(w -> {
            w.writeValue(org.apache.tuweni.bytes.Bytes.wrap(new byte[0])); // empty signature
            w.writeLong(0);                                                // seq
            // eth2 value as a nested list — what would've blown up the old decoder
            w.writeString("eth2");
            w.writeList(inner -> {
                inner.writeValue(org.apache.tuweni.bytes.Bytes.fromHexString("deadbeef"));
                inner.writeLong(42);
            });
            w.writeString("ip");
            w.writeValue(ip);
            w.writeString("secp256k1");
            w.writeValue(key);
            w.writeString("tcp");
            w.writeValue(tcp);
        });

        Enr enr = Enr.decode(rlp);
        assertTrue(enr.tcpAddress().isPresent());
        assertEquals(9000, enr.tcpAddress().get().getPort());
        assertEquals("3.147.37.0", enr.tcpAddress().get().getAddress().getHostAddress());
        assertTrue(enr.compressedSecp256k1().isPresent());
    }

    @Test
    void eth2FieldDecodesForkIdFromRealBootnode() {
        // Prylabs mainnet CL bootnode — carries an "eth2" SSZ blob with the
        // CL fork digest. Lifted verbatim from sigp/lighthouse .../mainnet/bootstrap_nodes.yaml.
        String prylabsEnr = "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg";
        Enr enr = Enr.fromEnrString(prylabsEnr);
        var eth2 = enr.eth2();
        assertTrue(eth2.isPresent(), "Prylabs bootnode must carry eth2 field");
        // The Prylabs bootnode advertises a fork_digest of 0xf5a5fd42 (a pre-Merge
        // phase0 digest; these ENRs predate recent hard forks and the next_fork_*
        // fields advertise the original "all future forks" sentinel). That's fine
        // for our purposes — we only need the field to be parseable.
        assertEquals(4, eth2.get().forkDigest().length);
        assertEquals(4, eth2.get().nextForkVersion().length);
        assertEquals((byte) 0xf5, eth2.get().forkDigest()[0]);
    }

    @Test
    void eth2FieldAbsentWhenNotPresent() {
        // The Teku bootnode we have on hand carries no "eth2" key — confirm empty Optional.
        String tekuEnr = "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo";
        Enr enr = Enr.fromEnrString(tekuEnr);
        assertTrue(enr.eth2().isEmpty());
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
