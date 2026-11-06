package io.myotis.node;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The shared CL peer cache can hold a QUIC-only peer the Rust engine found;
 * the Java engine (TCP-only) must skip it rather than dial it and charge it
 * failures that would evict it from the file both engines read.
 */
class TcpDialableClPeersTest {

    @Test
    void quicOnlyEntriesAreSkippedAndTcpOnesKeptInOrder() {
        String tcp = "/ip4/10.0.0.1/tcp/9000/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";
        String quic = "/ip4/10.0.0.2/udp/9001/quic-v1/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";
        String dns = "/dns4/roost.example/tcp/9105/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";
        assertEquals(List.of(tcp, dns), ChainStack.tcpDialable(List.of(tcp, quic, dns)));
    }

    @Test
    void quicOnlyKeysAreDroppedFromTheProvenRecords() {
        String tcp = "/ip4/10.0.0.1/tcp/9000/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";
        String quic = "/ip4/10.0.0.2/udp/9001/quic-v1/p2p/16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5";
        assertEquals(Map.of(tcp, 1500L), ChainStack.tcpDialable(Map.of(tcp, 1500L, quic, 1600L)));
    }
}
