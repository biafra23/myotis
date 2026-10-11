package com.jaeckel.ethp2p.networking.discv5;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Java twin of the Rust engine's {@code node_id_for_peer} derivation and
 * its {@code pinned_roost_identity_matches_its_seeded_enr} invariant: the
 * discv5 node id derived from a pinned libp2p peer id must equal the node id
 * of the record that peer actually publishes. Uses roost's real published
 * records as golden vectors — the same key signs both identities, which is the
 * property the targeted-lookup fast path stands on (#347). If these fail,
 * either the derivation drifted from the Rust engine's or roost split its
 * keys — both must be a red build, not a silent fallback to random-walk luck.
 */
class PinnedNodeIdDerivationTest {

    /**
     * (pinned libp2p peer id, the ENR that node published from behind the netcup
     * relay): the three roosts on 2026-09-06, and zbox's Sepolia Nimbus on
     * 2026-10-09 — pinned again by then, so its targeted lookup matters too.
     */
    private static final String[][] PIN_VECTORS = {
        { // sepolia, zbox's Nimbus v26.9.1: tcp 9104, quic 9001, cgc 4
            "16Uiu2HAkvYx58piGw1oxz34CUoeTv8nNQwTwE2cZZh4jR4wVMYy6",
            "enr:-Mi4QLzAB7ygmO5xbfcHYrY9dgOQH9qRLMiJyFhma6VMHVrHHJfEpekRAXlpprYesWtJErn-64LmKrCJVgDQTBFCB8gDh2F0dG5ldHOIAIABAAAAAACDY2djBIRldGgykGaebBGQAAB2__________-CaWSCdjSCaXCEvEQgEINuZmSEAAAAAIRxdWljgiMpiXNlY3AyNTZrMaECELjyr6TBb-b-kUs_Z1JmJ5eLH1_DMQM3V9Y10gqt83GDdGNwgiOQg3VkcIIjkA"
        },
        { // mainnet, tcp 9109
            "16Uiu2HAmAj4D6YGK1kvVL2ZtnoCjp3hdz3j6QLCNh6afhSuwYjLC",
            "enr:-KG4QKUnChEU8InNkAxOj6e_KZzebsvUQYJ850DJaEQAygKJb_8Y2Mv5IxDEOacUs0pkVctDN1f8CjrCfG7Vf2leulkIhGV0aDKQjJ9i_gYAAAD__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaEC41NP_bzrL7-rq6KmsQIeTl2Nw9yvIlgEvz-Pjz2dwTmDdGNwgiOVg3VkcIIjlQ"
        },
        { // sepolia, tcp 9105
            "16Uiu2HAkyDsNGDq5pbFCqdKTcJxp4Rd5caoy1Xe2KJVtyc94M8S5",
            "enr:-KG4QOZNbpU9w2wGBTa5tMaJKfLFOBvygYCYCtSewcQcXnWnNLbuZFar-gCtb70gJTLrAki7efXD5yBj1tSXOEBgul4HhGV0aDKQdNAUWZAAAHX__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaECOGinXjNuey5xwLNiO0Cd-MB7I3zLqCC5rbLWG6Bo9rqDdGNwgiORg3VkcIIjkQ"
        },
        { // gnosis, tcp 9108
            "16Uiu2HAmG76htC8Bht97af8tEoH5yeNbPatxz6zeHpWoYc4cHdzh",
            "enr:-KG4QCjwDSRCD6CysnECiWR9i6LBDoETDWI-0zU9bHBbFvgwKHZBGM4LBOBLl15zPJdgPePLlUNJrcbO8l9CGY6aagQHhGV0aDKQMjfatgYAAGT__________4JpZIJ2NIJpcIS8RCAQiXNlY3AyNTZrMaEDM0NY9iNV9hZMrtkoRrPEKj7tm2TLriwZv-m1ctszvvKDdGNwgiOUg3VkcIIjlA"
        },
    };

    @Test
    void derivedNodeIdMatchesThePublishedRecord() {
        for (String[] vector : PIN_VECTORS) {
            String peerId = vector[0];
            NodeRecord published = NodeRecordFactory.DEFAULT.fromEnr(vector[1]);
            Optional<Bytes> derived = Enr.nodeIdForPeerId(peerId);
            assertTrue(derived.isPresent(), peerId + ": derivation must succeed");
            assertEquals(published.getNodeId(), derived.get(),
                    peerId + ": derived discv5 node id != the published record's — "
                    + "either the derivation drifted from the Rust twin or the pinned "
                    + "node split its libp2p and discv5 keys");
        }
    }

    @Test
    void nonSecp256k1IdsDeriveNothing() {
        // An RSA/ed25519-style peer id is sha256-multihashed (Qm…, base58 of
        // 0x12 0x20 …) — the key is not recoverable, and the derivation must
        // say so rather than return garbage.
        assertTrue(Enr.nodeIdForPeerId("QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N").isEmpty());
        assertTrue(Enr.nodeIdForPeerId("not-base58-at-all-0OIl").isEmpty());
        assertTrue(Enr.nodeIdForPeerId("").isEmpty());
    }

    @Test
    void openingPassIsFastAndRevisitsArePolite() {
        // Opening pass: one quick walk per pinned id; then polite revisits.
        assertEquals(2_000, DiscV5Service.walkDelayMs(0, 3));
        assertEquals(2_000, DiscV5Service.walkDelayMs(2, 3));
        assertEquals(60_000, DiscV5Service.walkDelayMs(3, 3));
        assertEquals(60_000, DiscV5Service.walkDelayMs(100, 3));
    }
}
