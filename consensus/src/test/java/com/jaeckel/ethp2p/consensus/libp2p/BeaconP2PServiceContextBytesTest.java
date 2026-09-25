package com.jaeckel.ethp2p.consensus.libp2p;

import com.jaeckel.ethp2p.consensus.types.StatusMessage;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Context bytes — the fork digest of each light-client object's own epoch — pick the
 * decoder once Gloas changes the wire shape. Received ones are kept per object (and per
 * chunk: a range response can span the fork), and relayed objects are served under the
 * digest they arrived with, never the one current when a peer asks.
 */
class BeaconP2PServiceContextBytesTest {

    /** Sepolia's Fulu and Gloas digests. */
    private static final byte[] PRE = {0x74, (byte) 0xD0, 0x14, 0x59};
    private static final byte[] POST = {0x66, (byte) 0x9E, 0x6C, 0x11};

    private static BeaconP2PService service(AtomicReference<byte[]> current) {
        return new BeaconP2PService(() -> new StatusMessage(current.get(), new byte[32], 0L, new byte[32], 0L, 0L));
    }

    private static BeaconP2PService.ContextPayload serve(BeaconP2PService.ReqRespHandler h, byte[] req)
            throws Exception {
        return ((BeaconP2PService.ContextReqRespHandler) h).respond(req, "peer");
    }

    private static byte[] frame(BeaconP2PService.ContextPayload r, byte[] current) throws Exception {
        return BeaconP2PService.ResponderController.encodeSuccessResponse(
                r.payload(), true, r.forkDigest(), () -> current);
    }

    @Test
    void aRelayedObjectKeepsTheDigestItArrivedWith() throws Exception {
        AtomicReference<byte[]> current = new AtomicReference<>(POST);
        BeaconP2PService svc = service(current);
        byte[] ssz = {1, 2, 3, 4, 5};

        // After the fork, a cached pre-fork finality update stays tagged pre-fork...
        svc.cacheFinalityUpdate(PRE, ssz);
        BeaconP2PService.ContextPayload served = serve(svc.relayHandler(BeaconP2PService.FINALITY), new byte[0]);
        assertArrayEquals(PRE, served.forkDigest());
        byte[] wire = frame(served, POST);
        assertArrayEquals(PRE, Arrays.copyOfRange(wire, 1, 5));
        BeaconP2PService.ContextPayload back = BeaconP2PService.decodeSingleResponseWithContext(wire);
        assertArrayEquals(PRE, back.forkDigest());
        assertArrayEquals(ssz, back.payload());

        // ...and vice versa: a post-fork bootstrap served while our clock still reads pre-fork.
        current.set(PRE);
        byte[] root = new byte[32];
        root[0] = 7;
        svc.cacheBootstrap(root, POST, ssz);
        served = serve(svc.bootstrapHandler(), root);
        assertArrayEquals(POST, Arrays.copyOfRange(frame(served, PRE), 1, 5));
        assertNull(serve(svc.bootstrapHandler(), new byte[32]), "another root: ResourceUnavailable");

        // A response without its own context bytes is tagged with the current digest, as before.
        byte[] plain = BeaconP2PService.ResponderController.encodeSuccessResponse(ssz, true, null, () -> PRE);
        assertArrayEquals(PRE, Arrays.copyOfRange(plain, 1, 5));
    }

    @Test
    void anObjectWithoutItsContextBytesIsNotRelayed() throws Exception {
        BeaconP2PService svc = service(new AtomicReference<>(POST));
        svc.cacheOptimisticUpdate(null, new byte[]{1});
        svc.cacheFinalityUpdate(new byte[3], new byte[]{1});
        assertNull(serve(svc.relayHandler(BeaconP2PService.OPTIMISTIC), new byte[0]));
        assertNull(serve(svc.relayHandler(BeaconP2PService.FINALITY), new byte[0]));
    }

    /** One updates_by_range response can span the fork: each chunk keeps ITS digest. */
    @Test
    void eachRangeChunkKeepsItsOwnDigest() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        byte[] first = new byte[40];
        Arrays.fill(first, (byte) 0x01);
        byte[] second = new byte[60];
        Arrays.fill(second, (byte) 0x02);
        wire.write(BeaconP2PService.ResponderController.encodeSuccessResponse(first, true, PRE, () -> null));
        wire.write(BeaconP2PService.ResponderController.encodeSuccessResponse(second, true, POST, () -> null));

        List<BeaconP2PService.ContextPayload> chunks =
                BeaconP2PService.decodeMultiChunkResponseWithContext(wire.toByteArray(), 2);
        assertEquals(2, chunks.size());
        assertArrayEquals(PRE, chunks.get(0).forkDigest());
        assertArrayEquals(first, chunks.get(0).payload());
        assertArrayEquals(POST, chunks.get(1).forkDigest());
        assertArrayEquals(second, chunks.get(1).payload());
    }
}
