package com.jaeckel.ethp2p.consensus.libp2p;

import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService.ReqRespHandler;
import com.jaeckel.ethp2p.consensus.libp2p.BeaconP2PService.ResponderController;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The responder's inbound-stream discipline, driven through Netty's
 * {@link EmbeddedChannel} (the handler is a plain Netty handler; the libp2p
 * stream is only asked to {@code closeWrite()}): a bodyless binding answers at
 * {@code channelActive} and drops what follows; a {@link ResponderController#DRAINED_BODY}
 * binding — the root lists — answers only once its request has arrived, and
 * writes nothing; and a body nobody parses is bounded by
 * {@link ResponderController#MAX_DRAINED_REQUEST_BYTES}, past which the stream
 * is closed unanswered.
 */
class ResponderControllerTest {

    /** A libp2p {@code Stream} that only records which of its methods were called. */
    private static io.libp2p.core.Stream recordingStream(List<String> calls) {
        return (io.libp2p.core.Stream) Proxy.newProxyInstance(
                ResponderControllerTest.class.getClassLoader(),
                new Class<?>[] { io.libp2p.core.Stream.class },
                (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == args[0];
                            default -> "recording stream";
                        };
                    }
                    calls.add(method.getName());
                    return null;
                });
    }

    private static EmbeddedChannel channelFor(int expectedRequestSize, ReqRespHandler handler, List<String> calls) {
        ResponderController controller = new ResponderController(
                recordingStream(calls), handler, true, () -> new byte[4],
                expectedRequestSize, "/eth2/beacon_chain/req/test/1/ssz_snappy", "peer", "agent");
        // Construction registers the channel and fires channelActive through the handler.
        return new EmbeddedChannel(controller.nettyHandler());
    }

    private static long closeWrites(List<String> calls) {
        return calls.stream().filter("closeWrite"::equals).count();
    }

    /** Let the 150 ms "bytes stopped" timer fire. */
    private static void settle(EmbeddedChannel ch) throws InterruptedException {
        Thread.sleep(250);
        ch.runScheduledPendingTasks();
        ch.runPendingTasks();
    }

    @Test
    void aDrainedBodyIsAnsweredAfterTheRequestArrivedWithNothingWritten() throws Exception {
        List<String> calls = new ArrayList<>();
        EmbeddedChannel ch = channelFor(ResponderController.DRAINED_BODY,
                (req, peer) -> ReqRespHandler.NO_CHUNKS, calls);
        assertEquals(0, closeWrites(calls), "a DRAINED_BODY binding does not answer at channelActive");

        // A root list of 1024 roots (32 KiB), arriving in two reads.
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[16 * 1024]));
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[16 * 1024]));
        assertEquals(0, closeWrites(calls), "not answered while the request is still arriving");

        settle(ch);
        assertEquals(1, closeWrites(calls), "answered once the bytes stopped");
        assertNull(ch.readOutbound(), "zero chunks: nothing is written before the half-close");
        assertTrue(ch.isOpen(), "a well-formed request does not close the stream");
    }

    @Test
    void aDrainedBodyPastTheCapClosesTheStreamUnanswered() {
        List<String> calls = new ArrayList<>();
        EmbeddedChannel ch = channelFor(ResponderController.DRAINED_BODY,
                (req, peer) -> ReqRespHandler.NO_CHUNKS, calls);
        int written = 0;
        while (ch.isOpen() && written <= ResponderController.MAX_DRAINED_REQUEST_BYTES + 64 * 1024) {
            ch.writeInbound(Unpooled.wrappedBuffer(new byte[64 * 1024]));
            written += 64 * 1024;
        }
        assertFalse(ch.isOpen(), "past MAX_DRAINED_REQUEST_BYTES the stream is closed");
        assertTrue(written > ResponderController.MAX_DRAINED_REQUEST_BYTES, "and not before");
        assertEquals(0, closeWrites(calls), "closed, not answered");
        assertNull(ch.readOutbound());
    }

    @Test
    void aBodylessBindingAnswersAtChannelActiveAndDropsWhatFollows() {
        List<String> calls = new ArrayList<>();
        EmbeddedChannel ch = channelFor(0, (req, peer) -> new byte[17], calls);
        ByteBuf answer = ch.readOutbound();
        assertNotNull(answer, "answered at channelActive");
        assertEquals(0x00, answer.getByte(0), "a success chunk");
        answer.release();
        assertEquals(1, closeWrites(calls), "half-closed after the chunk");

        ch.writeInbound(Unpooled.wrappedBuffer(new byte[1000]));
        assertEquals(1, closeWrites(calls), "later bytes are dropped, nothing more is written");
        assertNull(ch.readOutbound());
        assertTrue(ch.isOpen());
    }

    @Test
    void aParsedBodyPastItsCapClosesTheStream() {
        List<String> calls = new ArrayList<>();
        EmbeddedChannel ch = channelFor(92, (req, peer) -> new byte[92], calls);
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[ResponderController.MAX_INBOUND_REQUEST_BYTES + 1]));
        assertFalse(ch.isOpen(), "a parsed body over MAX_INBOUND_REQUEST_BYTES closes the stream");
        assertEquals(0, closeWrites(calls));
    }
}
