package com.jaeckel.ethp2p.networking.traffic;

import com.jaeckel.ethp2p.core.traffic.TrafficMeter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.DatagramPacket;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CountingHandlerTest {

    @Test
    void countsStreamBytesBothWays() {
        TrafficMeter meter = new TrafficMeter();
        EmbeddedChannel ch = new EmbeddedChannel(new CountingHandler(meter.el));
        ch.writeInbound(Unpooled.wrappedBuffer(new byte[13]));
        ch.writeOutbound(Unpooled.wrappedBuffer(new byte[5]));
        ch.writeOutbound(Unpooled.wrappedBuffer(new byte[2]));
        assertEquals(13, meter.el.in());
        assertEquals(7, meter.el.out());
        assertEquals(0, meter.cl.in());
        ((ByteBuf) ch.readInbound()).release();
        ch.finishAndReleaseAll();
    }

    @Test
    void countsDatagramPayloads() {
        TrafficMeter meter = new TrafficMeter();
        EmbeddedChannel ch = new EmbeddedChannel(new CountingHandler(meter.el));
        InetSocketAddress peer = new InetSocketAddress("127.0.0.1", 30303);
        ch.writeInbound(new DatagramPacket(Unpooled.wrappedBuffer(new byte[98]), peer));
        ch.writeOutbound(new DatagramPacket(Unpooled.wrappedBuffer(new byte[150]), peer));
        assertEquals(98, meter.el.in());
        assertEquals(150, meter.el.out());
        ch.finishAndReleaseAll();
    }

    @Test
    void oneInstanceServesManyChannels() {
        // libp2p installs the same handler on every connection.
        TrafficMeter meter = new TrafficMeter();
        CountingHandler shared = new CountingHandler(meter.cl);
        EmbeddedChannel a = new EmbeddedChannel(shared);
        EmbeddedChannel b = new EmbeddedChannel(shared);
        a.writeInbound(Unpooled.wrappedBuffer(new byte[3]));
        b.writeInbound(Unpooled.wrappedBuffer(new byte[4]));
        assertEquals(7, meter.cl.in());
        a.finishAndReleaseAll();
        b.finishAndReleaseAll();
    }
}
