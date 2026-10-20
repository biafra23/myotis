package com.jaeckel.ethp2p.networking.traffic;

import com.jaeckel.ethp2p.core.traffic.TrafficMeter;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufHolder;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

/**
 * Counts the bytes that pass a Netty pipeline into one {@link TrafficMeter.Counter}:
 * every inbound and outbound {@link ByteBuf}, and the content of every
 * {@link ByteBufHolder} (a UDP {@code DatagramPacket}). Put it FIRST in the
 * pipeline, so what it sees is what the socket carries. Stateless beyond its
 * counter, so one instance may sit in many pipelines (libp2p installs it per
 * connection).
 */
@ChannelHandler.Sharable
public final class CountingHandler extends ChannelDuplexHandler {

    private final TrafficMeter.Counter counter;

    public CountingHandler(TrafficMeter.Counter counter) {
        this.counter = counter;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        counter.addIn(sizeOf(msg));
        super.channelRead(ctx, msg);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        // Sized before it is handed on: the buffer may be released once written.
        long n = sizeOf(msg);
        if (n > 0) {
            promise = promise.unvoid();
            promise.addListener(f -> {
                if (f.isSuccess()) counter.addOut(n);
            });
        }
        super.write(ctx, msg, promise);
    }

    static long sizeOf(Object msg) {
        if (msg instanceof ByteBuf b) return b.readableBytes();
        if (msg instanceof ByteBufHolder h) return h.content().readableBytes();
        return 0;
    }
}
