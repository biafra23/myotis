package com.jaeckel.ethp2p.networking.rlpx;

import com.jaeckel.ethp2p.core.crypto.NodeKey;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.handler.codec.ByteToMessageDecoder;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.function.Consumer;

/**
 * Netty channel handler for RLPx.
 *
 * State machine:
 *   HANDSHAKE_WRITE  → sends auth message
 *   HANDSHAKE_READ   → waits for ack, then transitions to FRAMED
 *   FRAMED           → reads frames, dispatches decoded messages
 *
 * After handshake, decoded (messageCode, payload) pairs are passed to
 * the provided messageConsumer for the eth/snap protocol handler.
 */
public final class RLPxHandler extends ByteToMessageDecoder {

    private static final Logger log = LoggerFactory.getLogger(RLPxHandler.class);

    // Approximate max size of an encrypted ack (EIP-8 with padding can be up to ~600 bytes)
    private static final int MAX_ACK_SIZE = 1024;
    // Minimum ack size: 0x04(1) + ephPub(65) + IV(16) + rlp-data(~100) + mac(32) ≈ 214
    private static final int MIN_ACK_SIZE = 200;

    private enum State { HANDSHAKE_WRITE, HANDSHAKE_READ, FRAMED }

    private State state = State.HANDSHAKE_WRITE;

    private final NodeKey localKey;
    private final SECP256K1.PublicKey remotePubkey;
    private final Consumer<RLPxMessage> messageConsumer;

    private AuthHandshake handshake;
    private FrameCodec frameCodec;
    private int pendingBodyLen = -1;

    public record RLPxMessage(int code, byte[] payload) {}

    public RLPxHandler(NodeKey localKey, SECP256K1.PublicKey remotePubkey,
                       Consumer<RLPxMessage> messageConsumer) {
        this.localKey = localKey;
        this.remotePubkey = remotePubkey;
        this.messageConsumer = messageConsumer;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        log.debug("[rlpx] Connected to {}, sending auth", ctx.channel().remoteAddress());
        handshake = new AuthHandshake(localKey, remotePubkey);
        Bytes authMsg = handshake.buildAuthMessage();
        log.debug("[rlpx] auth message: size={}, first4bytes={}",
            authMsg.size(), authMsg.slice(0, Math.min(4, authMsg.size())).toHexString());
        ByteBuf buf = ctx.alloc().buffer(authMsg.size());
        buf.writeBytes(authMsg.toArrayUnsafe());
        ctx.writeAndFlush(buf);
        state = State.HANDSHAKE_READ;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        log.debug("[rlpx] decode() called, state={}, readableBytes={}", state, in.readableBytes());
        switch (state) {
            case HANDSHAKE_READ -> decodeAck(ctx, in);
            case FRAMED -> decodeFrames(ctx, in);
            default -> { /* HANDSHAKE_WRITE: no data expected yet */ }
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.warn("[rlpx] Connection closed by peer: {} (state={})", ctx.channel().remoteAddress(), state);
        super.channelInactive(ctx);  // propagate to EthHandler
    }

    // -------------------------------------------------------------------------
    // Handshake: read ack
    // -------------------------------------------------------------------------
    private void decodeAck(ChannelHandlerContext ctx, ByteBuf in) {
        // The ack size is variable (EIP-8). We need to read enough bytes.
        // EIP-8: first 2 bytes of the ciphertext are the big-endian size of the encrypted message
        // (only in EIP-8 format). For our purposes, we buffer until we have a complete ack.

        if (in.readableBytes() < 2) return;

        // Peek at first 2 bytes to determine if this is EIP-8 (size prefix) or legacy
        int savedIdx = in.readerIndex();
        int firstByte = in.getUnsignedByte(in.readerIndex());

        int ackSize;
        boolean eip8;
        if (firstByte == 0x04) {
            // Legacy format: fixed size 210 bytes
            ackSize = 210;
            eip8 = false;
        } else {
            // EIP-8: first 2 bytes are big-endian total size
            if (in.readableBytes() < 2) return;
            ackSize = in.getUnsignedShort(in.readerIndex()) + 2; // +2 for the size prefix itself
            eip8 = true;
        }

        if (in.readableBytes() < ackSize) return;

        byte[] ackBytes = new byte[ackSize];
        in.readBytes(ackBytes);

        try {
            Bytes ack;
            byte[] ackAad;
            if (eip8) {
                ackAad = new byte[]{ackBytes[0], ackBytes[1]}; // ack-size as HMAC AAD
                ack = Bytes.wrap(ackBytes, 2, ackSize - 2);
            } else {
                ackAad = new byte[0];
                ack = Bytes.wrap(ackBytes);
            }
            handshake.processAck(ack, ackAad, ackBytes);
            SessionSecrets secrets = handshake.secrets();
            frameCodec = new FrameCodec(secrets);
            state = State.FRAMED;
            log.info("[rlpx] Handshake complete with {}", ctx.channel().remoteAddress());
            // Signal to the eth handler that the connection is ready
            ctx.fireUserEventTriggered("RLPX_READY");
        } catch (Exception e) {
            log.error("[rlpx] Handshake failed: {}", e.getMessage());
            ctx.close();
        }
    }

    // -------------------------------------------------------------------------
    // Frame decoding
    // -------------------------------------------------------------------------
    private void decodeFrames(ChannelHandlerContext ctx, ByteBuf in) {
        while (true) {
            if (pendingBodyLen < 0) {
                // Need to read header (16) + header-mac (16) = 32 bytes
                if (in.readableBytes() < 32) return;
                byte[] encHeader = new byte[16];
                byte[] headerMac = new byte[16];
                in.readBytes(encHeader);
                in.readBytes(headerMac);
                try {
                    pendingBodyLen = frameCodec.decodeHeader(encHeader, headerMac);
                } catch (Exception e) {
                    log.error("[rlpx] Frame header error: {}", e.getMessage());
                    ctx.close();
                    return;
                }
            }

            // Padded body length (round up to 16)
            int paddedBodyLen = (pendingBodyLen + 15) & ~15;
            // Need: paddedBody (paddedBodyLen) + body-mac (16)
            if (in.readableBytes() < paddedBodyLen + 16) return;

            byte[] encBody = new byte[paddedBodyLen];
            byte[] bodyMac = new byte[16];
            in.readBytes(encBody);
            in.readBytes(bodyMac);

            int capturedBodyLen = pendingBodyLen;
            pendingBodyLen = -1;

            try {
                FrameCodec.DecodeResult result = frameCodec.decodeBody(encBody, bodyMac, capturedBodyLen);
                messageConsumer.accept(new RLPxMessage(result.messageCode(), result.payload()));
            } catch (Exception e) {
                log.error("[rlpx] Frame body error: {}", e.getMessage());
                ctx.close();
                return;
            }
        }
    }

    /**
     * Send an RLPx framed message.
     * Frame encoding (AES-CTR cipher + Keccak MAC) is stateful and not thread-safe,
     * so we must ensure it always runs on the channel's event loop thread.
     */
    public void sendMessage(ChannelHandlerContext ctx, int code, byte[] payload) {
        if (frameCodec == null) throw new IllegalStateException("Handshake not complete");
        if (ctx.executor().inEventLoop()) {
            doSendMessage(ctx, code, payload);
        } else {
            ctx.executor().execute(() -> doSendMessage(ctx, code, payload));
        }
    }

    private void doSendMessage(ChannelHandlerContext ctx, int code, byte[] payload) {
        byte[] frame = frameCodec.encodeFrame(code, payload);
        ByteBuf buf = ctx.alloc().buffer(frame.length);
        buf.writeBytes(frame);
        log.debug("[rlpx] sendMessage code=0x{} payload={} bytes frame={} bytes to {}",
            Integer.toHexString(code), payload.length, frame.length,
            ctx.channel().remoteAddress());
        ctx.writeAndFlush(buf);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.error("[rlpx] Exception", cause);
        ctx.close();
    }
}
