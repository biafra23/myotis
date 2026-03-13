package com.jaeckel.ethp2p.consensus.libp2p;

import org.xerial.snappy.SnappyFramedInputStream;
import org.xerial.snappy.SnappyFramedOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Handles Ethereum 2 req/resp framing over libp2p streams.
 *
 * Request wire format:
 *   varint(length) || snappy_frame_compressed(ssz_bytes)
 *
 * Response wire format:
 *   result_byte (1B): 0=success, 1=InvalidRequest, 2=ServerError, 3=ResourceUnavailable
 *   context_bytes (4B, fork digest)
 *   varint(length)
 *   snappy_frame_compressed(ssz_bytes)
 */
public final class ReqRespCodec {

    private ReqRespCodec() {}

    /**
     * Encodes an SSZ payload as a req/resp request frame:
     *   varint(compressed_length) || snappy_frame_compressed(ssz_bytes)
     *
     * If sszPayload is empty (length 0), equivalent to {@link #encodeEmptyRequest()}.
     */
    public static byte[] encodeRequest(byte[] sszPayload) throws IOException {
        if (sszPayload == null || sszPayload.length == 0) {
            return encodeEmptyRequest();
        }
        byte[] compressed = snappyCompress(sszPayload);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // eth2 spec: varint encodes UNCOMPRESSED SSZ length, not compressed
        writeVarint(out, sszPayload.length);
        out.write(compressed);
        return out.toByteArray();
    }

    /**
     * Encodes an empty request (for protocols like finality_update / optimistic_update
     * that send no SSZ payload): just varint(0), no compressed data follows.
     */
    public static byte[] encodeEmptyRequest() {
        // varint(0) = single byte 0x00
        return new byte[]{0x00};
    }

    /**
     * Decodes an Ethereum 2 req/resp response frame.
     *
     * @param rawBytes raw bytes read from the stream
     * @return DecodeResult with resultCode, forkDigest (4 bytes), and decompressed SSZ payload
     * @throws IllegalArgumentException if resultCode != 0 (error response from peer)
     * @throws IOException if the snappy decompression or reading fails
     */
    public static DecodeResult decodeResponse(byte[] rawBytes) throws IOException {
        if (rawBytes == null || rawBytes.length < 1) {
            throw new IllegalArgumentException("Response too short: no result byte");
        }

        int pos = 0;

        // Byte 0: result code
        byte resultCode = rawBytes[pos++];

        if (resultCode != 0) {
            // Read any error message for context (best effort)
            String errorMsg = "";
            try {
                if (pos + 4 < rawBytes.length) {
                    // skip fork digest if present, then read remaining as message
                    errorMsg = new String(rawBytes, pos, rawBytes.length - pos, java.nio.charset.StandardCharsets.UTF_8).trim();
                }
            } catch (Exception ignored) {}

            String errorType = switch (resultCode) {
                case 1 -> "InvalidRequest";
                case 2 -> "ServerError";
                case 3 -> "ResourceUnavailable";
                default -> "Unknown(" + (resultCode & 0xFF) + ")";
            };
            throw new IllegalArgumentException("Peer returned error: " + errorType +
                    (errorMsg.isEmpty() ? "" : " — " + errorMsg));
        }

        // Bytes 1..4: fork digest (4 bytes context)
        if (rawBytes.length < pos + 4) {
            throw new IllegalArgumentException("Response too short: missing fork digest (need 4 bytes after result, have " +
                    (rawBytes.length - pos) + ")");
        }
        byte[] forkDigest = new byte[4];
        System.arraycopy(rawBytes, pos, forkDigest, 0, 4);
        pos += 4;

        // Next: varint(uncompressed SSZ payload length) per eth2 req/resp spec
        VarintResult varint = readVarint(rawBytes, pos);
        pos = varint.nextPos;
        int uncompressedLength = varint.value;

        if (uncompressedLength == 0) {
            // Empty payload
            return new DecodeResult(resultCode, forkDigest, new byte[0]);
        }

        // All remaining bytes are the snappy-framed compressed payload
        int compressedLength = rawBytes.length - pos;
        if (compressedLength <= 0) {
            throw new IllegalArgumentException(
                    "Response truncated: no compressed data after header");
        }

        byte[] compressedData = new byte[compressedLength];
        System.arraycopy(rawBytes, pos, compressedData, 0, compressedLength);
        byte[] sszPayload = snappyDecompress(compressedData);

        return new DecodeResult(resultCode, forkDigest, sszPayload);
    }

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    /**
     * Result of decoding a response frame.
     */
    public record DecodeResult(
            byte resultCode,
            byte[] forkDigest,
            byte[] sszPayload
    ) {}

    // -------------------------------------------------------------------------
    // Varint encoding (protobuf-style unsigned)
    // -------------------------------------------------------------------------

    /**
     * Write a protobuf-style unsigned varint to the output stream.
     * Values 0-127 encode as a single byte. Larger values use 7 data bits per byte,
     * with the MSB set to 1 indicating more bytes follow.
     */
    static void writeVarint(ByteArrayOutputStream out, int value) {
        // Handle unsigned — cast to long to avoid sign-extension issues with large values
        long v = Integer.toUnsignedLong(value);
        while (true) {
            if ((v & ~0x7FL) == 0) {
                out.write((int) v);
                return;
            }
            out.write((int) ((v & 0x7F) | 0x80));
            v >>>= 7;
        }
    }

    /**
     * Read a protobuf-style unsigned varint from a byte array starting at pos.
     *
     * @return VarintResult with the decoded integer value and the position after the varint
     */
    static VarintResult readVarint(byte[] data, int pos) {
        int result = 0;
        int shift = 0;
        while (pos < data.length) {
            int b = data[pos++] & 0xFF;
            result |= (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) {
                return new VarintResult(result, pos);
            }
            if (shift >= 35) {
                throw new IllegalArgumentException("Varint too long (overflow at shift " + shift + ")");
            }
        }
        throw new IllegalArgumentException("Truncated varint at position " + pos);
    }

    record VarintResult(int value, int nextPos) {}

    // -------------------------------------------------------------------------
    // Snappy framing helpers
    // -------------------------------------------------------------------------

    /**
     * Compress bytes using Snappy framing format.
     */
    static byte[] snappyCompress(byte[] input) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (SnappyFramedOutputStream snappyOut = new SnappyFramedOutputStream(baos)) {
            snappyOut.write(input);
        }
        return baos.toByteArray();
    }

    /**
     * Decompress bytes using Snappy framing format.
     */
    static byte[] snappyDecompress(byte[] input) throws IOException {
        try (SnappyFramedInputStream snappyIn = new SnappyFramedInputStream(
                new ByteArrayInputStream(input))) {
            return snappyIn.readAllBytes();
        }
    }
}
