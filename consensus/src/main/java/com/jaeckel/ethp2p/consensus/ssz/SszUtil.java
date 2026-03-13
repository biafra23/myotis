package com.jaeckel.ethp2p.consensus.ssz;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class SszUtil {

    /**
     * Precomputed zero hashes for each depth level.
     * ZERO_HASHES[0] = 32 zero bytes (hash of empty leaf)
     * ZERO_HASHES[n] = SHA256(ZERO_HASHES[n-1] || ZERO_HASHES[n-1])
     */
    public static final byte[][] ZERO_HASHES = new byte[64][];

    static {
        ZERO_HASHES[0] = new byte[32];
        for (int i = 1; i < 64; i++) {
            ZERO_HASHES[i] = sha256(ZERO_HASHES[i - 1], ZERO_HASHES[i - 1]);
        }
    }

    private SszUtil() {}

    /**
     * SHA-256 hash of concatenation of two 32-byte arrays.
     */
    public static byte[] sha256(byte[] a, byte[] b) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(a);
            digest.update(b);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Returns the next power of 2 >= n. Returns 1 for n <= 1.
     */
    private static int nextPowerOfTwo(int n) {
        if (n <= 1) return 1;
        int p = 1;
        while (p < n) p <<= 1;
        return p;
    }

    /**
     * Merkleize an array of 32-byte chunks, padding to the next power of 2.
     */
    public static byte[] merkleize(byte[][] chunks) {
        int count = chunks.length;
        int size = nextPowerOfTwo(count);
        return merkleizeWithSize(chunks, size, 0);
    }

    /**
     * Merkleize an array of 32-byte chunks with a specific limit (max chunk count).
     * Pads to max(nextPow2(len), limit) using zero hashes.
     */
    public static byte[] merkleize(byte[][] chunks, int limit) {
        int count = chunks.length;
        int size = Math.max(nextPowerOfTwo(count), limit);
        return merkleizeWithSize(chunks, size, 0);
    }

    /**
     * Internal merkleization with explicit size and depth offset for zero hashes.
     */
    private static byte[] merkleizeWithSize(byte[][] chunks, int size, int depthOffset) {
        // Build bottom layer: fill provided chunks, pad remainder with zero hashes at depthOffset
        byte[][] layer = new byte[size][];
        for (int i = 0; i < size; i++) {
            if (i < chunks.length) {
                layer[i] = chunks[i];
            } else {
                layer[i] = ZERO_HASHES[depthOffset];
            }
        }

        // Hash pairwise bottom-up
        int depth = 0;
        while (layer.length > 1) {
            byte[][] next = new byte[layer.length / 2][];
            for (int i = 0; i < next.length; i++) {
                next[i] = sha256(layer[2 * i], layer[2 * i + 1]);
            }
            layer = next;
            depth++;
        }
        return layer[0];
    }

    /**
     * hash_tree_root of a uint64: LE-encode 8 bytes, zero-pad to 32 bytes.
     */
    public static byte[] hashTreeRootUint64(long value) {
        byte[] chunk = new byte[32];
        chunk[0] = (byte) (value);
        chunk[1] = (byte) (value >>> 8);
        chunk[2] = (byte) (value >>> 16);
        chunk[3] = (byte) (value >>> 24);
        chunk[4] = (byte) (value >>> 32);
        chunk[5] = (byte) (value >>> 40);
        chunk[6] = (byte) (value >>> 48);
        chunk[7] = (byte) (value >>> 56);
        return chunk;
    }

    /**
     * hash_tree_root of a bytes32: return the 32-byte array directly as a chunk.
     */
    public static byte[] hashTreeRootBytes32(byte[] b32) {
        if (b32.length != 32) {
            throw new IllegalArgumentException("Expected 32 bytes, got " + b32.length);
        }
        return Arrays.copyOf(b32, 32);
    }

    /**
     * hash_tree_root of a container: merkleize its field roots.
     */
    public static byte[] hashTreeRootContainer(byte[]... fieldRoots) {
        return merkleize(fieldRoots);
    }

    /**
     * mix_in_length: SHA256(root || LE64(length) zero-padded to 32 bytes).
     */
    public static byte[] mixInLength(byte[] root, long length) {
        byte[] lengthChunk = new byte[32];
        lengthChunk[0] = (byte) (length);
        lengthChunk[1] = (byte) (length >>> 8);
        lengthChunk[2] = (byte) (length >>> 16);
        lengthChunk[3] = (byte) (length >>> 24);
        lengthChunk[4] = (byte) (length >>> 32);
        lengthChunk[5] = (byte) (length >>> 40);
        lengthChunk[6] = (byte) (length >>> 48);
        lengthChunk[7] = (byte) (length >>> 56);
        return sha256(root, lengthChunk);
    }

    /**
     * Verify a Merkle branch (SSZ inclusion proof).
     *
     * @param leaf   32-byte leaf value (already hashed)
     * @param branch array of sibling hashes, one per level
     * @param depth  number of levels in the branch
     * @param index  generalized index of the leaf (determines left/right at each level)
     * @param root   expected 32-byte Merkle root
     * @return true if the branch is valid
     */
    public static boolean verifyMerkleBranch(byte[] leaf, byte[][] branch, int depth, int index, byte[] root) {
        if (branch.length != depth) {
            return false;
        }
        byte[] value = Arrays.copyOf(leaf, 32);
        for (int i = 0; i < depth; i++) {
            if (((index >>> i) & 1) == 1) {
                // current node is right child
                value = sha256(branch[i], value);
            } else {
                // current node is left child
                value = sha256(value, branch[i]);
            }
        }
        return Arrays.equals(value, root);
    }

    /**
     * Merkleize with a large limit efficiently using recursive zero-hash pruning.
     * For a tree with limit=1M but only 100 actual chunks, this does ~2000 hashes
     * instead of 1M by short-circuiting all-zero subtrees.
     */
    public static byte[] merkleizeSparse(byte[][] chunks, int limit) {
        if (limit <= 0) return ZERO_HASHES[0];
        int depth = 0;
        int n = nextPowerOfTwo(limit);
        while ((1 << depth) < n) depth++;
        return merkleizeSparseRec(chunks, 0, depth);
    }

    private static byte[] merkleizeSparseRec(byte[][] chunks, int offset, int depth) {
        if (depth == 0) {
            return offset < chunks.length ? chunks[offset] : ZERO_HASHES[0];
        }
        byte[] left = merkleizeSparseRec(chunks, offset, depth - 1);
        int rightOffset = offset + (1 << (depth - 1));
        byte[] right = rightOffset >= chunks.length
                ? ZERO_HASHES[depth - 1]
                : merkleizeSparseRec(chunks, rightOffset, depth - 1);
        return sha256(left, right);
    }

    /**
     * hash_tree_root of a fixed-length byte vector of any size.
     * Splits into 32-byte chunks (last chunk zero-padded) and merkleizes.
     */
    public static byte[] hashTreeRootByteVector(byte[] data) {
        int numChunks = (data.length + 31) / 32;
        byte[][] chunks = new byte[numChunks][];
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = new byte[32];
            int start = i * 32;
            int len = Math.min(32, data.length - start);
            System.arraycopy(data, start, chunks[i], 0, len);
        }
        return merkleize(chunks);
    }

    /**
     * hash_tree_root of a uint256 stored as 32 bytes LE (already a chunk).
     */
    public static byte[] hashTreeRootUint256(byte[] bytes32Le) {
        if (bytes32Le.length != 32) {
            throw new IllegalArgumentException("Expected 32 bytes for uint256, got " + bytes32Le.length);
        }
        return Arrays.copyOf(bytes32Le, 32);
    }

    /**
     * hash_tree_root of a bytes20 value: zero-pad to 32 bytes.
     */
    public static byte[] hashTreeRootBytes20(byte[] b20) {
        if (b20.length != 20) {
            throw new IllegalArgumentException("Expected 20 bytes, got " + b20.length);
        }
        byte[] chunk = new byte[32];
        System.arraycopy(b20, 0, chunk, 0, 20);
        return chunk;
    }

    /**
     * hash_tree_root of a bytes4 value: zero-pad to 32 bytes.
     */
    public static byte[] hashTreeRootBytes4(byte[] b4) {
        if (b4.length != 4) {
            throw new IllegalArgumentException("Expected 4 bytes, got " + b4.length);
        }
        byte[] chunk = new byte[32];
        System.arraycopy(b4, 0, chunk, 0, 4);
        return chunk;
    }

    /**
     * hash_tree_root of a bytes256 value (logsBloom): split into 8 chunks of 32 bytes each,
     * then merkleize.
     */
    public static byte[] hashTreeRootBytes256(byte[] b256) {
        if (b256.length != 256) {
            throw new IllegalArgumentException("Expected 256 bytes, got " + b256.length);
        }
        byte[][] chunks = new byte[8][32];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(b256, i * 32, chunks[i], 0, 32);
        }
        return merkleize(chunks);
    }

    /**
     * hash_tree_root for a variable-length byte list with a limit.
     * Chunks the data into 32-byte pieces, merkleizes with limit, then mixes in length.
     */
    public static byte[] hashTreeRootByteList(byte[] data, int chunkLimit) {
        int numChunks = (data.length + 31) / 32;
        byte[][] chunks = new byte[numChunks == 0 ? 1 : numChunks][32];
        for (int i = 0; i < numChunks; i++) {
            int start = i * 32;
            int end = Math.min(start + 32, data.length);
            System.arraycopy(data, start, chunks[i], 0, end - start);
        }
        byte[] root = merkleize(chunks, chunkLimit);
        return mixInLength(root, data.length);
    }

    // =========================================================================
    // SSZ little-endian readers
    // =========================================================================

    /** Read a little-endian uint32 from a byte array at the given offset. */
    public static int readUint32(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    /** Read a little-endian uint64 from a byte array at the given offset. */
    public static long readUint64(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    // =========================================================================
    // SSZ list hashing helpers
    // =========================================================================

    /**
     * Zero-hash root for an empty list with the given limit.
     * Returns ZERO_HASHES[depth] where depth = ceil(log2(limit)).
     */
    public static byte[] emptyListRoot(int limit) {
        if (limit <= 0) return ZERO_HASHES[0];
        int depth = 0;
        int n = 1;
        while (n < limit) { n <<= 1; depth++; }
        return ZERO_HASHES[depth];
    }

    /**
     * hash_tree_root of a Bitlist[maxBits]: remove delimiter bit, pack into chunks,
     * merkleize with chunk limit, mix in bit length.
     */
    public static byte[] hashBitlist(byte[] serialized, int maxBits) {
        if (serialized.length == 0) {
            int chunkLimit = (maxBits + 255) / 256;
            return mixInLength(emptyListRoot(chunkLimit), 0);
        }
        // Find delimiter bit (highest set bit in last byte)
        byte lastByte = serialized[serialized.length - 1];
        int delimPos = 7;
        while (delimPos >= 0 && ((lastByte >> delimPos) & 1) == 0) delimPos--;
        int bitLength = (serialized.length - 1) * 8 + delimPos;

        // Copy bytes and clear delimiter bit
        byte[] bits = Arrays.copyOf(serialized, serialized.length);
        bits[bits.length - 1] = (byte) (bits[bits.length - 1] & ~(1 << delimPos));
        int neededBytes = (bitLength + 7) / 8;

        // Pack into 32-byte chunks
        int numChunks = Math.max(1, (neededBytes + 31) / 32);
        byte[][] chunks = new byte[numChunks][];
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = new byte[32];
            int copyStart = i * 32;
            int copyLen = Math.min(32, Math.min(bits.length - copyStart, neededBytes - copyStart));
            if (copyLen > 0) System.arraycopy(bits, copyStart, chunks[i], 0, copyLen);
        }

        int chunkLimit = (maxBits + 255) / 256;
        byte[] root = chunkLimit > 256
                ? merkleizeSparse(chunks, chunkLimit)
                : merkleize(chunks, chunkLimit);
        return mixInLength(root, bitLength);
    }

    /**
     * hash_tree_root of a List[uint64, limit]: pack uint64s into 32-byte chunks (4 per chunk).
     */
    public static byte[] hashUint64List(byte[] data, int limit) {
        int count = data.length / 8;
        int numChunks = (count + 3) / 4;
        byte[][] chunks = new byte[numChunks][];
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = new byte[32];
            int base = i * 4;
            for (int j = 0; j < 4 && base + j < count; j++) {
                System.arraycopy(data, (base + j) * 8, chunks[i], j * 8, 8);
            }
        }
        int chunkLimit = (limit + 3) / 4;
        byte[] root = chunkLimit > 256
                ? merkleizeSparse(chunks, chunkLimit)
                : merkleize(chunks, chunkLimit);
        return mixInLength(root, count);
    }

    @FunctionalInterface
    public interface FixedElementHasher {
        byte[] hash(byte[] data, int offset);
    }

    @FunctionalInterface
    public interface VariableElementHasher {
        byte[] hash(byte[] data, int offset, int end);
    }

    /**
     * Hash a list of fixed-size composite elements.
     * hash_tree_root(List[T, limit]) = mixInLength(merkleize(element_roots, limit), count)
     */
    public static byte[] hashFixedElementList(byte[] data, int start, int end,
                                               int elementSize, int limit,
                                               FixedElementHasher hasher) {
        int len = end - start;
        int count = elementSize > 0 ? len / elementSize : 0;
        byte[][] roots = new byte[count][];
        for (int i = 0; i < count; i++) {
            roots[i] = hasher.hash(data, start + i * elementSize);
        }
        byte[] root = limit > 256
                ? merkleizeSparse(roots, limit)
                : merkleize(roots, limit);
        return mixInLength(root, count);
    }

    /**
     * Hash a list of variable-size composite elements (uses SSZ offsets).
     */
    public static byte[] hashVariableElementList(byte[] data, int start, int end,
                                                  int limit, VariableElementHasher hasher) {
        int len = end - start;
        if (len == 0) return mixInLength(emptyListRoot(limit), 0);

        int firstOffset = readUint32(data, start);
        int count = firstOffset / 4;
        if (count == 0) return mixInLength(emptyListRoot(limit), 0);

        int[] offsets = new int[count];
        for (int i = 0; i < count; i++) {
            offsets[i] = readUint32(data, start + i * 4);
        }

        byte[][] roots = new byte[count][];
        for (int i = 0; i < count; i++) {
            int elemStart = start + offsets[i];
            int elemEnd = (i + 1 < count) ? start + offsets[i + 1] : end;
            roots[i] = hasher.hash(data, elemStart, elemEnd);
        }

        byte[] root = limit > 256
                ? merkleizeSparse(roots, limit)
                : merkleize(roots, limit);
        return mixInLength(root, count);
    }
}
