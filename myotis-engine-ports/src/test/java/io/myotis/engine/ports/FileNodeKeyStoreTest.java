package io.myotis.engine.ports;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FileNodeKeyStoreTest {

    private static byte[] secret() {
        byte[] s = new byte[32];
        for (int i = 0; i < s.length; i++) s[i] = (byte) (i * 7 + 3);
        return s;
    }

    @Test
    void storesTheLegacyFormatAndLoadsItBack(@TempDir Path dir) throws Exception {
        FileNodeKeyStore store = FileNodeKeyStore.inDirectory(dir);
        assertNull(store.load("mainnet"), "no file yet");
        store.store("mainnet", secret());
        // 0x-prefixed lowercase hex, no newline — what NodeKey.loadOrGenerate always wrote.
        String body = new String(Files.readAllBytes(dir.resolve("nodekey.hex")), StandardCharsets.UTF_8);
        assertEquals(66, body.length());
        assertEquals("0x030a", body.substring(0, 6)); // 3, then 10
        assertEquals(body, body.toLowerCase());
        assertArrayEquals(secret(), store.load("mainnet"));
    }

    @Test
    void readsAFileWithoutThePrefixAndWithWhitespace(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("nodekey-gnosis.hex"), ("  " + "AB".repeat(32) + "\n").getBytes(StandardCharsets.UTF_8));
        byte[] loaded = FileNodeKeyStore.inDirectory(dir).load("gnosis");
        assertEquals(32, loaded.length);
        assertEquals((byte) 0xab, loaded[0]);
    }

    @Test
    void otherNetworksGetTheirOwnFile(@TempDir Path dir) {
        FileNodeKeyStore store = FileNodeKeyStore.inDirectory(dir);
        store.store("sepolia", secret());
        assertNull(store.load("mainnet"), "mainnet must not share sepolia's identity");
        assertArrayEquals(secret(), store.load("sepolia"));
    }

    @Test
    void aCorruptFileIsAnError(@TempDir Path dir) throws Exception {
        Files.write(dir.resolve("nodekey.hex"), "0xzz".getBytes(StandardCharsets.UTF_8));
        assertThrows(RuntimeException.class, () -> FileNodeKeyStore.inDirectory(dir).load("mainnet"));
    }
}
