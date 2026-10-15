package io.myotis.engine.ports;

import io.myotis.api.ports.NodeKeyStore;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Function;

/**
 * Node-identity storage as one hex file per network — {@code 0x}-prefixed lowercase
 * hex of the 32-byte secret, no newline — byte-compatible with the files the Myotis
 * hosts have always written, so an existing install's identities carry over.
 *
 * <p>Hand-rolled hex on purpose: {@code java.util.HexFormat} is API 34 and not covered
 * by core-library desugaring, so it would crash at runtime on minSdk 29.
 */
public final class FileNodeKeyStore implements NodeKeyStore {

    private final Function<String, Path> fileFor;

    /** One file per network, named by {@code fileFor} from the canonical network name. */
    public FileNodeKeyStore(Function<String, Path> fileFor) {
        this.fileFor = Objects.requireNonNull(fileFor, "fileFor");
    }

    /** The default layout: {@link NetworkFiles#nodeKey} under {@code keyDir}. */
    public static FileNodeKeyStore inDirectory(Path keyDir) {
        Objects.requireNonNull(keyDir, "keyDir");
        return new FileNodeKeyStore(network -> NetworkFiles.nodeKey(keyDir, network));
    }

    @Override
    public byte[] load(String networkName) {
        Path file = fileFor.apply(networkName);
        if (!Files.exists(file)) return null;
        try {
            String hex = new String(Files.readAllBytes(file), StandardCharsets.UTF_8).strip();
            if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
            if (hex.length() % 2 != 0) throw new IllegalArgumentException("odd-length hex");
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) {
                int hi = Character.digit(hex.charAt(i * 2), 16);
                int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
                if (hi < 0 || lo < 0) throw new IllegalArgumentException("non-hex character");
                out[i] = (byte) ((hi << 4) | lo);
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException("failed to read node key " + file + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void store(String networkName, byte[] secret32) {
        Path file = fileFor.apply(networkName);
        try {
            StringBuilder sb = new StringBuilder(2 + secret32.length * 2);
            sb.append("0x");
            for (byte b : secret32) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16))
                  .append(Character.forDigit(b & 0xF, 16));
            }
            Files.write(file, sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("failed to write node key " + file + ": " + e.getMessage(), e);
        }
    }
}
