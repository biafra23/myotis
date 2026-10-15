package io.myotis.engine.ports;

import io.myotis.api.ports.NodeKeyStore;
import io.myotis.engines.common.Hex;

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
            // The library's strict codec (ASCII digits only), the same one the Rust
            // engine's FFI boundary parses with — not a second, laxer copy.
            return Hex.parseHexPrefixed(hex);
        } catch (Exception e) {
            throw new RuntimeException("failed to read node key " + file + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void store(String networkName, byte[] secret32) {
        Path file = fileFor.apply(networkName);
        try {
            String hex = Hex.formatHexPrefixed(secret32);
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            Files.write(file, hex.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("failed to write node key " + file + ": " + e.getMessage(), e);
        }
    }
}
