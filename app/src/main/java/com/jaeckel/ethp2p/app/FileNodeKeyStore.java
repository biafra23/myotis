package com.jaeckel.ethp2p.app;

import io.myotis.api.ports.NodeKeyStore;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.function.Function;

/**
 * The daemon's node-identity storage: one hex file per network (mainnet keeps the legacy
 * {@code nodekey.hex}), byte-compatible with the files {@code NodeKey.loadOrGenerate} has
 * always written, so existing identities carry over unchanged.
 */
public final class FileNodeKeyStore implements NodeKeyStore {

    private final Function<String, Path> fileFor;

    public FileNodeKeyStore(Function<String, Path> fileFor) {
        this.fileFor = fileFor;
    }

    @Override
    public byte[] load(String networkName) {
        Path file = fileFor.apply(networkName);
        if (!Files.exists(file)) return null;
        try {
            String hex = new String(Files.readAllBytes(file), StandardCharsets.UTF_8).strip();
            if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2);
            return HexFormat.of().parseHex(hex);
        } catch (Exception e) {
            throw new RuntimeException("failed to read node key " + file + ": " + e.getMessage(), e);
        }
    }

    @Override
    public void store(String networkName, byte[] secret32) {
        Path file = fileFor.apply(networkName);
        try {
            // Same format loadOrGenerate wrote: 0x-prefixed lowercase hex, no newline.
            Files.write(file, ("0x" + HexFormat.of().formatHex(secret32))
                    .getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("failed to write node key " + file + ": " + e.getMessage(), e);
        }
    }
}
