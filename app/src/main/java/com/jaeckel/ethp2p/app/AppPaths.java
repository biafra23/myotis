package com.jaeckel.ethp2p.app;

import com.jaeckel.ethp2p.networking.NetworkConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Per-user, per-OS locations for a packaged desktop install.
 *
 * <p>The CLI daemon historically writes its socket/lock to {@code /tmp} and its keys/caches
 * into the process working directory. That's fine for {@code ./gradlew :app:run} from a repo
 * checkout, but a jpackage'd desktop app has a read-only install directory and (on Windows)
 * no {@code /tmp}. This helper resolves OS-appropriate writable locations instead:
 *
 * <ul>
 *   <li><b>Linux</b> — {@code $XDG_DATA_HOME/myotis} (default {@code ~/.local/share/myotis});
 *       socket in {@code $XDG_RUNTIME_DIR} when set.</li>
 *   <li><b>macOS</b> — {@code ~/Library/Application Support/Myotis}; socket in {@code $TMPDIR}
 *       (kept short so the {@code AF_UNIX} path stays under the ~104-char limit).</li>
 *   <li><b>Windows</b> — {@code %LOCALAPPDATA%\Myotis}.</li>
 * </ul>
 *
 * <p>Everything can be overridden with {@code MYOTIS_DATA_DIR}; the socket path additionally
 * honours the daemon's existing {@code ETHP2P_SOCKET} override (handled in {@link Main}).
 */
public final class AppPaths {

    private AppPaths() {}

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static boolean isMac() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("mac") || os.contains("darwin");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** Writable base directory for keys, caches, and the verified-state snapshot. */
    public static Path dataDir() {
        String override = System.getenv("MYOTIS_DATA_DIR");
        if (!isBlank(override)) return Path.of(override);

        String home = System.getProperty("user.home", ".");
        if (isWindows()) {
            String local = System.getenv("LOCALAPPDATA");
            Path base = isBlank(local) ? Path.of(home, "AppData", "Local") : Path.of(local);
            return base.resolve("Myotis");
        }
        if (isMac()) {
            return Path.of(home, "Library", "Application Support", "Myotis");
        }
        String xdg = System.getenv("XDG_DATA_HOME");
        Path base = isBlank(xdg) ? Path.of(home, ".local", "share") : Path.of(xdg);
        return base.resolve("myotis");
    }

    /**
     * Short-lived runtime directory for the {@code AF_UNIX} IPC socket. Kept separate from
     * {@link #dataDir()} because {@code sun.nio} caps the socket path length (~108 on Linux,
     * ~104 on macOS) and the data dir can be long.
     */
    public static Path runtimeDir() {
        if (isWindows()) {
            // No /tmp on Windows, and the embedded GUI doesn't need the socket for itself.
            return dataDir();
        }
        if (isMac()) {
            String tmp = System.getenv("TMPDIR");
            return isBlank(tmp) ? Path.of("/tmp") : Path.of(tmp);
        }
        String run = System.getenv("XDG_RUNTIME_DIR");
        return isBlank(run) ? Path.of("/tmp") : Path.of(run);
    }

    /** Network suffix mirroring {@link Main}'s socket/cache naming ("" for mainnet). */
    private static String suffix(String networkName) {
        return "mainnet".equals(networkName) ? "" : "-" + networkName;
    }

    /**
     * Build a {@link DaemonRuntime.Config} rooted at the per-OS locations, creating the
     * directories if needed. Honours {@code ETHP2P_SOCKET} for the socket path so an
     * external CLI can be pointed at the GUI's daemon.
     */
    public static DaemonRuntime.Config daemonConfig(NetworkConfig network, int port, boolean gossipsubEnabled) {
        Path data = dataDir();
        Path runtime = runtimeDir();
        try {
            Files.createDirectories(data);
            Files.createDirectories(runtime);
        } catch (IOException e) {
            throw new RuntimeException("Cannot create Myotis data directory at " + data + ": " + e.getMessage(), e);
        }

        String suffix = suffix(network.name());
        String socketEnv = System.getenv("ETHP2P_SOCKET");
        Path socket = isBlank(socketEnv)
                ? runtime.resolve("ethp2p" + suffix + ".sock")
                : Path.of(socketEnv);

        return new DaemonRuntime.Config(
                network,
                port,
                gossipsubEnabled,
                socket,
                data.resolve("ethp2p" + suffix + ".lock"),
                data.resolve("nodekey.hex"),
                data.resolve("peers" + suffix + ".cache"),
                data.resolve("cl-peers" + suffix + ".cache"),
                data.resolve("sync-state" + suffix + ".snapshot"));
    }
}
