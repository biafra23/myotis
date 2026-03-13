package com.jaeckel.ethp2p.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Unix Domain Socket server that accepts JSON-Lines IPC commands.
 *
 * <p>Each accepted connection is handled in its own virtual thread. Commands
 * are dispatched to {@link CommandHandler}. Multiple requests per connection
 * are supported (useful for {@code nc -U /tmp/ethp2p.sock} sessions).
 *
 * <p>The socket file is created on {@link #start()} and deleted on {@link #close()}.
 */
public class DaemonServer {

    private static final Logger log = LoggerFactory.getLogger(DaemonServer.class);

    private final Path socketPath;
    private final CommandHandler handler;
    private volatile ServerSocketChannel serverChannel;
    private volatile boolean closed;

    public DaemonServer(Path socketPath, CommandHandler handler) {
        this.socketPath = socketPath;
        this.handler = handler;
    }

    /**
     * Bind the UDS socket and start accepting connections in a virtual-thread acceptor loop.
     * Returns immediately; the acceptor runs in the background.
     */
    public void start() throws Exception {
        Files.deleteIfExists(socketPath);

        var addr = UnixDomainSocketAddress.of(socketPath);
        serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        serverChannel.bind(addr);

        log.info("[daemon] IPC socket listening at {}", socketPath);
        log.info("[daemon] Test with: echo '{{\"cmd\":\"status\"}}' | nc -U {}", socketPath);

        Thread.ofVirtual().name("ipc-acceptor").start(this::acceptLoop);
    }

    private void acceptLoop() {
        try {
            while (!Thread.currentThread().isInterrupted() && serverChannel.isOpen()) {
                SocketChannel client = serverChannel.accept();
                Thread.ofVirtual().name("ipc-client").start(() -> handleClient(client));
            }
        } catch (Exception e) {
            if (serverChannel.isOpen()) {
                log.warn("[daemon] Acceptor error: {}", e.getMessage());
            }
        }
    }

    /** Read JSON-Lines from the client, dispatch each line, write response, loop until EOF. */
    private void handleClient(SocketChannel channel) {
        try (channel) {
            var reader = new BufferedReader(
                    new InputStreamReader(Channels.newInputStream(channel)));
            var writer = new BufferedWriter(
                    new OutputStreamWriter(Channels.newOutputStream(channel)));

            String line;
            while ((line = reader.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty()) continue;
                String response = handler.handle(line);
                writer.write(response);
                writer.newLine();
                writer.flush();
            }
        } catch (Exception e) {
            log.debug("[daemon] Client disconnected: {}", e.getMessage());
        }
    }

    /** Close the server socket and remove the socket file. Safe to call multiple times. */
    public synchronized void close() {
        if (closed) return;
        closed = true;
        try {
            if (serverChannel != null) {
                serverChannel.close();
            }
        } catch (Exception e) {
            log.warn("[daemon] Error closing server channel: {}", e.getMessage());
        }
        try {
            Files.deleteIfExists(socketPath);
            log.info("[daemon] Socket file removed: {}", socketPath);
        } catch (Exception e) {
            log.warn("[daemon] Failed to remove socket file {}: {}", socketPath, e.getMessage());
        }
    }
}
