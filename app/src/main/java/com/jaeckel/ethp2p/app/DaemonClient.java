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
import java.nio.channels.SocketChannel;
import java.nio.file.Path;

/**
 * Connects to the daemon's Unix Domain Socket, sends one JSON-Lines command,
 * prints the JSON response to stdout, then exits.
 *
 * <p>Usage via Gradle:
 * <pre>
 *   ./gradlew :app:run -Pargs=status
 *   ./gradlew :app:run -Pargs=peers
 *   ./gradlew :app:run -Pargs="get-headers 21000000 3"
 *   ./gradlew :app:run -Pargs=stop
 * </pre>
 *
 * <p>Or via nc:
 * <pre>
 *   echo '{"cmd":"status"}' | nc -U /tmp/ethp2p.sock
 * </pre>
 */
public class DaemonClient {

    private static final Logger log = LoggerFactory.getLogger(DaemonClient.class);

    /**
     * Send a command to the running daemon and print the response.
     *
     * @param args       CLI arguments (args[0] = command name, rest = parameters)
     * @param socketPath path to the Unix Domain Socket file
     */
    public static void sendCommand(String[] args, Path socketPath) throws Exception {
        String json = buildJson(args);
        log.debug("[client] Sending: {}", json);

        var addr = UnixDomainSocketAddress.of(socketPath);
        try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(addr);

            var writer = new BufferedWriter(
                    new OutputStreamWriter(Channels.newOutputStream(channel)));
            var reader = new BufferedReader(
                    new InputStreamReader(Channels.newInputStream(channel)));

            writer.write(json);
            writer.newLine();
            writer.flush();

            String response = reader.readLine();
            System.out.println(response);
        }
    }

    /**
     * Convert CLI args to a JSON-Lines request string.
     *
     * <p>Supported commands:
     * <ul>
     *   <li>{@code status} → {@code {"cmd":"status"}}
     *   <li>{@code peers} → {@code {"cmd":"peers"}}
     *   <li>{@code stop} → {@code {"cmd":"stop"}}
     *   <li>{@code get-headers [blockNumber] [count]} →
     *       {@code {"cmd":"get-headers","blockNumber":N,"count":C}}
     * </ul>
     */
    static String buildJson(String[] args) {
        if (args.length == 0) throw new IllegalArgumentException("No command specified");
        String cmd = args[0];
        return switch (cmd) {
            case "status", "peers", "stop" -> "{\"cmd\":\"" + cmd + "\"}";
            case "get-headers" -> {
                long blockNumber = args.length > 1 ? Long.parseLong(args[1]) : 21_000_000L;
                int count       = args.length > 2 ? Integer.parseInt(args[2]) : 3;
                yield "{\"cmd\":\"get-headers\",\"blockNumber\":" + blockNumber
                        + ",\"count\":" + count + "}";
            }
            case "get-block" -> {
                long blockNumber = args.length > 1 ? Long.parseLong(args[1]) : 21_000_000L;
                yield "{\"cmd\":\"get-block\",\"blockNumber\":" + blockNumber + "}";
            }
            case "get-account" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: get-account <0xAddress>");
                yield "{\"cmd\":\"get-account\",\"address\":\"" + args[1] + "\"}";
            }
            case "get-storage" -> {
                if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: get-storage <contractAddress> <slot> [holderAddress]");
                String json = "{\"cmd\":\"get-storage\",\"address\":\"" + args[1]
                    + "\",\"slot\":\"" + args[2] + "\"";
                if (args.length > 3) json += ",\"holder\":\"" + args[3] + "\"";
                json += "}";
                yield json;
            }
            case "dial" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: dial <enode://pubkey@host:port>");
                yield "{\"cmd\":\"dial\",\"enode\":\"" + args[1] + "\"}";
            }
            default -> "{\"cmd\":\"" + cmd + "\"}";
        };
    }
}
