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
            channel.shutdownOutput();

            String response;
            while ((response = reader.readLine()) != null) {
                System.out.println(response);
            }
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
            case "status", "peers", "stop", "pause", "resume" -> "{\"cmd\":\"" + esc(cmd) + "\"}";
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
                yield "{\"cmd\":\"get-account\",\"address\":\"" + esc(args[1]) + "\"}";
            }
            case "get-storage" -> {
                if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: get-storage <contractAddress> <slot> [holderAddress]");
                String json = "{\"cmd\":\"get-storage\",\"address\":\"" + esc(args[1])
                    + "\",\"slot\":\"" + esc(args[2]) + "\"";
                if (args.length > 3) json += ",\"holder\":\"" + esc(args[3]) + "\"";
                json += "}";
                yield json;
            }
            case "dial" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: dial <enode://pubkey@host:port>");
                yield "{\"cmd\":\"dial\",\"enode\":\"" + esc(args[1]) + "\"}";
            }
            case "get-transactions" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: get-transactions <0xAddress>");
                yield "{\"cmd\":\"get-transactions\",\"address\":\"" + esc(args[1]) + "\"}";
            }
            case "resolve-ens" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: resolve-ens <name.eth>");
                yield "{\"cmd\":\"resolve-ens\",\"name\":\"" + esc(args[1]) + "\"}";
            }
            case "reverse-ens" -> {
                if (args.length < 2) throw new IllegalArgumentException("Usage: reverse-ens <0xaddress>");
                yield "{\"cmd\":\"reverse-ens\",\"address\":\"" + esc(args[1]) + "\"}";
            }
            case "resolve-ens-text" -> {
                if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: resolve-ens-text <name.eth> <key>");
                yield "{\"cmd\":\"resolve-ens-text\",\"name\":\"" + esc(args[1])
                    + "\",\"key\":\"" + esc(args[2]) + "\"}";
            }
            case "resolve-ens-contenthash" -> {
                if (args.length < 2) throw new IllegalArgumentException(
                    "Usage: resolve-ens-contenthash <name.eth>");
                yield "{\"cmd\":\"resolve-ens-contenthash\",\"name\":\"" + esc(args[1]) + "\"}";
            }
            case "resolve-ens-addr-coin" -> {
                if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: resolve-ens-addr-coin <name.eth> <coinType>");
                yield "{\"cmd\":\"resolve-ens-addr-coin\",\"name\":\"" + esc(args[1])
                    + "\",\"coinType\":" + Long.parseLong(args[2]) + "}";
            }
            case "resolve-ens-pubkey" -> {
                if (args.length < 2) throw new IllegalArgumentException(
                    "Usage: resolve-ens-pubkey <name.eth>");
                yield "{\"cmd\":\"resolve-ens-pubkey\",\"name\":\"" + esc(args[1]) + "\"}";
            }
            case "resolve-ens-abi" -> {
                if (args.length < 2) throw new IllegalArgumentException(
                    "Usage: resolve-ens-abi <name.eth> [contentTypes]");
                String json = "{\"cmd\":\"resolve-ens-abi\",\"name\":\"" + esc(args[1]) + "\"";
                if (args.length > 2) {
                    json += ",\"contentTypes\":" + Long.parseLong(args[2]);
                }
                json += "}";
                yield json;
            }
            case "resolve-ens-dns" -> {
                if (args.length < 4) throw new IllegalArgumentException(
                    "Usage: resolve-ens-dns <name.eth> <dnsName> <resource>");
                yield "{\"cmd\":\"resolve-ens-dns\",\"name\":\"" + esc(args[1])
                    + "\",\"dnsName\":\"" + esc(args[2])
                    + "\",\"resource\":" + Long.parseLong(args[3]) + "}";
            }
            case "resolve-ens-interface" -> {
                if (args.length < 3) throw new IllegalArgumentException(
                    "Usage: resolve-ens-interface <name.eth> <0xInterfaceId>");
                yield "{\"cmd\":\"resolve-ens-interface\",\"name\":\"" + esc(args[1])
                    + "\",\"interfaceId\":\"" + esc(args[2]) + "\"}";
            }
            case "import-logindex" -> {
                if (args.length < 2) throw new IllegalArgumentException(
                    "Usage: import-logindex <file> [<file> ...]");
                StringBuilder sb = new StringBuilder("{\"cmd\":\"import-logindex\",\"paths\":[");
                for (int i = 1; i < args.length; i++) {
                    if (i > 1) sb.append(',');
                    // Absolute: the daemon's working directory is not the caller's.
                    sb.append('"')
                      .append(esc(java.nio.file.Path.of(args[i]).toAbsolutePath().normalize().toString()))
                      .append('"');
                }
                yield sb.append("]}").toString();
            }
            default -> "{\"cmd\":\"" + esc(cmd) + "\"}";
        };
    }

    /**
     * Minimal JSON string escaper for user-provided CLI args before they're
     * concatenated into a request body. Daemon command strings are expected
     * to be plain identifiers (addresses, ENS names, hex), but a stray
     * {@code "} or {@code \} would otherwise produce invalid JSON and could
     * inject extra fields into the daemon command stream. Backslash must be
     * escaped first so the subsequent quote-escape doesn't double-escape its
     * own output.
     */
    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"'  -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
