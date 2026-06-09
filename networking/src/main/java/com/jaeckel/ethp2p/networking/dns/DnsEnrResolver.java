package com.jaeckel.ethp2p.networking.dns;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * EIP-1459 DNS ENR tree resolver.
 *
 * <p>Walks an {@code enrtree://} tree anchored at a DNS domain, verifies the
 * root TXT record against the tree operator's secp256k1 public key, and returns
 * the list of ENRs at the leaves. Failures are logged and do not propagate —
 * the resolver returns whatever it successfully resolved.
 *
 * <p>Only the ENR subtree ({@code e=}) is walked; the link subtree ({@code l=})
 * is ignored because this client doesn't chase cross-tree links.
 */
public final class DnsEnrResolver {

    private static final Logger log = LoggerFactory.getLogger(DnsEnrResolver.class);

    private static final String ROOT_PREFIX = "enrtree-root:v1 ";
    private static final String BRANCH_PREFIX = "enrtree-branch:";
    private static final String LEAF_PREFIX = "enr:";

    /** Maximum total TXT lookups (branch + leaf) per tree. Caps DNS traffic even when
     *  a tree is large or malformed. 512 comfortably covers dev/seed needs. */
    static final int DEFAULT_MAX_NODES = 512;
    /** Maximum branch depth to walk. */
    static final int DEFAULT_MAX_DEPTH = 16;
    /** Grace beyond the deadline to let an in-flight tree walk return its partial
     *  results before we snapshot them. Covers one last lookup (which may try a few
     *  servers). Without it, results collected right at the deadline are dropped. */
    private static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(5);

    private final TxtResolver txtResolver;
    private final int maxNodes;
    private final int maxDepth;

    /** Explicit DNS server IPs to query, highest priority first. Empty = use the
     *  JVM/system resolver config. dnsjava's default {@code SimpleResolver()} relies
     *  on {@code ResolverConfig} reading /etc/resolv.conf, which is absent on Android
     *  (the lookup then fails with "network error"), so the Android layer must inject
     *  the active network's DNS servers here via {@link #setDnsServerIps}. */
    private volatile List<String> dnsServerIps = List.of();

    public DnsEnrResolver() {
        this.maxNodes = DEFAULT_MAX_NODES;
        this.maxDepth = DEFAULT_MAX_DEPTH;
        this.txtResolver = this::instanceTxtLookup;
    }

    /** Set the DNS server IP(s) used for TXT lookups (e.g. the active network's
     *  resolvers from Android's ConnectivityManager). Queried before the public-DNS
     *  fallbacks. Safe to call before {@code resolveAll*}. */
    public void setDnsServerIps(List<String> ips) {
        this.dnsServerIps = ips == null ? List.of() : List.copyOf(ips);
    }

    /** Package-private for tests. */
    DnsEnrResolver(TxtResolver resolver, int maxNodes, int maxDepth) {
        this.txtResolver = resolver;
        this.maxNodes = maxNodes;
        this.maxDepth = maxDepth;
    }

    /** Resolve every tree URL in parallel and concatenate successful ENR lists. */
    public List<Enr> resolveAll(List<EnrTreeUrl> urls, Duration timeout) {
        if (urls == null || urls.isEmpty()) return List.of();
        long start = System.nanoTime();
        long deadline = start + timeout.toNanos();
        List<Enr> all = java.util.Collections.synchronizedList(new ArrayList<>());

        // A plain fixed thread pool — NOT Executors.newVirtualThreadPerTaskExecutor():
        // virtual threads are a Java 21 API absent on Android/ART (NoSuchMethodError),
        // and this resolver must run on Android. Likewise we shut down explicitly
        // instead of try-with-resources, since ExecutorService.close() is a Java 19+
        // AutoCloseable method that isn't guaranteed on the Android runtime.
        ExecutorService exec = Executors.newFixedThreadPool(Math.min(urls.size(), 8));
        try {
            for (EnrTreeUrl url : urls) {
                exec.submit(() -> {
                    try {
                        all.addAll(resolve(url, deadline));
                    } catch (Exception e) {
                        log.warn("[dns] {} failed: {}", url.domain(), e.getMessage());
                    }
                });
            }
            exec.shutdown();
            // resolve() self-bounds by `deadline` and returns its PARTIAL list shortly
            // after the deadline (it checks between lookups). We must wait for that
            // return so all.addAll() runs — NOT cut off AT the deadline, which would
            // snapshot an empty `all` and drop everything the walk collected. So wait
            // the remaining time PLUS a grace window covering one last in-flight lookup.
            long graceNanos = (deadline - System.nanoTime()) + SHUTDOWN_GRACE.toNanos();
            if (graceNanos > 0) {
                exec.awaitTermination(graceNanos, TimeUnit.NANOSECONDS);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            exec.shutdownNow();
        }
        log.info("[dns] resolved {} ENR(s) from {} tree(s) in {} ms",
                all.size(), urls.size(), (System.nanoTime() - start) / 1_000_000);
        return new ArrayList<>(all);
    }

    /** Resolve a single tree with no deadline. Throws on hard failures. */
    public List<Enr> resolve(EnrTreeUrl url) throws Exception {
        return resolve(url, Long.MAX_VALUE);
    }

    /**
     * Resolve a single tree, returning partial results if {@code deadlineNanos} expires.
     * Throws only if the root record is missing or its signature doesn't verify — any
     * subtree fetch failure is logged and the walk continues with remaining nodes.
     */
    public List<Enr> resolve(EnrTreeUrl url, long deadlineNanos) throws Exception {
        String rootTxt = txtResolver.lookup(url.domain());
        Root root = parseAndVerifyRoot(rootTxt, url.publicKey());

        List<Enr> enrs = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Deque<HashNode> queue = new ArrayDeque<>();
        queue.push(new HashNode(root.eRoot, 0));
        int fetches = 0;

        while (!queue.isEmpty()) {
            if (System.nanoTime() > deadlineNanos) {
                log.info("[dns] {} deadline reached after {} lookups, {} ENRs collected",
                        url.domain(), fetches, enrs.size());
                break;
            }
            if (fetches >= maxNodes) {
                log.warn("[dns] {} hit maxNodes={} cap after collecting {} ENRs", url.domain(), maxNodes, enrs.size());
                break;
            }
            HashNode node = queue.pop();
            if (!visited.add(node.hash)) continue;
            if (node.depth > maxDepth) continue;

            fetches++;
            String txt;
            try {
                txt = txtResolver.lookup(node.hash + "." + url.domain());
            } catch (Exception e) {
                log.warn("[dns] subnode {}.{} failed: {}", node.hash, url.domain(), e.getMessage());
                continue;
            }
            if (txt.startsWith(BRANCH_PREFIX)) {
                String list = txt.substring(BRANCH_PREFIX.length());
                for (String child : list.split(",")) {
                    child = child.trim();
                    if (!child.isEmpty()) queue.push(new HashNode(child, node.depth + 1));
                }
            } else if (txt.startsWith(LEAF_PREFIX)) {
                try {
                    enrs.add(Enr.fromEnrString(txt));
                } catch (Exception e) {
                    log.debug("[dns] skipping invalid ENR at {}: {}", node.hash, e.getMessage());
                }
            } else {
                log.warn("[dns] unexpected record at {}.{}: {}", node.hash, url.domain(),
                        truncate(txt, 60));
            }
        }
        return enrs;
    }

    // ---- root record parse + signature verify ----

    record Root(String eRoot, String lRoot, long seq) {}

    private record HashNode(String hash, int depth) {}

    /**
     * Verify the root-record ECDSA signature against the tree's expected pubkey,
     * then return the parsed fields.
     *
     * <p>Per EIP-1459 §3, the signed message is the record string minus the
     * trailing {@code " sig=<base64>"} segment; the signature is 65 bytes
     * {@code r||s||v} base64url-no-padding, over {@code keccak256(message)}.
     */
    static Root parseAndVerifyRoot(String txt, SECP256K1.PublicKey expected) {
        if (txt == null || !txt.startsWith(ROOT_PREFIX)) {
            throw new IllegalArgumentException("not an enrtree-root:v1 record: " + truncate(txt, 60));
        }
        int sigIdx = txt.lastIndexOf(" sig=");
        if (sigIdx < 0) {
            throw new IllegalArgumentException("root record missing sig= field");
        }
        String signed = txt.substring(0, sigIdx);
        String sigB64 = txt.substring(sigIdx + " sig=".length()).trim();

        // Parse k=v tokens of the signed portion.
        String body = signed.substring(ROOT_PREFIX.length());
        String eRoot = null, lRoot = null;
        long seq = -1;
        for (String tok : body.split(" ")) {
            if (tok.isEmpty()) continue;
            int eq = tok.indexOf('=');
            if (eq < 0) continue;
            String k = tok.substring(0, eq);
            String v = tok.substring(eq + 1);
            switch (k) {
                case "e" -> eRoot = v;
                case "l" -> lRoot = v;
                case "seq" -> seq = Long.parseLong(v);
                default -> { /* ignore unknown */ }
            }
        }
        if (eRoot == null || lRoot == null || seq < 0) {
            throw new IllegalArgumentException("root missing e/l/seq: " + truncate(signed, 80));
        }

        byte[] sigBytes = Base64.getUrlDecoder().decode(padBase64(sigB64));
        if (sigBytes.length != 65) {
            throw new IllegalArgumentException("expected 65-byte signature, got " + sigBytes.length);
        }
        Bytes32 hash = Hash.keccak256(Bytes.wrap(signed.getBytes(StandardCharsets.UTF_8)));
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sigBytes, 0, 32));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sigBytes, 32, 64));
        byte v = sigBytes[64];
        SECP256K1.Signature sig = SECP256K1.Signature.create(v, r, s);

        SECP256K1.PublicKey recovered = SECP256K1.PublicKey.recoverFromHashAndSignature(hash, sig);
        if (recovered == null || !recovered.equals(expected)) {
            throw new IllegalStateException("root signature does not match tree public key");
        }
        return new Root(eRoot, lRoot, seq);
    }

    // ---- dnsjava lookup ----

    /** Abstraction so tests can inject a fake TXT resolver. */
    @FunctionalInterface
    interface TxtResolver {
        String lookup(String name) throws Exception;
    }

    /** Per-DNS-query timeout. Caps blocking on a single unresponsive nameserver so
     *  the overall deadline in {@link #resolveAll} can actually fire. */
    private static final Duration LOOKUP_TIMEOUT = Duration.ofSeconds(2);

    /** A DNS server to try. {@code ip == null} uses dnsjava's system-config resolver
     *  (works off-Android, no-op on Android). {@code tcp} forces DNS-over-TCP, which
     *  the Android emulator's SLIRP NAT forwards to public resolvers even when its own
     *  UDP DNS relay (10.0.2.3) is broken — the failure mode we actually hit. */
    private record DnsServer(String ip, boolean tcp) {
        @Override public String toString() {
            return (ip == null ? "system" : ip) + (tcp ? "/tcp" : "");
        }
    }

    /** Public DNS fallbacks, tried after explicit/system servers. Over TCP because
     *  that's the path proven reachable on the emulator when UDP DNS is dead. */
    private static final List<DnsServer> PUBLIC_DNS_FALLBACKS =
            List.of(new DnsServer("1.1.1.1", true), new DnsServer("8.8.8.8", true));

    /** The server that last answered, tried first on subsequent lookups. A tree walk
     *  is many TXT lookups; without this every one would re-pay the dead-primary tax
     *  (broken emulator DNS) before failing over. Pin it once, then go straight there. */
    private volatile DnsServer lastGood;

    /** Try each candidate DNS server until one resolves the TXT record.
     *  Order: last-good → explicit {@link #dnsServerIps} → system → public DNS. */
    private String instanceTxtLookup(String name) throws Exception {
        List<DnsServer> candidates = new ArrayList<>();
        DnsServer pinned = lastGood;
        if (pinned != null) candidates.add(pinned);
        for (String ip : dnsServerIps) candidates.add(new DnsServer(ip, false));
        if (dnsServerIps.isEmpty()) candidates.add(new DnsServer(null, false));
        candidates.addAll(PUBLIC_DNS_FALLBACKS);
        Exception last = null;
        for (DnsServer cand : candidates) {
            try {
                String result = txtLookupVia(name, cand);
                lastGood = cand;
                return result;
            } catch (Exception e) {
                last = e;
                log.debug("[dns] TXT {} via {} failed: {}", name, cand, e.getMessage());
            }
        }
        throw last != null ? last
                : new IllegalStateException("no DNS server resolved " + name);
    }

    private static String txtLookupVia(String name, DnsServer server) throws Exception {
        Lookup lookup = new Lookup(name, Type.TXT);
        org.xbill.DNS.SimpleResolver resolver = (server.ip() == null)
                ? new org.xbill.DNS.SimpleResolver()
                : new org.xbill.DNS.SimpleResolver(server.ip());
        resolver.setTimeout(LOOKUP_TIMEOUT);
        if (server.tcp()) resolver.setTCP(true);
        lookup.setResolver(resolver);
        Record[] records = lookup.run();
        if (lookup.getResult() != Lookup.SUCCESSFUL || records == null || records.length == 0) {
            throw new IllegalStateException(
                    "TXT lookup failed for " + name + ": " + lookup.getErrorString());
        }
        // EIP-1459 treats a single TXT RR (possibly split into multiple 255-char
        // segments) as the authoritative record. Multiple TXT RRs at the same name
        // would represent distinct values, and concatenating across them would
        // corrupt the record and break signature verification. If the resolver
        // returns more than one, log and use the first.
        List<TXTRecord> txts = new ArrayList<>();
        for (Record r : records) {
            if (r instanceof TXTRecord txt) txts.add(txt);
        }
        if (txts.isEmpty()) {
            throw new IllegalStateException("no TXT records for " + name);
        }
        if (txts.size() > 1) {
            log.warn("[dns] {} returned {} TXT records; using the first", name, txts.size());
        }
        StringBuilder sb = new StringBuilder();
        for (Object seg : txts.get(0).getStrings()) sb.append(seg);
        return sb.toString();
    }

    // ---- small utilities ----

    private static String padBase64(String s) {
        int rem = s.length() % 4;
        if (rem == 0) return s;
        return s + "====".substring(rem);
    }

    private static String truncate(String s, int n) {
        if (s == null) return "null";
        return s.length() <= n ? s : s.substring(0, n) + "...";
    }

    /**
     * Convenience: take tree URLs as strings, parse each, resolve all in parallel,
     * return the combined ENR list. Logs and skips unparseable URLs.
     */
    public List<Enr> resolveAllFromStrings(List<String> urlStrings, Duration timeout) {
        if (urlStrings == null || urlStrings.isEmpty()) return Collections.emptyList();
        List<EnrTreeUrl> parsed = new ArrayList<>(urlStrings.size());
        for (String s : urlStrings) {
            try {
                parsed.add(EnrTreeUrl.parse(s));
            } catch (Exception e) {
                log.warn("[dns] invalid enrtree URL '{}': {}", s, e.getMessage());
            }
        }
        return resolveAll(parsed, timeout);
    }
}
