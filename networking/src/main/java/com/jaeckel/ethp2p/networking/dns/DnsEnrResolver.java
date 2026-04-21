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
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
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

    private final TxtResolver txtResolver;
    private final int maxNodes;
    private final int maxDepth;

    public DnsEnrResolver() {
        this(DnsEnrResolver::defaultTxtLookup, DEFAULT_MAX_NODES, DEFAULT_MAX_DEPTH);
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

        // Each resolve() call respects the deadline and returns partial results, so
        // the ExecutorService's close() (which waits on submitted tasks) is bounded
        // by the per-tree walk rather than the timeout we're trying to enforce here.
        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            for (EnrTreeUrl url : urls) {
                exec.submit(() -> {
                    try {
                        all.addAll(resolve(url, deadline));
                    } catch (Exception e) {
                        log.warn("[dns] {} failed: {}", url.domain(), e.getMessage());
                    }
                });
            }
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

    private static String defaultTxtLookup(String name) throws Exception {
        Lookup lookup = new Lookup(name, Type.TXT);
        Record[] records = lookup.run();
        if (lookup.getResult() != Lookup.SUCCESSFUL || records == null || records.length == 0) {
            throw new IllegalStateException(
                    "TXT lookup failed for " + name + ": " + lookup.getErrorString());
        }
        // EIP-1459 §3: a single record may be split into multiple 255-char segments
        // that MUST be concatenated in wire order. Multiple TXT RRs at the same name
        // are not contemplated by the spec in practice, but resolvers can return
        // them in non-deterministic order — sort by RR content so the output is
        // stable regardless of DNS packet ordering. Segment order within each RR
        // is preserved.
        List<String> perRecord = new ArrayList<>();
        for (Record r : records) {
            if (!(r instanceof TXTRecord txt)) continue;
            StringBuilder sb = new StringBuilder();
            for (Object seg : txt.getStrings()) sb.append(seg);
            perRecord.add(sb.toString());
        }
        if (perRecord.size() > 1) {
            java.util.Collections.sort(perRecord);
        }
        return String.join("", perRecord);
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
