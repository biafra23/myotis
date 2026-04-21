package com.jaeckel.ethp2p.networking.dns;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the tree walk with an in-memory {@link DnsEnrResolver.TxtResolver} that
 * serves a small fabricated tree: signed root → branch → two ENR leaves. Verifies
 * the walk decodes both leaves, dedupes when a branch references the same hash
 * twice, and respects the depth cap.
 */
class DnsEnrResolverTreeTest {

    @BeforeAll
    static void setup() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Lighthouse mainnet ENR — reused for fixture leaves; content doesn't matter for the walk. */
    private static final String LEAF_ENR =
            "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo";

    private static String signRoot(SECP256K1.KeyPair kp, String e, String l, long seq) {
        String signed = "enrtree-root:v1 e=" + e + " l=" + l + " seq=" + seq;
        Bytes32 hash = Hash.keccak256(Bytes.wrap(signed.getBytes()));
        SECP256K1.Signature sig = SECP256K1.signHashed(hash, kp);
        byte[] r = padTo32(sig.r().toByteArray());
        byte[] s = padTo32(sig.s().toByteArray());
        byte[] sigBytes = new byte[65];
        System.arraycopy(r, 0, sigBytes, 0, 32);
        System.arraycopy(s, 0, sigBytes, 32, 32);
        sigBytes[64] = (byte) sig.v();
        return signed + " sig=" + Base64.getUrlEncoder().withoutPadding().encodeToString(sigBytes);
    }

    private static byte[] padTo32(byte[] in) {
        if (in.length == 32) return in;
        byte[] out = new byte[32];
        int src = in.length > 32 ? in.length - 32 : 0;
        int dst = 32 - (in.length - src);
        System.arraycopy(in, src, out, dst, in.length - src);
        return out;
    }

    @Test
    void walksBranchAndDecodesTwoLeaves() throws Exception {
        String domain = "tree.example";
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();

        String branchHash = "BRANCH1";
        String leafHash1 = "LEAF1";
        String leafHash2 = "LEAF2";

        Map<String, String> records = new HashMap<>();
        records.put(domain, signRoot(kp, branchHash, "LINK", 1L));
        records.put(branchHash + "." + domain, "enrtree-branch:" + leafHash1 + "," + leafHash2);
        records.put(leafHash1 + "." + domain, LEAF_ENR);
        records.put(leafHash2 + "." + domain, LEAF_ENR);

        DnsEnrResolver.TxtResolver fake = name -> {
            String v = records.get(name);
            if (v == null) throw new IllegalStateException("no record for " + name);
            return v;
        };

        DnsEnrResolver resolver = new DnsEnrResolver(fake, 100, 8);
        EnrTreeUrl url = new EnrTreeUrl(kp.publicKey(), domain);

        List<Enr> result = resolver.resolve(url);
        assertEquals(2, result.size(), "expected two leaves");
        for (Enr enr : result) {
            assertTrue(enr.tcpAddress().isPresent(), "each leaf should decode to an address-bearing ENR");
        }
    }

    @Test
    void dedupesRepeatedChildHash() throws Exception {
        String domain = "dup.example";
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();

        String branchHash = "BR";
        String leafHash = "L1";

        Map<String, String> records = new HashMap<>();
        records.put(domain, signRoot(kp, branchHash, "LINK", 1L));
        // Branch lists the same leaf twice — should still be visited once.
        records.put(branchHash + "." + domain, "enrtree-branch:" + leafHash + "," + leafHash);
        records.put(leafHash + "." + domain, LEAF_ENR);

        DnsEnrResolver.TxtResolver fake = name -> {
            String v = records.get(name);
            if (v == null) throw new IllegalStateException("no record for " + name);
            return v;
        };

        DnsEnrResolver resolver = new DnsEnrResolver(fake, 100, 8);
        EnrTreeUrl url = new EnrTreeUrl(kp.publicKey(), domain);

        List<Enr> result = resolver.resolve(url);
        assertEquals(1, result.size(), "duplicate child hash should be visited once");
    }

    @Test
    void respectsDepthCap() throws Exception {
        String domain = "deep.example";
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.random();

        Map<String, String> records = new HashMap<>();
        // Root → B1 → B2 → B3 → L1. With maxDepth=2 we should stop before reaching L1.
        records.put(domain, signRoot(kp, "B1", "LINK", 1L));
        records.put("B1." + domain, "enrtree-branch:B2");
        records.put("B2." + domain, "enrtree-branch:B3");
        records.put("B3." + domain, "enrtree-branch:L1");
        records.put("L1." + domain, LEAF_ENR);

        DnsEnrResolver.TxtResolver fake = name -> {
            String v = records.get(name);
            if (v == null) throw new IllegalStateException("no record for " + name);
            return v;
        };

        DnsEnrResolver resolver = new DnsEnrResolver(fake, 100, 2);
        EnrTreeUrl url = new EnrTreeUrl(kp.publicKey(), domain);

        List<Enr> result = resolver.resolve(url);
        assertEquals(0, result.size(), "depth cap should prevent reaching any leaves");
    }
}
