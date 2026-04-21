package com.jaeckel.ethp2p.networking.dns;

import com.jaeckel.ethp2p.core.enr.Enr;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.time.Duration;
import java.util.List;

public class DnsSmokeTest {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        String treeUrl = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net";
        long t0 = System.currentTimeMillis();
        List<Enr> enrs = new DnsEnrResolver().resolveAllFromStrings(List.of(treeUrl), Duration.ofSeconds(15));
        long t = System.currentTimeMillis() - t0;
        System.out.println("Resolved " + enrs.size() + " ENRs in " + t + "ms");
        int withTcp = 0, withMa = 0;
        for (Enr e : enrs) {
            if (e.tcpAddress().isPresent()) withTcp++;
            if (e.toLibp2pMultiaddr().isPresent()) withMa++;
        }
        System.out.println("  with tcpAddress: " + withTcp);
        System.out.println("  with libp2pMultiaddr: " + withMa);
        if (!enrs.isEmpty()) {
            System.out.println("Sample: " + enrs.get(0));
        }
    }
}
