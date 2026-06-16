package io.myotis.node;

import java.util.List;

/**
 * Supplies the DNS server IPs to use for EIP-1459 ENR-tree (TXT) lookups when refreshing
 * the snap-peer maintainer's candidate pool. dnsjava has no system-resolver config on
 * Android, so the Android host provides the active network's DNS servers; the daemon can
 * pass {@code null} (or a provider returning an empty list) to let the resolver use its
 * own default/public-DNS fallback.
 */
@FunctionalInterface
public interface DnsServerProvider {
    /** DNS server IPs (may be empty → resolver falls back to its default). */
    List<String> get();
}
