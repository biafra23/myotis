package io.myotis.api.ports;

import java.util.List;

/**
 * DNS server IPs for EIP-1459 enrtree TXT lookups. Mobile hosts supply the
 * active network's DNS servers (their resolvers have no system config); an empty
 * list falls back to the resolver's default.
 */
public interface DnsServers {

    List<String> dnsServerIps();
}
