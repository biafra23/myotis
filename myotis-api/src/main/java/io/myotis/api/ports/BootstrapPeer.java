package io.myotis.api.ports;

/**
 * A CL peer that served a light-client bootstrap, and for which period —
 * front-loads proven bootstrap servers on restart.
 */
public record BootstrapPeer(String multiaddr, long period) {
}
