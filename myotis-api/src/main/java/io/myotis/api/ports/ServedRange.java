package io.myotis.api.ports;

/**
 * A CL peer's proven catch-up service range: it has served sync-committee
 * updates for periods [{@code low}, {@code high}].
 */
public record ServedRange(String multiaddr, long low, long high) {
}
