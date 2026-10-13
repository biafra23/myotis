package io.myotis.api;

/**
 * One web origin that tried to use a network's JSON-RPC listener this run
 * ({@link ChainHandle#recentWebOrigins()}): the apps' "recent web pages" list,
 * from which a refused page is allowed with one tap. In memory only — it is
 * browsing history — and never exposed over JSON-RPC.
 *
 * @param origin              the normalized origin, {@code scheme://host[:port]}
 *                            (the opaque origin reads {@code null})
 * @param attempts            requests judged this run, CORS preflights included
 * @param lastSeenEpochMillis wall-clock ms of the latest attempt
 * @param lastAllowed         how the latest attempt ended — not whether the
 *                            current policy admits the origin
 */
public record WebOrigin(String origin, long attempts, long lastSeenEpochMillis, boolean lastAllowed) {
}
