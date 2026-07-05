/**
 * The host-implemented seams the engine calls OUT through — persistence, HTTP,
 * DNS, key storage, logging, time. Hosts implement these against their platform
 * (files + java.net.http on desktop, app-private storage + ConnectivityManager on
 * Android) and hand them to {@link io.myotis.api.MyotisEngine#create}.
 *
 * <p>All port methods are invoked by the engine from its own worker threads:
 * implementations must be thread-safe and should not block excessively (a slow
 * cache write stalls engine progress). {@link io.myotis.api.ports.HttpGateway} is
 * the deliberate exception — it is called for its blocking transport and the
 * engine budgets its timeout.
 *
 * <p>The same type rules as {@code io.myotis.api} apply: byte[], String,
 * long/int/boolean, enums, flat records, java.util.List only.
 */
package io.myotis.api.ports;
