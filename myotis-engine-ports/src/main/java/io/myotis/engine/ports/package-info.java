/**
 * The engine library's default port actuals — file-backed implementations of the
 * {@code io.myotis.api.ports} interfaces a host supplies on
 * {@link io.myotis.api.MyotisEngine#create}: the node-key file, the EL and CL peer
 * caches, the CCIP-Read HTTP gateway, and the per-network file layout they share.
 * {@link io.myotis.engine.ports.DefaultEnginePorts#forNetwork} assembles them for one
 * network from a key directory and a cache directory.
 *
 * <p>Android-safe at minSdk 29 (no {@code java.net.http}, no
 * {@code java.util.HexFormat}, no {@code Files.readString}) and Java 17, so the same
 * classes serve the Android AAR and the desktop jar.
 */
package io.myotis.engine.ports;
