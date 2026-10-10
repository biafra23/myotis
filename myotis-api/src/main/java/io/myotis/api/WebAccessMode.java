package io.myotis.api;

/**
 * Which web pages (browser origins) may use a network's loopback JSON-RPC
 * listener — the apps' "Web page access" setting (#502). Native wallets send no
 * {@code Origin} header and are unaffected by every mode.
 */
public enum WebAccessMode {
    /** No web page may use the node. */
    OFF,
    /** Only the origins listed in {@link WebAccessPolicy#origins()}, matched exactly
     *  (scheme + host + port). The default, with an empty list. */
    ALLOWLIST,
    /** Every web page — any page open on the device can detect the node and read from it. */
    ALL
}
