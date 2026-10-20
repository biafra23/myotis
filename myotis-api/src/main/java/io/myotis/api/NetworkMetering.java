package io.myotis.api;

/**
 * The host's word on the network the device is on now, for the data-usage
 * figures ({@link DataUsage}) — see {@link MyotisEngine#setNetworkMetering}.
 */
public enum NetworkMetering {
    /** Never reported (the daemon; a host that cannot tell). Not counted as metered. */
    UNKNOWN,
    /** Wi-Fi, Ethernet: no per-byte cost. */
    UNMETERED,
    /** Cellular, a hotspot, or anything the OS marks as costly. */
    METERED
}
