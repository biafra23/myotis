package io.myotis.api;

/**
 * One network's data usage: the bytes its stack sent and received on the wire
 * (docs/data-usage.md says exactly which).
 *
 * <p>The {@code today*} figures cover one LOCAL calendar day ({@link #day}) and
 * survive a restart of the network on the same day (the engine keeps them in
 * its data directory); they start from zero on a new day. The rest count since
 * the handle was created (this process). A host running several networks adds
 * their figures up for the app's total.
 *
 * @param bytesIn               received since the handle was created
 * @param bytesOut              sent since the handle was created
 * @param elBytesIn             of {@code bytesIn}, the execution layer's (RLPx, discv4)
 * @param elBytesOut            of {@code bytesOut}, the execution layer's
 * @param clBytesIn             of {@code bytesIn}, the consensus layer's (libp2p; plus discv5
 *                              on the Rust engine)
 * @param clBytesOut            of {@code bytesOut}, the consensus layer's
 * @param day                   the local date the {@code today*} figures cover
 *                              ({@code YYYY-MM-DD}); empty when not measured
 * @param todayBytesIn          received today
 * @param todayBytesOut         sent today
 * @param todayMeteredBytesIn   of {@code todayBytesIn}, received while the host
 *                              reported a {@link NetworkMetering#METERED} network
 * @param todayMeteredBytesOut  of {@code todayBytesOut}, sent while metered
 */
public record DataUsage(
        long bytesIn,
        long bytesOut,
        long elBytesIn,
        long elBytesOut,
        long clBytesIn,
        long clBytesOut,
        String day,
        long todayBytesIn,
        long todayBytesOut,
        long todayMeteredBytesIn,
        long todayMeteredBytesOut) {

    /** Nothing measured (an engine or handle that does not count). */
    public static final DataUsage NONE = new DataUsage(0, 0, 0, 0, 0, 0, "", 0, 0, 0, 0);

    /** Today's bytes in both directions. */
    public long todayBytes() {
        return todayBytesIn + todayBytesOut;
    }

    /** Today's metered bytes in both directions. */
    public long todayMeteredBytes() {
        return todayMeteredBytesIn + todayMeteredBytesOut;
    }
}
