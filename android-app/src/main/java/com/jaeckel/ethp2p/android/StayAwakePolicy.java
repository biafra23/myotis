package com.jaeckel.ethp2p.android;

/**
 * The "stay awake while charging" rule: whether the idle controller skips its pause, and
 * whether a background catch-up pass leaves the stack it resumed running. Pure (no Android
 * imports) so the rule is unit-testable on the JVM; {@link NodeService} feeds it the live
 * setting, plug state and active-network capabilities.
 *
 * <p>Power alone is not enough — the active network must also be UNMETERED. Plugged in on
 * mobile data or a metered hotspot the node sleeps on the ordinary idle timer: kept awake
 * until unplugged it would run at the awake per-minute rate
 * (docs/disk-and-network-usage.md §3.2) on the user's data plan. Plugged in but offline it
 * sleeps too: there is nothing to sync over.
 */
final class StayAwakePolicy {

    private StayAwakePolicy() {}

    /**
     * @param settingOn  the user's "Stay awake while charging" setting
     * @param pluggedIn  the device is on AC / USB / wireless power
     * @param internet   the active network has Internet capability
     * @param unmetered  the active network is unmetered (Android's {@code NOT_METERED})
     */
    static boolean applies(boolean settingOn, boolean pluggedIn, boolean internet,
                           boolean unmetered) {
        return settingOn && pluggedIn && internet && unmetered;
    }
}
