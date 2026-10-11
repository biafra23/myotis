package com.jaeckel.ethp2p.android;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class StayAwakePolicyTest {

    @Test
    public void staysAwakeOnlyPluggedInOnAnUnmeteredNetwork() {
        assertTrue(StayAwakePolicy.applies(true, true, true, true));
    }

    @Test
    public void chargingOnAMeteredNetworkSleeps() {
        // Pinned: power alone must not keep the node awake on mobile data or a metered
        // hotspot — that would spend the user's data plan until the phone is unplugged.
        assertFalse(StayAwakePolicy.applies(true, true, true, false));
    }

    @Test
    public void chargingOfflineSleeps() {
        assertFalse(StayAwakePolicy.applies(true, true, false, false));
        // An unmetered network without Internet (captive portal, local-only Wi-Fi) has
        // nothing to sync over either.
        assertFalse(StayAwakePolicy.applies(true, true, false, true));
    }

    @Test
    public void onBatteryOrWithTheSettingOffSleeps() {
        assertFalse(StayAwakePolicy.applies(true, false, true, true));
        assertFalse(StayAwakePolicy.applies(false, true, true, true));
    }
}
