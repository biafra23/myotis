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
        // Pure-function pin only: on a device the active (default) network practically always
        // carries INTERNET — a captive portal keeps it and lacks VALIDATED instead — so the live
        // rule's "internet" input is false only with no active network at all.
        assertFalse(StayAwakePolicy.applies(true, true, false, true));
    }

    @Test
    public void onBatteryOrWithTheSettingOffSleeps() {
        assertFalse(StayAwakePolicy.applies(true, false, true, true));
        assertFalse(StayAwakePolicy.applies(false, true, true, true));
    }
}
