package com.jaeckel.ethp2p.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class WatchPolicyTest {

    @Test
    public void backgroundChecksNeedThePlugAndAnUnmeteredNetwork() {
        assertTrue(WatchPolicy.backgroundApplies(true, true, true));
        // On battery, on mobile data, or offline: no background check.
        assertFalse(WatchPolicy.backgroundApplies(false, true, true));
        assertFalse(WatchPolicy.backgroundApplies(true, true, false));
        assertFalse(WatchPolicy.backgroundApplies(true, false, true));
    }

    @Test
    public void theForegroundChecksMostOften() {
        assertEquals(WatchPolicy.FOREGROUND_INTERVAL_MS, WatchPolicy.scheduledIntervalMs(true, false));
        assertEquals(WatchPolicy.FOREGROUND_INTERVAL_MS, WatchPolicy.scheduledIntervalMs(true, true));
        assertTrue(WatchPolicy.FOREGROUND_INTERVAL_MS < WatchPolicy.AWAKE_INTERVAL_MS);
    }

    @Test
    public void aBackgroundNodeIsCheckedOnScheduleOnlyWhileKeptAwake() {
        assertEquals(WatchPolicy.AWAKE_INTERVAL_MS, WatchPolicy.scheduledIntervalMs(false, true));
        // Pinned: a scheduled check counts as activity, so in the background without the
        // stay-awake rule it would keep awake a node the user lets sleep. None is scheduled;
        // the before-sleep and after-wake checks cover the charger instead.
        assertEquals(0, WatchPolicy.scheduledIntervalMs(false, false));
    }

    @Test
    public void aMeteredNetworkScansFewerBlocks() {
        assertTrue(WatchPolicy.scanBlocks(false) < WatchPolicy.scanBlocks(true));
        assertTrue(WatchPolicy.tokenScanBlocks(false) < WatchPolicy.tokenScanBlocks(true));
    }

    @Test
    public void aMeteredNetworkReadsTheTokensLessOften() {
        // Pinned: every token balance is an eth_call, ~15 per mainnet address per check.
        assertEquals(0, WatchPolicy.tokenIntervalMs(true));
        assertTrue(WatchPolicy.tokenIntervalMs(false) > WatchPolicy.FOREGROUND_INTERVAL_MS);
    }
}
