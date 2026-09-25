package com.jaeckel.ethp2p.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EngineGateTest {

    @Test
    public void gateIsAndroid13() {
        // Pinned: API 33 is where MethodHandles.byteArrayViewVarHandle and VarHandle
        // became public. Lowering it re-exposes the API-29 crash; raising it needs evidence.
        assertEquals(33, EngineGate.JAVA_ENGINE_MIN_SDK);
    }

    @Test
    public void belowTheGateIsRustOnlyWhateverThePreference() {
        for (int sdk = 29; sdk < EngineGate.JAVA_ENGINE_MIN_SDK; sdk++) {
            assertFalse("sdk " + sdk, EngineGate.javaEngineSupported(sdk));
            assertEquals("sdk " + sdk, "rust", EngineGate.engineChoice(sdk, false));
            // A stored "prefer Java" must not bring the Java engine (or its fallback) back.
            assertEquals("sdk " + sdk, "rust", EngineGate.engineChoice(sdk, true));
        }
    }

    @Test
    public void atAndAboveTheGateTheUsersPreferenceApplies() {
        for (int sdk : new int[] {EngineGate.JAVA_ENGINE_MIN_SDK, 34, 35, 36}) {
            assertTrue("sdk " + sdk, EngineGate.javaEngineSupported(sdk));
            assertEquals("sdk " + sdk, "auto", EngineGate.engineChoice(sdk, false));
            assertEquals("sdk " + sdk, "java", EngineGate.engineChoice(sdk, true));
        }
    }

    @Test
    public void reasonOnlyBelowTheGateAndNamesBothLevels() {
        assertNull(EngineGate.javaEngineUnavailableReason(EngineGate.JAVA_ENGINE_MIN_SDK));
        assertNull(EngineGate.javaEngineUnavailableReason(36));
        String reason = EngineGate.javaEngineUnavailableReason(29);
        assertNotNull(reason);
        assertTrue(reason, reason.contains("API 29"));
        assertTrue(reason, reason.contains("API 33"));
    }
}
