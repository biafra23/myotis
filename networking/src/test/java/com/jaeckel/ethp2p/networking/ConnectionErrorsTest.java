package com.jaeckel.ethp2p.networking;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedChannelException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Guards the benign-disconnect classifier — it's easy to regress (message substrings, cause-chain,
 *  depth cap) and it decides whether a peer drop is a quiet DEBUG line or an ERROR stacktrace. */
class ConnectionErrorsTest {

    @Test
    void benignTransportDisconnectsAreBenign() {
        assertTrue(ConnectionErrors.isBenignDisconnect(new SocketException("Connection reset")));
        assertTrue(ConnectionErrors.isBenignDisconnect(new SocketException("Connection reset by peer")));
        assertTrue(ConnectionErrors.isBenignDisconnect(new IOException("Broken pipe")));
        assertTrue(ConnectionErrors.isBenignDisconnect(new SocketTimeoutException("Read timed out")));
        assertTrue(ConnectionErrors.isBenignDisconnect(new ClosedChannelException()));
        assertTrue(ConnectionErrors.isBenignDisconnect(new PortUnreachableException()));
    }

    @Test
    void benignCauseIsFoundThroughTheChain() {
        assertTrue(ConnectionErrors.isBenignDisconnect(
                new RuntimeException("netty pipeline", new SocketException("Connection reset"))));
    }

    @Test
    void genuineFailuresStayNonBenign() {
        assertFalse(ConnectionErrors.isBenignDisconnect(new RuntimeException("decode failed")));
        assertFalse(ConnectionErrors.isBenignDisconnect(new NullPointerException()));
        assertFalse(ConnectionErrors.isBenignDisconnect(new IllegalStateException("bad state")));
        // An IOException whose message ISN'T a known benign disconnect must stay ERROR.
        assertFalse(ConnectionErrors.isBenignDisconnect(new IOException("No space left on device")));
    }

    @Test
    void nullIsNotBenignAndDescribesSafely() {
        assertFalse(ConnectionErrors.isBenignDisconnect(null));
        assertEquals("unknown", ConnectionErrors.describe(null));
    }

    @Test
    void describeReturnsRootCauseMessageOrClassName() {
        assertEquals("Connection reset",
                ConnectionErrors.describe(new SocketException("Connection reset")));
        assertEquals("Connection reset",
                ConnectionErrors.describe(new RuntimeException("wrap", new SocketException("Connection reset"))));
        // No message → simple class name.
        assertEquals("ClosedChannelException", ConnectionErrors.describe(new ClosedChannelException()));
    }

    @Test
    void selfReferentialCauseDoesNotHang() {
        // A Throwable whose getCause() returns itself must not loop (would spin to the depth cap
        // without the self-cause break, and could loop forever if that were removed too).
        Throwable selfCausing = new RuntimeException("loop") {
            @Override public synchronized Throwable getCause() { return this; }
        };
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(1), () -> {
            assertFalse(ConnectionErrors.isBenignDisconnect(selfCausing));
            assertEquals("loop", ConnectionErrors.describe(selfCausing));
        });
    }
}
