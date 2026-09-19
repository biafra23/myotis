package com.jaeckel.ethp2p.app;

import io.myotis.api.ChainHandle;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The backfill OFF switch's DAEMON-side contract.
 *
 * Two hazards are pinned here, both found in review of PR #468:
 *
 * 1. The {@code paused} value is parsed strictly. A substring match for the
 *    compact form reads {@code {"paused": true}} — what json.dumps and jq emit —
 *    as false and RESUMES the walk while answering the caller ok. A parameter
 *    that can change the answer is applied or refused, never inverted
 *    (CLAUDE.md §Trust).
 * 2. {@link CommandHandler#setBackfillPaused} refuses when no index is enabled.
 *    The engine accepts an empty watch list, so a push at a network with no
 *    index would install an enabled, zero-entry one and report success.
 */
class LogIndexBackfillCommandTest {

    /** A ChainHandle that answers a canned status and records the pushed config. */
    private static ChainHandle handleWith(String statusJson, AtomicReference<String> pushed) {
        return (ChainHandle) Proxy.newProxyInstance(
                ChainHandle.class.getClassLoader(),
                new Class<?>[] {ChainHandle.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "logIndexStatusJson" -> statusJson;
                    case "setLogIndexConfig" -> {
                        pushed.set((String) args[0]);
                        yield true;
                    }
                    default -> method.getReturnType() == boolean.class ? Boolean.FALSE : null;
                });
    }

    // -- strict boolean parse -------------------------------------------------

    @Test
    void spacedJsonParsesAsTrueRatherThanInvertingTheRequest() {
        assertTrue(CommandHandler.extractBoolean("{\"cmd\":\"x\", \"paused\": true}", "paused"),
                "ordinary JSON spacing must not read as false — that would resume the walk");
        assertTrue(CommandHandler.extractBoolean("{\"paused\":true}", "paused"));
        assertFalse(CommandHandler.extractBoolean("{\"paused\":   false }", "paused"));
    }

    @Test
    void nonBooleanValuesAreRefusedNotDefaulted() {
        // A quoted value, a number and a near-miss token are all malformed. Each
        // must throw so the caller gets the "paused must be true or false" error
        // instead of a silently chosen default.
        assertThrows(IllegalArgumentException.class,
                () -> CommandHandler.extractBoolean("{\"paused\":\"true\"}", "paused"));
        assertThrows(IllegalArgumentException.class,
                () -> CommandHandler.extractBoolean("{\"paused\":1}", "paused"));
        assertThrows(IllegalArgumentException.class,
                () -> CommandHandler.extractBoolean("{\"paused\":truthy}", "paused"));
        assertThrows(IllegalArgumentException.class,
                () -> CommandHandler.extractBoolean("{\"other\":true}", "paused"));
    }

    // -- the shared push ------------------------------------------------------

    @Test
    void pushCarriesTheLivePacingBitAndTheRequestedPause() {
        AtomicReference<String> pushed = new AtomicReference<>();
        ChainHandle h = handleWith("{\"enabled\":true,\"maxSpeed\":true,\"backfillPaused\":false}", pushed);
        assertTrue(CommandHandler.setBackfillPaused(h, true));
        assertEquals("{\"enabled\":true,\"maxSpeed\":true,\"backfillPaused\":true,\"watch\":[]}",
                pushed.get(),
                "maxSpeed is read back from the live status — omitting it would reset pacing");
    }

    @Test
    void aNetworkWithNoEnabledIndexIsRefusedInsteadOfHavingAnEmptyOneInstalled() {
        AtomicReference<String> pushed = new AtomicReference<>();
        ChainHandle none = handleWith("{\"enabled\":false,\"logCount\":0,\"entries\":[]}", pushed);
        assertFalse(CommandHandler.setBackfillPaused(none, true),
                "no enabled index means nothing to pause — refuse, so Main's warning fires");
        assertNull(pushed.get(), "nothing may be pushed at a network with no index");

        AtomicReference<String> pushed2 = new AtomicReference<>();
        ChainHandle absent = handleWith(null, pushed2);
        assertFalse(CommandHandler.setBackfillPaused(absent, true),
                "a null status (Java engine) is not an enabled index either");
        assertNull(pushed2.get());
    }

    @Test
    void theLivePauseBitIsReadableForCommandsThatMustCarryIt() {
        AtomicReference<String> ignored = new AtomicReference<>();
        assertTrue(CommandHandler.backfillPaused(
                handleWith("{\"enabled\":true,\"backfillPaused\":true}", ignored)));
        assertFalse(CommandHandler.backfillPaused(
                handleWith("{\"enabled\":true,\"backfillPaused\":false}", ignored)));
        assertFalse(CommandHandler.backfillPaused(handleWith(null, ignored)));
    }
}
