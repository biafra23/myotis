package com.jaeckel.ethp2p.core.consensus;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Rust twin: {@code rust/myotis-consensus/src/fork.rs} unit tests. */
class ForkScheduleTest {

    private static final byte[] A = {0x05, 0, 0, 0};
    private static final byte[] B = {0x06, 0, 0, 0};
    private static final byte[] C = {0x07, 0, 0, 0};

    private static ForkSchedule three() {
        return ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(10, 0x06000000), ForkSchedule.fork(20, 0x07000000));
    }

    @Test
    void versionAtEpochPicksLatestActivated() {
        ForkSchedule s = three();
        assertArrayEquals(A, s.versionAtEpoch(0));
        assertArrayEquals(A, s.versionAtEpoch(9));
        assertArrayEquals(B, s.versionAtEpoch(10));
        assertArrayEquals(B, s.versionAtEpoch(19));
        assertArrayEquals(C, s.versionAtEpoch(20));
        assertArrayEquals(C, s.versionAtEpoch(Long.MAX_VALUE));
    }

    @Test
    void priorVersionAtEpochIsTheOneBeforeTheActiveFork() {
        ForkSchedule s = three();
        assertNull(s.priorVersionAtEpoch(0));
        assertNull(s.priorVersionAtEpoch(9));
        assertArrayEquals(A, s.priorVersionAtEpoch(10));
        assertArrayEquals(B, s.priorVersionAtEpoch(20));
        assertArrayEquals(B, s.priorVersionAtEpoch(Long.MAX_VALUE));
    }

    /** The spec's max(signature_slot, 1) - 1: the FIRST slot of the activation epoch still signs OLD. */
    @Test
    void signatureSlotBoundaryIsOffByOnePerSpec() {
        ForkSchedule s = three();
        assertArrayEquals(A, s.versionForSignatureSlot(0));
        assertArrayEquals(A, s.versionForSignatureSlot(1));
        assertArrayEquals(A, s.versionForSignatureSlot(320)); // slot 319 -> epoch 9
        assertArrayEquals(B, s.versionForSignatureSlot(321)); // slot 320 -> epoch 10
        assertArrayEquals(B, s.versionForSignatureSlot(640));
        assertArrayEquals(C, s.versionForSignatureSlot(641));
    }

    /** SSZ uint64 >= 2^63 arrives negative in a long: far future, not slot 0. */
    @Test
    void hugeUnsignedSlotSelectsTheNewestFork() {
        ForkSchedule s = three();
        assertArrayEquals(C, s.versionForSignatureSlot(Long.MIN_VALUE));
        assertArrayEquals(C, s.versionForSignatureSlot(-1L));
        assertArrayEquals(C, s.versionForSignatureSlot(Long.MAX_VALUE));
    }

    @Test
    void slotsPerEpochIsPartOfTheSchedule() {
        ForkSchedule s = ForkSchedule.of(16, ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(10, 0x06000000));
        assertArrayEquals(A, s.versionForSignatureSlot(160)); // slot 159 -> epoch 9
        assertArrayEquals(B, s.versionForSignatureSlot(161)); // slot 160 -> epoch 10
    }

    @Test
    void newestAndSingle() {
        assertArrayEquals(C, three().newest());
        ForkSchedule one = ForkSchedule.single(A);
        assertArrayEquals(A, one.newest());
        assertNull(one.priorVersionAtEpoch(Long.MAX_VALUE));
        assertArrayEquals(A, one.versionForSignatureSlot(Long.MAX_VALUE));
        assertArrayEquals(new byte[]{(byte) 0x90, 0, 0, 0x75}, ForkSchedule.single(new byte[]{(byte) 0x90, 0, 0, 0x75}).newest());
    }

    @Test
    void forkVersionBytesAreBigEndian() {
        assertArrayEquals(new byte[]{0x06, 0x00, 0x00, 0x64}, ForkSchedule.fork(1, 0x06000064).versionBytes());
        assertArrayEquals(new byte[]{(byte) 0x90, 0x00, 0x00, 0x75}, ForkSchedule.fork(1, 0x90000075).versionBytes());
    }

    @Test
    void valueSemantics() {
        assertEquals(three(), three());
        assertEquals(three().hashCode(), three().hashCode());
        assertEquals(ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(0, 0x05000000));
        assertNotEquals(three(), ForkSchedule.of(16,
                ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(10, 0x06000000), ForkSchedule.fork(20, 0x07000000)));
        assertEquals("ForkSchedule{slotsPerEpoch=32, [0:05000000, 10:06000000, 20:07000000]}", three().toString());
        assertEquals(List.of(ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(10, 0x06000000), ForkSchedule.fork(20, 0x07000000)),
                three().forks());
    }

    @Test
    void rejectsMalformedSchedules() {
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(32));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(32, (ForkSchedule.Fork) null));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(32, ForkSchedule.fork(5, 0x05000000)));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(20, 0x06000000), ForkSchedule.fork(10, 0x07000000)));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(32,
                ForkSchedule.fork(0, 0x05000000), ForkSchedule.fork(10, 0x06000000), ForkSchedule.fork(10, 0x07000000)));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.of(0, ForkSchedule.fork(0, 0x05000000)));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.fork(-1, 0x05000000));
        assertThrows(IllegalArgumentException.class, () -> ForkSchedule.single(new byte[3]));
    }
}
