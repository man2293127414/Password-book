package com.passwordvault.local.core;

import com.passwordvault.local.core.lan.LanClock;
import com.passwordvault.local.core.lan.LanRandom;
import com.passwordvault.local.core.lan.LanReplayException;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanSessionState;
import com.passwordvault.local.core.lan.LanUnauthorizedException;
import com.passwordvault.local.core.lan.PairingResult;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

final class LanSessionManagerTest {
    private static final long MINUTE = 60_000L;

    static void run() {
        LanSessionManagerTest test = new LanSessionManagerTest();
        test.startGeneratesZeroPaddedSixDigitCode();
        test.fiveWrongCodesLockTheRun();
        test.successConsumesCodeAndCreatesOneSession();
        test.connectedRunRejectsSecondPairing();
        test.requestCounterRejectsReplayAndOutOfOrderMessages();
        test.consumedRequestDoesNotRefreshUntilSuccessfulOperation();
        test.validOperationRefreshesThirtyMinuteTimeout();
        test.invalidOperationDoesNotRefreshTimeout();
        test.awaitingCodeAlsoTimesOut();
        test.explicitStopRevokesSession();
        test.restartRevokesOldSessionAndCode();
        System.out.println("PASS LanSessionManagerTest");
    }

    private void startGeneratesZeroPaddedSixDigitCode() {
        Fixture fixture = fixture(new int[] {42}, new String[] {"session-1"});

        LanSessionState state = fixture.manager.start();

        assertEquals(LanSessionState.Status.AWAITING_CODE, state.getStatus());
        assertEquals("000042", state.getAccessCode());
        assertEquals(5, state.getRemainingAttempts());
    }

    private void fiveWrongCodesLockTheRun() {
        Fixture fixture = fixture(new int[] {123456}, new String[] {"unused"});
        fixture.manager.start();

        for (int attempt = 1; attempt <= 5; attempt++) {
            PairingResult result = fixture.manager.submitAccessCode("000000");
            assertTrue(!result.isSuccess(), "wrong code must fail");
            assertEquals(5 - attempt, result.getRemainingAttempts());
        }

        LanSessionState state = fixture.manager.getState();
        assertEquals(LanSessionState.Status.LOCKED_OUT, state.getStatus());
        assertEquals(null, state.getAccessCode());
        assertTrue(!fixture.manager.submitAccessCode("123456").isSuccess(), "locked run cannot recover");
    }

    private void successConsumesCodeAndCreatesOneSession() {
        Fixture fixture = fixture(new int[] {123456}, new String[] {"session-1"});
        fixture.manager.start();

        PairingResult result = fixture.manager.submitAccessCode("123456");

        assertTrue(result.isSuccess(), "correct code must succeed");
        assertEquals("session-1", result.getSessionId());
        assertEquals(LanSessionState.Status.CONNECTED, fixture.manager.getState().getStatus());
        assertEquals(null, fixture.manager.getState().getAccessCode());
    }

    private void connectedRunRejectsSecondPairing() {
        Fixture fixture = fixture(new int[] {123456}, new String[] {"session-1"});
        fixture.manager.start();
        fixture.manager.submitAccessCode("123456");

        PairingResult second = fixture.manager.submitAccessCode("123456");

        assertTrue(!second.isSuccess(), "second client must not pair");
        assertEquals(null, second.getSessionId());
        assertEquals("session-1", fixture.manager.getState().getSessionId());
    }

    private void requestCounterRejectsReplayAndOutOfOrderMessages() {
        Fixture fixture = connectedFixture();

        fixture.manager.recordValidOperation("session-1", 1L);
        expect(LanReplayException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.manager.recordValidOperation("session-1", 1L);
            }
        });
        expect(LanReplayException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.manager.recordValidOperation("session-1", 0L);
            }
        });
        fixture.manager.recordValidOperation("session-1", 2L);

        assertEquals(2L, fixture.manager.getState().getLastRequestCounter());
    }

    private void validOperationRefreshesThirtyMinuteTimeout() {
        Fixture fixture = connectedFixture();
        fixture.clock.advance(29L * MINUTE);

        fixture.manager.recordValidOperation("session-1", 1L);
        fixture.clock.advance(29L * MINUTE);
        fixture.manager.checkTimeout();

        assertEquals(LanSessionState.Status.CONNECTED, fixture.manager.getState().getStatus());
        fixture.clock.advance(MINUTE);
        fixture.manager.checkTimeout();
        assertEquals(LanSessionState.Status.TIMED_OUT, fixture.manager.getState().getStatus());
    }

    private void consumedRequestDoesNotRefreshUntilSuccessfulOperation() {
        Fixture fixture = connectedFixture();
        fixture.clock.advance(29L * MINUTE);

        fixture.manager.beginRequest("session-1", 7L);
        assertEquals(7L, fixture.manager.getState().getLastRequestCounter());
        fixture.clock.advance(MINUTE);
        fixture.manager.checkTimeout();
        assertEquals(LanSessionState.Status.TIMED_OUT, fixture.manager.getState().getStatus());

        Fixture successful = connectedFixture();
        successful.clock.advance(29L * MINUTE);
        successful.manager.beginRequest("session-1", 7L);
        successful.manager.recordSuccessfulOperation("session-1", 7L);
        successful.clock.advance(29L * MINUTE);
        successful.manager.checkTimeout();
        assertEquals(LanSessionState.Status.CONNECTED, successful.manager.getState().getStatus());
    }

    private void invalidOperationDoesNotRefreshTimeout() {
        Fixture fixture = connectedFixture();
        fixture.clock.advance(29L * MINUTE);

        expect(LanUnauthorizedException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.manager.recordValidOperation("wrong-session", 1L);
            }
        });
        fixture.clock.advance(MINUTE);
        fixture.manager.checkTimeout();

        assertEquals(LanSessionState.Status.TIMED_OUT, fixture.manager.getState().getStatus());
    }

    private void awaitingCodeAlsoTimesOut() {
        Fixture fixture = fixture(new int[] {123456}, new String[] {"unused"});
        fixture.manager.start();
        fixture.clock.advance(30L * MINUTE);

        fixture.manager.checkTimeout();

        assertEquals(LanSessionState.Status.TIMED_OUT, fixture.manager.getState().getStatus());
        assertEquals(null, fixture.manager.getState().getAccessCode());
    }

    private void explicitStopRevokesSession() {
        Fixture fixture = connectedFixture();

        fixture.manager.stop();

        assertEquals(LanSessionState.Status.STOPPED, fixture.manager.getState().getStatus());
        expect(LanUnauthorizedException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.manager.recordValidOperation("session-1", 1L);
            }
        });
    }

    private void restartRevokesOldSessionAndCode() {
        Fixture fixture = fixture(
                new int[] {111111, 222222},
                new String[] {"session-old", "session-new"}
        );
        fixture.manager.start();
        fixture.manager.submitAccessCode("111111");

        LanSessionState restarted = fixture.manager.start();

        assertEquals("222222", restarted.getAccessCode());
        expect(LanUnauthorizedException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.manager.recordValidOperation("session-old", 1L);
            }
        });
        PairingResult paired = fixture.manager.submitAccessCode("222222");
        assertEquals("session-new", paired.getSessionId());
    }

    private static Fixture connectedFixture() {
        Fixture fixture = fixture(new int[] {123456}, new String[] {"session-1"});
        fixture.manager.start();
        fixture.manager.submitAccessCode("123456");
        return fixture;
    }

    private static Fixture fixture(int[] codes, String[] sessionIds) {
        FakeClock clock = new FakeClock();
        FakeRandom random = new FakeRandom(codes, sessionIds);
        return new Fixture(clock, new LanSessionManager(clock, random));
    }

    private static void expect(Class<? extends Throwable> expectedType, ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected " + expectedType.getSimpleName());
        } catch (Throwable actual) {
            if (!expectedType.isInstance(actual)) {
                throw new AssertionError(
                        "Expected " + expectedType.getSimpleName() + " but got " + actual.getClass().getSimpleName(),
                        actual
                );
            }
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class Fixture {
        private final FakeClock clock;
        private final LanSessionManager manager;

        private Fixture(FakeClock clock, LanSessionManager manager) {
            this.clock = clock;
            this.manager = manager;
        }
    }

    private static final class FakeClock implements LanClock {
        private long now;

        @Override
        public long nowMillis() {
            return now;
        }

        private void advance(long millis) {
            now += millis;
        }
    }

    private static final class FakeRandom implements LanRandom {
        private final Queue<Integer> codes = new ArrayDeque<Integer>();
        private final Queue<String> sessionIds = new ArrayDeque<String>();

        private FakeRandom(int[] codeValues, String[] sessionValues) {
            for (int value : codeValues) codes.add(value);
            sessionIds.addAll(Arrays.asList(sessionValues));
        }

        @Override
        public int nextInt(int bound) {
            if (codes.isEmpty()) throw new AssertionError("No fake access code available");
            int value = codes.remove();
            if (value < 0 || value >= bound) throw new AssertionError("Fake value outside bound");
            return value;
        }

        @Override
        public String nextSessionId() {
            if (sessionIds.isEmpty()) throw new AssertionError("No fake session ID available");
            return sessionIds.remove();
        }
    }
}
