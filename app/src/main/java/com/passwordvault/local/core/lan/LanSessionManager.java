package com.passwordvault.local.core.lan;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public final class LanSessionManager {
    private static final int MAX_ATTEMPTS = 5;
    private static final long INACTIVITY_TIMEOUT_MILLIS = 30L * 60L * 1000L;

    private final LanClock clock;
    private final LanRandom random;

    private LanSessionState.Status status = LanSessionState.Status.STOPPED;
    private String accessCode;
    private String sessionId;
    private int failedAttempts;
    private long lastValidActivityMillis;
    private long lastRequestCounter = -1L;

    public LanSessionManager(LanClock clock, LanRandom random) {
        if (clock == null || random == null) {
            throw new IllegalArgumentException("LanSessionManager dependencies must not be null");
        }
        this.clock = clock;
        this.random = random;
    }

    public synchronized LanSessionState start() {
        accessCode = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        sessionId = null;
        failedAttempts = 0;
        lastRequestCounter = -1L;
        lastValidActivityMillis = clock.nowMillis();
        status = LanSessionState.Status.AWAITING_CODE;
        return snapshot();
    }

    public synchronized PairingResult submitAccessCode(String candidate) {
        applyTimeoutIfNeeded();
        if (status != LanSessionState.Status.AWAITING_CODE) {
            return PairingResult.rejected(remainingAttempts());
        }

        if (!constantTimeEquals(accessCode, candidate == null ? "" : candidate.trim())) {
            failedAttempts++;
            if (failedAttempts >= MAX_ATTEMPTS) {
                status = LanSessionState.Status.LOCKED_OUT;
                accessCode = null;
            }
            return PairingResult.rejected(remainingAttempts());
        }

        String generatedSessionId = random.nextSessionId();
        if (generatedSessionId == null || generatedSessionId.trim().isEmpty()) {
            throw new IllegalStateException("Generated LAN session ID must not be blank");
        }
        sessionId = generatedSessionId;
        accessCode = null;
        status = LanSessionState.Status.CONNECTED;
        lastValidActivityMillis = clock.nowMillis();
        lastRequestCounter = -1L;
        return PairingResult.success(sessionId);
    }

    public synchronized void recordValidOperation(String candidateSessionId, long requestCounter) {
        beginRequest(candidateSessionId, requestCounter);
        recordSuccessfulOperation(candidateSessionId, requestCounter);
    }

    /**
     * Authenticates and irreversibly consumes a request counter before a vault operation starts.
     * Callers must invoke this before any mutation so a replay cannot write twice.
     */
    public synchronized void beginRequest(String candidateSessionId, long requestCounter) {
        applyTimeoutIfNeeded();
        requireConnectedSession(candidateSessionId);
        if (requestCounter < 0 || requestCounter <= lastRequestCounter) {
            throw new LanReplayException();
        }
        lastRequestCounter = requestCounter;
    }

    /** Refreshes the inactivity timer only after the authenticated business operation succeeded. */
    public synchronized void recordSuccessfulOperation(String candidateSessionId, long requestCounter) {
        applyTimeoutIfNeeded();
        requireConnectedSession(candidateSessionId);
        if (requestCounter < 0 || requestCounter != lastRequestCounter) {
            throw new LanReplayException();
        }
        lastValidActivityMillis = clock.nowMillis();
    }

    public synchronized void checkTimeout() {
        applyTimeoutIfNeeded();
    }

    public synchronized void stop() {
        clearSecrets();
        status = LanSessionState.Status.STOPPED;
    }

    public synchronized LanSessionState getState() {
        applyTimeoutIfNeeded();
        return snapshot();
    }

    private void applyTimeoutIfNeeded() {
        if ((status == LanSessionState.Status.AWAITING_CODE
                || status == LanSessionState.Status.CONNECTED)
                && clock.nowMillis() - lastValidActivityMillis >= INACTIVITY_TIMEOUT_MILLIS) {
            clearSecrets();
            status = LanSessionState.Status.TIMED_OUT;
        }
    }

    private void clearSecrets() {
        accessCode = null;
        sessionId = null;
        failedAttempts = 0;
        lastRequestCounter = -1L;
        lastValidActivityMillis = 0L;
    }

    private int remainingAttempts() {
        return status == LanSessionState.Status.AWAITING_CODE
                ? MAX_ATTEMPTS - failedAttempts
                : 0;
    }

    private void requireConnectedSession(String candidateSessionId) {
        if (status != LanSessionState.Status.CONNECTED
                || sessionId == null
                || !constantTimeEquals(sessionId, candidateSessionId == null ? "" : candidateSessionId)) {
            throw new LanUnauthorizedException();
        }
    }

    private LanSessionState snapshot() {
        return new LanSessionState(
                status,
                accessCode,
                sessionId,
                remainingAttempts(),
                lastRequestCounter
        );
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8)
        );
    }
}
