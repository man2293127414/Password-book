package com.passwordvault.local.core.lan;

public final class LanSessionState {
    public enum Status {
        STOPPED,
        AWAITING_CODE,
        CONNECTED,
        LOCKED_OUT,
        TIMED_OUT
    }

    private final Status status;
    private final String accessCode;
    private final String sessionId;
    private final int remainingAttempts;
    private final long lastRequestCounter;

    LanSessionState(
            Status status,
            String accessCode,
            String sessionId,
            int remainingAttempts,
            long lastRequestCounter
    ) {
        this.status = status;
        this.accessCode = accessCode;
        this.sessionId = sessionId;
        this.remainingAttempts = remainingAttempts;
        this.lastRequestCounter = lastRequestCounter;
    }

    public Status getStatus() { return status; }
    public String getAccessCode() { return accessCode; }
    public String getSessionId() { return sessionId; }
    public int getRemainingAttempts() { return remainingAttempts; }
    public long getLastRequestCounter() { return lastRequestCounter; }
}
