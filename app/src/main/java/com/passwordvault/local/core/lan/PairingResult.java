package com.passwordvault.local.core.lan;

public final class PairingResult {
    private final boolean success;
    private final String sessionId;
    private final int remainingAttempts;

    private PairingResult(boolean success, String sessionId, int remainingAttempts) {
        this.success = success;
        this.sessionId = sessionId;
        this.remainingAttempts = remainingAttempts;
    }

    static PairingResult success(String sessionId) {
        return new PairingResult(true, sessionId, 0);
    }

    static PairingResult rejected(int remainingAttempts) {
        return new PairingResult(false, null, remainingAttempts);
    }

    public boolean isSuccess() { return success; }
    public String getSessionId() { return sessionId; }
    public int getRemainingAttempts() { return remainingAttempts; }
}
