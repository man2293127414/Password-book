package com.passwordvault.local;

import android.os.SystemClock;

final class BackupFlowWaiter {
    private static final long TIMEOUT_MILLIS = 10_000L;
    private static final long BACKOFF_MILLIS = 20L;

    interface Condition {
        boolean isMet();
    }

    static void waitFor(Condition condition) {
        long deadline = SystemClock.uptimeMillis() + TIMEOUT_MILLIS;
        while (!condition.isMet()) {
            if (SystemClock.uptimeMillis() >= deadline) {
                throw new AssertionError("Timed out waiting for backup flow condition");
            }
            SystemClock.sleep(BACKOFF_MILLIS);
        }
    }

    private BackupFlowWaiter() {
    }
}
