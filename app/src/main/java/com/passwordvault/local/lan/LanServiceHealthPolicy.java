package com.passwordvault.local.lan;

import com.passwordvault.local.core.lan.LanSessionState;

/** Separates a listener that is still starting from one that has failed or reached a terminal run. */
final class LanServiceHealthPolicy {
    private LanServiceHealthPolicy() {
    }

    static boolean shouldStop(
            boolean serverStartCompleted,
            boolean serverRunning,
            LanSessionState.Status sessionStatus
    ) {
        if (!serverStartCompleted) return false;
        if (!serverRunning || sessionStatus == null) return true;
        return sessionStatus == LanSessionState.Status.STOPPED
                || sessionStatus == LanSessionState.Status.TIMED_OUT
                || sessionStatus == LanSessionState.Status.LOCKED_OUT;
    }
}
