package com.passwordvault.local.lan;

import java.util.Objects;

/** Stops one LAN run when the default network that authorized it disappears or changes. */
final class LanNetworkGuard<N> {
    interface CurrentNetwork<N> {
        N current();
    }

    interface Stopper {
        void stop();
    }

    private final CurrentNetwork<N> currentNetwork;
    private final Stopper stopper;
    private N baseline;
    private boolean captured;
    private boolean stopped;

    LanNetworkGuard(CurrentNetwork<N> currentNetwork, Stopper stopper) {
        if (currentNetwork == null || stopper == null) {
            throw new IllegalArgumentException("network guard dependencies must not be null");
        }
        this.currentNetwork = currentNetwork;
        this.stopper = stopper;
    }

    synchronized boolean captureBaseline() {
        baseline = currentNetwork.current();
        captured = true;
        stopped = false;
        return true;
    }

    void onLost(N network) {
        if (isBaseline(network)) {
            stopOnce();
        }
    }

    void onDefaultNetworkChanged() {
        if (!isCurrentBaseline()) {
            stopOnce();
        }
    }

    synchronized void clear() {
        baseline = null;
        captured = false;
        stopped = true;
    }

    private synchronized boolean isBaseline(N network) {
        return captured && baseline != null && Objects.equals(baseline, network);
    }

    private synchronized boolean isCurrentBaseline() {
        return captured && Objects.equals(baseline, currentNetwork.current());
    }

    private void stopOnce() {
        synchronized (this) {
            if (stopped) {
                return;
            }
            stopped = true;
        }
        stopper.stop();
    }
}
