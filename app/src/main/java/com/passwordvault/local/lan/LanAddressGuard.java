package com.passwordvault.local.lan;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Stops one LAN run when its client-facing interface/address identity changes. */
final class LanAddressGuard {
    interface CurrentAddresses {
        Set<String> current();
    }

    private final CurrentAddresses currentAddresses;
    private final LanNetworkGuard.Stopper stopper;
    private Set<String> baseline = Collections.emptySet();
    private boolean captured;
    private boolean stopped;

    LanAddressGuard(CurrentAddresses currentAddresses, LanNetworkGuard.Stopper stopper) {
        if (currentAddresses == null || stopper == null) {
            throw new IllegalArgumentException("address guard dependencies must not be null");
        }
        this.currentAddresses = currentAddresses;
        this.stopper = stopper;
    }

    synchronized boolean captureBaseline() {
        baseline = normalized(currentAddresses.current());
        captured = true;
        stopped = false;
        return !baseline.isEmpty();
    }

    void onAddressesChanged() {
        boolean shouldStop;
        synchronized (this) {
            shouldStop = captured
                    && !stopped
                    && !baseline.equals(normalized(currentAddresses.current()));
            if (shouldStop) stopped = true;
        }
        if (shouldStop) stopper.stop();
    }

    synchronized void clear() {
        baseline = Collections.emptySet();
        captured = false;
        stopped = true;
    }

    synchronized Set<String> getBaseline() { return baseline; }

    private static Set<String> normalized(Set<String> values) {
        if (values == null || values.isEmpty()) return Collections.emptySet();
        return Collections.unmodifiableSet(new TreeSet<String>(values));
    }
}
