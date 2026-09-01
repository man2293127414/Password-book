package com.passwordvault.local.lan;

import com.passwordvault.local.core.lan.LanSessionState;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class LanLifecycleTest {
    private LanLifecycleTest() {
    }

    public static void main(String[] args) throws Exception {
        ownerClosesCandidateWhenStartFails();
        ownerClosesCandidateWhenStartThrowsRuntimeException();
        ownerStopIsIdempotent();
        networkGuardStopsOnceWhenDefaultNetworkChanges();
        networkGuardStopsOnceWhenBaselineIsLost();
        networkGuardIgnoresUnrelatedNetworkLoss();
        networkGuardSupportsHotspotWithoutDefaultNetwork();
        addressGuardStopsWhenHotspotClosesWithCellularDefault();
        addressGuardStopsWhenHotspotClosesWithoutDefaultNetwork();
        serviceHealthIgnoresStartingStateAndStopsTerminalRuns();
        System.out.println("PASS LanLifecycleTest");
    }

    private static void serviceHealthIgnoresStartingStateAndStopsTerminalRuns() {
        assertTrue(!LanServiceHealthPolicy.shouldStop(
                false,
                false,
                LanSessionState.Status.STOPPED
        ), "startup must not be stopped before the listener result is known");
        assertTrue(!LanServiceHealthPolicy.shouldStop(
                true,
                true,
                LanSessionState.Status.AWAITING_CODE
        ), "a healthy awaiting listener must remain active");
        assertTrue(LanServiceHealthPolicy.shouldStop(
                true,
                false,
                LanSessionState.Status.AWAITING_CODE
        ), "a completed start with a dead listener must stop");
        assertTrue(LanServiceHealthPolicy.shouldStop(
                true,
                true,
                LanSessionState.Status.STOPPED
        ), "an aborted run must stop its live listener");
        assertTrue(LanServiceHealthPolicy.shouldStop(
                true,
                true,
                LanSessionState.Status.TIMED_OUT
        ), "a timed-out run must stop");
        assertTrue(LanServiceHealthPolicy.shouldStop(
                true,
                true,
                LanSessionState.Status.LOCKED_OUT
        ), "a locked-out run must stop");
    }

    private static void ownerClosesCandidateWhenStartThrowsRuntimeException() {
        FakeServer server = new FakeServer(false, true);
        LanServerOwner owner = new LanServerOwner(new FixedFactory(server));
        assertTrue(!owner.start(), "runtime startup failure must not remain active");
        assertEquals(1, server.shutdownCalls);
    }

    private static void ownerClosesCandidateWhenStartFails() {
        FakeServer server = new FakeServer(true);
        LanServerOwner owner = new LanServerOwner(new FixedFactory(server));

        assertTrue(!owner.start(), "failing server must not become active");

        assertEquals(1, server.startCalls);
        assertEquals(1, server.shutdownCalls);
        assertTrue(!owner.isRunning(), "failed candidate must not remain owned");
    }

    private static void ownerStopIsIdempotent() {
        FakeServer server = new FakeServer(false);
        LanServerOwner owner = new LanServerOwner(new FixedFactory(server));

        assertTrue(owner.start(), "server should start");
        owner.stop();
        owner.stop();

        assertEquals(1, server.shutdownCalls);
        assertTrue(!owner.isRunning(), "stopped server must not remain active");
    }

    private static void networkGuardStopsOnceWhenDefaultNetworkChanges() {
        FakeNetworkSource networks = new FakeNetworkSource("wifi-a");
        CountingStopper stopper = new CountingStopper();
        LanNetworkGuard<String> guard = new LanNetworkGuard<String>(networks, stopper);

        assertTrue(guard.captureBaseline(), "a default network must be captured");
        networks.currentNetwork = "hotspot-b";
        guard.onDefaultNetworkChanged();
        guard.onDefaultNetworkChanged();

        assertEquals(1, stopper.stopCalls);
    }

    private static void networkGuardStopsOnceWhenBaselineIsLost() {
        FakeNetworkSource networks = new FakeNetworkSource("wifi-a");
        CountingStopper stopper = new CountingStopper();
        LanNetworkGuard<String> guard = new LanNetworkGuard<String>(networks, stopper);
        guard.captureBaseline();

        guard.onLost("wifi-a");
        guard.onLost("wifi-a");

        assertEquals(1, stopper.stopCalls);
    }

    private static void networkGuardIgnoresUnrelatedNetworkLoss() {
        FakeNetworkSource networks = new FakeNetworkSource("wifi-a");
        CountingStopper stopper = new CountingStopper();
        LanNetworkGuard<String> guard = new LanNetworkGuard<String>(networks, stopper);
        guard.captureBaseline();

        guard.onLost("hotspot-b");

        assertEquals(0, stopper.stopCalls);
    }

    private static void networkGuardSupportsHotspotWithoutDefaultNetwork() {
        FakeNetworkSource networks = new FakeNetworkSource(null);
        CountingStopper stopper = new CountingStopper();
        LanNetworkGuard<String> guard = new LanNetworkGuard<String>(networks, stopper);

        assertTrue(guard.captureBaseline(), "a missing default network is a valid hotspot baseline");
        guard.onDefaultNetworkChanged();
        assertEquals(0, stopper.stopCalls);

        networks.currentNetwork = "wifi-a";
        guard.onDefaultNetworkChanged();
        assertEquals(1, stopper.stopCalls);
    }

    private static void addressGuardStopsWhenHotspotClosesWithCellularDefault() {
        assertHotspotAddressLossStops("cellular");
    }

    private static void addressGuardStopsWhenHotspotClosesWithoutDefaultNetwork() {
        assertHotspotAddressLossStops(null);
    }

    private static void assertHotspotAddressLossStops(String defaultNetwork) {
        FakeNetworkSource networks = new FakeNetworkSource(defaultNetwork);
        FakeAddressSource addresses = new FakeAddressSource("ap0/192.168.43.1");
        CountingStopper stopper = new CountingStopper();
        LanNetworkGuard<String> networkGuard = new LanNetworkGuard<String>(networks, stopper);
        LanAddressGuard addressGuard = new LanAddressGuard(addresses, stopper);

        networkGuard.captureBaseline();
        assertTrue(addressGuard.captureBaseline(), "hotspot address must be captured");
        addresses.set();
        networkGuard.onDefaultNetworkChanged();
        assertEquals(0, stopper.stopCalls);
        addressGuard.onAddressesChanged();
        addressGuard.onAddressesChanged();
        assertEquals(1, stopper.stopCalls);
    }

    private static void assertEquals(int expected, int actual) {
        if (expected != actual) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class FixedFactory implements LanServerOwner.Factory {
        private final LanServerOwner.Server server;

        private FixedFactory(LanServerOwner.Server server) {
            this.server = server;
        }

        @Override
        public LanServerOwner.Server create() {
            return server;
        }
    }

    private static final class FakeServer implements LanServerOwner.Server {
        private final boolean failOnStart;
        private final boolean failRuntime;
        private int startCalls;
        private int shutdownCalls;
        private boolean alive;

        private FakeServer(boolean failOnStart) {
            this(failOnStart, false);
        }
        private FakeServer(boolean failOnStart, boolean failRuntime) {
            this.failOnStart = failOnStart;
            this.failRuntime = failRuntime;
        }

        @Override
        public void start() throws IOException {
            startCalls++;
            if (failOnStart) {
                throw new IOException("expected startup failure");
            }
            if (failRuntime) throw new IllegalStateException("expected runtime startup failure");
            alive = true;
        }

        @Override
        public void shutdown() {
            shutdownCalls++;
            alive = false;
        }

        @Override
        public boolean isAlive() {
            return alive;
        }
    }

    private static final class FakeNetworkSource implements LanNetworkGuard.CurrentNetwork<String> {
        private String currentNetwork;

        private FakeNetworkSource(String currentNetwork) {
            this.currentNetwork = currentNetwork;
        }

        @Override
        public String current() {
            return currentNetwork;
        }
    }

    private static final class CountingStopper implements LanNetworkGuard.Stopper {
        private int stopCalls;

        @Override
        public void stop() {
            stopCalls++;
        }
    }

    private static final class FakeAddressSource implements LanAddressGuard.CurrentAddresses {
        private Set<String> addresses;

        private FakeAddressSource(String... addresses) {
            set(addresses);
        }

        private void set(String... values) {
            addresses = values.length == 0
                    ? Collections.<String>emptySet()
                    : new LinkedHashSet<String>(Arrays.asList(values));
        }

        @Override
        public Set<String> current() {
            return addresses;
        }
    }
}
