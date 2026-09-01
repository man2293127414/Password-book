package com.passwordvault.local.core.lan;

import java.util.Arrays;

public final class LanSessionKeys {
    private static final int KEY_BYTES = 32;

    private final byte[] clientToServerKey;
    private final byte[] serverToClientKey;
    private boolean destroyed;

    LanSessionKeys(byte[] clientToServerKey, byte[] serverToClientKey) {
        requireKey(clientToServerKey);
        requireKey(serverToClientKey);
        this.clientToServerKey = clientToServerKey.clone();
        this.serverToClientKey = serverToClientKey.clone();
    }

    public synchronized byte[] getClientToServerKey() { requireOpen(); return clientToServerKey.clone(); }
    public synchronized byte[] getServerToClientKey() { requireOpen(); return serverToClientKey.clone(); }
    public synchronized void destroy() { Arrays.fill(clientToServerKey, (byte) 0); Arrays.fill(serverToClientKey, (byte) 0); destroyed = true; }
    public synchronized boolean isDestroyed() { return destroyed; }

    private void requireOpen() { if (destroyed) throw new IllegalStateException("LAN session keys have been destroyed"); }

    private static void requireKey(byte[] key) {
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalArgumentException("LAN session key must contain 32 bytes");
        }
    }
}
