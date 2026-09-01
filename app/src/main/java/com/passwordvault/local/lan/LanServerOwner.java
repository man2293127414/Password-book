package com.passwordvault.local.lan;

import java.io.IOException;

/** Owns one HTTP listener through startup failures and idempotent shutdown. */
final class LanServerOwner {
    interface Server {
        void start() throws IOException;

        void shutdown();

        boolean isAlive();
    }

    interface Factory {
        Server create();
    }

    private final Factory factory;
    private Server server;

    LanServerOwner(Factory factory) {
        if (factory == null) {
            throw new IllegalArgumentException("factory must not be null");
        }
        this.factory = factory;
    }

    synchronized boolean start() {
        if (server != null) {
            if (server.isAlive()) {
                return true;
            }
            server.shutdown();
            server = null;
        }

        Server candidate = factory.create();
        server = candidate;
        try {
            candidate.start();
            return true;
        } catch (IOException | RuntimeException exception) {
            server = null;
            candidate.shutdown();
            return false;
        }
    }

    synchronized void stop() {
        if (server == null) {
            return;
        }
        Server stoppedServer = server;
        server = null;
        stoppedServer.shutdown();
    }

    synchronized boolean isRunning() {
        return server != null && server.isAlive();
    }
}
