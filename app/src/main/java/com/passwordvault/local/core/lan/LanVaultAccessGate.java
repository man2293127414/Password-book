package com.passwordvault.local.core.lan;

import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

/** Drains authenticated LAN work before a phone-side replace-all or clear-all mutation. */
public final class LanVaultAccessGate {
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    public <T> T runLanRequest(Supplier<T> operation) {
        if (operation == null) throw new IllegalArgumentException("operation must not be null");
        lock.readLock().lock();
        try {
            return operation.get();
        } finally {
            lock.readLock().unlock();
        }
    }

    public void runExclusiveMutation(Runnable operation) {
        if (operation == null) throw new IllegalArgumentException("operation must not be null");
        lock.writeLock().lock();
        try {
            operation.run();
        } finally {
            lock.writeLock().unlock();
        }
    }
}
