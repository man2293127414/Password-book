package com.passwordvault.local.core.repository;

import com.passwordvault.local.core.model.VaultSnapshot;

public final class InMemoryVaultStore implements VaultStore {
    private VaultSnapshot snapshot;

    public InMemoryVaultStore(VaultSnapshot initialSnapshot) {
        if (initialSnapshot == null) {
            throw new IllegalArgumentException("initialSnapshot must not be null");
        }
        snapshot = initialSnapshot;
    }

    @Override
    public synchronized VaultSnapshot read() {
        return snapshot;
    }

    @Override
    public synchronized void replace(VaultSnapshot replacement) {
        if (replacement == null) {
            throw new IllegalArgumentException("replacement must not be null");
        }
        snapshot = replacement;
    }
}
