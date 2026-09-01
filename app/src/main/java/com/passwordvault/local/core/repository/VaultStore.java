package com.passwordvault.local.core.repository;

import com.passwordvault.local.core.model.VaultSnapshot;

public interface VaultStore {
    VaultSnapshot read();

    void replace(VaultSnapshot snapshot);
}
