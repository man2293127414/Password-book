package com.passwordvault.local.storage;

import android.content.Context;

import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.VaultStore;

import java.security.SecureRandom;

public final class EncryptedVaultStore implements VaultStore, AutoCloseable {
    private final VaultDatabase database;
    private final com.passwordvault.local.core.storage.EncryptedVaultStore delegate;

    public EncryptedVaultStore(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        database = new VaultDatabase(context);
        delegate = new com.passwordvault.local.core.storage.EncryptedVaultStore(
                database,
                new DeviceKeyProvider(),
                new VaultBinaryCodec(),
                new AesGcmCipher(new SecureRandom())
        );
    }

    @Override
    public VaultSnapshot read() {
        return delegate.read();
    }

    @Override
    public void replace(VaultSnapshot snapshot) {
        delegate.replace(snapshot);
    }

    @Override
    public void close() {
        database.close();
    }
}
