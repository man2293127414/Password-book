package com.passwordvault.local.core.storage;

import com.passwordvault.local.core.crypto.EncryptedPayload;

public interface EncryptedBlobStore {
    EncryptedPayload read();

    void replace(EncryptedPayload replacement);
}
