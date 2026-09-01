package com.passwordvault.local.core.storage;

import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.VaultStore;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKey;

public final class EncryptedVaultStore implements VaultStore {
    private static final byte[] ASSOCIATED_DATA = "PVL-DEVICE-V1".getBytes(StandardCharsets.UTF_8);

    private final EncryptedBlobStore blobStore;
    private final SecretKeyProvider keyProvider;
    private final VaultBinaryCodec codec;
    private final AesGcmCipher cipher;

    public EncryptedVaultStore(
            EncryptedBlobStore blobStore,
            SecretKeyProvider keyProvider,
            VaultBinaryCodec codec,
            AesGcmCipher cipher
    ) {
        if (blobStore == null || keyProvider == null || codec == null || cipher == null) {
            throw new IllegalArgumentException("EncryptedVaultStore dependencies must not be null");
        }
        this.blobStore = blobStore;
        this.keyProvider = keyProvider;
        this.codec = codec;
        this.cipher = cipher;
    }

    @Override
    public synchronized VaultSnapshot read() {
        EncryptedPayload encrypted = blobStore.read();
        if (encrypted == null) {
            return VaultSnapshot.empty();
        }

        SecretKey key = keyProvider.getOrCreate();
        byte[] plaintext = cipher.decrypt(key, encrypted, ASSOCIATED_DATA);
        try {
            return codec.decode(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public synchronized void replace(VaultSnapshot snapshot) {
        byte[] plaintext = codec.encode(snapshot);
        try {
            SecretKey key = keyProvider.getOrCreate();
            blobStore.replace(cipher.encrypt(key, plaintext, ASSOCIATED_DATA));
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }
}
