package com.passwordvault.local.storage;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.storage.SecretKeyProvider;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public final class DeviceKeyProvider implements SecretKeyProvider {
    static final String KEY_ALIAS = "password_vault_device_key_v1";

    private static final String KEY_STORE = "AndroidKeyStore";
    private static final Object KEY_LOCK = new Object();

    @Override
    public SecretKey getOrCreate() {
        synchronized (KEY_LOCK) {
            try {
                KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
                keyStore.load(null);

                Key existing = keyStore.getKey(KEY_ALIAS, null);
                if (existing != null) {
                    if (!(existing instanceof SecretKey)) {
                        throw new CryptoException(
                                "Device vault key has an unexpected type",
                                new IllegalStateException(existing.getClass().getName())
                        );
                    }
                    return (SecretKey) existing;
                }

                KeyGenerator generator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        KEY_STORE
                );
                generator.init(new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
                )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .setRandomizedEncryptionRequired(true)
                        .setUserAuthenticationRequired(false)
                        .build());
                return generator.generateKey();
            } catch (GeneralSecurityException | IOException exception) {
                throw new CryptoException("Unable to access the device vault key", exception);
            }
        }
    }
}
