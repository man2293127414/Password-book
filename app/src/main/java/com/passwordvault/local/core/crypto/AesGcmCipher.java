package com.passwordvault.local.core.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class AesGcmCipher {
    private static final int AUTHENTICATION_TAG_BITS = 128;

    private final SecureRandom secureRandom;

    public AesGcmCipher(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.secureRandom = secureRandom;
    }

    public EncryptedPayload encrypt(SecretKey key, byte[] plaintext, byte[] associatedData) {
        requireInputs(key, plaintext, associatedData);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, secureRandom);
            byte[] nonce = cipher.getIV();
            if (nonce == null || nonce.length != EncryptedPayload.NONCE_BYTES) {
                throw new GeneralSecurityException("AES-GCM provider returned an invalid nonce");
            }
            cipher.updateAAD(associatedData);
            return new EncryptedPayload(nonce, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to encrypt vault payload", exception);
        }
    }

    public byte[] decrypt(SecretKey key, EncryptedPayload encrypted, byte[] associatedData) {
        if (encrypted == null) {
            throw new IllegalArgumentException("encrypted must not be null");
        }
        requireInputs(key, encrypted.getCiphertext(), associatedData);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(AUTHENTICATION_TAG_BITS, encrypted.getNonce())
            );
            cipher.updateAAD(associatedData);
            return cipher.doFinal(encrypted.getCiphertext());
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Vault payload authentication failed", exception);
        }
    }

    private static void requireInputs(SecretKey key, byte[] bytes, byte[] associatedData) {
        if (key == null) throw new IllegalArgumentException("key must not be null");
        if (bytes == null) throw new IllegalArgumentException("data must not be null");
        if (associatedData == null) throw new IllegalArgumentException("associatedData must not be null");
    }
}
