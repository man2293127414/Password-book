package com.passwordvault.local.core.backup;

import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class BackupCrypto implements BackupPayloadCrypto {
    private static final int DERIVED_KEY_BITS = 512;
    private static final int AES_KEY_BYTES = 32;
    private static final byte[] PASSWORD_CHECK = "PVLB-PASSWORD-CHECK-V1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CIPHERTEXT_AAD = "PVLB-CIPHERTEXT-V1".getBytes(StandardCharsets.UTF_8);

    private final SecureRandom secureRandom;
    private final BackupEnvelopeCodec envelopeCodec;
    private final AesGcmCipher cipher;

    public BackupCrypto(SecureRandom secureRandom) {
        if (secureRandom == null) {
            throw new IllegalArgumentException("secureRandom must not be null");
        }
        this.secureRandom = secureRandom;
        this.envelopeCodec = new BackupEnvelopeCodec();
        this.cipher = new AesGcmCipher(secureRandom);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, char[] password) {
        requireInputs(plaintext, password);
        byte[] salt = new byte[BackupEnvelope.SALT_BYTES];
        secureRandom.nextBytes(salt);
        DerivedKeys keys = derive(password, salt);
        try {
            byte[] verifier = passwordVerifier(keys.verifierKey);
            EncryptedPayload encrypted = cipher.encrypt(keys.encryptionKey, plaintext, CIPHERTEXT_AAD);
            return envelopeCodec.encode(new BackupEnvelope(
                    salt,
                    verifier,
                    encrypted.getNonce(),
                    encrypted.getCiphertext()
            ));
        } finally {
            keys.clear();
            Arrays.fill(salt, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(byte[] backup, char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        BackupEnvelope envelope = envelopeCodec.decode(backup);
        byte[] salt = envelope.getSalt();
        DerivedKeys keys = derive(password, salt);
        try {
            byte[] expectedVerifier = passwordVerifier(keys.verifierKey);
            byte[] actualVerifier = envelope.getVerifier();
            boolean passwordMatches = MessageDigest.isEqual(expectedVerifier, actualVerifier);
            Arrays.fill(expectedVerifier, (byte) 0);
            Arrays.fill(actualVerifier, (byte) 0);
            if (!passwordMatches) {
                throw new WrongBackupPasswordException();
            }
            try {
                return cipher.decrypt(
                        keys.encryptionKey,
                        new EncryptedPayload(envelope.getNonce(), envelope.getCiphertext()),
                        CIPHERTEXT_AAD
                );
            } catch (CryptoException exception) {
                throw new CorruptBackupException("Backup ciphertext authentication failed", exception);
            }
        } finally {
            keys.clear();
            Arrays.fill(salt, (byte) 0);
        }
    }

    private static DerivedKeys derive(char[] password, byte[] salt) {
        PBEKeySpec keySpec = new PBEKeySpec(
                password,
                salt,
                BackupEnvelopeCodec.ITERATIONS,
                DERIVED_KEY_BITS
        );
        byte[] derived = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            derived = factory.generateSecret(keySpec).getEncoded();
            byte[] encryptionKey = Arrays.copyOfRange(derived, 0, AES_KEY_BYTES);
            byte[] verifierKey = Arrays.copyOfRange(derived, AES_KEY_BYTES, derived.length);
            return new DerivedKeys(encryptionKey, verifierKey);
        } catch (GeneralSecurityException exception) {
            throw new BackupException("Unable to derive backup key", exception);
        } finally {
            keySpec.clearPassword();
            if (derived != null) Arrays.fill(derived, (byte) 0);
        }
    }

    private static byte[] passwordVerifier(SecretKey verifierKey) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(verifierKey);
            return Arrays.copyOf(mac.doFinal(PASSWORD_CHECK), BackupEnvelope.VERIFIER_BYTES);
        } catch (GeneralSecurityException exception) {
            throw new BackupException("Unable to verify backup password", exception);
        }
    }

    private static void requireInputs(byte[] plaintext, char[] password) {
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
    }

    private static final class DerivedKeys {
        private final byte[] encryptionKeyBytes;
        private final byte[] verifierKeyBytes;
        private final SecretKey encryptionKey;
        private final SecretKey verifierKey;

        private DerivedKeys(byte[] encryptionKeyBytes, byte[] verifierKeyBytes) {
            this.encryptionKeyBytes = encryptionKeyBytes;
            this.verifierKeyBytes = verifierKeyBytes;
            this.encryptionKey = new SecretKeySpec(encryptionKeyBytes, "AES");
            this.verifierKey = new SecretKeySpec(verifierKeyBytes, "HmacSHA256");
        }

        private void clear() {
            Arrays.fill(encryptionKeyBytes, (byte) 0);
            Arrays.fill(verifierKeyBytes, (byte) 0);
        }
    }
}
