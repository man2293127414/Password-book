package com.passwordvault.local.core;

import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

final class AesGcmCipherTest {
    private static final byte[] NONCE = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    private static final byte[] AAD = "PVL-DEVICE-V1".getBytes(StandardCharsets.UTF_8);
    private static final SecretKey KEY = new SecretKeySpec(new byte[] {
            0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
    }, "AES");

    static void run() {
        AesGcmCipherTest test = new AesGcmCipherTest();
        test.encryptsAndDecryptsWithAesGcm();
        test.encryptedPayloadDefensivelyCopiesSecretBytes();
        test.rejectsTamperedCiphertext();
        test.rejectsDifferentAssociatedData();
        System.out.println("PASS AesGcmCipherTest");
    }

    private void encryptsAndDecryptsWithAesGcm() {
        AesGcmCipher cipher = new AesGcmCipher(new FixedSecureRandom(NONCE));
        byte[] plaintext = "账号和密码 secret".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload encrypted = cipher.encrypt(KEY, plaintext, AAD);
        byte[] decrypted = cipher.decrypt(KEY, encrypted, AAD);

        assertTrue(Arrays.equals(NONCE, encrypted.getNonce()), "cipher must use a 12-byte nonce");
        assertTrue(!Arrays.equals(plaintext, encrypted.getCiphertext()), "ciphertext must differ from plaintext");
        assertTrue(Arrays.equals(plaintext, decrypted), "decrypted bytes must equal plaintext");
    }

    private void encryptedPayloadDefensivelyCopiesSecretBytes() {
        AesGcmCipher cipher = new AesGcmCipher(new FixedSecureRandom(NONCE));
        byte[] plaintext = "secret".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload encrypted = cipher.encrypt(KEY, plaintext, AAD);

        byte[] exposedNonce = encrypted.getNonce();
        byte[] exposedCiphertext = encrypted.getCiphertext();
        exposedNonce[0] = 99;
        exposedCiphertext[0] ^= 1;

        assertTrue(Arrays.equals(plaintext, cipher.decrypt(KEY, encrypted, AAD)), "getter mutation must not alter payload");
    }

    private void rejectsTamperedCiphertext() {
        AesGcmCipher cipher = new AesGcmCipher(new FixedSecureRandom(NONCE));
        EncryptedPayload encrypted = cipher.encrypt(
                KEY,
                "secret".getBytes(StandardCharsets.UTF_8),
                AAD
        );
        byte[] tampered = encrypted.getCiphertext();
        tampered[tampered.length - 1] ^= 1;

        expectCryptoFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                cipher.decrypt(KEY, new EncryptedPayload(encrypted.getNonce(), tampered), AAD);
            }
        });
    }

    private void rejectsDifferentAssociatedData() {
        AesGcmCipher cipher = new AesGcmCipher(new FixedSecureRandom(NONCE));
        EncryptedPayload encrypted = cipher.encrypt(
                KEY,
                "secret".getBytes(StandardCharsets.UTF_8),
                AAD
        );

        expectCryptoFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                cipher.decrypt(
                        KEY,
                        encrypted,
                        "WRONG-AAD".getBytes(StandardCharsets.UTF_8)
                );
            }
        });
    }

    private static void expectCryptoFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected CryptoException");
        } catch (CryptoException expected) {
            // Expected behavior.
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class FixedSecureRandom extends SecureRandom {
        private final byte[] bytes;

        private FixedSecureRandom(byte[] bytes) {
            this.bytes = bytes.clone();
        }

        @Override
        public void nextBytes(byte[] target) {
            if (target.length != bytes.length) {
                throw new AssertionError("Unexpected random byte count: " + target.length);
            }
            System.arraycopy(bytes, 0, target, 0, bytes.length);
        }
    }
}
