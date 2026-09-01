package com.passwordvault.local.core;

import com.passwordvault.local.core.backup.BackupCrypto;
import com.passwordvault.local.core.backup.CorruptBackupException;
import com.passwordvault.local.core.backup.UnsupportedBackupVersionException;
import com.passwordvault.local.core.backup.WrongBackupPasswordException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

final class BackupCryptoTest {
    private static final char[] PASSWORD = "正确的备份密码-2026".toCharArray();

    static void run() {
        BackupCryptoTest test = new BackupCryptoTest();
        test.roundTripsEncryptedBackup();
        test.backupDoesNotContainPlaintext();
        test.classifiesWrongPassword();
        test.classifiesCorruptedCiphertext();
        test.rejectsUnsupportedVersion();
        test.rejectsTruncatedEnvelope();
        System.out.println("PASS BackupCryptoTest");
    }

    private void roundTripsEncryptedBackup() {
        BackupCrypto crypto = crypto();
        byte[] plaintext = "账号、密码、备注\nsecret".getBytes(StandardCharsets.UTF_8);

        byte[] backup = crypto.encrypt(plaintext, PASSWORD);
        byte[] decrypted = crypto.decrypt(backup, PASSWORD);

        assertTrue(Arrays.equals(plaintext, decrypted), "backup must decrypt to original bytes");
    }

    private void backupDoesNotContainPlaintext() {
        BackupCrypto crypto = crypto();
        byte[] plaintext = "unique-backup-password".getBytes(StandardCharsets.UTF_8);

        byte[] backup = crypto.encrypt(plaintext, PASSWORD);

        assertTrue(!contains(backup, plaintext), "backup file must not contain plaintext secret");
    }

    private void classifiesWrongPassword() {
        BackupCrypto crypto = crypto();
        final byte[] backup = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), PASSWORD);

        expect(WrongBackupPasswordException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decrypt(backup, "错误密码".toCharArray());
            }
        });
    }

    private void classifiesCorruptedCiphertext() {
        BackupCrypto crypto = crypto();
        final byte[] backup = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), PASSWORD);
        backup[backup.length - 1] ^= 1;

        expect(CorruptBackupException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decrypt(backup, PASSWORD);
            }
        });
    }

    private void rejectsUnsupportedVersion() {
        BackupCrypto crypto = crypto();
        final byte[] backup = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), PASSWORD);
        backup[7] = 2;

        expect(UnsupportedBackupVersionException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decrypt(backup, PASSWORD);
            }
        });
    }

    private void rejectsTruncatedEnvelope() {
        BackupCrypto crypto = crypto();
        byte[] backup = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), PASSWORD);
        final byte[] truncated = Arrays.copyOf(backup, backup.length - 1);

        expect(CorruptBackupException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decrypt(truncated, PASSWORD);
            }
        });
    }

    private static BackupCrypto crypto() {
        return new BackupCrypto(new CountingSecureRandom());
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[start + offset] != needle[offset]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static void expect(Class<? extends Throwable> expectedType, ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected " + expectedType.getSimpleName());
        } catch (Throwable actual) {
            if (!expectedType.isInstance(actual)) {
                throw new AssertionError(
                        "Expected " + expectedType.getSimpleName() + " but got " + actual.getClass().getSimpleName(),
                        actual
                );
            }
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class CountingSecureRandom extends SecureRandom {
        private int nextValue;

        @Override
        public void nextBytes(byte[] target) {
            for (int index = 0; index < target.length; index++) {
                target[index] = (byte) nextValue++;
            }
        }
    }
}
