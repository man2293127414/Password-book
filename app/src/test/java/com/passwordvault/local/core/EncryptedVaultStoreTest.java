package com.passwordvault.local.core;

import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.storage.EncryptedBlobStore;
import com.passwordvault.local.core.storage.EncryptedVaultStore;
import com.passwordvault.local.core.storage.SecretKeyProvider;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

final class EncryptedVaultStoreTest {
    private static final SecretKey KEY = new SecretKeySpec(new byte[] {
            0, 1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
    }, "AES");

    static void run() {
        EncryptedVaultStoreTest test = new EncryptedVaultStoreTest();
        test.emptyBlobStoreReadsAsEmptyVault();
        test.replacesAndReadsEncryptedSnapshot();
        test.corruptedCiphertextIsNeverReturnedAsEmptyData();
        System.out.println("PASS EncryptedVaultStoreTest");
    }

    private void emptyBlobStoreReadsAsEmptyVault() {
        InMemoryEncryptedBlobStore blobs = new InMemoryEncryptedBlobStore();
        EncryptedVaultStore store = store(blobs);

        VaultSnapshot snapshot = store.read();

        assertEquals(0L, snapshot.getRevision());
        assertTrue(snapshot.getCredentials().isEmpty(), "new store must start empty");
    }

    private void replacesAndReadsEncryptedSnapshot() {
        InMemoryEncryptedBlobStore blobs = new InMemoryEncryptedBlobStore();
        EncryptedVaultStore store = store(blobs);
        VaultSnapshot expected = snapshot("unique-plaintext-password");

        store.replace(expected);
        VaultSnapshot actual = store.read();

        assertEquals(expected.getRevision(), actual.getRevision());
        assertEquals(expected.getCredentials(), actual.getCredentials());
        assertTrue(blobs.payload != null, "encrypted blob must be written");
        assertTrue(
                !contains(
                        blobs.payload.getCiphertext(),
                        "unique-plaintext-password".getBytes(StandardCharsets.UTF_8)
                ),
                "stored ciphertext must not contain plaintext password"
        );
    }

    private void corruptedCiphertextIsNeverReturnedAsEmptyData() {
        InMemoryEncryptedBlobStore blobs = new InMemoryEncryptedBlobStore();
        EncryptedVaultStore store = store(blobs);
        store.replace(snapshot("secret"));
        byte[] corrupted = blobs.payload.getCiphertext();
        corrupted[0] ^= 1;
        blobs.payload = new EncryptedPayload(blobs.payload.getNonce(), corrupted);

        try {
            store.read();
            throw new AssertionError("Expected CryptoException");
        } catch (CryptoException expected) {
            // Corruption must be visible to the caller, not treated as an empty vault.
        }
    }

    private static EncryptedVaultStore store(InMemoryEncryptedBlobStore blobs) {
        return new EncryptedVaultStore(
                blobs,
                new SecretKeyProvider() {
                    @Override
                    public SecretKey getOrCreate() {
                        return KEY;
                    }
                },
                new VaultBinaryCodec(),
                new AesGcmCipher(new SecureRandom())
        );
    }

    private static VaultSnapshot snapshot(String password) {
        Credential credential = new Credential(
                "cred-1", "GitHub", "octocat", password, "https://github.com", null,
                Collections.<String>emptySet(), "notes", 1, 1000L, 1000L
        );
        return new VaultSnapshot(
                1,
                9L,
                Collections.singletonList(credential),
                Collections.emptyList(),
                Collections.emptyList()
        );
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

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class InMemoryEncryptedBlobStore implements EncryptedBlobStore {
        private EncryptedPayload payload;

        @Override
        public EncryptedPayload read() {
            return payload;
        }

        @Override
        public void replace(EncryptedPayload replacement) {
            payload = replacement;
        }
    }
}
