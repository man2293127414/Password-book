package com.passwordvault.local.core;

import com.passwordvault.local.core.backup.BackupPayloadCrypto;
import com.passwordvault.local.core.backup.BackupService;
import com.passwordvault.local.core.backup.ImportPreview;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.core.validation.VaultValidator;
import com.passwordvault.local.ui.BackupController;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class PhoneBackupControllerTest {
    private static final char[] PASSWORD = "backup-password".toCharArray();

    static void run() {
        PhoneBackupControllerTest test = new PhoneBackupControllerTest();
        test.exportRequiresMatchingNonEmptyPasswords();
        test.previewAndConfirmationReplaceVaultAndNotifyOnce();
        test.cancelledPreviewDoesNotNotifyOrWrite();
        System.out.println("PASS PhoneBackupControllerTest");
    }

    private void exportRequiresMatchingNonEmptyPasswords() {
        Fixture fixture = fixture(snapshot("current"));

        expectValidationFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.controller.exportBackup(new char[0], new char[0]);
            }
        });
        expectValidationFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.controller.exportBackup(
                        "first-password".toCharArray(),
                        "different-password".toCharArray()
                );
            }
        });
        assertEquals(0, fixture.crypto.encryptCount);
    }

    private void previewAndConfirmationReplaceVaultAndNotifyOnce() {
        Fixture exporter = fixture(snapshot("imported"));
        byte[] backup = exporter.controller.exportBackup(PASSWORD, PASSWORD);
        Fixture importer = fixture(snapshot("current"));

        ImportPreview preview = importer.controller.previewImport(backup, PASSWORD);
        assertEquals(1, preview.getCredentialCount());
        assertEquals("current", importer.store.read().getCredentials().get(0).getName());

        importer.controller.confirmImport(preview);

        assertEquals("imported", importer.store.read().getCredentials().get(0).getName());
        assertEquals(1, importer.importCallbackCount.get());
        expectIllegalState(new ThrowingRunnable() {
            @Override
            public void run() {
                importer.controller.confirmImport(preview);
            }
        });
        assertEquals(1, importer.importCallbackCount.get());
    }

    private void cancelledPreviewDoesNotNotifyOrWrite() {
        Fixture fixture = fixture(snapshot("current"));
        byte[] backup = fixture.controller.exportBackup(PASSWORD, PASSWORD);
        ImportPreview preview = fixture.controller.previewImport(backup, PASSWORD);

        fixture.controller.cancelImport(preview);

        assertEquals("current", fixture.store.read().getCredentials().get(0).getName());
        assertEquals(0, fixture.importCallbackCount.get());
        expectIllegalState(new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.controller.confirmImport(preview);
            }
        });
    }

    private static Fixture fixture(VaultSnapshot initial) {
        InMemoryVaultStore store = new InMemoryVaultStore(initial);
        VaultService vaultService = new VaultService(
                store,
                new VaultValidator(),
                new Supplier<String>() {
                    @Override
                    public String get() {
                        return "unused-id";
                    }
                },
                new LongSupplier() {
                    @Override
                    public long getAsLong() {
                        return 1_900_000_000_000L;
                    }
                }
        );
        PassThroughBackupCrypto crypto = new PassThroughBackupCrypto();
        BackupService backupService = new BackupService(
                vaultService,
                new VaultBinaryCodec(),
                crypto
        );
        AtomicInteger callbackCount = new AtomicInteger();
        BackupController controller = new BackupController(
                vaultService,
                backupService,
                new Runnable() {
                    @Override
                    public void run() {
                        callbackCount.incrementAndGet();
                    }
                }
        );
        return new Fixture(store, crypto, callbackCount, controller);
    }

    private static VaultSnapshot snapshot(String name) {
        Credential credential = new Credential(
                "credential-" + name,
                name,
                "account",
                "password",
                "",
                null,
                Collections.<String>emptySet(),
                "",
                1,
                1000L,
                1000L
        );
        return new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                1L,
                Collections.singletonList(credential),
                Collections.emptyList(),
                Collections.emptyList()
        );
    }

    private static void expectValidationFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected ValidationException");
        } catch (ValidationException expected) {
            // Expected.
        }
    }

    private static void expectIllegalState(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected IllegalStateException");
        } catch (IllegalStateException expected) {
            // Expected.
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class PassThroughBackupCrypto implements BackupPayloadCrypto {
        private int encryptCount;

        @Override
        public byte[] encrypt(byte[] plaintext, char[] password) {
            encryptCount++;
            return plaintext.clone();
        }

        @Override
        public byte[] decrypt(byte[] backup, char[] password) {
            return backup.clone();
        }
    }

    private static final class Fixture {
        private final InMemoryVaultStore store;
        private final PassThroughBackupCrypto crypto;
        private final AtomicInteger importCallbackCount;
        private final BackupController controller;

        private Fixture(
                InMemoryVaultStore store,
                PassThroughBackupCrypto crypto,
                AtomicInteger importCallbackCount,
                BackupController controller
        ) {
            this.store = store;
            this.crypto = crypto;
            this.importCallbackCount = importCallbackCount;
            this.controller = controller;
        }
    }
}
