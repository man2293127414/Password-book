package com.passwordvault.local.core;

import com.passwordvault.local.core.backup.BackupPayloadCrypto;
import com.passwordvault.local.core.backup.BackupService;
import com.passwordvault.local.core.backup.CorruptBackupException;
import com.passwordvault.local.core.backup.ImportPreview;
import com.passwordvault.local.core.backup.WrongBackupPasswordException;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.repository.VaultStore;
import com.passwordvault.local.core.validation.VaultValidator;

import java.util.Arrays;
import java.util.Collections;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class BackupServiceTest {
    private static final char[] PASSWORD = "backup-password".toCharArray();

    static void run() {
        BackupServiceTest test = new BackupServiceTest();
        test.previewReportsCountsWithoutWriting();
        test.confirmationReplacesEverythingExactlyOnce();
        test.previewCanOnlyBeAppliedOnce();
        test.newPreviewInvalidatesOlderPreview();
        test.cancelledPreviewCannotBeApplied();
        test.decryptFailureNeverWritesCurrentVault();
        test.invalidSnapshotNeverReachesPreviewOrStore();
        System.out.println("PASS BackupServiceTest");
    }

    private void previewReportsCountsWithoutWriting() {
        Fixture fixture = fixture(currentSnapshot());
        VaultSnapshot imported = importedSnapshot();
        byte[] backup = fixture.service.exportAll(imported, PASSWORD);

        ImportPreview preview = fixture.service.previewImport(backup, PASSWORD);

        assertEquals(2, preview.getCredentialCount());
        assertEquals(1, preview.getCategoryCount());
        assertEquals(2, preview.getTagCount());
        assertEquals(0, fixture.store.getReplaceCount());
        assertSame(fixture.initial, fixture.store.read());
    }

    private void confirmationReplacesEverythingExactlyOnce() {
        Fixture fixture = fixture(currentSnapshot());
        ImportPreview preview = fixture.service.previewImport(
                fixture.service.exportAll(importedSnapshot(), PASSWORD),
                PASSWORD
        );

        fixture.service.applyImport(preview);

        VaultSnapshot actual = fixture.store.read();
        assertEquals(1, fixture.store.getReplaceCount());
        assertEquals(fixture.initial.getRevision() + 1, actual.getRevision());
        assertEquals(importedSnapshot().getCredentials(), actual.getCredentials());
        assertEquals(importedSnapshot().getCategories(), actual.getCategories());
        assertEquals(importedSnapshot().getTags(), actual.getTags());
    }

    private void previewCanOnlyBeAppliedOnce() {
        Fixture fixture = fixture(currentSnapshot());
        final ImportPreview preview = fixture.service.previewImport(
                fixture.service.exportAll(importedSnapshot(), PASSWORD),
                PASSWORD
        );
        fixture.service.applyImport(preview);

        expect(IllegalStateException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.service.applyImport(preview);
            }
        });
        assertEquals(1, fixture.store.getReplaceCount());
    }

    private void newPreviewInvalidatesOlderPreview() {
        Fixture fixture = fixture(currentSnapshot());
        byte[] backup = fixture.service.exportAll(importedSnapshot(), PASSWORD);
        final ImportPreview first = fixture.service.previewImport(backup, PASSWORD);
        ImportPreview second = fixture.service.previewImport(backup, PASSWORD);

        expect(IllegalStateException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.service.applyImport(first);
            }
        });
        fixture.service.applyImport(second);
        assertEquals(1, fixture.store.getReplaceCount());
    }

    private void cancelledPreviewCannotBeApplied() {
        Fixture fixture = fixture(currentSnapshot());
        final ImportPreview preview = fixture.service.previewImport(
                fixture.service.exportAll(importedSnapshot(), PASSWORD),
                PASSWORD
        );

        fixture.service.cancelImport(preview);

        expect(IllegalStateException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.service.applyImport(preview);
            }
        });
        assertEquals(0, fixture.store.getReplaceCount());
    }

    private void decryptFailureNeverWritesCurrentVault() {
        Fixture fixture = fixture(currentSnapshot());
        fixture.crypto.failure = new WrongBackupPasswordException();

        expect(WrongBackupPasswordException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.service.previewImport(new byte[] {1, 2, 3}, PASSWORD);
            }
        });

        assertEquals(0, fixture.store.getReplaceCount());
        assertSame(fixture.initial, fixture.store.read());
    }

    private void invalidSnapshotNeverReachesPreviewOrStore() {
        Credential invalid = credential("cred-invalid", "Missing category", "missing");
        VaultSnapshot invalidSnapshot = new VaultSnapshot(
                1,
                1L,
                Collections.singletonList(invalid),
                Collections.<Category>emptyList(),
                Collections.<Tag>emptyList()
        );
        Fixture fixture = fixture(currentSnapshot());
        final byte[] backup = fixture.service.exportAll(invalidSnapshot, PASSWORD);

        expect(CorruptBackupException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                fixture.service.previewImport(backup, PASSWORD);
            }
        });

        assertEquals(0, fixture.store.getReplaceCount());
        assertSame(fixture.initial, fixture.store.read());
    }

    private static Fixture fixture(VaultSnapshot initial) {
        CountingVaultStore store = new CountingVaultStore(initial);
        VaultService vaultService = new VaultService(
                store,
                new VaultValidator(),
                new Supplier<String>() {
                    @Override
                    public String get() {
                        throw new AssertionError("ID generation is not expected during import");
                    }
                },
                new LongSupplier() {
                    @Override
                    public long getAsLong() {
                        return 9999L;
                    }
                }
        );
        FakeBackupCrypto crypto = new FakeBackupCrypto();
        BackupService service = new BackupService(vaultService, new VaultBinaryCodec(), crypto);
        return new Fixture(initial, store, crypto, service);
    }

    private static VaultSnapshot currentSnapshot() {
        return new VaultSnapshot(
                1,
                20L,
                Collections.singletonList(credential("current", "Current", null)),
                Collections.<Category>emptyList(),
                Collections.<Tag>emptyList()
        );
    }

    private static VaultSnapshot importedSnapshot() {
        Category category = new Category("cat-work", "工作", 1);
        Tag important = new Tag("tag-important", "重要", 1);
        Tag shared = new Tag("tag-shared", "共享", 1);
        Credential first = new Credential(
                "cred-1", "GitHub", "octocat", "secret-1", "https://github.com", "cat-work",
                new java.util.LinkedHashSet<String>(Arrays.asList("tag-important", "tag-shared")),
                "notes", 2, 1000L, 2000L
        );
        Credential second = credential("cred-2", "Bank", null);
        return new VaultSnapshot(
                1,
                3L,
                Arrays.asList(first, second),
                Collections.singletonList(category),
                Arrays.asList(important, shared)
        );
    }

    private static Credential credential(String id, String name, String categoryId) {
        return new Credential(
                id, name, "account", "secret", "https://example.com", categoryId,
                Collections.<String>emptySet(), "notes", 1, 1000L, 1000L
        );
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

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertSame(Object expected, Object actual) {
        if (expected != actual) throw new AssertionError("Expected same object reference");
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class Fixture {
        private final VaultSnapshot initial;
        private final CountingVaultStore store;
        private final FakeBackupCrypto crypto;
        private final BackupService service;

        private Fixture(
                VaultSnapshot initial,
                CountingVaultStore store,
                FakeBackupCrypto crypto,
                BackupService service
        ) {
            this.initial = initial;
            this.store = store;
            this.crypto = crypto;
            this.service = service;
        }
    }

    private static final class CountingVaultStore implements VaultStore {
        private VaultSnapshot snapshot;
        private int replaceCount;

        private CountingVaultStore(VaultSnapshot snapshot) {
            this.snapshot = snapshot;
        }

        @Override
        public VaultSnapshot read() {
            return snapshot;
        }

        @Override
        public void replace(VaultSnapshot replacement) {
            replaceCount++;
            snapshot = replacement;
        }

        private int getReplaceCount() {
            return replaceCount;
        }
    }

    private static final class FakeBackupCrypto implements BackupPayloadCrypto {
        private RuntimeException failure;

        @Override
        public byte[] encrypt(byte[] plaintext, char[] password) {
            return plaintext.clone();
        }

        @Override
        public byte[] decrypt(byte[] backup, char[] password) {
            if (failure != null) throw failure;
            return backup.clone();
        }
    }
}
