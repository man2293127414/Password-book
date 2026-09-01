package com.passwordvault.local.core;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.ConflictException;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.NotFoundException;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.core.validation.VaultValidator;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class VaultServiceTest {
    static void run() {
        VaultServiceTest test = new VaultServiceTest();
        test.createCredentialAssignsIdentityVersionAndTimestamps();
        test.failedCreateDoesNotWriteSnapshot();
        test.updateCredentialPreservesCreationAndIncrementsVersion();
        test.staleCredentialUpdateDoesNotOverwriteNewerData();
        test.deleteCredentialIsPermanentAndVersionChecked();
        test.categoryNamesAreNormalizedAndUnique();
        test.renamingCategoryIncrementsItsVersion();
        test.tagCreateAndRenameUseTheSameUniquenessRules();
        test.deletingCategoryUncategorizesCredentials();
        test.deletingTagRemovesAssociationsOnly();
        test.clearAllRemovesEveryEntityAndAdvancesRevision();
        test.missingEntitiesAreRejectedWithoutWriting();
        System.out.println("PASS VaultServiceTest");
    }

    private void createCredentialAssignsIdentityVersionAndTimestamps() {
        MutableClock clock = new MutableClock(1700000000000L);
        VaultService service = service(VaultSnapshot.empty(), ids("cred-1"), clock);

        Credential created = service.createCredential(draft("  GitHub  ", "secret"));

        assertEquals("cred-1", created.getId());
        assertEquals("GitHub", created.getName());
        assertEquals(1, created.getVersion());
        assertEquals(1700000000000L, created.getCreatedAtEpochMillis());
        assertEquals(1700000000000L, created.getUpdatedAtEpochMillis());
        assertEquals(1L, service.getSnapshot().getRevision());
        assertEquals(Collections.singletonList(created), service.getSnapshot().getCredentials());
    }

    private void failedCreateDoesNotWriteSnapshot() {
        VaultService service = service(VaultSnapshot.empty(), ids("unused"), new MutableClock(1L));

        expect(ValidationException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.createCredential(draft(" ", "secret"));
            }
        });

        assertEquals(0L, service.getSnapshot().getRevision());
        assertTrue(service.getSnapshot().getCredentials().isEmpty(), "failed create must not write");
    }

    private void updateCredentialPreservesCreationAndIncrementsVersion() {
        MutableClock clock = new MutableClock(1000L);
        VaultService service = service(VaultSnapshot.empty(), ids("cred-1"), clock);
        Credential created = service.createCredential(draft("GitHub", "old"));
        clock.set(2000L);

        Credential updated = service.updateCredential(
                created.getId(),
                created.getVersion(),
                draft("GitHub 工作", "new")
        );

        assertEquals("GitHub 工作", updated.getName());
        assertEquals("new", updated.getPassword());
        assertEquals(2, updated.getVersion());
        assertEquals(1000L, updated.getCreatedAtEpochMillis());
        assertEquals(2000L, updated.getUpdatedAtEpochMillis());
        assertEquals(2L, service.getSnapshot().getRevision());
    }

    private void staleCredentialUpdateDoesNotOverwriteNewerData() {
        MutableClock clock = new MutableClock(1000L);
        VaultService service = service(VaultSnapshot.empty(), ids("cred-1"), clock);
        Credential created = service.createCredential(draft("GitHub", "one"));
        clock.set(2000L);
        service.updateCredential(created.getId(), 1, draft("GitHub", "two"));
        final VaultSnapshot beforeStaleWrite = service.getSnapshot();

        expect(ConflictException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.updateCredential("cred-1", 1, draft("GitHub", "stale"));
            }
        });

        assertSame(beforeStaleWrite, service.getSnapshot());
        assertEquals("two", service.getSnapshot().getCredentials().get(0).getPassword());
    }

    private void deleteCredentialIsPermanentAndVersionChecked() {
        VaultService service = service(VaultSnapshot.empty(), ids("cred-1"), new MutableClock(1000L));
        Credential created = service.createCredential(draft("GitHub", "secret"));

        expect(ConflictException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.deleteCredential("cred-1", 99);
            }
        });
        service.deleteCredential(created.getId(), created.getVersion());

        assertTrue(service.getSnapshot().getCredentials().isEmpty(), "credential must be permanently removed");
        assertEquals(2L, service.getSnapshot().getRevision());
    }

    private void categoryNamesAreNormalizedAndUnique() {
        VaultService service = service(VaultSnapshot.empty(), ids("cat-1", "cat-2"), new MutableClock(1L));

        Category created = service.createCategory("  工作  ");

        assertEquals("cat-1", created.getId());
        assertEquals("工作", created.getName());
        assertEquals(1, created.getVersion());
        expect(ValidationException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.createCategory("工作");
            }
        });
        assertEquals(1, service.getSnapshot().getCategories().size());
    }

    private void renamingCategoryIncrementsItsVersion() {
        VaultService service = service(VaultSnapshot.empty(), ids("cat-1"), new MutableClock(1L));
        Category category = service.createCategory("工作");

        Category renamed = service.renameCategory(category.getId(), category.getVersion(), "项目");

        assertEquals("项目", renamed.getName());
        assertEquals(2, renamed.getVersion());
        expect(ConflictException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.renameCategory("cat-1", 1, "过期修改");
            }
        });
        assertEquals("项目", service.getSnapshot().getCategories().get(0).getName());
    }

    private void tagCreateAndRenameUseTheSameUniquenessRules() {
        VaultService service = service(VaultSnapshot.empty(), ids("tag-1", "tag-2"), new MutableClock(1L));
        Tag first = service.createTag("  重要  ");
        Tag second = service.createTag("共享");

        Tag renamed = service.renameTag(first.getId(), first.getVersion(), "私密");

        assertEquals("私密", renamed.getName());
        assertEquals(2, renamed.getVersion());
        assertEquals("共享", second.getName());
        expect(ValidationException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.renameTag("tag-1", 2, "共享");
            }
        });
        assertEquals("私密", service.getSnapshot().findTag("tag-1").getName());
    }

    private void deletingCategoryUncategorizesCredentials() {
        Category category = new Category("cat-work", "工作", 1);
        Credential credential = credential("cred-1", "GitHub", "cat-work", setOf("tag-important"), 4, 1000L, 1000L);
        VaultSnapshot initial = new VaultSnapshot(
                1, 7L, Collections.singletonList(credential), Collections.singletonList(category),
                Collections.singletonList(new Tag("tag-important", "重要", 1))
        );
        MutableClock clock = new MutableClock(2000L);
        VaultService service = service(initial, ids(), clock);

        service.deleteCategory("cat-work", 1);

        Credential changed = service.getSnapshot().getCredentials().get(0);
        assertTrue(service.getSnapshot().getCategories().isEmpty(), "category must be removed");
        assertEquals(null, changed.getCategoryId());
        assertEquals(5, changed.getVersion());
        assertEquals(2000L, changed.getUpdatedAtEpochMillis());
        assertEquals(setOf("tag-important"), changed.getTagIds());
        assertEquals(8L, service.getSnapshot().getRevision());
    }

    private void deletingTagRemovesAssociationsOnly() {
        Tag important = new Tag("tag-important", "重要", 1);
        Tag shared = new Tag("tag-shared", "共享", 1);
        Credential credential = credential(
                "cred-1", "GitHub", null, setOf("tag-important", "tag-shared"), 2, 1000L, 1000L
        );
        VaultSnapshot initial = new VaultSnapshot(
                1, 2L, Collections.singletonList(credential), Collections.<Category>emptyList(),
                Arrays.asList(important, shared)
        );
        MutableClock clock = new MutableClock(3000L);
        VaultService service = service(initial, ids(), clock);

        service.deleteTag("tag-important", 1);

        Credential changed = service.getSnapshot().getCredentials().get(0);
        assertEquals(Collections.singletonList(shared), service.getSnapshot().getTags());
        assertEquals(setOf("tag-shared"), changed.getTagIds());
        assertEquals(3, changed.getVersion());
        assertEquals(3000L, changed.getUpdatedAtEpochMillis());
        assertEquals(credential.getPassword(), changed.getPassword());
    }

    private void clearAllRemovesEveryEntityAndAdvancesRevision() {
        VaultSnapshot initial = new VaultSnapshot(
                1,
                12L,
                Collections.singletonList(credential("cred-1", "GitHub", null, Collections.<String>emptySet(), 1, 1L, 1L)),
                Collections.singletonList(new Category("cat-1", "工作", 1)),
                Collections.singletonList(new Tag("tag-1", "重要", 1))
        );
        VaultService service = service(initial, ids(), new MutableClock(1L));

        service.clearAll();

        VaultSnapshot cleared = service.getSnapshot();
        assertEquals(13L, cleared.getRevision());
        assertTrue(cleared.getCredentials().isEmpty(), "credentials must be empty");
        assertTrue(cleared.getCategories().isEmpty(), "categories must be empty");
        assertTrue(cleared.getTags().isEmpty(), "tags must be empty");
    }

    private void missingEntitiesAreRejectedWithoutWriting() {
        VaultService service = service(VaultSnapshot.empty(), ids(), new MutableClock(1L));
        final VaultSnapshot before = service.getSnapshot();

        expect(NotFoundException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.updateCredential("missing", 1, draft("GitHub", "secret"));
            }
        });
        expect(NotFoundException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.deleteCategory("missing", 1);
            }
        });
        expect(NotFoundException.class, new ThrowingRunnable() {
            @Override
            public void run() {
                service.deleteTag("missing", 1);
            }
        });
        assertSame(before, service.getSnapshot());
    }

    private static VaultService service(VaultSnapshot initial, Supplier<String> ids, LongSupplier clock) {
        return new VaultService(new InMemoryVaultStore(initial), new VaultValidator(), ids, clock);
    }

    private static CredentialDraft draft(String name, String password) {
        return new CredentialDraft(
                name, "account", password, "https://example.com", null,
                Collections.<String>emptySet(), "notes"
        );
    }

    private static Credential credential(
            String id,
            String name,
            String categoryId,
            java.util.Set<String> tagIds,
            int version,
            long createdAt,
            long updatedAt
    ) {
        return new Credential(
                id, name, "account", "secret", "https://example.com", categoryId, tagIds, "notes",
                version, createdAt, updatedAt
        );
    }

    private static Supplier<String> ids(final String... values) {
        return new Supplier<String>() {
            private int index;

            @Override
            public String get() {
                if (index >= values.length) {
                    throw new AssertionError("No test ID available");
                }
                return values[index++];
            }
        };
    }

    private static LinkedHashSet<String> setOf(String... values) {
        return new LinkedHashSet<String>(Arrays.asList(values));
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

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void assertSame(Object expected, Object actual) {
        if (expected != actual) {
            throw new AssertionError("Expected the same object reference");
        }
    }

    private interface ThrowingRunnable {
        void run();
    }

    private static final class MutableClock implements LongSupplier {
        private long value;

        private MutableClock(long value) {
            this.value = value;
        }

        @Override
        public long getAsLong() {
            return value;
        }

        private void set(long value) {
            this.value = value;
        }
    }
}
