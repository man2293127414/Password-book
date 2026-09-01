package com.passwordvault.local.core;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.query.VaultQuery;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.core.validation.VaultValidator;
import com.passwordvault.local.ui.CredentialEditorController;
import com.passwordvault.local.ui.TaxonomyController;
import com.passwordvault.local.ui.VaultListController;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

final class PhoneUiControllerTest {
    static void run() {
        PhoneUiControllerTest test = new PhoneUiControllerTest();
        test.passwordRevealIsFixedScopedAndClearedOnStop();
        test.searchAndTaxonomyFiltersUseCoreQueryRules();
        test.editorCreatesAndUpdatesThroughValidatedService();
        test.taxonomyManagementUpdatesCredentialReferences();
        test.removedTaxonomyClearsStaleListFilters();
        test.deleteAndClearMutateTheEncryptedStoreFacadeContract();
        System.out.println("PASS PhoneUiControllerTest");
    }

    private void passwordRevealIsFixedScopedAndClearedOnStop() {
        VaultListController controller = listController(sampleSnapshot());
        Credential first = controller.findCredential("credential-1");
        Credential second = controller.findCredential("credential-2");

        assertEquals(VaultListController.MASKED_PASSWORD, controller.passwordText(first));
        assertEquals(VaultListController.MASKED_PASSWORD, controller.passwordText(second));

        controller.togglePassword("credential-1");
        assertEquals("short", controller.passwordText(first));
        assertEquals(VaultListController.MASKED_PASSWORD, controller.passwordText(second));

        controller.togglePassword("credential-2");
        assertEquals(VaultListController.MASKED_PASSWORD, controller.passwordText(first));
        assertEquals("a-much-longer-password", controller.passwordText(second));

        controller.onStop();
        assertEquals(VaultListController.MASKED_PASSWORD, controller.passwordText(second));
    }

    private void searchAndTaxonomyFiltersUseCoreQueryRules() {
        VaultListController controller = listController(sampleSnapshot());

        controller.setSearchText("邮箱");
        assertCredentialIds(controller.visibleCredentials(), "credential-2");

        controller.setSearchText("");
        controller.setCategoryId("category-1");
        assertCredentialIds(controller.visibleCredentials(), "credential-1");

        controller.setCategoryId(null);
        controller.setTagIds(setOf("tag-1", "tag-2"));
        assertCredentialIds(controller.visibleCredentials(), "credential-1");
    }

    private void editorCreatesAndUpdatesThroughValidatedService() {
        InMemoryVaultStore store = new InMemoryVaultStore(VaultSnapshot.empty());
        VaultService service = service(store);
        CredentialEditorController editor = new CredentialEditorController(service);

        expectValidationFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                editor.create(new CredentialDraft(
                        " ", "account", "password", "", null,
                        Collections.<String>emptySet(), ""
                ));
            }
        });

        Credential created = editor.create(new CredentialDraft(
                "  GitHub  ", "octocat", "first-password", "https://github.com", null,
                Collections.<String>emptySet(), "notes"
        ));
        assertEquals("GitHub", created.getName());
        assertEquals(1, created.getVersion());

        Credential updated = editor.update(created, new CredentialDraft(
                "GitHub", "octocat", "second-password", "https://github.com", null,
                Collections.<String>emptySet(), "updated notes"
        ));
        assertEquals("second-password", updated.getPassword());
        assertEquals(2, updated.getVersion());
        assertEquals(updated, store.read().getCredentials().get(0));
    }

    private void taxonomyManagementUpdatesCredentialReferences() {
        InMemoryVaultStore store = new InMemoryVaultStore(sampleSnapshot());
        TaxonomyController taxonomy = new TaxonomyController(service(store));

        assertEquals(1, taxonomy.categoryUsageCount("category-1"));
        assertEquals(2, taxonomy.tagUsageCount("tag-1"));

        Category renamed = taxonomy.renameCategory("category-1", 1, "工作账号");
        assertEquals("工作账号", renamed.getName());
        taxonomy.deleteCategory(renamed.getId(), renamed.getVersion());
        assertEquals(null, taxonomy.snapshot().getCredentials().get(0).getCategoryId());

        Tag tag = taxonomy.snapshot().findTag("tag-1");
        taxonomy.deleteTag(tag.getId(), tag.getVersion());
        assertTrue(!taxonomy.snapshot().getCredentials().get(0).getTagIds().contains("tag-1"));
        assertTrue(taxonomy.snapshot().getCredentials().get(0).getTagIds().contains("tag-2"));
        assertTrue(taxonomy.snapshot().getCredentials().get(1).getTagIds().isEmpty());
    }

    private void deleteAndClearMutateTheEncryptedStoreFacadeContract() {
        InMemoryVaultStore store = new InMemoryVaultStore(sampleSnapshot());
        VaultListController controller = new VaultListController(service(store), new VaultQuery());

        Credential first = controller.findCredential("credential-1");
        controller.deleteCredential(first.getId(), first.getVersion());
        assertCredentialIds(controller.visibleCredentials(), "credential-2");

        controller.clearAll();
        assertTrue(controller.snapshot().getCredentials().isEmpty());
        assertTrue(controller.snapshot().getCategories().isEmpty());
        assertTrue(controller.snapshot().getTags().isEmpty());
    }

    private void removedTaxonomyClearsStaleListFilters() {
        InMemoryVaultStore store = new InMemoryVaultStore(sampleSnapshot());
        VaultService service = service(store);
        VaultListController list = new VaultListController(service, new VaultQuery());
        TaxonomyController taxonomy = new TaxonomyController(service);
        list.setCategoryId("category-1");
        list.setTagIds(setOf("tag-1", "tag-2"));

        taxonomy.deleteCategory("category-1", 1);
        taxonomy.deleteTag("tag-1", 1);
        list.snapshot();

        assertEquals(null, list.getCategoryId());
        assertTrue(!list.getTagIds().contains("tag-1"));
        assertTrue(list.getTagIds().contains("tag-2"));
    }

    private static VaultListController listController(VaultSnapshot snapshot) {
        return new VaultListController(
                service(new InMemoryVaultStore(snapshot)),
                new VaultQuery()
        );
    }

    private static VaultService service(InMemoryVaultStore store) {
        AtomicInteger id = new AtomicInteger();
        return new VaultService(
                store,
                new VaultValidator(),
                new Supplier<String>() {
                    @Override
                    public String get() {
                        return "generated-" + id.incrementAndGet();
                    }
                },
                new LongSupplier() {
                    @Override
                    public long getAsLong() {
                        return 1_800_000_000_000L;
                    }
                }
        );
    }

    private static VaultSnapshot sampleSnapshot() {
        Category category = new Category("category-1", "工作", 1);
        Tag important = new Tag("tag-1", "重要", 1);
        Tag twoFactor = new Tag("tag-2", "两步验证", 1);
        Credential first = new Credential(
                "credential-1", "GitHub", "octocat", "short", "https://github.com",
                category.getId(), setOf(important.getId(), twoFactor.getId()), "notes",
                1, 1_700_000_000_000L, 1_700_000_000_000L
        );
        Credential second = new Credential(
                "credential-2", "邮箱", "me@example.test", "a-much-longer-password", "",
                null, setOf(important.getId()), "", 1,
                1_700_000_000_000L, 1_700_000_000_000L
        );
        return new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                3L,
                Arrays.asList(first, second),
                Arrays.asList(category),
                Arrays.asList(important, twoFactor)
        );
    }

    private static Set<String> setOf(String... values) {
        return new LinkedHashSet<String>(Arrays.asList(values));
    }

    private static void assertCredentialIds(List<Credential> credentials, String... expectedIds) {
        assertEquals(expectedIds.length, credentials.size());
        for (int index = 0; index < expectedIds.length; index++) {
            assertEquals(expectedIds[index], credentials.get(index).getId());
        }
    }

    private static void expectValidationFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected ValidationException");
        } catch (ValidationException expected) {
            // Expected.
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition) {
        if (!condition) throw new AssertionError("Expected condition to be true");
    }

    private interface ThrowingRunnable {
        void run();
    }
}
