package com.passwordvault.local.core;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.query.VaultFilter;
import com.passwordvault.local.core.query.VaultQuery;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class VaultQueryTest {
    private final VaultQuery query = new VaultQuery();
    private final VaultSnapshot snapshot = fixture();

    static void run() {
        VaultQueryTest test = new VaultQueryTest();
        test.searchesNameAndAccountAndUrlCaseInsensitively();
        test.searchesResolvedCategoryName();
        test.searchesResolvedTagName();
        test.doesNotSearchPasswordOrNotes();
        test.filtersByCategory();
        test.filtersUnclassifiedCredentials();
        test.requiresEverySelectedTag();
        test.combinesSearchCategoryAndTags();
        test.sortsByNameByDefault();
        test.returnsImmutableResults();
        System.out.println("PASS VaultQueryTest");
    }

    private void searchesNameAndAccountAndUrlCaseInsensitively() {
        assertIds(query.apply(snapshot, filter("GIT")), "c1");
        assertIds(query.apply(snapshot, filter("SHOPPER")), "c2");
        assertIds(query.apply(snapshot, filter("bank.example")), "c3");
    }

    private void searchesResolvedCategoryName() {
        assertIds(query.apply(snapshot, filter("工作")), "c2", "c1");
    }

    private void searchesResolvedTagName() {
        assertIds(query.apply(snapshot, filter("重要")), "c1");
    }

    private void doesNotSearchPasswordOrNotes() {
        assertIds(query.apply(snapshot, filter("secret-gh")));
        assertIds(query.apply(snapshot, filter("private memo")));
    }

    private void filtersByCategory() {
        assertIds(
                query.apply(snapshot, new VaultFilter("", "cat-work", Collections.<String>emptySet())),
                "c2", "c1"
        );
        assertIds(
                query.apply(snapshot, new VaultFilter("", "missing", Collections.<String>emptySet()))
        );
    }

    private void filtersUnclassifiedCredentials() {
        Credential unclassified = credential(
                "c4", "本地服务", "local", "secret-local", "",
                null, Collections.<String>emptySet(), ""
        );
        VaultSnapshot withUnclassified = new VaultSnapshot(
                snapshot.getSchemaVersion(),
                snapshot.getRevision(),
                Arrays.asList(
                        snapshot.getCredentials().get(0),
                        snapshot.getCredentials().get(1),
                        snapshot.getCredentials().get(2),
                        unclassified
                ),
                snapshot.getCategories(),
                snapshot.getTags()
        );

        assertIds(
                query.apply(withUnclassified, new VaultFilter(
                        "",
                        VaultFilter.UNCLASSIFIED_CATEGORY_ID,
                        Collections.<String>emptySet()
                )),
                "c4"
        );
        assertIds(
                query.apply(withUnclassified, new VaultFilter(
                        "未分类",
                        null,
                        Collections.<String>emptySet()
                )),
                "c4"
        );
    }

    private void requiresEverySelectedTag() {
        assertIds(
                query.apply(snapshot, new VaultFilter("", null, setOf("tag-important", "tag-shared"))),
                "c1"
        );
    }

    private void combinesSearchCategoryAndTags() {
        assertIds(
                query.apply(snapshot, new VaultFilter("github", "cat-work", setOf("tag-important"))),
                "c1"
        );
        assertIds(
                query.apply(snapshot, new VaultFilter("amazon", "cat-work", setOf("tag-important")))
        );
    }

    private void sortsByNameByDefault() {
        assertIds(query.apply(snapshot, filter("")), "c2", "c1", "c3");
    }

    private void returnsImmutableResults() {
        final List<Credential> result = query.apply(snapshot, filter(""));
        try {
            result.clear();
            throw new AssertionError("Expected an immutable query result");
        } catch (UnsupportedOperationException expected) {
            // Expected behavior.
        }
    }

    private static VaultFilter filter(String searchText) {
        return new VaultFilter(searchText, null, Collections.<String>emptySet());
    }

    private static VaultSnapshot fixture() {
        Category work = new Category("cat-work", "工作", 1);
        Category personal = new Category("cat-personal", "个人", 1);
        Tag important = new Tag("tag-important", "重要", 1);
        Tag shared = new Tag("tag-shared", "共享", 1);
        Credential github = credential(
                "c1", "GitHub", "octocat", "secret-gh", "https://github.com",
                "cat-work", setOf("tag-important", "tag-shared"), "private memo"
        );
        Credential amazon = credential(
                "c2", "Amazon", "shopper", "secret-amz", "https://amazon.example",
                "cat-work", setOf("tag-shared"), ""
        );
        Credential bank = credential(
                "c3", "银行", "6222", "secret-bank", "https://bank.example",
                "cat-personal", Collections.<String>emptySet(), ""
        );
        return new VaultSnapshot(
                1,
                5L,
                Arrays.asList(github, bank, amazon),
                Arrays.asList(work, personal),
                Arrays.asList(important, shared)
        );
    }

    private static Credential credential(
            String id,
            String name,
            String account,
            String password,
            String url,
            String categoryId,
            Set<String> tagIds,
            String notes
    ) {
        return new Credential(
                id, name, account, password, url, categoryId, tagIds, notes,
                1, 1000L, 1000L
        );
    }

    private static LinkedHashSet<String> setOf(String... values) {
        return new LinkedHashSet<String>(Arrays.asList(values));
    }

    private static void assertIds(List<Credential> credentials, String... expectedIds) {
        if (credentials.size() != expectedIds.length) {
            throw new AssertionError(
                    "Expected IDs " + Arrays.toString(expectedIds) + " but got " + describeIds(credentials)
            );
        }
        for (int index = 0; index < expectedIds.length; index++) {
            String actualId = credentials.get(index).getId();
            if (!expectedIds[index].equals(actualId)) {
                throw new AssertionError(
                        "Expected IDs " + Arrays.toString(expectedIds) + " but got " + describeIds(credentials)
                );
            }
        }
    }

    private static String describeIds(List<Credential> credentials) {
        String[] ids = new String[credentials.size()];
        for (int index = 0; index < credentials.size(); index++) {
            ids[index] = credentials.get(index).getId();
        }
        return Arrays.toString(ids);
    }
}
