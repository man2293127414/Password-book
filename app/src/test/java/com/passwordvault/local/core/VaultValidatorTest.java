package com.passwordvault.local.core;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.core.validation.VaultValidator;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;

final class VaultValidatorTest {
    private final VaultValidator validator = new VaultValidator();

    static void run() {
        VaultValidatorTest test = new VaultValidatorTest();
        test.rejectsBlankCredentialName();
        test.rejectsEmptyPassword();
        test.normalizesNonSecretTextWithoutChangingPasswordOrNotes();
        test.rejectsMissingCategory();
        test.rejectsMissingTag();
        test.acceptsExistingCategoryAndTags();
        test.normalizesTaxonomyName();
        test.rejectsCaseInsensitiveDuplicateTaxonomyName();
        test.rejectsBlankTaxonomyName();
        System.out.println("PASS VaultValidatorTest");
    }

    private void rejectsBlankCredentialName() {
        expectValidation("名称不能为空", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.validateCredential(draft("   ", "secret"), VaultSnapshot.empty());
            }
        });
    }

    private void rejectsEmptyPassword() {
        expectValidation("密码不能为空", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.validateCredential(draft("GitHub", ""), VaultSnapshot.empty());
            }
        });
    }

    private void normalizesNonSecretTextWithoutChangingPasswordOrNotes() {
        CredentialDraft input = new CredentialDraft(
                "  GitHub  ",
                "  octocat@example.com  ",
                "  keep spaces  ",
                "  https://github.com  ",
                null,
                Collections.<String>emptySet(),
                "  private note  "
        );

        CredentialDraft actual = validator.validateCredential(input, VaultSnapshot.empty());

        assertEquals("GitHub", actual.getName());
        assertEquals("octocat@example.com", actual.getAccount());
        assertEquals("  keep spaces  ", actual.getPassword());
        assertEquals("https://github.com", actual.getUrl());
        assertEquals("  private note  ", actual.getNotes());
    }

    private void rejectsMissingCategory() {
        final CredentialDraft input = new CredentialDraft(
                "GitHub", "octocat", "secret", "", "missing",
                Collections.<String>emptySet(), ""
        );

        expectValidation("分类不存在", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.validateCredential(input, VaultSnapshot.empty());
            }
        });
    }

    private void rejectsMissingTag() {
        final CredentialDraft input = new CredentialDraft(
                "GitHub", "octocat", "secret", "", null,
                new LinkedHashSet<String>(Collections.singletonList("missing")), ""
        );

        expectValidation("标签不存在", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.validateCredential(input, VaultSnapshot.empty());
            }
        });
    }

    private void acceptsExistingCategoryAndTags() {
        VaultSnapshot snapshot = new VaultSnapshot(
                1,
                3L,
                Collections.emptyList(),
                Collections.singletonList(new Category("cat-work", "工作", 1)),
                Arrays.asList(new Tag("tag-important", "重要", 1), new Tag("tag-shared", "共享", 1))
        );
        CredentialDraft input = new CredentialDraft(
                "GitHub", "octocat", "secret", "https://github.com", "cat-work",
                new LinkedHashSet<String>(Arrays.asList("tag-important", "tag-shared")), ""
        );

        CredentialDraft actual = validator.validateCredential(input, snapshot);

        assertEquals("cat-work", actual.getCategoryId());
        assertEquals(new LinkedHashSet<String>(Arrays.asList("tag-important", "tag-shared")), actual.getTagIds());
    }

    private void normalizesTaxonomyName() {
        assertEquals(
                "工作",
                validator.normalizeTaxonomyName("  工作  ", Collections.singletonList("生活"))
        );
    }

    private void rejectsCaseInsensitiveDuplicateTaxonomyName() {
        expectValidation("名称已存在", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.normalizeTaxonomyName("WORK", Collections.singletonList("work"));
            }
        });
    }

    private void rejectsBlankTaxonomyName() {
        expectValidation("名称不能为空", new ThrowingRunnable() {
            @Override
            public void run() {
                validator.normalizeTaxonomyName("  ", Collections.<String>emptyList());
            }
        });
    }

    private static CredentialDraft draft(String name, String password) {
        return new CredentialDraft(
                name,
                "",
                password,
                "",
                null,
                Collections.<String>emptySet(),
                ""
        );
    }

    private static void expectValidation(String expectedMessage, ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected ValidationException: " + expectedMessage);
        } catch (ValidationException exception) {
            assertEquals(expectedMessage, exception.getMessage());
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
}
