package com.passwordvault.local.core.validation;

import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.VaultSnapshot;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

public final class VaultValidator {
    public CredentialDraft validateCredential(CredentialDraft draft, VaultSnapshot snapshot) {
        if (draft == null) {
            throw new ValidationException("记录不能为空");
        }
        if (snapshot == null) {
            throw new IllegalArgumentException("snapshot must not be null");
        }

        String name = trimToEmpty(draft.getName());
        if (name.isEmpty()) {
            throw new ValidationException("名称不能为空");
        }

        String password = valueOrEmpty(draft.getPassword());
        if (password.isEmpty()) {
            throw new ValidationException("密码不能为空");
        }

        String categoryId = trimToNull(draft.getCategoryId());
        if (categoryId != null && !snapshot.hasCategory(categoryId)) {
            throw new ValidationException("分类不存在");
        }

        Set<String> tagIds = new LinkedHashSet<String>();
        Set<String> sourceTagIds = draft.getTagIds() == null
                ? Collections.<String>emptySet()
                : draft.getTagIds();
        for (String sourceTagId : sourceTagIds) {
            String tagId = trimToEmpty(sourceTagId);
            if (!snapshot.hasTag(tagId)) {
                throw new ValidationException("标签不存在");
            }
            tagIds.add(tagId);
        }

        return new CredentialDraft(
                name,
                trimToEmpty(draft.getAccount()),
                password,
                trimToEmpty(draft.getUrl()),
                categoryId,
                tagIds,
                valueOrEmpty(draft.getNotes())
        );
    }

    public String normalizeTaxonomyName(String candidate, Collection<String> existingNames) {
        String normalized = trimToEmpty(candidate);
        if (normalized.isEmpty()) {
            throw new ValidationException("名称不能为空");
        }

        String comparisonName = normalized.toLowerCase(Locale.ROOT);
        Collection<String> names = existingNames == null
                ? Collections.<String>emptyList()
                : existingNames;
        for (String existingName : names) {
            if (trimToEmpty(existingName).toLowerCase(Locale.ROOT).equals(comparisonName)) {
                throw new ValidationException("名称已存在");
            }
        }
        return normalized;
    }

    private static String trimToNull(String value) {
        String trimmed = trimToEmpty(value);
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }
}
