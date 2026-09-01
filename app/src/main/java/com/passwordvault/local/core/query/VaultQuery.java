package com.passwordvault.local.core.query;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public final class VaultQuery {
    public List<Credential> apply(VaultSnapshot snapshot, VaultFilter filter) {
        if (snapshot == null) {
            throw new IllegalArgumentException("snapshot must not be null");
        }
        if (filter == null) {
            throw new IllegalArgumentException("filter must not be null");
        }

        List<Credential> matches = new ArrayList<Credential>();
        String searchTerm = normalizeForSearch(filter.getSearchText());
        for (Credential credential : snapshot.getCredentials()) {
            if (!matchesCategory(credential, filter)) continue;
            if (!credential.getTagIds().containsAll(filter.getTagIds())) continue;
            if (!matchesSearch(credential, snapshot, searchTerm)) continue;
            matches.add(credential);
        }

        Collections.sort(matches, new Comparator<Credential>() {
            @Override
            public int compare(Credential left, Credential right) {
                int byName = left.getName().compareToIgnoreCase(right.getName());
                return byName != 0 ? byName : left.getId().compareTo(right.getId());
            }
        });
        return Collections.unmodifiableList(matches);
    }

    private static boolean matchesCategory(Credential credential, VaultFilter filter) {
        String requiredCategoryId = filter.getCategoryId();
        if (requiredCategoryId == null) return true;
        if (VaultFilter.UNCLASSIFIED_CATEGORY_ID.equals(requiredCategoryId)) {
            return credential.getCategoryId() == null;
        }
        return requiredCategoryId.equals(credential.getCategoryId());
    }

    private static boolean matchesSearch(
            Credential credential,
            VaultSnapshot snapshot,
            String searchTerm
    ) {
        if (searchTerm.isEmpty()) return true;
        if (contains(credential.getName(), searchTerm)) return true;
        if (contains(credential.getAccount(), searchTerm)) return true;
        if (contains(credential.getUrl(), searchTerm)) return true;

        Category category = credential.getCategoryId() == null
                ? null
                : snapshot.findCategory(credential.getCategoryId());
        if (category != null && contains(category.getName(), searchTerm)) return true;
        if (credential.getCategoryId() == null && contains("未分类", searchTerm)) return true;

        for (String tagId : credential.getTagIds()) {
            Tag tag = snapshot.findTag(tagId);
            if (tag != null && contains(tag.getName(), searchTerm)) return true;
        }
        return false;
    }

    private static boolean contains(String candidate, String normalizedSearchTerm) {
        return normalizeForSearch(candidate).contains(normalizedSearchTerm);
    }

    private static String normalizeForSearch(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
