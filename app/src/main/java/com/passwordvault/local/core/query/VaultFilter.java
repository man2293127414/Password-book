package com.passwordvault.local.core.query;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class VaultFilter {
    public static final String UNCLASSIFIED_CATEGORY_ID = "pvl:unclassified";

    private final String searchText;
    private final String categoryId;
    private final Set<String> tagIds;

    public VaultFilter(String searchText, String categoryId, Set<String> tagIds) {
        this.searchText = trimToEmpty(searchText);
        this.categoryId = trimToNull(categoryId);

        LinkedHashSet<String> normalizedTagIds = new LinkedHashSet<String>();
        if (tagIds != null) {
            for (String tagId : tagIds) {
                String normalizedTagId = trimToEmpty(tagId);
                if (!normalizedTagId.isEmpty()) {
                    normalizedTagIds.add(normalizedTagId);
                }
            }
        }
        this.tagIds = Collections.unmodifiableSet(normalizedTagIds);
    }

    public String getSearchText() {
        return searchText;
    }

    public String getCategoryId() {
        return categoryId;
    }

    public Set<String> getTagIds() {
        return tagIds;
    }

    private static String trimToNull(String value) {
        String normalized = trimToEmpty(value);
        return normalized.isEmpty() ? null : normalized;
    }

    private static String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
