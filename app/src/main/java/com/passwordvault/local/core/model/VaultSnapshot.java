package com.passwordvault.local.core.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class VaultSnapshot {
    public static final int CURRENT_SCHEMA_VERSION = 1;

    private final int schemaVersion;
    private final long revision;
    private final List<Credential> credentials;
    private final List<Category> categories;
    private final List<Tag> tags;

    public VaultSnapshot(
            int schemaVersion,
            long revision,
            List<Credential> credentials,
            List<Category> categories,
            List<Tag> tags
    ) {
        this.schemaVersion = schemaVersion;
        this.revision = revision;
        this.credentials = immutableCopy(credentials);
        this.categories = immutableCopy(categories);
        this.tags = immutableCopy(tags);
    }

    public static VaultSnapshot empty() {
        return new VaultSnapshot(
                CURRENT_SCHEMA_VERSION,
                0L,
                Collections.<Credential>emptyList(),
                Collections.<Category>emptyList(),
                Collections.<Tag>emptyList()
        );
    }

    public int getSchemaVersion() { return schemaVersion; }
    public long getRevision() { return revision; }
    public List<Credential> getCredentials() { return credentials; }
    public List<Category> getCategories() { return categories; }
    public List<Tag> getTags() { return tags; }

    public boolean hasCategory(String id) {
        for (Category category : categories) {
            if (category.getId().equals(id)) return true;
        }
        return false;
    }

    public boolean hasTag(String id) {
        for (Tag tag : tags) {
            if (tag.getId().equals(id)) return true;
        }
        return false;
    }

    public Category findCategory(String id) {
        for (Category category : categories) {
            if (category.getId().equals(id)) return category;
        }
        return null;
    }

    public Tag findTag(String id) {
        for (Tag tag : tags) {
            if (tag.getId().equals(id)) return tag;
        }
        return null;
    }

    private static <T> List<T> immutableCopy(List<T> values) {
        return Collections.unmodifiableList(new ArrayList<T>(
                values == null ? Collections.<T>emptyList() : values
        ));
    }
}
