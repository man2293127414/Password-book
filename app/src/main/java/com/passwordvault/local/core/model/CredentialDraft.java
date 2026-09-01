package com.passwordvault.local.core.model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class CredentialDraft {
    private final String name;
    private final String account;
    private final String password;
    private final String url;
    private final String categoryId;
    private final Set<String> tagIds;
    private final String notes;

    public CredentialDraft(
            String name,
            String account,
            String password,
            String url,
            String categoryId,
            Set<String> tagIds,
            String notes
    ) {
        this.name = name;
        this.account = account;
        this.password = password;
        this.url = url;
        this.categoryId = categoryId;
        this.tagIds = Collections.unmodifiableSet(new LinkedHashSet<String>(
                tagIds == null ? Collections.<String>emptySet() : tagIds
        ));
        this.notes = notes;
    }

    public String getName() {
        return name;
    }

    public String getAccount() {
        return account;
    }

    public String getPassword() {
        return password;
    }

    public String getUrl() {
        return url;
    }

    public String getCategoryId() {
        return categoryId;
    }

    public Set<String> getTagIds() {
        return tagIds;
    }

    public String getNotes() {
        return notes;
    }
}
