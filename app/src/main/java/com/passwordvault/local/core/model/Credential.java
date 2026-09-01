package com.passwordvault.local.core.model;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

public final class Credential {
    private final String id;
    private final String name;
    private final String account;
    private final String password;
    private final String url;
    private final String categoryId;
    private final Set<String> tagIds;
    private final String notes;
    private final int version;
    private final long createdAtEpochMillis;
    private final long updatedAtEpochMillis;

    public Credential(
            String id,
            String name,
            String account,
            String password,
            String url,
            String categoryId,
            Set<String> tagIds,
            String notes,
            int version,
            long createdAtEpochMillis,
            long updatedAtEpochMillis
    ) {
        this.id = id;
        this.name = name;
        this.account = account;
        this.password = password;
        this.url = url;
        this.categoryId = categoryId;
        this.tagIds = Collections.unmodifiableSet(new LinkedHashSet<String>(tagIds));
        this.notes = notes;
        this.version = version;
        this.createdAtEpochMillis = createdAtEpochMillis;
        this.updatedAtEpochMillis = updatedAtEpochMillis;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getAccount() { return account; }
    public String getPassword() { return password; }
    public String getUrl() { return url; }
    public String getCategoryId() { return categoryId; }
    public Set<String> getTagIds() { return tagIds; }
    public String getNotes() { return notes; }
    public int getVersion() { return version; }
    public long getCreatedAtEpochMillis() { return createdAtEpochMillis; }
    public long getUpdatedAtEpochMillis() { return updatedAtEpochMillis; }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof Credential)) return false;
        Credential that = (Credential) other;
        return version == that.version
                && createdAtEpochMillis == that.createdAtEpochMillis
                && updatedAtEpochMillis == that.updatedAtEpochMillis
                && Objects.equals(id, that.id)
                && Objects.equals(name, that.name)
                && Objects.equals(account, that.account)
                && Objects.equals(password, that.password)
                && Objects.equals(url, that.url)
                && Objects.equals(categoryId, that.categoryId)
                && Objects.equals(tagIds, that.tagIds)
                && Objects.equals(notes, that.notes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, account, password, url, categoryId, tagIds, notes,
                version, createdAtEpochMillis, updatedAtEpochMillis);
    }
}
