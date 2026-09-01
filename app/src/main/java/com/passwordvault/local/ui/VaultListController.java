package com.passwordvault.local.ui;

import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.query.VaultFilter;
import com.passwordvault.local.core.query.VaultQuery;
import com.passwordvault.local.core.repository.NotFoundException;
import com.passwordvault.local.core.repository.VaultService;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class VaultListController {
    public static final String MASKED_PASSWORD = "••••••••";

    private final VaultService service;
    private final VaultQuery query;

    private String searchText = "";
    private String categoryId;
    private Set<String> tagIds = Collections.emptySet();
    private String revealedCredentialId;

    public VaultListController(VaultService service, VaultQuery query) {
        if (service == null || query == null) {
            throw new IllegalArgumentException("VaultListController dependencies must not be null");
        }
        this.service = service;
        this.query = query;
    }

    public VaultSnapshot snapshot() {
        VaultSnapshot snapshot = service.getSnapshot();
        reconcileFilters(snapshot);
        return snapshot;
    }

    public List<Credential> visibleCredentials() {
        return query.apply(snapshot(), new VaultFilter(searchText, categoryId, tagIds));
    }

    public Credential findCredential(String id) {
        for (Credential credential : snapshot().getCredentials()) {
            if (credential.getId().equals(id)) {
                return credential;
            }
        }
        throw new NotFoundException("credential", id);
    }

    public String getSearchText() {
        return searchText;
    }

    public void setSearchText(String searchText) {
        this.searchText = searchText == null ? "" : searchText;
        concealPasswords();
    }

    public String getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(String categoryId) {
        String normalized = categoryId == null ? "" : categoryId.trim();
        this.categoryId = normalized.isEmpty() ? null : normalized;
        concealPasswords();
    }

    public Set<String> getTagIds() {
        return tagIds;
    }

    public void setTagIds(Set<String> tagIds) {
        LinkedHashSet<String> copy = new LinkedHashSet<String>();
        if (tagIds != null) {
            for (String tagId : tagIds) {
                if (tagId != null && !tagId.trim().isEmpty()) {
                    copy.add(tagId.trim());
                }
            }
        }
        this.tagIds = Collections.unmodifiableSet(copy);
        concealPasswords();
    }

    public void togglePassword(String credentialId) {
        Credential credential = findCredential(credentialId);
        revealedCredentialId = credential.getId().equals(revealedCredentialId)
                ? null
                : credential.getId();
    }

    public boolean isPasswordRevealed(String credentialId) {
        return credentialId != null && credentialId.equals(revealedCredentialId);
    }

    public String passwordText(Credential credential) {
        if (credential == null) {
            throw new IllegalArgumentException("credential must not be null");
        }
        return isPasswordRevealed(credential.getId())
                ? credential.getPassword()
                : MASKED_PASSWORD;
    }

    public void concealPasswords() {
        revealedCredentialId = null;
    }

    public void onStop() {
        concealPasswords();
    }

    public void deleteCredential(String id, int expectedVersion) {
        service.deleteCredential(id, expectedVersion);
        if (id != null && id.equals(revealedCredentialId)) {
            concealPasswords();
        }
    }

    public void clearAll() {
        service.clearAll();
        searchText = "";
        categoryId = null;
        tagIds = Collections.emptySet();
        concealPasswords();
    }

    private void reconcileFilters(VaultSnapshot snapshot) {
        boolean changed = false;
        if (categoryId != null
                && !VaultFilter.UNCLASSIFIED_CATEGORY_ID.equals(categoryId)
                && !snapshot.hasCategory(categoryId)) {
            categoryId = null;
            changed = true;
        }

        LinkedHashSet<String> existingTagIds = new LinkedHashSet<String>();
        for (String tagId : tagIds) {
            if (snapshot.hasTag(tagId)) {
                existingTagIds.add(tagId);
            }
        }
        if (existingTagIds.size() != tagIds.size()) {
            tagIds = Collections.unmodifiableSet(existingTagIds);
            changed = true;
        }
        if (changed) {
            concealPasswords();
        }
    }
}
