package com.passwordvault.local.ui;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.VaultService;

public final class TaxonomyController {
    private final VaultService service;

    public TaxonomyController(VaultService service) {
        if (service == null) {
            throw new IllegalArgumentException("service must not be null");
        }
        this.service = service;
    }

    public VaultSnapshot snapshot() {
        return service.getSnapshot();
    }

    public Category createCategory(String name) {
        return service.createCategory(name);
    }

    public Category renameCategory(String id, int expectedVersion, String name) {
        return service.renameCategory(id, expectedVersion, name);
    }

    public void deleteCategory(String id, int expectedVersion) {
        service.deleteCategory(id, expectedVersion);
    }

    public Tag createTag(String name) {
        return service.createTag(name);
    }

    public Tag renameTag(String id, int expectedVersion, String name) {
        return service.renameTag(id, expectedVersion, name);
    }

    public void deleteTag(String id, int expectedVersion) {
        service.deleteTag(id, expectedVersion);
    }

    public int categoryUsageCount(String categoryId) {
        int count = 0;
        for (Credential credential : snapshot().getCredentials()) {
            if (categoryId != null && categoryId.equals(credential.getCategoryId())) {
                count++;
            }
        }
        return count;
    }

    public int tagUsageCount(String tagId) {
        int count = 0;
        for (Credential credential : snapshot().getCredentials()) {
            if (tagId != null && credential.getTagIds().contains(tagId)) {
                count++;
            }
        }
        return count;
    }
}
