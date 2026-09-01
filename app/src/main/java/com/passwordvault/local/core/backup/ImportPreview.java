package com.passwordvault.local.core.backup;

import com.passwordvault.local.core.model.VaultSnapshot;

public final class ImportPreview {
    private final Object owner;
    private final VaultSnapshot snapshot;
    private boolean active = true;

    ImportPreview(Object owner, VaultSnapshot snapshot) {
        this.owner = owner;
        this.snapshot = snapshot;
    }

    public int getCredentialCount() {
        return snapshot.getCredentials().size();
    }

    public int getCategoryCount() {
        return snapshot.getCategories().size();
    }

    public int getTagCount() {
        return snapshot.getTags().size();
    }

    VaultSnapshot consume(Object expectedOwner) {
        requireActive(expectedOwner);
        active = false;
        return snapshot;
    }

    void cancel(Object expectedOwner) {
        requireActive(expectedOwner);
        active = false;
    }

    void invalidate() {
        active = false;
    }

    boolean isActiveFor(Object expectedOwner) {
        return active && owner == expectedOwner;
    }

    private void requireActive(Object expectedOwner) {
        if (!isActiveFor(expectedOwner)) {
            throw new IllegalStateException("Import preview is no longer active");
        }
    }
}
