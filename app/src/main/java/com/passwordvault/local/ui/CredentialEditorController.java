package com.passwordvault.local.ui;

import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.repository.VaultService;

public final class CredentialEditorController {
    private final VaultService service;

    public CredentialEditorController(VaultService service) {
        if (service == null) {
            throw new IllegalArgumentException("service must not be null");
        }
        this.service = service;
    }

    public Credential create(CredentialDraft draft) {
        return service.createCredential(draft);
    }

    public Credential update(Credential existing, CredentialDraft draft) {
        if (existing == null) {
            throw new IllegalArgumentException("existing credential must not be null");
        }
        return service.updateCredential(existing.getId(), existing.getVersion(), draft);
    }
}
