package com.passwordvault.local.core.backup;

import com.passwordvault.local.core.codec.CodecException;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;
import com.passwordvault.local.core.validation.VaultValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class BackupService {
    private final VaultService vaultService;
    private final VaultBinaryCodec codec;
    private final BackupPayloadCrypto crypto;
    private final Object owner = new Object();
    private ImportPreview activePreview;

    public BackupService(
            VaultService vaultService,
            VaultBinaryCodec codec,
            BackupPayloadCrypto crypto
    ) {
        if (vaultService == null || codec == null || crypto == null) {
            throw new IllegalArgumentException("BackupService dependencies must not be null");
        }
        this.vaultService = vaultService;
        this.codec = codec;
        this.crypto = crypto;
    }

    public byte[] exportAll(VaultSnapshot snapshot, char[] password) {
        byte[] plaintext = codec.encode(snapshot);
        try {
            return crypto.encrypt(plaintext, password);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    public synchronized ImportPreview previewImport(byte[] backup, char[] password) {
        byte[] plaintext = crypto.decrypt(backup, password);
        VaultSnapshot snapshot;
        try {
            snapshot = codec.decode(plaintext);
            validateSnapshot(snapshot);
        } catch (CodecException | ValidationException exception) {
            throw new CorruptBackupException("Backup contains invalid vault data", exception);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }

        if (activePreview != null) activePreview.invalidate();
        activePreview = new ImportPreview(owner, snapshot);
        return activePreview;
    }

    public synchronized void applyImport(ImportPreview preview) {
        requireCurrentPreview(preview);
        VaultSnapshot snapshot = preview.consume(owner);
        activePreview = null;
        vaultService.replaceAll(snapshot);
    }

    public synchronized void cancelImport(ImportPreview preview) {
        requireCurrentPreview(preview);
        preview.cancel(owner);
        activePreview = null;
    }

    private void requireCurrentPreview(ImportPreview preview) {
        if (preview == null || preview != activePreview || !preview.isActiveFor(owner)) {
            throw new IllegalStateException("Import preview is no longer active");
        }
    }

    private static void validateSnapshot(VaultSnapshot snapshot) {
        if (snapshot.getSchemaVersion() != VaultSnapshot.CURRENT_SCHEMA_VERSION) {
            throw new CorruptBackupException("Backup uses an unsupported vault schema");
        }

        VaultValidator validator = new VaultValidator();
        Set<String> categoryIds = new HashSet<String>();
        List<String> categoryNames = new ArrayList<String>();
        for (Category category : snapshot.getCategories()) {
            requireIdentity("category", category.getId(), category.getVersion(), categoryIds);
            String normalized = validator.normalizeTaxonomyName(category.getName(), categoryNames);
            if (!normalized.equals(category.getName())) {
                throw new CorruptBackupException("Backup contains a non-normalized category");
            }
            categoryNames.add(category.getName());
        }

        Set<String> tagIds = new HashSet<String>();
        List<String> tagNames = new ArrayList<String>();
        for (Tag tag : snapshot.getTags()) {
            requireIdentity("tag", tag.getId(), tag.getVersion(), tagIds);
            String normalized = validator.normalizeTaxonomyName(tag.getName(), tagNames);
            if (!normalized.equals(tag.getName())) {
                throw new CorruptBackupException("Backup contains a non-normalized tag");
            }
            tagNames.add(tag.getName());
        }

        Set<String> credentialIds = new HashSet<String>();
        for (Credential credential : snapshot.getCredentials()) {
            requireIdentity("credential", credential.getId(), credential.getVersion(), credentialIds);
            if (credential.getCreatedAtEpochMillis() < 0
                    || credential.getUpdatedAtEpochMillis() < credential.getCreatedAtEpochMillis()) {
                throw new CorruptBackupException("Backup contains invalid credential timestamps");
            }
            CredentialDraft draft = new CredentialDraft(
                    credential.getName(),
                    credential.getAccount(),
                    credential.getPassword(),
                    credential.getUrl(),
                    credential.getCategoryId(),
                    credential.getTagIds(),
                    credential.getNotes()
            );
            CredentialDraft normalized = validator.validateCredential(draft, snapshot);
            if (!sameDraft(draft, normalized)) {
                throw new CorruptBackupException("Backup contains a non-normalized credential");
            }
        }
    }

    private static void requireIdentity(
            String entityName,
            String id,
            int version,
            Set<String> existingIds
    ) {
        if (id == null || id.trim().isEmpty() || version < 1 || !existingIds.add(id)) {
            throw new CorruptBackupException("Backup contains an invalid " + entityName);
        }
    }

    private static boolean sameDraft(CredentialDraft left, CredentialDraft right) {
        return equal(left.getName(), right.getName())
                && equal(left.getAccount(), right.getAccount())
                && equal(left.getPassword(), right.getPassword())
                && equal(left.getUrl(), right.getUrl())
                && equal(left.getCategoryId(), right.getCategoryId())
                && equal(left.getTagIds(), right.getTagIds())
                && equal(left.getNotes(), right.getNotes());
    }

    private static boolean equal(Object left, Object right) {
        return left == null ? right == null : left.equals(right);
    }
}
