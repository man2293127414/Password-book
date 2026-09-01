package com.passwordvault.local.core.repository;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.CredentialDraft;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.validation.VaultValidator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

public final class VaultService {
    private final VaultStore store;
    private final VaultValidator validator;
    private final Supplier<String> idSupplier;
    private final LongSupplier clock;

    public VaultService(
            VaultStore store,
            VaultValidator validator,
            Supplier<String> idSupplier,
            LongSupplier clock
    ) {
        if (store == null || validator == null || idSupplier == null || clock == null) {
            throw new IllegalArgumentException("VaultService dependencies must not be null");
        }
        this.store = store;
        this.validator = validator;
        this.idSupplier = idSupplier;
        this.clock = clock;
    }

    public synchronized VaultSnapshot getSnapshot() {
        return store.read();
    }

    public synchronized Credential createCredential(CredentialDraft draft) {
        VaultSnapshot current = store.read();
        CredentialDraft normalized = validator.validateCredential(draft, current);
        long now = clock.getAsLong();
        Credential created = new Credential(
                nextId(),
                normalized.getName(),
                normalized.getAccount(),
                normalized.getPassword(),
                normalized.getUrl(),
                normalized.getCategoryId(),
                normalized.getTagIds(),
                normalized.getNotes(),
                1,
                now,
                now
        );
        List<Credential> credentials = new ArrayList<Credential>(current.getCredentials());
        credentials.add(created);
        store.replace(nextSnapshot(current, credentials, current.getCategories(), current.getTags()));
        return created;
    }

    public synchronized Credential updateCredential(
            String id,
            int expectedVersion,
            CredentialDraft draft
    ) {
        VaultSnapshot current = store.read();
        int index = findCredentialIndex(current.getCredentials(), id);
        Credential existing = current.getCredentials().get(index);
        requireVersion("credential", id, expectedVersion, existing.getVersion());
        CredentialDraft normalized = validator.validateCredential(draft, current);
        Credential updated = new Credential(
                existing.getId(),
                normalized.getName(),
                normalized.getAccount(),
                normalized.getPassword(),
                normalized.getUrl(),
                normalized.getCategoryId(),
                normalized.getTagIds(),
                normalized.getNotes(),
                existing.getVersion() + 1,
                existing.getCreatedAtEpochMillis(),
                clock.getAsLong()
        );
        List<Credential> credentials = new ArrayList<Credential>(current.getCredentials());
        credentials.set(index, updated);
        store.replace(nextSnapshot(current, credentials, current.getCategories(), current.getTags()));
        return updated;
    }

    public synchronized void deleteCredential(String id, int expectedVersion) {
        VaultSnapshot current = store.read();
        int index = findCredentialIndex(current.getCredentials(), id);
        Credential existing = current.getCredentials().get(index);
        requireVersion("credential", id, expectedVersion, existing.getVersion());
        List<Credential> credentials = new ArrayList<Credential>(current.getCredentials());
        credentials.remove(index);
        store.replace(nextSnapshot(current, credentials, current.getCategories(), current.getTags()));
    }

    public synchronized Category createCategory(String name) {
        VaultSnapshot current = store.read();
        String normalized = validator.normalizeTaxonomyName(name, categoryNames(current.getCategories(), null));
        Category created = new Category(nextId(), normalized, 1);
        List<Category> categories = new ArrayList<Category>(current.getCategories());
        categories.add(created);
        store.replace(nextSnapshot(current, current.getCredentials(), categories, current.getTags()));
        return created;
    }

    public synchronized Category renameCategory(String id, int expectedVersion, String name) {
        VaultSnapshot current = store.read();
        int index = findCategoryIndex(current.getCategories(), id);
        Category existing = current.getCategories().get(index);
        requireVersion("category", id, expectedVersion, existing.getVersion());
        String normalized = validator.normalizeTaxonomyName(name, categoryNames(current.getCategories(), id));
        Category renamed = new Category(existing.getId(), normalized, existing.getVersion() + 1);
        List<Category> categories = new ArrayList<Category>(current.getCategories());
        categories.set(index, renamed);
        store.replace(nextSnapshot(current, current.getCredentials(), categories, current.getTags()));
        return renamed;
    }

    public synchronized void deleteCategory(String id, int expectedVersion) {
        VaultSnapshot current = store.read();
        int categoryIndex = findCategoryIndex(current.getCategories(), id);
        Category existing = current.getCategories().get(categoryIndex);
        requireVersion("category", id, expectedVersion, existing.getVersion());

        List<Category> categories = new ArrayList<Category>(current.getCategories());
        categories.remove(categoryIndex);
        List<Credential> credentials = new ArrayList<Credential>(current.getCredentials().size());
        Long changedAt = null;
        for (Credential credential : current.getCredentials()) {
            if (id.equals(credential.getCategoryId())) {
                if (changedAt == null) changedAt = clock.getAsLong();
                credentials.add(copyCredential(
                        credential,
                        null,
                        credential.getTagIds(),
                        credential.getVersion() + 1,
                        changedAt.longValue()
                ));
            } else {
                credentials.add(credential);
            }
        }
        store.replace(nextSnapshot(current, credentials, categories, current.getTags()));
    }

    public synchronized Tag createTag(String name) {
        VaultSnapshot current = store.read();
        String normalized = validator.normalizeTaxonomyName(name, tagNames(current.getTags(), null));
        Tag created = new Tag(nextId(), normalized, 1);
        List<Tag> tags = new ArrayList<Tag>(current.getTags());
        tags.add(created);
        store.replace(nextSnapshot(current, current.getCredentials(), current.getCategories(), tags));
        return created;
    }

    public synchronized Tag renameTag(String id, int expectedVersion, String name) {
        VaultSnapshot current = store.read();
        int index = findTagIndex(current.getTags(), id);
        Tag existing = current.getTags().get(index);
        requireVersion("tag", id, expectedVersion, existing.getVersion());
        String normalized = validator.normalizeTaxonomyName(name, tagNames(current.getTags(), id));
        Tag renamed = new Tag(existing.getId(), normalized, existing.getVersion() + 1);
        List<Tag> tags = new ArrayList<Tag>(current.getTags());
        tags.set(index, renamed);
        store.replace(nextSnapshot(current, current.getCredentials(), current.getCategories(), tags));
        return renamed;
    }

    public synchronized void deleteTag(String id, int expectedVersion) {
        VaultSnapshot current = store.read();
        int tagIndex = findTagIndex(current.getTags(), id);
        Tag existing = current.getTags().get(tagIndex);
        requireVersion("tag", id, expectedVersion, existing.getVersion());

        List<Tag> tags = new ArrayList<Tag>(current.getTags());
        tags.remove(tagIndex);
        List<Credential> credentials = new ArrayList<Credential>(current.getCredentials().size());
        Long changedAt = null;
        for (Credential credential : current.getCredentials()) {
            if (credential.getTagIds().contains(id)) {
                if (changedAt == null) changedAt = clock.getAsLong();
                Set<String> remainingTagIds = new LinkedHashSet<String>(credential.getTagIds());
                remainingTagIds.remove(id);
                credentials.add(copyCredential(
                        credential,
                        credential.getCategoryId(),
                        remainingTagIds,
                        credential.getVersion() + 1,
                        changedAt.longValue()
                ));
            } else {
                credentials.add(credential);
            }
        }
        store.replace(nextSnapshot(current, credentials, current.getCategories(), tags));
    }

    public synchronized void clearAll() {
        VaultSnapshot current = store.read();
        store.replace(new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                current.getRevision() + 1,
                Collections.<Credential>emptyList(),
                Collections.<Category>emptyList(),
                Collections.<Tag>emptyList()
        ));
    }

    public synchronized void replaceAll(VaultSnapshot replacement) {
        if (replacement == null) {
            throw new IllegalArgumentException("replacement must not be null");
        }
        VaultSnapshot current = store.read();
        store.replace(new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                current.getRevision() + 1,
                replacement.getCredentials(),
                replacement.getCategories(),
                replacement.getTags()
        ));
    }

    private String nextId() {
        String id = idSupplier.get();
        if (id == null || id.trim().isEmpty()) {
            throw new IllegalStateException("Generated ID must not be blank");
        }
        return id;
    }

    private static VaultSnapshot nextSnapshot(
            VaultSnapshot current,
            List<Credential> credentials,
            List<Category> categories,
            List<Tag> tags
    ) {
        return new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                current.getRevision() + 1,
                credentials,
                categories,
                tags
        );
    }

    private static Credential copyCredential(
            Credential source,
            String categoryId,
            Set<String> tagIds,
            int version,
            long updatedAt
    ) {
        return new Credential(
                source.getId(),
                source.getName(),
                source.getAccount(),
                source.getPassword(),
                source.getUrl(),
                categoryId,
                tagIds,
                source.getNotes(),
                version,
                source.getCreatedAtEpochMillis(),
                updatedAt
        );
    }

    private static int findCredentialIndex(List<Credential> credentials, String id) {
        for (int index = 0; index < credentials.size(); index++) {
            if (credentials.get(index).getId().equals(id)) return index;
        }
        throw new NotFoundException("credential", id);
    }

    private static int findCategoryIndex(List<Category> categories, String id) {
        for (int index = 0; index < categories.size(); index++) {
            if (categories.get(index).getId().equals(id)) return index;
        }
        throw new NotFoundException("category", id);
    }

    private static int findTagIndex(List<Tag> tags, String id) {
        for (int index = 0; index < tags.size(); index++) {
            if (tags.get(index).getId().equals(id)) return index;
        }
        throw new NotFoundException("tag", id);
    }

    private static void requireVersion(
            String entityType,
            String id,
            int expectedVersion,
            int actualVersion
    ) {
        if (expectedVersion != actualVersion) {
            throw new ConflictException(entityType, id, expectedVersion, actualVersion);
        }
    }

    private static Collection<String> categoryNames(List<Category> categories, String excludedId) {
        List<String> names = new ArrayList<String>();
        for (Category category : categories) {
            if (!category.getId().equals(excludedId)) names.add(category.getName());
        }
        return names;
    }

    private static Collection<String> tagNames(List<Tag> tags, String excludedId) {
        List<String> names = new ArrayList<String>();
        for (Tag tag : tags) {
            if (!tag.getId().equals(excludedId)) names.add(tag.getName());
        }
        return names;
    }
}
