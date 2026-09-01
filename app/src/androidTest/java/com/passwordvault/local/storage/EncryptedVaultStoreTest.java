package com.passwordvault.local.storage;

import android.database.DatabaseUtils;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.passwordvault.local.VaultTestReset;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public final class EncryptedVaultStoreTest {
    private static final String ACCOUNT = "plain-account@example.test";
    private static final String PASSWORD = "plain-password-4871";
    private static final String NOTES = "plain-notes-must-never-reach-sqlite";

    @Before
    public void setUp() {
        VaultTestReset.closeApplicationVault(ApplicationProvider.getApplicationContext());
        ApplicationProvider.getApplicationContext().deleteDatabase(VaultDatabase.DATABASE_NAME);
    }

    @After
    public void tearDown() {
        VaultTestReset.closeApplicationVault(ApplicationProvider.getApplicationContext());
        ApplicationProvider.getApplicationContext().deleteDatabase(VaultDatabase.DATABASE_NAME);
    }

    @Test
    public void emptyDatabaseReturnsEmptySnapshot() {
        EncryptedVaultStore store = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            VaultSnapshot snapshot = store.read();

            assertEquals(0L, snapshot.getRevision());
            assertTrue(snapshot.getCredentials().isEmpty());
            assertTrue(snapshot.getCategories().isEmpty());
            assertTrue(snapshot.getTags().isEmpty());
        } finally {
            store.close();
        }
    }

    @Test
    public void snapshotSurvivesStoreReopen() {
        VaultSnapshot expected = sampleSnapshot();

        EncryptedVaultStore writer = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            writer.replace(expected);
        } finally {
            writer.close();
        }

        EncryptedVaultStore reader = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            VaultSnapshot actual = reader.read();

            assertEquals(expected.getSchemaVersion(), actual.getSchemaVersion());
            assertEquals(expected.getRevision(), actual.getRevision());
            assertEquals(expected.getCredentials(), actual.getCredentials());
            assertEquals(expected.getCategories(), actual.getCategories());
            assertEquals(expected.getTags(), actual.getTags());
        } finally {
            reader.close();
        }
    }

    @Test
    public void replacementKeepsOnlyLatestSnapshot() {
        VaultSnapshot first = sampleSnapshot();
        VaultSnapshot second = new VaultSnapshot(
                first.getSchemaVersion(),
                first.getRevision() + 1L,
                first.getCredentials(),
                first.getCategories(),
                first.getTags()
        );

        EncryptedVaultStore store = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            store.replace(first);
            store.replace(second);
            assertEquals(second.getRevision(), store.read().getRevision());
        } finally {
            store.close();
        }

        VaultDatabase database = new VaultDatabase(ApplicationProvider.getApplicationContext());
        try {
            assertEquals(
                    1L,
                    DatabaseUtils.queryNumEntries(
                            database.getReadableDatabase(),
                            VaultDatabase.TABLE_NAME
                    )
            );
        } finally {
            database.close();
        }
    }

    @Test
    public void databaseContainsNoCredentialPlaintext() throws Exception {
        EncryptedVaultStore store = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            store.replace(sampleSnapshot());
        } finally {
            store.close();
        }

        File database = ApplicationProvider.getApplicationContext()
                .getDatabasePath(VaultDatabase.DATABASE_NAME);
        assertTrue(database.isFile());
        File[] files = database.getParentFile().listFiles();
        assertNotNull(files);
        for (File file : files) {
            if (!file.getName().startsWith(VaultDatabase.DATABASE_NAME)) {
                continue;
            }
            byte[] bytes = readAllBytes(file);
            assertFalse(contains(bytes, ACCOUNT.getBytes(StandardCharsets.UTF_8)));
            assertFalse(contains(bytes, PASSWORD.getBytes(StandardCharsets.UTF_8)));
            assertFalse(contains(bytes, NOTES.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    public void tamperedCiphertextIsRejected() {
        EncryptedVaultStore store = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            store.replace(sampleSnapshot());
        } finally {
            store.close();
        }

        VaultDatabase database = new VaultDatabase(ApplicationProvider.getApplicationContext());
        try {
            EncryptedPayload original = database.read();
            byte[] tampered = original.getCiphertext();
            tampered[0] ^= 0x01;
            database.replace(new EncryptedPayload(original.getNonce(), tampered));
        } finally {
            database.close();
        }

        EncryptedVaultStore reader = new EncryptedVaultStore(ApplicationProvider.getApplicationContext());
        try {
            try {
                reader.read();
                fail("Expected authentication failure for tampered ciphertext");
            } catch (CryptoException expected) {
                assertNotNull(expected.getCause());
            }
        } finally {
            reader.close();
        }
    }

    private static VaultSnapshot sampleSnapshot() {
        Category category = new Category("category-1", "工作", 1);
        Tag tag = new Tag("tag-1", "重要", 1);
        Credential credential = new Credential(
                "credential-1",
                "Example",
                ACCOUNT,
                PASSWORD,
                "https://example.test",
                category.getId(),
                new LinkedHashSet<String>(Arrays.asList(tag.getId())),
                NOTES,
                1,
                1_700_000_000_000L,
                1_700_000_001_000L
        );
        return new VaultSnapshot(
                VaultSnapshot.CURRENT_SCHEMA_VERSION,
                7L,
                Arrays.asList(credential),
                Arrays.asList(category),
                Arrays.asList(tag)
        );
    }

    private static byte[] readAllBytes(File file) throws IOException {
        FileInputStream input = new FileInputStream(file);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            int index = 0;
            while (index < needle.length && haystack[offset + index] == needle[index]) {
                index++;
            }
            if (index == needle.length) {
                return true;
            }
        }
        return false;
    }
}
