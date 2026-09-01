package com.passwordvault.local.core.codec;

import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class VaultBinaryCodec {
    private static final int MAGIC = 0x50564C54;
    private static final int FORMAT_VERSION = 1;
    private static final int MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;
    private static final int MAX_STRING_BYTES = 1024 * 1024;
    private static final int MAX_ENTITY_COUNT = 100_000;

    public byte[] encode(VaultSnapshot snapshot) {
        if (snapshot == null) {
            throw new IllegalArgumentException("snapshot must not be null");
        }

        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(snapshot.getSchemaVersion());
            output.writeLong(snapshot.getRevision());

            writeCount(output, snapshot.getCategories().size());
            for (Category category : snapshot.getCategories()) {
                writeString(output, category.getId());
                writeString(output, category.getName());
                output.writeInt(category.getVersion());
            }

            writeCount(output, snapshot.getTags().size());
            for (Tag tag : snapshot.getTags()) {
                writeString(output, tag.getId());
                writeString(output, tag.getName());
                output.writeInt(tag.getVersion());
            }

            writeCount(output, snapshot.getCredentials().size());
            for (Credential credential : snapshot.getCredentials()) {
                writeString(output, credential.getId());
                writeString(output, credential.getName());
                writeString(output, credential.getAccount());
                writeString(output, credential.getPassword());
                writeString(output, credential.getUrl());
                output.writeBoolean(credential.getCategoryId() != null);
                if (credential.getCategoryId() != null) {
                    writeString(output, credential.getCategoryId());
                }
                writeCount(output, credential.getTagIds().size());
                for (String tagId : credential.getTagIds()) {
                    writeString(output, tagId);
                }
                writeString(output, credential.getNotes());
                output.writeInt(credential.getVersion());
                output.writeLong(credential.getCreatedAtEpochMillis());
                output.writeLong(credential.getUpdatedAtEpochMillis());
            }
            output.flush();
            byte[] encoded = bytes.toByteArray();
            if (encoded.length > MAX_PAYLOAD_BYTES) {
                throw new CodecException("Vault payload is too large");
            }
            return encoded;
        } catch (IOException exception) {
            throw new CodecException("Unable to encode vault", exception);
        }
    }

    public VaultSnapshot decode(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new CodecException("Vault payload is empty");
        }
        if (encoded.length > MAX_PAYLOAD_BYTES) {
            throw new CodecException("Vault payload is too large");
        }

        try {
            ByteArrayInputStream bytes = new ByteArrayInputStream(encoded);
            DataInputStream input = new DataInputStream(bytes);
            if (input.readInt() != MAGIC) {
                throw new CodecException("Invalid vault payload magic");
            }
            int formatVersion = input.readInt();
            if (formatVersion != FORMAT_VERSION) {
                throw new CodecException("Unsupported vault payload version: " + formatVersion);
            }
            int schemaVersion = input.readInt();
            long revision = input.readLong();

            int categoryCount = readCount(input, "category");
            List<Category> categories = new ArrayList<Category>(categoryCount);
            for (int index = 0; index < categoryCount; index++) {
                categories.add(new Category(
                        readString(input),
                        readString(input),
                        input.readInt()
                ));
            }

            int tagCount = readCount(input, "tag");
            List<Tag> tags = new ArrayList<Tag>(tagCount);
            for (int index = 0; index < tagCount; index++) {
                tags.add(new Tag(
                        readString(input),
                        readString(input),
                        input.readInt()
                ));
            }

            int credentialCount = readCount(input, "credential");
            List<Credential> credentials = new ArrayList<Credential>(credentialCount);
            for (int index = 0; index < credentialCount; index++) {
                String id = readString(input);
                String name = readString(input);
                String account = readString(input);
                String password = readString(input);
                String url = readString(input);
                String categoryId = input.readBoolean() ? readString(input) : null;
                int tagIdCount = readCount(input, "credential tag");
                Set<String> tagIds = new LinkedHashSet<String>();
                for (int tagIndex = 0; tagIndex < tagIdCount; tagIndex++) {
                    tagIds.add(readString(input));
                }
                String notes = readString(input);
                int version = input.readInt();
                long createdAt = input.readLong();
                long updatedAt = input.readLong();
                credentials.add(new Credential(
                        id,
                        name,
                        account,
                        password,
                        url,
                        categoryId,
                        tagIds,
                        notes,
                        version,
                        createdAt,
                        updatedAt
                ));
            }

            if (bytes.available() != 0) {
                throw new CodecException("Vault payload contains trailing data");
            }
            return new VaultSnapshot(schemaVersion, revision, credentials, categories, tags);
        } catch (CodecException exception) {
            throw exception;
        } catch (EOFException exception) {
            throw new CodecException("Vault payload is truncated", exception);
        } catch (IOException exception) {
            throw new CodecException("Unable to decode vault", exception);
        } catch (RuntimeException exception) {
            throw new CodecException("Vault payload is malformed", exception);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        if (value == null) {
            throw new CodecException("Required string is null");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_BYTES) {
            throw new CodecException("String value is too large");
        }
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAX_STRING_BYTES) {
            throw new CodecException("Invalid string length: " + length);
        }
        byte[] bytes = new byte[length];
        input.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static void writeCount(DataOutputStream output, int count) throws IOException {
        if (count < 0 || count > MAX_ENTITY_COUNT) {
            throw new CodecException("Invalid entity count: " + count);
        }
        output.writeInt(count);
    }

    private static int readCount(DataInputStream input, String entityName) throws IOException {
        int count = input.readInt();
        if (count < 0 || count > MAX_ENTITY_COUNT) {
            throw new CodecException("Invalid " + entityName + " count: " + count);
        }
        return count;
    }
}
