package com.passwordvault.local.core.backup;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;

final class BackupEnvelopeCodec {
    static final int ITERATIONS = 600_000;

    private static final int MAGIC = 0x50564C42;
    private static final int FORMAT_VERSION = 1;
    private static final int KDF_PBKDF2_HMAC_SHA256 = 1;
    private static final int MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024;

    byte[] encode(BackupEnvelope envelope) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(MAGIC);
            output.writeInt(FORMAT_VERSION);
            output.writeInt(KDF_PBKDF2_HMAC_SHA256);
            output.writeInt(ITERATIONS);
            writeBytes(output, envelope.getSalt());
            writeBytes(output, envelope.getVerifier());
            writeBytes(output, envelope.getNonce());
            writeBytes(output, envelope.getCiphertext());
            output.flush();
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new CorruptBackupException("Unable to encode backup envelope", exception);
        }
    }

    BackupEnvelope decode(byte[] backup) {
        if (backup == null || backup.length == 0) {
            throw new CorruptBackupException("Backup file is empty");
        }
        try {
            ByteArrayInputStream bytes = new ByteArrayInputStream(backup);
            DataInputStream input = new DataInputStream(bytes);
            if (input.readInt() != MAGIC) {
                throw new CorruptBackupException("Backup file has invalid magic");
            }
            int formatVersion = input.readInt();
            if (formatVersion != FORMAT_VERSION) {
                throw new UnsupportedBackupVersionException(
                        "Unsupported backup format version: " + formatVersion
                );
            }
            int kdf = input.readInt();
            int iterations = input.readInt();
            if (kdf != KDF_PBKDF2_HMAC_SHA256 || iterations != ITERATIONS) {
                throw new UnsupportedBackupVersionException("Unsupported backup key derivation settings");
            }
            byte[] salt = readBytes(input, BackupEnvelope.SALT_BYTES, BackupEnvelope.SALT_BYTES, "salt");
            byte[] verifier = readBytes(
                    input,
                    BackupEnvelope.VERIFIER_BYTES,
                    BackupEnvelope.VERIFIER_BYTES,
                    "verifier"
            );
            byte[] nonce = readBytes(input, BackupEnvelope.NONCE_BYTES, BackupEnvelope.NONCE_BYTES, "nonce");
            byte[] ciphertext = readBytes(input, 16, MAX_CIPHERTEXT_BYTES, "ciphertext");
            if (bytes.available() != 0) {
                throw new CorruptBackupException("Backup file contains trailing data");
            }
            return new BackupEnvelope(salt, verifier, nonce, ciphertext);
        } catch (BackupException exception) {
            throw exception;
        } catch (EOFException exception) {
            throw new CorruptBackupException("Backup file is truncated", exception);
        } catch (IOException | IllegalArgumentException exception) {
            throw new CorruptBackupException("Backup file is malformed", exception);
        }
    }

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] readBytes(
            DataInputStream input,
            int minimumLength,
            int maximumLength,
            String fieldName
    ) throws IOException {
        int length = input.readInt();
        if (length < minimumLength || length > maximumLength) {
            throw new CorruptBackupException("Invalid backup " + fieldName + " length: " + length);
        }
        byte[] value = new byte[length];
        input.readFully(value);
        return value;
    }
}
