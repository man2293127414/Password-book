package com.passwordvault.local.backup;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import android.provider.DocumentsContract;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class AndroidBackupFiles {
    private static final int BUFFER_BYTES = 8192;
    private static final int MAX_BACKUP_BYTES = 64 * 1024 * 1024 + 1024;

    private final StreamProvider streams;
    private final int maxBytes;

    public AndroidBackupFiles(Context context) {
        this(new ContentResolverStreams(requireApplicationContext(context)), MAX_BACKUP_BYTES);
    }

    AndroidBackupFiles(StreamProvider streams, int maxBytes) {
        if (streams == null) {
            throw new IllegalArgumentException("streams must not be null");
        }
        if (maxBytes < 1) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        this.streams = streams;
        this.maxBytes = maxBytes;
    }

    public byte[] read(Uri uri) throws IOException {
        requireUri(uri);
        try (InputStream input = requireInput(streams.openInput(uri));
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[BUFFER_BYTES];
            int total = 0;
            int count;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                if (total > maxBytes) {
                    throw new IOException("Backup file is too large");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    public void write(Uri uri, byte[] encryptedBackup) throws IOException {
        requireUri(uri);
        if (encryptedBackup == null) {
            throw new IllegalArgumentException("encryptedBackup must not be null");
        }
        if (encryptedBackup.length > maxBytes) {
            throw new IOException("Backup file is too large");
        }

        try (OutputStream output = requireOutput(streams.openOutput(uri))) {
            output.write(encryptedBackup);
            output.flush();
        } catch (IOException | RuntimeException exception) {
            try {
                streams.delete(uri);
            } catch (IOException | RuntimeException deleteFailure) {
                exception.addSuppressed(deleteFailure);
            }
            throw exception;
        }
    }

    interface StreamProvider {
        InputStream openInput(Uri uri) throws IOException;

        OutputStream openOutput(Uri uri) throws IOException;

        void delete(Uri uri) throws IOException;
    }

    private static final class ContentResolverStreams implements StreamProvider {
        private final Context context;
        private final ContentResolver resolver;

        private ContentResolverStreams(Context context) {
            this.context = context;
            this.resolver = context.getContentResolver();
        }

        @Override
        public InputStream openInput(Uri uri) throws IOException {
            return resolver.openInputStream(uri);
        }

        @Override
        public OutputStream openOutput(Uri uri) throws IOException {
            return resolver.openOutputStream(uri, "rwt");
        }

        @Override
        public void delete(Uri uri) throws IOException {
            if (DocumentsContract.isDocumentUri(context, uri)) {
                DocumentsContract.deleteDocument(resolver, uri);
            }
        }
    }

    private static Context requireApplicationContext(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context must not be null");
        }
        Context applicationContext = context.getApplicationContext();
        return applicationContext == null ? context : applicationContext;
    }

    private static void requireUri(Uri uri) {
        if (uri == null) {
            throw new IllegalArgumentException("uri must not be null");
        }
    }

    private static InputStream requireInput(InputStream input) throws FileNotFoundException {
        if (input == null) {
            throw new FileNotFoundException("Unable to open backup for reading");
        }
        return input;
    }

    private static OutputStream requireOutput(OutputStream output) throws FileNotFoundException {
        if (output == null) {
            throw new FileNotFoundException("Unable to open backup for writing");
        }
        return output;
    }
}
