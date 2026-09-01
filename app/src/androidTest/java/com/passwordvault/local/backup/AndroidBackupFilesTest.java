package com.passwordvault.local.backup;

import android.net.Uri;
import android.test.AndroidTestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public final class AndroidBackupFilesTest extends AndroidTestCase {
    private static final Uri URI = Uri.parse("content://password-vault-test/backup.pvlb");

    public void testWritesAndReadsThroughBoundedStreams() throws Exception {
        FakeStreams streams = new FakeStreams();
        AndroidBackupFiles files = new AndroidBackupFiles(streams, 32);
        byte[] expected = new byte[] {1, 2, 3, 4, 5};

        files.write(URI, expected);
        streams.readBytes = streams.written.toByteArray();

        assertTrue(Arrays.equals(expected, files.read(URI)));
        assertFalse(streams.deleted);
    }

    public void testOversizedReadIsRejected() throws Exception {
        FakeStreams streams = new FakeStreams();
        streams.readBytes = new byte[17];
        AndroidBackupFiles files = new AndroidBackupFiles(streams, 16);

        try {
            files.read(URI);
            fail("Expected oversized backup rejection");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("too large"));
        }
    }

    public void testWriteFailureAttemptsToDeletePartialDocument() throws Exception {
        FakeStreams streams = new FakeStreams();
        streams.failWrite = true;
        AndroidBackupFiles files = new AndroidBackupFiles(streams, 32);

        try {
            files.write(URI, new byte[] {1, 2, 3});
            fail("Expected write failure");
        } catch (IOException expected) {
            assertTrue(streams.deleted);
        }
    }

    private static final class FakeStreams implements AndroidBackupFiles.StreamProvider {
        private byte[] readBytes = new byte[0];
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();
        private boolean failWrite;
        private boolean deleted;

        @Override
        public InputStream openInput(Uri uri) {
            return new ByteArrayInputStream(readBytes);
        }

        @Override
        public OutputStream openOutput(Uri uri) {
            if (!failWrite) {
                return written;
            }
            return new OutputStream() {
                @Override
                public void write(int value) throws IOException {
                    throw new IOException("simulated write failure");
                }
            };
        }

        @Override
        public void delete(Uri uri) {
            deleted = true;
        }
    }
}
