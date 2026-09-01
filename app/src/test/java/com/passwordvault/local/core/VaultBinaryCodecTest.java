package com.passwordvault.local.core;

import com.passwordvault.local.core.codec.CodecException;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;

final class VaultBinaryCodecTest {
    private final VaultBinaryCodec codec = new VaultBinaryCodec();

    static void run() {
        VaultBinaryCodecTest test = new VaultBinaryCodecTest();
        test.roundTripsEveryVaultField();
        test.producesDeterministicVersionedPayload();
        test.rejectsWrongMagic();
        test.rejectsUnsupportedFormatVersion();
        test.rejectsNegativeCollectionCount();
        test.rejectsOversizedStringLength();
        test.rejectsTruncatedPayload();
        test.rejectsTrailingBytes();
        System.out.println("PASS VaultBinaryCodecTest");
    }

    private void roundTripsEveryVaultField() {
        VaultSnapshot expected = fixture();

        VaultSnapshot actual = codec.decode(codec.encode(expected));

        assertEquals(expected.getSchemaVersion(), actual.getSchemaVersion());
        assertEquals(expected.getRevision(), actual.getRevision());
        assertEquals(expected.getCategories(), actual.getCategories());
        assertEquals(expected.getTags(), actual.getTags());
        assertEquals(expected.getCredentials(), actual.getCredentials());
    }

    private void producesDeterministicVersionedPayload() {
        byte[] first = codec.encode(fixture());
        byte[] second = codec.encode(fixture());

        assertTrue(Arrays.equals(first, second), "same snapshot must produce identical bytes");
        assertEquals((byte) 'P', first[0]);
        assertEquals((byte) 'V', first[1]);
        assertEquals((byte) 'L', first[2]);
        assertEquals((byte) 'T', first[3]);
        assertEquals((byte) 0, first[4]);
        assertEquals((byte) 0, first[5]);
        assertEquals((byte) 0, first[6]);
        assertEquals((byte) 1, first[7]);
    }

    private void rejectsWrongMagic() {
        final byte[] encoded = codec.encode(fixture());
        encoded[0] = (byte) 'X';

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(encoded);
            }
        });
    }

    private void rejectsUnsupportedFormatVersion() {
        final byte[] encoded = codec.encode(fixture());
        encoded[7] = 2;

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(encoded);
            }
        });
    }

    private void rejectsNegativeCollectionCount() {
        final byte[] encoded = codec.encode(fixture());
        for (int index = 20; index < 24; index++) {
            encoded[index] = (byte) 0xFF;
        }

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(encoded);
            }
        });
    }

    private void rejectsOversizedStringLength() {
        final byte[] encoded = codec.encode(fixture());
        encoded[24] = 0;
        encoded[25] = 16;
        encoded[26] = 0;
        encoded[27] = 1;

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(encoded);
            }
        });
    }

    private void rejectsTruncatedPayload() {
        final byte[] encoded = codec.encode(fixture());
        final byte[] truncated = Arrays.copyOf(encoded, encoded.length - 1);

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(truncated);
            }
        });
    }

    private void rejectsTrailingBytes() {
        final byte[] encoded = codec.encode(fixture());
        final byte[] extended = Arrays.copyOf(encoded, encoded.length + 1);
        extended[extended.length - 1] = 42;

        expectCodecFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                codec.decode(extended);
            }
        });
    }

    private static VaultSnapshot fixture() {
        Category category = new Category("cat-work", "工作", 2);
        Tag important = new Tag("tag-important", "重要", 3);
        Tag shared = new Tag("tag-shared", "共享", 1);
        Credential categorized = new Credential(
                "cred-1",
                "GitHub",
                "octocat@example.com",
                "  密码 with spaces  ",
                "https://github.com",
                "cat-work",
                new LinkedHashSet<String>(Arrays.asList("tag-important", "tag-shared")),
                "第一行\n第二行",
                4,
                1700000000000L,
                1700000005000L
        );
        Credential uncategorized = new Credential(
                "cred-2",
                "空字段",
                "",
                "secret",
                "",
                null,
                Collections.<String>emptySet(),
                "",
                1,
                1700000010000L,
                1700000010000L
        );
        return new VaultSnapshot(
                1,
                42L,
                Arrays.asList(categorized, uncategorized),
                Collections.singletonList(category),
                Arrays.asList(important, shared)
        );
    }

    private static void expectCodecFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected CodecException");
        } catch (CodecException expected) {
            // Expected behavior.
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private interface ThrowingRunnable {
        void run();
    }
}
