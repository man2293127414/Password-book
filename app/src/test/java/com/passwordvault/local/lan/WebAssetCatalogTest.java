package com.passwordvault.local.lan;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public final class WebAssetCatalogTest {
    private WebAssetCatalogTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesUtf8EntriesAndIgnoresBlankAndCommentLines();
        returnsAnImmutablePathSet();
        rejectsDuplicatePaths();
        rejectsAbsoluteAndMalformedPaths();
        rejectsMissingEmptyAndExtraMimeColumns();
        rejectsControlCharactersAndMalformedUtf8();
        enforcesThe64KiBByteLimit();
        System.out.println("PASS WebAssetCatalogTest");
    }

    private static void parsesUtf8EntriesAndIgnoresBlankAndCommentLines() throws Exception {
        WebAssetCatalog catalog = parse(
                "# browser runtime\n"
                        + "\n"
                        + "  # vendored modules\r\n"
                        + "styles.css\ttext/css; charset=utf-8\n"
                        + "模块.mjs\ttext/javascript; charset=utf-8\n"
        );

        assertEquals("text/css; charset=utf-8", catalog.contentType("styles.css"));
        assertEquals("text/javascript; charset=utf-8", catalog.contentType("模块.mjs"));
        assertEquals(null, catalog.contentType("index.html"));
        assertEquals(2, catalog.paths().size());
    }

    private static void returnsAnImmutablePathSet() throws Exception {
        final Set<String> paths = parse("app.mjs\ttext/javascript; charset=utf-8\n").paths();
        expectUnsupported(new ThrowingRunnable() {
            @Override
            public void run() {
                paths.add("injected.mjs");
            }
        });
    }

    private static void rejectsDuplicatePaths() throws Exception {
        expectIOException("duplicate path", bytes(
                "app.mjs\ttext/javascript; charset=utf-8\n"
                        + "app.mjs\ttext/javascript; charset=utf-8\n"
        ));
    }

    private static void rejectsAbsoluteAndMalformedPaths() throws Exception {
        expectInvalidPath("/styles.css");
        expectInvalidPath("C:/styles.css");
        expectInvalidPath("node_modules\\module.js");
        expectInvalidPath("./app.mjs");
        expectInvalidPath("node_modules/../app.mjs");
        expectInvalidPath("node_modules/./app.mjs");
        expectInvalidPath("node_modules//app.mjs");
        expectInvalidPath("node_modules/");
        expectInvalidPath("node_modules/%2e%2e/app.mjs");
        expectInvalidPath("app.mjs?download=1");
        expectInvalidPath("app.mjs#fragment");
    }

    private static void rejectsMissingEmptyAndExtraMimeColumns() throws Exception {
        expectIOException("missing MIME", bytes("app.mjs\n"));
        expectIOException("empty MIME", bytes("app.mjs\t\n"));
        expectIOException("extra column", bytes("app.mjs\ttext/javascript\textra\n"));
    }

    private static void rejectsControlCharactersAndMalformedUtf8() throws Exception {
        expectIOException("path control character", bytes(
                "bad\u0000name.mjs\ttext/javascript; charset=utf-8\n"
        ));
        expectIOException("MIME control character", bytes(
                "app.mjs\ttext/javascript\u0000; charset=utf-8\n"
        ));
        expectIOException("malformed UTF-8", new byte[] {(byte) 0xc3, 0x28});
    }

    private static void enforcesThe64KiBByteLimit() throws Exception {
        byte[] maximum = commentBytes(64 * 1024);
        WebAssetCatalog.parse(new ByteArrayInputStream(maximum));

        byte[] tooLarge = commentBytes(64 * 1024 + 1);
        expectIOException("over 64 KiB", tooLarge);
    }

    private static WebAssetCatalog parse(String text) throws IOException {
        return WebAssetCatalog.parse(new ByteArrayInputStream(bytes(text)));
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] commentBytes(int size) {
        byte[] bytes = new byte[size];
        bytes[0] = '#';
        for (int index = 1; index < size - 1; index++) bytes[index] = 'a';
        bytes[size - 1] = '\n';
        return bytes;
    }

    private static void expectInvalidPath(String path) throws Exception {
        expectIOException("invalid path " + path, bytes(
                path + "\ttext/javascript; charset=utf-8\n"
        ));
    }

    private static void expectIOException(String label, byte[] input) throws Exception {
        try {
            WebAssetCatalog.parse(new ByteArrayInputStream(input));
            throw new AssertionError("Expected IOException for " + label);
        } catch (IOException expected) {
            // The catalog must fail closed for malformed input.
        }
    }

    private static void expectUnsupported(ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
            throw new AssertionError("Expected immutable paths set");
        } catch (UnsupportedOperationException expected) {
            // Public callers cannot mutate the catalog.
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
