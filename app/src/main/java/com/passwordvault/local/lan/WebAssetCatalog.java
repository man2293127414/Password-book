package com.passwordvault.local.lan;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Immutable MIME whitelist for browser-requestable files under the bundled web directory. */
public final class WebAssetCatalog {
    private static final int MAX_BYTES = 64 * 1024;

    private final Map<String, String> contentTypes;

    private WebAssetCatalog(Map<String, String> contentTypes) {
        this.contentTypes = Collections.unmodifiableMap(
                new LinkedHashMap<String, String>(contentTypes)
        );
    }

    public static WebAssetCatalog parse(InputStream input) throws IOException {
        if (input == null) throw new IllegalArgumentException("input must not be null");

        byte[] encoded = readLimited(input);
        String decoded = decodeUtf8(encoded);
        LinkedHashMap<String, String> entries = new LinkedHashMap<String, String>();
        BufferedReader reader = new BufferedReader(new StringReader(decoded));
        String line;
        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();
            if (trimmed.length() == 0 || trimmed.startsWith("#")) continue;

            int separator = line.indexOf('\t');
            if (separator <= 0 || separator != line.lastIndexOf('\t')) {
                throw new IOException("Invalid runtime asset catalog row");
            }
            String path = line.substring(0, separator);
            String contentType = line.substring(separator + 1);
            validatePath(path);
            validateContentType(contentType);
            if (entries.containsKey(path)) {
                throw new IOException("Duplicate runtime asset path");
            }
            entries.put(path, contentType);
        }
        return new WebAssetCatalog(entries);
    }

    public String contentType(String relativePath) {
        return contentTypes.get(relativePath);
    }

    public Set<String> paths() {
        return contentTypes.keySet();
    }

    private static byte[] readLimited(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (output.size() + count > MAX_BYTES) {
                throw new IOException("Runtime asset catalog exceeds 64 KiB");
            }
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static String decodeUtf8(byte[] encoded) throws IOException {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IOException("Runtime asset catalog is not valid UTF-8", exception);
        }
    }

    private static void validatePath(String path) throws IOException {
        if (path.length() == 0 || path.startsWith("/") || path.indexOf('\\') >= 0
                || path.indexOf('%') >= 0 || path.indexOf('?') >= 0 || path.indexOf('#') >= 0
                || isWindowsAbsolutePath(path) || containsControlCharacter(path)) {
            throw new IOException("Invalid runtime asset path");
        }
        String[] segments = path.split("/", -1);
        for (String segment : segments) {
            if (segment.length() == 0 || ".".equals(segment) || "..".equals(segment)) {
                throw new IOException("Invalid runtime asset path segment");
            }
        }
    }

    private static boolean isWindowsAbsolutePath(String path) {
        return path.length() >= 2
                && ((path.charAt(0) >= 'A' && path.charAt(0) <= 'Z')
                || (path.charAt(0) >= 'a' && path.charAt(0) <= 'z'))
                && path.charAt(1) == ':';
    }

    private static void validateContentType(String contentType) throws IOException {
        if (contentType.trim().length() == 0 || containsControlCharacter(contentType)) {
            throw new IOException("Invalid runtime asset MIME type");
        }
    }

    private static boolean containsControlCharacter(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character <= 0x1f || character == 0x7f) return true;
        }
        return false;
    }
}
