package com.passwordvault.local.lan;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import fi.iki.elonen.NanoHTTPD;

/**
 * Serves the LAN web entry point. Its owner must call {@link #shutdown()} before releasing the
 * foreground service that created it.
 */
public final class LanHttpServer extends NanoHTTPD {
    public interface IndexHtmlSource {
        byte[] load() throws IOException;
    }
    public interface StaticAssetSource {
        StaticAsset load(String relativePath) throws IOException;
    }

    public static final class StaticAsset {
        private final byte[] content;
        private final String contentType;

        public StaticAsset(byte[] content, String contentType) {
            this.content = content;
            this.contentType = contentType;
        }

        public byte[] getContent() {
            return content;
        }

        public String getContentType() {
            return contentType;
        }
    }

    private final IndexHtmlSource indexHtmlSource;
    private final LanApiDispatcher api;
    private final StaticAssetSource staticAssets;
    private static final int MAX_API_BODY_BYTES = 32 * 1024;

    public LanHttpServer(int port, IndexHtmlSource indexHtmlSource) {
        this(port, indexHtmlSource, null);
    }

    public LanHttpServer(int port, IndexHtmlSource indexHtmlSource, LanApiDispatcher api) {
        this(null, port, indexHtmlSource, api, null);
    }
    public LanHttpServer(String hostname, int port, IndexHtmlSource indexHtmlSource, LanApiDispatcher api) {
        this(hostname, port, indexHtmlSource, api, null);
    }
    public LanHttpServer(String hostname, int port, IndexHtmlSource indexHtmlSource, LanApiDispatcher api, StaticAssetSource staticAssets) {
        super(hostname, port);
        if (indexHtmlSource == null) {
            throw new IllegalArgumentException("indexHtmlSource must not be null");
        }
        this.indexHtmlSource = indexHtmlSource;
        this.api = api;
        this.staticAssets = staticAssets;
    }

    @Override
    public Response serve(IHTTPSession session) {
        String path = session.getUri();
        if (api != null && ("/api/v1/pairing-info".equals(path)
                || "/api/v1/pairing-submit".equals(path) || "/api/v1/vault".equals(path))) {
            return apiResponse(session);
        }
        if (session.getMethod() != Method.GET) {
            Response response = secure(
                    Response.Status.METHOD_NOT_ALLOWED,
                    "Method not allowed",
                    MIME_PLAINTEXT
            );
            response.addHeader("Allow", "GET");
            return response;
        }
        if (!"/".equals(path) && !"/index.html".equals(path)) {
            return staticAsset(path);
        }
        try {
            byte[] indexHtml = indexHtmlSource.load();
            if (indexHtml == null) {
                throw new IOException("index.html source returned null");
            }
            return secure(
                    Response.Status.OK,
                    "text/html; charset=utf-8",
                    indexHtml
            );
        } catch (IOException exception) {
            return secure(
                    Response.Status.INTERNAL_ERROR,
                    "Unable to load page",
                    "text/plain; charset=" + StandardCharsets.UTF_8.name()
            );
        }
    }

    private Response staticAsset(String uri) {
        String relativePath = relativeAssetPath(uri);
        if (relativePath == null || staticAssets == null) {
            return secure(Response.Status.NOT_FOUND, "Not found", MIME_PLAINTEXT);
        }
        try {
            StaticAsset asset = staticAssets.load(relativePath);
            if (asset == null) {
                return secure(Response.Status.NOT_FOUND, "Not found", MIME_PLAINTEXT);
            }
            byte[] content = asset.getContent();
            String contentType = asset.getContentType();
            if (content == null || contentType == null || contentType.trim().length() == 0) {
                throw new IOException("Invalid static asset");
            }
            return secure(Response.Status.OK, contentType, content);
        } catch (IOException exception) {
            return secure(Response.Status.INTERNAL_ERROR, "Unable to load asset", MIME_PLAINTEXT);
        }
    }

    private static String relativeAssetPath(String uri) {
        if (uri == null || uri.length() < 2 || uri.charAt(0) != '/' || uri.charAt(1) == '/') {
            return null;
        }
        String relativePath = uri.substring(1);
        if (relativePath.indexOf('\\') >= 0 || relativePath.indexOf('%') >= 0
                || relativePath.indexOf('?') >= 0 || relativePath.indexOf('#') >= 0
                || isWindowsAbsolutePath(relativePath) || containsControlCharacter(relativePath)) {
            return null;
        }
        String[] segments = relativePath.split("/", -1);
        for (String segment : segments) {
            if (segment.length() == 0 || ".".equals(segment) || "..".equals(segment)) return null;
        }
        return relativePath;
    }

    private static boolean isWindowsAbsolutePath(String path) {
        return path.length() >= 2
                && ((path.charAt(0) >= 'A' && path.charAt(0) <= 'Z')
                || (path.charAt(0) >= 'a' && path.charAt(0) <= 'z'))
                && path.charAt(1) == ':';
    }

    private static boolean containsControlCharacter(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character <= 0x1f || character == 0x7f) return true;
        }
        return false;
    }

    private Response apiResponse(IHTTPSession session) {
        String method = session.getMethod().name();
        String allowedMethod = allowedApiMethod(session.getUri());
        if (!allowedMethod.equals(method)) {
            Response response = secure(
                    Response.Status.METHOD_NOT_ALLOWED,
                    "METHOD_NOT_ALLOWED",
                    MIME_PLAINTEXT
            );
            response.addHeader("Allow", allowedMethod);
            response.closeConnection(true);
            return response;
        }
        boolean post = "POST".equals(method);
        if (post && !isJson(session)) return rejectUnread(Response.Status.UNSUPPORTED_MEDIA_TYPE, "BAD_REQUEST");
        long length = post ? contentLength(session) : 0L;
        if (post && length < 0L) return rejectUnread(Response.Status.LENGTH_REQUIRED, "BAD_REQUEST");
        if (post && length > MAX_API_BODY_BYTES) return rejectUnread(Response.Status.PAYLOAD_TOO_LARGE, "BAD_REQUEST");
        String body = null;
        if (post) {
            try { body = new String(readExactly(session.getInputStream(), length), StandardCharsets.UTF_8); }
            catch (IOException exception) { return rejectUnread(Response.Status.BAD_REQUEST, "BAD_REQUEST"); }
        }
        LanApiDispatcher.OuterResponse result = api.handle(method, session.getUri(), body);
        Response.Status status = status(result.getStatus());
        Response response = secure(
                status,
                result.getBody(),
                result.isJson() ? "application/json; charset=utf-8" : MIME_PLAINTEXT
        );
        if (status == Response.Status.METHOD_NOT_ALLOWED) {
            response.addHeader("Allow", allowedApiMethod(session.getUri()));
        }
        return response;
    }

    private static String allowedApiMethod(String path) {
        return "/api/v1/pairing-info".equals(path) ? "GET" : "POST";
    }

    private static boolean isJson(IHTTPSession session) {
        String contentType = session.getHeaders().get("content-type");
        if (contentType == null) return false;
        String normalized = contentType.toLowerCase(java.util.Locale.ROOT).trim();
        return "application/json".equals(normalized) || normalized.startsWith("application/json;");
    }

    private static long contentLength(IHTTPSession session) {
        String value = session.getHeaders().get("content-length");
        if (value == null) return -1L;
        try { return Long.parseLong(value); } catch (NumberFormatException exception) { return -1L; }
    }

    private static byte[] readExactly(InputStream input, long length) throws IOException {
        if (length > Integer.MAX_VALUE) throw new IOException("Request body too large");
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) length); byte[] buffer = new byte[1024]; int count;
        while (out.size() < length && (count = input.read(buffer, 0, (int) Math.min(buffer.length, length - out.size()))) != -1) out.write(buffer, 0, count);
        if (out.size() != length) throw new IOException("Short request body");
        return out.toByteArray();
    }

    private static Response.Status status(int code) {
        if (code == 200) return Response.Status.OK; if (code == 400) return Response.Status.BAD_REQUEST;
        if (code == 401) return Response.Status.UNAUTHORIZED; if (code == 404) return Response.Status.NOT_FOUND;
        if (code == 405) return Response.Status.METHOD_NOT_ALLOWED; if (code == 429) return Response.Status.TOO_MANY_REQUESTS; return Response.Status.INTERNAL_ERROR;
    }

    private Response secure(Response.Status status, String body, String mime) {
        Response response = newFixedLengthResponse(status, mime, body);
        addSecurityHeaders(response);
        return response;
    }

    private Response secure(Response.Status status, String mime, byte[] content) {
        Response response = newFixedLengthResponse(
                status,
                mime,
                new ByteArrayInputStream(content),
                content.length
        );
        addSecurityHeaders(response);
        return response;
    }

    private static void addSecurityHeaders(Response response) {
        response.addHeader("Cache-Control", "no-store"); response.addHeader("X-Content-Type-Options", "nosniff");
    }

    private Response rejectUnread(Response.Status status, String body) {
        Response response = secure(status, body, MIME_PLAINTEXT);
        response.closeConnection(true);
        return response;
    }

    /** Releases the listening socket and all active HTTP connections. */
    public void shutdown() {
        closeAllConnections();
    }
}
