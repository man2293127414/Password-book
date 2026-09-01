package com.passwordvault.local.lan;

import com.passwordvault.local.core.lan.LanClock;
import com.passwordvault.local.core.lan.LanCrypto;
import com.passwordvault.local.core.lan.LanEnvelope;
import com.passwordvault.local.core.lan.LanKeyAgreement;
import com.passwordvault.local.core.lan.LanRandom;
import com.passwordvault.local.core.lan.LanSessionKeys;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.VaultValidator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public final class LanHttpServerTest {
    private LanHttpServerTest() {
    }

    public static void main(String[] args) throws Exception {
        servesOnlyBundledIndexWithoutCaching();
        servesCatalogAssetsWithDeclaredMimeAndSecureHeaders();
        rejectsStaticMethodsWithAllowAndSecureHeaders();
        rejectsUnlistedAndTraversalPaths();
        missingWhitelistedAssetFailsClosedWithoutLeakingItsPath();
        indexLoadFailureHasSecureHeaders();
        rejectsApiMethodsWithEndpointSpecificAllowHeaders();
        rejectsWrongApiMethodBeforeReadingItsDeclaredBody();
        apiReadsTheExactJsonBodyAndRejectsWrongMediaType();
        encryptedSnapshotRoundTripsOverHttp();
        oversizedApiBodyIsRejectedBeforeItIsRead();
        stopClosesTheListeningPort();
        System.out.println("PASS LanHttpServerTest");
    }

    private static void encryptedSnapshotRoundTripsOverHttp() throws Exception {
        LanHttpServer server = startApiServer();
        byte[] shared = null;
        byte[] requestPlaintext = "{\"op\":\"snapshot\"}".getBytes(StandardCharsets.UTF_8);
        byte[] responsePlaintext = null;
        LanSessionKeys keys = null;
        try {
            HttpURLConnection infoConnection = request(server, "/api/v1/pairing-info");
            assertEquals(200, infoConnection.getResponseCode());
            assertSecure(infoConnection);
            LanWireCodec.PairingInfo info = LanWireCodec.parsePairingInfo(
                    readUtf8(infoConnection.getInputStream())
            );

            LanKeyAgreement agreement = new LanKeyAgreement();
            LanCrypto crypto = new LanCrypto(new SecureRandom());
            KeyPair clientPair = agreement.generateKeyPair(new SecureRandom());
            byte[] clientPublic = agreement.publicKeyToSec1(clientPair.getPublic());
            byte[] serverPublic = info.getServerPublicKey();
            shared = agreement.deriveSharedSecret(
                    clientPair.getPrivate(),
                    agreement.publicKeyFromSec1(serverPublic)
            );
            String pairingBody = LanWireCodec.pairingSubmitJson(
                    clientPublic,
                    crypto.encryptAccessCode(
                            shared,
                            info.getRunId(),
                            serverPublic,
                            clientPublic,
                            "123456"
                    )
            );
            HttpURLConnection pairingConnection = post(
                    server,
                    "/api/v1/pairing-submit",
                    "application/json",
                    pairingBody
            );
            assertEquals(200, pairingConnection.getResponseCode());
            assertSecure(pairingConnection);
            String sessionId = LanWireCodec.parsePairingSuccess(crypto.decryptAccessCode(
                    shared,
                    info.getRunId(),
                    serverPublic,
                    clientPublic,
                    LanWireCodec.parsePairingReply(readUtf8(pairingConnection.getInputStream()))
            ));
            keys = crypto.deriveSessionKeys(shared, info.getRunId());

            LanEnvelope requestEnvelope = crypto.encryptClientRequest(
                    keys,
                    sessionId,
                    1L,
                    "POST",
                    "/api/v1/vault",
                    requestPlaintext
            );
            HttpURLConnection vaultConnection = post(
                    server,
                    "/api/v1/vault",
                    "application/json",
                    LanWireCodec.envelopeJson(sessionId, requestEnvelope)
            );
            assertEquals(200, vaultConnection.getResponseCode());
            assertSecure(vaultConnection);
            LanEnvelope responseEnvelope = LanWireCodec.parseEnvelope(
                    readUtf8(vaultConnection.getInputStream())
            );
            responsePlaintext = crypto.decryptServerResponse(
                    keys,
                    sessionId,
                    "POST",
                    "/api/v1/vault",
                    responseEnvelope
            );
            Map<String, Object> response = LanJson.object(LanJson.parse(
                    new String(responsePlaintext, StandardCharsets.UTF_8)
            ));
            assertEquals(Boolean.TRUE, response.get("ok"));
            assertTrue(response.containsKey("snapshot"), "encrypted HTTP response must contain snapshot");
        } finally {
            if (keys != null) keys.destroy();
            if (shared != null) Arrays.fill(shared, (byte) 0);
            Arrays.fill(requestPlaintext, (byte) 0);
            if (responsePlaintext != null) Arrays.fill(responsePlaintext, (byte) 0);
            server.shutdown();
        }
    }

    private static void apiReadsTheExactJsonBodyAndRejectsWrongMediaType() throws Exception {
        LanHttpServer server = startApiServer();
        try {
            HttpURLConnection malformed = post(server, "/api/v1/pairing-submit",
                    "application/json; charset=utf-8", "{}");
            assertEquals(400, malformed.getResponseCode());
            assertEquals("no-store", malformed.getHeaderField("Cache-Control"));
            assertEquals("nosniff", malformed.getHeaderField("X-Content-Type-Options"));
            drain(malformed);

            HttpURLConnection jsonp = post(server, "/api/v1/pairing-submit",
                    "application/jsonp", "{}");
            assertEquals(415, jsonp.getResponseCode());
            drain(jsonp);
        } finally {
            server.shutdown();
        }
    }

    private static void rejectsApiMethodsWithEndpointSpecificAllowHeaders() throws Exception {
        LanHttpServer server = startApiServer();
        try {
            assertApiMethodRejected(server, "/api/v1/pairing-info", "HEAD", "GET");
            assertApiMethodRejected(server, "/api/v1/pairing-submit", "GET", "POST");
            assertApiMethodRejected(server, "/api/v1/vault", "HEAD", "POST");
        } finally {
            server.shutdown();
        }
    }

    private static void assertApiMethodRejected(
            LanHttpServer server,
            String path,
            String method,
            String allowedMethod
    ) throws Exception {
        HttpURLConnection connection = request(server, path);
        connection.setRequestMethod(method);
        assertEquals(405, connection.getResponseCode());
        assertEquals(allowedMethod, connection.getHeaderField("Allow"));
        assertSecure(connection);
        if ("HEAD".equals(method)) connection.disconnect();
        else drain(connection);
    }

    private static void rejectsWrongApiMethodBeforeReadingItsDeclaredBody() throws Exception {
        LanHttpServer server = startApiServer();
        try (Socket socket = new Socket("127.0.0.1", server.getListeningPort())) {
            socket.setSoTimeout(1_000);
            String request = "POST /api/v1/pairing-info HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: 9\r\n"
                    + "Connection: keep-alive\r\n\r\n";
            OutputStream output = socket.getOutputStream();
            output.write(request.getBytes(StandardCharsets.US_ASCII));
            output.flush();

            InputStream input = socket.getInputStream();
            assertContains(readAsciiLine(input), "405");
            boolean allowsGet = false;
            boolean noStore = false;
            boolean noSniff = false;
            boolean closesConnection = false;
            String header;
            while (!(header = readAsciiLine(input)).isEmpty()) {
                String normalized = header.toLowerCase(java.util.Locale.ROOT);
                if ("allow: get".equals(normalized)) allowsGet = true;
                if ("cache-control: no-store".equals(normalized)) noStore = true;
                if ("x-content-type-options: nosniff".equals(normalized)) noSniff = true;
                if ("connection: close".equals(normalized)) closesConnection = true;
            }
            assertTrue(allowsGet, "wrong pairing-info method must advertise GET");
            assertTrue(noStore, "wrong API method must disable caching");
            assertTrue(noSniff, "wrong API method must set nosniff");
            assertTrue(closesConnection, "unread request bodies must close the connection");
        } finally {
            server.shutdown();
        }
    }

    private static void oversizedApiBodyIsRejectedBeforeItIsRead() throws Exception {
        LanHttpServer server = startApiServer();
        try (Socket socket = new Socket("127.0.0.1", server.getListeningPort())) {
            socket.setSoTimeout(2_000);
            String request = "POST /api/v1/pairing-submit HTTP/1.1\r\n"
                    + "Host: 127.0.0.1\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: 32769\r\n"
                    + "Connection: keep-alive\r\n\r\n";
            OutputStream output = socket.getOutputStream();
            output.write(request.getBytes(StandardCharsets.US_ASCII));
            output.flush();
            InputStream input = socket.getInputStream();
            String statusLine = readAsciiLine(input);
            assertContains(statusLine, "413");
            boolean closesConnection = false;
            String header;
            while (!(header = readAsciiLine(input)).isEmpty()) {
                if ("connection: close".equals(header.toLowerCase(java.util.Locale.ROOT))) {
                    closesConnection = true;
                }
            }
            assertTrue(closesConnection, "rejected unread body must close the HTTP connection");
        } finally {
            server.shutdown();
        }
    }

    private static void servesCatalogAssetsWithDeclaredMimeAndSecureHeaders() throws Exception {
        LanHttpServer server = startStaticServer(assetMap());
        try {
            HttpURLConnection css = request(server, "/styles.css");
            assertEquals(200, css.getResponseCode());
            assertContains(css.getContentType(), "text/css");
            assertSecure(css);
            assertEquals("body{}", readUtf8(css.getInputStream()));

            HttpURLConnection module = request(server, "/node_modules/@noble/curves/nist.js");
            assertEquals(200, module.getResponseCode());
            assertContains(module.getContentType(), "text/javascript");
            assertSecure(module);
            assertEquals("export {};", readUtf8(module.getInputStream()));
        } finally {
            server.shutdown();
        }
    }

    private static void rejectsStaticMethodsWithAllowAndSecureHeaders() throws Exception {
        LanHttpServer server = startStaticServer(assetMap());
        try {
            for (String method : new String[] {"HEAD", "POST"}) {
                HttpURLConnection connection = request(server, "/styles.css");
                connection.setRequestMethod(method);
                assertEquals(405, connection.getResponseCode());
                assertEquals("GET", connection.getHeaderField("Allow"));
                assertSecure(connection);
                if ("HEAD".equals(method)) connection.disconnect();
                else drain(connection);
            }
        } finally {
            server.shutdown();
        }
    }

    private static void rejectsUnlistedAndTraversalPaths() throws Exception {
        final AtomicInteger assetLoads = new AtomicInteger();
        final Map<String, LanHttpServer.StaticAsset> assets = assetMap();
        LanHttpServer server = startStaticServer(new LanHttpServer.StaticAssetSource() {
            @Override
            public LanHttpServer.StaticAsset load(String path) {
                assetLoads.incrementAndGet();
                return assets.get(path);
            }
        });
        try {
            for (String path : new String[] {
                    "/vendor-manifest.json",
                    "/node_modules/@noble/curves/LICENSE",
                    "/../index.html",
                    "/%2e%2e/index.html",
                    "//styles.css",
                    "/node_modules//module.js",
                    "/node_modules\\module.js"
            }) {
                HttpURLConnection connection = request(server, path);
                assertEquals(404, connection.getResponseCode());
                assertSecure(connection);
                drain(connection);
            }
            assertEquals(2, assetLoads.get());
        } finally {
            server.shutdown();
        }
    }

    private static void missingWhitelistedAssetFailsClosedWithoutLeakingItsPath() throws Exception {
        LanHttpServer server = startStaticServer(new LanHttpServer.StaticAssetSource() {
            @Override
            public LanHttpServer.StaticAsset load(String path) throws IOException {
                if ("app.mjs".equals(path)) throw new IOException("missing web/" + path);
                return null;
            }
        });
        try {
            HttpURLConnection connection = request(server, "/app.mjs");
            assertEquals(500, connection.getResponseCode());
            assertSecure(connection);
            String body = readUtf8(connection.getErrorStream());
            assertTrue(!body.contains("app.mjs"), "500 response must not leak the asset path");
        } finally {
            server.shutdown();
        }
    }

    private static void indexLoadFailureHasSecureHeaders() throws Exception {
        LanHttpServer server = new LanHttpServer(0, new LanHttpServer.IndexHtmlSource() {
            @Override
            public byte[] load() throws IOException {
                throw new IOException("private assets path");
            }
        });
        server.start(2_000, false);
        try {
            HttpURLConnection connection = request(server, "/");
            assertEquals(500, connection.getResponseCode());
            assertSecure(connection);
            assertTrue(!readUtf8(connection.getErrorStream()).contains("private assets path"),
                    "index failure must not leak its cause");
        } finally {
            server.shutdown();
        }
    }

    private static void servesOnlyBundledIndexWithoutCaching() throws Exception {
        LanHttpServer server = startServer();
        try {
            HttpURLConnection index = request(server, "/");
            assertEquals(200, index.getResponseCode());
            assertContains(index.getContentType(), "text/html");
            assertSecure(index);
            assertEquals("<html><body>LAN</body></html>", readUtf8(index.getInputStream()));

            HttpURLConnection missing = request(server, "/vault");
            assertEquals(404, missing.getResponseCode());
            assertSecure(missing);

            HttpURLConnection method = request(server, "/index.html");
            method.setRequestMethod("POST");
            assertEquals(405, method.getResponseCode());
            assertEquals("GET", method.getHeaderField("Allow"));
            assertSecure(method);
        } finally {
            server.shutdown();
        }
    }

    private static void stopClosesTheListeningPort() throws Exception {
        LanHttpServer server = startServer();
        int port = server.getListeningPort();

        server.shutdown();
        server.shutdown();

        assertTrue(!server.isAlive(), "server must not remain alive after shutdown");
        expectConnectionFailure(port);
    }

    private static LanHttpServer startServer() throws IOException {
        LanHttpServer server = new LanHttpServer(0, new LanHttpServer.IndexHtmlSource() {
            @Override
            public byte[] load() {
                return "<html><body>LAN</body></html>".getBytes(StandardCharsets.UTF_8);
            }
        });
        server.start(2_000, false);
        return server;
    }

    private static LanHttpServer startApiServer() throws IOException {
        AtomicInteger ids = new AtomicInteger();
        VaultService vault = new VaultService(
                new InMemoryVaultStore(VaultSnapshot.empty()),
                new VaultValidator(),
                () -> "id-" + ids.incrementAndGet(),
                () -> 1L
        );
        LanSessionManager sessions = new LanSessionManager(
                new LanClock() {
                    @Override public long nowMillis() { return 0L; }
                },
                new LanRandom() {
                    @Override public int nextInt(int ignored) { return 123456; }
                    @Override public String nextSessionId() { return "session-1"; }
                }
        );
        LanApiDispatcher api = new LanApiDispatcher(vault, sessions, new SecureRandom());
        api.startRun();
        LanHttpServer server = new LanHttpServer(
                null,
                0,
                () -> "<html></html>".getBytes(StandardCharsets.UTF_8),
                api
        );
        server.start(2_000, false);
        return server;
    }

    private static LanHttpServer startStaticServer(Map<String, LanHttpServer.StaticAsset> assets)
            throws IOException {
        return startStaticServer(new MapAssetSource(assets));
    }

    private static LanHttpServer startStaticServer(LanHttpServer.StaticAssetSource assets)
            throws IOException {
        LanHttpServer server = new LanHttpServer(
                null,
                0,
                () -> "index".getBytes(StandardCharsets.UTF_8),
                null,
                assets
        );
        server.start(2_000, false);
        return server;
    }

    private static Map<String, LanHttpServer.StaticAsset> assetMap() {
        Map<String, LanHttpServer.StaticAsset> assets = new LinkedHashMap<String, LanHttpServer.StaticAsset>();
        assets.put("styles.css", new LanHttpServer.StaticAsset(
                "body{}".getBytes(StandardCharsets.UTF_8),
                "text/css; charset=utf-8"
        ));
        assets.put("node_modules/@noble/curves/nist.js", new LanHttpServer.StaticAsset(
                "export {};".getBytes(StandardCharsets.UTF_8),
                "text/javascript; charset=utf-8"
        ));
        return assets;
    }

    private static HttpURLConnection post(
            LanHttpServer server,
            String path,
            String contentType,
            String body
    ) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        HttpURLConnection connection = request(server, path);
        connection.setConnectTimeout(2_000);
        connection.setReadTimeout(2_000);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", contentType);
        connection.setFixedLengthStreamingMode(bytes.length);
        connection.setDoOutput(true);
        OutputStream output = connection.getOutputStream();
        try {
            output.write(bytes);
        } finally {
            output.close();
        }
        return connection;
    }

    private static HttpURLConnection request(LanHttpServer server, String path) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(
                "http://127.0.0.1:" + server.getListeningPort() + path
        ).openConnection();
        connection.setRequestProperty("Connection", "close");
        return connection;
    }

    private static void expectConnectionFailure(int port) throws Exception {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/").openConnection();
            connection.setConnectTimeout(500);
            connection.setReadTimeout(500);
            connection.getResponseCode();
            throw new AssertionError("stopped server still accepts connections");
        } catch (IOException expected) {
            // A refused connection proves the listening socket was released.
        }
    }

    private static String readUtf8(InputStream stream) throws IOException {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            int count;
            while ((count = stream.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            stream.close();
        }
    }

    private static String readAsciiLine(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int value;
        while ((value = input.read()) != -1) {
            if (value == '\n') break;
            if (value != '\r') output.write(value);
        }
        return new String(output.toByteArray(), StandardCharsets.US_ASCII);
    }

    private static void drain(HttpURLConnection connection) throws IOException {
        InputStream input = connection.getErrorStream();
        if (input == null) input = connection.getInputStream();
        try {
            while (input.read() != -1) {
                // Consume the response so NanoHTTPD can close or reuse the socket cleanly.
            }
        } finally {
            input.close();
            connection.disconnect();
        }
    }

    private static void assertContains(String actual, String expectedPart) {
        if (actual == null || !actual.contains(expectedPart)) {
            throw new AssertionError("Expected <" + actual + "> to contain <" + expectedPart + ">");
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertSecure(HttpURLConnection connection) {
        assertEquals("no-store", connection.getHeaderField("Cache-Control"));
        assertEquals("nosniff", connection.getHeaderField("X-Content-Type-Options"));
    }

    private static final class MapAssetSource implements LanHttpServer.StaticAssetSource {
        private final Map<String, LanHttpServer.StaticAsset> assets;

        private MapAssetSource(Map<String, LanHttpServer.StaticAsset> assets) {
            this.assets = assets;
        }

        @Override
        public LanHttpServer.StaticAsset load(String path) {
            return assets.get(path);
        }
    }
}
