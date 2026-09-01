package com.passwordvault.local.lan;

import com.passwordvault.local.core.lan.LanClock;
import com.passwordvault.local.core.lan.LanCrypto;
import com.passwordvault.local.core.lan.LanEnvelope;
import com.passwordvault.local.core.lan.LanKeyAgreement;
import com.passwordvault.local.core.lan.LanRandom;
import com.passwordvault.local.core.lan.LanSessionKeys;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanSessionState;
import com.passwordvault.local.core.lan.LanVaultAccessGate;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.repository.VaultStore;
import com.passwordvault.local.core.validation.VaultValidator;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** Contract tests: authentication, encryption, replay, or route regressions must fail here. */
public final class LanApiDispatcherTest {
    public static void main(String[] args) {
        pairingMetadataDoesNotExposeVaultAndEncryptedSnapshotWorks();
        allVaultMutationRoutesUseTheSharedVaultService();
        businessFailuresUseStableEncryptedErrors();
        tamperedMessageDoesNotConsumeItsCounter();
        replayedMutationIsRejectedBeforeItCanWriteTwice();
        exclusivePhoneMutationDrainsAuthenticatedLanWrite();
        stoppedRunReturnsDisconnected();
        pairingReplyFailureStopsTheEstablishedSession();
        pairingSubmitIsRateLimited();
        deeplyNestedPublicJsonIsRejected();
        System.out.println("PASS LanApiDispatcherTest");
    }

    private static void pairingMetadataDoesNotExposeVaultAndEncryptedSnapshotWorks() {
        Fixture fixture = fixture();
        LanApiDispatcher.OuterResponse info = fixture.api.handle("GET", "/api/v1/pairing-info", null);
        assertEquals(200, info.getStatus());
        assertTrue(!info.getBody().contains("credentials"), "public metadata must not expose vault data");

        Session session = pair(fixture, info.getBody());
        Map<String, Object> response = command(fixture, session, 1L, "{\"op\":\"snapshot\"}");
        assertEquals(Boolean.TRUE, response.get("ok"));
        Map<String, Object> snapshot = LanJson.object(response.get("snapshot"));
        assertEquals(0L, ((Long) snapshot.get("revision")).longValue());
    }

    private static void allVaultMutationRoutesUseTheSharedVaultService() {
        Fixture fixture = fixture();
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());

        command(fixture, session, 1L, "{\"op\":\"category.create\",\"name\":\"工作\"}");
        Category category = fixture.vault.getSnapshot().getCategories().get(0);
        command(fixture, session, 2L, "{\"op\":\"category.rename\",\"id\":\"" + category.getId()
                + "\",\"expectedVersion\":1,\"name\":\"个人\"}");
        category = fixture.vault.getSnapshot().getCategories().get(0);
        assertEquals("个人", category.getName());
        assertEquals(2, category.getVersion());

        command(fixture, session, 3L, "{\"op\":\"tag.create\",\"name\":\"重要\"}");
        Tag tag = fixture.vault.getSnapshot().getTags().get(0);
        command(fixture, session, 4L, "{\"op\":\"tag.rename\",\"id\":\"" + tag.getId()
                + "\",\"expectedVersion\":1,\"name\":\"常用\"}");
        tag = fixture.vault.getSnapshot().getTags().get(0);
        assertEquals("常用", tag.getName());
        assertEquals(2, tag.getVersion());

        command(fixture, session, 5L, "{\"op\":\"credential.create\",\"name\":\"邮箱\","
                + "\"account\":\"me@example.com\",\"password\":\"secret\","
                + "\"url\":\"https://example.com\",\"categoryId\":\"" + category.getId() + "\","
                + "\"tagIds\":[\"" + tag.getId() + "\"],\"notes\":\"仅测试\"}");
        Credential credential = fixture.vault.getSnapshot().getCredentials().get(0);
        assertEquals("secret", credential.getPassword());
        assertEquals(category.getId(), credential.getCategoryId());
        assertTrue(credential.getTagIds().contains(tag.getId()), "created credential must keep its tag");

        command(fixture, session, 6L, "{\"op\":\"credential.update\",\"id\":\"" + credential.getId()
                + "\",\"expectedVersion\":1,\"name\":\"新邮箱\",\"account\":\"new@example.com\","
                + "\"password\":\"new-secret\",\"url\":null,\"categoryId\":null,"
                + "\"tagIds\":[],\"notes\":null}");
        credential = fixture.vault.getSnapshot().getCredentials().get(0);
        assertEquals("新邮箱", credential.getName());
        assertEquals("new-secret", credential.getPassword());
        assertEquals(2, credential.getVersion());

        command(fixture, session, 7L, "{\"op\":\"credential.delete\",\"id\":\"" + credential.getId()
                + "\",\"expectedVersion\":2}");
        command(fixture, session, 8L, "{\"op\":\"category.delete\",\"id\":\"" + category.getId()
                + "\",\"expectedVersion\":2}");
        command(fixture, session, 9L, "{\"op\":\"tag.delete\",\"id\":\"" + tag.getId()
                + "\",\"expectedVersion\":2}");
        assertEquals(0, fixture.vault.getSnapshot().getCredentials().size());
        assertEquals(0, fixture.vault.getSnapshot().getCategories().size());
        assertEquals(0, fixture.vault.getSnapshot().getTags().size());
    }

    private static void businessFailuresUseStableEncryptedErrors() {
        Fixture fixture = fixture();
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());

        assertEncryptedError(fixture, session, 1L,
                "{\"op\":\"category.create\",\"name\":\"   \"}", "VALIDATION");
        assertEncryptedError(fixture, session, 2L,
                "{\"op\":\"category.rename\",\"id\":\"missing\",\"expectedVersion\":1,\"name\":\"x\"}",
                "NOT_FOUND");
        command(fixture, session, 3L, "{\"op\":\"category.create\",\"name\":\"已有\"}");
        String categoryId = fixture.vault.getSnapshot().getCategories().get(0).getId();
        String stale = "{\"op\":\"category.rename\",\"id\":\"" + categoryId
                + "\",\"expectedVersion\":99,\"name\":\"新名称\"}";
        assertEncryptedError(fixture, session, 4L, stale, "STALE_VERSION");
        assertEncryptedError(fixture, session, 5L, "{\"op\":\"unknown\"}", "BAD_REQUEST");

        LanEnvelope replay = fixture.crypto.encryptClientRequest(session.keys, session.sessionId, 4L,
                "POST", "/api/v1/vault", stale.getBytes(StandardCharsets.UTF_8));
        assertEquals(401, fixture.api.handle("POST", "/api/v1/vault",
                LanWireCodec.envelopeJson(session.sessionId, replay)).getStatus());
    }

    private static void tamperedMessageDoesNotConsumeItsCounter() {
        Fixture fixture = fixture();
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        byte[] plaintext = "{\"op\":\"category.create\",\"name\":\"安全\"}"
                .getBytes(StandardCharsets.UTF_8);
        try {
            LanEnvelope valid = fixture.crypto.encryptClientRequest(session.keys, session.sessionId, 1L,
                    "POST", "/api/v1/vault", plaintext);
            byte[] damaged = valid.getCiphertext();
            damaged[0] ^= 1;

            LanApiDispatcher.OuterResponse rejected = fixture.api.handle("POST", "/api/v1/vault",
                    LanWireCodec.envelopeJson(session.sessionId, new LanEnvelope(1L, damaged)));
            assertEquals(401, rejected.getStatus());
            assertEquals(0, fixture.vault.getSnapshot().getCategories().size());

            assertEquals(200, fixture.api.handle("POST", "/api/v1/vault",
                    LanWireCodec.envelopeJson(session.sessionId, valid)).getStatus());
            assertEquals(1, fixture.vault.getSnapshot().getCategories().size());
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static void replayedMutationIsRejectedBeforeItCanWriteTwice() {
        Fixture fixture = fixture();
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        byte[] mutation = "{\"op\":\"category.create\",\"name\":\"工作\"}"
                .getBytes(StandardCharsets.UTF_8);
        try {
            LanEnvelope request = fixture.crypto.encryptClientRequest(session.keys, session.sessionId, 1L,
                    "POST", "/api/v1/vault", mutation);
            String outer = LanWireCodec.envelopeJson(session.sessionId, request);
            assertEquals(200, fixture.api.handle("POST", "/api/v1/vault", outer).getStatus());
            assertEquals(401, fixture.api.handle("POST", "/api/v1/vault", outer).getStatus());
            assertEquals(1, fixture.vault.getSnapshot().getCategories().size());
        } finally {
            Arrays.fill(mutation, (byte) 0);
        }
    }

    private static void exclusivePhoneMutationDrainsAuthenticatedLanWrite() {
        BlockingReplaceStore store = new BlockingReplaceStore();
        LanVaultAccessGate gate = new LanVaultAccessGate();
        Fixture fixture = fixture(new SecureRandom(), store, gate);
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        store.blockNextReplace();
        AtomicReference<Throwable> failure = new AtomicReference<Throwable>();

        Thread lanWrite = new Thread(() -> {
            try {
                command(fixture, session, 1L,
                        "{\"op\":\"category.create\",\"name\":\"旧会话写入\"}");
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        }, "in-flight LAN write");
        lanWrite.start();
        store.awaitBlockedReplace();

        Thread phoneClear = new Thread(() -> {
            try {
                gate.runExclusiveMutation(() -> {
                    fixture.sessions.stop();
                    fixture.vault.clearAll();
                });
            } catch (Throwable throwable) {
                failure.compareAndSet(null, throwable);
            }
        }, "exclusive phone clear");
        phoneClear.start();
        waitUntilBlocked(phoneClear);

        store.releaseBlockedReplace();
        join(lanWrite);
        join(phoneClear);
        if (failure.get() != null) throw new AssertionError("concurrent vault test failed", failure.get());
        assertEquals(0, fixture.vault.getSnapshot().getCategories().size());
    }

    private static void stoppedRunReturnsDisconnected() {
        Fixture fixture = fixture();
        Session session = pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        fixture.api.stopRun();
        LanEnvelope request = fixture.crypto.encryptClientRequest(session.keys, session.sessionId, 1L,
                "POST", "/api/v1/vault", "{\"op\":\"snapshot\"}".getBytes(StandardCharsets.UTF_8));
        LanApiDispatcher.OuterResponse response = fixture.api.handle("POST", "/api/v1/vault",
                LanWireCodec.envelopeJson(session.sessionId, request));
        assertEquals(401, response.getStatus());
        assertEquals("DISCONNECTED", response.getBody());
    }

    private static void pairingSubmitIsRateLimited() {
        Fixture fixture = fixture();
        pair(fixture, fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        LanApiDispatcher.OuterResponse limited = fixture.api.handle("POST", "/api/v1/pairing-submit", "{}");
        assertEquals(429, limited.getStatus());
        assertEquals("RATE_LIMITED", limited.getBody());
    }

    private static void pairingReplyFailureStopsTheEstablishedSession() {
        Fixture fixture = fixture(new ReplyNonceFailingRandom());
        LanWireCodec.PairingInfo info = LanWireCodec.parsePairingInfo(
                fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody()
        );
        LanKeyAgreement agreement = new LanKeyAgreement();
        KeyPair clientPair = agreement.generateKeyPair(new SecureRandom());
        byte[] clientPublic = agreement.publicKeyToSec1(clientPair.getPublic());
        byte[] serverPublic = info.getServerPublicKey();
        byte[] shared = agreement.deriveSharedSecret(
                clientPair.getPrivate(), agreement.publicKeyFromSec1(serverPublic)
        );
        try {
            String submit = LanWireCodec.pairingSubmitJson(clientPublic, fixture.crypto.encryptAccessCode(
                    shared, info.getRunId(), serverPublic, clientPublic, "123456"
            ));
            assertEquals(500, fixture.api.handle("POST", "/api/v1/pairing-submit", submit).getStatus());
            assertEquals(LanSessionState.Status.STOPPED, fixture.sessions.getState().getStatus());
            assertEquals("DISCONNECTED",
                    fixture.api.handle("GET", "/api/v1/pairing-info", null).getBody());
        } finally {
            Arrays.fill(shared, (byte) 0);
        }
    }

    private static void deeplyNestedPublicJsonIsRejected() {
        Fixture fixture = fixture();
        StringBuilder body = new StringBuilder();
        for (int index = 0; index < 33; index++) body.append('[');
        body.append('0');
        for (int index = 0; index < 33; index++) body.append(']');
        assertEquals(400, fixture.api.handle("POST", "/api/v1/pairing-submit", body.toString()).getStatus());
    }

    private static void assertEncryptedError(
            Fixture fixture,
            Session session,
            long counter,
            String json,
            String expectedCode
    ) {
        Map<String, Object> response = command(fixture, session, counter, json);
        assertEquals(Boolean.FALSE, response.get("ok"));
        assertEquals(expectedCode, response.get("error"));
    }

    private static Map<String, Object> command(Fixture fixture, Session session, long counter, String json) {
        byte[] plaintext = json.getBytes(StandardCharsets.UTF_8);
        byte[] responsePlaintext = null;
        try {
            LanEnvelope request = fixture.crypto.encryptClientRequest(session.keys, session.sessionId, counter,
                    "POST", "/api/v1/vault", plaintext);
            LanApiDispatcher.OuterResponse response = fixture.api.handle("POST", "/api/v1/vault",
                    LanWireCodec.envelopeJson(session.sessionId, request));
            assertEquals(200, response.getStatus());
            LanEnvelope encrypted = LanWireCodec.parseEnvelope(response.getBody());
            assertEquals(counter, encrypted.getCounter());
            responsePlaintext = fixture.crypto.decryptServerResponse(session.keys, session.sessionId,
                    "POST", "/api/v1/vault", encrypted);
            return LanJson.object(LanJson.parse(new String(responsePlaintext, StandardCharsets.UTF_8)));
        } finally {
            Arrays.fill(plaintext, (byte) 0);
            if (responsePlaintext != null) Arrays.fill(responsePlaintext, (byte) 0);
        }
    }

    private static Session pair(Fixture fixture, String pairingInfo) {
        LanWireCodec.PairingInfo info = LanWireCodec.parsePairingInfo(pairingInfo);
        LanKeyAgreement agreement = new LanKeyAgreement();
        KeyPair clientPair = agreement.generateKeyPair(new SecureRandom());
        byte[] clientPublic = agreement.publicKeyToSec1(clientPair.getPublic());
        byte[] serverPublic = info.getServerPublicKey();
        byte[] shared = agreement.deriveSharedSecret(
                clientPair.getPrivate(), agreement.publicKeyFromSec1(serverPublic));
        try {
            String submit = LanWireCodec.pairingSubmitJson(clientPublic, fixture.crypto.encryptAccessCode(
                    shared, info.getRunId(), serverPublic, clientPublic, "123456"));
            LanApiDispatcher.OuterResponse paired = fixture.api.handle("POST", "/api/v1/pairing-submit", submit);
            assertEquals(200, paired.getStatus());
            String sessionId = LanWireCodec.parsePairingSuccess(fixture.crypto.decryptAccessCode(
                    shared, info.getRunId(), serverPublic, clientPublic,
                    LanWireCodec.parsePairingReply(paired.getBody())));
            return new Session(sessionId, fixture.crypto.deriveSessionKeys(shared, info.getRunId()));
        } finally {
            Arrays.fill(shared, (byte) 0);
        }
    }

    private static Fixture fixture() {
        return fixture(new SecureRandom());
    }

    private static Fixture fixture(SecureRandom serverRandom) {
        return fixture(
                serverRandom,
                new InMemoryVaultStore(com.passwordvault.local.core.model.VaultSnapshot.empty()),
                new LanVaultAccessGate()
        );
    }

    private static Fixture fixture(
            SecureRandom serverRandom,
            VaultStore store,
            LanVaultAccessGate gate
    ) {
        AtomicInteger ids = new AtomicInteger();
        VaultService vault = new VaultService(
                store,
                new VaultValidator(), () -> "id-" + ids.incrementAndGet(), () -> 1L);
        MutableClock clock = new MutableClock();
        LanSessionManager sessions = new LanSessionManager(new LanClock() {
            @Override public long nowMillis() { return clock.getAsLong(); }
        }, new LanRandom() {
            @Override public int nextInt(int ignored) { return 123456; }
            @Override public String nextSessionId() { return "session-1"; }
        });
        LanApiDispatcher api = new LanApiDispatcher(vault, sessions, serverRandom, gate, clock);
        api.startRun();
        return new Fixture(vault, new LanCrypto(new SecureRandom()), api, sessions);
    }

    private static final class MutableClock implements LongSupplier {
        @Override public long getAsLong() { return 0L; }
    }

    private static final class Fixture {
        final VaultService vault;
        final LanCrypto crypto;
        final LanApiDispatcher api;
        final LanSessionManager sessions;

        Fixture(
                VaultService vault,
                LanCrypto crypto,
                LanApiDispatcher api,
                LanSessionManager sessions
        ) {
            this.vault = vault;
            this.crypto = crypto;
            this.api = api;
            this.sessions = sessions;
        }
    }

    private static final class ReplyNonceFailingRandom extends SecureRandom {
        private final SecureRandom delegate = new SecureRandom();

        @Override public void nextBytes(byte[] bytes) {
            if (bytes.length == 12) {
                throw new IllegalStateException("expected pairing reply nonce failure");
            }
            delegate.nextBytes(bytes);
        }
    }

    private static final class BlockingReplaceStore implements VaultStore {
        private com.passwordvault.local.core.model.VaultSnapshot snapshot =
                com.passwordvault.local.core.model.VaultSnapshot.empty();
        private final CountDownLatch replaceEntered = new CountDownLatch(1);
        private final CountDownLatch releaseReplace = new CountDownLatch(1);
        private boolean blockNextReplace;

        synchronized void blockNextReplace() {
            blockNextReplace = true;
        }

        void awaitBlockedReplace() {
            await(replaceEntered);
        }

        void releaseBlockedReplace() {
            releaseReplace.countDown();
        }

        @Override public synchronized com.passwordvault.local.core.model.VaultSnapshot read() {
            return snapshot;
        }

        @Override public void replace(com.passwordvault.local.core.model.VaultSnapshot replacement) {
            boolean shouldBlock;
            synchronized (this) {
                shouldBlock = blockNextReplace;
                blockNextReplace = false;
            }
            if (shouldBlock) {
                replaceEntered.countDown();
                await(releaseReplace);
            }
            synchronized (this) {
                snapshot = replacement;
            }
        }
    }

    private static final class Session {
        final String sessionId;
        final LanSessionKeys keys;
        Session(String sessionId, LanSessionKeys keys) { this.sessionId = sessionId; this.keys = keys; }
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void waitUntilBlocked(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (System.nanoTime() < deadline) {
            Thread.State state = thread.getState();
            if (state == Thread.State.WAITING || state == Thread.State.BLOCKED) return;
            Thread.yield();
        }
        throw new AssertionError("thread did not block behind the vault access gate");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(2L, TimeUnit.SECONDS)) throw new AssertionError("timed out waiting for latch");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("test interrupted", exception);
        }
    }

    private static void join(Thread thread) {
        try {
            thread.join(2_000L);
            if (thread.isAlive()) throw new AssertionError("test thread did not finish");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("test interrupted", exception);
        }
    }
}
