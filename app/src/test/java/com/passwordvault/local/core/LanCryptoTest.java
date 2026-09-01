package com.passwordvault.local.core;

import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;
import com.passwordvault.local.core.lan.LanCrypto;
import com.passwordvault.local.core.lan.LanEnvelope;
import com.passwordvault.local.core.lan.LanKeyAgreement;
import com.passwordvault.local.core.lan.LanSessionKeys;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

final class LanCryptoTest {
    private static final byte[] CLIENT_PRIVATE = decode("B7CNdsund0EQWHulMIea0AgfY891UYsmWHx79HdG0gY");
    private static final byte[] CLIENT_PUBLIC = decode("BKYdtvz9M4nGtouNSqLFyhPXqg401pgy5EgYSyK8YS2r0sF0SZ4MbNkrVu1yAM7zWXviFQk_P_0cSPLHblESLac");
    private static final byte[] SERVER_PRIVATE = decode("nA_t0pDOdyZEd4veULWGV7IAq8aCZoX4ijgpJNyMnhg");
    private static final byte[] SERVER_PUBLIC = decode("BGXayrNM7zDS2kPPl7I_-e4InsoSF7nTAELsAgqVLCbB__4oW7opTjBFbZBoGGx_n7JrhbbzUG5wOa-_g0Pcafw");
    private static final byte[] RUN_ID = decode("AAECAwQFBgcICQoLDA0ODw");
    private static final byte[] SHARED_SECRET = decode("_K77A6ajOj4heLq-EoEAu9tCBJg58A2os1Mjuufm9C8");
    private static final byte[] HANDSHAKE_KEY = decode("93b8uYYrjUYRCTKL4i-2U_LCl4K-7mCvKxJd3oh_E50");
    private static final byte[] CLIENT_TO_SERVER_KEY = decode("_xBG5kKsfnN2rDPBjPjnfK5vuwCpe9Y2cNQe9DuovH4");
    private static final byte[] SERVER_TO_CLIENT_KEY = decode("IXyAvkkUnVfe4ejZ_Rp9N7K4y8Ff1zeMPbxofz5pyIM");
    private static final byte[] PAIRING_NONCE = decode("EBESExQVFhcYGRob");
    private static final byte[] PAIRING_CIPHERTEXT = decode("K-oPT9iKq8MQZHtduiu79qEzrfc4Rg");
    private static final byte[] REQUEST_PLAINTEXT = decode("eyJhY3Rpb24iOiJsaXN0In0");
    private static final byte[] REQUEST_CIPHERTEXT = decode("-xQyD6mciRxaQ8pqy_WmzBCfZ0POCBCuCn2D_q9FBq2k");

    static void run() {
        LanCryptoTest test = new LanCryptoTest();
        test.derivesBrowserCompatibleSharedSecret();
        test.generatedKeyPairsAgreeAndRoundTripPublicEncoding();
        test.rejectsNonP256PublicKeyEncoding();
        test.derivesSeparatedSessionKeysFromKnownVector();
        test.encryptsAndDecryptsPairingCodeFromKnownVector();
        test.encryptsAndDecryptsRequestFromKnownVector();
        test.serverResponseUsesSeparateDirectionKey();
        test.rejectsTamperedRequestAndWrongDirectionKey();
        test.destroyedSessionKeysRejectFurtherReads();
        System.out.println("PASS LanCryptoTest");
    }

    private void destroyedSessionKeysRejectFurtherReads() {
        LanSessionKeys keys = new LanCrypto(new SecureRandom()).deriveSessionKeys(SHARED_SECRET, RUN_ID);
        keys.destroy();
        keys.destroy();
        assertTrue(keys.isDestroyed(), "destroy must mark keys closed");
        try { keys.getClientToServerKey(); throw new AssertionError("destroyed key must reject reads"); }
        catch (IllegalStateException expected) { }
        try { keys.getServerToClientKey(); throw new AssertionError("destroyed key must reject reads"); }
        catch (IllegalStateException expected) { }
    }

    private void derivesBrowserCompatibleSharedSecret() {
        LanKeyAgreement agreement = new LanKeyAgreement();
        PrivateKey clientPrivate = agreement.privateKeyFromScalar(CLIENT_PRIVATE);
        PublicKey serverPublic = agreement.publicKeyFromSec1(SERVER_PUBLIC);

        byte[] actual = agreement.deriveSharedSecret(clientPrivate, serverPublic);

        assertBytes(SHARED_SECRET, actual);
        assertBytes(SERVER_PUBLIC, agreement.publicKeyToSec1(serverPublic));
    }

    private void generatedKeyPairsAgreeAndRoundTripPublicEncoding() {
        LanKeyAgreement agreement = new LanKeyAgreement();
        KeyPair client = agreement.generateKeyPair(new SecureRandom());
        KeyPair server = agreement.generateKeyPair(new SecureRandom());
        byte[] clientShared = agreement.deriveSharedSecret(client.getPrivate(), server.getPublic());
        byte[] serverShared = agreement.deriveSharedSecret(server.getPrivate(), client.getPublic());

        assertBytes(clientShared, serverShared);
        assertBytes(
                agreement.publicKeyToSec1(client.getPublic()),
                agreement.publicKeyToSec1(
                        agreement.publicKeyFromSec1(agreement.publicKeyToSec1(client.getPublic()))
                )
        );
    }

    private void rejectsNonP256PublicKeyEncoding() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp384r1"));
            final PublicKey publicKey = generator.generateKeyPair().getPublic();

            expectIllegalArgument(new ThrowingRunnable() {
                @Override
                public void run() {
                    new LanKeyAgreement().publicKeyToSec1(publicKey);
                }
            });
        } catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    private void derivesSeparatedSessionKeysFromKnownVector() {
        LanCrypto crypto = cryptoWithNonce(PAIRING_NONCE);

        assertBytes(HANDSHAKE_KEY, crypto.deriveHandshakeKey(SHARED_SECRET, RUN_ID));
        LanSessionKeys keys = crypto.deriveSessionKeys(SHARED_SECRET, RUN_ID);
        assertBytes(CLIENT_TO_SERVER_KEY, keys.getClientToServerKey());
        assertBytes(SERVER_TO_CLIENT_KEY, keys.getServerToClientKey());
        assertTrue(!Arrays.equals(keys.getClientToServerKey(), keys.getServerToClientKey()), "direction keys must differ");
    }

    private void encryptsAndDecryptsPairingCodeFromKnownVector() {
        LanCrypto crypto = cryptoWithNonce(PAIRING_NONCE);

        EncryptedPayload encrypted = crypto.encryptAccessCode(
                SHARED_SECRET, RUN_ID, SERVER_PUBLIC, CLIENT_PUBLIC, "123456"
        );
        String decrypted = crypto.decryptAccessCode(
                SHARED_SECRET, RUN_ID, SERVER_PUBLIC, CLIENT_PUBLIC, encrypted
        );

        assertBytes(PAIRING_NONCE, encrypted.getNonce());
        assertBytes(PAIRING_CIPHERTEXT, encrypted.getCiphertext());
        assertEquals("123456", decrypted);
    }

    private void encryptsAndDecryptsRequestFromKnownVector() {
        LanCrypto crypto = cryptoWithNonce(PAIRING_NONCE);
        LanSessionKeys keys = crypto.deriveSessionKeys(SHARED_SECRET, RUN_ID);

        LanEnvelope envelope = crypto.encryptClientRequest(
                keys, "session-test-id", 1L, "POST", "/api/v1/vault", REQUEST_PLAINTEXT
        );
        byte[] decrypted = crypto.decryptClientRequest(
                keys, "session-test-id", "POST", "/api/v1/vault", envelope
        );

        assertEquals(1L, envelope.getCounter());
        assertBytes(REQUEST_CIPHERTEXT, envelope.getCiphertext());
        assertBytes(REQUEST_PLAINTEXT, decrypted);
    }

    private void rejectsTamperedRequestAndWrongDirectionKey() {
        LanCrypto crypto = cryptoWithNonce(PAIRING_NONCE);
        LanSessionKeys keys = crypto.deriveSessionKeys(SHARED_SECRET, RUN_ID);
        byte[] tampered = REQUEST_CIPHERTEXT.clone();
        tampered[0] ^= 1;
        final LanEnvelope tamperedEnvelope = new LanEnvelope(1L, tampered);
        final LanEnvelope validEnvelope = new LanEnvelope(1L, REQUEST_CIPHERTEXT);

        expectCryptoFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decryptClientRequest(
                        keys, "session-test-id", "POST", "/api/v1/vault", tamperedEnvelope
                );
            }
        });
        expectCryptoFailure(new ThrowingRunnable() {
            @Override
            public void run() {
                crypto.decryptServerResponse(
                        keys, "session-test-id", "POST", "/api/v1/vault", validEnvelope
                );
            }
        });
    }

    private void serverResponseUsesSeparateDirectionKey() {
        LanCrypto crypto = cryptoWithNonce(PAIRING_NONCE);
        LanSessionKeys keys = crypto.deriveSessionKeys(SHARED_SECRET, RUN_ID);
        byte[] plaintext = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);

        LanEnvelope response = crypto.encryptServerResponse(
                keys, "session-test-id", 1L, "POST", "/api/v1/vault", plaintext
        );
        byte[] decrypted = crypto.decryptServerResponse(
                keys, "session-test-id", "POST", "/api/v1/vault", response
        );

        assertBytes(plaintext, decrypted);
        assertTrue(!Arrays.equals(REQUEST_CIPHERTEXT, response.getCiphertext()), "response key must differ");
    }

    private static LanCrypto cryptoWithNonce(byte[] nonce) {
        return new LanCrypto(new FixedSecureRandom(nonce));
    }

    private static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private static void expectCryptoFailure(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected CryptoException");
        } catch (CryptoException expected) {
            // Expected behavior.
        }
    }

    private static void expectIllegalArgument(ThrowingRunnable runnable) {
        try {
            runnable.run();
            throw new AssertionError("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected behavior.
        }
    }

    private static void assertBytes(byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(
                    "Expected <" + Base64.getUrlEncoder().withoutPadding().encodeToString(expected)
                            + "> but was <" + Base64.getUrlEncoder().withoutPadding().encodeToString(actual) + ">"
            );
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

    private static final class FixedSecureRandom extends SecureRandom {
        private final byte[] nonce;

        private FixedSecureRandom(byte[] nonce) {
            this.nonce = nonce.clone();
        }

        @Override
        public void nextBytes(byte[] target) {
            if (target.length != nonce.length) {
                throw new AssertionError("Unexpected nonce length: " + target.length);
            }
            System.arraycopy(nonce, 0, target, 0, nonce.length);
        }
    }
}
