package com.passwordvault.local.core.lan;

import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.CryptoException;
import com.passwordvault.local.core.crypto.EncryptedPayload;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class LanCrypto {
    private static final byte[] HANDSHAKE_INFO = "PVL-LAN-HANDSHAKE-V1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CLIENT_TO_SERVER_INFO = "PVL-LAN-C2S-V1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER_TO_CLIENT_INFO = "PVL-LAN-S2C-V1".getBytes(StandardCharsets.UTF_8);
    private static final int AES_KEY_BYTES = 32;
    private static final int GCM_TAG_BITS = 128;

    private final AesGcmCipher pairingCipher;

    public LanCrypto(SecureRandom secureRandom) {
        pairingCipher = new AesGcmCipher(secureRandom);
    }

    public byte[] deriveHandshakeKey(byte[] sharedSecret, byte[] runId) {
        return hkdf(sharedSecret, runId, HANDSHAKE_INFO);
    }

    public LanSessionKeys deriveSessionKeys(byte[] sharedSecret, byte[] runId) {
        return new LanSessionKeys(
                hkdf(sharedSecret, runId, CLIENT_TO_SERVER_INFO),
                hkdf(sharedSecret, runId, SERVER_TO_CLIENT_INFO)
        );
    }

    public EncryptedPayload encryptAccessCode(
            byte[] sharedSecret,
            byte[] runId,
            byte[] serverPublicKey,
            byte[] clientPublicKey,
            String accessCode
    ) {
        byte[] keyBytes = deriveHandshakeKey(sharedSecret, runId);
        try {
            return pairingCipher.encrypt(
                    new SecretKeySpec(keyBytes, "AES"),
                    accessCode.getBytes(StandardCharsets.UTF_8),
                    pairingAad(runId, serverPublicKey, clientPublicKey)
            );
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public String decryptAccessCode(
            byte[] sharedSecret,
            byte[] runId,
            byte[] serverPublicKey,
            byte[] clientPublicKey,
            EncryptedPayload encrypted
    ) {
        byte[] keyBytes = deriveHandshakeKey(sharedSecret, runId);
        byte[] plaintext = null;
        try {
            plaintext = pairingCipher.decrypt(
                    new SecretKeySpec(keyBytes, "AES"),
                    encrypted,
                    pairingAad(runId, serverPublicKey, clientPublicKey)
            );
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    public LanEnvelope encryptClientRequest(
            LanSessionKeys keys,
            String sessionId,
            long counter,
            String method,
            String path,
            byte[] plaintext
    ) {
        return encryptMessage(
                keys.getClientToServerKey(), sessionId, counter, method, path, plaintext
        );
    }

    public byte[] decryptClientRequest(
            LanSessionKeys keys,
            String sessionId,
            String method,
            String path,
            LanEnvelope envelope
    ) {
        return decryptMessage(
                keys.getClientToServerKey(), sessionId, method, path, envelope
        );
    }

    public LanEnvelope encryptServerResponse(
            LanSessionKeys keys,
            String sessionId,
            long counter,
            String method,
            String path,
            byte[] plaintext
    ) {
        return encryptMessage(
                keys.getServerToClientKey(), sessionId, counter, method, path, plaintext
        );
    }

    public byte[] decryptServerResponse(
            LanSessionKeys keys,
            String sessionId,
            String method,
            String path,
            LanEnvelope envelope
    ) {
        return decryptMessage(
                keys.getServerToClientKey(), sessionId, method, path, envelope
        );
    }

    private static LanEnvelope encryptMessage(
            byte[] key,
            String sessionId,
            long counter,
            String method,
            String path,
            byte[] plaintext
    ) {
        requireMessageInputs(sessionId, counter, method, path, plaintext);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce(counter))
            );
            cipher.updateAAD(messageAad(sessionId, counter, method, path));
            return new LanEnvelope(counter, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to encrypt LAN message", exception);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] decryptMessage(
            byte[] key,
            String sessionId,
            String method,
            String path,
            LanEnvelope envelope
    ) {
        requireMessageInputs(sessionId, envelope.getCounter(), method, path, envelope.getCiphertext());
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce(envelope.getCounter()))
            );
            cipher.updateAAD(messageAad(sessionId, envelope.getCounter(), method, path));
            return cipher.doFinal(envelope.getCiphertext());
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("LAN message authentication failed", exception);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] hkdf(byte[] inputKeyMaterial, byte[] salt, byte[] info) {
        if (inputKeyMaterial == null || inputKeyMaterial.length == 0) {
            throw new IllegalArgumentException("sharedSecret must not be empty");
        }
        if (salt == null || salt.length == 0) throw new IllegalArgumentException("runId must not be empty");
        byte[] pseudorandomKey = null;
        try {
            Mac extract = Mac.getInstance("HmacSHA256");
            extract.init(new SecretKeySpec(salt, "HmacSHA256"));
            pseudorandomKey = extract.doFinal(inputKeyMaterial);

            Mac expand = Mac.getInstance("HmacSHA256");
            expand.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            expand.update(info);
            expand.update((byte) 1);
            return Arrays.copyOf(expand.doFinal(), AES_KEY_BYTES);
        } catch (GeneralSecurityException exception) {
            throw new CryptoException("Unable to derive LAN session key", exception);
        } finally {
            if (pseudorandomKey != null) Arrays.fill(pseudorandomKey, (byte) 0);
        }
    }

    private static byte[] pairingAad(byte[] runId, byte[] serverPublicKey, byte[] clientPublicKey) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(runId);
            output.write(serverPublicKey);
            output.write(clientPublicKey);
            return output.toByteArray();
        } catch (IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static byte[] nonce(long counter) {
        return ByteBuffer.allocate(12).putInt(0).putLong(counter).array();
    }

    private static byte[] messageAad(String sessionId, long counter, String method, String path) {
        return (method + "\n" + path + "\n" + sessionId + "\n" + counter)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static void requireMessageInputs(
            String sessionId,
            long counter,
            String method,
            String path,
            byte[] data
    ) {
        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("sessionId must not be empty");
        }
        if (counter < 0) throw new IllegalArgumentException("counter must not be negative");
        if (method == null || method.isEmpty()) throw new IllegalArgumentException("method must not be empty");
        if (path == null || path.isEmpty()) throw new IllegalArgumentException("path must not be empty");
        if (data == null) throw new IllegalArgumentException("data must not be null");
    }
}
