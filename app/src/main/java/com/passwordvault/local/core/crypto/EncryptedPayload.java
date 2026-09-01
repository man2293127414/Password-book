package com.passwordvault.local.core.crypto;

public final class EncryptedPayload {
    public static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;

    private final byte[] nonce;
    private final byte[] ciphertext;

    public EncryptedPayload(byte[] nonce, byte[] ciphertext) {
        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new IllegalArgumentException("AES-GCM nonce must contain 12 bytes");
        }
        if (ciphertext == null || ciphertext.length < GCM_TAG_BYTES) {
            throw new IllegalArgumentException("AES-GCM ciphertext is missing its authentication tag");
        }
        this.nonce = nonce.clone();
        this.ciphertext = ciphertext.clone();
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public byte[] getCiphertext() {
        return ciphertext.clone();
    }
}
