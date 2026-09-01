package com.passwordvault.local.core.backup;

final class BackupEnvelope {
    static final int SALT_BYTES = 16;
    static final int VERIFIER_BYTES = 16;
    static final int NONCE_BYTES = 12;

    private final byte[] salt;
    private final byte[] verifier;
    private final byte[] nonce;
    private final byte[] ciphertext;

    BackupEnvelope(byte[] salt, byte[] verifier, byte[] nonce, byte[] ciphertext) {
        requireLength("salt", salt, SALT_BYTES);
        requireLength("verifier", verifier, VERIFIER_BYTES);
        requireLength("nonce", nonce, NONCE_BYTES);
        if (ciphertext == null || ciphertext.length < 16) {
            throw new IllegalArgumentException("ciphertext must contain an AES-GCM tag");
        }
        this.salt = salt.clone();
        this.verifier = verifier.clone();
        this.nonce = nonce.clone();
        this.ciphertext = ciphertext.clone();
    }

    byte[] getSalt() { return salt.clone(); }
    byte[] getVerifier() { return verifier.clone(); }
    byte[] getNonce() { return nonce.clone(); }
    byte[] getCiphertext() { return ciphertext.clone(); }

    private static void requireLength(String name, byte[] value, int expected) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException(name + " must contain " + expected + " bytes");
        }
    }
}
