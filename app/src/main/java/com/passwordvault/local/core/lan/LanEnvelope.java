package com.passwordvault.local.core.lan;

public final class LanEnvelope {
    private final long counter;
    private final byte[] ciphertext;

    public LanEnvelope(long counter, byte[] ciphertext) {
        if (counter < 0) throw new IllegalArgumentException("counter must not be negative");
        if (ciphertext == null || ciphertext.length < 16) {
            throw new IllegalArgumentException("ciphertext must contain an AES-GCM tag");
        }
        this.counter = counter;
        this.ciphertext = ciphertext.clone();
    }

    public long getCounter() { return counter; }
    public byte[] getCiphertext() { return ciphertext.clone(); }
}
