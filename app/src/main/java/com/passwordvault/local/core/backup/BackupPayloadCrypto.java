package com.passwordvault.local.core.backup;

public interface BackupPayloadCrypto {
    byte[] encrypt(byte[] plaintext, char[] password);

    byte[] decrypt(byte[] backup, char[] password);
}
