package com.passwordvault.local.storage;

import android.test.AndroidTestCase;

import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.EncryptedPayload;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

public final class DeviceKeyProviderTest extends AndroidTestCase {
    public void testKeyIsNonExportableAndReusableAcrossProviderInstances() {
        SecretKey first = new DeviceKeyProvider().getOrCreate();
        SecretKey second = new DeviceKeyProvider().getOrCreate();

        assertNull(first.getEncoded());
        assertNull(second.getEncoded());

        AesGcmCipher cipher = new AesGcmCipher(new SecureRandom());
        byte[] plaintext = "keystore-round-trip".getBytes(StandardCharsets.UTF_8);
        byte[] associatedData = "device-key-test".getBytes(StandardCharsets.UTF_8);
        EncryptedPayload encrypted = cipher.encrypt(first, plaintext, associatedData);

        assertTrue(Arrays.equals(
                plaintext,
                cipher.decrypt(second, encrypted, associatedData)
        ));
    }
}
