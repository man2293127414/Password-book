package com.passwordvault.local.storage;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.passwordvault.local.core.crypto.AesGcmCipher;
import com.passwordvault.local.core.crypto.EncryptedPayload;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class DeviceKeyProviderTest {
    @Test
    public void keyIsNonExportableAndReusableAcrossProviderInstances() {
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
