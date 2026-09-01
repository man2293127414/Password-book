package com.passwordvault.local.core.storage;

import javax.crypto.SecretKey;

public interface SecretKeyProvider {
    SecretKey getOrCreate();
}
