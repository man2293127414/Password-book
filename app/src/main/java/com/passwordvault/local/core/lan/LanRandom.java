package com.passwordvault.local.core.lan;

public interface LanRandom {
    int nextInt(int bound);

    String nextSessionId();
}
