package com.passwordvault.local.core.lan;

public final class LanReplayException extends RuntimeException {
    public LanReplayException() {
        super("LAN request counter was already used");
    }
}
