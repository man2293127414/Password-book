package com.passwordvault.local.core.lan;

public final class LanUnauthorizedException extends RuntimeException {
    public LanUnauthorizedException() {
        super("LAN session is not authorized");
    }
}
