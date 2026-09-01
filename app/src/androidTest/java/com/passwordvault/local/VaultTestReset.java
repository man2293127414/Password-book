package com.passwordvault.local;

import android.content.Context;

/** Keeps direct database tests isolated from the application-owned production store. */
public final class VaultTestReset {
    private VaultTestReset() {
    }

    public static void closeApplicationVault(Context context) {
        PasswordVaultApplication application = (PasswordVaultApplication) context.getApplicationContext();
        application.stopLanAccess();
        application.closeVaultForInstrumentationTests();
    }
}
