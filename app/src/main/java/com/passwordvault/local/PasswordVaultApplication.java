package com.passwordvault.local;

import android.app.Application;
import android.content.Intent;
import android.os.SystemClock;

import com.passwordvault.local.core.lan.LanClock;
import com.passwordvault.local.core.lan.LanRandom;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanVaultAccessGate;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.VaultValidator;
import com.passwordvault.local.lan.LanAccessService;
import com.passwordvault.local.storage.EncryptedVaultStore;

import java.security.SecureRandom;
import java.util.UUID;

/** Owns the single session and vault service shared by the phone UI and LAN service. */
public final class PasswordVaultApplication extends Application {
    private final LanSessionManager lanSessionManager = new LanSessionManager(
            new LanClock() {
                @Override
                public long nowMillis() {
                    return SystemClock.elapsedRealtime();
                }
            },
            new LanRandom() {
                private final SecureRandom random = new SecureRandom();

                @Override
                public int nextInt(int bound) {
                    return random.nextInt(bound);
                }

                @Override
                public String nextSessionId() {
                    return UUID.randomUUID().toString();
                }
            }
    );
    private EncryptedVaultStore vaultStore;
    private VaultService vaultService;
    private final LanVaultAccessGate vaultAccessGate = new LanVaultAccessGate();
    private volatile String lanBindHost;

    public LanSessionManager getLanSessionManager() {
        return lanSessionManager;
    }

    public synchronized VaultService getVaultService() {
        if (vaultService == null) {
            vaultStore = new EncryptedVaultStore(this);
            vaultService = new VaultService(
                    vaultStore,
                    new VaultValidator(),
                    () -> UUID.randomUUID().toString(),
                    () -> System.currentTimeMillis()
            );
        }
        return vaultService;
    }

    public LanVaultAccessGate getLanVaultAccessGate() {
        return vaultAccessGate;
    }

    public void runExclusiveVaultMutation(final Runnable mutation) {
        if (mutation == null) throw new IllegalArgumentException("mutation must not be null");
        vaultAccessGate.runExclusiveMutation(new Runnable() {
            @Override public void run() {
                stopLanAccess();
                mutation.run();
            }
        });
    }

    /** Android instrumentation deletes its isolated database between test cases. */
    synchronized void closeVaultForInstrumentationTests() {
        if (vaultStore != null) vaultStore.close();
        vaultStore = null;
        vaultService = null;
    }

    public void stopLanAccess() { lanSessionManager.stop(); stopService(new Intent(this, LanAccessService.class)); }
    public void setLanBindHost(String host) { lanBindHost = host; }
    public String getLanBindHost() { return lanBindHost; }
    public String getLanAccessUrl() { String host = lanBindHost; return host == null ? null : "http://" + host + ":8080"; }
}
