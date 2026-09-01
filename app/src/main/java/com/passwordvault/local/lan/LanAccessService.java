package com.passwordvault.local.lan;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Build;
import android.os.IBinder;

import com.passwordvault.local.R;
import com.passwordvault.local.PasswordVaultApplication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/** Foreground-only owner of the embedded LAN HTTP listener. */
public final class LanAccessService extends Service {
    public static final String ACTION_STOP = "com.passwordvault.local.action.STOP_LAN_ACCESS";
    private static final String CHANNEL_ID = "lan_access";
    private static final int NOTIFICATION_ID = 41;
    private static final int HTTP_PORT = 8080;
    private static final long ADDRESS_CHECK_INTERVAL_SECONDS = 1L;

    private final Object lifecycleLock = new Object();
    private final Object webAssetCatalogLock = new Object();
    private volatile WebAssetCatalog webAssetCatalog;
    private final LanServerOwner serverOwner = new LanServerOwner(new LanServerOwner.Factory() {
        @Override
        public LanServerOwner.Server create() {
            return new LanServerOwner.Server() {
                private final LanApiDispatcher dispatcher = new LanApiDispatcher(
                        ((PasswordVaultApplication) getApplication()).getVaultService(),
                        ((PasswordVaultApplication) getApplication()).getLanSessionManager(),
                        new java.security.SecureRandom(),
                        ((PasswordVaultApplication) getApplication()).getLanVaultAccessGate()
                );
                private final LanHttpServer server = new LanHttpServer(((PasswordVaultApplication) getApplication()).getLanBindHost(), HTTP_PORT, new LanHttpServer.IndexHtmlSource() {
                    @Override
                    public byte[] load() throws IOException {
                        return loadBundledIndexHtml();
                    }
                }, dispatcher, new LanHttpServer.StaticAssetSource() {
                    @Override
                    public LanHttpServer.StaticAsset load(String path) throws IOException {
                        return loadBundledWebAsset(path);
                    }
                });

                @Override
                public void start() throws IOException {
                    dispatcher.startRun();
                    server.start(NanoHttpdTimeout.SOCKET_READ_TIMEOUT_MILLIS, false);
                }

                @Override
                public void shutdown() {
                    server.shutdown();
                    dispatcher.stopRun();
                }

                @Override
                public boolean isAlive() {
                    return server.isAlive();
                }
            };
        }
    });
    private final LanNetworkGuard<Network> networkGuard = new LanNetworkGuard<Network>(
            new LanNetworkGuard.CurrentNetwork<Network>() {
                @Override
                public Network current() {
                    ConnectivityManager manager;
                    synchronized (lifecycleLock) {
                        manager = connectivityManager;
                    }
                    return manager == null ? null : manager.getActiveNetwork();
                }
            },
            new LanNetworkGuard.Stopper() {
                @Override
                public void stop() {
                    stopLanAccess();
                }
            }
    );
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private LanAddressGuard addressGuard;
    private ScheduledExecutorService addressMonitor;
    private volatile boolean serverStartCompleted;
    private boolean stopping;

    public static Intent startIntent(Context context) {
        return new Intent(context, LanAccessService.class);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopLanAccess();
            return START_NOT_STICKY;
        }
        if (!hasRequiredRuntimePermissions()) {
            stopLanAccess();
            return START_NOT_STICKY;
        }
        if (serverOwner.isRunning() || isStopping()) {
            return START_NOT_STICKY;
        }

        try {
            startForeground(NOTIFICATION_ID, createNotification());
        } catch (RuntimeException exception) {
            stopLanAccess();
            return START_NOT_STICKY;
        }
        if (!registerDefaultNetworkCallback() || !startServerIfNotStopping()) {
            stopLanAccess();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        markStopping();
        shutdownResources();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private boolean hasRequiredRuntimePermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        return Build.VERSION.SDK_INT < 37
                || checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean registerDefaultNetworkCallback() {
        ConnectivityManager manager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (manager == null) {
            return false;
        }
        synchronized (lifecycleLock) {
            if (stopping) {
                return false;
            }
            connectivityManager = manager;
            networkGuard.captureBaseline();
            addressGuard = new LanAddressGuard(
                    new AndroidLanAddressSource(manager),
                    new LanNetworkGuard.Stopper() {
                        @Override
                        public void stop() {
                            stopLanAccess();
                        }
                    }
            );
            if (!addressGuard.captureBaseline()) {
                connectivityManager = null;
                addressGuard = null;
                networkGuard.clear();
                return false;
            }
            String address = addressGuard.getBaseline().iterator().next();
            ((PasswordVaultApplication) getApplication()).setLanBindHost(address.substring(address.indexOf('/') + 1));
            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(Network network) {
                    networkGuard.onDefaultNetworkChanged();
                }

                @Override
                public void onLost(Network network) {
                    networkGuard.onLost(network);
                }
            };
            try {
                addressMonitor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
                    @Override
                    public Thread newThread(Runnable runnable) {
                        Thread thread = new Thread(runnable, "LAN address monitor");
                        thread.setDaemon(true);
                        return thread;
                    }
                });
                final LanAddressGuard activeAddressGuard = addressGuard;
                addressMonitor.scheduleWithFixedDelay(new Runnable() {
                    @Override
                    public void run() {
                        if (!hasRequiredRuntimePermissions()) { stopLanAccess(); return; }
                        if (!serverStartCompleted) return;
                        activeAddressGuard.onAddressesChanged();
                        boolean serverRunning = serverOwner.isRunning();
                        ((PasswordVaultApplication) getApplication()).getLanSessionManager().checkTimeout();
                        com.passwordvault.local.core.lan.LanSessionState.Status state = ((PasswordVaultApplication) getApplication()).getLanSessionManager().getState().getStatus();
                        if (LanServiceHealthPolicy.shouldStop(
                                serverStartCompleted,
                                serverRunning,
                                state
                        )) {
                            stopLanAccess();
                        }
                    }
                }, ADDRESS_CHECK_INTERVAL_SECONDS, ADDRESS_CHECK_INTERVAL_SECONDS, TimeUnit.SECONDS);
                manager.registerDefaultNetworkCallback(networkCallback);
            } catch (RuntimeException exception) {
                networkCallback = null;
                connectivityManager = null;
                if (addressMonitor != null) addressMonitor.shutdownNow();
                addressMonitor = null;
                addressGuard.clear();
                addressGuard = null;
                networkGuard.clear();
                return false;
            }
        }
        networkGuard.onDefaultNetworkChanged();
        LanAddressGuard activeAddressGuard;
        synchronized (lifecycleLock) {
            activeAddressGuard = addressGuard;
        }
        if (activeAddressGuard != null) activeAddressGuard.onAddressesChanged();
        return !isStopping();
    }

    private boolean startServerIfNotStopping() {
        synchronized (lifecycleLock) {
            boolean started = !stopping && serverOwner.start();
            serverStartCompleted = started;
            return started;
        }
    }

    private void stopLanAccess() {
        if (!markStopping()) {
            return;
        }
        shutdownResources();
        stopSelf();
    }

    private boolean markStopping() {
        synchronized (lifecycleLock) {
            if (stopping) {
                return false;
            }
            stopping = true;
            serverStartCompleted = false;
            return true;
        }
    }

    private boolean isStopping() {
        synchronized (lifecycleLock) {
            return stopping;
        }
    }

    private void shutdownResources() {
        serverOwner.stop();
        stopAddressMonitor();
        unregisterNetworkCallback();
        stopForeground(true);
        ((PasswordVaultApplication) getApplication()).setLanBindHost(null);
    }

    private void stopAddressMonitor() {
        ScheduledExecutorService monitor;
        LanAddressGuard guard;
        synchronized (lifecycleLock) {
            monitor = addressMonitor;
            guard = addressGuard;
            addressMonitor = null;
            addressGuard = null;
        }
        if (guard != null) guard.clear();
        if (monitor != null) monitor.shutdownNow();
    }

    private void unregisterNetworkCallback() {
        ConnectivityManager manager;
        ConnectivityManager.NetworkCallback callback;
        synchronized (lifecycleLock) {
            manager = connectivityManager;
            callback = networkCallback;
            connectivityManager = null;
            networkCallback = null;
        }
        networkGuard.clear();
        if (manager != null && callback != null) {
            try {
                manager.unregisterNetworkCallback(callback);
            } catch (RuntimeException ignored) {
                // The callback was already removed by the system.
            }
        }
    }

    private Notification createNotification() {
        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.lan_service_channel_name),
                    NotificationManager.IMPORTANCE_LOW
            ));
        }
        Intent stopIntent = new Intent(this, LanAccessService.class).setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this,
                0,
                stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentTitle(getString(R.string.lan_service_notification_title))
                .setContentText(getString(R.string.lan_service_notification_text))
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(
                        0,
                        getString(R.string.lan_service_stop),
                        stopPendingIntent
                ).build())
                .build();
    }

    private byte[] loadBundledIndexHtml() throws IOException {
        return loadBundledAsset("web/index.html");
    }

    private LanHttpServer.StaticAsset loadBundledWebAsset(String relativePath) throws IOException {
        String contentType = runtimeWebAssetCatalog().contentType(relativePath);
        if (contentType == null) return null;
        return new LanHttpServer.StaticAsset(
                loadBundledAsset("web/" + relativePath),
                contentType
        );
    }

    private WebAssetCatalog runtimeWebAssetCatalog() throws IOException {
        WebAssetCatalog cached = webAssetCatalog;
        if (cached != null) return cached;
        synchronized (webAssetCatalogLock) {
            cached = webAssetCatalog;
            if (cached == null) {
                InputStream input = getAssets().open("web/runtime-assets.tsv");
                try {
                    cached = WebAssetCatalog.parse(input);
                } finally {
                    input.close();
                }
                webAssetCatalog = cached;
            }
            return cached;
        }
    }

    private byte[] loadBundledAsset(String assetPath) throws IOException {
        InputStream input = getAssets().open(assetPath);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static final class NanoHttpdTimeout {
        private static final int SOCKET_READ_TIMEOUT_MILLIS = 5_000;

        private NanoHttpdTimeout() {
        }
    }
}
