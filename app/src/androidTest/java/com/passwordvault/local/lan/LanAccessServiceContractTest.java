package com.passwordvault.local.lan;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.InputStream;
import java.util.Arrays;

/** Minimal device-side manifest/service contract; network and permission behavior runs in CI/device QA. */
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class LanAccessServiceContractTest {
    @Test
    public void startIntentTargetsForegroundService() {
        Context context = ApplicationProvider.getApplicationContext();
        Intent intent = LanAccessService.startIntent(context);
        assertEquals(LanAccessService.class.getName(), intent.getComponent().getClassName());
    }

    @Test
    public void serviceIsPrivateAndUsesConnectedDeviceForegroundType() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        ServiceInfo service = context.getPackageManager().getServiceInfo(
                new ComponentName(context, LanAccessService.class),
                0
        );
        assertFalse(service.exported);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            assertTrue((service.getForegroundServiceType()
                    & ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE) != 0);
        }
    }

    @Test
    public void requiredPermissionsArePackaged() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        PackageInfo info = context.getPackageManager().getPackageInfo(
                context.getPackageName(),
                PackageManager.GET_PERMISSIONS
        );
        assertNotNull(info.requestedPermissions);
        assertTrue(Arrays.asList(info.requestedPermissions).contains(Manifest.permission.INTERNET));
        assertTrue(Arrays.asList(info.requestedPermissions).contains(
                Manifest.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE
        ));
        assertTrue(Arrays.asList(info.requestedPermissions).contains(
                Manifest.permission.ACCESS_LOCAL_NETWORK
        ));
    }

    @Test
    public void runtimeCatalogAssetsAreBundledAndNonEmpty() throws Exception {
        WebAssetCatalog catalog = parseRuntimeCatalog();
        for (String path : catalog.paths()) {
            assertPackagedNonEmpty("web/" + path);
        }
    }

    @Test
    public void metadataAndLicensesArePackagedButExcludedFromRuntimeCatalog() throws Exception {
        WebAssetCatalog catalog = parseRuntimeCatalog();
        for (String path : new String[] {
                "vendor-manifest.json",
                "node_modules/@noble/ciphers/LICENSE",
                "node_modules/@noble/curves/LICENSE",
                "node_modules/@noble/hashes/LICENSE"
        }) {
            assertNull(catalog.contentType(path));
            assertPackagedNonEmpty("web/" + path);
        }
    }

    private WebAssetCatalog parseRuntimeCatalog() throws Exception {
        InputStream input = ApplicationProvider.getApplicationContext()
                .getAssets().open("web/runtime-assets.tsv");
        try {
            return WebAssetCatalog.parse(input);
        } finally {
            input.close();
        }
    }

    private void assertPackagedNonEmpty(String path) throws Exception {
        InputStream input = ApplicationProvider.getApplicationContext().getAssets().open(path);
        try {
            assertTrue(path + " must be non-empty", input.read() != -1);
        } finally {
            input.close();
        }
    }
}
