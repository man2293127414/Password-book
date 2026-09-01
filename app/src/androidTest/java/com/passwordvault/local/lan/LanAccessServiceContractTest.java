package com.passwordvault.local.lan;

import android.Manifest;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.test.AndroidTestCase;

import java.io.InputStream;
import java.util.Arrays;

/** Minimal device-side manifest/service contract; network and permission behavior runs in CI/device QA. */
public final class LanAccessServiceContractTest extends AndroidTestCase {
    public void testStartIntentTargetsForegroundService() {
        Context context = getContext();
        Intent intent = LanAccessService.startIntent(context);
        assertEquals(LanAccessService.class.getName(), intent.getComponent().getClassName());
    }

    public void testServiceIsPrivateAndUsesConnectedDeviceForegroundType() throws Exception {
        ServiceInfo service = getContext().getPackageManager().getServiceInfo(
                new ComponentName(getContext(), LanAccessService.class),
                0
        );
        assertFalse(service.exported);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            assertTrue((service.foregroundServiceType
                    & ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE) != 0);
        }
    }

    public void testRequiredPermissionsArePackaged() throws Exception {
        PackageInfo info = getContext().getPackageManager().getPackageInfo(
                getContext().getPackageName(),
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

    public void testRuntimeCatalogAssetsAreBundledAndNonEmpty() throws Exception {
        WebAssetCatalog catalog = parseRuntimeCatalog();
        for (String path : catalog.paths()) {
            assertPackagedNonEmpty("web/" + path);
        }
    }

    public void testMetadataAndLicensesArePackagedButExcludedFromRuntimeCatalog() throws Exception {
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
        InputStream input = getContext().getAssets().open("web/runtime-assets.tsv");
        try {
            return WebAssetCatalog.parse(input);
        } finally {
            input.close();
        }
    }

    private void assertPackagedNonEmpty(String path) throws Exception {
        InputStream input = getContext().getAssets().open(path);
        try {
            assertTrue(path + " must be non-empty", input.read() != -1);
        } finally {
            input.close();
        }
    }
}
