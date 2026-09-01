package com.passwordvault.local;

import android.test.ActivityInstrumentationTestCase2;
import android.view.WindowManager;
import android.widget.TextView;

import com.passwordvault.local.ui.VaultListController;

public final class VaultUiTest extends ActivityInstrumentationTestCase2<MainActivity> {
    private MainActivity activity;

    public VaultUiTest() {
        super(MainActivity.class);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        setActivityInitialTouchMode(true);
        VaultTestReset.closeApplicationVault(getInstrumentation().getTargetContext());
        getInstrumentation().getTargetContext().deleteDatabase("password_vault.db");
        activity = getActivity();
    }

    @Override
    protected void tearDown() throws Exception {
        if (activity != null) {
            getInstrumentation().runOnMainSync(new Runnable() {
                @Override
                public void run() {
                    activity.finish();
                }
            });
            getInstrumentation().waitForIdleSync();
        }
        VaultTestReset.closeApplicationVault(getInstrumentation().getTargetContext());
        getInstrumentation().getTargetContext().deleteDatabase("password_vault.db");
        super.tearDown();
    }

    public void testLaunchesUsablePasswordScreen() {
        TextView passwords = activity.findViewById(R.id.nav_passwords);
        TextView taxonomy = activity.findViewById(R.id.nav_taxonomy);
        TextView more = activity.findViewById(R.id.nav_more);

        assertNotNull(activity.findViewById(R.id.content_container));
        assertNotNull(activity.findViewById(R.id.search_input));
        assertNotNull(activity.findViewById(R.id.add_credential));
        assertNotNull(activity.findViewById(R.id.credential_list));
        assertEquals("密码", passwords.getText().toString());
        assertEquals("分类标签", taxonomy.getText().toString());
        assertEquals("更多", more.getText().toString());
        assertTrue((activity.getWindow().getAttributes().flags
                & WindowManager.LayoutParams.FLAG_SECURE) != 0);
    }

    public void testPasswordMaskHasFixedLength() {
        assertEquals("••••••••", VaultListController.MASKED_PASSWORD);
    }
}
