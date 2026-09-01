package com.passwordvault.local;

import android.app.Instrumentation;
import android.view.WindowManager;
import android.widget.TextView;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;

import com.passwordvault.local.ui.VaultListController;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class VaultUiTest {
    @Rule
    public final ActivityTestRule<MainActivity> activityRule =
            new ActivityTestRule<MainActivity>(MainActivity.class, true, false);

    private MainActivity activity;

    @Before
    public void setUp() {
        VaultTestReset.closeApplicationVault(getInstrumentation().getTargetContext());
        getInstrumentation().getTargetContext().deleteDatabase("password_vault.db");
        activity = activityRule.launchActivity(null);
    }

    @After
    public void tearDown() {
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
    }

    @Test
    public void launchesUsablePasswordScreen() {
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

    @Test
    public void passwordMaskHasFixedLength() {
        assertEquals("••••••••", VaultListController.MASKED_PASSWORD);
    }

    private static Instrumentation getInstrumentation() {
        return InstrumentationRegistry.getInstrumentation();
    }
}
