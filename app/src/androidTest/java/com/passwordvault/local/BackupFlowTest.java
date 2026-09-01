package com.passwordvault.local;

import android.app.AlertDialog;
import android.app.Instrumentation;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;

import com.passwordvault.local.core.backup.BackupCrypto;
import com.passwordvault.local.core.backup.BackupService;
import com.passwordvault.local.core.codec.VaultBinaryCodec;
import com.passwordvault.local.core.lan.LanSessionManager;
import com.passwordvault.local.core.lan.LanSessionState;
import com.passwordvault.local.core.model.Category;
import com.passwordvault.local.core.model.Credential;
import com.passwordvault.local.core.model.Tag;
import com.passwordvault.local.core.model.VaultSnapshot;
import com.passwordvault.local.core.repository.InMemoryVaultStore;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.VaultValidator;
import com.passwordvault.local.storage.EncryptedVaultStore;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class BackupFlowTest {
    private static final char[] PASSWORD = "backup-password".toCharArray();
    private MainActivity activity;
    private PasswordVaultApplication application;

    @Rule
    public final ActivityTestRule<MainActivity> activityRule =
            new ActivityTestRule<MainActivity>(MainActivity.class, true, false);

    @Before
    public void setUp() {
        VaultTestReset.closeApplicationVault(getInstrumentation().getTargetContext());
        getInstrumentation().getTargetContext().deleteDatabase("password_vault.db");
        seedCurrentVault();
        activity = activityRule.launchActivity(null);
        application = (PasswordVaultApplication) activity.getApplication();
        application.getLanSessionManager().stop();
    }

    @After
    public void tearDown() {
        if (application != null) application.getLanSessionManager().stop();
        if (activity != null) {
            getInstrumentation().runOnMainSync(new Runnable() {
                @Override
                public void run() {
                    activity.finish();
                }
            });
            getInstrumentation().waitForIdleSync();
            BackupFlowWaiter.waitFor(new BackupFlowWaiter.Condition() {
                @Override
                public boolean isMet() {
                    return activity.isBackupWorkStopped();
                }
            });
        }
        VaultTestReset.closeApplicationVault(getInstrumentation().getTargetContext());
        getInstrumentation().getTargetContext().deleteDatabase("password_vault.db");
    }

    @Test
    public void exportRequiresConfirmedBackupPassword() {
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                Intent result = new Intent().setData(Uri.parse("content://backup-test/export.pvlb"));
                activity.onActivityResult(MainActivity.REQUEST_EXPORT_BACKUP, MainActivity.RESULT_OK, result);
            }
        });
        final AlertDialog dialog = waitForActiveBackupDialog();
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                EditText password = dialog.findViewById(R.id.backup_password);
                EditText confirmation = dialog.findViewById(R.id.backup_password_confirmation);
                password.setText("first-password");
                confirmation.setText("other-password");
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
                assertNotNull(confirmation.getError());
                assertTrue(dialog.isShowing());
            }
        });
    }

    @Test
    public void cancelledFileSelectionDoesNotOpenBackupPasswordDialog() {
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                activity.findViewById(R.id.nav_more).performClick();
                assertNotNull(activity.findViewById(R.id.export_backup));
                assertNotNull(activity.findViewById(R.id.import_backup));
                activity.onActivityResult(MainActivity.REQUEST_IMPORT_BACKUP, MainActivity.RESULT_CANCELED,
                        new Intent());
                assertNull(activity.getActiveBackupDialog());
            }
        });
    }

    @Test
    public void importPreviewShowsCountsAndCancelPreservesCurrentVault() throws Exception {
        openImportWithPassword(createBackupFile(snapshot("imported"), PASSWORD), PASSWORD);

        final AlertDialog preview = waitForDialogContaining("备份包含 1 条密码记录、1 个分类和 1 个标签");
        assertTrue(dialogMessage(preview).contains("覆盖本机全部数据，且无法撤销"));
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                preview.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
                activity.findViewById(R.id.nav_passwords).performClick();
            }
        });

        assertTrue(containsText("current"));
        assertFalse(containsText("imported"));
        assertEquals(LanSessionState.Status.STOPPED,
                application.getLanSessionManager().getState().getStatus());
    }

    @Test
    public void confirmedImportReplacesVaultAndStopsSharedPcSession() throws Exception {
        LanSessionManager sessionManager = application.getLanSessionManager();
        sessionManager.start();
        openImportWithPassword(createBackupFile(snapshot("imported"), PASSWORD), PASSWORD);

        final AlertDialog preview = waitForDialogContaining("备份包含 1 条密码记录、1 个分类和 1 个标签");
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                preview.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
            }
        });

        waitFor(new BackupFlowWaiter.Condition() {
            @Override
            public boolean isMet() {
                return application.getLanSessionManager().getState().getStatus()
                        == LanSessionState.Status.STOPPED && containsText("imported");
            }
        });
    }

    @Test
    public void wrongPasswordThroughActivityKeepsVaultAndPcSession() throws Exception {
        LanSessionManager sessionManager = application.getLanSessionManager();
        sessionManager.start();
        openImportWithPassword(createBackupFile(snapshot("imported"), PASSWORD),
                "wrong-password".toCharArray());

        final AlertDialog error = waitForDialogContaining("备份密码不正确，现有数据未被修改");
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                error.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
                activity.findViewById(R.id.nav_passwords).performClick();
            }
        });

        assertTrue(containsText("current"));
        assertFalse(containsText("imported"));
        assertEquals(LanSessionState.Status.AWAITING_CODE,
                application.getLanSessionManager().getState().getStatus());
    }

    private void openImportWithPassword(final File backup, final char[] password) {
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                Intent result = new Intent().setData(Uri.fromFile(backup));
                activity.onActivityResult(MainActivity.REQUEST_IMPORT_BACKUP, MainActivity.RESULT_OK, result);
            }
        });
        final AlertDialog dialog = waitForActiveBackupDialog();
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                EditText input = dialog.findViewById(R.id.backup_password);
                input.setText(new String(password));
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
            }
        });
    }

    private AlertDialog waitForActiveBackupDialog() {
        final AtomicReference<AlertDialog> found = new AtomicReference<AlertDialog>();
        waitFor(new BackupFlowWaiter.Condition() {
            @Override
            public boolean isMet() {
                final boolean[] showing = new boolean[] {false};
                getInstrumentation().runOnMainSync(new Runnable() {
                    @Override
                    public void run() {
                        AlertDialog dialog = activity.getActiveBackupDialog();
                        if (dialog != null && dialog.isShowing()) {
                            found.set(dialog);
                            showing[0] = true;
                        }
                    }
                });
                return showing[0];
            }
        });
        return found.get();
    }

    private AlertDialog waitForDialogContaining(final String expectedText) {
        final AtomicReference<AlertDialog> found = new AtomicReference<AlertDialog>();
        waitFor(new BackupFlowWaiter.Condition() {
            @Override
            public boolean isMet() {
                final boolean[] matches = new boolean[] {false};
                getInstrumentation().runOnMainSync(new Runnable() {
                    @Override
                    public void run() {
                        AlertDialog dialog = activity.getActiveBackupDialog();
                        if (dialog != null && dialog.isShowing()
                                && dialogMessage(dialog).contains(expectedText)) {
                            found.set(dialog);
                            matches[0] = true;
                        }
                    }
                });
                return matches[0];
            }
        });
        return found.get();
    }

    private boolean containsText(final String expectedText) {
        final boolean[] found = new boolean[] {false};
        getInstrumentation().runOnMainSync(new Runnable() {
            @Override
            public void run() {
                found[0] = containsText(activity.getWindow().getDecorView(), expectedText);
            }
        });
        return found[0];
    }

    private static boolean containsText(View view, String expectedText) {
        if (view instanceof TextView
                && ((TextView) view).getText().toString().contains(expectedText)) {
            return true;
        }
        if (!(view instanceof ViewGroup)) return false;
        ViewGroup group = (ViewGroup) view;
        for (int index = 0; index < group.getChildCount(); index++) {
            if (containsText(group.getChildAt(index), expectedText)) return true;
        }
        return false;
    }

    private static String dialogMessage(AlertDialog dialog) {
        TextView message = dialog.findViewById(android.R.id.message);
        return message == null ? "" : message.getText().toString();
    }

    private static void waitFor(BackupFlowWaiter.Condition condition) {
        BackupFlowWaiter.waitFor(condition);
    }

    private File createBackupFile(VaultSnapshot snapshot, char[] password) throws IOException {
        VaultService vaultService = new VaultService(new InMemoryVaultStore(snapshot), new VaultValidator(),
                new Supplier<String>() {
                    @Override
                    public String get() {
                        return "unused";
                    }
                }, new LongSupplier() {
                    @Override
                    public long getAsLong() {
                        return 1L;
                    }
                });
        byte[] backup = new BackupService(vaultService, new VaultBinaryCodec(),
                new BackupCrypto(new SecureRandom())).exportAll(snapshot, password);
        File file = File.createTempFile("backup-flow", ".pvlb", activity.getCacheDir());
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(backup);
        } finally {
            java.util.Arrays.fill(backup, (byte) 0);
        }
        return file;
    }

    private void seedCurrentVault() {
        EncryptedVaultStore store = new EncryptedVaultStore(getInstrumentation().getTargetContext());
        try {
            store.replace(snapshot("current"));
        } finally {
            store.close();
        }
    }

    private static VaultSnapshot snapshot(String name) {
        Category category = new Category("category-" + name, "分类", 1);
        Tag tag = new Tag("tag-" + name, "标签", 1);
        Credential credential = new Credential("credential-" + name, name, "account", "password", "",
                category.getId(), Collections.singleton(tag.getId()), "", 1, 1000L, 1000L);
        return new VaultSnapshot(VaultSnapshot.CURRENT_SCHEMA_VERSION, 1L,
                Collections.singletonList(credential), Collections.singletonList(category),
                Collections.singletonList(tag));
    }

    private static Instrumentation getInstrumentation() {
        return InstrumentationRegistry.getInstrumentation();
    }
}
