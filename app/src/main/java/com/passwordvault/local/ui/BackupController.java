package com.passwordvault.local.ui;

import com.passwordvault.local.core.backup.BackupService;
import com.passwordvault.local.core.backup.ImportPreview;
import com.passwordvault.local.core.repository.VaultService;
import com.passwordvault.local.core.validation.ValidationException;

import java.util.Arrays;

public final class BackupController {
    private final VaultService vaultService;
    private final BackupService backupService;
    private final Runnable importSucceededCallback;

    public BackupController(
            VaultService vaultService,
            BackupService backupService,
            Runnable importSucceededCallback
    ) {
        if (vaultService == null || backupService == null || importSucceededCallback == null) {
            throw new IllegalArgumentException("BackupController dependencies must not be null");
        }
        this.vaultService = vaultService;
        this.backupService = backupService;
        this.importSucceededCallback = importSucceededCallback;
    }

    public byte[] exportBackup(char[] password, char[] confirmation) {
        requirePassword(password);
        if (confirmation == null || !Arrays.equals(password, confirmation)) {
            throw new ValidationException("两次输入的备份密码不一致");
        }
        return backupService.exportAll(vaultService.getSnapshot(), password);
    }

    public ImportPreview previewImport(byte[] backup, char[] password) {
        requirePassword(password);
        return backupService.previewImport(backup, password);
    }

    public void confirmImport(ImportPreview preview) {
        backupService.applyImport(preview);
        importSucceededCallback.run();
    }

    public void cancelImport(ImportPreview preview) {
        backupService.cancelImport(preview);
    }

    private static void requirePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new ValidationException("备份密码不能为空");
        }
    }
}
