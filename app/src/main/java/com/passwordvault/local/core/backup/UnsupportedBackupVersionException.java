package com.passwordvault.local.core.backup;

public final class UnsupportedBackupVersionException extends BackupException {
    public UnsupportedBackupVersionException(String message) {
        super(message);
    }
}
